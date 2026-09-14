//! W13 step 3: the SERVICE HOST's core — config, home, lifecycle state,
//! the loopback IPC control plane, and the per-user isolation gate the
//! engine's accept paths consult.
//!
//! IPC design deviation from the plan, recorded honestly: instead of a
//! raw named pipe (unsafe CreateNamedPipeW + DACL), the control plane is
//! a LOOPBACK-ONLY TCP listener with per-connection kernel-table peer
//! attribution (peer.rs, probe-validated 200/200). Security properties
//! are equal-or-better than the planned INTERACTIVE DACL: loopback is
//! unreachable off-box, and attribution pins commands to the OWNING
//! user's SID — the pipe DACL would have admitted ANY interactive user.

use crate::metrics;
use crate::peer;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

/// Lifecycle states (tray-facing).
pub const STATE_NEEDS_ENROLL: u8 = 0;
pub const STATE_DISCONNECTED: u8 = 1;
pub const STATE_CONNECTED: u8 = 2;
pub const STATE_DEGRADED: u8 = 3;

static STATE: AtomicU8 = AtomicU8::new(STATE_NEEDS_ENROLL);
static LAST_EVENT: OnceLock<Mutex<String>> = OnceLock::new();

fn last_event() -> &'static Mutex<String> {
    LAST_EVENT.get_or_init(|| Mutex::new("boot".into()))
}

pub fn set_state(s: u8, note: &str) {
    STATE.store(s, Ordering::SeqCst);
    *last_event().lock().unwrap() = note.to_string();
    let name = match s {
        STATE_CONNECTED => "connected",
        STATE_DISCONNECTED => "disconnected",
        STATE_DEGRADED => "degraded",
        _ => "needs_enrollment",
    };
    crate::log_event("tray_state_changed", &format!("{name} note={note}"));
}

pub fn last_event_text() -> String {
    last_event().lock().unwrap().clone()
}

pub fn state_name() -> &'static str {
    match STATE.load(Ordering::SeqCst) {
        STATE_CONNECTED => "connected",
        STATE_DISCONNECTED => "disconnected",
        STATE_DEGRADED => "degraded",
        _ => "needs_enrollment",
    }
}

// ---------- isolation gate (engine accept paths consult this) ----------

static OWNING_SID: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn owning_sid() -> &'static Mutex<Option<String>> {
    OWNING_SID.get_or_init(|| Mutex::new(None))
}

/// The service sets the owning user at login handoff; the standalone CLI
/// never sets it (single-user by construction — isolation off, as
/// documented in the plan).
/// Engine-generation cancellation: disconnect cancels the CURRENT token
/// (every serve loop selects on it and exits); connect arms a fresh one.
/// Aborting the parent engine task alone would orphan its spawned
/// forwarder children — this is the effective kill path (W13.3 run-1).
pub fn engine_cancel() -> tokio_util::sync::CancellationToken {
    static T: OnceLock<Mutex<tokio_util::sync::CancellationToken>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(tokio_util::sync::CancellationToken::new()))
        .lock()
        .unwrap()
        .clone()
}

pub fn engine_cancel_arm_fresh() {
    static T: OnceLock<Mutex<tokio_util::sync::CancellationToken>> = OnceLock::new();
    let mut t = T
        .get_or_init(|| Mutex::new(tokio_util::sync::CancellationToken::new()))
        .lock()
        .unwrap();
    *t = tokio_util::sync::CancellationToken::new();
}

pub fn set_owning_sid(sid: &str) {
    *owning_sid().lock().unwrap() = Some(sid.to_string());
}

pub fn owning_sid_get() -> Option<String> {
    owning_sid().lock().unwrap().clone()
}

/// The gate the forwarder/DNS accept paths call. `true` = allow (no
/// owner set = standalone CLI, or the peer IS the owning user's
/// process); `false` = refuse (counted + logged by the caller).
pub fn isolation_allows(peer: SocketAddr, tcp: bool) -> bool {
    let owner = owning_sid_get();
    let Some(owner) = owner else {
        return true;
    };
    let attributed = if tcp {
        peer::tcp_owner(peer)
    } else {
        peer::udp_owner(peer)
    };
    match attributed {
        Ok(o) => peer::peer_allowed(&owner, &o.sid),
        Err(_) => false, // fail closed (probe: fast-close = unresolvable)
    }
}

// ---------- config + home ----------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SvcConfig {
    /// W29: defaults to empty — a CLI-side svc.toml may carry only the
    /// ipc_bind (the caller just needs the socket path; an empty
    /// controller_url was a hard parse error before, which made a
    /// minimal caller config impossible)
    #[serde(default)]
    pub controller_url: String,
    #[serde(default)]
    pub controller_enroll_url: Option<String>,
    /// dests to serve when connected (host:port each; v1 explicit config
    /// — zones-driven list rides the tray step)
    #[serde(default)]
    pub dests: Vec<String>,
    #[serde(default)]
    pub dns: Option<String>,
    #[serde(default)]
    pub metrics: Option<String>,
    /// loopback-only control plane
    #[serde(default = "default_ipc")]
    pub ipc_bind: String,
    #[serde(default)]
    pub local_port: Option<u16>,
}

fn default_ipc() -> String {
    // W29 §3.5: unix IPC is a UDS path (0666 in a root-owned 0755 dir,
    // SO_PEERCRED does the authorizing); Windows keeps loopback TCP.
    #[cfg(unix)]
    {
        "/run/aztna-client/ipc.sock".into()
    }
    #[cfg(windows)]
    {
        "127.0.0.1:29171".into()
    }
}

/// Service home: Windows = ProgramData\aztna (or AZTNA_SVC_HOME — the E2E
/// run area overrides this); Linux = /var/lib/aztna-client (W29 plan §3.1).
/// The engine's state root (AZTNA_STATE_DIR) is pointed here BEFORE any
/// state use, so the whole engine (identity, cert, zones cache) lives in
/// the service home.
pub fn svc_home() -> std::path::PathBuf {
    if let Ok(d) = std::env::var("AZTNA_SVC_HOME") {
        return std::path::PathBuf::from(d);
    }
    #[cfg(windows)]
    {
        std::env::var("ProgramData")
            .map(|pd| std::path::PathBuf::from(pd).join("aztna"))
            .unwrap_or_else(|_| ".aztna-svc".into())
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/var/lib/aztna-client")
    }
}

/// W13 step 6 [MSI handoff]: the installer writes CONTROLLER_URL into
/// HKLM\SOFTWARE\aZTNA\Client — the service honors it when svc.toml
/// carries no controller (property-driven silent deploy). Linux has no
/// equivalent override in W29 — svc.toml (or its absence) is the whole
/// config surface there.
#[cfg(windows)]
pub fn registry_controller_override() -> Option<String> {
    use windows::core::HSTRING;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
    let subkey = HSTRING::from("SOFTWARE\\aZTNA\\Client");
    let value = HSTRING::from("controller_url");
    let mut buf = [0u16; 512];
    let mut cb = (buf.len() * 2) as u32;
    let ok = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &subkey,
            &value,
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut cb),
        )
    };
    if ok.is_err() {
        return None;
    }
    let len = (cb as usize / 2).saturating_sub(1);
    Some(String::from_utf16_lossy(&buf[..len]))
}

pub fn load_config() -> Result<SvcConfig> {
    let p = svc_home().join("svc.toml");
    // unix has no registry override, so the binding stays immutable there
    #[cfg(windows)]
    let mut cfg = if p.exists() {
        toml::from_str(&std::fs::read_to_string(p)?)?
    } else {
        SvcConfig::default()
    };
    #[cfg(not(windows))]
    let cfg = if p.exists() {
        toml::from_str(&std::fs::read_to_string(p)?)?
    } else {
        SvcConfig::default()
    };
    // MSI property override (registry beats a defaulted/absent toml value)
    #[cfg(windows)]
    if cfg.controller_url.is_empty() {
        cfg.controller_url = registry_controller_override().unwrap_or_default();
    }
    Ok(cfg)
}

// ---------- IPC: JSON lines over the platform transport ----------
// Windows: loopback-only TCP + kernel-table peer attribution (W13).
// Unix (W29 step 7, plan §3.5): a Unix domain socket with SO_PEERCRED —
// the kernel hands the connected uid directly (race-free), socket mode
// 0666 inside a root-owned dir so any local user can CONNECT and the
// OWNING-USER check decides at the IPC layer (Windows parity).

#[derive(Debug, Serialize, Deserialize)]
pub struct IpcReq {
    pub v: u32,
    pub cmd: String,
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpcResp {
    pub ok: bool,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

/// The connected peer's kernel-verified uid. The SID slot of the
/// owning-user model carries the decimal uid on unix.
/// Linux (W29 §3.5): SO_PEERCRED. macOS (W30): LOCAL_PEERTOKEN audit
/// token euid — implements with the step-5 hard gate; until then the
/// macOS arm fails closed (Err) and the service refuses the session.
#[cfg(target_os = "linux")]
pub fn uds_peer_uid(stream: &tokio::net::UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(anyhow!("SO_PEERCRED: {rc}"));
    }
    Ok(cred.uid)
}

/// W30 step 5 (plan §3.7 — the HARD GATE): the Darwin kernel
/// credential is `LOCAL_PEERTOKEN` under `SOL_LOCAL` — the kernel
/// returns an `audit_token_t` captured at CONNECT time; euid =
/// token[1] (the libbsm audit_token_to_euid mapping). One getsockopt,
/// no second syscall, no userland pid re-read — the pid-recycling race
/// class the round-1 review demanded be PROVEN absent (the acceptance
/// matrix + stress loop, not this comment, is the evidence).
/// Retrieval failure or unexpected length = Err = the session is
/// refused (fail closed). No weaker fallback exists.
#[cfg(target_os = "macos")]
pub fn uds_peer_uid(stream: &tokio::net::UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;
    // audit_token_t = u_int32_t[8]
    let mut token: [libc::c_uint; 8] = [0; 8];
    let want = std::mem::size_of::<[libc::c_uint; 8]>() as libc::socklen_t;
    let mut len = want;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(anyhow!(
            "LOCAL_PEERTOKEN getsockopt rc={rc}: {} - fail closed",
            std::io::Error::last_os_error()
        ));
    }
    if len != want {
        return Err(anyhow!(
            "LOCAL_PEERTOKEN returned {len} bytes (want {want}) - fail closed"
        ));
    }
    Ok(token[1])
}

/// Client side (glmcli svc-*): one request, one response line.
pub async fn ipc_call(bind: &str, req: &IpcReq) -> Result<IpcResp> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    #[cfg(unix)]
    let sock = {
        use tokio::io::AsyncRead as _;
        use tokio::io::AsyncWriteExt as _;
        let path = std::path::Path::new(bind);
        let s = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::UnixStream::connect(path),
        )
        .await
        .map_err(|_| anyhow!("service unreachable (is glmsvc running?)"))??;
        s
    };
    #[cfg(windows)]
    let sock = {
        let addr: SocketAddr = bind.parse().with_context(|| format!("ipc bind {bind}"))?;
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .map_err(|_| anyhow!("service unreachable (is glmsvc running?)"))??
    };
    let (r, mut w) = sock.into_split();
    use tokio::io::AsyncWriteExt as _;
    let line = serde_json::to_string(req)?;
    w.write_all(format!("{line}\n").as_bytes()).await?;
    let mut rl = BufReader::new(r);
    let mut resp = String::new();
    let got =
        tokio::time::timeout(std::time::Duration::from_secs(5), rl.read_line(&mut resp)).await;
    if let Ok(Ok(_)) = got {
        let line = resp.trim().to_string();
        if !line.is_empty() {
            return Ok(serde_json::from_str(&line)?);
        }
    }
    Err(anyhow!("no ipc response (timeout)"))
}

pub fn ipc_count(kind: &str, ok: bool) {
    metrics::ipc_requests_total()
        .with_label_values(&[kind, if ok { "ok" } else { "error" }])
        .inc();
}

// ---------------------------------------------------------------------
// W30 step 5 — Darwin IPC credential tests (the §3.7 acceptance
// matrix's mechanics layer; the ownership/sequencing layer is the
// ipc_matrix lane; together they are the hard-gate evidence).
// ---------------------------------------------------------------------
#[cfg(target_os = "macos")]
#[cfg(test)]
mod macos_ipc_tests {
    use super::*;

    fn tmp_sock(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("aztna-svcipc-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let p = d.join(name);
        let _ = std::fs::remove_file(&p);
        p
    }

    /// Matrix 1+4 (mechanics): a connected pair yields the kernel
    /// uid; the credential is readable the instant the connection
    /// exists (connect-time capture).
    #[tokio::test]
    async fn self_pair_credential_is_own_uid() {
        let path = tmp_sock("pair.sock");
        let l = tokio::net::UnixListener::bind(&path).unwrap();
        let c = tokio::net::UnixStream::connect(&path).await.unwrap();
        let (s, _) = l.accept().await.unwrap();
        let uid = uds_peer_uid(&s).expect("credential on a live pair");
        assert_eq!(uid, unsafe { libc::getuid() });
        drop(c);
        drop(s);
        let _ = std::fs::remove_file(&path);
    }

    /// Matrix 6 (fail closed): a socket that never had a peer (a
    /// listening fd) fails the credential read — Err, never a
    /// default/guessed uid.
    #[tokio::test]
    async fn no_peer_credential_fails_closed() {
        use std::os::fd::{AsRawFd, FromRawFd};
        let path = tmp_sock("npeer.sock");
        let l = tokio::net::UnixListener::bind(&path).unwrap();
        let fd = unsafe { libc::dup(l.as_raw_fd()) };
        let std_s = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        std_s.set_nonblocking(true).unwrap();
        let s = tokio::net::UnixStream::from_std(std_s).unwrap();
        assert!(
            uds_peer_uid(&s).is_err(),
            "no-peer socket must fail closed, not invent a uid"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Matrix 4+5 (the proof the review demanded): children that
    /// connect and die immediately — every accepted socket's
    /// credential still reads OUR uid; rapid churn never yields a
    /// wrong-user token (the pid-recycling race class).
    #[tokio::test]
    async fn dead_and_churning_peers_never_misattribute() {
        let path = tmp_sock("churn.sock");
        let l = tokio::net::UnixListener::bind(&path).unwrap();
        let mine = unsafe { libc::getuid() };
        for i in 0..12 {
            let mut child = std::process::Command::new("/usr/bin/python3")
                .args([
                    "-c",
                    &format!(
                        "import socket,time;s=socket.socket(socket.AF_UNIX);\
                         s.connect({:?});time.sleep(3)",
                        path
                    ),
                ])
                .spawn()
                .expect("python3 on the runner");
            let got = tokio::time::timeout(std::time::Duration::from_secs(10), l.accept()).await;
            let (s, _) = got.expect("connect deadline").expect("accept");
            let killed = i % 2 == 0;
            if killed {
                // half the children die mid-connection
                let _ = child.kill();
            }
            // DARWIN SEMANTICS (run 34774548504 evidence): a peer that
            // died before the credential read can yield EINVAL — the
            // kernel refuses the token, the session FAILS CLOSED. The
            // security property the matrix demands is NEVER-WRONG-USER:
            // live peer -> Ok(own uid); dead peer -> Err (refused) is
            // acceptable; Ok(other uid) is a hard failure either way.
            let verdict = uds_peer_uid(&s);
            match (&verdict, killed) {
                (Ok(uid), false) => {
                    assert_eq!(*uid, mine, "iteration {i}: live peer must read own uid")
                }
                (Ok(uid), true) => {
                    // peer died before the read: own uid still fine
                    assert_eq!(*uid, mine, "iteration {i}: dead peer read WRONG uid");
                }
                (Err(_), true) => {} // refused = fail closed, by design
                (Err(e), false) => panic!("iteration {i}: live peer credential failed: {e:#}"),
            }
            let _ = child.wait();
        }
        let _ = std::fs::remove_file(&path);
    }
}
