//! glmsvc — the SERVICE EXECUTION HOST over the shared client engine
//! [W13 step 3: one shared engine; CLI and service are execution hosts].
//!
//! Modes:
//!   glmsvc --console        supervised console mode (the E2E path)
//!   glmsvc                  SCM-invoked (sc.exe wrapper; v1 stop
//!                           semantics documented: process-killed —
//!                           proper SCM handler rides the owner-run lane)
//!   glmsvc install          registers the Windows service (auto-restart)
//!   glmsvc uninstall        removes it
//!
//! Startup order matters: the service home becomes the engine state root
//! (AZTNA_STATE_DIR) BEFORE any state load, and the token-store profile
//! is MACHINE before any save. Bootstrap enrollment (token placed at
//! <home>\bootstrap-token.txt by the installer/admin) runs with backoff
//! until it succeeds — never crash-loops (SCM restart is for crashes).

use anyhow::{Context, Result};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let a1 = std::env::args().nth(1);
    // W29: install/uninstall manage the Windows SCM service + tray Run
    // key; on Linux the service is systemd-managed (unit ships in W29
    // step 7 — until then console/foreground mode is the Linux path)
    #[cfg(windows)]
    match a1.as_deref() {
        Some("install") => install(),
        Some("uninstall") => uninstall().await,
        // W43 S3.3: the two-layer split-DNS watchdog execution modes —
        // short-lived standalone invocations, never the console engine
        Some("--splitdns-watchdog") => {
            let gen = std::env::args().nth(2).unwrap_or_default();
            aztna_client::splitdns::watchdog::companion_main(&gen).await;
            Ok(())
        }
        Some("--splitdns-watchdog-check") => {
            aztna_client::splitdns::watchdog::check_main().await;
            Ok(())
        }
        // MSI uninstall custom action: remove the backstop task + any
        // resident owned rules (plan §4.4 boot & uninstall)
        Some("--splitdns-uninstall-clean") => {
            aztna_client::splitdns::watchdog::delete_task();
            let n = aztna_client::splitdns::watchdog::clean().await;
            println!("splitdns uninstall clean: removed {n} owned rule(s)");
            Ok(())
        }
        // read-only ground-truth query (W43 S3.4): one JSON line per NRPT
        // rule — the PowerShell-free oracle for operators and the e2e lane
        Some("--splitdns-status") => aztna_client::splitdns::watchdog::status().await.map(|_| ()),
        _ => console_main().await,
    }
    // W43 S5.2: the macOS split-DNS watchdog modes — same standalone
    // invocation contract as the Windows arms (the launchd tick runs the
    // check; there is no companion mode — launchd polls natively)
    #[cfg(target_os = "macos")]
    match a1.as_deref() {
        Some("--splitdns-watchdog-check") => {
            aztna_client::splitdns::watchdog_macos::check_main().await;
            Ok(())
        }
        // W43 S5.3: dev/test hook for the CP-free mechanics lane on the
        // public mirror (plan §10 "client-only, stub zone map"): activate
        // the launchd watchdog + ONE reconciler tick against the stub
        // names given as argv — the REAL channel, real files, real
        // heartbeat, zero control plane. Never used by the service path.
        Some("--splitdns-selftest") => {
            let names: Vec<String> = std::env::args().skip(2).collect();
            aztna_client::splitdns::watchdog_macos::selftest(&names).await;
            Ok(())
        }
        Some("--splitdns-uninstall-clean") => {
            aztna_client::splitdns::watchdog_macos::delete_job();
            let n = aztna_client::splitdns::watchdog_macos::clean().await;
            println!("splitdns uninstall clean: removed {n} owned resolver file(s)");
            Ok(())
        }
        // read-only ground-truth oracle (same JSON shape as Windows)
        Some("--splitdns-status") => {
            let rules = aztna_client::splitdns::channel::enumerate_retry().await?;
            for r in &rules {
                println!(
                    "{{\"namespace\":\"{}\",\"id\":\"{}\",\"ours\":{},\"generation\":{}}}",
                    r.namespace,
                    r.id,
                    r.generation.is_some(),
                    match &r.generation {
                        Some(g) => format!("\"{g}\""),
                        None => "null".to_string(),
                    }
                );
            }
            Ok(())
        }
        Some("uninstall") => {
            // plan §4.4 boot & uninstall: the cleanup owner goes WITH the
            // product — launchd job deleted, owned resolver files removed
            aztna_client::splitdns::watchdog_macos::delete_job();
            let n = aztna_client::splitdns::watchdog_macos::clean().await;
            println!("splitdns uninstall clean: removed {n} owned resolver file(s)");
            Ok(())
        }
        _ => console_main().await,
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    match a1.as_deref() {
        Some("install") | Some("uninstall") => {
            anyhow::bail!("SCM install/uninstall is Windows-only; on Linux the glmsvc unit ships with the package (W29 step 7)")
        }
        _ => console_main().await,
    }
}

#[cfg(windows)]
fn service_bin() -> String {
    std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

#[cfg(windows)]
fn install() -> Result<()> {
    let bin = service_bin();
    let out = std::process::Command::new("sc")
        .args(["create", "aztna-svc", "binPath=", &bin, "start=", "auto"])
        .output()
        .context("sc create")?;
    println!("{}", String::from_utf8_lossy(&out.stdout));
    // crash policy: restart after 5 s (W13 plan resilience)
    for args in [
        vec![
            "failure",
            "aztna-svc",
            "reset=",
            "86400",
            "actions=",
            "restart/5000",
        ],
        vec!["failureflag", "aztna-svc", "1"],
    ] {
        let _ = std::process::Command::new("sc").args(&args).output();
    }
    let _ = std::process::Command::new("sc")
        .args(["start", "aztna-svc"])
        .output();
    // tray autostart at logon (HKLM Run key; W13 plan step 4)
    let cli = std::path::Path::new(&bin)
        .parent()
        .map(|d| d.join("glmcli.exe"))
        .map(|p| format!("\"{}\" tray", p.display()))
        .unwrap_or_default();
    if !cli.is_empty() {
        let _ = std::process::Command::new("reg")
            .args([
                "add",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "/v",
                "aztna-tray",
                "/t",
                "REG_SZ",
                "/d",
                &cli,
                "/f",
            ])
            .output();
    }
    println!("service aztna-svc installed + started (bin {bin}; tray Run key aztna-tray)");
    Ok(())
}

#[cfg(windows)]
async fn uninstall() -> Result<()> {
    let _ = std::process::Command::new("sc")
        .args(["stop", "aztna-svc"])
        .output();
    let out = std::process::Command::new("sc")
        .args(["delete", "aztna-svc"])
        .output()
        .context("sc delete")?;
    println!("{}", String::from_utf8_lossy(&out.stdout));
    // W43 S3.3 [plan §4.4 boot & uninstall]: the cleanup owner goes WITH
    // the product — backstop task deleted, resident owned rules removed
    aztna_client::splitdns::watchdog::delete_task();
    let n = aztna_client::splitdns::watchdog::clean().await;
    println!("splitdns uninstall clean: removed {n} owned rule(s)");
    Ok(())
}

async fn console_main() -> Result<()> {
    use aztna_client::svc;
    let home = svc::svc_home();
    // W29: the service home is the engine state dir on both platforms —
    // unix creates it 0700 (atrest hygiene; it holds key material)
    #[cfg(unix)]
    {
        aztna_client::atrest::ensure_dir_hygiene(&home)?;
    }
    #[cfg(windows)]
    {
        std::fs::create_dir_all(&home)?;
    }
    // engine state root = service home (BEFORE any state use)
    std::env::set_var("AZTNA_STATE_DIR", &home);
    // at-rest token profile = machine (this host's security parameter)
    aztna_client::tokenstore::set_machine_profile();
    aztna_client::metrics::init();
    let cfg = svc::load_config()?;

    // opt-in loopback metrics endpoint for the service itself
    if let Some(spec) = &cfg.metrics {
        if let Ok(l) = tokio::net::TcpListener::bind(spec.as_str()).await {
            println!("[svc] metrics on http://{spec}/metrics (loopback)");
            tokio::spawn(async move {
                loop {
                    if let Ok((sock, _)) = l.accept().await {
                        let _ = aztna_client::metrics_http_serve(sock).await;
                    }
                }
            });
        }
    }

    // bootstrap enrollment (unattended; token at <home>\bootstrap-token.txt)
    let mut st = aztna_client::load_state()?;
    if st.device_id.is_none() {
        let tok_path = home.join("bootstrap-token.txt");
        match std::fs::read_to_string(&tok_path) {
            Ok(t) if !t.trim().is_empty() => {
                svc::set_state(svc::STATE_NEEDS_ENROLL, "bootstrap enrollment starting");
                match aztna_client::run_with(aztna_client::Cli {
                    controller: Some(cfg.controller_url.clone()),
                    cmd: aztna_client::Cmd::Enroll {
                        token: t.trim().to_string(),
                        hostname: host_name(),
                    },
                })
                .await
                {
                    Ok(()) => {
                        aztna_client::log_event("bootstrap_enroll_ok", "service auto-enrolled");
                        st = aztna_client::load_state()?;
                    }
                    Err(e) => {
                        aztna_client::log_event(
                            "bootstrap_enroll_failed",
                            &format!(
                                "{e:#} (will NOT crash-loop; place a fresh token and restart)"
                            ),
                        );
                        svc::set_state(svc::STATE_NEEDS_ENROLL, "bootstrap enroll failed");
                    }
                }
            }
            _ => svc::set_state(svc::STATE_NEEDS_ENROLL, "no device + no bootstrap token"),
        }
    }
    if st.device_id.is_some() {
        svc::set_state(svc::STATE_DISCONNECTED, "ready");
    }
    aztna_client::metrics::service_starts_total()
        .with_label_values(&["ok"])
        .inc();

    // ---- the control plane ----
    // Windows (W13): loopback TCP + kernel-table peer attribution.
    // Unix (W29 §3.5): UDS + SO_PEERCRED — socket 0666 inside a
    // root-owned 0755 dir (any local user may CONNECT; the owning-user
    // check decides). systemd socket activation (LISTEN_FDS) takes the
    // pre-bound socket (SocketMode=0666 owned by systemd); a foreground
    // bind chmods explicitly — the process umask never decides (the
    // round-3 UMask=0077 lesson).
    let serve_task: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>> =
        Arc::new(std::sync::Mutex::new(None));

    #[cfg(unix)]
    {
        let listener = bind_ipc_unix(&cfg).await?;
        println!(
            "[svc] home {} ipc {} state {} (ctrl-c to stop)",
            home.display(),
            cfg.ipc_bind,
            svc::state_name()
        );
        loop {
            let (sock, _) = listener.accept().await?;
            let caller = aztna_client::svc::uds_peer_uid(&sock)
                .map(|uid| uid.to_string())
                .map_err(|e| anyhow::anyhow!("peercred: {e}"));
            let cfg = cfg.clone();
            let serve_task = serve_task.clone();
            tokio::spawn(async move {
                if let Err(e) = ipc_session_unix(sock, caller, cfg, serve_task).await {
                    println!("[svc] ipc session: {e:#}");
                }
            });
        }
    }
    #[cfg(windows)]
    {
        let listener = tokio::net::TcpListener::bind(cfg.ipc_bind.as_str())
            .await
            .with_context(|| format!("ipc bind {}", cfg.ipc_bind))?;
        println!(
            "[svc] home {} ipc {} state {} (ctrl-c to stop)",
            home.display(),
            cfg.ipc_bind,
            svc::state_name()
        );
        loop {
            let (sock, peer) = listener.accept().await?;
            let cfg = cfg.clone();
            let serve_task = serve_task.clone();
            tokio::spawn(async move {
                if let Err(e) = ipc_session(sock, peer, cfg, serve_task).await {
                    println!("[svc] ipc session {peer}: {e:#}");
                }
            });
        }
    }
}

/// True iff `fd` is a LISTENING AF_UNIX socket bound to exactly `want`
/// — the launchd-activation probe: launchd hands activated sockets to
/// the job at the lowest free fds, and the exact slot is not
/// contractually documented (both fd 0 and systemd-style 3 observed
/// across macOS versions), while daemon stdio is /dev/null — so the
/// fd is identified by what it IS, never by its number.
#[cfg(unix)]
/// Bound path of an AF_UNIX socket fd (None if not AF_UNIX).
fn fd_unix_path(fd: i32) -> Option<String> {
    unsafe {
        let mut ss: libc::sockaddr_storage = std::mem::zeroed();
        let mut slen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getsockname(fd, &mut ss as *mut _ as *mut libc::sockaddr, &mut slen) != 0 {
            return None;
        }
        if ss.ss_family != libc::AF_UNIX as libc::sa_family_t {
            return None;
        }
        let un = &*(&ss as *const libc::sockaddr_storage as *const libc::sockaddr_un);
        let bytes = std::ffi::CStr::from_ptr(un.sun_path.as_ptr()).to_bytes();
        if bytes.is_empty() {
            return Some(String::new());
        }
        String::from_utf8(bytes.to_vec()).ok()
    }
}

// W30 regression fix (2026-09-15): these fd helpers are launchd-probe
// plumbing used ONLY by the cfg(unix) bind_ipc_unix below — the v3/v4
// wedge-fix iterations split them out without carrying the cfg gate, so
// the WINDOWS glmsvc build broke on the unix-only `libc` dep (compiles
// on the macOS CI, where libc exists; found by the first Windows
// workspace build after the W30 merge).
#[cfg(unix)]
fn fd_is_socket(fd: i32) -> bool {
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        libc::fstat(fd, &mut st) == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK
    }
}

#[cfg(unix)]
fn fd_accepting(fd: i32) -> bool {
    unsafe {
        let mut accepting: libc::c_int = 0;
        let mut alen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            &mut accepting as *mut _ as *mut libc::c_void,
            &mut alen,
        ) == 0
            && accepting != 0
    }
}
#[cfg(unix)]
fn fd_is_launchd_ipc(fd: i32, want: &str) -> bool {
    // v4 (fd-dump evidence, runs 34867854293/34869279841): launchd hands
    // the socket BOUND-but-not-listening (SO_ACCEPTCONN false — the daemon
    // listens itself) and macOS getsockname returns an EMPTY sun_path for
    // launchd-managed sockets — so neither the accept check nor the path
    // compare can identify it. The definitive matcher is INODE IDENTITY:
    // a Unix-domain socket bound to a path has that file's inode, so
    // fstat(fd).st_ino == stat(want).st_ino picks the right fd among the
    // unnamed sockets launchd passes (three appeared per handoff).
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            return false;
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFSOCK {
            return false;
        }
        let mut want_st: libc::stat = std::mem::zeroed();
        let want_c = std::ffi::CString::new(want).unwrap_or_default();
        if libc::stat(want_c.as_ptr(), &mut want_st) != 0 {
            return false;
        }
        st.st_ino == want_st.st_ino
    }
}

/// Unix IPC listener: systemd-activated fd 3 when LISTEN_FDS=1, or a
/// launchd-activated fd (0..=4 probed, matched by bound path) when
/// AZTNA_LAUNCHD_SOCKETS=1 — the launchd Sockets dict owns bind+mode,
/// the Darwin analog of systemd's LISTEN_FDS — else bind + explicit
/// chmod(0666).
#[cfg(unix)]
async fn bind_ipc_unix(cfg: &aztna_client::svc::SvcConfig) -> Result<tokio::net::UnixListener> {
    use std::os::fd::FromRawFd;
    if std::env::var("AZTNA_LAUNCHD_SOCKETS").as_deref() == Ok("1") {
        // W30 §3.7/§3.8: launchd created the socket with SockPathName +
        // SockPathMode=0666 BEFORE this process started — the plist is
        // the mode authority; the daemon never umask-masks its own
        // socket (the W29 round-3 lesson, launchd flavor). Fail closed
        // when no probed fd matches: launchd believes it owns this
        // path, and a silent self-bind would race its socket (and its
        // mode authority) — KeepAlive restarts us until an admin
        // fixes the plist; the log line says exactly what was probed.
        // 0..=64: launchd does not document WHICH fd the socket lands on
        // (0..=4 was an assumption - lane evidence 2026-09-14: the daemon
        // exits fail-closed on the runner, so the handoff fd is outside
        // 0..=4 there). On a miss, dump the fd table to <svc-home>/fd-dump.txt
        // before bailing so the next run shows exactly where launchd put it.
        // v3 (fd-dump evidence, run 34867854293): launchd hands BOUND-
        // not-listening sockets (SO_ACCEPTCONN false - the daemon must
        // listen() itself) and the strict path compare missed. Strict
        // match first; fallback: an unambiguous AF_UNIX candidate.
        let mut hit: Option<i32> = None;
        let mut fallback: Option<i32> = None;
        let mut n_unix_socks = 0u32;
        for fd in 0..=64 {
            if fd_is_launchd_ipc(fd, &cfg.ipc_bind) {
                hit = Some(fd);
                break;
            }
            if fd_is_socket(fd) && fd_unix_path(fd).is_some() {
                n_unix_socks += 1;
                if fallback.is_none() {
                    fallback = Some(fd);
                }
            }
        }
        // only take a fallback when the candidate set is UNAMBIGUOUS
        if hit.is_none() && n_unix_socks == 1 {
            hit = fallback;
        }
        if let Some(fd) = hit {
            // launchd hands a BOUND socket; the daemon listens itself
            unsafe {
                if libc::listen(fd, 128) != 0 {
                    let err = std::io::Error::last_os_error();
                    anyhow::bail!("launchd socket fd {fd}: listen() failed: {err}");
                }
            }
            let std_sock = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
            std_sock.set_nonblocking(true)?;
            let l = tokio::net::UnixListener::from_std(std_sock)?;
            println!("[svc] ipc socket activated by launchd (fd {fd})");
            return Ok(l);
        }
        let mut dump = String::from("launchd fd table at probe time:");
        dump.push('\n');
        if let Ok(entries) = std::fs::read_dir("/dev/fd") {
            for e in entries.flatten() {
                if let Some(n) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) {
                    dump.push_str(&format!(
                        "fd {n}: socket={} accept={} path={} match={}\n",
                        fd_is_socket(n),
                        fd_accepting(n),
                        fd_unix_path(n).unwrap_or_default(),
                        fd_is_launchd_ipc(n, &cfg.ipc_bind)
                    ));
                }
            }
        }
        let home = std::env::var("AZTNA_SVC_HOME").unwrap_or_default();
        if !home.is_empty() {
            let _ = std::fs::write(format!("{home}/fd-dump.txt"), &dump);
        }
        anyhow::bail!(
            "AZTNA_LAUNCHD_SOCKETS=1 but no listening AF_UNIX fd in 0..=64 bound to {} \
             (fd table dumped to <svc-home>/fd-dump.txt)",
            cfg.ipc_bind
        );
    }
    if std::env::var("LISTEN_FDS").as_deref() == Ok("1") {
        // fd 3 (SD_LISTEN_FDS_START): already bound by systemd with
        // SocketMode from the unit — take it verbatim, no chmod (the
        // unit file is the mode authority under systemd)
        let std_sock = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
        std_sock.set_nonblocking(true)?;
        let l = tokio::net::UnixListener::from_std(std_sock)?;
        println!("[svc] ipc socket activated by systemd (fd 3)");
        return Ok(l);
    }
    let path = std::path::Path::new(&cfg.ipc_bind);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        // root-owned 0755 dir: blocks socket replacement (§3.5)
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    }
    let _ = std::fs::remove_file(path); // stale socket from a crash
    let l = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("ipc bind {}", cfg.ipc_bind))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(l)
}

fn host_name() -> String {
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "svc-host".into())
    }
    #[cfg(not(windows))]
    {
        let from_env = std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty());
        let from_file = std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|h| !h.is_empty());
        // W30 step 2 (plan §3.3): macOS has neither HOSTNAME nor
        // /etc/hostname in practice — the machine IDENTIFIER
        // (IOPlatformUUID) is the stable fallback before "svc-host"
        #[cfg(target_os = "macos")]
        let from_hw = aztna_client::identity::platform_machine_id();
        #[cfg(not(target_os = "macos"))]
        let from_hw = None;
        from_env
            .or(from_file)
            .or(from_hw)
            .unwrap_or_else(|| "svc-host".into())
    }
}

#[cfg(windows)]
async fn ipc_session(
    sock: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    cfg: aztna_client::svc::SvcConfig,
    serve_task: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut r, mut w) = sock.into_split();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), r.read(&mut buf))
        .await
        .ok()
        .and_then(|v| v.ok())
        .unwrap_or(0);
    if n == 0 {
        return Ok(());
    }
    let req: Result<aztna_client::svc::IpcReq, _> = serde_json::from_slice(&buf[..n]);
    // W13 isolation on the CONTROL plane: attribute the caller (the
    // kernel owner table names the true owning process on Windows).
    let caller = aztna_client::peer::tcp_owner(peer).ok().map(|o| o.sid);
    let (ok, resp) = ipc_dispatch(req, caller, cfg, serve_task)
        .await
        .unwrap_or_else(|e| (false, err_resp(&format!("ipc internal: {e:#}"))));
    let _ = w
        .write_all(format!("{}\n", serde_json::to_string(&resp)?).as_bytes())
        .await;
    let _ = ok;
    Ok(())
}

/// W29 step 7: the unix twin — same JSON framing over the UDS; the
/// caller uid came from SO_PEERCRED (kernel-verified, race-free).
#[cfg(unix)]
async fn ipc_session_unix(
    sock: tokio::net::UnixStream,
    caller: Result<String, anyhow::Error>,
    cfg: aztna_client::svc::SvcConfig,
    serve_task: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut r, mut w) = sock.into_split();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), r.read(&mut buf))
        .await
        .ok()
        .and_then(|v| v.ok())
        .unwrap_or(0);
    if n == 0 {
        return Ok(());
    }
    let req: Result<aztna_client::svc::IpcReq, _> = serde_json::from_slice(&buf[..n]);
    let (ok, resp) = ipc_dispatch(req, caller.ok(), cfg, serve_task)
        .await
        .unwrap_or_else(|e| (false, err_resp(&format!("ipc internal: {e:#}"))));
    let _ = w
        .write_all(format!("{}\n", serde_json::to_string(&resp)?).as_bytes())
        .await;
    let _ = ok;
    Ok(())
}

/// The shared command surface: commands that act on the active context
/// require the OWNING user (pre-login, any local user may hand off
/// their token). `caller` = uid string on unix, SID on Windows — the
/// owning-user comparison is exact-string either way.
async fn ipc_dispatch(
    parsed: Result<aztna_client::svc::IpcReq, serde_json::Error>,
    caller: Option<String>,
    cfg: aztna_client::svc::SvcConfig,
    serve_task: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
) -> anyhow::Result<(bool, aztna_client::svc::IpcResp)> {
    use aztna_client::svc::{self, IpcResp};
    let req = match parsed {
        Ok(v) if v.v == 1 => v,
        _ => {
            svc::ipc_count("status", false);
            return Ok((
                false,
                IpcResp {
                    ok: false,
                    state: svc::state_name().into(),
                    error: Some("bad request".into()),
                    detail: None,
                },
            ));
        }
    };
    let owner = svc::owning_sid_get();
    let authorized = match (&owner, &caller) {
        (_, None) => false, // unattributable — fail closed
        (None, _) => true,  // pre-login handoff window
        (Some(o), Some(c)) => aztna_client::peer::peer_allowed(o, c),
    };
    let (ok, resp) = match (req.cmd.as_str(), authorized) {
        ("status", _) => {
            svc::ipc_count("status", true);
            (
                true,
                IpcResp {
                    ok: true,
                    state: svc::state_name().into(),
                    error: None,
                    detail: Some(serde_json::json!({
                        "dests": cfg.dests,
                        "last_event": aztna_client::svc_last_event(),
                    })),
                },
            )
        }
        ("login", true) => {
            svc::ipc_count("login", true);
            match req.token {
                Some(t) if !t.is_empty() => {
                    let mut st = aztna_client::load_state()?;
                    st.access_token = Some(t);
                    st.controller_url = cfg.controller_url.clone();
                    if let Some(e) = &cfg.controller_enroll_url {
                        st.controller_enroll_url = Some(e.clone());
                    }
                    aztna_client::save_state(&st)?; // machine-DPAPI wrapped at rest
                    if let Some(c) = &caller {
                        svc::set_owning_sid(c); // the handoff: caller becomes owner
                    }
                    svc::set_state(
                        svc::STATE_DISCONNECTED,
                        "token handed off; ready to connect",
                    );
                    (true, ok_resp())
                }
                _ => (false, err_resp("login requires a token")),
            }
        }
        ("connect", true) => {
            let st = aztna_client::load_state()?;
            if st.access_token.is_none() {
                svc::ipc_count("connect", false);
                (false, err_resp("no token - login first"))
            } else if cfg.dests.is_empty() && cfg.dns.is_none() {
                // W43 S2: a dns-only service config is a valid engine (the
                // zone manager owns the forwarder set); refuse only when
                // there is literally nothing to serve
                svc::ipc_count("connect", false);
                (
                    false,
                    err_resp("no dests configured and no dns responder - nothing to serve"),
                )
            } else {
                svc::ipc_count("connect", true);
                let cli = aztna_client::Cli {
                    controller: Some(cfg.controller_url.clone()),
                    cmd: aztna_client::Cmd::Access {
                        dest: cfg.dests.clone(),
                        local_port: cfg.local_port.unwrap_or(21600),
                        serve: true,
                        gateway_relay: None,
                        transport: None, // W40: follow the tenant transport mode
                        bind: "127.0.0.1".into(),
                        print_token: false,
                        dns: cfg.dns.clone(),
                        metrics: None,
                        proto: "tcp".into(),
                    },
                };
                aztna_client::svc::engine_cancel_arm_fresh(); // fresh generation
                let t = tokio::spawn(async move {
                    if let Err(e) = aztna_client::run_with(cli).await {
                        println!("[svc] engine exited: {e:#}");
                    }
                });
                *serve_task.lock().unwrap() = Some(t);
                svc::set_state(svc::STATE_CONNECTED, "engine serving configured dests");
                (true, ok_resp())
            }
        }
        ("disconnect", true) => {
            svc::ipc_count("disconnect", true);
            if let Some(t) = serve_task.lock().unwrap().take() {
                t.abort();
            }
            // run-1 lesson: aborting the engine task alone ORPHANS the
            // spawned forwarders (detached children) — cancel the
            // generation token so every accept loop exits, port closes
            svc::engine_cancel().cancel();
            svc::set_state(svc::STATE_DISCONNECTED, "engine stopped by request");
            (true, ok_resp())
        }
        ("diagnostics", true) => {
            svc::ipc_count("diagnostics", true);
            let st = aztna_client::load_state()?;
            match aztna_client::diag::build_bundle(std::path::Path::new(&svc::svc_home()), &st)
                .await
            {
                Ok(rep) => (
                    true,
                    aztna_client::svc::IpcResp {
                        ok: true,
                        state: svc::state_name().into(),
                        error: None,
                        detail: Some(serde_json::json!({
                            "bundle": rep.dir.display().to_string(),
                            "partial": rep.partial,
                        })),
                    },
                ),
                Err(e) => (false, err_resp(&format!("bundle failed: {e:#}"))),
            }
        }
        (cmd, _) => {
            svc::ipc_count(&req.cmd, false);
            (
                false,
                err_resp(&format!(
                    "unknown or unauthorized command {cmd} (owner set: {})",
                    owner.is_some()
                )),
            )
        }
    };
    Ok((ok, resp))
}

fn ok_resp() -> aztna_client::svc::IpcResp {
    aztna_client::svc::IpcResp {
        ok: true,
        state: aztna_client::svc::state_name().into(),
        error: None,
        detail: None,
    }
}

fn err_resp(e: &str) -> aztna_client::svc::IpcResp {
    aztna_client::svc::IpcResp {
        ok: false,
        state: aztna_client::svc::state_name().into(),
        error: Some(e.into()),
        detail: None,
    }
}
