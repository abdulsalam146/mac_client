//! aZTNA Windows Client ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÂ¢Ã¢â€šÂ¬Ã‚Â M1 CLI [p1-plan ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â§2 deviations documented].
//! Subcommands:
//!   status                          show config/state
//!   enroll --token <tok>            T-02: keygen + CSR + CP-101 poll loop
//!   login [--code X]                T-03: OIDC login (manual paste in M1)
//!   access <fqdn:port>              T-04/05: decision + tunnel forwarder

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use ed25519_dalek::Signer as _;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod posture_collector;

mod posture_probes;

mod dns;

pub mod identity;
pub mod metrics;
mod tpmtls;

pub mod peer;

pub mod tokenstore;

pub mod svc;

// W29: the Win32 tray shell is a Windows-only execution host; Linux runs
// CLI + glmsvc (plan §1, tray explicitly out of scope)
#[cfg(windows)]
pub mod tray;

// W29 step 2: AZDP2 at-rest wrap for the Linux client (W21 machinery).
// Public because glmsvc (a bin, not a crate module) uses the hygiene
// helper for its service home.
#[cfg(unix)]
pub mod atrest;

// W29 step 4: the Linux TPM tier (tss-esapi). W30 step 1: Linux-only
// gate — macOS has no TPM2 (software tier only; plan §3.3/D3).
#[cfg(target_os = "linux")]
mod tpm;

pub mod diag;

#[derive(Parser)]
#[command(name = "aztna-client", about = "aZTNA client (M1 CLI)")]
pub struct Cli {
    /// Controller base URL override (default from config)
    #[arg(long, global = true)]
    pub controller: Option<String>,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    Status,
    Enroll {
        #[arg(long)]
        token: String,
        #[arg(long, default_value = "this-laptop")]
        hostname: String,
    },
    Login {
        /// M1: paste the code shown after IdP sign-in; omit to be prompted
        #[arg(long)]
        code: Option<String>,
    },
    /// W6.2 [U-06/FR-SES-002]: end the session server-side (self-revoke +
    /// kill own tunnels) and clear the local token
    Logout,
    Access {
        /// destination(s) host:port — several allowed; each gets its own
        /// local listener and is served via ITS decision's gateways [P3-MG]
        dest: Vec<String>,
        #[arg(long, default_value_t = 21444)]
        local_port: u16,
        /// keep serving: fresh decision+token per incoming local connection
        #[arg(long, default_value_t = false)]
        serve: bool,
        /// gateway relay override (dev): pin ALL dests to this relay,
        /// ignoring controller-directed via_gateways [P2-8]
        #[arg(long)]
        gateway_relay: Option<String>,
        /// data transport to the gateway [P2-4 FR-NET-002]; auto = QUIC, TCP fallback
        #[arg(long, value_enum, default_value_t = TransportKind::Auto)]
        transport: TransportKind,
        /// forwarder listen address [P3-MG; default loopback]
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        /// single-shot: print the minted token for offline testing [X4]
        #[arg(long, default_value_t = false)]
        print_token: bool,
        /// W4.1 [ADR-0016]: private-DNS mode — answer A queries for
        /// policy-allowed fqdns with sticky loopback IPs and run zone-driven
        /// forwarders on those IPs. Value [host][:port], default port 53
        /// (needs elevation; dev/E2E uses a custom port, e.g. 127.0.0.1:1053)
        #[arg(long)]
        dns: Option<String>,
        /// OBS.4 [NFR §7.3]: expose client metrics on a LOOPBACK endpoint,
        /// e.g. 127.0.0.1:29100. Off by default — never network-bound.
        #[arg(long)]
        metrics: Option<String>,
        /// W8.1 [ADR-0003 udp]: app-protocol of the destination. "udp"
        /// serves a local UDP forwarder against the gateway's raw UDP
        /// relay (relay port + 2); orthogonal to --transport (the stream
        /// carrier for tcp apps).
        #[arg(long, default_value = "tcp")]
        proto: String,
    },
    /// X8 [NFR-OBS-003/PERF-004]: tunnel-establishment bench — per tunnel:
    /// decision → token → gateway dial + admission ack; prints p50/p95 and
    /// appends a JSON report (see docs; fallback-stall needs T2/T3 blackhole)
    Bench {
        dest: String,
        #[arg(long, default_value_t = 20)]
        tunnels: u32,
        #[arg(long, value_enum, default_value_t = TransportKind::Auto)]
        transport: TransportKind,
        /// write the JSON report beside the source tree (deploy/bench/)
        #[arg(long, default_value_t = false)]
        report: bool,
    },
    /// W4.1 [ADR-0016]: print this device's private-DNS zone map (dev/test aid)
    DnsZones,
    /// W13 step 5 [DR-CLT-022]: export a sanitized diagnostics bundle
    Diagnostics {
        /// output directory (bundle lands in aztna-diag-<ts>/ inside it)
        #[arg(long, default_value = ".")]
        out: String,
    },
    /// W13 step 4: system-tray shell (pure service client over IPC)
    Tray {
        /// service IPC bind override (default: svc.toml ipc_bind)
        #[arg(long)]
        ipc: Option<String>,
    },
    /// W13 step 3: IPC client commands against the service host (glmsvc)
    SvcStatus,
    SvcConnect,
    SvcDisconnect,
    /// W13 step 5: bundle built BY THE SERVICE (the tray's path)
    SvcDiagnostics,
    /// W13: token handoff — send THIS client's login token to the service
    /// (the sender becomes the owning user for the active context)
    SvcLogin {
        #[arg(long)]
        token: String,
    },
    /// W5.1 [ADR-0010]: re-issue the device cert from the SAME identity key —
    /// fresh CSR → POST /v1/renew over mTLS presenting the CURRENT cert.
    /// device_id is unchanged (SPKI hash); no access token needed.
    Renew {
        #[arg(long, default_value = "this-laptop")]
        hostname: String,
    },
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum TransportKind {
    Tcp,
    Quic,
    /// W14: TLS 1.3 mTLS carrier (relay port +3) — the encrypted TCP
    /// fallback; plain TCP is reachable only via the legacy `tcp` value
    TlsTcp,
    Auto,
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct ClientState {
    pub controller_url: String,
    /// bootstrap listener (enroll/status/CA) â€” server-TLS, token-auth [P2-5]
    pub controller_enroll_url: Option<String>,
    pub device_id: Option<String>,
    pub cert_pem: Option<String>,
    pub access_token: Option<String>,
    /// W13 step 3: the at-rest form is DPAPI-wrapped (tokenstore); the
    /// plaintext field is kept ONLY for tolerant migration reads (legacy
    /// pre-W13 states) and is always None in what save_state writes.
    #[serde(default)]
    pub access_token_wrapped: Option<String>,
    pub posture_pubkey: Option<String>,
    /// tenant CA fetched once (TOFU on first contact; production pins via
    /// installer [DR-CLT-001])
    pub ca_pem: Option<String>,
    /// assurance tier of the identity key at enroll [ADR-0010]
    pub key_origin: Option<String>,
    /// controller mgmt base URL (policy-version polling) [P3-MG M5]
    #[serde(default)]
    pub mgmt_url: Option<String>,
}

impl ClientState {
    fn identity_dir(&self) -> PathBuf {
        state_path().parent().unwrap().to_path_buf()
    }
}

fn state_path() -> PathBuf {
    // AZTNA_STATE_DIR lets E2E run multiple independent client identities
    // on one host (device #2, strict-tenant probes) [P2-7 U7]
    if let Ok(d) = std::env::var("AZTNA_STATE_DIR") {
        return PathBuf::from(d).join("state.json");
    }
    // W29: $HOME on unix, USERPROFILE on Windows (same ~/.aztna layout)
    #[cfg(windows)]
    let base = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
    #[cfg(not(windows))]
    let base = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(base).join(".aztna").join("state.json")
}

pub fn load_state() -> Result<ClientState> {
    let p = state_path();
    if p.exists() {
        let mut st: ClientState = serde_json::from_str(&std::fs::read_to_string(p)?)?;
        // W13 step 3: at-rest token is DPAPI-wrapped. Unwrap into memory;
        // an unwrappable blob (scope mismatch/corruption) means NO token
        // (fail closed — treated as logged out, re-login fixes it).
        // A legacy PLAINTEXT token still loads (tolerant one-time
        // migration: the next save_state writes only the wrapped form).
        if st.access_token.is_none() {
            if let Some(w) = st.access_token_wrapped.clone() {
                match tokenstore::unwrap_token(&w) {
                    Ok(t) => st.access_token = Some(t),
                    Err(e) => {
                        log_event(
                            "token_unwrap_failed",
                            &format!("at-rest token unwrappable - treating as logged out: {e}"),
                        );
                        st.access_token_wrapped = None;
                    }
                }
            }
        } else {
            log_event(
                "token_migrated",
                "legacy plaintext token loaded - next save wraps it",
            );
        }
        Ok(st)
    } else {
        Ok(ClientState::default())
    }
}

pub fn save_state(st: &ClientState) -> Result<()> {
    let p = state_path();
    if let Some(dir) = p.parent() {
        // W29: unix state dirs are created 0700 (atrest hygiene — key
        // material and the wrapped token live here); Windows keeps its
        // profile-ACL-protected create_dir_all
        #[cfg(unix)]
        {
            crate::atrest::ensure_dir_hygiene(dir)?;
        }
        #[cfg(windows)]
        {
            std::fs::create_dir_all(dir)?;
        }
    }
    // W13 step 3 [DR-CLT-027 closed]: persist a SANITIZED copy — the
    // token only ever hits disk as a DPAPI blob (tokenstore, host
    // profile); the plaintext field is always written as None.
    let mut on_disk = ClientState {
        access_token: None,
        access_token_wrapped: match &st.access_token {
            Some(t) => Some(tokenstore::wrap_token(t)?),
            None => None,
        },
        ..st.clone()
    };
    // drop the derived field from the in-memory copy semantics: serde
    // clones fine; ensure the sanitized copy never leaks the raw field
    on_disk.access_token = None;
    let serialized = serde_json::to_string_pretty(&on_disk)?;
    // W29: unix state.json is 0600 (atomic) — the wrapped token + CA
    // trust material are nobody-else's business; Windows write unchanged
    #[cfg(unix)]
    {
        crate::atrest::atomic_write_0600(&p, serialized.as_bytes())?;
    }
    #[cfg(windows)]
    {
        std::fs::write(p, serialized)?;
    }
    Ok(())
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().build().expect("reqwest")
}

// ---------- P2-5: TLS plumbing ----------

fn enroll_base(st: &ClientState) -> String {
    st.controller_enroll_url
        .clone()
        .unwrap_or_else(|| aztna_common::urls::CONTROLLER_ENROLL.into())
}

/// Fetch the tenant CA once (TOFU; stored in state.json afterwards).
/// X6: the payload is a BUNDLE (previous + current CA during rotation
/// overlap) — every block is trusted.
async fn ensure_ca(st: &mut ClientState) -> Result<()> {
    if st.ca_pem.is_some() {
        return Ok(());
    }
    let tofu = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // bootstrap channel only [P2-5 note]
        .build()?;
    let pem = tofu
        .get(format!("{}/v1/ca", enroll_base(st)))
        .send()
        .await?
        .text()
        .await?;
    anyhow::ensure!(pem.contains("BEGIN CERTIFICATE"), "bad CA payload");
    st.ca_pem = Some(pem);
    save_state(st)?;
    Ok(())
}

/// X6: split a (possibly multi-cert) PEM bundle into individual blocks.
fn pem_blocks(bundle: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in bundle.lines() {
        cur.push_str(line);
        cur.push('\n');
        if line.contains("END CERTIFICATE") {
            out.push(std::mem::take(&mut cur));
        }
    }
    out
}

/// Build a client builder with every CA block of the stored bundle trusted.
fn trust_bundle_certs(b: reqwest::ClientBuilder, ca_pem: &str) -> Result<reqwest::ClientBuilder> {
    let mut b = b;
    for block in pem_blocks(ca_pem) {
        let cert = reqwest::Certificate::from_pem(block.as_bytes())?;
        b = b.add_root_certificate(cert);
    }
    Ok(b)
}

/// CA-verified client for the bootstrap listener (no device cert yet).
fn ca_client(st: &ClientState) -> Result<reqwest::Client> {
    Ok(trust_bundle_certs(
        reqwest::Client::builder(),
        st.ca_pem.as_deref().unwrap_or_default(),
    )?
    .build()?)
}

/// mTLS client: tenant CA + device certificate identity [CP-102].
/// TPM-backed key -> custom rustls signer (key never leaves the chip);
/// software key -> reqwest Identity from the DPAPI-unwrapped pair.
/// X6: CA trust = full bundle (rotation overlap).
fn mtls_client(st: &ClientState) -> Result<reqwest::Client> {
    let cert_pem = st.cert_pem.as_deref().ok_or_else(|| {
        anyhow::anyhow!("device certificate missing - device approved? run login")
    })?;
    let device = identity::DeviceKey::open_or_create(&st.identity_dir())?;
    if let Some(pem) = device.tls_identity_pem(cert_pem) {
        let ident = reqwest::Identity::from_pem(pem.as_bytes())?;
        Ok(trust_bundle_certs(
            reqwest::Client::builder().identity(ident),
            st.ca_pem.as_deref().unwrap_or_default(),
        )?
        .build()?)
    } else {
        tpmtls::tpm_mtls_client(
            st.ca_pem.as_deref().unwrap_or_default(),
            cert_pem,
            Arc::new(device),
        )
    }
}

/// W25 S2 [FR-AUTH-001 / DR-CLT-006 / CP-103 proper]: the full OIDC
/// Authorization Code + PKCE (S256) browser flow. Asks the controller
/// where to send the browser (`/v1/authn/begin`), generates the PKCE
/// pair + nonce + state locally, binds a loopback redirect listener
/// (configured port preferred, RFC 8252 §7.3 OS-assigned fallback),
/// opens the system browser (URL always printed as the manual fallback),
/// checks `state`, and returns (code, verifier, nonce, redirect_uri) for
/// the login POST. Bounded wait: AZTNA_LOGIN_BROWSER_TIMEOUT_SECS
/// (default 180 s, floor 30).
async fn browser_login(
    st: &ClientState,
    device_id: &str,
) -> Result<(String, String, String, String)> {
    use base64::Engine;
    use sha2::Digest;

    let b64url = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);

    // 1. login initiation [CP-103]: controller supplies the authorize
    //    endpoint + client_id (it owns the IdP config)
    let begin_url = format!("{}/v1/authn/begin", st.controller_url.trim_end_matches('/'));
    let begin: serde_json::Value = mtls_client(st)?
        .post(&begin_url)
        .json(&serde_json::json!({ "device_id": device_id }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let authorize_endpoint = begin["authorize_endpoint"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("begin response missing authorize_endpoint"))?
        .to_string();
    let client_id = begin["client_id"]
        .as_str()
        .unwrap_or("aztna-controller")
        .to_string();

    // 2. PKCE pair (S256) + nonce + state — all local, all single-use
    let mut vb = [0u8; 48];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut vb);
    let verifier = b64url(&vb); // 64 chars, within RFC 7636's 43..=128
    let challenge = b64url(&sha2::Sha256::digest(verifier.as_bytes()));
    let mut sb = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut sb);
    let state = b64url(&sb);
    let mut nb = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nb);
    let nonce = b64url(&nb);

    // 3. loopback redirect listener: preferred port, ephemeral fallback
    //    (RFC 8252 §7.3 — loopback redirect URIs may vary port)
    let preferred: u16 = std::env::var("AZTNA_LOGIN_REDIRECT_PORT")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(27_555);
    let std_l = match std::net::TcpListener::bind(("127.0.0.1", preferred)) {
        Ok(l) => l,
        Err(_) => std::net::TcpListener::bind(("127.0.0.1", 0))?,
    };
    let port = std_l.local_addr()?.port();
    // non-blocking BEFORE from_std (async-skill rule: a blocking socket
    // registered with the reactor parks a worker inside recv)
    std_l.set_nonblocking(true)?;
    let listener = tokio::net::TcpListener::from_std(std_l)?;
    let redirect_uri = format!("http://127.0.0.1:{port}/");

    // 4. authorize URL — printed ALWAYS (manual fallback; headless/e2e
    //    drives it from here), browser launch best-effort
    let enc = |s: &str| s.replace(':', "%3A").replace('/', "%2F");
    let authorize_url = format!(
        "{authorize_endpoint}?response_type=code&client_id={client_id}\
         &redirect_uri={}&scope=openid&state={state}&nonce={nonce}\
         &code_challenge={challenge}&code_challenge_method=S256",
        enc(&redirect_uri)
    );
    println!("sign in via the browser (opening automatically; if nothing opens, use this URL):");
    println!("{authorize_url}");
    // AZTNA_LOGIN_NO_BROWSER=1: headless/e2e runs suppress the launch (the
    // printed URL is the manual + automated path either way)
    if std::env::var("AZTNA_LOGIN_NO_BROWSER").as_deref() != Ok("1") {
        // W29: best-effort launch via the platform opener; failures are
        // non-fatal (the printed URL above is always the manual path)
        #[cfg(windows)]
        let spawned = std::process::Command::new("cmd")
            .args(["/c", "start", "", &authorize_url])
            .spawn();
        #[cfg(target_os = "linux")]
        let spawned = std::process::Command::new("xdg-open")
            .arg(&authorize_url)
            .spawn();
        // W30: macOS `open` — same best-effort contract, printed URL is
        // always the manual path
        #[cfg(target_os = "macos")]
        let spawned = std::process::Command::new("open")
            .arg(&authorize_url)
            .spawn();
        let _ = spawned;
    }
    log_event("login_browser", "authorize_started");

    // 5. bounded wait for the redirect GET, then state check
    let timeout_secs: u64 = std::env::var("AZTNA_LOGIN_BROWSER_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(180)
        .max(30);
    let (mut sock, _) = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        listener.accept(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("no browser redirect within {timeout_secs}s - re-run login"))??;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 8192];
    let n = sock.read(&mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let first_line = req.lines().next().unwrap_or_default().to_string();
    let _ = sock
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n\
              aZTNA sign-in complete - you can close this tab and return to the terminal.",
        )
        .await;
    let _ = sock.shutdown().await;
    // GET /?code=...&state=... HTTP/1.1
    let path = first_line.split_whitespace().nth(1).unwrap_or_default();
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or_default();
    let mut got_code = String::new();
    let mut got_state = String::new();
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            match k {
                "code" => got_code = v.to_string(),
                "state" => got_state = v.to_string(),
                _ => {}
            }
        }
    }
    anyhow::ensure!(
        !got_code.is_empty(),
        "redirect carried no code (request line: {first_line:?})"
    );
    anyhow::ensure!(
        got_state == state,
        "redirect state mismatch - refusing (possible CSRF/redirect injection)"
    );
    log_event("login_browser", "redirect_captured");
    Ok((got_code, verifier, nonce, redirect_uri))
}

/// W8.2: the client's QUIC mTLS identity (device key + issued cert),
/// assembled once at startup and cloned into every dial site (bench,
/// serve_dest, zone_manager). Missing material is a hard, metered error —
/// QUIC to a W8.2 gateway cannot work without it.
#[derive(Clone)]
struct QuicIdent {
    device: Arc<identity::DeviceKey>,
    cert_pem: String,
}

impl std::fmt::Debug for QuicIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("QuicIdent")
    }
}

impl QuicIdent {
    fn open(st: &ClientState) -> Result<Self> {
        let cert_pem = st.cert_pem.as_deref().ok_or_else(|| {
            metrics::mtls_identity_failures_total().inc();
            anyhow::anyhow!("device certificate missing - device approved? run login")
        })?;
        Ok(Self {
            device: Arc::new(identity::DeviceKey::open_or_create(&st.identity_dir())?),
            cert_pem: cert_pem.to_string(),
        })
    }
}

/// Fetch the issued certificate after admin approval (enroll_status).
/// Always refreshes: a re-enroll overwrites device-key.pem, so any cached
/// cert from a previous device must not survive [F-06 multi-device runs].
async fn ensure_cert(st: &mut ClientState) -> Result<()> {
    let Some(device_id) = st.device_id.clone() else {
        bail!("not enrolled - run `enroll` first");
    };
    ensure_ca(st).await?;
    let v: serde_json::Value = ca_client(st)?
        .get(format!("{}/v1/enroll/status/{device_id}", enroll_base(st)))
        .send()
        .await?
        .json()
        .await?;
    if let Some(pem) = v["cert_pem"].as_str() {
        st.cert_pem = Some(pem.to_string());
        save_state(st)?;
    }
    Ok(())
}

// ---------- W5.1: device cert expiry + renewal ----------

/// Parse a PEM certificate's not_after as unix seconds (local parse, no
/// network — no timeout applies by design).
fn cert_expiry_unix(cert_pem: &str) -> Result<i64> {
    use asn1_rs::FromDer;
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).context("cert pem parse")?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&pem.contents)
        .context("cert der parse")?;
    Ok(cert.tbs_certificate.validity.not_after.timestamp())
}

/// Whole days from `now_unix` until `expiry_unix`, floored: any past
/// expiry is ≤ −1 ("EXPIRED"), even by minutes (truncating division
/// would render that as a misleading "0 days").
fn cert_days_remaining(now_unix: i64, expiry_unix: i64) -> i64 {
    (expiry_unix - now_unix).div_euclid(86_400)
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Human expiry line for `status` (RFC 3339 + days remaining). Pre-W5.1
/// certs print their real (year-4096) not_after — truthful, not faked.
fn cert_expiry_line(cert_pem: &str) -> String {
    let exp = match cert_expiry_unix(cert_pem) {
        Ok(t) => t,
        Err(e) => return format!("? (parse failed: {e:#})"),
    };
    let days = cert_days_remaining(unix_now(), exp);
    let iso = time::OffsetDateTime::from_unix_timestamp(exp)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| exp.to_string());
    if days < 0 {
        format!("{iso} (EXPIRED {} days ago)", -days)
    } else {
        format!("{iso} ({days} days)")
    }
}

/// Decode a 64-char lowercase/uppercase hex string into a 32-byte seed.
/// Single source of truth for hex decoding â€” see unit test at bottom of file.
fn seed_from_hex(hexs: &str) -> Result<[u8; 32]> {
    let hexs = hexs.trim();
    if hexs.len() != 64 {
        bail!(
            "posture key hex has unexpected length {} (expected 64)",
            hexs.len()
        );
    }
    let mut seed = [0u8; 32];
    for b in 0..32 {
        seed[b] = u8::from_str_radix(&hexs[b * 2..b * 2 + 2], 16)
            .with_context(|| format!("invalid hex at char {}", b * 2))?;
    }
    Ok(seed)
}

/// Load the device's Ed25519 posture-signing key if present [ADR-0008].
/// W14S2 fix step 2 (plan §4.1 "Key-cache safety", review-verified): the
/// posture signing key, cached per device_id — it was re-read and re-parsed
/// from disk on EVERY report, and an AV first-scan stall on that read was
/// the only legitimate multi-second slow path left in the per-decision
/// sign. Key lifetime: the ONLY writer of posture-keys/<device_id>.hex is
/// `enroll` (writes once, keyed by the device_id it issues); a running
/// serve's device_id cannot change; a re-enroll lands at a different path.
/// The cache re-reads on any device_id mismatch — belt-and-braces; a
/// hypothetically stale key would fail LOUD at the controller
/// (posture_rejections_total{invalid_sig}), not silently. Operational
/// caveat (gap-register 2026-09-07): enroll re-run against a live
/// device_id would overwrite the file under a running process — restart
/// required to pick it up; no current code path does this.
static POSTURE_KEY: std::sync::Mutex<Option<(String, ed25519_dalek::SigningKey)>> =
    std::sync::Mutex::new(None);

fn load_posture_key(device_id: &str) -> Result<Option<ed25519_dalek::SigningKey>> {
    {
        let g = POSTURE_KEY.lock().unwrap();
        if let Some((id, sk)) = g.as_ref() {
            if id == device_id {
                return Ok(Some(sk.clone()));
            }
        }
    }
    let p = state_path()
        .parent()
        .unwrap()
        .join("posture-keys")
        .join(format!("{device_id}.hex"));
    if !p.exists() {
        return Ok(None);
    }
    let hexs = std::fs::read_to_string(p)?.trim().to_string();
    let seed = seed_from_hex(&hexs)?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    *POSTURE_KEY.lock().unwrap() = Some((device_id.to_string(), sk.clone()));
    Ok(Some(sk))
}

/// Build a signed posture report value [FR-DEV-001/002, P2-1].
/// W3.1: REAL collectors via WMI (unknown → fail-open true; only an
/// explicit false denies). `AZTNA_SIMULATE` is the documented test hook:
///   healthy        → force all booleans true (dev boxes without
///                    BitLocker/Defender; used by E2E default)
///   defender_off | bitlocker_off | firewall_off
///                  → named signal false, rest forced true (I5 deny path)
/// os/days/client_version stay REAL in every mode.
fn signed_posture(device_id: &str) -> Result<serde_json::Value> {
    signed_posture_from(crate::posture_collector::collect_cached(), device_id)
}

/// One-shot access path [W3.1]: bounded wait for REAL collected values. A
/// one-shot is not the forwarder hot path, so a bounded (20s, no join) wait
/// is safe here; the serve loop and reporter must stay on the non-blocking
/// `signed_posture` [W4.4].
fn signed_posture_fresh(device_id: &str) -> Result<serde_json::Value> {
    signed_posture_from(
        crate::posture_collector::collect_fresh_bounded(std::time::Duration::from_secs(20)),
        device_id,
    )
}

fn signed_posture_from(
    snap: crate::posture_collector::Snapshot,
    device_id: &str,
) -> Result<serde_json::Value> {
    // W14S2 fix step 1 (plan §4.2): every signed report classified by the
    // snapshot it was built from, at the single choke point all report
    // paths flow through (TCP serve, UDP establishment, one-shots, the
    // periodic reporter). "stale" serving was previously invisible —
    // last-good values go out silently once the slot passes the TTL.
    crate::metrics::posture_reports_total()
        .with_label_values(&[snap.slot_class()])
        .inc();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let sim = std::env::var("AZTNA_SIMULATE").unwrap_or_default();
    let mut bitlocker_on = snap.bitlocker_on.unwrap_or(true);
    let mut defender_healthy = snap.defender_healthy.unwrap_or(true);
    let mut firewall_enabled = snap.firewall_enabled.unwrap_or(true);
    match sim.as_str() {
        "healthy" => {
            bitlocker_on = true;
            defender_healthy = true;
            firewall_enabled = true;
        }
        "defender_off" => {
            defender_healthy = false;
            bitlocker_on = true;
            firewall_enabled = true;
        }
        "bitlocker_off" => {
            bitlocker_on = false;
            defender_healthy = true;
            firewall_enabled = true;
        }
        "firewall_off" => {
            firewall_enabled = false;
            bitlocker_on = true;
            defender_healthy = true;
        }
        _ => {}
    }
    // W29: entra_joined is Linux-collected (domain integration via
    // realm/sssd); Windows collects None and keeps its historical `true`
    // — byte-identical Windows reports before/after this field.
    let (entra_joined, os_version, days_since_patch) = (
        snap.domain_joined.unwrap_or(true),
        snap.os_version.unwrap_or_else(|| "unknown".into()),
        snap.days_since_patch.unwrap_or(-1),
    );
    let client_version = crate::posture_collector::CLIENT_VERSION.to_string();
    let Some(sk) = load_posture_key(device_id)? else {
        return Ok(serde_json::Value::Null);
    };
    // W3.5: requirement-spec extensions (canonical v2) — probe results from
    // the cache (serve mode warms it; one-shot blocks via run_probes_now).
    let (spec_version, extensions) = match crate::posture_probes::snapshot_results() {
        Some((v, ext)) => (Some(v), Some(ext)),
        None => (None, None),
    };
    let canonical = {
        let core = format!(
            "{ts}|{bitlocker_on}|{defender_healthy}|{firewall_enabled}|{entra_joined}|{os_version}|{days_since_patch}|{client_version}"
        );
        match spec_version {
            None => core,
            Some(v) => {
                let mut e = extensions.clone().unwrap_or_default();
                e.sort_by(|a, b| a.0.cmp(&b.0));
                let ext_s = e
                    .iter()
                    .map(|(i, val)| format!("{i}={val}"))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("v2|{core}|{v}|{ext_s}")
            }
        }
    };
    let sig = sk.sign(canonical.as_bytes());
    use base64::Engine as _;
    let mut report = serde_json::json!({
        "collected_at": ts,
        "bitlocker_on": bitlocker_on,
        "defender_healthy": defender_healthy,
        "firewall_enabled": firewall_enabled,
        "entra_joined": entra_joined,
        "os_version": os_version,
        "days_since_patch": days_since_patch,
        "client_version": client_version,
        "sig_b64": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
    });
    if let (Some(v), Some(ext)) = (spec_version, extensions) {
        report["spec_version"] = serde_json::json!(v);
        report["extensions"] = serde_json::json!(ext
            .into_iter()
            .map(|(id, value)| serde_json::json!({"id": id, "value": value}))
            .collect::<Vec<_>>());
    }
    Ok(report)
}

/// W3.5: fetch the posture requirement spec (client plane, mTLS + bearer).
/// Installs it into the probe module + updates the spec-version metric.
async fn fetch_posture_spec(
    mclient: &reqwest::Client,
    controller_url: &str,
    token: &str,
) -> Result<bool> {
    let url = format!("{}/v1/posture/spec", controller_url.trim_end_matches('/'));
    let resp = mclient.get(&url).bearer_auth(token).send().await?;
    let sc = resp.status();
    anyhow::ensure!(sc.is_success(), "posture spec fetch failed: {sc}");
    let v: serde_json::Value = resp.json().await?;
    let spec: crate::posture_probes::PostureSpec = serde_json::from_value(v)?;
    let version = spec.spec_version;
    let changed = crate::posture_probes::current_spec_version() != Some(version).filter(|v| *v > 0);
    if let Some(applied) = crate::posture_probes::set_spec(spec) {
        metrics::posture_spec_version().set(applied);
        if changed {
            println!("[posture] requirement spec v{applied} applied");
        }
    } else {
        metrics::posture_spec_version().set(0);
    }
    Ok(changed)
}

/// W3.4: values-only hash of a signed posture report (CHANGE detection) —
/// `collected_at` is deliberately EXCLUDED so an unchanged fleet produces a
/// stable hash; any value flip (incl. degradation like defender_off) changes it.
fn posture_values_hash(
    bitlocker_on: bool,
    defender_healthy: bool,
    firewall_enabled: bool,
    entra_joined: bool,
    os_version: &str,
    days_since_patch: i32,
    client_version: &str,
) -> String {
    use sha2::Digest;
    let canonical = format!(
        "{bitlocker_on}|{defender_healthy}|{firewall_enabled}|{entra_joined}|{os_version}|{days_since_patch}|{client_version}"
    );
    let d = sha2::Sha256::digest(canonical.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Extract the values-hash from a built report Value (fields as signed).
fn hash_of_report(r: &serde_json::Value) -> Option<String> {
    Some(posture_values_hash(
        r["bitlocker_on"].as_bool()?,
        r["defender_healthy"].as_bool()?,
        r["firewall_enabled"].as_bool()?,
        r["entra_joined"].as_bool()?,
        r["os_version"].as_str()?,
        r["days_since_patch"].as_i64()? as i32,
        r["client_version"].as_str().unwrap_or(""),
    ))
}

/// X1 [I5, DR-CLT-014/015]: periodic signed-posture push while serving.
/// W3.4: CHANGE-ONLY — full report when the values-hash changes (incl.
/// degradation, which is the whole point of the I5 channel) or on the
/// bounded full-refresh tick; otherwise a tiny unchanged MARKER that the
/// server credits as freshness liveness. Old-server fallback: any marker
/// rejection triggers an immediate full push.
/// Interval via AZTNA_POSTURE_SECS (default 30).
async fn posture_reporter(mclient: reqwest::Client, controller_url: String, device_id: String) {
    let interval = std::env::var("AZTNA_POSTURE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v >= 2)
        .unwrap_or(30);
    let url = format!("{}/v1/posture", controller_url.trim_end_matches('/'));
    let mut last_hash: Option<String> = None;
    let mut tick: u64 = 0;
    const FULL_REFRESH_TICKS: u64 = 10; // bound divergence: full push ≤ every 10th tick
    loop {
        let report = signed_posture(&device_id);
        match report {
            Ok(r) if !r.is_null() => {
                let hash = hash_of_report(&r);
                let changed = hash
                    .as_deref()
                    .map(|h| Some(h) != last_hash.as_deref())
                    .unwrap_or(true);
                let force_full = tick % FULL_REFRESH_TICKS == 0;
                let send_full = || {
                    let mut mclient = mclient.clone();
                    let url = url.clone();
                    let r = r.clone();
                    async move { mclient.post(&url).json(&r).send().await }
                };
                if changed || force_full || hash.is_none() {
                    match send_full().await {
                        Ok(resp) if resp.status().is_success() => {
                            let v: serde_json::Value = resp.json().await.unwrap_or_default();
                            if v["healthy"].as_bool() == Some(false) {
                                println!("[posture] controller marked this device UNHEALTHY");
                                metrics::posture_reports_sent()
                                    .with_label_values(&["unhealthy"])
                                    .inc();
                            } else {
                                metrics::posture_reports_sent()
                                    .with_label_values(&["healthy"])
                                    .inc();
                            }
                            metrics::posture_push_mode()
                                .with_label_values(&["full"])
                                .inc();
                            last_hash = hash.clone();
                        }
                        Ok(resp) => {
                            println!(
                                "[posture] rejected: {} {}",
                                resp.status(),
                                resp.text().await.unwrap_or_default()
                            );
                            metrics::posture_reports_sent()
                                .with_label_values(&["error"])
                                .inc();
                        }
                        Err(e) => {
                            println!("[posture] controller unreachable: {e}");
                            metrics::posture_reports_sent()
                                .with_label_values(&["error"])
                                .inc();
                        }
                    }
                } else {
                    // W3.4: unchanged → marker (hash only); server credits liveness
                    let marker = serde_json::json!({ "values_hash": hash });
                    let marker_ok = match mclient.post(&url).json(&marker).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            let v: serde_json::Value = resp.json().await.unwrap_or_default();
                            v["unchanged"].as_bool() == Some(true)
                        }
                        _ => false,
                    };
                    if marker_ok {
                        metrics::posture_push_mode()
                            .with_label_values(&["marker"])
                            .inc();
                    } else {
                        // stale-hash hint or old server → full push now
                        match send_full().await {
                            Ok(resp) if resp.status().is_success() => {
                                let v: serde_json::Value = resp.json().await.unwrap_or_default();
                                if v["healthy"].as_bool() == Some(false) {
                                    println!("[posture] controller marked this device UNHEALTHY");
                                    metrics::posture_reports_sent()
                                        .with_label_values(&["unhealthy"])
                                        .inc();
                                } else {
                                    metrics::posture_reports_sent()
                                        .with_label_values(&["healthy"])
                                        .inc();
                                }
                                metrics::posture_push_mode()
                                    .with_label_values(&["full"])
                                    .inc();
                                last_hash = hash.clone();
                            }
                            _ => metrics::posture_reports_sent()
                                .with_label_values(&["error"])
                                .inc(),
                        }
                    }
                }
            }
            Ok(_) => {
                println!("[posture] no posture key - reporting skipped");
                metrics::posture_reports_sent()
                    .with_label_values(&["skipped"])
                    .inc();
            }
            Err(e) => {
                println!("[posture] report build failed: {e}");
                metrics::posture_reports_sent()
                    .with_label_values(&["error"])
                    .inc();
            }
        }
        tick += 1;
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }
}

// ---------- T-07: rotating JSONL telemetry [FR-LOG-001 client slice] ----------

pub fn log_event(kind: &str, detail: &str) {
    use std::io::Write;
    let dir = state_path().parent().unwrap().to_path_buf();
    let log = dir.join("client.log");
    if let Ok(meta) = std::fs::metadata(&log) {
        if meta.len() > 1_000_000 {
            let _ = std::fs::rename(&log, dir.join("client.log.1"));
        }
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
    {
        let _ = writeln!(
            f,
            "{{\"ts\":{},\"kind\":\"{}\",\"detail\":\"{}\"}}",
            ts,
            kind,
            detail.replace('"', "'")
        );
    }
}

/// W13 step 2 [one shared engine]: the full client engine + CLI entry.
/// Execution hosts own the runtime and call in — the CLI bin
/// (src/bin/glmcli.rs) today; the service host (glmsvc) in step 3.
pub async fn run() -> Result<()> {
    run_with(Cli::parse()).await
}

/// W13 step 3: hosts call in with a constructed CLI (glmsvc drives the
/// same engine as the terminal user, one shared engine by contract).
pub async fn run_with(cli: Cli) -> Result<()> {
    let mut st = load_state()?;
    if let Some(url) = &cli.controller {
        st.controller_url = url.clone();
    }
    if st.controller_url.is_empty() {
        st.controller_url = aztna_common::urls::CONTROLLER_CLIENT.into();
    }
    ensure_ca(&mut st).await?;

    match cli.cmd {
        Cmd::Status => {
            println!("aZTNA client");
            println!("  controller : {}", st.controller_url);
            println!("  device_id  : {}", st.device_id.as_deref().unwrap_or("-"));
            println!("  enrolled   : {}", st.cert_pem.is_some());
            println!("  logged-in  : {}", st.access_token.is_some());
            if let Some(pem) = st.cert_pem.as_deref() {
                println!("  cert expires: {}", cert_expiry_line(pem));
            }
        }
        Cmd::Enroll { token, hostname } => {
            // ensure state directory exists before any writes [fresh-machine fix]
            // W29: unix creates it 0700 via atrest hygiene
            let state_dir = state_path().parent().unwrap().to_path_buf();
            #[cfg(unix)]
            {
                crate::atrest::ensure_dir_hygiene(&state_dir)?;
            }
            #[cfg(windows)]
            {
                std::fs::create_dir_all(&state_dir)?;
            }
            let url = format!("{}/v1/enroll", enroll_base(&st));
            let pkey = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let posture_pubkey_b64 =
                base64::engine::general_purpose::STANDARD.encode(pkey.verifying_key().to_bytes());

            let key = identity::DeviceKey::open_or_create(&st.identity_dir())?;
            let csr_pem = key.build_csr_pem(&hostname)?;
            let body = serde_json::json!({
                "token": token,
                "csr_pem": csr_pem,
                "posture_pubkey_b64": posture_pubkey_b64,
                "hostname": hostname,
                // assurance tier from actual key backing [ADR-0010 Stage B]
                "key_origin": key.origin,
            });
            let resp = ca_client(&st)?.post(&url).json(&body).send().await?;
            if !resp.status().is_success() {
                bail!("enroll failed {}: {}", resp.status(), resp.text().await?);
            }
            let v: serde_json::Value = resp.json().await?;
            st.device_id = Some(v["device_id"].as_str().unwrap_or("").to_string());
            st.key_origin = Some(key.origin.clone());
            let device_id = st.device_id.clone().unwrap_or_default();
            let pk_dir = state_path().parent().unwrap().join("posture-keys");
            #[cfg(unix)]
            {
                // W29: the posture signing seed is key material — 0700 dir,
                // 0600 atomic write on unix
                crate::atrest::ensure_dir_hygiene(&pk_dir)?;
                let hexs: String = pkey.to_bytes().iter().map(|x| format!("{x:02x}")).collect();
                crate::atrest::atomic_write_0600(
                    &pk_dir.join(format!("{device_id}.hex")),
                    hexs.as_bytes(),
                )?;
            }
            #[cfg(windows)]
            {
                std::fs::create_dir_all(&pk_dir)?;
                std::fs::write(
                    pk_dir.join(format!("{device_id}.hex")),
                    pkey.to_bytes()
                        .iter()
                        .map(|x| format!("{x:02x}"))
                        .collect::<String>(),
                )?;
            }
            save_state(&st)?;
            println!("state={}  device_id={}", v["state"], v["device_id"]);
            println!(
                "key_origin={} (identity key {} exfiltratable as a file)",
                key.origin,
                if key.origin == "tpm" { "NOT" } else { "is" }
            );
            println!("waiting for admin approval... re-run after approval to fetch certificate:");
            #[cfg(windows)]
            println!("  glmcli.exe login --code <code>");
            #[cfg(not(windows))]
            println!("  glmcli login --code <code>");
        }
        Cmd::Login { code } => {
            let Some(device_id) = st.device_id.clone() else {
                bail!("not enrolled - run `enroll` first");
            };
            let url = format!(
                "{}/v1/login/device",
                st.controller_url.trim_end_matches('/')
            );
            ensure_cert(&mut st).await?;
            if st.cert_pem.is_none() {
                bail!("device not APPROVED yet - ask an admin, then re-run login");
            }
            // W25 S2 [FR-AUTH-001/DR-CLT-006]: `--code` keeps the dev
            // paste path; bare `login` runs the full browser flow — PKCE
            // S256 pair + nonce + state generated here, loopback redirect
            // captured, verifier+nonce+redirect_uri ride the login POST.
            let (code, verifier, nonce, redirect_uri): (
                String,
                Option<String>,
                Option<String>,
                Option<String>,
            ) = match code {
                Some(c) => (c, None, None, None),
                None => match browser_login(&st, &device_id).await {
                    Ok((c, v, n, r)) => (c, Some(v), Some(n), Some(r)),
                    Err(e) => {
                        log_event("login_browser", &format!("failed: {e}"));
                        bail!("browser login failed: {e}");
                    }
                },
            };
            let resp = mtls_client(&st)?
                .post(&url)
                .json(&serde_json::json!({
                    "device_id": device_id,
                    "authorization_code": code,
                    "code_verifier": verifier,
                    "nonce": nonce,
                    "redirect_uri": redirect_uri,
                }))
                .send()
                .await?;
            if !resp.status().is_success() {
                let sc = resp.status();
                bail!("login denied: {} - {}", sc, resp.text().await?);
            }
            let v: serde_json::Value = resp.json().await?;
            st.access_token = Some(v["access_token"].as_str().unwrap_or("").to_string());
            save_state(&st)?;
            println!("login OK - session {}", v["session_id"]);
            log_event("login", &format!("session={}", v["session_id"]));
            // W4.4: kick the posture snapshot collect NOW (non-blocking) so
            // it lands during approve/assign/serve-setup instead of under
            // the first connection
            crate::posture_collector::kick_refresh();
            // W3.5: pick up the posture requirement spec at login time and
            // warm the probe cache so the next decision carries extensions
            if let Ok(mc) = mtls_client(&st) {
                let cu = st.controller_url.clone();
                let tk = st.access_token.clone().unwrap_or_default();
                tokio::spawn(async move {
                    if let Err(e) = fetch_posture_spec(&mc, &cu, &tk).await {
                        println!("[posture] spec fetch after login failed: {e}");
                    }
                    let _ =
                        tokio::task::spawn_blocking(crate::posture_probes::run_probes_now).await;
                });
            }
        }
        Cmd::Logout => {
            // W6.2 [U-06/FR-SES-002]: end the session server-side (self
            // revoke + kill own tunnels via the session_logout kill order)
            // and clear local state. Bounded (AZTNA_LOGOUT_TIMEOUT_SECS); on
            // ANY outcome the local token is cleared — logout must never
            // wedge, and the server row dies by idle/absolute regardless.
            let Some(token) = st.access_token.clone() else {
                bail!("not logged in");
            };
            let logout_to = aztna_common::env_secs("AZTNA_LOGOUT_TIMEOUT_SECS", 10, 1);
            let url = format!("{}/v1/logout", st.controller_url.trim_end_matches('/'));
            // bounded: a hung controller must not hang the CLI (single
            // attempt, no auto-retry — same discipline as renew)
            let sent = tokio::time::timeout(
                logout_to,
                mtls_client(&st)?.post(&url).bearer_auth(&token).send(),
            )
            .await;
            let note = match sent {
                Ok(Ok(r)) if r.status().is_success() => {
                    "session ended on controller (tunnels cut)".to_string()
                }
                Ok(Ok(r)) => {
                    format!(
                        "controller said {} - session ends server-side at idle/expiry",
                        r.status()
                    )
                }
                Ok(Err(e)) => {
                    format!(
                        "controller unreachable ({e:#}) - session ends server-side at idle/expiry"
                    )
                }
                Err(_) => {
                    format!(
                        "timed out after {logout_to:?} - session ends server-side at idle/expiry"
                    )
                }
            };
            st.access_token = None;
            save_state(&st)?;
            println!("logout OK - {note}");
        }
        Cmd::Diagnostics { out } => {
            let rep = diag::build_bundle(std::path::Path::new(&out), &st).await?;
            println!(
                "diagnostics bundle: {} ({})",
                rep.dir.display(),
                if rep.partial { "partial" } else { "ok" }
            );
        }
        Cmd::Tray { ipc } => {
            #[cfg(windows)]
            {
                tray::run_tray(ipc)?;
            }
            #[cfg(not(windows))]
            {
                let _ = ipc;
                bail!("tray UI is a Windows-only shell (W29: Linux runs CLI + glmsvc)");
            }
        }
        Cmd::SvcStatus => {
            let cfg = svc::load_config().ok();
            let bind = cfg
                .map(|c| c.ipc_bind)
                .unwrap_or_else(|| "127.0.0.1:29171".into());
            match svc::ipc_call(
                &bind,
                &svc::IpcReq {
                    v: 1,
                    cmd: "status".into(),
                    token: None,
                },
            )
            .await
            {
                Ok(r) => {
                    println!("service: {} (ok={})", r.state, r.ok);
                    if let Some(d) = &r.detail {
                        println!("detail  : {d}");
                    }
                }
                Err(e) => println!("service unreachable: {e:#}"),
            }
        }
        Cmd::SvcConnect => {
            ipc_simple("connect").await?;
        }
        Cmd::SvcDiagnostics => {
            ipc_simple("diagnostics").await?;
        }
        Cmd::SvcDisconnect => {
            ipc_simple("disconnect").await?;
        }
        Cmd::SvcLogin { token } => {
            let cfg = svc::load_config().ok();
            let bind = cfg
                .map(|c| c.ipc_bind)
                .unwrap_or_else(|| "127.0.0.1:29171".into());
            match svc::ipc_call(
                &bind,
                &svc::IpcReq {
                    v: 1,
                    cmd: "login".into(),
                    token: Some(token),
                },
            )
            .await
            {
                Ok(r) if r.ok => println!("token handed off; service ready to connect"),
                Ok(r) => bail!("login rejected: {}", r.error.unwrap_or_default()),
                Err(e) => bail!("service unreachable: {e:#}"),
            }
        }
        Cmd::Renew { hostname } => {
            let Some(device_id) = st.device_id.clone() else {
                bail!("not enrolled - run `enroll` first");
            };
            anyhow::ensure!(
                st.cert_pem.is_some(),
                "device certificate missing - run `login` first (renewal presents the CURRENT cert)"
            );
            let old_line = st.cert_pem.as_deref().map(cert_expiry_line);
            // same persisted identity key as enroll → SPKI hash (device_id)
            // is unchanged [ADR-0010]; the CSR CN is informational only
            let key = identity::DeviceKey::open_or_create(&st.identity_dir())?;
            let csr_pem = key.build_csr_pem(&hostname)?;
            let renew_to = aztna_common::env_secs("AZTNA_RENEW_TIMEOUT_SECS", 10, 1);
            let url = format!("{}/v1/renew", st.controller_url.trim_end_matches('/'));
            // bounded: a hung controller must not hang the CLI (single
            // attempt, no auto-retry — the user re-runs the command)
            let sent = tokio::time::timeout(
                renew_to,
                mtls_client(&st)?
                    .post(&url)
                    .json(&serde_json::json!({ "csr_pem": csr_pem }))
                    .send(),
            )
            .await;
            let resp = match sent {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => bail!("renew request failed: {e:#}"),
                Err(_) => bail!(
                    "renew timed out after {renew_to:?} - controller unreachable; re-run `glmcli renew`"
                ),
            };
            if !resp.status().is_success() {
                let sc = resp.status();
                bail!("renew denied: {} - {}", sc, resp.text().await?);
            }
            let v: serde_json::Value = resp.json().await?;
            let new_pem = v["cert_pem"].as_str().unwrap_or_default().to_string();
            anyhow::ensure!(
                new_pem.contains("BEGIN CERTIFICATE"),
                "renew response missing cert_pem"
            );
            let returned_id = v["device_id"].as_str().unwrap_or("").to_string();
            anyhow::ensure!(
                returned_id == device_id,
                "renew returned a different device_id ({returned_id}) - refusing to save"
            );
            st.cert_pem = Some(new_pem);
            save_state(&st)?;
            let na = v["not_after_unix"].as_i64().unwrap_or_default();
            log_event(
                "cert_renewed",
                &format!("device={device_id} not_after={na}"),
            );
            println!("renew OK - device_id unchanged: {device_id}");
            if let Some(old) = &old_line {
                println!("  old expiry: {old}");
            }
            println!(
                "  new expiry: {}",
                cert_expiry_line(st.cert_pem.as_deref().unwrap_or_default())
            );
            if let Ok(na) = cert_expiry_unix(st.cert_pem.as_deref().unwrap_or_default()) {
                metrics::device_cert_days_remaining().set(cert_days_remaining(unix_now(), na));
            }
        }
        Cmd::Bench {
            dest,
            tunnels,
            transport,
            report,
        } => {
            let Some(token) = st.access_token.clone() else {
                bail!("not logged in - run `login` first");
            };
            let Some((host, port_s)) = dest.split_once(':') else {
                bail!("dest must be fqdn-or-ip:port");
            };
            let is_ip = host.parse::<std::net::IpAddr>().is_ok();
            let port: i64 = port_s.parse()?;
            let url = format!("{}/v1/access", st.controller_url.trim_end_matches('/'));
            let mclient = mtls_client(&st)?;
            let ca_pem = st.ca_pem.clone().unwrap_or_default();
            let device_id = st.device_id.clone().unwrap_or_default();
            let quic_ident = QuicIdent::open(&st)?;
            let t_kind = match transport {
                TransportKind::Tcp => "tcp",
                TransportKind::Quic => "quic",
                TransportKind::TlsTcp => "tls-tcp",
                TransportKind::Auto => "auto",
            };
            println!("[bench] {tunnels} tunnels to {dest} (transport {t_kind})");
            let mut samples_ms: Vec<f64> = Vec::new();
            for i in 0..tunnels {
                let t0 = std::time::Instant::now();
                // decision
                let posture = signed_posture(&device_id)?;
                let resp = mclient
                    .post(&url)
                    .bearer_auth(&token)
                    .json(&serde_json::json!({
                        "fqdn": if is_ip { None } else { Some(host) },
                        "ip":   if is_ip { Some(host) } else { None },
                        "port": port,
                        "protocol": "tcp",
                        "posture": posture
                    }))
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    bail!("bench: decision {} failed at tunnel {i}", resp.status());
                }
                let v: serde_json::Value = resp.json().await?;
                let tok_b64 = v["connection_token_b64"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let relay = v["via_gateways"][0]["relay"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                let tls_capable = v["via_gateways"][0]["tls_tcp"].as_bool();
                anyhow::ensure!(!relay.is_empty(), "bench: no serving gateway");
                // dial + admission ack
                let mut gw =
                    connect_relay(&relay, transport, &ca_pem, &quic_ident, tls_capable).await?;
                gw.write_all(format!("TOKEN {tok_b64} DEST {dest}\n").as_bytes())
                    .await?;
                let mut ack = [0u8; 3];
                gw.read_exact(&mut ack).await?;
                anyhow::ensure!(&ack == b"OK\n", "bench: gateway denied at tunnel {i}");
                let dt = t0.elapsed().as_secs_f64() * 1000.0;
                samples_ms.push(dt);
            }
            samples_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let pick = |q: f64| samples_ms[((samples_ms.len() as f64 - 1.0) * q).round() as usize];
            let p50 = pick(0.50);
            let p95 = pick(0.95);
            println!("[bench] tunnels={} transport={} p50={p50:.1}ms p95={p95:.1}ms min={:.1}ms max={:.1}ms",
                samples_ms.len(), t_kind, samples_ms[0], samples_ms[samples_ms.len() - 1]);
            if report {
                let rec = serde_json::json!({
                    "ts": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
                    "dest": dest, "tunnels": samples_ms.len(), "transport": t_kind,
                    "p50_ms": p50, "p95_ms": p95,
                    "note": "loopback dev; fallback-stall + real NFR-PERF-004/022 numbers need cross-machine T2/T3"
                });
                // deploy/bench/ beside the binary's project root when present
                let dir = std::path::PathBuf::from("deploy").join("bench");
                let _ = std::fs::create_dir_all(&dir);
                let _ = std::fs::write(
                    dir.join(format!(
                        "bench-{t_kind}-{}.json",
                        rec["ts"].as_i64().unwrap_or(0)
                    )),
                    serde_json::to_string_pretty(&rec).unwrap_or_default(),
                );
                println!("[bench] report written under deploy/bench/");
            }
        }
        Cmd::Access {
            dest,
            local_port,
            serve,
            gateway_relay,
            transport,
            bind,
            print_token,
            dns,
            metrics: metrics_addr,
            proto,
        } => {
            let Some(token) = st.access_token.clone() else {
                bail!("not logged in - run `login` first");
            };
            if dns.is_some() && !serve {
                bail!("--dns requires --serve (zone-driven forwarders serve per-connection)");
            }
            if dest.is_empty() && dns.is_none() {
                bail!("at least one destination required (host:port)");
            }
            let url = format!("{}/v1/access", st.controller_url.trim_end_matches('/'));
            let mclient = mtls_client(&st)?;
            let ca_pem = st.ca_pem.clone().unwrap_or_default();
            let device_id = st.device_id.clone().unwrap_or_default();
            let quic_ident = QuicIdent::open(&st)?;

            // W3.5: ensure the requirement spec is applied before any
            // decision (one-shot determinism; serve continues via poller)
            {
                let _ = fetch_posture_spec(&mclient, &st.controller_url, &token).await;
                let _ = tokio::task::spawn_blocking(crate::posture_probes::run_probes_now).await;
            }
            if serve {
                // spec poller (10 s) + dedicated probe thread (COM off the
                // async workers, same discipline as the posture collector)
                let mc = mclient.clone();
                let cu = st.controller_url.clone();
                let tk = token.clone();
                tokio::spawn(async move {
                    loop {
                        let _ = fetch_posture_spec(&mc, &cu, &tk).await;
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    }
                });
                crate::posture_probes::start_probe_thread();
            }

            // shared per-connection decision fetch: ALLOW → (token, gateways)
            let decide = |dest: &str| {
                let mut mclient = mclient.clone();
                let url = url.clone();
                let token = token.clone();
                let device_id = device_id.clone();
                let proto = proto.clone();
                let dest = dest.to_string();
                async move {
                    let Some((host, port_s)) = dest.split_once(':') else {
                        anyhow::bail!("dest must be fqdn-or-ip:port");
                    };
                    let is_ip = host.parse::<std::net::IpAddr>().is_ok();
                    let dev = device_id.clone();
                    // blocking collect on the blocking pool, not a worker
                    let posture = tokio::task::spawn_blocking(move || signed_posture_fresh(&dev))
                        .await
                        .map_err(|e| anyhow::anyhow!("posture task join: {e}"))??;
                    let resp = mclient
                        .post(&url)
                        .bearer_auth(&token)
                        .json(&serde_json::json!({
                            "fqdn": if is_ip { None } else { Some(host) },
                            "ip":   if is_ip { Some(host) } else { None },
                            "port": port_s.parse::<i64>()?,
                            "protocol": proto,
                            "posture": posture
                        }))
                        .send()
                        .await?;
                    let sc = resp.status();
                    if !sc.is_success() {
                        let v: serde_json::Value = resp.json().await.unwrap_or_default();
                        log_event("access_deny", &format!("dest={dest}"));
                        let body = v.to_string();
                        // X5 [F-07]: actionable hint on step-up denials
                        if body.contains("step-up") {
                            anyhow::bail!(
                                "access DENIED: {} - {}\n  hint: re-authenticate with MFA (login --code <code>-mfa) and retry",
                                sc, body
                            );
                        }
                        // W6.2: session ended server-side (admin revoke, idle
                        // expiry, or self-logout) — the fix is a re-login
                        if let Some(hint) = session_end_hint(&body) {
                            anyhow::bail!("access DENIED: {} - {}\n  hint: {hint}", sc, body);
                        }
                        anyhow::bail!("access DENIED: {} - {}", sc, body);
                    }
                    let v: serde_json::Value = resp.json().await?;
                    Ok::<_, anyhow::Error>((dest, v))
                }
            };

            // single-shot: one decision per dest, print gateway + exit
            if !serve {
                for d in &dest {
                    let (d, v) = decide(d).await?;
                    println!(
                        "{d}: ALLOW via policy '{}' ttl={}s",
                        v["matched_policy"], v["ttl"]
                    );
                    if print_token {
                        // X4 test hook: expose the one-time token so an offline
                        // gateway admission can be probed directly
                        println!(
                            "TOKEN_B64={}",
                            v["connection_token_b64"].as_str().unwrap_or("")
                        );
                    }
                    if let Some(relay) = &gateway_relay {
                        println!("  override gateway relay {relay}");
                    } else {
                        let gws: Vec<String> = v["via_gateways"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .map(|g| {
                                        format!(
                                            "{}@{}",
                                            g["gateway_id"].as_str().unwrap_or("?"),
                                            g["relay"].as_str().unwrap_or("?")
                                        )
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        println!("  via gateways: {}", gws.join(", "));
                    }
                }
                println!(
                    "single-shot mode: tokens valid - relay splice lands with gateway (G-04/G-05)"
                );
                return Ok(());
            }

            // ---- T-05 forwarder, P3-MG: one task per dest ----
            // Each incoming connection fetches a fresh decision for ITS dest
            // and dials that decision's via_gateways in order (advance only
            // on connect failure) — multiple gateways may be live at once.
            // W4.4: kick the posture collect in the background but DO NOT
            // delay binding — a blocking warm-up here (cold WMI 7.5-9.2s)
            // pushed the listener past every suite/service timing envelope.
            // Until it lands, connections serve last-good/unknown (fail-open,
            // visible via the staleness gauge), never a stall.
            // OBS.4: init BEFORE anything publishes a series — init()
            // prezeroes every series (days_remaining = -1 etc.) and would
            // clobber values set earlier (found live 2026-08-29: the W5.1
            // runway gauge scraped as -1 in serve mode).
            if metrics_addr.is_some() {
                metrics::init();
            }
            crate::posture_collector::kick_refresh();
            // W5.1: publish local cert runway (no-op unless metrics enabled)
            if let Some(pem) = st.cert_pem.as_deref() {
                if let Ok(na) = cert_expiry_unix(pem) {
                    metrics::device_cert_days_remaining().set(cert_days_remaining(unix_now(), na));
                }
            }
            let mut tasks = Vec::new();
            for (i, d) in dest.iter().enumerate() {
                let lp = local_port + i as u16;
                if proto.eq_ignore_ascii_case("udp") {
                    // W8.1: local UDP forwarder -> gateway raw UDP relay
                    // (relay port + 2). Orthogonal to --transport.
                    let std_sock = std::net::UdpSocket::bind((bind.as_str(), lp))?;
                    aztna_common::net::udp_no_connreset(&std_sock);
                    std_sock.set_nonblocking(true)?;
                    let sock = tokio::net::UdpSocket::from_std(std_sock)?;
                    println!("[udp-forwarder] listening on {bind}:{lp} -> {d} (udp)");
                    tasks.push(tokio::spawn(udp_forwarder(
                        std::sync::Arc::new(sock),
                        d.clone(),
                        mclient.clone(),
                        url.clone(),
                        token.clone(),
                        device_id.clone(),
                        gateway_relay.clone(),
                        ca_pem.clone(),
                        quic_ident.clone(),
                    )));
                    continue;
                }
                let listen = tokio::net::TcpListener::bind((bind.as_str(), lp)).await?;
                println!("[forwarder] listening on {bind}:{lp} -> {d}");
                tasks.push(tokio::spawn(serve_dest(
                    listen,
                    d.clone(),
                    mclient.clone(),
                    url.clone(),
                    token.clone(),
                    device_id.clone(),
                    ca_pem.clone(),
                    quic_ident.clone(),
                    gateway_relay.clone(),
                    transport,
                )));
            }
            // OBS.4 [NFR §7.3]: loopback metrics endpoint (opt-in);
            // metrics::init() already ran above, before any series publish
            if let Some(spec) = &metrics_addr {
                let l = tokio::net::TcpListener::bind(spec.as_str()).await?;
                println!("[metrics] serving on http://{spec}/metrics (loopback)");
                tokio::spawn(async move {
                    loop {
                        if let Ok((sock, _)) = l.accept().await {
                            let _ = metrics_http_serve(sock).await;
                        }
                    }
                });
                metrics::tunnel_state().with_label_values(&["up"]).set(1);
            }
            // W4.1 [ADR-0016]: private-DNS mode — UDP responder (A-only, no
            // recursion) + zone-driven forwarders refreshed from the
            // controller's /v1/dns-zones (every 10 s)
            if let Some(spec) = &dns {
                let (dhost, dport) = parse_dns_addr(spec)?;
                let std_sock = std::net::UdpSocket::bind((dhost.as_str(), dport))?;
                dns::udp_no_connreset(&std_sock); // windows: avoid 10054 stalls
                std_sock.set_nonblocking(true)?;
                let sock = tokio::net::UdpSocket::from_std(std_sock)?;
                let zones: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>> =
                    Arc::new(Default::default());
                println!("[dns] responder on {dhost}:{dport} (A-only, no recursion)");
                tokio::spawn(dns::serve(sock, zones.clone()));
                tokio::spawn(zone_manager(
                    mclient.clone(),
                    st.controller_url.clone(),
                    token.clone(),
                    device_id.clone(),
                    ca_pem.clone(),
                    quic_ident.clone(),
                    gateway_relay.clone(),
                    transport,
                    zones,
                ));
            }
            // X1 [I5]: periodic posture push while serving (kill orders land
            // via the gateway channel; new decisions gate on health too)
            tokio::spawn(posture_reporter(
                mclient.clone(),
                st.controller_url.clone(),
                st.device_id.clone().unwrap_or_default(),
            ));
            // T-06: policy-change detection while serving (mgmt listener
            // [DR-CTL-003]; URL configurable [P3-MG M5 — no hardcoded IPs])
            {
                let mgmt = mgmt_url(&st);
                tokio::spawn(async move {
                    let mut last_pv = String::new();
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        if let Ok(pv) = http().get(format!("{mgmt}/v1/policy-version")).send().await
                        {
                            if let Ok(j) = pv.json::<serde_json::Value>().await {
                                let v = j["version"].to_string();
                                if !last_pv.is_empty() && v != last_pv {
                                    println!("[forwarder] policy version changed {last_pv} -> {v}");
                                    log_event(
                                        "policy_version_change",
                                        &format!("{last_pv} -> {v}"),
                                    );
                                }
                                last_pv = v;
                            }
                        }
                    }
                });
            }
            // any task exit (fatal) ends the command; pure --dns mode has no
            // explicit-dest tasks, so park forever (responder + zone manager
            // own the lifetime)
            if dns.is_some() && dest.is_empty() {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                }
            }
            let mut pending = tasks;
            while let Some(h) = pending.pop() {
                if let Ok(Err(e)) = h.await {
                    return Err(e);
                }
            }
            return Ok(());
        }
        Cmd::DnsZones => {
            let Some(token) = st.access_token.clone() else {
                bail!("not logged in - run `login` first");
            };
            let mclient = mtls_client(&st)?;
            let url = format!("{}/v1/dns-zones", st.controller_url.trim_end_matches('/'));
            let resp = mclient.get(&url).bearer_auth(&token).send().await?;
            let sc = resp.status();
            let body = resp.text().await?;
            anyhow::ensure!(sc.is_success(), "dns-zones failed: {sc} {body}");
            println!("{body}");
        }
    }
    Ok(())
}

/// OBS.4: one-shot metrics responder on an accepted loopback connection.
pub async fn metrics_http_serve(mut sock: tokio::net::TcpStream) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match sock.read(&mut byte).await? {
            0 => break,
            _ => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n") || buf.len() > 4096 {
                    break;
                }
            }
        }
    }
    let first = String::from_utf8_lossy(&buf);
    let target = first.split_whitespace().nth(1).unwrap_or("/");
    let (status, body) = if target.starts_with("/metrics") {
        ("200 OK", aztna_common::metrics::gather_text())
    } else {
        ("404 Not Found", "not found\n".to_string())
    };
    sock.write_all(
        &format!(
            "HTTP/1.0 {status}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            aztna_common::metrics::CONTENT_TYPE,
            body.len()
        )
        .into_bytes(),
    )
    .await?;
    Ok(())
}

/// Mgmt base URL for policy-version polling [P3-MG M5]: env → state →
/// derived from controller host (mgmt = same host, port from aztna-common).
fn mgmt_url(st: &ClientState) -> String {
    if let Ok(u) = std::env::var("AZTNA_MGMT_URL") {
        return u.trim_end_matches('/').to_string();
    }
    if let Some(u) = &st.mgmt_url {
        if !u.is_empty() {
            return u.trim_end_matches('/').to_string();
        }
    }
    let host = st
        .controller_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or(aztna_common::ips::CONTROLLER)
        .to_string();
    format!("http://{host}:{}", aztna_common::ports::CONTROLLER_MGMT)
}

/// Serve one destination: accept loop + per-connection decision + gateway
/// walk [P3-MG, ADR-0012]. `relay_override` pins to one gateway (dev).
#[allow(clippy::too_many_arguments)]
// ---------- W8.1 [ADR-0003 udp]: local UDP forwarder ----------

/// Session-establishing datagram: TOKEN/DEST header line + payload in
/// ONE datagram (the header rides only this packet — the plan's
/// first-datagram MTU note asks apps to keep it <= ~1200 B).
fn build_first_datagram(token_b64: &str, dest: &str, payload: &[u8]) -> Vec<u8> {
    let mut v = format!("TOKEN {token_b64} DEST {dest}\n").into_bytes();
    v.extend_from_slice(payload);
    v
}

/// Pure flow-liveness decision (W8.1 unit-tested): a flow is usable when
/// its token TTL has not lapsed AND it is inside the client idle window
/// (client idle < gateway reap by design, so the client re-establishes
/// proactively and never sends payload-only datagrams into a reaped
/// session — plan v0.2 resolves the spurious-DENY window this way).
fn udp_flow_live(
    expires_at: i64,
    last_active: std::time::Instant,
    idle: std::time::Duration,
) -> bool {
    unix_now() < expires_at && last_active.elapsed() < idle
}

/// One admitted client-side UDP flow (per local peer address): its own
/// gateway-facing socket (the gateway keys the session by that address),
/// the one-use token that established it, and liveness stamps.
struct UdpFlow {
    carrier: UdpCarrier,
    /// upstream dgram_id counter (QUIC mode; unused in raw)
    dgram_id: u16,
    expires_at: i64,
    last_active: std::time::Instant,
}

impl UdpFlow {
    /// W14S2 fix step 3: the session-map key this flow owns (Quic flows
    /// carry a gateway session id; raw-carrier flows own none).
    fn owned_sid(&self) -> Option<u32> {
        match &self.carrier {
            UdpCarrier::Quic { sid, .. } => Some(*sid),
            UdpCarrier::Raw(_) => None,
        }
    }
}

/// W14: how a UDP flow rides to the gateway — encrypted QUIC DATAGRAM
/// frames (session id from UDPOPEN) or the legacy raw relay socket.
#[derive(Clone)]
enum UdpCarrier {
    Raw(std::sync::Arc<tokio::net::UdpSocket>),
    Quic { conn: quinn::Connection, sid: u32 },
}

/// W14: fragment `payload` at the RUNTIME max and send as DATAGRAM
/// frames; a TooLarge mid-flight re-fragments once at the fresh max.
async fn udp_frag_send(conn: &quinn::Connection, sid: u32, id: u16, payload: &[u8]) -> bool {
    let max = conn.max_datagram_size().unwrap_or(1200);
    let frames = match aztna_common::udp_frag::fragment(sid, id, payload, max) {
        Some(f) => f,
        None => return false,
    };
    for f in frames {
        if let Err(quinn::SendDatagramError::TooLarge) = conn.send_datagram(f.into()) {
            let max2 = conn.max_datagram_size().unwrap_or(1200);
            let Some(fs) = aztna_common::udp_frag::fragment(sid, id, payload, max2) else {
                return false;
            };
            for f2 in fs {
                if conn.send_datagram(f2.into()).is_err() {
                    return false;
                }
            }
            return true;
        }
    }
    true
}

/// W14: dial the gateway's QUIC listener and return the raw connection
/// (the UDP-app carrier reuses one connection across sessions; the
/// stream carrier wraps this in open_bi — single dial definition).
async fn quic_dial(
    host: &str,
    tcp_port: u16,
    ca_pem: &str,
    ident: &QuicIdent,
    dial_to: std::time::Duration,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    use quinn::crypto::rustls::QuicClientConfig;
    let mut roots = rustls::RootCertStore::empty();
    let mut pem = std::io::BufReader::new(ca_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut pem) {
        roots.add(cert?)?;
    }
    let (certs, key) = identity::tls_client_identity(ident.device.clone(), &ident.cert_pem)
        .inspect_err(|_| metrics::mtls_identity_failures_total().inc())?;
    let certified = Arc::new(rustls::sign::CertifiedKey::new(certs, key));
    // W29 step 6: TPM-signed identities restrict to SHA-256-transcript
    // suites (the TPM signer takes a fixed 32-byte hash — see tpmtls)
    let tls = if ident.device.is_tpm() {
        tpmtls::sha256_only_client_config(roots, certified)
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_cert_resolver(Arc::new(tpmtls::Resolver { key: certified }))
    };
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    let mut qcfg = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    qcfg.transport_config(Arc::new({
        let mut t = quinn::TransportConfig::default();
        t.keep_alive_interval(Some(std::time::Duration::from_secs(30)));
        t
    }));
    endpoint.set_default_client_config(qcfg);
    let addr = match tokio::net::lookup_host((host, tcp_port)).await?.next() {
        Some(mut a) => {
            a.set_port(tcp_port + 1);
            a
        }
        None => bail!("cannot resolve relay host {host}"),
    };
    let conn = match tokio::time::timeout(dial_to, endpoint.connect(addr, host)?).await {
        Ok(r) => r?,
        Err(_) => {
            metrics::tunnel_setup_timeouts()
                .with_label_values(&["dial"])
                .inc();
            bail!("quic handshake timeout after {dial_to:?}")
        }
    };
    Ok((endpoint, conn))
}

/// W14: open one UDP-app session on a (possibly cached) QUIC connection:
/// UDPOPEN over a bi-stream inside TLS → "OK <sid>". Ok(None) = the peer
/// does not advertise DATAGRAM support (old gateway) — caller falls back
/// to the raw relay, counted.
async fn quic_udp_session(
    conn: &quinn::Connection,
    token_b64: &str,
    dest: &str,
    ack_to: std::time::Duration,
) -> Result<Option<u32>> {
    let max = match conn.max_datagram_size() {
        Some(m) => m,
        None => return Ok(None),
    };
    let _ = max;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(format!("UDPOPEN {token_b64} DEST {dest}\n").as_bytes())
        .await?;
    let mut line = Vec::new();
    let deadline = tokio::time::Instant::now() + ack_to;
    let mut b = [0u8; 1];
    loop {
        match tokio::time::timeout_at(deadline, recv.read(&mut b)).await {
            Ok(Ok(Some(n))) if n == 1 => {
                if b[0] == b'\n' {
                    break;
                }
                line.push(b[0]);
                if line.len() > 128 {
                    bail!("udpopen reply overlong");
                }
            }
            Ok(Ok(_)) => bail!("udpopen stream closed before reply"),
            Ok(Err(e)) => bail!("udpopen read: {e}"),
            Err(_) => bail!("udpopen ack timeout after {ack_to:?}"),
        }
    }
    let s = String::from_utf8_lossy(&line).trim_end().to_string();
    let sid = s
        .strip_prefix("OK ")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .ok_or_else(|| anyhow::anyhow!("gateway denied the udp-quic flow: {s}"))?;
    Ok(Some(sid))
}

/// W14: one reader per QUIC connection — demuxes fragmented DATAGRAM
/// frames by session id back to the local peer that opened the session.
async fn quic_udp_reader(
    conn: quinn::Connection,
    sock: std::sync::Arc<tokio::net::UdpSocket>,
    sids: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u32, std::net::SocketAddr>>>,
    flows: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<std::net::SocketAddr, UdpFlow>>,
    >,
    // W14S2 fix step 3: the reassembler map is SHARED with the forwarder —
    // client-side flow removals can prune their entries (previously only
    // gateway tombstones could, an unbounded-growth leak).
    reasms: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<u32, aztna_common::udp_frag::Reassembler>>,
    >,
    // W14S2 fix step 3 (H5c): the reader is the first to observe a lost
    // connection; the flag tells the forwarder to re-dial on the next
    // establishment instead of downgrading to the raw carrier forever.
    conn_alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    dest: String,
) {
    loop {
        let d = match conn.read_datagram().await {
            Ok(d) => d,
            Err(_) => {
                conn_alive.store(false, std::sync::atomic::Ordering::Relaxed);
                log_event(
                    "udp_carrier",
                    &format!("dest={dest} quic conn lost - next establishment re-dials"),
                );
                println!("[udp-forwarder {dest}] quic connection lost - will re-dial");
                break;
            }
        };
        // W14S2 fix step 1: reassembler-map size (leak visibility)
        metrics::udp_flows()
            .with_label_values(&["reasms"])
            .set(reasms.lock().unwrap().len() as i64);
        let frame = match aztna_common::udp_frag::decode(&d) {
            Some(f) => f,
            None => continue,
        };
        // W8.1 parity: total_len=0 tombstone = session severed gateway-side
        // (kill/idle) - drop the flow so the NEXT datagram re-decides
        // instead of riding a dead sid until TTL (the raw carrier's
        // DENY-on-live-flow hard signal).
        if frame.total_len == 0 {
            if let Some(peer) = sids.lock().unwrap().remove(&frame.session_id) {
                flows.lock().unwrap().remove(&peer);
                reasms.lock().unwrap().remove(&frame.session_id);
                metrics::udp_flows()
                    .with_label_values(&["reasms"])
                    .set(reasms.lock().unwrap().len() as i64);
                metrics::udp_datagrams_total()
                    .with_label_values(&["deny"])
                    .inc();
                println!(
                    "[udp-forwarder {dest}] session ended by gateway - will re-establish on next datagram"
                );
            }
            continue;
        }
        let peer = sids.lock().unwrap().get(&frame.session_id).copied();
        let Some(peer) = peer else { continue };
        // reassemble under the lock; the send happens after the guard
        // drops (a std MutexGuard must not live across the .await)
        let outcome = {
            let mut rg = reasms.lock().unwrap();
            rg.entry(frame.session_id)
                .or_insert_with(|| aztna_common::udp_frag::Reassembler::new(16, 256 * 1024))
                .accept(&frame, std::time::Instant::now())
        };
        if let aztna_common::udp_frag::Outcome::Complete(data) = outcome {
            if sock.send_to(&data, peer).await.is_ok() {
                metrics::udp_datagrams_total()
                    .with_label_values(&["upstream"])
                    .inc();
            }
        }
    }
}

/// W14S2 fix step 3 (H5a/b): remove a flow and the session-map entries the
/// flow owns. Called on every client-side removal (idle sweep, TTL,
/// re-establishment replacement) — previously sids/reasms entries were
/// pruned ONLY by gateway tombstones, so long-lived forwarders grew both
/// maps without bound, and a late tombstone for a superseded sid could
/// kill the peer's NEW flow.
fn prune_flow(
    peer: &std::net::SocketAddr,
    flows: &std::sync::Mutex<std::collections::HashMap<std::net::SocketAddr, UdpFlow>>,
    sids: &std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u32, std::net::SocketAddr>>>,
    reasms: &std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<u32, aztna_common::udp_frag::Reassembler>>,
    >,
) {
    let sid = flows
        .lock()
        .unwrap()
        .remove(peer)
        .and_then(|f| f.owned_sid());
    prune_session_entries(sid, sids, reasms);
}

/// W14S2 fix step 3: pure map-pruning core (unit-pinned) — a flow's owned
/// session entries die with the flow. `None` (raw-carrier flows, or the
/// peer had no flow) prunes nothing.
fn prune_session_entries(
    sid: Option<u32>,
    sids: &std::sync::Arc<std::sync::Mutex<std::collections::HashMap<u32, std::net::SocketAddr>>>,
    reasms: &std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<u32, aztna_common::udp_frag::Reassembler>>,
    >,
) {
    if let Some(sid) = sid {
        sids.lock().unwrap().remove(&sid);
        reasms.lock().unwrap().remove(&sid);
    }
}

/// W8.1: serve a local UDP port, forwarding datagrams to the gateway's
/// raw UDP relay (relay port + 2). Per local peer address = one flow:
/// first datagram triggers decision -> one-use token -> framed admission;
/// re-establishment is ALWAYS a fresh decision (the gateway's nonce guard
/// makes a resent token a replay by construction — the literal
/// one-decision-one-token-one-session contract). A DENY received on a
/// believed-live flow is a hard re-establish signal (kill orders,
/// upstream-error reaps, timing races).
#[allow(clippy::too_many_arguments)]
async fn udp_forwarder(
    sock: std::sync::Arc<tokio::net::UdpSocket>,
    dest: String,
    mclient: reqwest::Client,
    url: String,
    token: String,
    device_id: String,
    relay_override: Option<String>,
    ca_pem: String,
    quic_ident: QuicIdent,
) -> anyhow::Result<()> {
    let (host, port_s) = dest.split_once(':').context("dest must be host:port")?;
    let is_ip = host.parse::<std::net::IpAddr>().is_ok();
    let port: i64 = port_s.parse()?;
    // W14: one QUIC connection per forwarder (lazily dialed); sid→peer
    // routing feeds the single reader task
    let mut quic_state: Option<(quinn::Endpoint, quinn::Connection)> = None;
    let sids: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<u32, std::net::SocketAddr>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    // W14S2 fix step 3: shared reassembler map (client-side pruning) + the
    // conn-loss flag the reader sets and the establishment re-dial honors.
    let reasms: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<u32, aztna_common::udp_frag::Reassembler>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let conn_alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let idle = aztna_common::env_secs("AZTNA_CLT_UDP_IDLE_SECS", 20, 1);
    let ack_to = aztna_common::env_secs("AZTNA_UDP_ACK_TIMEOUT_SECS", 3, 1);
    let decision_to = aztna_common::env_secs("AZTNA_DECISION_TIMEOUT_SECS", 5, 1);
    let flows: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<std::net::SocketAddr, UdpFlow>>,
    > = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    let mut buf = vec![0u8; 65507];
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let (n, peer) = r?;
                let payload = buf[..n].to_vec();
                // fast path: live flow (lock only for the liveness check +
                // handle clone — the send happens after it drops)
                let live = {
                    let mut fs = flows.lock().unwrap();
                    match fs.get_mut(&peer) {
                        Some(f) if udp_flow_live(f.expires_at, f.last_active, idle) => {
                            f.last_active = std::time::Instant::now();
                            f.dgram_id = f.dgram_id.wrapping_add(1);
                            match f.carrier.clone() {
                                UdpCarrier::Raw(s) => Some((Some(s), None)),
                                UdpCarrier::Quic { conn, sid } => {
                                    Some((None, Some((conn, sid, f.dgram_id))))
                                }
                            }
                        }
                        _ => {
                            fs.remove(&peer); // stale: re-establish next
                            None
                        }
                    }
                };
                match live {
                    Some((Some(gw_sock), None)) => {
                        if gw_sock.send(&payload).await.is_ok() {
                            metrics::udp_datagrams_total().with_label_values(&["client"]).inc();
                        }
                        continue;
                    }
                    Some((None, Some((conn, sid, id)))) => {
                        if udp_frag_send(&conn, sid, id, &payload).await {
                            metrics::udp_datagrams_total().with_label_values(&["client"]).inc();
                        }
                        continue;
                    }
                    _ => {}
                }
                // establishment: fresh decision (never a resent token)
                // W14S2 fix step 1: phase timings (histogram) + timestamped
                // start/finish events — the regression guard for the
                // establishment-posture fix (plan §4.2). The finish events
                // land at every terminal branch so a future failing window
                // is a record, not a reconstruction.
                let est_t0 = std::time::Instant::now();
                let mut phases = String::new();
                let fin = |outcome: &str, phases: &str| {
                    log_event(
                        "udp_establishment",
                        &format!(
                            "finish dest={dest} outcome={outcome} {phases} total={}ms",
                            est_t0.elapsed().as_millis()
                        ),
                    );
                };
                log_event("udp_establishment", &format!("start dest={dest}"));
                // W14S2 fix step 2 (plan §4.1): NON-BLOCKING posture — the
                // fresh-WMI wait (collect_fresh_bounded's 20 s ceiling,
                // inline in this single recv loop) was the W14S2 stall:
                // first-datagram latency up to ~31 s under a wedged WMI
                // (idle collect alone is 6.5–9.2 s). Serve-mode
                // establishments now use the cached snapshot exactly like
                // serve_dest's TCP decision fetch — the W4.4 contract
                // restored. The one-shot path keeps signed_posture_fresh
                // (W3.1 real values; latency-tolerant process).
                let ph_t = std::time::Instant::now();
                let posture = match signed_posture(&device_id) {
                    Ok(p) => p,
                    Err(e) => { println!("[udp-forwarder {dest}] posture build failed: {e}"); fin("error_posture", &phases); continue; }
                };
                metrics::udp_establishment_seconds().with_label_values(&["posture"]).observe(ph_t.elapsed().as_secs_f64());
                phases.push_str(&format!("posture={}ms ", ph_t.elapsed().as_millis()));
                let dec_t = std::time::Instant::now();
                let sent = tokio::time::timeout(decision_to, mclient
                    .post(&url)
                    .bearer_auth(&token)
                    .json(&serde_json::json!({
                        "fqdn": if is_ip { None } else { Some(host) },
                        "ip":   if is_ip { Some(host) } else { None },
                        "port": port,
                        "protocol": "udp",
                        "posture": posture
                    }))
                    .send())
                    .await;
                metrics::udp_establishment_seconds().with_label_values(&["decision"]).observe(dec_t.elapsed().as_secs_f64());
                phases.push_str(&format!("decision={}ms ", dec_t.elapsed().as_millis()));
                let resp = match sent {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => { println!("[udp-forwarder {dest}] decision error: {e}"); fin("error_decision", &phases); continue; }
                    Err(_) => { println!("[udp-forwarder {dest}] decision timeout"); fin("error_decision_timeout", &phases); continue; }
                };
                if !resp.status().is_success() {
                    let body: serde_json::Value = resp.json().await.unwrap_or_default();
                    log_event("udp_access_deny", &format!("dest={dest}"));
                    println!("[udp-forwarder {dest}] DENIED: {body}");
                    fin("denied", &phases);
                    continue;
                }
                let v: serde_json::Value = resp.json().await?;
                let token_b64 = v["connection_token_b64"].as_str().unwrap_or("").to_string();
                let ttl = v["ttl"].as_i64().unwrap_or(30);
                let relay = match &relay_override {
                    Some(r) => r.clone(),
                    None => v["via_gateways"][0]["relay"].as_str().unwrap_or("").to_string(),
                };
                let Some((rhost, rport)) = relay.rsplit_once(':') else {
                    println!("[udp-forwarder {dest}] no gateway relay for dest");
                    fin("error_no_relay", &phases);
                    continue;
                };
                let Ok(rport): Result<u16, _> = rport.parse() else {
                    println!("[udp-forwarder {dest}] bad relay addr {relay}");
                    fin("error_bad_relay", &phases);
                    continue;
                };
                // raw UDP relay = relay port + 2 (tcp P / quic P+1 / udp P+2)
                // W14: encrypted QUIC DATAGRAM carrier first — one shared
                // connection per forwarder, sessions per flow; the raw
                // relay is only a counted fallback (old gateway / dial
                // failure — capability detection, never a policy guess)
                // W14S2 fix step 3 (H5c): a dead cached connection re-dials
                // here — never a permanent silent downgrade to the raw
                // carrier. The reader flags loss; retire the dead conn's
                // flows (their sids/reasms entries follow via prune_flow).
                if !conn_alive.load(std::sync::atomic::Ordering::Relaxed)
                    && quic_state.is_some()
                {
                    quic_state = None;
                    let peers: Vec<std::net::SocketAddr> = flows
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|(_, f)| matches!(f.carrier, UdpCarrier::Quic { .. }))
                        .map(|(a, _)| *a)
                        .collect();
                    for p in &peers {
                        prune_flow(p, &flows, &sids, &reasms);
                    }
                }
                if quic_state.is_none() {
                    let dial_t = std::time::Instant::now();
                    match quic_dial(rhost, rport, &ca_pem, &quic_ident, ack_to).await {
                        Ok((ep, c)) => {
                            conn_alive.store(true, std::sync::atomic::Ordering::Relaxed);
                            tokio::spawn(quic_udp_reader(
                                c.clone(),
                                sock.clone(),
                                sids.clone(),
                                flows.clone(),
                                reasms.clone(),
                                conn_alive.clone(),
                                dest.clone(),
                            ));
                            quic_state = Some((ep, c));
                        }
                        Err(e) => {
                            println!(
                                "[udp-forwarder {dest}] quic dial failed: {e:#} - raw relay fallback"
                            );
                        }
                    }
                    metrics::udp_establishment_seconds().with_label_values(&["dial"]).observe(dial_t.elapsed().as_secs_f64());
                    phases.push_str(&format!("dial={}ms ", dial_t.elapsed().as_millis()));
                }
                // W14: any quic-session failure is LOGGED before the raw
                // fallback (skill rule: no silent fallbacks) - note the raw
                // retry will legitimately DENY on the consumed nonce when
                // the failure was client-side post-admission.
                let sess_attempted = quic_state.is_some();
                let sess_t = std::time::Instant::now();
                let mut no_dgram = false; // Ok(None) = old gateway, no DATAGRAM support
                let quic_sess = match &quic_state {
                    Some((_, c)) => {
                        match quic_udp_session(c, &token_b64, &dest, ack_to).await {
                            Ok(None) => {
                                no_dgram = true;
                                None
                            }
                            Ok(v) => v,
                            Err(e) => {
                                println!("[udp-forwarder {dest}] udp-quic session failed: {e:#}");
                                None
                            }
                        }
                    }
                    None => None,
                };
                if sess_attempted {
                    metrics::udp_establishment_seconds().with_label_values(&["session"]).observe(sess_t.elapsed().as_secs_f64());
                    phases.push_str(&format!("session={}ms ", sess_t.elapsed().as_millis()));
                }
                if let Some(sid) = quic_sess {
                    if let Some((_, c)) = &quic_state {
                        // W14S2 fix step 3 (H5b): retire the peer's OLD
                        // flow first — its sids/reasms entries go with it,
                        // so a late tombstone for the old sid can no longer
                        // kill this NEW flow.
                        prune_flow(&peer, &flows, &sids, &reasms);
                        sids.lock().unwrap().insert(sid, peer);
                        let expires_at = unix_now() + ttl - 2; // re-decide BEFORE lapse
                        flows.lock().unwrap().insert(
                            peer,
                            UdpFlow {
                                carrier: UdpCarrier::Quic {
                                    conn: c.clone(),
                                    sid,
                                },
                                dgram_id: 1,
                                expires_at,
                                last_active: std::time::Instant::now(),
                            },
                        );
                        if udp_frag_send(c, sid, 1, &payload).await {
                            metrics::udp_datagrams_total()
                                .with_label_values(&["client"])
                                .inc();
                        }
                        fin("established_quic", &phases);
                        continue;
                    }
                }
                // W14S2 fix step 3: the counted downgrade carries its
                // REASON (bounded enum: dial_failed | no_datagram_support |
                // session_failed) — an "operating unencrypted" alarm you
                // can triage. Conn-loss never lands here: the re-dial
                // above replaces the dead connection before this point.
                let downgrade_reason = if quic_state.is_none() {
                    "dial_failed"
                } else if no_dgram {
                    "no_datagram_support"
                } else {
                    "session_failed"
                };
                metrics::carrier_downgrades_total()
                    .with_label_values(&["udp_quic_to_raw", downgrade_reason])
                    .inc();
                let gw_addr: std::net::SocketAddr = format!("{rhost}:{}", rport + 2).parse()
                    .context("bad gateway udp relay addr")?;
                let std_gw = std::net::UdpSocket::bind("0.0.0.0:0")?;
                aztna_common::net::udp_no_connreset(&std_gw);
                std_gw.set_nonblocking(true)?;
                let gw_sock = std::sync::Arc::new(tokio::net::UdpSocket::from_std(std_gw)?);
                let first = build_first_datagram(&token_b64, &dest, &payload);
                if gw_sock.send_to(&first, gw_addr).await.is_err() {
                    println!("[udp-forwarder {dest}] send to gateway failed");
                    fin("error_send_failed", &phases);
                    continue;
                }
                // bounded OK ack (W4.4 lesson); DENY is authoritative —
                // drop this datagram's flow, the next one re-decides
                let mut ackbuf = [0u8; 128];
                let ack = tokio::time::timeout(ack_to, gw_sock.recv(&mut ackbuf)).await;
                match ack {
                    Ok(Ok(m)) if &ackbuf[..m.min(3)] == b"OK\n" => {}
                    Ok(Ok(m)) => {
                        let reason = String::from_utf8_lossy(&ackbuf[..m]).trim_end().to_string();
                        println!("[udp-forwarder {dest}] gateway denied the flow: {reason}");
                        metrics::udp_datagrams_total().with_label_values(&["deny"]).inc();
                        fin("denied_by_gateway", &phases);
                        continue;
                    }
                    Ok(Err(e)) => { println!("[udp-forwarder {dest}] ack read failed: {e}"); fin("error_ack", &phases); continue; }
                    Err(_) => { println!("[udp-forwarder {dest}] ack timeout"); fin("error_ack_timeout", &phases); continue; }
                }
                let expires_at = unix_now() + ttl - 2; // re-decide BEFORE lapse
                prune_flow(&peer, &flows, &sids, &reasms); // retire old (H5b)
                flows.lock().unwrap().insert(peer, UdpFlow {
                    carrier: UdpCarrier::Raw(gw_sock.clone()),
                    dgram_id: 0,
                    expires_at,
                    last_active: std::time::Instant::now(),
                });
                metrics::udp_datagrams_total().with_label_values(&["client"]).inc();
                fin("established_raw", &phases);
                // reply pump: gateway -> local peer; a DENY here means the
                // session died mid-flow (kill/error/reap) — hard signal,
                // drop the flow so the next datagram re-establishes
                {
                    let flows = flows.clone();
                    let sock = sock.clone();
                    let dest = dest.clone();
                    tokio::spawn(async move {
                        let mut rb = vec![0u8; 65507];
                        loop {
                            match gw_sock.recv(&mut rb).await {
                                Ok(m) if m >= 4 && &rb[..4] == b"DENY" => {
                                    println!("[udp-forwarder {dest}] session ended by gateway - will re-establish on next datagram");
                                    flows.lock().unwrap().remove(&peer);
                                    break;
                                }
                                Ok(m) => {
                                    if sock.send_to(&rb[..m], peer).await.is_ok() {
                                        metrics::udp_datagrams_total().with_label_values(&["upstream"]).inc();
                                    } else { break; }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                // idle sweep: the fresh-decision re-establishment contract
                let due: Vec<std::net::SocketAddr> = {
                    let fs = flows.lock().unwrap();
                    fs.iter()
                        .filter(|(_, f)| !udp_flow_live(f.expires_at, f.last_active, idle))
                        .map(|(a, _)| *a)
                        .collect()
                };
                // W14S2 fix step 3: sweep removals now prune the session
                // maps with the flow (H5a — was flows-only, leaking
                // sids/reasms entries for every TTL-expired flow).
                for a in due {
                    prune_flow(&a, &flows, &sids, &reasms);
                }
                // W14S2 fix step 1: session-map sizes (leak visibility —
                // sids/reasms currently prune only on gateway tombstones)
                metrics::udp_flows().with_label_values(&["flows"])
                    .set(flows.lock().unwrap().len() as i64);
                metrics::udp_flows().with_label_values(&["sids"])
                    .set(sids.lock().unwrap().len() as i64);
            }
        }
    }
}

async fn serve_dest(
    listen: tokio::net::TcpListener,
    dest: String,
    mclient: reqwest::Client,
    url: String,
    token: String,
    device_id: String,
    ca_pem: String,
    quic_ident: QuicIdent,
    relay_override: Option<String>,
    transport: TransportKind,
) -> anyhow::Result<()> {
    let Some((host, port_s)) = dest.split_once(':') else {
        anyhow::bail!("dest must be fqdn-or-ip:port");
    };
    let is_ip = host.parse::<std::net::IpAddr>().is_ok();
    let port: i64 = port_s.parse()?;
    // X3 [DR-CLT-011/013]: last-known-good decision (visibility only —
    // one-time connection tokens make offline-allow impossible by design;
    // fail-mode is FAIL-CLOSED with informed logging)
    let mut cached: Option<(String, i64)> = None; // (result+rationale, expires_at)
                                                  // X2 [DR-CLT-017]: consecutive dial failures drive backoff+jitter
    let mut dial_failures: u32 = 0;
    // W4.4: bounded waits on every setup stage — the old code could wait
    // indefinitely at decision/dial/ack and stall the first connection.
    let decision_to = aztna_common::env_secs("AZTNA_DECISION_TIMEOUT_SECS", 5, 1);
    let dial_to = aztna_common::env_secs("AZTNA_QUIC_DIAL_TIMEOUT_SECS", 5, 1);
    let ack_to = aztna_common::env_secs("AZTNA_ACK_TIMEOUT_SECS", 5, 1);
    let engine_cancel = svc::engine_cancel();
    loop {
        let t_est = std::time::Instant::now();
        // W13: the service disconnect path cancels this token — an aborted
        // engine task alone would orphan these spawned forwarders
        let (mut inbound, peer) = match tokio::select! {
            biased;
            _ = engine_cancel.cancelled() => Option::<(tokio::net::TcpStream, std::net::SocketAddr)>::None,
            a = listen.accept() => Some(a?),
        } {
            None => return Ok(()),
            Some(v) => v,
        };
        // W13 step 3 [per-user tunnel isolation]: the kernel owner tables
        // attribute this connection to its true owning process; only the
        // owning user's session rides the service's forwarders. No owner
        // set = standalone CLI (single user by construction) = allow.
        // Fail-closed on unresolvable (probe: fast-close arm).
        if !svc::isolation_allows(peer, true) {
            inbound.shutdown().await.ok();
            log_event("peer_denied", &format!("dest={dest} peer={peer}"));
            metrics::intercepted_connections()
                .with_label_values(&["peer_denied"])
                .inc();
            continue;
        }
        println!("[forwarder {dest}] {} connected", peer);
        // fresh decision per connection (idempotent request => safe retry);
        // must carry signed posture [P2-1] or controller rejects with 403
        let posture = match signed_posture(&device_id) {
            Ok(p) => p,
            Err(e) => {
                inbound.shutdown().await.ok();
                println!("[forwarder {dest}] posture build failed: {e}");
                continue;
            }
        };
        // X2: network errors are per-connection, NEVER task-fatal
        let sent = tokio::time::timeout(
            decision_to,
            mclient
                .post(&url)
                .bearer_auth(&token)
                .json(&serde_json::json!({
                    "fqdn": if is_ip { None } else { Some(host) },
                    "ip":   if is_ip { Some(host) } else { None },
                    "port": port,
                    "protocol": "tcp",
                    "posture": posture
                }))
                .send(),
        )
        .await;
        let sent: Result<reqwest::Response, anyhow::Error> = match sent {
            Ok(r) => r.map_err(Into::into),
            Err(_) => {
                metrics::tunnel_setup_timeouts()
                    .with_label_values(&["decision"])
                    .inc();
                println!(
                    "[forwarder {dest}] decision timeout after {decision_to:?} - failing closed"
                );
                Err(anyhow::anyhow!("decision timeout after {decision_to:?}"))
            }
        };
        let resp = match sent {
            Ok(r) => r,
            Err(e) => {
                // X3: fail-mode — fail-closed, with cached-decision context
                inbound.shutdown().await.ok();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let ctx = match &cached {
                    Some((r, exp)) if now < *exp => {
                        format!("cached {r} unexpired but tokens unmintable")
                    }
                    Some((r, _)) => format!("cached {r} EXPIRED",),
                    None => "no cached decision".into(),
                };
                println!("[forwarder {dest}] fail_mode_closed: controller unreachable ({e}); {ctx} [DR-CLT-013]");
                log_event("fail_mode_closed", &format!("dest={dest} ({ctx})"));
                metrics::fail_mode_closed().inc();
                metrics::intercepted_connections()
                    .with_label_values(&["fail_closed"])
                    .inc();
                continue;
            }
        };
        if !resp.status().is_success() {
            let sc = resp.status();
            let body = resp.text().await.unwrap_or_default();
            cached = Some((format!("DENY({body})"), 0));
            inbound.shutdown().await.ok();
            println!("[forwarder {dest}] decision DENIED ({sc}) - closed");
            metrics::intercepted_connections()
                .with_label_values(&["deny"])
                .inc();
            continue;
        }
        let v: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                inbound.shutdown().await.ok();
                println!("[forwarder {dest}] decision decode failed: {e} - closed");
                continue;
            }
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        cached = Some((
            format!(
                "ALLOW via '{}'",
                v["matched_policy"].as_str().unwrap_or("?")
            ),
            now + v["ttl"].as_i64().unwrap_or(0),
        ));
        let Some(tok_b64) = v["connection_token_b64"].as_str().map(|s| s.to_string()) else {
            inbound.shutdown().await.ok();
            continue;
        };
        log_event("access_allow", &format!("dest={dest} ttl={}", v["ttl"]));
        // candidate relays: override pins to one (capability unknown — the
        // dev override dials an explicitly given relay, so the controller
        // signal legitimately does not exist); else the decision's list
        // with each gateway's W14 tls_tcp capability
        let candidates: Vec<(String, String, Option<bool>)> = if let Some(r) = &relay_override {
            vec![("override".into(), r.clone(), None)]
        } else {
            v["via_gateways"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|g| {
                            Some((
                                g["gateway_id"].as_str()?.to_string(),
                                g["relay"].as_str()?.to_string(),
                                // W14: authoritative per-gateway carrier signal
                                g["tls_tcp"].as_bool(),
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        if candidates.is_empty() {
            inbound.shutdown().await.ok();
            println!("[forwarder {dest}] no serving gateway in decision - closed");
            continue;
        }
        // dial in order; advance ONLY on connect failure (an admission DENY
        // from a reachable gateway is authoritative)
        let mut dialed: Option<RelayChannel> = None;
        let mut used_gw = String::new();
        for (gid, relay, tls_capable) in &candidates {
            match tokio::time::timeout(
                dial_to,
                connect_relay(relay, transport, &ca_pem, &quic_ident, *tls_capable),
            )
            .await
            {
                Ok(Ok(ch)) => {
                    dialed = Some(ch);
                    used_gw = gid.clone();
                    break;
                }
                Ok(Err(e)) => {
                    println!("[forwarder {dest}] gateway {gid} at {relay} unreachable: {e} - trying next");
                    metrics::reconnects_total().with_label_values(&[gid]).inc();
                }
                Err(_) => {
                    metrics::tunnel_setup_timeouts()
                        .with_label_values(&["dial"])
                        .inc();
                    println!("[forwarder {dest}] gateway {gid} at {relay} dial exceeded {dial_to:?} - trying next");
                    metrics::reconnects_total().with_label_values(&[gid]).inc();
                }
            }
        }
        let Some(mut gw) = dialed else {
            inbound.shutdown().await.ok();
            dial_failures += 1;
            // X2 [DR-CLT-017]: exp backoff + jitter before the next attempt
            let base = 200u64
                .saturating_mul(1u64 << dial_failures.min(5))
                .min(6_400);
            let jitter = rand::random::<u64>() % (base / 4 + 1);
            metrics::backoff_current_seconds().set(((base + jitter) / 1000) as i64);
            println!(
                "[forwarder {dest}] all serving gateways unreachable - closed (retry backoff ~{}ms)",
                base + jitter
            );
            tokio::time::sleep(std::time::Duration::from_millis(base + jitter)).await;
            continue;
        };
        dial_failures = 0;
        metrics::backoff_current_seconds().set(0);
        if used_gw != "override" {
            println!("[forwarder {dest}] via gateway {used_gw}");
        }
        // W4.4: the token write and OK-ack read are bounded and per-connection
        // — the old indefinite `read_exact` killed the whole serve task when
        // a gateway died between accept and ack.
        if let Err(e) = gw
            .write_all(format!("TOKEN {tok_b64} DEST {dest}\n").as_bytes())
            .await
        {
            println!("[forwarder {dest}] token write failed: {e}");
            metrics::intercepted_connections()
                .with_label_values(&["fail_closed"])
                .inc();
            inbound.shutdown().await.ok();
            dial_failures += 1;
            continue;
        }
        match read_ack(&mut gw, ack_to).await {
            AckOutcome::Ok => {}
            AckOutcome::Denied => {
                println!("[forwarder {dest}] gateway denied");
                metrics::intercepted_connections()
                    .with_label_values(&["deny"])
                    .inc();
                inbound.shutdown().await.ok();
                continue;
            }
            AckOutcome::TimedOut => {
                println!("[forwarder {dest}] gateway ack timeout after {ack_to:?}");
                inbound.shutdown().await.ok();
                dial_failures += 1;
                continue;
            }
            AckOutcome::Failed(e) => {
                println!("[forwarder {dest}] ack stage failed: {e}");
                inbound.shutdown().await.ok();
                dial_failures += 1;
                continue;
            }
        }
        metrics::intercepted_connections()
            .with_label_values(&["allow"])
            .inc();
        metrics::connection_establishment().observe(t_est.elapsed().as_secs_f64());
        tokio::spawn(async move {
            if tokio::io::copy_bidirectional(&mut inbound, &mut gw)
                .await
                .is_ok()
            {
                println!("[forwarder] session finished");
            }
        });
    }
}

// ---------- W4.1 [ADR-0016]: private DNS — zone sync + forwarders ----------

/// Zone entry from GET /v1/dns-zones: sticky loopback IP for an allowed
/// fqdn + the distinct destination ports of its segments.
#[derive(Clone, Debug, serde::Deserialize)]
struct ZoneEntry {
    fqdn: String,
    ip: String,
    ports: Vec<u16>,
}

/// "[host][:port]" -> (host, port). Default host 127.0.0.1, port 53.
fn parse_dns_addr(spec: &str) -> Result<(String, u16)> {
    match spec.rsplit_once(':') {
        Some((h, p)) => Ok((
            if h.is_empty() {
                "127.0.0.1".into()
            } else {
                h.into()
            },
            p.parse()?,
        )),
        None => Ok((
            if spec.is_empty() {
                "127.0.0.1".into()
            } else {
                spec.into()
            },
            53,
        )),
    }
}

/// W6.3: why a zone refresh was denied. `Failed` keeps the last-known map
/// (fail-safe serving); `Denied` applies the EMPTY set (aborts every
/// forwarder + clears the name map) — the session is gone, and both the map
/// and the bound listeners are reconnaissance surface. Established tunnels
/// are cut separately by the controller's kill feed.
enum ZonesFetch {
    Ok(Vec<ZoneEntry>),
    Denied(&'static str),
    Failed(String),
}

/// W6.3: classify a /v1/dns-zones denial. 401/403 mean the session is gone
/// (revoked / idle / bad token); the controller's 403 body carries the
/// session-ended reason, which also drives the metric label. Unit-tested.
fn zone_denial_reason(status: u16, body: &str) -> Option<&'static str> {
    match status {
        401 => Some("unauthorized"),
        403 if body.contains("session revoked") => Some("revoked"),
        403 if body.contains("session idle") => Some("idle"),
        403 => Some("unauthorized"),
        _ => None,
    }
}

async fn fetch_dns_zones(
    mclient: &reqwest::Client,
    controller_url: &str,
    token: &str,
) -> ZonesFetch {
    let url = format!("{}/v1/dns-zones", controller_url.trim_end_matches('/'));
    let resp = match mclient.get(&url).bearer_auth(token).send().await {
        Ok(r) => r,
        Err(e) => return ZonesFetch::Failed(e.to_string()),
    };
    let sc = resp.status().as_u16();
    if !(200..300).contains(&sc) {
        let body = resp.text().await.unwrap_or_default();
        if let Some(reason) = zone_denial_reason(sc, &body) {
            return ZonesFetch::Denied(reason);
        }
        return ZonesFetch::Failed(format!("dns-zones fetch failed: {sc} {body}"));
    }
    match resp.json::<serde_json::Value>().await {
        Ok(v) => match serde_json::from_value(v["zones"].clone()) {
            Ok(z) => ZonesFetch::Ok(z),
            Err(e) => ZonesFetch::Failed(e.to_string()),
        },
        Err(e) => ZonesFetch::Failed(e.to_string()),
    }
}

/// Refresh loop: fetch the user's zone map, keep the DNS name map current,
/// and bind/unbind one forwarder per (loopback IP, port) — each forwarder is
/// a serve_dest task on dest `fqdn:port`, so every connection takes the
/// normal decision→token→relay path (fqdn-matched by the PDP).
/// Fetch failures keep the last-known zones (fail-safe serving).
#[allow(clippy::too_many_arguments)]
async fn zone_manager(
    mclient: reqwest::Client,
    controller_url: String,
    token: String,
    device_id: String,
    ca_pem: String,
    quic_ident: QuicIdent,
    relay_override: Option<String>,
    transport: TransportKind,
    zones: Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>,
) -> anyhow::Result<()> {
    let access_url = format!("{}/v1/access", controller_url.trim_end_matches('/'));
    let mut live: std::collections::HashMap<
        (String, u16),
        tokio::task::JoinHandle<anyhow::Result<()>>,
    > = std::collections::HashMap::new();
    loop {
        match fetch_dns_zones(&mclient, &controller_url, &token).await {
            ZonesFetch::Ok(entries) => {
                // desired forwarder set: one per (ip, port)
                let mut want: std::collections::HashMap<(String, u16), String> =
                    std::collections::HashMap::new();
                for z in &entries {
                    for &p in &z.ports {
                        want.insert((z.ip.clone(), p), format!("{}:{}", z.fqdn, p));
                    }
                }
                let removed: Vec<_> = live
                    .keys()
                    .filter(|k| !want.contains_key(k))
                    .cloned()
                    .collect();
                for k in removed {
                    if let Some(h) = live.remove(&k) {
                        h.abort();
                        println!("[dns] forwarder removed {}:{}", k.0, k.1);
                    }
                }
                let added: Vec<((String, u16), String)> = want
                    .iter()
                    .filter(|(k, _)| !live.contains_key(k))
                    .map(|(k, d)| (k.clone(), d.clone()))
                    .collect();
                for ((ip, port), dest) in added {
                    match tokio::net::TcpListener::bind((ip.as_str(), port)).await {
                        Ok(l) => {
                            println!("[dns] forwarder {ip}:{port} -> {dest}");
                            live.insert(
                                (ip.clone(), port),
                                tokio::spawn(serve_dest(
                                    l,
                                    dest.clone(),
                                    mclient.clone(),
                                    access_url.clone(),
                                    token.clone(),
                                    device_id.clone(),
                                    ca_pem.clone(),
                                    quic_ident.clone(),
                                    relay_override.clone(),
                                    transport,
                                )),
                            );
                        }
                        Err(_) => {
                            metrics::dns_forwarder_bind_failures().inc();
                            println!("[dns] bind {ip}:{port} failed (skipped)");
                        }
                    }
                }
                // refresh the DNS name map (authoritative replace)
                {
                    let mut g = zones.write().await;
                    g.clear();
                    for z in &entries {
                        g.insert(z.fqdn.to_ascii_lowercase(), z.ip.clone());
                    }
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                metrics::dns_zones_last_success_timestamp().set(now);
                println!(
                    "[dns] {} zone(s) current ({} forwarder(s))",
                    entries.len(),
                    live.len()
                );
            }
            ZonesFetch::Denied(reason) => {
                // W6.3: session gone — apply the EMPTY entry set through the
                // same semantics as above: abort every forwarder AND clear
                // the name map (keeping either would leave the private
                // namespace's shape resident after revocation). No re-login
                // hint here — that path belongs to decision denials.
                log_event("zones_denied", &format!("reason={reason}"));
                metrics::zone_denies_total()
                    .with_label_values(&[reason])
                    .inc();
                let stopped = live.len();
                for (_, h) in live.drain() {
                    h.abort();
                }
                zones.write().await.clear();
                println!(
                    "[dns] zone refresh DENIED ({reason}) - {stopped} forwarder(s) removed, zone map cleared"
                );
            }
            ZonesFetch::Failed(e) => {
                println!("[dns] zone fetch failed: {e} - keeping current zones");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

/// P2-4 [FR-NET-002]: data-plane transport selection.
/// One enum, the carriers: plain TCP relay, QUIC (UDP port = relay port + 1),
/// TLS-TCP (relay port + 3, W14), or auto (QUIC probe, then the W14 chain).
enum RelayChannel {
    Tcp(tokio::net::TcpStream),
    /// W14: TLS 1.3 + mTLS over TCP — same wire protocol as plain TCP
    /// once the handshake completes; never chosen by a TLS *failure*
    /// (SSL-strip guard, w14 plan).
    TlsTcp(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
    Quic {
        // endpoint + conn kept alive: dropping the last endpoint handle
        // tears down the UDP driver and the connection with it
        _endpoint: quinn::Endpoint,
        _conn: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    },
}

impl tokio::io::AsyncRead for RelayChannel {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            RelayChannel::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            RelayChannel::TlsTcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            // quinn streams have inherent poll_* that shadow the trait impls —
            // call the tokio trait explicitly
            RelayChannel::Quic { recv, .. } => {
                <quinn::RecvStream as tokio::io::AsyncRead>::poll_read(
                    std::pin::Pin::new(recv),
                    cx,
                    buf,
                )
            }
        }
    }
}

impl tokio::io::AsyncWrite for RelayChannel {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        match self.get_mut() {
            RelayChannel::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            RelayChannel::TlsTcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            RelayChannel::Quic { send, .. } => {
                <quinn::SendStream as tokio::io::AsyncWrite>::poll_write(
                    std::pin::Pin::new(send),
                    cx,
                    buf,
                )
            }
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.get_mut() {
            RelayChannel::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            RelayChannel::TlsTcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            RelayChannel::Quic { send, .. } => {
                <quinn::SendStream as tokio::io::AsyncWrite>::poll_flush(
                    std::pin::Pin::new(send),
                    cx,
                )
            }
        }
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.get_mut() {
            RelayChannel::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            RelayChannel::TlsTcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            RelayChannel::Quic { send, .. } => {
                <quinn::SendStream as tokio::io::AsyncWrite>::poll_shutdown(
                    std::pin::Pin::new(send),
                    cx,
                )
            }
        }
    }
}

/// Outcome of the gateway's OK ack [W4.4]: `Denied` is authoritative (the
/// gateway parsed and rejected the token — do NOT advance/backoff);
/// `TimedOut`/`Failed` are connection failures (advance/backoff).
enum AckOutcome {
    Ok,
    Denied,
    TimedOut,
    Failed(String),
}

/// Bounded OK-ack read — the old indefinite `read_exact` stalled the first
/// connection whenever a gateway accepted the stream but never acked.
async fn read_ack<S: tokio::io::AsyncRead + Unpin>(
    gw: &mut S,
    to: std::time::Duration,
) -> AckOutcome {
    let mut ack = [0u8; 3]; // "OK\n"
    match tokio::time::timeout(to, gw.read_exact(&mut ack)).await {
        Err(_) => {
            metrics::tunnel_setup_timeouts()
                .with_label_values(&["ack"])
                .inc();
            AckOutcome::TimedOut
        }
        Ok(Err(e)) => AckOutcome::Failed(e.to_string()),
        Ok(Ok(_)) if &ack == b"OK\n" => AckOutcome::Ok,
        Ok(Ok(_)) => AckOutcome::Denied,
    }
}

/// W14: per-relay TLS capability cache (process lifetime) — stops the
/// serve loop re-probing a legacy gateway on every dial. Entries are
/// written ONLY on definitive outcomes (handshake completed = capable,
/// connect refused = absent); a handshake FAILURE proves nothing about
/// the gateway version and is never cached (fail-closed rule below).
fn tls_tcp_known(relay: &str) -> Option<bool> {
    static M: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, bool>>> =
        std::sync::OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock()
        .unwrap()
        .get(relay)
        .copied()
}

fn remember_tls_tcp(relay: &str, capable: bool) {
    static M: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, bool>>> =
        std::sync::OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock()
        .unwrap()
        .insert(relay.to_string(), capable);
}

/// W14 downgrade policy — PURE, unit-pinned. A connection-REFUSED on
/// relay port +3 is the only on-wire legacy signal; falling back to
/// plain TCP on it is allowed only when the controller did not
/// authoritatively promise the carrier (`tls_tcp: true`). With the
/// promise present, refused is an anomaly and must fail CLOSED. Any
/// other TLS failure (handshake error, timeout, cert rejection) NEVER
/// downgrades anywhere — answering it with plaintext is the classic
/// SSL-strip primitive [w14 plan v0.3 review].
fn refused_fallback_allowed(capability: Option<bool>) -> bool {
    capability != Some(true)
}

async fn connect_relay(
    relay: &str,
    transport: TransportKind,
    ca_pem: &str,
    ident: &QuicIdent,
    // W14: the decision's per-gateway `tls_tcp` capability
    // (None = old controller did not send the field).
    tls_capable: Option<bool>,
) -> Result<RelayChannel> {
    let (host, port_s) = relay.rsplit_once(':').context("relay must be host:port")?;
    let port: u16 = port_s.parse()?;
    let dial_to = aztna_common::env_secs("AZTNA_QUIC_DIAL_TIMEOUT_SECS", 5, 1);
    // every plaintext-TCP carrier tick the alertable downgrade counter
    // (with its reason), whichever branch produced it (explicit legacy
    // flag, capability says absent, or the transitional refused heuristic)
    let plain = |reason: &'static str| async {
        metrics::carrier_downgrades_total()
            .with_label_values(&["tls_tcp_to_plain", reason])
            .inc();
        match tokio::time::timeout(dial_to, tokio::net::TcpStream::connect(relay)).await {
            Ok(r) => Ok::<_, anyhow::Error>(RelayChannel::Tcp(r?)),
            Err(_) => {
                metrics::tunnel_setup_timeouts()
                    .with_label_values(&["dial"])
                    .inc();
                bail!("tcp connect timeout after {dial_to:?}")
            }
        }
    };
    // the W14 TLS step, shared by `auto` (after QUIC fails) and `tls-tcp`
    let tls_step = || async {
        if tls_capable == Some(false) || tls_tcp_known(relay) == Some(false) {
            println!("[transport] tls-tcp known-absent for {relay} - plain TCP (counted)");
            return plain("capability_absent").await;
        }
        match tls_tcp_connect(host, port, ca_pem, ident, dial_to).await {
            Ok(Some(c)) => {
                remember_tls_tcp(relay, true);
                println!("[transport] TLS-TCP to {host}:{} (mTLS)", port + 3);
                Ok(c)
            }
            Ok(None) => {
                if !refused_fallback_allowed(tls_capable) {
                    bail!(
                        "tls-tcp refused although the controller promised the carrier - failing closed"
                    );
                }
                remember_tls_tcp(relay, false);
                println!("[transport] tls-tcp refused (legacy gateway) - plain TCP to {relay} (counted downgrade)");
                plain("refused_legacy").await
            }
            Err(e) => Err(
                e.context("tls-tcp handshake failed - NOT downgrading to plain [SSL-strip guard]")
            ),
        }
    };
    match transport {
        TransportKind::Tcp => plain("legacy_flag").await,
        TransportKind::TlsTcp => tls_step().await,
        TransportKind::Quic => Ok(quic_connect(host, port, ca_pem, ident, dial_to).await?),
        TransportKind::Auto => match tokio::time::timeout(
            std::time::Duration::from_millis(1500),
            quic_connect(host, port, ca_pem, ident, dial_to),
        )
        .await
        {
            Ok(Ok(c)) => {
                println!("[transport] QUIC to {host}:{} (udp)", port + 1);
                Ok(c)
            }
            _ => {
                println!("[transport] QUIC unavailable - trying TLS-TCP");
                tls_step().await
            }
        },
    }
}

/// W14 [w14-carrier-mtls]: TLS-TCP carrier — relay port +3, the same
/// tenant-CA mTLS discipline as the QUIC carrier (client cert via the
/// shared tpmtls::Resolver so software AND TPM keys both work). Returns
/// Ok(None) ONLY for connection-refused on P+3 — the positive legacy
/// signal; every other failure is an error the caller must not answer
/// with a plaintext downgrade [SSL-strip guard].
async fn tls_tcp_connect(
    host: &str,
    tcp_port: u16,
    ca_pem: &str,
    ident: &QuicIdent,
    dial_to: std::time::Duration,
) -> Result<Option<RelayChannel>> {
    let mut roots = rustls::RootCertStore::empty();
    let mut pem = std::io::BufReader::new(ca_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut pem) {
        roots.add(cert?)?;
    }
    // W8.2 twin: present the tenant-issued device cert; the gateway's
    // TLS-TCP listener requires it. Resolver path (not
    // with_client_auth_cert) because the signer is a trait object.
    let (certs, key) = identity::tls_client_identity(ident.device.clone(), &ident.cert_pem)
        .inspect_err(|_| metrics::mtls_identity_failures_total().inc())?;
    let certified = Arc::new(rustls::sign::CertifiedKey::new(certs, key));
    // W29 step 6: TPM-signed identities restrict to SHA-256-transcript
    // suites (the TPM signer takes a fixed 32-byte hash — see tpmtls)
    let tls = if ident.device.is_tpm() {
        tpmtls::sha256_only_client_config(roots, certified)
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_cert_resolver(Arc::new(tpmtls::Resolver { key: certified }))
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
    // gateway TLS-TCP listener = relay TCP port + 3 [W14 port scheme]
    let addr = match tokio::net::lookup_host((host, tcp_port)).await?.next() {
        Some(mut a) => {
            a.set_port(tcp_port + 3);
            a
        }
        None => bail!("cannot resolve relay host {host}"),
    };
    let sock = match tokio::time::timeout(dial_to, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Ok(None),
        Ok(Err(e)) => bail!("tls-tcp connect {addr}: {e}"),
        Err(_) => {
            metrics::tunnel_setup_timeouts()
                .with_label_values(&["dial"])
                .inc();
            bail!("tls-tcp connect timeout after {dial_to:?}")
        }
    };
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid server name {host}"))?;
    let stream = match tokio::time::timeout(dial_to, connector.connect(name, sock)).await {
        Ok(r) => r?,
        Err(_) => {
            metrics::tunnel_setup_timeouts()
                .with_label_values(&["dial"])
                .inc();
            bail!("tls-tcp handshake timeout after {dial_to:?}")
        }
    };
    Ok(Some(RelayChannel::TlsTcp(stream)))
}

async fn quic_connect(
    host: &str,
    tcp_port: u16,
    ca_pem: &str,
    ident: &QuicIdent,
    dial_to: std::time::Duration,
) -> Result<RelayChannel> {
    // W14: the dial is one definition (quic_dial) — the stream carrier
    // opens a bi-stream on it; the UDP-app carrier reuses the connection.
    let (endpoint, conn) = quic_dial(host, tcp_port, ca_pem, ident, dial_to).await?;
    let (send, recv) = conn.open_bi().await?;
    Ok(RelayChannel::Quic {
        _endpoint: endpoint,
        _conn: conn,
        send,
        recv,
    })
}

/// W6.2: re-login hint for session-ended denies (revoked by admin, idle
/// expiry, or self-logout) — sibling of the X5 step-up hint. Pure so the
/// trigger set is unit-testable.
fn session_end_hint(deny_body: &str) -> Option<&'static str> {
    if deny_body.contains("session revoked") || deny_body.contains("session idle") {
        Some("session ended - re-login required (login --code <code>[-mfa])")
    } else {
        None
    }
}

// W29: tests that pin AZTNA_STATE_DIR serialize on this mutex — the env
// is process-global and the tokenstore/w82 tests both read it.
#[cfg(test)]
pub(crate) static TEST_STATE_ENV_SER: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_end_hint_triggers_only_on_session_ended_denies() {
        assert!(session_end_hint(r#"{"error":"session revoked"}"#).is_some());
        assert!(session_end_hint(r#"{"error":"session idle"}"#).is_some());
        assert_eq!(session_end_hint(r#"{"error":"no policy"}"#), None);
        assert_eq!(session_end_hint("step-up required"), None);
        assert!(session_end_hint("{}").is_none());
    }

    /// W6.3: only 401/403 deny a zone refresh (→ clear map + abort
    /// forwarders); everything else — including 5xx — keeps the last-known
    /// map (fail-safe serving). The 403 body's reason drives the label.
    #[test]
    fn zone_denial_reason_classifies() {
        assert_eq!(zone_denial_reason(401, ""), Some("unauthorized"));
        assert_eq!(
            zone_denial_reason(403, r#"{"error":"session revoked"}"#),
            Some("revoked")
        );
        assert_eq!(
            zone_denial_reason(403, r#"{"error":"session idle"}"#),
            Some("idle")
        );
        assert_eq!(zone_denial_reason(403, "other"), Some("unauthorized"));
        // not a denial: transient/server statuses and success
        assert_eq!(zone_denial_reason(500, "boom"), None);
        assert_eq!(zone_denial_reason(503, ""), None);
        assert_eq!(zone_denial_reason(200, ""), None);
    }

    /// W4.4 ack-stage contract: "OK\n" ok; other bytes = authoritative DENY
    /// (no backoff); silence past the deadline = TimedOut; early close =
    /// Failed. All bounded — none may hang.
    #[tokio::test]
    async fn read_ack_outcomes() {
        // OK
        let (mut c, mut s) = tokio::io::duplex(64);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            use tokio::io::AsyncWriteExt;
            let _ = s.write_all(b"OK\n").await;
        });
        assert!(matches!(
            read_ack(&mut c, std::time::Duration::from_secs(2)).await,
            AckOutcome::Ok
        ));

        // Denied (authoritative)
        let (mut c, mut s) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = s.write_all(b"NO!").await;
        });
        assert!(matches!(
            read_ack(&mut c, std::time::Duration::from_secs(2)).await,
            AckOutcome::Denied
        ));

        // Timed out (silent peer) — bounded, not indefinite
        let (mut c, _s) = tokio::io::duplex(64);
        let t0 = std::time::Instant::now();
        let out = read_ack(&mut c, std::time::Duration::from_millis(200)).await;
        assert!(matches!(out, AckOutcome::TimedOut));
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(2),
            "must not hang"
        );

        // Failed (peer closed before ack)
        let (mut c, s) = tokio::io::duplex(64);
        drop(s);
        assert!(matches!(
            read_ack(&mut c, std::time::Duration::from_secs(2)).await,
            AckOutcome::Failed(_)
        ));
    }

    /// W4.4: the decision POST is bounded — a controller that accepts and
    /// never answers must produce an error within the timeout, not a hang.
    #[tokio::test]
    async fn decision_post_is_bounded() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            // accept and deliberately never respond (deaf controller)
            if let Ok((sock, _)) = l.accept().await {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                drop(sock);
            }
        });
        let client = reqwest::Client::new();
        let to = std::time::Duration::from_millis(300);
        let fut = client
            .post(format!("http://{addr}/v1/access"))
            .json(&serde_json::json!({"ip": "127.0.0.220", "port": 28080}))
            .send();
        let t0 = std::time::Instant::now();
        let out = tokio::time::timeout(to, fut).await;
        assert!(out.is_err(), "deaf controller must hit the timeout");
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(2),
            "bounded, not 30s"
        );
    }

    /// W14S2 fix step 3 (H5a/b): a flow's owned session entries die with
    /// the flow — pruning by sid removes BOTH maps' entries; raw flows
    /// (None) prune nothing and leave other sids untouched.
    #[test]
    fn prune_session_entries_removes_both_maps() {
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        let sids: Arc<Mutex<HashMap<u32, std::net::SocketAddr>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let reasms: Arc<Mutex<HashMap<u32, aztna_common::udp_frag::Reassembler>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let peer: std::net::SocketAddr = "127.0.0.1:51000".parse().unwrap();
        sids.lock().unwrap().insert(7, peer);
        reasms
            .lock()
            .unwrap()
            .insert(7, aztna_common::udp_frag::Reassembler::new(16, 256 * 1024));
        sids.lock().unwrap().insert(9, peer); // a different flow's sid survives
        prune_session_entries(Some(7), &sids, &reasms);
        assert!(!sids.lock().unwrap().contains_key(&7));
        assert!(!reasms.lock().unwrap().contains_key(&7));
        assert!(
            sids.lock().unwrap().contains_key(&9),
            "unrelated sid survives"
        );
        // None (raw carrier / no flow) is a no-op
        prune_session_entries(None, &sids, &reasms);
        assert!(sids.lock().unwrap().contains_key(&9));
        // already-pruned sid: idempotent
        prune_session_entries(Some(7), &sids, &reasms);
        assert!(sids.lock().unwrap().contains_key(&9));
    }

    /// Regression test for the hex-decode index bug that produced
    /// three distinct Ed25519 keys per enrollment [P2-1 root cause].
    #[test]
    fn posture_key_hex_round_trip() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let hexs: String = sk.to_bytes().iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(hexs.len(), 64);
        let seed = seed_from_hex(&hexs).expect("decode");
        assert_eq!(seed, sk.to_bytes(), "round-trip must preserve seed bytes");
        let reloaded = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(
            reloaded.verifying_key(),
            sk.verifying_key(),
            "public key must survive encode/decode round-trip"
        );
    }

    #[test]
    fn posture_key_rejects_bad_length() {
        assert!(seed_from_hex("abcd").is_err());
        assert!(seed_from_hex(&"a".repeat(63)).is_err());
        assert!(seed_from_hex(&"a".repeat(65)).is_err());
    }

    /// W3.4: values-hash must be stable across timestamps (change detection
    /// keys on VALUES, not collection time) and flip on any value change.
    #[test]
    fn posture_values_hash_change_detection() {
        let h1 = posture_values_hash(true, true, true, true, "Windows 11 26200", 3, "0.1.0");
        let h2 = posture_values_hash(true, true, true, true, "Windows 11 26200", 3, "0.1.0");
        assert_eq!(h1, h2, "identical values -> identical hash");
        assert_eq!(h1.len(), 64, "sha256 hex");

        // degradation flips the hash (kill-order latency preserved)
        let degraded = posture_values_hash(true, false, true, true, "Windows 11 26200", 3, "0.1.0");
        assert_ne!(h1, degraded, "defender_off must change the hash");

        // os/patch-age drift flips it too
        let drifted = posture_values_hash(true, true, true, true, "Windows 11 26200", 40, "0.1.0");
        assert_ne!(h1, drifted);

        // hash_of_report extracts the same fields as the direct fn
        let report = serde_json::json!({
            "collected_at": 111, "bitlocker_on": true, "defender_healthy": true,
            "firewall_enabled": true, "entra_joined": true,
            "os_version": "Windows 11 26200", "days_since_patch": 3,
            "client_version": "0.1.0", "sig_b64": "xx"
        });
        assert_eq!(hash_of_report(&report).as_deref(), Some(h1.as_str()));
        let report_later = serde_json::json!({
            "collected_at": 999, "bitlocker_on": true, "defender_healthy": true,
            "firewall_enabled": true, "entra_joined": true,
            "os_version": "Windows 11 26200", "days_since_patch": 3,
            "client_version": "0.1.0", "sig_b64": "yy"
        });
        assert_eq!(
            hash_of_report(&report_later),
            hash_of_report(&report),
            "ts/sig excluded from the values-hash"
        );
    }

    /// W5.1: local cert-expiry parsing (status display + renew's runway
    /// checks) against a self-signed cert with a known not_after, plus the
    /// day-math edges (0-day, expired → negative, 4096-era pre-W5.1 certs).
    #[test]
    fn cert_expiry_parsing_and_day_math() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["exp-test".try_into().unwrap()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "exp-test");
        // +1h buffer keeps the integer-day floor stable against test runtime
        let target =
            time::OffsetDateTime::now_utc() + time::Duration::days(10) + time::Duration::hours(1);
        params.not_after = target;
        let pem = params.self_signed(&key).unwrap().pem();
        let parsed = cert_expiry_unix(&pem).unwrap();
        assert!(
            (parsed - target.unix_timestamp()).abs() < 5,
            "parsed not_after must match the issued one"
        );
        assert!(cert_expiry_unix("not a pem").is_err());

        // day math (pure)
        assert_eq!(cert_days_remaining(0, 86_400), 1);
        assert_eq!(cert_days_remaining(86_400, 86_400), 0);
        assert_eq!(
            cert_days_remaining(100_000, 86_400),
            -1,
            "expired → negative"
        );
        // pre-W5.1 certs (rcgen default not_after = 4096-01-01) parse and
        // report a huge runway
        let y4096 = time::OffsetDateTime::from_unix_timestamp(67_090_118_400).unwrap();
        assert_eq!(y4096.year(), 4096);
        assert!(cert_days_remaining(0, y4096.unix_timestamp()) > 700_000);

        // status line rendering carries the days and the RFC3339 year
        let line = cert_expiry_line(&pem);
        assert!(line.contains("(10 days)"), "line was: {line}");
        assert!(
            line.contains(&target.year().to_string()),
            "line was: {line}"
        );
    }

    /// W5.1: a CSR rebuilt from the SAME software identity key keeps the
    /// SPKI hash — the client-side half of the renewal identity contract
    /// (controller-side twin: ca::renewal_keeps_spki_id_and_extends_validity).
    #[test]
    fn renew_csr_from_same_key_keeps_spki() {
        use sha2::Digest;
        // W29 unix: this test opens device keys — serialize against the
        // TPM-env tests (a poisoned AZTNA_TPM2_TCTI window fail-closes
        // identity open elsewhere). W30: TPM_ENV is Linux-only.
        #[cfg(target_os = "linux")]
        let _tpm = crate::tpm::TPM_ENV.lock().unwrap();
        fn spki_hash(csr_pem: &str) -> String {
            use asn1_rs::FromDer;
            let (_, pem) = x509_parser::pem::parse_x509_pem(csr_pem.as_bytes()).unwrap();
            let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(
                &pem.contents,
            )
            .unwrap();
            sha2::Sha256::digest(
                csr.certification_request_info
                    .subject_pki
                    .subject_public_key
                    .data
                    .as_ref(),
            )
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
        }
        let tag = std::process::id();
        let dir = std::env::temp_dir().join(format!("aztna-cli-renew-{tag}-a"));
        std::fs::create_dir_all(&dir).unwrap();
        // W29 unix: identity at-rest hygiene requires 0700 state dirs
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        // force the software path: this env is read at open_or_create time
        std::env::set_var("AZTNA_KEY_ORIGIN", "software");
        let key = identity::DeviceKey::open_or_create(&dir).unwrap();
        let csr1 = key.build_csr_pem("host-a").unwrap();
        let csr2 = key.build_csr_pem("host-b").unwrap(); // CN may differ: SPKI is the identity
                                                         // a different key must differ (guards a trivially-constant hash fn)
        let dir2 = std::env::temp_dir().join(format!("aztna-cli-renew-{tag}-b"));
        std::fs::create_dir_all(&dir2).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir2, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let other = identity::DeviceKey::open_or_create(&dir2).unwrap();
        std::env::remove_var("AZTNA_KEY_ORIGIN");
        assert_eq!(
            spki_hash(&csr1),
            spki_hash(&csr2),
            "same key ⇒ same SPKI hash"
        );
        let csr3 = other.build_csr_pem("host-a").unwrap();
        assert_ne!(spki_hash(&csr1), spki_hash(&csr3));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }
}

#[cfg(test)]
mod w81_udp_tests {
    use super::*;

    /// The session-establishing datagram carries the header + payload in
    /// ONE datagram (header rides only this packet).
    #[test]
    fn first_datagram_encoding() {
        let d = build_first_datagram("QUJD", "h:1", b"PAY");
        assert_eq!(&d[..16], b"TOKEN QUJD DEST ");
        assert!(d.starts_with(
            b"TOKEN QUJD DEST h:1
"
        ));
        assert_eq!(&d[d.len() - 3..], b"PAY");
        // empty payload = header-only datagram (still valid)
        let h = build_first_datagram("QUJD", "h:1", b"");
        assert!(h.ends_with(
            b"
"
        ));
    }

    /// Flow liveness: TTL lapse and idle both drop the flow; the client
    /// idle window is what forces proactive (fresh-decision)
    /// re-establishment before the gateway reaps.
    #[test]
    fn flow_liveness_boundaries() {
        let idle = std::time::Duration::from_secs(20);
        let far_future = unix_now() + 3600;
        assert!(
            udp_flow_live(far_future, std::time::Instant::now(), idle),
            "fresh flow live"
        );
        assert!(
            !udp_flow_live(unix_now() - 1, std::time::Instant::now(), idle),
            "expired token dead"
        );
        // idle boundary: bracket with a 0s window instead of racing the
        // clock (the d1debd2 lesson — exact equality vs a re-read clock
        // is a flake by construction)
        assert!(
            !udp_flow_live(
                far_future,
                std::time::Instant::now(),
                std::time::Duration::from_secs(0)
            ),
            "idle-zero dead"
        );
    }
}

/// W8.2 client-side pins: the untouched software controller path builds,
/// and a certified-less state is a hard, metered QUIC-identity error.
#[cfg(test)]
mod w82_quic_mtls_tests {
    use super::*;

    /// Review-round-1 pin: mtls_client's SOFTWARE branch still builds a
    /// reqwest client (the controller path is untouched by construction;
    /// this test is the belt to those braces). Uses an env-scoped temp
    /// state dir serialized on TEST_STATE_ENV_SER (W29: the tokenstore
    /// tests now also read AZTNA_STATE_DIR — the env is process-global).
    #[tokio::test]
    async fn mtls_client_software_branch_still_builds() {
        let _env = TEST_STATE_ENV_SER.lock().unwrap();
        // W29 unix: opens a device key — see renew_csr test note.
        // W30: TPM_ENV is Linux-only.
        #[cfg(target_os = "linux")]
        let _tpm = crate::tpm::TPM_ENV.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("aztna-mtls-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // W29 unix: at-rest hygiene requires 0700
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let prev = std::env::var("AZTNA_STATE_DIR").ok();
        std::env::set_var("AZTNA_STATE_DIR", &dir);
        // device key first, then a cert issued over that exact key
        let device = identity::DeviceKey::open_or_create(&dir).unwrap();
        let identity::KeyKind::Software { key_pem } = &device.kind else {
            panic!("test env must yield a software key");
        };
        let pair = rcgen::KeyPair::from_pem(key_pem).unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "mtls-pin");
        let cert = params.self_signed(&pair).unwrap();
        let st = ClientState {
            controller_url: "https://127.0.0.1:1".into(),
            controller_enroll_url: None,
            device_id: Some("d1".into()),
            cert_pem: Some(cert.pem()),
            access_token: None,
            access_token_wrapped: None,
            posture_pubkey: None,
            ca_pem: Some(cert.pem()), // self-signed = its own trust root here
            key_origin: Some("software".into()),
            mgmt_url: None,
        };
        let client = mtls_client(&st);
        match prev {
            Some(v) => std::env::set_var("AZTNA_STATE_DIR", v),
            None => std::env::remove_var("AZTNA_STATE_DIR"),
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(client.is_ok(), "software branch must build: {client:?}");
    }

    /// A certified-less state is a hard, metered error for the QUIC
    /// identity (bail BEFORE touching the key store).
    #[test]
    fn quic_ident_open_requires_cert() {
        let st = ClientState {
            controller_url: String::new(),
            controller_enroll_url: None,
            device_id: None,
            cert_pem: None,
            access_token: None,
            access_token_wrapped: None,
            posture_pubkey: None,
            ca_pem: None,
            key_origin: None,
            mgmt_url: None,
        };
        let err = QuicIdent::open(&st).unwrap_err().to_string();
        assert!(
            err.contains("device certificate missing"),
            "error must name the missing material: {err}"
        );
    }

    /// W14 downgrade policy matrix [w14 plan v0.3 review]: connection-
    /// refused is the ONLY on-wire legacy signal, and falling back to
    /// plain TCP on it is allowed only without an authoritative
    /// controller promise. TLS failures never downgrade anywhere.
    #[test]
    fn w14_refused_downgrade_policy_matrix() {
        // old controller (field absent) — transitional heuristic applies
        assert!(refused_fallback_allowed(None));
        // controller explicitly says legacy — refused is expected
        assert!(refused_fallback_allowed(Some(false)));
        // controller PROMISED the carrier — refused is an anomaly: the
        // client must fail closed, not silently ride plaintext
        assert!(!refused_fallback_allowed(Some(true)));
    }
}

/// W13 step 3: delegate for the service bin (last notify text).
pub fn svc_last_event() -> String {
    svc::last_event_text()
}

/// W13 step 3: shared client for one-word IPC commands.
async fn ipc_simple(cmd: &'static str) -> Result<()> {
    let cfg = svc::load_config().ok();
    let bind = cfg
        .map(|c| c.ipc_bind)
        .unwrap_or_else(|| "127.0.0.1:29171".into());
    match svc::ipc_call(
        &bind,
        &svc::IpcReq {
            v: 1,
            cmd: cmd.into(),
            token: None,
        },
    )
    .await
    {
        Ok(r) if r.ok => {
            println!("service {cmd}: ok ({})", r.state);
            Ok(())
        }
        Ok(r) => bail!("service {cmd} rejected: {}", r.error.unwrap_or_default()),
        Err(e) => bail!("service unreachable: {e:#}"),
    }
}
