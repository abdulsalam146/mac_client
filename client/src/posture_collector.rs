//! W3.1 [architecture 5.1 posture]: REAL posture collectors via WMI.
//! Every probe degrades to `None` on any failure — unknown ≠ unhealthy
//! [plan W3.1: only an explicit false denies]. `AZTNA_SIMULATE` (handled by
//! the caller, not here) remains the documented test hook that overrides
//! the booleans.

// W29: the Deserialize derive is only used by the WMI result structs
#[cfg(windows)]
use serde::Deserialize;

/// Collected facts; `None` = could not determine (fail-open at the gate).
#[derive(Clone)]
pub struct Snapshot {
    pub bitlocker_on: Option<bool>,
    pub defender_healthy: Option<bool>,
    pub firewall_enabled: Option<bool>,
    pub os_version: Option<String>,
    pub days_since_patch: Option<i64>,
    /// W29: detected enterprise/domain integration on Linux (realm/sssd).
    /// Windows collects nothing here (None) — the report builder keeps
    /// its historical hardcoded `true` there, so Windows output is
    /// byte-identical before/after this field existed.
    pub domain_joined: Option<bool>,
    /// W14S2 fix step 1: slot state this snapshot was SERVED from —
    /// `None` = empty slot (never collected this process), `Some(age)` =
    /// age of the slot read in seconds. Stamped at slot-read time (never
    /// by the raw collect) so classification is snapshot-consistent; see
    /// `slot_class`.
    pub slot_age_secs: Option<i64>,
}

impl Snapshot {
    /// W14S2 fix step 1 (plan §4.2): report-classification label for
    /// `aztna_client_posture_reports_total` — "empty" (benign cold start),
    /// "stale" (collector/reporter stalled — serves last-good silently;
    /// the actionable case), "fresh".
    pub fn slot_class(&self) -> &'static str {
        match self.slot_age_secs {
            None => "empty",
            Some(a) if a < TTL_SECS as i64 => "fresh",
            Some(_) => "stale",
        }
    }
}

pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Cache TTL. Refresh happens in a background worker; the hot path NEVER
/// joins it. WMI does its own COM init, which must NOT happen on tokio
/// worker threads — and, measured on the dev box (Step 1 of the W4.4-stall
/// investigation), a cold collect takes 7.5-9.2s: joining it inline was the
/// first-connection stall (a connection arriving mid-collect blocked on the
/// cache mutex for up to ~6s — the suite's ~8s stall class).
const TTL_SECS: u64 = 30;
/// A worker wedged longer than this is orphaned (never joined) so refreshes
/// keep flowing; the orphan counts as a collection failure.
const COLLECT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

static SLOT: std::sync::Mutex<Option<(std::time::Instant, Snapshot)>> = std::sync::Mutex::new(None);
static COLLECTING: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);

/// Hot-path read: last-good snapshot, never blocks on WMI. Kicks the
/// background worker when the slot is stale. Never-collected ⇒ unknown
/// values (fail-open at the gate, visible via the age gauge).
pub fn collect_cached() -> Snapshot {
    let (mut snap, age) = {
        let g = SLOT.lock().unwrap();
        match g.as_ref() {
            Some((at, s)) => (s.clone(), at.elapsed().as_secs() as i64),
            None => (Snapshot::unknown(), -1),
        }
    };
    // W14S2 fix step 1: stamp the slot state ON the served snapshot (plan
    // §4.2 — classify at the source, never from a separate gauge read).
    snap.slot_age_secs = if age < 0 { None } else { Some(age) };
    crate::metrics::posture_last_collect_age().set(age);
    maybe_spawn_refresh(collect);
    snap
}

/// Fire-and-forget refresh kick for startup paths (login, serve): NEVER
/// blocks the caller and NEVER delays listener binding — the collect lands
/// in the background while the process keeps serving last-good/unknown.
pub fn kick_refresh() {
    maybe_spawn_refresh(collect);
}

/// One-shot path only (not the serve hot path): a single access is latency-
/// tolerant but correctness-sensitive — W3.1 requires REAL collected values
/// in the decision-time report. Wait (bounded, polling the slot — never a
/// join) for the background collect to land; past the ceiling serve
/// last-good/unknown. A hung WMI costs the ceiling, nothing more.
pub fn collect_fresh_bounded(max: std::time::Duration) -> Snapshot {
    let deadline = std::time::Instant::now() + max;
    loop {
        maybe_spawn_refresh(collect);
        {
            let g = SLOT.lock().unwrap();
            if let Some((at, s)) = g.as_ref() {
                if at.elapsed().as_secs() < TTL_SECS {
                    let mut s = s.clone();
                    // W14S2 fix step 1: slot-state stamp (plan §4.2)
                    s.slot_age_secs = Some(at.elapsed().as_secs() as i64);
                    crate::metrics::posture_last_collect_age().set(at.elapsed().as_secs() as i64);
                    return s;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            let (mut s, age) = {
                let g = SLOT.lock().unwrap();
                match g.as_ref() {
                    Some((at, s)) => (s.clone(), Some(at.elapsed().as_secs() as i64)),
                    None => (Snapshot::unknown(), None),
                }
            };
            // W14S2 fix step 1: slot-state stamp on the ceiling path too
            // (stale-served or empty — exactly the report class
            // posture_reports_total{slot} exists to expose).
            s.slot_age_secs = age;
            crate::metrics::posture_last_collect_age().set(-1);
            return s;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn maybe_spawn_refresh(collect_fn: fn() -> Snapshot) {
    let stale = {
        let g = SLOT.lock().unwrap();
        match g.as_ref() {
            Some((at, _)) => at.elapsed().as_secs() >= TTL_SECS,
            None => true,
        }
    };
    if !stale {
        return;
    }
    let mut c = COLLECTING.lock().unwrap();
    if let Some(t0) = *c {
        if t0.elapsed() < COLLECT_DEADLINE {
            return; // a fresh worker is already on it
        }
        // wedged past the deadline: orphan it (never joined) and retry
        crate::metrics::posture_collect_failures().inc();
        println!(
            "[posture] collect worker exceeded {:?} - orphaned",
            COLLECT_DEADLINE
        );
    }
    *c = Some(std::time::Instant::now());
    drop(c);
    std::thread::spawn(move || run_worker(collect_fn));
}

fn run_worker(collect_fn: fn() -> Snapshot) {
    let t0 = std::time::Instant::now();
    let result = std::panic::catch_unwind(collect_fn);
    // clear the in-flight marker FIRST so a panic still unblocks refreshes
    *COLLECTING.lock().unwrap() = None;
    // W14S2 fix step 1: collect duration + timestamped event — the
    // diagnostic pair for the W14S2 stall regime (idle ~7 s vs loaded 15 s+)
    let elapsed_ms = t0.elapsed().as_millis();
    crate::metrics::posture_collect_seconds().observe(t0.elapsed().as_secs_f64());
    match result {
        Ok(s) => {
            *SLOT.lock().unwrap() = Some((std::time::Instant::now(), s));
            println!("[posture] collected in {}ms", elapsed_ms);
            crate::log_event("posture_collect", &format!("ok {elapsed_ms}ms"));
        }
        Err(_) => {
            crate::metrics::posture_collect_failures().inc();
            println!("[posture] collect panicked - serving last-good/unknown");
            crate::log_event("posture_collect", &format!("panic {elapsed_ms}ms"));
        }
    }
}

#[cfg(test)]
pub(crate) fn reset_slots() {
    *SLOT.lock().unwrap() = None;
    *COLLECTING.lock().unwrap() = None;
}

impl Snapshot {
    fn unknown() -> Self {
        Snapshot {
            bitlocker_on: None,
            defender_healthy: None,
            firewall_enabled: None,
            os_version: None,
            days_since_patch: None,
            domain_joined: None,
            slot_age_secs: None,
        }
    }
}

pub fn collect() -> Snapshot {
    log_mapping_once();
    Snapshot {
        bitlocker_on: bitlocker(),
        defender_healthy: defender(),
        firewall_enabled: firewall(),
        os_version: os_version_text(),
        days_since_patch: patch_age_days(),
        domain_joined: domain_joined(),
        // placeholder — the true slot age is stamped when this snapshot is
        // SERVED from the slot (collect_cached / collect_fresh_bounded)
        slot_age_secs: Some(0),
    }
}

/// Per-OS mapping-event dispatch (W30 step 4: macOS joins the
/// one-time-visibility convention with its own semantics block).
#[cfg(windows)]
fn log_mapping_once() {}

#[cfg(target_os = "linux")]
fn log_mapping_once() {
    log_linux_mapping_once();
}

#[cfg(target_os = "macos")]
fn log_mapping_once() {
    log_macos_mapping_once();
}

/// Windows: "Caption (build N)". Linux: "PRETTY_NAME (kernel R)".
#[cfg(windows)]
fn os_version_text() -> Option<String> {
    os_build().map(|(caption, build)| format!("{caption} (build {build})"))
}

/// Linux: "PRETTY_NAME (kernel R)". macOS: "ProductName ProductVersion
/// (build B)". Windows: "Caption (build N)".
#[cfg(target_os = "linux")]
fn os_version_text() -> Option<String> {
    os_build().map(|(pretty, kernel)| format!("{pretty} (kernel {kernel})"))
}

#[cfg(target_os = "macos")]
fn os_version_text() -> Option<String> {
    os_build().map(|(name, ver, build)| format!("{name} {ver} (build {build})"))
}

/// Linux: the realm/sssd domain-integration signal. Windows: None (the
/// report builder's historical `true`).
#[cfg(windows)]
fn domain_joined() -> Option<bool> {
    None
}

#[cfg(not(windows))]
fn domain_joined() -> Option<bool> {
    entra_joined()
}

// ---------- Windows collectors (WMI) ----------

#[cfg(windows)]
fn con(ns: &str) -> anyhow::Result<wmi::WMIConnection> {
    let com = wmi::COMLibrary::new()?;
    Ok(wmi::WMIConnection::with_namespace_path(ns, com)?)
}

/// OS caption + build (Win32_OperatingSystem).
#[cfg(windows)]
fn os_build() -> Option<(String, String)> {
    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct Os {
        Caption: String,
        BuildNumber: String,
    }
    let w = con("ROOT\\CIMV2").ok()?;
    let v: Vec<Os> = w
        .raw_query("SELECT Caption, BuildNumber FROM Win32_OperatingSystem")
        .ok()?;
    let o = v.into_iter().next()?;
    Some((o.Caption, o.BuildNumber))
}

/// Days since the newest installed hotfix (Win32_QuickFixEngineering).
/// InstalledOn is a WMI DATETIME ("20260812000000.000000+060") or a plain
/// date string depending on source — take the leading 8 digits.
#[cfg(windows)]
fn patch_age_days() -> Option<i64> {
    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct Qfe {
        InstalledOn: Option<String>,
    }
    let w = con("ROOT\\CIMV2").ok()?;
    let v: Vec<Qfe> = w
        .raw_query("SELECT InstalledOn FROM Win32_QuickFixEngineering")
        .ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let latest = v
        .into_iter()
        .filter_map(|q| q.InstalledOn)
        .filter_map(|s| {
            let d: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
            if d.len() < 8 {
                return None;
            }
            let (y, m, day) = (&d[0..4], &d[4..6], &d[6..8]);
            date_to_unix(y.parse().ok()?, m.parse().ok()?, day.parse().ok()?)
        })
        .max()?;
    Some((now - latest) / 86_400)
}

#[cfg(windows)]
fn date_to_unix(y: i64, m: i64, d: i64) -> Option<i64> {
    // days-from-civil (Howard Hinnant) — good enough for age math
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146_097 + doe - 719_468) * 86_400)
}

/// All firewall profiles enabled (root\standardcimv2 FirewallProfile).
#[cfg(windows)]
fn firewall() -> Option<bool> {
    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct Fp {
        Enabled: bool,
    }
    let w = con("ROOT\\standardcimv2").ok()?;
    let v: Vec<Fp> = w.raw_query("SELECT Enabled FROM FirewallProfile").ok()?;
    if v.is_empty() {
        return None;
    }
    Some(v.into_iter().all(|p| p.Enabled))
}

/// OS volume BitLocker protection (Win32_EncryptableVolume; admin needed).
#[cfg(windows)]
fn bitlocker() -> Option<bool> {
    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct Vol {
        ProtectionStatus: u32,
    }
    let sys = std::env::var("SYSTEMDRIVE").unwrap_or_else(|_| "C:".into());
    let w = con("ROOT\\CIMV2\\security\\MicrosoftVolumeEncryption").ok()?;
    let v: Vec<Vol> = w
        .raw_query(format!(
            "SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter='{sys}'"
        ))
        .ok()?;
    let vol = v.into_iter().next()?;
    Some(vol.ProtectionStatus == 1)
}

/// Defender enabled + up to date (root\SecurityCenter2 productState decode:
/// bit 0x1000 = enabled, bit 0x10 = outdated — workstation-only namespace).
#[cfg(windows)]
fn defender() -> Option<bool> {
    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct Av {
        displayName: String,
        productState: u32,
    }
    let w = con("ROOT\\SecurityCenter2").ok()?;
    let v: Vec<Av> = w
        .raw_query("SELECT displayName, productState FROM AntivirusProduct")
        .ok()?;
    let d = v
        .into_iter()
        .find(|a| a.displayName.to_lowercase().contains("defender"))?;
    let enabled = d.productState & 0x1000 != 0;
    let outdated = d.productState & 0x10 != 0;
    Some(enabled && !outdated)
}

// ---------- Linux collectors (W29 step 3) ----------
// Same wire, Linux semantics, LOWER FIDELITY — stated for policy authors
// (plan §3.3, user-guide + FEATURES carry the caveat text):
//   bitlocker_on    -> root-disk crypto chain contains a dm-crypt layer
//                      (lsblk over the root source; "encrypted root disk")
//   defender_healthy-> None always: no AV/EDR concept in the protocol for
//                      Linux; None = unknown, and the gate fails OPEN
//                      (true) — the field means "no endpoint-protection
//                      FAILURE signal", not "protection present". Closes
//                      when the W24 adapter framework gains a Linux EDR
//                      collector (gap-register).
//   firewall_enabled-> "a firewall SERVICE is active" (nftables/ufw/
//                      firewalld via systemctl), NOT effective-firewall
//                      proof (rules can exist without the service, e.g.
//                      docker-loaded nft) — service-level signal only.
//   entra_joined   -> "detected enterprise/domain integration" (sssd
//                      config present or `realm list` shows a joined
//                      domain) — NOT Microsoft Entra device registration.
//   days_since_patch-> package-DB mtime (dpkg-status / rpm db) — a PROXY
//                      for patch age: the DB is touched by any package
//                      operation, security or not.
// Unknown (None) never denies — only an explicit false does (the W3.1
// gate convention, identical to the Windows collector's WMI failures).

/// One-time visibility: the mapping is logged when the first Linux
/// snapshot is built, so the semantics above are in the log stream, not
/// just in docs.
#[cfg(target_os = "linux")]
fn log_linux_mapping_once() {
    use std::sync::OnceLock;
    static DONE: OnceLock<()> = OnceLock::new();
    if DONE.set(()).is_ok() {
        crate::log_event(
            "posture_collector_linux",
            "bitlocker_on=root-disk-crypt(lsblk) defender_healthy=unknown-fail-open \
             firewall_enabled=service-active(systemctl) entra_joined=domain-integration(realm/sssd) \
             days_since_patch=package-db-mtime-proxy",
        );
    }
}

/// (PRETTY_NAME from /etc/os-release, kernel release from /proc/sys).
#[cfg(target_os = "linux")]
fn os_build() -> Option<(String, String)> {
    os_build_from(
        &std::fs::read_to_string("/etc/os-release").ok()?,
        &std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?,
    )
}

#[cfg(target_os = "linux")]
fn os_build_from(os_release: &str, osrelease_sys: &str) -> Option<(String, String)> {
    let pretty = os_release
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim().trim_matches('"').to_string())
        .or_else(|| {
            os_release
                .lines()
                .find_map(|l| l.strip_prefix("NAME="))
                .map(|v| v.trim().trim_matches('"').to_string())
        })?;
    let kernel = osrelease_sys.trim();
    if pretty.is_empty() || kernel.is_empty() {
        return None;
    }
    Some((pretty, kernel.to_string()))
}

#[cfg(target_os = "linux")]
fn patch_age_days() -> Option<i64> {
    // first existing package DB, Debian-family then RPM-family (Rocky 9
    // uses rpmdb.sqlite; legacy bdb is Packages)
    let path = [
        "/var/lib/dpkg/status",
        "/var/lib/rpm/rpmdb.sqlite",
        "/var/lib/rpm/Packages",
    ]
    .iter()
    .find(|p| std::path::Path::new(p).exists())?;
    let mtime = std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some(patch_age_from(now, mtime))
}

/// Pure age math: clock skew (mtime in the future) clamps to 0 days.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn patch_age_from(now_unix: i64, mtime_unix: i64) -> i64 {
    ((now_unix - mtime_unix) / 86_400).max(0)
}

#[cfg(target_os = "linux")]
fn firewall() -> Option<bool> {
    let out = run_capture(
        "systemctl",
        &["is-active", "nftables", "ufw", "firewalld"],
        std::time::Duration::from_secs(3),
    )?;
    firewall_from(&out)
}

/// `systemctl is-active a b c` prints one state per unit; ANY "active"
/// line counts (the service-level signal documented above). Whitespace-
/// only output = nothing reported = undeterminable.
#[cfg(target_os = "linux")]
fn firewall_from(is_active_output: &str) -> Option<bool> {
    let states: Vec<&str> = is_active_output
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if states.is_empty() {
        return None;
    }
    Some(states.contains(&"active"))
}

/// Root-disk crypto: the device chain under the root mount source must
/// contain a dm-crypt layer. Pure core parses /proc/self/mounts +
/// `lsblk -o TYPE` output; `None` when either input is unavailable.
#[cfg(target_os = "linux")]
fn bitlocker() -> Option<bool> {
    let mounts = std::fs::read_to_string("/proc/self/mounts").ok()?;
    let root_src = root_mount_source(&mounts)?;
    let types = run_capture(
        "lsblk",
        &["-no", "TYPE", &root_src],
        std::time::Duration::from_secs(3),
    )?;
    disk_crypto_from(&types)
}

/// First field of the " / " mount line (root fs device).
#[cfg(target_os = "linux")]
fn root_mount_source(mounts: &str) -> Option<String> {
    let line = mounts
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some("/"))?;
    let src = line.split_whitespace().next()?;
    if src.is_empty() || src == "rootfs" || src.starts_with("overlay") {
        // container/WSL-artifact mounts — no meaningful block chain
        return None;
    }
    Some(src.to_string())
}

/// lsblk on a mapped device prints the TYPES of the whole chain (crypt,
/// lvm, part, disk): a "crypt" line = dm-crypt somewhere under root.
#[cfg(target_os = "linux")]
fn disk_crypto_from(lsblk_types: &str) -> Option<bool> {
    let types: Vec<&str> = lsblk_types.lines().map(str::trim).collect();
    if types.is_empty() {
        return None;
    }
    Some(types.contains(&"crypt"))
}

#[cfg(not(windows))]
fn defender() -> Option<bool> {
    // deliberately unknown — see the mapping block above
    None
}

/// Detected enterprise/domain integration: sssd configured, or `realm
/// list` reporting a joined domain. NOT Entra device registration.
#[cfg(target_os = "linux")]
fn entra_joined() -> Option<bool> {
    if std::path::Path::new("/etc/sssd/sssd.conf").exists() {
        return Some(true);
    }
    let out = run_capture(
        "realm",
        &["list", "--name-only"],
        std::time::Duration::from_secs(3),
    );
    // realm not installed (None) = undeterminable — fail open upstream
    out.map(|listing| !listing.trim().is_empty())
}

// ---------------------------------------------------------------------
// W30 step 4 (plan §3.5) — macOS collectors, same wire + Linux-grade
// honesty. Field semantics, stated for the log stream + docs:
//   bitlocker_on  <- `fdesetup status` ("FileVault is On/Off/Deferred")
//                   — a REAL disk-encryption signal (better-than-Linux
//                   fidelity; stated as such).
//   firewall_enabled <- socketfilterfw --getglobalstate — actual
//                   enabled/disabled state, not service-presence.
//   entra_joined  <- `profiles status -type enrollment` — detected MDM/
//                   DEP enrollment. NOT Microsoft Entra device
//                   registration (same honesty class as Linux's
//                   realm/sssd mapping).
//   days_since_patch <- newest software-update receipt date in
//                   /Library/Receipts/InstallHistory.plist — an
//                   install-receipt PROXY, not a security-patch
//                   timestamp (same honesty class as Linux's
//                   package-DB mtime).
//   defender_healthy <- deliberately unknown (fail-open None) — the
//                   W24 `mdatp` adapter is the closure path.
// Unknown (None) never denies — only an explicit false does.
// Subprocess bound: 5 s fail-open (plan §3.5/§8 — fdesetup can take
// seconds on FileVault machines; justified vs Linux's 3 s).
// ---------------------------------------------------------------------

/// One-time visibility for the macOS mapping (the Linux twin's shape).
#[cfg(target_os = "macos")]
fn log_macos_mapping_once() {
    use std::sync::OnceLock;
    static DONE: OnceLock<()> = OnceLock::new();
    if DONE.set(()).is_ok() {
        crate::log_event(
            "posture_collector_macos",
            "bitlocker_on=fdesetup(FileVault-real) defender_healthy=unknown-fail-open \
             firewall_enabled=socketfilterfw-state entra_joined=mdm-enrollment-detected \
             days_since_patch=install-receipt-proxy(InstallHistory.plist)",
        );
    }
}

/// (ProductName, ProductVersion, build) via `sw_vers` + `sysctl -n
/// kern.osversion`.
#[cfg(target_os = "macos")]
fn os_build() -> Option<(String, String, String)> {
    let swvers = run_capture("sw_vers", &[], std::time::Duration::from_secs(5))?;
    let build = run_capture(
        "sysctl",
        &["-n", "kern.osversion"],
        std::time::Duration::from_secs(5),
    )?;
    let name = swvers_field(&swvers, "ProductName")?;
    let ver = swvers_field(&swvers, "ProductVersion")?;
    let build = build.trim().to_string();
    if name.is_empty() || ver.is_empty() || build.is_empty() {
        return None;
    }
    Some((name, ver, build))
}

/// `sw_vers` rows are `key: value` lines.
#[cfg(target_os = "macos")]
fn swvers_field(swvers_out: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    swvers_out
        .lines()
        .find_map(|l| l.trim().strip_prefix(&prefix))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Newest `com.apple.pkg.update*`-class receipt date in
/// InstallHistory.plist → days-ago. Missing/corrupt file → None
/// (undeterminable, fail-open upstream).
#[cfg(target_os = "macos")]
fn patch_age_days() -> Option<i64> {
    let plist = std::fs::read_to_string("/Library/Receipts/InstallHistory.plist").ok()?;
    let newest = newest_update_receipt_unix(&plist)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some(patch_age_from(now, newest))
}

/// Pure parser (fixture-tested): the newest <date> among install dicts
/// whose packageIdentifiers contain an update-package string
/// (`com.apple.pkg.update…`). Dates are ISO8601 "…T…Z" — day precision
/// is all the proxy claims.
#[cfg(target_os = "macos")]
fn newest_update_receipt_unix(install_history_plist: &str) -> Option<i64> {
    let mut newest: Option<i64> = None;
    for dict in install_history_plist.split("</dict>") {
        let is_update = dict.contains("com.apple.pkg.update");
        if !is_update {
            continue;
        }
        // <key>date</key><date>2026-01-15T14:32:11Z</date> (whitespace
        // between key/value tags tolerated)
        let Some(kidx) = dict.find("<key>date</key>") else {
            continue;
        };
        let after = &dict[kidx + "<key>date</key>".len()..];
        let Some(dopen) = after.find("<date>") else {
            continue;
        };
        let rest = &after[dopen + "<date>".len()..];
        let Some(dclose) = rest.find("</date>") else {
            continue;
        };
        if let Some(unix) = iso_date_to_unix(&rest[..dclose]) {
            newest = Some(newest.map_or(unix, |n: i64| n.max(unix)));
        }
    }
    newest
}

/// ISO8601 date prefix "YYYY-MM-DD…" → unix seconds (day precision —
/// Howard Hinnant's civil-from-days, no chrono dep).
#[cfg(target_os = "macos")]
fn iso_date_to_unix(iso: &str) -> Option<i64> {
    let s = iso.trim();
    if s.len() < 10 || s.as_bytes().get(4) != Some(&b'-') || s.as_bytes().get(7) != Some(&b'-') {
        return None;
    }
    let y: i64 = s.get(0..4)?.parse().ok()?;
    let m: i64 = s.get(5..7)?.parse().ok()?;
    let d: i64 = s.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let (y, m) = if m <= 2 { (y - 1, m + 12) } else { (y, m) };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * m - 457) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400)
}

/// `fdesetup status`: "FileVault is On." / "…Off." / "…Deferred."
#[cfg(target_os = "macos")]
fn bitlocker() -> Option<bool> {
    let out = run_capture("fdesetup", &["status"], std::time::Duration::from_secs(5))?;
    fdesetup_from(&out)
}

/// Pure parse (fixture-tested): On → true; Off/Deferred → false
/// (Deferred = armed but not yet active on the current volume —
/// honestly reported as not-on); anything else → None.
#[cfg(target_os = "macos")]
fn fdesetup_from(fdesetup_out: &str) -> Option<bool> {
    let o = fdesetup_out.to_lowercase();
    if o.contains("filevault is on") {
        Some(true)
    } else if o.contains("filevault is off") || o.contains("filevault is deferred") {
        Some(false)
    } else {
        None
    }
}

/// `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`:
/// "Firewall is enabled. (…)" / "…disabled. (…)".
#[cfg(target_os = "macos")]
fn firewall() -> Option<bool> {
    let out = run_capture(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
        std::time::Duration::from_secs(5),
    )?;
    firewall_macos_from(&out)
}

/// Pure parse (fixture-tested).
#[cfg(target_os = "macos")]
fn firewall_macos_from(out: &str) -> Option<bool> {
    let o = out.to_lowercase();
    if o.contains("firewall is enabled") {
        Some(true)
    } else if o.contains("firewall is disabled") {
        Some(false)
    } else {
        None
    }
}

/// `profiles status -type enrollment`: "Enrolled via DEP: Yes/No" /
/// "Not Enrolled". Detected management enrollment, NOT Entra
/// registration (the mapping block above).
#[cfg(target_os = "macos")]
fn entra_joined() -> Option<bool> {
    let out = run_capture(
        "profiles",
        &["status", "-type", "enrollment"],
        std::time::Duration::from_secs(5),
    )?;
    enrollment_from(&out)
}

/// Pure parse (fixture-tested): an explicit enrolled/Yes → true;
/// explicit Not-enrolled/No → false; unrecognized → None.
#[cfg(target_os = "macos")]
fn enrollment_from(out: &str) -> Option<bool> {
    let o = out.to_lowercase();
    // negatives FIRST — the bare-ends_with heuristic would otherwise
    // swallow "not enrolled" (CI-proven, run 34774193404)
    if o.contains("not enrolled") || o.contains("enrolled via dep: no") {
        Some(false)
    } else if o.contains("enrolled via dep: yes")
        || o.contains("enrolled via credential provider")
        || o.contains("enrolled via user approved mdm")
        || o.trim().ends_with("enrolled")
    {
        Some(true)
    } else {
        None
    }
}

/// Bounded subprocess capture (plan §8: 3 s, fail-open = None on
/// timeout/absence). Polls try_wait — no worker threads held hostage by
/// a stuck child; the child is killed at the deadline.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_capture(cmd: &str, args: &[&str], budget: std::time::Duration) -> Option<String> {
    use std::io::Read;
    let mut child = std::process::Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                let mut out = String::new();
                child.stdout.take()?.read_to_string(&mut out).ok()?;
                return Some(out);
            }
            Ok(Some(_)) => return None, // nonzero exit = undeterminable
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    }
}

// W30 step 1: Linux-only (was cfg(not(windows)) — these live tests read
// /etc/os-release + /proc/sys, which don't exist on macOS; the Linux
// collectors themselves still compile+run on macOS with fail-open
// defaults until step 4's macOS collectors land).
#[cfg(target_os = "linux")]
#[cfg(test)]
mod linux_tests {
    use super::*;

    #[test]
    fn os_release_parsing() {
        let rel = "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\nVERSION_ID=\"24.04\"\n";
        let (name, kr) = os_build_from(rel, "6.8.0-1014-azure\n").expect("parses");
        assert_eq!(name, "Ubuntu 24.04 LTS");
        assert_eq!(kr, "6.8.0-1014-azure");
        // PRETTY_NAME absent -> NAME fallback; empty kernel -> None
        assert_eq!(
            os_build_from("NAME=\"Rocky Linux\"\n", "6.18.0\n")
                .unwrap()
                .0,
            "Rocky Linux"
        );
        assert!(os_build_from("PRETTY_NAME=\"X\"\n", "  ").is_none());
        assert!(os_build_from("", "6.1\n").is_none());
    }

    #[test]
    fn patch_age_math_including_clock_skew() {
        assert_eq!(patch_age_from(1_800_000_000, 1_800_000_000), 0);
        assert_eq!(patch_age_from(1_800_086_400, 1_800_000_000), 1);
        // future mtime (skew) clamps to 0, never negative
        assert_eq!(patch_age_from(1_800_000_000, 1_800_100_000), 0);
    }

    #[test]
    fn firewall_service_parsing() {
        assert_eq!(firewall_from("active\ninactive\nactive\n"), Some(true));
        assert_eq!(firewall_from("inactive\ninactive\n"), Some(false));
        assert_eq!(firewall_from("failed\ninactive\n"), Some(false));
        assert_eq!(firewall_from("active\n"), Some(true));
        assert_eq!(firewall_from(""), None);
        assert_eq!(firewall_from("\n \n"), None);
    }

    #[test]
    fn root_mount_and_crypto_chain_parsing() {
        let mounts = concat!(
            "/dev/mapper/root--vg-root / ext4 rw 0 0\n",
            "proc /proc proc defaults 0 0\n",
            "/dev/sda1 /boot ext4 rw 0 0\n",
        );
        assert_eq!(
            root_mount_source(mounts).as_deref(),
            Some("/dev/mapper/root--vg-root")
        );
        // LUKS chain: crypt anywhere in the lsblk output
        assert_eq!(disk_crypto_from("crypt\npart\ndisk\n"), Some(true));
        // plain LVM, no crypt
        assert_eq!(disk_crypto_from("lvm\npart\ndisk\n"), Some(false));
        assert_eq!(disk_crypto_from("part\ndisk\n"), Some(false));
        assert_eq!(disk_crypto_from(""), None);
        // container-ish roots are undeterminable
        assert_eq!(root_mount_source("overlay / overlay rw 0 0\n"), None);
        assert_eq!(root_mount_source("rootfs / rootfs rw 0 0\n"), None);
        assert_eq!(root_mount_source("proc /proc proc defaults 0 0\n"), None);
    }

    /// Live box (WSL Ubuntu): the real collect produces a PRETTY_NAME and
    /// a package-DB age (dpkg exists); the boolean collectors may be
    /// Some(false) here (no firewall service, plain root device) — that
    /// is the honest Linux signal, not a bug.
    #[test]
    fn live_collect_os_and_patch_age() {
        let s = collect();
        let os = s.os_version.expect("os_release+kernel read must work");
        assert!(
            os.contains("kernel"),
            "formatted like '<name> (kernel x)': {os}"
        );
        assert!(
            s.days_since_patch.is_some(),
            "dpkg status mtime must exist on Ubuntu"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn date_math() {
        let t = date_to_unix(2026, 8, 28).unwrap();
        assert!(
            t > 1_700_000_000 && t < 1_900_000_000,
            "2026 epoch sanity: {t}"
        );
        assert_eq!(date_to_unix(1970, 1, 1), Some(0));
    }

    /// Real WMI on this box: OS build must look like a Windows version.
    #[cfg(windows)]
    #[test]
    fn real_os_build_collected() {
        let s = collect();
        let os = s.os_version.expect("WMI OS query should work on Windows");
        assert!(os.contains("build"), "os_version carries the build: {os}");
    }

    #[test]
    fn client_version_present() {
        assert!(!CLIENT_VERSION.is_empty());
    }

    /// W14S2 fix step 1: report classification is snapshot-consistent with
    /// the slot state — empty slot ⇒ "empty" (benign cold start), inside
    /// the TTL ⇒ "fresh", at/past the TTL ⇒ "stale" (the actionable class:
    /// last-good served silently).
    #[test]
    fn slot_class_semantics() {
        let mut s = Snapshot::unknown();
        assert_eq!(s.slot_class(), "empty");
        s.slot_age_secs = Some(0);
        assert_eq!(s.slot_class(), "fresh");
        s.slot_age_secs = Some(TTL_SECS as i64 - 1);
        assert_eq!(s.slot_class(), "fresh");
        s.slot_age_secs = Some(TTL_SECS as i64);
        assert_eq!(s.slot_class(), "stale");
    }

    // ---------- W4.4-stall hardening: shared-slot cache semantics ----------

    static TEST_SER: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn wait_collecting_clears(budget: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + budget;
        while std::time::Instant::now() < deadline {
            if COLLECTING.lock().unwrap().is_none() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        false
    }

    /// The hot path must serve the last-good snapshot INSTANTLY even when the
    /// slot is stale — no join, no WMI on the calling thread [W4.4 fix].
    #[test]
    fn stale_slot_served_without_blocking() {
        let _g = TEST_SER.lock().unwrap();
        reset_slots();
        let stale = Snapshot {
            bitlocker_on: Some(true),
            defender_healthy: Some(true),
            firewall_enabled: Some(true),
            os_version: Some("planted (build 0)".into()),
            days_since_patch: Some(1),
            domain_joined: None,
            slot_age_secs: Some(0),
        };
        *SLOT.lock().unwrap() = Some((
            std::time::Instant::now() - std::time::Duration::from_secs(TTL_SECS + 5),
            stale,
        ));
        let t0 = std::time::Instant::now();
        let s = collect_cached();
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(100),
            "stale read must not block on WMI"
        );
        assert_eq!(s.os_version.as_deref(), Some("planted (build 0)"));
        // a refresh was kicked; give the real worker a bounded window to finish
        // so later tests start from a quiet state
        if COLLECTING.lock().unwrap().is_some() {
            let cleared = wait_collecting_clears(std::time::Duration::from_secs(25));
            assert!(cleared, "worker should finish or be orphanable");
        }
    }

    /// A fresh in-flight worker (inside the deadline) blocks a second spawn;
    /// one wedged PAST the deadline is orphaned (failure counter + replace).
    #[test]
    fn worker_supersede_semantics() {
        let _g = TEST_SER.lock().unwrap();
        reset_slots();
        // fresh worker: a second kick must NOT replace it
        let t0 = std::time::Instant::now();
        *COLLECTING.lock().unwrap() = Some(t0);
        maybe_spawn_refresh(collect);
        let still = COLLECTING.lock().unwrap().unwrap();
        assert_eq!(still, t0, "fresh worker must not be superseded");
        // wedged worker (past deadline): orphaned + counted + replaced
        let before = crate::metrics::posture_collect_failures().get();
        *COLLECTING.lock().unwrap() = Some(t0 - std::time::Duration::from_secs(20));
        maybe_spawn_refresh(collect);
        let replaced = COLLECTING.lock().unwrap().unwrap();
        assert!(replaced > t0, "wedged worker must be replaced");
        assert!(crate::metrics::posture_collect_failures().get() > before);
        reset_slots();
    }

    /// kick_refresh must be NON-BLOCKING (returns immediately even when a
    /// real WMI collect is pending) — startup paths call it before binding
    /// listeners, and a blocking kick there broke the serve timing envelope
    /// (listener bind ~9s late; every suite tunnel check missed).
    #[test]
    fn kick_refresh_is_nonblocking() {
        let _g = TEST_SER.lock().unwrap();
        reset_slots();
        let t0 = std::time::Instant::now();
        kick_refresh();
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(100),
            "kick must not wait for the worker"
        );
        // a worker is in flight (real WMI on this box); give it a bounded
        // window so later tests start from a quiet state
        if COLLECTING.lock().unwrap().is_some() {
            let cleared = wait_collecting_clears(std::time::Duration::from_secs(25));
            assert!(cleared, "worker should finish or be orphanable");
        }
    }

    /// A panicking worker must not wedge refreshes: the in-flight marker
    /// clears and the failure counter moves.
    #[test]
    fn panicking_worker_counts_failure_and_unblocks() {
        fn boom() -> Snapshot {
            panic!("simulated WMI hang/panic");
        }
        let _g = TEST_SER.lock().unwrap();
        reset_slots();
        let before = crate::metrics::posture_collect_failures().get();
        maybe_spawn_refresh(boom);
        assert!(
            wait_collecting_clears(std::time::Duration::from_secs(3)),
            "in-flight marker must clear after a panic"
        );
        assert!(crate::metrics::posture_collect_failures().get() > before);
        reset_slots();
    }
}

// ---------------------------------------------------------------------
// W30 step 4: macOS collector tests — parse fixtures (pure) + live
// collector shape asserts on the runner (real macOS).
// ---------------------------------------------------------------------
#[cfg(target_os = "macos")]
#[cfg(test)]
mod macos_tests {
    use super::*;

    const INSTALL_HISTORY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<array>\n\t<dict>\n\t\t<key>date</key>\n\t\t<date>2025-11-02T09:14:03Z</date>\n\t\t<key>displayName</key>\n\t\t<string>XProtect Plist Data Service</string>\n\t\t<key>packageIdentifiers</key>\n\t\t<array>\n\t\t\t<string>com.apple.pkg.XProtectPlistDataService</string>\n\t\t</array>\n\t</dict>\n\t<dict>\n\t\t<key>date</key>\n\t\t<date>2026-01-15T14:32:11Z</date>\n\t\t<key>displayName</key>\n\t\t<string>macOS Sonoma 15.7.9 Update</string>\n\t\t<key>packageIdentifiers</key>\n\t\t<array>\n\t\t\t<string>com.apple.pkg.update.os.15.7.9</string>\n\t\t</array>\n\t</dict>\n\t<dict>\n\t\t<key>date</key>\n\t\t<date>2026-02-20T08:00:00Z</date>\n\t\t<key>displayName</key>\n\t\t<string>SomeApp</string>\n\t\t<key>packageIdentifiers</key>\n\t\t<array>\n\t\t\t<string>com.somecorp.pkg.app</string>\n\t\t</array>\n\t</dict>\n</array>\n</plist>";

    #[test]
    fn newest_update_receipt_ignores_non_updates() {
        // 2026-01-15 is the ONLY update-class receipt; 2026-02-20 (app)
        // and 2025-11-02 (XProtect, not pkg.update) must not win
        let unix = newest_update_receipt_unix(INSTALL_HISTORY).unwrap();
        // 2026-01-15 = day 20468 (2026-01-01 = 20454 + 14)
        assert_eq!(unix, 20_468 * 86_400);
    }

    #[test]
    fn corrupt_or_missing_receipts_are_none() {
        assert_eq!(newest_update_receipt_unix(""), None);
        assert_eq!(newest_update_receipt_unix("not a plist"), None);
        // update-class dict WITHOUT a parseable date = skipped
        assert_eq!(
            newest_update_receipt_unix(
                "<dict><key>packageIdentifiers</key><array><string>com.apple.pkg.update.x</string></array><key>date</key><date>garbage</date></dict>"
            ),
            None
        );
    }

    #[test]
    fn iso_date_math() {
        assert_eq!(iso_date_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            iso_date_to_unix("2026-01-15T14:32:11Z"),
            Some(20_468 * 86_400)
        );
        // leap year + month boundaries
        assert_eq!(
            iso_date_to_unix("2024-02-29T00:00:00Z"),
            Some(19_782 * 86_400)
        );
        // 2000-01-01 = day 10957; leap year -> +60 days to Mar 1 = 11017
        assert_eq!(
            iso_date_to_unix("2000-03-01T00:00:00Z"),
            Some(11_017 * 86_400)
        );
        // rejects malformed
        assert_eq!(iso_date_to_unix("20260115"), None);
        assert_eq!(iso_date_to_unix("2026-13-01T00:00:00Z"), None);
    }

    #[test]
    fn fdesetup_parsing() {
        assert_eq!(fdesetup_from("FileVault is On.\n"), Some(true));
        assert_eq!(fdesetup_from("FileVault is Off.\n"), Some(false));
        assert_eq!(fdesetup_from("FileVault is Deferred.\n"), Some(false));
        assert_eq!(fdesetup_from("something else"), None);
    }

    #[test]
    fn firewall_state_parsing() {
        assert_eq!(
            firewall_macos_from("Firewall is enabled. (State = 1)\n"),
            Some(true)
        );
        assert_eq!(
            firewall_macos_from("Firewall is disabled. (State = 0)\n"),
            Some(false)
        );
        assert_eq!(firewall_macos_from("unknown"), None);
    }

    #[test]
    fn enrollment_parsing() {
        assert_eq!(
            enrollment_from("Enrolled via DEP: Yes\nProfiles Status: ...\n"),
            Some(true)
        );
        assert_eq!(enrollment_from("Enrolled via DEP: No\n"), Some(false));
        assert_eq!(enrollment_from("Not Enrolled\n"), Some(false));
        assert_eq!(enrollment_from("mystery"), None);
    }

    #[test]
    fn swvers_parsing() {
        let out = "ProductName:\tmacOS\nProductVersion:\t15.7.9\nBuildVersion:\t24G830\n";
        assert_eq!(swvers_field(out, "ProductName").as_deref(), Some("macOS"));
        assert_eq!(
            swvers_field(out, "ProductVersion").as_deref(),
            Some("15.7.9")
        );
        assert_eq!(swvers_field(out, "BuildVersion").as_deref(), Some("24G830"));
        assert_eq!(swvers_field(out, "Missing"), None);
    }

    /// The runner IS macOS: the live collectors must report real shapes.
    #[test]
    fn live_collectors_report_shapes() {
        let s = collect();
        let os = s.os_version.expect("os_version on a real Mac");
        assert!(os.contains("macOS"), "unexpected os_version: {os}");
        assert!(os.contains("(build "), "unexpected os_version: {os}");
        // FileVault + firewall are REAL signals on macOS: the runner
        // answers Some (value may be either — the SHAPE is the assert)
        assert!(s.bitlocker_on.is_some(), "fdesetup must answer on macOS");
        assert!(
            s.firewall_enabled.is_some(),
            "socketfilterfw must answer on macOS"
        );
        // defender stays fail-open unknown on macOS (W24 mdatp closure)
        assert_eq!(s.defender_healthy, None);
    }
}
