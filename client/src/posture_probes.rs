//! W3.5 [posture-evolution-plan §2]: generic read-only posture PROBE families
//! driven by the controller's requirement spec (service running, process
//! running, file present, registry value). The spec carries PARAMETERS to
//! built-in families — never code; unknown families report `unsupported`.
//! Results are cached (dedicated thread, COM stays off async workers — same
//! discipline as posture_collector) and read by `signed_posture` when
//! building report v2.

use serde::Deserialize;
use std::collections::HashMap;

/// Max signals honored from a spec (bounded by design; extras = unsupported).
pub const MAX_SIGNALS: usize = 32;
/// Probe cache refresh cadence (serve mode keeps results warm).
const REFRESH_SECS: u64 = 10;

#[derive(Debug, Clone, Deserialize)]
pub struct SignalSpec {
    pub id: String,
    pub family: String,
    #[serde(default)]
    pub params: HashMap<String, String>,
    #[serde(default)]
    /// part of the spec wire schema; required-ness is evaluated
    /// controller-side, the client probe only reports the value
    #[allow(dead_code)]
    pub required: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PostureSpec {
    pub spec_version: i64,
    #[serde(default)]
    pub signals: Vec<SignalSpec>,
}

// ---------- shared state: current spec + latest probe results ----------

fn spec_cell() -> &'static std::sync::RwLock<Option<std::sync::Arc<PostureSpec>>> {
    static C: std::sync::OnceLock<std::sync::RwLock<Option<std::sync::Arc<PostureSpec>>>> =
        std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::RwLock::new(None))
}

fn results_cell() -> &'static std::sync::RwLock<HashMap<String, String>> {
    static C: std::sync::OnceLock<std::sync::RwLock<HashMap<String, String>>> =
        std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

/// Install/replace the current spec (fetch path). `Some` with version 0 or
/// no signals clears (core-only behavior).
pub fn set_spec(spec: PostureSpec) -> Option<i64> {
    let effective = if spec.spec_version <= 0 || spec.signals.is_empty() {
        None
    } else {
        Some(std::sync::Arc::new(spec))
    };
    let v = effective.as_ref().map(|s| s.spec_version);
    *spec_cell().write().unwrap() = effective;
    v
}

pub fn current_spec_version() -> Option<i64> {
    spec_cell().read().unwrap().as_ref().map(|s| s.spec_version)
}

/// Probe results for report building (id → asserted value).
pub fn snapshot_results() -> Option<(i64, Vec<(String, String)>)> {
    let g = spec_cell().read().unwrap();
    let spec = g.as_ref()?;
    let res = results_cell().read().unwrap();
    let ext = spec
        .signals
        .iter()
        .map(|s| {
            (
                s.id.clone(),
                res.get(&s.id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string()),
            )
        })
        .collect();
    Some((spec.spec_version, ext))
}

/// Serve-mode warmer: refresh probe results every REFRESH_SECS on a
/// dedicated thread (WMI COM must not init on async workers).
pub fn start_probe_thread() {
    std::thread::Builder::new()
        .name("posture-probes".into())
        .spawn(|| loop {
            if let Some(spec) = spec_cell().read().unwrap().clone() {
                let fresh = run_probes(&spec);
                *results_cell().write().unwrap() = fresh;
            }
            std::thread::sleep(std::time::Duration::from_secs(REFRESH_SECS));
        })
        .ok();
}

/// Run all probes for the current spec NOW (one-shot path — call via
/// spawn_blocking). Bounded by the per-probe semantics below.
pub fn run_probes_now() -> Option<(i64, Vec<(String, String)>)> {
    let spec = spec_cell().read().unwrap().clone()?;
    let fresh = run_probes(&spec);
    *results_cell().write().unwrap() = fresh.clone();
    Some((
        spec.spec_version,
        spec.signals
            .iter()
            .map(|s| {
                (
                    s.id.clone(),
                    fresh
                        .get(&s.id)
                        .cloned()
                        .unwrap_or_else(|| "unknown".into()),
                )
            })
            .collect(),
    ))
}

// ---------- probe families ----------

fn run_probes(spec: &PostureSpec) -> HashMap<String, String> {
    let mut out = HashMap::new();
    #[cfg(windows)]
    let mut wmi: Option<wmi::WMIConnection> = None;
    let t0 = std::time::Instant::now();
    for s in spec.signals.iter().take(MAX_SIGNALS) {
        // soft overall budget: stop probing, leave the rest unknown
        if t0.elapsed().as_secs() >= 5 {
            break;
        }
        let value = match s.family.as_str() {
            "file_exists" => match s.params.get("path") {
                Some(p) => match expand_env(p) {
                    Some(path) => if path.exists() { "true" } else { "false" }.to_string(),
                    None => "unknown".to_string(),
                },
                None => "unknown".to_string(),
            },
            // W29: service/process probes are WMI-backed — Windows-only
            // families; the Linux client reports `unsupported` (the same
            // string an unknown family gets) until step 3 revisits the
            // Linux probe policy.
            "service_state" => {
                #[cfg(windows)]
                {
                    match s.params.get("name") {
                        Some(name) => {
                            if wmi.is_none() {
                                wmi = con_root_cimv2();
                            }
                            match wmi.as_ref().and_then(|w| service_running(w, name)) {
                                Some(v) => v.to_string(),
                                None => "unknown".to_string(),
                            }
                        }
                        None => "unknown".to_string(),
                    }
                }
                #[cfg(not(windows))]
                {
                    "unsupported".to_string()
                }
            }
            "process_running" => {
                #[cfg(windows)]
                {
                    match s.params.get("image") {
                        Some(image) => {
                            if wmi.is_none() {
                                wmi = con_root_cimv2();
                            }
                            match wmi.as_ref().and_then(|w| process_running(w, image)) {
                                Some(v) => v.to_string(),
                                None => "unknown".to_string(),
                            }
                        }
                        None => "unknown".to_string(),
                    }
                }
                #[cfg(not(windows))]
                {
                    "unsupported".to_string()
                }
            }
            #[cfg(windows)]
            "registry_value" => match (s.params.get("path"), s.params.get("value")) {
                (Some(p), Some(v)) => registry_value(p, v).unwrap_or_else(|| "unknown".to_string()),
                _ => "unknown".to_string(),
            },
            _ => "unsupported".to_string(),
        };
        let result = value.as_str();
        let rclass = match result {
            "true" => "match",
            "false" => "nomatch",
            "unknown" => "error",
            "unsupported" => "unsupported",
            _ => "match", // string values count as matches (presence probes)
        };
        crate::metrics::posture_probe_results()
            .with_label_values(&[&s.family, rclass])
            .inc();
        out.insert(s.id.clone(), value);
    }
    out
}

#[cfg(windows)]
fn con_root_cimv2() -> Option<wmi::WMIConnection> {
    let com = wmi::COMLibrary::new().ok()?;
    wmi::WMIConnection::with_namespace_path("ROOT\\CIMV2", com).ok()
}

#[cfg(windows)]
fn wql_quote(s: &str) -> String {
    s.replace('\'', "''")
}

#[cfg(windows)]
fn service_running(w: &wmi::WMIConnection, name: &str) -> Option<bool> {
    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct Svc {
        State: Option<String>,
    }
    let v: Vec<Svc> = w
        .raw_query(format!(
            "SELECT State FROM Win32_Service WHERE Name='{}'",
            wql_quote(name)
        ))
        .ok()?;
    Some(
        v.into_iter()
            .next()
            .and_then(|s| s.State)
            .map(|st| st.eq_ignore_ascii_case("Running"))
            .unwrap_or(false),
    )
}

#[cfg(windows)]
fn process_running(w: &wmi::WMIConnection, image: &str) -> Option<bool> {
    #[derive(Deserialize)]
    #[allow(non_snake_case)]
    struct Proc {
        // selected only to constrain the row shape; presence is what counts
        #[allow(dead_code)]
        Name: String,
    }
    let v: Vec<Proc> = w
        .raw_query(format!(
            "SELECT Name FROM Win32_Process WHERE Name='{}'",
            wql_quote(image)
        ))
        .ok()?;
    Some(!v.is_empty())
}

/// %VAR% expansion for spec-provided paths (admin-authored; read-only use).
/// Unknown/unset variables → None (probe reports unknown).
pub fn expand_env(input: &str) -> Option<std::path::PathBuf> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after.find('%')?;
        let var = &after[..end];
        if var.is_empty() {
            return None;
        }
        let val = std::env::var(var).ok()?;
        out.push_str(&val);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(std::path::PathBuf::from(out))
}

/// Read a registry value. `path` = "HKLM\SOFTWARE\...\subkey", `value` =
/// value name. Returns: None on any error (probe reports unknown), "false"
/// when the value does not exist, otherwise a stable string form
/// (REG_SZ/EXPAND_SZ → data; DWORD → number; other types → "true").
#[cfg(windows)]
fn registry_value(path: &str, value: &str) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::RegGetValueW;

    let (hive, subkey) = split_hive(path)?;
    let mut wide_path: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut wide_val: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let mut ty = windows::Win32::System::Registry::REG_VALUE_TYPE(0);
    let mut buf = [0u16; 2048];
    let mut cb = (buf.len() * 2) as u32;
    let r = unsafe {
        RegGetValueW(
            hive,
            PCWSTR(wide_path.as_mut_ptr()),
            PCWSTR(wide_val.as_mut_ptr()),
            windows::Win32::System::Registry::RRF_RT_ANY,
            Some(&mut ty),
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            Some(&mut cb),
        )
    };
    if r.0 != 0 {
        if r.0 == 2 {
            // ERROR_FILE_NOT_FOUND (value or key absent) → explicit false
            return Some("false".to_string());
        }
        eprintln!(
            "[posture-probe] registry_value '{path}\\{value}' failed: win32 error {}",
            r.0
        );
        return None;
    }
    const REG_SZ: u32 = 2;
    const REG_EXPAND_SZ: u32 = 7;
    const REG_DWORD: u32 = 4;
    match ty.0 {
        REG_SZ | REG_EXPAND_SZ => {
            let len = (cb as usize / 2).min(buf.len());
            let s = String::from_utf16_lossy(&buf[..len]);
            Some(s.trim_end_matches('\0').to_string())
        }
        REG_DWORD => {
            let v = u32::from_le_bytes([buf[0] as u8, buf[1] as u8, buf[2] as u8, buf[3] as u8]);
            Some(v.to_string())
        }
        _ => Some("true".to_string()),
    }
}

/// "HKLM\SOFTWARE\X" → (predefined hive, normalized subkey path).
#[cfg(windows)]
fn split_hive(path: &str) -> Option<(windows::Win32::System::Registry::HKEY, String)> {
    use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let (hive_s, rest) = path.split_once(['\\', '/'])?;
    let subkey = rest.replace('/', "\\");
    match hive_s.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => Some((HKEY_LOCAL_MACHINE, subkey)),
        "HKCU" | "HKEY_CURRENT_USER" => Some((HKEY_CURRENT_USER, subkey)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_expansion() {
        std::env::set_var("AZTNA_PROBE_TEST", "C:\\x");
        assert_eq!(
            expand_env("%AZTNA_PROBE_TEST%\\a.txt").unwrap(),
            std::path::PathBuf::from("C:\\x\\a.txt")
        );
        assert_eq!(
            expand_env("plain\\path").unwrap(),
            std::path::PathBuf::from("plain\\path")
        );
        assert!(
            expand_env("%NO_SUCH_VAR_ZZZ%\\a").is_none(),
            "unset var -> unknown"
        );
        assert!(expand_env("%AZTNA_PROBE_TEST").is_none(), "unclosed var");
    }

    /// W3.5: registry probe against a value that always exists on Windows —
    /// ProductName is REG_SZ, InstallType on some SKUs is absent (false).
    #[cfg(windows)]
    #[test]
    fn registry_probe_known_values() {
        let pn = registry_value(
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "ProductName",
        )
        .unwrap();
        assert!(!pn.is_empty(), "ProductName must read as a string");
        // absent value → explicit false (not unknown)
        let miss = registry_value(
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "DefinitelyNoSuchValueZzz",
        )
        .unwrap();
        assert_eq!(miss, "false");
    }

    #[test]
    fn spec_set_and_snapshot() {
        // unsupported family surfaces as `unsupported`; unprobed as `unknown`
        let spec: PostureSpec = serde_json::from_value(serde_json::json!({
            "spec_version": 5,
            "signals": [
                {"id": "a", "family": "tpm_quote", "params": {}, "required": true},
                {"id": "b", "family": "file_exists", "params": {"path": "C:/definitely-not-here-xyz"}, "required": false}
            ]
        }))
        .unwrap();
        set_spec(spec);
        assert_eq!(current_spec_version(), Some(5));
        let res = run_probes_now().unwrap();
        assert_eq!(res.0, 5);
        let m: HashMap<String, String> = res.1.into_iter().collect();
        assert_eq!(m["a"], "unsupported");
        assert_eq!(m["b"], "false", "missing file must be an explicit false");
        // snapshot without probes for b2 stays unknown
        set_spec(
            serde_json::from_value(serde_json::json!({
                "spec_version": 6,
                "signals": [{"id": "b2", "family": "file_exists", "params": {"path": "C:/zzz"}}]
            }))
            .unwrap(),
        );
        let (v, ext) = snapshot_results().unwrap();
        assert_eq!(v, 6);
        assert_eq!(ext[0].1, "unknown", "unprobed signal reports unknown");
        // clearing (version 0 / no signals) returns None
        set_spec(
            serde_json::from_value(serde_json::json!({"spec_version": 0, "signals": []})).unwrap(),
        );
        assert!(current_spec_version().is_none());
    }
}
