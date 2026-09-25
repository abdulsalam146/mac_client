//! W43 S5.2: the macOS split-DNS cleanup watchdog (plan §4.4).
//!
//! ONE launchd system job (`com.aztna.splitdns.watchdog`, `RunAtLoad` +
//! `StartInterval 30`) whose action is `glmsvc --splitdns-watchdog-check`
//! — launchd natively polls every 30 s, so there is NO companion process
//! (the Windows L1/L2 split exists because Task Scheduler cannot repeat
//! faster than one minute; launchd can — plan §4.4's platform table).
//! Resolver files are PERSISTENT across reboots, hence `RunAtLoad`: the
//! backstop is boot-started, same shape as the Windows scheduled task.
//!
//! The check is heartbeat-gated: a stale heartbeat (> [`STALENESS_SECS`],
//! same 25 s lease the reconciler maintains) ⇒ remove every owned
//! resolver file. A healthy client heartbeats every ≤10 s, so a fresh
//! lease is a no-op. Worst degraded path: 25 + 30 + ~2 ≈ 57 s, inside
//! the 90 s per-origin ceiling. Evidence: the same durable JSONL
//! (`splitdns-watchdog.log`, one `splitdns_watchdog_recovered` line per
//! real recovery, source=launchd-tick) + the recovery counter, seeded at
//! reconciler start — identical contract to Windows.

#![cfg(target_os = "macos")]

use std::io::Write;
use std::path::PathBuf;

pub const JOB_LABEL: &str = "com.aztna.splitdns.watchdog";

fn plist_path() -> PathBuf {
    std::path::Path::new("/Library/LaunchDaemons").join(format!("{JOB_LABEL}.plist"))
}

pub fn evidence_path() -> PathBuf {
    crate::svc::svc_home().join("splitdns-watchdog.log")
}

// ---------------- evidence (same contract as the Windows watchdog) ----------------

fn append_evidence(source: &str, rules: usize) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0);
    let line = format!(
        "{{\"ts\":{ts},\"kind\":\"splitdns_watchdog_recovered\",\"source\":\"{source}\",\"rules\":{rules}}}\n"
    );
    if let Some(dir) = evidence_path().parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(evidence_path())
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Seed the recovery counter from the durable JSONL (survives client
/// restarts; the reconciler calls this at construction).
pub fn seed_recoveries_counter() {
    let n = std::fs::read_to_string(evidence_path())
        .map(|t| {
            t.lines()
                .filter(|l| l.contains("\"kind\":\"splitdns_watchdog_recovered\""))
                .count() as u64
        })
        .unwrap_or(0);
    if n > 0 {
        crate::metrics::splitdns_watchdog_recoveries().inc_by(n);
    }
}

// ---------------- cleanup ----------------

/// Remove every owned resolver file (any generation). Evidence + counter
/// only when something was actually removed — same rule as Windows.
pub async fn remove_all_tagged(source: &str) -> usize {
    let mut removed = 0;
    if let Ok(rules) = super::channel::enumerate_retry().await {
        for r in &rules {
            if r.generation.is_some() && super::channel::remove_retry(&r.id).await.is_ok() {
                removed += 1;
            }
        }
    }
    if removed > 0 {
        append_evidence(source, removed);
        crate::metrics::splitdns_watchdog_recoveries().inc();
        crate::metrics::splitdns_rules_active().set(0);
        crate::log_event(
            "splitdns_watchdog_recovered",
            &format!("source={source} rules={removed}"),
        );
    }
    removed
}

fn heartbeat_stale() -> bool {
    let Ok(txt) = std::fs::read_to_string(super::reconciler::heartbeat_path()) else {
        return true; // no heartbeat at all + owned files = stale by definition
    };
    let Ok(micros) = txt.trim().parse::<u128>() else {
        return true;
    };
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return false;
    };
    now.as_micros().saturating_sub(micros) > (super::reconciler::STALENESS_SECS as u128) * 1_000_000
}

// ---------------- activation (called by the zone-refresh loop) ----------------

fn plist_xml(exe: &str, svc_home: &str) -> String {
    // XML-escape the two operator-influenced strings (paths can carry &<>)
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
\t<key>Label</key><string>{JOB_LABEL}</string>\n\
\t<key>ProgramArguments</key>\n\
\t<array>\n\
\t\t<string>{}</string>\n\
\t\t<string>--splitdns-watchdog-check</string>\n\
\t</array>\n\
\t<key>EnvironmentVariables</key>\n\
\t<dict>\n\
\t\t<key>AZTNA_SVC_HOME</key><string>{}</string>\n\
\t</dict>\n\
\t<key>RunAtLoad</key><true/>\n\
\t<key>StartInterval</key><integer>30</integer>\n\
</dict>\n\
</plist>\n",
        esc(exe),
        esc(svc_home)
    )
}

fn launchctl_ok(args: &[&str]) -> bool {
    std::process::Command::new("launchctl")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Bring the cleanup owner up BEFORE auto mode installs anything (the
/// watchdog is a precondition, not an assumption — same contract as the
/// Windows activate). Registers/refreshes the system launchd job; needs
/// the root daemon context (a non-root dev console fails here, which is
/// exactly the no_watchdog → manual-fallback path).
pub fn activate() -> bool {
    let exe = match std::env::current_exe() {
        Ok(p) => p.display().to_string(),
        Err(_) => return false,
    };
    let plist = plist_path();
    if let Some(dir) = plist.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // The job MUST share the activating process's svc home (heartbeat +
    // evidence): launchd strips the environment, so a job without this
    // dict reads the DEFAULT home, finds no heartbeat ("stale by
    // definition") and its RunAtLoad instance removed the freshly
    // installed rule on the very first mirror run (36170226461).
    let home = crate::svc::svc_home().display().to_string();
    if std::fs::write(&plist, plist_xml(&exe, &home)).is_err() {
        return false;
    }
    // idempotent: boot out any prior instance, then bootstrap fresh
    launchctl_ok(&["bootout", "system", &plist.display().to_string()]);
    if launchctl_ok(&["bootstrap", "system", &plist.display().to_string()]) {
        return true;
    }
    // legacy fallback for older launchctl semantics
    launchctl_ok(&["load", "-w", &plist.display().to_string()])
}

/// L2 tick / boot pass: `glmsvc --splitdns-watchdog-check`. Heartbeat-gated
/// — a fresh lease (healthy client, ≤10 s cadence) is a no-op; a stale
/// one (> 25 s) removes every owned resolver file. The heartbeat is
/// re-read after enumeration finds owned rules: a tick straddling the
/// reconciler's install→heartbeat-write window (~ms) must not remove a
/// just-installed rule (the read-then-enumerate race, closed).
pub async fn check_main() {
    if !heartbeat_stale() {
        return;
    }
    if let Ok(rules) = super::channel::enumerate_retry().await {
        let owned = rules.iter().filter(|r| r.generation.is_some()).count();
        if owned == 0 {
            return;
        }
        if heartbeat_stale() {
            let _ = remove_all_tagged("launchd-tick").await;
        }
    }
}

/// Install-time / uninstall-time / manual-clean helper.
pub async fn clean() -> usize {
    remove_all_tagged("manual-clean").await
}

/// Remove the launchd job + its plist (uninstall path).
pub fn delete_job() {
    let p = plist_path().display().to_string();
    launchctl_ok(&["bootout", "system", &p]);
    launchctl_ok(&["unload", "-w", &p]);
    let _ = std::fs::remove_file(plist_path());
}

/// W43 S5.3 dev/test hook (`glmsvc --splitdns-selftest <fqdn>...`): the
/// CP-free mechanics path for the public-mirror lane - activate the
/// launchd backstop, then ONE real reconciler tick against the stub
/// zone names (the real channel, real files, real heartbeat + journal).
/// Refuses exactly like the service path when activation fails.
pub async fn selftest(names: &[String]) {
    let mut r = super::reconciler::Reconciler::new(super::SplitDnsConfig {
        mode: super::SplitDnsMode::Auto,
        suffix_allowlist: names.to_vec(),
    });
    if !r.active() {
        eprintln!("[splitdns-selftest] reconciler inactive");
        return;
    }
    if !activate() {
        r.deactivate();
        eprintln!("[splitdns-selftest] watchdog activation FAILED (no_watchdog)");
        return;
    }
    r.tick(names, true).await;
    // diagnosability for the CP-free lane: what actually landed
    let installed = super::journal::read()
        .map(|j| j.installed.len())
        .unwrap_or(0);
    println!(
        "[splitdns-selftest] tick complete (generation {}, journal installed {})",
        r.generation(),
        installed
    );
}
