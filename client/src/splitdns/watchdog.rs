//! W43 S3.3: the two-layer Windows cleanup watchdog (plan §4.4 v1.6).
//!
//! **L1 companion** — a detached instance of this binary
//! (`glmsvc --splitdns-watchdog <generation>`) spawned at auto-mode
//! activation; waits on the generation-scoped named objects
//! `Global\aztna-dns-<gen>-alive` (a mutex the CLIENT holds for the
//! session — process death abandons it, probe-measured 4 ms detection)
//! and `Global\aztna-dns-<gen>-standdown`. Also polls the heartbeat every
//! 5 s so a hung-but-alive client is caught at the staleness threshold.
//! **L2 backstop** — one scheduled task (PT1M + boot trigger, XML shape
//! probe-verified) whose action is `glmsvc --splitdns-watchdog-check`:
//! alive-mutex absent/abandoned OR heartbeat stale ⇒ tagged removal.
//! Covers L1's own death and the post-crash reboot (NRPT rules persist).
//!
//! The watchdog never installs anything — read-check-delete over tagged
//! rules only. Evidence outlives the (possibly dead) client: a JSONL line
//! per real recovery + the recovery counter, re-seeded at client start.

#![cfg(windows)]

use std::io::Write;
use std::path::PathBuf;

/// Plan §4.4: heartbeat staleness threshold (25 s — worst degraded path
/// 25 + 60 + ~2 ≈ 87 s fits the 90 s per-origin ceiling).
const STALENESS_SECS: u64 = 25;
/// L1 hang-poll cadence.
const HANG_POLL_SECS: u64 = 5;

pub const TASK_NAME: &str = "aztna-splitdns-watchdog";

pub fn evidence_path() -> PathBuf {
    crate::svc::svc_home().join("splitdns-watchdog.log")
}

// ---------------- evidence ----------------

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

/// Seed `splitdns_watchdog_recoveries_total` from the durable JSONL so the
/// counter survives client restarts (plan §4.4 evidence persistence).
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

// ---------------- shared cleanup ----------------

/// Remove every tagged rule (any generation — single-owner-per-machine).
/// Evidence + counter only when something was actually removed.
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
    let txt = match std::fs::read_to_string(super::reconciler::heartbeat_path()) {
        Ok(t) => t,
        Err(_) => return true, // no heartbeat at all + rules may exist = stale by definition
    };
    let Ok(micros) = txt.trim().parse::<u128>() else {
        return true;
    };
    let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return false;
    };
    now.as_micros().saturating_sub(micros) > (STALENESS_SECS as u128) * 1_000_000
}

// ---------------- generation-scoped session objects ----------------

fn alive_name(gen: &str) -> String {
    format!(r"Global\aztna-dns-{gen}-alive")
}
fn standdown_name(gen: &str) -> String {
    format!(r"Global\aztna-dns-{gen}-standdown")
}

/// Client-side session state: a DEDICATED std thread acquires and holds the
/// alive mutex for the whole session (thread ownership is what makes
/// process death an ABANDONEMENT — the parking thread never exits while
/// the process lives, so a tokio worker retiring can never produce a false
/// death signal). The standdown event signals graceful teardown.
pub struct SessionObjects {
    standdown: windows::Win32::Foundation::HANDLE,
    /// Existence anchor for the named alive mutex: a named kernel object
    /// is DESTROYED the moment its last handle closes, so this handle must
    /// stay open for the whole session or the parking thread's open-by-name
    /// (and the companion's) would race a destroyed object (the first FULL
    /// W43S3 run: mutex gone at creation ⇒ companion exited silently ⇒
    /// zero cleanups, zero evidence).
    anchor: windows::Win32::Foundation::HANDLE,
}

// SAFETY: a kernel HANDLE is thread-agnostic (usable from any thread); the
// zone-refresh task holds this across awaits, and Drop closes it exactly once.
unsafe impl Send for SessionObjects {}

impl SessionObjects {
    pub fn create(generation: &str) -> Option<SessionObjects> {
        use windows::Win32::System::Threading::{CreateEventW, CreateMutexW};
        let alive_name = alive_name(generation);
        let standdown_name = standdown_name(generation);
        let an = to_wide(&alive_name);
        let sn = to_wide(&standdown_name);
        // created UNOWNED; this handle stays open for the session lifetime
        // (existence anchor — see the struct doc). The parking thread below
        // opens it by NAME and takes ownership — no HANDLE crosses a thread
        // boundary at spawn time.
        let anchor =
            unsafe { CreateMutexW(None, false, windows::core::PCWSTR(an.as_ptr())) }.ok()?;
        let standdown =
            unsafe { CreateEventW(None, true, false, windows::core::PCWSTR(sn.as_ptr())) }.ok()?;
        // park forever holding the mutex: acquires ownership immediately
        // (unowned), releases only by thread death = process death
        std::thread::spawn(move || {
            use windows::Win32::System::Threading::{
                OpenMutexW, WaitForSingleObject, INFINITE, SYNCHRONIZATION_ACCESS_RIGHTS,
            };
            const SYNCHRONIZE: u32 = 0x0010_0000;
            let an = to_wide(&alive_name);
            if let Ok(h) = unsafe {
                OpenMutexW(
                    SYNCHRONIZATION_ACCESS_RIGHTS(SYNCHRONIZE),
                    false,
                    windows::core::PCWSTR(an.as_ptr()),
                )
            } {
                let _ = unsafe { WaitForSingleObject(h, INFINITE) };
                loop {
                    std::thread::park();
                }
            }
        });
        Some(SessionObjects { standdown, anchor })
    }

    /// Signal the companion to exit WITHOUT cleanup (the client removed its
    /// own rules first — shutdown order matters).
    pub fn signal_standdown(&self) {
        use windows::Win32::System::Threading::SetEvent;
        let _ = unsafe { SetEvent(self.standdown) };
    }
}

impl Drop for SessionObjects {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        let _ = unsafe { CloseHandle(self.standdown) };
        let _ = unsafe { CloseHandle(self.anchor) };
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

// ---------------- activation (called by the zone-refresh loop) ----------------

/// Bring the cleanup owner up before auto mode may install anything
/// (plan §4.4: the watchdog is a precondition, not an assumption):
/// register/refresh the L2 task, create the session objects, spawn the L1
/// companion. `false` = refuse auto (`result=no_watchdog`).
pub fn activate(generation: &str) -> Option<SessionObjects> {
    if !register_task() {
        return None;
    }
    // journal the CURRENT generation BEFORE anything can install rules —
    // the L2 check reads it, and the activation window must never point at
    // a dead generation
    let _ = super::journal::write(&super::journal::Journal::new(generation.to_string()));
    let objs = SessionObjects::create(generation)?;
    if !spawn_companion(generation) {
        return None;
    }
    Some(objs)
}

fn schtasks(args: &[&str]) -> bool {
    std::process::Command::new("schtasks")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Register/refresh the L2 backstop task (idempotent /F). XML shape
/// probe-verified: PT1M repetition (the Task Scheduler floor — PT30S is
/// rejected at schema level) + BootTrigger + StartWhenAvailable +
/// battery-agnostic + ExecutionTimeLimit PT1M.
fn register_task() -> bool {
    let exe = match std::env::current_exe() {
        Ok(p) => p.display().to_string(),
        Err(_) => return false,
    };
    let xml_path = crate::svc::svc_home().join("splitdns-watchdog-task.xml");
    if std::fs::write(&xml_path, task_xml(&exe)).is_err() {
        return false;
    }
    schtasks(&[
        "/Create",
        "/F",
        "/XML",
        &xml_path.display().to_string(),
        "/TN",
        TASK_NAME,
    ])
}

fn task_xml(exe: &str) -> Vec<u8> {
    // UTF-16LE with BOM — Task Scheduler's requirement (probe-measured)
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n\
<Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger>\
<TimeTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary>\
<Repetition><Interval>PT1M</Interval></Repetition></TimeTrigger></Triggers>\r\n\
<Settings><StartWhenAvailable>true</StartWhenAvailable>\
<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\
<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\
<ExecutionTimeLimit>PT1M</ExecutionTimeLimit>\
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy></Settings>\r\n\
<Actions Context=\"Author\"><Exec><Command>{exe}</Command>\
<Arguments>--splitdns-watchdog-check</Arguments></Exec></Actions>\r\n\
</Task>\r\n"
    );
    let mut bytes: Vec<u8> = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.push(u as u8);
        bytes.push((u >> 8) as u8);
    }
    bytes
}

fn spawn_companion(generation: &str) -> bool {
    use std::os::windows::process::CommandExt;
    use windows::Win32::System::Threading::{
        CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS,
    };
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("--splitdns-watchdog").arg(generation);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // breakaway first (escape any hosting job); plain detached fallback
    let spawned = cmd
        .creation_flags(
            DETACHED_PROCESS.0 | CREATE_NEW_PROCESS_GROUP.0 | CREATE_BREAKAWAY_FROM_JOB.0,
        )
        .spawn()
        .or_else(|_| {
            cmd.creation_flags(DETACHED_PROCESS.0 | CREATE_NEW_PROCESS_GROUP.0)
                .spawn()
        });
    spawned.is_ok()
}

// ---------------- the two execution modes ----------------

/// L1 companion: `glmsvc --splitdns-watchdog <generation>`.
pub async fn companion_main(generation: &str) {
    use windows::Win32::Foundation::{CloseHandle, WAIT_ABANDONED_0, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        OpenEventW, OpenMutexW, WaitForMultipleObjects, SYNCHRONIZATION_ACCESS_RIGHTS,
    };
    const SYNCHRONIZE: u32 = 0x0010_0000;

    let an = to_wide(&alive_name(generation));
    let sn = to_wide(&standdown_name(generation));
    let alive = unsafe {
        OpenMutexW(
            SYNCHRONIZATION_ACCESS_RIGHTS(SYNCHRONIZE),
            false,
            windows::core::PCWSTR(an.as_ptr()),
        )
    };
    let standdown = unsafe {
        OpenEventW(
            SYNCHRONIZATION_ACCESS_RIGHTS(SYNCHRONIZE),
            false,
            windows::core::PCWSTR(sn.as_ptr()),
        )
    };
    let (alive, standdown) = match (alive, standdown) {
        (Ok(a), Ok(s)) => (a, s),
        (am, sm) => {
            // never silent: this exact path hid the anchor-handle bug (the
            // companion exited instantly and the watchdog was a no-op)
            let detail = format!(
                "companion could not open session objects (alive={}, standdown={}) - exiting without watching",
                am.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
                sm.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
            );
            crate::log_event("splitdns_watchdog_error", &detail);
            eprintln!("[splitdns-watchdog] {detail}");
            return;
        }
    };

    loop {
        let r = unsafe {
            WaitForMultipleObjects(&[standdown, alive], false, (HANG_POLL_SECS * 1000) as u32)
        };
        let code = r.0;
        if code == WAIT_OBJECT_0.0 {
            // graceful: the client removed its own rules, then signalled
            break;
        }
        if code == WAIT_ABANDONED_0.0 + 1 {
            // client process died — immediate, CPU-load-immune death signal
            let _ = remove_all_tagged("companion-death").await;
            break;
        }
        // timeout: hang channel — a hung-but-alive client goes stale like a
        // dead one; stay alive ourselves (a resumed client re-converges via
        // the reconciler's no-install hold; a later true death still signals)
        if heartbeat_stale() {
            let _ = remove_all_tagged("companion-hang").await;
        }
    }
    let _ = unsafe { CloseHandle(alive) };
    let _ = unsafe { CloseHandle(standdown) };
}

/// L2 backstop / boot tick: `glmsvc --splitdns-watchdog-check`. Reads the
/// current generation from the journal (persisted across reboot).
pub async fn check_main() {
    let Some(j) = super::journal::read() else {
        return; // never activated on this machine — nothing owned
    };
    use windows::Win32::Foundation::WAIT_TIMEOUT;
    use windows::Win32::System::Threading::{
        OpenMutexW, WaitForSingleObject, SYNCHRONIZATION_ACCESS_RIGHTS,
    };
    const SYNCHRONIZE: u32 = 0x0010_0000;

    let an = to_wide(&alive_name(&j.generation));
    let alive = unsafe {
        OpenMutexW(
            SYNCHRONIZATION_ACCESS_RIGHTS(SYNCHRONIZE),
            false,
            windows::core::PCWSTR(an.as_ptr()),
        )
    };
    match alive {
        Ok(h) => {
            // 0 ms probe: WAIT_OBJECT_0 impossible (the parking thread holds
            // it); WAIT_TIMEOUT = held = process alive — but the HANG
            // channel still applies: the loop may be wedged with the
            // process healthy, so a stale heartbeat cleans too.
            let r = unsafe { WaitForSingleObject(h, 0) };
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(h) };
            if r.0 == WAIT_TIMEOUT.0 {
                if heartbeat_stale() {
                    let _ = remove_all_tagged("task-hang").await;
                }
                return;
            }
            let _ = remove_all_tagged("task-mutex-dead").await;
        }
        Err(_) => {
            // no such mutex: no live session for the journalled generation
            // (post-reboot, post-crash, or post-disconnect). Only act when
            // something is actually resident — the heartbeat gate covers
            // the hung-client-with-dead-companion case.
            let _ = remove_all_tagged("task-no-session").await;
        }
    }
}

/// Install-time / uninstall-time / manual-clean helper: synchronous wrapper
/// around the tagged cleanup (used by `glmsvc uninstall` and
/// `glmcli splitdns-clean`).
pub async fn clean() -> usize {
    remove_all_tagged("manual-clean").await
}

/// Read-only diagnostic: `glmsvc --splitdns-status` — print every OS
/// resolver rule we can see as one JSON line (namespace/id/generation) so
/// operators and the e2e lane can assert ground truth PowerShell-free
/// (a resolver probe CANNOT distinguish "rule gone" from "rule present,
/// server dead" — the second FULL W43S3 run's false-recovery lesson).
/// Never mutates anything.
pub async fn status() -> anyhow::Result<usize> {
    let rules = super::channel::enumerate_retry().await?;
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
    Ok(rules.len())
}

/// Remove the L2 task (uninstall path).
pub fn delete_task() {
    let _ = schtasks(&["/Delete", "/F", "/TN", TASK_NAME]);
}
