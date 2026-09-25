//! W43 S3.2: the split-DNS reconciler — desired-vs-installed convergence
//! for the exact namespaces the operator allowlisted (plan §4.2/§4.3/§4.4).
//!
//! Lifecycle: one `tick` per zone-refresh cycle (10 s cadence, the loop
//! that owns this reconciler), plus `shutdown` at session end. The health
//! lease is the loop itself: the heartbeat is written HERE, at the END of
//! a cycle — a hung loop stops heartbeating exactly like a dead one.
//!
//! Lease-gated installation has the r4 compare-before-write order: the
//! PREVIOUS successful heartbeat is compared against now BEFORE a new one
//! is written; a gap past [`STALENESS_SECS`] engages the no-install hold
//! and mints a NEW generation (a fresh heartbeat alone cannot clear the
//! hold — only one fully healthy cycle does).

use std::collections::HashMap;

use super::{
    channel, desired_namespaces, journal, new_generation, RejectReason, SplitDnsConfig,
    SplitDnsMode,
};

/// Plan §4.4 (v1.6): 25 s — the worst degraded path (hung client + dead
/// companion watchdog) fits the 90 s per-origin ceiling: 25 + 60 + ~2 ≈ 87.
pub const STALENESS_SECS: u64 = 25;

pub fn heartbeat_path() -> std::path::PathBuf {
    crate::svc::svc_home().join("dns.heartbeat")
}

/// Pure lease state machine (unit-tested): decides, from the age of the
/// PREVIOUS successful heartbeat and this cycle's health, whether the
/// just-woke loop was stale (engage hold + new generation) and whether an
/// existing hold may lift (one fully healthy cycle since it engaged).
#[derive(Debug, PartialEq, Eq)]
pub struct LeaseDecision {
    pub stale: bool,
    pub clear_hold: bool,
}

pub fn lease_decision(prev_age_secs: Option<u64>, fetch_ok: bool, hold: bool) -> LeaseDecision {
    let stale = match prev_age_secs {
        Some(age) => age > STALENESS_SECS,
        None => false, // first cycle of this process — nothing to compare
    };
    let clear_hold = hold && !stale && fetch_ok;
    LeaseDecision { stale, clear_hold }
}

/// Outcome summary for events/metrics.
#[derive(Default)]
pub struct TickStats {
    pub installed: usize,
    pub removed: usize,
    pub conflicts: Vec<String>,
    pub rejected_invalid: usize,
    pub rejected_not_allowlisted: usize,
    pub errors: usize,
}

pub struct Reconciler {
    active: bool,
    cfg: SplitDnsConfig,
    generation: String,
    hold: bool,
    installed: HashMap<String, String>, // namespace -> guid (fast path; enumeration is truth)
}

impl Reconciler {
    /// `Some` only when auto mode is configured AND the platform channel
    /// exists (Windows since S3; macOS since S5). Constructing with an
    /// unsupported platform yields an inactive reconciler that only
    /// reports `unsupported`.
    pub fn new(cfg: SplitDnsConfig) -> Self {
        let active = cfg.mode == SplitDnsMode::Auto && cfg!(any(windows, target_os = "macos"));
        let generation = new_generation();
        if active {
            #[cfg(windows)]
            super::watchdog::seed_recoveries_counter();
            #[cfg(target_os = "macos")]
            super::watchdog_macos::seed_recoveries_counter();
            // surface operator-config problems once at construction
            for a in &cfg.suffix_allowlist {
                if let Err(e) = super::normalize_name(a) {
                    crate::log_event(
                        "splitdns_conflict",
                        &format!("allowlist entry {a:?} invalid: {e}"),
                    );
                }
            }
            if cfg.suffix_allowlist.is_empty() {
                crate::log_event(
                    "splitdns_conflict",
                    "auto mode active with EMPTY suffix allowlist - no rules will install (D10)",
                );
            }
        }
        Reconciler {
            active,
            cfg,
            generation,
            hold: false,
            installed: HashMap::new(),
        }
    }

    pub fn active(&self) -> bool {
        self.active
    }

    /// Watchdog-precondition failure path (plan §4.4): auto mode refused,
    /// manual fallback.
    pub fn deactivate(&mut self) {
        if self.active {
            self.active = false;
        }
    }

    pub fn generation(&self) -> &str {
        &self.generation
    }

    /// One reconcile cycle. `zone_names` = the names the current (or
    /// last-known) zone map holds; `fetch_ok` = this cycle's zone fetch
    /// succeeded (or was a definitive Denied — still a healthy cycle;
    /// a transport failure is not).
    pub async fn tick(&mut self, zone_names: &[String], fetch_ok: bool) {
        if !self.active {
            return;
        }
        fault_pause_if_armed().await;
        let mut stats = TickStats::default();

        // ---- lease: compare the PREVIOUS heartbeat BEFORE writing a new one (r4)
        let prev = read_prev_heartbeat_secs();
        let dec = lease_decision(prev, fetch_ok, self.hold);
        if dec.stale {
            self.hold = true;
            self.generation = new_generation();
            self.installed.clear();
            crate::log_event(
                "splitdns_removed",
                "reason=stale_generation (lease gap past threshold - no-install hold engaged)",
            );
            metrics_event("recover", "stale_generation");
        } else if dec.clear_hold {
            self.hold = false;
            crate::log_event(
                "splitdns_removed",
                "reason=hold_released (one healthy cycle)",
            );
        }

        // ---- ground truth
        let ground = match channel::enumerate_retry().await {
            Ok(v) => v,
            Err(e) => {
                crate::log_event("splitdns_conflict", &format!("enumerate failed: {e:#}"));
                metrics_event("error", "enumerate");
                write_heartbeat(); // the loop itself is alive — lease stays fresh
                return;
            }
        };

        // ---- desired set (D10 allowlist)
        let (mut desired, rejected) =
            desired_namespaces(zone_names.iter().cloned(), &self.cfg.suffix_allowlist);
        stats.rejected_invalid = rejected
            .iter()
            .filter(|(_, r)| *r == RejectReason::InvalidSuffix)
            .count();
        stats.rejected_not_allowlisted = rejected.len() - stats.rejected_invalid;
        if stats.rejected_invalid > 0 {
            metrics_event("conflict", "invalid_suffix");
        }

        // ---- conflicts: a NON-owned rule for one of our suffixes → refuse
        //      that suffix (never overwrite admin config — plan §4.5)
        for r in &ground {
            if r.generation.is_none() && desired.contains(&r.namespace) {
                desired.retain(|n| n != &r.namespace);
                stats.conflicts.push(r.namespace.clone());
            }
        }
        for c in &stats.conflicts {
            crate::log_event(
                "splitdns_conflict",
                &format!("suffix={c} owner=foreign (refused)"),
            );
        }
        if !stats.conflicts.is_empty() {
            metrics_event("conflict", "conflict");
        }

        // ---- removals always converge (safe under hold):
        //      tagged rules of ANY generation not in the desired set
        for r in &ground {
            if r.generation.is_none() {
                continue;
            }
            if !desired.contains(&r.namespace)
                || r.generation.as_deref() != Some(self.generation.as_str())
            {
                match channel::remove_retry(&r.id).await {
                    Ok(()) => {
                        stats.removed += 1;
                        self.installed.remove(&r.namespace);
                    }
                    Err(e) => {
                        stats.errors += 1;
                        crate::log_event(
                            "splitdns_conflict",
                            &format!("remove {} failed: {e:#}", r.namespace),
                        );
                    }
                }
            }
        }

        // ---- installs: only under a fresh lease (no-install hold — r3-1/r4)
        if !self.hold {
            let missing: Vec<String> = desired
                .iter()
                .filter(|n| !self.installed.contains_key(*n))
                .cloned()
                .collect();
            for ns in &missing {
                match channel::add_retry(ns, &self.generation).await {
                    Ok(()) => {
                        stats.installed += 1;
                        crate::log_event("splitdns_installed", &format!("namespace={ns}"));
                    }
                    Err(e) => {
                        stats.errors += 1;
                        if channel::err_is_denied(&e) {
                            // unelevated context (dev console) — say it once per pass
                            crate::log_event(
                                "splitdns_conflict",
                                "install ACCESS-DENIED - auto mode needs the LocalSystem service context",
                            );
                        } else {
                            crate::log_event(
                                "splitdns_conflict",
                                &format!("install {ns} failed: {e:#}"),
                            );
                        }
                    }
                }
            }
            // capture platform ids for the journal (Add returns none) — one
            // re-enumerate only when something changed
            if stats.installed > 0 || stats.removed > 0 {
                if let Ok(fresh) = channel::enumerate_retry().await {
                    self.installed = fresh
                        .into_iter()
                        .filter(|r| r.generation.as_deref() == Some(self.generation.as_str()))
                        .map(|r| (r.namespace, r.id))
                        .collect();
                }
            }
        }

        // ---- observability + journal
        let _ = journal::write(&journal::Journal {
            schema: 1,
            generation: self.generation.clone(),
            installed: self
                .installed
                .iter()
                .map(|(ns, guid)| journal::JournalEntry {
                    namespace: ns.clone(),
                    guid: guid.clone(),
                })
                .collect(),
        });
        crate::metrics::splitdns_rules_active().set(self.installed.len() as i64);
        if stats.installed > 0 {
            metrics_event("install", "ok");
        }
        if stats.removed > 0 {
            metrics_event("remove", "ok");
        }
        if stats.errors > 0 {
            metrics_event("install", "error");
        }

        // ---- heartbeat LAST: written by the healthy loop itself; a tick
        //      that hangs mid-cycle never refreshes the lease
        write_heartbeat();
    }

    /// Session end (svc-disconnect / engine cancel): remove ALL tagged
    /// rules (single-owner-per-machine means no other live generation),
    /// reset the journal, zero the gauge.
    pub async fn shutdown(&mut self) {
        if !self.active {
            return;
        }
        let mut removed = 0;
        if let Ok(ground) = channel::enumerate_retry().await {
            for r in &ground {
                if r.generation.is_some() && channel::remove_retry(&r.id).await.is_ok() {
                    removed += 1;
                }
            }
        }
        self.installed.clear();
        let _ = journal::write(&journal::Journal::new(new_generation()));
        crate::metrics::splitdns_rules_active().set(0);
        if removed > 0 {
            crate::log_event(
                "splitdns_removed",
                &format!("reason=disconnect count={removed}"),
            );
            metrics_event("remove", "ok");
        }
    }
}

/// Dev/test-only fault hook (plan §10 drills (f)/(g)): armed by
/// `AZTNA_SPLITDNS_FAULT=1` (the e2e lane's svc env — never a production
/// config) and triggered by the presence of
/// `<svc-home>/splitdns-fault-hang`, this parks the tick BEFORE the
/// lease compare — the heartbeat freezes while the process stays alive
/// and the parking thread keeps the alive-mutex (a WEDGED loop, not a
/// dead one). On release the same tick's compare then sees the stale
/// previous heartbeat (r4's compare-before-write, at the post-gap
/// "now"), engages the no-install hold + a new generation, and the
/// fresh heartbeat it writes does NOT clear its own hold — one fully
/// healthy later cycle must arrive before installs resume.
async fn fault_pause_if_armed() {
    if std::env::var("AZTNA_SPLITDNS_FAULT").ok().as_deref() != Some("1") {
        return;
    }
    let p = crate::svc::svc_home().join("splitdns-fault-hang");
    while p.exists() {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

fn read_prev_heartbeat_secs() -> Option<u64> {
    let txt = std::fs::read_to_string(heartbeat_path()).ok()?;
    let micros: u128 = txt.trim().parse().ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    // clock skew guard: a future timestamp is not "fresh", it is unknown
    if micros > now {
        return None;
    }
    Some(((now - micros) / 1_000_000) as u64)
}

fn write_heartbeat() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0);
    let p = heartbeat_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(p, format!("{}", now));
}

fn metrics_event(op: &str, result: &str) {
    crate::metrics::splitdns_rule_ops()
        .with_label_values(&[platform_label(), op, result])
        .inc();
}

pub fn platform_label() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "macos"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_decision_matrix() {
        // first cycle: nothing to compare — not stale, hold untouched
        assert_eq!(
            lease_decision(None, true, false),
            LeaseDecision {
                stale: false,
                clear_hold: false
            }
        );
        // fresh lease, no hold
        assert_eq!(
            lease_decision(Some(5), true, false),
            LeaseDecision {
                stale: false,
                clear_hold: false
            }
        );
        // stale engages (r4: compare BEFORE the new write)
        assert_eq!(
            lease_decision(Some(30), true, false),
            LeaseDecision {
                stale: true,
                clear_hold: false
            }
        );
        // hold lifts only on a FULLY healthy cycle: stale ⇒ stays held ...
        assert_eq!(
            lease_decision(Some(30), true, true),
            LeaseDecision {
                stale: true,
                clear_hold: false
            }
        );
        // ... fresh but fetch failed ⇒ not fully healthy ...
        assert_eq!(
            lease_decision(Some(5), false, true),
            LeaseDecision {
                stale: false,
                clear_hold: false
            }
        );
        // ... fresh + fetch ok ⇒ lift
        assert_eq!(
            lease_decision(Some(5), true, true),
            LeaseDecision {
                stale: false,
                clear_hold: true
            }
        );
        // boundary: exactly the threshold is NOT stale (> is)
        assert!(!lease_decision(Some(STALENESS_SECS), true, false).stale);
        assert!(lease_decision(Some(STALENESS_SECS + 1), true, false).stale);
    }
}
