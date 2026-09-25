//! W43 S3: split-DNS owned-state journal (plan §4.4).
//!
//! Division of truth: **tag enumeration is the source of truth for
//! deletion** (works even if this journal is lost); the journal is the
//! audit + fast-path record of what THIS generation installed (namespace →
//! rule GUID, the measured NRPT deletion key). Reconcile-first at client
//! start re-enumerates rather than trusting the journal.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;

use super::is_ours;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JournalEntry {
    /// Exact namespace (fqdn) the rule routes.
    pub namespace: String,
    /// The NRPT rule's Name GUID — the only value Remove accepts.
    pub guid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Journal {
    pub schema: u8,
    pub generation: String,
    pub installed: Vec<JournalEntry>,
}

impl Journal {
    pub fn new(generation: String) -> Self {
        Journal {
            schema: 1,
            generation,
            installed: Vec::new(),
        }
    }
}

pub fn journal_path() -> PathBuf {
    crate::svc::svc_home().join("splitdns-state.json")
}

/// Atomic write (tmp + rename) so a crash mid-write can never leave a
/// half-parsed journal behind.
pub fn write(j: &Journal) -> io::Result<()> {
    let path = journal_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(j).unwrap_or_default())?;
    std::fs::rename(&tmp, &path)
}

pub fn read() -> Option<Journal> {
    let txt = std::fs::read_to_string(journal_path()).ok()?;
    let j: Journal = serde_json::from_str(&txt).ok()?;
    if j.schema != 1 {
        return None; // unknown future format — enumeration is the truth anyway
    }
    Some(j)
}

/// Rules present per the journal that this generation owns. Used only as a
/// cross-check against live enumeration (which filters by the ownership
/// tag, journal-independent).
pub fn owned_namespaces(j: &Journal) -> Vec<String> {
    j.installed.iter().map(|e| e.namespace.clone()).collect()
}

/// True if a rule's Comment carries our tag — the journal-independent
/// ownership test used before any deletion.
pub fn rule_is_ours(comment: &str) -> bool {
    is_ours(comment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // The journal lives in svc_home() — tests redirect via AZTNA_SVC_HOME
    // so they never touch a real ProgramData path.
    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn test_home() -> std::path::PathBuf {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let d = std::env::temp_dir().join(format!(
            "aztna-w43-journal-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // env-var tests serialized in ONE test fn — AZTNA_SVC_HOME is global
    // state and parallel #[test]s race on set/remove
    #[test]
    fn journal_roundtrip_unknown_schema_and_ownership() {
        let home = test_home();
        std::env::set_var("AZTNA_SVC_HOME", &home);

        // roundtrip + atomicity
        let j = Journal {
            schema: 1,
            generation: "gen-abc".into(),
            installed: vec![
                JournalEntry {
                    namespace: "erp.corp".into(),
                    guid: "{1111}".into(),
                },
                JournalEntry {
                    namespace: "api.erp.corp".into(),
                    guid: "{2222}".into(),
                },
            ],
        };
        write(&j).unwrap();
        let back = read().unwrap();
        assert_eq!(j, back);
        assert_eq!(
            owned_namespaces(&back),
            vec!["erp.corp".to_string(), "api.erp.corp".to_string()]
        );
        assert!(journal_path()
            .with_extension("json.tmp")
            .metadata()
            .is_err()); // no tmp residue

        // unknown future schema is ignored (enumeration is the truth anyway)
        std::fs::write(
            journal_path(),
            r#"{"schema":99,"generation":"x","installed":[]}"#,
        )
        .unwrap();
        assert!(read().is_none());

        // ownership test is tag-based, journal-independent
        assert!(rule_is_ours("aztna:w43:gen-1"));
        assert!(!rule_is_ours("admin's own rule"));
        assert!(!rule_is_ours(""));

        std::env::remove_var("AZTNA_SVC_HOME");
        let _ = std::fs::remove_dir_all(&home);
    }
}
