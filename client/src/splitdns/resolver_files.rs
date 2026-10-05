//! W43 S5.1b: the macOS resolver-files channel — `/etc/resolver/<fqdn>`
//! scoped-resolver files (plan §4.1).
//!
//! Ownership model (review r2-1/r2-5): the FIRST line of each file is the
//! marker `# aztna:w43:<generation> managed` — a file without our marker
//! belongs to someone else and is NEVER touched (enumeration reports it as
//! a foreign rule; the reconciler refuses that suffix, plan §4.5). Writes
//! are atomic (tmp + rename in the same directory); the directory itself
//! is created if absent (stock macOS ships without `/etc/resolver`).
//!
//! Files are PERSISTENT across reboots — which is why the launchd
//! watchdog (S5.2) is boot-started, same shape as the Windows backstop.
//! The channel is exercised by the macOS mirror lane (S5.3); the pure
//! marker helpers are unit-tested cross-platform in [`super`].

#![cfg(target_os = "macos")]

use anyhow::{anyhow, Result};

use super::channel::InstalledRule;
use super::{marker_generation, resolver_file_body};

const RESOLVER_DIR: &str = "/etc/resolver";

fn path_for(fqdn: &str) -> std::path::PathBuf {
    std::path::Path::new(RESOLVER_DIR).join(fqdn)
}

/// Every file in /etc/resolver mapped to the neutral rule shape: ours
/// carry the marker generation; foreign files (no marker on the first
/// line) report `generation: None` — the conflict signal. `id` is the
/// fqdn (the filename IS the deletion key).
pub fn enumerate() -> Result<Vec<InstalledRule>> {
    let dir = std::path::Path::new(RESOLVER_DIR);
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow!("read {RESOLVER_DIR}: {e}")),
    };
    let mut rules = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // a dotfile (e.g. our atomic-tmp leftovers never persist, but be
        // strict) is not a resolver scope
        if name.starts_with('.') {
            continue;
        }
        let first = std::fs::read_to_string(&path)
            .map(|t| t.lines().next().unwrap_or("").to_string())
            .unwrap_or_default();
        rules.push(InstalledRule {
            namespace: name.to_string(),
            id: name.to_string(),
            generation: marker_generation(&first).map(str::to_string),
        });
    }
    Ok(rules)
}

/// Write (or idempotently rewrite) our scoped-resolver file for `fqdn`.
/// A pre-existing file WITHOUT our marker is refused — never overwrite
/// admin config (§4.5).
pub fn add(fqdn: &str, generation: &str) -> Result<()> {
    let path = path_for(fqdn);
    if path.exists() {
        let first = std::fs::read_to_string(&path)
            .map(|t| t.lines().next().unwrap_or("").to_string())
            .unwrap_or_default();
        if marker_generation(&first).is_none() {
            return Err(anyhow!(
                "refusing to touch non-owned resolver file for {fqdn}"
            ));
        }
    }
    std::fs::create_dir_all(RESOLVER_DIR).map_err(|e| anyhow!("create {RESOLVER_DIR}: {e}"))?;
    let tmp = path.with_extension("aztna-tmp");
    std::fs::write(&tmp, resolver_file_body(generation))
        .map_err(|e| anyhow!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| anyhow!("rename into {}: {e}", path.display()))?;
    Ok(())
}

/// Remove our file for `fqdn`. A file without our marker is NOT ours —
/// refuse (the reconciler only calls this for owned rules; the guard is
/// defense in depth).
pub fn remove(fqdn: &str) -> Result<()> {
    let path = path_for(fqdn);
    match std::fs::read_to_string(&path) {
        Ok(t) => {
            let first = t.lines().next().unwrap_or("");
            if marker_generation(first).is_none() {
                return Err(anyhow!("refusing to remove non-owned file for {fqdn}"));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(anyhow!("read {}: {e}", path.display())),
    }
    std::fs::remove_file(&path).map_err(|e| anyhow!("remove {}: {e}", path.display()))
}

/// Privilege denial = the daemon is not root (EACCES on /etc/resolver).
pub fn err_is_denied(e: &anyhow::Error) -> bool {
    e.chain()
        .any(|c| c.to_string().contains("Permission denied"))
}
