//! W43 S5.1a: the platform channel for split-DNS OS-resolver rules.
//!
//! The reconciler speaks ONLY this neutral surface; each platform maps it
//! to its native mechanism (plan §4.1):
//! - Windows: NRPT rules via in-process WMI ([`super::nrpt`]) — the tag
//!   rides the rule Comment, deletion keys on the rule GUID.
//! - macOS (S5): `/etc/resolver/<fqdn>` files (resolver_files, next
//!   slice) — the tag rides a marker line, deletion keys on the fqdn.
//! - Other platforms: `unsupported` (the reconciler is inactive there
//!   anyway; the arm exists so every target COMPILES — the S3-era direct
//!   `nrpt` references from the reconciler broke all non-Windows builds,
//!   unnoticed because the WSL lane built a stale clone).
//!
//! [`InstalledRule::generation`] is `None` for a foreign (non-owned) rule
//! — that is the conflict signal (§4.5: refuse, never overwrite).

use anyhow::{anyhow, Result};

/// One installed resolver rule as seen by enumeration. `id` is the
/// platform deletion key (Windows: the rule GUID; macOS: the fqdn).
#[derive(Debug, Clone)]
pub struct InstalledRule {
    pub namespace: String,
    pub id: String,
    /// Some(generation) when the rule carries our ownership tag; None for
    /// a foreign rule.
    pub generation: Option<String>,
}

/// Plan §9: each privileged channel call gets 2 s + one retry.
#[cfg(any(windows, target_os = "macos"))]
const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[cfg(any(windows, target_os = "macos"))]
async fn run_with_timeout<T, F>(mut mk: F) -> Result<T>
where
    T: Send + 'static,
    F: FnMut() -> Box<dyn FnOnce() -> Result<T> + Send + 'static>,
{
    let mut last = anyhow!("channel call failed");
    for _ in 0..2 {
        let r = tokio::time::timeout(CALL_TIMEOUT, tokio::task::spawn_blocking(mk()))
            .await
            .map_err(|_| anyhow!("channel timeout"))?
            .map_err(|e| anyhow!("join: {e}"))
            .and_then(|r| r);
        match r {
            Ok(v) => return Ok(v),
            Err(e) => last = e,
        }
    }
    Err(last)
}

// ---------------- platform arms ----------------

/// Enumerate the rules the platform can see (ours AND foreign ones — the
/// reconciler needs foreign rules for conflict refusal).
pub async fn enumerate_retry() -> Result<Vec<InstalledRule>> {
    #[cfg(windows)]
    {
        run_with_timeout(|| Box::new(enumerate_sync)).await
    }
    #[cfg(target_os = "macos")]
    {
        run_with_timeout(|| Box::new(super::resolver_files::enumerate)).await
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err(anyhow!("unsupported platform (no split-DNS channel)"))
    }
}

/// Install/refresh our rule for `namespace` under `generation`. The
/// platform arm builds its own ownership tag.
pub async fn add_retry(namespace: &str, generation: &str) -> Result<()> {
    let ns = namespace.to_string();
    let gen = generation.to_string();
    #[cfg(windows)]
    {
        let comment = super::comment_for(&gen);
        run_with_timeout(move || {
            let ns = ns.clone();
            let comment = comment.clone();
            Box::new(move || super::nrpt::add(&ns, &comment))
        })
        .await
    }
    #[cfg(target_os = "macos")]
    {
        run_with_timeout(move || {
            let ns = ns.clone();
            let gen = gen.clone();
            Box::new(move || super::resolver_files::add(&ns, &gen))
        })
        .await
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (ns, gen);
        Err(anyhow!("unsupported platform (no split-DNS channel)"))
    }
}

/// Remove the rule with the platform deletion key `id`.
pub async fn remove_retry(id: &str) -> Result<()> {
    let g = id.to_string();
    #[cfg(windows)]
    {
        run_with_timeout(move || {
            let g = g.clone();
            Box::new(move || super::nrpt::remove(&g))
        })
        .await
    }
    #[cfg(target_os = "macos")]
    {
        run_with_timeout(move || {
            let g = g.clone();
            Box::new(move || super::resolver_files::remove(&g))
        })
        .await
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = g;
        Err(anyhow!("unsupported platform (no split-DNS channel)"))
    }
}

/// Whether an install failure is a privilege denial (the reconciler
/// surfaces the "needs the service context" hint for exactly this).
pub fn err_is_denied(e: &anyhow::Error) -> bool {
    #[cfg(windows)]
    {
        super::nrpt::err_is_access_denied(e)
    }
    #[cfg(target_os = "macos")]
    {
        super::resolver_files::err_is_denied(e)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = e;
        false
    }
}

#[cfg(windows)]
fn enumerate_sync() -> Result<Vec<InstalledRule>> {
    let rules = super::nrpt::enumerate()?;
    Ok(rules
        .into_iter()
        .map(|r| InstalledRule {
            generation: super::generation_of(&r.comment).map(str::to_string),
            namespace: r.namespace,
            id: r.guid,
        })
        .collect())
}
