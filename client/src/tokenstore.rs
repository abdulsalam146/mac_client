//! W13 step 3 [one token-store module, two profiles — closes the
//! state.json plaintext TODO(P2)/DR-CLT-027]: the access token is
//! DPAPI-wrapped at rest in BOTH hosts. The standalone CLI uses the
//! USER scope (only that account's processes can unprotect — not even
//! the service); the service host (glmsvc) uses MACHINE scope inside
//! its ACL-restricted ProgramData root (offline/stolen-disk protection;
//! the ACL excludes other local users). Same code, the scope is a
//! security parameter of the host. Fail-safe: an unwrappable blob means
//! NO token (logged-out), never a plaintext fallback.

use anyhow::{anyhow, Result};
use base64::Engine as _;
use std::sync::OnceLock;

/// The host declares its profile at startup (default: user — the CLI).
/// A process serves ONE profile for its lifetime.
static MACHINE: OnceLock<bool> = OnceLock::new();

pub fn set_machine_profile() {
    let _ = MACHINE.set(true);
}

pub fn machine_profile() -> bool {
    *MACHINE.get_or_init(|| false)
}

/// Wrap a token to base64(blob) under the active profile.
/// Windows: DPAPI (user/machine scope per the host profile).
/// Unix (W29 step 2): AZDP2 via the atrest module — one wrap key for the
/// state dir (key-file default or operator passphrase); the profile
/// distinction is a Windows concept and collapses there.
pub fn wrap_token(plain: &str) -> Result<String> {
    #[cfg(windows)]
    let blob = crate::identity::dpapi_protect_scoped(plain.as_bytes(), machine_profile())?;
    #[cfg(unix)]
    let blob = {
        let dir = crate::state_path()
            .parent()
            .ok_or_else(|| anyhow!("tokenstore: no state dir"))?
            .to_path_buf();
        crate::atrest::wrap(crate::atrest::env_lookup, &dir, plain.as_bytes())?
    };
    Ok(base64::engine::general_purpose::STANDARD.encode(blob))
}

/// Unwrap a base64(blob). Errors on scope mismatch, corruption, wrong
/// passphrase, or a different account — the caller treats Err as
/// no-token (fail closed).
pub fn unwrap_token(b64: &str) -> Result<String> {
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| anyhow!("token blob b64: {e}"))?;
    #[cfg(windows)]
    let plain = crate::identity::dpapi_unprotect_scoped(&blob, machine_profile())?;
    #[cfg(unix)]
    let plain = {
        let dir = crate::state_path()
            .parent()
            .ok_or_else(|| anyhow!("tokenstore: no state dir"))?
            .to_path_buf();
        // strict: a token is never legitimately plaintext at rest [W13]
        crate::atrest::unwrap_strict(crate::atrest::env_lookup, &dir, &blob)?
    };
    String::from_utf8(plain).map_err(|e| anyhow!("token utf8: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Windows: DPAPI semantics (profile scope). Unix (W29 step 2): AZDP2 —
    // assertions restored to "actually encrypted at rest", now against the
    // atrest tier. The unix tests pin AZTNA_STATE_DIR under a mutex (the
    // env is process-global; tests run in parallel).

    #[cfg(windows)]
    #[test]
    fn roundtrip_under_active_profile() {
        // default profile = user scope
        assert!(!machine_profile());
        let w = wrap_token("sekret-token-1").unwrap();
        assert_ne!(w, "sekret-token-1");
        assert!(!w.contains("sekret"));
        assert_eq!(unwrap_token(&w).unwrap(), "sekret-token-1");
    }

    #[cfg(windows)]
    #[test]
    fn corrupt_blob_fails_closed() {
        assert!(unwrap_token("AAAAnotablob==").is_err());
        // a random valid-b64 garbage blob fails at CryptUnprotectData
        let garbage = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert!(unwrap_token(&garbage).is_err());
    }

    #[cfg(unix)]
    mod azdp2 {
        use super::super::*;

        fn isolated_state() -> std::path::PathBuf {
            let d = std::env::temp_dir().join(format!(
                "aztna-tokenstore-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&d).unwrap();
            // fixture matches the hygiene contract (atrest refuses 0755)
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::env::set_var("AZTNA_STATE_DIR", &d);
            d
        }

        #[test]
        fn roundtrip_is_azdp2_encrypted() {
            let _g = crate::TEST_STATE_ENV_SER.lock().unwrap();
            let d = isolated_state();
            let w = wrap_token("sekret-token-1").unwrap();
            assert_ne!(w, "sekret-token-1");
            assert!(!w.contains("sekret"));
            let raw = base64::engine::general_purpose::STANDARD
                .decode(&w)
                .unwrap();
            assert!(raw.starts_with(b"AZDP2"), "token blob must be AZDP2");
            assert_eq!(unwrap_token(&w).unwrap(), "sekret-token-1");
            std::env::remove_var("AZTNA_STATE_DIR");
            let _ = std::fs::remove_dir_all(&d);
        }

        #[test]
        fn garbage_blob_fails_closed() {
            let _g = crate::TEST_STATE_ENV_SER.lock().unwrap();
            let d = isolated_state();
            // valid b64, neither AZDP2 nor AZDP1 — the strict tier refuses
            let garbage = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
            assert!(unwrap_token(&garbage).is_err());
            assert!(unwrap_token("AAAAnotablob==").is_err());
            std::env::remove_var("AZTNA_STATE_DIR");
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[cfg(windows)]
    #[test]
    fn scope_semantics_measured() {
        // MEASURED (2026-09-02, Win11): the unprotect FLAGS are NOT an
        // enforcement boundary — the BLOB's own scope decides which
        // master key can decrypt it. Consequences pinned by this test:
        // 1. a MACHINE blob unwraps under ANY local principal (here: this
        //    unelevated user process) — machine scope protects OFFLINE
        //    only; local-user exclusion is the service-root ACL's job.
        // 2. a USER blob roundtrips under the owning account. It cannot
        //    be decrypted by processes holding only the machine key
        //    (other accounts), which is what keeps the CLI's token
        //    opaque to the service — untestable single-account, stated.
        let m = crate::identity::dpapi_protect_scoped(b"m-scope", true).unwrap();
        assert!(crate::identity::dpapi_unprotect_scoped(&m, false).is_ok());
        let u = crate::identity::dpapi_protect_scoped(b"u-scope", false).unwrap();
        assert!(crate::identity::dpapi_unprotect_scoped(&u, false).is_ok());
    }
}
