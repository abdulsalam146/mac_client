//! aztna-keys — the shared key-at-rest wrap core [W23 S3, gap 2.12].
//!
//! Promoted VERBATIM from controller/src/dpapi.rs (W21) so the gateway can
//! protect its key material with the same machinery. PURE primitives
//! only — no metrics, no logging, no process-global state: callers own
//! their observability and their env resolution (the controller keeps its
//! wrapmode state machine; the gateway brings its own thin resolver over
//! the shared `wrapmode::resolve` decision core). On-disk formats are
//! byte-identical to W21's (the controller's W21 lane is the parity gate).

#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE,
};

const MAGIC: &[u8] = b"AZDP1";

pub fn is_wrapped(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// True when the bytes are wrapped in ANY at-rest format (AZDP1 DPAPI/
/// passthrough, or unix AZDP2). Key-file readers use this to distinguish
/// "unwrap this" from "this is legacy plaintext/hex payload".
pub fn is_wrapped_key(bytes: &[u8]) -> bool {
    // W23 S3: both magics on every platform — the CONTROLLER only ever
    // writes AZDP2 on unix (so its Windows behavior is unchanged), but
    // the shared crate must detect a wrapped blob regardless of which
    // host wrote it (a key file moved between hosts unwraps-or-errors,
    // never falls into the legacy-plaintext path).
    is_wrapped(bytes) || azdp2::is_azdp2(bytes)
}

/// Wrap plaintext; returns MAGIC || DPAPI blob. Non-Windows: passthrough
/// wrapped with the magic (documented dev limitation).
pub fn protect(plain: &[u8]) -> anyhow::Result<Vec<u8>> {
    #[cfg(windows)]
    {
        let blob = protect_win(plain)?;
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&blob);
        Ok(out)
    }
    #[cfg(not(windows))]
    {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(plain);
        Ok(out)
    }
}

/// Unwrap MAGIC || blob. Fails if the blob was copied from another host.
pub fn unprotect(wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
    let blob = wrapped
        .strip_prefix(MAGIC)
        .ok_or_else(|| anyhow::anyhow!("not a wrapped blob"))?;
    #[cfg(windows)]
    return unprotect_win(blob);
    #[cfg(not(windows))]
    Ok(blob.to_vec())
}

#[cfg(windows)]
fn crypt_blob(bytes: &[u8]) -> windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
    windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    }
}

#[cfg(windows)]
fn protect_win(plain: &[u8]) -> anyhow::Result<Vec<u8>> {
    let inb = crypt_blob(plain);
    let mut out = windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &inb,
            windows::core::PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut out,
        )
        .map_err(|e| anyhow::anyhow!("CryptProtectData: {e}"))?;
    }
    let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    unsafe {
        windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
            out.pbData as *mut _,
        ));
    }
    Ok(v)
}

#[cfg(windows)]
fn unprotect_win(blob: &[u8]) -> anyhow::Result<Vec<u8>> {
    let inb = crypt_blob(blob);
    let mut out = windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB::default();
    let res = unsafe {
        CryptUnprotectData(
            &inb,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut out,
        )
    };
    if let Err(e) = res {
        anyhow::bail!("CryptUnprotectData: {e} (blob copied from another host?)");
    }
    let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    unsafe {
        windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
            out.pbData as *mut _,
        ));
    }
    Ok(v)
}

// ---------- W21 Stage M: AZDP2 passphrase-wrapped at-rest (unix) ----------
// Closes gap 2.11's M tier: the CA/token/db key files are encrypted at
// rest under a passphrase secret (env / credential file / systemd
// LoadCredential=), so a stolen data dir is ciphertext, not keys.
// Windows is deliberately untouched: DPAPI stays unconditional there.

/// LOCKED one-way-door format (plan §3.2, D3 — owner review round 1):
/// `AZDP2` || argon2id salt (16B) || XChaCha20-Poly1305 nonce (24B) ||
/// ciphertext+tag (Poly1305 tag = trailing 16B). The byte-layout pin test
/// asserts these offsets; extend only via a new magic (AZDP3).
///
/// W23 S3: available on ALL platforms in the crate (pure crypto) — the
/// unix-only posture was the CONTROLLER's story; the gateway consumes it
/// where it runs. Callers cfg-gate their own surfaces as before.
pub mod azdp2 {
    use anyhow::Result;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    pub const MAGIC: &[u8; 5] = b"AZDP2";
    pub const SALT_LEN: usize = 16;
    pub const NONCE_LEN: usize = 24;
    pub const TAG_LEN: usize = 16;

    pub fn is_azdp2(bytes: &[u8]) -> bool {
        bytes.starts_with(MAGIC)
    }

    /// argon2id(pass, salt) -> 32B AEAD key. Params arrive floor-clamped
    /// by the caller (wrapmode) — env numbers are never trusted raw.
    pub fn derive_key(pass: &[u8], salt: &[u8], m_kib: u32, t: u32) -> Result<[u8; 32]> {
        let params = argon2::Params::new(m_kib, t, 1, Some(32))
            .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
        let a2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut key = [0u8; 32];
        a2.hash_password_into(pass, salt, &mut key)
            .map_err(|e| anyhow::anyhow!("argon2id KDF: {e}"))?;
        Ok(key)
    }

    /// Encrypt under the CALLER's salt (the salt and the KDF key must
    /// correspond — two independently generated salts was the bug the
    /// lifecycle test caught: the file salt must be the one the key was
    /// derived for). Only the nonce is generated here.
    pub fn wrap(plain: &[u8], key: &[u8; 32], salt: &[u8; SALT_LEN]) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new(key.into());
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload::from(plain))
            .map_err(|e| anyhow::anyhow!("azdp2 encrypt: {e}"))?;
        let mut out = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Layout split (also the parse the §9 pin test walks).
    pub fn parse(blob: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
        let body = blob
            .strip_prefix(MAGIC)
            .ok_or_else(|| anyhow::anyhow!("not an AZDP2 blob"))?;
        if body.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
            anyhow::bail!("AZDP2 blob truncated ({}B body)", body.len());
        }
        Ok((
            &body[..SALT_LEN],
            &body[SALT_LEN..SALT_LEN + NONCE_LEN],
            &body[SALT_LEN + NONCE_LEN..],
        ))
    }

    pub fn unwrap(blob: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        let (_salt, nonce, ct) = parse(blob)?;
        let cipher = XChaCha20Poly1305::new(key.into());
        cipher
            .decrypt(XNonce::from_slice(nonce), Payload::from(ct))
            .map_err(|_| {
                anyhow::anyhow!("AZDP2 authentication failed — wrong passphrase or corrupted file")
            })
    }
}

pub fn key_path_override_with(
    lookup: impl Fn(&str) -> Option<String>,
    _env_name: &str,
    default: &std::path::Path,
) -> std::path::PathBuf {
    match lookup(_env_name) {
        Some(p) => {
            let p = p.trim();
            if p.is_empty() {
                default.to_path_buf()
            } else {
                std::path::PathBuf::from(p)
            }
        }
        None => default.to_path_buf(),
    }
}

/// Env shell: a stray `AZTNA_CA_KEY_FILE=` must not redirect key material
/// to `""` (empty = unset, filtered in the pure core).
pub fn key_path_override(env_name: &str, default: &std::path::Path) -> std::path::PathBuf {
    key_path_override_with(|n| std::env::var(n).ok(), env_name, default)
}

/// The shared wrap-mode DECISION core (env resolution policy). The
/// controller's wrapmode state machine and the gateway's resolver both
/// call this — the policy text has exactly one home.
pub mod wrapmode {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WrapMode {
        /// AZDP1 passthrough — plaintext at rest, dev/pilot only, gated by
        /// AZTNA_ALLOW_PLAINTEXT_KEYS=1 under `auto` (the D2 strict flip).
        Plaintext,
        Azdp2,
    }

    #[derive(Debug, Clone)]
    pub struct Resolved {
        pub mode: WrapMode,
        pub passphrase: Option<String>,
        pub m_kib: u32,
        pub t: u32,
    }

    /// Pure decision core (the W19 pattern): every fail-closed branch
    /// returns a named, actionable error.
    pub fn resolve(
        mode_env: Option<&str>,
        secret: Option<&str>,
        allow_plaintext: bool,
    ) -> Result<WrapMode, String> {
        let mode = mode_env.unwrap_or("auto").trim().to_ascii_lowercase();
        let secret = secret.map(|s| !s.trim().is_empty()).unwrap_or(false);
        match mode.as_str() {
            "auto" => {
                if secret {
                    Ok(WrapMode::Azdp2)
                } else if allow_plaintext {
                    Ok(WrapMode::Plaintext)
                } else {
                    Err("no passphrase source and plaintext keys are not allowed: set \
                        AZTNA_KEY_WRAP_PASSPHRASE or AZTNA_KEY_PASSPHRASE_FILE, or explicitly \
                        opt into plaintext with AZTNA_ALLOW_PLAINTEXT_KEYS=1 (dev only)"
                        .into())
                }
            }
            "passphrase" => {
                if secret {
                    Ok(WrapMode::Azdp2)
                } else {
                    Err("AZTNA_KEY_WRAP_MODE=passphrase but no passphrase source \
                        (AZTNA_KEY_WRAP_PASSPHRASE / AZTNA_KEY_PASSPHRASE_FILE)"
                        .into())
                }
            }
            "plaintext-pilot" => {
                if secret {
                    Err("AZTNA_KEY_WRAP_MODE=plaintext-pilot but a passphrase source is \
                        also set — contradictory; pick one"
                        .into())
                } else {
                    Ok(WrapMode::Plaintext)
                }
            }
            other => Err(format!(
                "AZTNA_KEY_WRAP_MODE='{other}' is invalid (expected auto | passphrase | plaintext-pilot)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azdp1_roundtrip_and_magic() {
        let w = protect(b"secret-key-bytes").unwrap();
        assert!(is_wrapped(&w));
        assert!(is_wrapped_key(&w));
        assert_eq!(unprotect(&w).unwrap(), b"secret-key-bytes");
        assert!(!is_wrapped(b"-----BEGIN"));
    }

    #[test]
    fn azdp2_roundtrip_byte_layout() {
        let key = azdp2::derive_key(b"pass", b"[0123456789abcde]", 8, 1).unwrap();
        let salt = [7u8; azdp2::SALT_LEN];
        let blob = azdp2::wrap(b"payload", &key, &salt).unwrap();
        assert!(azdp2::is_azdp2(&blob));
        assert_eq!(azdp2::unwrap(&blob, &key).unwrap(), b"payload");
        let wrong = azdp2::derive_key(b"pass2", b"[0123456789abcde]", 8, 1).unwrap();
        assert!(azdp2::unwrap(&blob, &wrong).is_err());
    }

    #[test]
    fn resolve_core_matrix() {
        use crate::wrapmode::*;
        assert!(matches!(
            resolve(Some("auto"), Some("p"), false),
            Ok(WrapMode::Azdp2)
        ));
        assert!(matches!(
            resolve(Some("auto"), None, true),
            Ok(WrapMode::Plaintext)
        ));
        assert!(resolve(Some("auto"), None, false).is_err());
        assert!(resolve(Some("passphrase"), None, true).is_err());
        assert!(resolve(Some("plaintext-pilot"), Some("p"), false).is_err());
        assert!(resolve(Some("bogus"), None, false).is_err());
    }
}
