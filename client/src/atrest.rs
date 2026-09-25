//! W29 step 2 [plan §3.2]: at-rest wrap for the Linux client — W21's
//! AZDP2 machinery (`aztna-keys::azdp2`, argon2id + XChaCha20-Poly1305)
//! with a client-specific resolution policy.
//!
//! Policy divergence from the shared `wrapmode::resolve` core (stated,
//! not accidental): the server components REFUSE to boot `auto` without
//! a passphrase source — an operator must choose. The CLIENT must match
//! the Windows zero-prompt UX (DPAPI asks nobody), so `auto` with no
//! configured secret generates a random key-file inside the 0700 state
//! dir and wraps under it. Honest threat statement (plan §3.2): the
//! key-file default is PERMISSION-bound, not secret-bound — it defeats
//! casual single-file exfil/backup-sync; a full-dir thief gets blob and
//! key-file both. Operator hardening: `AZTNA_KEY_WRAP_PASSPHRASE` /
//! `AZTNA_KEY_PASSPHRASE_FILE` (same env family as controller/gateway,
//! F1-scrubbable, systemd `LoadCredential=` for the file) — a stolen
//! data dir is then ciphertext. Explicit plaintext is dev-only via
//! `AZTNA_KEY_WRAP_MODE=plaintext-pilot` (loudly logged).
//!
//! Hygiene: 0700 state dir, 0600 key material, temp+rename atomic
//! writes, and a permission check that REFUSES insecure pre-existing
//! modes with a named fix (fail closed, `state_insecure` event). Each
//! wrap/unwrap derives the argon2id key (default 64 MiB / t=3) — call
//! sites are login/logout/renew-frequency, not hot paths; no secret is
//! cached in process memory.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

pub const KEY_FILE_NAME: &str = "atrest.key";

#[derive(Debug, Clone, PartialEq)]
pub enum ClientWrap {
    /// zero-prompt default: random 64-hex key-file inside the state dir
    Keyfile {
        path: PathBuf,
        secret: String,
        m_kib: u32,
        t: u32,
    },
    /// operator hardening: passphrase env / credential file
    Passphrase { pass: String, m_kib: u32, t: u32 },
    /// explicit dev opt-in (AZTNA_KEY_WRAP_MODE=plaintext-pilot)
    Plaintext,
}

impl ClientWrap {
    pub fn mode_name(&self) -> &'static str {
        match self {
            ClientWrap::Keyfile { .. } => "keyfile",
            ClientWrap::Passphrase { .. } => "passphrase",
            ClientWrap::Plaintext => "plaintext-pilot",
        }
    }
}

/// Production env lookup (empty values treated as unset — the W19
/// stray-env-shell rule).
pub fn env_lookup(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.trim().is_empty())
}

fn clamp_u32(v: Option<String>, default: u32, floor: u32, max: u32) -> u32 {
    v.and_then(|s| s.trim().parse::<u32>().ok())
        .map(|n| n.clamp(floor, max))
        .unwrap_or(default)
}

/// Resolve the wrap policy. `state_dir` is only touched when the
/// key-file default actually needs to load/mint `atrest.key` — pass
/// `allow_mint=false` on UNWRAP paths so a missing key-file is a named
/// error instead of a fresh key that can never decrypt the blob.
pub fn resolve_with(
    lookup: impl Fn(&str) -> Option<String>,
    state_dir: &Path,
    allow_mint: bool,
) -> Result<ClientWrap> {
    let pass_env = lookup("AZTNA_KEY_WRAP_PASSPHRASE");
    let pass_file = lookup("AZTNA_KEY_PASSPHRASE_FILE");
    let argon2 = |l: &dyn Fn(&str) -> Option<String>| {
        (
            clamp_u32(l("AZTNA_ARGON2_M_KIB"), 65536, 8, 1 << 20),
            clamp_u32(l("AZTNA_ARGON2_T"), 3, 1, 16),
        )
    };
    let lookup2 = |n: &str| lookup(n);
    if let (Some(_), Some(_)) = (&pass_env, &pass_file) {
        bail!("both AZTNA_KEY_WRAP_PASSPHRASE and AZTNA_KEY_PASSPHRASE_FILE are set — pick one");
    }
    if let Some(p) = pass_env {
        let (m_kib, t) = argon2(&lookup2);
        return Ok(ClientWrap::Passphrase { pass: p, m_kib, t });
    }
    if let Some(f) = pass_file {
        let raw = std::fs::read_to_string(&f)
            .with_context(|| format!("AZTNA_KEY_PASSPHRASE_FILE '{f}' unreadable"))?;
        let p = raw.trim_end_matches(['\r', '\n']).to_string();
        if p.trim().is_empty() {
            bail!("passphrase source is empty — refusing (a blank passphrase protects nothing)");
        }
        let (m_kib, t) = argon2(&lookup2);
        return Ok(ClientWrap::Passphrase { pass: p, m_kib, t });
    }
    // no passphrase source: mode decides (client `auto` = key-file default)
    let mode = lookup("AZTNA_KEY_WRAP_MODE")
        .unwrap_or_else(|| "auto".into())
        .trim()
        .to_ascii_lowercase();
    match mode.as_str() {
        "auto" => {
            let (m_kib, t) = argon2(&lookup2);
            keyfile(state_dir, m_kib, t, allow_mint)
        }
        "passphrase" => bail!(
            "AZTNA_KEY_WRAP_MODE=passphrase but no passphrase source \
             (AZTNA_KEY_WRAP_PASSPHRASE / AZTNA_KEY_PASSPHRASE_FILE)"
        ),
        "plaintext-pilot" => Ok(ClientWrap::Plaintext),
        other => bail!(
            "AZTNA_KEY_WRAP_MODE='{other}' is invalid (expected auto | passphrase | plaintext-pilot)"
        ),
    }
}

fn keyfile(state_dir: &Path, m_kib: u32, t: u32, allow_mint: bool) -> Result<ClientWrap> {
    ensure_dir_hygiene(state_dir)?;
    let path = state_dir.join(KEY_FILE_NAME);
    if path.exists() {
        check_file_mode(&path)?;
        let secret = std::fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))?
            .trim()
            .to_string();
        if secret.is_empty() {
            bail!(
                "{} is empty — refusing (a blank key-file protects nothing)",
                path.display()
            );
        }
        return Ok(ClientWrap::Keyfile {
            path,
            secret,
            m_kib,
            t,
        });
    }
    if !allow_mint {
        bail!(
            "state is AZDP2-wrapped under the key-file but {} is missing — \
             restore it (or re-enroll); refusing to mint a fresh key that cannot decrypt",
            path.display()
        );
    }
    // mint: 32 random bytes, hex-encoded (64 chars)
    use rand::RngCore;
    let mut kb = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut kb);
    let secret: String = kb.iter().map(|b| format!("{b:02x}")).collect();
    atomic_write_0600(&path, secret.as_bytes())?;
    println!(
        "[atrest] generated key-file wrap material at {} (permission-bound default; \
         set AZTNA_KEY_WRAP_PASSPHRASE for a secret-bound deployment)",
        path.display()
    );
    Ok(ClientWrap::Keyfile {
        path,
        secret,
        m_kib,
        t,
    })
}

/// Wrap `plain` per the resolved policy. Fires `client_key_wrap_mode`
/// (once per process per mode change) so the at-rest posture is visible
/// in the log stream, never silent.
pub fn wrap(
    lookup: impl Fn(&str) -> Option<String>,
    state_dir: &Path,
    plain: &[u8],
) -> Result<Vec<u8>> {
    let w = resolve_with(lookup, state_dir, true)?;
    log_mode_once(w.mode_name());
    let blob = match &w {
        ClientWrap::Plaintext => plain.to_vec(),
        ClientWrap::Keyfile {
            secret, m_kib, t, ..
        }
        | ClientWrap::Passphrase {
            pass: secret,
            m_kib,
            t,
        } => azdp2_wrap(secret.as_bytes(), plain, *m_kib, *t)?,
    };
    Ok(blob)
}

/// Unwrap a blob: AZDP2 (the shipped format), AZDP1-magic (legacy
/// step-1/dev passthrough state — tolerated once, loudly), or plaintext
/// legacy (tolerated read; the next save re-wraps).
pub fn unwrap(
    lookup: impl Fn(&str) -> Option<String>,
    state_dir: &Path,
    blob: &[u8],
) -> Result<Vec<u8>> {
    if !aztna_keys::azdp2::is_azdp2(blob) && !aztna_keys::is_wrapped(blob) {
        log_mode_once("legacy-plaintext-read");
        return Ok(blob.to_vec());
    }
    unwrap_wrapped(lookup, state_dir, blob)
}

/// Strict variant for the TOKEN (W13: a token is never legitimately
/// plaintext at rest) — bare-plaintext blobs are refused, not tolerated.
pub fn unwrap_strict(
    lookup: impl Fn(&str) -> Option<String>,
    state_dir: &Path,
    blob: &[u8],
) -> Result<Vec<u8>> {
    if !aztna_keys::azdp2::is_azdp2(blob) && !aztna_keys::is_wrapped(blob) {
        bail!("token blob is neither AZDP2 nor AZDP1 — refusing (corrupt or hand-edited state)");
    }
    unwrap_wrapped(lookup, state_dir, blob)
}

fn unwrap_wrapped(
    lookup: impl Fn(&str) -> Option<String>,
    state_dir: &Path,
    blob: &[u8],
) -> Result<Vec<u8>> {
    if aztna_keys::azdp2::is_azdp2(blob) {
        let w = resolve_with(lookup, state_dir, false)?;
        log_mode_once(w.mode_name());
        let secret = match &w {
            ClientWrap::Keyfile { secret, .. } => secret.clone(),
            ClientWrap::Passphrase { pass, .. } => pass.clone(),
            ClientWrap::Plaintext => bail!(
                "state is AZDP2-wrapped but no passphrase/key-file source resolved \
                 (AZTNA_KEY_WRAP_MODE=plaintext-pilot contradicts wrapped state)"
            ),
        };
        let (m_kib, t) = match &w {
            ClientWrap::Keyfile { m_kib, t, .. } | ClientWrap::Passphrase { m_kib, t, .. } => {
                (*m_kib, *t)
            }
            ClientWrap::Plaintext => unreachable!(),
        };
        let parsed = aztna_keys::azdp2::parse(blob)?;
        let salt: [u8; aztna_keys::azdp2::SALT_LEN] = parsed
            .0
            .try_into()
            .map_err(|_| anyhow!("AZDP2 salt length"))?;
        let key = aztna_keys::azdp2::derive_key(secret.as_bytes(), &salt, m_kib, t)
            .context("atrest: argon2id KDF")?;
        return aztna_keys::azdp2::unwrap(blob, &key)
            .context("atrest: AZDP2 unwrap failed (wrong passphrase/key-file or corrupted file?)");
    }
    // AZDP1 magic: step-1 unix scaffolding wrote passthrough — read it
    // back once, loudly; the next save writes AZDP2.
    log_mode_once("legacy-azdp1-read");
    aztna_keys::unprotect(blob).context("atrest: legacy AZDP1 unwrap")
}

// ---------- crypto helper ----------

fn azdp2_wrap(secret: &[u8], plain: &[u8], m_kib: u32, t: u32) -> Result<Vec<u8>> {
    use rand::RngCore;
    let mut salt = [0u8; aztna_keys::azdp2::SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key =
        aztna_keys::azdp2::derive_key(secret, &salt, m_kib, t).context("atrest: argon2id KDF")?;
    aztna_keys::azdp2::wrap(plain, &key, &salt).context("atrest: AZDP2 wrap")
}

// ---------- hygiene: modes, atomic writes, visibility ----------

/// State dir must be 0700 (owner-only). Refuses with a named fix.
pub fn ensure_dir_hygiene(state_dir: &Path) -> Result<()> {
    if !state_dir.exists() {
        std::fs::create_dir_all(state_dir)?;
        set_mode(state_dir, 0o700)?;
        return Ok(());
    }
    let mode = dir_mode(state_dir)?;
    if mode & 0o777 != 0o700 {
        crate::log_event(
            "state_insecure",
            &format!(
                "state dir {} is {:o} (want 700) - refusing; fix: chmod 700 {}",
                state_dir.display(),
                mode & 0o777,
                state_dir.display()
            ),
        );
        bail!(
            "state dir {} has insecure mode {:o} — fix with: chmod 700 {}",
            state_dir.display(),
            mode & 0o777,
            state_dir.display()
        );
    }
    Ok(())
}

fn check_file_mode(path: &Path) -> Result<()> {
    let mode = dir_mode(path)?;
    if mode & 0o777 != 0o600 {
        crate::log_event(
            "state_insecure",
            &format!(
                "key file {} is {:o} (want 600) - refusing; fix: chmod 600 {}",
                path.display(),
                mode & 0o777,
                path.display()
            ),
        );
        bail!(
            "key file {} has insecure mode {:o} — fix with: chmod 600 {}",
            path.display(),
            mode & 0o777,
            path.display()
        );
    }
    Ok(())
}

/// Write via temp+rename with an explicit 0600 (umask never decides key
/// material permissions).
pub fn atomic_write_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    set_mode(&tmp, 0o600)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", path.display()))
}

fn dir_mode(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    let m = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(m.permissions().mode())
}

/// `client_key_wrap_mode` once per process per mode CHANGE (mode
/// switches mid-process are worth a line; steady-state is not).
fn log_mode_once(mode: &'static str) {
    static LAST: std::sync::Mutex<Option<&'static str>> = std::sync::Mutex::new(None);
    let mut g = LAST.lock().unwrap();
    if *g != Some(mode) {
        crate::log_event("client_key_wrap_mode", mode);
        *g = Some(mode);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(_n: &str) -> Option<String> {
        None
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "aztna-atrest-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // fixtures match the hygiene contract (0700) — the product code
        // refuses 0755 state dirs by design
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    fn mode_of(p: &Path) -> u32 {
        dir_mode(p).unwrap() & 0o777
    }

    #[test]
    fn default_keyfile_roundtrip_and_hygiene() {
        let d = tmpdir("default");
        let blob = wrap(none, &d, b"secret-material").unwrap();
        assert!(
            aztna_keys::azdp2::is_azdp2(&blob),
            "auto default wraps AZDP2"
        );
        assert!(!blob.windows(7).any(|w| w == b"secret-"));
        let kf = d.join(KEY_FILE_NAME);
        assert!(kf.exists(), "key-file minted");
        assert_eq!(mode_of(&kf), 0o600, "key-file mode");
        assert_eq!(mode_of(&d), 0o700, "state dir mode");
        assert_eq!(unwrap(none, &d, &blob).unwrap(), b"secret-material");
        // no temp leftovers from atomic writes
        assert!(std::fs::read_dir(&d)
            .unwrap()
            .all(|e| { e.unwrap().file_name().to_string_lossy() != "atrest.tmp" }));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn keyfile_reused_not_reminted() {
        let d = tmpdir("reuse");
        let b1 = wrap(none, &d, b"one").unwrap();
        let b2 = wrap(none, &d, b"two").unwrap();
        // both unwrap with the SAME minted key-file
        assert_eq!(unwrap(none, &d, &b1).unwrap(), b"one");
        assert_eq!(unwrap(none, &d, &b2).unwrap(), b"two");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn passphrase_env_roundtrip_and_no_keyfile() {
        let d = tmpdir("pass");
        let lookup = |n: &str| (n == "AZTNA_KEY_WRAP_PASSPHRASE").then(|| "op-secret".to_string());
        let blob = wrap(lookup, &d, b"material").unwrap();
        assert!(aztna_keys::azdp2::is_azdp2(&blob));
        assert!(
            !d.join(KEY_FILE_NAME).exists(),
            "no key-file in passphrase mode"
        );
        assert_eq!(unwrap(lookup, &d, &blob).unwrap(), b"material");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn both_sources_is_an_error() {
        let d = tmpdir("both");
        let lookup = |n: &str| match n {
            "AZTNA_KEY_WRAP_PASSPHRASE" | "AZTNA_KEY_PASSPHRASE_FILE" => Some("x".into()),
            _ => None,
        };
        let e = wrap(lookup, &d, b"m").unwrap_err();
        assert!(e.to_string().contains("pick one"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn wrong_passphrase_fails_closed_with_named_error() {
        let d = tmpdir("wrong");
        let good = |n: &str| (n == "AZTNA_KEY_WRAP_PASSPHRASE").then(|| "right".to_string());
        let bad = |n: &str| (n == "AZTNA_KEY_WRAP_PASSPHRASE").then(|| "wrong".to_string());
        let blob = wrap(good, &d, b"material").unwrap();
        let e = unwrap(bad, &d, &blob).unwrap_err();
        assert!(e.to_string().contains("wrong passphrase"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn mode_passphrase_without_source_is_an_error() {
        let d = tmpdir("nopass");
        let lookup = |n: &str| (n == "AZTNA_KEY_WRAP_MODE").then(|| "passphrase".to_string());
        let e = wrap(lookup, &d, b"m").unwrap_err();
        assert!(e.to_string().contains("no passphrase source"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn explicit_plaintext_pilot_is_loud_and_tolerated() {
        let d = tmpdir("plain");
        let lookup = |n: &str| (n == "AZTNA_KEY_WRAP_MODE").then(|| "plaintext-pilot".to_string());
        let blob = wrap(lookup, &d, b"material").unwrap();
        assert_eq!(blob, b"material", "plaintext-pilot writes plaintext");
        assert_eq!(unwrap(lookup, &d, &blob).unwrap(), b"material");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn invalid_mode_name_is_an_error() {
        let d = tmpdir("badmode");
        let lookup = |n: &str| (n == "AZTNA_KEY_WRAP_MODE").then(|| "rot13".to_string());
        let e = wrap(lookup, &d, b"m").unwrap_err();
        assert!(e.to_string().contains("is invalid"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn legacy_azdp1_and_plaintext_blobs_are_tolerated_reads() {
        let d = tmpdir("legacy");
        // AZDP1-magic passthrough blob (step-1 scaffolding shape)
        let azdp1 = aztna_keys::protect(b"legacy-bytes").unwrap();
        assert_eq!(unwrap(none, &d, &azdp1).unwrap(), b"legacy-bytes");
        // bare plaintext (pre-W29 dev state)
        assert_eq!(unwrap(none, &d, b"bare").unwrap(), b"bare");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_keyfile_on_unwrap_is_a_named_error_not_a_remint() {
        let d = tmpdir("missing");
        let b1 = wrap(none, &d, b"material").unwrap();
        std::fs::remove_file(d.join(KEY_FILE_NAME)).unwrap();
        let e = unwrap(none, &d, &b1).unwrap_err();
        assert!(e.to_string().contains("missing"), "{e}");
        assert!(
            !d.join(KEY_FILE_NAME).exists(),
            "no fresh mint on unwrap path"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn insecure_keyfile_mode_is_refused() {
        let d = tmpdir("insecure");
        let blob = wrap(none, &d, b"material").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            d.join(KEY_FILE_NAME),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let e = unwrap(none, &d, &blob).unwrap_err();
        assert!(e.to_string().contains("insecure mode"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let d = tmpdir("tamper");
        let mut blob = wrap(none, &d, b"material").unwrap();
        let n = blob.len();
        blob[n - 1] ^= 0xFF; // flip a tag byte
        let e = unwrap(none, &d, &blob).unwrap_err();
        assert!(e.to_string().contains("corrupted"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn insecure_state_dir_is_refused() {
        let d = tmpdir("dirmod");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        let e = wrap(none, &d, b"m").unwrap_err();
        assert!(e.to_string().contains("chmod 700"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
