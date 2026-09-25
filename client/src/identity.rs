//! P2-7 [ADR-0010 Stage B]: device identity key with hardware preference.
//! Selection order: TPM (Platform Crypto Provider) -> software.
//! TPM key: persisted ECDSA P-256 inside the TPM (non-exportable; S2-proven),
//! signs a hand-built CSR [proof of possession]. Software key: rcgen keypair
//! stored DPAPI machine-scope wrapped (blob is useless if copied off-host).
//! `key_origin` is reported at enroll and policy-gated [min_key_origin].

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use std::path::Path;

// The NCrypt persisted-key name lives as the `w!("aztna-device-key")`
// literal at both NCrypt call sites below (the w! macro needs a literal;
// see docs/spikes/S2-tpm-cng-findings.md for the naming contract).
#[cfg(windows)]
const DPAPI_FILE: &str = "device-key.dpapi";
#[cfg(not(windows))]
const ATREST_FILE: &str = "device-key.atrest";

#[cfg(windows)]
use windows::core::w;
#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSignHash, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE,
    NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
};

pub enum KeyKind {
    #[cfg(windows)]
    Tpm {
        prov: NCRYPT_PROV_HANDLE,
        key: NCRYPT_KEY_HANDLE,
        /// uncompressed point 0x04||X||Y
        point: Vec<u8>,
    },
    /// W29 step 4: the Linux TPM tier (tss-esapi; same ECDSA P-256 shape
    /// and origin string as the Windows NCrypt tier)
    #[cfg(target_os = "linux")]
    Tpm2 { dev: crate::tpm::TpmDevice },
    /// PEM held in memory only; on disk it exists solely wrapped at rest
    /// (DPAPI on Windows, AZDP2 on Linux — atrest.rs)
    Software { key_pem: String },
}

pub struct DeviceKey {
    pub origin: String, // tpm | software (vtpm distinction lands w/ Stage C attestation)
    pub kind: KeyKind,
}

// ---------- tiny DER builders for the hand-built TPM CSR ----------
// W29: used by the (Windows) TPM arm today; the Linux TPM tier (step 4)
// consumes the same builders — allow(dead_code) on unix until then.

fn der_len(n: usize, out: &mut Vec<u8>) {
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xff {
        out.push(0x81);
        out.push(n as u8);
    } else {
        out.push(0x82);
        out.push((n >> 8) as u8);
        out.push(n as u8);
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_len(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

fn der_uint_be(bytes: &[u8]) -> Vec<u8> {
    // strip leading zeros, prepend 0x00 when high bit set
    let mut b = bytes;
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    let mut v = Vec::with_capacity(b.len() + 1);
    if b[0] & 0x80 != 0 {
        v.push(0);
    }
    v.extend_from_slice(b);
    tlv(0x02, &v)
}

/// prime256v1 SubjectPublicKeyInfo around an uncompressed EC point.
fn spki_from_point(point: &[u8]) -> Vec<u8> {
    let alg = tlv(
        0x30,
        &[
            &tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])[..],
            &tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])[..],
        ]
        .concat(),
    );
    let mut bits = vec![0u8];
    bits.extend_from_slice(point);
    tlv(0x30, &[alg, tlv(0x03, &bits)].concat())
}

fn pem_wrap(tag: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {tag}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {tag}-----\n"));
    out
}

impl DeviceKey {
    /// W29: is this identity hardware-backed (either TPM tier)? The TLS
    /// config builders key off this — TPM signers need SHA-256-transcript
    /// cipher suites (tpmtls::sha256_only_client_config).
    pub fn is_tpm(&self) -> bool {
        match &self.kind {
            KeyKind::Software { .. } => false,
            #[cfg(windows)]
            KeyKind::Tpm { .. } => true,
            #[cfg(target_os = "linux")]
            KeyKind::Tpm2 { .. } => true,
        }
    }

    /// Detect-and-prefer [ADR-0010]: TPM when the provider opens and the key
    /// can be created/opened without elevation; otherwise wrapped software
    /// key. Force software with AZTNA_KEY_ORIGIN=software.
    pub fn open_or_create(state_dir: &Path) -> Result<DeviceKey> {
        // W30 D3 (plan §3.3): macOS has no TPM2 — an EXPLICIT TPM ask
        // fails closed with a named error + event; never a silent
        // software fallback.
        #[cfg(target_os = "macos")]
        {
            if tpm_requested(
                std::env::var("AZTNA_TPM2_TCTI").is_ok(),
                std::env::var("AZTNA_KEY_ORIGIN").ok().as_deref(),
            ) {
                crate::log_event(
                    "tpm_unsupported_macos",
                    "explicit TPM config on a platform with no TPM2 - failing closed",
                );
                return Err(anyhow!(
                    "TPM tier not available on macOS (no TPM2; Secure Enclave = future work) \
                     - refusing to fall back to software"
                ));
            }
        }
        if std::env::var("AZTNA_KEY_ORIGIN").as_deref() != Ok("software") {
            #[cfg(windows)]
            {
                if let Some(k) = Self::open_tpm() {
                    return Ok(k);
                }
            }
            #[cfg(target_os = "linux")]
            {
                match crate::tpm::TpmDevice::open_or_create() {
                    Ok(Some(dev)) => {
                        println!("[identity] TPM-backed device key active (non-exportable)");
                        return Ok(DeviceKey {
                            origin: "tpm".into(),
                            kind: KeyKind::Tpm2 { dev },
                        });
                    }
                    // explicit-TCTI failure already failed closed inside
                    // (tpm_fail_closed); Ok(None) = no TPM, software tier
                    Ok(None) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Self::open_software(state_dir)
    }

    #[cfg(windows)]
    fn open_tpm() -> Option<DeviceKey> {
        unsafe {
            let mut prov = NCRYPT_PROV_HANDLE::default();
            // Platform Crypto Provider = discrete TPM or vTPM (VM); both are
            // hardware-bound from our point of view [origin "tpm" until
            // Stage C attestation distinguishes vtpm]
            if NCryptOpenStorageProvider(&mut prov, w!("Microsoft Platform Crypto Provider"), 0)
                .is_err()
            {
                return None;
            }
            let mut key = NCRYPT_KEY_HANDLE::default();
            let opened = NCryptOpenKey(
                prov,
                &mut key,
                w!("aztna-device-key"),
                windows::Win32::Security::Cryptography::CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            );
            if opened.is_err() {
                let created = NCryptCreatePersistedKey(
                    prov,
                    &mut key,
                    w!("ECDSA_P256"),
                    w!("aztna-device-key"),
                    windows::Win32::Security::Cryptography::CERT_KEY_SPEC(0),
                    NCRYPT_OVERWRITE_KEY_FLAG,
                );
                if created.is_err() || NCryptFinalizeKey(key, NCRYPT_FLAGS(0)).is_err() {
                    let _ = NCryptFreeObject(prov);
                    return None;
                }
            }
            match export_public_point(key) {
                Ok(point) => {
                    println!("[identity] TPM-backed device key active (non-exportable)");
                    Some(DeviceKey {
                        origin: "tpm".into(),
                        kind: KeyKind::Tpm { prov, key, point },
                    })
                }
                Err(_) => {
                    let _ = NCryptFreeObject(prov);
                    None
                }
            }
        }
    }

    /// ECCPUBLICBLOB (BCRYPT_ECCKEY_BLOB) -> uncompressed EC point.
    #[cfg(windows)]
    unsafe fn export_public_point_raw(key: NCRYPT_KEY_HANDLE) -> Result<Vec<u8>> {
        use windows::Win32::Security::Cryptography::NCryptExportKey;
        let mut cb = 0u32;
        NCryptExportKey(
            key,
            NCRYPT_KEY_HANDLE::default(),
            w!("ECCPUBLICBLOB"),
            None,
            None,
            &mut cb,
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| anyhow!("pub export size: {e}"))?;
        let mut blob = vec![0u8; cb as usize];
        NCryptExportKey(
            key,
            NCRYPT_KEY_HANDLE::default(),
            w!("ECCPUBLICBLOB"),
            None,
            Some(&mut blob),
            &mut cb,
            NCRYPT_SILENT_FLAG,
        )
        .map_err(|e| anyhow!("pub export: {e}"))?;
        // layout: u32 magic (0x50 = P256 public), u32 cbKey, X, Y
        if blob.len() != 8 + 32 + 32 || blob[0] != 0x50 {
            return Err(anyhow!("unexpected ECCPUBLICBLOB shape"));
        }
        let mut point = vec![0x04];
        point.extend_from_slice(&blob[8..40]);
        point.extend_from_slice(&blob[40..72]);
        Ok(point)
    }

    #[cfg(windows)]
    fn open_tpm_point(key: NCRYPT_KEY_HANDLE) -> Result<Vec<u8>> {
        unsafe { Self::export_public_point_raw(key) }
    }

    fn open_software(state_dir: &Path) -> Result<DeviceKey> {
        #[cfg(windows)]
        let f = state_dir.join(DPAPI_FILE);
        #[cfg(not(windows))]
        let f = state_dir.join(ATREST_FILE);
        let key_pem = if f.exists() {
            let blob = std::fs::read(&f)?;
            #[cfg(windows)]
            let pem = dpapi_unprotect(&blob)
                .context("DPAPI unwrap failed (blob copied from another host?)")?;
            #[cfg(not(windows))]
            let pem = crate::atrest::unwrap(crate::atrest::env_lookup, state_dir, &blob)
                .context("device key at-rest unwrap failed")?;
            String::from_utf8(pem)?
        } else {
            let pair = rcgen::KeyPair::generate()?;
            let pem = pair.serialize_pem();
            #[cfg(windows)]
            {
                std::fs::write(&f, dpapi_protect(pem.as_bytes())?)?;
                println!(
                    "[identity] software device key created (DPAPI machine-scope wrapped at {})",
                    f.display()
                );
            }
            #[cfg(not(windows))]
            {
                // W29 step 2: AZDP2 wrap (W21 machinery) — key-file default
                // or operator passphrase; the wrap logs client_key_wrap_mode
                let blob =
                    crate::atrest::wrap(crate::atrest::env_lookup, state_dir, pem.as_bytes())?;
                crate::atrest::atomic_write_0600(&f, &blob)?;
                println!(
                    "[identity] software device key created (AZDP2 wrapped at {})",
                    f.display()
                );
            }
            pem
        };
        println!("[identity] software-backed device key active");
        Ok(DeviceKey {
            origin: "software".into(),
            kind: KeyKind::Software { key_pem },
        })
    }

    /// Build a CSR for this key. TPM (both tiers): hand-built, signature
    /// produced inside the TPM (proof of possession of a non-exportable
    /// key). Software: rcgen.
    pub fn build_csr_pem(&self, hostname: &str) -> Result<String> {
        match &self.kind {
            KeyKind::Software { key_pem } => {
                let pair = rcgen::KeyPair::from_pem(key_pem)?;
                let mut params = rcgen::CertificateParams::new(vec![hostname.to_string()])?;
                params
                    .distinguished_name
                    .push(rcgen::DnType::CommonName, hostname);
                let csr = params.serialize_request(&pair)?;
                Ok(csr.pem()?)
            }
            #[cfg(windows)]
            KeyKind::Tpm { point, .. } => {
                let sig = |digest: &[u8]| self.sign_digest_raw(digest);
                build_tpm_csr(hostname, point, sig)
            }
            #[cfg(target_os = "linux")]
            KeyKind::Tpm2 { dev } => {
                let sig = |digest: &[u8]| dev.sign_digest_raw(digest);
                build_tpm_csr(hostname, &dev.point, sig)
            }
        }
    }

    /// Sign a 32-byte digest; returns 64-byte raw r||s (TPM, both tiers)
    /// — software path is unused (rcgen signs internally).
    pub fn sign_digest_raw(&self, digest: &[u8]) -> Result<[u8; 64]> {
        match &self.kind {
            KeyKind::Software { .. } => Err(anyhow!("software keys sign via rcgen")),
            #[cfg(windows)]
            KeyKind::Tpm { key, .. } => unsafe {
                let mut sig = [0u8; 64];
                let mut cb = 0u32;
                NCryptSignHash(
                    *key,
                    None,
                    digest,
                    Some(&mut sig),
                    &mut cb,
                    NCRYPT_SILENT_FLAG,
                )
                .map_err(|e| anyhow!("TPM sign: {e}"))?;
                if cb != 64 {
                    return Err(anyhow!("unexpected TPM signature length {cb}"));
                }
                Ok(sig)
            },
            #[cfg(target_os = "linux")]
            KeyKind::Tpm2 { dev } => dev.sign_digest_raw(digest),
        }
    }

    /// TLS identity: software -> PEM pair for reqwest::Identity; TPM
    /// (both tiers) -> None (caller builds a custom rustls config around
    /// `sign_digest_raw`).
    pub fn tls_identity_pem(&self, cert_pem: &str) -> Option<String> {
        match &self.kind {
            KeyKind::Software { key_pem } => Some(format!("{cert_pem}\n{key_pem}")),
            #[cfg(windows)]
            KeyKind::Tpm { .. } => None,
            #[cfg(target_os = "linux")]
            KeyKind::Tpm2 { .. } => None,
        }
    }
}

/// W8.2: TLS client-auth material shared by the QUIC data path and the TPM
/// reqwest path - the issued cert chain parsed from PEM plus a signer chosen
/// by key kind. The SOFTWARE reqwest path (mtls_client) deliberately does
/// NOT use this: it stays on reqwest::Identity::from_pem, untouched by
/// construction [plan v0.2].
pub fn tls_client_identity(
    device: std::sync::Arc<DeviceKey>,
    cert_pem: &str,
) -> anyhow::Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    std::sync::Arc<dyn rustls::sign::SigningKey>,
)> {
    let mut certs = Vec::new();
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes())) {
        certs.push(cert?);
    }
    anyhow::ensure!(!certs.is_empty(), "no certificate in identity pem");
    let signer: std::sync::Arc<dyn rustls::sign::SigningKey> = match &device.kind {
        KeyKind::Software { key_pem } => {
            let key =
                rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem.as_bytes()))?
                    .ok_or_else(|| anyhow::anyhow!("no private key in device pem"))?;
            rustls::crypto::ring::sign::any_supported_type(&key)?
        }
        // W29: the same custom signer serves both TPM tiers — it signs
        // through DeviceKey::sign_digest_raw (NCrypt on Windows, ESYS on
        // Linux); the historical name stays.
        #[cfg(windows)]
        KeyKind::Tpm { .. } => std::sync::Arc::new(crate::tpmtls::NcryptSigningKey { device }),
        #[cfg(target_os = "linux")]
        KeyKind::Tpm2 { .. } => std::sync::Arc::new(crate::tpmtls::NcryptSigningKey { device }),
    };
    Ok((certs, signer))
}

/// W29 step 4: the hand-built ECDSA-P256 CSR shared by BOTH TPM tiers
/// (Windows NCrypt + Linux tss-esapi) — byte-identical construction to
/// the W5.1-era windows-only code, extracted so the Linux tier signs the
/// same shape.
fn build_tpm_csr(
    hostname: &str,
    point: &[u8],
    sign: impl Fn(&[u8]) -> Result<[u8; 64]>,
) -> Result<String> {
    // CertificationRequestInfo
    let version = tlv(0x02, &[0]);
    let cn_oid = tlv(0x06, &[0x55, 0x04, 0x03]);
    let cn_val = tlv(0x0C, hostname.as_bytes());
    let rdn = tlv(0x31, &tlv(0x30, &[cn_oid, cn_val].concat()));
    let name = tlv(0x30, &rdn);
    let spki = spki_from_point(point);
    let attrs = tlv(0xA0, &[]);
    let cri = tlv(0x30, &[version, name, spki, attrs].concat());

    // SHA-256(CRI) signed inside the TPM
    let digest = sha2_digest(&cri);
    let sig_raw = sign(&digest)?;
    let der_sig = tlv(
        0x30,
        &[der_uint_be(&sig_raw[..32]), der_uint_be(&sig_raw[32..])].concat(),
    );
    let alg = tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]);
    let sig_alg = tlv(0x30, &alg);
    let mut bits = vec![0u8];
    bits.extend_from_slice(&der_sig);
    let csr = tlv(0x30, &[cri, sig_alg, tlv(0x03, &bits)].concat());
    Ok(pem_wrap("CERTIFICATE REQUEST", &csr))
}

#[cfg(windows)]
unsafe fn export_public_point(key: NCRYPT_KEY_HANDLE) -> Result<Vec<u8>> {
    DeviceKey::open_tpm_point(key)
}

fn sha2_digest(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let h = sha2::Sha256::digest(data);
    h.into()
}

// ---------- DPAPI machine-scope wrap [ADR-0010 fallback tier] ----------

#[cfg(windows)]
fn crypt_blob(bytes: &[u8]) -> windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
    windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    }
}

#[cfg(windows)]
fn local_free(p: *mut u8) {
    unsafe {
        windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(p as *mut _));
    }
}

#[cfg(windows)]
pub fn dpapi_protect(plain: &[u8]) -> Result<Vec<u8>> {
    dpapi_protect_scoped(plain, true)
}

/// W13 step 3 [one token-store module, two profiles]: DPAPI wrapping
/// parameterized by scope — machine (service host in ProgramData; any
/// local SYSTEM code can read, ACL is the boundary) vs USER (standalone
/// CLI; only that account's processes can unprotect, not even the
/// service). The scope is a security parameter of the HOST, not a
/// behavior difference: same code both places.
#[cfg(windows)]
pub fn dpapi_protect_scoped(plain: &[u8], machine: bool) -> Result<Vec<u8>> {
    use windows::Win32::Security::Cryptography::CryptProtectData;
    let inb = crypt_blob(plain);
    let mut out = windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB::default();
    let flags = if machine {
        windows::Win32::Security::Cryptography::CRYPTPROTECT_LOCAL_MACHINE
    } else {
        windows::Win32::Security::Cryptography::CRYPTPROTECT_UI_FORBIDDEN
    };
    unsafe {
        CryptProtectData(
            &inb,
            windows::core::PCWSTR::null(),
            None,
            None,
            None,
            flags,
            &mut out,
        )
        .map_err(|e| anyhow!("CryptProtectData: {e}"))?;
    }
    let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    local_free(out.pbData);
    Ok(v)
}

#[cfg(windows)]
pub fn dpapi_unprotect(blob: &[u8]) -> Result<Vec<u8>> {
    dpapi_unprotect_scoped(blob, true)
}

#[cfg(windows)]
pub fn dpapi_unprotect_scoped(blob: &[u8], machine: bool) -> Result<Vec<u8>> {
    use windows::Win32::Security::Cryptography::CryptUnprotectData;
    let inb = crypt_blob(blob);
    let mut out = windows::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB::default();
    let flags = if machine {
        windows::Win32::Security::Cryptography::CRYPTPROTECT_LOCAL_MACHINE
    } else {
        windows::Win32::Security::Cryptography::CRYPTPROTECT_UI_FORBIDDEN
    };
    unsafe {
        CryptUnprotectData(&inb, None, None, None, None, flags, &mut out)
            .map_err(|e| anyhow!("CryptUnprotectData: {e}"))?;
    }
    let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    local_free(out.pbData);
    Ok(v)
}

// ---------------------------------------------------------------------
// W30 step 2 (plan §3.3): macOS machine identity = IOPlatformUUID via
// the `ioreg` subprocess. WORDING DISCIPLINE: this is a machine
// IDENTIFIER (names the Mac; stable across reinstalls), NOT a
// hardware-backed key (proof of key possession) — macOS W30 has no
// hardware-backed identity tier (D3; the product statement).
// ---------------------------------------------------------------------

/// Pure decision (D3 fail-closed): an explicit TPM ask on macOS —
/// unit-pinned here; the process-level behavior (env set → named
/// error, never silent software) is the step-7 lane's env-level test.
#[cfg(target_os = "macos")]
pub(crate) fn tpm_requested(tcti_set: bool, origin: Option<&str>) -> bool {
    tcti_set || origin == Some("tpm")
}

/// 3 s bounded `ioreg` read; None on timeout/failure (the caller's
/// fallback chain decides — identity enroll itself fails on a missing
/// hostname, never silently invents one).
#[cfg(target_os = "macos")]
pub fn platform_machine_id() -> Option<String> {
    use std::io::Read;
    let mut child = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            _ => {
                let _ = child.kill();
                return None; // 3 s bound exceeded or wait error
            }
        }
    }
    let mut s = String::new();
    child.stdout.take()?.read_to_string(&mut s).ok()?;
    parse_ioreg_platform_uuid(&s)
}

/// Pure parser — the fixture-test seam. `ioreg -rd1 -c
/// IOPlatformExpertDevice` emits `... "IOPlatformUUID" = "XXXX..."`.
#[cfg(target_os = "macos")]
pub(crate) fn parse_ioreg_platform_uuid(ioreg_out: &str) -> Option<String> {
    const KEY: &str = "\"IOPlatformUUID\" = \"";
    for line in ioreg_out.lines() {
        if let Some(idx) = line.find(KEY) {
            let rest = &line[idx + KEY.len()..];
            if let Some(end) = rest.find('"') {
                let v = rest[..end].trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- W30 step 2: macOS machine identity (IOPlatformUUID) ---------
    #[cfg(target_os = "macos")]
    mod macos_machine_id {
        use super::*;

        const FIXTURE: &str = "+-o IOPlatformExpertDevice 0  <class IOPlatformExpertDevice, id 0x1000002e5, registered, matched, active, busy 0 (186 ms), retain 8>\n    {\n      \"IOPlatformSerialNumber\" = \"C02TEST1234\"\n      \"IOPlatformUUID\" = \"57E82A7B-8C9D-4E1A-9F3B-2A6C8E0D5B41\"\n      \"board-id\" = <\"Mac-42FD25EABCDDD4BE\">\n    }";

        #[test]
        fn ioreg_fixture_parses() {
            assert_eq!(
                parse_ioreg_platform_uuid(FIXTURE).as_deref(),
                Some("57E82A7B-8C9D-4E1A-9F3B-2A6C8E0D5B41")
            );
        }

        #[test]
        fn ioreg_missing_key_is_none() {
            assert_eq!(
                parse_ioreg_platform_uuid("no key here\n\"other\" = \"x\""),
                None
            );
            assert_eq!(parse_ioreg_platform_uuid(""), None);
            // empty value rejected too
            assert_eq!(parse_ioreg_platform_uuid("\"IOPlatformUUID\" = \"\""), None);
        }

        #[test]
        fn live_ioreg_yields_a_uuid() {
            // the runner IS macOS: the bounded read must produce a value
            let v = platform_machine_id().expect("ioreg machine id");
            assert!(v.len() >= 8, "implausible machine id: {v}");
        }

        #[test]
        fn tpm_requested_decision_matrix() {
            // D3 fail-closed decision, unit-pinned (env-level behavior
            // is the lane's — env mutation here would race the parallel
            // identity tests, the W29 TPM_ENV lesson)
            assert!(tpm_requested(true, None));
            assert!(tpm_requested(true, Some("software")));
            assert!(tpm_requested(false, Some("tpm")));
            assert!(!tpm_requested(false, None));
            assert!(!tpm_requested(false, Some("software")));
        }
    }

    #[test]
    fn der_builders() {
        assert_eq!(tlv(0x30, &[1, 2]), vec![0x30, 0x02, 1, 2]);
        assert_eq!(der_uint_be(&[0x01]), vec![2, 1, 1]);
        assert_eq!(der_uint_be(&[0x80]), vec![2, 2, 0, 0x80]); // high bit padded
        assert_eq!(der_uint_be(&[0, 0, 5]), vec![2, 1, 5]); // leading zeros stripped
        let point = vec![0x04u8; 65];
        let spki = spki_from_point(&point);
        assert_eq!(spki.len(), 91);
        assert_eq!(spki[0], 0x30);
    }

    /// A TPM-shaped CSR (built from a fixed point + fake sig path is not
    /// possible cross-platform; verify the PEM framing of a real software
    /// CSR round-trips through x509 parse expectations instead).
    #[test]
    fn pem_wrapping() {
        let p = pem_wrap("CERTIFICATE REQUEST", &[0x30, 0x00]);
        assert!(p.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(p.ends_with("-----END CERTIFICATE REQUEST-----\n"));
    }
    /// W8.2: tls_client_identity must satisfy a client-cert-requiring TLS
    /// peer for software keys - a loopback QUIC handshake against a mini
    /// tenant CA whose leaf is issued over the DeviceKey's own key.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // the guard's PURPOSE is to span
                                         // the whole test: serialize against the TPM-env tests' poisoned window
    async fn tls_client_identity_software_signer_satisfies_mtls() {
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        // W29 unix: opens a device key — serialize against the TPM-env
        // tests (poisoned-window fail-close, see tpm.rs TPM_ENV)
        #[cfg(target_os = "linux")]
        let _tpm = crate::tpm::TPM_ENV.lock().unwrap();

        // software device key in a throwaway dir (no TPM in the test env)
        let dir = std::env::temp_dir().join(format!("aztna-quic-ident-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // W29: unix fixtures match the atrest hygiene contract (0700) —
        // unix-wide (macOS too; AZDP2 refuses insecure modes on all unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let device = DeviceKey::open_or_create(&dir).unwrap();
        let KeyKind::Software { key_pem } = &device.kind else {
            panic!("test env must yield a software key");
        };
        // the leaf is issued over the device's own key (the controller's
        // enroll shape), so the signer must match the cert's public key
        let pair = rcgen::KeyPair::from_pem(key_pem).unwrap();
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test Tenant CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let mut leaf_params = rcgen::CertificateParams::new(vec![]).unwrap();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "device-under-test");
        let leaf = leaf_params.signed_by(&pair, &ca, &ca_key).unwrap();
        let cert_pem = leaf.pem();

        // server: requires tenant-CA client certs (the W8.2 gateway shape)
        let srv_key = rcgen::KeyPair::generate().unwrap();
        let mut sp = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        sp.distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        let srv_cert = sp.self_signed(&srv_key).unwrap();
        let srv_key_der = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            srv_key.serialize_pem().as_bytes(),
        ))
        .unwrap()
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(ca.der().to_vec()))
            .unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(std::sync::Arc::new(roots))
            .build()
            .unwrap();
        let stls = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(
                    srv_cert.der().to_vec(),
                )],
                srv_key_der,
            )
            .unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(std::sync::Arc::new(
                QuicServerConfig::try_from(stls).unwrap(),
            )),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            conn.peer_identity().and_then(|i| {
                i.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                    .ok()
            })
        });

        // client: the helper under test provides the identity
        let (certs, signer) = tls_client_identity(std::sync::Arc::new(device), &cert_pem).unwrap();
        assert_eq!(certs.len(), 1, "single-leaf issuance shape");
        let mut c_roots = rustls::RootCertStore::empty();
        c_roots
            .add(rustls::pki_types::CertificateDer::from(
                srv_cert.der().to_vec(),
            ))
            .unwrap();
        let certified = rustls::sign::CertifiedKey::new(certs, signer);
        let ctl = rustls::ClientConfig::builder()
            .with_root_certificates(c_roots)
            .with_client_cert_resolver(std::sync::Arc::new(crate::tpmtls::Resolver {
                key: std::sync::Arc::new(certified),
            }));
        let mut c = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        c.set_default_client_config(quinn::ClientConfig::new(std::sync::Arc::new(
            QuicClientConfig::try_from(ctl).unwrap(),
        )));
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            c.connect(addr, "localhost").unwrap(),
        )
        .await
        .expect("identity handshake must not hang")
        .expect("identity handshake must complete");
        let peer = tokio::time::timeout(std::time::Duration::from_secs(5), srv)
            .await
            .unwrap()
            .unwrap()
            .expect("peer identity must be present");
        assert_eq!(
            peer[0],
            *leaf.der(),
            "server must see exactly the issued leaf"
        );
        conn.close(0u32.into(), b"done");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------------------
// W30 step 3: AZDP2 at-rest on macOS — same W21 machinery as the Linux
// tier; the explicit round-trip + hygiene evidence (env-agnostic: the
// wrap mode is whatever the ambient env selects, the test asserts the
// round-trip + file hygiene, not the mode).
// ---------------------------------------------------------------------
#[cfg(target_os = "macos")]
#[cfg(test)]
mod macos_atrest_tests {
    use super::*;

    #[test]
    fn software_key_wraps_reloads_and_holds_hygiene() {
        let dir = std::env::temp_dir().join(format!("aztna-mac-atrest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let k1 = DeviceKey::open_or_create(&dir).unwrap();
        assert_eq!(k1.origin, "software");
        let DeviceKey {
            kind: KeyKind::Software { key_pem: p1 },
            ..
        } = &k1
        else {
            panic!("macOS must yield the software tier");
        };

        // at-rest blob exists, is AZDP2-framed, and is 0600 in the 0700 dir
        let blob_path = dir.join("device-key.atrest");
        let blob = std::fs::read(&blob_path).expect("wrapped device key on disk");
        assert_eq!(&blob[..5], aztna_keys::azdp2::MAGIC.as_slice());
        let mode = std::fs::metadata(&blob_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "at-rest blob must be 0600");

        // reload through the same tier reproduces the SAME key
        let k2 = DeviceKey::open_or_create(&dir).unwrap();
        let DeviceKey {
            kind: KeyKind::Software { key_pem: p2 },
            ..
        } = &k2
        else {
            panic!("reload must stay software");
        };
        assert_eq!(p1, p2, "reload must unwrap the SAME device key");

        // the plaintext PEM never hits disk anywhere in the state dir
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            if entry.path().extension().is_some_and(|e| e == "atrest") {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                assert!(
                    !content.contains("PRIVATE KEY"),
                    "plaintext key leaked to {}",
                    entry.path().display()
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
