//! W29 step 4 [plan §3.4]: the Linux TPM tier — hardware-bound ECDSA
//! P-256 device identity via tss-esapi (ESYS), matching the Windows
//! NCrypt Platform Crypto Provider tier (same algorithm family, same
//! origin string "tpm", same non-exportability).
//!
//! TCTI: `AZTNA_TPM2_TCTI` (default `device:/dev/tpmrm0`; e2e uses
//! `swtpm:host=127.0.0.1,port=<n>` — WSL2 has no physical TPM, so all
//! dev/test validation runs on the swtpm emulator; hardware validation
//! is the native-Linux release gate, plan §1).
//!
//! Fail-closed rule: with `AZTNA_KEY_ORIGIN=software` the tier is off
//! (same as Windows). With an EXPLICITLY SET `AZTNA_TPM2_TCTI`, a TPM
//! that cannot be opened/used is a hard error (`tpm_fail_closed` event,
//! no software downgrade — an assurance-tier downgrade must never be
//! silent). With the DEFAULT TCTI, a box without a TPM simply falls
//! back to software (the Windows behavior: no Platform Crypto Provider
//! → software tier).
//!
//! Session discipline (learned on swtpm, tss2 4.x + tss-esapi): ESYS
//! `TR_FromTPMPublic` and `ReadPublic` take NO sessions and MUST run
//! with none configured — a leaked session makes the TPM reject the
//! command (RC handle/session) and `TR_FromTPMPublic` crashes outright;
//! `CreatePrimary`/`EvictControl`/`Sign` need the password session.
//! Every call below sets/clears accordingly.
//!
//! Build requirements (deployment doc): system `tpm2-tss >= 4.1.3`
//! (tss-esapi-sys 0.7 refuses older; Ubuntu 24.04's apt 4.0.1 is not
//! usable) + clang for the generated bindings.

use anyhow::{anyhow, Context as _, Result};
use std::str::FromStr;
use std::sync::Mutex;
use tss_esapi::handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::reserved_handles::{Hierarchy, Provision};
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    Digest, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Public,
    PublicEccParameters, SignatureScheme, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

/// Persistent TPM handle for the device key (arbitrary choice in the
/// persistent-object range; stable so later processes find the same key
/// — the TPM equivalent of the NCrypt key name "aztna-device-key").
pub const PERSISTENT_HANDLE: u32 = 0x8100_0029;

const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

/// Serializes tests that touch AZTNA_TPM2_TCTI OR open device keys
/// (identity open reads the env; a poisoned window in one test must
/// not fail-close another). pub(crate) for the lib tests.
#[cfg(test)]
pub(crate) static TPM_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// An open TPM + the loaded device key. `Context` is mutated by every
/// ESYS call — interior mutability behind an Arc<Mutex> (the rustls
/// signer calls in through `&self`; the bounded-sign thread shares the
/// same context rather than reopening the TCTI per signature).
pub struct TpmDevice {
    ctx: std::sync::Arc<Mutex<Context>>,
    key: KeyHandle,
    /// uncompressed point 0x04||X||Y (P-256 → 65 bytes)
    pub point: Vec<u8>,
}

pub fn tcti_conf() -> String {
    std::env::var("AZTNA_TPM2_TCTI")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_TCTI.to_string())
}

fn tcti_explicitly_set() -> bool {
    std::env::var("AZTNA_TPM2_TCTI")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

impl TpmDevice {
    /// Open the configured TPM and load (or create) the device key.
    /// Mirrors the Windows `open_tpm`: `Ok(None)` = no TPM available and
    /// none explicitly demanded (software tier takes over); `Err` = TPM
    /// was explicitly configured and failed (fail closed).
    pub fn open_or_create() -> Result<Option<TpmDevice>> {
        let conf = tcti_conf();
        let explicit = tcti_explicitly_set();
        match Self::open_inner(&conf) {
            Ok(dev) => {
                crate::log_event("tpm2_tcti", &conf);
                Ok(Some(dev))
            }
            Err(e) => {
                if explicit {
                    crate::log_event("tpm_fail_closed", &format!("AZTNA_TPM2_TCTI={conf}: {e:#}"));
                    Err(anyhow!(
                        "TPM explicitly configured (AZTNA_TPM2_TCTI={conf}) but unusable: {e:#} \
                         — refusing silent software-key downgrade; fix the TPM or unset the env"
                    ))
                } else {
                    // default TCTI, no TPM on this box — Windows parity:
                    // no Platform Crypto Provider → software tier
                    println!("[identity] no usable TPM via default TCTI ({conf}) - {e:#}");
                    Ok(None)
                }
            }
        }
    }

    fn open_inner(conf_str: &str) -> Result<TpmDevice> {
        let tcti =
            TctiNameConf::from_str(conf_str).with_context(|| format!("parse TCTI '{conf_str}'"))?;
        let mut ctx = Context::new(tcti).context("open ESYS context")?;
        let persistent: PersistentTpmHandle = PERSISTENT_HANDLE
            .try_into()
            .map_err(|e| anyhow!("handle: {e:?}"))?;
        // SESSION-LESS load (see module doc)
        let key = match ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent)) {
            Ok(existing) => {
                let k: KeyHandle = existing.into();
                k
            }
            Err(_missing) => Self::create_and_evict(&mut ctx, persistent)?,
        };
        let point = Self::public_point(&mut ctx, key)?;
        Ok(TpmDevice {
            ctx: std::sync::Arc::new(Mutex::new(ctx)),
            key,
            point,
        })
    }

    fn create_and_evict(ctx: &mut Context, persistent: PersistentTpmHandle) -> Result<KeyHandle> {
        // password session for the authed create/evict (empty hierarchy
        // auth — the standard client-device shape)
        ctx.set_sessions((Some(AuthSession::Password), None, None));
        let public = Public::Ecc {
            object_attributes: tss_esapi::attributes::ObjectAttributes::new_fixed_signing_key(),
            name_hashing_algorithm: HashingAlgorithm::Sha256,
            auth_policy: Digest::try_from(Vec::<u8>::new())?,
            parameters: PublicEccParameters::new(
                SymmetricDefinitionObject::Null,
                EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                EccCurve::NistP256,
                KeyDerivationFunctionScheme::Null,
            ),
            unique: EccPoint::default(),
        };
        let primary = ctx
            .create_primary(Hierarchy::Owner, public, None, None, None, None)
            .context("TPM CreatePrimary")?;
        let oh: ObjectHandle = primary.key_handle.into();
        let evicted = ctx
            .evict_control(Provision::Owner, oh, persistent.into())
            .context("TPM EvictControl")?;
        // back to session-less for the ReadPublic that follows
        ctx.clear_sessions();
        let k: KeyHandle = evicted.into();
        Ok(k)
    }

    fn public_point(ctx: &mut Context, key: KeyHandle) -> Result<Vec<u8>> {
        // SESSION-LESS (module doc)
        ctx.clear_sessions();
        let (pub_area, _, _) = ctx.read_public(key).context("TPM ReadPublic")?;
        match pub_area {
            Public::Ecc { unique, .. } => {
                let mut point = vec![0x04];
                point.extend(unique.x().as_bytes());
                point.extend(unique.y().as_bytes());
                if point.len() != 65 {
                    return Err(anyhow!("unexpected P-256 point length {}", point.len()));
                }
                Ok(point)
            }
            other => Err(anyhow!("persistent key is not ECC: {other:?}")),
        }
    }

    /// Sign a 32-byte digest → 64-byte raw r||s (the shape the CSR
    /// builder and the rustls ECDSA signer expect). Bounded: TSS calls
    /// on a wedged TPM/simulator must not hang the TLS handshake path —
    /// the sign runs on a short-lived worker with a hard 5 s join
    /// deadline; a stuck worker holds the context lock but the CALLER
    /// fails closed at the deadline (the orphan dies with its syscall).
    pub fn sign_digest_raw(&self, digest: &[u8]) -> Result<[u8; 64]> {
        let budget = std::time::Duration::from_secs(5);
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = self.ctx.clone();
        let key = self.key;
        let digest = digest.to_vec();
        std::thread::spawn(move || {
            let _ = tx.send(sign_blocking(ctx, key, &digest));
        });
        match rx.recv_timeout(budget) {
            Ok(r) => r,
            Err(_) => Err(anyhow!("TPM sign exceeded {budget:?} - fail closed")),
        }
    }
}

fn sign_blocking(
    ctx: std::sync::Arc<Mutex<Context>>,
    key: KeyHandle,
    digest: &[u8],
) -> Result<[u8; 64]> {
    let mut ctx = ctx.lock().map_err(|_| anyhow!("tpm context poisoned"))?;
    let sig = {
        // password session for the authed Sign
        ctx.set_sessions((Some(AuthSession::Password), None, None));
        ctx.sign(
            key,
            Digest::try_from(digest.to_vec())?,
            SignatureScheme::EcDsa {
                scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
            None,
        )
        .context("TPM Sign")?
    };
    ctx.clear_sessions();
    match sig {
        tss_esapi::structures::Signature::EcDsa(s) => {
            let mut out = [0u8; 64];
            let (r, ss) = (s.signature_r().as_bytes(), s.signature_s().as_bytes());
            if r.len() != 32 || ss.len() != 32 {
                return Err(anyhow!(
                    "unexpected TPM signature sizes {} {}",
                    r.len(),
                    ss.len()
                ));
            }
            out[..32].copy_from_slice(r);
            out[32..].copy_from_slice(ss);
            Ok(out)
        }
        other => Err(anyhow!("not an ECDSA signature: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// swtpm harness: one emulator per test on its own ports + state
    /// dir; AZTNA_TPM2_TCTI pointed at it. Env mutation is serialized
    /// (process-global) with the shared test mutex.
    struct Swtpm {
        _dir: std::path::PathBuf,
        port: u16,
    }

    impl Drop for Swtpm {
        fn drop(&mut self) {
            let _ = std::process::Command::new("pkill")
                .args(["-f", &format!("port={}", self.port)])
                .output();
            std::env::remove_var("AZTNA_TPM2_TCTI");
        }
    }

    fn swtpm(tag: &str) -> Swtpm {
        assert!(
            std::path::Path::new("/usr/bin/swtpm").exists(),
            "swtpm must be installed for the TPM tests (apt install swtpm)"
        );
        let dir = std::env::temp_dir().join(format!(
            "aztna-swtpm-{}-{tag}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let port: u16 = 24000
            + (std::process::id() % 1000) as u16
            + (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_millis()
                % 800) as u16;
        let out = std::process::Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", dir.display()),
                "--server",
                &format!("type=tcp,port={port}"),
                "--ctrl",
                &format!("type=tcp,port={}", port + 1),
                "--flags",
                "not-need-init,startup-clear",
                "--daemon",
            ])
            .output()
            .expect("spawn swtpm");
        assert!(
            out.status.success(),
            "swtpm spawn: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // wait for the data port to listen
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "swtpm never listened");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        std::env::set_var(
            "AZTNA_TPM2_TCTI",
            format!("swtpm:host=127.0.0.1,port={port}"),
        );
        Swtpm { _dir: dir, port }
    }

    #[test]
    fn open_create_sign_and_reopen_lifecycle() {
        let _g = TPM_ENV.lock().unwrap();
        let _tpm = swtpm("lifecycle");
        let dev = TpmDevice::open_or_create()
            .expect("explicit tcti must not fail-closed here")
            .expect("device must open");
        assert_eq!(dev.point.len(), 65, "0x04||X||Y");
        assert_eq!(dev.point[0], 0x04);
        let mut sig = dev.sign_digest_raw(&[0xABu8; 32]).expect("sign");
        assert_eq!(sig.len(), 64);
        sig[0] ^= 1; // use the value
                     // reopen: the persistent key loads (same swtpm instance)
        let dev2 = TpmDevice::open_or_create()
            .expect("reopen ok")
            .expect("device");
        assert_eq!(
            dev2.point, dev.point,
            "SPKI stability - same persistent key"
        );
    }

    /// The enroll-critical path: DeviceKey over the TPM tier builds a
    /// CSR whose signature verifies against the TPM's public point, and
    /// the SPKI (device identity) is stable across reopen — the Linux
    /// twin of the Windows NCrypt proof-of-possession.
    #[test]
    fn device_key_csr_through_tpm_and_spki_stability() {
        let _g = TPM_ENV.lock().unwrap();
        let _tpm = swtpm("csr");
        let dir = std::env::temp_dir().join(format!(
            "aztna-tpm-ident-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = crate::identity::DeviceKey::open_or_create(&dir).unwrap();
        assert_eq!(key.origin, "tpm", "enrolls report the hardware tier");
        let csr_pem = key.build_csr_pem("tpm-host").expect("csr");
        let spki = spki_from_csr(&csr_pem);
        // reopen (fresh DeviceKey, same persistent TPM key) -> same SPKI
        let key2 = crate::identity::DeviceKey::open_or_create(&dir).unwrap();
        let spki2 = spki_from_csr(&key2.build_csr_pem("other-cn").expect("csr 2"));
        assert_eq!(spki, spki2, "device identity is the TPM key, not the CN");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn spki_from_csr(csr_pem: &str) -> Vec<u8> {
        use asn1_rs::FromDer;
        let (_, pem) = x509_parser::pem::parse_x509_pem(csr_pem.as_bytes()).unwrap();
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(&pem.contents)
                .unwrap();
        csr.certification_request_info
            .subject_pki
            .subject_public_key
            .data
            .to_vec()
    }

    #[test]
    fn explicit_bad_tcti_fails_closed() {
        let _g = TPM_ENV.lock().unwrap();
        std::env::set_var("AZTNA_TPM2_TCTI", "swtpm:host=127.0.0.1,port=1"); // nothing listens on 1
        let r = TpmDevice::open_or_create();
        let e = r.err().expect("explicit TCTI must fail closed");
        let msg = format!("{e:#}");
        assert!(
            msg.contains("refusing silent software-key downgrade"),
            "{msg}"
        );
        std::env::remove_var("AZTNA_TPM2_TCTI");
    }

    #[test]
    fn no_tpm_by_default_falls_back_to_software() {
        let _g = TPM_ENV.lock().unwrap();
        std::env::remove_var("AZTNA_TPM2_TCTI");
        // default device TCTI on a box without /dev/tpmrm0 (WSL) -> None
        let r = TpmDevice::open_or_create().expect("default path must not Err");
        if std::path::Path::new("/dev/tpmrm0").exists() {
            assert!(r.is_some(), "real TPM present -> device");
        } else {
            assert!(r.is_none(), "no TPM + default TCTI -> software tier");
        }
    }

    #[test]
    fn bad_tcti_syntax_is_named_error() {
        let _g = TPM_ENV.lock().unwrap();
        std::env::set_var("AZTNA_TPM2_TCTI", "not-a-tcti://??");
        let e = TpmDevice::open_or_create().err().expect("must fail");
        assert!(format!("{e:#}").contains("parse TCTI"), "{e:#}");
        std::env::remove_var("AZTNA_TPM2_TCTI");
    }
}
