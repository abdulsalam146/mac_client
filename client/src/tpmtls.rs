//! P2-7: mTLS where the private key never leaves the TPM. rustls lets us
//! supply a custom client-cert resolver whose SigningKey calls NCryptSignHash
//! — reqwest accepts the resulting ClientConfig via use_preconfigured_tls.

use anyhow::Result;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, SignatureScheme};
use std::sync::Arc;

use crate::identity::DeviceKey;

// W29: the TPM signer pair is exercised by the (Windows) TPM tier today;
// the Linux TPM tier (step 4) consumes the same scheme + DER helper.
const SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;

pub struct NcryptSigningKey {
    pub device: Arc<DeviceKey>,
}

impl std::fmt::Debug for NcryptSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NcryptSigningKey")
    }
}

impl rustls::sign::SigningKey for NcryptSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&SCHEME) {
            Some(Box::new(NcryptSigner {
                device: self.device.clone(),
            }))
        } else {
            None
        }
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}

struct NcryptSigner {
    device: Arc<DeviceKey>,
}

impl std::fmt::Debug for NcryptSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NcryptSigner")
    }
}

impl rustls::sign::Signer for NcryptSigner {
    /// `message` is the finished transcript hash (32 bytes for SHA-256);
    /// NCryptSignHash signs exactly a digest.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        // TLS1.3 hands us the 32-byte transcript hash; TLS1.2 hands the
        // RAW handshake bytes the signer must hash itself (ring's
        // signers do this internally — found live by the W29 swtpm lane:
        // a 130-byte "bad transcript hash length"). Hash anything that
        // is not already a digest.
        let digest: [u8; 32] = if message.len() == 32 {
            message
                .try_into()
                .map_err(|_| rustls::Error::General("32-byte assert failed".into()))?
        } else {
            use sha2::Digest;
            let h: [u8; 32] = sha2::Sha256::digest(message).into();
            h
        };
        let raw = self
            .device
            .sign_digest_raw(&digest)
            .map_err(|e| rustls::Error::General(format!("tpm sign: {e}")))?;
        // TLS 1.3 carries ECDSA signatures DER-encoded (RFC 8446 §4.2.3)
        let der = raw_to_der(&raw);
        Ok(der)
    }
    fn scheme(&self) -> SignatureScheme {
        SCHEME
    }
}

fn raw_to_der(raw: &[u8; 64]) -> Vec<u8> {
    fn uint(b: &[u8]) -> Vec<u8> {
        let mut b = b;
        while b.len() > 1 && b[0] == 0 {
            b = &b[1..];
        }
        let mut v = Vec::with_capacity(b.len() + 1);
        if b[0] & 0x80 != 0 {
            v.push(0);
        }
        v.extend_from_slice(b);
        let mut out = vec![0x02];
        if v.len() >= 0x80 {
            out.push(0x81);
        }
        out.push(v.len() as u8);
        out.extend_from_slice(&v);
        out
    }
    let mut body = uint(&raw[..32]);
    body.extend(uint(&raw[32..]));
    let mut out = vec![0x30];
    if body.len() >= 0x80 {
        out.push(0x81);
    }
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

/// W8.2: pub + reused by the QUIC data path - any client config whose
/// identity is a (cert chain, signer) pair resolves it unconditionally.
#[derive(Debug)]
pub struct Resolver {
    pub key: Arc<CertifiedKey>,
}

impl rustls::client::ResolvesClientCert for Resolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _schemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.key.clone())
    }
    fn has_certs(&self) -> bool {
        true
    }
}

/// W29 step 6 fix (found by the swtpm lane; LATENT ON WINDOWS TOO — the
/// TPM TLS path was never e2e-exercised before it): the TPM ECDSA P-256
/// signer signs a fixed 32-byte transcript hash; a negotiated SHA-384
/// cipher suite (TLS_AES_256_GCM_SHA384 is offered first by the ring
/// default provider) hands it a 48-byte hash and the handshake dies
/// with "bad transcript hash length". TPM-signed configs therefore
/// restrict the suite list to SHA-256-transcript suites. The SOFTWARE
/// path is untouched (ring handles any digest length).
pub fn sha256_only_client_config(
    roots: RootCertStore,
    certified: Arc<CertifiedKey>,
) -> ClientConfig {
    let mut provider = rustls::crypto::ring::default_provider();
    // drop TLS1.3 SHA-384 suites (48-byte transcripts); every TLS1.2
    // suite in the ring provider is SHA-256-transcript already
    provider.cipher_suites.retain(|cs| match cs {
        rustls::SupportedCipherSuite::Tls13(cs13) => cs13.common.hash_provider.output_len() == 32,
        rustls::SupportedCipherSuite::Tls12(_) => true,
    });
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("safe default versions with the ring provider")
        .with_root_certificates(roots)
        .with_client_cert_resolver(Arc::new(Resolver { key: certified }))
}

/// reqwest client whose TLS identity is the TPM device key.
/// W8.2: (certs, signer) now sourced from identity::tls_client_identity —
/// identical NcryptSigningKey wiring as before, one construction shared
/// with the QUIC data path. The software reqwest path (mtls_client) does
/// not go through here and is untouched by construction.
pub fn tpm_mtls_client(
    ca_pem: &str,
    cert_pem: &str,
    device: Arc<DeviceKey>,
) -> Result<reqwest::Client> {
    let mut roots = RootCertStore::empty();
    let mut pem_reader = std::io::BufReader::new(ca_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut pem_reader) {
        roots.add(cert?)?;
    }
    let (certs, key) = crate::identity::tls_client_identity(device, cert_pem)?;
    let certified = Arc::new(CertifiedKey::new(certs, key));
    let config = sha256_only_client_config(roots, certified);
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .build()
        .map_err(Into::into)
}
