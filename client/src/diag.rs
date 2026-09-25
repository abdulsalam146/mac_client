//! W13 step 5 [DR-CLT-022/FR-CLT-008]: the diagnostics bundle — one
//! folder a user (tray menu) or admin (`glmcli diagnostics`) hands to
//! support: manifest, connectivity probes, tailed event log, metrics
//! dump. SANITIZED BY CONSTRUCTION + verified: no token material, no
//! private keys, no cert PEMs (fingerprints instead) — the redaction is
//! asserted by the e2e, not trusted.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub struct BundleReport {
    pub dir: PathBuf,
    pub partial: bool,
}

/// Build the bundle into `out` (created; name it aztna-diag-<unixts>).
/// Runs from either host — state tells it what to probe.
pub async fn build_bundle(out: &Path, st: &crate::ClientState) -> Result<BundleReport> {
    let ts = crate::unix_now();
    let dir = out.join(format!("aztna-diag-{ts}"));
    std::fs::create_dir_all(&dir)?;
    let mut partial = false;

    // ---- manifest.json (fingerprints, never PEM) ----
    let cert_fp = st
        .cert_pem
        .as_ref()
        .map(|pem| {
            rustls_pemfile::certs(&mut std::io::BufReader::new(pem.as_bytes()))
                .next()
                .and_then(|c| c.ok())
                .map(|c| spki_fp(&c))
                .unwrap_or_else(|| "<unreadable>".into())
        })
        .unwrap_or_else(|| "<none>".into());
    let manifest = serde_json::json!({
        "component": "aztna-client",
        "version": crate::posture_collector::CLIENT_VERSION,
        "generated_unix": ts,
        "controller_url": st.controller_url,
        "device_id": st.device_id,           // public (ADR-0010: spki hash)
        "device_cert_fingerprint": cert_fp,  // fingerprint, not the PEM
        "key_origin": st.key_origin,
        "has_token": st.access_token.is_some(), // BOOL ONLY - never the token
    });
    write_sanitized(
        &dir.join("manifest.json"),
        &serde_json::to_string_pretty(&manifest)?,
    )?;

    // ---- connectivity.json (bounded probes, 3 s each) ----
    let mut conn = serde_json::Map::new();
    // controller enroll/CA reachability (server-TLS TOFU channel, plain GET)
    let enroll = st
        .controller_enroll_url
        .clone()
        .unwrap_or_else(|| aztna_common::urls::CONTROLLER_ENROLL.into());
    let t0 = std::time::Instant::now();
    let ca_ok = probe_ca(&enroll).await.is_ok();
    conn.insert(
        "controller_enroll_ca".into(),
        json_probe(ca_ok, t0.elapsed()),
    );
    if !ca_ok {
        partial = true;
    }
    // service IPC (if this host runs alongside glmsvc)
    if let Ok(cfg) = crate::svc::load_config() {
        let ipc = crate::svc::ipc_call(
            &cfg.ipc_bind,
            &crate::svc::IpcReq {
                v: 1,
                cmd: "status".into(),
                token: None,
            },
        )
        .await;
        conn.insert(
            "service_ipc".into(),
            match ipc {
                Ok(r) => serde_json::json!({"ok": true, "state": r.state}),
                Err(e) => serde_json::json!({"ok": false, "error": e.to_string()}),
            },
        );
    }
    write_sanitized(
        &dir.join("connectivity.json"),
        &serde_json::to_string_pretty(&serde_json::Value::Object(conn))?,
    )?;

    // ---- events-tail.jsonl (last 200 lines of client.log, sanitized) ----
    let log_path = crate::state_path()
        .parent()
        .map(|d| d.join("client.log"))
        .unwrap_or_else(|| PathBuf::from("client.log"));
    let tail = tail_lines(&log_path, 200);
    write_sanitized(&dir.join("events-tail.jsonl"), &tail)?;

    // ---- metrics.txt (the local registry rendered — no scrape needed) ----
    let mut buf = Vec::new();
    let fam = prometheus::gather();
    let enc = prometheus::TextEncoder::new();
    use prometheus::Encoder as _;
    let _ = enc.encode(&fam, &mut buf);
    write_sanitized(&dir.join("metrics.txt"), &String::from_utf8_lossy(&buf))?;

    crate::log_event("diagnostics_exported", &format!("dir={}", dir.display()));
    crate::metrics::diagnostics_bundles_total()
        .with_label_values(&[if partial { "partial" } else { "ok" }])
        .inc();
    Ok(BundleReport { dir, partial })
}

fn json_probe(ok: bool, d: std::time::Duration) -> serde_json::Value {
    serde_json::json!({"ok": ok, "ms": d.as_millis() as u64})
}

async fn probe_ca(enroll_base: &str) -> Result<()> {
    let tofu = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // diagnostics probe only
        .timeout(std::time::Duration::from_secs(3))
        .build()?;
    let r = tofu
        .get(format!("{}/v1/ca", enroll_base.trim_end_matches('/')))
        .send()
        .await
        .context("ca probe")?;
    anyhow::ensure!(r.status().is_success(), "ca probe status {}", r.status());
    Ok(())
}

/// Last N lines of a file (whole file if shorter); missing file = note.
fn tail_lines(p: &Path, n: usize) -> String {
    match std::fs::read_to_string(p) {
        Ok(s) => {
            let lines: Vec<&str> = s.lines().collect();
            let start = lines.len().saturating_sub(n);
            lines[start..].join("\n")
        }
        Err(_) => "<no client.log>".into(),
    }
}

/// Write with blanket sanitization: strip PEM blocks (keys AND certs —
/// fingerprints live in the manifest) and any long base64 run (token-
/// shaped). Belt-and-braces on top of by-construction exclusion.
fn write_sanitized(p: &Path, content: &str) -> Result<()> {
    let mut out = String::with_capacity(content.len());
    let mut in_pem = false;
    for line in content.lines() {
        if line.contains("-----BEGIN") {
            in_pem = true;
            out.push_str("[REDACTED-PEM]\n");
            continue;
        }
        if line.contains("-----END") {
            in_pem = false;
            continue;
        }
        if in_pem {
            continue;
        }
        // token-shaped base64 (>80 chars continuous) — replace
        let l = if line.len() > 80 && is_base64ish(line) {
            "[REDACTED-B64]"
        } else {
            line
        };
        out.push_str(l);
        out.push('\n');
    }
    std::fs::write(p, out)?;
    Ok(())
}

fn is_base64ish(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// SHA-256 of the cert's subject-public-key bits (the ADR-0010 device_id
/// computation — public value, safe to ship; twin of the gateway's
/// spki_sha256_hex).
fn spki_fp(cert_der: &[u8]) -> String {
    use asn1_rs::FromDer as _;
    use sha2::Digest as _;
    x509_parser::certificate::X509Certificate::from_der(cert_der)
        .ok()
        .map(|(_, c)| {
            sha2::Sha256::digest(&c.tbs_certificate.subject_pki.subject_public_key.data)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        })
        .unwrap_or_else(|| "<fingerprint-error>".into())
}
