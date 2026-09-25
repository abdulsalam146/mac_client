//! W43 S3: system-wide split-DNS — the FR-NET-006 remainder.
//!
//! Core (platform-neutral) pieces: `[split_dns]` config, operator-suffix
//! normalization/matching (plan §4.2), the owned-state journal + generation
//! ID (plan §4.4), and the ownership-tag helpers. The privileged OS
//! channels live in per-platform submodules ([`nrpt`] on Windows).
//!
//! Design facts baked in here were MEASURED by the S3-pre probe
//! (`docs/spikes/S3-pre-d2-d5-probe-findings.md`): the ownership tag rides
//! the NRPT rule Comment; deletion keys on the rule's GUID (Name), never
//! the namespace.

use serde::{Deserialize, Serialize};

pub mod channel;
pub mod journal;
pub mod reconciler;

#[cfg(windows)]
pub mod watchdog;

#[cfg(target_os = "macos")]
pub mod watchdog_macos;

#[cfg(windows)]
pub mod nrpt;

#[cfg(target_os = "macos")]
pub mod resolver_files;

/// Ownership tag prefix carried in the NRPT rule Comment
/// (`aztna:w43:<generation>`). Deletion filters on this prefix — never
/// on namespace alone, and never touching rules without it.
pub const TAG_PREFIX: &str = "aztna:w43:";

pub fn comment_for(generation: &str) -> String {
    format!("{}{}", TAG_PREFIX, generation)
}

pub fn is_ours(comment: &str) -> bool {
    comment.starts_with(TAG_PREFIX)
}

pub fn generation_of(comment: &str) -> Option<&str> {
    comment.strip_prefix(TAG_PREFIX)
}

/// macOS (S5, plan §4.1): the ownership tag rides the FIRST line of each
/// `/etc/resolver/<fqdn>` file as `# aztna:w43:<generation> managed`.
/// Pure helpers live here so they unit-test on every platform.
pub fn marker_line(generation: &str) -> String {
    format!("# {} managed", comment_for(generation))
}

/// The generation carried by a marker line, or None for any other line
/// (a foreign file's first line is not ours — that is the conflict
/// signal; never touch such a file).
pub fn marker_generation(first_line: &str) -> Option<&str> {
    let body = first_line.strip_prefix("# ")?.strip_suffix(" managed")?;
    generation_of(body)
}

/// The scoped-resolver body for one fqdn: the client's loopback
/// responder, nothing else (no search, no options — resolver(5)).
pub fn resolver_file_body(generation: &str) -> String {
    format!("{}\nnameserver 127.0.0.1\n", marker_line(generation))
}

/// W43 D4: `auto` on Windows once S3 is green, `manual` elsewhere until
/// native qualification lanes pass. With the D10 empty default allowlist,
/// `auto` installs nothing until an operator supplies suffixes.
fn default_mode() -> SplitDnsMode {
    #[cfg(windows)]
    {
        SplitDnsMode::Auto
    }
    #[cfg(not(windows))]
    {
        SplitDnsMode::Manual
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitDnsMode {
    Off,
    Manual,
    Auto,
}

impl Default for SplitDnsMode {
    fn default() -> Self {
        default_mode()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SplitDnsConfig {
    #[serde(default)]
    pub mode: SplitDnsMode,
    /// Operator-declared private-namespace policy (D10): auto mode installs
    /// a rule only for zone entries under one of these suffixes. Empty (the
    /// default) ⇒ auto mode installs nothing — Windows `auto` is effectively
    /// inactive until an administrator supplies suffixes.
    #[serde(default)]
    pub suffix_allowlist: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SuffixError {
    Empty,
    Wildcard,
    LeadingDot,
    EmptyLabel,
    IpLiteral,
    InvalidIdn,
}

impl std::fmt::Display for SuffixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SuffixError::Empty => "empty suffix",
            SuffixError::Wildcard => "wildcards are not allowed",
            SuffixError::LeadingDot => "leading dot",
            SuffixError::EmptyLabel => "empty label",
            SuffixError::IpLiteral => "IP literals are not allowed",
            SuffixError::InvalidIdn => "IDN label could not be punycoded",
        };
        f.write_str(s)
    }
}

/// Normalize an operator suffix or a zone fqdn per plan §4.2: lowercase,
/// strip ONE trailing dot, reject wildcards/leading dots/IP literals/empty
/// labels, and punycode non-ASCII labels (A-label form).
pub fn normalize_name(raw: &str) -> Result<String, SuffixError> {
    let mut s = raw.trim().to_lowercase();
    if s.ends_with('.') {
        s.pop();
    }
    if s.is_empty() {
        return Err(SuffixError::Empty);
    }
    if s.contains('*') {
        return Err(SuffixError::Wildcard);
    }
    if s.starts_with('.') {
        return Err(SuffixError::LeadingDot);
    }
    if s.split('.').any(|l| l.is_empty()) {
        return Err(SuffixError::EmptyLabel);
    }
    if looks_like_ip(&s) {
        return Err(SuffixError::IpLiteral);
    }
    let mut labels = Vec::new();
    for label in s.split('.') {
        if label.is_ascii() {
            labels.push(label.to_string());
        } else {
            let enc = punycode_encode(label).ok_or(SuffixError::InvalidIdn)?;
            labels.push(format!("xn--{}", enc));
        }
    }
    Ok(labels.join("."))
}

fn looks_like_ip(s: &str) -> bool {
    if s.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    let t = s.trim_start_matches('[').trim_end_matches(']');
    t.parse::<std::net::Ipv6Addr>().is_ok()
        || t.contains(':') && !t.contains(char::is_alphabetic) && !t.is_empty()
}

/// Label-aligned suffix match: `erp.corp.example.com` matches the allowlist
/// entry `corp.example.com`; `notcorp.example.com` does not.
pub fn suffix_matches(name: &str, suffix: &str) -> bool {
    name == suffix || name.strip_suffix(&format!(".{}", suffix)).is_some()
}

/// Why a zone entry did not become a desired rule (metric/event label).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// Malformed name (normalization failed).
    InvalidSuffix,
    /// Well-formed, but not under any allowlist suffix (D10 policy).
    NotAllowlisted,
}

/// Compute the desired exact-namespace rule set from the live zone map and
/// the operator allowlist: every zone fqdn that normalizes cleanly and
/// falls under an allowlist suffix (after normalizing the allowlist too).
/// Returns (desired, rejected) with rejected carrying the reason for the
/// `splitdns_conflict`/`result=invalid_suffix` observability.
pub fn desired_namespaces(
    zone_names: impl Iterator<Item = String>,
    allowlist: &[String],
) -> (Vec<String>, Vec<(String, RejectReason)>) {
    let mut normalized_allow: Vec<String> = Vec::new();
    for a in allowlist {
        match normalize_name(a) {
            Ok(n) => normalized_allow.push(n),
            Err(_) => { /* operator-config problem: surfaced at load, not per-entry */ }
        }
    }
    let mut desired: Vec<String> = Vec::new();
    let mut rejected: Vec<(String, RejectReason)> = Vec::new();
    for name in zone_names {
        let n = match normalize_name(&name) {
            Ok(n) => n,
            Err(_) => {
                rejected.push((name, RejectReason::InvalidSuffix));
                continue;
            }
        };
        if normalized_allow.iter().any(|s| suffix_matches(&n, s)) {
            if !desired.contains(&n) {
                desired.push(n);
            }
        } else {
            rejected.push((name, RejectReason::NotAllowlisted));
        }
    }
    desired.sort();
    (desired, rejected)
}

// ---------------- punycode (RFC 3492 encode only) ----------------
// The allowlist is operator-typed and may carry Unicode; zone entries on
// the wire are already A-labels. Encode-only keeps this dependency-free.

fn punycode_encode(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    const INITIAL_BIAS: u32 = 72;
    const INITIAL_N: u32 = 128;

    fn adapt(mut delta: u32, numpoints: u32, firsttime: bool) -> u32 {
        delta = if firsttime { delta / DAMP } else { delta / 2 };
        delta += delta / numpoints;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
    }

    fn digit_to_char(d: u32) -> Option<char> {
        match d {
            0..=25 => Some((b'a' + d as u8) as char),
            26..=35 => Some((b'0' + (d - 26) as u8) as char),
            _ => None,
        }
    }

    let chars: Vec<char> = input.chars().collect();
    let mut output: String = chars.iter().filter(|c| c.is_ascii()).collect();
    let basic_len = output.chars().count() as u32;
    let handled = basic_len;
    if basic_len > 0 {
        output.push('-');
    }
    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let total = chars.len() as u32;
    let mut h = handled;
    while h < total {
        let m = chars.iter().map(|c| *c as u32).filter(|&c| c >= n).min()?;
        // overflow-checked (reject rather than wrap)
        delta += m.checked_sub(n).and_then(|d| d.checked_mul(h + 1))?;
        n = m;
        for c in &chars {
            let cp = *c as u32;
            if cp < n {
                delta = delta.checked_add(1)?;
            }
            if cp == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        TMIN
                    } else if k >= bias + TMAX {
                        TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    let digit = t + ((q - t) % (BASE - t));
                    output.push(digit_to_char(digit)?);
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(digit_to_char(q)?);
                bias = adapt(delta, h + 1, h == basic_len);
                delta = 0;
                h += 1;
            }
        }
        delta += 1;
        n += 1;
    }
    Some(output)
}

/// Mint a fresh generation ID (ownership-scope for rules and watchdog
/// objects; plan §4.4 — reconcile-first deletes owned rules from any OLDER
/// generation). Random + wall-clock: unique across processes and boots.
pub fn new_generation() -> String {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0);
    format!("{}-{:016x}", hex(&b), now)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_matrix() {
        // clean pass-through + case + one trailing dot
        assert_eq!(
            normalize_name("Corp.Example.COM.").unwrap(),
            "corp.example.com"
        );
        // rejections per plan §4.2
        assert_eq!(normalize_name(""), Err(SuffixError::Empty));
        assert_eq!(normalize_name("  "), Err(SuffixError::Empty));
        assert_eq!(normalize_name("*.corp.com"), Err(SuffixError::Wildcard));
        assert_eq!(normalize_name(".corp.com"), Err(SuffixError::LeadingDot));
        assert_eq!(normalize_name("corp..com"), Err(SuffixError::EmptyLabel));
        assert_eq!(normalize_name("10.1.2.3"), Err(SuffixError::IpLiteral));
        assert_eq!(normalize_name("[2001:db8::1]"), Err(SuffixError::IpLiteral));
        assert_eq!(normalize_name("2001:db8::1"), Err(SuffixError::IpLiteral));
    }

    #[test]
    fn normalize_idn_to_alabels() {
        // RFC 3492 vectors (the xn-- prefix is added per label)
        assert_eq!(normalize_name("Bücher.corp").unwrap(), "xn--bcher-kva.corp");
        assert_eq!(normalize_name("münchen.de").unwrap(), "xn--mnchen-3ya.de");
        assert_eq!(normalize_name("日本語.jp").unwrap(), "xn--wgv71a119e.jp");
    }

    #[test]
    fn suffix_matching_is_label_aligned() {
        assert!(suffix_matches("erp.corp.example.com", "corp.example.com"));
        assert!(suffix_matches("corp.example.com", "corp.example.com"));
        assert!(!suffix_matches("notcorp.example.com", "corp.example.com"));
        assert!(!suffix_matches(
            "corp.example.com.evil.net",
            "corp.example.com"
        ));
    }

    #[test]
    fn desired_set_respects_allowlist() {
        let zones = vec![
            "erp.corp.example.com".to_string(),
            "ERP.CORP.EXAMPLE.COM.".to_string(), // dup after normalization
            "api.erp.corp.example.com".to_string(),
            "stray.example.com".to_string(), // well-formed, not allowlisted
            "bad..name".to_string(),         // malformed
        ];
        let allow = vec!["Corp.Example.COM".to_string()];
        let (desired, rejected) = desired_namespaces(zones.into_iter(), &allow);
        assert_eq!(
            desired,
            vec![
                "api.erp.corp.example.com".to_string(),
                "erp.corp.example.com".to_string()
            ]
        );
        assert_eq!(rejected.len(), 2);
        assert!(rejected.contains(&(
            "stray.example.com".to_string(),
            RejectReason::NotAllowlisted
        )));
        assert!(rejected.contains(&("bad..name".to_string(), RejectReason::InvalidSuffix)));
    }

    #[test]
    fn empty_allowlist_desires_nothing() {
        let (desired, rejected) = desired_namespaces(["erp.corp".into()].into_iter(), &[]);
        assert!(desired.is_empty());
        assert_eq!(rejected.len(), 1);
    }

    #[test]
    fn tag_roundtrip() {
        let gen = new_generation();
        let c = comment_for(&gen);
        assert!(is_ours(&c));
        assert_eq!(generation_of(&c), Some(gen.as_str()));
        assert!(!is_ours(""));
        assert!(!is_ours("aztna:w43-probe-legacy"));
        assert_eq!(generation_of("some admin rule"), None);
    }

    #[test]
    fn marker_roundtrip_and_foreign_detection() {
        // the macOS resolver-file ownership marker (plan §4.1): first line
        // `# aztna:w43:<generation> managed`
        let gen = new_generation();
        let m = marker_line(&gen);
        assert_eq!(m, format!("# aztna:w43:{gen} managed"));
        assert_eq!(marker_generation(&m), Some(gen.as_str()));
        // a foreign file's first line carries no generation — the conflict
        // signal; the channel must never touch it
        assert_eq!(marker_generation("# some admin tool managed"), None);
        assert_eq!(marker_generation("nameserver 10.0.0.1"), None);
        assert_eq!(marker_generation(""), None);
        // the body is exactly marker + our loopback responder
        assert_eq!(
            resolver_file_body(&gen),
            format!("{m}\nnameserver 127.0.0.1\n")
        );
    }

    #[test]
    fn generation_is_unique() {
        assert_ne!(new_generation(), new_generation());
    }
}
