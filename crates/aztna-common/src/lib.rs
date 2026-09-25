//! Shared types/constants for aZTNA components.

pub mod metrics;
pub mod net;
pub mod udp_frag;

/// Canonical product name used across components.
pub const APP_NAME: &str = "aZTNA";

/// Default ports per T1 dev topology [implementation-plan §4] — glm variant
/// (2xxxx block; sibling aZTNA clone keeps the legacy 9443/74xx block).
pub mod ports {
    pub const CONTROLLER_MGMT: u16 = 29443;
    pub const CONTROLLER_CLIENT: u16 = 27443;
    pub const CONTROLLER_GATEWAY: u16 = 27444;
    /// bootstrap listener (enroll / gateway register / CA) [P2-5, ADR-0009]
    pub const CONTROLLER_ENROLL: u16 = 27445;
    /// SaaS-facing OP listener (W27 IdP mode; binds only when
    /// `[idp_mode] act_as_idp = true` — contract docs/w27-op-contract.md)
    pub const CONTROLLER_OP: u16 = 27446;
    pub const MOCK_OIDC: u16 = 25556;
}

/// T1 loopback IPs (glm variant).
pub mod ips {
    pub const CONTROLLER: &str = "127.0.0.210";
    pub const GATEWAY_RELAY: &str = "127.0.0.211";
    pub const MOCK_OIDC: &str = "127.0.0.212";
    pub const TEST_APP: &str = "127.0.0.220";
    /// second test app for multi-gateway E2E [P3-MG]
    pub const TEST_APP2: &str = "127.0.0.221";
}

/// Canonical URL forms of the dev topology [P3-MG M5 — single source; no IP
/// literals scattered across binaries].
pub mod urls {
    pub const CONTROLLER_MGMT: &str = "http://127.0.0.210:29443";
    pub const CONTROLLER_CLIENT: &str = "https://127.0.0.210:27443";
    pub const CONTROLLER_GATEWAY: &str = "https://127.0.0.210:27444";
    pub const CONTROLLER_ENROLL: &str = "https://127.0.0.210:27445";
    pub const IDP_BASE: &str = "http://127.0.0.212:25556";
}

/// Listener address forms (host:port, parseable as SocketAddr).
pub mod addrs {
    pub const MGMT: &str = "127.0.0.210:29443";
    pub const CLIENT: &str = "127.0.0.210:27443";
    pub const GATEWAY: &str = "127.0.0.210:27444";
    pub const ENROLL: &str = "127.0.0.210:27445";
    pub const OP: &str = "127.0.0.210:27446";
}

#[derive(Debug, thiserror::Error)]
pub enum CommonError {
    #[error("config error: {0}")]
    Config(String),
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
}

// ---------- W40 S2 [FR-NET-002]: the tenant transport mode ----------

/// W40 [FR-NET-002]: the tenant transport mode — ONE canonical value
/// representation everywhere (controller.toml, env, settings API, DB
/// row, snapshot payload, policy-version + pinning wire fields, client,
/// gateway). Serde wire form is the lowercase snake_case string
/// (`auto` | `tcp_first` | `quic_only` | `tcp_only`).
///
/// Desired-mode semantics (plan §1.1/§3.5): a carrier-selection
/// PREFERENCE distributed by polling — never an enforcement control and
/// never a trust change (mTLS intact in every mode).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    #[default]
    Auto,
    TcpFirst,
    QuicOnly,
    TcpOnly,
}

impl TransportMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportMode::Auto => "auto",
            TransportMode::TcpFirst => "tcp_first",
            TransportMode::QuicOnly => "quic_only",
            TransportMode::TcpOnly => "tcp_only",
        }
    }

    /// Every legal wire value (spec enums, validation lists, gauge
    /// pre-creation — one source).
    pub const ALL: [TransportMode; 4] = [
        TransportMode::Auto,
        TransportMode::TcpFirst,
        TransportMode::QuicOnly,
        TransportMode::TcpOnly,
    ];

    /// STRICT parse — for values that must be exact (API PUT, stored
    /// rows, rollback targets): an unknown value is an error, never a
    /// silent tier drop.
    pub fn parse_exact(s: &str) -> Option<TransportMode> {
        TransportMode::ALL.iter().copied().find(|m| m.as_str() == s)
    }

    /// LENIENT parse — the receive-side half of the fail-safe contract
    /// (plan §3.1): returns the mode plus `true` when the value was
    /// unknown/malformed and the caller should count/warn (the
    /// once-per-distinct-value dedup is the CONSUMER's — client and
    /// gateway own their log streams).
    pub fn parse_lenient(s: &str) -> (TransportMode, bool) {
        match TransportMode::parse_exact(s) {
            Some(m) => (m, false),
            None => (TransportMode::Auto, true),
        }
    }

    /// The fail-safe FIELD contract for received messages: missing or
    /// null -> Auto; a known string -> parsed; any other JSON value
    /// (unknown string, number, object...) -> Auto + fallback=true.
    /// The containing message still parses BY CONSTRUCTION — the caller
    /// deserializes this field through a custom `deserialize_with` that
    /// routes here, so an unknown FUTURE value can never break an
    /// older peer's whole response parse (unknown FIELD is separately
    /// ignored by the no-`deny_unknown_fields` convention — the two
    /// cases are deliberately distinct, plan §3.1).
    pub fn from_json_fail_safe(v: Option<&serde_json::Value>) -> (TransportMode, bool) {
        match v {
            None | Some(serde_json::Value::Null) => (TransportMode::Auto, false),
            Some(serde_json::Value::String(s)) => TransportMode::parse_lenient(s),
            Some(_) => (TransportMode::Auto, true), // malformed type
        }
    }
}

#[cfg(test)]
mod w40_transport_mode_tests {
    use super::*;

    #[test]
    fn wire_strings_round_trip() {
        for m in TransportMode::ALL {
            let s = serde_json::to_string(&m).unwrap();
            let back: TransportMode = serde_json::from_str(&s).unwrap();
            assert_eq!(back, m, "{s} round-trips");
        }
        assert_eq!(
            serde_json::to_string(&TransportMode::TcpFirst).unwrap(),
            "\"tcp_first\""
        );
    }

    #[test]
    fn exact_vs_lenient_matrix() {
        assert_eq!(
            TransportMode::parse_exact("quic_only"),
            Some(TransportMode::QuicOnly)
        );
        assert_eq!(TransportMode::parse_exact("future_mode"), None);
        let (m, fb) = TransportMode::parse_lenient("future_mode");
        assert_eq!((m, fb), (TransportMode::Auto, true));
        let (m, fb) = TransportMode::parse_lenient("tcp_only");
        assert_eq!((m, fb), (TransportMode::TcpOnly, false));
    }

    #[test]
    fn fail_safe_field_matrix() {
        // missing / null -> auto, no fallback
        assert_eq!(
            TransportMode::from_json_fail_safe(None),
            (TransportMode::Auto, false)
        );
        assert_eq!(
            TransportMode::from_json_fail_safe(Some(&serde_json::Value::Null)),
            (TransportMode::Auto, false)
        );
        // known string
        assert_eq!(
            TransportMode::from_json_fail_safe(Some(&serde_json::json!("tcp_first"))),
            (TransportMode::TcpFirst, false)
        );
        // unknown string + malformed types -> auto + fallback
        for v in [
            serde_json::json!("future_mode"),
            serde_json::json!(7),
            serde_json::json!({"x": 1}),
        ] {
            assert_eq!(
                TransportMode::from_json_fail_safe(Some(&v)),
                (TransportMode::Auto, true),
                "{v} degrades to auto + fallback"
            );
        }
        // the containing message still parses when the field rides a
        // fail-safe deserializer: simulate a W41 response shape
        #[derive(serde::Deserialize)]
        struct Resp {
            version: i64,
            #[serde(default, deserialize_with = "mode_field")]
            transport_mode: TransportMode,
        }
        fn mode_field<'de, D>(d: D) -> std::result::Result<TransportMode, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::Deserialize as _;
            let raw = Option::<serde_json::Value>::deserialize(d)?;
            Ok(TransportMode::from_json_fail_safe(raw.as_ref()).0)
        }
        let r: Resp =
            serde_json::from_str(r#"{"version": 3, "transport_mode": "future_mode"}"#).unwrap();
        assert_eq!((r.version, r.transport_mode), (3, TransportMode::Auto));
        let r: Resp = serde_json::from_str(r#"{"version": 4}"#).unwrap();
        assert_eq!(r.transport_mode, TransportMode::Auto);
        let r: Resp = serde_json::from_str(r#"{"version": 5, "transport_mode": 9}"#).unwrap();
        assert_eq!(r.transport_mode, TransportMode::Auto);
    }
}

pub type Result<T> = std::result::Result<T, CommonError>;

/// Read a seconds-tuning env var (same pattern as PIN_POLL_SECS /
/// AZTNA_POSTURE_SECS): absent or below-floor ⇒ default. Resilience policy:
/// networked waits are bounded AND operator-tunable without a redeploy.
pub fn env_secs(var: &str, default: u64, min: u64) -> std::time::Duration {
    let v = std::env::var(var)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|v| *v >= min)
        .unwrap_or(default);
    std::time::Duration::from_secs(v)
}
