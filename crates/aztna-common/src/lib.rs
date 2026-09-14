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
