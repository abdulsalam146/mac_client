//! Client metric accessors [NFR-OBS §7.2 client section; §7.3 loopback-only
//! export via `--metrics`]. Prometheus does the math; we count occurrences.

use aztna_common::metrics as mm;

pub fn intercepted_connections() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_intercepted_connections_total",
            "Forwarder connection outcomes: allow|deny|fail_closed",
            &["result"],
        )
    })
    .clone()
}

pub fn connection_establishment() -> prometheus::Histogram {
    static C: std::sync::OnceLock<prometheus::Histogram> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::histogram(
            "aztna_client_connection_establishment_seconds",
            "Local accept → gateway OK ack [PERF-004 ≤2 s]",
            mm::SETUP_BUCKETS,
        )
    })
    .clone()
}

pub fn reconnects_total() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_reconnects_total",
            "Gateway dial attempts that failed (advance/backoff)",
            &["gateway_id"],
        )
    })
    .clone()
}

pub fn backoff_current_seconds() -> prometheus::IntGauge {
    static C: std::sync::OnceLock<prometheus::IntGauge> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_gauge(
            "aztna_client_backoff_current_seconds",
            "Current dial backoff (0 when healthy) [F-08]",
        )
    })
    .clone()
}

pub fn tunnel_state() -> prometheus::IntGaugeVec {
    static C: std::sync::OnceLock<prometheus::IntGaugeVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_gauge_vec(
            "aztna_client_tunnel_state",
            "1 while this serve session is up",
            &["state"],
        )
    })
    .clone()
}

pub fn posture_reports_sent() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_posture_reports_sent_total",
            "Posture push outcomes: healthy|unhealthy|error|skipped [F-13]",
            &["outcome"],
        )
    })
    .clone()
}

/// W3.4 [posture-evolution-plan §1]: push mix — full reports vs unchanged
/// markers (change-only push efficiency + liveness credit).
pub fn posture_push_mode() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_posture_push_mode_total",
            "Periodic pushes by mode: full (changed/refresh) | marker (unchanged)",
            &["mode"],
        )
    })
    .clone()
}

/// W3.5: which requirement-spec version this client implements.
pub fn posture_spec_version() -> prometheus::IntGauge {
    static C: std::sync::OnceLock<prometheus::IntGauge> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_gauge(
            "aztna_client_posture_spec_version",
            "Posture requirement spec version currently applied (0 = none)",
        )
    })
    .clone()
}

/// W3.5: probe family outcomes.
pub fn posture_probe_results() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_posture_probe_results_total",
            "Probe results per family: match|nomatch|error|unsupported",
            &["family", "result"],
        )
    })
    .clone()
}

pub fn dns_queries_total() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_dns_queries_total",
            "Private-responder queries: answered|nxdomain|empty [W4.1]",
            &["result"],
        )
    })
    .clone()
}

pub fn dns_responder_errors() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_dns_responder_errors_total",
            "Responder socket errors: conn_reset|other (deafness watchdog)",
            &["class"],
        )
    })
    .clone()
}

pub fn dns_zones_last_success_timestamp() -> prometheus::IntGauge {
    static C: std::sync::OnceLock<prometheus::IntGauge> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_gauge(
            "aztna_client_dns_zones_last_success_timestamp",
            "Unix ts of last successful zone fetch (age = time() - x)",
        )
    })
    .clone()
}

pub fn dns_forwarder_bind_failures() -> prometheus::IntCounter {
    static C: std::sync::OnceLock<prometheus::IntCounter> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter(
            "aztna_client_dns_forwarder_bind_failures_total",
            "Loopback forwarder binds that failed (port conflicts/elevation)",
        )
    })
    .clone()
}

/// W6.3 [NFR §7.2 EXT]: /v1/dns-zones denials by reason. reason enum:
/// revoked | idle | unauthorized. Each denial clears the zone map AND the
/// forwarder listeners (the namespace shape must not stay resident).
pub fn zone_denies_total() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_zone_denies_total",
            "zone refreshes denied by the session registry, by reason [W6.3]",
            &["reason"],
        )
    })
    .clone()
}

pub fn fail_mode_closed() -> prometheus::IntCounter {
    static C: std::sync::OnceLock<prometheus::IntCounter> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter(
            "aztna_client_fail_mode_closed_total",
            "Connections closed because the controller was unreachable [DR-CLT-013]",
        )
    })
    .clone()
}

/// W4.4-stall hardening: bounded-wait exhaustion on the setup path (the old
/// code waited indefinitely at these points — the stall class that produced
/// the ~8s first-connection samples).
pub fn tunnel_setup_timeouts() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_tunnel_setup_timeouts_total",
            "Setup-path bounded waits exhausted: decision|dial|ack",
            &["phase"],
        )
    })
    .clone()
}

/// W4.4-stall hardening: posture collection is a background worker; panics or
/// deadline-orphaned workers mean the hot path serves a stale snapshot.
pub fn posture_collect_failures() -> prometheus::IntCounter {
    static C: std::sync::OnceLock<prometheus::IntCounter> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter(
            "aztna_client_posture_collect_failures_total",
            "Posture worker panics/orphans (stale snapshot served meanwhile)",
        )
    })
    .clone()
}

/// Staleness signal for the posture snapshot (AGENTS.md staleness category).
pub fn posture_last_collect_age() -> prometheus::IntGauge {
    static C: std::sync::OnceLock<prometheus::IntGauge> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_gauge(
            "aztna_client_posture_last_collect_age_seconds",
            "Age of the served posture snapshot (-1 = never collected)",
        )
    })
    .clone()
}

/// W14S2 fix step 1: WMI collect duration in the background worker —
/// separates idle (~7 s) from loaded (15 s+) WMI health at a glance. Buckets
/// straddle the regimes that matter: idle 6.5–9.2 s / orphan marker 15 s /
/// one-shot fresh-wait ceiling 20 s.
pub fn posture_collect_seconds() -> prometheus::Histogram {
    static C: std::sync::OnceLock<prometheus::Histogram> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::histogram(
            "aztna_client_posture_collect_seconds",
            "WMI posture collect duration in the background worker (idle ~7 s; >15 s = the W14S2 stall regime)",
            &[0.5, 1.0, 2.5, 5.0, 7.5, 10.0, 12.5, 15.0, 20.0, 30.0],
        )
    })
    .clone()
}

/// W14S2 fix step 1: per-phase UDP flow establishment latency — the
/// regression guard for the establishment-posture fix (phase=posture must
/// stay ≪1 s post-fix). Buckets deliberately top out at 10 s: pre-fix
/// 15–31 s observations land in +Inf; characterizing how far past 10 s a
/// regression falls is posture_collect_seconds' job, not this series'.
pub fn udp_establishment_seconds() -> prometheus::HistogramVec {
    static C: std::sync::OnceLock<prometheus::HistogramVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::histogram_vec(
            "aztna_client_udp_establishment_seconds",
            "UDP flow establishment by phase (posture|decision|dial|session); le=5 covers all post-fix posture observations",
            &["phase"],
            &[
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 7.5, 10.0,
            ],
        )
    })
    .clone()
}

/// W14S2 fix step 1 (review R3): every signed posture report classified by
/// the snapshot it was built from — fresh (inside the TTL), stale (older
/// than the 30 s TTL: collector/reporter stalled, the actionable case;
/// these reports serve last-good values SILENTLY otherwise), empty (never
/// collected this process; benign cold-start window). Counted at the
/// signed_posture_from choke point for every use (TCP, UDP, one-shot,
/// reporter pushes); the label set is the denominator + both failure modes.
pub fn posture_reports_total() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_posture_reports_total",
            "Signed posture reports by snapshot slot state: fresh|stale|empty",
            &["slot"],
        )
    })
    .clone()
}

/// W14S2 fix step 1: session-map sizes (leak visibility — sids/reasms are
/// pruned only by gateway tombstones today; watch for unbounded growth on
/// long-lived serves until step 3 adds client-side pruning).
pub fn udp_flows() -> prometheus::IntGaugeVec {
    static C: std::sync::OnceLock<prometheus::IntGaugeVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_gauge_vec(
            "aztna_client_udp_flows",
            "UDP forwarder session-map sizes by map: flows|sids|reasms",
            &["map"],
        )
    })
    .clone()
}

/// W5.1: local device-cert runway in days (-1 = no cert). Set at serve
/// start and after `glmcli renew`.
pub fn device_cert_days_remaining() -> prometheus::IntGauge {
    static C: std::sync::OnceLock<prometheus::IntGauge> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_gauge(
            "aztna_client_device_cert_days_remaining",
            "Days until the stored device cert expires (-1 = no cert) [W5.1]",
        )
    })
    .clone()
}

/// OBS.4 [NFR-OBS-004]: build identity + process series (registered at
/// serve start when metrics are enabled) + zero-init label combinations.
pub fn init() {
    let v = mm::int_gauge_vec("aztna_client_build_info", "Build metadata", &["version"]);
    v.with_label_values(&[env!("CARGO_PKG_VERSION")]).set(1);
    mm::init_process_metrics("client");
    // W40: mode x carrier children pre-created (never-hit = absent)
    let _ = carrier_selected_total();

    for r in ["allow", "deny", "fail_closed"] {
        intercepted_connections().with_label_values(&[r]).inc_by(0);
    }
    // W8.2: identity-failure counter pre-registered (never-hit = absent)
    mtls_identity_failures_total().inc_by(0);
    // W14: plaintext-carrier downgrades pre-registered on both paths —
    // the alertable "operating unencrypted" signal (tls_tcp_to_plain is
    // live in step 1; udp_quic_to_raw arrives with step 2).
    // W14S2 fix step 3: reason label added — every combo prezeroed so
    // the zero-value asserts stay deterministic.
    for (p, r) in [
        ("tls_tcp_to_plain", "legacy_flag"),
        ("tls_tcp_to_plain", "capability_absent"),
        ("tls_tcp_to_plain", "refused_legacy"),
        ("udp_quic_to_raw", "dial_failed"),
        ("udp_quic_to_raw", "no_datagram_support"),
        ("udp_quic_to_raw", "session_failed"),
    ] {
        carrier_downgrades_total()
            .with_label_values(&[p, r])
            .inc_by(0);
    }
    // W13 step 3: service-host series (pre-registered, never-hit = absent)
    service_starts_total().with_label_values(&["ok"]).inc_by(0);
    service_starts_total()
        .with_label_values(&["error"])
        .inc_by(0);
    controller_last_success_timestamp().set(0);
    for k in ["status", "connect", "disconnect", "login", "diagnostics"] {
        ipc_requests_total().with_label_values(&[k, "ok"]).inc_by(0);
        ipc_requests_total()
            .with_label_values(&[k, "error"])
            .inc_by(0);
    }
    // the isolation family gains the peer_denied value (W13 plan)
    intercepted_connections()
        .with_label_values(&["peer_denied"])
        .inc_by(0);
    for r in ["answered", "nxdomain", "empty"] {
        dns_queries_total().with_label_values(&[r]).inc_by(0);
    }
    dns_responder_errors()
        .with_label_values(&["conn_reset"])
        .inc_by(0);
    dns_responder_errors()
        .with_label_values(&["other"])
        .inc_by(0);
    for o in ["healthy", "unhealthy", "error", "skipped"] {
        posture_reports_sent().with_label_values(&[o]).inc_by(0);
    }
    for m in ["full", "marker"] {
        posture_push_mode().with_label_values(&[m]).inc_by(0);
    }
    posture_spec_version().set(0);
    for f in [
        "service_state",
        "process_running",
        "file_exists",
        "registry_value",
    ] {
        for r in ["match", "nomatch", "error", "unsupported"] {
            posture_probe_results().with_label_values(&[f, r]).inc_by(0);
        }
    }
    for p in ["decision", "dial", "ack"] {
        tunnel_setup_timeouts().with_label_values(&[p]).inc_by(0);
    }
    posture_collect_failures().inc_by(0);
    posture_last_collect_age().set(-1);
    device_cert_days_remaining().set(-1);
    // W14S2 fix step 1: pre-register the new families so presence asserts
    // are deterministic (OBS.4). Histogram children render zeroed once
    // created; the plain collect histogram registers zeroed on access.
    let _ = posture_collect_seconds();
    for ph in ["posture", "decision", "dial", "session"] {
        let _ = udp_establishment_seconds().with_label_values(&[ph]);
    }
    for s in ["fresh", "stale", "empty"] {
        posture_reports_total().with_label_values(&[s]).inc_by(0);
    }
    for m in ["flows", "sids", "reasms"] {
        udp_flows().with_label_values(&[m]).set(0);
    }
}

/// W8.1 [NFR §7.3]: UDP forwarder activity. direction = client|upstream
/// (forwarded datagrams) | deny (gateway-refused establishments and
/// mid-flow session ends — the hard re-establish signal).
pub fn udp_datagrams_total() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_udp_datagrams_total",
            "UDP forwarder datagrams by direction [W8.1]",
            &["direction"],
        )
    })
    .clone()
}

pub fn mtls_identity_failures_total() -> prometheus::IntCounter {
    static C: std::sync::OnceLock<prometheus::IntCounter> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter(
            "aztna_client_mtls_identity_failures_total",
            "QUIC dials that could not assemble the client identity (W8.2)",
        )
    })
    .clone()
}

/// W14 [w14-carrier-mtls]: plaintext-carrier fallbacks — the alertable
/// "operating unencrypted" signal, WITH the reason that produced them.
/// `tls_tcp_to_plain` reasons: legacy_flag (explicit --transport tcp) |
/// capability_absent | refused_legacy (transitional heuristic).
/// `udp_quic_to_raw` reasons (W14S2 fix step 3): dial_failed |
/// no_datagram_support (old gateway) | session_failed. A lost QUIC
/// connection does NOT downgrade — it re-dials (bug report H5c fix).
pub fn carrier_downgrades_total() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_carrier_downgrades_total",
            "Plaintext-carrier fallbacks by path and reason (W14; W14S2 fix: reason label)",
            &["path", "reason"],
        )
    })
    .clone()
}

/// W13 step 3: glmsvc start outcomes.
pub fn service_starts_total() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_service_starts_total",
            "Service-host start outcomes (W13)",
            &["result"],
        )
    })
    .clone()
}

/// W13 step 3: control-plane request outcomes by kind.
pub fn ipc_requests_total() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_ipc_requests_total",
            "Service IPC requests by kind and result (W13; loopback + peer-attributed)",
            &["kind", "result"],
        )
    })
    .clone()
}

/// W13 step 3: staleness — unix ts of the last successful controller-
/// plane call from the service host (0 = never).
pub fn controller_last_success_timestamp() -> prometheus::IntGauge {
    static C: std::sync::OnceLock<prometheus::IntGauge> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_gauge(
            "aztna_client_controller_last_success_timestamp",
            "Last successful controller-plane call from the service host (W13 staleness signal)",
        )
    })
    .clone()
}

/// W13 step 5: diagnostics bundle outcomes [DR-CLT-022].
pub fn diagnostics_bundles_total() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter_vec(
            "aztna_client_diagnostics_bundles_total",
            "Diagnostics bundle exports by result (W13)",
            &["result"],
        )
    })
    .clone()
}

/// W40 [tenant transport mode]: carrier selected per dial, labeled by the
/// mode ACTUALLY APPLIED (post-resolution, CLI override included) — the
/// useful "is the tenant mode steering dials" observable. The
/// `cli_legacy_tcp` label is the legacy `--transport tcp` escape hatch
/// (no tenant mode produces it).
pub fn carrier_selected_total() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        let v = mm::int_counter_vec(
            "aztna_client_carrier_selected_total",
            "Carrier selections by applied transport mode",
            &["mode", "carrier"],
        );
        for mode in [
            "auto",
            "tcp_first",
            "quic_only",
            "tcp_only",
            "cli_legacy_tcp",
        ] {
            for carrier in ["quic", "tls_tcp", "tcp"] {
                v.with_label_values(&[mode, carrier]).inc_by(0);
            }
        }
        v
    })
    .clone()
}

/// Tick the carrier-selected counter (labels are 'static by construction).
pub fn carrier_selected(mode: &'static str, carrier: &'static str) {
    carrier_selected_total()
        .with_label_values(&[mode, carrier])
        .inc();
}

// ---------- W43 S3: system-wide split-DNS (plan docs/w43-split-dns-plan.md §6) ----------

/// Reconciler + watchdog rule operations. op: install|remove|conflict|recover;
/// result: ok|conflict|invalid_suffix|no_watchdog|error.
pub fn splitdns_rule_ops() -> prometheus::IntCounterVec {
    static C: std::sync::OnceLock<prometheus::IntCounterVec> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        let v = mm::int_counter_vec(
            "aztna_client_splitdns_rule_ops_total",
            "split-DNS rule operations by the reconciler and watchdog",
            &["platform", "op", "result"],
        );
        for op in ["install", "remove", "conflict", "recover"] {
            for result in ["ok", "conflict", "invalid_suffix", "no_watchdog", "error"] {
                v.with_label_values(&["windows", op, result]).inc_by(0);
                // S5: the macOS channel rides the same series (the label
                // comes from the reconciler's platform_label())
                v.with_label_values(&["macos", op, result]).inc_by(0);
            }
        }
        v
    })
    .clone()
}

/// Installed owned-rule count (generation-current).
pub fn splitdns_rules_active() -> prometheus::IntGauge {
    static C: std::sync::OnceLock<prometheus::IntGauge> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_gauge(
            "aztna_client_splitdns_rules_active",
            "installed owned split-DNS resolver rules (should be 0 while disconnected)",
        )
    })
    .clone()
}

/// Crash-recovery events by the watchdog (should stay 0 in healthy fleets).
pub fn splitdns_watchdog_recoveries() -> prometheus::IntCounter {
    static C: std::sync::OnceLock<prometheus::IntCounter> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        mm::int_counter(
            "aztna_client_splitdns_watchdog_recoveries_total",
            "split-DNS watchdog crash-recovery events",
        )
    })
    .clone()
}
