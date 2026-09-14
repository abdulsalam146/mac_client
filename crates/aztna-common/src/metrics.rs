//! Shared Prometheus metrics plumbing [NFR-OBS §7].
//! One registry per process. Division of labor: we expose ONLY
//! counters/gauges/histograms with §7.1-compliant names/labels — percentiles,
//! rates, alerting, dashboards and storage are Prometheus built-ins and are
//! deliberately NOT re-implemented here.

use prometheus::{Encoder, Registry};

/// Process-global registry (each component binary has exactly one).
pub fn registry() -> &'static Registry {
    static REG: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();
    REG.get_or_init(Registry::new)
}

/// Register a metric, failing loudly on duplicate registration (a bug in
/// metric declaration, not a runtime condition).
pub fn register<T: prometheus::core::Collector + Clone + Send + Sync + 'static>(metric: T) -> T {
    registry()
        .register(Box::new(metric.clone()))
        .expect("duplicate metric registration");
    metric
}

pub fn int_counter(name: &str, help: &str) -> prometheus::IntCounter {
    register(
        prometheus::IntCounter::with_opts(prometheus::Opts::new(name, help))
            .expect("valid counter opts"),
    )
}

pub fn int_counter_vec(name: &str, help: &str, labels: &[&str]) -> prometheus::IntCounterVec {
    register(
        prometheus::IntCounterVec::new(prometheus::Opts::new(name, help), labels)
            .expect("valid counter vec opts"),
    )
}

pub fn int_gauge(name: &str, help: &str) -> prometheus::IntGauge {
    register(
        prometheus::IntGauge::with_opts(prometheus::Opts::new(name, help))
            .expect("valid gauge opts"),
    )
}

pub fn int_gauge_vec(name: &str, help: &str, labels: &[&str]) -> prometheus::IntGaugeVec {
    register(
        prometheus::IntGaugeVec::new(prometheus::Opts::new(name, help), labels)
            .expect("valid gauge vec opts"),
    )
}

pub fn histogram(name: &str, help: &str, buckets: &[f64]) -> prometheus::Histogram {
    register(
        prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::new(name, help).buckets(buckets.to_vec()),
        )
        .expect("valid histogram opts"),
    )
}

pub fn histogram_vec(
    name: &str,
    help: &str,
    labels: &[&str],
    buckets: &[f64],
) -> prometheus::HistogramVec {
    register(
        prometheus::HistogramVec::new(
            prometheus::HistogramOpts::new(name, help).buckets(buckets.to_vec()),
            labels,
        )
        .expect("valid histogram vec opts"),
    )
}

/// Render the registry in the Prometheus text exposition format
/// (content-type `text/plain; version=0.0.4`).
pub fn gather_text() -> String {
    let encoder = prometheus::TextEncoder::new();
    let mut buf = Vec::new();
    encoder
        .encode(&registry().gather(), &mut buf)
        .expect("text encoding cannot fail");
    String::from_utf8_lossy(&buf).into_owned()
}

pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Standard latency buckets for decision/API paths (p95 < 20 ms gate
/// [PERF-010] needs resolution around the target).
pub const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Tunnel setup buckets (E2E setup ≤ 2 s gate [PERF-004]); the 10 s bucket
/// attributes stall-class samples instead of dumping them into +Inf.
pub const SETUP_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0,
];

// ---------- process self-metrics [NFR §7.1 base series] ----------
// Process-scoped ONLY (this binary's own RSS/CPU/handles) — host CPU/RAM/
// disk/network belong to Prometheus Node Exporter per the observability plan
// §2b; never enumerate the host here.

/// Resident set size of THIS process, bytes.
#[cfg(windows)]
pub fn process_memory_bytes() -> u64 {
    use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Threading::GetCurrentProcess;
    let mut pmc = PROCESS_MEMORY_COUNTERS::default();
    pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) };
    if ok.is_ok() {
        pmc.WorkingSetSize as u64
    } else {
        0
    }
}

#[cfg(unix)]
pub fn process_memory_bytes() -> u64 {
    // /proc/self/statm field 2 = resident pages
    let s = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    s.split_whitespace()
        .nth(1)
        .and_then(|p| p.parse::<u64>().ok())
        .map(|pages| pages * 4096)
        .unwrap_or(0)
}

/// Cumulative CPU seconds (user+kernel) of THIS process.
#[cfg(windows)]
pub fn process_cpu_seconds_total() -> f64 {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    if !ok.is_ok() {
        return 0.0;
    }
    let to_secs = |t: FILETIME| {
        let v = ((t.dwHighDateTime as u64) << 32) | t.dwLowDateTime as u64;
        v as f64 / 10_000_000.0 // 100ns ticks
    };
    to_secs(kernel) + to_secs(user)
}

#[cfg(unix)]
pub fn process_cpu_seconds_total() -> f64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    // fields 14+15 (utime+stime) in clock ticks; after the comm field which
    // may contain spaces — split after the closing ')'
    let after_comm = s.split(')').next_back().unwrap_or("");
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let utime: f64 = fields.get(11).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let stime: f64 = fields.get(12).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    (utime + stime) / 100.0
}

/// Register the two §7.1 base process series against `component` and spawn a
/// 5 s sampler that keeps them current (they are gauges/counters of THIS
/// process; a ticker avoids scrape-time OS calls on the request path).
pub fn init_process_metrics(component: &'static str) {
    let mem = int_gauge(
        &format!("aztna_{component}_process_memory_bytes"),
        "Resident memory of this process (RSS) [RES/REL gates]",
    );
    let cpu = int_gauge(
        &format!("aztna_{component}_process_cpu_seconds_total"),
        "Cumulative CPU seconds of this process (gauge-exported counter value) [REL-001]",
    );
    let update = move || {
        mem.set(process_memory_bytes() as i64);
        cpu.set(process_cpu_seconds_total() as i64);
    };
    update();
    std::thread::Builder::new()
        .name(format!("metrics-sampler-{component}"))
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            update();
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OBS.1: helpers register into the process registry and the text
    /// exposition contains the series with labels and histogram buckets.
    #[test]
    fn register_and_expose() {
        let c = int_counter("aztna_test_things_total", "test counter");
        c.inc();
        let v = int_counter_vec("aztna_test_kinds_total", "test vec", &["kind"]);
        v.with_label_values(&["a"]).inc_by(3);
        let g = int_gauge("aztna_test_depth", "test gauge");
        g.set(7);
        let h = histogram("aztna_test_latency_seconds", "test hist", LATENCY_BUCKETS);
        h.observe(0.015);

        let text = gather_text();
        assert!(text.contains("aztna_test_things_total 1"), "{}", text);
        assert!(
            text.contains(r#"aztna_test_kinds_total{kind="a"} 3"#),
            "{}",
            text
        );
        assert!(text.contains("aztna_test_depth 7"), "{}", text);
        assert!(
            text.contains("aztna_test_latency_seconds_count 1") && text.contains(r#"le="0.02""#),
            "buckets must be exposed for PromQL histogram_quantile: {}",
            text
        );
        // re-registering the same name must fail loudly, not double-export
        let result = std::panic::catch_unwind(|| int_counter("aztna_test_things_total", "dup"));
        assert!(result.is_err(), "duplicate registration must panic");
    }
}
