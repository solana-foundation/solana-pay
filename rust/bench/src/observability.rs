//! Telemetry for the bench: delegates to the shared `solana_pay_core::otel`
//! init (re-exported as `pay_kit::mpp::otel`) so the bench, the proxy, and the
//! settlement worker all land in one collector under one trace view. The only
//! bench-local piece is [`named_runtime`], which names tokio worker threads
//! `bench-worker-N` so "what each thread is doing" stays legible.

use std::sync::atomic::{AtomicUsize, Ordering};

/// OTLP provider guard — hold for the process lifetime so batches flush on exit.
pub use pay_kit::mpp::otel::Guard;

/// Console filter — quiet: bench INFO + real failures, but the in-process
/// proxy's chatty per-request logs are suppressed. `RUST_LOG` overrides.
fn console_filter() -> String {
    std::env::var("RUST_LOG").unwrap_or_else(|_| {
        "info,pay_core=error,pay_kit::mpp=warn,hyper=warn,reqwest=warn,tower=warn".to_string()
    })
}

/// Trace-export filter — permissive: captures the server + settlement runloop
/// spans so they show up in the trace view. `BENCH_TRACE_FILTER` overrides; for
/// high-volume (30k) runs, dial `pay_core`/`pay_kit::mpp` back to keep span
/// volume sane.
fn trace_filter() -> String {
    std::env::var("BENCH_TRACE_FILTER").unwrap_or_else(|_| {
        "info,hyper=warn,reqwest=warn,tower=warn,h2=warn,opentelemetry=warn".to_string()
    })
}

/// Initialize telemetry. With `otlp` set (a `host:port` or URL), spans + metrics
/// export to that OTLP collector in addition to the console; otherwise only the
/// console layer is installed.
pub fn init(service_name: &str, otlp: Option<&str>) -> Guard {
    pay_kit::mpp::otel::init(pay_kit::mpp::otel::OtelOptions {
        service_name,
        service_version: env!("CARGO_PKG_VERSION"),
        otlp_endpoint: otlp,
        console_filter: &console_filter(),
        trace_filter: &trace_filter(),
    })
}

/// A multi-thread tokio runtime whose worker threads are named `<prefix>-worker-N`.
pub fn named_runtime(prefix: &'static str) -> std::io::Result<tokio::runtime::Runtime> {
    let counter = AtomicUsize::new(0);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name_fn(move || {
            let n = counter.fetch_add(1, Ordering::Relaxed);
            format!("{prefix}-worker-{n}")
        })
        .build()
}
