//! The load driver — the measured hot path.
//!
//! One tokio task per user paces its pre-built request buffer at
//! `rps_per_user` (token-bucket). Each request is fired as a bounded-concurrency
//! task against a shared, tuned HTTP pool; every outcome lands in an
//! hdrhistogram + atomic counters, with a 1-second RPS sampler running
//! alongside. The driver is scheme-agnostic: it just fires [`PreparedRequest`]s.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use std::sync::Mutex;
use tokio::sync::Semaphore;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::scheme::{PreparedRequest, build_request};

/// Adapts the prepared-request header vec to the OpenTelemetry injector.
struct HeaderInjector<'a>(&'a mut Vec<(String, String)>);
impl opentelemetry::propagation::Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        self.0.push((key.to_string(), value));
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DriverConfig {
    pub rps_per_user: f64,
    pub max_concurrency: usize,
    /// Stop dispatching after this long (the measured window).
    pub deadline: Duration,
    /// Tuned connections kept alive per host.
    pub pool_per_host: usize,
}

/// Shared, lock-light metrics sink.
struct Metrics {
    hist_us: Mutex<Histogram<u64>>,
    dispatched: AtomicU64,
    completed: AtomicU64,
    ok: AtomicU64,
    fail: AtomicU64,
    status: Mutex<HashMap<u16, u64>>,
    errors: Mutex<HashMap<String, u64>>,
}

impl Metrics {
    fn new() -> Self {
        Metrics {
            // Auto-resizing histogram, 3 significant figures, values in µs.
            hist_us: Mutex::new(Histogram::<u64>::new(3).expect("valid histogram")),
            dispatched: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            ok: AtomicU64::new(0),
            fail: AtomicU64::new(0),
            status: Mutex::new(HashMap::new()),
            errors: Mutex::new(HashMap::new()),
        }
    }

    fn record(&self, latency: Duration, status: Option<u16>, error: Option<String>) {
        let us = latency.as_micros().min(u64::MAX as u128) as u64;
        self.hist_us.lock().unwrap().saturating_record(us);
        if let Some(s) = status {
            *self.status.lock().unwrap().entry(s).or_insert(0) += 1;
            if (200..300).contains(&s) {
                self.ok.fetch_add(1, Ordering::Relaxed);
            } else {
                self.fail.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.fail.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(e) = error {
            *self.errors.lock().unwrap().entry(e).or_insert(0) += 1;
        }
        self.completed.fetch_add(1, Ordering::Relaxed);
    }
}

/// Final, serializable-friendly numbers from a run.
#[derive(Debug, Clone)]
pub struct DriverReport {
    pub dispatched: u64,
    pub completed: u64,
    pub ok: u64,
    pub fail: u64,
    pub wall: Duration,
    pub rps_overall: f64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub p999_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
    pub status_counts: HashMap<u16, u64>,
    pub error_counts: HashMap<String, u64>,
    /// Completed-requests-per-second, sampled once per second.
    pub rps_series: Vec<u64>,
}

/// Fire every prepared request (one task per user, paced + bounded), measuring
/// each. `reqs_per_user[i]` is user `i`'s ordered buffer.
pub async fn run(
    reqs_per_user: Vec<Vec<PreparedRequest>>,
    http: reqwest::Client,
    cfg: DriverConfig,
) -> DriverReport {
    let metrics = Arc::new(Metrics::new());
    let sem = Arc::new(Semaphore::new(cfg.max_concurrency.max(1)));
    let stop_sampler = Arc::new(AtomicBool::new(false));

    // 1s RPS sampler.
    let sampler = {
        let metrics = Arc::clone(&metrics);
        let stop = Arc::clone(&stop_sampler);
        tokio::spawn(async move {
            let mut series = Vec::new();
            let mut last = 0u64;
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.tick().await; // immediate first tick
            loop {
                tick.tick().await;
                let now = metrics.completed.load(Ordering::Relaxed);
                series.push(now.saturating_sub(last));
                last = now;
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }
            series
        })
    };

    let started = Instant::now();
    let dispatch_deadline = started + cfg.deadline;
    let mut pacers = Vec::with_capacity(reqs_per_user.len());
    for (idx, reqs) in reqs_per_user.into_iter().enumerate() {
        if reqs.is_empty() {
            continue;
        }
        let http = http.clone();
        let metrics = Arc::clone(&metrics);
        let sem = Arc::clone(&sem);
        let period = Duration::from_secs_f64(1.0 / cfg.rps_per_user.max(0.001));
        // One span per user (child of the surrounding `unleash` span). The
        // pacer runs inside it, so each fired request's trace context is what we
        // inject into the request headers — the proxy then parents its spans here.
        //
        // Requests for a given user fire **in order** (awaited inline): sessions
        // need monotonic voucher watermarks, and the per-user rate is the limiter
        // anyway, so this doesn't cost throughput for the unordered schemes. The
        // global semaphore still bounds total in-flight across all users.
        let user_span = tracing::info_span!("user_load", index = idx as u64);
        let pacer = async move {
            let mut tick = tokio::time::interval(period);
            for req in reqs {
                if Instant::now() >= dispatch_deadline {
                    break;
                }
                tick.tick().await;
                let permit = match Arc::clone(&sem).acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                metrics.dispatched.fetch_add(1, Ordering::Relaxed);
                fire(&http, &req, &metrics).await;
                drop(permit);
            }
        };
        pacers.push(tokio::spawn(pacer.instrument(user_span)));
    }

    // We can't see `started` inside the spawned closure cheaply; instead bound
    // the whole dispatch loop by a wall-clock deadline via a select below.
    let _ = tokio::time::timeout(cfg.deadline + Duration::from_millis(50), async {
        for p in pacers {
            let _ = p.await;
        }
    })
    .await;

    // Drain in-flight requests (bounded grace period).
    let drain_deadline = Instant::now() + Duration::from_secs(30);
    while metrics.completed.load(Ordering::Relaxed) < metrics.dispatched.load(Ordering::Relaxed)
        && Instant::now() < drain_deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let wall = started.elapsed();

    stop_sampler.store(true, Ordering::Relaxed);
    let rps_series = sampler.await.unwrap_or_default();

    let hist = metrics.hist_us.lock().unwrap();
    let to_ms = |us: u64| us as f64 / 1000.0;
    let completed = metrics.completed.load(Ordering::Relaxed);
    DriverReport {
        dispatched: metrics.dispatched.load(Ordering::Relaxed),
        completed,
        ok: metrics.ok.load(Ordering::Relaxed),
        fail: metrics.fail.load(Ordering::Relaxed),
        wall,
        rps_overall: if wall.as_secs_f64() > 0.0 {
            completed as f64 / wall.as_secs_f64()
        } else {
            0.0
        },
        p50_ms: to_ms(hist.value_at_quantile(0.50)),
        p90_ms: to_ms(hist.value_at_quantile(0.90)),
        p99_ms: to_ms(hist.value_at_quantile(0.99)),
        p999_ms: to_ms(hist.value_at_quantile(0.999)),
        max_ms: to_ms(hist.max()),
        mean_ms: hist.mean() / 1000.0,
        status_counts: metrics.status.lock().unwrap().clone(),
        error_counts: metrics.errors.lock().unwrap().clone(),
        rps_series,
    }
}

/// Build a tuned HTTP client for the load phase (keepalive pool, HTTP/2 where
/// the server negotiates it).
pub fn build_http(cfg: &DriverConfig) -> reqwest::Client {
    reqwest::Client::builder()
        .pool_max_idle_per_host(cfg.pool_per_host)
        .pool_idle_timeout(Duration::from_secs(90))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("build http client")
}

async fn fire(http: &reqwest::Client, req: &PreparedRequest, metrics: &Metrics) {
    let start = Instant::now();
    // Inject the current span's W3C trace context (traceparent) so the proxy
    // stitches its spans onto this trace.
    let mut headers = req.headers.clone();
    let cx = tracing::Span::current().context();
    opentelemetry::global::get_text_map_propagator(|prop| {
        prop.inject_context(&cx, &mut HeaderInjector(&mut headers));
    });
    let res = build_request(http, &req.method, &req.url, &req.body, None, &headers)
        .send()
        .await;
    let latency = start.elapsed();
    match res {
        Ok(r) => metrics.record(latency, Some(r.status().as_u16()), None),
        Err(e) => metrics.record(latency, None, Some(classify_error(&e))),
    }
}

/// Collapse reqwest errors into a few stable buckets for the error table.
fn classify_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timeout".into()
    } else if e.is_connect() {
        "connect".into()
    } else if e.is_request() {
        "request".into()
    } else {
        "other".into()
    }
}
