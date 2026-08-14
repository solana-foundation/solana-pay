//! Bounded open-loop load generation for the measured voucher path.
//!
//! A small fixed worker set owns deterministic channel shards. Each source has
//! one request in flight, so session vouchers stay monotonic without spawning
//! a task or interval per user. Metrics are worker-local and merged after the
//! run; no completion takes a global histogram or status-map lock.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use hdrhistogram::Histogram;
use tokio::sync::Semaphore;

use crate::scheme::{RequestSource, build_request};

#[derive(Clone, Copy, Debug)]
pub struct DriverConfig {
    pub rps_per_user: f64,
    pub max_concurrency: usize,
    pub deadline: Duration,
    pub pool_per_host: usize,
    pub workers: usize,
}

#[derive(Debug, Clone)]
pub struct DriverReport {
    pub scheduled: u64,
    pub dispatched: u64,
    pub completed: u64,
    pub accepted: u64,
    pub ok: u64,
    pub fail: u64,
    pub dropped: u64,
    pub wall: Duration,
    pub rps_overall: f64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub p999_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
    pub schedule_delay_p99_ms: f64,
    pub end_to_end_p99_ms: f64,
    pub signing_rps: f64,
    pub status_counts: HashMap<u16, u64>,
    pub error_counts: HashMap<String, u64>,
    pub rps_series: Vec<u64>,
}

struct SourceState {
    source: Box<dyn RequestSource>,
    next_scheduled: Instant,
}

struct Completion {
    slot: usize,
    source: Box<dyn RequestSource>,
    scheduled: Instant,
    next_scheduled: Instant,
    dispatched: Option<Instant>,
    signing: Duration,
    logical_payment: bool,
    status: Option<u16>,
    error: Option<String>,
    completed_at: Instant,
}

type InFlight = BoxFuture<'static, Completion>;

struct LocalMetrics {
    service_us: Histogram<u64>,
    schedule_delay_us: Histogram<u64>,
    end_to_end_us: Histogram<u64>,
    scheduled: u64,
    dispatched: u64,
    completed: u64,
    accepted: u64,
    ok: u64,
    fail: u64,
    dropped: u64,
    signing: Duration,
    status: HashMap<u16, u64>,
    errors: HashMap<String, u64>,
    rps_series: Vec<u64>,
}

impl LocalMetrics {
    fn new() -> Self {
        Self {
            service_us: Histogram::new(3).expect("valid histogram"),
            schedule_delay_us: Histogram::new(3).expect("valid histogram"),
            end_to_end_us: Histogram::new(3).expect("valid histogram"),
            scheduled: 0,
            dispatched: 0,
            completed: 0,
            accepted: 0,
            ok: 0,
            fail: 0,
            dropped: 0,
            signing: Duration::ZERO,
            status: HashMap::new(),
            errors: HashMap::new(),
            rps_series: Vec::new(),
        }
    }

    fn record(&mut self, completion: &Completion, started: Instant) {
        self.signing += completion.signing;
        let schedule_delay = completion
            .dispatched
            .unwrap_or(completion.completed_at)
            .saturating_duration_since(completion.scheduled);
        self.schedule_delay_us
            .saturating_record(duration_us(schedule_delay));
        self.end_to_end_us.saturating_record(duration_us(
            completion
                .completed_at
                .saturating_duration_since(completion.scheduled),
        ));

        if let Some(dispatched) = completion.dispatched {
            self.dispatched += 1;
            self.service_us.saturating_record(duration_us(
                completion
                    .completed_at
                    .saturating_duration_since(dispatched),
            ));
        } else {
            self.dropped += 1;
        }

        if let Some(status) = completion.status {
            *self.status.entry(status).or_insert(0) += 1;
            if (200..300).contains(&status) {
                self.ok += 1;
                if completion.logical_payment {
                    self.accepted += 1;
                }
            } else {
                self.fail += 1;
            }
        } else {
            self.fail += 1;
        }
        if let Some(error) = &completion.error {
            *self.errors.entry(error.clone()).or_insert(0) += 1;
        }
        self.completed += 1;
        let second = completion
            .completed_at
            .saturating_duration_since(started)
            .as_secs() as usize;
        if self.rps_series.len() <= second {
            self.rps_series.resize(second + 1, 0);
        }
        self.rps_series[second] += 1;
    }

    fn merge(&mut self, other: Self) {
        let _ = self.service_us.add(&other.service_us);
        let _ = self.schedule_delay_us.add(&other.schedule_delay_us);
        let _ = self.end_to_end_us.add(&other.end_to_end_us);
        self.scheduled += other.scheduled;
        self.dispatched += other.dispatched;
        self.completed += other.completed;
        self.accepted += other.accepted;
        self.ok += other.ok;
        self.fail += other.fail;
        self.dropped += other.dropped;
        self.signing += other.signing;
        for (status, count) in other.status {
            *self.status.entry(status).or_insert(0) += count;
        }
        for (error, count) in other.errors {
            *self.errors.entry(error).or_insert(0) += count;
        }
        if self.rps_series.len() < other.rps_series.len() {
            self.rps_series.resize(other.rps_series.len(), 0);
        }
        for (second, count) in other.rps_series.into_iter().enumerate() {
            self.rps_series[second] += count;
        }
    }
}

/// Run indefinitely-producing sources for the measured window. Sources are
/// partitioned by `user_index % workers`, which is deterministic and keeps a
/// channel on exactly one worker and shard.
pub async fn run(
    sources: Vec<Box<dyn RequestSource>>,
    http: reqwest::Client,
    cfg: DriverConfig,
) -> DriverReport {
    let started = Instant::now();
    let deadline = started + cfg.deadline;
    let source_count = sources.len().max(1);
    let worker_count = cfg.workers.clamp(1, source_count);
    let mut partitions: Vec<Vec<Box<dyn RequestSource>>> =
        (0..worker_count).map(|_| Vec::new()).collect();
    for source in sources {
        let worker = source.user_index() as usize % worker_count;
        partitions[worker].push(source);
    }

    let permits = Arc::new(Semaphore::new(cfg.max_concurrency.max(1)));
    let mut workers = FuturesUnordered::new();
    for sources in partitions {
        if sources.is_empty() {
            continue;
        }
        workers.push(run_worker(
            sources,
            http.clone(),
            Arc::clone(&permits),
            cfg,
            started,
            deadline,
            source_count,
        ));
    }

    let mut totals = LocalMetrics::new();
    while let Some(metrics) = workers.next().await {
        totals.merge(metrics);
    }
    let wall = started.elapsed();
    let to_ms = |value: u64| value as f64 / 1000.0;
    DriverReport {
        scheduled: totals.scheduled,
        dispatched: totals.dispatched,
        completed: totals.completed,
        accepted: totals.accepted,
        ok: totals.ok,
        fail: totals.fail,
        dropped: totals.dropped,
        wall,
        rps_overall: totals.completed as f64 / wall.as_secs_f64().max(f64::MIN_POSITIVE),
        p50_ms: to_ms(totals.service_us.value_at_quantile(0.50)),
        p90_ms: to_ms(totals.service_us.value_at_quantile(0.90)),
        p99_ms: to_ms(totals.service_us.value_at_quantile(0.99)),
        p999_ms: to_ms(totals.service_us.value_at_quantile(0.999)),
        max_ms: to_ms(totals.service_us.max()),
        mean_ms: totals.service_us.mean() / 1000.0,
        schedule_delay_p99_ms: to_ms(totals.schedule_delay_us.value_at_quantile(0.99)),
        end_to_end_p99_ms: to_ms(totals.end_to_end_us.value_at_quantile(0.99)),
        signing_rps: totals.dispatched as f64 / totals.signing.as_secs_f64().max(f64::MIN_POSITIVE),
        status_counts: totals.status,
        error_counts: totals.errors,
        rps_series: totals.rps_series,
    }
}

async fn run_worker(
    sources: Vec<Box<dyn RequestSource>>,
    http: reqwest::Client,
    permits: Arc<Semaphore>,
    cfg: DriverConfig,
    started: Instant,
    deadline: Instant,
    source_count: usize,
) -> LocalMetrics {
    let period = Duration::from_secs_f64(1.0 / cfg.rps_per_user.max(0.001));
    let mut slots: Vec<Option<SourceState>> = sources
        .into_iter()
        .map(|source| {
            let phase = period.mul_f64(source.user_index() as f64 / source_count as f64);
            Some(SourceState {
                source,
                next_scheduled: started + phase,
            })
        })
        .collect();
    let mut in_flight: FuturesUnordered<InFlight> = FuturesUnordered::new();
    let mut metrics = LocalMetrics::new();

    while Instant::now() < deadline {
        while Instant::now() < deadline && in_flight.len() < cfg.max_concurrency.max(1) {
            let now = Instant::now();
            let Some(slot) = slots.iter().position(|state| {
                state
                    .as_ref()
                    .is_some_and(|state| state.next_scheduled <= now)
            }) else {
                break;
            };
            let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                break;
            };
            let mut state = slots[slot].take().expect("ready source slot");
            let scheduled = state.next_scheduled;
            state.next_scheduled += period;
            let next_scheduled = state.next_scheduled;
            metrics.scheduled += 1;
            let client = http.clone();
            in_flight.push(
                async move {
                    let signing_started = Instant::now();
                    let request = state.source.next_request().await;
                    let signing = signing_started.elapsed();
                    let completion = match request {
                        Ok(request) => {
                            let dispatched = Instant::now();
                            let result = build_request(
                                &client,
                                &request.method,
                                &request.url,
                                &request.body,
                                None,
                                &request.headers,
                            )
                            .send()
                            .await;
                            let completed_at = Instant::now();
                            match result {
                                Ok(response) => Completion {
                                    slot,
                                    source: state.source,
                                    scheduled,
                                    next_scheduled,
                                    dispatched: Some(dispatched),
                                    signing,
                                    logical_payment: request.logical_payment,
                                    status: Some(response.status().as_u16()),
                                    error: None,
                                    completed_at,
                                },
                                Err(error) => Completion {
                                    slot,
                                    source: state.source,
                                    scheduled,
                                    next_scheduled,
                                    dispatched: Some(dispatched),
                                    signing,
                                    logical_payment: request.logical_payment,
                                    status: None,
                                    error: Some(classify_error(&error)),
                                    completed_at,
                                },
                            }
                        }
                        Err(_) => Completion {
                            slot,
                            source: state.source,
                            scheduled,
                            next_scheduled,
                            dispatched: None,
                            signing,
                            logical_payment: false,
                            status: None,
                            error: Some("signing".to_string()),
                            completed_at: Instant::now(),
                        },
                    };
                    drop(permit);
                    completion
                }
                .boxed(),
            );
        }

        let next = slots
            .iter()
            .filter_map(|state| state.as_ref().map(|state| state.next_scheduled))
            .min()
            .unwrap_or(deadline);
        if in_flight.is_empty() {
            tokio::time::sleep_until(tokio::time::Instant::from_std(next.min(deadline))).await;
        } else {
            tokio::select! {
                Some(completion) = in_flight.next() => {
                    let slot = completion.slot;
                    metrics.record(&completion, started);
                    slots[slot] = Some(SourceState {
                        source: completion.source,
                        next_scheduled: completion.next_scheduled,
                    });
                }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(next.min(deadline))) => {}
            }
        }
    }

    while let Some(completion) = in_flight.next().await {
        let slot = completion.slot;
        metrics.record(&completion, started);
        slots[slot] = Some(SourceState {
            source: completion.source,
            next_scheduled: completion.next_scheduled,
        });
    }
    metrics
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

fn duration_us(duration: Duration) -> u64 {
    duration.as_micros().min(u64::MAX as u128) as u64
}

fn classify_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "timeout".into()
    } else if error.is_connect() {
        "connect".into()
    } else if error.is_request() {
        "request".into()
    } else {
        "other".into()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use axum::{Router, http::StatusCode, routing::get};

    use super::*;

    struct TestSource {
        index: u32,
        url: String,
        logical_payment: bool,
        issued: Arc<AtomicU64>,
    }

    #[async_trait::async_trait]
    impl RequestSource for TestSource {
        fn user_index(&self) -> u32 {
            self.index
        }

        async fn next_request(&mut self) -> anyhow::Result<crate::scheme::PreparedRequest> {
            self.issued.fetch_add(1, Ordering::Relaxed);
            Ok(crate::scheme::PreparedRequest {
                method: "GET".to_string(),
                url: self.url.clone(),
                headers: Vec::new(),
                body: String::new(),
                logical_payment: self.logical_payment,
            })
        }
    }

    #[tokio::test]
    async fn counts_only_successful_logical_payments_as_accepted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/", get(|| async { StatusCode::OK })),
            )
            .await
            .unwrap();
        });
        let issued = Arc::new(AtomicU64::new(0));
        let source = TestSource {
            index: 7,
            url: format!("http://{address}/"),
            logical_payment: true,
            issued: Arc::clone(&issued),
        };
        let report = run(
            vec![Box::new(source)],
            reqwest::Client::new(),
            DriverConfig {
                rps_per_user: 200.0,
                max_concurrency: 1,
                deadline: Duration::from_millis(60),
                pool_per_host: 1,
                workers: 1,
            },
        )
        .await;
        server.abort();

        assert!(issued.load(Ordering::Relaxed) > 0);
        assert!(report.completed > 0);
        assert_eq!(report.accepted, report.ok);
        assert_eq!(report.fail, 0);
    }

    #[tokio::test]
    async fn free_generator_requests_never_count_as_accepted_payments() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/", get(|| async { StatusCode::OK })),
            )
            .await
            .unwrap();
        });
        let source = TestSource {
            index: 1,
            url: format!("http://{address}/"),
            logical_payment: false,
            issued: Arc::new(AtomicU64::new(0)),
        };
        let report = run(
            vec![Box::new(source)],
            reqwest::Client::new(),
            DriverConfig {
                rps_per_user: 200.0,
                max_concurrency: 1,
                deadline: Duration::from_millis(60),
                pool_per_host: 1,
                workers: 1,
            },
        )
        .await;
        server.abort();

        assert!(report.ok > 0);
        assert_eq!(report.accepted, 0);
    }
}
