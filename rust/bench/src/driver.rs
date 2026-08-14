//! Bounded open-loop load generation for the measured voucher path.
//!
//! A small fixed worker set owns deterministic channel shards. Each source has
//! one request in flight, so session vouchers stay monotonic without spawning
//! a task or interval per user. Metrics are worker-local and merged after the
//! run; no completion takes a global histogram or status-map lock.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use futures::{FutureExt, StreamExt, stream::FuturesUnordered};
use hdrhistogram::Histogram;

use crate::scheme::{RequestSource, build_request};

#[derive(Clone, Copy, Debug)]
pub struct DriverConfig {
    pub rps_per_user: f64,
    pub max_concurrency: usize,
    pub deadline: Duration,
    pub pool_per_host: usize,
    pub workers: usize,
    pub http2_prior_knowledge: bool,
}

#[derive(Debug, Clone)]
pub struct DriverReport {
    pub target_rps: f64,
    pub scheduled: u64,
    pub dispatched: u64,
    pub completed: u64,
    pub accepted: u64,
    pub ok: u64,
    pub fail: u64,
    pub dropped: u64,
    pub wall: Duration,
    pub drain: Duration,
    pub completed_rps: f64,
    pub accepted_rps: f64,
    pub signing_rps: f64,
    pub service_latency_ms: LatencySummary,
    pub signing_latency_ms: LatencySummary,
    pub schedule_delay_ms: LatencySummary,
    pub end_to_end_latency_ms: LatencySummary,
    pub max_in_flight: usize,
    pub status_counts: HashMap<u16, u64>,
    pub error_counts: HashMap<String, u64>,
    pub rps_series: Vec<u64>,
    pub accepted_rps_series: Vec<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct LatencySummary {
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub p999: f64,
    pub max: f64,
    pub mean: f64,
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

#[derive(Clone)]
struct WorkerContext {
    http: reqwest::Client,
    worker_max_in_flight: usize,
    cfg: DriverConfig,
    started: Instant,
    deadline: Instant,
    phase_denominator: u64,
}

struct LocalMetrics {
    service_us: Histogram<u64>,
    signing_us: Histogram<u64>,
    schedule_delay_us: Histogram<u64>,
    end_to_end_us: Histogram<u64>,
    scheduled: u64,
    dispatched: u64,
    completed: u64,
    accepted: u64,
    ok: u64,
    fail: u64,
    dropped: u64,
    max_in_flight: usize,
    status: HashMap<u16, u64>,
    errors: HashMap<String, u64>,
    rps_series: Vec<u64>,
    accepted_rps_series: Vec<u64>,
}

impl LocalMetrics {
    fn new() -> Self {
        Self {
            service_us: latency_histogram(),
            signing_us: latency_histogram(),
            schedule_delay_us: latency_histogram(),
            end_to_end_us: latency_histogram(),
            scheduled: 0,
            dispatched: 0,
            completed: 0,
            accepted: 0,
            ok: 0,
            fail: 0,
            dropped: 0,
            max_in_flight: 0,
            status: HashMap::new(),
            errors: HashMap::new(),
            rps_series: Vec::new(),
            accepted_rps_series: Vec::new(),
        }
    }

    fn record(&mut self, completion: &Completion, started: Instant) {
        self.signing_us
            .saturating_record(duration_us(completion.signing));
        let schedule_delay = completion
            .dispatched
            .unwrap_or(completion.completed_at)
            .saturating_duration_since(completion.scheduled);
        self.schedule_delay_us
            .saturating_record(duration_us(schedule_delay));
        let end_to_end = completion
            .completed_at
            .saturating_duration_since(completion.scheduled);
        self.end_to_end_us
            .saturating_record(duration_us(end_to_end));

        if let Some(dispatched) = completion.dispatched {
            self.dispatched += 1;
            let service = completion
                .completed_at
                .saturating_duration_since(dispatched);
            debug_assert!(end_to_end >= service);
            self.service_us.saturating_record(duration_us(service));
        } else {
            self.dropped += 1;
        }

        if let Some(status) = completion.status {
            *self.status.entry(status).or_insert(0) += 1;
            if (200..300).contains(&status) {
                self.ok += 1;
                if completion.logical_payment {
                    self.accepted += 1;
                    record_series(
                        &mut self.accepted_rps_series,
                        completion.completed_at,
                        started,
                    );
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
        record_series(&mut self.rps_series, completion.completed_at, started);
    }

    fn merge(&mut self, other: Self) {
        self.service_us
            .add(&other.service_us)
            .expect("compatible service latency histograms");
        self.signing_us
            .add(&other.signing_us)
            .expect("compatible signing latency histograms");
        self.schedule_delay_us
            .add(&other.schedule_delay_us)
            .expect("compatible schedule latency histograms");
        self.end_to_end_us
            .add(&other.end_to_end_us)
            .expect("compatible end-to-end latency histograms");
        self.scheduled += other.scheduled;
        self.dispatched += other.dispatched;
        self.completed += other.completed;
        self.accepted += other.accepted;
        self.ok += other.ok;
        self.fail += other.fail;
        self.dropped += other.dropped;
        self.max_in_flight += other.max_in_flight;
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
        merge_series(&mut self.accepted_rps_series, other.accepted_rps_series);
    }
}

fn latency_histogram() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 60_000_000, 3).expect("valid latency histogram")
}

fn latency_summary(histogram: &Histogram<u64>) -> LatencySummary {
    let to_ms = |value: u64| value as f64 / 1_000.0;
    LatencySummary {
        p50: to_ms(histogram.value_at_quantile(0.50)),
        p90: to_ms(histogram.value_at_quantile(0.90)),
        p99: to_ms(histogram.value_at_quantile(0.99)),
        p999: to_ms(histogram.value_at_quantile(0.999)),
        max: to_ms(histogram.max()),
        mean: histogram.mean() / 1_000.0,
    }
}

fn record_series(series: &mut Vec<u64>, completed_at: Instant, started: Instant) {
    let second = completed_at.saturating_duration_since(started).as_secs() as usize;
    if series.len() <= second {
        series.resize(second + 1, 0);
    }
    series[second] += 1;
}

fn merge_series(into: &mut Vec<u64>, other: Vec<u64>) {
    if into.len() < other.len() {
        into.resize(other.len(), 0);
    }
    for (second, count) in other.into_iter().enumerate() {
        into[second] += count;
    }
}

/// Run indefinitely-producing sources for the measured window. Sources are
/// partitioned by `user_index % workers`, which is deterministic and keeps a
/// channel on exactly one worker and shard.
pub async fn run(sources: Vec<Box<dyn RequestSource>>, cfg: DriverConfig) -> DriverReport {
    let source_count = sources.len().max(1);
    let phase_denominator = sources
        .iter()
        .map(|source| u64::from(source.user_index()) + 1)
        .max()
        .unwrap_or(1);
    let worker_count = cfg.workers.clamp(1, source_count);
    let mut partitions: Vec<Vec<Box<dyn RequestSource>>> =
        (0..worker_count).map(|_| Vec::new()).collect();
    for source in sources {
        let worker = source.user_index() as usize % worker_count;
        partitions[worker].push(source);
    }

    // reqwest clones share one connection pool. At high rates that turns the
    // pool into a cross-runtime-thread synchronization point and left a 128
    // thread Sunburst run using roughly eleven cores. Give each deterministic
    // worker its own bounded pool instead. The aggregate idle-connection cap
    // remains `pool_per_host`, so sharding the pool does not increase socket
    // pressure.
    let worker_pool_per_host = cfg.pool_per_host.div_ceil(worker_count).max(1);
    let worker_max_in_flight = cfg.max_concurrency.div_ceil(worker_count).max(1);
    let worker_clients: Vec<_> = (0..worker_count)
        .map(|_| {
            build_http(&DriverConfig {
                pool_per_host: worker_pool_per_host,
                ..cfg
            })
        })
        .collect();
    // Client/pool construction is setup, not part of the measured window.
    let started = Instant::now();
    let deadline = started + cfg.deadline;
    let worker_context = WorkerContext {
        // Replaced by each worker's independently-owned client below.
        http: worker_clients[0].clone(),
        worker_max_in_flight,
        cfg,
        started,
        deadline,
        phase_denominator,
    };
    let mut workers = tokio::task::JoinSet::new();
    for (sources, http) in partitions.into_iter().zip(worker_clients) {
        if sources.is_empty() {
            continue;
        }
        let mut context = worker_context.clone();
        context.http = http;
        workers.spawn(run_worker(sources, context));
    }

    let mut totals = LocalMetrics::new();
    while let Some(metrics) = workers.join_next().await {
        totals.merge(metrics.expect("load worker panicked"));
    }
    let elapsed = started.elapsed();
    let wall_secs = cfg.deadline.as_secs_f64().max(f64::MIN_POSITIVE);
    DriverReport {
        target_rps: cfg.rps_per_user * source_count as f64,
        scheduled: totals.scheduled,
        dispatched: totals.dispatched,
        completed: totals.completed,
        accepted: totals.accepted,
        ok: totals.ok,
        fail: totals.fail,
        dropped: totals.dropped,
        wall: cfg.deadline,
        drain: elapsed.saturating_sub(cfg.deadline),
        completed_rps: totals.completed as f64 / wall_secs,
        accepted_rps: totals.accepted as f64 / wall_secs,
        signing_rps: totals.dispatched as f64 / wall_secs,
        service_latency_ms: latency_summary(&totals.service_us),
        signing_latency_ms: latency_summary(&totals.signing_us),
        schedule_delay_ms: latency_summary(&totals.schedule_delay_us),
        end_to_end_latency_ms: latency_summary(&totals.end_to_end_us),
        // Workers have disjoint fixed caps. Summing their observed peaks is a
        // conservative aggregate peak without a contended global counter in
        // the measured path.
        max_in_flight: totals.max_in_flight,
        status_counts: totals.status,
        error_counts: totals.errors,
        rps_series: totals.rps_series,
        accepted_rps_series: totals.accepted_rps_series,
    }
}

async fn run_worker(sources: Vec<Box<dyn RequestSource>>, context: WorkerContext) -> LocalMetrics {
    let WorkerContext {
        http,
        worker_max_in_flight,
        cfg,
        started,
        deadline,
        phase_denominator,
    } = context;
    let period = Duration::from_secs_f64(1.0 / cfg.rps_per_user.max(0.001));
    let mut slots: Vec<Option<SourceState>> = sources
        .into_iter()
        .map(|source| {
            let phase = period.mul_f64(f64::from(source.user_index()) / phase_denominator as f64);
            Some(SourceState {
                source,
                next_scheduled: started + phase,
            })
        })
        .collect();
    let mut schedule: BinaryHeap<Reverse<(Instant, usize)>> = slots
        .iter()
        .enumerate()
        .filter_map(|(slot, state)| {
            state
                .as_ref()
                .map(|state| Reverse((state.next_scheduled, slot)))
        })
        .collect();
    let mut in_flight: FuturesUnordered<InFlight> = FuturesUnordered::new();
    let mut metrics = LocalMetrics::new();

    while Instant::now() < deadline {
        while Instant::now() < deadline && in_flight.len() < worker_max_in_flight {
            let Some(Reverse((scheduled, slot))) = schedule.peek().copied() else {
                break;
            };
            if scheduled > Instant::now() {
                break;
            }
            schedule.pop();
            let mut state = slots[slot].take().expect("ready source slot");
            debug_assert_eq!(scheduled, state.next_scheduled);
            state.next_scheduled += period;
            let next_scheduled = state.next_scheduled;
            metrics.scheduled += 1;
            let client = http.clone();
            in_flight.push(
                async move {
                    let signing_started = Instant::now();
                    let request = state.source.next_request().await;
                    let signing = signing_started.elapsed();
                    match request {
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
                    }
                }
                .boxed(),
            );
            metrics.max_in_flight = metrics.max_in_flight.max(in_flight.len());
        }

        let next = if in_flight.len() >= worker_max_in_flight {
            deadline
        } else {
            schedule
                .peek()
                .map(|Reverse((scheduled, _))| *scheduled)
                .unwrap_or(deadline)
        };
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
                    schedule.push(Reverse((completion.next_scheduled, slot)));
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
        schedule.push(Reverse((completion.next_scheduled, slot)));
    }
    for state in slots.into_iter().flatten() {
        let deficit = due_before(state.next_scheduled, deadline, period);
        metrics.scheduled = metrics.scheduled.saturating_add(deficit);
        metrics.dropped = metrics.dropped.saturating_add(deficit);
    }
    metrics
}

fn due_before(next: Instant, deadline: Instant, period: Duration) -> u64 {
    if next >= deadline {
        return 0;
    }
    let remaining_nanos = deadline.duration_since(next).as_nanos();
    let period_nanos = period.as_nanos().max(1);
    let due = 1 + remaining_nanos.saturating_sub(1) / period_nanos;
    due.min(u64::MAX as u128) as u64
}

/// Build a tuned HTTP client for the load phase (keepalive pool, HTTP/2 where
/// the server negotiates it).
pub fn build_http(cfg: &DriverConfig) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .pool_max_idle_per_host(cfg.pool_per_host)
        .pool_idle_timeout(Duration::from_secs(90))
        .timeout(Duration::from_secs(30));
    if cfg.http2_prior_knowledge {
        builder = builder.http2_prior_knowledge().http2_adaptive_window(true);
    }
    builder.build().expect("build http client")
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use axum::{Router, http::StatusCode, routing::get};

    use super::*;

    struct TestSource {
        index: u32,
        url: String,
        logical_payment: bool,
        issued: Arc<AtomicU64>,
        signing_delay: Duration,
        signing_barrier: Option<Arc<std::sync::Barrier>>,
    }

    #[async_trait::async_trait]
    impl RequestSource for TestSource {
        fn user_index(&self) -> u32 {
            self.index
        }

        async fn next_request(&mut self) -> anyhow::Result<crate::scheme::PreparedRequest> {
            self.issued.fetch_add(1, Ordering::Relaxed);
            if let Some(barrier) = self.signing_barrier.take() {
                barrier.wait();
            }
            tokio::time::sleep(self.signing_delay).await;
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
            signing_delay: Duration::ZERO,
            signing_barrier: None,
        };
        let report = run(
            vec![Box::new(source)],
            DriverConfig {
                rps_per_user: 200.0,
                max_concurrency: 1,
                deadline: Duration::from_millis(60),
                pool_per_host: 1,
                workers: 1,
                http2_prior_knowledge: false,
            },
        )
        .await;
        server.abort();

        assert!(issued.load(Ordering::Relaxed) > 0);
        assert!(report.completed > 0);
        assert_eq!(report.accepted, report.ok);
        assert_eq!(report.fail, 0);
        assert!(report.end_to_end_latency_ms.p99 >= report.service_latency_ms.p99);
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
            signing_delay: Duration::ZERO,
            signing_barrier: None,
        };
        let report = run(
            vec![Box::new(source)],
            DriverConfig {
                rps_per_user: 200.0,
                max_concurrency: 1,
                deadline: Duration::from_millis(60),
                pool_per_host: 1,
                workers: 1,
                http2_prior_knowledge: false,
            },
        )
        .await;
        server.abort();

        assert!(report.ok > 0);
        assert_eq!(report.accepted, 0);
    }

    #[tokio::test]
    async fn records_unsent_open_loop_schedule_as_dropped() {
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
            index: 0,
            url: format!("http://{address}/"),
            logical_payment: true,
            issued: Arc::new(AtomicU64::new(0)),
            signing_delay: Duration::from_millis(10),
            signing_barrier: None,
        };
        let report = run(
            vec![Box::new(source)],
            DriverConfig {
                rps_per_user: 1_000.0,
                max_concurrency: 1,
                deadline: Duration::from_millis(50),
                pool_per_host: 1,
                workers: 1,
                http2_prior_knowledge: false,
            },
        )
        .await;
        server.abort();

        assert_eq!(report.scheduled, 50);
        assert_eq!(report.dropped, report.scheduled - report.dispatched);
        assert!(report.schedule_delay_ms.p99 >= 1.0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn worker_partitions_execute_on_separate_runtime_tasks() {
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
        let barrier = Arc::new(std::sync::Barrier::new(4));
        let sources: Vec<Box<dyn RequestSource>> = (0..4)
            .map(|index| {
                Box::new(TestSource {
                    index,
                    url: format!("http://{address}/"),
                    logical_payment: false,
                    issued: Arc::new(AtomicU64::new(0)),
                    signing_delay: Duration::ZERO,
                    signing_barrier: Some(Arc::clone(&barrier)),
                }) as Box<dyn RequestSource>
            })
            .collect();
        let report = tokio::time::timeout(
            Duration::from_secs(1),
            run(
                sources,
                DriverConfig {
                    rps_per_user: 1_000.0,
                    max_concurrency: 4,
                    deadline: Duration::from_millis(20),
                    pool_per_host: 4,
                    workers: 4,
                    http2_prior_knowledge: false,
                },
            ),
        )
        .await
        .expect("worker tasks did not run concurrently");
        server.abort();

        assert!(report.completed >= 4);
    }

    #[test]
    fn due_count_excludes_the_deadline_boundary() {
        let started = Instant::now();
        assert_eq!(
            due_before(
                started,
                started + Duration::from_millis(10),
                Duration::from_millis(1),
            ),
            10
        );
        assert_eq!(
            due_before(
                started + Duration::from_millis(10),
                started + Duration::from_millis(10),
                Duration::from_millis(1),
            ),
            0
        );
    }
}
