//! Reconcile durable MPP sessions with on-chain payment channels.
//!
//! Proxies persist each accepted cumulative voucher and a minute-bucketed idle
//! deadline in Redis. This worker continuously pushes newer watermarks and
//! closes every still-due channel through pay-kit's byte-bounded batching
//! worker.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::routing::get;
use pay_api_core::rpc::RpcClient;
use pay_kit::core::payment_channels;
use pay_kit::core::settlement::worker::{RpcBroadcaster, SettlementConfig, spawn};
use pay_kit::core::store::{
    ChannelState, ChannelStore, DEFAULT_FINALIZED_CHANNEL_RETENTION, RedisChannelStore, StoreError,
};
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_worker::channel::{self, STATUS_CLOSING, STATUS_DISTRIBUTED, STATUS_OPEN, STATUS_SEALED};
use pay_worker::config::Config;
use pay_worker::error::JobError;
use pay_worker::signer::build_fee_payer_signer;
use pay_worker::telemetry::{self, SettleSessionsMetrics};
use solana_pubkey::Pubkey;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

const DEFAULT_REDIS_PREFIX: &str = "pay:session:v1:";
const SETTLEMENT_LOCK_KEY: &str = "pay:jobs:settle-sessions:lock";
const DEFAULT_RECONCILIATION_INTERVAL_SECONDS: u64 = 10;
const DEFAULT_PORT: u64 = 8080;

struct LeaseHeartbeat {
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl LeaseHeartbeat {
    fn start(
        mut connection: redis::aio::ConnectionManager,
        owner: String,
        ttl_seconds: u64,
    ) -> Self {
        const RENEW: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 0
"#;
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let renewal_interval = Duration::from_secs((ttl_seconds / 3).max(1));
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(renewal_interval);
            loop {
                tokio::select! {
                    () = task_cancel.cancelled() => return,
                    _ = interval.tick() => {
                        match redis::Script::new(RENEW)
                            .key(SETTLEMENT_LOCK_KEY)
                            .arg(&owner)
                            .arg(ttl_seconds)
                            .invoke_async::<i32>(&mut connection)
                            .await
                        {
                            Ok(1) => {}
                            Ok(_) => {
                                warn!("settlement lease ownership was lost; stopping renewal");
                                return;
                            }
                            Err(error) => {
                                warn!(%error, "failed to renew settlement lease");
                            }
                        }
                    }
                }
            }
        });
        Self { cancel, handle }
    }

    async fn shutdown(self) {
        self.cancel.cancel();
        if let Err(error) = self.handle.await {
            warn!(%error, "settlement lease heartbeat task failed");
        }
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let _telemetry = telemetry::init("pay-jobs-settle-sessions");
    let run_once = match parse_bool_env("RUN_ONCE", true) {
        Ok(run_once) => run_once,
        Err(error) => return record_startup_failure(error),
    };
    let runtime = match SettlementRuntime::load().await {
        Ok(runtime) => runtime,
        Err(error) => return record_startup_failure(error),
    };
    if run_once {
        return record_iteration(run(&runtime).await, true);
    }

    let interval_seconds = match parse_u64_env(
        "SETTLEMENT_INTERVAL_SECONDS",
        DEFAULT_RECONCILIATION_INTERVAL_SECONDS,
    ) {
        Ok(0) => {
            return record_startup_failure(JobError::Config(
                "SETTLEMENT_INTERVAL_SECONDS must be greater than zero".into(),
            ));
        }
        Ok(interval_seconds) => interval_seconds,
        Err(error) => return record_startup_failure(error),
    };
    let port = match parse_u64_env("PORT", DEFAULT_PORT) {
        Ok(port) if u16::try_from(port).is_ok() => port as u16,
        Ok(_) => {
            return record_startup_failure(JobError::Config(
                "PORT must be between 0 and 65535".into(),
            ));
        }
        Err(error) => return record_startup_failure(error),
    };

    let address = format!("0.0.0.0:{port}");
    let listener = match tokio::net::TcpListener::bind(&address).await {
        Ok(listener) => listener,
        Err(error) => {
            return record_startup_failure(JobError::Config(format!(
                "failed to bind worker health endpoint on {address}: {error}"
            )));
        }
    };
    let app = Router::new().route("/health", get(|| async { "ok" }));
    info!(
        %address,
        interval_seconds,
        "continuous settle-sessions worker starting"
    );

    let cancel = CancellationToken::new();
    let server_shutdown = cancel.clone();
    let cancel_on_server_exit = cancel.clone();
    let server = tokio::spawn(async move {
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(server_shutdown.cancelled_owned())
            .await;
        cancel_on_server_exit.cancel();
        result
    });
    let cancel_on_signal = cancel.clone();
    let signal = tokio::spawn(async move {
        shutdown_signal().await;
        info!("settle-sessions shutdown signal received");
        cancel_on_signal.cancel();
    });

    run_continuously(
        &runtime,
        Duration::from_secs(interval_seconds),
        cancel.clone(),
    )
    .await;
    cancel.cancel();

    let server_result = server.await;
    if !signal.is_finished() {
        signal.abort();
    }
    let _ = signal.await;

    match server_result {
        Ok(Ok(())) => std::process::ExitCode::SUCCESS,
        Ok(Err(error)) => {
            error!(%error, "settle-sessions health server failed");
            std::process::ExitCode::FAILURE
        }
        Err(error) => {
            error!(%error, "settle-sessions health server task failed");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run_continuously(
    runtime: &SettlementRuntime,
    interval: Duration,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = ticker.tick() => {}
        }
        let _ = record_iteration(run(runtime).await, false);
        if cancel.is_cancelled() {
            break;
        }
    }
}

fn record_iteration(
    result: Result<SettleSessionsMetrics, JobError>,
    terminal: bool,
) -> std::process::ExitCode {
    match result {
        Ok(metrics) => {
            log_summary(&metrics);
            telemetry::record_settle_sessions(&metrics);
            if metrics.failures == 0 {
                info!(
                    event = if terminal {
                        "settle_sessions_exit"
                    } else {
                        "settle_sessions_iteration"
                    },
                    outcome = metrics.outcome,
                    "settle-sessions reconciliation finished"
                );
                std::process::ExitCode::SUCCESS
            } else {
                error!(
                    event = if terminal {
                        "settle_sessions_exit"
                    } else {
                        "settle_sessions_iteration"
                    },
                    outcome = metrics.outcome,
                    failures = metrics.failures,
                    "settle-sessions reconciliation finished with failures"
                );
                std::process::ExitCode::FAILURE
            }
        }
        Err(error) => {
            let metrics = SettleSessionsMetrics {
                outcome: "aborted",
                failures: 1,
                ..SettleSessionsMetrics::default()
            };
            telemetry::record_settle_sessions(&metrics);
            error!(
                event = if terminal {
                    "settle_sessions_exit"
                } else {
                    "settle_sessions_iteration"
                },
                outcome = "aborted",
                %error,
                "settle-sessions reconciliation aborted; will retry"
            );
            std::process::ExitCode::FAILURE
        }
    }
}

fn record_startup_failure(error: JobError) -> std::process::ExitCode {
    let metrics = SettleSessionsMetrics {
        outcome: "aborted",
        failures: 1,
        ..SettleSessionsMetrics::default()
    };
    telemetry::record_settle_sessions(&metrics);
    error!(
        event = "settle_sessions_exit",
        outcome = "aborted",
        %error,
        "settle-sessions startup failed"
    );
    std::process::ExitCode::FAILURE
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

struct SettlementRuntime {
    redis_url: String,
    dry_run: bool,
    lock_ttl: u64,
    network: String,
    rpc_url: String,
    treasury_owner: Pubkey,
    rpc: RpcClient,
    store: RedisChannelStore,
    signer: Arc<dyn SolanaSigner>,
    operator: Pubkey,
    confirm_timeout: Duration,
}

impl SettlementRuntime {
    async fn load() -> Result<Self, JobError> {
        let redis_url = required_env("PAY_SESSION_REDIS_URL")?;
        let redis_prefix = std::env::var("PAY_SESSION_REDIS_PREFIX")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_REDIS_PREFIX.to_string());
        let finalized_retention = Duration::from_secs(parse_u64_env(
            "PAY_SESSION_FINALIZED_RETENTION_SECONDS",
            DEFAULT_FINALIZED_CHANNEL_RETENTION.as_secs(),
        )?);
        let dry_run = parse_bool_env("DRY_RUN", true)?;
        let lock_ttl = parse_u64_env("SETTLEMENT_LOCK_TTL_SECONDS", 300)?;
        let network = std::env::var("NETWORK")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "mainnet".to_string());
        let config = Config::load(&network)?;
        let rpc_url = config.rpc_url_for(&network)?.to_string();
        let treasury_owner = Pubkey::from_str(config.treasury_owner.trim()).map_err(|_| {
            JobError::Config(format!("invalid treasury_owner: {}", config.treasury_owner))
        })?;
        let rpc = RpcClient::new(Duration::from_millis(config.rpc_timeout_ms))?;
        let store = RedisChannelStore::connect_with_finalized_retention(
            &redis_url,
            redis_prefix,
            finalized_retention,
        )
        .await
        .map_err(|error| JobError::Config(format!("session Redis: {error}")))?;
        let signer = build_fee_payer_signer(&config.send.fee_payer).await?;
        let operator = signer.pubkey();
        let confirm_timeout = Duration::from_secs(config.confirm_timeout_seconds);

        Ok(Self {
            redis_url,
            dry_run,
            lock_ttl,
            network,
            rpc_url,
            treasury_owner,
            rpc,
            store,
            signer,
            operator,
            confirm_timeout,
        })
    }
}

async fn run(runtime: &SettlementRuntime) -> Result<SettleSessionsMetrics, JobError> {
    let started_at = Instant::now();
    let Some(lock) = SettlementLock::acquire(&runtime.redis_url, runtime.lock_ttl).await? else {
        info!(
            event = "settle_sessions_lease_contended",
            "another settle-sessions execution owns the Redis lease; skipping"
        );
        return Ok(SettleSessionsMetrics {
            outcome: "lease_contended",
            lease_contended: 1,
            duration_seconds: started_at.elapsed().as_secs_f64(),
            ..SettleSessionsMetrics::default()
        });
    };
    let channels = runtime
        .store
        .list_channels()
        .await
        .map_err(|error| JobError::Config(format!("list session channels: {error}")))?;

    info!(
        dry_run = runtime.dry_run,
        network = runtime.network,
        channels = channels.len(),
        operator = %runtime.operator,
        "settle-sessions reconciliation starting"
    );

    let now = unix_now();
    let now_ms = unix_now_millis();
    let channels_scanned = channels.len();
    let mut candidates = Vec::new();
    let mut skipped = 0_usize;
    let mut failures = 0_usize;
    let mut finalized = 0_usize;
    let mut inventory = LifecycleInventory::default();
    for scanned_state in channels {
        let state = if !runtime.dry_run && channel_close_due(&scanned_state, now_ms) {
            match claim_due_close(
                &runtime.store,
                &scanned_state.channel_id,
                now_ms,
                now as u64,
            )
            .await
            {
                Ok(state) => state,
                Err(error) => {
                    failures += 1;
                    skipped += 1;
                    warn!(
                        channel_id = %scanned_state.channel_id,
                        %error,
                        "failed to claim due session close"
                    );
                    continue;
                }
            }
        } else {
            scanned_state
        };

        match reconcile_channel(
            &runtime.rpc,
            &runtime.rpc_url,
            state,
            now,
            now_ms,
            &runtime.operator,
            &runtime.treasury_owner,
        )
        .await
        {
            Ok(result) => {
                if let Some(settled_base_units) = result.stablecoin_settled_base_units {
                    telemetry::record_settle_sessions_channel_settled(
                        &result.channel_id,
                        settled_base_units,
                    );
                }
                if let Some(distributed_base_units) = result.stablecoin_distributed_base_units {
                    telemetry::record_settle_sessions_channel_distributed(
                        &result.channel_id,
                        distributed_base_units,
                    );
                }
                if let Some(escrow_active) = result.escrow_active {
                    telemetry::record_settle_sessions_channel_escrow_active(
                        &result.channel_id,
                        escrow_active,
                    );
                }
                inventory.record(result.snapshot);
                match result.store_disposition {
                    StoreDisposition::Keep => {}
                    StoreDisposition::Expire { newly_finalized } => {
                        finalized += usize::from(newly_finalized);
                        if !runtime.dry_run
                            && let Err(error) =
                                runtime.store.mark_finalized(&result.channel_id).await
                        {
                            failures += 1;
                            warn!(
                                channel_id = %result.channel_id,
                                %error,
                                "failed to mark finalized session channel in Redis"
                            );
                        }
                    }
                    StoreDisposition::Delete => {
                        finalized += 1;
                        if runtime.dry_run {
                            info!(
                                channel_id = %result.channel_id,
                                "would delete Redis session for absent on-chain channel"
                            );
                        } else {
                            match runtime.store.delete_channel(&result.channel_id).await {
                                Ok(()) => info!(
                                    channel_id = %result.channel_id,
                                    "deleted Redis session for absent on-chain channel"
                                ),
                                Err(error) => {
                                    failures += 1;
                                    warn!(
                                        channel_id = %result.channel_id,
                                        %error,
                                        "failed to delete Redis session for absent on-chain channel"
                                    );
                                }
                            }
                        }
                    }
                }
                match result.candidate {
                    Some(candidate) => candidates.push(candidate),
                    None => skipped += 1,
                }
            }
            Err(error) => {
                failures += 1;
                skipped += 1;
                warn!(%error, "session channel reconciliation failed; skipping");
            }
        }
    }

    if runtime.dry_run {
        let planned = candidates.len();
        let idle_close_planned = candidates
            .iter()
            .filter(|candidate| candidate.kind == CandidateKind::IdleClose)
            .count();
        let watermark_planned = planned.saturating_sub(idle_close_planned);
        let metrics = SettleSessionsMetrics {
            outcome: "dry_run",
            channels_scanned,
            watermark_planned,
            idle_close_planned,
            idle_closed: 0,
            finalized,
            transactions: 0,
            skipped,
            failures,
            opened_zero_settlements: inventory.opened_zero_settlements,
            unsealed: inventory.unsealed,
            rent_unclaimed: inventory.rent_unclaimed,
            stablecoin_settled_base_units: inventory.stablecoin_settled_base_units,
            stablecoin_undistributed_base_units: inventory.stablecoin_undistributed_base_units,
            stablecoin_distributed_base_units: inventory.stablecoin_distributed_base_units,
            stablecoin_unsettled_base_units: inventory.stablecoin_unsettled_base_units,
            redis_chain_mismatches: inventory.redis_chain_mismatches,
            lease_contended: 0,
            duration_seconds: started_at.elapsed().as_secs_f64(),
        };
        lock.release().await;
        return Ok(metrics);
    }

    let planned = candidates.len();
    let idle_close_planned = candidates
        .iter()
        .filter(|candidate| candidate.kind == CandidateKind::IdleClose)
        .count();
    let watermark_planned = planned.saturating_sub(idle_close_planned);
    let handle = spawn(
        SettlementConfig::new(runtime.operator, Arc::clone(&runtime.signer)),
        Arc::new(RpcBroadcaster::new(runtime.rpc_url.clone())),
    );
    let mut submissions = JoinSet::new();
    for candidate in candidates {
        let handle = handle.clone();
        submissions.spawn(async move {
            let SettlementCandidate {
                channel_id,
                instructions,
                kind,
                before,
                after,
            } = candidate;
            let result = handle.settle(channel_id.clone(), instructions).await;
            (channel_id, kind, before, after, result)
        });
    }
    drop(handle);

    let mut submissions_by_signature: HashMap<
        String,
        Vec<(
            String,
            CandidateKind,
            ChannelInventorySnapshot,
            ChannelInventorySnapshot,
        )>,
    > = HashMap::new();
    while let Some(joined) = submissions.join_next().await {
        match joined {
            Ok((channel_id, kind, before, after, Ok(signature))) => {
                info!(%channel_id, ?kind, %signature, "session lifecycle transaction broadcast");
                submissions_by_signature
                    .entry(signature)
                    .or_default()
                    .push((channel_id, kind, before, after));
            }
            Ok((channel_id, kind, _, _, Err(error))) => {
                failures += 1;
                error!(%channel_id, ?kind, %error, "session lifecycle broadcast failed");
            }
            Err(error) => {
                failures += 1;
                error!(%error, "session settlement task failed");
            }
        }
    }

    let mut idle_closed = 0_usize;
    let mut transactions = 0_usize;
    for (signature, submitted) in &submissions_by_signature {
        if let Err(error) = runtime
            .rpc
            .confirm_signature(&runtime.rpc_url, signature, runtime.confirm_timeout)
            .await
        {
            failures += 1;
            error!(%signature, %error, "session settlement confirmation failed");
            continue;
        }
        transactions += 1;

        for (channel_id, kind, before, after) in submitted {
            inventory.replace(*before, *after);
            telemetry::record_settle_sessions_channel_settled(
                channel_id,
                after.stablecoin_settled_base_units,
            );
            telemetry::record_settle_sessions_channel_distributed(
                channel_id,
                after.stablecoin_distributed_base_units,
            );
            telemetry::record_settle_sessions_channel_escrow_active(
                channel_id,
                !after.rent_unclaimed,
            );
            if *kind != CandidateKind::IdleClose {
                continue;
            }
            match runtime.store.mark_finalized(channel_id).await {
                Ok(()) => idle_closed += 1,
                Err(error) => {
                    failures += 1;
                    error!(
                        %channel_id,
                        %error,
                        "closed session channel but failed to mark it sealed in Redis"
                    );
                }
            }
        }
    }

    let metrics = SettleSessionsMetrics {
        outcome: if failures == 0 { "succeeded" } else { "failed" },
        channels_scanned,
        watermark_planned,
        idle_close_planned,
        idle_closed,
        finalized,
        transactions,
        skipped,
        failures,
        opened_zero_settlements: inventory.opened_zero_settlements,
        unsealed: inventory.unsealed,
        rent_unclaimed: inventory.rent_unclaimed,
        stablecoin_settled_base_units: inventory.stablecoin_settled_base_units,
        stablecoin_undistributed_base_units: inventory.stablecoin_undistributed_base_units,
        stablecoin_distributed_base_units: inventory.stablecoin_distributed_base_units,
        stablecoin_unsettled_base_units: inventory.stablecoin_unsettled_base_units,
        redis_chain_mismatches: inventory.redis_chain_mismatches,
        lease_contended: 0,
        duration_seconds: started_at.elapsed().as_secs_f64(),
    };
    lock.release().await;
    Ok(metrics)
}

fn log_summary(metrics: &SettleSessionsMetrics) {
    info!(
        event = "settle_sessions_summary",
        outcome = metrics.outcome,
        channels_scanned = metrics.channels_scanned,
        planned = metrics
            .watermark_planned
            .saturating_add(metrics.idle_close_planned),
        watermark_planned = metrics.watermark_planned,
        idle_close_planned = metrics.idle_close_planned,
        idle_closed = metrics.idle_closed,
        finalized = metrics.finalized,
        transactions = metrics.transactions,
        skipped = metrics.skipped,
        failures = metrics.failures,
        opened_zero_settlements = metrics.opened_zero_settlements,
        unsealed = metrics.unsealed,
        rent_unclaimed = metrics.rent_unclaimed,
        stablecoin_settled_base_units = metrics.stablecoin_settled_base_units,
        stablecoin_undistributed_base_units = metrics.stablecoin_undistributed_base_units,
        stablecoin_distributed_base_units = metrics.stablecoin_distributed_base_units,
        stablecoin_unsettled_base_units = metrics.stablecoin_unsettled_base_units,
        redis_chain_mismatches = metrics.redis_chain_mismatches,
        lease_contended = metrics.lease_contended,
        duration_ms = (metrics.duration_seconds * 1_000.0) as u64,
        "settle-sessions summary"
    );
}

#[derive(Default)]
struct LifecycleInventory {
    opened_zero_settlements: usize,
    unsealed: usize,
    rent_unclaimed: usize,
    stablecoin_settled_base_units: u64,
    stablecoin_undistributed_base_units: u64,
    stablecoin_distributed_base_units: u64,
    stablecoin_unsettled_base_units: u64,
    redis_chain_mismatches: usize,
}

impl LifecycleInventory {
    fn record(&mut self, snapshot: ChannelInventorySnapshot) {
        self.opened_zero_settlements += usize::from(snapshot.opened_zero_settlements);
        self.unsealed += usize::from(snapshot.unsealed);
        self.rent_unclaimed += usize::from(snapshot.rent_unclaimed);
        self.stablecoin_settled_base_units = self
            .stablecoin_settled_base_units
            .saturating_add(snapshot.stablecoin_settled_base_units);
        self.stablecoin_undistributed_base_units = self
            .stablecoin_undistributed_base_units
            .saturating_add(snapshot.stablecoin_undistributed_base_units);
        self.stablecoin_distributed_base_units = self
            .stablecoin_distributed_base_units
            .saturating_add(snapshot.stablecoin_distributed_base_units);
        self.stablecoin_unsettled_base_units = self
            .stablecoin_unsettled_base_units
            .saturating_add(snapshot.stablecoin_unsettled_base_units);
        self.redis_chain_mismatches += usize::from(snapshot.redis_chain_mismatch);
    }

    fn replace(&mut self, before: ChannelInventorySnapshot, after: ChannelInventorySnapshot) {
        self.opened_zero_settlements = self
            .opened_zero_settlements
            .saturating_sub(usize::from(before.opened_zero_settlements));
        self.unsealed = self.unsealed.saturating_sub(usize::from(before.unsealed));
        self.rent_unclaimed = self
            .rent_unclaimed
            .saturating_sub(usize::from(before.rent_unclaimed));
        self.stablecoin_settled_base_units = self
            .stablecoin_settled_base_units
            .saturating_sub(before.stablecoin_settled_base_units);
        self.stablecoin_undistributed_base_units = self
            .stablecoin_undistributed_base_units
            .saturating_sub(before.stablecoin_undistributed_base_units);
        self.stablecoin_distributed_base_units = self
            .stablecoin_distributed_base_units
            .saturating_sub(before.stablecoin_distributed_base_units);
        self.stablecoin_unsettled_base_units = self
            .stablecoin_unsettled_base_units
            .saturating_sub(before.stablecoin_unsettled_base_units);
        self.redis_chain_mismatches = self
            .redis_chain_mismatches
            .saturating_sub(usize::from(before.redis_chain_mismatch));
        self.record(after);
    }
}

#[derive(Clone, Copy, Default)]
struct ChannelInventorySnapshot {
    opened_zero_settlements: bool,
    unsealed: bool,
    rent_unclaimed: bool,
    stablecoin_settled_base_units: u64,
    stablecoin_undistributed_base_units: u64,
    stablecoin_distributed_base_units: u64,
    stablecoin_unsettled_base_units: u64,
    redis_chain_mismatch: bool,
}

struct ReconcileResult {
    channel_id: String,
    candidate: Option<SettlementCandidate>,
    store_disposition: StoreDisposition,
    snapshot: ChannelInventorySnapshot,
    stablecoin_settled_base_units: Option<u64>,
    stablecoin_distributed_base_units: Option<u64>,
    escrow_active: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreDisposition {
    Keep,
    Expire { newly_finalized: bool },
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateKind {
    Watermark,
    IdleClose,
}

struct SettlementCandidate {
    channel_id: String,
    instructions: Vec<solana_instruction::Instruction>,
    kind: CandidateKind,
    before: ChannelInventorySnapshot,
    after: ChannelInventorySnapshot,
}

fn inventory_snapshot(
    redis_sealed: bool,
    onchain_status: u8,
    onchain_settled: u64,
    onchain_payout_watermark: u64,
    redis_cumulative: u64,
    mint: &Pubkey,
) -> ChannelInventorySnapshot {
    let unsealed = matches!(onchain_status, STATUS_OPEN | STATUS_CLOSING);
    let onchain_distributed =
        effective_distributed_amount(onchain_status, onchain_settled, onchain_payout_watermark);
    ChannelInventorySnapshot {
        opened_zero_settlements: onchain_status == STATUS_OPEN && onchain_settled == 0,
        unsealed,
        rent_unclaimed: onchain_status == STATUS_DISTRIBUTED,
        stablecoin_settled_base_units: settled_stablecoin_base_units(mint, onchain_settled),
        stablecoin_undistributed_base_units: stablecoin_base_units(
            mint,
            onchain_settled.saturating_sub(onchain_distributed),
        ),
        stablecoin_distributed_base_units: stablecoin_base_units(mint, onchain_distributed),
        stablecoin_unsettled_base_units: unsettled_stablecoin_base_units(
            mint,
            redis_cumulative,
            onchain_settled,
        ),
        redis_chain_mismatch: redis_sealed && unsealed,
    }
}

/// Resolve the amount known to have left escrow.
///
/// A final sealed `distribute` drains and closes the escrow account before
/// marking the channel `Distributed`, but does not persist the payout
/// watermark. The terminal status therefore supersedes that stale watermark.
fn effective_distributed_amount(status: u8, settled: u64, payout_watermark: u64) -> u64 {
    if status == STATUS_DISTRIBUTED {
        settled
    } else {
        payout_watermark
    }
}

const MAINNET_STABLECOIN_MINT: Pubkey =
    solana_pubkey::pubkey!("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v");
const DEVNET_STABLECOIN_MINT: Pubkey =
    solana_pubkey::pubkey!("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");

fn unsettled_stablecoin_base_units(mint: &Pubkey, cumulative: u64, settled: u64) -> u64 {
    stablecoin_base_units(mint, cumulative.saturating_sub(settled))
}

fn settled_stablecoin_base_units(mint: &Pubkey, settled: u64) -> u64 {
    stablecoin_base_units(mint, settled)
}

fn stablecoin_base_units(mint: &Pubkey, amount: u64) -> u64 {
    stablecoin_base_units_option(mint, amount).unwrap_or_default()
}

fn stablecoin_base_units_option(mint: &Pubkey, amount: u64) -> Option<u64> {
    (*mint == MAINNET_STABLECOIN_MINT || *mint == DEVNET_STABLECOIN_MINT).then_some(amount)
}

fn absent_onchain_store_disposition(state: &ChannelState) -> StoreDisposition {
    if state.open_slot.is_some() {
        StoreDisposition::Delete
    } else {
        StoreDisposition::Keep
    }
}

async fn reconcile_channel(
    rpc: &RpcClient,
    rpc_url: &str,
    state: ChannelState,
    now: i64,
    now_ms: u64,
    operator: &Pubkey,
    treasury_owner: &Pubkey,
) -> Result<ReconcileResult, JobError> {
    let state_channel_id = state.channel_id.clone();
    let absent_disposition = absent_onchain_store_disposition(&state);
    if absent_disposition == StoreDisposition::Keep {
        return Ok(ReconcileResult {
            channel_id: state_channel_id,
            candidate: None,
            store_disposition: StoreDisposition::Keep,
            snapshot: ChannelInventorySnapshot::default(),
            stablecoin_settled_base_units: None,
            stablecoin_distributed_base_units: None,
            escrow_active: None,
        });
    }

    let channel_id = Pubkey::from_str(&state.channel_id)
        .map_err(|_| JobError::InvalidAddress(state.channel_id.clone()))?;
    let onchain = match channel::fetch_channel(rpc, rpc_url, &channel_id).await {
        Ok(Some(onchain)) => onchain,
        Ok(None) => {
            return Ok(ReconcileResult {
                channel_id: state_channel_id,
                candidate: None,
                store_disposition: absent_disposition,
                snapshot: ChannelInventorySnapshot::default(),
                stablecoin_settled_base_units: None,
                stablecoin_distributed_base_units: None,
                escrow_active: Some(false),
            });
        }
        Err(error) => return Err(error),
    };

    let snapshot = inventory_snapshot(
        state.sealed,
        onchain.channel.status,
        onchain.channel.settlement.settled,
        onchain.channel.settlement.payout_watermark,
        state.cumulative,
        &onchain.mint(),
    );
    let stablecoin_settled_base_units =
        stablecoin_base_units_option(&onchain.mint(), onchain.channel.settlement.settled);
    let distributed_amount = effective_distributed_amount(
        onchain.channel.status,
        onchain.channel.settlement.settled,
        onchain.channel.settlement.payout_watermark,
    );
    let stablecoin_distributed_base_units =
        stablecoin_base_units_option(&onchain.mint(), distributed_amount);
    let escrow_active = Some(onchain.channel.status != STATUS_DISTRIBUTED);

    if onchain.channel.status == STATUS_DISTRIBUTED {
        return Ok(ReconcileResult {
            channel_id: state_channel_id,
            candidate: None,
            store_disposition: StoreDisposition::Expire {
                newly_finalized: !state.sealed,
            },
            snapshot,
            stablecoin_settled_base_units,
            stablecoin_distributed_base_units,
            escrow_active,
        });
    }

    if state.sealed {
        return Ok(ReconcileResult {
            channel_id: state_channel_id,
            candidate: None,
            store_disposition: StoreDisposition::Keep,
            snapshot,
            stablecoin_settled_base_units,
            stablecoin_distributed_base_units,
            escrow_active,
        });
    }

    if channel_close_due(&state, now_ms) {
        let candidate = build_idle_close_candidate(
            rpc,
            rpc_url,
            &state,
            &onchain,
            now,
            operator,
            treasury_owner,
        )
        .await?;
        return Ok(ReconcileResult {
            channel_id: state_channel_id,
            candidate,
            store_disposition: StoreDisposition::Keep,
            snapshot,
            stablecoin_settled_base_units,
            stablecoin_distributed_base_units,
            escrow_active,
        });
    }

    if state.cumulative == 0 {
        return Ok(ReconcileResult {
            channel_id: state_channel_id,
            candidate: None,
            store_disposition: StoreDisposition::Keep,
            snapshot,
            stablecoin_settled_base_units,
            stablecoin_distributed_base_units,
            escrow_active,
        });
    }
    let (Some(signature), Some(expires_at)) = (
        state.highest_voucher_signature.as_deref(),
        state.highest_voucher_expires_at,
    ) else {
        return Ok(ReconcileResult {
            channel_id: state_channel_id,
            candidate: None,
            store_disposition: StoreDisposition::Keep,
            snapshot,
            stablecoin_settled_base_units,
            stablecoin_distributed_base_units,
            escrow_active,
        });
    };
    if expires_at != 0 && expires_at <= now {
        warn!(
            channel_id = %state.channel_id,
            expires_at,
            "latest unsettled voucher expired"
        );
        return Ok(ReconcileResult {
            channel_id: state_channel_id,
            candidate: None,
            store_disposition: StoreDisposition::Keep,
            snapshot,
            stablecoin_settled_base_units,
            stablecoin_distributed_base_units,
            escrow_active,
        });
    }

    if onchain.channel.status != STATUS_OPEN
        || onchain.channel.settlement.settled >= state.cumulative
    {
        return Ok(ReconcileResult {
            channel_id: state_channel_id,
            candidate: None,
            store_disposition: StoreDisposition::Keep,
            snapshot,
            stablecoin_settled_base_units,
            stablecoin_distributed_base_units,
            escrow_active,
        });
    }

    let authorized_signer = Pubkey::from_str(&state.authorized_signer)
        .map_err(|_| JobError::InvalidAddress(state.authorized_signer.clone()))?;
    let onchain_signer = Pubkey::from(onchain.channel.authorized_signer.to_bytes());
    if onchain_signer != authorized_signer {
        return Err(JobError::Config(format!(
            "channel {} authorized signer differs from Redis",
            state.channel_id
        )));
    }
    let signature: [u8; 64] = bs58::decode(signature)
        .into_vec()
        .map_err(|error| JobError::TxBuild(format!("voucher signature: {error}")))?
        .try_into()
        .map_err(|_| JobError::TxBuild("voucher signature is not 64 bytes".into()))?;
    let instructions = payment_channels::build_settle_instructions(
        &channel_id,
        &authorized_signer,
        &signature,
        state.cumulative,
        expires_at,
        &payment_channels::default_program_id(),
    )
    .map_err(|error| JobError::TxBuild(format!("settle instruction: {error}")))?;
    let after = inventory_snapshot(
        state.sealed,
        onchain.channel.status,
        state.cumulative,
        onchain.channel.settlement.payout_watermark,
        state.cumulative,
        &onchain.mint(),
    );
    Ok(ReconcileResult {
        channel_id: state_channel_id,
        candidate: Some(SettlementCandidate {
            channel_id: state.channel_id,
            instructions,
            kind: CandidateKind::Watermark,
            before: snapshot,
            after,
        }),
        store_disposition: StoreDisposition::Keep,
        snapshot,
        stablecoin_settled_base_units,
        stablecoin_distributed_base_units,
        escrow_active,
    })
}

fn channel_close_due(state: &ChannelState, now_ms: u64) -> bool {
    !state.sealed
        && state.open_slot.is_some()
        && (state.close_requested_at.is_some()
            || state
                .lifecycle
                .as_ref()
                .is_some_and(|lifecycle| lifecycle.close_after <= now_ms))
}

async fn claim_due_close(
    store: &RedisChannelStore,
    channel_id: &str,
    now_ms: u64,
    now_seconds: u64,
) -> Result<ChannelState, JobError> {
    const MAX_ATTEMPTS: usize = 3;
    let mut last_error = None;
    for _ in 0..MAX_ATTEMPTS {
        let updated = store
            .update_channel(
                channel_id,
                Box::new(move |current| claim_channel_close(current, now_ms, now_seconds)),
            )
            .await;
        match updated {
            Ok(state) => return Ok(state),
            Err(error) => last_error = Some(error),
        }
    }
    Err(JobError::Config(format!(
        "claim session close after {MAX_ATTEMPTS} attempts: {}",
        last_error.expect("at least one claim attempt")
    )))
}

fn claim_channel_close(
    current: Option<ChannelState>,
    now_ms: u64,
    now_seconds: u64,
) -> Result<ChannelState, StoreError> {
    let mut state = current.ok_or_else(|| StoreError::Internal("Channel not found".to_string()))?;
    if channel_close_due(&state, now_ms) {
        state.close_requested_at.get_or_insert(now_seconds);
    }
    Ok(state)
}

async fn build_idle_close_candidate(
    rpc: &RpcClient,
    rpc_url: &str,
    state: &ChannelState,
    onchain: &channel::DecodedChannel,
    now: i64,
    operator: &Pubkey,
    treasury_owner: &Pubkey,
) -> Result<Option<SettlementCandidate>, JobError> {
    if onchain.payee() != *operator {
        return Err(JobError::Config(format!(
            "channel {} payee {} differs from lifecycle operator {operator}",
            state.channel_id,
            onchain.payee()
        )));
    }

    let mut instructions = match onchain.channel.status {
        STATUS_OPEN => {
            let onchain_signer = Pubkey::from(onchain.channel.authorized_signer.to_bytes());
            let (signature, cumulative, expires_at) = close_voucher(
                state,
                onchain.channel.settlement.settled,
                &onchain_signer,
                now,
            )?;
            payment_channels::build_settle_and_seal_instructions(
                operator,
                &onchain.address,
                &onchain_signer,
                signature.as_ref(),
                cumulative,
                expires_at,
                &payment_channels::default_program_id(),
            )
            .map_err(|error| JobError::TxBuild(format!("settle-and-seal instruction: {error}")))?
        }
        STATUS_SEALED => Vec::new(),
        STATUS_CLOSING if now >= onchain.close_deadline() => {
            vec![channel::build_seal_ix(&onchain.address)]
        }
        STATUS_CLOSING => return Ok(None),
        STATUS_DISTRIBUTED => return Ok(None),
        status => {
            return Err(JobError::TxBuild(format!(
                "channel {} has unknown status {status}",
                state.channel_id
            )));
        }
    };

    let token_program = channel::resolve_token_program(rpc, rpc_url, &onchain.mint()).await?;
    let preimage = channel::recover_distribution_preimage(rpc, rpc_url, onchain).await?;
    instructions
        .push(channel::build_distribute_ix(onchain, treasury_owner, &token_program, &preimage).0);
    let before = inventory_snapshot(
        state.sealed,
        onchain.channel.status,
        onchain.channel.settlement.settled,
        onchain.channel.settlement.payout_watermark,
        state.cumulative,
        &onchain.mint(),
    );
    let after = inventory_snapshot(
        true,
        STATUS_DISTRIBUTED,
        onchain.channel.settlement.settled.max(state.cumulative),
        onchain.channel.settlement.settled.max(state.cumulative),
        state.cumulative,
        &onchain.mint(),
    );

    Ok(Some(SettlementCandidate {
        channel_id: state.channel_id.clone(),
        instructions,
        kind: CandidateKind::IdleClose,
        before,
        after,
    }))
}

fn close_voucher(
    state: &ChannelState,
    onchain_settled: u64,
    onchain_signer: &Pubkey,
    now: i64,
) -> Result<(Option<[u8; 64]>, u64, i64), JobError> {
    if state.cumulative <= onchain_settled {
        return Ok((None, onchain_settled, 0));
    }

    let authorized_signer = Pubkey::from_str(&state.authorized_signer)
        .map_err(|_| JobError::InvalidAddress(state.authorized_signer.clone()))?;
    if authorized_signer != *onchain_signer {
        return Err(JobError::Config(format!(
            "channel {} authorized signer differs from Redis",
            state.channel_id
        )));
    }
    let signature = state
        .highest_voucher_signature
        .as_deref()
        .ok_or_else(|| JobError::TxBuild("latest unsettled voucher has no signature".into()))?;
    let expires_at = state
        .highest_voucher_expires_at
        .ok_or_else(|| JobError::TxBuild("latest unsettled voucher has no expiry".into()))?;
    if expires_at != 0 && expires_at <= now {
        return Err(JobError::TxBuild(format!(
            "latest unsettled voucher for {} expired at {expires_at}",
            state.channel_id
        )));
    }
    let signature = decode_voucher_signature(signature)?;
    Ok((Some(signature), state.cumulative, expires_at))
}

fn decode_voucher_signature(signature: &str) -> Result<[u8; 64], JobError> {
    bs58::decode(signature)
        .into_vec()
        .map_err(|error| JobError::TxBuild(format!("voucher signature: {error}")))?
        .try_into()
        .map_err(|_| JobError::TxBuild("voucher signature is not 64 bytes".into()))
}

struct SettlementLock {
    connection: redis::aio::ConnectionManager,
    owner: String,
    heartbeat: LeaseHeartbeat,
}

impl SettlementLock {
    async fn acquire(redis_url: &str, ttl_seconds: u64) -> Result<Option<Self>, JobError> {
        let client = redis::Client::open(redis_url)
            .map_err(|error| JobError::Config(format!("Redis client: {error}")))?;
        let mut connection = client
            .get_connection_manager()
            .await
            .map_err(|error| JobError::Config(format!("Redis connect: {error}")))?;
        let owner = format!("{}-{}", std::process::id(), unix_nanos());
        let acquired: Option<String> = redis::cmd("SET")
            .arg(SETTLEMENT_LOCK_KEY)
            .arg(&owner)
            .arg("NX")
            .arg("EX")
            .arg(ttl_seconds.max(1))
            .query_async(&mut connection)
            .await
            .map_err(|error| JobError::Config(format!("Redis settlement lock: {error}")))?;
        Ok(acquired.map(|_| Self {
            heartbeat: LeaseHeartbeat::start(connection.clone(), owner.clone(), ttl_seconds),
            connection,
            owner,
        }))
    }

    async fn release(mut self) {
        self.heartbeat.shutdown().await;
        const RELEASE: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"#;
        if let Err(error) = redis::Script::new(RELEASE)
            .key(SETTLEMENT_LOCK_KEY)
            .arg(&self.owner)
            .invoke_async::<i32>(&mut self.connection)
            .await
        {
            warn!(%error, "failed to release settlement lease; TTL will expire it");
        }
    }
}

fn required_env(name: &str) -> Result<String, JobError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| JobError::Config(format!("{name} is required")))
}

fn parse_bool_env(name: &str, default: bool) -> Result<bool, JobError> {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| JobError::Config(format!("{name} must be true or false"))),
        Err(_) => Ok(default),
    }
}

fn parse_u64_env(name: &str, default: u64) -> Result<u64, JobError> {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| JobError::Config(format!("{name} must be an integer"))),
        Err(_) => Ok(default),
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn unix_now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pay_kit::core::store::ChannelLifecycle;

    fn channel_state() -> ChannelState {
        ChannelState {
            channel_id: Pubkey::new_unique().to_string(),
            authorized_signer: Pubkey::new_unique().to_string(),
            deposit: 1_000_000,
            cumulative: 0,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            open_slot: Some(42),
            payer: Pubkey::new_unique().to_string(),
            rent_payer: Pubkey::new_unique().to_string(),
            opening_challenge_id: String::new(),
            authentication: None,
            voucher_signer: "client".to_string(),
            idle_timeout_seconds: None,
            last_activity_at: 0,
            spent_amount: 0,
            settled_on_chain: 0,
            processed_uses: vec![],
            processed_topup_signatures: vec![],
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
            lifecycle: None,
            schema_version: pay_kit::mpp::CHANNEL_STATE_SCHEMA_VERSION,
            extra: Default::default(),
        }
    }

    #[test]
    fn inventory_classifies_channel_lifecycle_state() {
        let empty_open =
            inventory_snapshot(false, STATUS_OPEN, 0, 0, 123, &MAINNET_STABLECOIN_MINT);
        assert!(empty_open.opened_zero_settlements);
        assert!(empty_open.unsealed);
        assert!(!empty_open.rent_unclaimed);
        assert_eq!(empty_open.stablecoin_settled_base_units, 0);
        assert_eq!(empty_open.stablecoin_undistributed_base_units, 0);
        assert_eq!(empty_open.stablecoin_distributed_base_units, 0);
        assert_eq!(empty_open.stablecoin_unsettled_base_units, 123);

        let stuck = inventory_snapshot(
            true,
            STATUS_OPEN,
            17_581,
            4_000,
            17_581,
            &MAINNET_STABLECOIN_MINT,
        );
        assert!(stuck.unsealed);
        assert!(stuck.redis_chain_mismatch);
        assert_eq!(stuck.stablecoin_settled_base_units, 17_581);
        assert_eq!(stuck.stablecoin_undistributed_base_units, 13_581);
        assert_eq!(stuck.stablecoin_distributed_base_units, 4_000);
        assert_eq!(stuck.stablecoin_unsettled_base_units, 0);

        let distributed = inventory_snapshot(
            true,
            STATUS_DISTRIBUTED,
            17_581,
            0,
            17_581,
            &MAINNET_STABLECOIN_MINT,
        );
        assert!(distributed.rent_unclaimed);
        assert!(!distributed.unsealed);
        assert!(!distributed.redis_chain_mismatch);
        assert_eq!(distributed.stablecoin_settled_base_units, 17_581);
        assert_eq!(distributed.stablecoin_undistributed_base_units, 0);
        assert_eq!(distributed.stablecoin_distributed_base_units, 17_581);
    }

    #[test]
    fn terminal_status_supersedes_the_final_payout_watermark() {
        assert_eq!(
            effective_distributed_amount(STATUS_DISTRIBUTED, 17_581, 0),
            17_581
        );
        assert_eq!(
            effective_distributed_amount(STATUS_OPEN, 17_581, 4_000),
            4_000
        );
    }

    #[test]
    fn unsettled_stablecoin_uses_cumulative_voucher_delta_in_base_units() {
        assert_eq!(
            unsettled_stablecoin_base_units(&MAINNET_STABLECOIN_MINT, 1_234_567, 234_567),
            1_000_000
        );
        assert_eq!(
            unsettled_stablecoin_base_units(&DEVNET_STABLECOIN_MINT, 100, 101),
            0
        );
        assert_eq!(
            unsettled_stablecoin_base_units(&Pubkey::new_unique(), 1_234_567, 0),
            0
        );
        assert_eq!(
            settled_stablecoin_base_units(&MAINNET_STABLECOIN_MINT, 1_234_567),
            1_234_567
        );
        assert_eq!(
            settled_stablecoin_base_units(&Pubkey::new_unique(), 1_234_567),
            0
        );
    }

    #[test]
    fn confirmed_settlement_updates_the_reported_inventory_snapshot() {
        let before = inventory_snapshot(
            false,
            STATUS_OPEN,
            100_000,
            25_000,
            150_000,
            &MAINNET_STABLECOIN_MINT,
        );
        let after = inventory_snapshot(
            false,
            STATUS_OPEN,
            150_000,
            25_000,
            150_000,
            &MAINNET_STABLECOIN_MINT,
        );
        let mut inventory = LifecycleInventory::default();

        inventory.record(before);
        inventory.replace(before, after);

        assert_eq!(inventory.stablecoin_settled_base_units, 150_000);
        assert_eq!(inventory.stablecoin_undistributed_base_units, 125_000);
        assert_eq!(inventory.stablecoin_distributed_base_units, 25_000);
        assert_eq!(inventory.stablecoin_unsettled_base_units, 0);
        assert_eq!(inventory.unsealed, 1);
        assert_eq!(inventory.rent_unclaimed, 0);
    }

    #[test]
    fn absent_push_channel_is_deleted_but_pull_session_is_kept() {
        let push = channel_state();
        assert_eq!(
            absent_onchain_store_disposition(&push),
            StoreDisposition::Delete
        );

        let mut pull = channel_state();
        pull.open_slot = None;
        assert_eq!(
            absent_onchain_store_disposition(&pull),
            StoreDisposition::Keep
        );
    }

    #[test]
    fn idle_close_requires_a_due_push_channel() {
        let mut state = channel_state();
        state.lifecycle = Some(ChannelLifecycle {
            owner: "proxy-a".to_string(),
            close_after: 120_000,
        });

        assert!(!channel_close_due(&state, 119_999));
        assert!(channel_close_due(&state, 120_000));

        state.lifecycle.as_mut().unwrap().close_after = 180_000;
        state.close_requested_at = Some(120);
        assert!(
            channel_close_due(&state, 120_000),
            "a previously claimed close must resume on the next worker run"
        );

        state.sealed = true;
        assert!(!channel_close_due(&state, 120_000));

        state.sealed = false;
        state.open_slot = None;
        assert!(
            !channel_close_due(&state, 120_000),
            "pull sessions do not have payment channels to close"
        );
    }

    #[test]
    fn close_claim_rechecks_the_latest_deadline() {
        let mut state = channel_state();
        state.lifecycle = Some(ChannelLifecycle {
            owner: "proxy-a".to_string(),
            close_after: 180_000,
        });

        let unchanged = claim_channel_close(Some(state.clone()), 120_000, 120).unwrap();
        assert!(
            unchanged.close_requested_at.is_none(),
            "a concurrent wake-up must cancel the stale close candidate"
        );

        state.lifecycle.as_mut().unwrap().close_after = 120_000;
        let claimed = claim_channel_close(Some(state), 120_000, 120).unwrap();
        assert_eq!(claimed.close_requested_at, Some(120));
    }

    #[test]
    fn idle_close_uses_only_a_strictly_newer_unexpired_voucher() {
        let signer = Pubkey::new_unique();
        let mut state = channel_state();
        state.authorized_signer = signer.to_string();
        state.cumulative = 75;
        state.highest_voucher_signature = Some(bs58::encode([7_u8; 64]).into_string());
        state.highest_voucher_expires_at = Some(500);

        let (signature, cumulative, expires_at) = close_voucher(&state, 50, &signer, 400).unwrap();
        assert_eq!(signature, Some([7_u8; 64]));
        assert_eq!(cumulative, 75);
        assert_eq!(expires_at, 500);

        let (signature, cumulative, expires_at) = close_voucher(&state, 75, &signer, 400).unwrap();
        assert_eq!(signature, None);
        assert_eq!(cumulative, 75);
        assert_eq!(expires_at, 0);

        assert!(close_voucher(&state, 50, &signer, 500).is_err());

        state.highest_voucher_expires_at = Some(0);
        let (signature, cumulative, expires_at) =
            close_voucher(&state, 50, &signer, i64::MAX).unwrap();
        assert_eq!(signature, Some([7_u8; 64]));
        assert_eq!(cumulative, 75);
        assert_eq!(expires_at, 0);
    }
}
