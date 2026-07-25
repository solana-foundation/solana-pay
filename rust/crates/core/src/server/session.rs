//! Server-side session intent — channel lifecycle and voucher verification.
//!
//! Wraps [`pay_kit::mpp::server::session::SessionServer`] with an in-memory
//! channel store and provides challenge issuance + action dispatch that fits
//! the pay-core middleware pattern.
//!
//! # Pull-mode session flow
//!
//! ```text
//! Client sends `open` with deterministic payment-channel fields
//!   │
//!   ▼
//! Server validates the fields against the challenge and opens the channel
//!   │
//!   ▼
//! Server records channel state; the client signs vouchers for that channel
//! ```
//!
use pay_kit::mpp::blockhash::{BlockhashCache, CachedBlockhash};
use pay_kit::mpp::server::session::{SealParams, SessionConfig, SessionServer};
use pay_kit::mpp::settlement::worker::{RpcBroadcaster, SettlementConfig, SettlementHandle, spawn};
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_kit::mpp::store::{ChannelState, ChannelStore, MemoryChannelStore};
use pay_kit::mpp::{
    Base64UrlJson, CommitReceipt, OpenPayload, PaymentChallenge, SessionAction, SessionMode,
    SessionPullVoucherStrategy, SessionSettlementAuthority, SignedVoucher, VoucherData,
    VoucherPayload, parse_authorization,
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};

use crate::server::session_capacity::{CapacityLeaseCoordinator, CapacityLeaseToken};
use crate::{Error, Result};

const INTENT: &str = "session";
const METHOD: &str = "solana";
const DEFAULT_REALM: &str = "MPP Session";
fn session_close_already_finalized(error: &pay_kit::mpp::Error) -> bool {
    error.to_string().contains("already finalized")
}

fn session_close_needs_reconciliation(error: &pay_kit::mpp::Error) -> bool {
    let message = error.to_string();
    message.contains("Close already requested") || message.contains("Channel is already sealed")
}

// ── Session outcome ────────────────────────────────────────────────────────

/// The result of processing a session action.
#[derive(Debug)]
pub enum SessionOutcome {
    /// `open` or `topup` — channel state after the action and the on-chain
    /// transaction signature that authorized it.
    Active {
        state: ChannelState,
        signature: Option<String>,
    },
    /// `voucher` accepted — channel id + new settled cumulative (base units).
    Voucher { channel_id: String, cumulative: u64 },
    /// `commit` accepted — receipt for the metered delivery.
    Commit(CommitReceipt),
    /// `close` accepted — `SealParams` carries what's needed to submit the
    /// on-chain settle+seal + distribute transactions.
    Closed {
        params: SealParams,
        signature: Option<String>,
    },
}

#[derive(Clone)]
struct SessionOperatorRuntime {
    server: Arc<SessionServer<Arc<dyn ChannelStore>>>,
    channel_store: Arc<dyn ChannelStore>,
    rpc_url: Option<String>,
    payment_channel_signer: Arc<Mutex<Option<Arc<dyn SolanaSigner>>>>,
    payment_channel_payer_signer: Arc<Mutex<Option<Arc<dyn SolanaSigner>>>>,
    committed_watermarks: Arc<Mutex<HashMap<String, u64>>>,
    capacity: CapacityLeaseCoordinator,
    delegated_voucher_lock: Arc<tokio::sync::Mutex<()>>,
    /// Channel id → on-chain settlement signature, recorded when the channel
    /// finalizes. Surfaced via the `/sessions/receipt/:channelId` poll so the
    /// playground can show the settle receipt URL (sessions settle out-of-band
    /// at idle-close, so there's no per-request settlement header like x402).
    settlement_signatures: Arc<Mutex<HashMap<String, String>>>,
    /// Batched settlement worker, spawned lazily on first close (the signer is
    /// set after construction). Concurrent closes pack into shared txs.
    settlement_worker: Arc<tokio::sync::OnceCell<SettlementHandle>>,
}

impl SessionOperatorRuntime {
    async fn reserve_capacity(&self, channel_id: &str) -> Result<Option<CapacityLeaseToken>> {
        self.capacity.try_acquire(channel_id).await
    }

    fn release_capacity(&self, channel_id: &str, token: &CapacityLeaseToken) {
        self.capacity.release(channel_id, token);
    }

    fn record_committed_watermark(&self, session_id: impl Into<String>, cumulative: u64) {
        if let Ok(mut watermarks) = self.committed_watermarks.lock() {
            let session_id = session_id.into();
            let entry = watermarks.entry(session_id).or_default();
            *entry = (*entry).max(cumulative);
        }
    }

    fn record_settlement_signature(&self, channel_id: impl Into<String>, signature: String) {
        if let Ok(mut sigs) = self.settlement_signatures.lock() {
            sigs.insert(channel_id.into(), signature);
        }
    }

    fn settlement_signature(&self, channel_id: &str) -> Option<String> {
        self.settlement_signatures
            .lock()
            .ok()
            .and_then(|sigs| sigs.get(channel_id).cloned())
    }

    fn payment_channel_signer(&self) -> Option<Arc<dyn SolanaSigner>> {
        self.payment_channel_signer
            .lock()
            .ok()
            .and_then(|signer| signer.clone())
    }

    fn payment_channel_payer_signer(&self) -> Option<Arc<dyn SolanaSigner>> {
        self.payment_channel_payer_signer
            .lock()
            .ok()
            .and_then(|signer| signer.clone())
            .or_else(|| self.payment_channel_signer())
    }

    /// Push the latest accepted cumulative voucher on-chain without sealing
    /// the channel. The on-chain watermark is read first, so retries are
    /// idempotent and a successfully landed watermark is not re-broadcast on
    /// every lifecycle tick.
    async fn operator_push_watermark(&self, channel_id: &str) -> Result<()> {
        let Some(signer) = self.payment_channel_signer() else {
            // Verification-only servers have no authority to settle. Idle
            // close retains its existing no-op behavior for these instances.
            return Ok(());
        };
        let Some(rpc_url) = self.rpc_url.clone() else {
            return Ok(());
        };
        let params = self
            .server
            .seal_params(channel_id)
            .await
            .map_err(|e| Error::Mpp(format!("Failed to get watermark params: {e}")))?;
        if params.settled == 0 {
            return Ok(());
        }

        let channel = self.fetch_payment_channel(channel_id).await?;
        let Some(channel) = channel else {
            // A missing/deallocated channel has nothing left to settle.
            return Ok(());
        };
        // Only OPEN channels accept an intermediate settle. CLOSING/SEALED/
        // DISTRIBUTED channels are already advancing through the close path.
        if channel.status != 0 || channel.settlement.settled >= params.settled {
            return Ok(());
        }

        let authorized_signer = params.authorized_signer.ok_or_else(|| {
            Error::Mpp("payment-channel watermark missing authorized signer".to_string())
        })?;
        let voucher_signature = params.voucher_signature.as_deref().ok_or_else(|| {
            Error::Mpp("payment-channel watermark missing voucher signature".to_string())
        })?;
        let signature = decode_voucher_signature(voucher_signature)?;
        let expires_at = params.voucher_expires_at.ok_or_else(|| {
            Error::Mpp("payment-channel watermark missing voucher expiry".to_string())
        })?;
        let instructions = pay_kit::mpp::program::payment_channels::build_settle_instructions(
            &params.channel_id,
            &authorized_signer,
            &signature,
            params.settled,
            expires_at,
            &params.program_id,
        )
        .map_err(|e| Error::Mpp(format!("failed to build watermark instruction: {e}")))?;

        let operator = signer.pubkey();
        let handle = self
            .settlement_worker
            .get_or_init(|| {
                let signer = Arc::clone(&signer);
                async move {
                    spawn(
                        SettlementConfig::new(operator, signer),
                        Arc::new(RpcBroadcaster::new(rpc_url)),
                    )
                }
            })
            .await;
        let signature = handle
            .settle(params.channel_id.to_string(), instructions)
            .await
            .map_err(|e| Error::Mpp(format!("payment-channel watermark settlement: {e}")))?;
        tracing::info!(
            channel_id,
            cumulative = params.settled,
            %signature,
            "payment-channel watermark broadcast"
        );
        Ok(())
    }

    async fn operator_close_channel(&self, channel_id: &str) -> Result<SessionCloseResult> {
        use pay_kit::mpp::ClosePayload;

        if self.channel_is_tombstoned_on_chain(channel_id).await {
            self.server
                .mark_sealed(channel_id)
                .await
                .map_err(|e| Error::Mpp(format!("Failed to mark session sealed: {e}")))?;
            return Ok(SessionCloseResult::AlreadyFinalized);
        }

        let payload = ClosePayload {
            channel_id: channel_id.to_string(),
            voucher: None,
        };
        let params = match self.server.process_close(&payload).await {
            Ok(params) => params,
            Err(error) if session_close_already_finalized(&error) => {
                return Ok(SessionCloseResult::AlreadyFinalized);
            }
            Err(error) if session_close_needs_reconciliation(&error) => self
                .server
                .seal_params(channel_id)
                .await
                .map_err(|e| Error::Mpp(format!("Failed to get seal params: {e}")))?,
            Err(error) => {
                return Err(Error::Mpp(format!("Session auto-close failed: {error}")));
            }
        };

        self.record_committed_watermark(params.channel_id.to_string(), params.settled);
        let settlement = self.submit_payment_channel_settlement(&params).await;
        let signature = match settlement {
            Ok(signature) => signature,
            Err(_error) if self.channel_is_tombstoned_on_chain(channel_id).await => {
                self.server
                    .mark_sealed(channel_id)
                    .await
                    .map_err(|e| Error::Mpp(format!("Failed to mark session sealed: {e}")))?;
                return Ok(SessionCloseResult::AlreadyFinalized);
            }
            Err(error) => return Err(error),
        };
        if let Some(signature) = signature {
            self.server
                .mark_sealed(&params.channel_id.to_string())
                .await
                .map_err(|e| Error::Mpp(format!("Failed to mark session sealed: {e}")))?;
            // Retain the settle signature so `/sessions/receipt/:channelId` can
            // surface the on-chain receipt URL (sessions settle out-of-band).
            self.record_settlement_signature(params.channel_id.to_string(), signature.clone());
            tracing::info!(
                monotonic_counter.pay_payment_channels_closed_total = 1_u64,
                %signature,
                channel = %params.channel_id,
                "payment-channel settlement confirmed"
            );
        }

        Ok(SessionCloseResult::Closed {
            settled: params.settled,
        })
    }

    async fn channel_is_tombstoned_on_chain(&self, channel_id: &str) -> bool {
        let Some(rpc_url) = self.rpc_url.clone() else {
            return false;
        };
        let Ok(channel) = solana_pubkey::Pubkey::from_str(channel_id) else {
            return false;
        };

        use pay_kit::mpp::solana_rpc_client::nonblocking::rpc_client::RpcClient;
        RpcClient::new(rpc_url)
            .get_account(&channel)
            .await
            .map(|account| account.data.as_slice() == [2])
            .unwrap_or(false)
    }

    async fn fetch_payment_channel(
        &self,
        channel_id: &str,
    ) -> Result<
        Option<pay_kit::mpp::program::payment_channels::generated::generated::accounts::Channel>,
    > {
        let Some(rpc_url) = self.rpc_url.clone() else {
            return Ok(None);
        };
        let channel = solana_pubkey::Pubkey::from_str(channel_id)
            .map_err(|e| Error::Mpp(format!("invalid payment channel: {e}")))?;
        use pay_kit::mpp::program::payment_channels::generated::generated::accounts::Channel;
        use pay_kit::mpp::solana_rpc_client::nonblocking::rpc_client::RpcClient;
        use solana_commitment_config::CommitmentConfig;
        RpcClient::new(rpc_url)
            .get_account_with_commitment(&channel, CommitmentConfig::confirmed())
            .await
            .map_err(|error| Error::Mpp(format!("failed to fetch payment channel: {error}")))?
            .value
            .map(|account| {
                Channel::from_bytes(&account.data)
                    .map_err(|e| Error::Mpp(format!("failed to decode payment channel: {e}")))
            })
            .transpose()
    }

    async fn submit_payment_channel_settlement(
        &self,
        params: &SealParams,
    ) -> Result<Option<String>> {
        // `settle_and_finalize` requires the **merchant** (recipient) to sign,
        // and for client-voucher pull the recipient is pinned to the settlement
        // signer — so the worker must sign with that. The channel's `rent_payer`
        // (the advertised operator / channel payer, distinct in sandbox) is a
        // *non-signer* account on `distribute`; it only has to equal the
        // channel's stored rent_payer (else 0xA InvalidChannelRentPayer). Keeping
        // these separate fixes both the rent-payer check and the merchant sig.
        let Some(signer) = self.payment_channel_signer() else {
            return Ok(None);
        };
        let rent_payer = self
            .payment_channel_payer_signer()
            .map(|s| s.pubkey())
            .unwrap_or_else(|| signer.pubkey());
        let rpc_url = self.rpc_url.clone().ok_or_else(|| {
            Error::Mpp("payment-channel settlement requires an RPC URL".to_string())
        })?;
        let payer = params
            .payer
            .ok_or_else(|| Error::Mpp("payment-channel settlement missing payer".to_string()))?;
        let mint = params
            .mint
            .ok_or_else(|| Error::Mpp("payment-channel settlement missing mint".to_string()))?;
        let authorized_signer = params.authorized_signer.ok_or_else(|| {
            Error::Mpp("payment-channel settlement missing authorized signer".to_string())
        })?;
        let token_program = spl_token_program();

        // A periodic watermark push may have landed immediately before this
        // close. Reusing that same cumulative voucher in `settle_and_seal`
        // fails with VoucherWatermarkNotMonotonic (0xEA). When chain already
        // has the latest accepted watermark, seal it without another voucher.
        let channel_id = params.channel_id.to_string();
        let onchain_settled = self
            .fetch_payment_channel(&channel_id)
            .await?
            .map(|channel| channel.settlement.settled)
            .unwrap_or_default();
        let voucher_required = close_voucher_required(onchain_settled, params.settled);
        let signature = match (voucher_required, params.voucher_signature.as_deref()) {
            (false, _) => None,
            (true, Some(signature)) => Some(decode_voucher_signature(signature)?),
            (true, None) if params.settled == 0 => None,
            (true, None) => {
                return Err(Error::Mpp(
                    "payment-channel settlement missing highest voucher signature".to_string(),
                ));
            }
        };
        let expires_at = params.voucher_expires_at.unwrap_or(0);

        let mut instructions =
            pay_kit::mpp::program::payment_channels::build_settle_and_seal_instructions(
                &params.recipient,
                &params.channel_id,
                &authorized_signer,
                signature.as_ref(),
                params.settled,
                expires_at,
                &params.program_id,
            )
            .map_err(|e| Error::Mpp(format!("failed to build settlement instruction: {e}")))?;
        let recipients = params
            .splits
            .iter()
            .map(
                |split| pay_kit::mpp::program::payment_channels::Distribution {
                    recipient: split.recipient,
                    bps: split.bps,
                },
            )
            .collect::<Vec<_>>();
        instructions.push(
            pay_kit::mpp::program::payment_channels::build_distribute_instruction(
                &params.channel_id,
                &payer,
                // rentPayer must match the channel's stored rent_payer (the
                // advertised operator / channel payer), NOT the settlement
                // signer — it's a non-signer account here, so they can differ.
                &rent_payer,
                &params.recipient,
                &pay_kit::mpp::program::payment_channels::treasury_owner(),
                &mint,
                &recipients,
                &token_program,
                &params.program_id,
            ),
        );

        // Route through the shared batched worker: concurrent closes pack into
        // shared transactions, signed once by the operator and broadcast.
        let operator = signer.pubkey();
        let handle = self
            .settlement_worker
            .get_or_init(|| {
                let signer = Arc::clone(&signer);
                let rpc_url = rpc_url.clone();
                async move {
                    spawn(
                        SettlementConfig::new(operator, signer),
                        Arc::new(RpcBroadcaster::new(rpc_url)),
                    )
                }
            })
            .await;
        let signature = handle
            .settle(channel_id, instructions)
            .await
            .map_err(|e| Error::Mpp(format!("payment-channel settlement: {e}")))?;
        wait_for_transaction_confirmed(&rpc_url, &signature, "payment-channel settlement").await?;
        Ok(Some(signature))
    }
}

fn close_voucher_required(onchain_settled: u64, latest_accepted: u64) -> bool {
    onchain_settled < latest_accepted
}

/// Exclusive claim on a delegated session's remaining capacity.
///
/// The claim is released on drop so adapter errors, cancelled requests, and
/// settlement failures cannot strand a channel in the reserved state.
pub struct DelegatedCapacityLease {
    runtime: SessionOperatorRuntime,
    channel_id: String,
    token: CapacityLeaseToken,
}

impl DelegatedCapacityLease {
    /// False once the shared lease was lost (expired or taken over), so the
    /// caller must stop the metered work this lease was protecting.
    pub fn is_held(&self) -> bool {
        self.token.is_held()
    }

    /// Resolves when the lease is lost; select on it to cancel in-flight work.
    pub async fn lost(&self) {
        self.token.lost().await;
    }

    /// Run `work` under this lease, abandoning it if the lease is lost first.
    pub async fn guard<T>(&self, work: impl std::future::Future<Output = T>) -> Result<T> {
        self.token.guard(work).await
    }
}

impl Drop for DelegatedCapacityLease {
    fn drop(&mut self) {
        self.runtime.release_capacity(&self.channel_id, &self.token);
    }
}

#[derive(Clone)]
struct SessionLifecycleHandle {
    tx: mpsc::UnboundedSender<SessionLifecycleCommand>,
}

impl SessionLifecycleHandle {
    fn send(&self, command: SessionLifecycleCommand) {
        if self.tx.send(command).is_err() {
            tracing::debug!("session lifecycle runloop is not accepting events");
        }
    }
}

#[derive(Debug)]
enum SessionLifecycleCommand {
    Configure {
        close_delay: Option<Duration>,
        settlement_interval: Option<Duration>,
    },
    Touch {
        channel_id: String,
    },
    Remove {
        channel_id: String,
    },
}

struct SessionLifecycleRunloop {
    runtime: SessionOperatorRuntime,
    close_delay: Option<Duration>,
    settlement_interval: Option<Duration>,
    next_settlement: Option<Instant>,
    rx: mpsc::UnboundedReceiver<SessionLifecycleCommand>,
    last_activity: HashMap<String, Instant>,
}

/// Close one channel under an already-held lease. Extracted so composition
/// tests can drive the same guard → release wiring as `close_due_channels`.
async fn close_channel_under_lease(
    runtime: SessionOperatorRuntime,
    channel_id: String,
    token: CapacityLeaseToken,
) -> (String, Result<SessionCloseResult>) {
    let result = token
        .guard(runtime.operator_close_channel(&channel_id))
        .await
        .and_then(|closed| closed);
    runtime.release_capacity(&channel_id, &token);
    (channel_id, result)
}

impl SessionLifecycleRunloop {
    fn new(
        runtime: SessionOperatorRuntime,
        rx: mpsc::UnboundedReceiver<SessionLifecycleCommand>,
    ) -> Self {
        Self {
            runtime,
            close_delay: None,
            settlement_interval: None,
            next_settlement: None,
            rx,
            last_activity: HashMap::new(),
        }
    }

    async fn run(mut self) {
        loop {
            if let Some(deadline) = self.next_wakeup() {
                tokio::select! {
                    command = self.rx.recv() => {
                        if !self.handle_command(command) {
                            break;
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        self.close_due_channels().await;
                        self.push_due_watermarks().await;
                    }
                }
            } else {
                let command = self.rx.recv().await;
                if !self.handle_command(command) {
                    break;
                }
            }
        }
    }

    fn handle_command(&mut self, command: Option<SessionLifecycleCommand>) -> bool {
        match command {
            Some(SessionLifecycleCommand::Configure {
                close_delay,
                settlement_interval,
            }) => {
                self.close_delay = close_delay;
                self.settlement_interval = settlement_interval;
                self.next_settlement = settlement_interval
                    .filter(|_| !self.last_activity.is_empty())
                    .map(|interval| Instant::now() + interval);
                true
            }
            Some(SessionLifecycleCommand::Touch { channel_id }) => {
                self.last_activity.insert(channel_id, Instant::now());
                if self.next_settlement.is_none()
                    && let Some(interval) = self.settlement_interval
                {
                    self.next_settlement = Some(Instant::now() + interval);
                }
                true
            }
            Some(SessionLifecycleCommand::Remove { channel_id }) => {
                self.last_activity.remove(&channel_id);
                if self.last_activity.is_empty() {
                    self.next_settlement = None;
                }
                true
            }
            None => false,
        }
    }

    fn next_wakeup(&self) -> Option<Instant> {
        let close = self.close_delay.and_then(|delay| {
            self.last_activity
                .values()
                .map(|last_activity| *last_activity + delay)
                .min()
        });
        match (close, self.next_settlement) {
            (Some(close), Some(settlement)) => Some(close.min(settlement)),
            (Some(close), None) => Some(close),
            (None, Some(settlement)) => Some(settlement),
            (None, None) => None,
        }
    }

    async fn close_due_channels(&mut self) {
        let Some(close_delay) = self.close_delay else {
            return;
        };
        let now = Instant::now();
        let due = self
            .last_activity
            .iter()
            .filter(|(_, last_activity)| **last_activity + close_delay <= now)
            .map(|(channel_id, _)| channel_id.clone())
            .collect::<Vec<_>>();

        let mut closing = Vec::with_capacity(due.len());
        for channel_id in due {
            self.last_activity.remove(&channel_id);
            // Closing and serving both claim the same channel slot. This makes
            // the reservation check atomic with the start of close: a request
            // already in flight defers close, while a close already in progress
            // prevents a new request from reserving stale capacity.
            let token = match self.runtime.reserve_capacity(&channel_id).await {
                Ok(Some(token)) => token,
                Ok(None) => {
                    self.last_activity.insert(channel_id, Instant::now());
                    continue;
                }
                Err(error) => {
                    tracing::warn!(
                        channel_id,
                        error = %error,
                        "capacity lease unavailable; deferring auto-close"
                    );
                    self.last_activity.insert(channel_id, Instant::now());
                    continue;
                }
            };
            let runtime = self.runtime.clone();
            closing.push(close_channel_under_lease(runtime, channel_id, token));
        }

        for (channel_id, close_result) in futures_util::future::join_all(closing).await {
            match close_result {
                Ok(SessionCloseResult::Closed { settled }) => {
                    tracing::info!(channel_id, settled, "operator auto-closed payment channel");
                }
                Ok(SessionCloseResult::AlreadyFinalized) => {
                    tracing::debug!(channel_id, "payment channel already finalized");
                }
                Err(error) => {
                    tracing::warn!(
                        channel_id,
                        error = %error,
                        "operator auto-close failed; retrying after delay"
                    );
                    self.last_activity.insert(channel_id, Instant::now());
                }
            }
        }
    }

    async fn push_due_watermarks(&mut self) {
        let Some(interval) = self.settlement_interval else {
            self.next_settlement = None;
            return;
        };
        let now = Instant::now();
        if self.next_settlement.is_some_and(|deadline| deadline > now) {
            return;
        }

        // Idle channels were removed (or rescheduled after an error) by
        // `close_due_channels`; everything left here should remain open.
        let channels = self.last_activity.keys().cloned().collect::<Vec<_>>();
        let mut settlements = Vec::with_capacity(channels.len());
        for channel_id in channels {
            let token = match self.runtime.reserve_capacity(&channel_id).await {
                Ok(Some(token)) => token,
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(
                        channel_id,
                        error = %error,
                        "capacity lease unavailable; skipping watermark push"
                    );
                    continue;
                }
            };
            let runtime = self.runtime.clone();
            settlements.push(async move {
                let result = token
                    .guard(runtime.operator_push_watermark(&channel_id))
                    .await
                    .and_then(|pushed| pushed);
                runtime.release_capacity(&channel_id, &token);
                (channel_id, result)
            });
        }
        for (channel_id, result) in futures_util::future::join_all(settlements).await {
            if let Err(error) = result {
                tracing::warn!(
                    channel_id,
                    error = %error,
                    "operator watermark push failed; retrying next interval"
                );
            }
        }

        self.next_settlement = (!self.last_activity.is_empty()).then(|| now + interval);
    }
}

enum SessionCloseResult {
    Closed { settled: u64 },
    AlreadyFinalized,
}

// ── Session manager ────────────────────────────────────────────────────────

/// Server-side session manager.
///
/// Holds a [`SessionServer`] backed by an in-memory channel store.  For
/// production, swap `MemoryChannelStore` with a persistent backend.
///
/// Payment-channel push sessions submit a client-signed transaction that the
/// server validates and co-signs. Pull-mode delegation setup remains available
/// for compatibility, but it no longer opens a synthetic channel.
pub struct SessionMpp {
    server: Arc<SessionServer<Arc<dyn ChannelStore>>>,
    session_config: SessionConfig,
    challenge_binding_secret: String,
    realm: String,
    rpc_url: Option<String>,
    blockhash_cache: Option<BlockhashCache>,
    payment_channel_signer: Arc<Mutex<Option<Arc<dyn SolanaSigner>>>>,
    payment_channel_payer_signer: Arc<Mutex<Option<Arc<dyn SolanaSigner>>>>,
    committed_watermarks: Arc<Mutex<HashMap<String, u64>>>,
    pull_sessions: Arc<Mutex<HashSet<String>>>,
    lifecycle: SessionLifecycleHandle,
    operator_runtime: SessionOperatorRuntime,
    pull_voucher_strategy: PullVoucherStrategy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PullVoucherStrategy {
    #[default]
    Disabled,
    ClientVoucher,
}

impl SessionMpp {
    /// Network slug (for explorer/receipt URLs).
    pub fn network(&self) -> &str {
        &self.session_config.network
    }

    /// Currency identifier advertised by this session backend.
    pub fn currency(&self) -> &str {
        &self.session_config.currency
    }

    /// Create from a [`SessionConfig`] and an HMAC secret key.
    pub fn new(config: SessionConfig, challenge_binding_secret: impl Into<String>) -> Self {
        Self::new_with_channel_store(
            config,
            challenge_binding_secret,
            Arc::new(MemoryChannelStore::new()),
        )
    }

    /// Create with a caller-provided durable channel store.
    pub fn new_with_channel_store(
        config: SessionConfig,
        challenge_binding_secret: impl Into<String>,
        channel_store: Arc<dyn ChannelStore>,
    ) -> Self {
        Self::new_with_stores(
            config,
            challenge_binding_secret,
            channel_store,
            CapacityLeaseCoordinator::local(),
        )
    }

    /// Create with an explicit channel store and capacity coordinator.
    pub fn new_with_stores(
        config: SessionConfig,
        challenge_binding_secret: impl Into<String>,
        channel_store: Arc<dyn ChannelStore>,
        capacity: CapacityLeaseCoordinator,
    ) -> Self {
        let session_config = config.clone();
        let server = Arc::new(SessionServer::new(config, Arc::clone(&channel_store)));
        let payment_channel_signer = Arc::new(Mutex::new(None));
        let payment_channel_payer_signer = Arc::new(Mutex::new(None));
        let committed_watermarks = Arc::new(Mutex::new(HashMap::new()));
        let delegated_voucher_lock = Arc::new(tokio::sync::Mutex::new(()));
        let settlement_signatures = Arc::new(Mutex::new(HashMap::new()));
        let pull_sessions = Arc::new(Mutex::new(HashSet::new()));
        let operator_runtime = SessionOperatorRuntime {
            server: Arc::clone(&server),
            channel_store,
            rpc_url: session_config.rpc_url.clone(),
            payment_channel_signer: Arc::clone(&payment_channel_signer),
            payment_channel_payer_signer: Arc::clone(&payment_channel_payer_signer),
            committed_watermarks: Arc::clone(&committed_watermarks),
            capacity,
            delegated_voucher_lock,
            settlement_signatures: Arc::clone(&settlement_signatures),
            settlement_worker: Arc::new(tokio::sync::OnceCell::new()),
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let runloop = SessionLifecycleRunloop::new(operator_runtime.clone(), rx);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(runloop.run());
        } else {
            tracing::debug!("session lifecycle runloop not started; no tokio runtime is active");
        }

        Self {
            rpc_url: session_config.rpc_url.clone(),
            blockhash_cache: None,
            server,
            session_config,
            challenge_binding_secret: challenge_binding_secret.into(),
            realm: DEFAULT_REALM.to_string(),
            payment_channel_signer,
            payment_channel_payer_signer,
            committed_watermarks,
            pull_sessions,
            lifecycle: SessionLifecycleHandle { tx },
            operator_runtime,
            pull_voucher_strategy: PullVoucherStrategy::Disabled,
        }
    }

    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = realm.into();
        self
    }

    pub fn with_pull_voucher_strategy(mut self, strategy: PullVoucherStrategy) -> Self {
        self.pull_voucher_strategy = strategy;
        self
    }

    /// Share the server's recent-blockhash cache with session challenge
    /// issuance so `recentBlockhash` and `recentSlot` come from the same
    /// `getLatestBlockhash` observation.
    pub fn with_blockhash_cache(mut self, cache: BlockhashCache) -> Self {
        self.blockhash_cache = Some(cache);
        self
    }

    /// Configure the operator signer used to co-sign client-provided
    /// payment-channel open transactions and to submit close settlement txs.
    pub fn with_payment_channel_signer(self, signer: Arc<dyn SolanaSigner>) -> Self {
        if let Ok(mut payment_channel_signer) = self.payment_channel_signer.lock() {
            *payment_channel_signer = Some(signer);
        }
        self
    }

    /// Configure the signer that funds server-opened payment channels.
    ///
    /// When omitted, the settlement signer is reused for backwards
    /// compatibility. Server-opened client-voucher sessions normally set this
    /// to a distinct funded payer because the payment-channel program rejects
    /// `payer == payee`.
    pub fn with_payment_channel_payer_signer(self, signer: Arc<dyn SolanaSigner>) -> Self {
        if let Ok(mut payment_channel_payer_signer) = self.payment_channel_payer_signer.lock() {
            *payment_channel_payer_signer = Some(signer);
        }
        self
    }

    /// Start the single operator-side lifecycle runloop for delayed channel close.
    ///
    /// The runloop is intentionally centralized: request handlers only record
    /// activity, while this task owns the close/settle/distribute sequence.
    pub fn start_lifecycle_runloop(&self, close_delay: Duration) {
        self.start_lifecycle_runloop_with_settlement(close_delay, Duration::ZERO);
    }

    /// Configure the lifecycle runloop to reconcile active channels' latest
    /// cumulative voucher on-chain and to settle+seal channels after an idle
    /// period. Either duration may be zero to disable that behavior.
    pub fn start_lifecycle_runloop_with_settlement(
        &self,
        close_delay: Duration,
        settlement_interval: Duration,
    ) {
        let close_delay = (!close_delay.is_zero()).then_some(close_delay);
        let settlement_interval = (!settlement_interval.is_zero()).then_some(settlement_interval);
        self.lifecycle.send(SessionLifecycleCommand::Configure {
            close_delay,
            settlement_interval,
        });
        tracing::info!(
            close_delay_ms = close_delay.map(|delay| delay.as_millis()),
            settlement_interval_ms = settlement_interval.map(|interval| interval.as_millis()),
            "started session lifecycle runloop"
        );
    }

    /// Token decimals for base-unit settlement amounts.
    pub fn decimals(&self) -> u8 {
        self.session_config.decimals
    }

    /// Minimum accepted voucher increment in base units.
    pub fn min_voucher_delta(&self) -> u64 {
        self.session_config.min_voucher_delta
    }

    /// Who is authorized to sign cumulative settlement vouchers.
    pub fn settlement_authority(&self) -> SessionSettlementAuthority {
        self.session_config.settlement_authority
    }

    /// Meter a successful response and persist an operator-signed cumulative
    /// voucher before releasing that response to the client.
    pub async fn authorize_delegated_usage(&self, channel_id: &str, amount: u64) -> Result<u64> {
        if self.settlement_authority() != SessionSettlementAuthority::Delegated {
            return Err(Error::Mpp(
                "session does not delegate voucher authority to the operator".to_string(),
            ));
        }
        // Serialize read/sign/verify so concurrent responses cannot construct
        // two vouchers from the same cumulative watermark.
        let _guard = self.operator_runtime.delegated_voucher_lock.lock().await;
        // The durable store is authoritative. Reading it on every delegated
        // authorization also lets a restarted or different gateway replica
        // continue from a watermark advanced by another process.
        let current = self
            .operator_runtime
            .channel_store
            .get_channel(channel_id)
            .await
            .map_err(|error| {
                Error::Mpp(format!(
                    "failed to restore delegated session channel {channel_id}: {error}"
                ))
            })?
            .ok_or_else(|| Error::Mpp(format!("unknown delegated session channel: {channel_id}")))?
            .cumulative;
        self.record_committed_watermark(channel_id.to_string(), current);
        if amount == 0 {
            return Ok(current);
        }
        let cumulative = current
            .checked_add(amount)
            .ok_or_else(|| Error::Mpp("session cumulative amount overflow".to_string()))?;
        let signer = self
            .operator_runtime
            .payment_channel_signer()
            .ok_or_else(|| Error::Mpp("delegated session signer is not configured".to_string()))?;
        let operator = solana_pubkey::Pubkey::from_str(&self.session_config.operator)
            .map_err(|e| Error::Mpp(format!("invalid session operator: {e}")))?;
        if signer.pubkey() != operator {
            return Err(Error::Mpp(format!(
                "delegated session signer {} does not match operator {operator}",
                signer.pubkey()
            )));
        }

        let data = VoucherData {
            channel_id: channel_id.to_string(),
            cumulative: cumulative.to_string(),
            expires_at: pay_kit::mpp::DEFAULT_SESSION_EXPIRES_AT,
            nonce: None,
        };
        let message = data
            .message_bytes()
            .map_err(|e| Error::Mpp(format!("failed to encode delegated voucher: {e}")))?;
        let signature = signer
            .sign_message(&message)
            .await
            .map_err(|e| Error::Mpp(format!("failed to sign delegated voucher: {e}")))?;
        let accepted = self
            .server
            .verify_voucher(&VoucherPayload {
                voucher: SignedVoucher {
                    data,
                    signature: bs58::encode(signature.as_ref()).into_string(),
                },
            })
            .await
            .map_err(|e| Error::PaymentRejected(e.to_string()))?;
        self.record_committed_watermark(channel_id.to_string(), accepted.cumulative);
        self.touch_channel(channel_id.to_string());
        Ok(accepted.cumulative)
    }

    pub async fn reserve_delegated_capacity(
        &self,
        channel_id: &str,
        _amount: u64,
    ) -> Result<Option<DelegatedCapacityLease>> {
        Ok(self
            .operator_runtime
            .reserve_capacity(channel_id)
            .await?
            .map(|token| DelegatedCapacityLease {
                runtime: self.operator_runtime.clone(),
                channel_id: channel_id.to_string(),
                token,
            }))
    }

    /// Seed watermark cache + lifecycle timers from the durable store (call once at boot).
    pub async fn rehydrate_from_store(&self) -> Result<usize> {
        let channels = self
            .operator_runtime
            .channel_store
            .list_channels()
            .await
            .map_err(|error| {
                Error::Mpp(format!("failed to list durable session channels: {error}"))
            })?;
        let mut restored = 0usize;
        for state in channels {
            if state.sealed {
                continue;
            }
            self.record_committed_watermark(state.channel_id.clone(), state.cumulative);
            self.touch_channel(state.channel_id);
            restored += 1;
        }
        if restored > 0 {
            tracing::info!(
                restored,
                "rehydrated open payment channels from durable session store"
            );
        }
        Ok(restored)
    }

    /// Latest cumulative watermark from the local cache only.
    pub fn committed_watermark(&self, session_id: &str) -> Option<u64> {
        self.committed_watermarks
            .lock()
            .ok()
            .and_then(|watermarks| watermarks.get(session_id).copied())
    }

    /// Always read the store and monotonically merge into the local watermark cache.
    pub async fn refresh_committed_watermark(&self, session_id: &str) -> Option<u64> {
        let state = self
            .operator_runtime
            .channel_store
            .get_channel(session_id)
            .await
            .ok()
            .flatten()?;
        self.record_committed_watermark(session_id.to_string(), state.cumulative);
        Some(state.cumulative)
    }

    /// Cache hit, else durable store (seeds the cache).
    pub async fn load_committed_watermark(&self, session_id: &str) -> Option<u64> {
        if let Some(cumulative) = self.committed_watermark(session_id) {
            return Some(cumulative);
        }
        self.refresh_committed_watermark(session_id).await
    }

    /// Record channel activity so the lifecycle runloop can defer auto-close.
    pub fn touch_channel(&self, channel_id: impl Into<String>) {
        let channel_id = channel_id.into();
        if self
            .pull_sessions
            .lock()
            .map(|sessions| sessions.contains(&channel_id))
            .unwrap_or(false)
        {
            return;
        }
        self.lifecycle
            .send(SessionLifecycleCommand::Touch { channel_id });
    }

    /// On-chain settle signature for a finalized session channel, if recorded.
    /// Powers `/sessions/receipt/:channelId` — the playground polls it to show
    /// the settle receipt URL (sessions settle out-of-band at idle-close, so
    /// there's no per-request settlement header like x402 has).
    pub fn settlement_signature(&self, channel_id: &str) -> Option<String> {
        self.operator_runtime.settlement_signature(channel_id)
    }

    /// Build a [`PaymentChallenge`] for a new session with the given cap.
    pub fn challenge(&self, cap: u64) -> Result<PaymentChallenge> {
        let mut request = self.server.build_challenge_request(cap);
        match self.pull_voucher_strategy {
            PullVoucherStrategy::Disabled => {
                request.modes.retain(|mode| mode != &SessionMode::Pull);
                request.pull_voucher_strategy = None;
            }
            PullVoucherStrategy::ClientVoucher => {
                if request.modes.contains(&SessionMode::Pull) {
                    request.pull_voucher_strategy = Some(SessionPullVoucherStrategy::ClientVoucher);
                }
            }
        }
        if request.modes == [SessionMode::Push] {
            request.modes.clear();
        }
        if let Some(hint) = self.prefetch_latest_blockhash_hint() {
            request.recent_blockhash = Some(hint.blockhash);
            request.recent_slot = Some(hint.slot);
        }
        let encoded = Base64UrlJson::from_typed(&request)
            .map_err(|e| Error::Mpp(format!("Failed to encode session request: {e}")))?;
        Ok(PaymentChallenge::with_challenge_binding_secret(
            &self.challenge_binding_secret,
            &self.realm,
            METHOD,
            INTENT,
            encoded,
        ))
    }

    /// Format a session challenge as a `WWW-Authenticate` header value.
    pub fn challenge_header(&self, cap: u64) -> Result<String> {
        self.challenge(cap)?
            .to_header()
            .map_err(|e| Error::Mpp(format!("Failed to format session challenge: {e}")))
    }

    /// Process an `Authorization` header containing a [`SessionAction`].
    ///
    /// For payment-channel `open` actions, the server either co-signs a
    /// client-provided open transaction or opens the channel itself from its
    /// configured payment-channel signer, then stores the confirmed channel.
    #[tracing::instrument(name = "session_process", skip_all)]
    pub async fn process(&self, auth_header: &str) -> Result<SessionOutcome> {
        let credential = parse_authorization(auth_header)
            .map_err(|e| Error::Mpp(format!("Invalid authorization header: {e}")))?;

        if credential.challenge.intent.as_str() != INTENT {
            return Err(Error::Mpp(format!(
                "Expected '{}' intent, got '{}'",
                INTENT, credential.challenge.intent
            )));
        }

        let action: SessionAction = serde_json::from_value(credential.payload)
            .map_err(|e| Error::Mpp(format!("Unrecognized session action payload: {e}")))?;

        match &action {
            SessionAction::Open(p) => {
                let client_voucher_pull = p.mode == SessionMode::Pull
                    && self.pull_voucher_strategy == PullVoucherStrategy::ClientVoucher;
                if p.mode == SessionMode::Pull {
                    self.process_pull_open(p).await?;
                }

                let mut submitted_open = None;
                let open_payload;
                let submit_client_transaction =
                    p.transaction.is_some() && (p.mode == SessionMode::Push || client_voucher_pull);
                let payload_for_open = if submit_client_transaction || client_voucher_pull {
                    let signature = if p.transaction.is_some() {
                        self.submit_payment_channel_open(p).await?.ok_or_else(|| {
                            Error::Mpp(
                                "client-voucher pull open transaction was not submitted"
                                    .to_string(),
                            )
                        })?
                    } else {
                        self.submit_server_payment_channel_open(p).await?
                    };
                    open_payload = {
                        let mut payload = p.clone();
                        payload.signature = signature.clone();
                        payload
                    };
                    submitted_open = Some(signature);
                    &open_payload
                } else {
                    p
                };

                // The host has independently validated, co-signed, submitted,
                // and observed a successful status for transactions it
                // broadcasts. Persist those opens without asking a second RPC
                // client to rediscover the same signature. Opens received by
                // any other integration retain PayKit's standard verification.
                let state = if submitted_open.is_some() {
                    self.server.process_preverified_open(payload_for_open).await
                } else {
                    self.server.process_open(payload_for_open).await
                }
                .map_err(|e| Error::Mpp(format!("Session open failed: {e}")))?;

                if let Some(signature) = &submitted_open {
                    tracing::info!(%signature, "payment-channel open transaction confirmed");
                }

                if p.mode == SessionMode::Pull && !client_voucher_pull {
                    self.record_pull_session(state.channel_id.clone());
                }
                self.record_committed_watermark(state.channel_id.clone(), state.cumulative);
                self.touch_channel(state.channel_id.clone());
                Ok(SessionOutcome::Active {
                    state,
                    signature: Some(payload_for_open.signature.clone()),
                })
            }

            SessionAction::Voucher(p) => {
                let cumulative = self
                    .server
                    .verify_voucher(p)
                    .await
                    .map_err(|e| Error::PaymentRejected(e.to_string()))?
                    .cumulative;
                let channel_id = p.voucher.data.channel_id.clone();
                self.record_committed_watermark(channel_id.clone(), cumulative);
                self.touch_channel(channel_id.clone());
                Ok(SessionOutcome::Voucher {
                    channel_id,
                    cumulative,
                })
            }

            SessionAction::Commit(p) => {
                let receipt = self
                    .server
                    .process_commit(p)
                    .await
                    .map_err(|e| Error::PaymentRejected(e.to_string()))?;
                if let Ok(cumulative) = receipt.cumulative.parse::<u64>() {
                    self.record_committed_watermark(receipt.session_id.clone(), cumulative);
                }
                self.touch_channel(receipt.session_id.clone());
                Ok(SessionOutcome::Commit(receipt))
            }

            SessionAction::TopUp(p) => {
                let state = self
                    .server
                    .process_topup(p)
                    .await
                    .map_err(|e| Error::Mpp(format!("TopUp failed: {e}")))?;
                self.record_committed_watermark(state.channel_id.clone(), state.cumulative);
                self.touch_channel(state.channel_id.clone());
                Ok(SessionOutcome::Active {
                    state,
                    signature: Some(p.signature.clone()),
                })
            }

            SessionAction::Close(p) => {
                let lease = self
                    .reserve_delegated_capacity(&p.channel_id, 0)
                    .await?
                    .ok_or_else(|| {
                        Error::Mpp(format!(
                            "Session channel {} is busy with another request",
                            p.channel_id
                        ))
                    })?;
                lease.guard(self.close_session_channel(p)).await?
            }
        }
    }

    /// Settle, seal, and record a client-initiated close. Callers hold the
    /// channel's capacity lease for the whole sequence.
    async fn close_session_channel(
        &self,
        p: &pay_kit::mpp::ClosePayload,
    ) -> Result<SessionOutcome> {
        let params = match self.server.process_close(p).await {
            Ok(params) => params,
            Err(error) if session_close_needs_reconciliation(&error) => self
                .server
                .seal_params(&p.channel_id)
                .await
                .map_err(|e| Error::Mpp(format!("Failed to get seal params: {e}")))?,
            Err(error) => {
                return Err(Error::Mpp(format!("Session close failed: {error}")));
            }
        };
        self.record_committed_watermark(params.channel_id.to_string(), params.settled);
        let settlement = self.submit_payment_channel_settlement(&params).await;
        let signature = match settlement {
            Ok(signature) => signature,
            Err(_error)
                if self
                    .operator_runtime
                    .channel_is_tombstoned_on_chain(&params.channel_id.to_string())
                    .await =>
            {
                self.server
                    .mark_sealed(&params.channel_id.to_string())
                    .await
                    .map_err(|e| Error::Mpp(format!("Failed to mark session sealed: {e}")))?;
                None
            }
            Err(error) => return Err(error),
        };
        if let Some(signature) = signature.as_ref() {
            self.server
                .mark_sealed(&params.channel_id.to_string())
                .await
                .map_err(|e| Error::Mpp(format!("Failed to mark session sealed: {e}")))?;
            self.operator_runtime
                .record_settlement_signature(params.channel_id.to_string(), signature.clone());
            tracing::info!(
                monotonic_counter.pay_payment_channels_closed_total = 1_u64,
                %signature,
                channel = %params.channel_id,
                "payment-channel settlement confirmed"
            );
        }
        self.unschedule_channel_close(params.channel_id.to_string());
        Ok(SessionOutcome::Closed { params, signature })
    }

    /// Retrieve settle+seal parameters for an open channel.
    ///
    /// Named `finalize_params` for API compatibility; the underlying pay-kit
    /// call is `seal_params` since the epoch-addressed migration renamed the
    /// finalize step to settle+seal (behavior unchanged).
    pub async fn finalize_params(&self, channel_id: &str) -> Result<SealParams> {
        self.server
            .seal_params(channel_id)
            .await
            .map_err(|e| Error::Mpp(format!("Failed to get seal params: {e}")))
    }

    /// Reserve a metered delivery so a client can later acknowledge it with a
    /// signed `commit` voucher.
    pub async fn begin_delivery(
        &self,
        request: pay_kit::mpp::server::session::DeliveryRequest,
    ) -> Result<pay_kit::mpp::MeteringDirective> {
        let session_id = request.session_id.clone();
        let directive = self
            .server
            .begin_delivery(request)
            .await
            .map_err(|e| Error::Mpp(format!("Failed to reserve session delivery: {e}")))?;
        self.touch_channel(session_id);
        Ok(directive)
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn unschedule_channel_close(&self, channel_id: impl Into<String>) {
        self.lifecycle.send(SessionLifecycleCommand::Remove {
            channel_id: channel_id.into(),
        });
    }

    fn record_committed_watermark(&self, session_id: impl Into<String>, cumulative: u64) {
        self.operator_runtime
            .record_committed_watermark(session_id, cumulative);
    }

    fn record_pull_session(&self, session_id: impl Into<String>) {
        if let Ok(mut sessions) = self.pull_sessions.lock() {
            sessions.insert(session_id.into());
        }
    }

    /// Validate and prepare a pull-mode open.
    async fn process_pull_open(&self, payload: &OpenPayload) -> Result<()> {
        match self.pull_voucher_strategy {
            PullVoucherStrategy::Disabled => Err(Error::Mpp(
                "pull-mode sessions are disabled; use push or configure pull_voucher_strategy"
                    .to_string(),
            )),
            PullVoucherStrategy::ClientVoucher => self.validate_client_voucher_pull_open(payload),
        }
    }

    fn validate_client_voucher_pull_open(&self, payload: &OpenPayload) -> Result<()> {
        if payload.channel_id.is_none() || payload.deposit.is_none() {
            return Err(Error::Mpp(
                "client-voucher pull sessions require payment-channel channelId and deposit"
                    .to_string(),
            ));
        }
        if payload.token_account.is_some() || payload.approved_amount.is_some() {
            return Err(Error::Mpp(
                "token-account delegation pull sessions are no longer supported; use client-voucher payment channels"
                    .to_string(),
            ));
        }
        Ok(())
    }

    async fn submit_payment_channel_open(&self, payload: &OpenPayload) -> Result<Option<String>> {
        let Some(transaction) = payload.transaction.as_deref() else {
            return Ok(None);
        };
        // The client builds the open with `fee_payer = challenge.operator`, which
        // is the channel payer (a dedicated, funded signer in sandbox; the main
        // settlement signer otherwise). Co-sign and validate against *that* payer
        // — not the settlement signer, which may differ from the advertised
        // operator and would trip the fee-payer check.
        let signer = self
            .operator_runtime
            .payment_channel_payer_signer()
            .ok_or_else(|| {
                Error::Mpp(
                    "payment-channel open transaction requires an operator signer".to_string(),
                )
            })?;
        let rpc_url = self.rpc_url.clone().ok_or_else(|| {
            Error::Mpp("payment-channel open transaction requires an RPC URL".to_string())
        })?;

        let mut tx = decode_base64_transaction(transaction)?;
        let expected = self.expected_payment_channel_open_instruction(payload)?;
        let operator = signer.pubkey();
        validate_payment_channel_open_transaction(&tx, &expected, &operator)?;

        // Co-sign the operator's fee-payer slot via the shared payment-channels
        // helper (handles both legacy and v0 transactions), then broadcast.
        pay_kit::mpp::program::payment_channels::cosign_fee_payer(
            signer.as_ref(),
            &operator,
            &mut tx,
        )
        .await
        .map_err(|e| Error::Mpp(e.to_string()))?;

        submit_versioned_transaction(rpc_url, tx, "payment-channel open")
            .await
            .map(Some)
    }

    async fn submit_server_payment_channel_open(&self, payload: &OpenPayload) -> Result<String> {
        let signer = self
            .operator_runtime
            .payment_channel_payer_signer()
            .ok_or_else(|| {
                Error::Mpp("server-opened payment channel requires an operator signer".to_string())
            })?;
        let rpc_url = self.rpc_url.clone().ok_or_else(|| {
            Error::Mpp("server-opened payment channel requires an RPC URL".to_string())
        })?;
        let params = self.payment_channel_open_params(payload)?;
        let fee_payer = signer.pubkey();
        if params.payer != fee_payer {
            return Err(Error::Mpp(
                "server-opened payment-channel payer must match operator signer".to_string(),
            ));
        }

        let instruction = pay_kit::mpp::program::payment_channels::build_open_instruction(&params);
        let blockhash = fetch_latest_blockhash(&rpc_url)?;
        let message = solana_message::Message::new_with_blockhash(
            &[instruction],
            Some(&fee_payer),
            &blockhash,
        );
        let mut tx = solana_transaction::Transaction::new_unsigned(message);
        sign_and_submit_transaction(
            Arc::clone(&signer),
            rpc_url,
            &mut tx,
            "payment-channel open",
        )
        .await
    }

    async fn submit_payment_channel_settlement(
        &self,
        params: &SealParams,
    ) -> Result<Option<String>> {
        self.operator_runtime
            .submit_payment_channel_settlement(params)
            .await
    }

    fn expected_payment_channel_open_instruction(
        &self,
        payload: &OpenPayload,
    ) -> Result<solana_instruction::Instruction> {
        self.server
            .payment_channel_open_instruction(payload)
            .map_err(|e| Error::Mpp(e.to_string()))
    }

    fn payment_channel_open_params(
        &self,
        payload: &OpenPayload,
    ) -> Result<pay_kit::mpp::program::payment_channels::OpenChannelParams> {
        self.server
            .payment_channel_open_params(payload)
            .map_err(|e| Error::Mpp(e.to_string()))
    }

    /// Best-effort prefetch of the latest blockhash + slot for session
    /// challenges.
    fn prefetch_latest_blockhash_hint(&self) -> Option<CachedBlockhash> {
        use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;

        if let Some(cached) = self.blockhash_cache.as_ref().and_then(BlockhashCache::get) {
            return Some(cached);
        }
        let rpc_url = self.rpc_url.as_ref()?;
        let rpc = RpcClient::new(rpc_url.clone());
        match pay_kit::mpp::blockhash::fetch_blockhash_with_slot(&rpc, rpc.commitment()) {
            Ok(hint) => Some(hint),
            Err(error) => {
                tracing::debug!(rpc_url, %error, "failed to prefetch session blockhash hint");
                None
            }
        }
    }
}

fn spl_token_program() -> solana_pubkey::Pubkey {
    use pay_kit::mpp::protocol::solana::programs;
    use std::str::FromStr;
    solana_pubkey::Pubkey::from_str(programs::TOKEN_PROGRAM).expect("valid SPL token program id")
}

/// Decode a client-built open transaction. Delegates to the shared
/// payment-channels decoder, which accepts both legacy (pay Rust client) and v0
/// versioned (canonical pay-kit JS client) wire formats.
fn decode_base64_transaction(
    tx_base64: &str,
) -> Result<solana_transaction::versioned::VersionedTransaction> {
    pay_kit::mpp::program::payment_channels::decode_transaction(tx_base64)
        .map_err(|e| Error::Mpp(e.to_string()))
}

fn decode_voucher_signature(signature: &str) -> Result<[u8; 64]> {
    let bytes = bs58::decode(signature)
        .into_vec()
        .map_err(|e| Error::Mpp(format!("invalid voucher signature encoding: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| Error::Mpp("voucher signature is not 64 bytes".to_string()))
}

fn transaction_contains_instruction(
    tx: &solana_transaction::versioned::VersionedTransaction,
    expected: &solana_instruction::Instruction,
) -> bool {
    let keys = tx.message.static_account_keys();
    tx.message.instructions().iter().any(|compiled| {
        let Some(program_id) = keys.get(compiled.program_id_index as usize) else {
            return false;
        };
        if program_id != &expected.program_id || compiled.data != expected.data {
            return false;
        }

        let accounts = compiled
            .accounts
            .iter()
            .filter_map(|index| keys.get(*index as usize).copied())
            .collect::<Vec<_>>();
        let expected_accounts = expected
            .accounts
            .iter()
            .map(|account| account.pubkey)
            .collect::<Vec<_>>();
        accounts == expected_accounts
    })
}

fn validate_payment_channel_open_transaction(
    tx: &solana_transaction::versioned::VersionedTransaction,
    expected: &solana_instruction::Instruction,
    fee_payer: &solana_pubkey::Pubkey,
) -> Result<()> {
    if tx.message.static_account_keys().first() != Some(fee_payer) {
        return Err(Error::Mpp(
            "payment-channel open transaction fee payer does not match operator".to_string(),
        ));
    }

    if tx.message.instructions().len() != 1 {
        return Err(Error::Mpp(
            "payment-channel open transaction must contain exactly one instruction".to_string(),
        ));
    }

    if !transaction_contains_instruction(tx, expected) {
        return Err(Error::Mpp(
            "payment-channel open transaction does not match the session challenge".to_string(),
        ));
    }

    Ok(())
}

fn fetch_latest_blockhash(rpc_url: &str) -> Result<solana_hash::Hash> {
    use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;

    RpcClient::new(rpc_url.to_string())
        .get_latest_blockhash()
        .map_err(|e| Error::Mpp(format!("failed to fetch latest blockhash: {e}")))
}

async fn sign_and_submit_transaction(
    signer: Arc<dyn SolanaSigner>,
    rpc_url: String,
    tx: &mut solana_transaction::Transaction,
    context: &'static str,
) -> Result<String> {
    signer
        .sign_transaction(tx)
        .await
        .map_err(|e| Error::Mpp(format!("failed to sign {context} transaction: {e}")))?;

    submit_versioned_transaction(
        rpc_url,
        solana_transaction::versioned::VersionedTransaction::from(tx.clone()),
        context,
    )
    .await
}

/// Broadcast an already-signed transaction (legacy or v0) and wait for its
/// first successful processed status before returning.
async fn submit_versioned_transaction(
    rpc_url: String,
    tx: solana_transaction::versioned::VersionedTransaction,
    context: &'static str,
) -> Result<String> {
    tokio::task::spawn_blocking(move || {
        use std::time::Instant;

        use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;
        use solana_commitment_config::CommitmentConfig;

        let rpc = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::processed());
        let expected_signature =
            tx.signatures.first().copied().ok_or_else(|| {
                Error::Mpp(format!("{context} transaction is missing a signature"))
            })?;

        let submit_started = Instant::now();
        match rpc.send_transaction(&tx) {
            Ok(signature) => {
                let rpc_send_ms = submit_started.elapsed().as_millis();
                let wait_started = Instant::now();
                wait_for_transaction_processed(&rpc, &signature, context)?;
                tracing::info!(
                    %signature,
                    context,
                    rpc_send_ms,
                    processed_wait_ms = wait_started.elapsed().as_millis(),
                    "transaction reached processed status"
                );
                Ok(signature.to_string())
            }
            Err(send_error) => {
                let rpc_send_ms = submit_started.elapsed().as_millis();
                let wait_started = Instant::now();
                match wait_for_transaction_processed(&rpc, &expected_signature, context) {
                    Ok(()) => {
                        tracing::warn!(
                            %expected_signature,
                            error = %send_error,
                            context,
                            rpc_send_ms,
                            processed_wait_ms = wait_started.elapsed().as_millis(),
                            "{context} transaction confirmed after submit returned an error"
                        );
                        Ok(expected_signature.to_string())
                    }
                    Err(_) => Err(Error::Mpp(format!(
                        "{context} transaction submission failed: {send_error}"
                    ))),
                }
            }
        }
    })
    .await
    .map_err(|e| Error::Mpp(format!("spawn_blocking join error: {e}")))?
}

/// Wait for a previously broadcast transaction to succeed at confirmed
/// commitment before allowing durable state to advance.
async fn wait_for_transaction_confirmed(
    rpc_url: &str,
    signature: &str,
    context: &'static str,
) -> Result<()> {
    use pay_kit::mpp::solana_rpc_client::nonblocking::rpc_client::RpcClient;
    use solana_commitment_config::CommitmentConfig;

    let signature = solana_signature::Signature::from_str(signature)
        .map_err(|e| Error::Mpp(format!("invalid {context} signature: {e}")))?;
    let rpc = RpcClient::new(rpc_url.to_string());
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_status_error = None;
    while Instant::now() < deadline {
        match rpc
            .get_signature_status_with_commitment(&signature, CommitmentConfig::confirmed())
            .await
        {
            Ok(Some(Ok(()))) => return Ok(()),
            Ok(Some(Err(error))) => {
                return Err(Error::Mpp(format!("{context} transaction failed: {error}")));
            }
            Ok(None) => {}
            Err(error) => last_status_error = Some(error.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    let detail = last_status_error
        .map(|error| format!("; last status error: {error}"))
        .unwrap_or_default();
    Err(Error::Mpp(format!(
        "{context} transaction was not confirmed before timeout{detail}"
    )))
}

/// Wait for the transaction's first successful status. `get_signature_status`
/// has no confirmation filter, so this accepts `processed` and anything above
/// it rather than waiting for `confirmed` or `finalized`.
fn wait_for_transaction_processed(
    rpc: &pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient,
    signature: &solana_signature::Signature,
    context: &'static str,
) -> Result<()> {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_status_error = None;
    while Instant::now() < deadline {
        match rpc.get_signature_status(signature) {
            Ok(Some(Ok(()))) => return Ok(()),
            Ok(Some(Err(error))) => {
                return Err(Error::Mpp(format!("{context} transaction failed: {error}")));
            }
            Ok(None) => {}
            Err(error) => {
                last_status_error = Some(error.to_string());
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    let detail = last_status_error
        .map(|error| format!("; last status error: {error}"))
        .unwrap_or_default();
    Err(Error::Mpp(format!(
        "{context} transaction was not confirmed before timeout{detail}"
    )))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::session::SessionHandle;
    use pay_kit::mpp::solana_keychain::{SolanaSigner, memory::MemorySigner};
    use pay_kit::mpp::{PaymentCredential, format_authorization};
    use std::sync::Arc;

    const CAP: u64 = 1_000_000;

    fn test_session_config() -> SessionConfig {
        SessionConfig {
            operator: solana_pubkey::Pubkey::new_unique().to_string(),
            recipient: solana_pubkey::Pubkey::new_unique().to_string(),
            max_cap: 5 * CAP,
            currency: solana_pubkey::Pubkey::new_unique().to_string(),
            network: "localnet".to_string(),
            modes: vec![SessionMode::Push, SessionMode::Pull],
            ..SessionConfig::default()
        }
    }

    fn test_session_mpp() -> SessionMpp {
        SessionMpp::new(test_session_config(), "test-secret")
    }

    fn test_session_signer() -> Box<dyn SolanaSigner> {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::generate(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(vk.as_bytes());
        Box::new(MemorySigner::from_bytes(&kp).unwrap())
    }

    #[tokio::test]
    async fn rehydrate_restores_watermark_after_restart() {
        let store: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::new());
        let first = SessionMpp::new_with_channel_store(
            test_session_config(),
            "test-secret",
            Arc::clone(&store),
        );
        let challenge = first.challenge(CAP).unwrap();
        let handle = SessionHandle::new(
            solana_pubkey::Pubkey::new_unique(),
            test_session_signer(),
            challenge,
        );
        let open_header = handle.open_header(CAP, "open_sig").await.unwrap();
        let SessionOutcome::Active { state: opened, .. } =
            first.process(&open_header).await.unwrap()
        else {
            panic!("expected open");
        };
        let voucher_header = handle.voucher_header(75).await.unwrap();
        first.process(&voucher_header).await.unwrap();
        assert_eq!(first.committed_watermark(&opened.channel_id), Some(75));

        // Simulate a gateway restart: new SessionMpp, same durable store.
        let restarted = SessionMpp::new_with_channel_store(
            test_session_config(),
            "test-secret",
            Arc::clone(&store),
        );
        assert_eq!(restarted.committed_watermark(&opened.channel_id), None);
        let restored = restarted.rehydrate_from_store().await.unwrap();
        assert_eq!(restored, 1);
        assert_eq!(restarted.committed_watermark(&opened.channel_id), Some(75));
        assert_eq!(
            restarted.load_committed_watermark(&opened.channel_id).await,
            Some(75)
        );
    }

    #[test]
    fn with_realm_updates_challenge_realm() {
        let session = test_session_mpp().with_realm("Custom Realm");
        let challenge = session.challenge(CAP).unwrap();
        assert_eq!(challenge.realm, "Custom Realm");
    }

    #[test]
    fn prefetch_latest_blockhash_without_rpc_returns_none() {
        assert!(
            test_session_mpp()
                .prefetch_latest_blockhash_hint()
                .is_none()
        );
    }

    #[test]
    fn challenge_uses_cached_blockhash_and_recent_slot() {
        let cache = BlockhashCache::new();
        cache.set(
            "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxxxx11x".to_string(),
            42,
            123,
        );

        let session = test_session_mpp().with_blockhash_cache(cache);
        let challenge = session.challenge(CAP).unwrap();
        let request: pay_kit::mpp::SessionRequest = challenge.request.decode().unwrap();

        assert_eq!(
            request.recent_blockhash.as_deref(),
            Some("SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxxxx11x")
        );
        assert_eq!(request.recent_slot, Some(123));
    }

    #[tokio::test]
    async fn process_rejects_non_session_intent() {
        let session = test_session_mpp();
        let challenge = PaymentChallenge::with_challenge_binding_secret(
            "test-secret",
            "test-realm",
            METHOD,
            "charge",
            Base64UrlJson::from_typed(&session.server.build_challenge_request(CAP)).unwrap(),
        );
        let handle = SessionHandle::new(
            solana_pubkey::Pubkey::new_unique(),
            test_session_signer(),
            challenge,
        );
        let auth_header = handle.open_header(CAP, "open_sig").await.unwrap();

        let err = session
            .process(&auth_header)
            .await
            .expect_err("non-session intent should error");
        assert!(
            err.to_string().contains("Expected 'session' intent"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn process_rejects_invalid_authorization_header() {
        let session = test_session_mpp();
        let err = session
            .process("Bearer definitely-not-mpp")
            .await
            .expect_err("invalid auth should error");
        assert!(
            err.to_string().contains("Invalid authorization header"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn process_rejects_unknown_session_action_payload() {
        let session = test_session_mpp();
        let challenge = session.challenge(CAP).unwrap();
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            serde_json::json!({ "action": "mystery" }),
        );
        let auth_header = format_authorization(&credential).unwrap();

        let err = session
            .process(&auth_header)
            .await
            .expect_err("unknown action should error");
        assert!(
            err.to_string()
                .contains("Unrecognized session action payload"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn process_supports_open_voucher_topup_and_close() {
        let session = test_session_mpp();
        let challenge = session.challenge(CAP).unwrap();
        let handle = SessionHandle::new(
            solana_pubkey::Pubkey::new_unique(),
            test_session_signer(),
            challenge,
        );
        let open_header = handle.open_header(CAP, "open_sig").await.unwrap();

        let SessionOutcome::Active {
            state: opened,
            signature: open_signature,
        } = session.process(&open_header).await.unwrap()
        else {
            panic!("expected open to return active session");
        };
        assert_eq!(open_signature.as_deref(), Some("open_sig"));
        assert_eq!(opened.deposit, CAP);
        assert_eq!(session.committed_watermark(&opened.channel_id), Some(0));

        let voucher_header = handle.voucher_header(75).await.unwrap();
        let SessionOutcome::Voucher { cumulative, .. } =
            session.process(&voucher_header).await.unwrap()
        else {
            panic!("expected voucher outcome");
        };
        assert_eq!(cumulative, 75);
        assert_eq!(session.committed_watermark(&opened.channel_id), Some(75));

        let topup_header = handle.topup_header(CAP + 500, "topup_sig").await.unwrap();
        let SessionOutcome::Active {
            state: topped_up,
            signature: topup_signature,
        } = session.process(&topup_header).await.unwrap()
        else {
            panic!("expected topup outcome");
        };
        assert_eq!(topup_signature.as_deref(), Some("topup_sig"));
        assert_eq!(topped_up.deposit, CAP + 500);

        let close_header = handle.close_header(Some(25)).await.unwrap();
        let competing_lease = session
            .reserve_delegated_capacity(&opened.channel_id, 0)
            .await
            .unwrap()
            .expect("test should reserve the channel");
        let error = session.process(&close_header).await.unwrap_err();
        assert!(
            error.to_string().contains("busy with another request"),
            "client close must not race another channel owner: {error}"
        );
        drop(competing_lease);

        let SessionOutcome::Closed { params, signature } =
            session.process(&close_header).await.unwrap()
        else {
            panic!("expected close outcome");
        };
        assert_eq!(params.settled, 100);
        assert_eq!(signature, None);
        assert_eq!(session.committed_watermark(&opened.channel_id), Some(100));
    }

    #[tokio::test]
    async fn client_voucher_pull_uses_payment_channel_payload_shape() {
        let session =
            test_session_mpp().with_pull_voucher_strategy(PullVoucherStrategy::ClientVoucher);
        let mut payload = payment_channel_payload(
            &session,
            solana_pubkey::Pubkey::new_unique(),
            solana_pubkey::Pubkey::new_unique(),
            42,
        );
        payload.mode = SessionMode::Pull;

        session.process_pull_open(&payload).await.unwrap();
    }

    #[tokio::test]
    async fn push_open_submits_the_client_transaction_before_verification() {
        let session = test_session_mpp();
        let payload = payment_channel_payload(
            &session,
            solana_pubkey::Pubkey::new_unique(),
            solana_pubkey::Pubkey::new_unique(),
            45,
        );
        let challenge = session.challenge(CAP).unwrap();
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            serde_json::to_value(SessionAction::Open(payload)).unwrap(),
        );
        let auth_header = format_authorization(&credential).unwrap();

        let err = session.process(&auth_header).await.unwrap_err();
        assert!(
            err.to_string().contains("requires an operator signer"),
            "push transaction was not routed through server submission: {err}"
        );
    }

    #[tokio::test]
    async fn client_voucher_pull_accepts_server_opened_payment_channel_shape() {
        let session =
            test_session_mpp().with_pull_voucher_strategy(PullVoucherStrategy::ClientVoucher);
        let mut payload = payment_channel_payload(
            &session,
            solana_pubkey::Pubkey::new_unique(),
            solana_pubkey::Pubkey::new_unique(),
            43,
        );
        payload.mode = SessionMode::Pull;
        payload.transaction = None;

        session.process_pull_open(&payload).await.unwrap();
    }

    #[tokio::test]
    async fn client_voucher_pull_rejects_delegated_token_payload_shape() {
        let session =
            test_session_mpp().with_pull_voucher_strategy(PullVoucherStrategy::ClientVoucher);
        let payload = OpenPayload::pull(
            solana_pubkey::Pubkey::new_unique().to_string(),
            CAP.to_string(),
            solana_pubkey::Pubkey::new_unique().to_string(),
            solana_pubkey::Pubkey::new_unique().to_string(),
            "open_sig".to_string(),
        );

        let err = session.process_pull_open(&payload).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("client-voucher pull sessions require payment-channel")
        );
    }

    #[tokio::test]
    async fn server_opened_payment_channel_requires_operator_payer() {
        let signer: Arc<dyn SolanaSigner> = Arc::from(test_session_signer());
        let mut config = test_session_config();
        config.operator = signer.pubkey().to_string();
        config.rpc_url = Some("http://127.0.0.1:8899".to_string());
        let session = SessionMpp::new(config, "test-secret")
            .with_pull_voucher_strategy(PullVoucherStrategy::ClientVoucher)
            .with_payment_channel_signer(Arc::clone(&signer));
        let mut payload = payment_channel_payload(
            &session,
            solana_pubkey::Pubkey::new_unique(),
            solana_pubkey::Pubkey::new_unique(),
            44,
        );
        payload.mode = SessionMode::Pull;
        payload.transaction = None;

        let err = session
            .submit_server_payment_channel_open(&payload)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("payer must match operator signer"));
    }

    #[tokio::test]
    async fn lifecycle_runloop_operator_closes_idle_channel() {
        let session = Arc::new(test_session_mpp());
        session.start_lifecycle_runloop(Duration::from_millis(10));
        let challenge = session.challenge(CAP).unwrap();
        let handle = SessionHandle::new(
            solana_pubkey::Pubkey::new_unique(),
            test_session_signer(),
            challenge,
        );

        let open_header = handle.open_header(CAP, "open_sig").await.unwrap();
        let SessionOutcome::Active { state: opened, .. } =
            session.process(&open_header).await.unwrap()
        else {
            panic!("expected open to return active session");
        };
        assert_eq!(session.committed_watermark(&opened.channel_id), Some(0));

        tokio::time::sleep(Duration::from_millis(60)).await;

        let voucher_header = handle.voucher_header(75).await.unwrap();
        let err = session.process(&voucher_header).await.unwrap_err();
        assert!(
            err.to_string().contains("close is pending"),
            "expected auto-close to reject later voucher, got: {err}"
        );
    }

    #[tokio::test]
    async fn delegated_capacity_lease_releases_on_drop() {
        let session = test_session_mpp();
        let first = session
            .reserve_delegated_capacity("channel", CAP)
            .await
            .unwrap()
            .expect("first reservation should succeed");
        assert!(
            session
                .reserve_delegated_capacity("channel", CAP)
                .await
                .unwrap()
                .is_none(),
            "a live lease must exclude concurrent reservations"
        );

        drop(first);

        assert!(
            session
                .reserve_delegated_capacity("channel", CAP)
                .await
                .unwrap()
                .is_some(),
            "dropping the lease must release capacity"
        );
    }

    #[tokio::test]
    async fn delegated_capacity_lease_defers_idle_close() {
        let session = Arc::new(test_session_mpp());
        session.start_lifecycle_runloop(Duration::from_millis(10));
        let challenge = session.challenge(CAP).unwrap();
        let handle = SessionHandle::new(
            solana_pubkey::Pubkey::new_unique(),
            test_session_signer(),
            challenge,
        );

        let open_header = handle.open_header(CAP, "open_sig").await.unwrap();
        let SessionOutcome::Active { state: opened, .. } =
            session.process(&open_header).await.unwrap()
        else {
            panic!("expected open to return active session");
        };
        let lease = session
            .reserve_delegated_capacity(&opened.channel_id, CAP)
            .await
            .unwrap()
            .expect("request should reserve channel capacity");

        tokio::time::sleep(Duration::from_millis(60)).await;

        let voucher_header = handle.voucher_header(75).await.unwrap();
        assert!(
            session.process(&voucher_header).await.is_ok(),
            "idle-close must not start while a request owns the lease"
        );

        drop(lease);
        tokio::time::sleep(Duration::from_millis(60)).await;

        let voucher_header = handle.voucher_header(75).await.unwrap();
        let error = session.process(&voucher_header).await.unwrap_err();
        assert!(
            error.to_string().contains("close is pending"),
            "expected idle-close after lease release, got: {error}"
        );
    }

    #[tokio::test]
    async fn process_supports_reserved_delivery_commit() {
        let session = test_session_mpp();
        let challenge = session.challenge(CAP).unwrap();
        let channel_id = solana_pubkey::Pubkey::new_unique();
        let active =
            pay_kit::mpp::client::session::ActiveSession::new(channel_id, test_session_signer());

        let open_action = active.open_action(CAP, "open_sig");
        let open_header =
            pay_kit::mpp::format_authorization(&pay_kit::mpp::PaymentCredential::new(
                challenge.to_echo(),
                serde_json::to_value(open_action).unwrap(),
            ))
            .unwrap();
        let SessionOutcome::Active { .. } = session.process(&open_header).await.unwrap() else {
            panic!("expected open outcome");
        };

        let directive = session
            .server
            .begin_delivery(pay_kit::mpp::server::session::DeliveryRequest::new(
                active.channel_id_str(),
                60,
            ))
            .await
            .unwrap();
        let voucher = active.prepare_increment(60).await.unwrap();
        let commit_action = SessionAction::Commit(pay_kit::mpp::CommitPayload {
            delivery_id: directive.delivery_id.clone(),
            voucher,
        });
        let commit_header =
            pay_kit::mpp::format_authorization(&pay_kit::mpp::PaymentCredential::new(
                challenge.to_echo(),
                serde_json::to_value(commit_action).unwrap(),
            ))
            .unwrap();

        let SessionOutcome::Commit(receipt) = session.process(&commit_header).await.unwrap() else {
            panic!("expected commit outcome");
        };
        assert_eq!(receipt.delivery_id, directive.delivery_id);
        assert_eq!(receipt.amount, "60");
        assert_eq!(receipt.cumulative, "60");
        assert_eq!(
            session.committed_watermark(&active.channel_id_str()),
            Some(60)
        );
    }

    #[tokio::test]
    async fn delegated_usage_signs_and_persists_cumulative_voucher() {
        let signer: Arc<dyn SolanaSigner> = Arc::from(test_session_signer());
        let operator = signer.pubkey();
        let mut config = test_session_config();
        config.operator = operator.to_string();
        config.settlement_authority = SessionSettlementAuthority::Delegated;
        let session =
            SessionMpp::new(config, "test-secret").with_payment_channel_signer(Arc::clone(&signer));
        let payload =
            payment_channel_payload(&session, solana_pubkey::Pubkey::new_unique(), operator, 91);
        let opened = tokio::time::timeout(
            Duration::from_secs(2),
            session.server.process_preverified_open(&payload),
        )
        .await
        .expect("delegated open timed out")
        .unwrap();
        session.record_committed_watermark(opened.channel_id.clone(), opened.cumulative);

        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(2),
                session.authorize_delegated_usage(&opened.channel_id, 75),
            )
            .await
            .expect("first delegated voucher timed out")
            .unwrap(),
            75
        );
        session
            .committed_watermarks
            .lock()
            .expect("watermark lock")
            .clear();
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(2),
                session.authorize_delegated_usage(&opened.channel_id, 25),
            )
            .await
            .expect("second delegated voucher timed out")
            .unwrap(),
            100
        );
        let close_payload = pay_kit::mpp::ClosePayload {
            channel_id: opened.channel_id.clone(),
            voucher: None,
        };
        let close = tokio::time::timeout(
            Duration::from_secs(2),
            session.server.process_close(&close_payload),
        )
        .await
        .expect("delegated close timed out")
        .unwrap();
        assert_eq!(close.settled, 100);
        assert_eq!(session.committed_watermark(&opened.channel_id), Some(100));
    }

    #[tokio::test]
    async fn challenge_header_formats_session_challenge() {
        let header = test_session_mpp().challenge_header(CAP).unwrap();
        let challenge = pay_kit::mpp::parse_www_authenticate(&header).unwrap();
        assert_eq!(challenge.intent.as_str(), INTENT);
        assert_eq!(challenge.method.as_str(), METHOD);
    }

    #[tokio::test]
    async fn finalize_params_returns_error_for_unknown_channel() {
        let err = test_session_mpp()
            .finalize_params("missing-channel")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Failed to get seal params"));
    }

    fn payment_channel_payload(
        session: &SessionMpp,
        payer: solana_pubkey::Pubkey,
        authorized_signer: solana_pubkey::Pubkey,
        salt: u64,
    ) -> OpenPayload {
        let payee = solana_pubkey::Pubkey::try_from(session.session_config.recipient.as_str())
            .expect("valid test payee");
        let mint = solana_pubkey::Pubkey::try_from(session.session_config.currency.as_str())
            .expect("valid test mint");
        let program_id = session
            .session_config
            .program_id
            .unwrap_or_else(pay_kit::mpp::program::payment_channels::default_program_id);
        let token_program = spl_token_program();
        // The open slot is a channel-PDA seed since the epoch-addressed
        // migration; keep it identical between the params used to derive the
        // channel and the payload's recentSlot so the server re-derives the
        // same PDA.
        let open_slot = 4_242u64;
        let params = pay_kit::mpp::program::payment_channels::OpenChannelParams {
            payer,
            rent_payer: payer,
            payee,
            mint,
            authorized_signer,
            salt,
            open_slot,
            deposit: CAP,
            grace_period: 900,
            recipients: vec![],
            token_program,
            program_id,
        };
        let channel = pay_kit::mpp::program::payment_channels::derive_channel_addresses(&params)
            .channel
            .to_string();

        OpenPayload::payment_channel(
            channel,
            CAP.to_string(),
            payer.to_string(),
            payee.to_string(),
            mint.to_string(),
            salt,
            900,
            open_slot,
            authorized_signer.to_string(),
            "pending".to_string(),
        )
        .with_transaction("tx".to_string())
    }

    #[test]
    fn payment_channel_open_params_validate_challenge_fields() {
        let session = test_session_mpp();
        let payload = payment_channel_payload(
            &session,
            solana_pubkey::Pubkey::new_unique(),
            solana_pubkey::Pubkey::new_unique(),
            42,
        );

        let params = session.payment_channel_open_params(&payload).unwrap();
        assert_eq!(params.deposit, CAP);
        assert_eq!(params.grace_period, 900);

        let mut tampered = payload.clone();
        tampered.payee = Some(solana_pubkey::Pubkey::new_unique().to_string());
        let err = session.payment_channel_open_params(&tampered).unwrap_err();
        assert!(err.to_string().contains("payee"));
    }

    #[test]
    fn payment_channel_open_params_validates_stablecoin_symbols_via_sdk() {
        let session = SessionMpp::new(
            SessionConfig {
                currency: "USDC".to_string(),
                network: "localnet".to_string(),
                ..test_session_config()
            },
            "test-secret",
        );
        let payer = solana_pubkey::Pubkey::new_unique();
        let authorized_signer = solana_pubkey::Pubkey::new_unique();
        let payee = solana_pubkey::Pubkey::try_from(session.session_config.recipient.as_str())
            .expect("valid test payee");
        let mint = solana_pubkey::Pubkey::try_from(pay_kit::mpp::mints::USDC_MAINNET)
            .expect("valid USDC mint");
        let program_id = session
            .session_config
            .program_id
            .unwrap_or_else(pay_kit::mpp::program::payment_channels::default_program_id);
        let open_slot = 4_242u64;
        let params = pay_kit::mpp::program::payment_channels::OpenChannelParams {
            payer,
            rent_payer: payer,
            payee,
            mint,
            authorized_signer,
            salt: 99,
            open_slot,
            deposit: CAP,
            grace_period: 900,
            recipients: vec![],
            token_program: spl_token_program(),
            program_id,
        };
        let channel = pay_kit::mpp::program::payment_channels::derive_channel_addresses(&params)
            .channel
            .to_string();
        let payload = OpenPayload::payment_channel(
            channel,
            CAP.to_string(),
            payer.to_string(),
            payee.to_string(),
            mint.to_string(),
            params.salt,
            params.grace_period,
            params.open_slot,
            authorized_signer.to_string(),
            "pending".to_string(),
        );

        let parsed = session.payment_channel_open_params(&payload).unwrap();
        assert_eq!(parsed.mint, mint);

        let mut tampered = payload;
        tampered.mint = Some(solana_pubkey::Pubkey::new_unique().to_string());
        let err = session.payment_channel_open_params(&tampered).unwrap_err();
        assert!(err.to_string().contains("mint does not match"));
    }

    #[test]
    fn transaction_contains_expected_payment_channel_open_instruction() {
        let session = test_session_mpp();
        let payload = payment_channel_payload(
            &session,
            solana_pubkey::Pubkey::new_unique(),
            solana_pubkey::Pubkey::new_unique(),
            7,
        );
        let expected = session
            .expected_payment_channel_open_instruction(&payload)
            .unwrap();
        let fee_payer = solana_pubkey::Pubkey::new_unique();
        let message = solana_message::Message::new_with_blockhash(
            std::slice::from_ref(&expected),
            Some(&fee_payer),
            &solana_hash::Hash::default(),
        );
        let tx = solana_transaction::versioned::VersionedTransaction::from(
            solana_transaction::Transaction::new_unsigned(message),
        );
        assert!(transaction_contains_instruction(&tx, &expected));

        let mut tampered = expected.clone();
        tampered.data.push(99);
        assert!(!transaction_contains_instruction(&tx, &tampered));
    }

    #[test]
    fn validate_payment_channel_open_transaction_rejects_extra_instructions() {
        let session = test_session_mpp();
        let payload = payment_channel_payload(
            &session,
            solana_pubkey::Pubkey::new_unique(),
            solana_pubkey::Pubkey::new_unique(),
            11,
        );
        let expected = session
            .expected_payment_channel_open_instruction(&payload)
            .unwrap();
        let fee_payer = solana_pubkey::Pubkey::new_unique();
        let extra = solana_instruction::Instruction {
            program_id: solana_pubkey::Pubkey::new_unique(),
            accounts: vec![],
            data: vec![1],
        };
        let message = solana_message::Message::new_with_blockhash(
            &[expected.clone(), extra],
            Some(&fee_payer),
            &solana_hash::Hash::default(),
        );
        let tx = solana_transaction::versioned::VersionedTransaction::from(
            solana_transaction::Transaction::new_unsigned(message),
        );

        let err =
            validate_payment_channel_open_transaction(&tx, &expected, &fee_payer).unwrap_err();
        assert!(err.to_string().contains("exactly one instruction"));
    }

    #[test]
    fn validate_payment_channel_open_transaction_rejects_wrong_fee_payer() {
        let session = test_session_mpp();
        let payload = payment_channel_payload(
            &session,
            solana_pubkey::Pubkey::new_unique(),
            solana_pubkey::Pubkey::new_unique(),
            12,
        );
        let expected = session
            .expected_payment_channel_open_instruction(&payload)
            .unwrap();
        let fee_payer = solana_pubkey::Pubkey::new_unique();
        let message = solana_message::Message::new_with_blockhash(
            std::slice::from_ref(&expected),
            Some(&fee_payer),
            &solana_hash::Hash::default(),
        );
        let tx = solana_transaction::versioned::VersionedTransaction::from(
            solana_transaction::Transaction::new_unsigned(message),
        );

        let wrong_fee_payer = solana_pubkey::Pubkey::new_unique();
        let err = validate_payment_channel_open_transaction(&tx, &expected, &wrong_fee_payer)
            .unwrap_err();
        assert!(err.to_string().contains("fee payer"));
    }

    #[test]
    fn close_omits_voucher_when_watermark_already_landed() {
        assert!(close_voucher_required(4_330, 4_331));
        assert!(!close_voucher_required(4_331, 4_331));
        assert!(!close_voucher_required(4_332, 4_331));
    }

    #[test]
    fn close_reconciles_durable_state_after_failed_broadcast() {
        let close_pending = pay_kit::mpp::Error::Other("Close already requested".to_string());
        let sealed = pay_kit::mpp::Error::Other("Channel is already sealed".to_string());
        let missing = pay_kit::mpp::Error::Other("Channel not found".to_string());

        assert!(session_close_needs_reconciliation(&close_pending));
        assert!(session_close_needs_reconciliation(&sealed));
        assert!(!session_close_needs_reconciliation(&missing));
    }
}

#[cfg(all(test, feature = "redis-session-store"))]
mod redis_e2e_tests {
    use super::*;
    use crate::client::session::SessionHandle;
    use crate::server::gate::{SessionForward, settle_delegated_session};
    use crate::server::metering::{RequestProperties, UptoSettlementPlan};
    use crate::server::session_capacity::CAPACITY_LEASE_TTL;
    use crate::server::session_capacity::CapacityLeaseCoordinator;
    use crate::server::session_capacity::redis_test_support::{
        assert_no_overlapping_holders, await_released, del_lease_key, redis_test_url, unique_prefix,
    };
    use http::HeaderMap;
    use pay_kit::mpp::solana_keychain::{SolanaSigner, memory::MemorySigner};
    use pay_kit::mpp::store::RedisChannelStore;
    use pay_types::metering::{BillingUnit, MeterDimension, MeterDirection, Metering, PriceTier};
    use std::sync::Arc;
    use std::time::Duration;

    const CAP: u64 = 1_000_000;

    fn config() -> SessionConfig {
        SessionConfig {
            operator: solana_pubkey::Pubkey::new_unique().to_string(),
            recipient: solana_pubkey::Pubkey::new_unique().to_string(),
            max_cap: 5 * CAP,
            currency: solana_pubkey::Pubkey::new_unique().to_string(),
            network: "localnet".to_string(),
            modes: vec![SessionMode::Push, SessionMode::Pull],
            ..SessionConfig::default()
        }
    }

    fn signer() -> Box<dyn SolanaSigner> {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::generate(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(vk.as_bytes());
        Box::new(MemorySigner::from_bytes(&kp).unwrap())
    }

    fn output_bytes_plan() -> UptoSettlementPlan {
        UptoSettlementPlan {
            metering: Metering {
                dimensions: vec![MeterDimension {
                    direction: MeterDirection::Output,
                    unit: BillingUnit::Tokens,
                    scale: 1,
                    period: None,
                    tiers: vec![PriceTier {
                        up_to: None,
                        price_usd: 0.000001,
                        condition: None,
                        notes: None,
                        splits: vec![],
                    }],
                    meter: None,
                }],
                variants: vec![],
                sku_tiers: vec![],
                splits: vec![],
                schemes: None,
                min_usd: None,
                upto: None,
            },
            variant_hint: None,
            request_properties: RequestProperties::default(),
            ceiling_usd: 0.001,
            inferred_usage: Some(crate::InferenceUsage {
                model: None,
                streamed: false,
                ttft_ms: None,
                tokens_prompt: None,
                tokens_completion: Some(10),
                tokens_per_sec: None,
            }),
        }
    }

    async fn open_delegated_pair_with_ttl(
        url: &str,
        prefix: &str,
        ttl: Duration,
    ) -> (Arc<SessionMpp>, Arc<SessionMpp>, String, SessionHandle) {
        let store: Arc<dyn ChannelStore> = Arc::new(
            RedisChannelStore::connect(url, prefix.to_string())
                .await
                .expect("redis store"),
        );
        let first = Arc::new(SessionMpp::new_with_stores(
            config(),
            "redis-e2e",
            Arc::clone(&store),
            CapacityLeaseCoordinator::redis_with_ttl(url, prefix, ttl)
                .await
                .unwrap(),
        ));
        let second = Arc::new(SessionMpp::new_with_stores(
            config(),
            "redis-e2e",
            Arc::clone(&store),
            CapacityLeaseCoordinator::redis_with_ttl(url, prefix, ttl)
                .await
                .unwrap(),
        ));
        let handle = SessionHandle::new(
            solana_pubkey::Pubkey::new_unique(),
            signer(),
            first.challenge(CAP).unwrap(),
        );
        let open = handle.open_header(CAP, "open_sig").await.unwrap();
        let SessionOutcome::Active { state: opened, .. } = first.process(&open).await.unwrap()
        else {
            panic!("expected open");
        };
        (first, second, opened.channel_id, handle)
    }

    /// Default to the production TTL: only loss-injection tests want a short one.
    async fn open_delegated_pair(
        url: &str,
        prefix: &str,
    ) -> (Arc<SessionMpp>, Arc<SessionMpp>, String, SessionHandle) {
        open_delegated_pair_with_ttl(url, prefix, CAPACITY_LEASE_TTL).await
    }

    #[tokio::test]
    async fn redis_rehydrate_and_lease_across_replicas() {
        let Some(url) = redis_test_url() else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };
        let prefix = unique_prefix("session");
        let (first, second, channel_id, handle) = open_delegated_pair(&url, &prefix).await;
        first
            .process(&handle.voucher_header(88).await.unwrap())
            .await
            .unwrap();

        let lease = first
            .reserve_delegated_capacity(&channel_id, 0)
            .await
            .unwrap()
            .expect("first lease");
        assert!(
            first
                .reserve_delegated_capacity(&channel_id, 0)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            second
                .reserve_delegated_capacity(&channel_id, 0)
                .await
                .unwrap()
                .is_none()
        );

        drop(lease);
        await_released(&url, &prefix, &channel_id, CAPACITY_LEASE_TTL).await;

        assert!(second.rehydrate_from_store().await.unwrap() >= 1);
        assert_eq!(second.load_committed_watermark(&channel_id).await, Some(88));
        assert!(
            second
                .reserve_delegated_capacity(&channel_id, 0)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn dual_replica_watermark_refresh_sees_peer_commit() {
        let Some(url) = redis_test_url() else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };
        let prefix = unique_prefix("watermark");
        let (first, second, channel_id, handle) = open_delegated_pair(&url, &prefix).await;
        first
            .process(&handle.voucher_header(42).await.unwrap())
            .await
            .unwrap();
        assert_eq!(first.committed_watermark(&channel_id), Some(42));
        assert_eq!(second.committed_watermark(&channel_id), None);
        assert_eq!(
            second.refresh_committed_watermark(&channel_id).await,
            Some(42)
        );
        assert_eq!(second.committed_watermark(&channel_id), Some(42));
    }

    #[tokio::test]
    async fn rehydrate_skips_sealed_channels() {
        let Some(url) = redis_test_url() else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };
        let prefix = unique_prefix("rehydrate-sealed");
        let (first, second, channel_id, _) = open_delegated_pair(&url, &prefix).await;
        assert_eq!(
            second.rehydrate_from_store().await.unwrap(),
            1,
            "open channel must be present before sealing"
        );
        first
            .operator_runtime
            .channel_store
            .mark_sealed(&channel_id)
            .await
            .expect("seal");
        let restarted = SessionMpp::new_with_stores(
            config(),
            "redis-e2e",
            Arc::clone(&first.operator_runtime.channel_store),
            CapacityLeaseCoordinator::redis(&url, &prefix)
                .await
                .unwrap(),
        );
        assert_eq!(restarted.rehydrate_from_store().await.unwrap(), 0);
        assert_eq!(restarted.committed_watermark(&channel_id), None);
    }

    #[tokio::test]
    async fn settle_delegated_session_abandons_when_lease_lost() {
        let Some(url) = redis_test_url() else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };
        let prefix = unique_prefix("settle-loss");
        let ttl = Duration::from_secs(2);
        let peer_coordinator = CapacityLeaseCoordinator::redis_with_ttl(&url, &prefix, ttl)
            .await
            .unwrap();
        let (first, second, channel_id, _) = open_delegated_pair_with_ttl(&url, &prefix, ttl).await;
        let lease = first
            .reserve_delegated_capacity(&channel_id, CAP)
            .await
            .unwrap()
            .expect("lease");
        assert_no_overlapping_holders(&peer_coordinator, &channel_id).await;

        del_lease_key(&url, &prefix, &channel_id).await;
        assert_no_overlapping_holders(&peer_coordinator, &channel_id).await;
        tokio::time::timeout(ttl * 4, lease.lost())
            .await
            .expect("holder must observe lease loss");

        let forward = SessionForward::delegated(
            Arc::clone(&first),
            channel_id.clone(),
            0,
            output_bytes_plan(),
            CAP,
            lease,
        );
        let error = match settle_delegated_session(forward, &HeaderMap::new(), Some(b"hello-world"))
            .await
        {
            Ok(ok) => panic!(
                "lost lease must abandon settlement, got Ok(is_some={})",
                ok.is_some()
            ),
            Err(error) => error,
        };
        assert!(
            error.contains("capacity lease was lost"),
            "unexpected settle error: {error}"
        );
        await_released(&url, &prefix, &channel_id, ttl).await;
        assert!(
            second
                .reserve_delegated_capacity(&channel_id, 0)
                .await
                .unwrap()
                .is_some(),
            "peer may acquire only after the abandoned holder released"
        );
    }

    #[tokio::test]
    async fn auto_close_defers_when_a_peer_holds_the_lease() {
        let Some(url) = redis_test_url() else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };
        let prefix = unique_prefix("lifecycle-contention");
        let (session, peer, channel_id, _) = open_delegated_pair(&url, &prefix).await;

        let _peer_lease = peer
            .reserve_delegated_capacity(&channel_id, 0)
            .await
            .unwrap()
            .expect("peer lease");

        let (_tx, rx) = mpsc::unbounded_channel();
        let mut runloop = SessionLifecycleRunloop::new(session.operator_runtime.clone(), rx);
        runloop.close_delay = Some(Duration::ZERO);
        runloop
            .last_activity
            .insert(channel_id.clone(), Instant::now() - Duration::from_secs(1));

        runloop.close_due_channels().await;

        assert!(
            runloop.last_activity.contains_key(&channel_id),
            "a channel held by a peer must be rescheduled, not dropped"
        );
        assert_eq!(
            session.refresh_committed_watermark(&channel_id).await,
            Some(0),
            "a deferred close must not touch the durable channel state"
        );
    }

    #[tokio::test]
    async fn lifecycle_auto_close_abandons_when_lease_lost() {
        let Some(url) = redis_test_url() else {
            eprintln!("skipping: set PAY_SESSION_REDIS_URL or PAY_KIT_TEST_REDIS_URL");
            return;
        };
        let prefix = unique_prefix("lifecycle-loss");
        let ttl = Duration::from_secs(2);
        let peer_coordinator = CapacityLeaseCoordinator::redis_with_ttl(&url, &prefix, ttl)
            .await
            .unwrap();
        let (session, peer, channel_id, _) = open_delegated_pair_with_ttl(&url, &prefix, ttl).await;

        // Drive the extracted close_channel_under_lease path (same wiring as
        // close_due_channels). Loss before the guarded close must abandon work
        // and release so a peer can take over.
        let token = session
            .operator_runtime
            .reserve_capacity(&channel_id)
            .await
            .unwrap()
            .expect("lifecycle lease");
        assert_no_overlapping_holders(&peer_coordinator, &channel_id).await;

        del_lease_key(&url, &prefix, &channel_id).await;
        assert_no_overlapping_holders(&peer_coordinator, &channel_id).await;
        tokio::time::timeout(ttl * 4, token.lost())
            .await
            .expect("holder must observe lease loss");

        let (closed_id, result) =
            close_channel_under_lease(session.operator_runtime.clone(), channel_id.clone(), token)
                .await;
        assert_eq!(closed_id, channel_id);
        let error = match result {
            Ok(_) => panic!("lost lease must abandon auto-close"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("capacity lease was lost"),
            "unexpected close error: {error}"
        );
        await_released(&url, &prefix, &channel_id, ttl).await;
        assert!(
            peer.reserve_delegated_capacity(&channel_id, 0)
                .await
                .unwrap()
                .is_some()
        );
    }
}
