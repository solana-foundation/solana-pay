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
use pay_kit::mpp::store::{
    ChannelLifecycle, ChannelState, ChannelStore, MemoryChannelStore, StoreError,
};
use pay_kit::mpp::{
    Base64UrlJson, CommitReceipt, OpenPayload, PaymentChallenge, SessionAction, SessionMode,
    SessionPullVoucherStrategy, SessionSettlementAuthority, SignedVoucher, VoucherData,
    VoucherPayload, parse_authorization,
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant};

use crate::server::telemetry;
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
    reserved_capacity: Arc<Mutex<HashMap<String, u64>>>,
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
    fn reserve_capacity(&self, channel_id: &str, amount: u64) -> bool {
        let Ok(mut reservations) = self.reserved_capacity.lock() else {
            return false;
        };
        if reservations.contains_key(channel_id) {
            return false;
        }
        reservations.insert(channel_id.to_string(), amount);
        true
    }
    fn release_capacity(&self, channel_id: &str) {
        if let Ok(mut reservations) = self.reserved_capacity.lock() {
            reservations.remove(channel_id);
        }
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
            telemetry::record_payment_channel_closed(&signature, &params.channel_id.to_string());
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
}

impl Drop for DelegatedCapacityLease {
    fn drop(&mut self) {
        self.runtime.release_capacity(&self.channel_id);
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

    async fn touch(&self, channel_id: String, touched_at_ms: u64) -> Result<Option<ChannelState>> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(SessionLifecycleCommand::Touch {
                channel_id,
                touched_at_ms,
                response: response_tx,
            })
            .map_err(|_| Error::Mpp("session lifecycle runloop is unavailable".to_string()))?;
        response_rx
            .await
            .map_err(|_| Error::Mpp("session lifecycle touch was cancelled".to_string()))?
            .map_err(Error::Mpp)
    }

    fn touch_unconfirmed(&self, channel_id: String, touched_at_ms: u64) {
        let (response, _discarded) = oneshot::channel();
        self.send(SessionLifecycleCommand::Touch {
            channel_id,
            touched_at_ms,
            response,
        });
    }
}

#[derive(Debug)]
enum SessionLifecycleCommand {
    Configure {
        close_delay: Option<Duration>,
        close_batch_interval: Duration,
        settlement_interval: Option<Duration>,
        reconciliation: SessionLifecycleReconciliation,
    },
    Touch {
        channel_id: String,
        touched_at_ms: u64,
        response: oneshot::Sender<std::result::Result<Option<ChannelState>, String>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLifecycleReconciliation {
    /// This process owns the lifecycle clock and closes due channels.
    Embedded,
    /// This process only persists touches; an external worker owns the clock.
    External,
}

const LIFECYCLE_OWNER_LEASE_PREFIX: &str = "embedded-v1:";
const MIN_LIFECYCLE_OWNER_LEASE: Duration = Duration::from_secs(30);

fn parse_lifecycle_owner_lease(owner: &str) -> Option<(&str, u64)> {
    let owner = owner.strip_prefix(LIFECYCLE_OWNER_LEASE_PREFIX)?;
    let (owner_id, expires_at_ms) = owner.rsplit_once(':')?;
    Some((owner_id, expires_at_ms.parse().ok()?))
}

struct SessionLifecycleRunloop {
    runtime: SessionOperatorRuntime,
    owner: String,
    close_delay: Option<Duration>,
    close_batch_interval: Duration,
    settlement_interval: Option<Duration>,
    next_settlement: Option<Instant>,
    reconciliation: SessionLifecycleReconciliation,
    rx: mpsc::UnboundedReceiver<SessionLifecycleCommand>,
}

impl SessionLifecycleRunloop {
    fn new(
        runtime: SessionOperatorRuntime,
        rx: mpsc::UnboundedReceiver<SessionLifecycleCommand>,
    ) -> Self {
        Self {
            runtime,
            owner: uuid::Uuid::new_v4().to_string(),
            close_delay: None,
            close_batch_interval: Duration::from_secs(60),
            settlement_interval: None,
            next_settlement: None,
            reconciliation: SessionLifecycleReconciliation::Embedded,
            rx,
        }
    }

    async fn run(mut self) {
        loop {
            if let Some(delay) = self.next_wakeup_delay() {
                tokio::select! {
                    command = self.rx.recv() => {
                        if !self.handle_command(command).await {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(delay) => {
                        if self.reconciliation == SessionLifecycleReconciliation::Embedded {
                            self.reconcile_persisted_ownership().await;
                            self.close_due_channels().await;
                        }
                        self.push_due_watermarks().await;
                    }
                }
            } else {
                let command = self.rx.recv().await;
                if !self.handle_command(command).await {
                    break;
                }
            }
        }
    }

    async fn handle_command(&mut self, command: Option<SessionLifecycleCommand>) -> bool {
        match command {
            Some(SessionLifecycleCommand::Configure {
                close_delay,
                close_batch_interval,
                settlement_interval,
                reconciliation,
            }) => {
                self.close_delay = close_delay;
                self.close_batch_interval = close_batch_interval;
                self.settlement_interval = settlement_interval;
                self.next_settlement =
                    settlement_interval.map(|interval| Instant::now() + interval);
                self.reconciliation = reconciliation;
                if reconciliation == SessionLifecycleReconciliation::Embedded {
                    self.reconcile_persisted_ownership().await;
                }
                true
            }
            Some(SessionLifecycleCommand::Touch {
                channel_id,
                touched_at_ms,
                response,
            }) => {
                let result = self
                    .persist_touch(&channel_id, touched_at_ms)
                    .await
                    .map_err(|error| error.to_string());
                if let Err(error) = &result {
                    tracing::warn!(
                        channel_id,
                        error,
                        "failed to persist payment-channel lifecycle touch"
                    );
                }
                let _ = response.send(result);
                true
            }
            None => false,
        }
    }

    async fn persist_touch(
        &self,
        channel_id: &str,
        touched_at_ms: u64,
    ) -> Result<Option<ChannelState>> {
        let Some(close_delay) = self.close_delay else {
            return Ok(None);
        };
        let idle_deadline = touched_at_ms.saturating_add(duration_millis(close_delay));
        let close_after =
            round_up_timestamp(idle_deadline, duration_millis(self.close_batch_interval));
        let owner = if self.reconciliation == SessionLifecycleReconciliation::Embedded {
            self.leased_owner(unix_millis())
        } else {
            self.owner.clone()
        };
        let state = self
            .runtime
            .channel_store
            .touch_channel_lifecycle(channel_id, ChannelLifecycle { owner, close_after })
            .await
            .map_err(|error| {
                Error::Mpp(format!(
                    "failed to persist lifecycle deadline for {channel_id}: {error}"
                ))
            })?;
        Ok(Some(state))
    }

    fn lifecycle_owner_lease_duration(&self) -> Duration {
        self.close_batch_interval
            .saturating_mul(3)
            .max(MIN_LIFECYCLE_OWNER_LEASE)
    }

    fn leased_owner(&self, now_ms: u64) -> String {
        let expires_at_ms =
            now_ms.saturating_add(duration_millis(self.lifecycle_owner_lease_duration()));
        format!(
            "{LIFECYCLE_OWNER_LEASE_PREFIX}{}:{expires_at_ms}",
            self.owner
        )
    }

    fn owns_lifecycle(&self, lifecycle: &ChannelLifecycle) -> bool {
        parse_lifecycle_owner_lease(&lifecycle.owner)
            .map(|(owner, _)| owner == self.owner)
            .unwrap_or_else(|| lifecycle.owner == self.owner)
    }

    /// Renew this runloop's leases and atomically claim legacy or expired
    /// records. Active leases owned by another gateway are left untouched.
    async fn reconcile_persisted_ownership(&self) {
        let states = match self.runtime.channel_store.list_channels().await {
            Ok(states) => states,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "failed to enumerate payment channels for lifecycle ownership reconciliation"
                );
                return;
            }
        };
        let now_ms = unix_millis();
        let leased_owner = self.leased_owner(now_ms);
        for state in states {
            if state.sealed || state.close_requested_at.is_some() {
                continue;
            }
            if state.lifecycle.is_none() {
                continue;
            }
            let owner_id = self.owner.clone();
            let replacement_owner = leased_owner.clone();
            if let Err(error) = self
                .runtime
                .channel_store
                .update_channel(
                    &state.channel_id,
                    Box::new(move |current| {
                        let mut current = current
                            .ok_or_else(|| StoreError::Internal("Channel not found".to_string()))?;
                        if current.sealed || current.close_requested_at.is_some() {
                            return Ok(current);
                        }
                        let Some(lifecycle) = current.lifecycle.as_mut() else {
                            return Ok(current);
                        };
                        let claimable = parse_lifecycle_owner_lease(&lifecycle.owner).is_none_or(
                            |(current_owner, expires_at_ms)| {
                                current_owner == owner_id || expires_at_ms <= now_ms
                            },
                        );
                        if claimable {
                            lifecycle.owner = replacement_owner;
                        }
                        Ok(current)
                    }),
                )
                .await
            {
                // Redis reports a compare-and-set miss when another gateway
                // changed the record after this scan. The next scan reconciles
                // the new state, so this is expected contention rather than a
                // lifecycle failure.
                tracing::debug!(
                    channel_id = state.channel_id,
                    %error,
                    "payment-channel lifecycle ownership changed during reconciliation"
                );
            }
        }
    }

    fn next_wakeup_delay(&self) -> Option<Duration> {
        let close = if self.reconciliation == SessionLifecycleReconciliation::Embedded
            && self.close_delay.is_some()
        {
            Some(duration_until_next_boundary(self.close_batch_interval))
        } else {
            None
        };
        let settlement = self
            .next_settlement
            .map(|deadline| deadline.saturating_duration_since(Instant::now()));
        match (close, settlement) {
            (Some(close), Some(settlement)) => Some(close.min(settlement)),
            (Some(close), None) => Some(close),
            (None, Some(settlement)) => Some(settlement),
            (None, None) => None,
        }
    }

    async fn close_due_channels(&mut self) {
        if self.close_delay.is_none() {
            return;
        }
        let now_ms = unix_millis();
        let states = match self.runtime.channel_store.list_channels().await {
            Ok(states) => states,
            Err(error) => {
                tracing::warn!(%error, "failed to enumerate payment-channel lifecycle state");
                return;
            }
        };
        let due = states
            .into_iter()
            .filter(|state| !state.sealed && state.close_requested_at.is_none())
            .filter_map(|state| {
                state
                    .lifecycle
                    .as_ref()
                    .filter(|lifecycle| {
                        self.owns_lifecycle(lifecycle) && lifecycle.close_after <= now_ms
                    })
                    .map(|_| state.channel_id)
            })
            .collect::<Vec<_>>();

        let mut closing = Vec::with_capacity(due.len());
        for channel_id in due {
            // Closing and serving both claim the same channel slot. This makes
            // the reservation check atomic with the start of close: a request
            // already in flight defers close, while a close already in progress
            // prevents a new request from reserving stale capacity.
            if !self.runtime.reserve_capacity(&channel_id, 0) {
                if let Err(error) = self.persist_touch(&channel_id, now_ms).await {
                    tracing::warn!(channel_id, %error, "failed to defer busy channel close");
                }
                continue;
            }
            let runtime = self.runtime.clone();
            closing.push(async move {
                let result = runtime.operator_close_channel(&channel_id).await;
                (channel_id, result)
            });
        }

        for (channel_id, close_result) in futures_util::future::join_all(closing).await {
            self.runtime.release_capacity(&channel_id);
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
                    if let Err(touch_error) = self.persist_touch(&channel_id, unix_millis()).await {
                        tracing::warn!(
                            channel_id,
                            error = %touch_error,
                            "failed to reschedule payment-channel close"
                        );
                    }
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

        let states = match self.runtime.channel_store.list_channels().await {
            Ok(states) => states,
            Err(error) => {
                tracing::warn!(%error, "failed to enumerate active payment channels");
                self.next_settlement = Some(now + interval);
                return;
            }
        };
        let channels = states
            .into_iter()
            .filter(|state| !state.sealed && state.close_requested_at.is_none())
            .filter(|state| {
                state
                    .lifecycle
                    .as_ref()
                    .is_some_and(|lifecycle| self.owns_lifecycle(lifecycle))
            })
            .map(|state| state.channel_id)
            .collect::<Vec<_>>();
        let mut settlements = Vec::with_capacity(channels.len());
        for channel_id in channels {
            if !self.runtime.reserve_capacity(&channel_id, 0) {
                continue;
            }
            let runtime = self.runtime.clone();
            settlements.push(async move {
                let result = runtime.operator_push_watermark(&channel_id).await;
                (channel_id, result)
            });
        }
        for (channel_id, result) in futures_util::future::join_all(settlements).await {
            self.runtime.release_capacity(&channel_id);
            if let Err(error) = result {
                tracing::warn!(
                    channel_id,
                    error = %error,
                    "operator watermark push failed; retrying next interval"
                );
            }
        }

        self.next_settlement = Some(now + interval);
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(duration_millis)
        .unwrap_or_default()
}

fn round_up_timestamp(timestamp_ms: u64, interval_ms: u64) -> u64 {
    if interval_ms == 0 {
        return timestamp_ms;
    }
    let remainder = timestamp_ms % interval_ms;
    if remainder == 0 {
        timestamp_ms
    } else {
        timestamp_ms.saturating_add(interval_ms - remainder)
    }
}

fn duration_until_next_boundary(interval: Duration) -> Duration {
    let now = unix_millis();
    let next = round_up_timestamp(now.saturating_add(1), duration_millis(interval));
    Duration::from_millis(next.saturating_sub(now))
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
        let session_config = config.clone();
        let server = Arc::new(SessionServer::new(config, Arc::clone(&channel_store)));
        let payment_channel_signer = Arc::new(Mutex::new(None));
        let payment_channel_payer_signer = Arc::new(Mutex::new(None));
        let committed_watermarks = Arc::new(Mutex::new(HashMap::new()));
        let reserved_capacity = Arc::new(Mutex::new(HashMap::new()));
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
            reserved_capacity: Arc::clone(&reserved_capacity),
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
        self.start_lifecycle_runloop_with_settlement_and_batching(
            close_delay,
            close_delay,
            Duration::ZERO,
            SessionLifecycleReconciliation::Embedded,
        );
    }

    /// Configure the lifecycle runloop to reconcile active channels' latest
    /// cumulative voucher on-chain and to settle+seal channels after an idle
    /// period. Either duration may be zero to disable that behavior.
    pub fn start_lifecycle_runloop_with_settlement(
        &self,
        close_delay: Duration,
        settlement_interval: Duration,
    ) {
        self.start_lifecycle_runloop_with_settlement_and_batching(
            close_delay,
            close_delay,
            settlement_interval,
            SessionLifecycleReconciliation::Embedded,
        );
    }

    /// Configure store-backed lifecycle scheduling.
    ///
    /// Every request persists its rounded idle deadline through
    /// [`ChannelStore`]. In external mode this process does not own the clock;
    /// a durable reconciliation worker closes due channels.
    pub fn start_lifecycle_runloop_with_settlement_and_batching(
        &self,
        close_delay: Duration,
        close_batch_interval: Duration,
        settlement_interval: Duration,
        reconciliation: SessionLifecycleReconciliation,
    ) {
        let close_delay = (!close_delay.is_zero()).then_some(close_delay);
        let close_batch_interval = if close_batch_interval.is_zero() {
            Duration::from_secs(60)
        } else {
            close_batch_interval
        };
        let settlement_interval = (reconciliation == SessionLifecycleReconciliation::Embedded
            && !settlement_interval.is_zero())
        .then_some(settlement_interval);
        self.lifecycle.send(SessionLifecycleCommand::Configure {
            close_delay,
            close_batch_interval,
            settlement_interval,
            reconciliation,
        });
        tracing::info!(
            close_delay_ms = close_delay.map(|delay| delay.as_millis()),
            close_batch_interval_ms = close_batch_interval.as_millis(),
            settlement_interval_ms = settlement_interval.map(|interval| interval.as_millis()),
            reconciliation = ?reconciliation,
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
        telemetry::record_payment_channel_voucher_cumulative(
            channel_id,
            self.currency(),
            self.network(),
            accepted.cumulative,
        );
        self.record_committed_watermark(channel_id.to_string(), accepted.cumulative);
        self.touch_channel(channel_id.to_string()).await?;
        Ok(accepted.cumulative)
    }

    pub async fn reserve_delegated_capacity(
        &self,
        channel_id: &str,
        amount: u64,
    ) -> Result<Option<DelegatedCapacityLease>> {
        self.touch_channel(channel_id.to_string()).await?;
        Ok(self
            .operator_runtime
            .reserve_capacity(channel_id, amount)
            .then(|| DelegatedCapacityLease {
                runtime: self.operator_runtime.clone(),
                channel_id: channel_id.to_string(),
            }))
    }

    /// Record channel activity so the lifecycle runloop can defer auto-close.
    pub async fn touch_channel(&self, channel_id: impl Into<String>) -> Result<()> {
        let channel_id = channel_id.into();
        if self
            .pull_sessions
            .lock()
            .map(|sessions| sessions.contains(&channel_id))
            .unwrap_or(false)
        {
            return Ok(());
        }
        if let Some(state) = self.lifecycle.touch(channel_id, unix_millis()).await?
            && (state.sealed || state.close_requested_at.is_some())
        {
            return Err(Error::PaymentRejected(
                "payment channel close is pending".to_string(),
            ));
        }
        Ok(())
    }

    /// Queue a best-effort lifecycle extension for a request that has already
    /// performed a confirmed wake-up. Streaming paths use this to avoid a
    /// Redis round trip per response chunk while still extending long-lived
    /// requests.
    pub fn touch_channel_unconfirmed(&self, channel_id: impl Into<String>) {
        let channel_id = channel_id.into();
        if self
            .pull_sessions
            .lock()
            .map(|sessions| sessions.contains(&channel_id))
            .unwrap_or(false)
        {
            return;
        }
        self.lifecycle.touch_unconfirmed(channel_id, unix_millis());
    }

    /// Latest cumulative watermark accepted by this process for a session.
    pub fn committed_watermark(&self, session_id: &str) -> Option<u64> {
        self.committed_watermarks
            .lock()
            .ok()
            .and_then(|watermarks| watermarks.get(session_id).copied())
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

                // A replayed transaction signature can remain confirmed long
                // after its channel account has been reclaimed. Solana RPC may
                // return "already processed" on re-submission, and signature
                // confirmation alone cannot distinguish that stale replay
                // from a newly landed open. Before creating durable state,
                // require the channel itself to exist at confirmed commitment.
                //
                // Keep absence and RPC failure distinct: `Ok(None)` is a stale
                // open, while `Err` is propagated so an unavailable RPC can
                // never cause Redis state to be created or deleted.
                let payment_channel_open = p.mode == SessionMode::Push || client_voucher_pull;
                let (account_confirmed, client_id) = if let (true, Some(rpc_url)) =
                    (payment_channel_open, self.rpc_url.as_deref())
                {
                    let client_id = self
                        .payment_channel_open_params(payload_for_open)?
                        .payer
                        .to_string();
                    let signature = payload_for_open.signature.as_str();
                    let channel_id = payload_for_open
                        .session_id()
                        .map_err(|e| Error::Mpp(format!("Invalid session channel: {e}")))?;
                    wait_for_transaction_confirmed(rpc_url, signature, "payment-channel open")
                        .await?;
                    if self
                        .operator_runtime
                        .fetch_payment_channel(channel_id)
                        .await?
                        .is_none()
                    {
                        return Err(Error::Mpp(format!(
                            "payment-channel open transaction is confirmed, but channel {channel_id} is absent on-chain"
                        )));
                    }
                    (true, Some(client_id))
                } else {
                    (false, None)
                };

                // The host has independently validated, co-signed, submitted,
                // and observed a successful status for transactions it
                // broadcasts. Persist those opens without asking a second RPC
                // client to rediscover the same signature. Opens received by
                // any other integration retain PayKit's standard verification.
                let acceptance = if submitted_open.is_some() {
                    self.server
                        .process_preverified_open_with_outcome(payload_for_open)
                        .await
                } else {
                    self.server
                        .process_open_with_outcome(payload_for_open)
                        .await
                }
                .map_err(|e| Error::Mpp(format!("Session open failed: {e}")))?;
                let state = acceptance.state;

                if !acceptance.replay
                    && account_confirmed
                    && let Some(client_id) = client_id.as_deref()
                {
                    telemetry::record_payment_channel_opened(
                        &payload_for_open.signature,
                        &state.channel_id.to_string(),
                        client_id,
                        self.currency(),
                        self.network(),
                        state.deposit,
                    );
                }

                if p.mode == SessionMode::Pull && !client_voucher_pull {
                    self.record_pull_session(state.channel_id.clone());
                }
                self.record_committed_watermark(state.channel_id.clone(), state.cumulative);
                self.touch_channel(state.channel_id.clone()).await?;
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
                telemetry::record_payment_channel_voucher_cumulative(
                    &channel_id,
                    self.currency(),
                    self.network(),
                    cumulative,
                );
                self.record_committed_watermark(channel_id.clone(), cumulative);
                self.touch_channel(channel_id.clone()).await?;
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
                    telemetry::record_payment_channel_voucher_cumulative(
                        &receipt.session_id,
                        self.currency(),
                        self.network(),
                        cumulative,
                    );
                    self.record_committed_watermark(receipt.session_id.clone(), cumulative);
                }
                self.touch_channel(receipt.session_id.clone()).await?;
                Ok(SessionOutcome::Commit(receipt))
            }

            SessionAction::TopUp(p) => {
                let state = self
                    .server
                    .process_topup(p)
                    .await
                    .map_err(|e| Error::Mpp(format!("TopUp failed: {e}")))?;
                self.record_committed_watermark(state.channel_id.clone(), state.cumulative);
                self.touch_channel(state.channel_id.clone()).await?;
                Ok(SessionOutcome::Active {
                    state,
                    signature: Some(p.signature.clone()),
                })
            }

            SessionAction::Close(p) => {
                let _lease = self
                    .reserve_delegated_capacity(&p.channel_id, 0)
                    .await?
                    .ok_or_else(|| {
                        Error::Mpp(format!(
                            "Session channel {} is busy with another request",
                            p.channel_id
                        ))
                    })?;
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
                telemetry::record_payment_channel_voucher_cumulative(
                    &params.channel_id.to_string(),
                    self.currency(),
                    self.network(),
                    params.settled,
                );
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
                            .map_err(|e| {
                                Error::Mpp(format!("Failed to mark session sealed: {e}"))
                            })?;
                        None
                    }
                    Err(error) => return Err(error),
                };
                if let Some(signature) = signature.as_ref() {
                    self.server
                        .mark_sealed(&params.channel_id.to_string())
                        .await
                        .map_err(|e| Error::Mpp(format!("Failed to mark session sealed: {e}")))?;
                    self.operator_runtime.record_settlement_signature(
                        params.channel_id.to_string(),
                        signature.clone(),
                    );
                    telemetry::record_payment_channel_closed(
                        signature,
                        &params.channel_id.to_string(),
                    );
                }
                Ok(SessionOutcome::Closed { params, signature })
            }
        }
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
        self.touch_channel(session_id).await?;
        Ok(directive)
    }

    // ── Private helpers ──────────────────────────────────────────────────────

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

    #[test]
    fn lifecycle_deadlines_round_up_to_batch_boundary() {
        assert_eq!(round_up_timestamp(120_000, 60_000), 120_000);
        assert_eq!(round_up_timestamp(120_001, 60_000), 180_000);
        assert_eq!(round_up_timestamp(u64::MAX - 10, 60_000), u64::MAX);
        assert_eq!(round_up_timestamp(123, 0), 123);
    }

    #[tokio::test]
    async fn external_lifecycle_persists_deadline_without_closing_locally() {
        let session = Arc::new(test_session_mpp());
        session.start_lifecycle_runloop_with_settlement_and_batching(
            Duration::from_millis(10),
            Duration::from_millis(10),
            Duration::ZERO,
            SessionLifecycleReconciliation::External,
        );
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

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let persisted = session
                    .operator_runtime
                    .channel_store
                    .get_channel(&opened.channel_id)
                    .await
                    .unwrap()
                    .unwrap();
                if persisted.lifecycle.is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lifecycle touch should be persisted");

        tokio::time::sleep(Duration::from_millis(60)).await;

        let persisted = session
            .operator_runtime
            .channel_store
            .get_channel(&opened.channel_id)
            .await
            .unwrap()
            .unwrap();
        assert!(persisted.lifecycle.is_some());
        assert!(
            persisted.close_requested_at.is_none(),
            "external mode must leave close ownership to the worker"
        );

        session
            .operator_runtime
            .channel_store
            .update_channel(
                &opened.channel_id,
                Box::new(|state| {
                    let mut state = state.unwrap();
                    state.close_requested_at = Some(1);
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        let error = session
            .touch_channel(opened.channel_id)
            .await
            .expect_err("a worker-claimed close cannot be woken");
        assert!(error.to_string().contains("close is pending"));
    }

    #[tokio::test]
    async fn embedded_lifecycle_adopts_persisted_deadlines_after_restart() {
        let store: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::new());
        let config = test_session_config();
        let first =
            SessionMpp::new_with_channel_store(config.clone(), "test-secret", Arc::clone(&store));
        first.start_lifecycle_runloop_with_settlement_and_batching(
            Duration::from_secs(3600),
            Duration::from_secs(60),
            Duration::ZERO,
            SessionLifecycleReconciliation::External,
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
            panic!("expected open to return active session");
        };

        let persisted = store
            .get_channel(&opened.channel_id)
            .await
            .unwrap()
            .unwrap();
        let original = persisted.lifecycle.expect("deadline should be persisted");
        drop(first);

        let restarted =
            SessionMpp::new_with_channel_store(config, "test-secret", Arc::clone(&store));
        restarted.start_lifecycle_runloop_with_settlement_and_batching(
            Duration::from_secs(3600),
            Duration::from_secs(60),
            Duration::ZERO,
            SessionLifecycleReconciliation::Embedded,
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let persisted = store
                    .get_channel(&opened.channel_id)
                    .await
                    .unwrap()
                    .unwrap();
                let lifecycle = persisted.lifecycle.unwrap();
                if lifecycle.owner != original.owner {
                    assert_eq!(lifecycle.close_after, original.close_after);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("restarted embedded worker should adopt the persisted deadline");
    }

    #[tokio::test]
    async fn embedded_lifecycle_preserves_live_owner_then_reclaims_expired_lease() {
        let store: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::new());
        let session = SessionMpp::new_with_channel_store(
            test_session_config(),
            "test-secret",
            Arc::clone(&store),
        );
        session.start_lifecycle_runloop_with_settlement_and_batching(
            Duration::from_secs(3600),
            Duration::from_secs(60),
            Duration::ZERO,
            SessionLifecycleReconciliation::External,
        );
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

        let live_owner = "other-live-gateway";
        let live_lease = format!(
            "{LIFECYCLE_OWNER_LEASE_PREFIX}{live_owner}:{}",
            unix_millis().saturating_add(60_000)
        );
        let original_deadline = store
            .update_channel(
                &opened.channel_id,
                Box::new({
                    let live_lease = live_lease.clone();
                    move |state| {
                        let mut state = state.unwrap();
                        let lifecycle = state.lifecycle.as_mut().unwrap();
                        lifecycle.owner = live_lease;
                        Ok(state)
                    }
                }),
            )
            .await
            .unwrap()
            .lifecycle
            .unwrap()
            .close_after;

        let (_tx, rx) = mpsc::unbounded_channel();
        let contender = SessionLifecycleRunloop::new(session.operator_runtime.clone(), rx);
        contender.reconcile_persisted_ownership().await;

        let persisted = store
            .get_channel(&opened.channel_id)
            .await
            .unwrap()
            .unwrap()
            .lifecycle
            .unwrap();
        assert_eq!(
            persisted.owner, live_lease,
            "a live gateway must retain lifecycle ownership"
        );
        assert_eq!(persisted.close_after, original_deadline);

        store
            .update_channel(
                &opened.channel_id,
                Box::new(move |state| {
                    let mut state = state.unwrap();
                    state.lifecycle.as_mut().unwrap().owner =
                        format!("{LIFECYCLE_OWNER_LEASE_PREFIX}{live_owner}:0");
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        contender.reconcile_persisted_ownership().await;

        let reclaimed = store
            .get_channel(&opened.channel_id)
            .await
            .unwrap()
            .unwrap()
            .lifecycle
            .unwrap();
        let (reclaimed_owner, expires_at_ms) =
            parse_lifecycle_owner_lease(&reclaimed.owner).expect("owner should contain a lease");
        assert_eq!(reclaimed_owner, contender.owner);
        assert!(expires_at_ms > unix_millis());
        assert_eq!(
            reclaimed.close_after, original_deadline,
            "ownership transfer must preserve the existing close deadline"
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
    async fn delegated_capacity_reservation_persists_idle_deadline_before_returning() {
        let session = Arc::new(test_session_mpp());
        let close_delay = Duration::from_secs(120);
        session.start_lifecycle_runloop_with_settlement_and_batching(
            close_delay,
            Duration::from_secs(60),
            Duration::ZERO,
            SessionLifecycleReconciliation::External,
        );
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
        session
            .operator_runtime
            .channel_store
            .update_channel(
                &opened.channel_id,
                Box::new(|state| {
                    let mut state = state.unwrap();
                    state.lifecycle.as_mut().unwrap().close_after = 1;
                    Ok(state)
                }),
            )
            .await
            .unwrap();

        let touched_after = unix_millis();
        let _lease = session
            .reserve_delegated_capacity(&opened.channel_id, CAP)
            .await
            .unwrap()
            .expect("request should reserve channel capacity");

        let persisted = session
            .operator_runtime
            .channel_store
            .get_channel(&opened.channel_id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            persisted.lifecycle.unwrap().close_after
                >= touched_after.saturating_add(duration_millis(close_delay)),
            "capacity reservation must persist the request-start deadline before forwarding"
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
