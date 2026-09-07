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
use pay_kit::core::tx_pipeline::{TxPipeline, TxPipelineError};
use pay_kit::mpp::blockhash::BlockhashCache;
use pay_kit::mpp::server::session::{SealParams, SessionConfig, SessionOpenContext, SessionServer};
use pay_kit::mpp::settlement::worker::{RpcBroadcaster, SettlementConfig, SettlementHandle, spawn};
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_kit::mpp::store::{
    ChannelLifecycle, ChannelState, ChannelStore, MemoryChannelStore, StoreError,
};
use pay_kit::mpp::{
    Base64UrlJson, ChallengeEcho, PaymentChallenge, SessionAction, SessionRequest,
    SessionVoucherSigner, SignedVoucher, UsePayload, VoucherData, VoucherPayload,
    VoucherSignatureType, parse_authorization,
};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Duration, Instant};

use crate::server::telemetry;
use crate::{Error, Result};

const INTENT: &str = "session";
const METHOD: &str = "solana";
const DEFAULT_REALM: &str = "MPP Session";

const VERIFIED_CHALLENGE_CACHE_ENTRIES: usize = 1_024;

thread_local! {
    /// Challenge echoes rotate slowly compared with voucher traffic. Keep a
    /// tiny worker-local cache so a valid echo is HMAC-checked and its embedded
    /// session request decoded once per worker, rather than once per voucher.
    /// Every echoed field and the binding secret are compared on a hit; an id
    /// collision or altered echo therefore still takes the fail-closed path.
    static VERIFIED_CHALLENGES: RefCell<VerifiedChallengeCache> =
        RefCell::new(VerifiedChallengeCache::default());
}

#[derive(Default)]
struct VerifiedChallengeCache {
    entries: HashMap<String, VerifiedChallenge>,
    insertion_order: VecDeque<String>,
}

impl VerifiedChallengeCache {
    fn get(&self, binding_secret: &str, echo: &ChallengeEcho) -> Option<SessionRequest> {
        self.entries
            .get(&echo.id)
            .filter(|cached| cached.matches(binding_secret, echo))
            .map(|cached| cached.decoded.clone())
    }

    fn insert(&mut self, binding_secret: &str, echo: &ChallengeEcho, decoded: SessionRequest) {
        if self.entries.contains_key(&echo.id) {
            self.entries.insert(
                echo.id.clone(),
                VerifiedChallenge::new(binding_secret, echo, decoded),
            );
            return;
        }
        while self.entries.len() >= VERIFIED_CHALLENGE_CACHE_ENTRIES {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.insertion_order.push_back(echo.id.clone());
        self.entries.insert(
            echo.id.clone(),
            VerifiedChallenge::new(binding_secret, echo, decoded),
        );
    }
}

#[derive(Clone)]
struct VerifiedChallenge {
    binding_secret: String,
    id: String,
    realm: String,
    method: String,
    intent: String,
    request: String,
    expires: Option<String>,
    digest: Option<String>,
    opaque: Option<String>,
    decoded: SessionRequest,
}

impl VerifiedChallenge {
    fn matches(&self, binding_secret: &str, echo: &ChallengeEcho) -> bool {
        self.binding_secret == binding_secret
            && self.id == echo.id
            && self.realm == echo.realm
            && self.method == echo.method.as_str()
            && self.intent == echo.intent.as_str()
            && self.request == echo.request.raw()
            && self.expires == echo.expires
            && self.digest == echo.digest
            && self.opaque.as_deref() == echo.opaque.as_ref().map(Base64UrlJson::raw)
    }

    fn new(binding_secret: &str, echo: &ChallengeEcho, decoded: SessionRequest) -> Self {
        Self {
            binding_secret: binding_secret.to_string(),
            id: echo.id.clone(),
            realm: echo.realm.clone(),
            method: echo.method.as_str().to_string(),
            intent: echo.intent.as_str().to_string(),
            request: echo.request.raw().to_string(),
            expires: echo.expires.clone(),
            digest: echo.digest.clone(),
            opaque: echo.opaque.as_ref().map(|value| value.raw().to_string()),
            decoded,
        }
    }
}

/// Rejection message fragments for session errors that will never clear on
/// retry: the channel, credential, or proof they name cannot become valid
/// again without a fresh session. A payer proxy caching a `use` credential
/// must treat any of these as proof the cached session is dead, not a
/// transient store hiccup — pinned here so the two sides can't drift apart.
pub mod terminal_errors {
    /// The channel a cached credential names no longer exists in the store.
    pub const UNKNOWN_CHANNEL: &str = "unknown session channel";
    /// The credential's challenge echo does not verify against this server's
    /// challenge-binding secret (forged, replayed, or for a different server).
    pub const CHALLENGE_ECHO_MISMATCH: &str =
        "session credential echoes a challenge this server did not issue";
    /// A `use` action against a channel that isn't operator-signed.
    pub const OPERATOR_ONLY: &str = "use is only valid for operator-signed sessions";
    /// The channel predates reusable-proof binding; only re-opening fixes it.
    pub const PREDATES_PROOF_BINDING: &str = "predates proof binding";
    /// The bearer proof presented doesn't match what was bound at open.
    pub const PROOF_MISMATCH: &str = "does not match the proof bound at open";
}
fn session_close_already_finalized(message: &str) -> bool {
    message.contains("already finalized")
}

fn session_close_needs_reconciliation(message: &str) -> bool {
    message.contains("Close already requested") || message.contains("Channel is already sealed")
}

// ── Session outcome ────────────────────────────────────────────────────────

/// The result of processing a session action.
#[derive(Debug)]
pub enum SessionOutcome {
    /// `open` or `topup` — channel state after the action and the on-chain
    /// transaction signature that authorized it.
    Active {
        /// Boxed: this is by far the largest payload in the enum, and every
        /// other variant would otherwise be moved around at its size.
        state: Box<ChannelState>,
        signature: Option<String>,
    },
    /// `voucher` accepted — channel id + new settled cumulative (base units).
    Voucher { channel_id: String, cumulative: u64 },
    /// `close` accepted — `SealParams` carries what's needed to submit the
    /// on-chain settle+seal + distribute transactions.
    Closed {
        /// Boxed for the same reason as `Active`'s state: it is large enough
        /// that carrying it inline would size the whole enum by it.
        params: Box<SealParams>,
        signature: Option<String>,
    },
}

/// State needed to emit a canonical receipt after delegated usage is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegatedUsageAuthorization {
    pub cumulative: u64,
    pub idle_timeout_seconds: u32,
}

#[derive(Clone)]
struct SessionOperatorRuntime {
    server: Arc<SessionServer<Arc<dyn ChannelStore>>>,
    channel_store: Arc<dyn ChannelStore>,
    rpc_url: Option<String>,
    network: String,
    token_program: String,
    payment_channel_signer: Arc<Mutex<Option<Arc<dyn SolanaSigner>>>>,
    payment_channel_payer_signer: Arc<Mutex<Option<Arc<dyn SolanaSigner>>>>,
    committed_watermarks: Arc<dashmap::DashMap<String, u64>>,
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
    async fn transaction_pipeline(&self) -> Result<TxPipeline> {
        self.server
            .transaction_pipeline()
            .await
            .map_err(|error| Error::Mpp(format!("payment-channel RPC pipeline: {error}")))
    }

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
        self.committed_watermarks
            .entry(session_id.into())
            .and_modify(|current| *current = (*current).max(cumulative))
            .or_insert(cumulative);
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
    async fn operator_push_watermark(&self, channel_id: &str) -> Result<bool> {
        let Some(signer) = self.payment_channel_signer() else {
            // Verification-only servers have no authority to settle. Idle
            // close retains its existing no-op behavior for these instances.
            return Ok(false);
        };
        if self.rpc_url.is_none() {
            return Ok(false);
        }
        let tx_pipeline = self.transaction_pipeline().await?;
        let params = self
            .server
            .seal_params(channel_id)
            .await
            .map_err(|e| Error::Mpp(format!("Failed to get watermark params: {e}")))?;
        if params.settled == 0 {
            return Ok(false);
        }

        let channel = self.fetch_payment_channel(channel_id).await?;
        let Some(channel) = channel else {
            // A missing/deallocated channel has nothing left to settle.
            return Ok(false);
        };
        // Only OPEN channels accept an intermediate settle. CLOSING/SEALED/
        // DISTRIBUTED channels are already advancing through the close path.
        if channel.status != 0 || channel.settlement.settled >= params.settled {
            return Ok(false);
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
                let tx_pipeline = tx_pipeline.clone();
                async move {
                    spawn(
                        SettlementConfig::new(operator, signer),
                        Arc::new(RpcBroadcaster::with_pipeline(tx_pipeline)),
                    )
                }
            })
            .await;
        let signature = handle
            .settle(params.channel_id.to_string(), instructions)
            .await
            .map_err(|e| Error::Mpp(format!("payment-channel watermark settlement: {e}")))?;
        tracing::debug!(
            channel_id,
            cumulative = params.settled,
            %signature,
            "payment-channel watermark broadcast"
        );
        Ok(true)
    }

    /// Record a server-initiated close request on the channel state.
    ///
    /// The wire `close` action authenticates the caller (client voucher or
    /// operator-bound payer proof), so idle close cannot go through
    /// [`SessionServer::process_close`] — the server closes on its own
    /// authority and seals at the highest accepted watermark.
    async fn request_server_close(&self, channel_id: &str) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.channel_store
            .update_channel(
                channel_id,
                Box::new(move |state| {
                    let mut state = state
                        .ok_or_else(|| StoreError::Internal("Channel not found".to_string()))?;
                    if state.sealed {
                        return Err(StoreError::Internal(
                            "Channel is already sealed".to_string(),
                        ));
                    }
                    if state.close_requested_at.is_some() {
                        return Err(StoreError::Internal("Close already requested".to_string()));
                    }
                    state.close_requested_at = Some(now);
                    Ok(state)
                }),
            )
            .await
            .map_err(|error| Error::Mpp(format!("Session auto-close failed: {error}")))?;
        Ok(())
    }

    async fn operator_close_channel(&self, channel_id: &str) -> Result<SessionCloseResult> {
        if self.channel_is_tombstoned_on_chain(channel_id).await {
            self.server
                .mark_sealed(channel_id)
                .await
                .map_err(|e| Error::Mpp(format!("Failed to mark session sealed: {e}")))?;
            return Ok(SessionCloseResult::AlreadyFinalized);
        }

        match self.request_server_close(channel_id).await {
            Ok(()) => {}
            Err(error) if session_close_already_finalized(&error.to_string()) => {
                return Ok(SessionCloseResult::AlreadyFinalized);
            }
            Err(error) if session_close_needs_reconciliation(&error.to_string()) => {}
            Err(error) => return Err(error),
        }
        let params = self
            .server
            .seal_params(channel_id)
            .await
            .map_err(|e| Error::Mpp(format!("Failed to get seal params: {e}")))?;

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
        if self.rpc_url.is_none() {
            return false;
        }
        let Ok(channel) = solana_pubkey::Pubkey::from_str(channel_id) else {
            return false;
        };
        let Ok(pipeline) = self.transaction_pipeline().await else {
            return false;
        };
        pipeline
            .read_account_data(channel, None)
            .await
            .map(|account| account.is_some_and(|data| data.as_slice() == [2]))
            .unwrap_or(false)
    }

    async fn fetch_payment_channel(
        &self,
        channel_id: &str,
    ) -> Result<
        Option<pay_kit::mpp::program::payment_channels::generated::generated::accounts::Channel>,
    > {
        if self.rpc_url.is_none() {
            return Ok(None);
        }
        let channel = solana_pubkey::Pubkey::from_str(channel_id)
            .map_err(|e| Error::Mpp(format!("invalid payment channel: {e}")))?;
        use pay_kit::mpp::program::payment_channels::generated::generated::accounts::Channel;
        let pipeline = self.transaction_pipeline().await?;
        pipeline
            .read_account_data(channel, None)
            .await
            .map_err(|error| Error::Mpp(format!("failed to fetch payment channel: {error}")))?
            .map(|data| {
                Channel::from_bytes(&data)
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
        let tx_pipeline = self.transaction_pipeline().await?;
        let payer = params
            .payer
            .ok_or_else(|| Error::Mpp("payment-channel settlement missing payer".to_string()))?;
        let mint = params
            .mint
            .ok_or_else(|| Error::Mpp("payment-channel settlement missing mint".to_string()))?;
        let authorized_signer = params.authorized_signer.ok_or_else(|| {
            Error::Mpp("payment-channel settlement missing authorized signer".to_string())
        })?;
        let token_program =
            solana_pubkey::Pubkey::from_str(&self.token_program).map_err(|error| {
                Error::Mpp(format!(
                    "invalid payment-channel token program {}: {error}",
                    self.token_program
                ))
            })?;
        let treasury = payment_channel_treasury_owner(&self.network)?;

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
                &treasury,
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
                let tx_pipeline = tx_pipeline.clone();
                async move {
                    spawn(
                        SettlementConfig::new(operator, signer),
                        Arc::new(RpcBroadcaster::with_pipeline(tx_pipeline)),
                    )
                }
            })
            .await;
        let signature = handle
            .settle(channel_id, instructions)
            .await
            .map_err(|e| Error::Mpp(format!("payment-channel settlement: {e}")))?;
        let parsed_signature = solana_signature::Signature::from_str(&signature)
            .map_err(|error| Error::Mpp(format!("invalid settlement signature: {error}")))?;
        match tx_pipeline.confirm(parsed_signature).await {
            Ok(_) => {}
            Err(TxPipelineError::TransactionFailed { reason, .. }) => {
                return Err(Error::Mpp(format!(
                    "payment-channel settlement transaction failed: {reason}"
                )));
            }
            Err(error) => {
                return Err(Error::Mpp(format!(
                    "payment-channel settlement was not confirmed: {error}"
                )));
            }
        }
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
    cancel: watch::Sender<bool>,
    heartbeat: tokio::task::JoinHandle<()>,
}

impl Drop for DelegatedCapacityLease {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        self.heartbeat.abort();
        self.runtime.release_capacity(&self.channel_id);
    }
}

#[derive(Clone)]
struct SessionLifecycleHandle {
    tx: mpsc::UnboundedSender<SessionLifecycleCommand>,
    touches_enabled: Arc<AtomicBool>,
}

impl SessionLifecycleHandle {
    fn send(&self, command: SessionLifecycleCommand) {
        if self.tx.send(command).is_err() {
            tracing::debug!("session lifecycle runloop is not accepting events");
        }
    }

    async fn touch(&self, channel_id: String, touched_at_ms: u64) -> Result<Option<ChannelState>> {
        if !self.touches_enabled.load(Ordering::Acquire) {
            return Ok(None);
        }
        self.touch_with_cancellation(channel_id, touched_at_ms, None)
            .await
    }

    async fn touch_with_cancellation(
        &self,
        channel_id: String,
        touched_at_ms: u64,
        cancellation: Option<watch::Receiver<bool>>,
    ) -> Result<Option<ChannelState>> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(SessionLifecycleCommand::Touch {
                channel_id,
                touched_at_ms,
                cancellation,
                response: response_tx,
            })
            .map_err(|_| Error::Mpp("session lifecycle runloop is unavailable".to_string()))?;
        response_rx
            .await
            .map_err(|_| Error::Mpp("session lifecycle touch was cancelled".to_string()))?
            .map_err(Error::Mpp)
    }

    fn touch_unconfirmed(&self, channel_id: String, touched_at_ms: u64) {
        if !self.touches_enabled.load(Ordering::Acquire) {
            return;
        }
        let (response, _discarded) = oneshot::channel();
        self.send(SessionLifecycleCommand::Touch {
            channel_id,
            touched_at_ms,
            cancellation: None,
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
        cancellation: Option<watch::Receiver<bool>>,
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
#[cfg(not(test))]
const DELEGATED_ACTIVITY_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(test)]
const DELEGATED_ACTIVITY_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(10);

async fn run_while_lease_active<T>(
    mut cancellation: watch::Receiver<bool>,
    operation: impl std::future::Future<Output = T>,
) -> Option<T> {
    if *cancellation.borrow() {
        return None;
    }
    tokio::select! {
        biased;
        _ = cancellation.changed() => None,
        result = operation => Some(result),
    }
}

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
    /// Rotating offset into the active-channel set for the per-cycle settlement
    /// cap, so successive cycles cover different channels (bounded settle age).
    settlement_cursor: usize,
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
            settlement_cursor: 0,
        }
    }

    async fn run(mut self) {
        loop {
            if let Some((delay, close_due)) = self.next_wakeup() {
                tokio::select! {
                    command = self.rx.recv() => {
                        if !self.handle_command(command).await {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(delay) => {
                        if close_due
                            && self.reconciliation == SessionLifecycleReconciliation::Embedded
                        {
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
                cancellation,
                response,
            }) => {
                let result = match cancellation {
                    Some(cancellation) => {
                        let Some(result) = run_while_lease_active(
                            cancellation,
                            self.persist_touch(&channel_id, touched_at_ms),
                        )
                        .await
                        else {
                            return true;
                        };
                        result
                    }
                    None => self.persist_touch(&channel_id, touched_at_ms).await,
                }
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
        let mut effective_delay_ms = duration_millis(close_delay);
        let negotiated_idle_timeout_seconds = self
            .runtime
            .channel_store
            .get_channel(channel_id)
            .await
            .map_err(|error| {
                Error::Mpp(format!(
                    "failed to load channel {channel_id} for lifecycle touch: {error}"
                ))
            })?
            .and_then(|state| state.idle_timeout_seconds);
        if let Some(idle_timeout_seconds) = negotiated_idle_timeout_seconds {
            effective_delay_ms =
                effective_delay_ms.min(u64::from(idle_timeout_seconds).saturating_mul(1_000));
        }
        let idle_deadline = touched_at_ms.saturating_add(effective_delay_ms);
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
        let close_lease = self
            .close_batch_interval
            .saturating_mul(3)
            .max(MIN_LIFECYCLE_OWNER_LEASE);
        let settlement_lease = self
            .settlement_interval
            .map(|interval| interval.saturating_mul(3))
            .unwrap_or_default();
        close_lease.max(settlement_lease)
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
            let locally_active_for_settlement = self.settlement_interval.is_some()
                && self
                    .runtime
                    .committed_watermarks
                    .contains_key(&state.channel_id);
            if state.lifecycle.is_none() && !locally_active_for_settlement {
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
                        if let Some(lifecycle) = current.lifecycle.as_mut() {
                            let claimable = parse_lifecycle_owner_lease(&lifecycle.owner)
                                .is_none_or(|(current_owner, expires_at_ms)| {
                                    current_owner == owner_id || expires_at_ms <= now_ms
                                });
                            if claimable {
                                lifecycle.owner = replacement_owner;
                            }
                        } else if locally_active_for_settlement {
                            current.lifecycle = Some(ChannelLifecycle {
                                owner: replacement_owner,
                                // Automatic close is disabled, so this field
                                // is ownership metadata only. A later finite
                                // close touch advances it monotonically.
                                close_after: now_ms,
                            });
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

    fn next_wakeup(&self) -> Option<(Duration, bool)> {
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
        next_lifecycle_wakeup(close, settlement)
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

        // Candidates are the channels this process has accepted vouchers for,
        // read directly from `committed_watermarks` (a DashMap updated on the
        // voucher hot path). Deriving candidacy here — rather than from the
        // lifecycle-ownership reconcile — decouples settlement from the
        // request-path lifecycle touch, which starves under high request load
        // and left busy channels unsettled until they went idle.
        // `operator_push_watermark` still reads each channel's stored voucher to
        // build the settle and skips any sealed/closing or already-settled.
        let mut all: Vec<String> = self
            .runtime
            .committed_watermarks
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        let active_count = all.len();
        // Optional per-cycle cap (PAY_SETTLEMENT_MAX_PER_CYCLE): settle at most
        // this many channels per cycle, rotating a cursor through the fleet so
        // every active channel settles within ceil(active / cap) cycles. Bounds
        // both the on-chain settle rate and the worst-case settle age. Unset =
        // settle every active channel every cycle (prior behavior).
        let channels = match settlement_max_per_cycle() {
            Some(cap) if all.len() > cap => {
                all.sort_unstable();
                let start = self.settlement_cursor % all.len();
                let slice: Vec<String> =
                    all.iter().cycle().skip(start).take(cap).cloned().collect();
                self.settlement_cursor = (start + cap) % all.len();
                slice
            }
            _ => all,
        };
        let candidate_count = channels.len();
        let cycle_started = Instant::now();
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
        let mut broadcast_count = 0usize;
        let mut failure_count = 0usize;
        // Each settlement does an on-chain getAccountInfo read. Draining the
        // whole set with an unbounded join_all bursts the RPC with tens of
        // thousands of concurrent reads (429s/timeouts) and backpressures the
        // request path. Bound in-flight reads so the burst is smoothed while the
        // cycle still completes well within the settlement interval.
        const SETTLEMENT_READ_CONCURRENCY: usize = 256;
        use futures_util::stream::StreamExt as _;
        let results: Vec<_> = futures_util::stream::iter(settlements)
            .buffer_unordered(SETTLEMENT_READ_CONCURRENCY)
            .collect()
            .await;
        for (channel_id, result) in results {
            self.runtime.release_capacity(&channel_id);
            match result {
                Ok(true) => broadcast_count += 1,
                Ok(false) => {}
                Err(error) => {
                    failure_count += 1;
                    tracing::warn!(
                        channel_id,
                        error = %error,
                        "operator watermark push failed; retrying next interval"
                    );
                }
            }
        }
        tracing::info!(
            active = active_count,
            candidates = candidate_count,
            broadcast = broadcast_count,
            skipped = candidate_count.saturating_sub(broadcast_count + failure_count),
            failed = failure_count,
            elapsed_ms = cycle_started.elapsed().as_millis(),
            "operator watermark cycle completed"
        );

        self.next_settlement = Some(now + interval);
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Per-cycle cap on how many active channels the settlement runloop pushes
/// on-chain, from `PAY_SETTLEMENT_MAX_PER_CYCLE`. `None`/unset/0 = no cap
/// (settle every active channel each cycle). Cached on first read. A cap bounds
/// the on-chain settle rate (RPC load) while the runloop rotates through the
/// fleet, so every active channel settles within ceil(active / cap) cycles.
fn settlement_max_per_cycle() -> Option<usize> {
    static CAP: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| {
        std::env::var("PAY_SETTLEMENT_MAX_PER_CYCLE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0)
    })
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

fn next_lifecycle_wakeup(
    close: Option<Duration>,
    settlement: Option<Duration>,
) -> Option<(Duration, bool)> {
    match (close, settlement) {
        (Some(close), Some(settlement)) if close <= settlement => Some((close, true)),
        (Some(_), Some(settlement)) => Some((settlement, false)),
        (Some(close), None) => Some((close, true)),
        (None, Some(settlement)) => Some((settlement, false)),
        (None, None) => None,
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
/// Payment-channel sessions submit a client-signed open transaction that
/// PayKit verifies against the challenge, broadcasts, and confirms.
pub struct SessionMpp {
    server: Arc<SessionServer<Arc<dyn ChannelStore>>>,
    session_config: SessionConfig,
    challenge_binding_secret: String,
    realm: String,
    payment_channel_signer: Arc<Mutex<Option<Arc<dyn SolanaSigner>>>>,
    payment_channel_payer_signer: Arc<Mutex<Option<Arc<dyn SolanaSigner>>>>,
    committed_watermarks: Arc<dashmap::DashMap<String, u64>>,
    lifecycle: SessionLifecycleHandle,
    operator_runtime: SessionOperatorRuntime,
    /// When true, a client voucher for a channel this process never opened
    /// lazily loads the channel from chain (resuming from its on-chain settled
    /// watermark) instead of rejecting it. Enables reusing channels opened by a
    /// prior run across a gateway restart (`session.reuse_from_chain` in yml).
    reuse_from_chain: bool,
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

    /// Whether a challenge currency identifies this session backend's mint.
    pub fn accepts_currency(&self, currency: &str) -> bool {
        if self.currency().eq_ignore_ascii_case(currency) {
            return true;
        }
        let network = Some(self.session_config.network.as_str());
        matches!(
            (
                pay_kit::mpp::protocol::solana::resolve_stablecoin_mint(
                    &self.session_config.currency,
                    network,
                ),
                pay_kit::mpp::protocol::solana::resolve_stablecoin_mint(currency, network),
            ),
            (Some(configured), Some(advertised)) if configured == advertised
        )
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
        let committed_watermarks = Arc::new(dashmap::DashMap::new());
        let reserved_capacity = Arc::new(Mutex::new(HashMap::new()));
        let delegated_voucher_lock = Arc::new(tokio::sync::Mutex::new(()));
        let settlement_signatures = Arc::new(Mutex::new(HashMap::new()));
        let operator_runtime = SessionOperatorRuntime {
            server: Arc::clone(&server),
            channel_store,
            rpc_url: session_config.rpc_url.clone(),
            network: session_config.network.clone(),
            token_program: session_config
                .token_program
                .map(|address| address.to_string())
                .unwrap_or_else(|| {
                    pay_kit::mpp::protocol::solana::default_token_program_for_currency(
                        &session_config.currency,
                        Some(&session_config.network),
                    )
                    .to_string()
                }),
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
            server,
            session_config,
            challenge_binding_secret: challenge_binding_secret.into(),
            realm: DEFAULT_REALM.to_string(),
            payment_channel_signer,
            payment_channel_payer_signer,
            committed_watermarks,
            lifecycle: SessionLifecycleHandle {
                tx,
                touches_enabled: Arc::new(AtomicBool::new(false)),
            },
            operator_runtime,
            reuse_from_chain: false,
        }
    }

    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = realm.into();
        self
    }

    /// Enable lazy loading of prior-run channels from chain on an unknown-channel
    /// client voucher (see [`SessionMpp::reuse_from_chain`]).
    pub fn with_reuse_from_chain(mut self, enabled: bool) -> Self {
        self.reuse_from_chain = enabled;
        self
    }

    /// Share the server's recent-blockhash cache with session challenge
    /// issuance so `recentBlockhash` and `recentSlot` come from the same
    /// `getLatestBlockhash` observation instead of a per-challenge RPC call.
    ///
    /// Rebuilds the inner [`SessionServer`] with the cache attached. The
    /// lifecycle runloop keeps its handle to the original server; both wrap
    /// the same channel store and config, and the cache only affects
    /// challenge issuance, which always goes through `self.server`.
    pub fn with_blockhash_cache(mut self, cache: BlockhashCache) -> Self {
        let server = Arc::new(
            SessionServer::new(
                self.session_config.clone(),
                Arc::clone(&self.operator_runtime.channel_store),
            )
            .with_blockhash_cache(cache),
        );
        self.server = Arc::clone(&server);
        self.operator_runtime.server = server;
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
        self.lifecycle
            .touches_enabled
            .store(close_delay.is_some(), Ordering::Release);
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
    pub fn voucher_signer(&self) -> SessionVoucherSigner {
        self.session_config.voucher_signer
    }

    /// Meter a successful response and persist an operator-signed cumulative
    /// voucher before releasing that response to the client.
    pub async fn authorize_delegated_usage(
        &self,
        channel_id: &str,
        amount: u64,
    ) -> Result<DelegatedUsageAuthorization> {
        if self.voucher_signer() != SessionVoucherSigner::Operator {
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
        let state = self
            .operator_runtime
            .channel_store
            .get_channel(channel_id)
            .await
            .map_err(|error| {
                Error::Mpp(format!(
                    "failed to restore delegated session channel {channel_id}: {error}"
                ))
            })?
            .ok_or_else(|| {
                Error::Mpp(format!("unknown delegated session channel: {channel_id}"))
            })?;
        let current = state.cumulative;
        let idle_timeout_seconds = state.idle_timeout_seconds.ok_or_else(|| {
            Error::Mpp(format!(
                "delegated session channel {channel_id} is missing its negotiated idle timeout"
            ))
        })?;
        self.record_committed_watermark(channel_id.to_string(), current);
        if amount == 0 {
            return Ok(DelegatedUsageAuthorization {
                cumulative: current,
                idle_timeout_seconds,
            });
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
            cumulative_amount: cumulative.to_string(),
            expires_at: Some(pay_kit::mpp::DEFAULT_SESSION_EXPIRES_AT),
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
                channel_id: channel_id.to_string(),
                voucher: SignedVoucher {
                    data,
                    signer: operator.to_string(),
                    signature: crate::b58::encode_64(&<[u8; 64]>::from(signature)),
                    signature_type: VoucherSignatureType::Ed25519,
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
        telemetry::record_payment_channel_voucher_accepted_for_protocol(
            "mpp/session",
            self.currency(),
            self.network(),
            accepted.charged,
        );
        self.record_committed_watermark(channel_id.to_string(), accepted.cumulative);
        self.touch_channel(channel_id.to_string()).await?;
        Ok(DelegatedUsageAuthorization {
            cumulative: accepted.cumulative,
            idle_timeout_seconds,
        })
    }

    pub async fn reserve_delegated_capacity(
        &self,
        channel_id: &str,
        amount: u64,
    ) -> Result<Option<DelegatedCapacityLease>> {
        self.touch_channel(channel_id.to_string()).await?;
        if !self.operator_runtime.reserve_capacity(channel_id, amount) {
            return Ok(None);
        }

        let lifecycle = self.lifecycle.clone();
        let heartbeat_channel_id = channel_id.to_string();
        let (cancel, mut cancellation) = watch::channel(false);
        let heartbeat = tokio::spawn(async move {
            let mut interval = tokio::time::interval(DELEGATED_ACTIVITY_HEARTBEAT_INTERVAL);
            interval.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = cancellation.changed() => break,
                    _ = interval.tick() => {}
                }
                if let Err(error) = lifecycle
                    .touch_with_cancellation(
                        heartbeat_channel_id.clone(),
                        unix_millis(),
                        Some(cancellation.clone()),
                    )
                    .await
                {
                    if *cancellation.borrow() {
                        break;
                    }
                    tracing::warn!(
                        channel_id = heartbeat_channel_id,
                        %error,
                        "failed to heartbeat active delegated session"
                    );
                }
            }
        });

        Ok(Some(DelegatedCapacityLease {
            runtime: self.operator_runtime.clone(),
            channel_id: channel_id.to_string(),
            cancel,
            heartbeat,
        }))
    }

    /// Record channel activity so the lifecycle runloop can defer auto-close.
    pub async fn touch_channel(&self, channel_id: impl Into<String>) -> Result<()> {
        let channel_id = channel_id.into();
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
        self.lifecycle
            .touch_unconfirmed(channel_id.into(), unix_millis());
    }

    /// Latest cumulative watermark accepted by this process for a session.
    pub fn committed_watermark(&self, session_id: &str) -> Option<u64> {
        self.committed_watermarks
            .get(session_id)
            .map(|watermark| *watermark)
    }

    /// On-chain settle signature for a finalized session channel, if recorded.
    /// Powers `/sessions/receipt/:channelId` — the playground polls it to show
    /// the settle receipt URL (sessions settle out-of-band at idle-close, so
    /// there's no per-request settlement header like x402 has).
    pub fn settlement_signature(&self, channel_id: &str) -> Option<String> {
        self.operator_runtime.settlement_signature(channel_id)
    }

    /// Build a [`PaymentChallenge`] for a new session.
    ///
    /// `amount` overrides the advertised per-unit price (base units) when the
    /// gate resolved an endpoint-specific price; `None` keeps the configured
    /// default.
    pub fn challenge(&self, amount: Option<u64>) -> Result<PaymentChallenge> {
        let mut request = self
            .server
            .build_challenge_request()
            .map_err(|e| Error::Mpp(format!("Failed to build session challenge: {e}")))?;
        if let Some(amount) = amount {
            request.amount = amount.to_string();
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
    pub fn challenge_header(&self, amount: Option<u64>) -> Result<String> {
        self.challenge(amount)?
            .to_header()
            .map_err(|e| Error::Mpp(format!("Failed to format session challenge: {e}")))
    }

    /// Verify that the credential's echoed challenge was minted by this
    /// server (HMAC challenge binding) and decode its session request.
    ///
    /// Opens are bound to the challenged `recentBlockhash`/`recentSlot`, so
    /// the echo must be authenticated before any of its fields are trusted.
    fn verify_challenge_echo(
        &self,
        credential: &pay_kit::mpp::PaymentCredential,
    ) -> Result<SessionRequest> {
        let echo = &credential.challenge;
        if let Some(request) =
            VERIFIED_CHALLENGES.with_borrow(|cache| cache.get(&self.challenge_binding_secret, echo))
        {
            return Ok(request);
        }
        let challenge = PaymentChallenge {
            id: echo.id.clone(),
            realm: echo.realm.clone(),
            method: echo.method.clone(),
            intent: echo.intent.clone(),
            request: echo.request.clone(),
            expires: echo.expires.clone(),
            description: None,
            digest: echo.digest.clone(),
            opaque: echo.opaque.clone(),
        };
        if !challenge.verify(&self.challenge_binding_secret) {
            return Err(Error::Mpp(
                terminal_errors::CHALLENGE_ECHO_MISMATCH.to_string(),
            ));
        }
        let request: SessionRequest = echo
            .request
            .decode()
            .map_err(|e| Error::Mpp(format!("Invalid session challenge request: {e}")))?;
        VERIFIED_CHALLENGES.with_borrow_mut(|cache| {
            cache.insert(&self.challenge_binding_secret, echo, request.clone());
        });
        Ok(request)
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

        self.process_credential(credential).await
    }

    /// Process an already-parsed session credential.
    ///
    /// HTTP adapters commonly need the decoded intent and currency to route a
    /// credential before verification. Accepting that parsed value here avoids
    /// decoding the same base64url JSON again on the hot voucher path.
    #[tracing::instrument(name = "session_process_credential", skip_all)]
    pub async fn process_credential(
        &self,
        credential: pay_kit::mpp::PaymentCredential,
    ) -> Result<SessionOutcome> {
        if credential.challenge.intent.as_str() != INTENT {
            return Err(Error::Mpp(format!(
                "Expected '{}' intent, got '{}'",
                INTENT, credential.challenge.intent
            )));
        }

        // Every credential echoes the challenge it answers; authenticate the
        // echo before trusting any of its fields (opens are bound to the
        // challenged `recentBlockhash`/`recentSlot`).
        let request = self.verify_challenge_echo(&credential)?;

        let action: SessionAction = serde_json::from_value(credential.payload)
            .map_err(|e| Error::Mpp(format!("Unrecognized session action payload: {e}")))?;

        match &action {
            SessionAction::Open(p) => {
                let details = &request.method_details;
                let recent_blockhash = details.recent_blockhash.as_deref().ok_or_else(|| {
                    Error::Mpp(
                        "session open echoes a challenge without recentBlockhash".to_string(),
                    )
                })?;
                let recent_slot = details.recent_slot.ok_or_else(|| {
                    Error::Mpp("session open echoes a challenge without recentSlot".to_string())
                })?;
                let context = SessionOpenContext {
                    challenge_id: &credential.challenge.id,
                    expires: credential.challenge.expires.as_deref(),
                    recent_blockhash,
                    recent_slot,
                };

                // PayKit verifies the exact open instruction against the
                // challenge, requires the challenged blockhash, broadcasts,
                // and confirms the resulting channel account before creating
                // durable state; a replayed open is an idempotent no-op.
                let acceptance = self
                    .server
                    .process_open_with_outcome(p, context)
                    .await
                    .map_err(|e| Error::Mpp(format!("Session open failed: {e}")))?;
                let replay = acceptance.replay;
                let signature = Some(acceptance.transaction_signature);
                let state = acceptance.state;

                if !replay {
                    telemetry::record_payment_channel_opened(
                        signature.as_deref().unwrap_or_default(),
                        &state.channel_id,
                        &p.payer,
                        self.currency(),
                        self.network(),
                        state.deposit,
                    );
                }

                self.record_committed_watermark(state.channel_id.clone(), state.cumulative);
                self.touch_channel(state.channel_id.clone()).await?;
                Ok(SessionOutcome::Active {
                    state: Box::new(state),
                    signature,
                })
            }

            SessionAction::Use(p) => {
                let state = self.verify_use_authentication(p).await?;
                self.record_committed_watermark(state.channel_id.clone(), state.cumulative);
                self.touch_channel(state.channel_id.clone()).await?;
                Ok(SessionOutcome::Active {
                    state: Box::new(state),
                    signature: None,
                })
            }

            SessionAction::Voucher(p) => {
                // Reuse: adopt a prior-run channel from chain before verifying,
                // so a voucher for a channel this process never opened is honored
                // instead of rejected as unknown.
                self.ensure_channel_loaded(&p.voucher.data.channel_id)
                    .await?;
                let acceptance = self
                    .server
                    .verify_voucher(p)
                    .await
                    .map_err(|e| Error::PaymentRejected(e.to_string()))?;
                let cumulative = acceptance.cumulative;
                let channel_id = p.voucher.data.channel_id.clone();
                telemetry::record_payment_channel_voucher_cumulative(
                    &channel_id,
                    self.currency(),
                    self.network(),
                    cumulative,
                );
                telemetry::record_payment_channel_voucher_accepted_for_protocol(
                    "mpp/session",
                    self.currency(),
                    self.network(),
                    acceptance.charged,
                );
                self.record_committed_watermark(channel_id.clone(), cumulative);
                self.touch_channel(channel_id.clone()).await?;
                Ok(SessionOutcome::Voucher {
                    channel_id,
                    cumulative,
                })
            }

            SessionAction::TopUp(p) => {
                let acceptance = self
                    .server
                    .process_topup_with_outcome(p)
                    .await
                    .map_err(|e| Error::Mpp(format!("TopUp failed: {e}")))?;
                let signature = Some(acceptance.transaction_signature);
                let state = acceptance.state;
                self.record_committed_watermark(state.channel_id.clone(), state.cumulative);
                self.touch_channel(state.channel_id.clone()).await?;
                Ok(SessionOutcome::Active {
                    state: Box::new(state),
                    signature,
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
                    Err(error) if session_close_needs_reconciliation(&error.to_string()) => self
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
                Ok(SessionOutcome::Closed {
                    params: Box::new(params),
                    signature,
                })
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

    /// Verify a `use` action's reusable payer proof against the channel
    /// state bound at open.
    ///
    /// Authenticates the request only — metering happens response-side via
    /// [`Self::authorize_delegated_usage`], which prices the delivered
    /// service and persists the operator-signed cumulative voucher.
    /// Lazily load a channel opened by a prior run into the in-memory store so a
    /// client voucher for it verifies instead of being rejected as unknown.
    /// No-op unless `reuse_from_chain` is set, the channel is absent from the
    /// store, and it exists on-chain in the open state. The resumed watermark is
    /// the on-chain settled amount, so the first reuse voucher must exceed it.
    async fn ensure_channel_loaded(&self, channel_id: &str) -> Result<()> {
        if !self.reuse_from_chain {
            return Ok(());
        }
        if self
            .operator_runtime
            .channel_store
            .get_channel(channel_id)
            .await
            .map_err(|e| Error::Mpp(format!("read session channel {channel_id}: {e}")))?
            .is_some()
        {
            return Ok(());
        }
        // Absent on-chain → leave it for verify_voucher to reject as unknown.
        let Some(chan) = self
            .operator_runtime
            .fetch_payment_channel(channel_id)
            .await?
        else {
            return Ok(());
        };
        // Only adopt channels still open (status 0), for this gateway's
        // configured recipient and mint. Otherwise a valid voucher for an
        // unrelated channel could make this server account for/settle it.
        if chan.status != 0
            || chan.payee.to_string() != self.session_config.recipient
            || !self.accepts_currency(&chan.mint.to_string())
        {
            return Ok(());
        }
        let settled = chan.settlement.settled;
        let voucher_signer = if self.voucher_signer() == SessionVoucherSigner::Operator {
            "operator"
        } else {
            "client"
        };
        let state = ChannelState {
            channel_id: channel_id.to_string(),
            authorized_signer: chan.authorized_signer.to_string(),
            deposit: chan.deposit,
            cumulative: settled,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            open_slot: Some(chan.open_slot),
            payer: chan.payer.to_string(),
            rent_payer: chan.rent_payer.to_string(),
            // The proof-binding fields live off-chain (open credential) and are
            // absent here — fine for the client-voucher path, which verifies the
            // ed25519 signature against `authorized_signer` rather than a proof.
            opening_challenge_id: String::new(),
            authentication: None,
            voucher_signer: voucher_signer.to_string(),
            idle_timeout_seconds: Some(300),
            last_activity_at: unix_millis(),
            spent_amount: 0,
            settled_on_chain: settled,
            distributed_on_chain: chan.settlement.payout_watermark,
            processed_uses: vec![],
            processed_topup_signatures: vec![],
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: Default::default(),
            pending_setup: None,
            onchain_checked_at: 0,
            lifecycle: None,
            schema_version: pay_kit::mpp::CHANNEL_STATE_SCHEMA_VERSION,
            extra: Default::default(),
        };
        // Insert only if still absent — a concurrent voucher for the same
        // channel may have loaded it first.
        self.operator_runtime
            .channel_store
            .update_channel(
                channel_id,
                Box::new(move |existing| Ok(existing.unwrap_or(state))),
            )
            .await
            .map_err(|e| Error::Mpp(format!("load channel {channel_id} from chain: {e}")))?;
        // Adopt it into the settlement candidate set at its on-chain watermark.
        self.record_committed_watermark(channel_id.to_string(), settled);
        tracing::debug!(
            channel = channel_id,
            settled,
            "reuse: loaded channel from chain"
        );
        Ok(())
    }

    async fn verify_use_authentication(&self, payload: &UsePayload) -> Result<ChannelState> {
        if self.voucher_signer() != SessionVoucherSigner::Operator {
            return Err(Error::Mpp(terminal_errors::OPERATOR_ONLY.to_string()));
        }
        let state = self
            .operator_runtime
            .channel_store
            .get_channel(&payload.channel_id)
            .await
            .map_err(|error| {
                Error::Mpp(format!(
                    "failed to read session channel {}: {error}",
                    payload.channel_id
                ))
            })?
            .ok_or_else(|| {
                Error::PaymentRejected(format!(
                    "{}: {}",
                    terminal_errors::UNKNOWN_CHANNEL,
                    payload.channel_id
                ))
            })?;
        if state.sealed || state.close_requested_at.is_some() {
            return Err(Error::PaymentRejected(
                "payment channel close is pending".to_string(),
            ));
        }
        // A record with no binding at all is not a mismatch: it either
        // predates proof binding or was rewritten by a pre-binding writer.
        // Name it so the client knows re-opening — not retrying the proof —
        // is the fix. Mirrors PayKit's process_use.
        if state.opening_challenge_id.is_empty() && state.authentication.is_none() {
            return Err(Error::PaymentRejected(format!(
                "session channel {}; open a new session",
                terminal_errors::PREDATES_PROOF_BINDING
            )));
        }
        let bound = serde_json::to_string(&payload.authentication)
            .map_err(|error| Error::Mpp(format!("serialize authentication: {error}")))?;
        let proof = &payload.authentication;
        // No comparison against the request's outer challenge id: per
        // draft-solana-session-00 the same bearer proof is presented for the
        // channel's whole lifetime while the outer challenge rotates, and
        // PayKit's canonical check binds the proof to the opening challenge
        // only.
        if state.voucher_signer != "operator"
            || state.authentication.as_deref() != Some(bound.as_str())
            || proof.challenge_id != state.opening_challenge_id
            || proof.payer != state.payer
            || !proof
                .verify(&state.channel_id)
                .map_err(|error| Error::Mpp(error.to_string()))?
        {
            return Err(Error::PaymentRejected(format!(
                "use authentication {}",
                terminal_errors::PROOF_MISMATCH
            )));
        }
        Ok(state)
    }

    async fn submit_payment_channel_settlement(
        &self,
        params: &SealParams,
    ) -> Result<Option<String>> {
        self.operator_runtime
            .submit_payment_channel_settlement(params)
            .await
    }
}

/// Build confirmed channel state for tests, bypassing the on-chain open path
/// (transaction verification, broadcast, and confirmation are PayKit's and
/// are exercised end-to-end by the surfpool tests). Seed it through the
/// [`ChannelStore`] handed to [`SessionMpp::new_with_channel_store`].
#[doc(hidden)]
pub fn test_channel_state(
    channel_id: impl Into<String>,
    deposit: u64,
    authorized_signer: impl Into<String>,
    voucher_signer: &str,
    opening_challenge_id: impl Into<String>,
    payer: impl Into<String>,
    authentication: Option<String>,
) -> ChannelState {
    let payer = payer.into();
    ChannelState {
        channel_id: channel_id.into(),
        authorized_signer: authorized_signer.into(),
        deposit,
        cumulative: 0,
        sealed: false,
        highest_voucher_signature: None,
        highest_voucher_expires_at: None,
        close_requested_at: None,
        open_slot: Some(42),
        rent_payer: payer.clone(),
        payer,
        opening_challenge_id: opening_challenge_id.into(),
        authentication,
        voucher_signer: voucher_signer.to_string(),
        idle_timeout_seconds: Some(300),
        last_activity_at: unix_millis(),
        spent_amount: 0,
        settled_on_chain: 0,
        distributed_on_chain: 0,
        processed_uses: vec![],
        processed_topup_signatures: vec![],
        next_delivery_sequence: 0,
        pending_deliveries: vec![],
        committed_deliveries: Default::default(),
        pending_setup: None,
        onchain_checked_at: 0,
        lifecycle: None,
        schema_version: pay_kit::mpp::CHANNEL_STATE_SCHEMA_VERSION,
        extra: Default::default(),
    }
}

fn payment_channel_treasury_owner(network: &str) -> Result<solana_pubkey::Pubkey> {
    const DEVNET_TREASURY_OWNER: &str = "4zTeC5mVqWLruDexgU2mV66p9t5vCA9JyiZqdGDUspap";

    if network == "devnet" {
        return solana_pubkey::Pubkey::from_str(DEVNET_TREASURY_OWNER)
            .map_err(|error| Error::Mpp(format!("invalid devnet treasury owner: {error}")));
    }
    Ok(pay_kit::mpp::program::payment_channels::treasury_owner())
}

fn decode_voucher_signature(signature: &str) -> Result<[u8; 64]> {
    crate::b58::decode_64(signature)
        .map_err(|e| Error::Mpp(format!("invalid voucher signature encoding: {e}")))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::session::SessionHandle;
    use pay_kit::mpp::solana_keychain::{SolanaSigner, memory::MemorySigner};
    use pay_kit::mpp::{PaymentCredential, SessionAuthentication, format_authorization};
    use std::sync::Arc;

    const CAP: u64 = 1_000_000;
    const TEST_BLOCKHASH: &str = "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxxxx11x";
    const TEST_SLOT: u64 = 123;

    fn test_session_config() -> SessionConfig {
        SessionConfig {
            operator: solana_pubkey::Pubkey::new_unique().to_string(),
            recipient: solana_pubkey::Pubkey::new_unique().to_string(),
            amount: 25,
            suggested_deposit: Some(5 * CAP),
            currency: solana_pubkey::Pubkey::new_unique().to_string(),
            network: "localnet".to_string(),
            ..SessionConfig::default()
        }
    }

    fn test_blockhash_cache() -> BlockhashCache {
        let cache = BlockhashCache::new();
        cache.set(TEST_BLOCKHASH.to_string(), 42, TEST_SLOT);
        cache
    }

    fn test_session_mpp() -> SessionMpp {
        SessionMpp::new(test_session_config(), "test-secret")
            .with_blockhash_cache(test_blockhash_cache())
    }

    #[test]
    fn usdtest_settlement_uses_token_2022() {
        use pay_kit::mpp::protocol::solana::programs;

        let session = SessionMpp::new(
            SessionConfig {
                currency: "USDtest".to_string(),
                network: "devnet".to_string(),
                token_program: None,
                ..test_session_config()
            },
            "test-secret",
        );
        assert_eq!(
            session.operator_runtime.token_program,
            programs::TOKEN_2022_PROGRAM
        );
        assert_eq!(
            payment_channel_treasury_owner(&session.operator_runtime.network)
                .unwrap()
                .to_string(),
            "4zTeC5mVqWLruDexgU2mV66p9t5vCA9JyiZqdGDUspap"
        );
    }

    #[test]
    fn session_currency_matches_its_advertised_mint() {
        let mut config = test_session_config();
        config.currency = "USDC".to_string();
        let session = SessionMpp::new(config, "test-secret");

        assert!(session.accepts_currency("USDC"));
        assert!(session.accepts_currency(pay_kit::mpp::mints::USDC_MAINNET));
        assert!(!session.accepts_currency(pay_kit::mpp::mints::USDG_MAINNET));
    }

    fn test_keypair() -> (ed25519_dalek::SigningKey, Box<dyn SolanaSigner>) {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::generate(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(vk.as_bytes());
        (sk, Box::new(MemorySigner::from_bytes(&kp).unwrap()))
    }

    fn test_session_signer() -> Box<dyn SolanaSigner> {
        test_keypair().1
    }

    #[tokio::test]
    async fn disabled_lifecycle_touch_bypasses_the_runloop() {
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);
        let handle = SessionLifecycleHandle {
            tx,
            touches_enabled: Arc::new(AtomicBool::new(false)),
        };

        assert!(
            handle
                .touch("channel".to_string(), 1)
                .await
                .unwrap()
                .is_none()
        );
        handle.touch_unconfirmed("channel".to_string(), 1);
    }

    #[test]
    fn lifecycle_configuration_controls_the_touch_fast_path() {
        let session = test_session_mpp();
        assert!(!session.lifecycle.touches_enabled.load(Ordering::Acquire));

        session.start_lifecycle_runloop(Duration::from_secs(10));
        assert!(session.lifecycle.touches_enabled.load(Ordering::Acquire));

        session.start_lifecycle_runloop(Duration::ZERO);
        assert!(!session.lifecycle.touches_enabled.load(Ordering::Acquire));
    }

    #[test]
    fn session_backend_accepts_its_normalized_challenge_mint() {
        let mut config = test_session_config();
        config.currency = "USDC".to_string();
        let session =
            SessionMpp::new(config, "test-secret").with_blockhash_cache(test_blockhash_cache());
        let challenge = session.challenge(None).unwrap();
        let request: SessionRequest = challenge.request.decode().unwrap();

        assert_ne!(session.currency(), request.currency);
        assert!(session.accepts_currency(&request.currency));
    }

    /// Insert confirmed channel state directly — see [`test_channel_state`].
    #[allow(clippy::too_many_arguments)]
    async fn seed_channel(
        session: &SessionMpp,
        channel_id: &str,
        deposit: u64,
        authorized_signer: &str,
        voucher_signer: &str,
        opening_challenge_id: &str,
        payer: &str,
        authentication: Option<String>,
    ) {
        let state = test_channel_state(
            channel_id,
            deposit,
            authorized_signer,
            voucher_signer,
            opening_challenge_id,
            payer,
            authentication,
        );
        session
            .operator_runtime
            .channel_store
            .put_channel(channel_id, state)
            .await
            .unwrap();
        session.record_committed_watermark(channel_id.to_string(), 0);
    }

    #[test]
    fn with_realm_updates_challenge_realm() {
        let session = test_session_mpp().with_realm("Custom Realm");
        let challenge = session.challenge(None).unwrap();
        assert_eq!(challenge.realm, "Custom Realm");
    }

    #[test]
    fn challenge_without_blockhash_source_errors() {
        let session = SessionMpp::new(test_session_config(), "test-secret");
        let err = session.challenge(None).unwrap_err();
        assert!(
            err.to_string().contains("recentBlockhash"),
            "challenges must carry the open-transaction context: {err}"
        );
    }

    #[test]
    fn challenge_uses_cached_blockhash_and_recent_slot() {
        let session = test_session_mpp();
        let challenge = session.challenge(Some(77)).unwrap();
        let request: pay_kit::mpp::SessionRequest = challenge.request.decode().unwrap();

        assert_eq!(
            request.method_details.recent_blockhash.as_deref(),
            Some(TEST_BLOCKHASH)
        );
        assert_eq!(request.method_details.recent_slot, Some(TEST_SLOT));
        assert_eq!(request.amount, "77");
    }

    #[tokio::test]
    async fn process_rejects_non_session_intent() {
        let session = test_session_mpp();
        let challenge = PaymentChallenge::with_challenge_binding_secret(
            "test-secret",
            "test-realm",
            METHOD,
            "charge",
            Base64UrlJson::from_typed(&session.server.build_challenge_request().unwrap()).unwrap(),
        );
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            serde_json::json!({ "action": "close" }),
        );
        let auth_header = format_authorization(&credential).unwrap();

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
    async fn process_rejects_forged_challenge_echo() {
        let session = test_session_mpp();
        // Same request bytes, but bound with a different secret: the echoed
        // challenge id no longer matches this server's HMAC.
        let forged = PaymentChallenge::with_challenge_binding_secret(
            "attacker-secret",
            "test-realm",
            METHOD,
            INTENT,
            session.challenge(None).unwrap().request,
        );
        let credential =
            PaymentCredential::new(forged.to_echo(), serde_json::json!({ "action": "close" }));
        let auth_header = format_authorization(&credential).unwrap();

        let err = session
            .process(&auth_header)
            .await
            .expect_err("forged echo should error");
        assert!(err.to_string().contains("did not issue"), "got: {err}");
    }

    #[tokio::test]
    async fn verified_challenge_cache_compares_the_complete_echo() {
        let session = test_session_mpp();
        let challenge = session.challenge(None).unwrap();

        // Reach action decoding with a valid echo, which primes the cache.
        let valid = PaymentCredential::new(
            challenge.to_echo(),
            serde_json::json!({ "action": "mystery" }),
        );
        let _ = session.process_credential(valid).await.unwrap_err();

        // Reusing its valid id while altering any bound field must not hit the
        // cache or bypass the HMAC comparison.
        let mut altered_echo = challenge.to_echo();
        altered_echo.realm.push_str("-altered");
        let altered =
            PaymentCredential::new(altered_echo, serde_json::json!({ "action": "close" }));
        let err = session
            .process_credential(altered)
            .await
            .expect_err("altered cached echo should error");
        assert!(err.to_string().contains("did not issue"), "got: {err}");
    }

    #[test]
    fn verified_challenge_cache_is_bounded() {
        let session = test_session_mpp();
        let request = session.challenge(None).unwrap().request;
        let mut cache = VerifiedChallengeCache::default();
        let mut first = None;
        let mut last = None;

        for index in 0..=VERIFIED_CHALLENGE_CACHE_ENTRIES {
            let challenge = PaymentChallenge::with_challenge_binding_secret(
                "test-secret",
                format!("test-realm-{index}"),
                METHOD,
                INTENT,
                request.clone(),
            );
            let echo = challenge.to_echo();
            if index == 0 {
                first = Some(echo.clone());
            }
            if index == VERIFIED_CHALLENGE_CACHE_ENTRIES {
                last = Some(echo.clone());
            }
            cache.insert("test-secret", &echo, request.decode().unwrap());
        }

        assert_eq!(cache.entries.len(), VERIFIED_CHALLENGE_CACHE_ENTRIES);
        assert!(cache.get("test-secret", &first.unwrap()).is_none());
        assert!(cache.get("test-secret", &last.unwrap()).is_some());
    }

    #[tokio::test]
    async fn process_rejects_unknown_session_action_payload() {
        let session = test_session_mpp();
        let challenge = session.challenge(None).unwrap();
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
    async fn process_supports_voucher_and_close_on_open_channel() {
        let session = test_session_mpp();
        let challenge = session.challenge(None).unwrap();
        let channel = solana_pubkey::Pubkey::new_unique();
        let (voucher_key, signer) = test_keypair();
        let authorized_signer = signer.pubkey().to_string();
        let handle =
            SessionHandle::new(channel, signer, challenge.clone()).with_voucher_key(voucher_key);
        seed_channel(
            &session,
            &channel.to_string(),
            CAP,
            &authorized_signer,
            "client",
            &challenge.id,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            None,
        )
        .await;

        let voucher_header = handle.voucher_header(75).await.unwrap();
        let SessionOutcome::Voucher { cumulative, .. } =
            session.process(&voucher_header).await.unwrap()
        else {
            panic!("expected voucher outcome");
        };
        assert_eq!(cumulative, 75);
        assert_eq!(session.committed_watermark(&channel.to_string()), Some(75));

        let close_header = handle.close_header(Some(25)).await.unwrap();
        let competing_lease = session
            .reserve_delegated_capacity(&channel.to_string(), 0)
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
        assert_eq!(session.committed_watermark(&channel.to_string()), Some(100));
    }

    #[tokio::test]
    async fn use_rejected_for_client_signed_sessions() {
        let session = test_session_mpp();
        let challenge = session.challenge(None).unwrap();
        let payer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let channel = solana_pubkey::Pubkey::new_unique();
        let proof = SessionAuthentication::sign(challenge.id.clone(), &channel.to_string(), &payer)
            .unwrap();
        let handle = SessionHandle::new(channel, test_session_signer(), challenge)
            .with_authentication(proof);

        let err = session
            .process(&handle.use_header().await.unwrap())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("only valid for operator-signed sessions"),
            "got: {err}"
        );
    }

    async fn operator_session_with_bound_channel() -> (
        SessionMpp,
        PaymentChallenge,
        solana_pubkey::Pubkey,
        SessionAuthentication,
        ed25519_dalek::SigningKey,
    ) {
        let mut config = test_session_config();
        config.voucher_signer = SessionVoucherSigner::Operator;
        let session =
            SessionMpp::new(config, "test-secret").with_blockhash_cache(test_blockhash_cache());
        let challenge = session.challenge(None).unwrap();
        let payer = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let payer_address = bs58::encode(payer.verifying_key().as_bytes()).into_string();
        let channel = solana_pubkey::Pubkey::new_unique();
        let proof = SessionAuthentication::sign(challenge.id.clone(), &channel.to_string(), &payer)
            .unwrap();
        seed_channel(
            &session,
            &channel.to_string(),
            CAP,
            &session.session_config.operator.clone(),
            "operator",
            &challenge.id,
            &payer_address,
            Some(serde_json::to_string(&proof).unwrap()),
        )
        .await;
        (session, challenge, channel, proof, payer)
    }

    #[tokio::test]
    async fn use_authenticates_the_proof_bound_at_open() {
        let (session, challenge, channel, proof, _payer) =
            operator_session_with_bound_channel().await;
        let handle = SessionHandle::new(channel, test_session_signer(), challenge)
            .with_authentication(proof);

        let SessionOutcome::Active { state, signature } = session
            .process(&handle.use_header().await.unwrap())
            .await
            .unwrap()
        else {
            panic!("expected use to authenticate the channel");
        };
        assert_eq!(state.channel_id, channel.to_string());
        assert_eq!(signature, None);
    }

    #[tokio::test]
    async fn use_rejects_a_proof_for_another_challenge() {
        let (session, challenge, channel, _proof, payer) =
            operator_session_with_bound_channel().await;
        let forged =
            SessionAuthentication::sign("some-other-challenge", &channel.to_string(), &payer)
                .unwrap();
        let handle = SessionHandle::new(channel, test_session_signer(), challenge)
            .with_authentication(forged);

        let err = session
            .process(&handle.use_header().await.unwrap())
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the proof bound at open"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn use_names_a_record_that_predates_proof_binding() {
        // A record whose binding fields were stripped by a pre-binding
        // writer (or that predates proof binding) fails with its own error,
        // not the generic proof mismatch.
        let (session, challenge, _bound_channel, _proof, payer) =
            operator_session_with_bound_channel().await;
        let wiped = solana_pubkey::Pubkey::new_unique();
        let payer_address = bs58::encode(payer.verifying_key().as_bytes()).into_string();
        seed_channel(
            &session,
            &wiped.to_string(),
            CAP,
            &session.session_config.operator.clone(),
            "",
            "",
            &payer_address,
            None,
        )
        .await;
        let proof =
            SessionAuthentication::sign(challenge.id.clone(), &wiped.to_string(), &payer).unwrap();
        let handle =
            SessionHandle::new(wiped, test_session_signer(), challenge).with_authentication(proof);

        let err = session
            .process(&handle.use_header().await.unwrap())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("predates proof binding"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn operator_close_uses_bound_proof() {
        let (session, challenge, channel, proof, _payer) =
            operator_session_with_bound_channel().await;
        let handle = SessionHandle::new(channel, test_session_signer(), challenge)
            .with_authentication(proof);

        let SessionOutcome::Closed { params, signature } = session
            .process(&handle.close_header(None).await.unwrap())
            .await
            .unwrap()
        else {
            panic!("expected close outcome");
        };
        assert_eq!(params.channel_id, channel);
        assert_eq!(signature, None);
    }

    #[tokio::test]
    async fn lifecycle_runloop_operator_closes_idle_channel() {
        let session = Arc::new(test_session_mpp());
        session.start_lifecycle_runloop(Duration::from_millis(10));
        let challenge = session.challenge(None).unwrap();
        let channel = solana_pubkey::Pubkey::new_unique();
        let (voucher_key, signer) = test_keypair();
        let authorized_signer = signer.pubkey().to_string();
        let handle =
            SessionHandle::new(channel, signer, challenge.clone()).with_voucher_key(voucher_key);
        seed_channel(
            &session,
            &channel.to_string(),
            CAP,
            &authorized_signer,
            "client",
            &challenge.id,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            None,
        )
        .await;
        session.touch_channel(channel.to_string()).await.unwrap();

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

    #[test]
    fn settlement_wakeup_does_not_run_close_reconciliation_early() {
        assert_eq!(
            next_lifecycle_wakeup(Some(Duration::from_secs(60)), Some(Duration::from_secs(5))),
            Some((Duration::from_secs(5), false))
        );
        assert_eq!(
            next_lifecycle_wakeup(Some(Duration::from_secs(5)), Some(Duration::from_secs(60))),
            Some((Duration::from_secs(5), true))
        );
        assert_eq!(
            next_lifecycle_wakeup(Some(Duration::from_secs(5)), Some(Duration::from_secs(5))),
            Some((Duration::from_secs(5), true))
        );
    }

    #[tokio::test]
    async fn settlement_only_claims_active_channels_without_enabling_hot_path_touches() {
        let session = Arc::new(test_session_mpp());
        session.start_lifecycle_runloop_with_settlement_and_batching(
            Duration::ZERO,
            Duration::from_millis(10),
            Duration::from_millis(10),
            SessionLifecycleReconciliation::Embedded,
        );
        assert!(!session.lifecycle.touches_enabled.load(Ordering::Acquire));

        let challenge = session.challenge(None).unwrap();
        let channel = solana_pubkey::Pubkey::new_unique().to_string();
        seed_channel(
            &session,
            &channel,
            CAP,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            "client",
            &challenge.id,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            None,
        )
        .await;
        session.record_committed_watermark(channel.clone(), 75);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let state = session
                    .operator_runtime
                    .channel_store
                    .get_channel(&channel)
                    .await
                    .unwrap()
                    .unwrap();
                if state.lifecycle.is_some() {
                    assert!(state.close_requested_at.is_none());
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("settlement boundary should claim the active channel");
    }

    #[tokio::test]
    async fn lease_cancellation_interrupts_in_flight_heartbeat() {
        let (cancel, cancellation) = watch::channel(false);
        let (started_tx, started_rx) = oneshot::channel();
        let heartbeat = tokio::spawn(run_while_lease_active(cancellation, async move {
            started_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        }));

        started_rx.await.unwrap();
        cancel.send(true).unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(100), heartbeat)
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn queued_touch_is_discarded_after_lease_cancellation() {
        let session = Arc::new(test_session_mpp());
        session.start_lifecycle_runloop_with_settlement_and_batching(
            Duration::from_millis(30),
            Duration::from_millis(1),
            Duration::ZERO,
            SessionLifecycleReconciliation::External,
        );
        let challenge = session.challenge(None).unwrap();
        let channel = solana_pubkey::Pubkey::new_unique().to_string();
        seed_channel(
            &session,
            &channel,
            CAP,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            "client",
            &challenge.id,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            None,
        )
        .await;

        session.touch_channel(channel.clone()).await.unwrap();
        let baseline = session
            .operator_runtime
            .channel_store
            .get_channel(&channel)
            .await
            .unwrap()
            .unwrap()
            .lifecycle
            .unwrap()
            .close_after;

        // The race from pay#416's review: a heartbeat `Touch` is dequeued
        // only after its lease has been released. Queue the command and flip
        // its cancellation before yielding to the runloop — exactly the state
        // `DelegatedCapacityLease::drop` leaves behind (cancel is signalled
        // before the heartbeat task is aborted). The far-future timestamp
        // makes any wrongly persisted deadline unmissable.
        let (cancel, cancellation) = watch::channel(false);
        let (response_tx, response_rx) = oneshot::channel();
        session.lifecycle.send(SessionLifecycleCommand::Touch {
            channel_id: channel.clone(),
            touched_at_ms: unix_millis() + 3_600_000,
            cancellation: Some(cancellation),
            response: response_tx,
        });
        cancel.send(true).unwrap();

        assert!(
            response_rx.await.is_err(),
            "a cancelled queued touch must be discarded, not persisted"
        );
        let after_discard = session
            .operator_runtime
            .channel_store
            .get_channel(&channel)
            .await
            .unwrap()
            .unwrap()
            .lifecycle
            .unwrap()
            .close_after;
        assert_eq!(
            after_discard, baseline,
            "a touch dequeued after lease release must not advance the idle deadline"
        );

        // The discard path must keep the runloop serving later commands.
        session.touch_channel(channel.clone()).await.unwrap();
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
        let challenge = session.challenge(None).unwrap();
        let channel = solana_pubkey::Pubkey::new_unique().to_string();
        seed_channel(
            &session,
            &channel,
            CAP,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            "client",
            &challenge.id,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            None,
        )
        .await;
        session.touch_channel(channel.clone()).await.unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let persisted = session
                    .operator_runtime
                    .channel_store
                    .get_channel(&channel)
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
            .get_channel(&channel)
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
                &channel,
                Box::new(|state| {
                    let mut state = state.unwrap();
                    state.close_requested_at = Some(1);
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        let error = session
            .touch_channel(channel)
            .await
            .expect_err("a worker-claimed close cannot be woken");
        assert!(error.to_string().contains("close is pending"));
    }

    #[tokio::test]
    async fn embedded_lifecycle_adopts_persisted_deadlines_after_restart() {
        let store: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::new());
        let config = test_session_config();
        let first =
            SessionMpp::new_with_channel_store(config.clone(), "test-secret", Arc::clone(&store))
                .with_blockhash_cache(test_blockhash_cache());
        first.start_lifecycle_runloop_with_settlement_and_batching(
            Duration::from_secs(3600),
            Duration::from_secs(60),
            Duration::ZERO,
            SessionLifecycleReconciliation::External,
        );
        let challenge = first.challenge(None).unwrap();
        let channel = solana_pubkey::Pubkey::new_unique().to_string();
        seed_channel(
            &first,
            &channel,
            CAP,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            "client",
            &challenge.id,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            None,
        )
        .await;
        first.touch_channel(channel.clone()).await.unwrap();

        let persisted = store.get_channel(&channel).await.unwrap().unwrap();
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
                let persisted = store.get_channel(&channel).await.unwrap().unwrap();
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
        )
        .with_blockhash_cache(test_blockhash_cache());
        session.start_lifecycle_runloop_with_settlement_and_batching(
            Duration::from_secs(3600),
            Duration::from_secs(60),
            Duration::ZERO,
            SessionLifecycleReconciliation::External,
        );
        let challenge = session.challenge(None).unwrap();
        let channel = solana_pubkey::Pubkey::new_unique().to_string();
        seed_channel(
            &session,
            &channel,
            CAP,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            "client",
            &challenge.id,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            None,
        )
        .await;
        session.touch_channel(channel.clone()).await.unwrap();

        let live_owner = "other-live-gateway";
        let live_lease = format!(
            "{LIFECYCLE_OWNER_LEASE_PREFIX}{live_owner}:{}",
            unix_millis().saturating_add(60_000)
        );
        let original_deadline = store
            .update_channel(
                &channel,
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
            .get_channel(&channel)
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
                &channel,
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
            .get_channel(&channel)
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
        let challenge = session.challenge(None).unwrap();
        let channel = solana_pubkey::Pubkey::new_unique().to_string();
        seed_channel(
            &session,
            &channel,
            CAP,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            "client",
            &challenge.id,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            None,
        )
        .await;
        session
            .operator_runtime
            .channel_store
            .update_channel(
                &channel,
                Box::new(|state| {
                    let mut state = state.unwrap();
                    state.lifecycle = Some(ChannelLifecycle {
                        owner: "seed".to_string(),
                        close_after: 1,
                    });
                    Ok(state)
                }),
            )
            .await
            .unwrap();

        let touched_after = unix_millis();
        let _lease = session
            .reserve_delegated_capacity(&channel, CAP)
            .await
            .unwrap()
            .expect("request should reserve channel capacity");

        let persisted = session
            .operator_runtime
            .channel_store
            .get_channel(&channel)
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
    async fn touch_honors_negotiated_idle_timeout_shorter_than_close_delay() {
        let session = Arc::new(test_session_mpp());
        let close_delay = Duration::from_secs(120);
        let negotiated_idle_timeout_seconds = 5u32;
        session.start_lifecycle_runloop_with_settlement_and_batching(
            close_delay,
            Duration::from_secs(60),
            Duration::ZERO,
            SessionLifecycleReconciliation::External,
        );
        let challenge = session.challenge(None).unwrap();
        let channel = solana_pubkey::Pubkey::new_unique().to_string();
        seed_channel(
            &session,
            &channel,
            CAP,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            "client",
            &challenge.id,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            None,
        )
        .await;
        session
            .operator_runtime
            .channel_store
            .update_channel(
                &channel,
                Box::new(move |state| {
                    let mut state = state.unwrap();
                    state.idle_timeout_seconds = Some(negotiated_idle_timeout_seconds);
                    Ok(state)
                }),
            )
            .await
            .unwrap();

        let touched_after = unix_millis();
        let _lease = session
            .reserve_delegated_capacity(&channel, CAP)
            .await
            .unwrap()
            .expect("request should reserve channel capacity");

        let persisted = session
            .operator_runtime
            .channel_store
            .get_channel(&channel)
            .await
            .unwrap()
            .unwrap();
        let close_after = persisted.lifecycle.unwrap().close_after;
        let negotiated_deadline_ms =
            u64::from(negotiated_idle_timeout_seconds).saturating_mul(1_000);
        assert!(
            close_after < touched_after.saturating_add(duration_millis(close_delay)),
            "touch must not fall back to the un-negotiated close_delay when the channel \
             selected a shorter idle_timeout_seconds"
        );
        assert!(
            close_after <= touched_after.saturating_add(negotiated_deadline_ms) + 60_000,
            "persisted deadline must be bounded by the negotiated idle timeout \
             (plus one close-batch-interval of rounding), got {close_after}"
        );
    }

    #[tokio::test]
    async fn delegated_capacity_lease_heartbeats_external_idle_deadline() {
        let session = Arc::new(test_session_mpp());
        session.start_lifecycle_runloop_with_settlement_and_batching(
            Duration::from_millis(30),
            Duration::from_millis(1),
            Duration::ZERO,
            SessionLifecycleReconciliation::External,
        );
        let challenge = session.challenge(None).unwrap();
        let channel = solana_pubkey::Pubkey::new_unique().to_string();
        seed_channel(
            &session,
            &channel,
            CAP,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            "client",
            &challenge.id,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            None,
        )
        .await;
        let lease = session
            .reserve_delegated_capacity(&channel, CAP)
            .await
            .unwrap()
            .expect("request should reserve channel capacity");
        let initial_deadline = session
            .operator_runtime
            .channel_store
            .get_channel(&channel)
            .await
            .unwrap()
            .unwrap()
            .lifecycle
            .unwrap()
            .close_after;

        tokio::time::sleep(Duration::from_millis(35)).await;

        let heartbeat_deadline = session
            .operator_runtime
            .channel_store
            .get_channel(&channel)
            .await
            .unwrap()
            .unwrap()
            .lifecycle
            .unwrap()
            .close_after;
        assert!(
            heartbeat_deadline > initial_deadline,
            "an in-flight request must renew the external worker's idle deadline"
        );

        drop(lease);
        tokio::time::sleep(Duration::from_millis(25)).await;
        let released_deadline = session
            .operator_runtime
            .channel_store
            .get_channel(&channel)
            .await
            .unwrap()
            .unwrap()
            .lifecycle
            .unwrap()
            .close_after;
        assert_eq!(
            released_deadline, heartbeat_deadline,
            "dropping the request lease must stop lifecycle heartbeats"
        );
    }

    #[tokio::test]
    async fn delegated_capacity_lease_defers_idle_close() {
        let session = Arc::new(test_session_mpp());
        session.start_lifecycle_runloop(Duration::from_millis(10));
        let challenge = session.challenge(None).unwrap();
        let channel = solana_pubkey::Pubkey::new_unique();
        let (voucher_key, signer) = test_keypair();
        let authorized_signer = signer.pubkey().to_string();
        let handle =
            SessionHandle::new(channel, signer, challenge.clone()).with_voucher_key(voucher_key);
        seed_channel(
            &session,
            &channel.to_string(),
            CAP,
            &authorized_signer,
            "client",
            &challenge.id,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            None,
        )
        .await;
        // The kit re-arms `lifecycle.close_after` from the channel's
        // negotiated `idle_timeout_seconds` on every accepted session action.
        // Production derives that negotiation from `close_delay_ms` with a
        // one-second floor; mirror the same relationship here so the kit's
        // re-arm and this test's 10ms runloop clock stay on one schedule.
        session
            .operator_runtime
            .channel_store
            .update_channel(
                &channel.to_string(),
                Box::new(|state| {
                    let mut state = state.unwrap();
                    state.idle_timeout_seconds = Some(1);
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        let lease = session
            .reserve_delegated_capacity(&channel.to_string(), CAP)
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
        // Wait out the kit's one-second re-arm window plus a margin so the
        // embedded runloop observes the lapsed deadline and closes.
        tokio::time::sleep(Duration::from_millis(1_300)).await;

        let voucher_header = handle.voucher_header(75).await.unwrap();
        let error = session.process(&voucher_header).await.unwrap_err();
        assert!(
            error.to_string().contains("close is pending"),
            "expected idle-close after lease release, got: {error}"
        );
    }

    #[tokio::test]
    async fn delegated_usage_signs_and_persists_cumulative_voucher() {
        let signer: Arc<dyn SolanaSigner> = Arc::from(test_session_signer());
        let operator = signer.pubkey();
        let mut config = test_session_config();
        config.operator = operator.to_string();
        config.voucher_signer = SessionVoucherSigner::Operator;
        let session = SessionMpp::new(config, "test-secret")
            .with_blockhash_cache(test_blockhash_cache())
            .with_payment_channel_signer(Arc::clone(&signer));
        let challenge = session.challenge(None).unwrap();
        let channel = solana_pubkey::Pubkey::new_unique().to_string();
        seed_channel(
            &session,
            &channel,
            CAP,
            &operator.to_string(),
            "operator",
            &challenge.id,
            &solana_pubkey::Pubkey::new_unique().to_string(),
            None,
        )
        .await;

        let first = tokio::time::timeout(
            Duration::from_secs(2),
            session.authorize_delegated_usage(&channel, 75),
        )
        .await
        .expect("first delegated voucher timed out")
        .unwrap();
        assert_eq!(first.cumulative, 75);
        assert_eq!(first.idle_timeout_seconds, 300);
        session.committed_watermarks.clear();
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(2),
                session.authorize_delegated_usage(&channel, 25),
            )
            .await
            .expect("second delegated voucher timed out")
            .unwrap()
            .cumulative,
            100
        );

        // Server-initiated close (idle path) seals at the accepted watermark.
        session
            .operator_runtime
            .request_server_close(&channel)
            .await
            .unwrap();
        let params = session.server.seal_params(&channel).await.unwrap();
        assert_eq!(params.settled, 100);
        assert_eq!(session.committed_watermark(&channel), Some(100));
    }

    #[tokio::test]
    async fn challenge_header_formats_session_challenge() {
        let header = test_session_mpp().challenge_header(None).unwrap();
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

    #[test]
    fn close_omits_voucher_when_watermark_already_landed() {
        assert!(close_voucher_required(4_330, 4_331));
        assert!(!close_voucher_required(4_331, 4_331));
        assert!(!close_voucher_required(4_332, 4_331));
    }

    #[test]
    fn close_reconciles_durable_state_after_failed_broadcast() {
        assert!(session_close_needs_reconciliation(
            "Close already requested"
        ));
        assert!(session_close_needs_reconciliation(
            "Channel is already sealed"
        ));
        assert!(!session_close_needs_reconciliation("Channel not found"));
    }
}
