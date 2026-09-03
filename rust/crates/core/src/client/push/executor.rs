//! The bounded, backpressured pipeline that turns a planned `pay push` run
//! into landed (or durably-failed) chunks.
//!
//! ## Where this lives
//!
//! This is `core::client::push::executor`, not a `pay-cli` module. There is
//! no `pay push` CLI subcommand yet (no arg parsing, no CSV wiring) — this
//! module is the reusable pipeline a *future* CLI subcommand would call
//! with almost no logic of its own, matching this codebase's house rule
//! that business logic belongs in a shared core crate, not a thin frontend.
//! It is also the natural place for a future MCP tool or another frontend
//! to drive a push run without duplicating any of this.
//!
//! ## Four stages, per chunk
//!
//! 1. **Instruction batching** — already done by
//!    [`super::planner::pack_chunks`]; this module just iterates the
//!    resulting `Vec<super::planner::PlannedChunk>`.
//! 2. **Transaction encoding** — [`super::planner::build_chunk_transaction`]
//!    compiles the chunk's real transaction against a live fee payer +
//!    blockhash (from [`ChunkBroadcaster::prepare`]), then
//!    [`super::permit::BatchSigningPermit::sign_chunk`] signs it.
//! 3. **Transaction sending** — [`ChunkBroadcaster::broadcast`]. Direct
//!    (self-funded) transports fire `sendTransaction` and return
//!    immediately with a *pending* signature; they never block this stage
//!    on confirmation. A gasless transport's HTTP response to pay-api's
//!    `/api/v1/transfer-batches` *is* the final, already-confirmed outcome
//!    (see that endpoint's docs), so it returns `Settled` instead.
//! 4. **Journaling** — [`super::journal::Journal::append_chunk_signed`]
//!    (durable, fsync'd) runs before stage 3's broadcast call. This isn't a
//!    convention this module has to remember to follow: the journal's
//!    `ChunkBroadcastPermit` is the only value [`Journal::append_chunk_broadcast`]
//!    accepts, and the only way to obtain one is a completed
//!    `append_chunk_signed` fsync — see `journal`'s module docs. There is no
//!    code path in [`PushExecutor::run`] that reaches a broadcast call
//!    without one in hand.
//!
//! ## Backpressure
//!
//! Signing is inherently serial (one [`super::permit::BatchSigningPermit`],
//! one mutable signer), so this executor is a single sequential loop rather
//! than a worker pool — no channels or spawned tasks are needed to get
//! genuine "many transactions in flight on the network at once" behavior.
//! Before compiling/signing the *next* chunk, [`PushExecutor::run`] blocks
//! until the number of broadcast-but-not-yet-settled signatures drops below
//! `max_in_flight`, driving that wait with **one** batched
//! [`ChunkBroadcaster::poll_pending`] call per tick covering every
//! outstanding signature — never one status lookup per signature. Because
//! `sendTransaction` itself doesn't block on confirmation, up to
//! `max_in_flight` chunks are genuinely in flight on the network
//! simultaneously; a slow poll (direct mode) or a slow synchronous
//! round trip (gasless mode, awaited per chunk since pay-api's response is
//! final) both directly throttle the loop's throughput — no separate rate
//! limiter is needed for either.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_signature::Signature;

use super::journal::Journal;
use super::permit::{BatchSigningPermit, SignedChunk};
use super::planner::{self, PlannedChunk};
use crate::{Error, Result};

/// Bounded in-flight window default — matches the "single payer, bounded
/// in-flight queue" pattern this project has converged on elsewhere.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 32;

/// How often [`PushExecutor::run`] re-polls outstanding signatures while
/// waiting for the in-flight window to free up (or draining it at the end
/// of a run).
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(800);

/// The mint/authority context [`planner::build_chunk_transaction`] needs
/// that isn't carried on a bare [`PlannedChunk`]. The CLI already has all
/// of this on hand (it's exactly `TransferManifest::context` plus the
/// account that authorized the plan), so it costs nothing to pass through
/// explicitly rather than adding new accessors to
/// [`BatchSigningPermit`]'s otherwise-private state.
#[derive(Debug, Clone, Copy)]
pub struct ChunkTxContext {
    pub sender: Pubkey,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub decimals: u8,
}

/// Fee payer + blockhash to build/sign one chunk against, resolved by
/// whichever [`ChunkBroadcaster`] is active. For a direct/self-funded
/// transport this is just a fresh `getLatestBlockhash`; for a gasless one
/// it's pay-api's 402 quote (`fee_payer` + `recentBlockhash` +
/// `challengeLastValidBlockHeight`).
#[derive(Debug, Clone, Copy)]
pub struct PreparedChunkContext {
    pub fee_payer: Pubkey,
    pub blockhash: Hash,
    pub last_valid_block_height: u64,
}

/// What broadcasting one signed chunk produced.
#[derive(Debug, Clone, Copy)]
pub enum BroadcastOutcome {
    /// Submitted, outcome not yet known. The executor tracks this
    /// signature as in-flight until [`ChunkBroadcaster::poll_pending`]
    /// reports a terminal status for it.
    Pending(Signature),
    /// Already final — nothing left to poll. A gasless transport's HTTP
    /// response to pay-api *is* the settlement outcome.
    Settled(Signature),
}

/// The result of one batched status check for a signature that was
/// previously `Pending`.
#[derive(Debug, Clone)]
pub enum PendingStatus {
    StillPending,
    Confirmed,
    Failed(String),
}

/// One in-flight signature plus the expiry it was signed against, so a
/// [`ChunkBroadcaster::poll_pending`] implementation can tell "RPC doesn't
/// see it yet, still within its validity window" apart from "RPC doesn't see
/// it and it can no longer land" — an unconfirmed signature past its
/// `last_valid_block_height` must resolve to a terminal status instead of
/// polling forever.
#[derive(Debug, Clone, Copy)]
pub struct PendingSignature {
    pub signature: Signature,
    pub last_valid_block_height: u64,
}

/// The pluggable transport [`PushExecutor`] drives. One implementation per
/// fee-payer mode: [`DirectSolanaBroadcaster`] for self-funded runs,
/// [`GaslessApiBroadcaster`] for gasless ones. Tests use a third,
/// in-memory implementation to drive the backpressure loop deterministically
/// (see `tests::MockBroadcaster` below) — the same pattern
/// `journal::ResumeRpc` and `permit`'s tests already use elsewhere in this
/// module tree.
///
/// Uses native `async fn` rather than `#[async_trait]`: `PushExecutor` is
/// generic over `B: ChunkBroadcaster` (never `dyn`), so there's no
/// object-safety need for a boxed future, and every call site in this
/// module already runs on a single task — the auto-`Send` bound the lint
/// below is warning about doesn't matter here.
#[allow(async_fn_in_trait)]
pub trait ChunkBroadcaster {
    /// Resolve the fee payer + blockhash to build `chunk` against.
    async fn prepare(&self, chunk: &PlannedChunk) -> Result<PreparedChunkContext>;
    /// Submit an already-signed chunk.
    async fn broadcast(&self, signed: &SignedChunk) -> Result<BroadcastOutcome>;
    /// One batched status check for every currently-outstanding signature.
    /// Must return exactly one status per input signature, in the same
    /// order.
    async fn poll_pending(&self, pending: &[PendingSignature]) -> Result<Vec<PendingStatus>>;
}

/// Tunables for [`PushExecutor::run`]'s bounded in-flight loop.
#[derive(Debug, Clone, Copy)]
pub struct PushExecutorConfig {
    pub max_in_flight: usize,
    pub poll_interval: Duration,
}

impl Default for PushExecutorConfig {
    fn default() -> Self {
        Self {
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            poll_interval: DEFAULT_POLL_INTERVAL,
        }
    }
}

/// Outcome counts for a completed (or interrupted) [`PushExecutor::run`]
/// call. The journal is the durable source of truth for exactly which rows
/// landed; this is a coarse summary for the CLI to print.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunSummary {
    pub confirmed: usize,
    pub failed: usize,
}

struct InFlightChunk {
    chunk_index: u32,
    signature: Signature,
    last_valid_block_height: u64,
}

/// Drives stages 2-4 for a sequence of already-planned chunks (stage 1).
/// Borrows the permit and journal for the run's duration — both are
/// single-writer by design (see their own module docs), which is exactly
/// what a sequential executor loop needs.
pub struct PushExecutor<'a, B: ChunkBroadcaster> {
    permit: &'a mut BatchSigningPermit,
    journal: &'a mut Journal,
    broadcaster: &'a B,
    ctx: ChunkTxContext,
    config: PushExecutorConfig,
}

impl<'a, B: ChunkBroadcaster> PushExecutor<'a, B> {
    pub fn new(
        permit: &'a mut BatchSigningPermit,
        journal: &'a mut Journal,
        broadcaster: &'a B,
        ctx: ChunkTxContext,
        config: PushExecutorConfig,
    ) -> Self {
        Self {
            permit,
            journal,
            broadcaster,
            ctx,
            config,
        }
    }

    /// Run every chunk in `chunks` through stages 2-4, in order. The caller
    /// is responsible for having already reduced `journal::reduce_chunk_resume_action`
    /// down to the chunks that actually still need work on a resume — this
    /// executor always attempts everything it's handed.
    pub async fn run(&mut self, chunks: &[PlannedChunk]) -> Result<RunSummary> {
        let mut in_flight: Vec<InFlightChunk> = Vec::new();
        let mut summary = RunSummary::default();

        for chunk in chunks {
            // Backpressure: never let more than `max_in_flight` broadcast
            // signatures sit unconfirmed at once. Blocks here, not by
            // refusing to accept work, but by refusing to *sign and send
            // more* until room frees up.
            while in_flight.len() >= self.config.max_in_flight {
                self.drain_in_flight(&mut in_flight, &mut summary).await?;
                if in_flight.len() >= self.config.max_in_flight {
                    tokio::time::sleep(self.config.poll_interval).await;
                }
            }

            let prepared = self.broadcaster.prepare(chunk).await?;

            // Stage 2: encode + sign.
            let transaction = planner::build_chunk_transaction(
                chunk,
                &self.ctx.mint,
                &self.ctx.token_program,
                self.ctx.decimals,
                &self.ctx.sender,
                &prepared.fee_payer,
                prepared.blockhash,
            )?;
            let signed = sign_off_runtime_thread(
                self.permit,
                chunk.chunk_index,
                &transaction,
                prepared.last_valid_block_height,
            )?;

            // Stage 4 (before stage 3, structurally): durable write, then
            // the only credential that can ever reach `append_chunk_broadcast`.
            let (_, broadcast_permit) = self.journal.append_chunk_signed(
                signed.chunk_index,
                signed.row_numbers.clone(),
                &signed.signature,
                signed.signed_transaction_base64.clone(),
                &signed.blockhash,
                signed.last_valid_block_height,
            )?;

            // Stage 3: send.
            match self.broadcaster.broadcast(&signed).await {
                Ok(BroadcastOutcome::Pending(signature)) => {
                    self.journal
                        .append_chunk_broadcast(broadcast_permit, &signature)?;
                    in_flight.push(InFlightChunk {
                        chunk_index: signed.chunk_index,
                        signature,
                        last_valid_block_height: signed.last_valid_block_height,
                    });
                }
                Ok(BroadcastOutcome::Settled(signature)) => {
                    self.journal
                        .append_chunk_broadcast(broadcast_permit, &signature)?;
                    self.journal
                        .append_chunk_confirmed(signed.chunk_index, &signature)?;
                    summary.confirmed += 1;
                }
                Err(error) => {
                    // `broadcast_permit` (a `Copy` marker type) is simply
                    // left unused here: it only ever proved a signed record
                    // exists before a broadcast *attempt* — it never
                    // promised the attempt succeeds. Never calling
                    // `append_chunk_broadcast` is correct: no signature was
                    // ever produced by the network to record.
                    let _ = broadcast_permit;
                    self.journal.append_chunk_failed(
                        signed.chunk_index,
                        error.to_string(),
                        true,
                    )?;
                    summary.failed += 1;
                }
            }
        }

        // Drain whatever's still outstanding before reporting a final tally.
        while !in_flight.is_empty() {
            self.drain_in_flight(&mut in_flight, &mut summary).await?;
            if !in_flight.is_empty() {
                tokio::time::sleep(self.config.poll_interval).await;
            }
        }

        Ok(summary)
    }

    /// One batched status check covering every currently in-flight
    /// signature — never one call per signature.
    async fn drain_in_flight(
        &mut self,
        in_flight: &mut Vec<InFlightChunk>,
        summary: &mut RunSummary,
    ) -> Result<()> {
        if in_flight.is_empty() {
            return Ok(());
        }
        let pending: Vec<PendingSignature> = in_flight
            .iter()
            .map(|c| PendingSignature {
                signature: c.signature,
                last_valid_block_height: c.last_valid_block_height,
            })
            .collect();
        let statuses = self.broadcaster.poll_pending(&pending).await?;
        if statuses.len() != in_flight.len() {
            return Err(Error::Config(
                "poll_pending returned a different number of statuses than signatures queried"
                    .to_string(),
            ));
        }

        let mut still_pending = Vec::new();
        for (chunk, status) in in_flight.drain(..).zip(statuses) {
            match status {
                PendingStatus::StillPending => still_pending.push(chunk),
                PendingStatus::Confirmed => {
                    self.journal
                        .append_chunk_confirmed(chunk.chunk_index, &chunk.signature)?;
                    summary.confirmed += 1;
                }
                PendingStatus::Failed(reason) => {
                    self.journal
                        .append_chunk_failed(chunk.chunk_index, reason, true)?;
                    summary.failed += 1;
                }
            }
        }
        *in_flight = still_pending;
        Ok(())
    }
}

/// Run [`BatchSigningPermit::sign_chunk`] on a plain native thread rather
/// than calling it directly from `PushExecutor::run`'s async task.
///
/// `sign_chunk` is a synchronous method that internally drives its own
/// isolated single-threaded Tokio runtime (`BatchSigningPermit` builds it
/// once in `authorize` and reuses it for every signature, so a CLI's
/// one-approval flow doesn't need its caller to be async at all). Calling
/// it directly from inside `PushExecutor::run` — which must itself run on a
/// Tokio runtime to `.await` the broadcaster — would try to enter a runtime
/// from a thread Tokio already considers "inside a runtime" and panic
/// ("Cannot start a runtime from within a runtime"), regardless of the two
/// runtimes being different instances. A plain OS thread carries no such
/// context, so signing there sidesteps the conflict entirely; joining it
/// blocks this task exactly as long as signing takes, which is the
/// executor's intended sequential behavior anyway (see the module docs'
/// "Backpressure" section — stage 2 is not part of what needs concurrency).
fn sign_off_runtime_thread(
    permit: &mut BatchSigningPermit,
    chunk_index: u32,
    transaction: &solana_transaction::Transaction,
    last_valid_block_height: u64,
) -> Result<SignedChunk> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| permit.sign_chunk(chunk_index, transaction, last_valid_block_height))
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

/// Drop a [`BatchSigningPermit`] safely from inside a Tokio runtime.
///
/// `BatchSigningPermit` owns a single-threaded Tokio `Runtime` (built once
/// in `authorize` and reused by every `sign_chunk`/`resign_chunk` call, so a
/// CLI never has to be async just to sign) — see that type's docs.
/// `Runtime`'s `Drop` impl blocks the current thread waiting for its worker
/// to shut down, which panics ("cannot drop a runtime in a context where
/// blocking is not allowed") if that drop happens on a thread that's
/// already inside a *different* async runtime, e.g. the one driving
/// [`PushExecutor::run`].
///
/// This is a real interop gap between `permit`'s synchronous-by-design API
/// and any async caller — not something `PushExecutor` can paper over
/// internally, since ownership of the permit (and therefore of *when* it
/// gets dropped) belongs to the executor's caller. Flagged here rather than
/// silently worked around: anything that constructs a `BatchSigningPermit`
/// and then runs inside a Tokio runtime — this module's own tests included —
/// must drop it through this helper (or an equivalent off-runtime thread)
/// instead of letting an in-scope drop happen inline.
pub fn drop_permit_off_runtime_thread(permit: BatchSigningPermit) {
    let _ = std::thread::scope(|scope| scope.spawn(move || drop(permit)).join());
}

// ── Production transports ───────────────────────────────────────────────

/// Self-funded mode: broadcast straight to a Solana JSON-RPC endpoint.
/// `fee_payer` is the sender's own pubkey in this mode (self-funded means
/// the sender pays its own fees).
///
/// This is a small, hand-rolled JSON-RPC client rather than a dependency on
/// `solana-client` (a `[dev-dependencies]`-only crate in this workspace) or
/// `pay-api-core::RpcClient` (which `core` cannot depend on — see
/// `pay-api-core::transfer_batch`'s module docs for the equivalent
/// constraint in the other direction). It intentionally only implements the
/// three calls this transport needs.
pub struct DirectSolanaBroadcaster {
    http: reqwest::Client,
    rpc_url: String,
    fee_payer: Pubkey,
    blockhash_cache: tokio::sync::Mutex<Option<(PreparedChunkContext, Instant)>>,
}

impl DirectSolanaBroadcaster {
    pub fn new(rpc_url: String, fee_payer: Pubkey) -> Self {
        Self {
            http: reqwest::Client::new(),
            rpc_url,
            fee_payer,
            blockhash_cache: tokio::sync::Mutex::new(None),
        }
    }

    async fn call(&self, body: serde_json::Value) -> Result<serde_json::Value> {
        let response = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Config(format!("RPC transport error: {e}")))?;
        let parsed: serde_json::Value = response
            .json()
            .await
            .map_err(|e| Error::Config(format!("RPC response was not valid JSON: {e}")))?;
        if let Some(error) = parsed.get("error") {
            return Err(Error::Config(format!("RPC returned an error: {error}")));
        }
        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| Error::Config("RPC response is missing `result`".to_string()))
    }

    async fn fetch_block_height(&self) -> Result<u64> {
        let result = self
            .call(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBlockHeight",
                "params": [{ "commitment": "confirmed" }],
            }))
            .await?;
        result
            .as_u64()
            .ok_or_else(|| Error::Config("malformed getBlockHeight response".to_string()))
    }
}

/// What a `null` `getSignatureStatuses` entry means once the current
/// confirmed block height is known: still within the signed blockhash's
/// validity window (RPC just hasn't seen it, or hasn't indexed it, yet), or
/// past it (the transaction can never land, on-chain or off — the loop that
/// keeps polling this signature must stop, not spin forever).
fn classify_missing_signature(
    current_block_height: u64,
    last_valid_block_height: u64,
) -> PendingStatus {
    if current_block_height > last_valid_block_height {
        PendingStatus::Failed(format!(
            "signature not found and its blockhash expired (current height \
             {current_block_height} > last valid height {last_valid_block_height})"
        ))
    } else {
        PendingStatus::StillPending
    }
}

impl ChunkBroadcaster for DirectSolanaBroadcaster {
    async fn prepare(&self, _chunk: &PlannedChunk) -> Result<PreparedChunkContext> {
        let mut cache = self.blockhash_cache.lock().await;
        if let Some((prepared, fetched_at)) = *cache
            && fetched_at.elapsed() < Duration::from_secs(5)
        {
            return Ok(prepared);
        }
        let result = self
            .call(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getLatestBlockhash",
                "params": [{ "commitment": "confirmed" }],
            }))
            .await?;
        let blockhash_str = result
            .pointer("/value/blockhash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Config("malformed getLatestBlockhash response".to_string()))?;
        let last_valid_block_height = result
            .pointer("/value/lastValidBlockHeight")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Config("malformed getLatestBlockhash response".to_string()))?;
        let blockhash = Hash::from_str(blockhash_str).map_err(|_| {
            Error::Config("getLatestBlockhash returned a malformed blockhash".to_string())
        })?;
        let prepared = PreparedChunkContext {
            fee_payer: self.fee_payer,
            blockhash,
            last_valid_block_height,
        };
        *cache = Some((prepared, Instant::now()));
        Ok(prepared)
    }

    async fn broadcast(&self, signed: &SignedChunk) -> Result<BroadcastOutcome> {
        let result = self
            .call(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "sendTransaction",
                "params": [
                    signed.signed_transaction_base64,
                    {
                        "encoding": "base64",
                        "skipPreflight": false,
                        "preflightCommitment": "confirmed",
                        "maxRetries": 0,
                    }
                ],
            }))
            .await?;
        let signature_str = result
            .as_str()
            .ok_or_else(|| Error::Config("malformed sendTransaction response".to_string()))?;
        let signature = Signature::from_str(signature_str).map_err(|_| {
            Error::Config("sendTransaction returned a malformed signature".to_string())
        })?;
        Ok(BroadcastOutcome::Pending(signature))
    }

    async fn poll_pending(&self, pending: &[PendingSignature]) -> Result<Vec<PendingStatus>> {
        if pending.is_empty() {
            return Ok(Vec::new());
        }
        let signature_strings: Vec<String> =
            pending.iter().map(|p| p.signature.to_string()).collect();
        let result = self
            .call(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getSignatureStatuses",
                "params": [signature_strings, { "searchTransactionHistory": true }],
            }))
            .await?;
        let entries = result
            .get("value")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::Config("malformed getSignatureStatuses response".to_string()))?;
        if entries.len() != pending.len() {
            return Err(Error::Config(
                "getSignatureStatuses returned a different number of entries than signatures queried"
                    .to_string(),
            ));
        }

        // Fetched lazily and at most once per call: a `null` status entry
        // needs the current block height to tell "still within its
        // validity window" apart from "expired, and will never confirm" —
        // most polls see no `null` entries at all and never pay for it.
        let mut current_block_height: Option<u64> = None;

        let mut statuses = Vec::with_capacity(entries.len());
        for (entry, pending_signature) in entries.iter().zip(pending) {
            if entry.is_null() {
                let height = match current_block_height {
                    Some(height) => height,
                    None => {
                        let height = self.fetch_block_height().await?;
                        current_block_height = Some(height);
                        height
                    }
                };
                statuses.push(classify_missing_signature(
                    height,
                    pending_signature.last_valid_block_height,
                ));
                continue;
            }
            let failed = entry.get("err").map(|err| !err.is_null()).unwrap_or(false);
            if failed {
                statuses.push(PendingStatus::Failed(format!(
                    "transaction failed on-chain: {}",
                    entry.get("err").cloned().unwrap_or_default()
                )));
                continue;
            }
            let confirmation = entry
                .get("confirmationStatus")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if confirmation == "confirmed" || confirmation == "finalized" {
                statuses.push(PendingStatus::Confirmed);
            } else {
                statuses.push(PendingStatus::StillPending);
            }
        }
        Ok(statuses)
    }
}

/// Gasless mode: every chunk goes through pay-api's
/// `POST /api/v1/transfer-batches` two-step flow (see that endpoint's
/// module docs in `pay-api-core::transfer_batch`) instead of a direct RPC
/// call.
///
pub struct GaslessApiBroadcaster {
    http: reqwest::Client,
    /// e.g. `https://pay.example.com/api/v1/transfer-batches`.
    endpoint: String,
    batch_id: String,
    sender: Pubkey,
    currency: String,
    network: &'static str,
    decimals: u8,
    prepared_requests: Mutex<HashMap<u32, serde_json::Value>>,
}

impl GaslessApiBroadcaster {
    pub fn new(
        endpoint: String,
        batch_id: String,
        sender: Pubkey,
        currency: String,
        network: &'static str,
        decimals: u8,
    ) -> Self {
        Self {
            http: reqwest::Client::new(),
            endpoint,
            batch_id,
            sender,
            currency,
            network,
            decimals,
            prepared_requests: Mutex::new(HashMap::new()),
        }
    }

    fn request_body(&self, chunk: &PlannedChunk) -> serde_json::Value {
        use crate::client::send::format_token_amount;

        serde_json::json!({
            "batchId": self.batch_id,
            "chunkIndex": chunk.chunk_index,
            "sender": self.sender.to_string(),
            "currency": self.currency,
            "network": self.network,
            "transfers": chunk.entries.iter().map(|entry| serde_json::json!({
                "rowId": entry.row_number,
                "recipient": entry.recipient.to_string(),
                "amount": format_token_amount(entry.amount_raw, self.decimals),
            })).collect::<Vec<_>>(),
        })
    }
}

impl ChunkBroadcaster for GaslessApiBroadcaster {
    async fn prepare(&self, chunk: &PlannedChunk) -> Result<PreparedChunkContext> {
        let request = self.request_body(chunk);
        let response = self
            .http
            .post(&self.endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::Config(format!("pay-api transport error: {e}")))?;
        if response.status().as_u16() != 402 {
            return Err(Error::Config(format!(
                "pay-api quote returned unexpected status {}",
                response.status()
            )));
        }
        let body: serde_json::Value = response.json().await.map_err(|e| {
            Error::Config(format!("pay-api quote response was not valid JSON: {e}"))
        })?;
        let fee_payer_str = body
            .get("feePayer")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Config("pay-api quote is missing feePayer".to_string()))?;
        let blockhash_str = body
            .get("recentBlockhash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Config("pay-api quote is missing recentBlockhash".to_string()))?;
        let last_valid_block_height = body
            .get("challengeLastValidBlockHeight")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                Error::Config("pay-api quote is missing challengeLastValidBlockHeight".to_string())
            })?;

        self.prepared_requests
            .lock()
            .map_err(|_| Error::Config("gasless request cache lock poisoned".to_string()))?
            .insert(chunk.chunk_index, request);
        Ok(PreparedChunkContext {
            fee_payer: Pubkey::from_str(fee_payer_str).map_err(|_| {
                Error::Config("pay-api quote returned a malformed feePayer".to_string())
            })?,
            blockhash: Hash::from_str(blockhash_str).map_err(|_| {
                Error::Config("pay-api quote returned a malformed recentBlockhash".to_string())
            })?,
            last_valid_block_height,
        })
    }

    async fn broadcast(&self, signed: &SignedChunk) -> Result<BroadcastOutcome> {
        let request = self
            .prepared_requests
            .lock()
            .map_err(|_| Error::Config("gasless request cache lock poisoned".to_string()))?
            .get(&signed.chunk_index)
            .cloned()
            .ok_or_else(|| {
                Error::Config(format!(
                    "missing prepared gasless request for chunk {}",
                    signed.chunk_index
                ))
            })?;
        let response = self
            .http
            .post(&self.endpoint)
            .header(
                "Authorization",
                format!("Bearer {}", signed.signed_transaction_base64),
            )
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::Config(format!("pay-api transport error: {e}")))?;
        if !response.status().is_success() {
            return Err(Error::Config(format!(
                "pay-api submit returned unexpected status {}",
                response.status()
            )));
        }
        let body: serde_json::Value = response.json().await.map_err(|e| {
            Error::Config(format!("pay-api submit response was not valid JSON: {e}"))
        })?;
        let signature_str = body
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::Config("pay-api submit response is missing signature".to_string())
            })?;
        let signature = Signature::from_str(signature_str).map_err(|_| {
            Error::Config("pay-api submit returned a malformed signature".to_string())
        })?;
        self.prepared_requests
            .lock()
            .map_err(|_| Error::Config("gasless request cache lock poisoned".to_string()))?
            .remove(&signed.chunk_index);
        Ok(BroadcastOutcome::Settled(signature))
    }

    async fn poll_pending(&self, _pending: &[PendingSignature]) -> Result<Vec<PendingStatus>> {
        // `broadcast` never returns `Pending` for this transport (pay-api's
        // response is always final), so the executor should never call
        // this. Fail loudly rather than silently reporting a wrong status
        // if that assumption is ever broken.
        Err(Error::Config(
            "GaslessApiBroadcaster::poll_pending should never be called: broadcast() never returns Pending".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{Account, AccountsFile, Keystore, MemoryAccountsStore};
    use crate::client::push::manifest::{ManifestContext, parse_manifest_csv};
    use crate::client::push::planner::{
        AtaSnapshot, DestinationAtaStatus, FeePayerMode, PlannedTransferEntry, pack_chunks,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn fresh_account_and_store() -> (MemoryAccountsStore, Pubkey) {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let mut full = Vec::with_capacity(64);
        full.extend_from_slice(&signing_key.to_bytes());
        full.extend_from_slice(&verifying_key.to_bytes());

        let account = Account {
            keystore: Keystore::Ephemeral,
            provider: None,
            active: false,
            auth_required: Some(false),
            pubkey: Some(bs58::encode(verifying_key.to_bytes()).into_string()),
            vault: None,
            account: None,
            path: None,
            secret_key_b58: Some(bs58::encode(&full).into_string()),
            created_at: Some("2026-08-12T00:00:00Z".to_string()),
            subscriptions: std::collections::BTreeMap::new(),
        };

        let mut file = AccountsFile::default();
        file.upsert("localnet", "default", account);
        let store = MemoryAccountsStore::with_file(file);
        let pubkey = Pubkey::new_from_array(verifying_key.to_bytes());
        (store, pubkey)
    }

    #[test]
    fn gasless_request_keeps_transfer_data_and_uses_mint_decimals() {
        let sender = Pubkey::new_from_array([1; 32]);
        let recipient = Pubkey::new_from_array([2; 32]);
        let broadcaster = GaslessApiBroadcaster::new(
            "https://pay.example/api/v1/transfer-batches".to_string(),
            "batch-1".to_string(),
            sender,
            "USDG".to_string(),
            "devnet",
            2,
        );
        let chunk = PlannedChunk {
            chunk_index: 7,
            entries: vec![PlannedTransferEntry {
                row_number: 42,
                recipient,
                amount_raw: 123,
                ata_creation_required: false,
            }],
            compute_unit_price_micro_lamports: 0,
            compute_unit_limit: 0,
            memo: "test".to_string(),
            serialized_len: 0,
        };

        let body = broadcaster.request_body(&chunk);
        assert_eq!(body["transfers"][0]["rowId"], 42);
        assert_eq!(body["transfers"][0]["recipient"], recipient.to_string());
        assert_eq!(body["transfers"][0]["amount"], "1.23");
    }

    /// Builds a fresh keystore-backed account, plans `rows` gasless
    /// transfers against it, and authorizes a permit for the plan. The
    /// returned `Pubkey` is the plan's authority (`sender`) — it comes from
    /// the store's actual loaded keypair, not an arbitrary caller-supplied
    /// value, since the permit internally re-derives its own `source_ata`
    /// from whichever key it loaded and every `sign_chunk` call re-checks
    /// that the transaction's authority matches it exactly.
    fn plan_and_permit(
        rows: usize,
    ) -> (
        BatchSigningPermit,
        Vec<PlannedChunk>,
        ChunkTxContext,
        Pubkey,
    ) {
        let (store, sender) = fresh_account_and_store();
        let mut csv = String::from("recipient,amount\n");
        for i in 0..rows {
            let recipient = Pubkey::new_from_array([(i + 10) as u8; 32]);
            csv.push_str(&format!("{recipient},1\n"));
        }
        let context = ManifestContext {
            network_genesis_hash: [3; 32],
            mint: Pubkey::new_from_array([77; 32]),
            token_program: super::planner::token_program_id(),
            decimals: 6,
        };
        let manifest = parse_manifest_csv(csv.as_bytes(), context).unwrap();
        let ata = AtaSnapshot {
            sender_ata: Pubkey::new_unique(),
            sender_ata_exists: true,
            destinations: manifest
                .rows
                .iter()
                .map(|row| DestinationAtaStatus {
                    recipient: row.recipient,
                    ata: Pubkey::new_unique(),
                    exists: true,
                })
                .collect(),
        };
        let fee_payer = Pubkey::new_unique();
        let plan = pack_chunks(
            &manifest,
            &ata,
            FeePayerMode::Gasless,
            &sender,
            &fee_payer,
            1,
        )
        .unwrap();
        let max_total_raw = plan.total_token_raw().unwrap();
        let summary = super::super::permit::BatchAuthorizationSummary {
            account: "default",
            currency: "USDG",
            currency_decimals: 6,
            network: "localnet",
            recipient_total_raw: max_total_raw,
            max_total_raw,
        };
        let permit = BatchSigningPermit::authorize(
            "localnet",
            &store,
            Some("default"),
            manifest.context.network_genesis_hash,
            &manifest,
            plan.clone(),
            summary,
            chrono::Duration::hours(1),
            None,
        )
        .unwrap();
        let ctx = ChunkTxContext {
            sender,
            mint: manifest.context.mint,
            token_program: manifest.context.token_program,
            decimals: manifest.context.decimals,
        };
        (permit, plan.chunks, ctx, sender)
    }

    /// An in-memory transport that always returns `Pending`, confirms a
    /// signature only after it has been polled `confirm_after_polls` times,
    /// and records the maximum number of signatures ever passed to one
    /// `poll_pending` call — the thing every backpressure test asserts on.
    struct MockBroadcaster {
        fee_payer: Pubkey,
        confirm_after_polls: u32,
        poll_counts: Mutex<HashMap<Signature, u32>>,
        max_batch_seen: Mutex<usize>,
        prepare_calls: Mutex<usize>,
    }

    impl MockBroadcaster {
        fn new(fee_payer: Pubkey, confirm_after_polls: u32) -> Self {
            Self {
                fee_payer,
                confirm_after_polls,
                poll_counts: Mutex::new(HashMap::new()),
                max_batch_seen: Mutex::new(0),
                prepare_calls: Mutex::new(0),
            }
        }

        fn max_batch_seen(&self) -> usize {
            *self.max_batch_seen.lock().unwrap()
        }

        fn prepare_calls(&self) -> usize {
            *self.prepare_calls.lock().unwrap()
        }
    }

    impl ChunkBroadcaster for MockBroadcaster {
        async fn prepare(&self, _chunk: &PlannedChunk) -> Result<PreparedChunkContext> {
            *self.prepare_calls.lock().unwrap() += 1;
            Ok(PreparedChunkContext {
                fee_payer: self.fee_payer,
                blockhash: Hash::new_unique(),
                last_valid_block_height: 1_000_000,
            })
        }

        async fn broadcast(&self, signed: &SignedChunk) -> Result<BroadcastOutcome> {
            Ok(BroadcastOutcome::Pending(signed.signature))
        }

        async fn poll_pending(&self, pending: &[PendingSignature]) -> Result<Vec<PendingStatus>> {
            let mut counts = self.poll_counts.lock().unwrap();
            let mut max_batch_seen = self.max_batch_seen.lock().unwrap();
            *max_batch_seen = (*max_batch_seen).max(pending.len());

            let mut out = Vec::with_capacity(pending.len());
            for p in pending {
                let count = counts.entry(p.signature).or_insert(0);
                *count += 1;
                if *count >= self.confirm_after_polls {
                    out.push(PendingStatus::Confirmed);
                } else {
                    out.push(PendingStatus::StillPending);
                }
            }
            Ok(out)
        }
    }

    #[tokio::test]
    async fn run_confirms_every_chunk_and_journals_signed_before_broadcast() {
        let (mut permit, chunks, ctx, _sender) = plan_and_permit(5);
        let broadcaster = MockBroadcaster::new(permit.fee_payer(), 1); // confirms on first poll

        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::create_new(dir.path().join("run.jsonl")).unwrap();
        let config = PushExecutorConfig {
            max_in_flight: 2,
            poll_interval: Duration::from_millis(1),
        };
        let mut executor = PushExecutor::new(&mut permit, &mut journal, &broadcaster, ctx, config);

        let summary = executor.run(&chunks).await.unwrap();
        assert_eq!(summary.confirmed, chunks.len());
        assert_eq!(summary.failed, 0);
        assert_eq!(broadcaster.prepare_calls(), chunks.len());

        let events =
            super::super::journal::load_events(dir.path().join("run.jsonl").as_path()).unwrap();
        let mut last_signed_sequence: HashMap<u32, u64> = HashMap::new();
        for event in &events {
            match &event.kind {
                super::super::journal::JournalEventKind::ChunkSigned { chunk_index, .. } => {
                    last_signed_sequence.insert(*chunk_index, event.sequence);
                }
                super::super::journal::JournalEventKind::ChunkBroadcast { chunk_index, .. } => {
                    let signed_at = last_signed_sequence
                        .get(chunk_index)
                        .expect("a chunk_broadcast event must always be preceded by chunk_signed");
                    assert!(
                        *signed_at < event.sequence,
                        "chunk {chunk_index}: chunk_signed ({signed_at}) must precede chunk_broadcast ({})",
                        event.sequence
                    );
                }
                _ => {}
            }
        }
        drop_permit_off_runtime_thread(permit);
    }

    #[tokio::test]
    async fn run_never_exceeds_the_configured_in_flight_window() {
        // 40 rows, gasless-capped at MAX_SPLITS=8 transfers per chunk with
        // pre-existing ATAs, packs as 8+8+8+8+8 = 5 chunks — plenty to
        // exercise a max_in_flight=3 window.
        let (mut permit, chunks, ctx, _sender) = plan_and_permit(40);
        assert!(
            chunks.len() >= 4,
            "need several chunks to exercise the window"
        );

        // Never confirms: every broadcast chunk stays pending forever, which
        // is exactly the "slow RPC" scenario backpressure has to survive
        // without ever letting more than `max_in_flight` signatures pile up.
        // `run` would then never return, so it's bounded by a timeout and
        // never expected to complete — what's under test is what the mock
        // observed before the timeout fired.
        let broadcaster = MockBroadcaster::new(permit.fee_payer(), u32::MAX);
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::create_new(dir.path().join("run.jsonl")).unwrap();
        let config = PushExecutorConfig {
            max_in_flight: 3,
            poll_interval: Duration::from_millis(1),
        };
        let mut executor = PushExecutor::new(&mut permit, &mut journal, &broadcaster, ctx, config);

        let result = tokio::time::timeout(Duration::from_millis(200), executor.run(&chunks)).await;
        assert!(
            result.is_err(),
            "run should still be blocked on confirmations that never arrive"
        );

        // The window must have filled (proving the bound is actually
        // reached, not just never violated because nothing ran) and must
        // never have been exceeded.
        assert_eq!(broadcaster.max_batch_seen(), 3);
        drop_permit_off_runtime_thread(permit);
    }

    #[tokio::test]
    async fn poll_pending_is_always_called_with_every_outstanding_signature_at_once() {
        // 20 rows packs as 8+8+4 = 3 chunks (see
        // `planner::tests::gasless_chunks_cap_at_eight_transfers`).
        let (mut permit, chunks, ctx, _sender) = plan_and_permit(20);
        assert!(
            chunks.len() > 1,
            "need multiple chunks for a batched poll to be meaningful"
        );
        let broadcaster = MockBroadcaster::new(permit.fee_payer(), 2); // confirms on 2nd poll
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::create_new(dir.path().join("run.jsonl")).unwrap();
        let config = PushExecutorConfig {
            max_in_flight: 10, // large enough that every chunk is in flight together
            poll_interval: Duration::from_millis(1),
        };
        let mut executor = PushExecutor::new(&mut permit, &mut journal, &broadcaster, ctx, config);

        let summary = executor.run(&chunks).await.unwrap();
        assert_eq!(summary.confirmed, chunks.len());
        // Every chunk should have been outstanding simultaneously by the
        // time the final drain loop polls them, proving `poll_pending` is
        // called with a batch, not once per signature.
        assert_eq!(broadcaster.max_batch_seen(), chunks.len());
        drop_permit_off_runtime_thread(permit);
    }

    struct FailingBroadcaster {
        fee_payer: Pubkey,
    }

    impl ChunkBroadcaster for FailingBroadcaster {
        async fn prepare(&self, _chunk: &PlannedChunk) -> Result<PreparedChunkContext> {
            Ok(PreparedChunkContext {
                fee_payer: self.fee_payer,
                blockhash: Hash::new_unique(),
                last_valid_block_height: 1_000_000,
            })
        }

        async fn broadcast(&self, _signed: &SignedChunk) -> Result<BroadcastOutcome> {
            Err(Error::Config("simulated broadcast failure".to_string()))
        }

        async fn poll_pending(&self, pending: &[PendingSignature]) -> Result<Vec<PendingStatus>> {
            Ok(pending
                .iter()
                .map(|_| PendingStatus::StillPending)
                .collect())
        }
    }

    #[tokio::test]
    async fn a_broadcast_error_is_journaled_as_failed_without_a_broadcast_event() {
        let (mut permit, chunks, ctx, _sender) = plan_and_permit(1);
        let broadcaster = FailingBroadcaster {
            fee_payer: permit.fee_payer(),
        };
        let dir = tempfile::tempdir().unwrap();
        let mut journal = Journal::create_new(dir.path().join("run.jsonl")).unwrap();
        let mut executor = PushExecutor::new(
            &mut permit,
            &mut journal,
            &broadcaster,
            ctx,
            PushExecutorConfig::default(),
        );

        let summary = executor.run(&chunks).await.unwrap();
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.confirmed, 0);

        let events =
            super::super::journal::load_events(dir.path().join("run.jsonl").as_path()).unwrap();
        assert!(events.iter().any(|e| matches!(
            e.kind,
            super::super::journal::JournalEventKind::ChunkFailed { .. }
        )));
        assert!(!events.iter().any(|e| matches!(
            e.kind,
            super::super::journal::JournalEventKind::ChunkBroadcast { .. }
        )));
        drop_permit_off_runtime_thread(permit);
    }

    #[test]
    fn missing_signature_within_validity_window_stays_pending() {
        assert!(matches!(
            classify_missing_signature(999, 1_000),
            PendingStatus::StillPending
        ));
        // Still valid at the exact boundary height.
        assert!(matches!(
            classify_missing_signature(1_000, 1_000),
            PendingStatus::StillPending
        ));
    }

    #[test]
    fn missing_signature_past_its_expiry_is_a_terminal_failure_not_still_pending() {
        // This is the exact bug Greptile flagged: a `null` status entry
        // must not be treated as `StillPending` forever once the signed
        // blockhash can no longer land.
        match classify_missing_signature(1_001, 1_000) {
            PendingStatus::Failed(reason) => assert!(reason.contains("expired")),
            other => panic!("expected a terminal Failed status, got {other:?}"),
        }
    }
}
