//! x402 `batch-settlement` scheme — push mode. Cloned from `mpp_session`,
//! with the wire format swapped from MPP session vouchers to the x402
//! `batch-settlement` `PAYMENT-SIGNATURE` envelope.
//!
//! Per user (= one escrow channel):
//!   - **provision** (on-chain, once): fetch the endpoint's 402 `batch-settlement`
//!     challenge, resolve its terms, build a sponsored `deposit` (channel `open`
//!     + first voucher), and send it under the `PAYMENT-SIGNATURE` header. The
//!     sponsor (`extra.feePayer`) co-signs + broadcasts; the client pays no SOL.
//!   - **prepare** (off-chain): pre-sign N ordered cumulative vouchers (monotonic
//!     watermark, `expiresAt = 0`) → ready-to-fire `PAYMENT-SIGNATURE` headers.
//!   - **unleash**: the driver fires the vouchers in order (cheap; the gateway
//!     ed25519-verifies each and serves immediately, redeeming later in batches).
//!   - **settle_and_close**: send a payer-signed `refund` (`request_close`).
//!
//! Only the wire format differs from `mpp_session`: the signer-pool threading,
//! per-channel queue lanes, closed-loop, and [`HotPathGuard`] are identical.

use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use crossbeam_queue::ArrayQueue;
use ed25519_dalek::{Signer as _, SigningKey};
use pay_kit::core::payment_channels as pc;
use pay_kit::mpp::solana_keychain::memory::MemorySigner;
use pay_kit::x402::PAYMENT_SIGNATURE_HEADER;
use pay_kit::x402::client::batch_settlement::{
    BatchChannel, build_deposit, build_refund, encode_payment_header, parse_challenge,
    resolve_terms_with_token_program,
};
use pay_kit::x402::protocol::schemes::batch_settlement::{
    BatchChannelConfig, BatchPayload, BatchRequirements, BatchVoucher, VOUCHER_EXPIRES_AT,
};
use reqwest::StatusCode;
use solana_hash::Hash;
use solana_pubkey::Pubkey;

use super::{
    BenchScheme, Endpoint, HotPathGuard, HotPathStats, Load, PerUserFunding, PreparedRequest,
    RequestSource, ResolvedPrice, UserCtx, UserSetup, build_request, validate_payment_transport,
};
use crate::config::RunConfig;

/// SOL funded per user when the payer funds its own open. `batch-settlement` is
/// always sponsored (the challenge names an `extra.feePayer` that pays fees and
/// channel rent), so this is only reached if a challenge omits a sponsor.
const PER_USER_SOL_LAMPORTS: u64 = 25_000_000;

fn open_sol_lamports(offline: bool, fee_sponsored: bool) -> u64 {
    if offline || fee_sponsored {
        0
    } else {
        PER_USER_SOL_LAMPORTS
    }
}

pub(crate) fn voucher_base_units(voucher_usdc: f64) -> u64 {
    (voucher_usdc * 1e6).max(1.0) as u64
}

/// One channel's retained state: the immutable channel config echoed on every
/// payload, the priced challenge, the payer's ed25519 voucher key
/// (`payerAuthorizer` == `payer`), the per-request base, and the cumulative
/// watermark already charged (the `deposit`'s first voucher, or the reused
/// channel's on-chain settled amount).
#[derive(Clone)]
struct BatchHandle {
    channel_id: Pubkey,
    config: BatchChannelConfig,
    requirements: BatchRequirements,
    voucher_key: SigningKey,
    base: u64,
    charged_cumulative: u64,
}

/// One channel's slot in the background signer pipeline: a single producer, so
/// vouchers stay monotonic, and the bounded queue lanes drain.
struct SignerTask {
    voucher_key: SigningKey,
    channel_id: Pubkey,
    config: BatchChannelConfig,
    requirements: BatchRequirements,
    /// Advanced by `base` before each voucher is signed; single-owner, so the
    /// cumulative watermark stays strictly monotonic without coordination.
    cumulative: u64,
    base: u64,
    queue: Arc<ArrayQueue<String>>,
}

pub struct BatchSettlement {
    deposit_base: u64,
    voucher_base: u64,
    offline: bool,
    pre_sign_requests_per_user: usize,
    /// A positive value uses dedicated signer threads to fill per-channel
    /// queues off the hot path for the whole run (see [`SessionCfg::background_signers`]).
    background_signers: usize,
    close_after_run: bool,
    /// Live channel state, keyed by user index.
    handles: Mutex<HashMap<u32, BatchHandle>>,
    /// Reuse mode: user index → (existing channel address, on-chain settled).
    reuse_channels: Mutex<HashMap<u32, (String, u64)>>,
    /// Opens whose payload was constructed and is about to be sent; retained so
    /// an ambiguous transport failure still yields the deterministic channel ID.
    ambiguous_opens: Mutex<HashMap<u32, UserSetup>>,
    /// Per-channel signer slots, consumed by [`BatchSettlement::spawn_hot_path`].
    signer_registry: Mutex<Vec<SignerTask>>,
    hot_stats: Arc<HotPathStats>,
}

impl BatchSettlement {
    pub fn new(cfg: &RunConfig) -> Self {
        let (deposit_usdc, voucher_usdc) = cfg
            .session
            .as_ref()
            .map(|s| (s.deposit_usdc, s.voucher_usdc))
            .unwrap_or((1.0, 0.001));
        let offline = cfg.session.as_ref().map(|s| s.offline).unwrap_or(false);
        let pre_sign_requests_per_user = cfg
            .session
            .as_ref()
            .map(|session| session.pre_sign_requests_per_user)
            .unwrap_or(0);
        let background_signers = cfg
            .session
            .as_ref()
            .map(|session| session.background_signers)
            .unwrap_or(0);
        let close_after_run = cfg
            .session
            .as_ref()
            .map(|session| session.close_after_run)
            .unwrap_or(true);
        Self {
            deposit_base: (deposit_usdc * 1e6) as u64,
            voucher_base: voucher_base_units(voucher_usdc),
            offline,
            pre_sign_requests_per_user,
            background_signers,
            close_after_run,
            handles: Mutex::new(HashMap::new()),
            reuse_channels: Mutex::new(HashMap::new()),
            ambiguous_opens: Mutex::new(HashMap::new()),
            signer_registry: Mutex::new(Vec::new()),
            hot_stats: Arc::new(HotPathStats::default()),
        }
    }

    fn queue_depth(&self) -> usize {
        if self.pre_sign_requests_per_user > 0 {
            self.pre_sign_requests_per_user
        } else {
            1024
        }
    }

    fn handle(&self, index: u32) -> Option<BatchHandle> {
        self.handles.lock().unwrap().get(&index).cloned()
    }

    fn reuse_lookup(&self, index: u32) -> Option<(String, u64)> {
        self.reuse_channels.lock().unwrap().get(&index).cloned()
    }

    /// Rebuild the immutable channel config from a priced challenge + payer.
    fn config_for(&self, requirements: &BatchRequirements, payer: &Pubkey, open_slot: u64) -> BatchChannelConfig {
        BatchChannelConfig {
            payer: pc::pubkey_string(payer),
            payer_authorizer: pc::pubkey_string(payer),
            receiver: requirements.pay_to.clone(),
            receiver_authorizer: requirements.extra.receiver_authorizer.clone(),
            token: requirements.asset.clone(),
            withdraw_delay: requirements.extra.withdraw_delay,
            // Reuse cannot recover the original salt from the trait's
            // `(channel_id, settled)` pair; the voucher is signed over the
            // channel_id directly (not a rederived address), so a placeholder
            // salt/open_slot keeps the echoed config well-formed.
            salt: "0".to_string(),
            open_slot,
        }
    }
}

/// Build one `batch-settlement` `PAYMENT-SIGNATURE` header for a steady-state
/// voucher. Pure-sync: no tokio runtime, no async signer — the ed25519 sign is
/// done directly over the canonical 50-byte message.
fn batch_header_sync(
    voucher_key: &SigningKey,
    channel_id: &Pubkey,
    cumulative: u64,
    config: &BatchChannelConfig,
    requirements: &BatchRequirements,
) -> Result<String> {
    let msg = pc::voucher_message_bytes(channel_id, cumulative, VOUCHER_EXPIRES_AT)
        .map_err(|e| anyhow::anyhow!("voucher message bytes: {e}"))?; // 50 bytes
    let sig = voucher_key.sign(&msg);
    let voucher = BatchVoucher {
        channel_id: channel_id.to_string(),
        max_claimable_amount: cumulative.to_string(),
        expires_at: VOUCHER_EXPIRES_AT,
        signature: bs58::encode(sig.to_bytes()).into_string(),
    };
    let payload = BatchPayload::Voucher {
        channel_config: config.clone(),
        voucher,
    };
    encode_payment_header(requirements, payload).map_err(|e| anyhow::anyhow!("encode payment header: {e}"))
}

/// Send an unauthenticated request and collect the 402 challenge material: the
/// status, the response headers (for [`parse_challenge`]'s `PAYMENT-REQUIRED`
/// lookup), and the body (its fallback source).
async fn fetch_challenge(ctx: &UserCtx) -> Result<(StatusCode, Vec<(String, String)>, String)> {
    let resp = build_request(
        &ctx.http,
        &ctx.endpoint.method,
        &ctx.endpoint.url,
        &ctx.endpoint.body,
        ctx.host_override.as_deref(),
        &[],
    )
    .send()
    .await
    .context("batch challenge request failed")?;
    let status = resp.status();
    let headers = resp
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            std::str::from_utf8(value.as_bytes())
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect();
    let body = resp
        .text()
        .await
        .context("reading batch challenge body")?;
    Ok((status, headers, body))
}

fn parse_batch_challenge(
    status: StatusCode,
    headers: &[(String, String)],
    body: &str,
) -> Result<BatchRequirements> {
    if status.as_u16() != 402 {
        bail!("expected 402 batch-settlement challenge, got {status}");
    }
    let (requirements, _corrective) = parse_challenge(headers, Some(body))
        .context("not a batch-settlement challenge (no PAYMENT-REQUIRED)")?;
    Ok(requirements)
}

/// The construction hints a fresh open needs: a blockhash and slot. The
/// challenge carries them as `extra.recentBlockhash` / `extra.recentSlot`.
fn open_hints(requirements: &BatchRequirements) -> Result<(Hash, u64)> {
    let blockhash = requirements
        .extra
        .recent_blockhash
        .as_deref()
        .context("batch challenge omitted extra.recentBlockhash")?;
    let blockhash =
        Hash::from_str(blockhash).map_err(|e| anyhow::anyhow!("bad recentBlockhash: {e}"))?;
    let open_slot = requirements
        .extra
        .recent_slot
        .context("batch challenge omitted extra.recentSlot")?;
    Ok((blockhash, open_slot))
}

fn validate_open_response(status: StatusCode, body: &[u8]) -> Result<()> {
    // A `deposit` payload both opens the channel and pays for this first
    // request, so the gateway serves the resource (2xx) on success.
    if status.is_success() {
        return Ok(());
    }
    let message = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|payload| {
            payload
                .get("message")
                .or_else(|| payload.get("error"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
    bail!("provision: batch channel open was rejected with {status}: {message}")
}

pub(crate) fn validate_close_response(status: StatusCode, body: &[u8]) -> Result<()> {
    if status.is_success() {
        return Ok(());
    }
    let message = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|payload| {
            payload
                .get("message")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
    bail!("batch refund was rejected with {status}: {message}")
}

#[async_trait]
impl BenchScheme for BatchSettlement {
    fn name(&self) -> &'static str {
        "x402_batch_settlement"
    }

    async fn resolve(
        &self,
        http: &reqwest::Client,
        endpoint: &Endpoint,
        host_override: Option<&str>,
    ) -> Result<ResolvedPrice> {
        let resp = build_request(http, &endpoint.method, &endpoint.url, &endpoint.body, host_override, &[])
            .send()
            .await
            .context("batch probe failed")?;
        let status = resp.status();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                std::str::from_utf8(value.as_bytes())
                    .ok()
                    .map(|v| (name.as_str().to_string(), v.to_string()))
            })
            .collect();
        let body = resp.text().await.context("reading batch probe body")?;
        let requirements = parse_batch_challenge(status, &headers, &body)?;
        Ok(ResolvedPrice {
            amount_base: requirements.amount().unwrap_or(self.voucher_base),
            currency: requirements.asset.clone(),
            mint: Some(requirements.asset.clone()),
            recipient: requirements.pay_to.clone(),
            network: requirements.network.clone(),
            decimals: 6,
            // The challenge always names a distinct sponsor (`extra.feePayer`)
            // that pays fees + channel rent.
            fee_sponsored: true,
        })
    }

    fn funding_plan(&self, _load: &Load, price: &ResolvedPrice) -> PerUserFunding {
        // The sponsor covers SOL; the client still funds the escrow deposit in
        // the payment token.
        PerUserFunding {
            sol_lamports: open_sol_lamports(self.offline, price.fee_sponsored),
            token_base: if self.offline { 0 } else { self.deposit_base },
        }
    }

    fn set_reuse_channels(&self, channels: HashMap<u32, (String, u64)>) {
        *self.reuse_channels.lock().unwrap() = channels;
    }

    async fn provision_user(&self, ctx: &UserCtx) -> Result<UserSetup> {
        validate_payment_transport(&ctx.endpoint.url)?;
        if self.offline {
            bail!("x402_batch_settlement has no offline seeded-fixture path; use an online gateway");
        }

        // 1. Fresh batch-settlement 402 → priced requirements.
        let (status, headers, body) = fetch_challenge(ctx).await?;
        let requirements = parse_batch_challenge(status, &headers, &body)
            .context("provision: batch challenge")?;
        let base = requirements.amount().unwrap_or(self.voucher_base);
        let voucher_key = SigningKey::from_bytes(&ctx.wallet.seed());
        let payer = Pubkey::new_from_array(voucher_key.verifying_key().to_bytes());

        // Reuse: this wallet already owns an open channel on-chain. Drive it by
        // address, resuming from its settled watermark, instead of opening (and
        // depositing into) a new one.
        if let Some((channel_id, settled)) = self.reuse_lookup(ctx.index) {
            let channel = Pubkey::from_str(&channel_id)
                .map_err(|e| anyhow::anyhow!("reuse: bad channel id {channel_id}: {e}"))?;
            let (_, open_slot) = open_hints(&requirements).unwrap_or((Hash::default(), 0));
            let handle = BatchHandle {
                channel_id: channel,
                config: self.config_for(&requirements, &payer, open_slot),
                requirements: requirements.clone(),
                voucher_key,
                base,
                charged_cumulative: settled,
            };
            self.handles.lock().unwrap().insert(ctx.index, handle);
            return Ok(UserSetup {
                channel_id: Some(channel_id),
                open_sig: None,
                ata: None,
            });
        }

        // 2. Build a genuine sponsored channel `open` + first voucher, bound to
        // the challenged blockhash + slot. The sponsor co-signs and broadcasts.
        let token_program = pc::parse_pubkey(&requirements.extra.token_program)
            .map_err(|e| anyhow::anyhow!("bad extra.tokenProgram: {e}"))?;
        let terms = resolve_terms_with_token_program(&requirements, token_program)
            .map_err(|e| anyhow::anyhow!("resolve batch terms: {e}"))?;
        let (blockhash, open_slot) = open_hints(&requirements)?;
        let payer_signer = MemorySigner::from_bytes(&ctx.wallet.keypair)
            .map_err(|e| anyhow::anyhow!("payer signer: {e}"))?;
        let (channel, payload) = build_deposit(
            &payer_signer,
            &requirements,
            &terms,
            self.deposit_base,
            blockhash,
            open_slot,
        )
        .await
        .map_err(|e| anyhow::anyhow!("build batch deposit: {e}"))?;
        let header = encode_payment_header(&requirements, payload)
            .map_err(|e| anyhow::anyhow!("encode deposit header: {e}"))?;
        let channel_id = channel.channel_id().to_string();
        let handle = BatchHandle {
            channel_id: *channel.channel_id(),
            config: channel.config().clone(),
            requirements: requirements.clone(),
            voucher_key,
            base,
            // The deposit's first voucher already charged one `base`; the
            // steady-state stream continues monotonically above it.
            charged_cumulative: terms.amount,
        };
        let setup = UserSetup {
            channel_id: Some(channel_id.clone()),
            open_sig: None,
            ata: None,
        };
        // The gateway may broadcast the open and then lose its HTTP response.
        // Save the deterministic channel ID before sending.
        self.ambiguous_opens
            .lock()
            .unwrap()
            .insert(ctx.index, setup.clone());

        // 3. Send the deposit under the x402 payment header. Success serves the
        // first request (2xx).
        let resp = build_request(
            &ctx.http,
            &ctx.endpoint.method,
            &ctx.endpoint.url,
            &ctx.endpoint.body,
            ctx.host_override.as_deref(),
            &[(PAYMENT_SIGNATURE_HEADER.to_string(), header)],
        )
        .send()
        .await
        .context("provision: batch open request failed")?;
        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .context("provision: failed to read batch open response")?;
        validate_open_response(status, &body)?;

        self.handles.lock().unwrap().insert(ctx.index, handle);
        self.ambiguous_opens.lock().unwrap().remove(&ctx.index);
        Ok(setup)
    }

    async fn request_source(
        &self,
        ctx: &UserCtx,
        _setup: &UserSetup,
    ) -> Result<Box<dyn RequestSource>> {
        validate_payment_transport(&ctx.endpoint.url)?;
        let handle = self
            .handle(ctx.index)
            .with_context(|| format!("no batch handle for user {}", ctx.index))?;

        // Background-signer mode: a shared bounded queue is filled by the signer
        // pool (started in `spawn_hot_path`) and drained by this source's lane.
        if self.background_signers > 0 {
            let queue = Arc::new(ArrayQueue::new(self.queue_depth()));
            self.signer_registry.lock().unwrap().push(SignerTask {
                voucher_key: handle.voucher_key.clone(),
                channel_id: handle.channel_id,
                config: handle.config.clone(),
                requirements: handle.requirements.clone(),
                cumulative: handle.charged_cumulative,
                base: handle.base,
                queue: queue.clone(),
            });
            return Ok(Box::new(BatchSource {
                index: ctx.index,
                voucher_key: handle.voucher_key,
                channel_id: handle.channel_id,
                config: handle.config,
                requirements: handle.requirements,
                cumulative: handle.charged_cumulative,
                base: handle.base,
                method: ctx.endpoint.method.clone(),
                url: ctx.endpoint.url.clone(),
                host_override: ctx.host_override.clone(),
                body: ctx.endpoint.body.clone(),
                presigned: None,
                queue: Some(queue),
                stats: self.hot_stats.clone(),
            }));
        }

        let presigned = if self.pre_sign_requests_per_user > 0 {
            let count = self.pre_sign_requests_per_user;
            let voucher_key = handle.voucher_key.clone();
            let channel_id = handle.channel_id;
            let config = handle.config.clone();
            let requirements = handle.requirements.clone();
            let base = handle.base;
            let mut cumulative = handle.charged_cumulative;
            tokio::task::spawn_blocking(move || -> Result<VecDeque<String>> {
                let mut headers = VecDeque::with_capacity(count);
                for _ in 0..count {
                    cumulative = cumulative
                        .checked_add(base)
                        .context("cumulative voucher overflow")?;
                    headers.push_back(batch_header_sync(
                        &voucher_key,
                        &channel_id,
                        cumulative,
                        &config,
                        &requirements,
                    )?);
                }
                Ok(headers)
            })
            .await
            .context("pre-sign task panicked")??
        } else {
            VecDeque::new()
        };
        Ok(Box::new(BatchSource {
            index: ctx.index,
            voucher_key: handle.voucher_key,
            channel_id: handle.channel_id,
            config: handle.config,
            requirements: handle.requirements,
            cumulative: handle.charged_cumulative,
            base: handle.base,
            method: ctx.endpoint.method.clone(),
            url: ctx.endpoint.url.clone(),
            host_override: ctx.host_override.clone(),
            body: ctx.endpoint.body.clone(),
            presigned: (self.pre_sign_requests_per_user > 0).then_some(presigned),
            queue: None,
            stats: self.hot_stats.clone(),
        }))
    }

    fn take_ambiguous_setup(&self, ctx: &UserCtx) -> Option<UserSetup> {
        self.ambiguous_opens.lock().unwrap().remove(&ctx.index)
    }

    async fn settle_and_close(&self, ctx: &UserCtx, _setup: &UserSetup) -> Result<()> {
        // The gateway redeems accepted vouchers on its own batch schedule, so an
        // explicit client close is optional. When requested, send a payer-signed
        // `refund` (forced `request_close`); it needs a fresh blockhash, so
        // re-probe for a current challenge first.
        if self.offline || !self.close_after_run {
            return Ok(());
        }
        let Some(handle) = self.handle(ctx.index) else {
            return Ok(());
        };
        let (status, headers, body) = fetch_challenge(ctx).await?;
        let requirements = parse_batch_challenge(status, &headers, &body)
            .context("close: batch recovery challenge")?;
        let token_program = pc::parse_pubkey(&requirements.extra.token_program)
            .map_err(|e| anyhow::anyhow!("close: bad extra.tokenProgram: {e}"))?;
        let terms = resolve_terms_with_token_program(&requirements, token_program)
            .map_err(|e| anyhow::anyhow!("close: resolve batch terms: {e}"))?;
        let (blockhash, _open_slot) = open_hints(&requirements)?;
        let signer = MemorySigner::from_bytes(&ctx.wallet.keypair)
            .map_err(|e| anyhow::anyhow!("close: payer signer: {e}"))?;
        let channel = BatchChannel::new(
            handle.channel_id,
            handle.config.clone(),
            handle.charged_cumulative,
            self.deposit_base,
        );
        let payload = build_refund(&signer, &channel, &terms, blockhash)
            .await
            .map_err(|e| anyhow::anyhow!("build batch refund: {e}"))?;
        let header = encode_payment_header(&requirements, payload)
            .map_err(|e| anyhow::anyhow!("encode refund header: {e}"))?;
        let resp = build_request(
            &ctx.http,
            &ctx.endpoint.method,
            &ctx.endpoint.url,
            &ctx.endpoint.body,
            ctx.host_override.as_deref(),
            &[(PAYMENT_SIGNATURE_HEADER.to_string(), header)],
        )
        .send()
        .await
        .context("close request failed")?;
        let status = resp.status();
        let body = resp.bytes().await.context("reading close response")?;
        validate_close_response(status, &body)
    }

    fn spawn_hot_path(&self) -> Option<HotPathGuard> {
        if self.background_signers == 0 {
            return None;
        }
        let tasks: Vec<SignerTask> = std::mem::take(&mut *self.signer_registry.lock().unwrap());
        if tasks.is_empty() {
            return None;
        }
        let threads = self.background_signers.min(tasks.len());
        let stop = Arc::new(AtomicBool::new(false));
        let stats = self.hot_stats.clone();

        // Partition channels across signer threads round-robin: each channel is
        // owned by exactly one thread, so its cumulative watermark stays strictly
        // monotonic without cross-thread coordination.
        let mut buckets: Vec<Vec<SignerTask>> = (0..threads).map(|_| Vec::new()).collect();
        for (i, task) in tasks.into_iter().enumerate() {
            buckets[i % threads].push(task);
        }

        let mut joins = Vec::with_capacity(threads);
        for (tid, bucket) in buckets.into_iter().enumerate() {
            let stop = stop.clone();
            let stats = stats.clone();
            let join = std::thread::Builder::new()
                .name(format!("batch-signer-{tid}"))
                .spawn(move || signer_thread(bucket, stop, stats))
                .expect("spawn batch signer thread");
            joins.push(join);
        }
        tracing::info!(
            signer_threads = threads,
            "batch signer pool started (ed25519 off the hot path for the whole run)"
        );
        Some(HotPathGuard::new(stop, joins, stats))
    }
}

/// One signer thread: owns a disjoint set of channels and keeps their queues
/// topped up. Pure-sync — the `batch-settlement` voucher is an ed25519 signature
/// over 50 bytes plus a JSON envelope serialization, so unlike the MPP session
/// path this needs no tokio runtime at all.
fn signer_thread(mut bucket: Vec<SignerTask>, stop: Arc<AtomicBool>, stats: Arc<HotPathStats>) {
    let mut produced_local: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        let mut progressed = false;
        for task in &mut bucket {
            // Top this channel back up to capacity, then move on so every
            // channel gets refilled each pass (fair across the bucket).
            while task.queue.len() < task.queue.capacity() {
                let next = match task.cumulative.checked_add(task.base) {
                    Some(next) => next,
                    None => {
                        tracing::error!("batch signer: cumulative overflow");
                        break;
                    }
                };
                match batch_header_sync(
                    &task.voucher_key,
                    &task.channel_id,
                    next,
                    &task.config,
                    &task.requirements,
                ) {
                    Ok(header) => {
                        if task.queue.push(header).is_err() {
                            break; // filled concurrently; watermark not advanced
                        }
                        task.cumulative = next;
                        produced_local += 1;
                        progressed = true;
                        if produced_local.is_multiple_of(8192) {
                            stats.produced.fetch_add(8192, Ordering::Relaxed);
                        }
                    }
                    Err(e) => {
                        tracing::error!("batch signer: header build failed: {e}");
                        break;
                    }
                }
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
        }
        // All queues full: park briefly instead of spinning hot so we don't
        // steal a core from the lane threads while waiting.
        if !progressed {
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
    }
    stats
        .produced
        .fetch_add(produced_local % 8192, Ordering::Relaxed);
}

struct BatchSource {
    index: u32,
    voucher_key: SigningKey,
    channel_id: Pubkey,
    config: BatchChannelConfig,
    requirements: BatchRequirements,
    /// Last cumulative watermark signed; advanced by `base` per request.
    cumulative: u64,
    base: u64,
    method: String,
    url: String,
    host_override: Option<String>,
    body: String,
    presigned: Option<VecDeque<String>>,
    /// Background-signer mode: pop pre-signed headers the pool fills. When set,
    /// this source never signs (single producer per channel is the pool).
    queue: Option<Arc<ArrayQueue<String>>>,
    stats: Arc<HotPathStats>,
}

#[async_trait]
impl RequestSource for BatchSource {
    fn user_index(&self) -> u32 {
        self.index
    }

    async fn next_request(&mut self) -> Result<PreparedRequest> {
        let header = if let Some(queue) = &self.queue {
            // Vouchers are FIFO within a channel, so popping in order preserves
            // the monotonic watermark. If momentarily empty the pool fell behind
            // — wait rather than signing here (which would race its watermark).
            loop {
                if let Some(header) = queue.pop() {
                    break header;
                }
                self.stats.stalls.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        } else {
            match &mut self.presigned {
                Some(presigned) => presigned
                    .pop_front()
                    .context("pre-signed voucher window exhausted")?,
                None => {
                    self.cumulative = self
                        .cumulative
                        .checked_add(self.base)
                        .context("cumulative voucher overflow")?;
                    batch_header_sync(
                        &self.voucher_key,
                        &self.channel_id,
                        self.cumulative,
                        &self.config,
                        &self.requirements,
                    )?
                }
            }
        };
        let mut headers = vec![(PAYMENT_SIGNATURE_HEADER.to_string(), header)];
        if let Some(host) = &self.host_override {
            headers.push(("host".to_string(), host.clone()));
        }
        Ok(PreparedRequest {
            method: self.method.clone(),
            url: self.url.clone(),
            headers,
            body: self.body.clone(),
            logical_payment: true,
        })
    }
}
