//! x402 `batch-settlement` scheme — push mode. Cloned from `mpp_session`,
//! with the wire format swapped from MPP session vouchers to the x402
//! `batch-settlement` `PAYMENT-SIGNATURE` envelope.
//!
//! Per user (= one escrow channel):
//!   - **provision** (on-chain, once): fetch the endpoint's 402 `batch-settlement`
//!     challenge, resolve its terms, build a sponsored `deposit` (channel `open`
//!     plus the first voucher), and send it under the `PAYMENT-SIGNATURE` header.
//!     The sponsor (`extra.feePayer`) co-signs and broadcasts; client pays no SOL.
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use crossbeam_queue::ArrayQueue;
use ed25519_dalek::{Signer as _, SigningKey};
use pay_kit::core::payment_channels as pc;
use pay_kit::mpp::solana_keychain::memory::MemorySigner;
use pay_kit::x402::client::batch_settlement::{
    BatchChannel, build_deposit, build_refund, encode_payment_header, parse_challenge,
    resolve_terms_with_token_program,
};
use pay_kit::x402::protocol::schemes::batch_settlement::{
    BatchChannelConfig, BatchPayload, BatchRequirements, BatchVoucher, VOUCHER_EXPIRES_AT, errors,
};
use pay_kit::x402::{PAYMENT_REQUIRED_HEADER, PAYMENT_RESPONSE_HEADER, PAYMENT_SIGNATURE_HEADER};
use reqwest::StatusCode;
use solana_hash::Hash;
use solana_pubkey::Pubkey;

use super::{
    BenchScheme, Endpoint, HotPathGuard, HotPathStats, Load, PerUserFunding, PreparedRequest,
    RequestSource, ResolvedPrice, ReusableChannel, UserCtx, UserSetup, build_request,
    validate_payment_transport,
};
use crate::config::RunConfig;

/// SOL funded per user when the payer funds its own open. `batch-settlement` is
/// always sponsored (the challenge names an `extra.feePayer` that pays fees and
/// channel rent), so this is only reached if a challenge omits a sponsor.
const PER_USER_SOL_LAMPORTS: u64 = 25_000_000;
const OPEN_MAX_ATTEMPTS: usize = 6;
const OPEN_RETRY_BASE_DELAY_MS: u64 = 100;

fn open_sol_lamports(offline: bool, fee_sponsored: bool) -> u64 {
    if offline || fee_sponsored {
        0
    } else {
        PER_USER_SOL_LAMPORTS
    }
}

fn token_funding_base(deposit_base: u64, offline: bool, reuse: bool) -> u64 {
    if offline || reuse { 0 } else { deposit_base }
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

/// Per-channel signing state shared between the background signer thread
/// (the producer, which advances `cumulative`) and the request source (the
/// consumer, and the writer on a resync). `epoch` is bumped whenever a
/// corrective response resyncs `cumulative`, so vouchers already queued under
/// the stale baseline can be told apart from fresh ones without draining the
/// lock-free queue directly — see [`ChannelQueueEntry`].
#[derive(Default)]
struct ChannelSignState {
    cumulative: u64,
    epoch: u64,
}

/// One signer-pool queue entry: the epoch `cumulative` was read under when
/// this header was signed, alongside the header itself. The consumer
/// discards entries whose epoch no longer matches the channel's current
/// epoch instead of sending a voucher signed under a baseline the server has
/// since corrected.
type ChannelQueueEntry = (u64, String);

/// One channel's slot in the background signer pipeline: a single producer, so
/// vouchers stay monotonic, and the bounded queue lanes drain.
struct SignerTask {
    voucher_key: SigningKey,
    channel_id: Pubkey,
    config: BatchChannelConfig,
    requirements: BatchRequirements,
    base: u64,
    state: Arc<Mutex<ChannelSignState>>,
    queue: Arc<ArrayQueue<ChannelQueueEntry>>,
}

pub struct BatchSettlement {
    deposit_base: u64,
    voucher_base: u64,
    offline: bool,
    reuse: bool,
    pre_sign_requests_per_user: usize,
    /// A positive value uses dedicated signer threads to fill per-channel
    /// queues off the hot path for the whole run (see [`SessionCfg::background_signers`]).
    background_signers: usize,
    close_after_run: bool,
    /// Live channel state, keyed by user index.
    handles: Mutex<HashMap<u32, BatchHandle>>,
    /// Reuse mode: user index → (existing channel address, on-chain settled).
    reuse_channels: Mutex<HashMap<u32, ReusableChannel>>,
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
        let reuse = cfg.session.as_ref().map(|s| s.reuse).unwrap_or(false);
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
            reuse,
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

    fn reuse_lookup(&self, index: u32) -> Option<ReusableChannel> {
        self.reuse_channels.lock().unwrap().get(&index).cloned()
    }

    /// Rebuild the immutable channel config from a priced challenge + payer.
    fn config_for(
        requirements: &BatchRequirements,
        payer: &Pubkey,
        open_slot: u64,
    ) -> BatchChannelConfig {
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

    fn config_for_reuse(
        requirements: &BatchRequirements,
        payer: &Pubkey,
        reused: &ReusableChannel,
    ) -> BatchChannelConfig {
        let mut config = Self::config_for(requirements, payer, reused.open_slot);
        config.salt = reused.salt.to_string();
        config
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
    encode_payment_header(requirements, payload)
        .map_err(|e| anyhow::anyhow!("encode payment header: {e}"))
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
    let body = resp.text().await.context("reading batch challenge body")?;
    Ok((status, headers, body))
}

async fn fetch_batch_requirements(ctx: &UserCtx) -> Result<BatchRequirements> {
    const ATTEMPTS: usize = 3;
    for attempt in 1..=ATTEMPTS {
        match fetch_challenge(ctx).await {
            Ok((status, headers, body)) => match parse_batch_challenge(status, &headers, &body) {
                Ok(requirements) => return Ok(requirements),
                Err(error) if status.is_server_error() && attempt < ATTEMPTS => {
                    tracing::warn!(
                        attempt,
                        status = %status,
                        "retrying transient batch challenge failure"
                    );
                    tokio::time::sleep(Duration::from_millis(50 * attempt as u64)).await;
                    let _ = error;
                }
                Err(error) => return Err(error).context("provision: batch challenge"),
            },
            Err(error) if attempt < ATTEMPTS => {
                tracing::warn!(attempt, %error, "retrying transient batch challenge transport failure");
                tokio::time::sleep(Duration::from_millis(50 * attempt as u64)).await;
            }
            Err(error) => return Err(error).context("provision: batch challenge"),
        }
    }
    unreachable!("the bounded challenge retry loop always returns on its final attempt")
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

fn corrective_requirements_from_challenge(
    status: u16,
    header: Option<&str>,
) -> Option<BatchRequirements> {
    if status != StatusCode::PAYMENT_REQUIRED.as_u16() {
        return None;
    }
    let header_value = header?;
    let (requirements, error) = parse_challenge(
        &[(
            PAYMENT_REQUIRED_HEADER.to_string(),
            header_value.to_string(),
        )],
        None,
    )?;
    if error.as_deref() != Some(errors::INVALID_CUMULATIVE_AMOUNT_MISMATCH) {
        return None;
    }
    Some(requirements)
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

fn validate_open_response(
    status: StatusCode,
    has_settlement_receipt: bool,
    body: &[u8],
) -> Result<()> {
    // A `deposit` payload both opens the channel and pays for this first
    // request. A 2xx alone is insufficient: the upstream can succeed before
    // the post-response open/commit fails. PAYMENT-RESPONSE is the proof that
    // the gateway actually finished the setup transaction and watermark.
    if status.is_success() && has_settlement_receipt {
        return Ok(());
    }
    if status.is_success() {
        bail!(
            "provision: batch channel open returned {status} without {PAYMENT_RESPONSE_HEADER}; setup was not committed"
        );
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
        let resp = build_request(
            http,
            &endpoint.method,
            &endpoint.url,
            &endpoint.body,
            host_override,
            &[],
        )
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
            token_base: token_funding_base(self.deposit_base, self.offline, self.reuse),
        }
    }

    fn set_reuse_channels(&self, channels: HashMap<u32, ReusableChannel>) {
        *self.reuse_channels.lock().unwrap() = channels;
    }

    async fn provision_user(&self, ctx: &UserCtx) -> Result<UserSetup> {
        validate_payment_transport(&ctx.endpoint.url)?;
        if self.offline {
            bail!(
                "x402_batch_settlement has no offline seeded-fixture path; use an online gateway"
            );
        }

        // 1. Fresh batch-settlement 402 → priced requirements.
        let requirements = fetch_batch_requirements(ctx).await?;
        let base = requirements.amount().unwrap_or(self.voucher_base);
        let voucher_key = SigningKey::from_bytes(&ctx.wallet.seed());
        let payer = Pubkey::new_from_array(voucher_key.verifying_key().to_bytes());

        // Reuse: this wallet already owns an open channel on-chain. Drive it by
        // address, resuming from its settled watermark, instead of opening (and
        // depositing into) a new one.
        if let Some(reused) = self.reuse_lookup(ctx.index) {
            let channel = Pubkey::from_str(&reused.channel_id)
                .map_err(|e| anyhow::anyhow!("reuse: bad channel id {}: {e}", reused.channel_id))?;
            let config = Self::config_for_reuse(&requirements, &payer, &reused);
            let mut charged_cumulative = reused
                .settled
                .checked_add(base)
                .context("reuse: cumulative voucher overflow")?;
            let mut header = batch_header_sync(
                &voucher_key,
                &channel,
                charged_cumulative,
                &config,
                &requirements,
            )?;

            // Hydrate a restarted gateway's store before the measured window.
            // Its recovery path verifies this voucher, reads the existing
            // channel from chain, and commits the new watermark without
            // opening or funding another channel.
            let mut last_error = None;
            for attempt in 0..OPEN_MAX_ATTEMPTS {
                let result = build_request(
                    &ctx.http,
                    &ctx.endpoint.method,
                    &ctx.endpoint.url,
                    &ctx.endpoint.body,
                    ctx.host_override.as_deref(),
                    &[(PAYMENT_SIGNATURE_HEADER.to_string(), header.clone())],
                )
                .send()
                .await;
                match result {
                    Ok(resp) => {
                        let status = resp.status();
                        let has_receipt = resp.headers().contains_key(PAYMENT_RESPONSE_HEADER);
                        let corrective_header = resp
                            .headers()
                            .get(PAYMENT_REQUIRED_HEADER)
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_owned);
                        let body = resp
                            .bytes()
                            .await
                            .context("reuse: failed to read warm-up response")?;
                        match validate_open_response(status, has_receipt, &body) {
                            Ok(()) => {
                                last_error = None;
                                break;
                            }
                            Err(error) => {
                                if let Some(corrective) = corrective_requirements_from_challenge(
                                    status.as_u16(),
                                    corrective_header.as_deref(),
                                ) {
                                    let mut proof_channel = BatchChannel::new(
                                        channel,
                                        config.clone(),
                                        charged_cumulative,
                                        self.deposit_base,
                                    );
                                    let corrected = proof_channel
                                        .adopt_corrective_state(&corrective)
                                        .map_err(|error| {
                                            anyhow::anyhow!(
                                                "reuse: corrective watermark proof rejected: {error}"
                                            )
                                        })?;
                                    charged_cumulative = corrected
                                        .checked_add(base)
                                        .context("reuse: corrected cumulative voucher overflow")?;
                                    header = batch_header_sync(
                                        &voucher_key,
                                        &channel,
                                        charged_cumulative,
                                        &config,
                                        &requirements,
                                    )?;
                                }
                                last_error = Some(error);
                            }
                        }
                    }
                    Err(error) => {
                        last_error = Some(anyhow::anyhow!(
                            "reuse: channel warm-up request failed: {error}"
                        ));
                    }
                }
                if attempt + 1 < OPEN_MAX_ATTEMPTS {
                    let delay = OPEN_RETRY_BASE_DELAY_MS << attempt;
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
            }
            if let Some(error) = last_error {
                return Err(error).context(format!(
                    "reuse: channel {} did not hydrate after {OPEN_MAX_ATTEMPTS} attempts",
                    reused.channel_id
                ));
            }
            let handle = BatchHandle {
                channel_id: channel,
                config,
                requirements: requirements.clone(),
                voucher_key,
                base,
                charged_cumulative,
            };
            self.handles.lock().unwrap().insert(ctx.index, handle);
            return Ok(UserSetup {
                channel_id: Some(reused.channel_id),
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

        // 3. Send the same deterministic deposit until the gateway returns a
        // settlement receipt. Retrying is safe: a request whose handler ran
        // resumes its durable commit, while a committed request replays it.
        // This closes the post-response failure window where a bare 2xx used
        // to admit a channel that was still stuck in `pending_setup`.
        let mut last_error = None;
        for attempt in 0..OPEN_MAX_ATTEMPTS {
            let result = build_request(
                &ctx.http,
                &ctx.endpoint.method,
                &ctx.endpoint.url,
                &ctx.endpoint.body,
                ctx.host_override.as_deref(),
                &[(PAYMENT_SIGNATURE_HEADER.to_string(), header.clone())],
            )
            .send()
            .await;
            match result {
                Ok(resp) => {
                    let status = resp.status();
                    let has_receipt = resp.headers().contains_key(PAYMENT_RESPONSE_HEADER);
                    let body = resp
                        .bytes()
                        .await
                        .context("provision: failed to read batch open response")?;
                    match validate_open_response(status, has_receipt, &body) {
                        Ok(()) => {
                            last_error = None;
                            break;
                        }
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(error) => {
                    last_error = Some(anyhow::anyhow!(
                        "provision: batch open request failed: {error}"
                    ));
                }
            }
            if attempt + 1 < OPEN_MAX_ATTEMPTS {
                let delay = OPEN_RETRY_BASE_DELAY_MS << attempt;
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
        }
        if let Some(error) = last_error {
            return Err(error).context(format!(
                "provision: batch open did not commit after {OPEN_MAX_ATTEMPTS} attempts"
            ));
        }

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
        // `state` is shared between the two so a resync (see
        // `BatchSource::on_response`) is visible to the signer thread's next
        // refill pass without any extra coordination.
        if self.background_signers > 0 {
            let queue = Arc::new(ArrayQueue::new(self.queue_depth()));
            let state = Arc::new(Mutex::new(ChannelSignState {
                cumulative: handle.charged_cumulative,
                epoch: 0,
            }));
            let epoch = Arc::new(AtomicU64::new(0));
            self.signer_registry.lock().unwrap().push(SignerTask {
                voucher_key: handle.voucher_key.clone(),
                channel_id: handle.channel_id,
                config: handle.config.clone(),
                requirements: handle.requirements.clone(),
                base: handle.base,
                state: state.clone(),
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
                state: Some(state),
                epoch: Some(epoch),
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
            state: None,
            epoch: None,
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
                // Hold this only across the signer operation. There is one
                // producer per channel, so this lock is uncontended except for
                // a rare corrective 402 resync. Request lanes read the mirrored
                // atomic epoch and never bounce this mutex between CPU cores.
                let mut state = task.state.lock().unwrap();
                let Some(next) = state.cumulative.checked_add(task.base) else {
                    tracing::error!("batch signer: cumulative overflow");
                    break;
                };
                let epoch = state.epoch;
                match batch_header_sync(
                    &task.voucher_key,
                    &task.channel_id,
                    next,
                    &task.config,
                    &task.requirements,
                ) {
                    Ok(header) => {
                        if task.queue.push((epoch, header)).is_err() {
                            break; // filled concurrently; watermark not advanced
                        }
                        state.cumulative = next;
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
    /// Last cumulative watermark signed; advanced by `base` per request. Only
    /// meaningful in the direct/presigned paths (no `state`) — background-signer
    /// mode tracks this in the shared `state` instead.
    cumulative: u64,
    base: u64,
    method: String,
    url: String,
    host_override: Option<String>,
    body: String,
    presigned: Option<VecDeque<String>>,
    /// Background-signer mode: pop pre-signed headers the pool fills. When set,
    /// this source never signs (single producer per channel is the pool).
    queue: Option<Arc<ArrayQueue<ChannelQueueEntry>>>,
    /// Shared with this channel's `SignerTask` in background-signer mode; a
    /// resync (see `on_response`) writes the server's corrected cumulative
    /// here and bumps the epoch so stale queued vouchers are discarded
    /// instead of sent. `None` outside background-signer mode.
    state: Option<Arc<Mutex<ChannelSignState>>>,
    /// Atomic mirror of `state.epoch` for the per-request stale-entry check.
    epoch: Option<Arc<AtomicU64>>,
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
            // An entry signed before the last resync (stale epoch) is discarded
            // instead of sent — it was built against a baseline the server has
            // since corrected, so sending it would just repeat the mismatch.
            loop {
                match queue.pop() {
                    Some((epoch, header)) => {
                        let current = self
                            .epoch
                            .as_ref()
                            .expect("queue implies epoch")
                            .load(Ordering::Acquire);
                        if epoch == current {
                            break header;
                        }
                    }
                    None => {
                        self.stats.stalls.fetch_add(1, Ordering::Relaxed);
                        tokio::task::yield_now().await;
                    }
                }
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

    fn resync_header(&self) -> Option<&'static str> {
        Some(PAYMENT_REQUIRED_HEADER)
    }

    /// A cumulative-amount mismatch means our local watermark drifted from the
    /// server's (e.g. a deposit's implicit first charge silently failed to
    /// record server-side — a known, documented gap: "that loss is logged,
    /// not surfaced"). The mismatch response carries the server's real
    /// watermark specifically so a client can resynchronize instead of
    /// repeating the same wrong voucher forever. The shared channel verifier
    /// authenticates the carried voucher against this benchmark wallet before
    /// the signing watermark can move.
    fn on_response(&mut self, status: u16, header: Option<&str>) {
        let Some(corrective) = corrective_requirements_from_challenge(status, header) else {
            return;
        };
        let mut proof_channel =
            BatchChannel::new(self.channel_id, self.config.clone(), self.cumulative, 0);
        let corrected = match proof_channel.adopt_corrective_state(&corrective) {
            Ok(corrected) => corrected,
            Err(error) => {
                tracing::error!(%error, "batch corrective watermark proof rejected");
                return;
            }
        };
        match &self.state {
            Some(state) => {
                let mut guard = state.lock().unwrap();
                guard.cumulative = corrected;
                guard.epoch += 1;
                self.epoch
                    .as_ref()
                    .expect("state implies epoch")
                    .store(guard.epoch, Ordering::Release);
            }
            None => {
                self.cumulative = corrected;
                if let Some(presigned) = &mut self.presigned {
                    // The rejected voucher was already popped, and every
                    // remaining entry was signed from the same stale base.
                    // Replace both it and the remaining window from the
                    // corrective watermark so the finite pre-sign path can
                    // still deliver its configured number of successes.
                    let count = presigned.len().saturating_add(1);
                    let mut rebuilt = VecDeque::with_capacity(count);
                    for _ in 0..count {
                        let Some(next) = self.cumulative.checked_add(self.base) else {
                            tracing::error!("batch pre-sign resync: cumulative overflow");
                            return;
                        };
                        match batch_header_sync(
                            &self.voucher_key,
                            &self.channel_id,
                            next,
                            &self.config,
                            &self.requirements,
                        ) {
                            Ok(header) => rebuilt.push_back(header),
                            Err(error) => {
                                tracing::error!(%error, "batch pre-sign resync failed");
                                return;
                            }
                        }
                        self.cumulative = next;
                    }
                    *presigned = rebuilt;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BatchSettlement, BatchSource, HotPathStats, RequestSource, ReusableChannel,
        corrective_requirements_from_challenge, token_funding_base, validate_open_response,
    };
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use pay_kit::core::payment_channels as pc;
    use pay_kit::x402::protocol::schemes::batch_settlement::{
        BatchExtra, BatchRequirements, derive_channel_id,
    };
    use reqwest::StatusCode;
    use solana_pubkey::Pubkey;

    #[test]
    fn reuse_does_not_refund_wallets_that_already_escrowed_their_deposit() {
        assert_eq!(token_funding_base(5_000_000, false, true), 0);
        assert_eq!(token_funding_base(5_000_000, false, false), 5_000_000);
    }

    #[test]
    fn reuse_warmup_reads_corrective_cumulative() {
        let envelope = serde_json::json!({
            "x402Version": 2,
            "error": "invalid_batch_settlement_svm_cumulative_amount_mismatch",
            "accepts": [{
                "scheme": "batch-settlement",
                "network": "solana:devnet",
                "amount": "1",
                "asset": Pubkey::from([4_u8; 32]).to_string(),
                "payTo": Pubkey::from([5_u8; 32]).to_string(),
                "maxTimeoutSeconds": 60,
                "extra": {
                    "feePayer": Pubkey::from([3_u8; 32]).to_string(),
                    "withdrawDelay": 3600,
                    "tokenProgram": Pubkey::from([6_u8; 32]).to_string(),
                    "voucherState": {
                        "signedMaxClaimable": "43551",
                        "expiresAt": 0,
                        "signature": "benchmark-trusts-the-gateway"
                    }
                }
            }]
        });
        let header = STANDARD.encode(serde_json::to_vec(&envelope).unwrap());

        assert_eq!(
            corrective_requirements_from_challenge(402, Some(&header))
                .and_then(|requirements| requirements.extra.voucher_state)
                .and_then(|voucher| voucher.signed_max_claimable().ok()),
            Some(43_551),
        );
        assert!(corrective_requirements_from_challenge(200, Some(&header)).is_none());
    }

    #[test]
    fn corrective_response_rebuilds_finite_presigned_window() {
        use std::collections::VecDeque;
        use std::sync::Arc;

        use ed25519_dalek::{Signer as _, SigningKey};

        let payer = SigningKey::from_bytes(&[7_u8; 32]);
        let fee_payer = Pubkey::from([3_u8; 32]);
        let requirements = BatchRequirements {
            scheme: "batch-settlement".to_string(),
            network: "solana:devnet".to_string(),
            amount: "1".to_string(),
            asset: Pubkey::from([4_u8; 32]).to_string(),
            pay_to: Pubkey::from([5_u8; 32]).to_string(),
            max_timeout_seconds: 60,
            extra: BatchExtra {
                payment_flow: None,
                fee_payer: fee_payer.to_string(),
                receiver_authorizer: None,
                withdraw_delay: 3_600,
                token_program: Pubkey::from([6_u8; 32]).to_string(),
                memo: None,
                recent_blockhash: None,
                recent_slot: None,
                channel_state: None,
                voucher_state: None,
            },
        };
        let payer_pubkey = Pubkey::new_from_array(payer.verifying_key().to_bytes());
        let config = BatchSettlement::config_for(&requirements, &payer_pubkey, 9);
        let channel_id = derive_channel_id(
            &config,
            &requirements.extra.fee_payer,
            &pc::default_program_id(),
        )
        .expect("channel id");
        let proof_message = pc::voucher_message_bytes(&channel_id, 100, 0).expect("voucher bytes");
        let proof_signature = bs58::encode(payer.sign(&proof_message).to_bytes()).into_string();
        let mut source = BatchSource {
            index: 0,
            voucher_key: payer,
            channel_id,
            config,
            requirements,
            cumulative: 12,
            base: 1,
            method: "GET".to_string(),
            url: "https://example.test".to_string(),
            host_override: None,
            body: String::new(),
            presigned: Some(VecDeque::from([
                "stale-1".to_string(),
                "stale-2".to_string(),
            ])),
            queue: None,
            state: None,
            epoch: None,
            stats: Arc::new(HotPathStats::default()),
        };

        let mut envelope = serde_json::json!({
            "x402Version": 2,
            "error": "invalid_batch_settlement_svm_cumulative_amount_mismatch",
            "accepts": [{
                "scheme": "batch-settlement",
                "network": "solana:devnet",
                "amount": "1",
                "asset": Pubkey::from([4_u8; 32]).to_string(),
                "payTo": Pubkey::from([5_u8; 32]).to_string(),
                "maxTimeoutSeconds": 60,
                "extra": {
                    "feePayer": fee_payer.to_string(),
                    "withdrawDelay": 3600,
                    "tokenProgram": Pubkey::from([6_u8; 32]).to_string(),
                    "channelState": {
                        "channelId": channel_id.to_string(),
                        "balance": "5000000",
                        "totalClaimed": "0",
                        "withdrawRequestedAt": 0,
                        "chargedCumulativeAmount": "100"
                    },
                    "voucherState": {
                        "signedMaxClaimable": "100",
                        "expiresAt": 0,
                        "signature": "not-a-valid-payer-signature"
                    }
                }
            }]
        });
        let rejected = STANDARD.encode(serde_json::to_vec(&envelope).unwrap());
        RequestSource::on_response(&mut source, 402, Some(&rejected));
        assert_eq!(source.cumulative, 12);
        assert_eq!(
            source
                .presigned
                .as_ref()
                .and_then(|queue| queue.front())
                .map(String::as_str),
            Some("stale-1")
        );

        envelope["accepts"][0]["extra"]["voucherState"]["signature"] =
            serde_json::Value::String(proof_signature);
        let header = STANDARD.encode(serde_json::to_vec(&envelope).unwrap());

        RequestSource::on_response(&mut source, 402, Some(&header));

        let rebuilt = source.presigned.expect("finite window");
        assert_eq!(rebuilt.len(), 3, "replace rejected voucher plus remainder");
        assert!(rebuilt.iter().all(|header| !header.starts_with("stale")));
        assert_eq!(source.cumulative, 103);
    }

    #[test]
    fn reuse_reconstructs_the_original_pda_bound_config() {
        let payer = Pubkey::from([2u8; 32]);
        let fee_payer = Pubkey::from([3u8; 32]);
        let requirements = BatchRequirements {
            scheme: "batch-settlement".to_string(),
            network: "solana:devnet".to_string(),
            amount: "1".to_string(),
            asset: pc::pubkey_string(&Pubkey::from([4u8; 32])),
            pay_to: pc::pubkey_string(&Pubkey::from([5u8; 32])),
            max_timeout_seconds: 60,
            extra: BatchExtra {
                payment_flow: None,
                fee_payer: pc::pubkey_string(&fee_payer),
                receiver_authorizer: None,
                withdraw_delay: 3_600,
                token_program: pc::pubkey_string(&Pubkey::from([6u8; 32])),
                memo: None,
                recent_blockhash: None,
                recent_slot: None,
                channel_state: None,
                voucher_state: None,
            },
        };
        let mut original = BatchSettlement::config_for(&requirements, &payer, 123_456);
        original.salt = "987654321".to_string();
        let channel_id = derive_channel_id(
            &original,
            &requirements.extra.fee_payer,
            &pc::default_program_id(),
        )
        .expect("original channel derives");
        let reused = ReusableChannel {
            channel_id: pc::pubkey_string(&channel_id),
            settled: 42,
            salt: 987_654_321,
            open_slot: 123_456,
        };

        let reconstructed = BatchSettlement::config_for_reuse(&requirements, &payer, &reused);
        assert_eq!(reconstructed, original);
        assert_eq!(
            derive_channel_id(
                &reconstructed,
                &requirements.extra.fee_payer,
                &pc::default_program_id(),
            )
            .unwrap(),
            channel_id
        );
    }

    #[test]
    fn open_requires_settlement_receipt() {
        let error = validate_open_response(StatusCode::OK, false, b"upstream response")
            .expect_err("a bare upstream success must not commit provisioning");

        assert!(error.to_string().contains("PAYMENT-RESPONSE"));
    }

    #[test]
    fn open_accepts_success_with_settlement_receipt() {
        validate_open_response(StatusCode::OK, true, b"upstream response").unwrap();
    }

    #[test]
    fn open_preserves_gateway_rejection_message() {
        let error = validate_open_response(
            StatusCode::BAD_GATEWAY,
            false,
            br#"{"message":"open confirmation failed"}"#,
        )
        .expect_err("a rejected open must fail provisioning");

        assert!(error.to_string().contains("open confirmation failed"));
    }
}
