//! MPP session scheme — push mode. The 30k path.
//!
//! Per user (= one channel):
//!   - **provision** (on-chain, once): fetch the session 402, build and submit
//!     a payment-channel open transaction bound to its challenged blockhash and
//!     slot, then retain a [`SessionHandle`] with an ephemeral voucher signer.
//!   - **prepare** (off-chain): pre-sign N ordered vouchers (monotonic
//!     watermark, no blockhash, no expiry) → ready-to-fire requests.
//!   - **unleash**: the driver fires the vouchers in order (cheap, signature-
//!     verify only on the server — this is what scales).
//!   - **settle_and_close**: send the `close` Authorization → server batch-settles.

use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use crossbeam_queue::ArrayQueue;
use pay_core::client::session::{RawSession, SessionHandle, voucher_header_sync};
use pay_kit::mpp::client::{
    PaymentChannelOpenOptions, PaymentChannelSessionOpenOptions,
    create_payment_channel_session_opener,
};
use pay_kit::mpp::solana_keychain::memory::MemorySigner;
use pay_kit::mpp::{PaymentCredential, format_authorization};
use reqwest::StatusCode;
use solana_pubkey::Pubkey;

use super::{
    BenchScheme, Endpoint, HotPathGuard, HotPathStats, Load, PerUserFunding, PreparedRequest,
    RequestSource, ResolvedPrice, ReusableChannel, UserCtx, UserSetup, build_request,
    validate_payment_transport, www_authenticate,
};
use crate::config::RunConfig;
use crate::seeded_session;
use crate::wallet;

/// SOL funded per user when the payer funds its own open: payment-channel rent
/// plus a fee margin. Sponsored challenges move both costs to the operator.
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

/// One channel's slot in the background signer pipeline: its handle (single
/// producer, so vouchers stay monotonic) and the bounded queue lanes drain.
struct SignerTask {
    handle: SessionHandle,
    queue: Arc<ArrayQueue<String>>,
    base: u64,
}

pub struct MppSession {
    deposit_base: u64,
    voucher_base: u64,
    offline: bool,
    offline_namespace: String,
    pre_sign_requests_per_user: usize,
    /// A positive value uses dedicated signer threads to fill per-channel
    /// queues off the hot path for the whole run (see [`SessionCfg::background_signers`]).
    background_signers: usize,
    close_after_run: bool,
    /// Live channel handles, keyed by user index. `SessionHandle` is `Clone`
    /// (Arc inside), so we clone one out under the lock and `.await` on it —
    /// never holding the std mutex across an await.
    handles: Mutex<HashMap<u32, SessionHandle>>,
    /// Reuse mode: user index → (existing channel address, on-chain settled).
    /// Populated once before provisioning; `provision_user` drives these instead
    /// of opening new channels. Empty unless `session.reuse` is set.
    reuse_channels: Mutex<HashMap<u32, ReusableChannel>>,
    /// Opens for which the authorization was constructed and is about to be
    /// sent. If the request/response fails ambiguously, retain the deterministic
    /// channel address so the engine can journal and close it before sweeping.
    ambiguous_opens: Mutex<HashMap<u32, UserSetup>>,
    /// Per-channel signer slots, registered as request sources are built and
    /// consumed by [`MppSession::spawn_hot_path`]. Empty unless background mode.
    signer_registry: Mutex<Vec<SignerTask>>,
    /// Shared with the sources (stall counter) and the pool (produced counter).
    hot_stats: Arc<HotPathStats>,
}

impl MppSession {
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
        // USDC-like 6 decimals for voucher accounting.
        Self {
            deposit_base: (deposit_usdc * 1e6) as u64,
            voucher_base: voucher_base_units(voucher_usdc),
            offline,
            offline_namespace: cfg.offline_namespace().to_string(),
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

    /// Per-channel queue depth for background mode. Falls back to a sane default
    /// when `pre_sign_requests_per_user` is left at 0.
    fn queue_depth(&self) -> usize {
        if self.pre_sign_requests_per_user > 0 {
            self.pre_sign_requests_per_user
        } else {
            1024
        }
    }

    fn handle(&self, index: u32) -> Option<SessionHandle> {
        self.handles.lock().unwrap().get(&index).cloned()
    }

    fn reuse_lookup(&self, index: u32) -> Option<ReusableChannel> {
        self.reuse_channels.lock().unwrap().get(&index).cloned()
    }

    fn require_live_channel_close(&self) -> Result<()> {
        if !self.offline && !self.close_after_run {
            bail!(
                "session.close_after_run=false leaves live payment channels open; refusing to sweep wallets or mark the run complete without real-network recovery"
            );
        }
        Ok(())
    }
}

fn validate_open_response(status: StatusCode, body: &[u8], expected_channel: &str) -> Result<()> {
    if status != StatusCode::PAYMENT_REQUIRED {
        bail!("provision: expected 402 after open, got {status}");
    }

    let payload: serde_json::Value =
        serde_json::from_slice(body).context("provision: 402 after open was not valid JSON")?;
    let error = payload
        .get("error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing error code");
    if error != "session_voucher_required" {
        let message = payload
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("no server message");
        bail!("provision: channel open was rejected ({error}): {message}");
    }

    let channel_id = payload
        .get("channelId")
        .and_then(serde_json::Value::as_str)
        .context("provision: successful open response omitted channelId")?;
    anyhow::ensure!(
        channel_id == expected_channel,
        "provision: server opened channel {channel_id}, expected {expected_channel}"
    );
    Ok(())
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
    bail!("session close was rejected with {status}: {message}")
}

#[async_trait]
impl BenchScheme for MppSession {
    fn name(&self) -> &'static str {
        "mpp_session"
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
        .context("session probe failed")?;
        if resp.status().as_u16() != 402 {
            bail!("expected 402 session challenge, got {}", resp.status());
        }
        let www = www_authenticate(&resp).context("402 had no www-authenticate")?;
        let (_challenge, request) =
            SessionHandle::parse_challenge(&www).context("not a session challenge")?;
        let mint = pay_kit::mpp::resolve_stablecoin_mint(
            &request.currency,
            Some(&request.method_details.network),
        )
        .map(str::to_string);
        let fee_sponsored = request.method_details.fee_payer == Some(true)
            && request.method_details.fee_payer_key.is_some();
        Ok(ResolvedPrice {
            amount_base: self.voucher_base,
            currency: request.currency,
            mint,
            recipient: request.recipient,
            network: request.method_details.network,
            decimals: request.method_details.decimals.unwrap_or(6),
            fee_sponsored,
        })
    }

    fn funding_plan(&self, _load: &Load, price: &ResolvedPrice) -> PerUserFunding {
        // Offline mode touches no chain. A current PayKit session open still
        // requires a valid payment-channel transaction, so offline configs are
        // retained only until the synthetic verifier fixture is ported.
        PerUserFunding {
            sol_lamports: open_sol_lamports(self.offline, price.fee_sponsored),
            token_base: if self.offline { 0 } else { self.deposit_base },
        }
    }

    fn set_reuse_channels(&self, channels: HashMap<u32, ReusableChannel>) {
        *self.reuse_channels.lock().unwrap() = channels;
    }

    async fn provision_user(&self, ctx: &UserCtx) -> Result<UserSetup> {
        validate_payment_transport(&ctx.endpoint.url)?;
        if self.offline {
            // The server owns a benchmark-only confirmed-state fixture. The
            // client still obtains and echoes a real signed challenge, then
            // signs normal vouchers; no open bypass exists in Pay's CLI.
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
            .context("offline provision: challenge request failed")?;
            if resp.status().as_u16() != 402 {
                bail!("offline provision: expected 402, got {}", resp.status());
            }
            let www = www_authenticate(&resp).context("offline provision: no session challenge")?;
            let (challenge, _) = SessionHandle::parse_challenge(&www)
                .context("offline provision: invalid challenge")?;
            let material = seeded_session::handle_for_challenge(
                &self.offline_namespace,
                ctx.index,
                challenge,
            )?;
            let channel_id = material.channel_id().await;
            self.handles.lock().unwrap().insert(ctx.index, material);
            return Ok(UserSetup {
                channel_id: Some(channel_id),
                open_sig: None,
                ata: None,
            });
        }
        // 1. Fresh session 402 → challenge + request (operator, cap).
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
        .context("provision: session challenge request failed")?;
        if resp.status().as_u16() != 402 {
            bail!("provision: expected 402, got {}", resp.status());
        }
        let www = www_authenticate(&resp).context("provision: no www-authenticate")?;
        let (challenge, request) =
            SessionHandle::parse_challenge(&www).context("provision: not a session challenge")?;

        // Reuse: this wallet already owns an open channel on-chain. Drive it by
        // address, resuming from its settled watermark, instead of opening (and
        // paying rent for) a new one. The gateway loads it from chain on the
        // first voucher (see `session.load_from_chain`).
        if let Some(reused) = self.reuse_lookup(ctx.index) {
            let channel = Pubkey::from_str(&reused.channel_id)
                .map_err(|e| anyhow::anyhow!("reuse: bad channel id {}: {e}", reused.channel_id))?;
            let session_kp = wallet::subkey(&ctx.wallet.seed(), "session");
            let signer = Box::new(
                MemorySigner::from_bytes(&session_kp.keypair)
                    .map_err(|e| anyhow::anyhow!("reuse session signer: {e}"))?,
            );
            let mut raw = RawSession::new(channel, signer);
            // Continue the monotonic voucher watermark above what is already
            // settled on-chain, so the first reuse voucher is accepted and
            // settlement advances rather than rejecting a stale amount.
            raw.cumulative = reused.settled;
            let voucher_key = ed25519_dalek::SigningKey::from_bytes(&session_kp.seed());
            let handle = SessionHandle::from_active(raw, challenge).with_voucher_key(voucher_key);
            self.handles.lock().unwrap().insert(ctx.index, handle);
            return Ok(UserSetup {
                channel_id: Some(reused.channel_id),
                open_sig: None,
                ata: None,
            });
        }

        // 2. Build a genuine payment-channel open transaction against the
        // challenged blockhash and slot. The proxy verifies and broadcasts the
        // transaction before it admits the channel.
        let session_kp = wallet::subkey(&ctx.wallet.seed(), "session");
        let session_signer = Box::new(
            MemorySigner::from_bytes(&session_kp.keypair)
                .map_err(|e| anyhow::anyhow!("session signer: {e}"))?,
        );
        let payer_signer = MemorySigner::from_bytes(&ctx.wallet.keypair)
            .map_err(|e| anyhow::anyhow!("payer signer: {e}"))?;
        let opened = create_payment_channel_session_opener(
            &request,
            &payer_signer,
            session_signer,
            None,
            PaymentChannelSessionOpenOptions {
                open: PaymentChannelOpenOptions {
                    deposit: Some(self.deposit_base),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("build payment-channel open: {e}"))?;
        let auth =
            format_authorization(&PaymentCredential::new(challenge.to_echo(), opened.action))
                .map_err(|e| anyhow::anyhow!("format session open authorization: {e}"))?;
        let voucher_key = ed25519_dalek::SigningKey::from_bytes(&session_kp.seed());
        let handle =
            SessionHandle::from_active(opened.session, challenge).with_voucher_key(voucher_key);
        let channel_id = opened.open.channel_id.to_string();
        let setup = UserSetup {
            channel_id: Some(channel_id.clone()),
            open_sig: None,
            ata: None,
        };
        // The gateway may broadcast this authorization and then lose its HTTP
        // response. Save its deterministic channel ID before sending so that
        // an error cannot turn an on-chain deposit into an untracked wallet.
        self.ambiguous_opens
            .lock()
            .unwrap()
            .insert(ctx.index, setup.clone());

        // 3. Submit the open authorization. A successful open returns a 402
        // requesting the first voucher, not a free 200 response.
        let resp = build_request(
            &ctx.http,
            &ctx.endpoint.method,
            &ctx.endpoint.url,
            &ctx.endpoint.body,
            ctx.host_override.as_deref(),
            &[("authorization".to_string(), auth)],
        )
        .send()
        .await
        .context("provision: open request failed")?;
        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .context("provision: failed to read open response")?;
        validate_open_response(status, &body, &channel_id)?;

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
            .with_context(|| format!("no session handle for user {}", ctx.index))?;

        // Background-signer mode: a shared bounded queue is filled by the signer
        // pool (started in `spawn_hot_path`) and drained by this source's lane.
        // The source never signs — ed25519 is off the hot path for the whole run.
        if self.background_signers > 0 {
            let queue = Arc::new(ArrayQueue::new(self.queue_depth()));
            self.signer_registry.lock().unwrap().push(SignerTask {
                handle: handle.clone(),
                queue: queue.clone(),
                base: self.voucher_base,
            });
            return Ok(Box::new(SessionSource {
                index: ctx.index,
                handle,
                voucher_base: self.voucher_base,
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
            let voucher_base = self.voucher_base;
            let signing_handle = handle.clone();
            tokio::task::spawn_blocking(move || -> Result<VecDeque<String>> {
                let mut headers = VecDeque::with_capacity(count);
                for _ in 0..count {
                    headers.push_back(
                        voucher_header_sync(&signing_handle, voucher_base)
                            .map_err(|e| anyhow::anyhow!("pre-sign voucher: {e}"))?,
                    );
                }
                Ok(headers)
            })
            .await
            .context("pre-sign task panicked")??
        } else {
            VecDeque::new()
        };
        Ok(Box::new(SessionSource {
            index: ctx.index,
            handle,
            voucher_base: self.voucher_base,
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

    async fn settle_and_close(&self, ctx: &UserCtx, setup: &UserSetup) -> Result<()> {
        // Seeded offline fixtures do not own real channels or a settlement
        // signer.  Closing them after the measured window adds an unbounded
        // serial HTTP tail (and can outlive the synthetic challenge) without
        // exercising a production path.
        if self.offline {
            return Ok(());
        }
        // A successful return lets the engine sweep the wallet and mark the
        // durable user record clean. Deferred real channels cannot be recovered
        // on devnet/mainnet yet, so fail before that point and leave the journal
        // outstanding with its channel ID instead of stranding the deposit.
        self.require_live_channel_close()?;
        let handle = if let Some(handle) = self.handle(ctx.index) {
            handle
        } else {
            // An open request can reach the gateway while the client observes
            // a transport/response error. Rebuild a close-only session from
            // the durable deterministic channel ID; if this close fails the
            // engine leaves the journal unswept instead of reclaiming only the
            // wallet balance and stranding the channel deposit/rent.
            let channel_id = setup
                .channel_id
                .as_deref()
                .context("ambiguous session open has no channel id")?
                .parse()
                .context("ambiguous session open has an invalid channel id")?;
            let challenge_response = build_request(
                &ctx.http,
                &ctx.endpoint.method,
                &ctx.endpoint.url,
                &ctx.endpoint.body,
                ctx.host_override.as_deref(),
                &[],
            )
            .send()
            .await
            .context("requesting recovery challenge for ambiguous open")?;
            anyhow::ensure!(
                challenge_response.status() == StatusCode::PAYMENT_REQUIRED,
                "expected 402 recovery challenge, got {}",
                challenge_response.status()
            );
            let www = www_authenticate(&challenge_response)
                .context("ambiguous-open recovery challenge missing")?;
            let (challenge, _) = SessionHandle::parse_challenge(&www)
                .context("invalid ambiguous-open recovery challenge")?;
            let session_key = wallet::subkey(&ctx.wallet.seed(), "session");
            let signer = Box::new(
                MemorySigner::from_bytes(&session_key.keypair)
                    .map_err(|error| anyhow::anyhow!("session signer: {error}"))?,
            );
            let voucher_key = ed25519_dalek::SigningKey::from_bytes(&session_key.seed());
            SessionHandle::new(channel_id, signer, challenge).with_voucher_key(voucher_key)
        };
        let auth = handle
            .close_header(None)
            .await
            .map_err(|e| anyhow::anyhow!("close_header: {e}"))?;
        let resp = build_request(
            &ctx.http,
            &ctx.endpoint.method,
            &ctx.endpoint.url,
            &ctx.endpoint.body,
            ctx.host_override.as_deref(),
            &[("authorization".to_string(), auth)],
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
        // owned by exactly one thread, so its `voucher_header` calls are
        // serialized and the cumulative watermark stays strictly monotonic
        // without any cross-thread coordination.
        let mut buckets: Vec<Vec<SignerTask>> = (0..threads).map(|_| Vec::new()).collect();
        for (i, task) in tasks.into_iter().enumerate() {
            buckets[i % threads].push(task);
        }

        let mut joins = Vec::with_capacity(threads);
        for (tid, bucket) in buckets.into_iter().enumerate() {
            let stop = stop.clone();
            let stats = stats.clone();
            let join = std::thread::Builder::new()
                .name(format!("signer-{tid}"))
                .spawn(move || signer_thread(bucket, stop, stats))
                .expect("spawn signer thread");
            joins.push(join);
        }
        tracing::info!(
            signer_threads = threads,
            "signer pool started (ed25519 off the hot path for the whole run)"
        );
        Some(HotPathGuard::new(stop, joins, stats))
    }
}

/// One signer thread: owns a disjoint set of channels and keeps their queues
/// topped up. Builds a single current-thread runtime and reuses it for every
/// voucher — `voucher_header_sync` builds a fresh runtime per call, which would
/// dominate cost at these rates. Uncontended per-channel async mutex, so
/// `block_on` here is just driving the ed25519 sign + header serialization.
fn signer_thread(bucket: Vec<SignerTask>, stop: Arc<AtomicBool>, stats: Arc<HotPathStats>) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("signer thread runtime: {e}");
            return;
        }
    };
    rt.block_on(async move {
        let mut produced_local: u64 = 0;
        while !stop.load(Ordering::Relaxed) {
            let mut progressed = false;
            for task in &bucket {
                // Top this channel back up to capacity, then move on so every
                // channel gets refilled each pass (fair across the bucket).
                while task.queue.len() < task.queue.capacity() {
                    match task.handle.voucher_header(task.base).await {
                        Ok(header) => {
                            if task.queue.push(header).is_err() {
                                break; // drained concurrently filled it; race, fine
                            }
                            produced_local += 1;
                            progressed = true;
                            if produced_local.is_multiple_of(8192) {
                                stats.produced.fetch_add(8192, Ordering::Relaxed);
                            }
                        }
                        Err(e) => {
                            tracing::error!("signer: voucher_header failed: {e}");
                            break;
                        }
                    }
                }
                if stop.load(Ordering::Relaxed) {
                    break;
                }
            }
            // All queues full: nothing to do until lanes drain. Park briefly
            // (dedicated thread) instead of spinning hot, so we don't steal a
            // core from the lane threads while waiting.
            if !progressed {
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
        }
        stats
            .produced
            .fetch_add(produced_local % 8192, Ordering::Relaxed);
    });
}

struct SessionSource {
    index: u32,
    handle: SessionHandle,
    voucher_base: u64,
    method: String,
    url: String,
    host_override: Option<String>,
    body: String,
    presigned: Option<VecDeque<String>>,
    /// Background-signer mode: pop pre-signed vouchers the pool fills. When set,
    /// this source never signs (single producer per channel is the signer pool).
    queue: Option<Arc<ArrayQueue<String>>>,
    stats: Arc<HotPathStats>,
}

#[async_trait]
impl RequestSource for SessionSource {
    fn user_index(&self) -> u32 {
        self.index
    }

    async fn next_request(&mut self) -> Result<PreparedRequest> {
        let auth = if let Some(queue) = &self.queue {
            // Vouchers are FIFO within a channel, so popping in order preserves
            // the monotonic watermark. If the queue is momentarily empty the
            // signer pool fell behind — wait for it rather than signing here
            // (which would race the pool's watermark and break ordering).
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
                None => self
                    .handle
                    .voucher_header(self.voucher_base)
                    .await
                    .map_err(|e| anyhow::anyhow!("voucher_header: {e}"))?,
            }
        };
        let mut headers = vec![("authorization".to_string(), auth)];
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_voucher_challenge_for_expected_open_channel() {
        validate_open_response(
            StatusCode::PAYMENT_REQUIRED,
            br#"{"error":"session_voucher_required","channelId":"channel-a"}"#,
            "channel-a",
        )
        .unwrap();
    }

    #[test]
    fn rejects_verification_failure_rechallenge() {
        let error = validate_open_response(
            StatusCode::PAYMENT_REQUIRED,
            br#"{"error":"verification_failed","message":"Session open failed: program error 0x38"}"#,
            "channel-a",
        )
        .unwrap_err();
        assert!(error.to_string().contains("verification_failed"));
        assert!(error.to_string().contains("program error 0x38"));
    }

    #[test]
    fn rejects_success_marker_for_another_channel() {
        let error = validate_open_response(
            StatusCode::PAYMENT_REQUIRED,
            br#"{"error":"session_voucher_required","channelId":"channel-b"}"#,
            "channel-a",
        )
        .unwrap_err();
        assert!(error.to_string().contains("channel-b"));
        assert!(error.to_string().contains("channel-a"));
    }

    #[test]
    fn rejects_non_402_and_malformed_402() {
        assert!(
            validate_open_response(StatusCode::OK, b"{}", "channel-a")
                .unwrap_err()
                .to_string()
                .contains("expected 402")
        );
        assert!(
            validate_open_response(StatusCode::PAYMENT_REQUIRED, b"not json", "channel-a")
                .unwrap_err()
                .to_string()
                .contains("not valid JSON")
        );
    }

    #[test]
    fn rejects_failed_close_with_server_message() {
        let error = validate_close_response(
            StatusCode::PAYMENT_REQUIRED,
            br#"{"message":"payment-channel settlement: custom program error: 0x35"}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("402 Payment Required"));
        assert!(error.to_string().contains("custom program error: 0x35"));
        validate_close_response(StatusCode::OK, b"").unwrap();
    }

    #[test]
    fn sponsored_funding_plan_does_not_budget_client_sol() {
        let config: RunConfig = serde_yml::from_str(include_str!(
            "../../configs/session-devnet-100k-1m-rehearsal.yml"
        ))
        .unwrap();
        let scheme = MppSession::new(&config);
        let mut price = ResolvedPrice {
            amount_base: 1,
            currency: "USDtest".into(),
            mint: Some(config.run.mint.clone().unwrap()),
            recipient: "recipient".into(),
            network: "devnet".into(),
            decimals: 6,
            fee_sponsored: true,
        };

        let sponsored = scheme.funding_plan(&config.load, &price);
        assert_eq!(sponsored.sol_lamports, 0);
        assert_eq!(sponsored.token_base, 20_000);

        price.fee_sponsored = false;
        assert_eq!(
            scheme.funding_plan(&config.load, &price).sol_lamports,
            PER_USER_SOL_LAMPORTS
        );
    }

    #[test]
    fn ambiguous_open_setup_is_retained_for_engine_cleanup() {
        let config: RunConfig = serde_yml::from_str(include_str!(
            "../../configs/session-devnet-100k-1m-rehearsal.yml"
        ))
        .unwrap();
        let scheme = MppSession::new(&config);
        let setup = UserSetup {
            channel_id: Some("channel-after-response-loss".to_string()),
            open_sig: None,
            ata: None,
        };
        scheme
            .ambiguous_opens
            .lock()
            .unwrap()
            .insert(7, setup.clone());
        let ctx = UserCtx {
            index: 7,
            wallet: wallet::derive_user(&[9; 32], "ambiguous-open-test", 7),
            rpc_url: "http://127.0.0.1:8899".to_string(),
            endpoint: config.endpoints[0].clone(),
            http: reqwest::Client::new(),
            host_override: None,
            mint: None,
        };

        assert_eq!(
            scheme
                .take_ambiguous_setup(&ctx)
                .and_then(|value| value.channel_id),
            setup.channel_id
        );
        assert!(scheme.take_ambiguous_setup(&ctx).is_none());
    }

    #[test]
    fn live_deferred_channels_are_not_reported_as_cleaned_up() {
        let mut config: RunConfig = serde_yml::from_str(include_str!(
            "../../configs/session-devnet-100k-1m-rehearsal.yml"
        ))
        .unwrap();
        config.session.as_mut().unwrap().close_after_run = false;
        let scheme = MppSession::new(&config);

        let error = scheme.require_live_channel_close().unwrap_err();
        assert!(error.to_string().contains("refusing to sweep wallets"));
    }

    #[test]
    fn offline_deferred_channels_do_not_require_a_close() {
        let mut config: RunConfig = serde_yml::from_str(include_str!(
            "../../configs/session-devnet-100k-1m-rehearsal.yml"
        ))
        .unwrap();
        let session = config.session.as_mut().unwrap();
        session.offline = true;
        session.close_after_run = false;

        MppSession::new(&config)
            .require_live_channel_close()
            .unwrap();
    }
}
