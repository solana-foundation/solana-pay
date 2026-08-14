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

use std::collections::HashMap;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use pay_core::client::session::SessionHandle;
use pay_kit::mpp::client::{
    PaymentChannelOpenOptions, PaymentChannelSessionOpenOptions,
    create_payment_channel_session_opener,
};
use pay_kit::mpp::solana_keychain::memory::MemorySigner;
use pay_kit::mpp::{PaymentCredential, format_authorization};

use super::{
    BenchScheme, Endpoint, Load, PerUserFunding, PreparedRequest, RequestSource, ResolvedPrice,
    UserCtx, UserSetup, build_request, www_authenticate,
};
use crate::config::RunConfig;
use crate::seeded_session;
use crate::wallet;

/// SOL funded per user: a payment-channel open needs rent plus a fee margin.
const PER_USER_SOL_LAMPORTS: u64 = 25_000_000;

pub struct MppSession {
    deposit_base: u64,
    voucher_base: u64,
    offline: bool,
    offline_namespace: String,
    /// Live channel handles, keyed by user index. `SessionHandle` is `Clone`
    /// (Arc inside), so we clone one out under the lock and `.await` on it —
    /// never holding the std mutex across an await.
    handles: Mutex<HashMap<u32, SessionHandle>>,
}

impl MppSession {
    pub fn new(cfg: &RunConfig) -> Self {
        let (deposit_usdc, voucher_usdc) = cfg
            .session
            .as_ref()
            .map(|s| (s.deposit_usdc, s.voucher_usdc))
            .unwrap_or((1.0, 0.001));
        let offline = cfg.session.as_ref().map(|s| s.offline).unwrap_or(false);
        // USDC-like 6 decimals for voucher accounting.
        Self {
            deposit_base: (deposit_usdc * 1e6) as u64,
            voucher_base: (voucher_usdc * 1e6).max(1.0) as u64,
            offline,
            offline_namespace: cfg.run.name.clone(),
            handles: Mutex::new(HashMap::new()),
        }
    }

    fn handle(&self, index: u32) -> Option<SessionHandle> {
        self.handles.lock().unwrap().get(&index).cloned()
    }
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
        Ok(ResolvedPrice {
            amount_base: self.voucher_base,
            currency: request.currency,
            mint,
            recipient: request.recipient,
            network: request.method_details.network,
            decimals: request.method_details.decimals.unwrap_or(6),
        })
    }

    fn funding_plan(&self, _load: &Load, _price: &ResolvedPrice) -> PerUserFunding {
        // Offline mode touches no chain. A current PayKit session open still
        // requires a valid payment-channel transaction, so offline configs are
        // retained only until the synthetic verifier fixture is ported.
        PerUserFunding {
            sol_lamports: if self.offline {
                0
            } else {
                PER_USER_SOL_LAMPORTS
            },
            token_base: if self.offline { 0 } else { self.deposit_base },
        }
    }

    async fn provision_user(&self, ctx: &UserCtx) -> Result<UserSetup> {
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
        if resp.status().as_u16() != 402 {
            bail!("provision: expected 402 after open, got {}", resp.status());
        }

        self.handles.lock().unwrap().insert(ctx.index, handle);
        Ok(UserSetup {
            channel_id: Some(channel_id),
            open_sig: None,
            ata: None,
        })
    }

    async fn request_source(
        &self,
        ctx: &UserCtx,
        _setup: &UserSetup,
    ) -> Result<Box<dyn RequestSource>> {
        let handle = self
            .handle(ctx.index)
            .with_context(|| format!("no session handle for user {}", ctx.index))?;
        Ok(Box::new(SessionSource {
            index: ctx.index,
            handle,
            voucher_base: self.voucher_base,
            method: ctx.endpoint.method.clone(),
            url: ctx.endpoint.url.clone(),
            host_override: ctx.host_override.clone(),
            body: ctx.endpoint.body.clone(),
        }))
    }

    async fn settle_and_close(&self, ctx: &UserCtx, _setup: &UserSetup) -> Result<()> {
        let Some(handle) = self.handle(ctx.index) else {
            return Ok(());
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
        if !resp.status().is_success() {
            tracing::warn!(index = ctx.index, status = %resp.status(), "session close not accepted");
        }
        Ok(())
    }
}

struct SessionSource {
    index: u32,
    handle: SessionHandle,
    voucher_base: u64,
    method: String,
    url: String,
    host_override: Option<String>,
    body: String,
}

#[async_trait]
impl RequestSource for SessionSource {
    fn user_index(&self) -> u32 {
        self.index
    }

    async fn next_request(&mut self) -> Result<PreparedRequest> {
        let auth = self
            .handle
            .voucher_header(self.voucher_base)
            .await
            .map_err(|e| anyhow::anyhow!("voucher_header: {e}"))?;
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
