//! MPP charge scheme — one on-chain-settled credential per request.
//!
//! This is the **pipeline-correctness** scheme: each charge builds a fresh
//! credential the server settles on-chain (replay protection forbids reuse), so
//! throughput is Solana-bound, not the 30k path. It exercises the whole machine
//! (resolve → fund → prepare → unleash → sweep) end-to-end at modest rate.

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use pay_kit::mpp::ChargeRequest;
use pay_kit::mpp::solana_keychain::memory::MemorySigner;
use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;

use super::{
    BenchScheme, Endpoint, Load, PerUserFunding, PreparedRequest, ResolvedPrice, UserCtx,
    UserSetup, build_request, www_authenticate,
};

pub struct MppCharge;

/// Treat these currency labels as native SOL (no SPL token / ATA).
fn is_native(currency: &str) -> bool {
    currency.eq_ignore_ascii_case("sol")
}

#[async_trait]
impl BenchScheme for MppCharge {
    fn name(&self) -> &'static str {
        "mpp_charge"
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
        .context("probe request failed")?;
        if resp.status().as_u16() != 402 {
            bail!("expected 402 challenge, got {}", resp.status());
        }
        let www = www_authenticate(&resp).context("402 had no www-authenticate header")?;
        let challenge = pay_kit::mpp::parse_www_authenticate(&www)
            .map_err(|e| anyhow::anyhow!("parse challenge: {e}"))?;
        let req: ChargeRequest = challenge
            .request
            .decode()
            .map_err(|e| anyhow::anyhow!("decode charge request: {e}"))?;

        let amount_base = req
            .amount
            .parse::<u64>()
            .context("charge amount not an integer")?;
        let md = req.method_details.unwrap_or_default();
        let decimals = md.get("decimals").and_then(|v| v.as_u64()).unwrap_or(9) as u8;
        let network = md
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("mainnet")
            .to_string();
        let mint = if is_native(&req.currency) {
            None
        } else {
            Some(req.currency.clone())
        };
        Ok(ResolvedPrice {
            amount_base,
            currency: req.currency,
            mint,
            recipient: req.recipient.unwrap_or_default(),
            network,
            decimals,
        })
    }

    fn funding_plan(&self, load: &Load, price: &ResolvedPrice) -> PerUserFunding {
        // Fund for the whole unleash window plus a margin; each charge spends
        // `amount_base` of the currency once.
        let n =
            ((load.requests_per_sec_per_user * load.unleash_secs as f64) * 1.2).ceil() as u64 + 16;
        let spend = n.saturating_mul(price.amount_base);
        const FEE_RESERVE: u64 = 50_000_000; // 0.05 SOL for tx fees (+ ATA rent if SPL)
        if price.mint.is_none() {
            PerUserFunding {
                sol_lamports: spend + FEE_RESERVE,
                token_base: 0,
            }
        } else {
            PerUserFunding {
                sol_lamports: FEE_RESERVE,
                token_base: spend,
            }
        }
    }

    async fn provision_user(&self, _ctx: &UserCtx) -> Result<UserSetup> {
        // Charge needs no on-chain channel; the engine funds the wallet.
        Ok(UserSetup::default())
    }

    async fn prepare(
        &self,
        ctx: &UserCtx,
        _setup: &UserSetup,
        n: usize,
    ) -> Result<Vec<PreparedRequest>> {
        let signer = MemorySigner::from_bytes(&ctx.wallet.keypair)
            .map_err(|e| anyhow::anyhow!("signer from keypair: {e}"))?;
        let rpc = RpcClient::new(ctx.rpc_url.clone());

        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            // Each credential is single-use, so fetch a fresh challenge each time.
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
            .context("prepare: challenge request failed")?;
            if resp.status().as_u16() != 402 {
                bail!("prepare: expected 402, got {}", resp.status());
            }
            let www = www_authenticate(&resp).context("prepare: no www-authenticate")?;
            let challenge = pay_kit::mpp::parse_www_authenticate(&www)
                .map_err(|e| anyhow::anyhow!("prepare: parse challenge: {e}"))?;
            let auth = pay_kit::mpp::client::build_credential_header(&signer, &rpc, &challenge)
                .await
                .map_err(|e| anyhow::anyhow!("prepare: build credential: {e}"))?;

            let mut headers = vec![("authorization".to_string(), auth)];
            if let Some(host) = &ctx.host_override {
                headers.push(("host".to_string(), host.clone()));
            }
            out.push(PreparedRequest {
                method: ctx.endpoint.method.clone(),
                url: ctx.endpoint.url.clone(),
                headers,
                body: ctx.endpoint.body.clone(),
            });
        }
        Ok(out)
    }

    async fn settle_and_close(&self, _ctx: &UserCtx, _setup: &UserSetup) -> Result<()> {
        // Nothing to settle for charge; the engine sweeps residual funds.
        Ok(())
    }
}
