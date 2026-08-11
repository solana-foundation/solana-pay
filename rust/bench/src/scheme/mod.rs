//! The scheme abstraction — one impl per payment intent / x402 scheme.
//!
//! The engine runs a fixed pipeline (resolve → fund → provision → prepare →
//! unleash → settle); each scheme fills in the protocol-specific pieces. The
//! driver fires [`PreparedRequest`]s generically, so the hot path is identical
//! across schemes — only how a request is *built* differs.

pub mod mpp_charge;
pub mod mpp_session;
pub mod selftest;
pub mod x402;

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use solana_pubkey::Pubkey;

use crate::config::{Endpoint, Load};
use crate::wallet::Wallet;

/// Price + routing learned by probing an endpoint's 402 challenge.
// `network`/`recipient` are consumed by the session + mainnet paths (M2/M4).
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ResolvedPrice {
    pub amount_base: u64,
    pub currency: String,
    /// `None` ⇒ native SOL; `Some(mint)` ⇒ SPL token.
    pub mint: Option<String>,
    pub recipient: String,
    pub network: String,
    pub decimals: u8,
}

/// Funds one user needs for the whole run.
#[derive(Clone, Copy, Debug, Default)]
pub struct PerUserFunding {
    pub sol_lamports: u64,
    pub token_base: u64,
}

/// Everything a scheme needs to act on behalf of one user.
// `mint` is read by the session/mainnet paths (M2/M4).
#[derive(Clone)]
#[allow(dead_code)]
pub struct UserCtx {
    pub index: u32,
    pub wallet: Wallet,
    pub rpc_url: String,
    pub endpoint: Endpoint,
    pub http: reqwest::Client,
    /// `Host` header to force (rehearsal proxy routes by subdomain). `None` on
    /// mainnet where the URL host is already correct.
    pub host_override: Option<String>,
    pub mint: Option<Pubkey>,
}

/// On-chain / registration state from provisioning, needed at teardown.
#[derive(Clone, Debug, Default)]
pub struct UserSetup {
    pub channel_id: Option<String>,
    pub ata: Option<String>,
    pub open_sig: Option<String>,
}

/// A fully-formed request, built off-chain during prepare, fired during unleash.
#[derive(Clone, Debug)]
pub struct PreparedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Result of firing one prepared request. (The driver records into its own
/// metrics sink today; this type is for schemes that need richer per-fire data.)
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Outcome {
    pub ok: bool,
    pub status: Option<u16>,
    pub latency: Duration,
    pub error: Option<String>,
}

#[async_trait]
pub trait BenchScheme: Send + Sync {
    fn name(&self) -> &'static str;

    /// Probe one endpoint's 402 challenge to learn price + routing.
    async fn resolve(
        &self,
        http: &reqwest::Client,
        endpoint: &Endpoint,
        host_override: Option<&str>,
    ) -> Result<ResolvedPrice>;

    /// How much to fund each user, given the load and resolved price.
    fn funding_plan(&self, load: &Load, price: &ResolvedPrice) -> PerUserFunding;

    /// On-chain (or registration) setup for one user. Charge: no-op.
    async fn provision_user(&self, ctx: &UserCtx) -> Result<UserSetup>;

    /// Build `n` ready-to-fire requests for one user (off-chain signing).
    async fn prepare(
        &self,
        ctx: &UserCtx,
        setup: &UserSetup,
        n: usize,
    ) -> Result<Vec<PreparedRequest>>;

    /// Settle + close for one user. Charge: no-op (engine sweeps funds).
    async fn settle_and_close(&self, ctx: &UserCtx, setup: &UserSetup) -> Result<()>;
}

/// Construct the scheme impl named by config.
pub fn build(cfg: &crate::config::RunConfig) -> Box<dyn BenchScheme> {
    match cfg.run.scheme {
        crate::config::Scheme::MppCharge => Box::new(mpp_charge::MppCharge),
        crate::config::Scheme::MppSession => Box::new(mpp_session::MppSession::new(cfg)),
        crate::config::Scheme::X402Exact => Box::new(x402::X402Exact),
        crate::config::Scheme::SelfTest => Box::new(selftest::SelfTest),
    }
}

// ── Shared HTTP helpers ──────────────────────────────────────────────────────

/// Build a request, applying an optional forced `Host` and extra headers.
pub fn build_request(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    body: &str,
    host: Option<&str>,
    headers: &[(String, String)],
) -> reqwest::RequestBuilder {
    let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::POST);
    let mut rb = client.request(m, url).body(body.to_string());
    if let Some(h) = host {
        rb = rb.header(reqwest::header::HOST, h);
    }
    for (k, v) in headers {
        rb = rb.header(k.as_str(), v.as_str());
    }
    rb
}

/// Read `www-authenticate` from a response as a string. Parses from raw bytes,
/// not `to_str()` — challenge descriptions may carry non-ASCII (e.g. an em-dash)
/// that `HeaderValue::to_str()` rejects even though it's valid UTF-8.
pub fn www_authenticate(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get("www-authenticate")
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
        .map(str::to_string)
}
