//! The scheme abstraction — one impl per payment intent / x402 scheme.
//!
//! The engine runs a fixed pipeline (resolve → fund → provision → prepare →
//! unleash → settle); each scheme fills in the protocol-specific pieces. The
//! driver fires [`PreparedRequest`]s generically, so the hot path is identical
//! across schemes — only how a request is *built* differs.

pub mod batch_settlement;
pub mod mpp_charge;
pub mod mpp_session;
pub mod selftest;
pub mod x402;

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
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
    /// The challenge names a distinct gateway signer that pays transaction
    /// fees and payment-channel rent for the client.
    pub fee_sponsored: bool,
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

/// Immutable on-chain information needed to resume a fixture channel without
/// paying to open another one. MPP needs only the address and watermark;
/// x402 batch settlement also reconstructs the PDA-bound channel config from
/// the original salt and open slot.
#[derive(Clone, Debug)]
pub struct ReusableChannel {
    pub channel_id: String,
    pub settled: u64,
    pub salt: u64,
    pub open_slot: u64,
}

/// A fully-formed request, built off-chain during prepare, fired during unleash.
#[derive(Clone, Debug)]
pub struct PreparedRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// Only a fresh voucher accepted with a successful response is a logical
    /// payment. Free generator-ceiling traffic must never affect this count.
    pub logical_payment: bool,
}

/// Bounded, per-channel request producer. Sources are owned by one load
/// worker, which preserves voucher ordering by keeping at most one request
/// from a source in flight.
#[async_trait]
pub trait RequestSource: Send {
    fn user_index(&self) -> u32;
    async fn next_request(&mut self) -> Result<PreparedRequest>;

    /// Response header name this source wants captured on a non-2xx status
    /// (e.g. a scheme's corrective-challenge header), so it can resynchronize
    /// signing state that drifted from the server. `None` by default — most
    /// schemes don't carry state that can desync this way.
    fn resync_header(&self) -> Option<&'static str> {
        None
    }

    /// Report a completed response. `header` is the value of
    /// `resync_header()`'s named header when present on this response.
    /// Default no-op; only sources that override `resync_header` need to act
    /// on this.
    fn on_response(&mut self, _status: u16, _header: Option<&str>) {}
}

/// RAII handle for a scheme's background hot-path pipeline (e.g. the session
/// signer pool). Started after prepare, stopped when this drops (after the
/// measured window). Dropping signals the workers and joins them.
pub struct HotPathGuard {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    joins: Vec<std::thread::JoinHandle<()>>,
    /// Reported once on drop: (vouchers produced, times a lane found its queue
    /// empty and had to wait for a signer).
    stats: std::sync::Arc<HotPathStats>,
}

#[derive(Default)]
pub struct HotPathStats {
    pub produced: std::sync::atomic::AtomicU64,
    pub stalls: std::sync::atomic::AtomicU64,
}

impl HotPathGuard {
    pub fn new(
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        joins: Vec<std::thread::JoinHandle<()>>,
        stats: std::sync::Arc<HotPathStats>,
    ) -> Self {
        Self { stop, joins, stats }
    }
}

impl Drop for HotPathGuard {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        self.stop.store(true, Ordering::Relaxed);
        for j in self.joins.drain(..) {
            let _ = j.join();
        }
        tracing::info!(
            produced = self.stats.produced.load(Ordering::Relaxed),
            lane_stalls = self.stats.stalls.load(Ordering::Relaxed),
            "signer pool stopped"
        );
    }
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

    /// Supply pre-discovered reusable channels so `provision_user` can drive an
    /// existing channel instead of opening a new one. Called once before
    /// provisioning when `session.reuse` is set. Default: ignored.
    fn set_reuse_channels(&self, _channels: HashMap<u32, ReusableChannel>) {}

    /// On-chain (or registration) setup for one user. Charge: no-op.
    async fn provision_user(&self, ctx: &UserCtx) -> Result<UserSetup>;

    /// Takes setup state for an open that may have reached chain even though
    /// [`Self::provision_user`] returned an error. The engine persists and
    /// closes this state before allowing a wallet to be swept. Most schemes
    /// have no ambiguous on-chain operation, so the default is empty.
    fn take_ambiguous_setup(&self, _ctx: &UserCtx) -> Option<UserSetup> {
        None
    }

    /// Create the bounded request producer for one user. The production-shaped
    /// path signs only when the driver asks for an eligible request. Explicit
    /// offline capacity-isolation configs may pre-sign a fixed, validated
    /// number so client signing does not consume the proxy host during load.
    async fn request_source(
        &self,
        ctx: &UserCtx,
        setup: &UserSetup,
    ) -> Result<Box<dyn RequestSource>>;

    /// Settle + close for one user. Charge: no-op (engine sweeps funds).
    async fn settle_and_close(&self, ctx: &UserCtx, setup: &UserSetup) -> Result<()>;

    /// Optionally start a background pipeline that feeds the hot path, after
    /// prepare and before the measured window. Returns a guard whose drop stops
    /// it (after unleash). Default: none. The session scheme uses this to run a
    /// dedicated signer pool so ed25519 stays off the request lanes for the
    /// whole run, not just a fixed pre-signed window.
    fn spawn_hot_path(&self) -> Option<HotPathGuard> {
        None
    }
}

/// Construct the scheme impl named by config.
pub fn build(cfg: &crate::config::RunConfig) -> Box<dyn BenchScheme> {
    match cfg.run.scheme {
        crate::config::Scheme::MppCharge => Box::new(mpp_charge::MppCharge),
        crate::config::Scheme::MppSession => Box::new(mpp_session::MppSession::new(cfg)),
        crate::config::Scheme::X402Exact => Box::new(x402::X402Exact),
        crate::config::Scheme::X402BatchSettlement => {
            Box::new(batch_settlement::BatchSettlement::new(cfg))
        }
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

/// Set only via the `--allow-insecure-http` CLI flag (which itself requires
/// `PAY_BENCH_ALLOW_INSECURE_HTTP=1`). Benchmarking escape hatch to isolate
/// TLS/transport from a run's numbers — never set this against real funds.
pub static ALLOW_INSECURE_HTTP: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Payment credentials are bearer-like until their cumulative watermark is
/// consumed. Never send them over public cleartext transport; local loopback
/// HTTP remains available for deterministic rehearsal and profiling, and
/// `--allow-insecure-http` opts a whole run out for controlled benchmarking.
pub fn validate_payment_transport(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).with_context(|| format!("invalid endpoint URL {url}"))?;
    if parsed.scheme() == "https" {
        return Ok(());
    }
    let loopback = parsed.host_str().is_some_and(|host| {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if parsed.scheme() == "http"
        && (loopback || ALLOW_INSECURE_HTTP.load(std::sync::atomic::Ordering::Relaxed))
    {
        return Ok(());
    }
    bail!(
        "refusing to send payment credentials to cleartext endpoint {url}; use HTTPS (HTTP is allowed only on loopback, or pass --allow-insecure-http for a controlled benchmark run)"
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_transport_requires_https_or_loopback() {
        assert!(validate_payment_transport("https://provider.example/v1").is_ok());
        assert!(validate_payment_transport("http://127.0.0.1:1402/v1").is_ok());
        assert!(validate_payment_transport("http://[::1]:1402/v1").is_ok());
        assert!(validate_payment_transport("http://localhost:1402/v1").is_ok());

        let error = validate_payment_transport("http://213.239.141.29:1402/v1").unwrap_err();
        assert!(error.to_string().contains("use HTTPS"));

        // Shares process-wide state with other tests in this binary, so flip
        // it and reset within this single test rather than a separate one.
        ALLOW_INSECURE_HTTP.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(validate_payment_transport("http://213.239.141.29:1402/v1").is_ok());
        ALLOW_INSECURE_HTTP.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}
