//! Run configuration — the YAML the bench takes as input.
//!
//! One file fully describes a run: which scheme/intent, which network, the
//! funder, the load profile, the endpoints under test, and the hard spend caps
//! that gate any real-money run.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Payment scheme / intent under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    /// One on-chain-settled credential per request. Pipeline-correctness scheme
    /// (on-chain-bound, not the 30k path).
    MppCharge,
    /// Open a channel once, stream off-chain vouchers. The 30k path.
    MppSession,
    /// x402 `exact` fixed-amount scheme.
    X402Exact,
    /// x402 `batch-settlement` scheme: open one escrow channel, stream cumulative
    /// off-chain vouchers, server batch-settles on-chain later. The x402 wire
    /// analogue of `mpp_session`.
    X402BatchSettlement,
    /// Generator ceiling check: no on-chain work — fires plain requests at a
    /// free proxy path to measure how many users/req-s the bench + proxy can
    /// sustain, decoupled from settlement.
    SelfTest,
}

/// Where the run executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    /// Local surfpool JIT mainnet-fork — no real funds. Rehearsal.
    Fork,
    /// Real mainnet — real USDC + SOL fees.
    Mainnet,
    /// Devnet.
    Devnet,
}

impl Network {
    /// Network slug as the MPP/server layer expects it. Surfpool is a localnet
    /// implementation, so a fork rehearses as `localnet`.
    pub fn slug(self) -> &'static str {
        match self {
            Network::Fork => "localnet",
            Network::Mainnet => "mainnet",
            Network::Devnet => "devnet",
        }
    }
    pub fn is_real_money(self) -> bool {
        matches!(self, Network::Mainnet)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RunConfig {
    pub run: RunMeta,
    pub load: Load,
    pub endpoints: Vec<Endpoint>,
    #[serde(default)]
    pub session: Option<SessionCfg>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RunMeta {
    pub name: String,
    pub scheme: Scheme,
    pub network: Network,
    /// Env var holding the RPC URL (preferred for secrets), or…
    #[serde(default)]
    pub rpc_url_env: Option<String>,
    /// …an explicit URL. Ignored for `network: fork` (surfpool supplies it).
    #[serde(default)]
    pub rpc_url: Option<String>,
    /// Env var containing the path to a private benchmark CA certificate.
    #[serde(default)]
    pub tls_ca_cert_env: Option<String>,
    /// Explicit PEM path for a private benchmark CA. Prefer
    /// `tls_ca_cert_env` in shared configs.
    #[serde(default)]
    pub tls_ca_cert: Option<String>,
    /// Charge/voucher currency. `None` ⇒ native SOL; `Some(mint)` ⇒ SPL token.
    #[serde(default)]
    pub mint: Option<String>,
    #[serde(default)]
    pub funder: FunderCfg,
    pub safety: Safety,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FunderCfg {
    /// Env var holding the funder keypair (solana JSON array or base58).
    #[serde(default)]
    pub keypair_env: Option<String>,
    /// Path to a solana-CLI keypair JSON file.
    #[serde(default)]
    pub keypair_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Safety {
    /// Hard ceiling on total USDC dispersed across all users.
    pub max_total_usdc: f64,
    /// Hard ceiling on total SOL (rent + fees). Recovered on sweep.
    pub max_total_sol: f64,
    /// Require an explicit `--yes` on real-money networks.
    #[serde(default = "default_true")]
    pub require_confirmation: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Load {
    /// Simulated users. For sessions this is the number of concurrent channels.
    pub users: usize,
    /// Target request rate per user during the unleash phase.
    pub requests_per_sec_per_user: f64,
    /// Seconds spent pre-building the request buffer before unleashing.
    #[serde(default = "default_prepare_secs")]
    pub prepare_secs: u64,
    /// Measured-window length. The driver also stops early if the buffer drains.
    #[serde(default = "default_unleash_secs")]
    pub unleash_secs: u64,
    /// Cap on in-flight requests across all users.
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: usize,
    /// Maximum concurrent per-user funding and scheme provisioning operations.
    /// Session opens each submit and confirm an on-chain transaction, so live
    /// lifecycle benchmarks normally set this much higher than the default.
    #[serde(default = "default_provision_concurrency")]
    pub provision_concurrency: usize,
    /// Maximum concurrent per-user close and sweep operations after the
    /// measured window. Keep this independently bounded: session close waits
    /// for an on-chain transaction, while provisioning and request traffic
    /// have different capacity limits.
    #[serde(default = "default_settlement_concurrency")]
    pub settlement_concurrency: usize,
    /// Fixed generator workers. Channels are deterministically assigned by
    /// user index, avoiding one Tokio task and interval per logical session.
    #[serde(default = "default_worker_count")]
    pub workers: usize,
    /// Use HTTP/2 prior knowledge against the benchmark's h2c loopback gate.
    /// This multiplexes requests without changing their HTTP/payment shape.
    #[serde(default)]
    pub http2_prior_knowledge: bool,
    /// Pingora data-plane workers for an embedded benchmark proxy. `None`
    /// keeps the production default (all available logical CPUs).
    #[serde(default)]
    pub proxy_workers: Option<usize>,
    /// Deterministic generator-fleet shard index, zero based.
    #[serde(default)]
    pub shard_index: usize,
    /// Total generator-fleet shards. Each channel is assigned to exactly one.
    #[serde(default = "default_shard_count")]
    pub shard_count: usize,
    /// Use a fixed pool of this many persistent HTTP/2 connections
    /// (`StableH2Pool`) instead of reqwest's churning `Ver::Auto` pool. `0`
    /// (default) keeps the reqwest client. Non-zero opens exactly this many
    /// connections once and multiplexes all requests over them — mirrors
    /// `h2load -c`, eliminating the handshake churn that otherwise caps
    /// throughput far below the gateway's capacity.
    #[serde(default)]
    pub stable_connections: usize,
    /// Use the closed-loop driver (h2load model) for maximum single-host
    /// throughput: fixed concurrency lanes that fire-next-on-completion with
    /// no per-request scheduling/allocation, instead of the rate-paced
    /// scheduler. Best paired with `stable_connections`. Default `false`.
    #[serde(default)]
    pub closed_loop: bool,
    /// Fraction of the shard's channels that must provision successfully for the
    /// run to proceed. `1.0` (default) aborts on the first failed open. Lower it
    /// for large fixtures where a few transient devnet RPC drops are expected
    /// when opening tens of thousands of channels — failed users are skipped and
    /// the measured run uses whatever channels came up. Must be in (0, 1].
    #[serde(default = "default_provision_min_success_fraction")]
    pub provision_min_success_fraction: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Endpoint {
    pub url: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default = "default_body")]
    pub body: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionCfg {
    /// On-chain deposit locked per channel.
    pub deposit_usdc: f64,
    /// Per-voucher increment.
    pub voucher_usdc: f64,
    /// Open **real** payment channels and batch-settle them on-chain at close
    /// (real txids in the trace). Requires a datasource that carries the
    /// payment-channels program (e.g. `rpc_url: https://402.surfnet.dev:8899`,
    /// JIT-fetched into the fork). Default `false` keeps the SOL-transfer
    /// stand-in (settlement is a no-op).
    #[serde(default)]
    pub settle_onchain: bool,
    /// Request an immediate channel close after the measured window. Disable
    /// this when validating the server's periodic settlement lifecycle.
    #[serde(default = "default_true")]
    pub close_after_run: bool,
    /// Reuse existing on-chain channels instead of opening new ones. Before
    /// provisioning, the engine discovers each fixture wallet's open channel and
    /// the scheme drives it by address (resuming from its on-chain settled
    /// watermark), skipping the open. Wallets with no existing channel fall back
    /// to opening one (bootstrap). Avoids re-paying channel rent every run. MPP
    /// requires `session.load_from_chain: true`; x402 batch settlement rebuilds
    /// a missing gateway record from the confirmed channel on first use.
    #[serde(default)]
    pub reuse: bool,
    /// Pure off-chain benchmark mode (no surfpool/fork): deterministic,
    /// confirmed channel state is seeded in the `pay-bench` process and normal
    /// client vouchers are verified through the regular gateway path.
    #[serde(default)]
    pub offline: bool,
    /// Stable deterministic seed namespace shared by an offline fixture and
    /// its distributed load-generator shards. Defaults to `run.name`.
    #[serde(default)]
    pub offline_namespace: Option<String>,
    /// Number of deterministic, confirmed channels to seed in the dedicated
    /// benchmark harness. This is only valid with `offline: true`; it never
    /// exposes a production state-injection endpoint.
    #[serde(default)]
    pub offline_seeded_channels: usize,
    /// Pre-sign this many vouchers per channel before the measured window.
    /// Offline capacity-isolation runs use this to keep client signing from
    /// consuming the same host CPU as the proxy under test. Zero keeps the
    /// production-shaped on-demand signing path.
    ///
    /// When `background_signers > 0` this is reinterpreted as the per-channel
    /// voucher-queue depth (head-start capacity), NOT a fixed window — the
    /// signer pool keeps refilling it, so it need not cover the whole run.
    #[serde(default)]
    pub pre_sign_requests_per_user: usize,
    /// Number of dedicated OS threads that continuously sign vouchers into
    /// per-channel queues while the load lanes only pop-and-send. Zero keeps
    /// the in-lane signing path. When set, signing runs off the hot path
    /// *for the whole run* (unlike `pre_sign_requests_per_user` alone, which is
    /// a fixed pre-signed window), so one host can sustain its gateway-bound
    /// paid ceiling indefinitely with bounded memory. Users are partitioned
    /// across these threads (one producer per channel → monotonic vouchers).
    #[serde(default)]
    pub background_signers: usize,
}

fn default_true() -> bool {
    true
}
fn default_provision_min_success_fraction() -> f64 {
    1.0
}
fn default_prepare_secs() -> u64 {
    30
}
fn default_unleash_secs() -> u64 {
    60
}
fn default_max_concurrency() -> usize {
    2048
}
fn default_provision_concurrency() -> usize {
    16
}
fn default_settlement_concurrency() -> usize {
    16
}
fn default_worker_count() -> usize {
    32
}
fn default_shard_count() -> usize {
    1
}
fn default_method() -> String {
    "POST".into()
}
fn default_body() -> String {
    "{}".into()
}
fn default_weight() -> u32 {
    1
}

impl RunConfig {
    pub fn offline_namespace(&self) -> &str {
        self.session
            .as_ref()
            .and_then(|session| session.offline_namespace.as_deref())
            .unwrap_or(&self.run.name)
    }

    pub fn from_yaml_path(path: &str) -> Result<Self> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
        let cfg: RunConfig =
            serde_yml::from_str(&raw).with_context(|| format!("parsing config {path}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load the optional benchmark CA once, before any HTTP clients are built.
    pub fn tls_ca_certificate(&self) -> Result<Option<reqwest::Certificate>> {
        let path = if let Some(path) = self.run.tls_ca_cert.as_deref() {
            Some(path.to_string())
        } else if let Some(var) = self.run.tls_ca_cert_env.as_deref() {
            Some(
                std::env::var(var)
                    .with_context(|| format!("tls_ca_cert_env `{var}` is not set"))?,
            )
        } else {
            None
        };
        let Some(path) = path else {
            return Ok(None);
        };
        if path.trim().is_empty() {
            bail!("run.tls_ca_cert must not be empty");
        }
        let pem = std::fs::read(&path)
            .with_context(|| format!("reading benchmark TLS CA certificate {path}"))?;
        let certificate = reqwest::Certificate::from_pem(&pem)
            .with_context(|| format!("parsing benchmark TLS CA certificate {path}"))?;
        Ok(Some(certificate))
    }

    /// Raw PEM bytes of the optional benchmark CA, for the churn-free
    /// [`crate::h2pool::StableH2Pool`] (which needs the PEM, not reqwest's
    /// opaque `Certificate`). Same resolution as [`Self::tls_ca_certificate`].
    pub fn tls_ca_pem(&self) -> Result<Option<Vec<u8>>> {
        let path = if let Some(path) = self.run.tls_ca_cert.as_deref() {
            Some(path.to_string())
        } else if let Some(var) = self.run.tls_ca_cert_env.as_deref() {
            Some(
                std::env::var(var)
                    .with_context(|| format!("tls_ca_cert_env `{var}` is not set"))?,
            )
        } else {
            None
        };
        let Some(path) = path else {
            return Ok(None);
        };
        if path.trim().is_empty() {
            return Ok(None);
        }
        let pem = std::fs::read(&path)
            .with_context(|| format!("reading benchmark TLS CA certificate {path}"))?;
        Ok(Some(pem))
    }

    pub fn validate(&self) -> Result<()> {
        if self.load.users == 0 {
            bail!("load.users must be > 0");
        }
        if self.load.requests_per_sec_per_user <= 0.0 {
            bail!("load.requests_per_sec_per_user must be > 0");
        }
        if self.load.workers == 0 {
            bail!("load.workers must be > 0");
        }
        if self.load.provision_concurrency == 0 {
            bail!("load.provision_concurrency must be > 0");
        }
        if self.load.settlement_concurrency == 0 {
            bail!("load.settlement_concurrency must be > 0");
        }
        if !(self.load.provision_min_success_fraction.is_finite()
            && self.load.provision_min_success_fraction > 0.0
            && self.load.provision_min_success_fraction <= 1.0)
        {
            bail!("load.provision_min_success_fraction must be finite and in (0, 1]");
        }
        if self.load.proxy_workers == Some(0) {
            bail!("load.proxy_workers must be > 0 when set");
        }
        if self.load.shard_count == 0 || self.load.shard_index >= self.load.shard_count {
            bail!("load.shard_index must be less than non-zero load.shard_count");
        }
        if self.endpoints.is_empty() {
            bail!("at least one endpoint is required");
        }
        self.tls_ca_certificate()?;
        for (label, cap) in [
            ("max_total_usdc", self.run.safety.max_total_usdc),
            ("max_total_sol", self.run.safety.max_total_sol),
        ] {
            // Reject `.nan`/`.inf`: a non-finite cap silently disables the
            // `total > cap` guard in `enforce_caps` (all IEEE-754 comparisons
            // with NaN are false), letting a real-money run exceed its budget.
            if !(cap.is_finite() && cap >= 0.0) {
                bail!("safety.{label} must be a finite number >= 0");
            }
        }
        if matches!(
            self.run.scheme,
            Scheme::MppSession | Scheme::X402BatchSettlement
        ) && self.session.is_none()
        {
            bail!("scheme requires a `session:` block");
        }
        if let Some(session) = &self.session
            && session.offline
            && session.offline_seeded_channels < self.load.users
        {
            bail!("session.offline_seeded_channels must cover every load user in offline mode");
        }
        if let Some(session) = &self.session
            && session
                .offline_namespace
                .as_deref()
                .is_some_and(str::is_empty)
        {
            bail!("session.offline_namespace must not be empty");
        }
        if self
            .session
            .as_ref()
            .is_some_and(|session| !session.offline && session.offline_namespace.is_some())
        {
            bail!("session.offline_namespace requires session.offline: true");
        }
        if self
            .session
            .as_ref()
            .is_some_and(|session| !session.offline && session.offline_seeded_channels != 0)
        {
            bail!("session.offline_seeded_channels requires session.offline: true");
        }
        if let Some(session) = &self.session
            && session.pre_sign_requests_per_user > 0
            // In background-signer mode `pre_sign_requests_per_user` is only the
            // queue depth (a head start); the pool refills it for the whole run,
            // so it need not cover the full request window.
            && session.background_signers == 0
        {
            // Pre-signing works against a real (online) gateway too: provision
            // opens the real channel and retains the SessionHandle, and the
            // pre-sign path calls the SAME `voucher_header_sync` the live path
            // uses — the vouchers are identical monotonic-cumulative headers,
            // just generated before the measured window instead of inside it.
            // This is the lever that takes ed25519 signing out of the hot path
            // so one generator can drive far more than its live-signing rate.
            let required = (self.load.requests_per_sec_per_user * self.load.unleash_secs as f64)
                .ceil() as usize;
            if session.pre_sign_requests_per_user < required {
                bail!(
                    "session.pre_sign_requests_per_user must be at least {required} for the configured load window"
                );
            }
        }
        Ok(())
    }

    /// Resolve the RPC URL from explicit value or env var. For `fork`, the
    /// caller overrides this with the surfpool URL, so a missing value is OK.
    pub fn resolve_rpc_url(&self) -> Result<Option<String>> {
        if let Some(url) = &self.run.rpc_url {
            return Ok(Some(url.clone()));
        }
        if let Some(var) = &self.run.rpc_url_env {
            let v =
                std::env::var(var).with_context(|| format!("rpc_url_env `{var}` is not set"))?;
            return Ok(Some(v));
        }
        if self.run.network == Network::Fork {
            return Ok(None);
        }
        bail!(
            "network `{:?}` needs rpc_url or rpc_url_env",
            self.run.network
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selftest_config() -> RunConfig {
        serde_yml::from_str(include_str!("../configs/selftest-10k.yml")).unwrap()
    }

    #[test]
    fn selftest_config_validates() {
        selftest_config().validate().unwrap();
    }

    #[test]
    fn million_rps_devnet_plans_parse_and_fit_their_deposits() {
        for raw in [
            include_str!("../configs/session-devnet-100k-1m-rehearsal.yml"),
            include_str!("../configs/session-devnet-100k-1m-20m.yml"),
        ] {
            let config: RunConfig = serde_yml::from_str(raw).unwrap();
            assert_eq!(config.load.users, 100_000);
            assert_eq!(config.load.requests_per_sec_per_user, 10.0);
            assert_eq!(config.session.as_ref().unwrap().deposit_usdc, 0.02);
            assert_eq!(config.run.safety.max_total_sol, 0.0);

            let required_per_channel = config.load.requests_per_sec_per_user
                * config.load.unleash_secs as f64
                * config.session.as_ref().unwrap().voucher_usdc;
            assert!(required_per_channel <= config.session.as_ref().unwrap().deposit_usdc);
        }
    }

    #[test]
    fn lifecycle_gateway_uses_five_minute_settlement_without_idle_close() {
        let api: pay_types::metering::ApiSpec =
            serde_yml::from_str(include_str!("../configs/devnet-pingora-lifecycle.yml")).unwrap();
        let session = api.session.unwrap();
        assert_eq!(session.cap_usdc, 0.02);
        assert_eq!(session.close_delay_ms, 0);
        assert_eq!(session.settlement_interval_ms, 300_000);
    }

    #[test]
    fn non_finite_safety_caps_are_rejected() {
        for cap in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut cfg = selftest_config();
            cfg.run.safety.max_total_usdc = cap;
            assert!(
                cfg.validate().is_err(),
                "max_total_usdc={cap} must be rejected"
            );

            let mut cfg = selftest_config();
            cfg.run.safety.max_total_sol = cap;
            assert!(
                cfg.validate().is_err(),
                "max_total_sol={cap} must be rejected"
            );
        }
    }

    #[test]
    fn zero_provision_concurrency_is_rejected() {
        let mut cfg = selftest_config();
        cfg.load.provision_concurrency = 0;
        let error = cfg.validate().unwrap_err();
        assert!(error.to_string().contains("provision_concurrency"));
    }

    #[test]
    fn zero_settlement_concurrency_is_rejected() {
        let mut cfg = selftest_config();
        cfg.load.settlement_concurrency = 0;
        let error = cfg.validate().unwrap_err();
        assert!(error.to_string().contains("settlement_concurrency"));
    }

    #[test]
    fn invalid_provision_success_fraction_is_rejected() {
        for fraction in [f64::NEG_INFINITY, -0.1, 0.0, 1.1, f64::INFINITY, f64::NAN] {
            let mut cfg = selftest_config();
            cfg.load.provision_min_success_fraction = fraction;
            let error = cfg.validate().unwrap_err();
            assert!(
                error.to_string().contains("provision_min_success_fraction"),
                "fraction={fraction} must be rejected"
            );
        }
    }
}
