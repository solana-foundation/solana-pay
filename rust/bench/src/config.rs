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
    /// Fixed generator workers. Channels are deterministically assigned by
    /// user index, avoiding one Tokio task and interval per logical session.
    #[serde(default = "default_worker_count")]
    pub workers: usize,
    /// Deterministic generator-fleet shard index, zero based.
    #[serde(default)]
    pub shard_index: usize,
    /// Total generator-fleet shards. Each channel is assigned to exactly one.
    #[serde(default = "default_shard_count")]
    pub shard_count: usize,
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
    /// Pure off-chain benchmark mode (no surfpool/fork): deterministic,
    /// confirmed channel state is seeded in the `pay-bench` process and normal
    /// client vouchers are verified through the regular gateway path.
    #[serde(default)]
    pub offline: bool,
    /// Number of deterministic, confirmed channels to seed in the dedicated
    /// benchmark harness. This is only valid with `offline: true`; it never
    /// exposes a production state-injection endpoint.
    #[serde(default)]
    pub offline_seeded_channels: usize,
}

fn default_true() -> bool {
    true
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
    pub fn from_yaml_path(path: &str) -> Result<Self> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
        let cfg: RunConfig =
            serde_yml::from_str(&raw).with_context(|| format!("parsing config {path}"))?;
        cfg.validate()?;
        Ok(cfg)
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
        if self.load.shard_count == 0 || self.load.shard_index >= self.load.shard_count {
            bail!("load.shard_index must be less than non-zero load.shard_count");
        }
        if self.endpoints.is_empty() {
            bail!("at least one endpoint is required");
        }
        if self.run.safety.max_total_usdc < 0.0 || self.run.safety.max_total_sol < 0.0 {
            bail!("safety caps must be >= 0");
        }
        if self.run.scheme == Scheme::MppSession && self.session.is_none() {
            bail!("scheme `mpp_session` requires a `session:` block");
        }
        if let Some(session) = &self.session
            && session.offline
            && session.offline_seeded_channels < self.load.users
        {
            bail!("session.offline_seeded_channels must cover every load user in offline mode");
        }
        if self
            .session
            .as_ref()
            .is_some_and(|session| !session.offline && session.offline_seeded_channels != 0)
        {
            bail!("session.offline_seeded_channels requires session.offline: true");
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
