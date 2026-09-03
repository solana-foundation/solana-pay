//! Configuration for the `close-channels` job.
//!
//! Mirrors pay-api's figment layering (`config/default.yaml` → prefixed env),
//! but with the `JOBS_` prefix and the shared `PAY_API_SEND__FEE_PAYER__*`
//! fee-payer keys so a single Doppler config serves both.

use std::collections::HashMap;

use figment::Figment;
use figment::providers::{Env, Format, Yaml};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Supported networks → RPC config.
    pub networks: HashMap<String, NetworkConfig>,

    /// Base58 owner of the treasury ATA the payment-channels program credits
    /// protocol fees to. `distribute` checks the treasury ATA against
    /// `ATA(treasury_owner, mint, token_program)`.
    pub treasury_owner: String,

    /// Per-RPC-call timeout (ms).
    #[serde(default = "default_timeout_ms")]
    pub rpc_timeout_ms: u64,

    /// Max wall-clock seconds to wait for a broadcast tx's `confirmed`
    /// commitment.
    #[serde(default = "default_confirm_timeout_seconds")]
    pub confirm_timeout_seconds: u64,

    /// Fee-payer wallet — shares pay-api's `send` block shape so the same env
    /// keys (`PAY_API_SEND__FEE_PAYER__*`) configure both.
    #[serde(default)]
    pub send: SendConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub rpc_url: String,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct SendConfig {
    #[serde(default)]
    pub fee_payer: FeePayerConfig,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct FeePayerConfig {
    /// GCP KMS key resource name.
    #[serde(default)]
    pub key_name: Option<String>,
    /// Base58 pubkey of the KMS-backed signer.
    #[serde(default)]
    pub pubkey: Option<String>,
}

fn default_timeout_ms() -> u64 {
    15_000
}

fn default_confirm_timeout_seconds() -> u64 {
    60
}

impl Config {
    /// Load `config/default.yaml`, overlay `JOBS_*` and `PAY_API_*` env, then
    /// honor a top-level `RPC_URL` override for the chosen network.
    pub fn load(network: &str) -> Result<Self, ConfigError> {
        let figment = Figment::new()
            .merge(Yaml::file("config/default.yaml"))
            // pay-api's send.fee_payer.* keys, shared verbatim so one Doppler
            // secret set drives both services.
            .merge(Env::prefixed("PAY_API_").split("__"))
            // Job-specific overrides win last.
            .merge(Env::prefixed("JOBS_").split("__"));

        let mut cfg: Self = figment.extract().map_err(Box::new)?;
        cfg.apply_rpc_url_env(network);
        cfg.validate(network)?;
        Ok(cfg)
    }

    /// Honor a top-level `RPC_URL` env var as the RPC for the active network,
    /// matching the agent-gateway / pay-api convention (Doppler sets `RPC_URL`
    /// to a Helius endpoint).
    fn apply_rpc_url_env(&mut self, network: &str) {
        if let Ok(url) = std::env::var("RPC_URL") {
            let url = url.trim();
            if !url.is_empty() {
                self.networks
                    .entry(network.to_string())
                    .and_modify(|n| n.rpc_url = url.to_string())
                    .or_insert_with(|| NetworkConfig {
                        rpc_url: url.to_string(),
                    });
            }
        }
    }

    /// Resolve the RPC URL for the active network.
    pub fn rpc_url_for(&self, network: &str) -> Result<&str, ConfigError> {
        self.networks
            .get(network)
            .map(|n| n.rpc_url.as_str())
            .ok_or_else(|| ConfigError::Invalid(format!("network not configured: {network}")))
    }

    fn validate(&self, network: &str) -> Result<(), ConfigError> {
        if self.networks.is_empty() {
            return Err(ConfigError::Invalid(
                "config.networks must contain at least one entry".into(),
            ));
        }
        let rpc = self.rpc_url_for(network)?;
        if rpc.trim().is_empty() {
            return Err(ConfigError::Invalid(format!(
                "networks.{network}.rpc_url is empty"
            )));
        }
        if self.treasury_owner.trim().is_empty() {
            return Err(ConfigError::Invalid("treasury_owner is empty".into()));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config error: {0}")]
    Figment(#[from] Box<figment::Error>),

    #[error("invalid config: {0}")]
    Invalid(String),
}
