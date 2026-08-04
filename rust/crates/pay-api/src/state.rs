use std::collections::HashMap;
use std::time::Duration;

use pay_api_core::ata::TOKEN_2022_PROGRAM_ID;
use pay_api_core::{Error, RpcClient, Stablecoin};
use pay_api_types::Network;

use pay_kit::mpp::server::{self, ConfidentialHandle, ConfidentialWorkerConfig};

use crate::config::{
    Config, FeePayerConfig, MoonpayConfig, NetworkConfig, SendConfig, SubscriptionsConfig,
};
use crate::endpoints::redeem::RedemptionState;

/// Application state — read-only after construction, so a plain `Arc<AppState>`
/// is enough; no `RwLock` is needed.
pub struct AppState {
    pub rpc: RpcClient,
    pub networks: HashMap<Network, NetworkConfig>,
    pub stablecoins: Vec<Stablecoin>,
    pub moonpay: MoonpayConfig,
    pub send: SendConfig,
    pub subscriptions: SubscriptionsConfig,
    /// Effective HMAC secret for the subscriptions handler — already
    /// resolved against the `send` fallback at boot.
    pub subscriptions_challenge_binding_secret: Option<String>,
    /// Effective fee-payer for `/v1/subscriptions/cancel`, resolved at
    /// boot from `subscriptions.fee_payer` and falling back to
    /// `send.fee_payer` so a single deployment shares one KMS-backed
    /// signer across both endpoints.
    pub subscriptions_fee_payer: FeePayerConfig,
    /// Resolved `/v1/redeem` settings. `None` when `redemption.enabled`
    /// is false; the handler returns 503 in that case.
    pub redemption: Option<RedemptionState>,
    /// Handles to confidential-settlement worker run-loops, keyed by the
    /// request network they settle against. Empty when confidential settlement
    /// can't be configured (send disabled, no fee-payer signer, no network, or
    /// no Token-2022 coin).
    pub confidential: HashMap<Network, ConfidentialHandle>,
}

impl AppState {
    pub async fn new(config: &Config) -> Result<Self, Error> {
        // Resolve every spec at boot so per-request work is just lookups.
        let stablecoins = config
            .stablecoins
            .iter()
            .map(|s| s.resolve())
            .collect::<Result<Vec<_>, _>>()?;

        let subscriptions_challenge_binding_secret = config
            .subscriptions_challenge_binding_secret()
            .map(str::to_string);
        let subscriptions_fee_payer = config.effective_subscriptions_fee_payer();

        let redemption = if config.redemption.enabled {
            Some(RedemptionState::from_config(&config.redemption)?)
        } else {
            None
        };

        let confidential = build_confidential_workers(config, &stablecoins).await;

        Ok(Self {
            rpc: RpcClient::new(Duration::from_millis(config.rpc_timeout_ms))?,
            networks: config.networks.clone(),
            stablecoins,
            moonpay: config.moonpay.clone(),
            send: config.send.clone(),
            subscriptions: config.subscriptions.clone(),
            subscriptions_challenge_binding_secret,
            subscriptions_fee_payer,
            redemption,
            confidential,
        })
    }

    pub fn rpc_url_for(&self, network: Network) -> Result<&str, Error> {
        self.networks
            .get(&network)
            .map(|n| n.rpc_url.as_str())
            .ok_or_else(|| Error::NetworkNotConfigured(network.as_str().into()))
    }
}

/// Spin up confidential-settlement workers at boot, one per configured network.
/// Returns an empty map (logged) when any prerequisite is missing —
/// confidential settlement is then unavailable, but the rest of the API runs
/// normally.
async fn build_confidential_workers(
    config: &Config,
    stablecoins: &[Stablecoin],
) -> HashMap<Network, ConfidentialHandle> {
    if !config.send.enabled {
        return HashMap::new();
    }
    // The sweep Mpp needs any Token-2022 coin (the sweep is currency-agnostic).
    let Some(coin) = stablecoins
        .iter()
        .find(|c| c.token_program == TOKEN_2022_PROGRAM_ID)
    else {
        tracing::info!("confidential worker disabled: no Token-2022 stablecoin configured");
        return HashMap::new();
    };
    if config.networks.is_empty() {
        tracing::info!("confidential worker disabled: no network configured");
        return HashMap::new();
    }
    let signer = match crate::signer::build_fee_payer_signer(
        &config.send.fee_payer,
        "send.fee_payer.key_name is missing",
        "send.fee_payer.pubkey is missing",
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "confidential worker disabled: no fee-payer signer");
            return HashMap::new();
        }
    };
    let Some(fee_payer_pubkey) = config.send.fee_payer.pubkey.clone() else {
        tracing::warn!("confidential worker disabled: no fee-payer pubkey");
        return HashMap::new();
    };

    spawn_confidential_workers(config, coin, signer, fee_payer_pubkey)
}

fn spawn_confidential_workers(
    config: &Config,
    coin: &Stablecoin,
    signer: std::sync::Arc<dyn pay_kit::mpp::solana_keychain::SolanaSigner>,
    fee_payer_pubkey: String,
) -> HashMap<Network, ConfidentialHandle> {
    let mut handles = HashMap::with_capacity(config.networks.len());
    for (network, net_cfg) in &config.networks {
        // pay-kit's `Mpp::new` validates the canonical MPP wire slug
        // (mainnet/devnet/localnet), so each settlement worker must use the same
        // mapping the /v1/send issue path uses, not Solana's RPC hostname slug.
        let cluster = match network {
            Network::Mainnet => "mainnet",
            Network::Sandbox => "localnet",
        };

        let handle = server::spawn_confidential_worker(
            ConfidentialWorkerConfig {
                network: cluster.to_string(),
                rpc_url: net_cfg.rpc_url.clone(),
                challenge_binding_secret: config.send.mpp_challenge_binding_secret.clone(),
                realm: config.send.realm.clone(),
                sweep_currency: coin.mint.to_string(),
                sweep_decimals: coin.decimals,
                fee_payer_pubkey: fee_payer_pubkey.clone(),
                // /v1/send relays to an arbitrary user-chosen recipient (the gateway
                // is NOT the payee), so it cannot decrypt the recipient balance —
                // facilitator/trust-proofs settlement. The client's range/validity
                // proofs are verified on-chain; the recipient reconciles the amount.
                recipient_signer: None,
            },
            signer.clone(),
        );
        handles.insert(*network, handle);
    }
    handles
}

#[cfg(test)]
mod tests {
    use super::*;
    use pay_kit::mpp::solana_keychain::{Signer, SolanaSigner};

    /// A minimal config with send disabled (its default).
    fn minimal_config(send_enabled: bool) -> Config {
        serde_json::from_value(serde_json::json!({
            "networks": {},
            "stablecoins": [],
            "send": { "enabled": send_enabled },
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn confidential_worker_disabled_when_send_disabled() {
        assert!(
            build_confidential_workers(&minimal_config(false), &[])
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn confidential_worker_disabled_without_token_2022_coin() {
        // Send enabled but no fee-payer signer / Token-2022 coin ⇒ no worker.
        assert!(
            build_confidential_workers(&minimal_config(true), &[])
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn confidential_workers_are_created_per_configured_network() {
        let keypair = solana_keypair::Keypair::new();
        let keypair_bytes = serde_json::to_string(&keypair.to_bytes().to_vec()).unwrap();
        let signer = std::sync::Arc::new(Signer::from_memory(&keypair_bytes).unwrap());
        let coin = Stablecoin {
            symbol: "USDC22".into(),
            mint: solana_pubkey::Pubkey::new_unique(),
            token_program: TOKEN_2022_PROGRAM_ID,
            decimals: 6,
        };
        let config: Config = serde_json::from_value(serde_json::json!({
            "networks": {
                "mainnet": {"rpc_url": "http://mainnet.invalid"},
                "sandbox": {"rpc_url": "http://sandbox.invalid"}
            },
            "stablecoins": [],
            "send": {"enabled": true}
        }))
        .unwrap();

        let handles =
            spawn_confidential_workers(&config, &coin, signer.clone(), signer.pubkey().to_string());

        assert_eq!(handles.len(), 2);
        assert!(handles.contains_key(&Network::Mainnet));
        assert!(handles.contains_key(&Network::Sandbox));
    }
}
