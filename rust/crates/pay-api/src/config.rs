use std::collections::{HashMap, HashSet};

use figment::Figment;
use figment::providers::{Env, Format, Yaml};
use pay_api_core::StablecoinSpec;
use pay_api_types::Network;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Cloud Run injects `PORT`; default 8080 for local dev.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Per-RPC-call timeout (ms).
    #[serde(default = "default_timeout_ms")]
    pub rpc_timeout_ms: u64,

    /// Supported networks → RPC config. Driven entirely by config so adding a
    /// network is a YAML edit, not a code change.
    pub networks: HashMap<Network, NetworkConfig>,

    /// The stablecoin set the API reports balances for. Order is preserved in
    /// every response.
    pub stablecoins: Vec<StablecoinSpec>,

    /// MoonPay checkout configuration for `/v1/onramp/start`.
    #[serde(default)]
    pub moonpay: MoonpayConfig,

    /// MPP-backed `/v1/send` configuration.
    #[serde(default)]
    pub send: SendConfig,

    /// MPP-backed `/v1/subscriptions/*` configuration. Shares the same
    /// fee-payer wallet pattern as `send`, but lives in its own block so
    /// each endpoint can be enabled / disabled independently.
    #[serde(default)]
    pub subscriptions: SubscriptionsConfig,

    /// `/v1/redeem` activation-campaign configuration. Reuses
    /// `send.fee_payer.*` as the hot wallet that holds the USDC pool
    /// and signs payouts.
    #[serde(default)]
    pub redemption: RedemptionConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub rpc_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MoonpayConfig {
    #[serde(default)]
    pub publishable_api_key: Option<String>,

    #[serde(default = "default_moonpay_onramp_currency_code")]
    pub onramp_currency_code: String,

    #[serde(default = "default_moonpay_onramp_base_currency_amount")]
    pub onramp_base_currency_amount: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SendConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_send_realm")]
    pub realm: String,

    #[serde(default)]
    pub mpp_challenge_binding_secret: Option<String>,

    #[serde(default = "default_estimated_fee_lamports")]
    pub estimated_fee_lamports: u64,

    #[serde(default = "default_sol_price_asset")]
    pub sol_price_asset: String,

    #[serde(default)]
    pub fee_payer: FeePayerConfig,

    #[serde(default)]
    pub fee_refund_split: FeeRefundSplitConfig,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct FeePayerConfig {
    #[serde(default)]
    pub key_name: Option<String>,

    #[serde(default)]
    pub pubkey: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FeeRefundSplitConfig {
    #[serde(default = "default_fee_refund_split_label")]
    pub label: String,

    // Deserialized for config-schema completeness; not yet read anywhere.
    #[allow(dead_code)]
    #[serde(default = "default_fee_refund_split_memo")]
    pub memo: String,
}

impl Default for SendConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            realm: default_send_realm(),
            mpp_challenge_binding_secret: None,
            estimated_fee_lamports: default_estimated_fee_lamports(),
            sol_price_asset: default_sol_price_asset(),
            fee_payer: FeePayerConfig::default(),
            fee_refund_split: FeeRefundSplitConfig::default(),
        }
    }
}

/// `/v1/subscriptions/*` config. The cancel handler returns a charge-intent
/// 402 priced cost-based — `estimated_fee_lamports` defines the SOL cost
/// the gateway expects to pay for the cancel transaction (typically
/// 5_000 lamports per signature × 2 signatures = 10_000), then the
/// `sol_price_asset` oracle converts that to USDC at challenge time.
#[derive(Debug, Deserialize, Clone)]
pub struct SubscriptionsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_subscriptions_realm")]
    pub realm: String,

    /// HMAC secret for the charge challenge. Falls back to `send.mpp_challenge_binding_secret`
    /// when unset so a single deployment can share both, but the field is
    /// here for cases where you want a dedicated secret.
    #[serde(default)]
    pub mpp_challenge_binding_secret: Option<String>,

    #[serde(default = "default_cancel_estimated_fee_lamports")]
    pub estimated_fee_lamports: u64,

    /// SOL/USD price asset id (Helius DAS getAsset). Defaults to the
    /// wrapped-SOL mint, matching the send endpoint.
    #[serde(default = "default_sol_price_asset")]
    pub sol_price_asset: String,

    /// Operator wallet that signs as fee-payer on the cancel transaction
    /// AND receives the USDC charge for the service fee. The same wallet
    /// fills both roles in the cost-based model.
    #[serde(default)]
    pub fee_payer: FeePayerConfig,

    /// Maximum wall-clock seconds to wait for the cancel transaction's
    /// `confirmed` commitment after broadcast.
    #[serde(default = "default_confirm_timeout_seconds")]
    pub confirm_timeout_seconds: u64,
}

impl Default for SubscriptionsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            realm: default_subscriptions_realm(),
            mpp_challenge_binding_secret: None,
            estimated_fee_lamports: default_cancel_estimated_fee_lamports(),
            sol_price_asset: default_sol_price_asset(),
            fee_payer: FeePayerConfig::default(),
            confirm_timeout_seconds: default_confirm_timeout_seconds(),
        }
    }
}

fn default_subscriptions_realm() -> String {
    "pay-api subscriptions".to_string()
}

fn default_cancel_estimated_fee_lamports() -> u64 {
    // 5_000 lamports per ed25519 signature × 2 (subscriber + fee-payer).
    // Cancel needs no rent / ATA creation.
    10_000
}

fn default_confirm_timeout_seconds() -> u64 {
    30
}

/// `/v1/redeem` config. Hot wallet is shared with `/v1/send` —
/// `send.fee_payer.*` is the GCP-KMS key that signs the payout
/// transactions and holds the stablecoin pool.
///
/// The mint, token program, and decimals are not configured here:
/// they're resolved from the `currency` symbol via the same pay-kit
/// helpers (`pay_kit::mpp::protocol::solana::resolve_stablecoin_mint` +
/// `default_token_program_for_currency`) the `/v1/send` endpoint uses.
/// That keeps stablecoin metadata in one place and makes the YAML
/// surface tiny.
#[derive(Debug, Deserialize, Clone)]
pub struct RedemptionConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Stablecoin symbol — `USDC`, `USDT`, `USDG`, `PYUSD`, `CASH`.
    /// Defaults to USDC.
    #[serde(default = "default_redemption_currency")]
    pub currency: String,

    /// Per-claim payout for legacy flat code lists, in the mint's
    /// smallest unit. Versioned campaign documents carry their own
    /// per-campaign amount.
    #[serde(default = "default_redemption_amount")]
    pub amount: u64,

    /// Network slug used to (a) pick the right per-network mint and
    /// (b) resolve the RPC URL via `state.rpc_url_for(network)`.
    #[serde(default = "default_redemption_network")]
    pub network: Network,

    /// API credential for the configured transaction-history provider.
    /// Required while redemption is enabled.
    #[serde(default)]
    pub solana_rpc_api_key: String,

    /// Helius base URL — change for staging / on-prem.
    #[serde(default = "default_helius_base")]
    pub helius_base: String,

    /// Max history pages to walk on the Helius dedup scan.
    #[serde(default)]
    pub max_scan_pages: Option<usize>,

    /// Unix timestamp at which Redis became the authoritative redemption
    /// claim store. The history scan stops once it reaches this boundary:
    /// newer redemptions are already protected by Redis, while older ones
    /// still need the legacy memo lookup.
    #[serde(default)]
    pub legacy_scan_cutoff_unix_seconds: Option<i64>,

    /// Redis URL for durable, atomic redemption claims. Required while
    /// redemption is enabled so claims survive replicas and restarts.
    #[serde(default)]
    pub claim_store_url: String,

    /// Legacy flat redemption-code whitelist. Kept during the migration
    /// to versioned campaigns so an older Doppler value remains usable.
    #[serde(default)]
    pub codes: Vec<String>,

    /// Independently enabled campaigns with their own payout amount.
    /// Populated from a versioned JSON document in `REDEMPTION_CODES`.
    #[serde(default)]
    pub campaigns: Vec<RedemptionCampaignConfig>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct RedemptionCampaignConfig {
    pub id: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Per-claim payout in the mint's smallest unit.
    pub amount: u64,

    #[serde(default)]
    pub codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RedemptionCampaignDocument {
    version: u8,
    campaigns: Vec<RedemptionCampaignConfig>,
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedRedemptionSecret {
    LegacyCodes(Vec<String>),
    Campaigns(Vec<RedemptionCampaignConfig>),
}

impl Default for RedemptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            currency: default_redemption_currency(),
            amount: default_redemption_amount(),
            network: default_redemption_network(),
            solana_rpc_api_key: String::new(),
            helius_base: default_helius_base(),
            max_scan_pages: None,
            legacy_scan_cutoff_unix_seconds: None,
            claim_store_url: String::new(),
            codes: Vec::new(),
            campaigns: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_redemption_currency() -> String {
    "USDC".into()
}

fn default_redemption_amount() -> u64 {
    5_000_000
}

fn default_redemption_network() -> Network {
    Network::Mainnet
}

fn default_helius_base() -> String {
    "https://api.helius.xyz".into()
}

/// Parse the `REDEMPTION_CODES` env var. The preferred form is a
/// versioned campaign document:
///
/// `{"version":1,"campaigns":[{"id":"event","amount":5000000,"codes":["CODE1"]}]}`
///
/// JSON arrays and comma-separated lists remain supported as a
/// migration fallback and use `redemption.amount`.
fn parse_redemption_secret(raw: &str) -> Result<ParsedRedemptionSecret, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(ParsedRedemptionSecret::LegacyCodes(Vec::new()));
    }
    if trimmed.starts_with('{') {
        let document: RedemptionCampaignDocument =
            serde_json::from_str(trimmed).map_err(|e| format!("invalid campaign document: {e}"))?;
        if document.version != 1 {
            return Err(format!(
                "unsupported redemption campaign document version {}",
                document.version
            ));
        }
        return Ok(ParsedRedemptionSecret::Campaigns(document.campaigns));
    }
    if trimmed.starts_with('[') {
        let parsed = serde_json::from_str::<Vec<String>>(trimmed)
            .map_err(|e| format!("invalid redemption code array: {e}"))?;
        return Ok(ParsedRedemptionSecret::LegacyCodes(
            parsed
                .into_iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        ));
    }
    Ok(ParsedRedemptionSecret::LegacyCodes(
        trimmed
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    ))
}

pub(crate) fn validate_redemption_code(code: &str) -> Result<(), String> {
    const MIN_CODE_LEN: usize = 6;
    const MAX_CODE_LEN: usize = 32;

    if code.len() < MIN_CODE_LEN || code.len() > MAX_CODE_LEN {
        return Err(format!(
            "code length must be {MIN_CODE_LEN}..{MAX_CODE_LEN} chars, got {}",
            code.len()
        ));
    }
    if !code.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("code must be ASCII alphanumeric".into());
    }
    Ok(())
}

fn validate_campaign_id(id: &str) -> Result<(), String> {
    const MAX_CAMPAIGN_ID_LEN: usize = 64;

    if id.is_empty() || id.len() > MAX_CAMPAIGN_ID_LEN {
        return Err(format!(
            "campaign id length must be 1..={MAX_CAMPAIGN_ID_LEN} chars, got {}",
            id.len()
        ));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err("campaign id must be ASCII alphanumeric, '-' or '_'".into());
    }
    Ok(())
}

fn validate_redemption_config(redemption: &RedemptionConfig) -> Result<(), String> {
    if redemption.network != Network::Mainnet {
        return Err(
            "redemption.network must be mainnet because the Helius history scan is mainnet-only"
                .into(),
        );
    }
    if redemption.solana_rpc_api_key.trim().is_empty() {
        return Err(
            "redemption.solana_rpc_api_key is required when redemption.enabled is true".to_string(),
        );
    }
    if redemption.claim_store_url.trim().is_empty() {
        return Err(
            "redemption.claim_store_url is required when redemption.enabled is true".into(),
        );
    }
    if redemption.max_scan_pages == Some(0) {
        return Err("redemption.max_scan_pages must be greater than zero".into());
    }
    if redemption
        .legacy_scan_cutoff_unix_seconds
        .unwrap_or_default()
        <= 0
    {
        return Err(
            "redemption.legacy_scan_cutoff_unix_seconds must be set to the Redis claim-store rollout time when redemption.enabled is true".into(),
        );
    }
    if redemption.codes.is_empty()
        && !redemption
            .campaigns
            .iter()
            .any(|campaign| campaign.enabled && !campaign.codes.is_empty())
    {
        return Err(
            "no active redemption codes (set REDEMPTION_CODES to a versioned campaign document \
             or legacy code list) when redemption.enabled is true"
                .into(),
        );
    }
    if !redemption.codes.is_empty() && redemption.amount == 0 {
        return Err("redemption.amount must be greater than zero for legacy codes".into());
    }

    let mut campaign_ids = HashSet::new();
    let mut redemption_codes = HashSet::new();
    for code in &redemption.codes {
        validate_redemption_code(code)
            .map_err(|message| format!("invalid legacy redemption code: {message}"))?;
        if !redemption_codes.insert(code) {
            return Err("duplicate redemption code in legacy code list".into());
        }
    }
    for campaign in &redemption.campaigns {
        validate_campaign_id(&campaign.id).map_err(|message| {
            format!("invalid redemption campaign `{}`: {message}", campaign.id)
        })?;
        if !campaign_ids.insert(campaign.id.as_str()) {
            return Err(format!(
                "duplicate redemption campaign id `{}`",
                campaign.id
            ));
        }
        if campaign.amount == 0 {
            return Err(format!(
                "redemption campaign `{}` amount must be greater than zero",
                campaign.id
            ));
        }
        if campaign.enabled && campaign.codes.is_empty() {
            return Err(format!(
                "enabled redemption campaign `{}` has no codes",
                campaign.id
            ));
        }
        for code in &campaign.codes {
            validate_redemption_code(code).map_err(|message| {
                format!(
                    "invalid code in redemption campaign `{}`: {message}",
                    campaign.id
                )
            })?;
            if !redemption_codes.insert(code) {
                return Err(format!(
                    "duplicate redemption code across campaigns (campaign `{}`)",
                    campaign.id
                ));
            }
        }
    }
    Ok(())
}

/// Pull `api-key=` out of a Helius-style RPC URL.
fn extract_solana_rpc_api_key(rpc_url: &str) -> Option<String> {
    let parsed = Url::parse(rpc_url).ok()?;
    parsed
        .query_pairs()
        .find(|(k, _)| k == "api-key")
        .map(|(_, v)| v.into_owned())
}

impl Default for FeeRefundSplitConfig {
    fn default() -> Self {
        Self {
            label: default_fee_refund_split_label(),
            memo: default_fee_refund_split_memo(),
        }
    }
}

impl Default for MoonpayConfig {
    fn default() -> Self {
        Self {
            publishable_api_key: None,
            onramp_currency_code: default_moonpay_onramp_currency_code(),
            onramp_base_currency_amount: default_moonpay_onramp_base_currency_amount(),
        }
    }
}

fn default_port() -> u16 {
    8080
}
fn default_timeout_ms() -> u64 {
    3_000
}
fn default_moonpay_onramp_currency_code() -> String {
    "usdc_sol".to_string()
}
fn default_moonpay_onramp_base_currency_amount() -> String {
    "20".to_string()
}
fn default_send_realm() -> String {
    "pay-api send".to_string()
}
fn default_estimated_fee_lamports() -> u64 {
    10_000
}
fn default_sol_price_asset() -> String {
    "So11111111111111111111111111111111111111112".to_string()
}
fn default_fee_refund_split_label() -> String {
    "Fee payer refund".to_string()
}
fn default_fee_refund_split_memo() -> String {
    "fee-payer-refund".to_string()
}

impl Config {
    /// Load order: `config/default.yaml` → `PAY_API_*` env (with `__` for
    /// nesting). Cloud Run's `PORT` is also honoured.
    pub fn load() -> Result<Self, ConfigError> {
        let figment = Figment::new()
            .merge(Yaml::file("config/default.yaml"))
            .merge(Env::prefixed("PAY_API_").split("__"))
            .merge(
                Env::raw()
                    .only(&["PORT"])
                    .map(|k| k.as_str().to_lowercase().into()),
            );

        let mut cfg: Self = figment.extract()?;
        cfg.apply_moonpay_env();
        cfg.apply_send_env();
        cfg.apply_rpc_url_env();
        cfg.apply_redemption_env()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Honor a top-level `RPC_URL` env var as the mainnet RPC. Matches the
    /// convention used elsewhere in the agent-gateway project (e.g. doppler
    /// `gateway-402/prd` sets `RPC_URL` to a Helius endpoint) so the receipt
    /// endpoint can use DAS for SOL/USD pricing without each consumer having
    /// to set the verbose `PAY_API_NETWORKS__MAINNET__RPC_URL` form.
    fn apply_rpc_url_env(&mut self) {
        if let Ok(url) = std::env::var("RPC_URL") {
            let url = url.trim();
            if !url.is_empty() {
                self.networks
                    .entry(Network::Mainnet)
                    .and_modify(|n| n.rpc_url = url.to_string())
                    .or_insert_with(|| NetworkConfig {
                        rpc_url: url.to_string(),
                    });
            }
        }
    }

    fn apply_moonpay_env(&mut self) {
        if let Ok(api_key) = std::env::var("MOONPAY_PUBLISHABLE_API_KEY") {
            let api_key = api_key.trim();
            self.moonpay.publishable_api_key = (!api_key.is_empty()).then(|| api_key.to_string());
        }
        if let Ok(currency_code) = std::env::var("MOONPAY_ONRAMP_CURRENCY_CODE") {
            let currency_code = currency_code.trim();
            if !currency_code.is_empty() {
                self.moonpay.onramp_currency_code = currency_code.to_string();
            }
        }
        if let Ok(base_currency_amount) = std::env::var("MOONPAY_ONRAMP_BASE_CURRENCY_AMOUNT") {
            let base_currency_amount = base_currency_amount.trim();
            if !base_currency_amount.is_empty() {
                self.moonpay.onramp_base_currency_amount = base_currency_amount.to_string();
            }
        }
    }

    /// Resolve `redemption.solana_rpc_api_key` from the environment.
    ///
    /// Sources, first match wins:
    ///   1. `SOLANA_RPC_API_KEY` (explicit provider credential).
    ///   2. The `api-key=` query param of the mainnet RPC URL —
    ///      `RPC_URL` is already a Helius endpoint in prod (doppler
    ///      `gateway-402/prd`), so the dedup endpoint can piggyback on
    ///      the same secret without a separate doppler entry.
    fn apply_redemption_env(&mut self) -> Result<(), ConfigError> {
        if self.redemption.solana_rpc_api_key.is_empty()
            && let Ok(key) = std::env::var("SOLANA_RPC_API_KEY")
        {
            let key = key.trim();
            if !key.is_empty() {
                self.redemption.solana_rpc_api_key = key.to_string();
            }
        }
        if self.redemption.solana_rpc_api_key.is_empty()
            && let Some(rpc_url) = self
                .networks
                .get(&Network::Mainnet)
                .map(|n| n.rpc_url.as_str())
            && let Some(key) = extract_solana_rpc_api_key(rpc_url)
        {
            self.redemption.solana_rpc_api_key = key;
        }

        if self.redemption.claim_store_url.is_empty()
            && let Ok(url) = std::env::var("PAY_SESSION_REDIS_URL")
        {
            let url = url.trim();
            if !url.is_empty() {
                self.redemption.claim_store_url = url.to_string();
            }
        }

        // `REDEMPTION_CODES` is stored in Doppler so redemption
        // credentials are never committed or baked into the image.
        // Prefer the versioned campaign document; keep flat lists
        // readable while existing deployments migrate.
        if self.redemption.codes.is_empty()
            && self.redemption.campaigns.is_empty()
            && let Ok(raw) = std::env::var("REDEMPTION_CODES")
        {
            match parse_redemption_secret(&raw).map_err(ConfigError::Invalid)? {
                ParsedRedemptionSecret::LegacyCodes(codes) => {
                    self.redemption.codes = codes;
                }
                ParsedRedemptionSecret::Campaigns(campaigns) => {
                    self.redemption.campaigns = campaigns;
                }
            }
        }
        Ok(())
    }

    fn apply_send_env(&mut self) {
        // Canonical key is `MPP_CHALLENGE_BINDING_SECRET` (aligned with
        // pay-kit's MPP server config and pay's `pay server` operator
        // YAML). The two legacy keys are kept as aliases so existing
        // deployments don't break during the rollout — once every
        // environment is migrated the aliases can be dropped.
        for key in [
            "MPP_CHALLENGE_BINDING_SECRET",
            "PAY_MPP_CHALLENGE_SECRET",
            "MPP_SECRET_KEY",
        ] {
            if let Ok(secret) = std::env::var(key) {
                let secret = secret.trim();
                if !secret.is_empty() {
                    self.send.mpp_challenge_binding_secret = Some(secret.to_string());
                }
            }
        }
    }

    /// Resolve the effective HMAC secret for the subscriptions endpoint:
    /// dedicated `subscriptions.mpp_challenge_binding_secret` wins, then falls back to
    /// the `send` secret so a single deployment can share both.
    pub fn subscriptions_challenge_binding_secret(&self) -> Option<&str> {
        self.subscriptions
            .mpp_challenge_binding_secret
            .as_deref()
            .or(self.send.mpp_challenge_binding_secret.as_deref())
    }

    /// Effective fee-payer for the subscriptions endpoint. The pay-api
    /// only deploys one KMS-backed signer in practice, so a missing
    /// `subscriptions.fee_payer.*` falls back to `send.fee_payer.*`.
    /// "Missing" means an empty/whitespace string, since envy /
    /// figment cannot represent a "really unset" Option once nested
    /// env vars overlay defaults.
    pub fn effective_subscriptions_fee_payer(&self) -> FeePayerConfig {
        fn nonblank(value: &Option<String>) -> Option<&str> {
            value.as_deref().map(str::trim).filter(|s| !s.is_empty())
        }
        FeePayerConfig {
            key_name: nonblank(&self.subscriptions.fee_payer.key_name)
                .or_else(|| nonblank(&self.send.fee_payer.key_name))
                .map(str::to_string),
            pubkey: nonblank(&self.subscriptions.fee_payer.pubkey)
                .or_else(|| nonblank(&self.send.fee_payer.pubkey))
                .map(str::to_string),
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.networks.is_empty() {
            return Err(ConfigError::Invalid(
                "config.networks must contain at least one entry".into(),
            ));
        }
        for (net, nc) in &self.networks {
            if nc.rpc_url.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "networks.{}.rpc_url is empty",
                    net.as_str()
                )));
            }
        }
        if self.stablecoins.is_empty() {
            return Err(ConfigError::Invalid(
                "config.stablecoins must contain at least one entry".into(),
            ));
        }
        if self.moonpay.onramp_currency_code.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "moonpay.onramp_currency_code is empty".into(),
            ));
        }
        if self.moonpay.onramp_base_currency_amount.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "moonpay.onramp_base_currency_amount is empty".into(),
            ));
        }
        if self.send.enabled {
            if self
                .send
                .mpp_challenge_binding_secret
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(ConfigError::Invalid(
                    "send.mpp_challenge_binding_secret is required when send.enabled is true"
                        .into(),
                ));
            }
            if self
                .send
                .fee_payer
                .key_name
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(ConfigError::Invalid(
                    "send.fee_payer.key_name is required when send.enabled is true".into(),
                ));
            }
            if self
                .send
                .fee_payer
                .pubkey
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(ConfigError::Invalid(
                    "send.fee_payer.pubkey is required when send.enabled is true".into(),
                ));
            }
            if self.send.estimated_fee_lamports == 0 {
                return Err(ConfigError::Invalid(
                    "send.estimated_fee_lamports must be greater than zero".into(),
                ));
            }
            if self.send.sol_price_asset.trim().is_empty() {
                return Err(ConfigError::Invalid("send.sol_price_asset is empty".into()));
            }
        }
        if self.redemption.enabled {
            validate_redemption_config(&self.redemption).map_err(ConfigError::Invalid)?;
            // The redeem handler signs payouts with `send.fee_payer`, so
            // the same key_name + pubkey must be configured even when
            // `send.enabled` is false (redemption-only deployments).
            if self
                .send
                .fee_payer
                .key_name
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(ConfigError::Invalid(
                    "send.fee_payer.key_name is required when redemption.enabled is true".into(),
                ));
            }
            if self
                .send
                .fee_payer
                .pubkey
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(ConfigError::Invalid(
                    "send.fee_payer.pubkey is required when redemption.enabled is true".into(),
                ));
            }
        }
        if self.subscriptions.enabled {
            if self
                .subscriptions_challenge_binding_secret()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                return Err(ConfigError::Invalid(
                    "subscriptions.mpp_challenge_binding_secret (or send.mpp_challenge_binding_secret) is required when \
                     subscriptions.enabled is true"
                        .into(),
                ));
            }
            // The subscriptions fee-payer falls back to the send
            // fee-payer (same KMS-backed signer in every deployment),
            // so only require that the effective resolution yields a
            // non-empty key_name + pubkey.
            let effective = self.effective_subscriptions_fee_payer();
            if effective
                .key_name
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                return Err(ConfigError::Invalid(
                    "subscriptions.fee_payer.key_name (or send.fee_payer.key_name) is required \
                     when subscriptions.enabled is true"
                        .into(),
                ));
            }
            if effective.pubkey.as_deref().unwrap_or("").trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "subscriptions.fee_payer.pubkey (or send.fee_payer.pubkey) is required when \
                     subscriptions.enabled is true"
                        .into(),
                ));
            }
            if self.subscriptions.estimated_fee_lamports == 0 {
                return Err(ConfigError::Invalid(
                    "subscriptions.estimated_fee_lamports must be greater than zero".into(),
                ));
            }
            if self.subscriptions.sol_price_asset.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "subscriptions.sol_price_asset is empty".into(),
                ));
            }
            if self.subscriptions.confirm_timeout_seconds == 0 {
                return Err(ConfigError::Invalid(
                    "subscriptions.confirm_timeout_seconds must be greater than zero".into(),
                ));
            }
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

impl From<figment::Error> for ConfigError {
    fn from(e: figment::Error) -> Self {
        Self::Figment(Box::new(e))
    }
}

#[cfg(test)]
mod tests {
    use pay_api_types::Network;

    use super::{
        ParsedRedemptionSecret, RedemptionCampaignConfig, RedemptionConfig,
        parse_redemption_secret, validate_campaign_id, validate_redemption_code,
        validate_redemption_config,
    };

    #[test]
    fn parses_versioned_redemption_campaigns() {
        let parsed = parse_redemption_secret(
            r#"{
                "version": 1,
                "campaigns": [
                    {
                        "id": "anthropic-tokyo-Q2-2026",
                        "amount": 5000000,
                        "codes": ["TOKYO123"]
                    },
                    {
                        "id": "superteam-uk-Q3-2026",
                        "enabled": true,
                        "amount": 50000000,
                        "codes": ["SUPER123"]
                    }
                ]
            }"#,
        )
        .expect("campaign document should parse");

        let ParsedRedemptionSecret::Campaigns(campaigns) = parsed else {
            panic!("expected campaigns");
        };
        assert_eq!(campaigns.len(), 2);
        assert_eq!(campaigns[0].id, "anthropic-tokyo-Q2-2026");
        assert_eq!(campaigns[0].amount, 5_000_000);
        assert!(campaigns[0].enabled);
        assert_eq!(campaigns[1].id, "superteam-uk-Q3-2026");
        assert_eq!(campaigns[1].amount, 50_000_000);
    }

    #[test]
    fn keeps_legacy_redemption_code_formats_compatible() {
        assert_eq!(
            parse_redemption_secret(r#"[" CODE123 ", "CODE456"]"#).unwrap(),
            ParsedRedemptionSecret::LegacyCodes(vec!["CODE123".to_string(), "CODE456".to_string()])
        );
        assert_eq!(
            parse_redemption_secret("CODE123, CODE456").unwrap(),
            ParsedRedemptionSecret::LegacyCodes(vec!["CODE123".to_string(), "CODE456".to_string()])
        );
    }

    #[test]
    fn rejects_unknown_redemption_campaign_document_versions() {
        let error = parse_redemption_secret(r#"{"version":2,"campaigns":[]}"#)
            .expect_err("unknown version must fail");
        assert!(error.contains("unsupported redemption campaign document version 2"));
    }

    #[test]
    fn validates_campaign_ids_and_redemption_codes() {
        assert!(validate_campaign_id("superteam-uk-Q3-2026").is_ok());
        assert!(validate_campaign_id("spaces are invalid").is_err());
        assert!(validate_redemption_code("STUKQ3ABC123").is_ok());
        assert!(validate_redemption_code("contains-hyphen").is_err());
    }

    #[test]
    fn rejects_duplicate_codes_across_campaigns() {
        let redemption = RedemptionConfig {
            solana_rpc_api_key: "test-key".to_string(),
            claim_store_url: "redis://127.0.0.1/".to_string(),
            legacy_scan_cutoff_unix_seconds: Some(1),
            campaigns: vec![
                RedemptionCampaignConfig {
                    id: "anthropic-tokyo-Q2-2026".to_string(),
                    enabled: true,
                    amount: 5_000_000,
                    codes: vec!["DUPLICATE1".to_string()],
                },
                RedemptionCampaignConfig {
                    id: "superteam-uk-Q3-2026".to_string(),
                    enabled: true,
                    amount: 50_000_000,
                    codes: vec!["DUPLICATE1".to_string()],
                },
            ],
            ..RedemptionConfig::default()
        };

        let error = validate_redemption_config(&redemption)
            .expect_err("the same code cannot belong to two campaigns");
        assert!(error.contains("duplicate redemption code across campaigns"));
    }

    #[test]
    fn rejects_redemption_without_provider_credential() {
        let redemption = RedemptionConfig {
            codes: vec!["CODE123".to_string()],
            ..RedemptionConfig::default()
        };

        let error = validate_redemption_config(&redemption)
            .expect_err("enabled redemption requires durable deduplication");
        assert!(error.contains("redemption.solana_rpc_api_key is required"));
    }

    #[test]
    fn rejects_redemption_without_durable_claim_store() {
        let redemption = RedemptionConfig {
            solana_rpc_api_key: "test-key".to_string(),
            codes: vec!["CODE123".to_string()],
            ..RedemptionConfig::default()
        };

        let error = validate_redemption_config(&redemption)
            .expect_err("enabled redemption requires an atomic claim store");
        assert!(error.contains("redemption.claim_store_url is required"));
    }

    #[test]
    fn rejects_redemption_without_a_legacy_scan_cutoff() {
        let redemption = RedemptionConfig {
            solana_rpc_api_key: "test-key".to_string(),
            claim_store_url: "redis://127.0.0.1/".to_string(),
            codes: vec!["CODE123".to_string()],
            ..RedemptionConfig::default()
        };

        let error = validate_redemption_config(&redemption)
            .expect_err("redemption must bound its legacy history scan");
        assert!(error.contains("redemption.legacy_scan_cutoff_unix_seconds"));
    }

    #[test]
    fn rejects_redemption_on_non_mainnet_networks() {
        let redemption = RedemptionConfig {
            network: Network::Sandbox,
            solana_rpc_api_key: "test-key".to_string(),
            claim_store_url: "redis://127.0.0.1/".to_string(),
            codes: vec!["CODE123".to_string()],
            ..RedemptionConfig::default()
        };

        let error = validate_redemption_config(&redemption)
            .expect_err("Helius history cannot deduplicate sandbox redemptions");
        assert!(error.contains("redemption.network must be mainnet"));
    }
}
