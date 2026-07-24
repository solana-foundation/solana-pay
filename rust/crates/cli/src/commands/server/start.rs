//! `pay server start` — start a payment gateway proxy.

use std::str::FromStr;
use std::sync::Arc;

use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use owo_colors::OwoColorize;
use pay_core::PaymentState;
use pay_core::accounts::AccountsStore;
use pay_core::server::session::SessionMpp;
use pay_core::server::telemetry::FeePayerWallet;
use pay_kit::mpp::server::Mpp;
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_types::Stablecoin;
use pay_types::metering::{ApiSpec, OperatorConfig, RoutingConfig, SignerConfig};
use tokio::time::{Duration, Instant};

use super::payments::{
    self, PayoutRecipientTarget, lamports_to_sol, resolve_currency,
    should_use_auto_fee_payer_signer, stable_token_account_requirements, surfpool_funding_targets,
};
use crate::components::{PAY_SH_TAGLINE, render_pay_banner, solana_explorer_cluster_query};
use crate::network::SolanaNetwork;

const BROWSER_RPC_PROXY_PATH: &str = "/__402/rpc";
const FEE_PAYER_BALANCE_OBSERVE_INTERVAL: Duration = Duration::from_secs(300);
const DEFAULT_SERVER_BIND: &str = "0.0.0.0:1402";
const BROWSER_RPC_ALLOWED_METHODS: &[&str] = &[
    "getLatestBlockhash",
    "surfnet_setAccount",
    "surfnet_setTokenAccount",
];

fn default_bind() -> String {
    match std::env::var("PORT") {
        Ok(port) => {
            let port = port.trim();
            if !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) {
                format!("0.0.0.0:{port}")
            } else {
                DEFAULT_SERVER_BIND.to_string()
            }
        }
        Err(_) => DEFAULT_SERVER_BIND.to_string(),
    }
}

async fn session_channel_store() -> pay_core::Result<Arc<dyn pay_kit::mpp::store::ChannelStore>> {
    let redis_url = std::env::var("PAY_SESSION_REDIS_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let Some(redis_url) = redis_url else {
        return Ok(Arc::new(pay_kit::mpp::store::MemoryChannelStore::new()));
    };

    #[cfg(feature = "redis-session-store")]
    {
        let prefix = std::env::var("PAY_SESSION_REDIS_PREFIX")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "pay:session:v1:".to_string());
        let store = pay_kit::mpp::store::RedisChannelStore::connect(&redis_url, prefix)
            .await
            .map_err(|error| {
                pay_core::Error::Config(format!("failed to connect session Redis store: {error}"))
            })?;
        tracing::info!("using durable Redis channel store for MPP sessions");
        return Ok(Arc::new(store));
    }

    #[cfg(not(feature = "redis-session-store"))]
    {
        let _ = redis_url;
        Err(pay_core::Error::Config(
            "PAY_SESSION_REDIS_URL is set, but this pay binary was built without the \
             redis-session-store feature"
                .to_string(),
        ))
    }
}

/// Start the payment gateway proxy.
///
/// Loads an API spec from a YAML file and starts an HTTP proxy that:
/// - Returns 402 with MPP challenge for metered endpoints
/// - Forwards to upstream on valid payment
/// - Passes through free endpoints directly
#[derive(clap::Args)]
pub struct StartCommand {
    /// Path to the provider YAML spec file.
    pub spec: String,

    /// Address to bind to. Defaults to 0.0.0.0:$PORT when PORT is set.
    #[arg(long, default_value_t = default_bind())]
    pub bind: String,

    /// Recipient wallet address for payments.
    #[arg(long)]
    pub recipient: Option<String>,

    /// Payment currency (SOL, USDC, etc.).
    #[arg(long, default_value = "USDC")]
    pub currency: String,

    /// RPC URL for payment verification.
    #[arg(long)]
    pub rpc_url: Option<String>,

    /// Launch the Payment Debugger UI alongside the gateway.
    /// Automatically enabled in sandbox mode (`pay --sandbox server start`).
    #[arg(long)]
    pub debugger: bool,

    /// Export traces and metrics to an OTLP HTTP sidecar at HOST:PORT.
    #[arg(long, value_name = "HOST:PORT")]
    pub otlp_sidecar: Option<String>,

    /// Path to an OpenAPI 3 or Google Discovery JSON document that
    /// describes the upstream API. When set, the server exposes the spec at
    /// `GET /openapi.json` with `rootUrl` (Discovery) and/or `servers[].url`
    /// (OpenAPI 3) rewritten to point at the proxy itself, so downstream
    /// agents can drive the proxy without knowing the upstream URL.
    #[arg(long, value_name = "PATH")]
    pub openapi: Option<String>,

    /// Override the public base URL used when rewriting `rootUrl` /
    /// `servers[].url` in the served `/openapi.json`. When omitted, the URL
    /// is derived from the request's `Host` header at serve time.
    #[arg(long, value_name = "URL")]
    pub public_url: Option<String>,

    /// Skip decentralized provider registration even when `--public-url` and
    /// a versioned API profile are present.
    #[arg(long)]
    pub no_register: bool,

    #[arg(skip)]
    pub scaffolded_spec: Option<String>,
}

#[derive(Clone)]
struct AppState {
    apis: Arc<Vec<ApiSpec>>,
    mpps: Vec<Mpp>,
    session_mpps: Vec<Arc<SessionMpp>>,
    browser_rpc_url: Option<String>,
    fee_payer_wallet: Option<FeePayerWallet>,
    fee_payer_signer: Option<Arc<dyn SolanaSigner>>,
    x402: Option<pay_kit::x402::server::X402>,
    x402_upto: Option<pay_kit::x402::server::X402Upto>,
    pdb: Option<pay_pdb::PdbState>,
}

impl PaymentState for AppState {
    fn apis(&self) -> &[ApiSpec] {
        &self.apis
    }
    fn mpp(&self) -> Option<&Mpp> {
        self.mpps.first()
    }
    fn mpps(&self) -> Vec<&Mpp> {
        self.mpps.iter().collect()
    }
    fn browser_rpc_url(&self) -> Option<&str> {
        self.browser_rpc_url.as_deref()
    }
    fn session_mpp(&self) -> Option<&SessionMpp> {
        self.session_mpps.first().map(Arc::as_ref)
    }
    fn session_mpp_handle(&self) -> Option<Arc<SessionMpp>> {
        self.session_mpps.first().cloned()
    }
    fn session_mpps(&self) -> Vec<&SessionMpp> {
        self.session_mpps.iter().map(Arc::as_ref).collect()
    }
    fn session_mpp_handles(&self) -> Vec<Arc<SessionMpp>> {
        self.session_mpps.clone()
    }
    fn fee_payer_wallet(&self) -> Option<&FeePayerWallet> {
        self.fee_payer_wallet.as_ref()
    }
    fn fee_payer_signer(&self) -> Option<Arc<dyn SolanaSigner>> {
        self.fee_payer_signer.clone()
    }
    fn x402(&self) -> Option<&pay_kit::x402::server::X402> {
        self.x402.as_ref()
    }
    fn x402_upto(&self) -> Option<&pay_kit::x402::server::X402Upto> {
        self.x402_upto.as_ref()
    }
    fn record_exchange(&self, exchange: pay_core::HttpExchange) {
        let Some(pdb) = &self.pdb else {
            return;
        };
        let entry = pay_pdb::types::LogEntry {
            id: pdb.next_log_id(),
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            method: exchange.method,
            path: exchange.path,
            status: exchange.status,
            ms: exchange.ms,
            req_headers: exchange.req_headers.into_iter().collect(),
            res_headers: exchange.res_headers.into_iter().collect(),
            res_body: None,
            client_ip: exchange.client_ip,
        };
        if let Ok(mut engine) = pdb.correlation.lock() {
            engine.ingest(entry);
        }
    }
}

fn x402_upto_payout_for_recipient(
    recipient: &str,
    receiver_authorizer: &str,
) -> pay_kit::x402::server::UptoPayout {
    if recipient == receiver_authorizer {
        pay_kit::x402::server::UptoPayout::ReceiverKeepsAll
    } else {
        pay_kit::x402::server::UptoPayout::Beneficiary {
            address: recipient.to_string(),
        }
    }
}

fn x402_currency_configs(
    currency_configs: &[(String, String, u8)],
    network: &str,
) -> Vec<pay_kit::x402::server::CurrencyConfig> {
    let mut configs: Vec<_> = currency_configs
        .iter()
        .map(
            |(_symbol, mint, decimals)| pay_kit::x402::server::CurrencyConfig {
                currency: mint.clone(),
                decimals: *decimals,
                token_program: None,
            },
        )
        .collect();
    if configs.is_empty() {
        configs.push(pay_kit::x402::server::CurrencyConfig {
            currency: Stablecoin::Usdc.mint(Some(network)).to_string(),
            decimals: 6,
            token_program: None,
        });
    }
    configs
}

fn resolve_session_splits(
    api: &ApiSpec,
    session: &pay_types::metering::SessionSpec,
) -> pay_core::Result<Vec<pay_kit::mpp::server::session::Split>> {
    let mut splits = Vec::with_capacity(session.splits.len());
    let mut total_bps: u16 = 0;

    for rule in &session.splits {
        if rule.amount.is_some() {
            return Err(pay_core::Error::Config(format!(
                "session split `{}` uses `amount`; session channel splits must use `percent`",
                rule.recipient
            )));
        }

        let percent = rule.percent.ok_or_else(|| {
            pay_core::Error::Config(format!(
                "session split `{}` must set `percent`",
                rule.recipient
            ))
        })?;
        if !percent.is_finite() {
            return Err(pay_core::Error::Config(format!(
                "session split `{}` percent must be a finite number",
                rule.recipient
            )));
        }
        if percent <= 0.0 {
            return Err(pay_core::Error::Config(format!(
                "session split `{}` percent must be positive",
                rule.recipient
            )));
        }

        let bps = (percent * 100.0).round();
        if !(1.0..10_000.0).contains(&bps) {
            return Err(pay_core::Error::Config(format!(
                "session split `{}` percent must convert to 1..9999 basis points",
                rule.recipient
            )));
        }
        let bps = bps as u16;
        total_bps += bps;
        if total_bps >= 10_000 {
            return Err(pay_core::Error::Config(
                "session splits must leave a positive primary recipient share".to_string(),
            ));
        }

        let alias = api.recipients.get(&rule.recipient).ok_or_else(|| {
            pay_core::Error::Config(format!(
                "session split references unknown recipient `{}`",
                rule.recipient
            ))
        })?;
        let account = resolve_static_account(&alias.account)?;
        let recipient = solana_pubkey::Pubkey::from_str(&account).map_err(|e| {
            pay_core::Error::Config(format!(
                "session split `{}` recipient is not a valid Solana pubkey: {e}",
                rule.recipient
            ))
        })?;

        splits.push(pay_kit::mpp::server::session::Split { recipient, bps });
    }

    Ok(splits)
}

fn delegated_session_channel_payout(
    recipient: &str,
    operator: &str,
    mut splits: Vec<pay_kit::mpp::server::session::Split>,
) -> pay_core::Result<(String, Vec<pay_kit::mpp::server::session::Split>)> {
    if recipient == operator {
        return Ok((recipient.to_string(), splits));
    }

    let recipient = solana_pubkey::Pubkey::from_str(recipient).map_err(|e| {
        pay_core::Error::Config(format!(
            "delegated session recipient is not a valid Solana pubkey: {e}"
        ))
    })?;
    let explicit_bps = splits
        .iter()
        .try_fold(0_u16, |total, split| total.checked_add(split.bps))
        .ok_or_else(|| {
            pay_core::Error::Config("delegated session split basis points overflow".to_string())
        })?;
    let primary_bps = 10_000_u16.checked_sub(explicit_bps).ok_or_else(|| {
        pay_core::Error::Config("delegated session splits exceed 100%".to_string())
    })?;

    if let Some(existing) = splits.iter_mut().find(|split| split.recipient == recipient) {
        existing.bps = existing.bps.checked_add(primary_bps).ok_or_else(|| {
            pay_core::Error::Config(
                "delegated session recipient split basis points overflow".to_string(),
            )
        })?;
    } else {
        splits.push(pay_kit::mpp::server::session::Split {
            recipient,
            bps: primary_bps,
        });
    }

    Ok((operator.to_string(), splits))
}

fn account_env_var(account: &str) -> Option<&str> {
    account
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
}

fn resolve_static_account(account: &str) -> pay_core::Result<String> {
    if let Some(name) = account_env_var(account) {
        return match std::env::var(name) {
            Ok(value) if !value.is_empty() => Ok(value),
            _ => Err(pay_core::Error::Config(format!(
                "session split account references unset environment variable `{name}`"
            ))),
        };
    }
    Ok(account.to_string())
}

fn resolve_startup_payout_account(account: &str) -> pay_core::Result<Option<String>> {
    let Some(name) = account_env_var(account) else {
        return Ok(Some(account.to_string()));
    };

    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Ok(Some(value)),
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(pay_core::Error::Config(format!(
            "split account environment variable `{name}` is not valid Unicode"
        ))),
    }
}

fn apply_spec_env_vars(api: &ApiSpec) -> pay_core::Result<()> {
    for (key, value) in &api.env {
        let resolved = if let Some(var_name) = account_env_var(value) {
            match std::env::var(var_name) {
                Ok(v) => Some(v),
                Err(std::env::VarError::NotPresent) => None,
                Err(std::env::VarError::NotUnicode(_)) => {
                    return Err(pay_core::Error::Config(format!(
                        "spec env `{key}` references non-Unicode environment variable `{var_name}`"
                    )));
                }
            }
        } else {
            Some(value.clone())
        };

        if let Some(resolved) = resolved {
            // SAFETY: called before the server runtime and worker threads are spawned.
            unsafe { std::env::set_var(key, resolved) };
        }
    }
    Ok(())
}

fn parse_payout_recipient(
    label: String,
    account: &str,
    context: &str,
) -> pay_core::Result<PayoutRecipientTarget> {
    let recipient = solana_pubkey::Pubkey::from_str(account).map_err(|e| {
        pay_core::Error::Config(format!(
            "{context} account is not a valid Solana pubkey: {e}"
        ))
    })?;
    Ok(PayoutRecipientTarget {
        label,
        pubkey: recipient,
    })
}

async fn create_surfpool_payment_channel_payer(
    rpc_url: &str,
) -> pay_core::Result<Arc<dyn SolanaSigner>> {
    use ed25519_dalek::SigningKey;
    use pay_kit::mpp::solana_keychain::MemorySigner;

    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let vk = sk.verifying_key();
    let mut kp = [0u8; 64];
    kp[..32].copy_from_slice(sk.as_bytes());
    kp[32..].copy_from_slice(vk.as_bytes());
    let signer = MemorySigner::from_bytes(&kp).map_err(|e| {
        pay_core::Error::Config(format!(
            "failed to create session channel payer signer: {e}"
        ))
    })?;
    let pubkey = signer.pubkey().to_string();
    pay_core::client::sandbox::fund_via_surfpool(rpc_url, &pubkey).await?;
    Ok(Arc::new(signer) as Arc<dyn SolanaSigner>)
}

async fn ensure_surfpool_session_distribution_accounts(
    rpc_url: &str,
    splits: &[pay_kit::mpp::server::session::Split],
) -> pay_core::Result<()> {
    let treasury = pay_kit::mpp::program::payment_channels::treasury_owner().to_string();
    pay_core::client::sandbox::set_surfpool_usdc_token_account(rpc_url, &treasury, 0).await?;
    for split in splits {
        pay_core::client::sandbox::set_surfpool_usdc_token_account(
            rpc_url,
            &split.recipient.to_string(),
            0,
        )
        .await?;
    }
    Ok(())
}

fn add_payout_recipient_target(
    targets: &mut Vec<PayoutRecipientTarget>,
    label: impl Into<String>,
    pubkey: solana_pubkey::Pubkey,
) {
    let label = label.into();
    if let Some(existing) = targets.iter_mut().find(|target| target.pubkey == pubkey) {
        if !existing.label.split(" + ").any(|part| part == label) {
            existing.label.push_str(" + ");
            existing.label.push_str(&label);
        }
    } else {
        targets.push(PayoutRecipientTarget { label, pubkey });
    }
}

fn payout_recipient_targets(
    api: &ApiSpec,
    x402_upto_beneficiary: Option<solana_pubkey::Pubkey>,
) -> pay_core::Result<Vec<PayoutRecipientTarget>> {
    let mut recipients = Vec::new();
    if let Some(beneficiary) = x402_upto_beneficiary {
        add_payout_recipient_target(&mut recipients, "x402-upto beneficiary", beneficiary);
    }
    for target in charge_split_recipient_targets(api)? {
        add_payout_recipient_target(&mut recipients, target.label, target.pubkey);
    }
    Ok(recipients)
}

fn payout_recipient_pubkeys(targets: &[PayoutRecipientTarget]) -> Vec<solana_pubkey::Pubkey> {
    targets.iter().map(|target| target.pubkey).collect()
}

fn charge_split_recipient_targets(api: &ApiSpec) -> pay_core::Result<Vec<PayoutRecipientTarget>> {
    let mut recipients = Vec::new();
    for ep in &api.endpoints {
        let Some(meter) = ep.metering.as_ref() else {
            continue;
        };
        if !meter
            .accepted_schemes()
            .contains(&pay_types::metering::Scheme::MppCharge)
        {
            continue;
        }

        for rule in pay_core::server::metering::resolve_split_rules(meter) {
            let Some(alias) = api.recipients.get(&rule.recipient) else {
                return Err(pay_core::Error::Config(format!(
                    "{}: split recipient '{}' not declared",
                    ep.path, rule.recipient
                )));
            };
            let label = alias
                .label
                .as_ref()
                .map(|display| format!("split recipient {} ({display})", rule.recipient))
                .unwrap_or_else(|| format!("split recipient {}", rule.recipient));
            let Some(account) = resolve_startup_payout_account(&alias.account)? else {
                tracing::debug!(
                    endpoint = %ep.path,
                    recipient = %rule.recipient,
                    "skipping runtime split recipient during startup payout preparation"
                );
                continue;
            };
            let context = format!("{}: split recipient '{}'", ep.path, rule.recipient);
            let target = parse_payout_recipient(label, &account, &context)?;
            add_payout_recipient_target(&mut recipients, target.label, target.pubkey);
        }
    }
    Ok(recipients)
}

fn api_accepts_x402_upto(api: &ApiSpec) -> bool {
    api.endpoints.iter().any(|ep| {
        ep.metering.as_ref().is_some_and(|meter| {
            meter
                .accepted_schemes()
                .contains(&pay_types::metering::Scheme::X402Upto)
        })
    })
}

fn x402_upto_beneficiary_pubkey(
    api: &ApiSpec,
    recipient: &str,
    operator: Option<&str>,
) -> pay_core::Result<Option<solana_pubkey::Pubkey>> {
    let Some(operator) = operator else {
        return Ok(None);
    };
    if !api_accepts_x402_upto(api) || recipient == operator {
        return Ok(None);
    }

    solana_pubkey::Pubkey::from_str(recipient)
        .map(Some)
        .map_err(|e| {
            pay_core::Error::Config(format!(
                "x402 upto recipient `{recipient}` is not a valid Solana pubkey: {e}"
            ))
        })
}

impl StartCommand {
    pub fn run(self, active_account_name: Option<&str>, sandbox: bool) -> pay_core::Result<()> {
        let debugger = self.debugger || sandbox;
        let expanded = shellexpand::tilde(&self.spec);
        let contents = std::fs::read_to_string(expanded.as_ref())
            .map_err(|e| pay_core::Error::Config(format!("Failed to read {}: {e}", self.spec)))?;

        let (mut api, api_profile) = pay_core::server::profiles::load_yaml_with_profile(&contents)
            .map_err(|e| pay_core::Error::Config(format!("Invalid spec: {e}")))?;

        apply_spec_env_vars(&api)?;
        api.resolve_env_templates()
            .map_err(pay_core::Error::Config)?;

        // Resolve per-endpoint `schemes` defaults once, before the gate, the
        // OpenAPI builder, and the x402-backend probe read them — a session
        // spec that omits `schemes` keeps accepting `intent=session` instead of
        // silently regressing to charge-only.
        api.apply_scheme_defaults();

        // Validate the resolved spec once at boot — after `apply_scheme_defaults`
        // — so configuration errors (unknown or duplicate split recipients,
        // splits exceeding the price, malformed tiers, …) abort startup instead
        // of surfacing as a runtime `challenge_generation_failed` 500 (charge) or
        // an on-chain channel `open` rejection (session) on the first paid
        // request. Aborting via `Error::Config` reuses the single notice the CLI
        // already renders for every config check (`main::print_command_error`),
        // consolidating these checks behind one boot-time gate.
        let spec_issues = pay_types::metering::validate_api_spec(&api);
        if !spec_issues.is_empty() {
            let detail = spec_issues
                .iter()
                .map(|issue| format!("  • {issue}"))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(pay_core::Error::Config(format!(
                "{} configuration error(s) in spec `{}`:\n{detail}",
                spec_issues.len(),
                self.spec,
            )));
        }

        // Optional OpenAPI / Discovery doc — loaded once, filtered to the
        // YAML's `endpoints[]` allow-list, and exposed at `GET /openapi.json`
        // with `rootUrl` / `servers[].url` rewritten per-request from the
        // `Host` header (or `--public-url` when set).
        let upstream_openapi: Option<Arc<serde_json::Value>> = match &self.openapi {
            Some(input) => {
                let source = if input.starts_with("http://") || input.starts_with("https://") {
                    pay_types::registry::OpenapiSource::Url {
                        url: input.to_string(),
                    }
                } else {
                    pay_types::registry::OpenapiSource::Path {
                        path: input.to_string(),
                    }
                };
                let spec_dir = std::path::Path::new(expanded.as_ref())
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."));
                let mut doc = pay_core::server::openapi::load_document(&source, spec_dir)?;
                pay_core::server::openapi::filter_to_endpoints(&mut doc, &api.endpoints);
                // Carry per-endpoint metering (incl. per-model `variants[]`)
                // as the `x-pay-metering` extension so pricing a live probe
                // can't observe reaches the published pay-skills spec.
                pay_core::server::openapi::attach_metering_extension(&mut doc, &api.endpoints);
                // Drop schemas/parameters/responses no surviving operation
                // references — for heavily-trimmed proxies (e.g. bigquery
                // 47 endpoints → 2) this cuts the served openapi size from
                // hundreds of KB to a handful.
                pay_core::server::openapi::prune_unused_components(&mut doc);
                // Strip upstream-auth metadata (OAuth2 scopes etc.) — the
                // proxy handles upstream credentials internally; surfacing
                // them on /openapi.json misleads agents into attaching
                // tokens the proxy won't use.
                pay_core::server::openapi::strip_upstream_auth(&mut doc);
                Some(Arc::new(doc))
            }
            // No upstream doc — synthesized later (after the operator identity
            // resolves) from the spec itself, like pay-kit's TS
            // `openapiFromExpress`. See the `openapi_doc` binding below.
            None => None,
        };
        let openapi_proxy_mode = matches!(api.routing, RoutingConfig::Proxy { .. });
        let public_url_override = self.public_url.clone();

        let op = api.operator.clone();
        let op = op.as_ref();

        // Note: we used to refuse any `operator.signer` block unless the
        // `gcp_kms` feature was built. That was over-broad — the new
        // `Account` and `File` variants need no extra build features and
        // are the recommended path for local dev. The per-variant gate
        // now lives inside `resolve_signer` itself.

        // Resolve config that doesn't need async.
        let currencies = resolve_operator_currencies(op, &self.currency);

        // `--sandbox` is an authoritative local-dev switch: pin the
        // network to localnet regardless of the spec's `operator.network`.
        // Otherwise `pay --sandbox server start <spec with network:
        // devnet>` would derive `auto_network = "devnet"` below and
        // silently mint (and persist) an `accounts.devnet.gateway`
        // ephemeral while talking to real devnet — the opposite of what
        // `--sandbox` implies.
        let network = if sandbox {
            SolanaNetwork::Localnet
        } else {
            SolanaNetwork::from_slug(
                op.and_then(|o| o.network.clone())
                    .unwrap_or_else(|| "mainnet".to_string()),
            )
        };
        // Captured into the async block below for synthesized-openapi offers.
        let network_slug = network.slug().to_string();

        // RPC URL fallback chain. Network-aware so that `localnet`
        // defaults to the hosted Surfpool sandbox (where ephemeral
        // wallets can be auto-created and auto-funded). Users running
        // a real `solana-test-validator` should set `operator.rpc_url`
        // explicitly or pass `--rpc-url`.
        //
        // In sandbox we deliberately drop the spec's `operator.rpc_url`
        // from the chain — a devnet/mainnet URL in the YAML must not be
        // able to pull the pinned-localnet sandbox onto a real cluster.
        // Explicit `--rpc-url` / `PAY_RPC_URL` are still honored so a
        // local `solana-test-validator` works.
        let rpc_url = if sandbox {
            payments::resolve_sandbox_rpc_url(self.rpc_url.clone())
        } else {
            op.and_then(|o| o.rpc_url.clone())
                .or(self.rpc_url.clone())
                .or_else(|| std::env::var("PAY_RPC_URL").ok())
                .unwrap_or_else(|| network.default_rpc_url(sandbox))
        };

        let fee_payer = op.map(|o| o.fee_payer).unwrap_or(false);
        let signer_cfg = op.and_then(|o| o.signer.clone());
        let active_account_name_owned = active_account_name.map(|s| s.to_string());

        // Create the runtime first — everything async runs inside it so
        // background tasks (like GCP auth token refresh) stay alive. Worker
        // threads are named `pay-server-worker-N` so logs/profilers/span thread
        // attributes show which thread is doing what.
        let worker_seq = std::sync::atomic::AtomicUsize::new(0);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name_fn(move || {
                let n = worker_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                format!("pay-server-worker-{n}")
            })
            .build()
            .map_err(|e| pay_core::Error::Config(format!("Failed to create runtime: {e}")))?;

        let gateway = rt.block_on(async {
            // ── Resolve fee-payer signer (async — needs the runtime) ──
            //
            // Lookup order, first match wins:
            //
            //   1. **`--sandbox` flag** — authoritative local dev mode.
            //      Force a dedicated localnet gateway ephemeral from
            //      accounts.yml regardless of the YAML's production
            //      `operator.signer` / `operator.network`. This keeps
            //      local sanity tests off real signers and makes the
            //      emitted MPP challenges compatible with `pay --sandbox
            //      curl`.
            //
            //   2. **Explicit `operator.signer` in YAML** — production
            //      path. Handles GcpKms (build-feature gated), Account
            //      (named entry in accounts.yml), and File (JSON keypair
            //      on disk).
            //
            //   3. **Throwaway network slug** (`localnet` / `devnet`)**
            //      with no explicit signer** — smart default: route
            //      through the network-aware loader so users running
            //      `pay server start` against a localnet/devnet spec
            //      don't have to think about signers. Same code path as
            //      the sandbox flag.
            //
            //   4. **None** — leaves fee_payer_signer empty. Caught by
            //      the early-validation guard below if `fee_payer: true`.
            let mut generated_gateway_account: Option<(String, String)> = None;
            let fee_payer_signer: Option<Arc<dyn SolanaSigner>> = if should_use_auto_fee_payer_signer(
                sandbox,
                &network,
                signer_cfg.as_ref(),
            ) {
                let (signer, generated) = payments::load_auto_fee_payer_signer(&network)?;
                generated_gateway_account = generated;
                Some(signer)
            } else if let Some(ref cfg) = signer_cfg {
                Some(resolve_signer(cfg).await?)
            } else if let Some(ref source) = active_account_name_owned {
                // Mainnet (or unknown network) with no `operator.signer`
                // block but a default keypair from `pay setup` —
                // typically `keychain:default`. Load it once at startup
                // with a meaningful reason string so the OS auth prompt
                // tells the user *why* it's being asked. The same
                // signer is then used as both the fee-payer and the
                // recipient-pubkey source (no second load).
                let intent = pay_core::keystore::AuthIntent::use_gateway_fee_payer();
                let signer = pay_core::signer::load_signer_with_intent(source, &intent)?;
                Some(Arc::new(signer) as Arc<dyn SolanaSigner>)
            } else {
                None
            };

            // ── Resolve recipient ──
            //
            // Lookup order (first match wins):
            //   1. operator.recipient in YAML
            //   2. --recipient flag
            //   3. PAY_PAYMENT_RECIPIENT env var
            //   4. fee_payer_signer's pubkey — covers sandbox, throwaway-
            //      network smart default, explicit operator.signer block,
            //      and the active_account_name fallback (all four set
            //      fee_payer_signer above).
            let recipient = if let Some(r) = op.and_then(|o| o.recipient.as_ref()) {
                r.clone()
            } else if let Some(r) = &self.recipient {
                r.clone()
            } else if let Ok(r) = std::env::var("PAY_PAYMENT_RECIPIENT") {
                r
            } else if let Some(ref signer) = fee_payer_signer {
                signer.pubkey().to_string()
            } else {
                return Err(pay_core::Error::Config(
                    "No recipient specified. Use operator.recipient in YAML, --recipient flag, PAY_PAYMENT_RECIPIENT env, or `pay setup`."
                        .to_string(),
                ));
            };

            // ── Validate fee_payer / signer consistency ──
            //
            // If the operator YAML demands `fee_payer: true` (the
            // server co-signs to sponsor transaction fees) but no
            // signer is available, the server would start happily and
            // then fail every single payment at verify time with the
            // unhelpful "Fee payer enabled but no signer configured"
            // error. Catch it at startup instead so the user knows
            // immediately what to fix.
            if fee_payer && fee_payer_signer.is_none() {
                return Err(pay_core::Error::Config(
                    "operator.fee_payer is `true` but no fee payer signer is configured.\n\n\
                     In sandbox mode, start the server with `pay --sandbox server start ...` \
                     (or use `pay -s server demo`).\n\
                     In production, set `operator.signer` in the YAML (`backend: env`, \
                     `backend: account`, `backend: file`, or a gcp-kms signer in a \
                     gcp_kms build) or set `operator.fee_payer: false` \
                     so clients pay their own fees."
                        .to_string(),
                ));
            }

            // ── Ensure each subscription endpoint has its on-chain Plan ─
            //
            // A subscription endpoint can't emit a usable 402 challenge
            // until the merchant's Plan PDA exists on-chain — the spec's
            // `methodDetails.planId` field is required and the server
            // re-derives it from `(operator, plan_id_numeric)`.
            //
            // For each `subscription:` block in the spec we:
            //   1. compute the deterministic plan_id_numeric,
            //   2. RPC-check whether the Plan PDA exists,
            //   3. interactively prompt (dialoguer) to publish on miss,
            //   4. broadcast `create_plan` with the operator's signer,
            //   5. write plan_id / plan_id_numeric / plan_bump /
            //      plan_created_at back into the YAML so subsequent
            //      restarts (and the subscriber client) see the same PDA.
            //
            // Skipped silently when the YAML has no subscription
            // endpoints. Server startup aborts if the operator declines
            // the prompt — we can't serve a half-configured gateway.
            let api = ensure_subscription_plans(
                api,
                &self.spec,
                &recipient,
                fee_payer_signer.clone(),
                &rpc_url,
            )
            .await?;

            // Discovery doc served at `/openapi.json`: prefer the operator's
            // upstream OpenAPI; otherwise synthesize one from the spec + the
            // now-resolved operator identity (recipient → `payTo`, fee-payer →
            // x402 `feePayer`), mirroring pay-kit's TS `openapiFromExpress`.
            let openapi_doc: Option<Arc<serde_json::Value>> = match upstream_openapi.clone() {
                Some(doc) => Some(doc),
                None => {
                    let fee_payer_pk = fee_payer_signer.as_ref().map(|s| s.pubkey().to_string());
                    let ctx = pay_core::server::openapi::DiscoveryContext {
                        network_slug: &network_slug,
                        pay_to: Some(recipient.as_str()),
                        fee_payer: fee_payer_pk.as_deref(),
                    };
                    Some(Arc::new(pay_core::server::openapi::synthesize_from_spec(
                        &api, &ctx,
                    )))
                }
            };

            let currency_configs: Vec<_> = currencies
                .iter()
                .map(|currency| {
                    let (mpp_currency, decimals) = resolve_currency(currency, network.slug());
                    (currency.clone(), mpp_currency, decimals)
                })
                .collect();
            let operator_pubkey = fee_payer_signer
                .as_ref()
                .map(|signer| signer.pubkey().to_string());
            let operator_balance_address = operator_pubkey.as_deref().unwrap_or(&recipient);
            let x402_upto_beneficiary =
                x402_upto_beneficiary_pubkey(&api, &recipient, operator_pubkey.as_deref())?;
            let payout_recipient_targets =
                payout_recipient_targets(&api, x402_upto_beneficiary)?;
            let payout_recipients = payout_recipient_pubkeys(&payout_recipient_targets);
            let stable_requirements =
                stable_token_account_requirements(&currency_configs, network.slug())?;

            // ── Auto-fund local Surfpool wallets ──
            //
            // See `payments::prepare_funding_targets` for when funding
            // triggers and why it's idempotent.
            let surfpool_targets =
                surfpool_funding_targets(&recipient, operator_pubkey.as_deref());
            let (should_fund, funding_balances) = payments::prepare_funding_targets(
                sandbox,
                &network,
                &rpc_url,
                &surfpool_targets,
                &payout_recipient_targets,
                &stable_requirements,
            )
            .await?;
            let operator_sol = funding_balances
                .iter()
                .find(|balance| balance.address == operator_balance_address)
                .map(|balance| lamports_to_sol(balance.lamports))
                .ok_or_else(|| {
                    pay_core::Error::Config(
                        "internal error: operator signer was not validated".to_string(),
                    )
                })?;

            // ── Create MPP servers ──
            // (Also mirrors the charge HMAC secret into
            // MPP_CHALLENGE_BINDING_SECRET for the subscription middleware —
            // see `payments::init_challenge_binding_secret`.)
            let challenge_binding_secret = payments::init_challenge_binding_secret();

            payments::ensure_payout_recipient_token_accounts(
                &payout_recipients,
                &stable_requirements,
                network.slug(),
                &rpc_url,
                should_fund,
                fee_payer_signer.clone(),
            )
            .await?;
            // Shared recent-blockhash cache, refreshed by a background thread
            // (see `payments::spawn_blockhash_cache` for why).
            let blockhash_cache = payments::spawn_blockhash_cache(&rpc_url);

            let mpps: Vec<Mpp> = payments::build_charge_mpps(
                &currency_configs,
                &recipient,
                network.slug(),
                &rpc_url,
                &challenge_binding_secret,
                fee_payer,
                fee_payer_signer.clone(),
                &blockhash_cache,
            )?;
            // ── Create one session MPP server per configured currency ──
            let session_mpps: Vec<Arc<SessionMpp>> = if let Some(ref sess) = api.session {
                use pay_core::server::session::PullVoucherStrategy;
                use pay_types::metering::{
                    SessionPullVoucherStrategy as ConfigPullVoucherStrategy,
                    SessionSettlementAuthority as ConfigSettlementAuthority,
                };
                use pay_kit::mpp::server::session::{
                    SessionConfig, SettlementAuthority,
                };
                use pay_kit::mpp::{SessionMode, SessionPullVoucherStrategy};
                use std::str::FromStr;

                let session_secret = std::env::var("PAY_SESSION_SECRET")
                    .unwrap_or_else(|_| challenge_binding_secret.clone());
                // Default to pull + clientVoucher (payment-channel) when `modes`
                // is omitted — matches the canonical pay-kit `session()` adapter
                // and the JS playground client. Explicit `modes:` is respected.
                let modes_omitted = sess.modes.is_empty();
                let requested_modes: Vec<SessionMode> = if modes_omitted {
                    vec![SessionMode::Pull]
                } else {
                    sess.modes
                        .iter()
                        .map(|m| match m.as_str() {
                            "pull" => SessionMode::Pull,
                            _ => SessionMode::Push,
                        })
                        .collect()
                };
                let pull_voucher_strategy = match sess.pull_voucher_strategy {
                    // Omitting `modes` opts into the pull default, so also enable
                    // clientVoucher (otherwise pull gets stripped back to push).
                    ConfigPullVoucherStrategy::Disabled if modes_omitted => {
                        PullVoucherStrategy::ClientVoucher
                    }
                    ConfigPullVoucherStrategy::Disabled => PullVoucherStrategy::Disabled,
                    ConfigPullVoucherStrategy::ClientVoucher => PullVoucherStrategy::ClientVoucher,
                    ConfigPullVoucherStrategy::OperatedVoucher => {
                        return Err(pay_core::Error::Config(
                            "session.pull_voucher_strategy = operated_voucher is no longer \
                             supported; use client_voucher or disabled"
                                .to_string(),
                        ));
                    }
                };
                let mut modes = requested_modes.clone();
                if pull_voucher_strategy == PullVoucherStrategy::Disabled {
                    if requested_modes.contains(&SessionMode::Pull) {
                        tracing::warn!(
                            "pull mode requested but pull_voucher_strategy is disabled; advertising push only"
                        );
                    }
                    modes.retain(|mode| mode != &SessionMode::Pull);
                }
                if modes.is_empty() {
                    modes.push(SessionMode::Push);
                }
                let sdk_pull_voucher_strategy = if modes.contains(&SessionMode::Pull) {
                    match pull_voucher_strategy {
                        PullVoucherStrategy::Disabled => None,
                        PullVoucherStrategy::ClientVoucher => {
                            Some(SessionPullVoucherStrategy::ClientVoucher)
                        }
                    }
                } else {
                    None
                };
                let channel_program_id = std::env::var("PAY_PAYMENT_CHANNELS_PROGRAM_ID")
                    .or_else(|_| std::env::var("PAY_FIBER_PROGRAM_ID"))
                    .ok()
                    .and_then(|value| solana_pubkey::Pubkey::from_str(&value).ok())
                    .unwrap_or_else(pay_kit::mpp::program::payment_channels::default_program_id);
                let session_splits = resolve_session_splits(&api, sess)?;
                let client_voucher_pull = modes.contains(&SessionMode::Pull)
                    && pull_voucher_strategy == PullVoucherStrategy::ClientVoucher;
                let settlement_authority = match sess.settlement_authority {
                    ConfigSettlementAuthority::ClientVoucher => {
                        SettlementAuthority::ClientVoucher
                    }
                    ConfigSettlementAuthority::Delegated => SettlementAuthority::Delegated,
                };
                if settlement_authority == SettlementAuthority::Delegated
                    && fee_payer_signer.is_none()
                {
                    return Err(pay_core::Error::Config(
                        "delegated session settlement requires operator.fee_payer so the gateway can sign metered vouchers".to_string(),
                    ));
                }
                if client_voucher_pull
                    && let Some(settlement_signer) = fee_payer_signer.as_ref()
                    && recipient != settlement_signer.pubkey().to_string()
                {
                    return Err(pay_core::Error::Config(
                        "pull/client_voucher sessions require the primary recipient to match the gateway settlement signer. Remove operator.recipient or set it to the configured signer pubkey.".to_string(),
                    ));
                }
                let session_channel_payer_signer = if client_voucher_pull && should_fund {
                    Some(create_surfpool_payment_channel_payer(&rpc_url).await?)
                } else {
                    None
                };
                let session_operator = fee_payer_signer
                    .as_ref()
                    .or(session_channel_payer_signer.as_ref())
                    .map(|signer| signer.pubkey().to_string())
                    .unwrap_or_else(|| recipient.clone());
                let (session_recipient, session_splits) =
                    if settlement_authority == SettlementAuthority::Delegated {
                        delegated_session_channel_payout(
                            &recipient,
                            &session_operator,
                            session_splits,
                        )?
                    } else {
                        (recipient.clone(), session_splits)
                    };
                if client_voucher_pull && should_fund {
                    ensure_surfpool_session_distribution_accounts(&rpc_url, &session_splits)
                        .await?;
                }

                let session_channel_store = session_channel_store().await?;
                let mut session_mpps = Vec::with_capacity(currency_configs.len());
                for (_currency, session_mpp_currency, session_decimals) in &currency_configs {
                    let cap_base =
                        (sess.cap_usdc * 10f64.powi(i32::from(*session_decimals))).round() as u64;
                    let config = SessionConfig {
                        recipient: session_recipient.clone(),
                        operator: session_operator.clone(),
                        splits: session_splits.clone(),
                        currency: session_mpp_currency.clone(),
                        decimals: *session_decimals,
                        network: network.slug().to_string(),
                        max_cap: cap_base,
                        min_voucher_delta: sess.min_voucher_delta,
                        settlement_authority,
                        modes: modes.clone(),
                        pull_voucher_strategy: sdk_pull_voucher_strategy.clone(),
                        grace_period_seconds:
                            pay_kit::mpp::program::payment_channels::DEFAULT_GRACE_PERIOD_SECONDS,
                        rpc_url: Some(rpc_url.clone()),
                        program_id: Some(channel_program_id),
                    };

                    let mut smpp = SessionMpp::new_with_channel_store(
                        config,
                        session_secret.clone(),
                        Arc::clone(&session_channel_store),
                    )
                        .with_realm(api.title.clone())
                        .with_pull_voucher_strategy(pull_voucher_strategy)
                        .with_blockhash_cache(blockhash_cache.clone());
                    if let Some(operator_signer) = fee_payer_signer.clone() {
                        smpp = smpp.with_payment_channel_signer(operator_signer);
                    }
                    if let Some(channel_payer_signer) = session_channel_payer_signer.clone() {
                        smpp = smpp.with_payment_channel_payer_signer(channel_payer_signer);
                    }

                    let smpp = Arc::new(smpp);
                    smpp.start_lifecycle_runloop_with_settlement(
                        Duration::from_millis(sess.close_delay_ms),
                        Duration::from_millis(sess.settlement_interval_ms),
                    );
                    session_mpps.push(smpp);
                }
                session_mpps
            } else {
                Vec::new()
            };

            // Validate split recipients that are knowable at startup. Runtime
            // `${VAR}` recipients are allowed to resolve from request query
            // parameters, so they cannot be treated as launch blockers.
            ensure_static_split_recipient_accounts_valid(&api)?;

            // ── Banner ──
            let metered_count = api
                .endpoints
                .iter()
                .filter(|e| e.metering.is_some())
                .count();
            let subscription_count = api
                .endpoints
                .iter()
                .filter(|e| e.subscription.is_some())
                .count();
            let free_count = api
                .endpoints
                .len()
                .saturating_sub(metered_count)
                .saturating_sub(subscription_count);

            let banner = render_pay_banner(PAY_SH_TAGLINE.dimmed());
            let has_startup_status =
                generated_gateway_account.is_some() || self.scaffolded_spec.is_some();
            if !banner.is_empty() {
                eprintln!("{banner}");
                if has_startup_status {
                    eprintln!();
                }
            }
            if let Some((account_name, pubkey)) = &generated_gateway_account {
                // Name the network — auto-minting a persisted ephemeral on a
                // real cluster (devnet) should never look like a silent no-op.
                eprintln!(
                    "{} account {} {} on {}",
                    "Generating".green(),
                    account_name,
                    pubkey,
                    network.slug().dimmed(),
                );
            }
            if let Some(scaffolded_spec) = &self.scaffolded_spec {
                eprintln!("{} {}", "Scaffolding".green(), scaffolded_spec);
            }
            eprintln!();

            // Network link
            let network_label = if sandbox { "sandbox" } else { network.slug() };
            let network_url = if sandbox {
                if rpc_url.contains("localhost") || rpc_url.contains("127.0.0.1") {
                    "http://localhost:18488".to_string()
                } else {
                    rpc_url.clone()
                }
            } else {
                "https://explorer.solana.com".to_string()
            };
            let network_link = crate::components::link::link_with_arrow(network_label, &network_url);

            // Operator link (explorer token page).
            let operator_display = operator_balance_address;
            let short_operator = if operator_display.len() > 8 {
                format!(
                    "{}...{}",
                    &operator_display[..4],
                    &operator_display[operator_display.len() - 4..]
                )
            } else {
                operator_display.to_string()
            };
            let explorer_cluster = network.explorer_cluster(&rpc_url);
            let cluster_query = solana_explorer_cluster_query(&explorer_cluster);
            let operator_url = format!(
                "https://explorer.solana.com/address/{}/tokens{}",
                operator_display, cluster_query
            );
            let operator_link = crate::components::link::link_with_arrow(&short_operator, &operator_url);

            // Pad labels to a fixed visible width — tabs land on
            // terminal-dependent stops, so a 7-char label followed by
            // a tab aligns differently than an 8-char one.
            eprintln!("{}  {}", format!("{:<10}", "network").dimmed(), network_link);
            eprintln!(
                "{}  {} via {}",
                format!("{:<10}", "currency").dimmed(),
                "$".green(),
                currencies.join(", ").green()
            );

            // Color thresholds (covers all networks):
            //   ≥ 0.10 SOL  → green   (comfortable runway)
            //   ≥ 0.05 SOL  → yellow  (top up soon)
            //    < 0.05 SOL → red     (next tx may fail)
            let balance_text = format!(" ({} SOL)", format_price(operator_sol));
            let balance_colored = if operator_sol >= 0.10 {
                balance_text.green().to_string()
            } else if operator_sol >= 0.05 {
                balance_text.yellow().to_string()
            } else {
                balance_text.red().to_string()
            };
            eprintln!(
                "{}  {}{}",
                format!("{:<10}", "operator").dimmed(),
                operator_link,
                balance_colored
            );
            eprintln!();

            let fee_payer_wallet = if fee_payer {
                fee_payer_signer.as_ref().map(|signer| {
                    FeePayerWallet::new(rpc_url.clone(), signer.pubkey().to_string())
                })
            } else {
                None
            };
            if let Some(ref wallet) = fee_payer_wallet {
                wallet.observe("startup", &api.subdomain, "__startup").await;
                spawn_fee_payer_balance_observer(wallet.clone(), api.subdomain.clone());
            }

            let mut category_parts: Vec<String> = Vec::new();
            category_parts.push(format!("{metered_count} metered"));
            if subscription_count > 0 {
                category_parts.push(format!("{subscription_count} subscription"));
            }
            category_parts.push(format!("{free_count} free"));
            eprintln!(
                "{}",
                format!(
                    "{} endpoints ({})",
                    api.endpoints.len(),
                    category_parts.join(", ")
                )
                .dimmed()
            );
            eprintln!();

            let max_path_len = api
                .endpoints
                .iter()
                .map(|e| e.path.len())
                .max()
                .unwrap_or(20);

            let rule = format!(
                "{}{}{}",
                "─".repeat(9),
                "─".repeat(max_path_len + 2),
                "─".repeat(16)
            );
            eprintln!("{}", rule.dimmed());

            for ep in &api.endpoints {
                let method = format!("{:?}", ep.method).to_uppercase();
                let method_padded = format!("{:<7}", method);
                let method_colored = match method.as_str() {
                    "GET" => method_padded.green().to_string(),
                    "POST" => method_padded.blue().to_string(),
                    "PUT" => method_padded.yellow().to_string(),
                    "DELETE" => method_padded.red().to_string(),
                    "PATCH" => method_padded.cyan().to_string(),
                    _ => method_padded.dimmed().to_string(),
                };
                // Variant-priced endpoints list each variant on its own
                // row below the path (see loop after the main line), so
                // the price column here flags the count instead of
                // collapsing to a single (misleading) variant price.
                let variants = ep
                    .metering
                    .as_ref()
                    .map(|m| m.variants.as_slice())
                    .unwrap_or(&[]);
                let price_tag = if let Some(ref m) = ep.metering {
                    if !m.variants.is_empty() {
                        format!("{:>14}", format!("{} variants", m.variants.len()))
                            .yellow()
                            .to_string()
                    } else {
                        let price = first_tier_price(&m.dimensions);
                        format!("{:>14}", format!("${}", format_price(price)))
                            .yellow()
                            .to_string()
                    }
                } else if let Some(ref sub) = ep.subscription {
                    // Show `$9.99/30d` for subscription endpoints. Falls
                    // back to bare period when neither `price_usd` nor
                    // `amount_base_units` is set (shouldn't happen at
                    // boot — `ensure_subscription_plans` validates it).
                    let price = sub
                        .price_usd
                        .map(|p| format!("${}", format_price(p)))
                        .or_else(|| {
                            sub.amount_base_units.as_ref().map(|a| format!("{a}u"))
                        })
                        .unwrap_or_else(|| "?".to_string());
                    format!("{:>14}", format!("{price}/{}", sub.period))
                        .cyan()
                        .to_string()
                } else {
                    format!("{:>14}", "free").green().to_string()
                };

                // Link target uses a concrete example path so it's
                // clickable (no brace-encoding) and selects a real
                // variant; the visible label keeps the `{…}` template.
                let path_url = format!(
                    "http://{}/{}",
                    self.bind.replace("0.0.0.0", "127.0.0.1"),
                    example_path(ep).trim_start_matches('/')
                );
                let path_linked = crate::components::link::link_with_arrow(&ep.path, &path_url);
                // Pad after the link (padding itself is not clickable)
                let padding = " ".repeat(max_path_len.saturating_sub(ep.path.len()));
                eprintln!(
                    "{} {}{} {}",
                    method_colored,
                    path_linked,
                    padding,
                    price_tag,
                );

                // One row per pricing variant, e.g.
                //   model=gemini-3.1-pro-preview              $0.000002
                // The `param=value` label sits in the path column and the
                // price right-aligns under the main price column. Width:
                // the 2-space indent eats into the 8-col method gutter
                // (−6), and `link_with_arrow` adds a 2-col ` ↗` suffix to
                // the path that the main-line padding doesn't count (+2),
                // so the label field is `max_path_len + 8`.
                let label_field_width = max_path_len + 8;
                for variant in variants {
                    let label = format!("{}={}", variant.param, variant.value);
                    let label_pad =
                        " ".repeat(label_field_width.saturating_sub(label.len()));
                    let price = first_tier_price(&variant.dimensions);
                    let variant_price =
                        format!("{:>14}", format!("${}", format_price(price)));
                    eprintln!(
                        "  {}{} {}",
                        label.dimmed(),
                        label_pad,
                        variant_price.yellow(),
                    );
                }
            }

            eprintln!("{}", rule.dimmed());

            eprintln!();

            // ── Build router ──
            let endpoints_json = build_endpoints_json(&api);

            let verify_mpps = mpps.clone();

            // x402 `exact` backend — enables x402 challenges + verification for
            // any endpoint that accepts an x402 scheme (mirrors the MPP wiring;
            // without it the gate silently drops x402 from challenges).
            let wants_x402 = api.endpoints.iter().any(|e| {
                e.metering.as_ref().is_some_and(|m| {
                    m.accepted_schemes().iter().any(|s| {
                        matches!(
                            s,
                            pay_types::metering::Scheme::X402Exact
                                | pay_types::metering::Scheme::X402Upto
                                | pay_types::metering::Scheme::X402BatchSettlement
                        )
                    })
                })
            });
            // x402 currency descriptors — one per configured operator currency.
            // `CurrencyConfig.currency` is serialized as x402 `asset`, so it
            // must be the resolved mint (or native SOL marker), not the display
            // symbol. Passing "USDC" leaks into client RPC calls as an invalid
            // pubkey.
            let x402_currencies = x402_currency_configs(&currency_configs, network.slug());
            let x402 = if wants_x402 {
                let cfg = pay_kit::x402::server::Config {
                    recipient: recipient.clone(),
                    currencies: x402_currencies.clone(),
                    network: network.slug().to_string(),
                    rpc_url: Some(rpc_url.clone()),
                    resource: api.subdomain.clone(),
                    description: None,
                    max_age: Some(300),
                    // The operator co-signs fees only when configured to.
                    fee_payer_key: if fee_payer {
                        fee_payer_signer.as_ref().map(|s| s.pubkey().to_string())
                    } else {
                        None
                    },
                };
                match pay_kit::x402::server::X402::new(cfg) {
                    Ok(x) => Some(x.with_blockhash_cache(blockhash_cache.clone())),
                    Err(e) => {
                        eprintln!("x402 backend disabled ({e}); x402 schemes won't be offered");
                        None
                    }
                }
            } else {
                None
            };

            // x402 `upto` backend — open-before-serve, settle-after. Requires the
            // operator signer (it co-signs the channel open as fee payer and signs
            // settlement vouchers), so it's only available with a fee-payer signer.
            let x402_upto = match (wants_x402, fee_payer_signer.clone()) {
                (true, Some(signer)) => {
                    let receiver_authorizer = signer.pubkey().to_string();
                    let cfg = pay_kit::x402::server::UptoConfig {
                        // If the YAML recipient differs from the receiver signer,
                        // pay the recipient through a bound 100% distribution
                        // split; otherwise the receiver keeps the channel payout.
                        payout: x402_upto_payout_for_recipient(
                            &recipient,
                            &receiver_authorizer,
                        ),
                        currencies: x402_currencies.clone(),
                        cluster: network.slug().to_string(),
                        rpc_url: Some(rpc_url.clone()),
                        resource: api.subdomain.clone(),
                        description: None,
                        max_timeout_seconds: 300,
                        program_id: None,
                        withdraw_delay: 0,
                        fee_payer_signer: signer,
                        receiver_authorizer_signer: None,
                    };
                    match pay_kit::x402::server::X402Upto::new(cfg) {
                        Ok(u) => Some(u.with_blockhash_cache(blockhash_cache.clone())),
                        Err(e) => {
                            eprintln!("x402 upto backend disabled ({e})");
                            None
                        }
                    }
                }
                _ => None,
            };

            let pdb_state = if debugger {
                let pdb_config = build_pdb_config(&api, &recipient, network.slug(), &rpc_url);
                let pdb = pay_pdb::PdbState::new(pdb_config);
                pdb.spawn_cleanup();
                Some(pdb)
            } else {
                None
            };

            if !self.no_register
                && let (Some(public_url), Some(profile)) =
                    (public_url_override.as_deref(), api_profile.as_ref())
            {
                let signer = fee_payer_signer.clone().ok_or_else(|| {
                    pay_core::Error::Config(
                        "provider registration requires an active account or operator signer; pass --no-register to serve without publishing"
                            .to_string(),
                    )
                })?;
                let (category, protocol) =
                    super::provider_registration::profile_keys(profile);
                let registration = super::provider_registration::ServiceRegistration::new(
                    category,
                    protocol,
                    api.name.clone(),
                    api.description.clone(),
                    public_url,
                )?;
                let registry_rpc_url =
                    super::provider_registration::registry_rpc_url_with_fallback(&rpc_url);
                let outcome = super::provider_registration::register_service(
                    &registration,
                    signer.clone(),
                    &registry_rpc_url,
                )
                .await?;
                if let Some(signature) = outcome.signature {
                    tracing::info!(%signature, pda = %outcome.pda, "provider registry heartbeat published");
                }
                super::provider_registration::spawn_renewal_task(
                    registration,
                    signer,
                    registry_rpc_url,
                );
            }

            let state = AppState {
                apis: Arc::new(vec![api.clone()]),
                mpps,
                session_mpps,
                browser_rpc_url: Some(BROWSER_RPC_PROXY_PATH.to_string()),
                fee_payer_wallet,
                fee_payer_signer: fee_payer_signer.clone(),
                x402,
                x402_upto,
                // The gate calls `record_exchange` per proxied request to feed PDB.
                pdb: pdb_state.clone(),
            };

            let verify_pdb = pdb_state.clone();
            let rpc_proxy_url = rpc_url.clone();
            let rpc_proxy_client = reqwest::Client::new();
            let delivery_state = state.clone();
            let mut app = axum::Router::new()
                .route("/__402/health", get(|| async { "ok" }))
                .route(
                    BROWSER_RPC_PROXY_PATH,
                    post(move |body: axum::body::Bytes| {
                        let client = rpc_proxy_client.clone();
                        let rpc_url = rpc_proxy_url.clone();
                        async move { browser_rpc_proxy(client, rpc_url, body).await }
                    }),
                )
                .route(
                    "/__402/endpoints",
                    get(move || async move { axum::Json(endpoints_json).into_response() }),
                )
                .route(
                    "/__402/verify",
                    post(move |body: axum::Json<GatewayVerifyRequest>| async move {
                        gateway_verify(verify_mpps.clone(), body.0, verify_pdb.as_ref()).await
                    }),
                )
                .route(
                    "/__402/session/deliveries",
                    post(move |body: axum::Json<SessionDeliveryRequest>| {
                        reserve_session_delivery(delivery_state.clone(), body.0)
                    }),
                )
                // Payment-channel settle-receipt poll. Payment-channel sessions
                // settle out-of-band at idle-close, so (unlike x402) there's no
                // per-request settlement header — clients poll this for the
                // on-chain signature to build the receipt URL.
                .route(
                    "/__402/payment-channels/receipt/{channel_id}",
                    get({
                        let receipt_state = state.clone();
                        move |axum::extract::Path(channel_id): axum::extract::Path<String>| {
                            let state = receipt_state.clone();
                            async move { session_receipt(state, channel_id) }
                        }
                    }),
                );

            if let Some(doc) = openapi_doc.clone() {
                let public_override = public_url_override.clone();
                let proxy_mode = openapi_proxy_mode;
                app = app.route(
                    "/openapi.json",
                    get(move |headers: axum::http::HeaderMap| {
                        let doc = doc.clone();
                        let public_override = public_override.clone();
                        async move {
                            serve_openapi(doc, proxy_mode, public_override.as_deref(), &headers)
                        }
                    }),
                );
            }

            // Local-discovery: synthesized catalog at the IETF well-known
            // path so a local MCP agent's `list_catalog` can pick up the
            // running server's endpoints. Registered + reaped by the
            // ephemeral-source lifecycle below.
            {
                let api_for_catalog = api.clone();
                let public_override = public_url_override.clone();
                let bind = self.bind.clone();
                let has_openapi = openapi_doc.is_some();
                app = app.route(
                    pay_core::skills::local::WELL_KNOWN_PATH,
                    get(move || {
                        let api = api_for_catalog.clone();
                        let public_override = public_override.clone();
                        let bind = bind.clone();
                        async move {
                            let base_url = public_override.unwrap_or_else(|| {
                                format!("http://{}", bind.replace("0.0.0.0", "127.0.0.1"))
                            });
                            let openapi_url = if has_openapi {
                                Some(format!("{}/openapi.json", base_url.trim_end_matches('/')))
                            } else {
                                None
                            };
                            axum::Json(pay_core::skills::local::synthesize_catalog(
                                &api,
                                &base_url,
                                openapi_url.as_deref(),
                            ))
                        }
                    }),
                );
            }

            if let Some(ref pdb) = pdb_state {
                app = app
                    .route(
                        "/",
                        get(|headers: axum::http::HeaderMap| async move {
                            let accepts_html = headers
                                .get("accept")
                                .and_then(|v| v.to_str().ok())
                                .is_some_and(|v| v.contains("text/html"));
                            if accepts_html {
                                axum::response::Redirect::temporary(
                                        &format!("{}/", pay_pdb::PDB_PATH),
                                    )
                                    .into_response()
                            } else {
                                axum::Json(serde_json::json!({"status": "ok"})).into_response()
                            }
                        }),
                    )
                    .nest_service(
                        pay_pdb::PDB_PATH,
                    pay_pdb::debugger_router(pdb.clone()),
                );
            }

            // Captured for the local-skills registration call below — the
            // `fallback` closure takes `api` by move, so we stash the
            // subdomain string out of band first.
            let api_subdomain_for_registration = api.subdomain.clone();
            let app = app
                .fallback(any(move |req: axum::http::Request<axum::body::Body>| {
                    let api = api.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        // 404 for paths not listed in the spec — prevents OAuth2
                        // token fetches for browser auto-requests like /favicon.ico.
                        let path = parts.uri.path().trim_start_matches('/');
                        if pay_core::server::metering::find_endpoint_by_path(&api, path).is_none() {
                            return axum::response::IntoResponse::into_response((
                                axum::http::StatusCode::NOT_FOUND,
                                axum::Json(serde_json::json!({"error": "not_found"})),
                            ));
                        }
                        let session_context = parts
                            .extensions
                            .get::<pay_core::server::session_stream::SessionStreamContext>()
                            .cloned();
                        let bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
                            .await
                            .unwrap_or_default();
                        pay_core::server::proxy::forward_request_with_session_metering(
                            &api,
                            parts.method,
                            &parts.uri,
                            &parts.headers,
                            bytes,
                            session_context,
                        )
                        .await
                        .unwrap_or_else(|e| e)
                    }
                }))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    pay_core::server::payment::payment_middleware::<AppState>,
                ))
                .with_state(state.clone())
                // Logging layer (outermost — executes first).
                // Extension must be added AFTER the middleware layer (LIFO order)
                // so the extension is available when the middleware runs.
                .layer(middleware::from_fn(pay_pdb::logging::logging_middleware))
                .layer(axum::Extension(pdb_state));

            // axum serves the control plane on an internal port; Pingora
            // (`Http402Gate`) fronts the public `self.bind` below, after
            // `block_on` returns (Pingora owns its own runtimes).
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| {
                    pay_core::Error::Config(format!("Failed to bind control-plane: {e}"))
                })?;
            let internal_addr = listener.local_addr().map_err(|e| {
                pay_core::Error::Config(format!("control-plane local_addr: {e}"))
            })?;
            let display_addr = self.bind.replace("0.0.0.0", "127.0.0.1");
            let url = format!("http://{}", display_addr);
            if debugger {
                eprintln!(
                    "  {} {}",
                    "Running Payment debugger".green().bold(),
                    crate::components::link::link_with_arrow(&url, &url),
                );
            } else {
                eprintln!(
                    "  {} {}",
                    "listening".green().bold(),
                    crate::components::link::link_with_arrow(&url, &url),
                );
            }
            eprintln!();

            // ── Local skills registration ──────────────────────────────────
            //
            // Reap dead ephemeral entries from prior crashed `pay server`
            // runs before adding ours, then register this server so any
            // MCP agent on the same host can discover its endpoints via
            // the standard `list_catalog` path. The matching deregister
            // fires on graceful shutdown below.
            let _ = super::local_registration::sweep_dead_ephemeral_sources();
            let registered_source_url = match super::local_registration::register(
                &api_subdomain_for_registration,
                &self.bind,
            ) {
                Ok((name, url)) => {
                    tracing::debug!(
                        name = %name,
                        url = %url,
                        "registered local skills source"
                    );
                    Some(url)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to register local skills source");
                    None
                }
            };

            // Serve the control-plane axum on the runtime's workers; Pingora
            // fronts the public hot path after `block_on` returns. `rt` stays in
            // scope (alive) while Pingora runs, so these workers keep running.
            //
            // NOTE: the local-skills deregister hook no longer fires on shutdown
            // (Pingora's `run_forever` owns the process exit); stale entries are
            // reaped by `sweep_dead_ephemeral_sources()` on the next start.
            let _ = &registered_source_url;
            tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, app).await {
                    tracing::error!(error = %e, "control-plane axum server exited unexpectedly");
                }
            });

            Ok::<(std::net::SocketAddr, AppState), pay_core::Error>((internal_addr, state))
        })?;

        // Pingora owns the public port + the hot path. It manages its own
        // runtimes, so it must run on a thread with no ambient tokio runtime —
        // the main thread, now that `block_on` has returned.
        let (internal_addr, gate_state) = gateway;
        let cores = std::thread::available_parallelism().map(|n| n.get()).ok();
        pay_proxy::run(gate_state, &self.bind, internal_addr.to_string(), cores)
            .map_err(|e| pay_core::Error::Config(format!("gateway: {e}")))
    }
}

/// Wait for the first SIGINT or SIGTERM. Retained for the planned control-plane
/// graceful-shutdown path; Pingora currently owns the process exit, so axum's
/// `with_graceful_shutdown` is no longer wired.
#[allow(dead_code)]
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}

fn spawn_fee_payer_balance_observer(wallet: FeePayerWallet, subdomain: String) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval_at(
            Instant::now() + FEE_PAYER_BALANCE_OBSERVE_INTERVAL,
            FEE_PAYER_BALANCE_OBSERVE_INTERVAL,
        );

        loop {
            interval.tick().await;
            wallet.observe("periodic", &subdomain, "__periodic").await;
        }
    });
}

fn build_endpoints_json(api: &ApiSpec) -> serde_json::Value {
    let endpoints: Vec<serde_json::Value> = api
        .endpoints
        .iter()
        .map(|ep| {
            let mut obj = serde_json::json!({
                "method": format!("{:?}", ep.method).to_uppercase(),
                "path": ep.path,
                "metered": ep.metering.is_some(),
            });
            if let Some(desc) = &ep.description {
                obj["description"] = serde_json::Value::String(desc.clone());
            }
            if let Some(ref m) = ep.metering {
                let price = m
                    .dimensions
                    .first()
                    .map(|d| d.tiers.first().map(|t| t.price_usd).unwrap_or(0.0))
                    .unwrap_or(0.0);
                obj["price_usd"] = serde_json::json!(price);
            }
            obj
        })
        .collect();

    serde_json::json!({
        "name": api.name,
        "title": api.title,
        "forward": {
            "url": api.routing.display_url(),
        },
        "endpoints": endpoints,
    })
}

/// Build the sidebar config for the PDB frontend.
fn build_pdb_config(
    api: &ApiSpec,
    recipient: &str,
    network: &str,
    rpc_url: &str,
) -> serde_json::Value {
    let metered: Vec<serde_json::Value> = api
        .endpoints
        .iter()
        .filter(|e| e.metering.is_some())
        .map(|e| {
            let price = e
                .metering
                .as_ref()
                .and_then(|m| m.dimensions.first())
                .and_then(|d| d.tiers.first())
                .map(|t| format!("${}", format_price(t.price_usd)))
                .unwrap_or_else(|| "metered".into());
            serde_json::json!({
                "method": format!("{:?}", e.method).to_uppercase(),
                "path": e.path,
                "example": example_path(e),
                "price": price,
                "description": e.description.as_deref().unwrap_or(""),
            })
        })
        .collect();

    let free: Vec<serde_json::Value> = api
        .endpoints
        .iter()
        .filter(|e| e.metering.is_none())
        .map(|e| {
            serde_json::json!({
                "method": format!("{:?}", e.method).to_uppercase(),
                "path": e.path,
                "example": example_path(e),
                "price": "free",
                "description": e.description.as_deref().unwrap_or(""),
            })
        })
        .collect();

    serde_json::json!({
        "recipient": recipient,
        "network": network,
        "rpcUrl": rpc_url,
        "endpoints": {
            "mpp": metered,
            "x402": [],
            "oauth": free,
        }
    })
}

/// Serve the configured OpenAPI / Discovery document at `/openapi.json`.
///
/// When the spec's `routing` is `proxy` we rewrite `rootUrl` /
/// `servers[].url` to the public URL of *this* server so callers can drive
/// the proxy directly from the spec. The public URL comes from
/// `--public-url` if set, else from the request's `Host` header.
fn serve_openapi(
    doc: Arc<serde_json::Value>,
    proxy_mode: bool,
    public_override: Option<&str>,
    headers: &axum::http::HeaderMap,
) -> Response {
    let mut out = (*doc).clone();
    // Rewrite `servers[].url` to point at the gateway. In proxy mode this
    // retargets the upstream doc's servers; for a synthesized doc (respond mode)
    // it turns the placeholder `/` into the absolute gateway URL. Harmless when
    // there are no rewritable URLs.
    let _ = proxy_mode;
    let public_url = public_override
        .map(str::to_string)
        .unwrap_or_else(|| derive_public_url_from_host(headers));
    pay_core::server::openapi::rewrite_urls(&mut out, &public_url);
    axum::Json(out).into_response()
}

fn derive_public_url_from_host(headers: &axum::http::HeaderMap) -> String {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:1402");
    // `x-forwarded-proto` if present (Cloud Run sets it to `https`); else
    // assume http for localhost-shaped hosts and https for everything else.
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if host.starts_with("localhost") || host.starts_with("127.0.0.1") {
                "http".to_string()
            } else {
                "https".to_string()
            }
        });
    format!("{scheme}://{host}")
}

async fn browser_rpc_proxy(
    client: reqwest::Client,
    rpc_url: String,
    body: axum::body::Bytes,
) -> Response {
    if let Err(message) = validate_browser_rpc_request(&body) {
        return rpc_proxy_error(axum::http::StatusCode::BAD_REQUEST, message);
    }

    let upstream = match client
        .post(&rpc_url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(error = %error, "Browser RPC proxy request failed");
            return rpc_proxy_error(
                axum::http::StatusCode::BAD_GATEWAY,
                "Payment RPC is unavailable.",
            );
        }
    };

    let status = axum::http::StatusCode::from_u16(upstream.status().as_u16())
        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let bytes = match upstream.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(error = %error, "Browser RPC proxy response read failed");
            return rpc_proxy_error(
                axum::http::StatusCode::BAD_GATEWAY,
                "Payment RPC response could not be read.",
            );
        }
    };

    Response::builder()
        .status(status)
        .header(axum::http::header::CONTENT_TYPE, content_type)
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::from(bytes))
        .unwrap()
}

fn validate_browser_rpc_request(body: &[u8]) -> Result<(), &'static str> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "Payment RPC request must be valid JSON.")?;

    let calls: Vec<&serde_json::Value> = match &value {
        serde_json::Value::Object(_) => vec![&value],
        serde_json::Value::Array(calls) if !calls.is_empty() => calls.iter().collect(),
        _ => return Err("Payment RPC request must be a JSON-RPC object."),
    };

    for call in calls {
        let method = call
            .get("method")
            .and_then(|method| method.as_str())
            .ok_or("Payment RPC request is missing a method.")?;
        if !BROWSER_RPC_ALLOWED_METHODS.contains(&method) {
            return Err("Payment RPC method is not allowed.");
        }
    }

    Ok(())
}

fn rpc_proxy_error(status: axum::http::StatusCode, message: &'static str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({
            "error": "payment_rpc_failed",
            "message": message,
        })),
    )
        .into_response()
}

/// Resolve a currency label to the value used in the MPP challenge.
/// SPL tokens use their mint address; SOL uses "sol".
/// Walk every endpoint with a `subscription:` block, check whether its
/// Plan PDA exists on-chain, and interactively publish missing ones.
///
/// Mutates the supplied `ApiSpec` in place so the returned value has
/// fully-populated `subscription.plan_id` / `plan_id_numeric` /
/// `plan_bump` / `plan_created_at` for every endpoint. Persists the
/// same fields back to `spec_path` on disk via `write_back_published_plans`.
async fn ensure_subscription_plans(
    mut api: ApiSpec,
    spec_path: &str,
    operator_pubkey_str: &str,
    fee_payer_signer: Option<Arc<dyn SolanaSigner>>,
    rpc_url: &str,
) -> pay_core::Result<ApiSpec> {
    use dialoguer::Confirm;
    use dialoguer::theme::ColorfulTheme;
    use pay_core::server::subscription::{
        PlanStatus, check_plan_exists, compute_plan_id_numeric, publish_plan,
    };
    use pay_kit::mpp::program::subscriptions::{default_program_id, find_plan_pda, plan_id_seed};
    use solana_pubkey::Pubkey;

    // Bail early when the spec has no subscription endpoints — keeps the
    // common case (charge / session) zero-overhead at startup.
    if !api.endpoints.iter().any(|ep| ep.subscription.is_some()) {
        return Ok(api);
    }

    // Subscription endpoints emit `WWW-Authenticate` challenges with an
    // HMAC-derived nonce so the `authenticate` verify path stays
    // stateless. The HMAC secret MUST be supplied by the operator —
    // there's no safe silent default, and a server-restart that
    // randomises the secret invalidates every outstanding session
    // token. Fail at boot so the misconfiguration surfaces before any
    // subscriber can hit the broken endpoint.
    if api
        .operator
        .as_ref()
        .and_then(|o| o.challenge_binding_secret.as_deref())
        .is_none_or(str::is_empty)
    {
        return Err(pay_core::Error::Config(format!(
            "subscription endpoints require `operator.challenge_binding_secret` in {spec_path}. \
             Generate one with `openssl rand -hex 32` and paste it under the \
             `operator:` block. The same value must be reused across server \
             restarts — rotating it invalidates every outstanding SIWMPP \
             session token."
        )));
    }

    let operator = Pubkey::from_str(operator_pubkey_str).map_err(|e| {
        pay_core::Error::Config(format!(
            "operator pubkey `{operator_pubkey_str}` is not valid base58: {e}"
        ))
    })?;
    let program_id = default_program_id();

    let mut publications: Vec<pay_core::server::subscription::PublishedPlan> = Vec::new();

    for endpoint in api.endpoints.iter_mut() {
        let Some(sub_spec) = endpoint.subscription.as_mut() else {
            continue;
        };

        // `free_trial_days` is reserved for a future iteration —
        // surface that loudly at boot so an operator who set the
        // field doesn't assume billing will be deferred.
        if let Some(days) = sub_spec.free_trial_days
            && days > 0
        {
            tracing::warn!(
                endpoint = %endpoint.path,
                free_trial_days = days,
                "`subscription.free_trial_days` is set but not honored in v0 — \
                 subscribers will be charged on the first period as usual. \
                 Remove the field from your YAML to silence this warning."
            );
        }

        // Stable id derived from `(operator, endpoint.path)`. Reuse the
        // value persisted in YAML if present so manual edits stick.
        let plan_id_numeric = sub_spec
            .plan_id_numeric
            .unwrap_or_else(|| compute_plan_id_numeric(operator_pubkey_str, &endpoint.path));
        let seed = plan_id_seed(plan_id_numeric);
        let (plan_pda, plan_bump) = find_plan_pda(&operator, &seed, &program_id);

        // Treat a YAML-pinned plan_id that disagrees with our derivation
        // as a configuration error — the operator probably edited the
        // numeric id but not the PDA string (or vice versa).
        if let Some(yaml_plan_id) = sub_spec.plan_id.as_deref()
            && yaml_plan_id != plan_pda.to_string()
        {
            return Err(pay_core::Error::Config(format!(
                "endpoint `{}` has plan_id `{yaml_plan_id}` but \
                 plan_id_numeric={plan_id_numeric} derives to `{plan_pda}`. \
                 Clear plan_id from the YAML and let `pay server start` regenerate it.",
                endpoint.path
            )));
        }

        let status = check_plan_exists(rpc_url, &plan_pda).await?;
        match status {
            PlanStatus::Exists => {
                tracing::info!(
                    endpoint = %endpoint.path,
                    plan = %plan_pda,
                    "subscription Plan already on-chain — reusing",
                );
                sub_spec.plan_id = Some(plan_pda.to_string());
                sub_spec.plan_id_numeric = Some(plan_id_numeric);
                sub_spec.plan_bump = Some(plan_bump);
                // created_at we cannot determine without an extra RPC fetch;
                // leave any existing YAML value untouched. The client falls
                // back to fetching the Plan when this is None.
            }
            PlanStatus::WrongOwner { actual_owner } => {
                return Err(pay_core::Error::Config(format!(
                    "endpoint `{}` derives Plan PDA `{plan_pda}` but that account is \
                     owned by `{actual_owner}` (not the subscriptions program). \
                     Choose a different plan_id_numeric or close the squatting account.",
                    endpoint.path
                )));
            }
            PlanStatus::Missing => {
                let signer = match fee_payer_signer.clone() {
                    Some(s) => s,
                    None => {
                        return Err(pay_core::Error::Config(format!(
                            "endpoint `{}` requires publishing Plan `{plan_pda}` on-chain, but \
                             no operator signer is configured. Set `operator.signer` in the YAML \
                             or run with `--sandbox` for a localnet ephemeral.",
                            endpoint.path
                        )));
                    }
                };

                eprintln!();
                eprintln!(
                    "{} {}",
                    "Subscription endpoint needs an on-chain Plan:".bold(),
                    endpoint.path,
                );
                eprintln!(
                    "  period   {}\n  price    {} {}\n  plan PDA {}",
                    sub_spec.period,
                    sub_spec
                        .price_usd
                        .map(|p| format!("{p:.2}"))
                        .unwrap_or_else(|| sub_spec.amount_base_units.clone().unwrap_or_default()),
                    sub_spec.currency,
                    plan_pda,
                );
                let theme = ColorfulTheme::default();
                let confirmed = Confirm::with_theme(&theme)
                    .with_prompt(
                        "Publish create_plan on-chain now? (costs ~0.001 SOL in rent + fees)",
                    )
                    .default(false)
                    .interact()
                    .map_err(|e| {
                        pay_core::Error::Config(format!("dialoguer prompt failed: {e}"))
                    })?;
                if !confirmed {
                    return Err(pay_core::Error::Config(format!(
                        "operator declined to publish Plan for endpoint `{}` — startup aborted.",
                        endpoint.path
                    )));
                }

                eprintln!("Publishing Plan…");
                let mut published =
                    publish_plan(sub_spec, &operator, signer, rpc_url, plan_id_numeric)
                        .await
                        .map_err(|e| {
                            pay_core::Error::Config(format!(
                                "create_plan broadcast failed for `{}`: {e}",
                                endpoint.path
                            ))
                        })?;
                published.endpoint_path = endpoint.path.clone();
                eprintln!(
                    "  {} {}",
                    "✓".green(),
                    format!(
                        "Plan {} published (tx {})",
                        published.plan_pda,
                        published
                            .broadcast_signature
                            .as_deref()
                            .unwrap_or("<existing>")
                    )
                    .dimmed()
                );

                sub_spec.plan_id = Some(published.plan_pda.clone());
                sub_spec.plan_id_numeric = Some(published.plan_id_numeric);
                sub_spec.plan_bump = Some(published.plan_bump);
                sub_spec.plan_created_at = Some(published.plan_created_at);
                publications.push(published);
            }
        }
    }

    // Persist any new plan IDs back to disk so subsequent restarts skip
    // the publish prompt and the subscriber client picks up the same PDA.
    if !publications.is_empty() {
        let expanded = shellexpand::tilde(spec_path);
        let raw = std::fs::read_to_string(expanded.as_ref()).map_err(|e| {
            pay_core::Error::Config(format!(
                "Failed to re-read spec {} for write-back: {e}",
                spec_path
            ))
        })?;
        let updated = write_back_published_plans(&raw, &publications);
        std::fs::write(expanded.as_ref(), updated).map_err(|e| {
            pay_core::Error::Config(format!("Failed to write spec {}: {e}", spec_path))
        })?;
    }

    Ok(api)
}

/// In-place YAML rewrite of `plan_id` / `plan_id_numeric` / `plan_bump`
/// / `plan_created_at` under each freshly-published subscription block.
/// Preserves comments and key ordering — line-based rewrite rather than
/// a full serde round-trip.
fn write_back_published_plans(
    yaml: &str,
    publications: &[pay_core::server::subscription::PublishedPlan],
) -> String {
    use std::collections::HashMap;
    // Lookup by endpoint path.
    let by_path: HashMap<&str, &pay_core::server::subscription::PublishedPlan> = publications
        .iter()
        .map(|p| (p.endpoint_path.as_str(), p))
        .collect();

    let mut out = String::with_capacity(yaml.len() + 512);
    let mut current_path: Option<String> = None;
    let mut current_published: Option<&pay_core::server::subscription::PublishedPlan> = None;
    let mut inside_subscription = false;
    let mut subscription_indent: Option<usize> = None;
    let mut wrote_fields = false;

    for line in yaml.lines() {
        let stripped = line.trim_start();
        let indent = line.len() - stripped.len();

        // Track current endpoint via `path:`.
        if let Some(rest) = stripped.strip_prefix("path:") {
            let path_value = rest.trim().trim_matches('"').trim_matches('\'').to_string();
            current_published = by_path.get(path_value.as_str()).copied();
            current_path = Some(path_value);
            inside_subscription = false;
            subscription_indent = None;
            wrote_fields = false;
        } else if stripped.starts_with("subscription:") {
            inside_subscription = true;
            subscription_indent = Some(indent);
        } else if inside_subscription
            && let Some(block_indent) = subscription_indent
            && indent > block_indent
        {
            // Drop any pre-existing entries for the fields we're about to (re)write.
            if let Some(published) = current_published {
                let trimmed = stripped.trim_end();
                if trimmed.starts_with("plan_id:")
                    || trimmed.starts_with("plan_id_numeric:")
                    || trimmed.starts_with("plan_bump:")
                    || trimmed.starts_with("plan_created_at:")
                {
                    // Skip the existing line; we'll emit fresh ones below
                    // when we leave the subscription block.
                    let _ = published;
                    continue;
                }
            }
        } else if inside_subscription
            && let Some(block_indent) = subscription_indent
            && indent <= block_indent
            && !stripped.is_empty()
            && !stripped.starts_with('#')
        {
            // Leaving the subscription block — emit the published fields
            // immediately before the closing line.
            if let Some(published) = current_published
                && !wrote_fields
            {
                let field_indent = " ".repeat(block_indent + 2);
                out.push_str(&field_indent);
                out.push_str("plan_id: ");
                out.push_str(&published.plan_pda);
                out.push('\n');
                out.push_str(&field_indent);
                out.push_str("plan_id_numeric: ");
                out.push_str(&published.plan_id_numeric.to_string());
                out.push('\n');
                out.push_str(&field_indent);
                out.push_str("plan_bump: ");
                out.push_str(&published.plan_bump.to_string());
                out.push('\n');
                out.push_str(&field_indent);
                out.push_str("plan_created_at: ");
                out.push_str(&published.plan_created_at.to_string());
                out.push('\n');
                wrote_fields = true;
            }
            inside_subscription = false;
            subscription_indent = None;
        }

        out.push_str(line);
        out.push('\n');
    }

    // Trailing subscription block at EOF.
    if inside_subscription
        && let Some(published) = current_published
        && !wrote_fields
        && let Some(block_indent) = subscription_indent
    {
        let field_indent = " ".repeat(block_indent + 2);
        out.push_str(&field_indent);
        out.push_str("plan_id: ");
        out.push_str(&published.plan_pda);
        out.push('\n');
        out.push_str(&field_indent);
        out.push_str("plan_id_numeric: ");
        out.push_str(&published.plan_id_numeric.to_string());
        out.push('\n');
        out.push_str(&field_indent);
        out.push_str("plan_bump: ");
        out.push_str(&published.plan_bump.to_string());
        out.push('\n');
        out.push_str(&field_indent);
        out.push_str("plan_created_at: ");
        out.push_str(&published.plan_created_at.to_string());
        out.push('\n');
    }

    let _ = current_path;
    out
}

fn resolve_operator_currencies(op: Option<&OperatorConfig>, cli_currency: &str) -> Vec<String> {
    let configured = op
        .and_then(|operator| operator.currencies.get("usd"))
        .filter(|currencies| !currencies.is_empty())
        .cloned()
        .unwrap_or_else(|| vec![cli_currency.to_string()]);

    let mut deduped = Vec::new();
    for currency in configured {
        let currency = currency.trim();
        if currency.is_empty() {
            continue;
        }
        if !deduped
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(currency))
        {
            deduped.push(currency.to_string());
        }
    }

    if deduped.is_empty() {
        vec![cli_currency.to_string()]
    } else {
        deduped
    }
}

/// Create a SolanaSigner from the operator.signer config.
///
/// Production wrapper around [`resolve_signer_with_store`] that uses the
/// real on-disk accounts file. Tests use the lower-level function with a
/// `MemoryAccountsStore` so they don't touch `~/.config/pay/accounts.yml`.
///
/// Must be called from within the main async runtime so the GCP auth
/// token cache's background refresh tasks stay alive.
async fn resolve_signer(config: &SignerConfig) -> pay_core::Result<Arc<dyn SolanaSigner>> {
    let store = pay_core::accounts::FileAccountsStore::default_path();
    resolve_signer_with_store(config, &store).await
}

/// Testable core: same as [`resolve_signer`] but takes the accounts
/// store as a parameter.
///
/// Handles all `SignerConfig` variants. The GCP KMS branch is feature-
/// gated because it pulls in the gcp-auth crate; the Account and File
/// branches need no extra build features.
async fn resolve_signer_with_store(
    config: &SignerConfig,
    store: &dyn AccountsStore,
) -> pay_core::Result<Arc<dyn SolanaSigner>> {
    match config {
        #[cfg(feature = "gcp_kms")]
        SignerConfig::GcpKms { key_name, pubkey } => {
            let signer =
                pay_kit::mpp::solana_keychain::GcpKmsSigner::new(key_name.clone(), pubkey.clone())
                    .await
                    .map_err(|e| {
                        pay_core::Error::Config(format!("Failed to create GCP KMS signer: {e}"))
                    })?;
            Ok(Arc::new(signer))
        }
        #[cfg(not(feature = "gcp_kms"))]
        SignerConfig::GcpKms { .. } => Err(pay_core::Error::Config(
            "operator.signer.backend = gcp-kms requires the `gcp_kms` build feature. \
             Rebuild pay with `cargo build --features gcp_kms`, or use `backend: env`, \
             `backend: account`, or `backend: file` instead."
                .to_string(),
        )),
        SignerConfig::Account { name } => {
            // Resolve through the accounts file. For keychain-backed
            // accounts this triggers the OS auth prompt ONCE here (at
            // server startup), then the loaded signer is reused for
            // every payment — no per-request prompt.
            //
            // Search mainnet first, then any other network, for the
            // named account.
            let file = store.load()?;
            let (network, account) = file
                .accounts
                .get(pay_core::accounts::MAINNET_NETWORK)
                .and_then(|net| {
                    net.get(name)
                        .map(|account| (pay_core::accounts::MAINNET_NETWORK, account))
                })
                .or_else(|| {
                    file.accounts.iter().find_map(|(network, net)| {
                        net.get(name).map(|account| (network.as_str(), account))
                    })
                })
                .ok_or_else(|| {
                    pay_core::Error::Config(format!(
                        "operator.signer.name = `{name}` does not exist in \
                         ~/.config/pay/accounts.yml. Run `pay account ls` to see \
                         available accounts, or `pay setup` to create one."
                    ))
                })?;
            // Use the Account's load path so ephemeral entries work too.
            let signer = if account.keystore == pay_core::accounts::Keystore::Ephemeral {
                let bytes = account.ephemeral_keypair_bytes().ok_or_else(|| {
                    pay_core::Error::Config(format!(
                        "Account `{name}` is ephemeral but has no inline secret_key_b58"
                    ))
                })?;
                pay_kit::mpp::solana_keychain::MemorySigner::from_bytes(&bytes).map_err(|e| {
                    pay_core::Error::Config(format!("Invalid keypair bytes for `{name}`: {e}"))
                })?
            } else {
                let intent = pay_core::keystore::AuthIntent::use_gateway_fee_payer();
                pay_core::signer::load_signer_from_account_with_intent(
                    account, name, network, &intent,
                )?
            };
            Ok(Arc::new(signer))
        }
        SignerConfig::File { path } => {
            let expanded = shellexpand::tilde(path).into_owned();
            let intent = pay_core::keystore::AuthIntent::use_gateway_fee_payer();
            let signer =
                pay_core::signer::load_signer_with_intent(&expanded, &intent).map_err(|e| {
                    pay_core::Error::Config(format!(
                        "operator.signer.path = `{path}` could not be loaded: {e}.\n\n\
                     Expected a Solana CLI keypair file (a JSON array of exactly \
                     64 bytes: 32 bytes secret + 32 bytes public key).\n\n\
                     Generate one with `solana-keygen new -o {path}`."
                    ))
                })?;
            Ok(Arc::new(signer))
        }
        SignerConfig::Env { value_from_env } => {
            let signer = load_env_keypair_signer(value_from_env)?;
            Ok(Arc::new(signer))
        }
    }
}

fn load_env_keypair_signer(
    value_from_env: &str,
) -> pay_core::Result<pay_kit::mpp::solana_keychain::MemorySigner> {
    let raw = std::env::var(value_from_env).map_err(|error| match error {
        std::env::VarError::NotPresent => pay_core::Error::Config(format!(
            "operator.signer.value_from_env = `{value_from_env}` is not set"
        )),
        std::env::VarError::NotUnicode(_) => pay_core::Error::Config(format!(
            "operator.signer.value_from_env = `{value_from_env}` is not valid Unicode"
        )),
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(pay_core::Error::Config(format!(
            "operator.signer.value_from_env = `{value_from_env}` is empty"
        )));
    }

    let keypair = parse_env_keypair(trimmed, value_from_env)?;
    pay_kit::mpp::solana_keychain::MemorySigner::from_bytes(&keypair).map_err(|e| {
        pay_core::Error::Config(format!(
            "operator.signer.value_from_env = `{value_from_env}` could not be decoded as a Solana keypair: {e}"
        ))
    })
}

fn parse_env_keypair(input: &str, value_from_env: &str) -> pay_core::Result<Vec<u8>> {
    let bytes = if input.starts_with('[') {
        serde_json::from_str::<Vec<u8>>(input).map_err(|e| {
            pay_core::Error::Config(format!(
                "operator.signer.value_from_env = `{value_from_env}` contains invalid keypair JSON: {e}"
            ))
        })?
    } else {
        bs58::decode(input).into_vec().map_err(|e| {
            pay_core::Error::Config(format!(
                "operator.signer.value_from_env = `{value_from_env}` contains invalid base58 keypair: {e}"
            ))
        })?
    };

    if bytes.len() != 64 {
        return Err(pay_core::Error::Config(format!(
            "operator.signer.value_from_env = `{value_from_env}` must decode to exactly 64 bytes, got {}",
            bytes.len()
        )));
    }

    Ok(bytes)
}

/// Build a concrete, clickable example path for an endpoint whose `path`
/// may contain `{placeholder}` segments.
///
/// Browsers percent-encode `{` and `}`, so a templated link like
/// `/v1/models/{model}/infer` arrives as `/v1/models/%7Bmodel%7D/infer`
/// and shows up mangled in the debugger (and never matches a real
/// variant). We substitute each placeholder with a concrete sample:
///   - the first variant's `value` for the segment that follows a
///     `models`/`voices` selector (the variant-selection convention), else
///   - the placeholder's own name with the braces stripped, as a neutral
///     URL-safe sample.
///
/// Partial segments such as `{model}:infer` keep their suffix (→
/// `fast:infer`). Endpoints with no placeholders are returned unchanged.
fn example_path(ep: &pay_types::metering::Endpoint) -> String {
    let first_variant_value = ep
        .metering
        .as_ref()
        .and_then(|m| m.variants.first())
        .map(|v| v.value.as_str());

    let segs: Vec<&str> = ep.path.split('/').collect();
    let mut out: Vec<String> = Vec::with_capacity(segs.len());
    for (i, seg) in segs.iter().enumerate() {
        if !seg.contains('{') {
            out.push((*seg).to_string());
            continue;
        }
        let open = seg.find('{').unwrap();
        let prefix = &seg[..open];
        let rest = &seg[open + 1..];
        let (name, suffix) = match rest.find('}') {
            Some(close) => (&rest[..close], &rest[close + 1..]),
            None => (rest, ""),
        };
        let follows_selector = i > 0 && matches!(segs[i - 1], "models" | "voices");
        let sample = match (follows_selector, first_variant_value) {
            // Variant values come from config and may contain reserved URL
            // characters (`/`, `?`, `#`, ` `, `%`); encode as a single path
            // segment so the link/curl target the intended route.
            (true, Some(value)) => urlencoding::encode(value).into_owned(),
            _ => name.to_string(),
        };
        out.push(format!("{prefix}{sample}{suffix}"));
    }
    out.join("/")
}

/// Representative price for a set of pricing dimensions: the first
/// tier of the first dimension. Mirrors the single-price heuristic used
/// for direct-metered endpoints so variant rows read consistently.
fn first_tier_price(dims: &[pay_types::metering::MeterDimension]) -> f64 {
    dims.first()
        .and_then(|d| d.tiers.first())
        .map(|t| t.price_usd)
        .unwrap_or(0.0)
}

fn format_price(price: f64) -> String {
    if price.fract() == 0.0 {
        format!("{}", price as u64)
    } else {
        let s = format!("{:.4}", price);
        s.trim_end_matches('0').to_string()
    }
}

/// Emit an OSC 8 clickable hyperlink for terminals that support it.

// ── Gateway verify endpoint ──

#[derive(serde::Deserialize)]
struct GatewayVerifyRequest {
    method: String,
    path: String,
    price: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    authorization: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    request_id: Option<String>,
    #[serde(default)]
    external_id: Option<String>,
    /// JSON-encoded splits array from the gateway (assembled by JS policy).
    #[serde(default)]
    splits_json: Option<String>,
}

#[derive(serde::Serialize)]
struct GatewayVerifyResponse {
    decision: String,
    status_code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    www_authenticate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    www_authenticate_headers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionDeliveryRequest {
    session_id: String,
    amount: String,
    #[serde(default)]
    delivery_id: Option<String>,
    #[serde(default)]
    commit_url: Option<String>,
    #[serde(default)]
    proof: Option<String>,
    #[serde(default)]
    expires_at: Option<i64>,
}

/// Payment-channel settle-receipt poll
/// (`GET /__402/payment-channels/receipt/:channelId`): `{ settledSignature,
/// finalized }` for a channel. Clients poll this until `settledSignature` is
/// non-null to render the on-chain receipt URL (payment-channel sessions settle
/// out-of-band at idle-close, so there's no per-request header).
fn session_receipt(state: AppState, channel_id: String) -> axum::response::Response {
    let signature = state
        .session_mpps
        .iter()
        .find_map(|session| session.settlement_signature(&channel_id));
    axum::Json(serde_json::json!({
        "settledSignature": signature,
        "finalized": signature.is_some(),
    }))
    .into_response()
}

/// Abort launch if a statically-known split recipient is not a valid address.
/// Runtime `${VAR}` recipients may resolve from request query parameters, so an
/// unset env var here means the account must be checked when a request uses it.
fn ensure_static_split_recipient_accounts_valid(
    api: &pay_types::metering::ApiSpec,
) -> Result<(), pay_core::Error> {
    for ep in &api.endpoints {
        let Some(meter) = ep.metering.as_ref() else {
            continue;
        };
        for rule in pay_core::server::metering::resolve_split_rules(meter) {
            let endpoint = ep.path.as_str();
            let recipient = rule.recipient.as_str();
            let Some(alias) = api.recipients.get(recipient) else {
                return Err(pay_core::Error::Config(format!(
                    "{endpoint}: split recipient '{recipient}' not declared"
                )));
            };
            let Some(account) = resolve_startup_payout_account(&alias.account)? else {
                continue;
            };
            solana_pubkey::Pubkey::from_str(&account).map_err(|e| {
                pay_core::Error::Config(format!(
                    "{endpoint}: split recipient '{recipient}' account is not a valid Solana pubkey: {e}"
                ))
            })?;
        }
    }
    Ok(())
}

async fn reserve_session_delivery(
    state: AppState,
    req: SessionDeliveryRequest,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use pay_kit::mpp::server::session::DeliveryRequest;

    if state.session_mpps.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": "session_not_configured",
                "message": "This gateway is not configured for session payments",
            })),
        )
            .into_response();
    }

    let Some(session_mpp) = state
        .session_mpps
        .iter()
        .find(|session| session.committed_watermark(&req.session_id).is_some())
    else {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "error": "session_not_found",
                "message": "No active session matches the supplied session ID",
            })),
        )
            .into_response();
    };

    let amount = match req.amount.parse::<u64>() {
        Ok(amount) if amount > 0 => amount,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "invalid_amount",
                    "message": "amount must be a positive base-unit integer",
                })),
            )
                .into_response();
        }
    };

    let mut delivery = DeliveryRequest::new(req.session_id, amount);
    delivery.delivery_id = req.delivery_id;
    delivery.commit_url = req.commit_url;
    delivery.proof = req.proof;
    delivery.expires_at = req.expires_at;

    match session_mpp.begin_delivery(delivery).await {
        Ok(directive) => axum::Json(directive).into_response(),
        Err(error) => (
            StatusCode::PAYMENT_REQUIRED,
            axum::Json(serde_json::json!({
                "error": "delivery_reservation_failed",
                "message": error.to_string(),
            })),
        )
            .into_response(),
    }
}

async fn gateway_verify(
    mpps: Vec<Mpp>,
    req: GatewayVerifyRequest,
    pdb: Option<&pay_pdb::PdbState>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use pay_kit::mpp::{format_receipt, format_www_authenticate_many, parse_authorization};

    let auth = req
        .authorization
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());

    // Parse splits from JSON string (assembled by Apigee JS policy).
    let splits: Vec<pay_kit::mpp::protocol::solana::Split> = req
        .splits_json
        .as_deref()
        .filter(|s| !s.is_empty() && *s != "[]")
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    match auth {
        None => {
            let challenges = match gateway_charge_challenges(&mpps, &req, splits.clone()) {
                Ok(challenges) => challenges,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(serde_json::json!({"error": e.to_string()})),
                    )
                        .into_response();
                }
            };
            let www_auths = format_www_authenticate_many(&challenges).unwrap_or_default();
            let first_www_auth = www_auths.first().cloned().unwrap_or_default();

            // Log 402 challenge to PDB
            if let Some(pdb) = pdb {
                let mut res_headers = std::collections::HashMap::new();
                res_headers.insert("www-authenticate".to_string(), www_auths.join("\n"));
                let entry = pay_pdb::types::LogEntry {
                    id: pdb.next_log_id(),
                    ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    method: req.method.clone(),
                    path: req.path.clone(),
                    status: 402,
                    ms: 0,
                    req_headers: std::collections::HashMap::new(),
                    res_headers,
                    res_body: None,
                    client_ip: "gateway".to_string(),
                };
                pdb.correlation.lock().unwrap().ingest(entry);
            }

            axum::Json(GatewayVerifyResponse {
                decision: "payment_required".to_string(),
                status_code: 402,
                www_authenticate: Some(first_www_auth),
                www_authenticate_headers: Some(www_auths),
                body: Some(serde_json::json!({
                    "error": "payment_required",
                    "endpoint": { "method": req.method, "path": req.path },
                })),
                challenge_id: challenges.first().map(|challenge| challenge.id.clone()),
                external_id: req.external_id,
                receipt: None,
                receipt_status: None,
                receipt_reference: None,
            })
            .into_response()
        }
        Some(auth_value) => {
            let credential = match parse_authorization(auth_value) {
                Ok(c) => c,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({"error": e.to_string()})),
                    )
                        .into_response();
                }
            };
            let mut last_error = None;
            for mpp in &mpps {
                // Audit #2: verify against the request this route would issue
                // (rebuilt from the gateway's own price + splits), not the
                // values echoed in the client's credential.
                let expected: pay_kit::mpp::ChargeRequest = match mpp.charge_with_options(
                    &req.price,
                    pay_kit::mpp::server::ChargeOptions {
                        description: req.description.as_deref(),
                        external_id: req.external_id.as_deref(),
                        splits: splits.clone(),
                        ..Default::default()
                    },
                ) {
                    Ok(challenge) => match challenge.request.decode() {
                        Ok(r) => r,
                        Err(e) => {
                            last_error = Some(pay_kit::mpp::server::VerificationError::new(
                                format!("failed to decode expected charge request: {e}"),
                            ));
                            continue;
                        }
                    },
                    Err(e) => {
                        last_error = Some(pay_kit::mpp::server::VerificationError::new(format!(
                            "failed to rebuild expected charge challenge: {e}"
                        )));
                        continue;
                    }
                };
                match mpp
                    .verify_credential_with_expected(&credential, &expected)
                    .await
                {
                    Ok(receipt) => {
                        let kind = pay_kit::mpp::ReceiptKind::Charge(receipt);
                        let encoded = format_receipt(&kind).unwrap_or_default();
                        // Pull the underlying Receipt out for the legacy
                        // PDB logging path that still operates on the
                        // intent-agnostic shape.
                        let receipt = match &kind {
                            pay_kit::mpp::ReceiptKind::Charge(r) => r.clone(),
                            // The charge verify path never produces a
                            // Subscription kind; this arm is unreachable.
                            pay_kit::mpp::ReceiptKind::Subscription { base, .. } => base.clone(),
                        };

                        // Log successful payment to PDB
                        if let Some(pdb) = pdb {
                            let mut req_headers = std::collections::HashMap::new();
                            req_headers.insert(
                                "authorization".to_string(),
                                format!("Payment {}", auth_value),
                            );
                            let entry = pay_pdb::types::LogEntry {
                                id: pdb.next_log_id(),
                                ts: chrono::Utc::now()
                                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                                method: req.method.clone(),
                                path: req.path.clone(),
                                status: 200,
                                ms: 0,
                                req_headers,
                                res_headers: std::collections::HashMap::new(),
                                res_body: None,
                                client_ip: "gateway".to_string(),
                            };
                            pdb.correlation.lock().unwrap().ingest(entry);
                        }

                        return axum::Json(GatewayVerifyResponse {
                            decision: "allow".to_string(),
                            status_code: 200,
                            receipt: Some(encoded),
                            receipt_status: Some(receipt.status.to_string()),
                            receipt_reference: Some(receipt.reference),
                            challenge_id: Some(receipt.challenge_id),
                            external_id: req.external_id,
                            www_authenticate: None,
                            www_authenticate_headers: None,
                            body: Some(serde_json::json!({"pdb_active": pdb.is_some()})),
                        })
                        .into_response();
                    }
                    Err(error) => last_error = Some(error),
                }
            }

            let error = last_error.unwrap_or_else(|| {
                pay_kit::mpp::server::VerificationError::new("MPP not configured")
            });
            let message = pay_core::server::payment::readable_verification_message(&error);
            // Re-issue challenge on failure
            let challenges = gateway_charge_challenges(&mpps, &req, splits).unwrap_or_default();
            let www_auths = format_www_authenticate_many(&challenges).unwrap_or_default();
            axum::Json(GatewayVerifyResponse {
                decision: "payment_required".to_string(),
                status_code: 402,
                www_authenticate: www_auths.first().cloned(),
                www_authenticate_headers: Some(www_auths),
                body: Some(serde_json::json!({
                    "error": "verification_failed",
                    "message": message,
                    "retryable": error.retryable,
                })),
                challenge_id: challenges.first().map(|challenge| challenge.id.clone()),
                external_id: req.external_id,
                receipt: None,
                receipt_status: Some("failed".to_string()),
                receipt_reference: None,
            })
            .into_response()
        }
    }
}

fn gateway_charge_challenges(
    mpps: &[Mpp],
    req: &GatewayVerifyRequest,
    splits: Vec<pay_kit::mpp::protocol::solana::Split>,
) -> Result<Vec<pay_kit::mpp::PaymentChallenge>, pay_kit::mpp::Error> {
    mpps.iter()
        .map(|mpp| {
            mpp.charge_with_options(
                &req.price,
                pay_kit::mpp::server::ChargeOptions {
                    description: req.description.as_deref(),
                    external_id: req.external_id.as_deref(),
                    splits: splits.clone(),
                    ..Default::default()
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::payments::{
        PayoutRecipientTarget, create_associated_token_account_idempotent_ix, resolve_currency,
        should_use_auto_fee_payer_signer, stable_token_account_requirements,
        surfpool_funding_targets, surfpool_prep_notice_body,
    };
    use super::{
        build_pdb_config, default_bind, delegated_session_channel_payout, payout_recipient_pubkeys,
        payout_recipient_targets, resolve_operator_currencies, validate_browser_rpc_request,
        x402_currency_configs, x402_upto_beneficiary_pubkey, x402_upto_payout_for_recipient,
    };
    use crate::network::SolanaNetwork;
    use serial_test::serial;
    use solana_pubkey::Pubkey;
    use std::str::FromStr;

    #[test]
    fn profile_yaml_expands_before_startup_validation() {
        let api = pay_core::server::profiles::load_yaml(
            r#"
name: local-ai
subdomain: local-ai
title: Local AI
description: OpenAI-compatible local inference.
category: ai_ml
version: v1
profile:
  type: openai-compatible
  version: v1
routing:
  type: proxy
  url: http://127.0.0.1:8000
"#,
        )
        .unwrap();

        let paths: Vec<_> = api
            .endpoints
            .iter()
            .map(|endpoint| endpoint.path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "v1/responses",
                "v1/chat/completions",
                "v1/embeddings",
                "v1/models",
            ]
        );
        assert!(pay_types::metering::validate_api_spec(&api).is_empty());
    }

    #[test]
    fn resolve_operator_currencies_prefers_usd_group() {
        let op: pay_types::metering::OperatorConfig = serde_yml::from_str(
            r#"
currencies:
  usd: ["USDC", "USDT", "CASH"]
"#,
        )
        .unwrap();

        assert_eq!(
            resolve_operator_currencies(Some(&op), "PYUSD"),
            ["USDC", "USDT", "CASH"]
        );
    }

    #[test]
    fn resolve_operator_currencies_falls_back_to_cli_currency() {
        let op: pay_types::metering::OperatorConfig =
            serde_yml::from_str(r#"network: "devnet""#).unwrap();

        assert_eq!(resolve_operator_currencies(Some(&op), "USDC"), ["USDC"]);
    }

    #[test]
    #[serial]
    fn default_bind_uses_port_env_when_present() {
        let previous = std::env::var("PORT").ok();
        unsafe { std::env::set_var("PORT", "8080") };

        assert_eq!(default_bind(), "0.0.0.0:8080");

        match previous {
            Some(value) => unsafe { std::env::set_var("PORT", value) },
            None => unsafe { std::env::remove_var("PORT") },
        }
    }

    #[test]
    #[serial]
    fn default_bind_ignores_invalid_port_env() {
        let previous = std::env::var("PORT").ok();
        unsafe { std::env::set_var("PORT", "not-a-port") };

        assert_eq!(default_bind(), "0.0.0.0:1402");

        match previous {
            Some(value) => unsafe { std::env::set_var("PORT", value) },
            None => unsafe { std::env::remove_var("PORT") },
        }
    }

    #[test]
    fn surfpool_funding_targets_include_distinct_operator_and_recipient() {
        let operator = VALID_TEST_KEYPAIR_PUBKEY;
        let recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";

        let targets = surfpool_funding_targets(recipient, Some(operator));

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].label, "operator signer");
        assert_eq!(targets[0].address, operator);
        assert!(targets[0].requires_sol);
        assert_eq!(targets[1].label, "payment recipient");
        assert_eq!(targets[1].address, recipient);
        assert!(!targets[1].requires_sol);
    }

    #[test]
    fn surfpool_funding_targets_dedupes_operator_recipient() {
        let targets =
            surfpool_funding_targets(VALID_TEST_KEYPAIR_PUBKEY, Some(VALID_TEST_KEYPAIR_PUBKEY));

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].label, "operator signer");
        assert_eq!(targets[0].address, VALID_TEST_KEYPAIR_PUBKEY);
        assert!(targets[0].requires_sol);
    }

    #[test]
    fn surfpool_prep_notice_body_names_wallet_and_ata_work() {
        let targets =
            surfpool_funding_targets("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY", None);
        let payout_recipients = vec![
            PayoutRecipientTarget {
                label: "x402-upto beneficiary".to_string(),
                pubkey: Pubkey::from_str("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY").unwrap(),
            },
            PayoutRecipientTarget {
                label: "split recipient partner (Partner)".to_string(),
                pubkey: Pubkey::from_str("mandyRKj8mvxhuk9Np7pJEXd7BjoEZZNRFxUTpDFeAp").unwrap(),
            },
        ];
        let stable_requirements = stable_token_account_requirements(
            &[
                (
                    "USDC".to_string(),
                    pay_types::Stablecoin::Usdc
                        .mint(Some("localnet"))
                        .to_string(),
                    6,
                ),
                (
                    "PYUSD".to_string(),
                    pay_types::Stablecoin::Pyusd
                        .mint(Some("localnet"))
                        .to_string(),
                    6,
                ),
            ],
            "localnet",
        )
        .unwrap();

        let body = surfpool_prep_notice_body(
            "https://402.surfnet.dev:8899",
            &targets,
            &payout_recipients,
            &stable_requirements,
            true,
        );

        assert!(body.contains("rpc: https://402.surfnet.dev:8899"));
        assert!(body.contains("checking payment recipient (SOL optional)"));
        assert!(body.contains(
            "creating missing ATAs for all configured stable tokens (USDC, PYUSD) across 2 payout recipient(s)"
        ));
        assert!(
            body.contains("x402-upto beneficiary: CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY")
        );
        assert!(body.contains(
            "split recipient partner (Partner): mandyRKj8mvxhuk9Np7pJEXd7BjoEZZNRFxUTpDFeAp"
        ));
    }

    #[test]
    fn stable_token_account_requirements_resolve_stable_mints_and_programs() {
        let configs = vec![
            resolve_currency("USDC", "localnet"),
            resolve_currency("PYUSD", "localnet"),
            resolve_currency("SOL", "localnet"),
        ]
        .into_iter()
        .zip(["USDC", "PYUSD", "SOL"])
        .map(|((mint, decimals), label)| (label.to_string(), mint, decimals))
        .collect::<Vec<_>>();

        let requirements = stable_token_account_requirements(&configs, "localnet").unwrap();

        assert_eq!(requirements.len(), 2);
        assert!(requirements.iter().any(|req| {
            req.label == "USDC"
                && req.mint == pay_types::Stablecoin::Usdc.mint(Some("localnet"))
                && req.token_program == pay_kit::mpp::protocol::solana::programs::TOKEN_PROGRAM
        }));
        assert!(requirements.iter().any(|req| {
            req.label == "PYUSD"
                && req.mint == pay_types::Stablecoin::Pyusd.mint(Some("localnet"))
                && req.token_program == pay_kit::mpp::protocol::solana::programs::TOKEN_2022_PROGRAM
        }));
    }

    #[test]
    fn payout_recipient_pubkeys_collects_mpp_charge_splits() {
        let api: pay_types::metering::ApiSpec = serde_yml::from_str(
            r#"
name: splits-demo
subdomain: splits-demo
title: Splits Demo
description: Splits Demo
category: finance
version: v1
routing:
  type: respond
recipients:
  partner:
    account: mandyRKj8mvxhuk9Np7pJEXd7BjoEZZNRFxUTpDFeAp
endpoints:
  - method: POST
    path: v1/report
    metering:
      schemes: [mpp-charge]
      dimensions:
        - direction: usage
          unit: requests
          scale: 1
          tiers:
            - price_usd: 0.10
      splits:
        - recipient: partner
          percent: 20
  - method: POST
    path: v1/exact
    metering:
      schemes: [x402-exact]
      dimensions:
        - direction: usage
          unit: requests
          scale: 1
          tiers:
            - price_usd: 0.10
      splits:
        - recipient: partner
          percent: 20
"#,
        )
        .unwrap();

        let targets = payout_recipient_targets(&api, None).unwrap();
        let recipients = payout_recipient_pubkeys(&targets);

        assert_eq!(recipients.len(), 1);
        assert_eq!(
            recipients[0].to_string(),
            "mandyRKj8mvxhuk9Np7pJEXd7BjoEZZNRFxUTpDFeAp"
        );
        assert_eq!(targets[0].label, "split recipient partner");
    }

    #[test]
    fn payout_recipient_pubkeys_skip_unresolved_runtime_split_recipients() {
        let env_var = format!("PAY_TEST_UNSET_DYNAMIC_SPLIT_WALLET_{}", std::process::id());
        // SAFETY: this test uses a process-unique variable name and does not
        // depend on any other environment state.
        unsafe { std::env::remove_var(&env_var) };
        let spec = format!(
            r#"
name: runtime-splits-demo
subdomain: runtime-splits-demo
title: Runtime Splits Demo
description: Runtime Splits Demo
category: finance
version: v1
routing:
  type: respond
recipients:
  partner:
    account: mandyRKj8mvxhuk9Np7pJEXd7BjoEZZNRFxUTpDFeAp
  affiliate:
    account: "${{{env_var}}}"
endpoints:
  - method: POST
    path: v1/referral
    metering:
      schemes: [mpp-charge]
      dimensions:
        - direction: usage
          unit: requests
          scale: 1
          tiers:
            - price_usd: 1.00
      splits:
        - recipient: partner
          percent: 20
        - recipient: affiliate
          percent: 10
"#
        );
        let api: pay_types::metering::ApiSpec = serde_yml::from_str(&spec).unwrap();

        let targets = payout_recipient_targets(&api, None).unwrap();
        let recipients = payout_recipient_pubkeys(&targets);

        assert_eq!(recipients.len(), 1);
        assert_eq!(
            recipients[0].to_string(),
            "mandyRKj8mvxhuk9Np7pJEXd7BjoEZZNRFxUTpDFeAp"
        );
        assert_eq!(targets[0].label, "split recipient partner");
    }

    #[test]
    fn payout_recipient_pubkeys_includes_x402_upto_beneficiary() {
        let api: pay_types::metering::ApiSpec = serde_yml::from_str(
            r#"
name: upto-demo
subdomain: upto-demo
title: Upto Demo
description: Upto Demo
category: finance
version: v1
routing:
  type: respond
recipients:
  partner:
    account: mandyRKj8mvxhuk9Np7pJEXd7BjoEZZNRFxUTpDFeAp
endpoints:
  - method: POST
    path: v1/report
    metering:
      schemes: [mpp-charge, x402-upto]
      dimensions:
        - direction: usage
          unit: requests
          scale: 1
          tiers:
            - price_usd: 0.10
      splits:
        - recipient: partner
          percent: 20
"#,
        )
        .unwrap();
        let x402_recipient =
            Pubkey::from_str("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY").unwrap();

        let targets = payout_recipient_targets(&api, Some(x402_recipient)).unwrap();
        let recipients = payout_recipient_pubkeys(&targets);

        assert_eq!(recipients.len(), 2);
        assert!(recipients.contains(&x402_recipient));
        assert!(recipients.iter().any(
            |recipient| recipient.to_string() == "mandyRKj8mvxhuk9Np7pJEXd7BjoEZZNRFxUTpDFeAp"
        ));
        assert_eq!(targets[0].label, "x402-upto beneficiary");
        assert_eq!(targets[1].label, "split recipient partner");
    }

    #[test]
    fn x402_upto_beneficiary_pubkey_only_for_distinct_recipient() {
        let api: pay_types::metering::ApiSpec = serde_yml::from_str(
            r#"
name: upto-demo
subdomain: upto-demo
title: Upto Demo
description: Upto Demo
category: finance
version: v1
routing:
  type: respond
endpoints:
  - method: POST
    path: v1/report
    metering:
      schemes: [x402-upto]
      dimensions:
        - direction: usage
          unit: requests
          scale: 1
          tiers:
            - price_usd: 0.10
"#,
        )
        .unwrap();
        let recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
        let operator = VALID_TEST_KEYPAIR_PUBKEY;

        let beneficiary = x402_upto_beneficiary_pubkey(&api, recipient, Some(operator)).unwrap();
        let same_as_operator =
            x402_upto_beneficiary_pubkey(&api, operator, Some(operator)).unwrap();

        assert_eq!(beneficiary.unwrap().to_string(), recipient);
        assert_eq!(same_as_operator, None);
    }

    #[test]
    fn delegated_session_uses_operator_as_zero_share_payee() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();

        let (payee, splits) = delegated_session_channel_payout(
            &recipient.to_string(),
            &operator.to_string(),
            Vec::new(),
        )
        .unwrap();

        assert_eq!(payee, operator.to_string());
        assert_eq!(splits.len(), 1);
        assert_eq!(splits[0].recipient, recipient);
        assert_eq!(splits[0].bps, 10_000);
    }

    #[test]
    fn delegated_session_preserves_explicit_splits_and_routes_remainder() {
        let operator = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let partner = Pubkey::new_unique();

        let (payee, splits) = delegated_session_channel_payout(
            &recipient.to_string(),
            &operator.to_string(),
            vec![pay_kit::mpp::server::session::Split {
                recipient: partner,
                bps: 2_500,
            }],
        )
        .unwrap();

        assert_eq!(payee, operator.to_string());
        assert!(
            splits
                .iter()
                .any(|split| { split.recipient == recipient && split.bps == 7_500 })
        );
        assert!(
            splits
                .iter()
                .any(|split| { split.recipient == partner && split.bps == 2_500 })
        );
        assert_eq!(splits.iter().map(|split| split.bps).sum::<u16>(), 10_000);
    }

    #[test]
    fn create_associated_token_account_ix_is_idempotent_shape() {
        let payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mint = Pubkey::from_str(pay_types::Stablecoin::Usdc.mint(Some("localnet"))).unwrap();
        let token_program =
            Pubkey::from_str(pay_kit::mpp::protocol::solana::programs::TOKEN_PROGRAM).unwrap();
        let (ata, _) = pay_kit::mpp::program::payment_channels::find_associated_token_address(
            &owner,
            &mint,
            &token_program,
        );

        let ix =
            create_associated_token_account_idempotent_ix(&payer, &owner, &mint, &token_program);

        assert_eq!(
            ix.program_id.to_string(),
            pay_kit::mpp::protocol::solana::programs::ASSOCIATED_TOKEN_PROGRAM
        );
        assert_eq!(ix.data, vec![1]);
        assert_eq!(ix.accounts[0].pubkey, payer);
        assert!(ix.accounts[0].is_signer);
        assert_eq!(ix.accounts[1].pubkey, ata);
        assert_eq!(ix.accounts[2].pubkey, owner);
        assert_eq!(ix.accounts[3].pubkey, mint);
        assert_eq!(ix.accounts[5].pubkey, token_program);
    }

    #[test]
    fn operator_config_rejects_removed_currency_field() {
        let err = serde_yml::from_str::<pay_types::metering::OperatorConfig>(r#"currency: "USDT""#)
            .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn resolve_currency_uses_mpp_stablecoin_constants() {
        assert_eq!(
            resolve_currency("USDT", "mainnet").0,
            pay_types::stablecoin_mints::USDT_MAINNET
        );
        assert_eq!(
            resolve_currency("CASH", "mainnet").0,
            pay_types::stablecoin_mints::CASH_MAINNET
        );
        assert_eq!(
            resolve_currency("USDG", "mainnet").0,
            pay_types::stablecoin_mints::USDG_MAINNET
        );
    }

    #[test]
    fn x402_currency_configs_use_resolved_mints_not_symbols() {
        let currency_configs = vec![(
            "USDC".to_string(),
            pay_types::stablecoin_mints::USDC_DEVNET.to_string(),
            6,
        )];

        let configs = x402_currency_configs(&currency_configs, "devnet");

        assert_eq!(configs.len(), 1);
        assert_eq!(
            configs[0].currency,
            pay_types::stablecoin_mints::USDC_DEVNET
        );
        assert_eq!(configs[0].decimals, 6);
    }

    #[test]
    fn x402_currency_configs_default_to_network_usdc_mint() {
        let configs = x402_currency_configs(&[], "devnet");

        assert_eq!(configs.len(), 1);
        assert_eq!(
            configs[0].currency,
            pay_types::stablecoin_mints::USDC_DEVNET
        );
        assert_eq!(configs[0].decimals, 6);
    }

    #[test]
    fn x402_upto_payout_keeps_all_when_recipient_is_receiver_authorizer() {
        let payout =
            x402_upto_payout_for_recipient(VALID_TEST_KEYPAIR_PUBKEY, VALID_TEST_KEYPAIR_PUBKEY);

        assert!(matches!(
            payout,
            pay_kit::x402::server::UptoPayout::ReceiverKeepsAll
        ));
    }

    #[test]
    fn x402_upto_payout_splits_100_percent_to_distinct_recipient() {
        let recipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
        let payout = x402_upto_payout_for_recipient(recipient, VALID_TEST_KEYPAIR_PUBKEY);

        match payout {
            pay_kit::x402::server::UptoPayout::Beneficiary { address } => {
                assert_eq!(address, recipient);
            }
            pay_kit::x402::server::UptoPayout::ReceiverKeepsAll => {
                panic!("distinct recipient should be configured as beneficiary")
            }
        }
    }

    #[test]
    fn browser_rpc_proxy_accepts_payment_page_methods() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "confirmed"}],
        });

        validate_browser_rpc_request(request.to_string().as_bytes()).unwrap();
    }

    #[test]
    fn browser_rpc_proxy_accepts_surfpool_setup_batch() {
        let request = serde_json::json!([
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "surfnet_setAccount",
                "params": [],
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "surfnet_setTokenAccount",
                "params": [],
            }
        ]);

        validate_browser_rpc_request(request.to_string().as_bytes()).unwrap();
    }

    #[test]
    fn browser_rpc_proxy_rejects_unneeded_rpc_methods() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendTransaction",
            "params": [],
        });

        let err = validate_browser_rpc_request(request.to_string().as_bytes()).unwrap_err();
        assert_eq!(err, "Payment RPC method is not allowed.");
    }

    #[test]
    fn pdb_config_uses_real_rpc_url_for_explorer_links() {
        let api: pay_types::metering::ApiSpec = serde_yml::from_str(
            r#"
name: testapi
subdomain: testapi
title: Test API
description: Test API
category: ai_ml
version: v1
routing:
  type: respond
operator:
  recipient: CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY
endpoints:
  - method: GET
    path: v1/data
    resource: data
    metering:
      dimensions:
        - direction: usage
          unit: requests
          scale: 1
          tiers:
            - price_usd: 0.01
"#,
        )
        .unwrap();

        let config = build_pdb_config(
            &api,
            "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            "localnet",
            "https://402.surfnet.dev:8899",
        );

        assert_eq!(config["rpcUrl"], "https://402.surfnet.dev:8899");
    }

    #[test]
    fn sandbox_prefers_auto_fee_payer_signer_even_with_explicit_signer() {
        let signer = SignerConfig::GcpKms {
            key_name: "projects/x/locations/y/keyRings/z/cryptoKeys/a/cryptoKeyVersions/1"
                .to_string(),
            pubkey: VALID_TEST_KEYPAIR_PUBKEY.to_string(),
        };

        assert!(should_use_auto_fee_payer_signer(
            true,
            &SolanaNetwork::Localnet,
            Some(&signer),
        ));
        assert!(!should_use_auto_fee_payer_signer(
            false,
            &SolanaNetwork::Mainnet,
            Some(&signer),
        ));
        assert!(should_use_auto_fee_payer_signer(
            false,
            &SolanaNetwork::Devnet,
            None
        ));
    }

    // ── resolve_signer (operator.signer in YAML) ───────────────────────────
    //
    // Tests for the SignerConfig variants exposed via `operator.signer` in
    // a provider YAML. Each variant is exercised through
    // `resolve_signer_with_store` so we can inject a `MemoryAccountsStore`
    // and never touch `~/.config/pay/accounts.yml`.

    use super::resolve_signer_with_store;
    use pay_core::accounts::{
        Account, AccountsFile, Keystore as AcctKeystore, MemoryAccountsStore,
    };
    use pay_types::metering::SignerConfig;
    // SolanaSigner trait is brought into scope by the parent module's
    // `use pay_kit::mpp::solana_keychain::SolanaSigner;` so calls like
    // `signer.pubkey()` resolve through the trait method.

    /// A real ed25519 keypair (sk[32] || pk[32]) lifted from the
    /// solana-keychain crate's test fixtures. Stable across runs so
    /// pubkey assertions can pin a known value.
    const VALID_TEST_KEYPAIR_BYTES: [u8; 64] = [
        41, 99, 180, 88, 51, 57, 48, 80, 61, 63, 219, 75, 176, 49, 116, 254, 227, 176, 196, 204,
        122, 47, 166, 133, 155, 252, 217, 0, 253, 17, 49, 143, 47, 94, 121, 167, 195, 136, 72, 22,
        157, 48, 77, 88, 63, 96, 57, 122, 181, 243, 236, 188, 241, 134, 174, 224, 100, 246, 17,
        170, 104, 17, 151, 48,
    ];

    /// Pubkey base58 derived from `VALID_TEST_KEYPAIR_BYTES[32..]` —
    /// pinned so the tests catch unintended drift in the keypair format.
    const VALID_TEST_KEYPAIR_PUBKEY: &str = "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR";

    fn write_test_keypair_file(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("test-key.json");
        let json: Vec<i64> = VALID_TEST_KEYPAIR_BYTES.iter().map(|&b| b as i64).collect();
        std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();
        path
    }

    fn ephemeral_account_with_known_pubkey() -> (Account, String) {
        let pubkey = bs58::encode(&VALID_TEST_KEYPAIR_BYTES[32..]).into_string();
        let acct = Account {
            keystore: AcctKeystore::Ephemeral,
            active: false,
            auth_required: Some(false),
            pubkey: Some(pubkey.clone()),
            vault: None,
            account: None,
            path: None,
            secret_key_b58: Some(bs58::encode(&VALID_TEST_KEYPAIR_BYTES[..]).into_string()),
            created_at: Some("2026-04-10T00:00:00Z".to_string()),
            subscriptions: std::collections::BTreeMap::new(),
        };
        (acct, pubkey)
    }

    // ── File backend ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_signer_file_loads_valid_keypair() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_test_keypair_file(dir.path());
        let cfg = SignerConfig::File {
            path: path.to_string_lossy().into_owned(),
        };
        let store = MemoryAccountsStore::new();

        let signer = resolve_signer_with_store(&cfg, &store).await.unwrap();
        assert_eq!(
            signer.pubkey().to_string(),
            VALID_TEST_KEYPAIR_PUBKEY,
            "loaded signer's pubkey must match the keypair we wrote"
        );
    }

    #[tokio::test]
    async fn resolve_signer_file_errors_on_missing_path() {
        let cfg = SignerConfig::File {
            path: "/var/folders/sr/this-path-definitely-does-not-exist.json".to_string(),
        };
        let store = MemoryAccountsStore::new();

        let err = match resolve_signer_with_store(&cfg, &store).await {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        };
        let msg = err.to_string();
        // The wrapped error should mention the offending path AND the
        // keygen hint so the user knows what to do next.
        assert!(
            msg.contains("does-not-exist.json"),
            "missing path in error: {msg}"
        );
        assert!(
            msg.contains("solana-keygen new"),
            "missing remediation hint: {msg}"
        );
    }

    #[tokio::test]
    async fn resolve_signer_file_errors_on_garbage_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.json");
        std::fs::write(&path, "this is not a keypair").unwrap();
        let cfg = SignerConfig::File {
            path: path.to_string_lossy().into_owned(),
        };
        let store = MemoryAccountsStore::new();

        let err = match resolve_signer_with_store(&cfg, &store).await {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("64 bytes"), "missing length hint: {msg}");
    }

    // ── Env backend ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_signer_env_loads_valid_json_keypair() {
        let env_name = format!("_PAY_TEST_SIGNER_KEYPAIR_{}", std::process::id());
        let json: Vec<u8> = VALID_TEST_KEYPAIR_BYTES.to_vec();
        unsafe { std::env::set_var(&env_name, serde_json::to_string(&json).unwrap()) };
        let cfg = SignerConfig::Env {
            value_from_env: env_name.clone(),
        };
        let store = MemoryAccountsStore::new();

        let signer = resolve_signer_with_store(&cfg, &store).await.unwrap();

        assert_eq!(signer.pubkey().to_string(), VALID_TEST_KEYPAIR_PUBKEY);
        unsafe { std::env::remove_var(&env_name) };
    }

    #[tokio::test]
    async fn resolve_signer_env_rejects_missing_env() {
        let env_name = format!("_PAY_TEST_MISSING_SIGNER_KEYPAIR_{}", std::process::id());
        unsafe { std::env::remove_var(&env_name) };
        let cfg = SignerConfig::Env {
            value_from_env: env_name.clone(),
        };
        let store = MemoryAccountsStore::new();

        let err = match resolve_signer_with_store(&cfg, &store).await {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        };

        let msg = err.to_string();
        assert!(msg.contains(&env_name), "missing env var name: {msg}");
        assert!(msg.contains("not set"), "missing not-set hint: {msg}");
    }

    #[tokio::test]
    async fn resolve_signer_env_error_does_not_leak_secret_value() {
        let env_name = format!("_PAY_TEST_BAD_SIGNER_KEYPAIR_{}", std::process::id());
        unsafe { std::env::set_var(&env_name, "definitely-not-a-keypair") };
        let cfg = SignerConfig::Env {
            value_from_env: env_name.clone(),
        };
        let store = MemoryAccountsStore::new();

        let err = match resolve_signer_with_store(&cfg, &store).await {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        };

        let msg = err.to_string();
        assert!(msg.contains(&env_name), "missing env var name: {msg}");
        assert!(
            !msg.contains("definitely-not-a-keypair"),
            "error leaked secret value: {msg}"
        );
        unsafe { std::env::remove_var(&env_name) };
    }

    // ── Account backend ────────────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_signer_account_loads_ephemeral_entry() {
        // The most common dev path: a named ephemeral account in
        // accounts.yml. No OS auth prompt fires because the secret is
        // stored inline.
        let mut file = AccountsFile::default();
        let (account, expected_pubkey) = ephemeral_account_with_known_pubkey();
        file.upsert(pay_core::accounts::MAINNET_NETWORK, "test-payer", account);
        let store = MemoryAccountsStore::with_file(file);

        let cfg = SignerConfig::Account {
            name: "test-payer".to_string(),
        };
        let signer = resolve_signer_with_store(&cfg, &store).await.unwrap();
        assert_eq!(signer.pubkey().to_string(), expected_pubkey);
    }

    #[tokio::test]
    async fn resolve_signer_account_errors_on_unknown_name() {
        let store = MemoryAccountsStore::new();
        let cfg = SignerConfig::Account {
            name: "ghost-account".to_string(),
        };

        let err = match resolve_signer_with_store(&cfg, &store).await {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("ghost-account"), "missing account name: {msg}");
        assert!(
            msg.contains("pay account ls"),
            "missing remediation hint: {msg}"
        );
    }

    #[tokio::test]
    async fn resolve_signer_account_errors_on_corrupt_ephemeral_secret() {
        // Account is marked ephemeral but secret_key_b58 isn't valid
        // base58. Should fail with a helpful message naming the account.
        let mut file = AccountsFile::default();
        let bad = Account {
            keystore: AcctKeystore::Ephemeral,
            active: false,
            auth_required: Some(false),
            pubkey: Some("4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR".to_string()),
            vault: None,
            account: None,
            path: None,
            // Valid base58 but wrong length (decodes to <64 bytes).
            secret_key_b58: Some("abc".to_string()),
            created_at: Some("2026-04-10T00:00:00Z".to_string()),
            subscriptions: std::collections::BTreeMap::new(),
        };
        file.upsert(pay_core::accounts::MAINNET_NETWORK, "broken", bad);
        let store = MemoryAccountsStore::with_file(file);

        let cfg = SignerConfig::Account {
            name: "broken".to_string(),
        };
        let err = match resolve_signer_with_store(&cfg, &store).await {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("broken"), "missing account name: {msg}");
    }

    // ── GcpKms backend (build-feature gated) ──────────────────────────────

    #[tokio::test]
    #[cfg(not(feature = "gcp_kms"))]
    async fn resolve_signer_gcp_kms_errors_when_feature_missing() {
        // Without the gcp_kms feature, the GcpKms variant must error
        // with a clear "rebuild with --features gcp_kms" hint AND
        // mention the alternative backends so the user has options.
        let cfg = SignerConfig::GcpKms {
            key_name: "projects/x/locations/y/keyRings/z/cryptoKeys/a/cryptoKeyVersions/1"
                .to_string(),
            pubkey: "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR".to_string(),
        };
        let store = MemoryAccountsStore::new();

        let err = match resolve_signer_with_store(&cfg, &store).await {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("gcp_kms"), "missing feature name: {msg}");
        assert!(
            msg.contains("backend: account"),
            "missing alt-backend hint: {msg}"
        );
    }
}
