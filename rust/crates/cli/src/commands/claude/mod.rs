pub(crate) mod translate;

use std::io::IsTerminal;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use clap::Args;

use super::agent_args::model_arg;
use owo_colors::OwoColorize;

use crate::commands::payer_proxy;
use crate::commands::server::inference::{
    self,
    discovery::{self, DiscoveredProvider},
    providers::{self, Dialect, InferenceProvider, catalog as catalog_providers},
};
use crate::tui::{ProviderSelection, select_provider};
use pay_pdb::types::ProviderSummary;

const ALLOWED_TOOLS: &str = "mcp__pay__curl,mcp__pay__search_catalog,mcp__pay__list_catalog,mcp__pay__get_catalog_entry,mcp__pay__get_balance,mcp__pay__topup,mcp__pay__create_skill";
const PROVIDER_PROBE_TIMEOUT: Duration = Duration::from_millis(400);
const ANTHROPIC_BASE_URL_ENV: &str = "ANTHROPIC_BASE_URL";
const ANTHROPIC_API_KEY_ENV: &str = "ANTHROPIC_API_KEY";
const ANTHROPIC_AUTH_TOKEN_ENV: &str = "ANTHROPIC_AUTH_TOKEN";
const CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION_ENV: &str = "CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION";
const CLAUDE_CODE_DISABLE_TERMINAL_TITLE_ENV: &str = "CLAUDE_CODE_DISABLE_TERMINAL_TITLE";
const OLLAMA_AUTH_TOKEN: &str = "ollama";
/// Hosted catalog gateways are remote (TLS handshake included) — give their
/// reachability/model probes more room than the localhost ones.
const CATALOG_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const CUSTOM_PROVIDER_TIMEOUT: Duration = Duration::from_secs(5);
/// Run Claude Code with 402 payment support.
///
/// Launches Claude Code with the pay MCP server injected automatically.
/// All arguments are passed through to the `claude` binary.
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct ClaudeCommand {
    /// Arguments forwarded to claude.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

impl ClaudeCommand {
    pub fn run(
        self,
        pay_bin: &str,
        active_account_name: Option<&str>,
        network_override: Option<&str>,
        alternate_provider: bool,
    ) -> pay_core::Result<i32> {
        let launch = prepare_claude_launch(
            &self.args,
            alternate_provider,
            network_override,
            active_account_name,
        )?;

        let mut mcp_server = serde_json::json!({
            "command": pay_bin,
            "args": ["mcp"]
        });

        // Pass config to the MCP server via env vars
        let mut env = serde_json::Map::new();
        if let Some(source) = active_account_name {
            env.insert(
                "PAY_ACTIVE_ACCOUNT".to_string(),
                serde_json::Value::String(source.to_string()),
            );
        }
        if let Ok(url) = std::env::var("PAY_RPC_URL") {
            env.insert("PAY_RPC_URL".to_string(), serde_json::Value::String(url));
        }
        if let Ok(network) = std::env::var("PAY_NETWORK_ENFORCED") {
            env.insert(
                "PAY_NETWORK_ENFORCED".to_string(),
                serde_json::Value::String(network),
            );
        }
        if let Ok(protocol) = std::env::var("PAY_PROTOCOL_ENFORCED") {
            env.insert(
                "PAY_PROTOCOL_ENFORCED".to_string(),
                serde_json::Value::String(protocol),
            );
        }
        if let Ok(proxy) = std::env::var("PAY_DEBUGGER_PROXY") {
            env.insert(
                "PAY_DEBUGGER_PROXY".to_string(),
                serde_json::Value::String(proxy),
            );
        }
        if !env.is_empty() {
            mcp_server["env"] = serde_json::Value::Object(env);
        }

        let mcp_config = serde_json::json!({
            "mcpServers": {
                "pay": mcp_server
            }
        });

        #[cfg(windows)]
        return launch_windows(
            mcp_config,
            &launch.args,
            launch.base_url.as_deref(),
            launch.model.as_deref(),
        );

        #[cfg(not(windows))]
        {
            let mut command = Command::new("claude");
            command
                .arg("--mcp-config")
                .arg(mcp_config.to_string())
                .arg("--strict-mcp-config")
                .arg("--allowedTools")
                .arg(ALLOWED_TOOLS)
                .arg("--append-system-prompt")
                .arg(pay_core::instructions::INSTRUCTIONS)
                .args(&launch.args)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());

            if let Some(base_url) = launch.base_url.as_deref() {
                command.envs(claude_env(base_url, launch.model.as_deref()));
            }

            let status = command.status().map_err(|e| {
                pay_core::Error::Config(format!("Failed to launch claude: {e}. Is it installed?"))
            })?;

            Ok(status.code().unwrap_or(1))
        }
    }
}

struct ClaudeLaunch {
    base_url: Option<String>,
    model: Option<String>,
    args: Vec<String>,
}

/// Agent harness using a provider selected by `--alt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AlternateClient {
    Claude,
    Codex,
    Goose,
    Qoder,
}

impl AlternateClient {
    fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Goose => "goose",
            Self::Qoder => "qoder",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Claude => "Claude",
            Self::Codex => "Codex",
            Self::Goose => "Goose",
            Self::Qoder => "Qoder",
        }
    }

    fn compatibility_label(self) -> &'static str {
        match self {
            Self::Claude => "Anthropic or OpenAI-compatible",
            Self::Codex => "OpenAI Responses-compatible",
            Self::Goose => "OpenAI Chat Completions-compatible",
            Self::Qoder => "OpenAI Chat Completions-compatible",
        }
    }

    fn fallback_dialect(self) -> Dialect {
        match self {
            Self::Claude => Dialect::Anthropic,
            Self::Codex | Self::Goose | Self::Qoder => Dialect::OpenAiCompat,
        }
    }

    fn supports_dialect(self, dialect: Dialect) -> bool {
        match self {
            Self::Claude => matches!(dialect, Dialect::Anthropic | Dialect::OpenAiCompat),
            Self::Codex | Self::Goose | Self::Qoder => dialect == Dialect::OpenAiCompat,
        }
    }

    fn provider_supported(self, provider: &DiscoveredProvider) -> bool {
        let dialect = provider.provider.dialect();
        if !self.supports_dialect(dialect) {
            return false;
        }
        match (self, dialect) {
            (Self::Claude, Dialect::Anthropic) => supports_post_endpoint(provider, "v1/messages"),
            (Self::Claude, Dialect::OpenAiCompat) => {
                supports_post_endpoint(provider, "chat/completions")
            }
            (Self::Codex, Dialect::OpenAiCompat) => {
                supports_post_endpoint(provider, "v1/responses")
            }
            (Self::Goose | Self::Qoder, Dialect::OpenAiCompat) => {
                supports_post_endpoint(provider, "chat/completions")
            }
            _ => false,
        }
    }

    fn payer_base_url(self, payer_base_url: &str) -> String {
        match self {
            Self::Claude => payer_base_url.to_string(),
            // Goose takes a host and a separate `OPENAI_BASE_PATH`.
            Self::Goose => payer_base_url.to_string(),
            // Codex and Qoder append their operation to an OpenAI `/v1` base.
            Self::Codex | Self::Qoder => {
                format!("{}/v1", payer_base_url.trim_end_matches('/'))
            }
        }
    }
}

/// One-run provider settings backed by the local payer proxy.
pub(crate) struct AlternateProvider {
    pub base_url: String,
    pub model: Option<String>,
}

/// Provider metadata used by setup-time integrations that need a deterministic,
/// headless `pay --alt` route without starting the payer proxy yet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AlternateProviderOption {
    pub slug: String,
    pub title: String,
    pub models: Vec<String>,
}

#[derive(Clone, Copy)]
enum AlternateRouteKind {
    Hosted,
    LocalGateway,
    Direct,
}

/// Discover, filter, select, and proxy a provider for an alternate agent
/// harness. Compatibility is enforced before the provider picker is shown.
pub(crate) fn prepare_alternate_provider(
    client: AlternateClient,
    args: &[String],
    network_override: Option<&str>,
    account_override: Option<&str>,
) -> pay_core::Result<AlternateProvider> {
    prepare_alternate_provider_for(client, args, network_override, account_override, None)
}

pub(crate) fn prepare_alternate_provider_for(
    client: AlternateClient,
    args: &[String],
    network_override: Option<&str>,
    account_override: Option<&str>,
    requested_provider: Option<&str>,
) -> pay_core::Result<AlternateProvider> {
    let agent = client.name();
    let requested_model = model_arg(args);
    let interactive_picker = std::io::stderr().is_terminal() && requested_provider.is_none();
    let (providers, gateway_up, provider_updates) = if interactive_picker {
        let gateway_up = gateway_listening();
        (
            Vec::new(),
            gateway_up,
            Some(discover_providers_in_background(client, gateway_up)),
        )
    } else {
        let (providers, gateway_up) = discover_compatible_providers(client)?;
        (providers, gateway_up, None)
    };

    let choice = if providers.is_empty() && !std::io::stderr().is_terminal() {
        None
    } else {
        Some(select_provider_choice(
            client,
            providers,
            requested_model.as_deref(),
            requested_provider,
            provider_updates,
        )?)
    };

    let translated = client == AlternateClient::Claude
        && choice
            .as_ref()
            .is_some_and(|choice| choice.provider.provider.dialect() == Dialect::OpenAiCompat);

    let (upstream, model, provider_name, route_kind) = match choice {
        Some(choice) if choice.provider.hosted() => {
            let provider_name = choice.provider.title().to_string();
            let upstream = payer_upstream(&choice.provider, choice.provider.base_url.clone());
            (
                upstream,
                Some(choice.model),
                provider_name,
                AlternateRouteKind::Hosted,
            )
        }
        Some(choice) if gateway_up => {
            let provider_name = choice.provider.title().to_string();
            let upstream = gateway_payer_upstream(&choice.provider);
            (
                upstream,
                Some(choice.model),
                provider_name,
                AlternateRouteKind::LocalGateway,
            )
        }
        Some(choice) => {
            let provider_name = choice.provider.title().to_string();
            let upstream = payer_upstream(&choice.provider, choice.provider.base_url.clone());
            (
                upstream,
                Some(choice.model),
                provider_name,
                AlternateRouteKind::Direct,
            )
        }
        None if gateway_up => {
            let upstream = payer_proxy::PayerUpstream {
                base_url: inference::LOCAL_GATEWAY_BASE_URL.to_string(),
                host_header: None,
                dialect: client.fallback_dialect(),
                chat_path: providers::OPENAI_CHAT_COMPLETIONS_PATH.to_string(),
                responses_path: "v1/responses".to_string(),
                require_payment: false,
                payment_protocol: payer_proxy::PaymentProtocol::Auto,
            };
            (
                upstream,
                requested_model,
                "Local gateway".to_string(),
                AlternateRouteKind::LocalGateway,
            )
        }
        None => {
            return Err(pay_core::Error::Config(format!(
                "no {} provider found for {agent} and no gateway is listening on {}",
                client.compatibility_label(),
                inference::LOCAL_GATEWAY_BASE_URL
            )));
        }
    };

    let payer = payer_proxy::start_background(upstream, network_override, account_override)?;
    print_alternate_route(
        client,
        &provider_name,
        model.as_deref(),
        route_kind,
        translated,
        payer.payer_pubkey.as_deref(),
    );

    Ok(AlternateProvider {
        base_url: client.payer_base_url(&payer.base_url),
        model,
    })
}

/// Discover providers that can back an ACP runtime without launching a payer
/// proxy. Buzz setup uses this to persist a provider and model for its
/// headless custom-harness process.
pub(crate) fn discover_acp_provider_options(
    client: AlternateClient,
) -> pay_core::Result<Vec<AlternateProviderOption>> {
    let (providers, _) = discover_compatible_providers(client)?;
    Ok(providers
        .into_iter()
        .map(|provider| AlternateProviderOption {
            slug: provider.slug().to_string(),
            title: provider.title().to_string(),
            models: provider.models,
        })
        .collect())
}

fn discover_compatible_providers(
    client: AlternateClient,
) -> pay_core::Result<(Vec<DiscoveredProvider>, bool)> {
    let (mut providers, gateway_up) = discover_runtime_providers(client)?;
    providers.extend(discover_catalog_providers());
    providers.retain(|provider| client.provider_supported(provider));
    Ok((providers, gateway_up))
}

/// Loopback-only discovery shared by headless selection and the interactive
/// picker's background worker.
fn discover_runtime_providers(
    client: AlternateClient,
) -> pay_core::Result<(Vec<DiscoveredProvider>, bool)> {
    let gateway_up = gateway_listening();
    let providers = discover_runtime_providers_for_gateway(client, gateway_up)?;
    Ok((providers, gateway_up))
}

fn discover_runtime_providers_for_gateway(
    client: AlternateClient,
    gateway_up: bool,
) -> pay_core::Result<Vec<DiscoveredProvider>> {
    let mut providers = discover_local_providers()?;
    if gateway_up {
        let gateway_providers = gateway_provider_summaries();
        if !gateway_providers.is_empty() {
            apply_gateway_provider_summaries(&mut providers, &gateway_providers);
        } else {
            apply_gateway_proxy_fallback(&mut providers);
        }
    }
    providers.retain(|provider| client.provider_supported(provider));
    Ok(providers)
}

fn discover_providers_in_background(
    client: AlternateClient,
    gateway_up: bool,
) -> std::sync::mpsc::Receiver<Vec<DiscoveredProvider>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    let local_sender = sender.clone();
    let _ = std::thread::Builder::new()
        .name("pay-local-provider-discovery".to_string())
        .spawn(move || {
            let providers =
                discover_runtime_providers_for_gateway(client, gateway_up).unwrap_or_default();
            let _ = local_sender.send(providers);
        });
    let catalog_sender = sender.clone();
    let _ = std::thread::Builder::new()
        .name("pay-catalog-provider-discovery".to_string())
        .spawn(move || {
            let mut providers = discover_catalog_providers();
            providers.retain(|provider| client.provider_supported(provider));
            let _ = catalog_sender.send(providers);
            let pinned = discover_pinned_inference_providers(client);
            let _ = catalog_sender.send(pinned);
        });
    drop(sender);
    receiver
}

fn discover_pinned_inference_providers(client_kind: AlternateClient) -> Vec<DiscoveredProvider> {
    let Ok(config) = pay_core::skills::config::SkillsConfig::load() else {
        return Vec::new();
    };
    let sources: Vec<String> = config
        .sources
        .iter()
        .filter(|source| pinned_inference_source(source))
        .map(|source| source.url.clone())
        .collect();
    if sources.is_empty() {
        return Vec::new();
    }

    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return Vec::new();
    };
    let mut discovered = Vec::new();
    let mut reachable = Vec::new();
    let mut stale = Vec::new();
    runtime.block_on(async {
        let Ok(client) = reqwest::Client::builder()
            .timeout(CUSTOM_PROVIDER_TIMEOUT)
            .build()
        else {
            return;
        };
        for source in &sources {
            if client.get(source).send().await.is_err() {
                stale.push(source.clone());
                continue;
            }
            reachable.push(source.clone());
            if let Ok(mut providers) = discover_custom_providers(client_kind, source).await {
                discovered.append(&mut providers);
            }
        }
    });

    if !stale.is_empty() || !reachable.is_empty() {
        let Ok(mut config) = pay_core::skills::config::SkillsConfig::load() else {
            return discovered;
        };
        let mut changed = false;
        for source in stale {
            changed |= config.remove_source_by_url(&source);
        }
        for source in reachable {
            changed |= config.add_inference_source(&source);
        }
        if changed {
            let _ = config.save();
        }
    }
    discovered
}

fn pinned_inference_source(source: &pay_core::skills::config::Source) -> bool {
    !source.ephemeral
        && (source.inference
            || reqwest::Url::parse(&source.url)
                .ok()
                .is_some_and(|url| url.path().to_ascii_lowercase().ends_with("/openapi.json")))
}

fn print_alternate_route(
    client: AlternateClient,
    provider: &str,
    model: Option<&str>,
    route_kind: AlternateRouteKind,
    translated: bool,
    payer_pubkey: Option<&str>,
) {
    let model = model
        .map(|model| format!(" {}", format!("· {model}").magenta()))
        .unwrap_or_default();
    let translation = if translated {
        format!(" {}", "· Anthropic→OpenAI".dimmed())
    } else {
        String::new()
    };
    let route = match route_kind {
        AlternateRouteKind::Hosted => payer_pubkey
            .map(abbreviate_pubkey)
            .map(|payer| format!(" {}", format!("· payer {payer}").dimmed()))
            .unwrap_or_else(|| format!(" {}", "· paid".dimmed())),
        AlternateRouteKind::LocalGateway => format!(" {}", "· local gateway".dimmed()),
        AlternateRouteKind::Direct => format!(" {}", "· direct".dimmed()),
    };

    eprintln!(
        "{} {} {} {}{}{}{}",
        "⚡".yellow().bold(),
        client.display_name().bold(),
        "→".dimmed(),
        provider.cyan().bold(),
        model,
        translation,
        route,
    );
}

fn abbreviate_pubkey(pubkey: &str) -> String {
    if pubkey.len() <= 12 {
        return pubkey.to_string();
    }
    format!("{}…{}", &pubkey[..5], &pubkey[pubkey.len() - 4..])
}

fn supports_post_endpoint(provider: &DiscoveredProvider, endpoint_path: &str) -> bool {
    let required = endpoint_path.trim_matches('/');
    provider.provider.paid_endpoints().iter().any(|endpoint| {
        matches!(endpoint.method, pay_types::metering::HttpMethod::Post)
            && endpoint.path.trim_matches('/').ends_with(required)
    })
}

fn prepare_claude_launch(
    args: &[String],
    alternate_provider: bool,
    network_override: Option<&str>,
    account_override: Option<&str>,
) -> pay_core::Result<ClaudeLaunch> {
    if !alternate_provider {
        return Ok(ClaudeLaunch {
            base_url: None,
            model: None,
            args: args.to_vec(),
        });
    }

    prepare_alternate_claude_launch(args, network_override, account_override)
}

/// Decide where Claude Code's traffic goes and put the 402-paying payer
/// proxy in front of it.
///
/// `pay claude` never spawns a gateway itself — it routes:
///
/// 1. **Hosted compatible provider selected** (Model Studio, … from
///    the pay catalog) → payer proxy targets its `service_url` directly
///    and settles the gateway's MPP 402 challenges per request.
/// 2. **Gateway on 127.0.0.1:1402** (the user ran `pay gate inference`,
///    possibly priced, in another terminal) → payer proxy targets the
///    gateway and settles its MPP 402 challenges.
/// 3. **No gateway** → run local provider discovery and target the
///    selected provider directly (e.g. Ollama on :11434) — unmetered
///    passthrough, no 402s.
/// 4. **None of the above** → error with a hint.
fn prepare_alternate_claude_launch(
    args: &[String],
    network_override: Option<&str>,
    account_override: Option<&str>,
) -> pay_core::Result<ClaudeLaunch> {
    if claude_metadata_requested(args) {
        return Ok(ClaudeLaunch {
            base_url: None,
            model: None,
            args: args.to_vec(),
        });
    }

    let alternate = prepare_alternate_provider(
        AlternateClient::Claude,
        args,
        network_override,
        account_override,
    )?;
    let args = claude_args_with_model(args, alternate.model.as_deref());

    Ok(ClaudeLaunch {
        base_url: Some(alternate.base_url),
        model: alternate.model,
        args,
    })
}

/// Payer upstream for a picked provider: its dialect plus the
/// chat-completions path translated `/v1/messages` requests are sent to.
fn payer_upstream(provider: &DiscoveredProvider, base_url: String) -> payer_proxy::PayerUpstream {
    payer_proxy::PayerUpstream {
        base_url,
        host_header: None,
        dialect: provider.provider.dialect(),
        chat_path: chat_completions_path(provider.provider.as_ref()),
        responses_path: responses_path(provider.provider.as_ref()),
        require_payment: provider_requires_payment(provider),
        payment_protocol: provider_payment_protocol(provider),
    }
}

/// Remote catalog gateways are expected to enforce their advertised payment
/// gate. Loopback OpenAPI providers may intentionally mix priced and free
/// models/routes; the payer still handles any 402 it receives, but a successful
/// passthrough is not a security error.
fn provider_requires_payment(provider: &DiscoveredProvider) -> bool {
    if !provider.hosted() {
        return false;
    }
    reqwest::Url::parse(&provider.base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .is_none_or(|host| {
            if host == "localhost" {
                return false;
            }
            host.parse::<std::net::IpAddr>()
                .map(|ip| !ip.is_loopback())
                .unwrap_or(true)
        })
}

/// The inference gateway routes providers by Host subdomain. The payer proxy
/// still connects to 127.0.0.1 so it does not depend on wildcard localhost
/// DNS, but it sends the selected provider Host to the gateway.
fn gateway_payer_upstream(provider: &DiscoveredProvider) -> payer_proxy::PayerUpstream {
    payer_proxy::PayerUpstream {
        base_url: inference::LOCAL_GATEWAY_BASE_URL.to_string(),
        host_header: Some(inference::local_gateway_provider_host(provider.slug())),
        dialect: provider.provider.dialect(),
        chat_path: chat_completions_path(provider.provider.as_ref()),
        responses_path: responses_path(provider.provider.as_ref()),
        require_payment: false,
        payment_protocol: provider_payment_protocol(provider),
    }
}

/// Alibaba Model Studio and Gemini are session-only agent routes. Keeping the
/// requirement here makes the local payer fail closed even while a stale
/// catalog entry still advertises the legacy x402 fallback.
fn provider_payment_protocol(provider: &DiscoveredProvider) -> payer_proxy::PaymentProtocol {
    match provider.slug() {
        "alibaba" | "google" | "modelstudio" | "generativelanguage" => {
            payer_proxy::PaymentProtocol::MppSession
        }
        _ => payer_proxy::PaymentProtocol::Auto,
    }
}

/// The provider's chat-completions path, from its paid endpoints (that's
/// where the catalog pins Alibaba's `compatible-mode/v1/chat/completions`),
/// falling back to the OpenAI-compatible default.
fn chat_completions_path(provider: &dyn InferenceProvider) -> String {
    provider
        .paid_endpoints()
        .into_iter()
        .filter(|ep| matches!(ep.method, pay_types::metering::HttpMethod::Post))
        .map(|ep| ep.path)
        .find(|path| path.to_ascii_lowercase().contains("chat/completions"))
        .unwrap_or_else(|| providers::OPENAI_CHAT_COMPLETIONS_PATH.to_string())
}

/// The provider's Responses API path. Some hosted providers expose it below
/// the same compatibility prefix as Chat Completions.
fn responses_path(provider: &dyn InferenceProvider) -> String {
    provider
        .paid_endpoints()
        .into_iter()
        .filter(|ep| matches!(ep.method, pay_types::metering::HttpMethod::Post))
        .map(|ep| ep.path)
        .find(|path| path.trim_matches('/').ends_with("/responses"))
        .unwrap_or_else(|| "v1/responses".to_string())
}

fn select_provider_choice(
    client: AlternateClient,
    providers: Vec<DiscoveredProvider>,
    requested_model: Option<&str>,
    requested_provider: Option<&str>,
    provider_updates: Option<std::sync::mpsc::Receiver<Vec<DiscoveredProvider>>>,
) -> pay_core::Result<crate::tui::ProviderChoice> {
    let agent = client.name();
    if let Some(requested_provider) = requested_provider {
        let available = providers
            .iter()
            .map(DiscoveredProvider::slug)
            .collect::<Vec<_>>()
            .join(", ");
        let provider = providers
            .into_iter()
            .find(|provider| {
                provider_slug_matches(provider.slug(), requested_provider)
                    || provider.title().eq_ignore_ascii_case(requested_provider)
            })
            .ok_or_else(|| {
                pay_core::Error::Config(format!(
                    "provider `{requested_provider}` is not available for {agent}; available providers: {available}"
                ))
            })?;
        let model = requested_model
            .map(str::to_string)
            .or_else(|| provider.models.first().cloned())
            .ok_or_else(|| {
                pay_core::Error::Config(format!(
                    "provider `{}` did not report any models; pass `--model <MODEL>`",
                    provider.slug()
                ))
            })?;
        return Ok(crate::tui::ProviderChoice { provider, model });
    }

    match select_provider(agent, providers, requested_model, provider_updates, |url| {
        discover_and_save_custom_providers(client, url)
    })
    .map_err(|e| pay_core::Error::Config(format!("Provider selection failed: {e}")))?
    {
        ProviderSelection::Selected(choice) => Ok(choice),
        ProviderSelection::Cancelled => Err(pay_core::Error::Config(format!(
            "{agent} provider selection cancelled"
        ))),
    }
}

/// Turn a pasted inference origin into the draft-standard `/openapi.json`
/// discovery URL. Explicit OpenAPI or catalog JSON URLs are respected.
fn custom_source_url(input: &str) -> Result<String, String> {
    let input = input.trim();
    let candidate = if input.contains("://") {
        input.to_string()
    } else {
        format!("https://{input}")
    };
    let mut url =
        reqwest::Url::parse(&candidate).map_err(|error| format!("Invalid server URL: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("Server URL must use http:// or https://".to_string());
    }
    if url.host_str().is_none() {
        return Err("Server URL must include a host".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Server URL must not contain credentials".to_string());
    }
    // An explicitly entered IP is commonly a LAN or bare-metal inference
    // server without a TLS hostname. Keep HTTP disabled for DNS names so a
    // typo cannot silently downgrade a hosted provider.
    let http_allowed = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok()
    });
    if url.scheme() == "http" && !http_allowed {
        return Err(
            "Payment discovery requires HTTPS for hostnames (http:// is allowed for localhost and literal IP addresses)"
                .to_string(),
        );
    }
    url.set_fragment(None);
    let path = url.path().to_ascii_lowercase();
    let direct_catalog = path.ends_with("/pay-skills.json")
        || path.ends_with("/catalog.json")
        || path.ends_with("/skills.json");
    let direct_openapi = path.ends_with("/openapi.json");
    if direct_catalog || direct_openapi {
        return Ok(url.to_string());
    }

    url.set_path("/openapi.json");
    url.set_query(None);
    Ok(url.to_string())
}

fn discover_and_save_custom_providers(
    client_kind: AlternateClient,
    input: &str,
) -> Result<Vec<DiscoveredProvider>, String> {
    let source_url = custom_source_url(input)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("Could not start discovery: {error}"))?;
    let providers = runtime.block_on(discover_custom_providers(client_kind, &source_url))?;

    let mut config = pay_core::skills::config::SkillsConfig::load().map_err(|error| {
        format!("Discovered provider but could not load skills config: {error}")
    })?;
    if config.add_inference_source(&source_url) {
        config.save().map_err(|error| {
            format!("Discovered provider but could not save {source_url}: {error}")
        })?;
    }
    Ok(providers)
}

/*
 * Keep custom discovery beside provider selection: it is harness-aware and
 * returns the same DiscoveredProvider abstraction used by local and catalog
 * providers.
 */
async fn discover_custom_providers(
    client_kind: AlternateClient,
    source_url: &str,
) -> Result<Vec<DiscoveredProvider>, String> {
    let client = reqwest::Client::builder()
        .timeout(CUSTOM_PROVIDER_TIMEOUT)
        .build()
        .map_err(|error| format!("Could not create discovery client: {error}"))?;
    let response = client
        .get(source_url)
        .send()
        .await
        .map_err(|error| format!("Could not discover {source_url}: {error}"))?;
    if !response.status().is_success() {
        if response.status() == reqwest::StatusCode::NOT_FOUND
            && reqwest::Url::parse(source_url)
                .ok()
                .is_some_and(|url| url.path().eq_ignore_ascii_case("/openapi.json"))
        {
            return discover_inference_gateway(client_kind, &client, source_url).await;
        }
        return Err(format!(
            "No discovery document at {source_url} ({})",
            response.status()
        ));
    }
    let raw = response
        .text()
        .await
        .map_err(|error| format!("Could not read {source_url}: {error}"))?;
    let mut catalog = pay_core::skills::parse_catalog_source(&raw, source_url)
        .map_err(|error| format!("Invalid discovery document at {source_url}: {error}"))?;
    if catalog.providers.is_empty() {
        return Err("The discovered catalog contains no providers".to_string());
    }

    let fqns: Vec<String> = catalog
        .providers
        .iter()
        .map(|provider| provider.fqn.clone())
        .collect();
    let mut discovered = Vec::new();
    let mut rejected = Vec::new();
    for fqn in fqns {
        if let Err(error) = pay_core::skills::ensure_endpoints(&mut catalog, &fqn).await {
            rejected.push(format!("{fqn}: OpenAPI endpoints unavailable ({error})"));
            continue;
        }
        let Some(service) = catalog
            .providers
            .iter()
            .find(|provider| provider.fqn == fqn)
        else {
            continue;
        };
        if service.meta.service_url.trim().is_empty() {
            rejected.push(format!("{fqn}: service_url is missing"));
            continue;
        }

        let provider = catalog_providers::CatalogProvider::from_service(service);
        let base_url = provider.service_url().to_string();
        let Some(version) = provider.identify(&client, &base_url).await else {
            rejected.push(format!("{fqn}: inference server is unreachable"));
            continue;
        };
        let (models, model_pricing) = provider.list_models_with_pricing(&client, &base_url).await;
        if models.is_empty() {
            rejected.push(format!("{fqn}: no models were discovered"));
            continue;
        }
        let has_pricing = provider.pricing_hint().is_some()
            || model_pricing.iter().any(|model| model.price.is_some());
        if !has_pricing {
            rejected.push(format!("{fqn}: no pricing metadata was discovered"));
            continue;
        }

        let found = DiscoveredProvider {
            provider: Arc::new(provider),
            base_url,
            models,
            version,
            pricing: None,
            model_pricing,
        };
        if !client_kind.provider_supported(&found) {
            rejected.push(format!(
                "{fqn}: not compatible with {}",
                client_kind.display_name()
            ));
            continue;
        }
        discovered.push(found);
    }

    if discovered.is_empty() {
        let detail = rejected
            .first()
            .map(|reason| format!(": {reason}"))
            .unwrap_or_default();
        return Err(format!(
            "No compatible priced inference provider found{detail}"
        ));
    }
    Ok(discovered)
}

/// Older `pay gate inference` versions expose their provider snapshot at `/`
/// but do not publish `/openapi.json`. Accept that first-party index as a
/// discovery fallback so a remote gateway can be added by IP address.
async fn discover_inference_gateway(
    client_kind: AlternateClient,
    client: &reqwest::Client,
    source_url: &str,
) -> Result<Vec<DiscoveredProvider>, String> {
    let mut origin =
        reqwest::Url::parse(source_url).map_err(|error| format!("Invalid server URL: {error}"))?;
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    let response = client
        .get(origin.clone())
        .send()
        .await
        .map_err(|error| format!("Could not discover {origin}: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "No discovery document at {source_url}, and the server index returned {}",
            response.status()
        ));
    }
    let index = response
        .json::<GatewayConfig>()
        .await
        .map_err(|error| format!("Invalid inference server index at {origin}: {error}"))?;
    if index.service.as_deref() != Some("pay gate inference") {
        return Err(format!(
            "No discovery document at {source_url}, and {origin} is not a pay inference gateway"
        ));
    }

    let base_url = origin.as_str().trim_end_matches('/').to_string();
    let mut discovered = Vec::new();
    let mut rejected = Vec::new();
    for summary in index.providers.into_iter().filter(|provider| provider.up) {
        if summary.models.is_empty() {
            rejected.push(format!("{}: no models were discovered", summary.slug));
            continue;
        }
        if !summary
            .model_pricing
            .iter()
            .any(|model| model.price.is_some())
        {
            rejected.push(format!(
                "{}: no pricing metadata was discovered",
                summary.slug
            ));
            continue;
        }
        let provider = providers::CustomProvider {
            slug: summary.slug,
            title: summary.title,
            ports: Vec::new(),
            color: summary.color,
            identify: Vec::new(),
            models: None,
            paid: providers::openai_paid_endpoints(),
        };
        let found = DiscoveredProvider {
            provider: Arc::new(provider),
            base_url: base_url.clone(),
            models: summary.models,
            version: summary.version,
            pricing: None,
            model_pricing: summary.model_pricing,
        };
        if client_kind.provider_supported(&found) {
            discovered.push(found);
        } else {
            rejected.push(format!(
                "{}: not compatible with {}",
                found.slug(),
                client_kind.display_name()
            ));
        }
    }

    if discovered.is_empty() {
        let detail = rejected
            .first()
            .map(|reason| format!(": {reason}"))
            .unwrap_or_default();
        return Err(format!(
            "No compatible priced inference provider found{detail}"
        ));
    }
    Ok(discovered)
}

/// Match current provider brands while accepting CLI values persisted before
/// the catalog picker switched from API-resource names to brand names.
fn provider_slug_matches(slug: &str, requested: &str) -> bool {
    slug.eq_ignore_ascii_case(requested)
        || match slug {
            "google" => requested.eq_ignore_ascii_case("generativelanguage"),
            "blockrun" => requested.eq_ignore_ascii_case("openai"),
            "alibaba" => requested.eq_ignore_ascii_case("modelstudio"),
            _ => false,
        }
}

fn discover_local_providers() -> pay_core::Result<Vec<DiscoveredProvider>> {
    let registry =
        discovery::load_registry().map_err(|e| pay_core::Error::Config(format!("{e}")))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| pay_core::Error::Config(format!("tokio runtime: {e}")))?;
    Ok(rt.block_on(discovery::discover(&registry, PROVIDER_PROBE_TIMEOUT, None)))
}

#[derive(serde::Deserialize)]
struct GatewayConfig {
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    providers: Vec<ProviderSummary>,
}

fn gateway_provider_summaries() -> Vec<ProviderSummary> {
    let Ok(client) = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(500))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return Vec::new();
    };
    fetch_gateway_provider_summaries(&client, "/__402/pdb/api/config")
        // `pay gate inference --no-web` exposes the same provider snapshot at
        // `/` instead of mounting the PDB config route.
        .or_else(|| fetch_gateway_provider_summaries(&client, "/"))
        .unwrap_or_default()
}

fn fetch_gateway_provider_summaries(
    client: &reqwest::blocking::Client,
    path: &str,
) -> Option<Vec<ProviderSummary>> {
    let response = client
        .get(format!("{}{path}", inference::LOCAL_GATEWAY_BASE_URL))
        .send()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response
        .json::<GatewayConfig>()
        .ok()
        .map(|config| config.providers)
}

fn apply_gateway_provider_summaries(
    providers: &mut Vec<DiscoveredProvider>,
    summaries: &[ProviderSummary],
) {
    providers.retain(|provider| {
        summaries
            .iter()
            .any(|summary| summary.up && summary.slug == provider.slug())
    });

    for provider in providers {
        let Some(summary) = summaries
            .iter()
            .find(|summary| summary.up && summary.slug == provider.slug())
        else {
            continue;
        };
        provider.base_url = inference::LOCAL_GATEWAY_BASE_URL.to_string();
        provider.models = summary.models.clone();
        provider.version = summary.version.clone();
        provider.model_pricing = summary.model_pricing.clone();
    }
}

fn apply_gateway_proxy_fallback(providers: &mut Vec<DiscoveredProvider>) {
    for provider in providers {
        provider.base_url = inference::LOCAL_GATEWAY_BASE_URL.to_string();
    }
}

/// Hosted pay-catalog providers appended to the picker after local
/// discovery. Everything degrades silently to local-only: catalog
/// unavailable, an fqn not (yet) published, or an unreachable gateway all
/// skip the entry with a debug log.
fn discover_catalog_providers() -> Vec<DiscoveredProvider> {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return Vec::new();
    };
    rt.block_on(async {
        let mut resolved = match load_catalog_quietly() {
            Ok(mut catalog) => {
                let fqns = catalog_providers::picker_catalog_fqns(&catalog);
                catalog_providers::resolve_catalog_providers(&mut catalog, &fqns).await
            }
            Err(e) => {
                tracing::debug!(error = %e, "skills catalog unavailable — using built-in gateway providers");
                Vec::new()
            }
        };
        catalog_providers::append_default_fallbacks(&mut resolved);
        let Ok(client) = reqwest::Client::builder()
            .timeout(CATALOG_PROBE_TIMEOUT)
            .build()
        else {
            return Vec::new();
        };

        let mut probes = tokio::task::JoinSet::new();
        for (index, provider) in resolved.drain(..).enumerate() {
            let client = client.clone();
            probes.spawn(async move {
                let base_url = provider.service_url().to_string();
                let Some(version) = provider.identify(&client, &base_url).await else {
                    tracing::debug!(
                        slug = provider.slug(),
                        %base_url,
                        "hosted catalog provider unreachable — skipping"
                    );
                    return None;
                };
                let (models, model_pricing) = provider
                    .list_models_with_pricing(&client, &base_url)
                    .await;
                let provider: Arc<dyn InferenceProvider> = Arc::new(provider);
                Some((
                    index,
                    DiscoveredProvider {
                        provider,
                        base_url,
                        models,
                        version,
                        pricing: None,
                        model_pricing,
                    },
                ))
            });
        }
        let mut discovered = Vec::new();
        while let Some(result) = probes.join_next().await {
            if let Ok(Some(provider)) = result {
                discovered.push(provider);
            }
        }
        discovered.sort_by_key(|(index, _)| *index);
        discovered
            .into_iter()
            .map(|(_, provider)| provider)
            .collect()
    })
}

/// Load the skills catalog without waking the local gateway or blocking the
/// picker on a catalog refresh.
///
/// `pay_core::skills::load_skills()` re-fetches every *ephemeral* source on
/// each call — including the `/.well-known/pay-skills.json` a running
/// `pay gate inference` auto-registers — and that fetch goes through the
/// payment gate, polluting the gateway's CONNECTIONS panel with an
/// anonymous 127.0.0.1 row on every `pay claude` launch. Provider selection is
/// not a catalog-update command, so any non-empty on-disk snapshot is suitable;
/// pinned OpenAPI sources are refreshed separately in the background.
fn load_catalog_quietly() -> pay_core::Result<pay_core::skills::Catalog> {
    if let Ok(mut catalog) = pay_core::skills::load_cached_skills() {
        pay_core::skills::overlay::merge_pins_into(&mut catalog);
        return Ok(catalog);
    }
    let mut catalog = pay_core::skills::Catalog {
        schema_version: "1".to_string(),
        generated_at: String::new(),
        base_url: String::new(),
        provider_count: 0,
        providers: Vec::new(),
    };
    pay_core::skills::overlay::merge_pins_into(&mut catalog);
    if catalog.providers.is_empty() {
        return Err(pay_core::Error::Config(
            "no cached or pinned inference providers".to_string(),
        ));
    }
    catalog.provider_count = catalog.providers.len() as u32;
    Ok(catalog)
}

/// Whether an inference gateway is already serving HTTP on its default
/// loopback URL.
///
/// `/` answers with a 307 redirect (to `/__402/ui/`), not a 200, so any
/// HTTP response at all counts as "gateway present" — only a failed
/// connection means the port is free. `/__402/pdb/api/config` returns
/// 200 JSON on a healthy gateway.
fn gateway_listening() -> bool {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(500))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .and_then(|client| {
            client
                .get(format!(
                    "{}/__402/pdb/api/config",
                    inference::LOCAL_GATEWAY_BASE_URL
                ))
                .send()
        })
        .is_ok()
}

fn claude_metadata_requested(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help" | "--version" | "-v"))
}

fn claude_args_with_model(args: &[String], model: Option<&str>) -> Vec<String> {
    let Some(model) = model else {
        return args.to_vec();
    };
    if model_arg(args).is_some() {
        return args.to_vec();
    }
    let mut out = vec!["--model".to_string(), model.to_string()];
    out.extend(args.iter().cloned());
    out
}

pub(crate) fn claude_env(base_url: &str, model: Option<&str>) -> Vec<(String, String)> {
    let mut env = vec![
        (ANTHROPIC_BASE_URL_ENV.to_string(), base_url.to_string()),
        (ANTHROPIC_API_KEY_ENV.to_string(), String::new()),
        (
            ANTHROPIC_AUTH_TOKEN_ENV.to_string(),
            OLLAMA_AUTH_TOKEN.to_string(),
        ),
        (
            "CLAUDE_CODE_ATTRIBUTION_HEADER".to_string(),
            "0".to_string(),
        ),
        (
            CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION_ENV.to_string(),
            "false".to_string(),
        ),
        (
            CLAUDE_CODE_DISABLE_TERMINAL_TITLE_ENV.to_string(),
            "1".to_string(),
        ),
    ];

    if let Some(model) = model {
        env.extend([
            (
                "ANTHROPIC_DEFAULT_OPUS_MODEL".to_string(),
                model.to_string(),
            ),
            (
                "ANTHROPIC_DEFAULT_SONNET_MODEL".to_string(),
                model.to_string(),
            ),
            (
                "ANTHROPIC_DEFAULT_HAIKU_MODEL".to_string(),
                model.to_string(),
            ),
            ("CLAUDE_CODE_SUBAGENT_MODEL".to_string(), model.to_string()),
        ]);
    }

    env
}

// On Windows, cmd.exe (used to execute .cmd batch wrappers like claude.cmd) rejects
// arguments containing angle brackets, backticks, or double-quotes. The instructions
// and mcp config both have these characters. We work around this by:
//   1. Writing the mcp config JSON to a temp file (--mcp-config accepts a file path).
//   2. Generating a PowerShell script that uses a single-quoted here-string for the
//      system prompt — here-strings are 100% literal so no character escaping is needed.
//   3. Invoking powershell -File <script> so the script handles all the quoting.
#[cfg(windows)]
fn launch_windows(
    mcp_config: serde_json::Value,
    extra_args: &[String],
    base_url: Option<&str>,
    model: Option<&str>,
) -> pay_core::Result<i32> {
    let tmp_dir = std::env::temp_dir();

    let config_path = tmp_dir.join("pay_mcp_config.json");
    std::fs::write(&config_path, mcp_config.to_string())
        .map_err(|e| pay_core::Error::Config(format!("Failed to write MCP config: {e}")))?;

    // Escape single quotes in the path for use inside a PS single-quoted string ('').
    let config_path_str = config_path.to_string_lossy().replace('\'', "''");

    // PowerShell single-quoted here-string: content is 100% literal — backticks,
    // angle brackets, quotes, etc. all pass through without interpretation.
    let script = format!(
        "& claude --mcp-config '{config_path_str}' --strict-mcp-config --allowedTools '{ALLOWED_TOOLS}' --append-system-prompt @'\n{instructions}\n'@ @args\n",
        instructions = pay_core::instructions::INSTRUCTIONS,
    );

    let script_path = tmp_dir.join("pay_claude_launcher.ps1");
    std::fs::write(&script_path, &script)
        .map_err(|e| pay_core::Error::Config(format!("Failed to write launcher script: {e}")))?;

    let mut command = Command::new("powershell");
    command
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script_path)
        .args(extra_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if let Some(base_url) = base_url {
        command.envs(claude_env(base_url, model));
    }

    let status = command.status().map_err(|e| {
        pay_core::Error::Config(format!(
            "Failed to launch `claude`: {e}. Install: `npm install -g @anthropic-ai/claude-code` (or see https://claude.com/claude-code)."
        ))
    })?;

    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_tools_include_all_pay_mcp_tools() {
        for tool in [
            "mcp__pay__curl",
            "mcp__pay__search_catalog",
            "mcp__pay__list_catalog",
            "mcp__pay__get_catalog_entry",
            "mcp__pay__get_balance",
            "mcp__pay__topup",
            "mcp__pay__create_skill",
        ] {
            assert!(ALLOWED_TOOLS.split(',').any(|allowed| allowed == tool));
        }
    }

    #[test]
    fn native_launch_preserves_args_without_provider_overrides() {
        let args = vec!["--model".into(), "sonnet".into(), "hello".into()];

        let launch = prepare_claude_launch(&args, false, None, None).unwrap();

        assert_eq!(launch.args, args);
        assert_eq!(launch.base_url, None);
        assert_eq!(launch.model, None);
    }

    #[test]
    fn claude_args_inject_model_when_missing() {
        assert_eq!(
            claude_args_with_model(&["-p".into(), "hi".into()], Some("llama3.2")),
            vec!["--model", "llama3.2", "-p", "hi"]
        );
        assert_eq!(
            claude_args_with_model(&["--model".into(), "qwen3.5".into()], Some("llama3.2")),
            vec!["--model", "qwen3.5"]
        );
    }

    #[test]
    fn claude_env_points_anthropic_to_gateway_and_model_tiers() {
        let env = claude_env("http://127.0.0.1:1402", Some("llama3.2"));

        assert!(env.contains(&(
            ANTHROPIC_BASE_URL_ENV.to_string(),
            "http://127.0.0.1:1402".to_string()
        )));
        assert!(env.contains(&(ANTHROPIC_API_KEY_ENV.to_string(), String::new())));
        assert!(env.contains(&(
            ANTHROPIC_AUTH_TOKEN_ENV.to_string(),
            OLLAMA_AUTH_TOKEN.to_string()
        )));
        assert!(env.contains(&(
            "ANTHROPIC_DEFAULT_SONNET_MODEL".to_string(),
            "llama3.2".to_string()
        )));
        assert!(env.contains(&(
            "CLAUDE_CODE_SUBAGENT_MODEL".to_string(),
            "llama3.2".to_string()
        )));
        assert!(env.contains(&(
            CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION_ENV.to_string(),
            "false".to_string()
        )));
        assert!(env.contains(&(
            CLAUDE_CODE_DISABLE_TERMINAL_TITLE_ENV.to_string(),
            "1".to_string()
        )));
    }

    #[test]
    fn alternate_clients_filter_incompatible_dialects_before_selection() {
        assert!(!AlternateClient::Claude.supports_dialect(Dialect::GeminiNative));
        assert!(AlternateClient::Claude.supports_dialect(Dialect::Anthropic));
        assert!(AlternateClient::Claude.supports_dialect(Dialect::OpenAiCompat));
        assert!(!AlternateClient::Codex.supports_dialect(Dialect::Anthropic));
        assert!(AlternateClient::Codex.supports_dialect(Dialect::OpenAiCompat));
        assert!(AlternateClient::Goose.supports_dialect(Dialect::OpenAiCompat));
        assert!(AlternateClient::Qoder.supports_dialect(Dialect::OpenAiCompat));
    }

    #[test]
    fn provider_brand_slugs_accept_legacy_resource_aliases() {
        assert!(provider_slug_matches("google", "google"));
        assert!(provider_slug_matches("google", "generativelanguage"));
        assert!(provider_slug_matches("blockrun", "openai"));
        assert!(provider_slug_matches("alibaba", "modelstudio"));
        assert!(!provider_slug_matches("blockrun", "google"));
    }

    #[test]
    fn custom_provider_url_resolves_server_origins_and_accepts_direct_catalogs() {
        assert_eq!(
            custom_source_url("inference.example.com").unwrap(),
            "https://inference.example.com/openapi.json"
        );
        assert_eq!(
            custom_source_url("http://127.0.0.1:1402/v1").unwrap(),
            "http://127.0.0.1:1402/openapi.json"
        );
        assert_eq!(
            custom_source_url("https://example.com/custom/catalog.json?channel=dev").unwrap(),
            "https://example.com/custom/catalog.json?channel=dev"
        );
        assert_eq!(
            custom_source_url("https://example.com/openapi.json").unwrap(),
            "https://example.com/openapi.json"
        );
        assert_eq!(
            custom_source_url("http://213.239.141.29:80").unwrap(),
            "http://213.239.141.29/openapi.json"
        );
        assert_eq!(
            custom_source_url("http://192.168.1.20:1402/v1").unwrap(),
            "http://192.168.1.20:1402/openapi.json"
        );
        assert_eq!(
            custom_source_url("http://[2001:db8::20]:1402").unwrap(),
            "http://[2001:db8::20]:1402/openapi.json"
        );
        assert!(custom_source_url("file:///tmp/catalog.json").is_err());
        assert!(custom_source_url("https://user:secret@example.com").is_err());
        assert!(custom_source_url("http://inference.example.com").is_err());
    }

    #[test]
    fn only_provider_picker_sources_are_treated_as_inference_pins() {
        let canonical: pay_core::skills::config::Source =
            serde_json::from_value(serde_json::json!({
                "name": "pay-skills",
                "url": pay_core::skills::config::DEFAULT_SOURCE
            }))
            .unwrap();
        assert!(!pinned_inference_source(&canonical));

        let legacy_openapi: pay_core::skills::config::Source =
            serde_json::from_value(serde_json::json!({
                "name": "openapi.json",
                "url": "http://127.0.0.1:1402/openapi.json"
            }))
            .unwrap();
        assert!(pinned_inference_source(&legacy_openapi));

        let marked_catalog: pay_core::skills::config::Source =
            serde_json::from_value(serde_json::json!({
                "name": "custom",
                "url": "https://inference.example.com/catalog.json",
                "inference": true
            }))
            .unwrap();
        assert!(pinned_inference_source(&marked_catalog));
    }

    #[test]
    fn custom_openapi_discovers_models_pricing_and_openai_routes() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use axum::Router;
                use axum::routing::get;

                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let base_url = format!("http://{}", listener.local_addr().unwrap());
                let openapi = serde_json::json!({
                    "openapi": "3.1.0",
                    "info": {"title": "Acme Inference", "version": "1.0.0"},
                    "servers": [{"url": base_url.clone()}],
                    "x-service-info": {"categories": ["compute"]},
                    "paths": {
                        "/v1/models": {
                            "get": {
                                "summary": "Models",
                                "responses": {"200": {"description": "Models"}}
                            }
                        },
                        "/v1/chat/completions": {
                            "post": {
                                "summary": "Chat",
                                "tags": ["openai"],
                                "x-payment-info": {
                                    "offers": [{
                                        "intent": "charge",
                                        "method": "x402",
                                        "amount": null,
                                        "currency": "USDC"
                                    }]
                                },
                                "x-pay-metering": {
                                    "variants": [{
                                        "param": "model",
                                        "value": "acme-large",
                                        "dimensions": [
                                            {
                                                "direction": "input",
                                                "unit": "tokens",
                                                "scale": 1000000,
                                                "tiers": [{"price_usd": 0.4}]
                                            },
                                            {
                                                "direction": "output",
                                                "unit": "tokens",
                                                "scale": 1000000,
                                                "tiers": [{"price_usd": 1.6}]
                                            }
                                        ]
                                    }]
                                },
                                "responses": {
                                    "200": {"description": "OK"},
                                    "402": {"description": "Payment Required"}
                                }
                            }
                        }
                    }
                })
                .to_string();
                let models = serde_json::json!({
                    "data": [
                        {"id": "acme-large"},
                        {"id": "acme-small"}
                    ]
                })
                .to_string();
                let app = Router::new()
                    .route(
                        "/openapi.json",
                        get({
                            let openapi = openapi.clone();
                            move || {
                                let openapi = openapi.clone();
                                async move { openapi }
                            }
                        }),
                    )
                    .route(
                        "/v1/models",
                        get({
                            let models = models.clone();
                            move || {
                                let models = models.clone();
                                async move { models }
                            }
                        }),
                    );
                tokio::spawn(async move {
                    axum::serve(listener, app).await.unwrap();
                });

                let providers = discover_custom_providers(
                    AlternateClient::Goose,
                    &format!("{base_url}/openapi.json"),
                )
                .await
                .unwrap();

                assert_eq!(providers.len(), 1);
                assert_eq!(providers[0].slug(), "acme-inference");
                assert_eq!(providers[0].models, ["acme-large", "acme-small"]);
                assert_eq!(
                    providers[0]
                        .pricing_hint_for_model(Some("acme-large"))
                        .unwrap()
                        .to_string(),
                    "input $0.40 · output $1.60 / 1M tokens"
                );
            });
    }

    #[test]
    fn custom_provider_falls_back_to_pay_inference_gateway_index() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use axum::Router;
                use axum::routing::get;

                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let base_url = format!("http://{}", listener.local_addr().unwrap());
                let index = serde_json::json!({
                    "service": "pay gate inference",
                    "providers": [{
                        "slug": "llama-cpp",
                        "title": "llama.cpp",
                        "baseUrl": "http://127.0.0.1:8081",
                        "up": true,
                        "models": ["local-model"],
                        "color": "#f59e0b",
                        "modelPricing": [{
                            "model": "local-model",
                            "variant": "local-model",
                            "price": "input $0.10 · output $0.30 / 1M tokens"
                        }]
                    }]
                })
                .to_string();
                let app = Router::new().route(
                    "/",
                    get(move || {
                        let index = index.clone();
                        async move { index }
                    }),
                );
                tokio::spawn(async move {
                    axum::serve(listener, app).await.unwrap();
                });

                let providers = discover_custom_providers(
                    AlternateClient::Goose,
                    &format!("{base_url}/openapi.json"),
                )
                .await
                .unwrap();

                assert_eq!(providers.len(), 1);
                assert_eq!(providers[0].slug(), "llama-cpp");
                assert_eq!(providers[0].base_url, base_url);
                assert_eq!(providers[0].models, ["local-model"]);
                assert_eq!(
                    providers[0]
                        .pricing_hint_for_model(Some("local-model"))
                        .unwrap()
                        .to_string(),
                    "input $0.10 · output $0.30 / 1M tokens"
                );
            });
    }

    #[test]
    fn launch_banner_abbreviates_payer_pubkeys() {
        assert_eq!(
            abbreviate_pubkey("CHPEgF7X1hYJf64oRx53ABUL43DXpEjTJBzAYmZWNuKR"),
            "CHPEg…NuKR"
        );
        assert_eq!(abbreviate_pubkey("short"), "short");
    }

    #[test]
    fn alibaba_chat_path_uses_the_deployed_gateway_prefix() {
        let provider = catalog_providers::alibaba_modelstudio_fallback();
        assert_eq!(
            chat_completions_path(&provider),
            "compatible-mode/v1/chat/completions"
        );
        assert_eq!(responses_path(&provider), "compatible-mode/v1/responses");
    }

    #[test]
    fn hosted_fallbacks_are_filtered_by_agent_wire_api() {
        let alibaba = catalog_providers::alibaba_modelstudio_fallback();
        let alibaba = DiscoveredProvider {
            models: vec!["qwen3.7-plus".to_string()],
            base_url: alibaba.service_url().to_string(),
            provider: Arc::new(alibaba),
            version: None,
            pricing: None,
            model_pricing: Vec::new(),
        };
        assert!(AlternateClient::Claude.provider_supported(&alibaba));
        assert!(AlternateClient::Codex.provider_supported(&alibaba));
        assert!(AlternateClient::Goose.provider_supported(&alibaba));

        let gemini = catalog_providers::google_gemini_fallback();
        let gemini = DiscoveredProvider {
            models: vec!["gemini-2.5-flash".to_string()],
            base_url: gemini.service_url().to_string(),
            provider: Arc::new(gemini),
            version: None,
            pricing: None,
            model_pricing: Vec::new(),
        };
        assert!(AlternateClient::Claude.provider_supported(&gemini));
        assert!(!AlternateClient::Codex.provider_supported(&gemini));
        assert!(AlternateClient::Goose.provider_supported(&gemini));
    }

    #[test]
    fn gateway_summaries_rewrite_local_provider_to_proxy_and_pricing() {
        let mut providers = vec![DiscoveredProvider {
            provider: Arc::new(crate::commands::server::inference::providers::ollama::Ollama),
            base_url: "http://127.0.0.1:11434".into(),
            models: vec!["gemma4:latest".into()],
            version: Some("0.31.1".into()),
            pricing: None,
            model_pricing: Vec::new(),
        }];
        let summaries = vec![ProviderSummary {
            slug: "ollama".into(),
            title: "Ollama".into(),
            base_url: "http://127.0.0.1:11434".into(),
            up: true,
            models: vec!["gemma4:latest".into()],
            version: Some("0.31.1".into()),
            color: Some("#22c55e".into()),
            model_pricing: vec![pay_pdb::types::ModelPricingSummary {
                model: "gemma4:latest".into(),
                variant: Some("gemma4".into()),
                price: Some("input $1.00 · output $3.00 / 1M tokens".into()),
                description: None,
            }],
        }];

        apply_gateway_provider_summaries(&mut providers, &summaries);

        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].base_url, inference::LOCAL_GATEWAY_BASE_URL);
        assert_eq!(providers[0].models, vec!["gemma4:latest"]);
        let hint = providers[0]
            .pricing_hint_for_model(Some("gemma4:latest"))
            .unwrap();
        assert_eq!(hint.to_string(), "input $1.00 · output $3.00 / 1M tokens");
        assert_eq!(hint.variant.as_deref(), Some("gemma4"));
    }

    #[test]
    fn gateway_summary_fallback_rewrites_local_provider_to_proxy() {
        let mut providers = vec![DiscoveredProvider {
            provider: Arc::new(crate::commands::server::inference::providers::ollama::Ollama),
            base_url: "http://127.0.0.1:11434".into(),
            models: vec!["gemma4:latest".into()],
            version: Some("0.31.1".into()),
            pricing: None,
            model_pricing: Vec::new(),
        }];

        apply_gateway_proxy_fallback(&mut providers);

        assert_eq!(providers[0].base_url, inference::LOCAL_GATEWAY_BASE_URL);
        assert_eq!(providers[0].models, vec!["gemma4:latest"]);
    }

    #[test]
    fn gateway_payer_upstream_preserves_selected_provider_host() {
        let provider = DiscoveredProvider {
            provider: Arc::new(crate::commands::server::inference::providers::ollama::Ollama),
            base_url: inference::LOCAL_GATEWAY_BASE_URL.into(),
            models: vec!["gemma4:latest".into()],
            version: Some("0.31.1".into()),
            pricing: None,
            model_pricing: Vec::new(),
        };

        let upstream = gateway_payer_upstream(&provider);

        assert_eq!(upstream.base_url, inference::LOCAL_GATEWAY_BASE_URL);
        assert_eq!(
            upstream.host_header.as_deref(),
            Some("ollama.localhost:1402")
        );
    }

    #[test]
    fn loopback_catalog_provider_does_not_require_every_route_to_charge() {
        let service: pay_core::skills::Service = serde_json::from_value(serde_json::json!({
            "fqn": "custom/ollama",
            "title": "Ollama",
            "category": "ai_ml",
            "service_url": "http://127.0.0.1:1402",
            "endpoints": [{
                "method": "POST",
                "path": "v1/chat/completions",
                "resource": "openai",
                "pricing": {"dimensions": [{"unit": "requests", "tiers": [{"price_usd": 0.01}]}]}
            }]
        }))
        .unwrap();
        let catalog = catalog_providers::CatalogProvider::from_service(&service);
        let provider = DiscoveredProvider {
            provider: Arc::new(catalog),
            base_url: "http://127.0.0.1:1402".to_string(),
            models: vec!["gemma4:latest".to_string()],
            version: None,
            pricing: None,
            model_pricing: Vec::new(),
        };
        assert!(!provider_requires_payment(&provider));

        let mut remote = provider;
        remote.base_url = "https://inference.example.com".to_string();
        assert!(provider_requires_payment(&remote));
    }
}
