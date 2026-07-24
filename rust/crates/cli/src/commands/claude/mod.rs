pub(crate) mod translate;

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
    let agent = client.name();
    let requested_model = model_arg(args);
    let gateway_up = gateway_listening();
    let mut providers = discover_local_providers()?;
    if gateway_up {
        let gateway_providers = gateway_provider_summaries();
        if !gateway_providers.is_empty() {
            apply_gateway_provider_summaries(&mut providers, &gateway_providers);
        } else {
            apply_gateway_proxy_fallback(&mut providers);
        }
    }
    providers.extend(discover_catalog_providers());
    providers.retain(|provider| client.provider_supported(provider));

    let choice = if providers.is_empty() {
        None
    } else {
        Some(select_provider_choice(
            agent,
            providers,
            requested_model.as_deref(),
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
/// 2. **Gateway on 127.0.0.1:1402** (the user ran `pay serve inference`,
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
        require_payment: provider.hosted(),
        payment_protocol: provider_payment_protocol(provider),
    }
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
        "modelstudio" | "generativelanguage" => payer_proxy::PaymentProtocol::MppSession,
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
    agent: &str,
    providers: Vec<DiscoveredProvider>,
    requested_model: Option<&str>,
) -> pay_core::Result<crate::tui::ProviderChoice> {
    match select_provider(agent, providers, requested_model)
        .map_err(|e| pay_core::Error::Config(format!("Provider selection failed: {e}")))?
    {
        ProviderSelection::Selected(choice) => Ok(choice),
        ProviderSelection::Cancelled => Err(pay_core::Error::Config(format!(
            "{agent} provider selection cancelled"
        ))),
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
        // `pay serve inference --no-web` exposes the same provider snapshot at
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
        let mut resolved = match load_catalog_quietly().await {
            Ok(mut catalog) => catalog_providers::resolve_catalog_providers(
                &mut catalog,
                catalog_providers::DEFAULT_CATALOG_FQNS,
            )
            .await,
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

        let mut discovered = Vec::new();
        for provider in resolved {
            let base_url = provider.service_url().to_string();
            let provider: Arc<dyn InferenceProvider> = Arc::new(provider);
            let Some(version) = provider.identify(&client, &base_url).await else {
                tracing::debug!(
                    slug = provider.slug(),
                    %base_url,
                    "hosted catalog provider unreachable — skipping"
                );
                continue;
            };
            let models = provider.list_models(&client, &base_url).await;
            discovered.push(DiscoveredProvider {
                provider,
                base_url,
                models,
                version,
                pricing: None,
                model_pricing: Vec::new(),
            });
        }
        discovered
    })
}

/// Load the skills catalog without waking the local gateway when possible.
///
/// `pay_core::skills::load_skills()` re-fetches every *ephemeral* source on
/// each call — including the `/.well-known/pay-skills.json` a running
/// `pay serve inference` auto-registers — and that fetch goes through the
/// payment gate, polluting the gateway's CONNECTIONS panel with an
/// anonymous 127.0.0.1 row on every `pay claude` launch. The hosted
/// defaults are durable CDN entries, so a fresh on-disk cache (pure disk
/// read) is all we need; the full network load only runs when the cache is
/// stale or missing — the same cadence as any other `pay skills` command.
async fn load_catalog_quietly() -> pay_core::Result<pay_core::skills::Catalog> {
    let cache_is_fresh = pay_core::skills::config::SkillsConfig::load()
        .map(|cfg| cfg.valid_cache_path().is_some())
        .unwrap_or(false);
    if cache_is_fresh && let Ok(catalog) = pay_core::skills::load_cached_skills() {
        return Ok(catalog);
    }
    pay_core::skills::load_skills().await
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

fn claude_env(base_url: &str, model: Option<&str>) -> Vec<(String, String)> {
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
        assert_eq!(responses_path(&provider), "v1/responses");
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
                price: Some("in $1.00 · out $3.00 /1M tok".into()),
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
        assert_eq!(hint.to_string(), "in $1.00 · out $3.00 /1M tok");
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
}
