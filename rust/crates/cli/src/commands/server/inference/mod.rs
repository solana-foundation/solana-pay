//! `pay serve inference` — discover local AI inference servers (Ollama,
//! LM Studio, llama.cpp, vLLM, exo) and front them with the Pingora gateway,
//! tracking every request live in the TUI and the embedded web UI.
//!
//! By default this is free passthrough: synthesized specs have no metered
//! endpoints, so the payment gate forwards everything while
//! `record_exchange` still feeds the PDB correlation engine (`AllExchanges`
//! mode). With `--sandbox --price`/`--pricing` (per-model token rates), the
//! registry's `paid` endpoints are synthesized as x402-upto per-token
//! metered endpoints and the command builds a sandbox charge stack reusing
//! the `server start` machinery (localnet + Surfpool, ephemeral fee-payer
//! signer, USDC). Each priced request opens a channel with a per-request USD
//! ceiling and settles the ACTUAL token cost after serving (input×in-rate +
//! output×out-rate, from the response stream observer) — entirely in-gate,
//! no extra control-plane routes. See docs/serve-inference.md.

pub mod discovery;
pub mod pricing;
pub mod providers;
pub mod spec;

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::response::Redirect;
use axum::routing::get;
use clap::Args;
use pay_core::PaymentState;
use pay_core::server::telemetry::FeePayerWallet;
use pay_kit::mpp::server::Mpp;
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_pdb::PdbState;
use pay_pdb::correlation::CorrelationMode;
use pay_pdb::types::{InferenceInfo, ProviderSummary};
use pay_types::metering::ApiSpec;

use super::payments;
use discovery::{DiscoveredProvider, ProviderRegistry, load_registry};
use providers::InferenceProvider;

/// Canonical (user-visible) mount of the web UI in inference mode. Must live
/// under `/__402/` — the gate only forwards that prefix (plus root) to the
/// control plane. The SPA also stays mounted at `pay_pdb::PDB_PATH` because
/// its API/SSE calls are absolute paths there.
const UI_PATH: &str = "/__402/ui";
/// Local address where `pay serve inference` listens by default.
pub const DEFAULT_BIND: &str = "127.0.0.1:1402";
/// Loopback URL for the default local inference gateway.
pub const LOCAL_GATEWAY_BASE_URL: &str = "http://127.0.0.1:1402";

/// Host header that routes to a provider through the default local gateway.
pub fn local_gateway_provider_host(slug: &str) -> String {
    format!("{slug}.localhost:{}", default_gateway_port())
}

fn default_gateway_port() -> &'static str {
    DEFAULT_BIND
        .rsplit_once(':')
        .map(|(_, port)| port)
        .unwrap_or("1402")
}

#[derive(Debug, Args)]
pub struct InferenceCommand {
    /// Public bind for the gateway.
    #[arg(long, default_value = DEFAULT_BIND)]
    pub bind: String,

    /// Public IP or domain this gateway is reachable at (e.g.
    /// `203.0.113.4` or `gateway.example.com`, with optional `scheme://`
    /// and `:port`). Shown on the inference-server identity card. Omitted
    /// advertises the local bind; pass `auto` to discover the public IP via
    /// a third-party echo service (opt-in — it leaks your public IP).
    #[arg(long)]
    pub public_url: Option<String>,

    /// Skip decentralized provider registration even when `--public-url` is
    /// supplied.
    #[arg(long)]
    pub no_register: bool,

    /// Only probe these providers (comma-separated slugs, e.g. `ollama,vllm`).
    #[arg(long, value_delimiter = ',')]
    pub providers: Vec<String>,

    /// Per-endpoint probe timeout in milliseconds.
    #[arg(long, default_value_t = 400)]
    pub probe_timeout: u64,

    /// Headless: log lines instead of the TUI.
    #[arg(long)]
    pub no_tui: bool,

    /// Don't serve the embedded web UI.
    #[arg(long)]
    pub no_web: bool,

    /// Seconds between provider re-probes (0 disables watching).
    #[arg(long, default_value_t = 10)]
    pub watch_interval: u64,

    /// Extra hand-written ApiSpec YAML(s) to serve alongside discovered
    /// providers (escape hatch).
    #[arg(long)]
    pub spec: Vec<String>,

    /// Sandbox guard: refuse any spec whose operator is not explicitly
    /// `network: localnet`, so no mainnet stablecoins can move through this
    /// gateway. (Also honored when the global `pay --sandbox` flag is set.)
    #[arg(short = 's', long)]
    pub sandbox: bool,

    /// Per-model token pricing file (YAML). With `--sandbox` this CHARGES per
    /// token via x402-upto (input×in-rate + output×out-rate, settled after
    /// serve); model-listing/health stay free. Mutually exclusive with
    /// `--price`. Shape:
    ///
    /// ```yaml
    /// default: { in: 0.10, out: 0.30 }
    /// models:
    ///   "gemma4": { in: 0.15, out: 0.60 }
    ///   "qwen3:8b": { in: 0.50, out: 1.50 }
    /// ```
    #[arg(long, value_name = "FILE", conflicts_with = "price")]
    pub pricing: Option<String>,

    /// Inline per-model token pricing shorthand (comma-separated
    /// `model=in/out`; `*=in/out` or a bare `in/out` sets the default), USD
    /// per 1M tokens. With `--sandbox` this CHARGES per token via x402-upto.
    /// e.g. `gemma4=0.15/0.60,qwen3:8b=0.5/1.5,*=0.1/0.3`.
    #[arg(long, value_name = "SPEC")]
    pub price: Option<String>,
}

/// Payment state for the inference gateway: the PDB hook for live tracking,
/// plus — only when per-model pricing is set (with `--sandbox`) — the sandbox
/// x402-upto charge backend. Unpriced, the backend fields stay empty and
/// every request is `Passthrough`, exactly as before.
#[derive(Clone)]
pub struct InferenceState {
    apis: Arc<Vec<ApiSpec>>,
    /// Registry providers, for per-provider endpoint-kind classification
    /// (spec name == provider slug).
    providers: Arc<Vec<Arc<dyn InferenceProvider>>>,
    pdb: PdbState,
    /// x402-upto charge backend — the only charge scheme for inference, since
    /// per-token settlement happens AFTER the response (mpp-charge cannot).
    x402_upto: Option<pay_kit::x402::server::X402Upto>,
    fee_payer_signer: Option<Arc<dyn SolanaSigner>>,
    fee_payer_wallet: Option<FeePayerWallet>,
}

impl InferenceState {
    /// `chat` | `completion` | `embeddings` | `other` for a request path,
    /// asked of the provider that owns the spec; specs without a matching
    /// provider (`--spec` extras) fall back to the shared default mapping.
    fn endpoint_kind(&self, provider_slug: &str, path: &str) -> &'static str {
        self.providers
            .iter()
            .find(|p| p.slug() == provider_slug)
            .map(|p| p.endpoint_kind(path))
            .unwrap_or_else(|| providers::default_endpoint_kind(path))
    }
}

impl PaymentState for InferenceState {
    fn apis(&self) -> &[ApiSpec] {
        &self.apis
    }
    fn mpp(&self) -> Option<&Mpp> {
        // Inference charges only via x402-upto (post-response settlement), so
        // there is no mpp-charge backend.
        None
    }
    fn x402_upto(&self) -> Option<&pay_kit::x402::server::X402Upto> {
        self.x402_upto.as_ref()
    }
    fn fee_payer_signer(&self) -> Option<Arc<dyn SolanaSigner>> {
        self.fee_payer_signer.clone()
    }
    fn fee_payer_wallet(&self) -> Option<&FeePayerWallet> {
        self.fee_payer_wallet.as_ref()
    }
    fn record_request_start(&self, start: &pay_core::RequestStart) -> Option<u64> {
        // Same host→spec resolution the gate uses; provider slug == spec name.
        let subdomain = start.host.as_deref()?.split('.').next().unwrap_or("");
        let provider = self
            .apis
            .iter()
            .find(|a| a.subdomain == subdomain)
            .or_else(|| (self.apis.len() == 1).then(|| self.apis.first()).flatten())?
            .name
            .clone();
        let info = InferenceInfo {
            endpoint_kind: Some(self.endpoint_kind(&provider, &start.path).to_string()),
            provider,
            ..Default::default()
        };
        Some(self.pdb.begin_exchange(
            &start.method,
            &start.path,
            &start.client_ip,
            start.payment,
            Some(info),
        ))
    }
    fn record_exchange_update(&self, log_id: u64, usage: &pay_core::InferenceUsage) {
        self.pdb.update_exchange(log_id, usage_to_info(usage));
    }
    fn record_exchange(&self, exchange: pay_core::HttpExchange) {
        // Fold the final observer telemetry in while the exchange is still
        // open, then close it (or create a completed flow if no start was
        // tracked — id continuity is what ties the two together).
        if let (Some(log_id), Some(usage)) = (exchange.log_id, exchange.usage.as_ref()) {
            self.pdb.update_exchange(log_id, usage_to_info(usage));
        }
        let entry = pay_pdb::types::LogEntry {
            id: exchange.log_id.unwrap_or_else(|| self.pdb.next_log_id()),
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
        if let Ok(mut engine) = self.pdb.correlation.lock() {
            engine.ingest(entry);
        }
    }
}

/// The `--sandbox` guard: a spec may only carry an operator that explicitly
/// declares `network: localnet`. Anything else — mainnet, devnet, or an
/// unset network (which would fall back to other resolution rules) — is
/// refused loudly rather than silently rewritten, so no mainnet stablecoins
/// can move through this gateway.
fn enforce_sandbox(spec: &ApiSpec, path: &str) -> pay_core::Result<()> {
    let Some(operator) = &spec.operator else {
        return Ok(()); // no operator ⇒ no payment backend ⇒ nothing can move
    };
    match operator.network.as_deref() {
        Some("localnet") => Ok(()),
        Some(other) => Err(pay_core::Error::Config(format!(
            "--sandbox: spec {path} declares operator network \"{other}\" — only \
             \"localnet\" is allowed in sandbox mode"
        ))),
        None => Err(pay_core::Error::Config(format!(
            "--sandbox: spec {path} has an operator without an explicit network — \
             set `operator.network: localnet` to run it in sandbox mode"
        ))),
    }
}

/// Per-model pricing charge gate: per-token charging is sandbox-only for now
/// (localnet stablecoins via the Surfpool sandbox). Per-model pricing WITHOUT
/// `--sandbox` is refused loudly rather than silently pointed at a real
/// cluster — mainnet per-token charging is not wired yet. No pricing flag ⇒
/// free passthrough (unchanged).
fn enforce_pricing_sandbox(
    pricing_config: Option<&pricing::PricingConfig>,
    sandbox: bool,
) -> pay_core::Result<()> {
    if pricing_config.is_some() && !sandbox {
        return Err(pay_core::Error::Config(
            "--price/--pricing: mainnet per-token charging is not wired yet — run with --sandbox"
                .into(),
        ));
    }
    Ok(())
}

/// Resolve the per-model token pricing from `--pricing <FILE>` or `--price
/// <SPEC>`. At most one may be set (enforced by clap `conflicts_with`,
/// re-checked here so a programmatic caller can't slip both past). `None`
/// means no per-model pricing: free passthrough.
fn resolve_pricing_config(
    pricing_file: Option<&str>,
    price_inline: Option<&str>,
) -> pay_core::Result<Option<pricing::PricingConfig>> {
    match (pricing_file, price_inline) {
        (Some(_), Some(_)) => Err(pay_core::Error::Config(
            "--price and --pricing both set per-model token pricing — use one".into(),
        )),
        (Some(path), None) => Ok(Some(pricing::PricingConfig::from_yaml_file(path)?)),
        (None, Some(spec)) => Ok(Some(pricing::PricingConfig::from_inline(spec)?)),
        (None, None) => Ok(None),
    }
}

/// Public address shown on the inference-server identity card.
///
/// Precedence: explicit `--public-url` (normalized to include a scheme) →
/// auto-discovered public IP (`http://<ip>:<port>`) → the local bind
/// (`http://127.0.0.1:<port>`) when discovery is unavailable. The port is
/// carried from `bind` so the advertised address is directly dialable.
fn resolve_public_address(public_url: Option<&str>, bind: &str) -> String {
    let port = bind.rsplit(':').next().unwrap_or("1402");

    let local = || format!("http://{}", bind.replace("0.0.0.0", "127.0.0.1"));

    let Some(url) = public_url.map(str::trim).filter(|s| !s.is_empty()) else {
        // No flag: advertise the local bind. We do NOT phone a third-party IP
        // echo service by default — that leaks the host's public IP on every
        // launch. Opt in explicitly with `--public-url auto`.
        return local();
    };

    if url.eq_ignore_ascii_case("auto") {
        return match discover_public_ip() {
            Some(ip) => format!("http://{ip}:{port}"),
            None => local(),
        };
    }

    // Respect an explicit scheme; otherwise assume http and append the bind
    // port when the operator didn't specify one.
    if url.contains("://") {
        url.to_string()
    } else if url.contains(':') {
        format!("http://{url}")
    } else {
        format!("http://{url}:{port}")
    }
}

/// Best-effort public IP lookup via a plaintext echo service. Returns
/// `None` on any failure (offline, timeout, unparseable) so the caller
/// falls back to the local bind — the identity card must always render.
fn discover_public_ip() -> Option<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(1500))
        .build()
        .ok()?;
    let ip = client
        .get("https://api.ipify.org")
        .send()
        .ok()?
        .text()
        .ok()?
        .trim()
        .to_string();
    // Guard against an error page sneaking through as the "IP".
    ip.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())
}

/// Observer telemetry → PDB wire type. Provider is left empty — the
/// correlation engine merges field-wise onto the request-time info.
fn usage_to_info(usage: &pay_core::InferenceUsage) -> InferenceInfo {
    InferenceInfo {
        provider: String::new(),
        model: usage.model.clone(),
        endpoint_kind: None,
        streamed: usage.streamed,
        tokens_prompt: usage.tokens_prompt,
        tokens_completion: usage.tokens_completion,
        ttft_ms: usage.ttft_ms,
        tokens_per_sec: usage.tokens_per_sec,
    }
}

impl InferenceCommand {
    pub fn run(
        self,
        active_account_name: Option<&str>,
        global_sandbox: bool,
    ) -> pay_core::Result<()> {
        let sandbox = self.sandbox || global_sandbox;
        let pricing_config =
            resolve_pricing_config(self.pricing.as_deref(), self.price.as_deref())?;
        enforce_pricing_sandbox(pricing_config.as_ref(), sandbox)?;

        // Probe the public bind up front: Pingora only discovers a taken port
        // deep inside its service thread, where the bind failure is a panic.
        // Fail here with an actionable message instead (a second gateway is
        // usually another `pay serve inference` or a `pay claude` session).
        match std::net::TcpListener::bind(&self.bind) {
            Ok(probe) => drop(probe),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                return Err(pay_core::Error::Config(format!(
                    "{} is already in use — another gateway is running (pay serve \
                     inference or a pay claude session). Stop it or pass --bind \
                     with a free port.",
                    self.bind
                )));
            }
            Err(e) => {
                return Err(pay_core::Error::Config(format!(
                    "cannot bind {}: {e}",
                    self.bind
                )));
            }
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| pay_core::Error::Config(format!("tokio runtime: {e}")))?;

        let (internal_addr, state) = rt.block_on(self.setup(sandbox, pricing_config))?;

        if !self.no_register && self.public_url.is_some() {
            let endpoint = resolve_public_address(self.public_url.as_deref(), &self.bind);
            let signer = if let Some(signer) = state.fee_payer_signer.clone() {
                signer
            } else {
                let source = active_account_name.ok_or_else(|| {
                    pay_core::Error::Config(
                        "provider registration requires an active account; pass --no-register to serve without publishing"
                            .to_string(),
                    )
                })?;
                let intent = pay_core::keystore::AuthIntent::from_reason(
                    "register your inference service in the pay provider registry",
                );
                Arc::new(pay_core::signer::load_signer_with_intent(source, &intent)?)
                    as Arc<dyn SolanaSigner>
            };
            let registration = super::provider_registration::ServiceRegistration::new(
                "inference",
                "openai-v1",
                "pay-inference",
                "OpenAI-compatible inference served through pay",
                endpoint,
            )?;
            let rpc_url = super::provider_registration::registry_rpc_url(sandbox);
            rt.block_on(async {
                let outcome = super::provider_registration::register_service(
                    &registration,
                    signer.clone(),
                    &rpc_url,
                )
                .await?;
                if let Some(signature) = outcome.signature {
                    tracing::info!(%signature, pda = %outcome.pda, "provider registry heartbeat published");
                }
                super::provider_registration::spawn_renewal_task(
                    registration,
                    signer,
                    rpc_url,
                );
                Ok::<(), pay_core::Error>(())
            })?;
        }

        let cores = std::thread::available_parallelism().map(|n| n.get()).ok();
        // `rt` stays alive so the watch/cleanup/axum/bridge tasks keep
        // running for the life of the gateway.

        let use_tui = !self.no_tui && std::io::IsTerminal::is_terminal(&std::io::stderr());
        if !use_tui {
            // Headless: Pingora owns the main thread (it must run without an
            // ambient tokio runtime, which is true here after block_on).
            return pay_proxy::run(state, &self.bind, internal_addr.to_string(), cores)
                .map_err(|e| pay_core::Error::Config(format!("gateway: {e}")));
        }

        // TUI mode: the terminal needs the main thread, so Pingora runs on a
        // spawned thread with a caller-owned shutdown (returns instead of
        // exiting the process, so we can restore the terminal after quit).
        //
        // Subscribe the event bridge BEFORE snapshotting so no flow event
        // falls between the two.
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        let mut broadcast_rx = state.pdb.tx.subscribe();
        rt.spawn(async move {
            loop {
                match broadcast_rx.recv().await {
                    Ok(msg) => {
                        if event_tx.send(msg).is_err() {
                            break; // TUI gone
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        let initial_providers = state.pdb.providers();
        let initial_flows = state.pdb.correlation.lock().unwrap().snapshot();
        let initial_connections = state.pdb.connections();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let proxy_thread = {
            let state = state.clone();
            let bind = self.bind.clone();
            let control_plane = internal_addr.to_string();
            std::thread::spawn(move || {
                if let Err(e) =
                    pay_proxy::run_with_shutdown(state, &bind, control_plane, cores, shutdown_rx)
                {
                    tracing::error!(error = %e, "gateway exited with error");
                }
            })
        };

        let display_addr = self.bind.replace("0.0.0.0", "127.0.0.1");
        let public_url = resolve_public_address(self.public_url.as_deref(), &self.bind);
        let tui_result = crate::tui::run_inference_tui(crate::tui::InferenceTuiArgs {
            gateway_url: format!("http://{display_addr}"),
            web_url: (!self.no_web).then(|| format!("http://{display_addr}{UI_PATH}/")),
            public_url,
            initial_providers,
            initial_flows,
            initial_connections,
            events: event_rx,
        });

        let _ = shutdown_tx.send(true);
        let _ = proxy_thread.join();
        tui_result.map_err(|e| pay_core::Error::Config(format!("tui: {e}")))
    }

    async fn setup(
        &self,
        sandbox: bool,
        pricing_config: Option<pricing::PricingConfig>,
    ) -> pay_core::Result<(std::net::SocketAddr, InferenceState)> {
        let registry =
            load_registry().map_err(|e| pay_core::Error::Config(format!("registry: {e}")))?;
        let restrict = (!self.providers.is_empty()).then_some(self.providers.as_slice());
        let timeout = Duration::from_millis(self.probe_timeout);

        // Single-line probe progress: the spinner narrates the provider being
        // probed while results print above it. Hidden automatically when
        // stderr isn't a terminal.
        let spinner = indicatif::ProgressBar::new_spinner().with_style(
            indicatif::ProgressStyle::with_template("{spinner:.green} {msg}")
                .expect("static template")
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "⏺"]),
        );
        spinner.enable_steady_tick(Duration::from_millis(80));
        // On a hidden draw target (non-TTY stderr) `ProgressBar::println` is
        // dropped — fall back to plain eprintln so headless logs keep the
        // probe results.
        let emit = |line: String| {
            if spinner.is_hidden() {
                eprintln!("{line}");
            } else {
                spinner.println(line);
            }
        };
        let discovered =
            discovery::discover_with(&registry, timeout, restrict, |event| match event {
                discovery::ProbeEvent::Started(provider) => {
                    let port = provider.ports().first().copied().unwrap_or_default();
                    spinner.set_message(format!("probing {} (:{port})…", provider.title()));
                }
                discovery::ProbeEvent::Found(provider) => {
                    let version = provider
                        .version
                        .as_deref()
                        .map(|v| format!(" ({v})"))
                        .unwrap_or_default();
                    emit(format!(
                        "  {} ✓  {} · {} model{}{version}",
                        provider.slug(),
                        provider.base_url,
                        provider.models.len(),
                        if provider.models.len() == 1 { "" } else { "s" },
                    ));
                }
                discovery::ProbeEvent::Missed(provider) => {
                    emit(format!("  {} — not detected", provider.title()));
                }
            })
            .await;
        spinner.finish_and_clear();

        let mut discovered = discovered;
        if discovered.is_empty() {
            return Err(pay_core::Error::Config(
                "no local inference providers found — start one (e.g. `ollama serve`) and retry"
                    .into(),
            ));
        }

        // Per-model pricing: validate explicit model keys against the union
        // of discovered models, then ensure each routed provider has at least
        // one resolved rate (or a default). Fail BEFORE opening the
        // gateway/TUI, the same way the sandbox guard does.
        if let Some(config) = &pricing_config {
            let errs = validate_pricing_config_for_discovered(config, &discovered);
            if !errs.is_empty() {
                return Err(pay_core::Error::Config(errs.join("; ")));
            }
            for provider in &mut discovered {
                provider.pricing = Some(config.clone());
            }
        }

        // Sandbox charge stack — only when priced. `enforce_pricing_sandbox`
        // guarantees pricing implies sandbox, so this is localnet-only.
        let payment = match &pricing_config {
            Some(config) => Some(build_sandbox_payments(config.clone()).await?),
            None => None,
        };

        // Synthesized specs (+ pricing when monetized) + any --spec extras.
        let pricing = payment.as_ref().map(|p| &p.pricing);
        let mut specs: Vec<ApiSpec> = discovered
            .iter()
            .map(|provider| spec::provider_spec(provider, pricing))
            .collect();
        for path in &self.spec {
            let contents = std::fs::read_to_string(shellexpand::tilde(path).as_ref())
                .map_err(|e| pay_core::Error::Config(format!("read {path}: {e}")))?;
            let mut api = pay_core::server::profiles::load_yaml(&contents)
                .map_err(|e| pay_core::Error::Config(format!("parse {path}: {e}")))?;
            if sandbox {
                enforce_sandbox(&api, path)?;
            }
            api.apply_scheme_defaults();
            specs.push(api);
        }
        if sandbox {
            eprintln!("⏺ sandbox — localnet only; mainnet stablecoins cannot move");
        }

        let summaries = provider_summaries(&registry, restrict, &discovered);
        let pdb = PdbState::with_mode(
            serde_json::json!({
                "mode": "inference",
                "title": "Pay Inference",
                "providers": summaries,
                "network": if sandbox { "sandbox" } else { "local" },
            }),
            CorrelationMode::AllExchanges,
        );
        pdb.set_providers(summaries);
        pdb.spawn_cleanup();

        if self.watch_interval > 0 {
            spawn_watch_task(
                registry.clone(),
                self.providers.clone(),
                pricing_config,
                timeout,
                Duration::from_secs(self.watch_interval),
                pdb.clone(),
            );
        }

        // Internal control plane: the gate forwards `/__402/*` and root here.
        // The UI's canonical URL in inference mode is /__402/ui/ (users see
        // it in the address bar); the SPA's API calls are absolute
        // `/__402/pdb/*` paths, so the router stays mounted there too.
        // `nest_service` (not `nest`) so the nested root `/…/` resolves —
        // same as `server start`.
        let mut router = Router::new();
        if !self.no_web {
            router = router
                .nest_service(UI_PATH, pay_pdb::debugger_router(pdb.clone()))
                .nest_service(pay_pdb::PDB_PATH, pay_pdb::debugger_router(pdb.clone()))
                .route(
                    "/",
                    get(|| async { Redirect::temporary(&format!("{UI_PATH}/")) }),
                );
        } else {
            let index = provider_index(&pdb);
            router = router.route("/", get(move || async move { index }));
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| pay_core::Error::Config(format!("bind control-plane: {e}")))?;
        let internal_addr = listener
            .local_addr()
            .map_err(|e| pay_core::Error::Config(format!("control-plane local_addr: {e}")))?;
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                tracing::error!(error = %e, "control-plane axum server exited unexpectedly");
            }
        });

        let display_addr = self.bind.replace("0.0.0.0", "127.0.0.1");
        eprintln!("⏺ gateway on http://{display_addr}");
        if !self.no_web {
            eprintln!("⏺ web UI http://{display_addr}{UI_PATH}/");
        }
        for provider in &discovered {
            let host_port = display_addr
                .rsplit_once(':')
                .map(|(_, p)| p)
                .unwrap_or("1402");
            eprintln!(
                "  {} → http://{}.localhost:{}/",
                provider.slug(),
                provider.slug(),
                host_port
            );
        }
        if payment.is_some() {
            eprintln!("⏺ charging per token (localnet) — in/out rates from your pricing");
        }

        let (x402_upto, fee_payer_signer, fee_payer_wallet) = match payment {
            Some(payment) => (
                Some(payment.x402_upto),
                Some(payment.fee_payer_signer),
                Some(payment.fee_payer_wallet),
            ),
            None => (None, None, None),
        };
        let state = InferenceState {
            apis: Arc::new(specs),
            providers: Arc::new(registry),
            pdb,
            x402_upto,
            fee_payer_signer,
            fee_payer_wallet,
        };
        Ok((internal_addr, state))
    }
}

/// Sandbox charge backends for per-model pricing: everything the gate needs to
/// 402 the paid endpoints and settle the per-token x402-upto channel in-gate.
struct SandboxPayments {
    pricing: spec::SpecPricing,
    x402_upto: pay_kit::x402::server::X402Upto,
    fee_payer_signer: Arc<dyn SolanaSigner>,
    fee_payer_wallet: FeePayerWallet,
}

/// Build the minimal sandbox charge stack, reusing the `server start`
/// machinery (`super::payments`): localnet + sandbox RPC, the ephemeral
/// auto fee-payer signer (payout recipient = the signer's own wallet), USDC
/// only, Surfpool funding + recipient ATA preparation, the blockhash cache,
/// the charge HMAC secret env mirror, and the x402-upto charge backend (the
/// only scheme that can settle the ACTUAL per-token cost after the response).
async fn build_sandbox_payments(
    config: pricing::PricingConfig,
) -> pay_core::Result<SandboxPayments> {
    let network = crate::network::SolanaNetwork::Localnet;
    let rpc_url = payments::resolve_sandbox_rpc_url(None);

    let (fee_payer_signer, generated) = payments::load_auto_fee_payer_signer(&network)?;
    if let Some((account_name, pubkey)) = &generated {
        eprintln!("⏺ generated gateway account {account_name} ({pubkey}) on localnet");
    }
    // Funds land in the gateway's own sandbox wallet — no separate
    // recipient flag in sandbox monetization.
    let recipient = fee_payer_signer.pubkey().to_string();
    let recipient_pubkey = solana_pubkey::Pubkey::from_str(&recipient)
        .map_err(|e| pay_core::Error::Config(format!("gateway wallet pubkey: {e}")))?;

    let currency_configs = vec![{
        let (mint, decimals) = payments::resolve_currency("USDC", network.slug());
        ("USDC".to_string(), mint, decimals)
    }];
    let stable_requirements =
        payments::stable_token_account_requirements(&currency_configs, network.slug())?;

    let surfpool_targets = payments::surfpool_funding_targets(&recipient, Some(&recipient));
    let payout_targets = vec![payments::PayoutRecipientTarget {
        label: "gateway wallet".to_string(),
        pubkey: recipient_pubkey,
    }];
    let (should_fund, _balances) = payments::prepare_funding_targets(
        true,
        &network,
        &rpc_url,
        &surfpool_targets,
        &payout_targets,
        &stable_requirements,
    )
    .await?;

    // Mirror the charge HMAC secret into the env for any subscription
    // middleware that lazy-builds; the x402-upto backend itself signs vouchers
    // with the operator key and doesn't consume it, so we don't hold the value.
    let _ = payments::init_challenge_binding_secret();

    payments::ensure_payout_recipient_token_accounts(
        &[recipient_pubkey],
        &stable_requirements,
        network.slug(),
        &rpc_url,
        should_fund,
        Some(fee_payer_signer.clone()),
    )
    .await?;

    let blockhash_cache = payments::spawn_blockhash_cache(&rpc_url);
    // Charging is x402-upto only: the client opens a channel with a per-request
    // ceiling and the operator settles the ACTUAL token cost after serving the
    // response (mpp-charge cannot settle post-response). The backend-level
    // resource is a fallback label; each endpoint carries its own resource for
    // per-challenge memo uniqueness.
    let x402_upto = payments::build_sandbox_upto_backend(
        &currency_configs,
        &recipient,
        network.slug(),
        &rpc_url,
        "inference",
        fee_payer_signer.clone(),
        &blockhash_cache,
    )?;
    let fee_payer_wallet = FeePayerWallet::new(rpc_url, recipient.clone());

    Ok(SandboxPayments {
        pricing: spec::SpecPricing { config, recipient },
        x402_upto,
        fee_payer_signer,
        fee_payer_wallet,
    })
}

/// Registry providers in scope for probing (`--providers` filter applied).
fn registry_scope<'a>(
    registry: &'a ProviderRegistry,
    restrict: Option<&[String]>,
) -> Vec<&'a Arc<dyn InferenceProvider>> {
    registry
        .iter()
        .filter(|p| {
            restrict
                .map(|allowed| allowed.iter().any(|s| s == p.slug()))
                .unwrap_or(true)
        })
        .collect()
}

fn validate_pricing_config_for_discovered(
    config: &pricing::PricingConfig,
    discovered: &[DiscoveredProvider],
) -> Vec<String> {
    let available_models: Vec<String> = discovered
        .iter()
        .flat_map(|provider| provider.models.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut errs = config.validate("discovered providers", &available_models);
    if config.default.is_none() {
        for provider in discovered {
            if !provider
                .models
                .iter()
                .any(|model| config.resolve(model).is_some())
            {
                errs.push(format!(
                    "pricing: no configured model is served by {} and no `default` rate is set",
                    provider.slug()
                ));
            }
        }
    }
    errs
}

/// One summary per in-scope registry provider — discovered ones carry
/// models/version and `up: true`, the rest render as "not detected".
fn provider_summaries(
    registry: &ProviderRegistry,
    restrict: Option<&[String]>,
    discovered: &[DiscoveredProvider],
) -> Vec<ProviderSummary> {
    registry_scope(registry, restrict)
        .into_iter()
        .map(
            |provider| match discovered.iter().find(|d| d.slug() == provider.slug()) {
                Some(found) => found.summary(true),
                None => ProviderSummary {
                    slug: provider.slug().to_string(),
                    title: provider.title().to_string(),
                    base_url: format!(
                        "http://127.0.0.1:{}",
                        provider.ports().first().copied().unwrap_or_default()
                    ),
                    up: false,
                    models: Vec::new(),
                    version: None,
                    color: provider.color().map(str::to_string),
                    model_pricing: Vec::new(),
                },
            },
        )
        .collect()
}

/// Re-probe on an interval and broadcast provider status changes. Routes are
/// fixed at startup (subdomain → base_url), so a provider restarting on the
/// same port resumes seamlessly; a brand-new provider needs a gateway
/// restart, which we log once when first seen.
fn spawn_watch_task(
    registry: ProviderRegistry,
    restrict: Vec<String>,
    pricing_config: Option<pricing::PricingConfig>,
    timeout: Duration,
    interval: Duration,
    pdb: PdbState,
) {
    tokio::spawn(async move {
        let restrict_ref = (!restrict.is_empty()).then_some(restrict.as_slice());
        let mut routed: Vec<String> = pdb
            .providers()
            .iter()
            .filter(|p| p.up)
            .map(|p| p.slug.clone())
            .collect();
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await; // first tick fires immediately; skip it
        loop {
            ticker.tick().await;
            let mut discovered = discovery::discover(&registry, timeout, restrict_ref).await;
            if let Some(config) = &pricing_config {
                for provider in &mut discovered {
                    provider.pricing = Some(config.clone());
                }
            }
            for provider in &discovered {
                if !routed.iter().any(|slug| slug == provider.slug()) {
                    routed.push(provider.slug().to_string());
                    tracing::info!(
                        provider = %provider.slug(),
                        "new provider detected — restart `pay serve inference` to route it"
                    );
                }
            }
            pdb.set_providers(provider_summaries(&registry, restrict_ref, &discovered));
        }
    });
}

fn provider_index(pdb: &PdbState) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "service": "pay serve inference",
        "providers": pdb.providers(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pay_pdb::types::FlowStatus;

    fn discovered_provider(
        provider: Arc<dyn InferenceProvider>,
        models: &[&str],
    ) -> discovery::DiscoveredProvider {
        discovery::DiscoveredProvider {
            provider,
            base_url: "http://127.0.0.1:9999".into(),
            models: models.iter().map(|model| (*model).to_string()).collect(),
            version: None,
            pricing: None,
            model_pricing: Vec::new(),
        }
    }

    fn discovered_ollama() -> discovery::DiscoveredProvider {
        discovered_provider(Arc::new(providers::ollama::Ollama), &[])
    }

    fn state() -> InferenceState {
        InferenceState {
            apis: Arc::new(vec![spec::provider_spec(&discovered_ollama(), None)]),
            providers: Arc::new(providers::builtin_providers()),
            pdb: PdbState::with_mode(serde_json::json!({}), CorrelationMode::AllExchanges),
            x402_upto: None,
            fee_payer_signer: None,
            fee_payer_wallet: None,
        }
    }

    #[test]
    fn public_address_precedence_and_normalization() {
        // Explicit scheme is respected verbatim.
        assert_eq!(
            resolve_public_address(Some("https://gw.example.com"), "0.0.0.0:1402"),
            "https://gw.example.com"
        );
        // Host with an explicit port gets an http scheme.
        assert_eq!(
            resolve_public_address(Some("203.0.113.4:8080"), "0.0.0.0:1402"),
            "http://203.0.113.4:8080"
        );
        // Bare host/domain inherits the bind port.
        assert_eq!(
            resolve_public_address(Some("gw.example.com"), "0.0.0.0:1402"),
            "http://gw.example.com:1402"
        );
        assert_eq!(
            resolve_public_address(Some("203.0.113.4"), "0.0.0.0:4000"),
            "http://203.0.113.4:4000"
        );
        // No flag (or a blank one) advertises the local bind — no network
        // call, no public-IP leak by default.
        assert_eq!(
            resolve_public_address(None, "0.0.0.0:1402"),
            "http://127.0.0.1:1402"
        );
        assert_eq!(
            resolve_public_address(Some("   "), "127.0.0.1:1402"),
            "http://127.0.0.1:1402"
        );
        // `auto` opts into public-IP discovery; offline it falls back to the
        // local bind — this test only asserts a usable http URL shape.
        let auto = resolve_public_address(Some("auto"), "127.0.0.1:1402");
        assert!(auto.starts_with("http://"), "got {auto}");
    }

    #[test]
    fn pricing_without_sandbox_is_refused() {
        let config = pricing::PricingConfig::from_inline("*=0.1/0.3").unwrap();

        // Per-model pricing without --sandbox is refused (mainnet per-token
        // charging is not wired yet).
        let err = enforce_pricing_sandbox(Some(&config), false).expect_err("must refuse");
        assert!(
            err.to_string()
                .contains("mainnet per-token charging is not wired yet — run with --sandbox"),
            "unexpected message: {err}"
        );

        // With --sandbox it is allowed.
        assert!(enforce_pricing_sandbox(Some(&config), true).is_ok());

        // No pricing = free passthrough, sandbox or not.
        assert!(enforce_pricing_sandbox(None, false).is_ok());
        assert!(enforce_pricing_sandbox(None, true).is_ok());
    }

    #[test]
    fn pricing_validation_uses_discovered_model_union() {
        let config =
            pricing::PricingConfig::from_inline("gemma4=0.15/0.60,llama3.2=0.1/0.3").unwrap();
        let discovered = vec![
            discovered_provider(Arc::new(providers::ollama::Ollama), &["gemma4:latest"]),
            discovered_provider(Arc::new(providers::lm_studio::LmStudio), &["llama3.2:3b"]),
        ];

        assert_eq!(
            validate_pricing_config_for_discovered(&config, &discovered),
            Vec::<String>::new()
        );
    }

    #[test]
    fn pricing_validation_requires_provider_rate_without_default() {
        let config = pricing::PricingConfig::from_inline("gemma4=0.15/0.60").unwrap();
        let discovered = vec![
            discovered_provider(Arc::new(providers::ollama::Ollama), &["gemma4:latest"]),
            discovered_provider(Arc::new(providers::lm_studio::LmStudio), &["llama3.2:3b"]),
        ];

        let errs = validate_pricing_config_for_discovered(&config, &discovered);
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(
            errs[0].contains("no configured model is served by lm-studio"),
            "{errs:?}"
        );
    }

    #[test]
    fn sandbox_guard_rejects_non_localnet_operators() {
        let base = spec::provider_spec(&discovered_ollama(), None);

        // No operator: nothing can move, allowed.
        assert!(enforce_sandbox(&base, "spec.yml").is_ok());

        // OperatorConfig has no Default; build via YAML like real specs do.
        let with_network = |network: Option<&str>| {
            let mut spec = base.clone();
            let yaml = match network {
                Some(n) => format!("network: \"{n}\""),
                None => "fee_payer: false".to_string(),
            };
            spec.operator = Some(serde_yml::from_str(&yaml).unwrap());
            spec
        };

        assert!(enforce_sandbox(&with_network(Some("localnet")), "spec.yml").is_ok());
        let mainnet_err = enforce_sandbox(&with_network(Some("mainnet")), "spec.yml")
            .expect_err("mainnet must be refused");
        assert!(mainnet_err.to_string().contains("mainnet"));
        assert!(
            enforce_sandbox(&with_network(None), "spec.yml").is_err(),
            "unset network must be refused, not defaulted"
        );
    }

    #[test]
    fn endpoint_kind_resolves_via_provider_with_default_fallback() {
        let state = state();
        // Known provider slug: asked of the provider trait impl.
        assert_eq!(state.endpoint_kind("ollama", "/api/generate"), "completion");
        assert_eq!(
            state.endpoint_kind("ollama", "/v1/chat/completions"),
            "chat"
        );
        // Unknown spec (`--spec` extras): shared default mapping.
        assert_eq!(
            state.endpoint_kind("hand-written", "/v1/embeddings"),
            "embeddings"
        );
        assert_eq!(state.endpoint_kind("hand-written", "/status"), "other");
    }

    #[test]
    fn request_start_to_exchange_lifecycle() {
        let state = state();

        let log_id = state.record_request_start(&pay_core::RequestStart {
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            host: Some("ollama.localhost:1402".into()),
            client_ip: "127.0.0.1".into(),
            payment: false,
        });
        let log_id = log_id.expect("provider-matched request must be tracked");

        // In-flight with provider + endpoint kind from request time.
        let flows = state.pdb.correlation.lock().unwrap().snapshot();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, FlowStatus::InProgress);
        let inf = flows[0].inference.as_ref().unwrap();
        assert_eq!(inf.provider, "ollama");
        assert_eq!(inf.endpoint_kind.as_deref(), Some("chat"));

        // Live observer update merges usage without losing provider.
        state.record_exchange_update(
            log_id,
            &pay_core::InferenceUsage {
                model: Some("llama3.2:3b".into()),
                streamed: true,
                ttft_ms: Some(180),
                tokens_completion: Some(20),
                ..Default::default()
            },
        );

        // Completion closes the same flow (id continuity) with final usage.
        state.record_exchange(pay_core::HttpExchange {
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            status: 200,
            ms: 2300,
            req_headers: vec![],
            res_headers: vec![("payment-response".into(), "receipt-signature".into())],
            client_ip: "127.0.0.1".into(),
            log_id: Some(log_id),
            usage: Some(pay_core::InferenceUsage {
                model: Some("llama3.2:3b".into()),
                streamed: true,
                ttft_ms: Some(180),
                tokens_prompt: Some(12),
                tokens_completion: Some(214),
                tokens_per_sec: Some(41.2),
            }),
        });

        let flows = state.pdb.correlation.lock().unwrap().snapshot();
        assert_eq!(flows.len(), 1, "completion must close the in-flight flow");
        assert_eq!(flows[0].status, FlowStatus::ResourceDelivered);
        let inf = flows[0].inference.as_ref().unwrap();
        assert_eq!(inf.provider, "ollama");
        assert_eq!(inf.tokens_prompt, Some(12));
        assert_eq!(inf.tokens_completion, Some(214));
        assert_eq!(inf.tokens_per_sec, Some(41.2));
        assert_eq!(
            flows[0]
                .response_headers
                .as_ref()
                .and_then(|headers| headers.get("payment-response"))
                .map(String::as_str),
            Some("receipt-signature")
        );
    }

    #[test]
    fn unknown_host_is_not_tracked_in_flight() {
        let state = state();
        // Two specs would disable the single-API fallback; with one spec any
        // host matches, so test with an explicit second spec.
        let mut apis = (*state.apis).clone();
        apis.push({
            let mut second = apis[0].clone();
            second.name = "vllm".into();
            second.subdomain = "vllm".into();
            second
        });
        let state = InferenceState {
            apis: Arc::new(apis),
            providers: state.providers.clone(),
            pdb: state.pdb.clone(),
            x402_upto: None,
            fee_payer_signer: None,
            fee_payer_wallet: None,
        };

        let log_id = state.record_request_start(&pay_core::RequestStart {
            method: "GET".into(),
            path: "/whatever".into(),
            host: Some("unknown.localhost:1402".into()),
            client_ip: "127.0.0.1".into(),
            payment: false,
        });
        assert!(log_id.is_none());
    }
}
