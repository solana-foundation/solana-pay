//! Rehearsal mode — run the entire pipeline against an embedded surfpool
//! validator + a locally-spun pay proxy, with **no real funds**. This is the
//! safe way to validate provision→prepare→unleash→settle→sweep before any
//! mainnet run; flipping `network: mainnet` swaps the funder/target for the
//! same engine code.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::routing::any;
use axum::{Router, middleware};
use pay_core::PaymentState;
use pay_core::server::session::SessionMpp;
use pay_kit::mpp::server::Mpp;
use pay_kit::mpp::server::session::{SessionConfig, VoucherSigner};
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_kit::mpp::solana_keychain::memory::MemorySigner;
use pay_types::metering::ApiSpec;
use surfpool_sdk::{Keypair, Signer, Surfnet};

use crate::config::{Endpoint, Network, RunConfig, Scheme};
use crate::engine::{self, PipelineParams};
use crate::journal::{self, Journal};
use crate::report::ReportJson;
use crate::scheme;
use crate::wallet::{self, ForkFunder};

const PROVIDER_SPEC: &str = include_str!("../configs/bench-provider.yml");

/// Strip the query string (e.g. `?api-key=…`) before logging a datasource URL.
fn redact(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}
const HOST_HEADER: &str = "bench.localhost";
const CHARGE_PATH: &str = "v1/charge";

#[derive(Clone)]
struct AppState {
    apis: Arc<Vec<ApiSpec>>,
    mpp: Option<Mpp>,
    session_mpp: Option<Arc<SessionMpp>>,
}

impl PaymentState for AppState {
    fn apis(&self) -> &[ApiSpec] {
        &self.apis
    }
    fn mpp(&self) -> Option<&Mpp> {
        self.mpp.as_ref()
    }
    fn session_mpp(&self) -> Option<&SessionMpp> {
        self.session_mpp.as_deref()
    }
}

/// Bind a TCP listener with an explicit accept backlog (capped by the OS
/// `somaxconn`), returned as a tokio listener. The default `TcpListener::bind`
/// uses a small/somaxconn-limited backlog that overflows under connect bursts.
pub(crate) fn bind_with_backlog(addr: &str, backlog: i32) -> Result<tokio::net::TcpListener> {
    use socket2::{Domain, Socket, Type};
    let addr: std::net::SocketAddr = addr.parse().context("parse bind addr")?;
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(backlog)?;
    tokio::net::TcpListener::from_std(sock.into()).context("listener from std")
}

/// Serve the in-process pay proxy with the given state; return its base URL.
async fn serve(state: AppState) -> Result<String> {
    let app = Router::new()
        .fallback(any(|| async {
            axum::Json(serde_json::json!({"ok": true}))
        }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<AppState>,
        ))
        .with_state(state);

    // Bind with a large accept backlog (default is tiny / somaxconn-capped),
    // so bursts of concurrent connects don't overflow the queue → refused.
    let listener = bind_with_backlog("127.0.0.1:0", 2048).context("bind proxy listener")?;
    let url = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    Ok(url)
}

/// Build the proxy state for the configured scheme. Session runs need a
/// `SessionMpp` (push mode) + a funded operator; everything else uses a charge
/// `Mpp`. Returns (state, operator pubkey if any).
fn build_state(
    scheme: Scheme,
    apis: Arc<Vec<ApiSpec>>,
    rpc_url: &str,
    recipient: &str,
    operator: &str,
    operator_signer: Option<Arc<dyn SolanaSigner>>,
) -> Result<AppState> {
    match scheme {
        Scheme::MppSession => {
            // With an operator signer, session closes can settle on-chain
            // through the batched worker. Without one, the benchmark still
            // exercises open and voucher verification but does not settle.
            let mut session_mpp = SessionMpp::new(
                SessionConfig {
                    operator: operator.to_string(),
                    recipient: recipient.to_string(),
                    amount: 1_000,
                    suggested_deposit: Some(1_000_000_000),
                    // PayKit resolves this canonical symbol to the
                    // corresponding settlement mint when building the
                    // challenge.
                    currency: "USDC".to_string(),
                    decimals: 6,
                    network: "localnet".to_string(),
                    voucher_signer: VoucherSigner::Client,
                    rpc_url: Some(rpc_url.to_string()),
                    ..Default::default()
                },
                "bench-session-secret",
            );
            if let Some(signer) = operator_signer {
                session_mpp = session_mpp.with_payment_channel_signer(signer);
            }
            Ok(AppState {
                apis,
                mpp: None,
                session_mpp: Some(Arc::new(session_mpp)),
            })
        }
        _ => {
            let mpp = Mpp::new(pay_kit::mpp::server::Config {
                recipient: recipient.to_string(),
                currency: "SOL".to_string(),
                decimals: 9,
                network: "localnet".to_string(),
                rpc_url: Some(rpc_url.to_string()),
                challenge_binding_secret: Some("bench-rehearsal-secret-not-for-prod!".to_string()),
                ..Default::default()
            })
            .map_err(|e| anyhow::anyhow!("mpp config: {e}"))?;
            Ok(AppState {
                apis,
                mpp: Some(mpp),
                session_mpp: None,
            })
        }
    }
}

/// Spin a surfpool fork + the pay proxy, returning the live handle (keep it
/// alive) and the proxy/RPC URLs. Shared by `run` (in-process driver), `serve`
/// (proxy-only, separate process), and tests.
async fn setup_fork_proxy(cfg: &RunConfig) -> Result<(Surfnet, String, String)> {
    // The fork's datasource: if the config supplies an RPC (rpc_url /
    // rpc_url_env), surfpool JIT-fetches mainnet state from it (a real
    // mainnet-fork); otherwise it runs as a pure offline localnet.
    let datasource = cfg.resolve_rpc_url()?;
    let mut builder = Surfnet::builder().airdrop_sol(10_000_000_000);
    match &datasource {
        Some(url) => {
            tracing::info!(datasource = %redact(url), "starting surfpool JIT mainnet-fork");
            builder = builder.remote_rpc_url(url.clone());
        }
        None => {
            tracing::info!("starting surfpool offline localnet (no datasource configured)");
            builder = builder.offline(true);
        }
    }
    let surfnet = builder
        .start()
        .await
        .map_err(|e| anyhow::anyhow!("start surfnet: {e}"))?;
    let rpc_url = surfnet.rpc_url().to_string();

    // The wallet that collects proceeds — funded so its account exists.
    let recipient = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&recipient.pubkey(), 1_000_000_000)
        .map_err(|e| anyhow::anyhow!("fund recipient: {e}"))?;
    // The operator (session fee-payer / channel authority + settlement signer)
    // — funded, and its signer drives on-chain batched settlement at close.
    let operator = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&operator.pubkey(), 1_000_000_000)
        .map_err(|e| anyhow::anyhow!("fund operator: {e}"))?;
    // Only hand the proxy a settlement signer when the config opts into real
    // on-chain settlement; otherwise the stand-in close stays a no-op.
    let settle_onchain = cfg
        .session
        .as_ref()
        .map(|s| s.settle_onchain)
        .unwrap_or(false);
    let operator_signer: Option<Arc<dyn SolanaSigner>> = if settle_onchain {
        Some(Arc::new(
            MemorySigner::from_bytes(&operator.to_bytes())
                .map_err(|e| anyhow::anyhow!("operator signer: {e}"))?,
        ))
    } else {
        None
    };

    let api: ApiSpec = serde_yml::from_str(PROVIDER_SPEC).context("parse rehearsal provider")?;
    let state = build_state(
        cfg.run.scheme,
        Arc::new(vec![api]),
        &rpc_url,
        &recipient.pubkey().to_string(),
        &operator.pubkey().to_string(),
        operator_signer,
    )?;
    let proxy_url = serve(state).await?;
    tracing::info!(%proxy_url, %rpc_url, scheme = ?cfg.run.scheme, "fork proxy up");
    Ok((surfnet, proxy_url, rpc_url))
}

/// Point `cfg` at the proxy + force the routing Host header. Self-test targets a
/// free path (passthrough → 200) to isolate raw throughput; the on-chain schemes
/// hit the metered path.
fn rewrite_endpoints(cfg: &mut RunConfig, proxy_url: &str) {
    cfg.endpoints = match cfg.run.scheme {
        crate::config::Scheme::SelfTest => vec![Endpoint {
            url: format!("{proxy_url}/__402/health"),
            method: "GET".into(),
            body: String::new(),
            weight: 1,
        }],
        _ => vec![Endpoint {
            url: format!("{proxy_url}/{CHARGE_PATH}"),
            method: "POST".into(),
            body: "{}".into(),
            weight: 1,
        }],
    };
}

/// Run the driver pipeline (provision → prepare → unleash → settle/sweep)
/// against an already-configured proxy, with the given funder.
async fn drive(
    cfg: &RunConfig,
    funder: &dyn wallet::Funder,
    rpc_url: String,
) -> Result<ReportJson> {
    let funder_wallet = wallet::load_funder(&cfg.run.funder, Network::Fork)?;
    let scheme = scheme::build(cfg);
    let run_id = journal::new_run_id(&cfg.run.name, &chrono::Utc::now());
    let mut jrnl = Journal::create(
        run_id.clone(),
        cfg.run.name.clone(),
        cfg.run.scheme,
        Network::Fork,
        funder_wallet.pubkey.to_string(),
    )?;
    let result = engine::run_pipeline(PipelineParams {
        config: cfg,
        scheme: scheme.as_ref(),
        funder,
        funder_seed: funder_wallet.seed(),
        wallet_set_id: &run_id,
        rpc_url,
        host_override: Some(HOST_HEADER.to_string()),
        journal: &mut jrnl,
    })
    .await;
    match &result {
        Ok(_) => tracing::info!(run_id = %jrnl.state().run_id, "run complete"),
        Err(e) => {
            let _ = jrnl.set_status(crate::journal::Status::Failed);
            tracing::error!(error = %format!("{e:#}"), "run failed");
        }
    }
    result
}

/// Run a full rehearsal of `cfg` against a local fork (proxy + driver in one
/// process). Returns the report.
pub async fn run(mut cfg: RunConfig) -> Result<ReportJson> {
    let (surfnet, proxy_url, rpc_url) = setup_fork_proxy(&cfg).await?;
    rewrite_endpoints(&mut cfg, &proxy_url);
    let funder = ForkFunder { surfnet: &surfnet };
    drive(&cfg, &funder, rpc_url).await
}

fn is_offline(cfg: &RunConfig) -> bool {
    cfg.session.as_ref().map(|s| s.offline).unwrap_or(false)
}

/// Offline axum proxy: no fork. Current PayKit still requires a verifiable
/// payment-channel open, so this path is kept for the forthcoming synthetic
/// verification fixture rather than reported as a production-session run.
async fn setup_offline_proxy() -> Result<String> {
    let operator = Keypair::new().pubkey().to_string();
    let recipient = Keypair::new().pubkey().to_string();
    let api: ApiSpec = serde_yml::from_str(PROVIDER_SPEC).context("parse rehearsal provider")?;
    let session_mpp = SessionMpp::new(
        SessionConfig {
            operator,
            recipient,
            amount: 1_000,
            suggested_deposit: Some(1_000_000_000),
            currency: "USDC".to_string(),
            decimals: 6,
            network: "localnet".to_string(),
            voucher_signer: VoucherSigner::Client,
            rpc_url: None,
            ..Default::default()
        },
        "bench-session-secret",
    );
    let state = AppState {
        apis: Arc::new(vec![api]),
        mpp: None,
        session_mpp: Some(Arc::new(session_mpp)),
    };
    serve(state).await
}

/// Spin **only** the proxy and block — so it can be profiled in isolation while
/// a separate `bench load` process drives it. Offline (no fork) when configured.
pub async fn serve_proxy(cfg: RunConfig) -> Result<()> {
    if is_offline(&cfg) {
        let proxy_url = setup_offline_proxy().await?;
        println!("\n  proxy_url = {proxy_url}   (offline — no rpc needed)\n");
        println!("drive it:\n  bench load <config> --proxy {proxy_url} --rpc unused\n");
        tracing::info!(%proxy_url, "offline axum proxy serving (Ctrl-C to stop)");
        tokio::signal::ctrl_c().await.ok();
        return Ok(());
    }
    let (_surfnet, proxy_url, rpc_url) = setup_fork_proxy(&cfg).await?;
    println!("\n  proxy_url = {proxy_url}\n  rpc_url   = {rpc_url}\n");
    println!(
        "drive it from another shell:\n  bench load <config> --proxy {proxy_url} --rpc {rpc_url}\n"
    );
    tracing::info!(%proxy_url, %rpc_url, "proxy serving (Ctrl-C to stop)");
    tokio::signal::ctrl_c().await.ok();
    Ok(())
}

/// Drive load against an **external** proxy (run in a separate process from
/// `serve`, so the proxy's flamegraph isn't polluted by the generator). Offline
/// mode needs no fork/funding; otherwise funds users via cheatcode RPC.
pub async fn load(mut cfg: RunConfig, proxy_url: String, rpc_url: String) -> Result<ReportJson> {
    rewrite_endpoints(&mut cfg, &proxy_url);
    if is_offline(&cfg) {
        return drive(&cfg, &wallet::NoopFunder, rpc_url).await;
    }
    let funder = wallet::ExternalForkFunder {
        rpc_url: rpc_url.clone(),
    };
    drive(&cfg, &funder, rpc_url).await
}
