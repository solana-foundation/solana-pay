//! Rehearsal mode — run the entire pipeline against an embedded surfpool
//! validator + a locally-spun pay proxy, with **no real funds**. This is the
//! safe way to validate provision→prepare→unleash→settle→sweep before any
//! mainnet run; flipping `network: mainnet` swaps the funder/target for the
//! same engine code.

use std::sync::Arc;
use tokio::sync::watch;

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
use crate::seeded_session;
use crate::wallet::{self, ForkFunder};

const PROVIDER_SPEC: &str = include_str!("../configs/bench-provider.yml");
const GATE_ONLY_PROVIDER_SPEC: &str = r#"
name: bench
subdomain: bench
title: "Bench Gate-Only API"
description: "Minimal MPP-session verifier fixture."
category: ai_ml
version: v1
routing:
  type: respond
accounting: pooled
endpoints:
  - method: GET
    path: "v1/free"
    resource: "free"
    description: "Unmetered direct-response generator control."
  - method: POST
    path: "v1/charge"
    resource: "charge"
    description: "Flat rate per request."
    metering:
      schemes: [mpp-session]
      dimensions:
        - direction: usage
          unit: requests
          scale: 1
          tiers:
            - price_usd: 0.001
"#;

/// Strip the query string (e.g. `?api-key=…`) before logging a datasource URL.
fn redact(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}
const HOST_HEADER: &str = "bench.localhost";
const CHARGE_PATH: &str = "v1/charge";

fn local_usdc_currency() -> Result<String> {
    pay_kit::mpp::resolve_stablecoin_mint("USDC", Some("localnet"))
        .map(str::to_string)
        .context("resolve local USDC mint")
}

#[derive(Clone)]
struct AppState {
    apis: Arc<Vec<ApiSpec>>,
    mpp: Option<Mpp>,
    session_mpp: Option<Arc<SessionMpp>>,
}

/// Handles for the two benchmark-only listeners. The public listener is the
/// production `Http402Gate`; the axum listener is only its internal control
/// plane for free/discovery paths. Dropping this shuts the Pingora process down.
struct OfflineProxy {
    url: String,
    shutdown: watch::Sender<bool>,
}

impl Drop for OfflineProxy {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
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
    fn records_http_exchanges(&self) -> bool {
        false
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
            let currency = local_usdc_currency()?;
            // With an operator signer, session closes can settle on-chain
            // through the batched worker. Without one, the benchmark still
            // exercises open and voucher verification but does not settle.
            let mut session_mpp = SessionMpp::new(
                SessionConfig {
                    operator: operator.to_string(),
                    recipient: recipient.to_string(),
                    amount: 1_000,
                    suggested_deposit: Some(1_000_000_000),
                    // The gate dispatches by the exact canonical challenge
                    // currency, which is the settlement mint rather than the
                    // human-friendly USDC symbol.
                    currency,
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
            url: format!("{proxy_url}/v1/free"),
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
    if is_no_chain(&cfg) {
        let proxy_url = if is_offline(&cfg) {
            setup_offline_proxy(&cfg).await?
        } else {
            setup_free_proxy().await?
        };
        rewrite_endpoints(&mut cfg, &proxy_url.url);
        return drive(&cfg, &wallet::NoopFunder, "unused".to_string()).await;
    }
    let (surfnet, proxy_url, rpc_url) = setup_fork_proxy(&cfg).await?;
    rewrite_endpoints(&mut cfg, &proxy_url);
    let funder = ForkFunder { surfnet: &surfnet };
    drive(&cfg, &funder, rpc_url).await
}

fn is_offline(cfg: &RunConfig) -> bool {
    cfg.session.as_ref().map(|s| s.offline).unwrap_or(false)
}

fn is_no_chain(cfg: &RunConfig) -> bool {
    is_offline(cfg) || cfg.run.scheme == crate::config::Scheme::SelfTest
}

async fn setup_free_proxy() -> Result<OfflineProxy> {
    let api: ApiSpec =
        serde_yml::from_str(GATE_ONLY_PROVIDER_SPEC).context("parse free-path provider")?;
    start_local_pingora(
        AppState {
            apis: Arc::new(vec![api]),
            mpp: None,
            session_mpp: None,
        },
        None,
    )
    .await
}

/// Offline Pingora proxy: no fork. It uses the benchmark-only confirmed-state
/// fixture and must never be reported as an open-channel or network benchmark.
async fn setup_offline_proxy(cfg: &RunConfig) -> Result<OfflineProxy> {
    let operator = Keypair::new().pubkey().to_string();
    let recipient = Keypair::new().pubkey().to_string();
    let api: ApiSpec =
        serde_yml::from_str(GATE_ONLY_PROVIDER_SPEC).context("parse gate-only provider")?;
    let session_mpp = seeded_session::build(
        SessionConfig {
            operator,
            recipient,
            amount: 1_000,
            suggested_deposit: Some(1_000_000_000),
            currency: local_usdc_currency()?,
            decimals: 6,
            network: "localnet".to_string(),
            voucher_signer: VoucherSigner::Client,
            rpc_url: None,
            ..Default::default()
        },
        cfg.offline_namespace(),
        cfg.session
            .as_ref()
            .expect("validated session config")
            .offline_seeded_channels,
    )
    .await?;
    let state = AppState {
        apis: Arc::new(vec![api]),
        mpp: None,
        session_mpp: Some(session_mpp.session),
    };
    start_local_pingora(state, cfg.load.proxy_workers).await
}

async fn start_local_pingora(
    state: AppState,
    proxy_workers: Option<usize>,
) -> Result<OfflineProxy> {
    let control_plane = serve(state.clone()).await?;
    let control_plane = control_plane
        .strip_prefix("http://")
        .context("offline control-plane URL must use http")?
        .to_string();

    // Pingora currently accepts a bind address rather than an already-bound
    // socket. Reserve a loopback port immediately before starting it; this is
    // benchmark-local and never exposes the fixture on a public interface.
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").context("reserve offline Pingora listener")?;
    let bind = listener
        .local_addr()
        .context("read offline Pingora listener address")?
        .to_string();
    drop(listener);
    let (shutdown, receiver) = watch::channel(false);
    let gate_bind = bind.clone();
    std::thread::Builder::new()
        .name("pay-bench-pingora".to_string())
        .spawn(move || {
            if let Err(error) = pay_proxy::run_with_shutdown(
                state,
                &gate_bind,
                control_plane,
                proxy_workers,
                receiver,
            ) {
                tracing::error!(%error, "offline Pingora gate stopped unexpectedly");
            }
        })
        .context("start offline Pingora gate")?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if tokio::net::TcpStream::connect(&bind).await.is_ok() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("offline Pingora gate did not bind {bind} within five seconds");
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    Ok(OfflineProxy {
        url: format!("http://{bind}"),
        shutdown,
    })
}

/// Spin **only** the proxy and block — so it can be profiled in isolation while
/// a separate `bench load` process drives it. Offline (no fork) when configured.
pub async fn serve_proxy(cfg: RunConfig) -> Result<()> {
    if is_no_chain(&cfg) {
        let proxy_url = if is_offline(&cfg) {
            setup_offline_proxy(&cfg).await?
        } else {
            setup_free_proxy().await?
        };
        println!(
            "\n  proxy_url = {}   (offline — no rpc needed)\n",
            proxy_url.url
        );
        println!(
            "drive it:\n  bench load <config> --proxy {} --rpc unused\n",
            proxy_url.url
        );
        tracing::info!(proxy_url = %proxy_url.url, "local Pingora proxy serving (Ctrl-C to stop)");
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
    if is_no_chain(&cfg) {
        return drive(&cfg, &wallet::NoopFunder, rpc_url).await;
    }
    let funder = wallet::ExternalForkFunder {
        rpc_url: rpc_url.clone(),
    };
    drive(&cfg, &funder, rpc_url).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FunderCfg, Load, RunMeta, Safety, SessionCfg};
    use crate::scheme::www_authenticate;
    use pay_core::client::session::SessionHandle;

    fn offline_config() -> RunConfig {
        RunConfig {
            run: RunMeta {
                name: "offline-http-equivalence".to_string(),
                scheme: Scheme::MppSession,
                network: Network::Fork,
                rpc_url_env: None,
                rpc_url: None,
                tls_ca_cert_env: None,
                tls_ca_cert: None,
                mint: None,
                funder: FunderCfg::default(),
                safety: Safety {
                    max_total_usdc: 0.0,
                    max_total_sol: 0.0,
                    require_confirmation: false,
                },
            },
            load: Load {
                users: 1,
                requests_per_sec_per_user: 1.0,
                prepare_secs: 0,
                unleash_secs: 1,
                max_concurrency: 1,
                workers: 1,
                http2_prior_knowledge: false,
                proxy_workers: None,
                shard_index: 0,
                shard_count: 1,
            },
            endpoints: vec![],
            session: Some(SessionCfg {
                deposit_usdc: 1.0,
                voucher_usdc: 0.000001,
                settle_onchain: false,
                close_after_run: true,
                offline: true,
                offline_namespace: None,
                offline_seeded_channels: 1,
                pre_sign_requests_per_user: 0,
            }),
        }
    }

    #[tokio::test]
    async fn seeded_fixture_voucher_passes_the_http_gate() {
        let cfg = offline_config();
        let proxy = setup_offline_proxy(&cfg).await.unwrap();
        let client = reqwest::Client::new();
        let challenge = client
            .post(format!("{}/v1/charge", proxy.url))
            .header("host", HOST_HEADER)
            .send()
            .await
            .unwrap();
        assert_eq!(challenge.status(), reqwest::StatusCode::PAYMENT_REQUIRED);
        let header = www_authenticate(&challenge).unwrap();
        let (challenge, _) = SessionHandle::parse_challenge(&header).unwrap();
        let request: pay_kit::mpp::SessionRequest = challenge.request.decode().unwrap();
        assert_eq!(request.currency, local_usdc_currency().unwrap());
        let handle = seeded_session::handle_for_challenge(&cfg.run.name, 0, challenge).unwrap();
        let voucher = handle.voucher_header(1).await.unwrap();
        let response = client
            .post(format!("{}/v1/charge", proxy.url))
            .header("host", HOST_HEADER)
            .header("authorization", voucher)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        assert!(status.is_success(), "status {status}: {body}");
    }
}
