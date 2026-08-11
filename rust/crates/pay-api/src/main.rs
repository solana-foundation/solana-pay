mod config;
mod endpoints;
mod observability;
mod signer;
mod state;
mod telemetry;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::config::Config;
use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _logging_guard = observability::init();

    let config = Config::load()?;
    info!(
        port = config.port,
        rpc_timeout_ms = config.rpc_timeout_ms,
        "starting pay-api"
    );

    // Spins up the single confidential-settlement worker run-loop (settlement +
    // periodic orphan sweep) against the server's configured network.
    let state = Arc::new(AppState::new(&config).await?);

    let app = Router::new()
        .route("/health", get(endpoints::health::handler))
        .route("/v1/onramp/start", get(endpoints::onramp::handler))
        .route(
            "/v1/onramp/complete",
            get(endpoints::onramp::complete_handler),
        )
        // Legacy aliases kept during the CLI and dashboard rollout.
        .route("/onramp", get(endpoints::onramp::handler))
        .route("/onramp/done", get(endpoints::onramp::complete_handler))
        .route(
            "/v1/balance/stablecoins",
            get(endpoints::stablecoin_balances::handler),
        )
        .route("/v1/receipt", get(endpoints::receipt::handler))
        .route("/v1/receipts", get(endpoints::receipt::handler))
        .route(
            "/v1/receipts/{signature}",
            get(endpoints::receipt::handler_by_path),
        )
        .route("/v1/send", post(endpoints::send::handler))
        .route("/v1/redeem", post(endpoints::redeem::handler))
        .route(
            "/v1/subscriptions/cancel",
            post(endpoints::subscriptions::cancel_handler),
        )
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr = format!("0.0.0.0:{}", config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!(%addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
