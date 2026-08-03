use std::str::FromStr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use pay_api_core::{Error, fetch_stablecoin_balances};
use pay_api_types::Network;
use serde::Deserialize;
use serde_json::json;
use solana_pubkey::Pubkey;
use tracing::warn;

use crate::state::AppState;
use crate::telemetry;

#[derive(Deserialize)]
pub struct Params {
    address: String,
    network: String,
}

pub async fn handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<Params>,
) -> Result<impl IntoResponse, ApiError> {
    let owner = Pubkey::from_str(&params.address).map_err(|_| ApiError(Error::InvalidAddress))?;
    let network: Network = params
        .network
        .parse()
        .map_err(Error::from)
        .map_err(ApiError)?;
    let rpc_url = state.rpc_url_for(network).map_err(ApiError)?;

    let balances =
        fetch_stablecoin_balances(&state.rpc, rpc_url, &owner, network, &state.stablecoins)
            .await
            .map_err(ApiError)?;
    telemetry::record_balance_request(network, balances.balances.len());

    Ok(Json(balances))
}

pub struct ApiError(Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status =
            StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        // 4xx are caller-driven; only log 5xx so we don't spam tracing on bad input.
        if status.is_server_error() {
            warn!(error = %self.0, "stablecoin balance request failed");
        }
        telemetry::record_balance_error(status.as_u16(), &self.0.to_string());
        let body = Json(json!({ "error": self.0.to_string() }));
        (status, body).into_response()
    }
}
