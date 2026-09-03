use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use pay_api_core::{Error, Receipt, apply_confirmation_status, build_receipt};
use pay_api_types::Network;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, warn};

use crate::state::AppState;
use crate::telemetry;

#[derive(Deserialize)]
pub struct Params {
    /// Long form. The plural route also accepts `sig` for brevity.
    #[serde(default, alias = "sig")]
    signature: Option<String>,
    #[serde(default = "default_network")]
    network: String,
}

#[derive(Deserialize, Default)]
pub struct NetworkQuery {
    #[serde(default = "default_network")]
    network: String,
}

fn default_network() -> String {
    "mainnet".to_string()
}

/// `GET /v1/receipt(s)?signature=…&network=…` — query-param shape. Accepts
/// either `?signature=` or the shorter `?sig=` alias, and works at both
/// `/v1/receipt` (singular) and `/v1/receipts` (plural) for forgiveness.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<Params>,
) -> Result<impl IntoResponse, ApiError> {
    let sig = params.signature.ok_or_else(|| {
        ApiError::not_found("`signature` (or `sig`) query parameter is required".into())
    })?;
    resolve_receipt(state, sig, params.network).await
}

/// `GET /v1/receipts/{signature}?network=…` — RESTful path-param shape used
/// for shareable receipt URLs.
pub async fn handler_by_path(
    State(state): State<Arc<AppState>>,
    Path(signature): Path<String>,
    Query(query): Query<NetworkQuery>,
) -> Result<impl IntoResponse, ApiError> {
    resolve_receipt(state, signature, query.network).await
}

async fn resolve_receipt(
    state: Arc<AppState>,
    signature: String,
    network: String,
) -> Result<impl IntoResponse, ApiError> {
    let signature = signature.trim().to_string();
    if signature.is_empty() {
        return Err(ApiError::not_found("signature is required".into()));
    }
    if !is_plausible_signature(&signature) {
        return Err(ApiError::bad_request(Error::InvalidAddress));
    }

    let network: Network = network
        .parse()
        .map_err(Error::from)
        .map_err(ApiError::bad_request)?;
    let rpc_url = state.rpc_url_for(network).map_err(ApiError::bad_request)?;

    let tx = state
        .rpc
        .get_transaction_json_parsed(rpc_url, &signature)
        .await
        .map_err(ApiError::upstream)?;

    let Some(tx_value) = tx else {
        telemetry::record_receipt_error(404, "not_found");
        return Err(ApiError::not_found(format!(
            "transaction {signature} not found on {}",
            network.as_str()
        )));
    };

    let mut receipt: Receipt = build_receipt(
        &state.rpc,
        rpc_url,
        &signature,
        network,
        &tx_value,
        &state.stablecoins,
    )
    .await
    .map_err(ApiError::upstream)?;

    // Best-effort confirmation status; ignore failures.
    if let Ok(status_value) = state.rpc.get_signature_status(rpc_url, &signature).await {
        apply_confirmation_status(&mut receipt, status_value.as_ref());
    }

    // Best-effort SOL/USD **spot** price (NOT the price at the receipt's
    // block_time — Helius DAS / CoinGecko's simple endpoint both return live
    // prices). Try Helius DAS first if the mainnet RPC supports it; fall
    // back to CoinGecko's free public endpoint so this works even with the
    // default public mainnet RPC. Failures are silent.
    receipt.sol_usd_price = fetch_sol_spot_price(&state).await;

    telemetry::record_receipt_request(network, &receipt);

    Ok(Json(receipt))
}

/// Resolve the current SOL/USD spot price, trying Helius DAS first (if the
/// configured mainnet RPC supports it) then falling back to CoinGecko. Returns
/// `None` if both fail; the field is informational and never load-bearing.
async fn fetch_sol_spot_price(state: &AppState) -> Option<f64> {
    if let Ok(mainnet_rpc) = state.rpc_url_for(Network::Mainnet) {
        match state
            .rpc
            .get_asset_price_per_token(mainnet_rpc, &state.send.sol_price_asset)
            .await
        {
            Ok(price) => return Some(price),
            Err(err) => debug!(error = %err, "DAS price unavailable, falling back to CoinGecko"),
        }
    }
    match state.rpc.fetch_sol_usd_spot_via_coingecko().await {
        Ok(price) => Some(price),
        Err(err) => {
            warn!(error = %err, "SOL spot price unavailable");
            None
        }
    }
}

fn is_plausible_signature(value: &str) -> bool {
    // Base58 signatures are 86-88 chars; never include non-base58 chars.
    let len_ok = (32..=128).contains(&value.len());
    let chars_ok = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l'));
    len_ok && chars_ok
}

pub enum ApiError {
    BadRequest(Error),
    NotFound(String),
    Upstream(Error),
}

impl ApiError {
    fn bad_request(err: Error) -> Self {
        Self::BadRequest(err)
    }
    fn not_found(msg: String) -> Self {
        Self::NotFound(msg)
    }
    fn upstream(err: Error) -> Self {
        Self::Upstream(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            Self::BadRequest(err) => (
                StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::BAD_REQUEST),
                err.to_string(),
            ),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, message),
            Self::Upstream(err) => {
                let status = StatusCode::from_u16(err.http_status())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                let message = err.to_string();
                if status.is_server_error() {
                    warn!(error = %message, "receipt request failed");
                }
                (status, message)
            }
        };
        telemetry::record_receipt_error(status.as_u16(), &message);
        let body = Json(json!({ "error": message }));
        (status, body).into_response()
    }
}
