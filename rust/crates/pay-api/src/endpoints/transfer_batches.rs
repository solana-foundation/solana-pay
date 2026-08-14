//! `POST /api/v1/transfer-batches`
//!
//! Gasless CSV batch payouts — `pay push`'s server side. This handler is
//! intentionally thin: it parses the HTTP request, resolves which network
//! runtime to use, and dispatches to `pay_api_core::transfer_batch`'s
//! `quote`/`submit` for every actual decision (validation, pricing,
//! instruction-shape checks, signing, broadcasting). See that module's docs
//! for the full two-step flow and the design decisions behind it.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use pay_api_core::Error;
use pay_api_core::transfer_batch::{
    TransferBatchError, TransferBatchRuntime, TransferBatchSettings, TransferBatchSponsor, quote,
    submit, validate_request,
};
use pay_api_types::transfer_batch::{TransferBatchRequest, TransferNetwork};
use tracing::warn;

use crate::config::PushConfig;
use crate::state::AppState;

const NOT_CONFIGURED_MESSAGE: &str =
    "set PAY_API_PUSH__ENABLED=true and configure push.fee_payer / push.networks";

pub async fn handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<TransferBatchRequest>,
) -> Result<Response, ApiError> {
    let push = state.push.as_ref().ok_or_else(|| {
        ApiError(TransferBatchError::SponsorNotConfigured(
            NOT_CONFIGURED_MESSAGE.to_string(),
        ))
    })?;

    let chunk = validate_request(&request, &state.stablecoins).map_err(ApiError)?;
    let runtime = TransferBatchRuntime::resolve(
        &chunk,
        &state.rpc,
        &push.networks,
        &push.sponsor,
        &push.settings,
    )
    .map_err(ApiError)?;

    match headers.get(AUTHORIZATION) {
        None => {
            let body = quote(&runtime, &chunk).await.map_err(ApiError)?;
            Ok((StatusCode::PAYMENT_REQUIRED, Json(body)).into_response())
        }
        Some(header) => {
            let header_str = header.to_str().map_err(|_| {
                ApiError(TransferBatchError::MalformedCredential(
                    "Authorization header is not valid UTF-8".to_string(),
                ))
            })?;
            let credential = header_str
                .strip_prefix("Bearer ")
                .unwrap_or(header_str)
                .trim();
            let body = submit(&runtime, &chunk, credential)
                .await
                .map_err(ApiError)?;
            Ok((StatusCode::OK, Json(body)).into_response())
        }
    }
}

pub struct ApiError(TransferBatchError);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        if status.is_server_error() {
            warn!(error = %self.0, "transfer-batches request failed");
        }
        (status, Json(self.0.to_body())).into_response()
    }
}

// ── State carried at boot ───────────────────────────────────────────────

/// Cached push settings the api boots with. The sponsor's fee-payer
/// signer is resolved once here (not per-request) since a batch push
/// naturally reuses it across many chunks.
pub struct PushState {
    pub networks: HashMap<TransferNetwork, String>,
    pub sponsor: TransferBatchSponsor,
    pub settings: TransferBatchSettings,
}

impl PushState {
    pub async fn from_config(cfg: &PushConfig) -> Result<Self, Error> {
        let signer = crate::signer::build_fee_payer_signer(
            &cfg.fee_payer,
            "push.fee_payer.key_name is missing",
            "push.fee_payer.pubkey is missing",
        )
        .await?;
        let fee_payer_pubkey = signer.pubkey();
        let networks = cfg
            .networks
            .iter()
            .map(|(network, nc)| (*network, nc.rpc_url.clone()))
            .collect();

        Ok(Self {
            networks,
            sponsor: TransferBatchSponsor {
                fee_payer_pubkey,
                signer,
            },
            settings: TransferBatchSettings {
                compute_unit_price_micro_lamports: cfg.compute_unit_price_micro_lamports,
                compute_unit_limit: cfg.compute_unit_limit,
                estimated_fee_lamports: cfg.estimated_fee_lamports,
                ata_rent_lamports: cfg.ata_rent_lamports,
                usd_per_sol: cfg.usd_per_sol,
                challenge_ttl: chrono::Duration::seconds(cfg.challenge_ttl_seconds),
                confirm_timeout: std::time::Duration::from_secs(cfg.confirm_timeout_seconds),
            },
        })
    }
}
