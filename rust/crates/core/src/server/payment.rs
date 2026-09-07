//! Payment middleware for the proxy.
//!
//! Intercepts requests to metered endpoints:
//! - No payment header → 402 with MPP challenge (WWW-Authenticate)
//! - Payment header → verify with solana-mpp, then forward upstream

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http_body::Body as _;
use pay_kit::mpp::AUTHORIZATION_HEADER;

use crate::PaymentState;
use crate::server::metering::{self, RequestProperties};
use crate::server::session_stream::{self, SessionStreamContext};
use crate::server::telemetry;

const MAX_DELEGATED_MODEL_HINT_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Axum middleware that gates metered endpoints behind MPP payment.
pub async fn payment_middleware<S: PaymentState>(
    axum::extract::State(state): axum::extract::State<S>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let span = tracing::info_span!(
        "payment_middleware",
        tx_sig = tracing::field::Empty,
        receipt_url = tracing::field::Empty,
    );
    #[cfg(feature = "otel")]
    crate::server::otel::set_parent_from_headers(&span, req.headers());
    tracing::Instrument::instrument(gate_adapter(state, req, next), span).await
}

/// Thin axum adapter over the framework-agnostic [`crate::server::gate`]: build
/// a `GateRequest`, evaluate, and map the `GateDecision` back onto axum.
async fn gate_adapter<S: PaymentState>(state: S, req: Request<Body>, next: Next) -> Response {
    use crate::server::gate::{GateDecision, GateRequest, PaymentGate};

    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let path = uri.path().trim_start_matches('/').to_string();

    let str_header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let authorization = str_header(AUTHORIZATION_HEADER);
    let content_length = headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let query = uri.query().map(str::to_string);
    let x402_payment = str_header(pay_kit::x402::PAYMENT_SIGNATURE_HEADER)
        .or_else(|| str_header(pay_kit::x402::X402_V1_PAYMENT_HEADER));

    let gate_req = GateRequest {
        method: &method,
        path: &path,
        host: host.as_deref(),
        accept: accept.as_deref(),
        authorization: authorization.as_deref(),
        content_length,
        query: query.as_deref(),
        x402_payment: x402_payment.as_deref(),
    };
    let gate = PaymentGate::new(state.clone());
    match gate.evaluate(&gate_req).await {
        GateDecision::Respond(r) => {
            let mut builder = Response::builder().status(r.status);
            for (n, v) in &r.headers {
                builder = builder.header(n, v);
            }
            builder
                .body(Body::from(r.body))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        GateDecision::Forward {
            session,
            receipt,
            upto,
            batch,
            paid_request,
        } => {
            let mut req = req;
            let mut delegated_session = None;
            if let Some(sf) = session {
                let mut sf = *sf;
                if sf.settlement.is_some() {
                    // Delegated sessions are settled from the completed
                    // response below. The client-voucher stream context waits
                    // for client commits and must not be installed here.
                    if sf
                        .settlement
                        .as_deref()
                        .is_some_and(|plan| plan.variant_hint.is_none())
                    {
                        let force_stream_usage = path.ends_with("chat/completions");
                        let (restored, body_variant) =
                            match prepare_delegated_request_body(req, force_stream_usage).await {
                                Ok(result) => result,
                                Err(response) => return response,
                            };
                        req = restored;
                        if let Some(plan) = sf.settlement.as_deref_mut() {
                            plan.variant_hint = body_variant;
                        }
                    }
                    delegated_session = Some(sf);
                } else {
                    req.extensions_mut().insert(SessionStreamContext::new(
                        sf.handle,
                        sf.channel_id,
                        sf.committed_base_units,
                    ));
                }
            }
            let mut response = next.run(req).await;
            if let Some(sf) = delegated_session {
                response = settle_axum_delegated_response(sf, response).await;
            }
            // x402 `upto`: settle the opened channel *after* serving — debit the
            // metered amount on success, refund on failure.
            if let Some(uf) = upto {
                let served_ok = response.status().is_success();
                if let Some(plan) = uf.settlement {
                    if metering::upto_requires_response_body(
                        &plan.metering,
                        plan.variant_hint.as_deref(),
                    ) {
                        let limit = metering::upto_response_body_limit(&plan.metering);
                        let (mut parts, body) = response.into_parts();
                        match axum::body::to_bytes(body, limit).await {
                            Ok(bytes) => {
                                if let Some((n, v)) = crate::server::gate::settle_upto_metered(
                                    &state,
                                    *uf.open,
                                    plan,
                                    served_ok,
                                    &parts.headers,
                                    Some(&bytes),
                                    uf.telemetry,
                                )
                                .await
                                {
                                    parts.headers.append(n, v);
                                }
                                parts.headers.remove(header::CONTENT_LENGTH);
                                response = Response::from_parts(parts, Body::from(bytes));
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "failed to buffer x402 upto response body; refunding"
                                );
                                let mut builder =
                                    Response::builder().status(StatusCode::BAD_GATEWAY);
                                if let Some((n, v)) = crate::server::gate::settle_upto(
                                    &state,
                                    *uf.open,
                                    0,
                                    false,
                                    uf.telemetry,
                                )
                                .await
                                {
                                    builder = builder.header(n, v);
                                }
                                response = builder
                                    .header(header::CONTENT_TYPE, "application/json")
                                    .body(Body::from(r#"{"error":"response_metering_failed"}"#))
                                    .unwrap_or_else(|_| {
                                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                                    });
                            }
                        }
                    } else if let Some((n, v)) = crate::server::gate::settle_upto_metered(
                        &state,
                        *uf.open,
                        plan,
                        served_ok,
                        response.headers(),
                        None,
                        uf.telemetry,
                    )
                    .await
                    {
                        response.headers_mut().append(n, v);
                    }
                } else if let Some((n, v)) = crate::server::gate::settle_upto(
                    &state,
                    *uf.open,
                    uf.settle_amount,
                    served_ok,
                    uf.telemetry,
                )
                .await
                {
                    response.headers_mut().append(n, v);
                }
            }
            // x402 `batch-settlement`: the voucher commits only now, and only
            // for a response that actually served. A failure drops the outcome,
            // leaving the client uncharged and free to retry it.
            if let Some(bf) = batch {
                let mut served_ok = response.status().is_success();
                let mut cached = None;
                if served_ok {
                    let cacheable = response.body().size_hint().upper().is_some_and(|length| {
                        length <= crate::server::gate::MAX_BATCH_CACHED_RESPONSE_BYTES as u64
                    });
                    if cacheable {
                        let (mut parts, body) = response.into_parts();
                        match axum::body::to_bytes(
                            body,
                            crate::server::gate::MAX_BATCH_CACHED_RESPONSE_BYTES,
                        )
                        .await
                        {
                            Ok(bytes) => {
                                cached = Some(crate::server::gate::batch_cached_response(
                                    parts.status,
                                    &parts.headers,
                                    &bytes,
                                ));
                                parts.headers.remove(header::CONTENT_LENGTH);
                                response = Response::from_parts(parts, Body::from(bytes));
                            }
                            Err(error) => {
                                tracing::warn!(
                                    %error,
                                    "failed to buffer x402 batch response; releasing authorization"
                                );
                                served_ok = false;
                                response = StatusCode::BAD_GATEWAY.into_response();
                            }
                        }
                    }
                }
                if let Some((n, v)) =
                    crate::server::gate::settle_batch(&state, *bf, served_ok, cached).await
                {
                    response.headers_mut().append(n, v);
                }
            }
            if let Some(ann) = receipt {
                for (n, v) in ann.headers {
                    response.headers_mut().append(n, v);
                }
                if let Some(reference) = ann.reference {
                    tracing::Span::current().record("tx_sig", reference.as_str());
                }
            }
            if let Some(paid_request) = paid_request {
                telemetry::record_paid_request_completed(
                    paid_request.protocol,
                    &paid_request.subdomain,
                    &path,
                    response.status(),
                    paid_request.payment.as_ref(),
                );
            }
            response
        }
        GateDecision::Passthrough => next.run(req).await,
    }
}

/// Read the model selected by OpenAI/Anthropic-compatible JSON requests and
/// restore the body for the upstream handler. Native model routes already
/// carry their variant in the path and never enter this path.
// A direct `Response` error lets the middleware short-circuit without losing
// status, headers, or body content produced while reading the request body.
#[allow(clippy::result_large_err)]
async fn prepare_delegated_request_body(
    request: Request<Body>,
    force_stream_usage: bool,
) -> Result<(Request<Body>, Option<String>), Response> {
    let (mut parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_DELEGATED_MODEL_HINT_BODY_BYTES)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "failed to read delegated session request model");
            Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"request_body_too_large"}"#))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        })?;
    let (variant, bytes) = prepare_delegated_json_body(&bytes, force_stream_usage);
    if force_stream_usage && let Ok(content_length) = bytes.len().to_string().parse() {
        parts.headers.insert(header::CONTENT_LENGTH, content_length);
    }
    Ok((Request::from_parts(parts, Body::from(bytes)), variant))
}

fn prepare_delegated_json_body(body: &[u8], force_stream_usage: bool) -> (Option<String>, Vec<u8>) {
    let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return (None, body.to_vec());
    };
    let variant = json
        .get("model")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .map(str::to_string);

    let is_stream = json
        .get("stream")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if !force_stream_usage || !is_stream {
        return (variant, body.to_vec());
    }

    let Some(object) = json.as_object_mut() else {
        return (variant, body.to_vec());
    };
    let stream_options = object
        .entry("stream_options")
        .or_insert_with(|| serde_json::json!({}));
    if !stream_options.is_object() {
        *stream_options = serde_json::json!({});
    }
    if let Some(stream_options) = stream_options.as_object_mut() {
        stream_options.insert("include_usage".to_string(), serde_json::Value::Bool(true));
    }

    (
        variant,
        serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec()),
    )
}

async fn settle_axum_delegated_response(
    forward: crate::server::gate::SessionForward,
    response: Response,
) -> Response {
    if !response.status().is_success() {
        // Dropping `forward` releases the capacity lease without charging for
        // a response that was not successfully served.
        return response;
    }

    let is_sse = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .any(|part| part.trim().eq_ignore_ascii_case("text/event-stream"))
        });
    if is_sse && session_stream::DelegatedSessionStreamMeter::supports(&forward) {
        let (mut parts, body) = response.into_parts();
        let meter = match session_stream::DelegatedSessionStreamMeter::from_forward(forward) {
            Ok(meter) => meter,
            Err(error) => {
                tracing::error!(%error, "failed to configure delegated session stream metering");
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"error":"session_metering_failed"}"#))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        };
        parts.headers.remove(header::CONTENT_LENGTH);
        return Response::from_parts(
            parts,
            Body::from_stream(session_stream::meter_delegated_response_stream(
                body.into_data_stream(),
                meter,
                true,
            )),
        );
    }

    let limit = forward
        .settlement
        .as_deref()
        .map(|plan| metering::upto_response_body_limit(&plan.metering))
        .unwrap_or(1024 * 1024);
    let (mut parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, limit).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, "failed to buffer delegated session response body");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"response_metering_failed"}"#))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };

    match crate::server::gate::settle_delegated_session(forward, &parts.headers, Some(&bytes)).await
    {
        Ok(receipt) => {
            if let Some(receipt) = receipt {
                for (name, value) in receipt.headers {
                    parts.headers.append(name, value);
                }
            }
            parts.headers.remove(header::CONTENT_LENGTH);
            Response::from_parts(parts, Body::from(bytes))
        }
        Err(error) => {
            tracing::error!(%error, "failed to settle delegated MPP session usage");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"session_settlement_failed"}"#))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

/// Resolved per-unit price in token base units — the session challenge's
/// `amount` field (price per unit of service).
///
/// Converts the USD price by decimal scaling alone, so it is only sound for
/// USD-pegged settlement tokens (1 whole token == $1). Server startup
/// enforces that invariant by refusing non-pegged session currencies
/// (`ensure_session_currencies_usd_pegged` in the CLI server start path).
pub(crate) fn price_unit_base_amount(price: &metering::ResolvedPrice, decimals: u8) -> u64 {
    let per_unit = price
        .dimensions
        .first()
        .map(|d| d.price_usd / d.scale.max(1) as f64)
        .unwrap_or(0.01);
    ((per_unit * 10f64.powi(i32::from(decimals))).round() as u64).max(1)
}

/// Per-unit charge amount (USD, as a decimal string) derived from the
/// resolved price; falls back to "0.01" when no price is configured. Shared
/// by the 402-issuing and verify paths so the advertised and expected amounts
/// always match.
pub(crate) fn charge_amount_from_price(price: Option<&metering::ResolvedPrice>) -> String {
    price
        .and_then(|p| p.dimensions.first())
        .map(|d| {
            let per_unit = d.price_usd / d.scale.max(1) as f64;
            format!("{}", per_unit)
        })
        .unwrap_or_else(|| "0.01".to_string())
}

pub(crate) fn resolve_charge_splits(
    mpp: &pay_kit::mpp::server::Mpp,
    meter: &pay_types::metering::Metering,
    api: &pay_types::metering::ApiSpec,
    uri: &axum::http::Uri,
    amount: &str,
) -> Vec<pay_kit::mpp::protocol::solana::Split> {
    let split_rules = metering::resolve_split_rules(meter);
    if split_rules.is_empty() {
        return vec![];
    }

    let amount_f64: f64 = amount.parse().unwrap_or(0.0);
    let decimals = mpp.decimals() as u8;
    let query_params = parse_query_params(uri);

    match pay_types::splits::resolve_splits(
        split_rules,
        &api.recipients,
        amount_f64,
        decimals,
        &query_params,
    ) {
        Ok(resolved) => resolved
            .into_iter()
            .map(|split| pay_kit::mpp::protocol::solana::Split {
                recipient: split.recipient,
                amount: split.amount.to_string(),
                ata_creation_required: None,
                label: split.label,
                memo: split.memo,
            })
            .collect(),
        Err(e) => {
            tracing::debug!(error = %e, "Splits not resolved — omitting from challenge");
            vec![]
        }
    }
}

pub(crate) fn decode_payment_amount(
    credential: &pay_kit::mpp::PaymentCredential,
    decimals: u8,
) -> Option<telemetry::PaymentAmount> {
    let request: pay_kit::mpp::ChargeRequest = credential.challenge.request.decode().ok()?;
    telemetry::payment_amount_from_raw(&request.amount, decimals, request.currency)
}

const RESOURCE_MEMO_NONCE_HEX_LEN: usize = 3;
const RESOURCE_MEMO_TRUNC_HASH_HEX_LEN: usize = 6;
const RESOURCE_MEMO_TRUNC_SUFFIX_LEN: usize =
    1 + 1 + RESOURCE_MEMO_TRUNC_HASH_HEX_LEN + RESOURCE_MEMO_NONCE_HEX_LEN;

pub(crate) fn resource_memo_with_nonce(resource: Option<&str>, max_bytes: usize) -> Option<String> {
    let resource = resource.map(str::trim).filter(|r| !r.is_empty())?;
    let nonce = rand::random::<[u8; 2]>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
        .chars()
        .take(RESOURCE_MEMO_NONCE_HEX_LEN)
        .collect::<String>();
    let memo = format!("{resource}#{nonce}");
    if memo.len() <= max_bytes {
        Some(memo)
    } else {
        let prefix_len = max_bytes.checked_sub(RESOURCE_MEMO_TRUNC_SUFFIX_LEN)?;
        let prefix = truncate_to_char_boundary(resource, prefix_len);
        if prefix.is_empty() {
            None
        } else {
            let hash = resource_memo_hash(resource);
            Some(format!("{prefix}#t{hash}{nonce}"))
        }
    }
}

pub(crate) fn resource_memo_matches(memo: &str, resource: &str, max_bytes: usize) -> bool {
    if memo == resource {
        return true;
    }
    let Some((prefix, suffix)) = memo.rsplit_once('#') else {
        return false;
    };
    if suffix.len() == RESOURCE_MEMO_NONCE_HEX_LEN
        && suffix.as_bytes().iter().all(u8::is_ascii_hexdigit)
        && prefix == resource
    {
        return true;
    }
    let Some(binding) = suffix.strip_prefix('t') else {
        return false;
    };
    if binding.len() != RESOURCE_MEMO_TRUNC_HASH_HEX_LEN + RESOURCE_MEMO_NONCE_HEX_LEN
        || !binding.as_bytes().iter().all(u8::is_ascii_hexdigit)
        || !binding.starts_with(&resource_memo_hash(resource))
    {
        return false;
    }
    let Some(expected_prefix_len) = max_bytes.checked_sub(RESOURCE_MEMO_TRUNC_SUFFIX_LEN) else {
        return false;
    };
    let expected_prefix = truncate_to_char_boundary(resource, expected_prefix_len);
    resource.len() > expected_prefix_len
        && !expected_prefix.is_empty()
        && prefix == expected_prefix
        && memo.len() <= max_bytes
}

fn resource_memo_hash(resource: &str) -> String {
    blake3::hash(resource.as_bytes()).to_hex()[..RESOURCE_MEMO_TRUNC_HASH_HEX_LEN].to_string()
}

fn truncate_to_char_boundary(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

pub fn readable_verification_message(error: &pay_kit::mpp::server::VerificationError) -> String {
    let message = error.to_string();
    if message.contains("Fee payer cannot authorize the SPL payment transfer") {
        return "Payment used the same account for the server and client. Restart the demo server, then retry the request.".to_string();
    }
    if message.contains("Fee payer token account cannot fund the SPL payment transfer") {
        return "Payment used the server account instead of the client account. Restart the demo server, then retry the request.".to_string();
    }
    if message.contains("ATA creation owner is not authorized by the challenge") {
        return "Payment tried to create a token account this charge did not allow.".to_string();
    }
    message
}

fn parse_query_params(uri: &axum::http::Uri) -> std::collections::HashMap<String, String> {
    uri.query()
        .map(|query| {
            query
                .split('&')
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    Some((
                        parts.next()?.to_string(),
                        parts.next().unwrap_or("").to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn extract_request_properties(headers: &HeaderMap, _path: &str) -> RequestProperties {
    let body_size = headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    RequestProperties {
        body_size,
        ..Default::default()
    }
}

pub(crate) fn extract_variant_hint(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        if (*part == "models" || *part == "voices")
            && let Some(next) = parts.get(i + 1)
        {
            return Some(next.split(':').next().unwrap_or(next).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPLIT_RECIPIENT: &str = "CNR1b172rotbSG6kCpfR76KB2ios2y7X4p8yEEc7pjLu";

    fn configured_charge_splits() -> (pay_types::metering::ApiSpec, pay_types::metering::Metering) {
        let spec: pay_types::metering::ProviderSpec = serde_yml::from_str(&format!(
            r#"
provider: test
generated_at: "2026-09-02T00:00:00Z"
apis:
  - name: split-test
    subdomain: split-test
    title: "Split test"
    description: "Exercises configured MPP charge splits."
    category: ai_ml
    version: v1
    routing:
      type: respond
    recipients:
      rounding:
        account: "{SPLIT_RECIPIENT}"
        label: "Rounding leg"
      platform:
        account: "{SPLIT_RECIPIENT}"
        label: "Platform leg"
    endpoints:
      - method: POST
        path: v1/test
        metering:
          dimensions:
            - direction: usage
              unit: requests
              scale: 1
              tiers:
                - price_usd: 0.0015
          splits:
            # This rounds to zero USDC base units at six decimals.
            - recipient: rounding
              amount: 0.0000004
              memo: "Rounding adjustment"
            # A second leg to the same account is valid when its memo differs.
            - recipient: platform
              percent: 5
              memo: "Platform fee"
"#
        ))
        .expect("test YAML should parse");
        let api = spec.apis.into_iter().next().expect("test API should exist");
        let meter = api.endpoints[0]
            .metering
            .clone()
            .expect("test endpoint should be metered");
        (api, meter)
    }

    fn test_mpp() -> pay_kit::mpp::server::Mpp {
        pay_kit::mpp::server::Mpp::new(pay_kit::mpp::server::Config {
            recipient: SPLIT_RECIPIENT.to_string(),
            // An unreachable local RPC keeps challenge construction offline.
            rpc_url: Some("http://127.0.0.1:1".to_string()),
            challenge_binding_secret: Some(
                "test-challenge-binding-secret-must-be-32-bytes".to_string(),
            ),
            ..Default::default()
        })
        .expect("test MPP server should initialize")
    }

    fn challenge_splits_from_config() -> serde_json::Value {
        let (api, meter) = configured_charge_splits();
        let mpp = test_mpp();
        let uri: axum::http::Uri = "/v1/test".parse().unwrap();
        let splits = resolve_charge_splits(&mpp, &meter, &api, &uri, "0.0015");

        let challenge = mpp
            .charge_with_options(
                "0.0015",
                pay_kit::mpp::server::ChargeOptions {
                    splits,
                    ..Default::default()
                },
            )
            .expect("PayKit should accept resolved charge splits");
        let request: pay_kit::mpp::ChargeRequest = challenge
            .request
            .decode()
            .expect("PayKit challenge should decode");
        request
            .method_details
            .expect("PayKit charge challenge should include method details")
    }

    #[test]
    fn configured_charge_split_that_rounds_to_zero_reaches_pay_kit() {
        let details = challenge_splits_from_config();
        let splits = details["splits"]
            .as_array()
            .expect("PayKit challenge should include splits");

        assert_eq!(splits.len(), 2);
        assert_eq!(splits[0]["recipient"], SPLIT_RECIPIENT);
        assert_eq!(splits[0]["amount"], "0");
        assert_eq!(splits[0]["memo"], "Rounding adjustment");
    }

    #[test]
    fn configured_charge_splits_allow_same_recipient_with_distinct_memos() {
        let details = challenge_splits_from_config();
        let splits = details["splits"]
            .as_array()
            .expect("PayKit challenge should include splits");

        assert_eq!(splits[0]["recipient"], splits[1]["recipient"]);
        assert_eq!(splits[0]["memo"], "Rounding adjustment");
        assert_eq!(splits[1]["memo"], "Platform fee");
        assert_eq!(splits[1]["amount"], "75");
    }

    #[test]
    fn extract_variant_hint_models() {
        assert_eq!(
            extract_variant_hint("v1/models/gemini-2.0-flash:generateContent"),
            Some("gemini-2.0-flash".to_string())
        );
    }

    #[test]
    fn extract_variant_hint_voices() {
        assert_eq!(
            extract_variant_hint("v1/voices/chirp-3-hd:synthesize"),
            Some("chirp-3-hd".to_string())
        );
    }

    #[test]
    fn extract_variant_hint_no_colon() {
        assert_eq!(
            extract_variant_hint("v1/models/gpt-4"),
            Some("gpt-4".to_string())
        );
    }

    #[test]
    fn extract_variant_hint_no_match() {
        assert_eq!(extract_variant_hint("v1/images/generate"), None);
    }

    #[test]
    fn extract_variant_hint_empty() {
        assert_eq!(extract_variant_hint(""), None);
    }

    #[test]
    fn extract_variant_hint_models_at_end() {
        // "models" is the last segment — no next segment
        assert_eq!(extract_variant_hint("v1/models"), None);
    }

    #[test]
    fn delegated_json_body_reads_openai_compatible_model() {
        assert_eq!(
            prepare_delegated_json_body(br#"{"model":"qwen3.7-max","stream":true}"#, false).0,
            Some("qwen3.7-max".to_string())
        );
    }

    #[test]
    fn delegated_json_body_rejects_missing_or_invalid_models() {
        assert_eq!(
            prepare_delegated_json_body(br#"{"stream":true}"#, false).0,
            None
        );
        assert_eq!(
            prepare_delegated_json_body(br#"{"model":"  "}"#, false).0,
            None
        );
        assert_eq!(prepare_delegated_json_body(b"not json", false).0, None);
    }

    #[test]
    fn delegated_chat_stream_forces_provider_usage_frames() {
        let (variant, body) = prepare_delegated_json_body(
            br#"{"model":"qwen3.7-plus","stream":true,"stream_options":{"include_usage":false}}"#,
            true,
        );
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(variant.as_deref(), Some("qwen3.7-plus"));
        assert_eq!(
            json.pointer("/stream_options/include_usage"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn delegated_non_stream_request_body_is_unchanged() {
        let body = br#"{"model":"qwen3.7-plus","stream":false}"#;
        let (_, prepared) = prepare_delegated_json_body(body, true);
        assert_eq!(prepared, body);
    }

    #[test]
    fn extract_request_properties_with_content_length() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", "12345".parse().unwrap());
        let props = extract_request_properties(&headers, "/v1/test");
        assert_eq!(props.body_size, Some(12345));
    }

    #[test]
    fn extract_request_properties_no_content_length() {
        let headers = HeaderMap::new();
        let props = extract_request_properties(&headers, "/v1/test");
        assert_eq!(props.body_size, None);
    }

    #[test]
    fn extract_request_properties_invalid_content_length() {
        let mut headers = HeaderMap::new();
        headers.insert("content-length", "not-a-number".parse().unwrap());
        let props = extract_request_properties(&headers, "/v1/test");
        assert_eq!(props.body_size, None);
    }

    #[test]
    fn parse_query_params_keeps_missing_values() {
        let uri: axum::http::Uri = "/v1/test?foo=bar&empty&baz=qux".parse().unwrap();
        let params = parse_query_params(&uri);
        assert_eq!(params.get("foo"), Some(&"bar".to_string()));
        assert_eq!(params.get("empty"), Some(&"".to_string()));
        assert_eq!(params.get("baz"), Some(&"qux".to_string()));
    }

    #[test]
    fn resource_memo_keeps_resource_and_adds_3_hex_char_nonce() {
        let memo = resource_memo_with_nonce(Some("fortune"), 566).unwrap();
        assert!(memo.starts_with("fortune#"));
        assert_eq!(memo.len(), "fortune#".len() + 3);
        assert!(resource_memo_matches(&memo, "fortune", 566));
    }

    #[test]
    fn resource_memo_matcher_accepts_legacy_static_resource() {
        assert!(resource_memo_matches("fortune", "fortune", 566));
        assert!(!resource_memo_matches("fortune#not-hex", "fortune", 566));
        assert!(!resource_memo_matches("other#012", "fortune", 566));
    }

    #[test]
    fn resource_memo_truncates_resource_to_keep_nonce_within_limit() {
        let resource = "fortune/very/long";
        let memo = resource_memo_with_nonce(Some(resource), 12).unwrap();
        assert!(memo.starts_with("f#t"));
        assert_eq!(memo.len(), 12);
        assert!(resource_memo_matches(&memo, resource, 12));
        assert!(!resource_memo_matches(
            &memo,
            resource,
            pay_kit::mpp::protocol::solana::MAX_MEMO_BYTES
        ));
    }

    #[test]
    fn resource_memo_matcher_rejects_short_resource_memo_for_longer_resource() {
        assert!(!resource_memo_matches("api/path#abc", "api/path/extra", 12));
    }

    #[test]
    fn readable_verification_message_explains_fee_payer_authority_conflict() {
        let error = pay_kit::mpp::server::VerificationError::invalid_payload(
            "Fee payer cannot authorize the SPL payment transfer",
        );
        let message = readable_verification_message(&error);
        assert_eq!(
            message,
            "Payment used the same account for the server and client. Restart the demo server, then retry the request."
        );
    }

    #[test]
    fn readable_verification_message_explains_disallowed_ata_creation() {
        let error = pay_kit::mpp::server::VerificationError::invalid_payload(
            "ATA creation owner is not authorized by the challenge",
        );
        let message = readable_verification_message(&error);
        assert_eq!(
            message,
            "Payment tried to create a token account this charge did not allow."
        );
    }
}
