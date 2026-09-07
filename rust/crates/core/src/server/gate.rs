//! Framework-agnostic payment gate.
//!
//! [`PaymentGate::evaluate`] is the single source of truth for "what should
//! happen to this request" — discovery passthrough, the HTTP 402 challenge, and
//! credential verification across the charge / session / subscription paths. It
//! reads only request **metadata** (never the body) and returns a
//! [`GateDecision`] describing the outcome in framework-neutral terms.
//!
//! Thin adapters map a framework's request/response onto this core:
//! - the axum `payment_middleware` (this crate), and
//! - `Http402Gate` (the Pingora `ProxyHttp` gateway, `pay-proxy` crate).
//!
//! Keeping the decision here means the gating logic lives once and is unit
//! testable without any HTTP framework.

use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use pay_kit::mpp::server::{ChargeOptions, VerificationError};
use pay_kit::mpp::{
    ChargeRequest, PAYMENT_RECEIPT_HEADER, PaymentCredential, Receipt, ReceiptKind,
    SessionReceiptExtensions, SessionReceiptIntent, base64url_encode, format_receipt,
    format_www_authenticate, format_www_authenticate_many, parse_authorization,
};
use pay_kit::x402::PAYMENT_RESPONSE_HEADER;
use pay_kit::x402::server::{
    BatchAccess, BatchOutcome, ExactOptions, VerifiedUptoOpen, X402, X402BatchSettlement, X402Upto,
};
use pay_types::metering::Scheme;
use serde_json::json;

use crate::PaymentState;
use crate::server::metering;
use crate::server::session::{DelegatedCapacityLease, SessionMpp, SessionOutcome};
use crate::server::telemetry;

/// `payment-receipt-url` — shareable `pay.sh/receipt/<sig>` link.
const PAYMENT_RECEIPT_URL: HeaderName = HeaderName::from_static("payment-receipt-url");

/// CSP for the rendered HTML 402 payment page.
const PAYMENT_PAGE_CSP: &str = "\
    default-src 'self'; \
    script-src 'unsafe-inline'; \
    style-src 'unsafe-inline'; \
    img-src 'self' data: blob: https:; \
    connect-src 'self' http://localhost:* http://127.0.0.1:* https:; \
    worker-src 'self'";

/// Match pay-kit's bounded representation cache. Larger or streaming bodies
/// keep settlement-only replay semantics instead of growing channel state
/// without bound.
pub const MAX_BATCH_CACHED_RESPONSE_BYTES: usize = 1024 * 1024;

/// Everything the gate needs from a request. No body — the decision is made
/// from metadata alone, so the body can stream straight to the upstream.
pub struct GateRequest<'a> {
    pub method: &'a Method,
    /// Path with the leading `/` trimmed (e.g. `v1/chat`).
    pub path: &'a str,
    pub host: Option<&'a str>,
    pub accept: Option<&'a str>,
    pub authorization: Option<&'a str>,
    pub content_length: Option<u64>,
    pub query: Option<&'a str>,
    /// x402 payment header value (`PAYMENT-SIGNATURE` or `X-PAYMENT`), if present.
    pub x402_payment: Option<&'a str>,
}

/// A complete response the adapter should send as-is. `headers` is a `Vec` so
/// duplicate `WWW-Authenticate` lines (RFC 7235, one per currency) are preserved.
pub struct GateResponse {
    pub status: StatusCode,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
}

impl GateResponse {
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }
    pub fn header(mut self, name: HeaderName, value: impl Into<String>) -> Self {
        if let Ok(v) = HeaderValue::from_str(&value.into()) {
            self.headers.push((name, v));
        }
        self
    }
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }
    pub fn json(status: StatusCode, body: impl Into<Bytes>) -> Self {
        Self::new(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
    }
}

/// Annotation applied to the upstream response after a verified payment: the
/// `payment-receipt-url` / `payment-receipt-header` lines and the settlement
/// signature (recorded on the trace span).
pub struct ReceiptAnnotation {
    /// Response headers to set on the forwarded response — protocol-specific:
    /// MPP sets `payment-receipt-url` + `payment-receipt-header`, x402 sets
    /// `PAYMENT-RESPONSE`.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// Settlement reference / signature, recorded as `tx_sig` on the span.
    pub reference: Option<String>,
}

/// Bounded telemetry context carried from payment verification to the adapter's
/// final upstream response. Authentication-only forwards leave this absent.
pub struct PaidRequestTelemetry {
    pub protocol: &'static str,
    pub subdomain: String,
    pub payment: Option<telemetry::PaymentAmount>,
}

/// Session-stream metering context for a forwarded session request. The
/// adapter attaches it so the response-stream metering layer can debit the
/// channel as bytes flow back.
pub struct SessionForward {
    pub handle: Arc<SessionMpp>,
    pub channel_id: String,
    pub committed_base_units: u64,
    /// Response-metered settlement plan for a delegated session. The adapter
    /// rates actual usage and persists an operator-signed cumulative voucher
    /// before releasing the matching response bytes.
    pub settlement: Option<Box<metering::UptoSettlementPlan>>,
    /// Remaining channel capacity available to the metered delivery.
    pub available_base_units: u64,
    /// Releases the exclusive capacity reservation on every terminal path.
    _reservation: Option<DelegatedCapacityLease>,
}

impl SessionForward {
    pub(crate) fn delegated(
        handle: Arc<SessionMpp>,
        channel_id: String,
        committed_base_units: u64,
        settlement: metering::UptoSettlementPlan,
        available_base_units: u64,
        reservation: DelegatedCapacityLease,
    ) -> Self {
        Self {
            handle,
            channel_id,
            committed_base_units,
            settlement: Some(Box::new(settlement)),
            available_base_units,
            _reservation: Some(reservation),
        }
    }
}

pub fn delegated_session_receipt_annotation(
    network: &str,
    currency: &str,
    channel_id: &str,
    amount: u64,
    cumulative: u64,
    authorized: u64,
    idle_timeout_seconds: u32,
) -> Result<ReceiptAnnotation, String> {
    let mut receipt = serde_json::to_value(ReceiptKind::Session {
        base: Receipt::success("solana", channel_id, ""),
        extensions: SessionReceiptExtensions {
            intent: SessionReceiptIntent::Session,
            accepted_cumulative: cumulative,
            spent: cumulative,
            idle_timeout_seconds,
            tx_hash: None,
            refunded: None,
        },
    })
    .map_err(|error| format!("failed to serialize MPP session receipt: {error}"))?;
    let fields = receipt
        .as_object_mut()
        .ok_or_else(|| "MPP session receipt did not serialize as an object".to_string())?;
    fields.insert("amount".to_string(), serde_json::json!(amount.to_string()));
    fields.insert(
        "authorized".to_string(),
        serde_json::json!(authorized.to_string()),
    );
    fields.insert(
        "remaining".to_string(),
        serde_json::json!(authorized.saturating_sub(cumulative).to_string()),
    );
    fields.insert("currency".to_string(), serde_json::json!(currency));
    fields.insert("network".to_string(), serde_json::json!(network));

    let encoded = serde_json::to_vec(&receipt)
        .map(|json| base64url_encode(&json))
        .map_err(|error| format!("failed to encode MPP session receipt: {error}"))?;
    let receipt_value = HeaderValue::from_str(&encoded)
        .map_err(|error| format!("invalid MPP session receipt header: {error}"))?;
    let mut headers = vec![(
        HeaderName::from_static(PAYMENT_RECEIPT_HEADER),
        receipt_value,
    )];
    if let Some(url) = crate::explorer::account_url(network, channel_id) {
        let value = HeaderValue::from_str(&url)
            .map_err(|error| format!("invalid MPP session receipt URL: {error}"))?;
        headers.push((PAYMENT_RECEIPT_URL, value));
    }

    Ok(ReceiptAnnotation {
        headers,
        // The stable receipt reference is the channel PDA, not a transaction
        // signature. Settlement only reaches chain when the channel closes.
        reference: None,
    })
}

/// Rate and persist a delegated-session response before releasing it.
///
/// Consuming `pending` also consumes its capacity lease. The lease's drop
/// implementation therefore releases capacity on success and on every error.
pub async fn settle_delegated_session(
    pending: SessionForward,
    response_headers: &HeaderMap,
    response_body: Option<&[u8]>,
) -> Result<Option<ReceiptAnnotation>, String> {
    let Some(plan) = pending.settlement.as_deref() else {
        return Ok(None);
    };
    let actual = metering::upto_actual_amount_from_response(
        plan,
        pending.available_base_units,
        response_headers,
        response_body,
    )
    .map_err(|error| error.to_string())?;
    if actual.base_units == 0 {
        pending
            .handle
            .touch_channel(pending.channel_id.clone())
            .await
            .map_err(|error| error.to_string())?;
        tracing::info!(
            channel = %pending.channel_id,
            "delegated MPP session response rated at zero"
        );
        return Ok(None);
    }

    let acceptance = pending
        .handle
        .authorize_delegated_usage(&pending.channel_id, actual.base_units)
        .await
        .map_err(|error| error.to_string())?;
    tracing::info!(
        channel = %pending.channel_id,
        amount = actual.base_units,
        cumulative = acceptance.cumulative,
        usd = actual.usd,
        "delegated MPP session voucher accepted"
    );
    let authorized = pending
        .committed_base_units
        .saturating_add(pending.available_base_units);
    delegated_session_receipt_annotation(
        pending.handle.network(),
        pending.handle.currency(),
        &pending.channel_id,
        actual.base_units,
        acceptance.cumulative,
        authorized,
        acceptance.idle_timeout_seconds,
    )
    .map(Some)
}

/// An x402 `upto` channel opened (and confirmed on-chain) before the resource
/// is served, carried to the adapter's post-response hook for settlement.
///
/// `upto` is settle-after-serve: the adapter forwards, then settles the actual
/// amount on success or refunds (`0`) on failure. Holds the `!Clone`
/// [`VerifiedUptoOpen`] (with its in-flight guard) until settled.
pub struct UptoForward {
    /// Boxed — `VerifiedUptoOpen` is large, and boxing keeps the common
    /// `GateDecision` variants small (clippy `large_enum_variant`).
    pub open: Box<VerifiedUptoOpen>,
    /// Voucher amount (base units) to settle on a successful serve — the
    /// configured `min` (clamped to the ceiling), or the full ceiling when no
    /// `min` is set. Failures always settle `0` (full refund).
    pub settle_amount: u64,
    /// Response-metered settlement plan. `None` preserves the legacy fixed
    /// success amount above.
    pub settlement: Option<metering::UptoSettlementPlan>,
    /// Stable context needed to attribute the amount actually debited after
    /// the upstream response has been metered.
    pub telemetry: UptoPaymentTelemetry,
}

/// An x402 `batch-settlement` payment verified before the resource is served,
/// carried to the adapter's post-response hook for commitment.
///
/// The scheme's `authorization` flow is verify-then-serve-then-commit:
/// verification only reserves the channel, and the cumulative watermark
/// advances — and any deposit transaction broadcasts — only after the upstream
/// succeeds. A failed serve therefore leaves the client uncharged and free to
/// retry the same voucher.
///
/// Holds the `!Clone` [`BatchOutcome`], whose in-flight guard serializes the
/// channel until it is dropped or settled.
pub struct BatchForward {
    /// Boxed to keep the `GateDecision::Forward` variant small.
    pub outcome: Box<BatchOutcome>,
    /// Stable context for attributing the amount actually charged.
    pub telemetry: BatchPaymentTelemetry,
}

pub struct BatchPaymentTelemetry {
    pub subdomain: String,
    pub path: String,
    pub payment: Option<telemetry::PaymentAmount>,
}

pub struct UptoPaymentTelemetry {
    pub subdomain: String,
    pub path: String,
    pub ceiling_usd: f64,
}

/// The outcome of gating a request.
pub enum GateDecision {
    /// Send this response now and stop (402 challenge, service-worker JS, 404,
    /// a 200 receipt JSON, …).
    Respond(GateResponse),
    /// Payment verified — forward to the endpoint's configured upstream. When a
    /// session credential opened/advanced a channel, `session` carries the
    /// stream-metering context the adapter attaches to the upstream request;
    /// `receipt` is applied to the response. For x402 `upto`, `upto` carries the
    /// opened channel the adapter settles *after* the response; `batch` does the
    /// same for x402 `batch-settlement`, whose voucher commits post-serve.
    Forward {
        session: Option<Box<SessionForward>>,
        receipt: Option<ReceiptAnnotation>,
        upto: Option<Box<UptoForward>>,
        batch: Option<Box<BatchForward>>,
        paid_request: Option<PaidRequestTelemetry>,
    },
    /// Not gated (discovery / free / unknown) — let normal routing handle it
    /// (forward to the default upstream, or serve a control-plane route).
    Passthrough,
}

/// The framework-agnostic payment gate, parameterized over the host's
/// [`PaymentState`] (MPP / session / subscription backends + API specs).
pub struct PaymentGate<S: PaymentState> {
    state: S,
}

impl<S: PaymentState> PaymentGate<S> {
    pub fn new(state: S) -> Self {
        Self { state }
    }

    /// Decide what to do with `req`. See the module docs for the full tree.
    pub async fn evaluate(&self, req: &GateRequest<'_>) -> GateDecision {
        use pay_kit::mpp::server::html as mpp_html;

        let path = req.path;

        // Control-plane + discovery surfaces stay unauthenticated.
        if path.starts_with("__402/") || path == "openapi.json" || path.starts_with(".well-known/")
        {
            return GateDecision::Passthrough;
        }

        let subdomain = req.host.unwrap_or("").split('.').next().unwrap_or("");
        let accepts_html = req.accept.is_some_and(mpp_html::accepts_html);

        let apis = self.state.apis();
        let api = match apis.iter().find(|a| a.subdomain == subdomain) {
            Some(api) => api,
            // Single-API mode: one configured API serves any subdomain.
            None if apis.len() == 1 => &apis[0],
            None => return GateDecision::Passthrough,
        };

        // Service worker for the HTML payment-link UI — before metering lookup
        // so it works for any path/method.
        if req
            .query
            .unwrap_or("")
            .contains(mpp_html::SERVICE_WORKER_PARAM)
        {
            return GateDecision::Respond(
                GateResponse::new(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/javascript")
                    .header(HeaderName::from_static("service-worker-allowed"), "/")
                    .body(mpp_html::service_worker_js()),
            );
        }

        // HEAD is gated like GET.
        let match_method = if req.method == Method::HEAD {
            "GET"
        } else {
            req.method.as_str()
        };
        // Session commits/closes are POSTed to the *opened resource* regardless
        // of its declared method (the canonical client commits to the resource
        // URL by default), so a `POST` voucher commit lands on a `GET` stream
        // endpoint. Detect a session credential up front so we can resolve the
        // endpoint by path — otherwise the method mismatch 404s before the
        // session handler ever runs.
        // Decode a Payment credential once. Endpoint routing needs its intent,
        // and the session verifier consumes the same parsed value below.
        // Previously the paid session path decoded the base64url JSON three
        // times per voucher (path fallback, intent dispatch, verification).
        let payment_credential = req
            .authorization
            .filter(is_payment_authorization)
            .map(parse_authorization);
        let is_session_credential = payment_credential.as_ref().is_some_and(|result| {
            result
                .as_ref()
                .is_ok_and(|c| c.challenge.intent.as_str() == "session")
        });
        let exact_match = metering::find_endpoint(api, match_method, path);
        let endpoint = exact_match.or_else(|| {
            // Browsers often GET a POST-only paid endpoint via a payment link;
            // fall back to path-only resolution so we can render the 402 page.
            // Session commits likewise need path-only resolution (see above).
            if accepts_html || is_session_credential {
                metering::find_endpoint_by_path(api, path)
            } else {
                None
            }
        });
        let metering_config = endpoint.and_then(|ep| ep.metering.as_ref());
        let subscription_config = endpoint.and_then(|ep| ep.subscription.as_ref());

        if metering_config.is_none() && subscription_config.is_none() {
            // Respond-routing with a known path but wrong method → 404 (no
            // upstream to fall through to).
            if api.routing.is_respond()
                && exact_match.is_none()
                && metering::find_endpoint_by_path(api, path).is_some()
            {
                return GateDecision::Respond(GateResponse::json(
                    StatusCode::NOT_FOUND,
                    Bytes::from_static(br#"{"error":"not_found","message":"method not allowed"}"#),
                ));
            }
            return GateDecision::Passthrough;
        }

        // ── Gated endpoint ──────────────────────────────────────────────────
        // (Not wired into any adapter yet — the axum middleware still owns these
        // paths — so unimplemented arms below are never reached in production.)
        if let Some(spec) = subscription_config {
            let description = endpoint.and_then(|e| e.description.as_deref());
            return self
                .evaluate_subscription(api, spec, description, req, subdomain, path)
                .await;
        }
        let meter = metering_config.expect("gated endpoint has metering");
        let accepted = meter.accepted_schemes();

        let session_handles = self.state.session_mpp_handles();
        let session_mpps: Vec<&SessionMpp> = if session_handles.is_empty() {
            self.state.session_mpps()
        } else {
            session_handles.iter().map(Arc::as_ref).collect()
        };

        // MPP credential present → dispatch by intent (only if accepted). Only
        // `Payment`-scheme Authorization headers are payment credentials — any
        // other scheme (Bearer/Basic/…) is auth destined for the upstream
        // (e.g. Claude Code's ANTHROPIC_AUTH_TOKEN) and must fall through to
        // the 402 challenge, not 400. A `Payment` credential that then fails
        // to parse is a genuine client error (400).
        if let Some(parsed) = payment_credential {
            match parsed {
                Ok(cred) => {
                    let intent = cred.challenge.intent.as_str();
                    if intent == "session"
                        && accepted.contains(&Scheme::MppSession)
                        && let Ok(request) = cred
                            .challenge
                            .request
                            .decode::<pay_kit::mpp::SessionRequest>()
                        && let Some(index) = session_mpps
                            .iter()
                            .position(|session| session.accepts_currency(&request.currency))
                    {
                        return session_authorized(
                            session_mpps[index],
                            session_handles.get(index).cloned(),
                            cred,
                            meter,
                            req,
                            subdomain,
                            path,
                        )
                        .await;
                    }
                    if intent == "charge" && accepted.contains(&Scheme::MppCharge) {
                        let auth = req
                            .authorization
                            .expect("parsed Payment credential has an Authorization header");
                        let description = endpoint.and_then(|e| e.description.as_deref());
                        let resource = endpoint.and_then(|e| e.resource.as_deref());
                        return self
                            .charge_verify(
                                api,
                                meter,
                                description,
                                resource,
                                auth,
                                subdomain,
                                path,
                                req,
                            )
                            .await;
                    }
                    // Parseable but not an accepted scheme → fall through to re-challenge.
                }
                Err(e) => {
                    return GateDecision::Respond(GateResponse::json(
                        StatusCode::BAD_REQUEST,
                        serde_json::to_vec(&json!({
                            "error": "malformed_credential", "message": e.to_string()
                        }))
                        .unwrap_or_default(),
                    ));
                }
            }
        }

        // x402 credential (PAYMENT-SIGNATURE / X-PAYMENT) → dispatch by scheme.
        if let Some(pay_header) = req.x402_payment {
            if accepted.contains(&Scheme::X402Exact)
                && let Some(x402) = self.state.x402()
            {
                let resource = endpoint.and_then(|e| e.resource.as_deref());
                return self
                    .x402_exact_verify(x402, meter, req, path, pay_header, subdomain, resource)
                    .await;
            }
            if accepted.contains(&Scheme::X402BatchSettlement)
                && let Some(batch) = self.state.x402_batch()
            {
                let resource = endpoint.and_then(|e| e.resource.as_deref());
                return self
                    .x402_batch_verify(batch, meter, req, path, pay_header, subdomain, resource)
                    .await;
            }
            if accepted.contains(&Scheme::X402Upto)
                && let Some(upto) = self.state.x402_upto()
            {
                return self
                    .x402_upto_verify(upto, meter, req, path, pay_header, subdomain)
                    .await;
            }
        }

        // No (matching) credential → advertise every accepted + available scheme.
        let description = endpoint.and_then(|e| e.description.as_deref());
        let resource = endpoint.and_then(|e| e.resource.as_deref());
        self.build_challenge(
            api,
            meter,
            &accepted,
            &session_mpps,
            req,
            subdomain,
            path,
            description,
            resource,
            accepts_html,
        )
    }

    /// Assemble a single 402 advertising one challenge per accepted scheme that
    /// the server has a backend for (session `WWW-Authenticate` + per-MPP charge
    /// `WWW-Authenticate`; x402 `PAYMENT-REQUIRED` to follow). Fails closed (500)
    /// if a metered endpoint has no usable backend for any accepted scheme.
    #[allow(clippy::too_many_arguments)]
    fn build_challenge(
        &self,
        api: &pay_types::metering::ApiSpec,
        meter: &pay_types::metering::Metering,
        accepted: &[Scheme],
        session_mpps: &[&SessionMpp],
        req: &GateRequest<'_>,
        subdomain: &str,
        path: &str,
        description: Option<&str>,
        resource: Option<&str>,
        accepts_html: bool,
    ) -> GateDecision {
        // When set, render the browser HTML 402 page from this charge challenge.
        let mut html_challenge: Option<(pay_kit::mpp::PaymentChallenge, String, String)> = None;
        let gen_failed = || {
            GateDecision::Respond(GateResponse::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                Bytes::from_static(br#"{"error":"challenge_generation_failed"}"#),
            ))
        };
        let props = metering::RequestProperties {
            body_size: req.content_length,
            ..Default::default()
        };
        let variant = variant_hint_from_path(path);
        let price = metering::resolve_price(meter, &props, variant.as_deref(), None);

        let mut challenge_headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
        let mut advertised: Vec<&str> = Vec::new();

        if accepted.contains(&Scheme::MppSession) && !session_mpps.is_empty() {
            for sm in session_mpps {
                let unit_amount = price.as_ref().map(|price| {
                    crate::server::payment::price_unit_base_amount(price, sm.decimals())
                });
                match sm.challenge_header(unit_amount) {
                    Ok(h) => {
                        if let Ok(v) = HeaderValue::from_str(&h) {
                            challenge_headers.push((header::WWW_AUTHENTICATE, v));
                        }
                    }
                    Err(e) => {
                        telemetry::record_challenge_error(
                            "mpp/session",
                            sm.currency(),
                            &e.to_string(),
                        );
                        return gen_failed();
                    }
                }
            }
            advertised.push("mpp/session");
        }

        if accepted.contains(&Scheme::MppCharge) {
            let mpps = self.state.mpps();
            if !mpps.is_empty() {
                let amount = crate::server::payment::charge_amount_from_price(price.as_ref());
                let uri = reconstruct_uri(path, req.query);
                let external_id = crate::server::payment::resource_memo_with_nonce(
                    resource,
                    pay_kit::mpp::protocol::solana::MAX_MEMO_BYTES,
                );
                let mut challenges = Vec::with_capacity(mpps.len());
                for mpp in &mpps {
                    match mpp.charge_with_options(
                        &amount,
                        ChargeOptions {
                            description,
                            // The main recipient's settlement memo is the endpoint
                            // resource plus a per-challenge suffix, so repeated
                            // same-route payments don't rely on blockhash uniqueness.
                            external_id: external_id.as_deref(),
                            splits: crate::server::payment::resolve_charge_splits(
                                mpp, meter, api, &uri, &amount,
                            ),
                            ..Default::default()
                        },
                    ) {
                        Ok(c) => challenges.push(c),
                        Err(e) => {
                            telemetry::record_challenge_error(
                                "mpp/charge",
                                mpp.currency(),
                                &e.to_string(),
                            );
                            return gen_failed();
                        }
                    }
                }
                match format_www_authenticate_many(&challenges) {
                    Ok(v) => {
                        for w in v {
                            if let Ok(hv) = HeaderValue::from_str(&w) {
                                challenge_headers.push((header::WWW_AUTHENTICATE, hv));
                            }
                        }
                        advertised.push("mpp/charge");
                    }
                    Err(_) => return gen_failed(),
                }
                // Browser payment-link UI: render the first charge challenge as HTML.
                if accepts_html
                    && let (Some(ch), Some(mpp)) = (challenges.into_iter().next(), mpps.first())
                {
                    let rpc = self
                        .state
                        .browser_rpc_url()
                        .map(str::to_string)
                        .unwrap_or_else(|| mpp.rpc_url().to_string());
                    html_challenge = Some((ch, rpc, mpp.network().to_string()));
                }
            }
        }

        if accepted.contains(&Scheme::X402Exact)
            && let Some(x402) = self.state.x402()
        {
            let amount = crate::server::payment::charge_amount_from_price(price.as_ref());
            // Parity with MPP charge external_id: resource plus per-challenge
            // suffix, so repeated same-route payments are distinct on-chain.
            let memo = crate::server::payment::resource_memo_with_nonce(
                resource,
                pay_kit::x402::exact::MAX_MEMO_BYTES,
            );
            match x402.payment_required_header(
                &amount,
                ExactOptions {
                    memo: memo.as_deref(),
                    ..Default::default()
                },
            ) {
                Ok((name, value)) => {
                    if let (Ok(n), Ok(v)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_str(&value),
                    ) {
                        challenge_headers.push((n, v));
                        advertised.push("x402/exact");
                    }
                }
                // Drop only the x402 challenge on error — MPP clients are unaffected.
                Err(e) => {
                    telemetry::record_challenge_error(
                        "x402/exact",
                        x402.currency(),
                        &e.to_string(),
                    );
                }
            }
        }

        if accepted.contains(&Scheme::X402Upto)
            && let Some(upto) = self.state.x402_upto()
        {
            // The advertised ceiling: `metering.upto.max_usd` for usage-metered
            // configs, or the legacy metered charge for older configs. The
            // client funds a channel with this as the deposit; settlement later
            // debits actual usage and refunds the rest.
            let amount = format!("{}", metering::upto_max_usd(meter, price.as_ref()));
            match upto.payment_required_header(&amount) {
                Ok((name, value)) => {
                    if let (Ok(n), Ok(v)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_str(&value),
                    ) {
                        challenge_headers.push((n, v));
                        advertised.push("x402/upto");
                    }
                }
                Err(e) => {
                    telemetry::record_challenge_error("x402/upto", "configured", &e.to_string());
                }
            }
        }

        if accepted.contains(&Scheme::X402BatchSettlement)
            && let Some(batch) = self.state.x402_batch()
        {
            let amount = crate::server::payment::charge_amount_from_price(price.as_ref());
            match batch.payment_required_header(&amount, resource) {
                Ok((name, value)) => {
                    if let (Ok(n), Ok(v)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_str(&value),
                    ) {
                        challenge_headers.push((n, v));
                        advertised.push("x402/batch");
                    }
                }
                Err(e) => {
                    telemetry::record_challenge_error("x402/batch", "configured", &e.to_string());
                }
            }
        }

        if challenge_headers.is_empty() {
            // Metered, but no configured backend for any accepted scheme — fail
            // closed rather than serve the resource for free.
            return GateDecision::Respond(GateResponse::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                Bytes::from_static(
                    br#"{"error":"payment_backend_unconfigured","message":"No payment backend for the accepted schemes."}"#,
                ),
            ));
        }

        let amount_usd = price
            .as_ref()
            .and_then(|p| p.dimensions.first())
            .map(|d| d.price_usd / d.scale.max(1) as f64);
        let challenge_protocol = if advertised.len() == 1 {
            advertised[0]
        } else {
            "mixed"
        };
        telemetry::record_402_challenge_sent(
            challenge_protocol,
            subdomain,
            path,
            req.method.as_str(),
            amount_usd,
            &advertised.join(","),
            challenge_headers.len(),
        );

        // Browser flow: render the HTML payment page instead of JSON.
        if let Some((challenge, rpc_url, network)) = html_challenge {
            let page =
                pay_kit::mpp::server::html::challenge_to_html(&challenge, &rpc_url, &network);
            let mut resp = GateResponse::new(StatusCode::PAYMENT_REQUIRED)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .header(header::CONTENT_SECURITY_POLICY, PAYMENT_PAGE_CSP)
                .body(Bytes::from(page));
            resp.headers.extend(challenge_headers);
            return GateDecision::Respond(resp);
        }

        let body = json!({
            "error": "payment_required",
            "message": "This endpoint requires payment.",
            "endpoint": { "method": req.method.as_str(), "path": path },
            "pricing": price,
            "payment": { "schemes": advertised },
        });
        let mut resp = GateResponse::json(
            StatusCode::PAYMENT_REQUIRED,
            serde_json::to_vec(&body).unwrap_or_default(),
        );
        resp.headers.extend(challenge_headers);
        GateDecision::Respond(resp)
    }

    /// Verify an x402 `exact` payment. On success, forward with a `PAYMENT-RESPONSE`
    /// receipt; on failure or a referenceless payment, re-challenge with 402.
    #[allow(clippy::too_many_arguments)]
    async fn x402_exact_verify(
        &self,
        x402: &X402,
        meter: &pay_types::metering::Metering,
        req: &GateRequest<'_>,
        path: &str,
        pay_header: &str,
        subdomain: &str,
        resource: Option<&str>,
    ) -> GateDecision {
        let props = metering::RequestProperties {
            body_size: req.content_length,
            ..Default::default()
        };
        let variant = variant_hint_from_path(path);
        let amount = crate::server::payment::charge_amount_from_price(
            metering::resolve_price(meter, &props, variant.as_deref(), None).as_ref(),
        );
        let payment = amount
            .parse()
            .ok()
            .map(|ui_amount| telemetry::PaymentAmount {
                currency: x402.currency().to_string(),
                ui_amount,
            });
        let reject = |msg: String| {
            telemetry::record_settlement_error("x402/exact", subdomain, path, &msg, true);
            GateDecision::Respond(GateResponse::json(
                StatusCode::PAYMENT_REQUIRED,
                serde_json::to_vec(&json!({"error":"verification_failed","message":msg}))
                    .unwrap_or_default(),
            ))
        };
        let memo = match x402_exact_payment_memo(x402, pay_header, resource) {
            Ok(memo) => memo,
            Err(e) => return reject(e),
        };
        let verified = match x402
            .process_payment(
                pay_header,
                &amount,
                ExactOptions {
                    memo: memo.as_deref(),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(verified) => verified,
            Err(e) => return reject(e.to_string()),
        };
        // `process_payment` only *verified* the credential — it did not move
        // funds. Settle on-chain BEFORE serving: co-sign the sponsor's fee-payer
        // slot, broadcast, and await confirmation (mirrors the MPP charge path).
        // Without this the resource would be served against an unbroadcast
        // transaction (the receipt would carry the null signature).
        let Some(signer) = self.state.fee_payer_signer() else {
            return reject(
                "x402 exact settlement requires a fee-payer signer (set operator.fee_payer)"
                    .to_string(),
            );
        };
        match x402.settle_exact(verified, signer.as_ref()).await {
            Ok(reference) => {
                telemetry::record_payment_collected(
                    "x402/exact",
                    subdomain,
                    path,
                    payment.as_ref(),
                    &reference,
                );
                let mut headers = Vec::new();
                if let Ok(n) = HeaderName::from_bytes(PAYMENT_RESPONSE_HEADER.as_bytes())
                    && let Ok(v) = HeaderValue::from_str(&reference)
                {
                    headers.push((n, v));
                }
                GateDecision::Forward {
                    session: None,
                    receipt: Some(ReceiptAnnotation {
                        headers,
                        reference: Some(reference),
                    }),
                    upto: None,
                    batch: None,
                    paid_request: Some(PaidRequestTelemetry {
                        protocol: "x402/exact",
                        subdomain: subdomain.to_string(),
                        payment,
                    }),
                }
            }
            Err(e) => reject(e.to_string()),
        }
    }

    /// Verify an x402 `upto` authorization: broadcast + confirm the channel
    /// `open` on-chain (deposit = the advertised ceiling), then forward. The
    /// channel is settled *after* the response by the adapter ([`UptoForward`]) —
    /// the metered amount on a successful serve, `0` (full refund) on failure.
    /// On a verification failure, re-challenge with 402.
    async fn x402_upto_verify(
        &self,
        upto: &X402Upto,
        meter: &pay_types::metering::Metering,
        req: &GateRequest<'_>,
        path: &str,
        pay_header: &str,
        subdomain: &str,
    ) -> GateDecision {
        let props = metering::RequestProperties {
            body_size: req.content_length,
            ..Default::default()
        };
        let variant = variant_hint_from_path(path);
        let price = metering::resolve_price(meter, &props, variant.as_deref(), None);
        let amount = format!("{}", metering::upto_max_usd(meter, price.as_ref()));
        match upto.verify_open(pay_header, &amount).await {
            Ok(open) => {
                let ceiling_usd: f64 = amount.parse().unwrap_or(0.0);
                let settle_amount =
                    upto_settle_amount(metering::upto_min_usd(meter), ceiling_usd, open.max_amount);
                let settlement = metering::upto_uses_response_usage(meter, variant.as_deref())
                    .then(|| metering::UptoSettlementPlan {
                        metering: meter.clone(),
                        variant_hint: variant.clone(),
                        request_properties: props,
                        ceiling_usd,
                        inferred_usage: None,
                    });
                GateDecision::Forward {
                    session: None,
                    receipt: None,
                    batch: None,
                    upto: Some(Box::new(UptoForward {
                        open: Box::new(open),
                        settle_amount,
                        settlement,
                        telemetry: UptoPaymentTelemetry {
                            subdomain: subdomain.to_string(),
                            path: path.to_string(),
                            ceiling_usd,
                        },
                    })),
                    paid_request: Some(PaidRequestTelemetry {
                        protocol: "x402/upto",
                        subdomain: subdomain.to_string(),
                        payment: None,
                    }),
                }
            }
            Err(e) => {
                telemetry::record_settlement_error(
                    "x402/upto",
                    subdomain,
                    path,
                    &e.to_string(),
                    true,
                );
                GateDecision::Respond(GateResponse::json(
                    StatusCode::PAYMENT_REQUIRED,
                    serde_json::to_vec(
                        &json!({"error":"verification_failed","message":e.to_string()}),
                    )
                    .unwrap_or_default(),
                ))
            }
        }
    }

    /// Verify an x402 `batch-settlement` payment before the resource is served.
    ///
    /// Verification is read-only: it checks the cumulative voucher and reserves
    /// the channel, but does not charge. The commitment is made by
    /// [`settle_batch`] after the upstream responds, so a failed serve leaves
    /// the client uncharged and able to retry the same voucher. On-chain
    /// redemption is batched out of band by the operator.
    ///
    /// A `refund` bypasses the upstream entirely — a channel close is a
    /// payment-control operation, not a paid request.
    #[allow(clippy::too_many_arguments)]
    async fn x402_batch_verify(
        &self,
        batch: &X402BatchSettlement,
        meter: &pay_types::metering::Metering,
        req: &GateRequest<'_>,
        path: &str,
        pay_header: &str,
        subdomain: &str,
        resource: Option<&str>,
    ) -> GateDecision {
        let props = metering::RequestProperties {
            body_size: req.content_length,
            ..Default::default()
        };
        let variant = variant_hint_from_path(path);
        let amount = crate::server::payment::charge_amount_from_price(
            metering::resolve_price(meter, &props, variant.as_deref(), None).as_ref(),
        );
        let payment = amount
            .parse()
            .ok()
            .map(|ui_amount| telemetry::PaymentAmount {
                currency: "USD".to_string(),
                ui_amount,
            });

        let access = match batch.verify_and_reserve_payment(pay_header, &amount).await {
            Ok(access) => access,
            Err(e) => {
                telemetry::record_challenge_error("x402/batch", subdomain, &e.to_string());
                // A cumulative mismatch comes back as a corrective 402 carrying
                // the server's snapshot plus the client's own signed voucher, so
                // the client can resynchronize and retry rather than be stuck.
                let mut resp = GateResponse::json(
                    StatusCode::PAYMENT_REQUIRED,
                    serde_json::to_vec(
                        &json!({"error":"verification_failed","message":e.to_string()}),
                    )
                    .unwrap_or_default(),
                );
                if let Ok((name, value)) = batch
                    .challenge_for_failure(pay_header, &amount, &e, resource)
                    .await
                    && let (Ok(n), Ok(v)) = (
                        HeaderName::from_bytes(name.as_bytes()),
                        HeaderValue::from_str(&value),
                    )
                {
                    resp.headers.push((n, v));
                }
                return GateDecision::Respond(resp);
            }
        };

        let outcome = match access {
            // Already charged and served. The client lost the response, not
            // the payment, so it gets the original settlement result back
            // rather than a conflict — the scheme requires the recorded
            // response for this commitment, and refusing it would leave a paid
            // request unrecoverable.
            BatchAccess::Replay(settlement, cached) => {
                return GateDecision::Respond(batch_replay_response(
                    batch,
                    &settlement,
                    cached.as_ref(),
                ));
            }
            // Another in-flight request owns this authorization. This is the
            // one case that is genuinely a conflict, and it is retryable.
            BatchAccess::InProgress => {
                let mut resp = GateResponse::json(
                    StatusCode::CONFLICT,
                    serde_json::to_vec(&json!({
                        "error": "duplicate_settlement",
                        "message": "payment authorization is already in flight",
                    }))
                    .unwrap_or_default(),
                );
                if let Ok(v) = HeaderValue::from_str("1") {
                    resp.headers
                        .push((HeaderName::from_static("retry-after"), v));
                }
                return GateDecision::Respond(resp);
            }
            // A previous attempt served this request but never charged it.
            // Finishing that charge is the only safe continuation; the
            // upstream must not run again.
            BatchAccess::Resume(outcome) => {
                return match batch.finish_commit(&outcome).await {
                    Ok(settlement) => {
                        GateDecision::Respond(batch_replay_response(batch, &settlement, None))
                    }
                    Err(e) => {
                        telemetry::record_settlement_error(
                            "x402/batch",
                            subdomain,
                            path,
                            &e.to_string(),
                            true,
                        );
                        GateDecision::Respond(GateResponse::json(
                            StatusCode::BAD_GATEWAY,
                            serde_json::to_vec(
                                &json!({"error":"settlement_failed","message":e.to_string()}),
                            )
                            .unwrap_or_default(),
                        ))
                    }
                };
            }
            BatchAccess::Serve(outcome) | BatchAccess::Control(outcome) => outcome,
        };

        // A channel close: commit it now and acknowledge without serving.
        if !outcome.serve {
            let mut resp = GateResponse::json(
                StatusCode::OK,
                Bytes::from_static(br#"{"status":"channel_closing"}"#),
            );
            match batch.settle_payment(outcome).await {
                Ok(settlement) => {
                    if let Ok((name, value)) = batch.settlement_header(&settlement)
                        && let (Ok(n), Ok(v)) = (
                            HeaderName::from_bytes(name.as_bytes()),
                            HeaderValue::from_str(&value),
                        )
                    {
                        resp.headers.push((n, v));
                    }
                }
                Err(e) => {
                    telemetry::record_settlement_error(
                        "x402/batch",
                        subdomain,
                        path,
                        &e.to_string(),
                        true,
                    );
                    return GateDecision::Respond(GateResponse::json(
                        StatusCode::BAD_GATEWAY,
                        serde_json::to_vec(
                            &json!({"error":"close_failed","message":e.to_string()}),
                        )
                        .unwrap_or_default(),
                    ));
                }
            }
            return GateDecision::Respond(resp);
        }

        GateDecision::Forward {
            session: None,
            receipt: None,
            upto: None,
            batch: Some(Box::new(BatchForward {
                outcome: Box::new(outcome),
                telemetry: BatchPaymentTelemetry {
                    subdomain: subdomain.to_string(),
                    path: path.to_string(),
                    payment: payment.clone(),
                },
            })),
            paid_request: Some(PaidRequestTelemetry {
                protocol: "x402/batch",
                subdomain: subdomain.to_string(),
                payment,
            }),
        }
    }

    /// Subscription endpoint: no auth → 402 (subscription + authenticate
    /// challenges); `authenticate` intent → stateless verify → forward / 402;
    /// `subscription` intent → activation → forward (+ receipt + "next time"
    /// authenticate challenge) / 402.
    async fn evaluate_subscription(
        &self,
        api: &pay_types::metering::ApiSpec,
        spec: &pay_types::metering::SubscriptionEndpoint,
        description: Option<&str>,
        req: &GateRequest<'_>,
        subdomain: &str,
        path: &str,
    ) -> GateDecision {
        use crate::server::{authenticate, subscription as sub};

        let mpps = self.state.mpps();
        let operator = api.operator.as_ref();
        let Some(puller) = operator
            .and_then(|o| o.recipient.clone())
            .or_else(|| mpps.first().map(|m| m.recipient().to_string()))
        else {
            return GateDecision::Respond(GateResponse::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                Bytes::from_static(
                    br#"{"error":"subscription_misconfigured","message":"missing operator.recipient"}"#,
                ),
            ));
        };
        let recipient = spec.recipient.clone().unwrap_or_else(|| puller.clone());
        let network = operator
            .and_then(|o| o.network.clone())
            .unwrap_or_else(|| "mainnet".to_string());
        let rpc_url = mpps
            .first()
            .map(|m| m.rpc_url().to_string())
            .unwrap_or_else(|| {
                pay_kit::mpp::protocol::solana::default_rpc_url(&network).to_string()
            });
        let fee_payer = operator.map(|o| o.fee_payer).unwrap_or(false);
        let signer = self.state.fee_payer_signer();
        let csec = operator.and_then(|o| o.challenge_binding_secret.as_deref());
        let realm = operator
            .and_then(|o| o.realm.as_deref())
            .or(Some(subdomain));
        let canonical = format!("https://{subdomain}/");
        let defaults = sub::OperatorDefaults {
            puller: &puller,
            recipient: &recipient,
            network: &network,
            rpc_url: &rpc_url,
            challenge_binding_secret: csec,
            realm,
            fee_payer,
            fee_payer_signer: signer.clone(),
        };

        // Build the 402: subscription challenge + optional authenticate challenge.
        let challenge_402 = |error: Option<(&str, bool)>| -> GateDecision {
            let mut headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
            match sub::build_challenge(spec, defaults.clone(), description) {
                Ok(c) => {
                    if let Ok(w) = format_www_authenticate(&c)
                        && let Ok(v) = HeaderValue::from_str(&w)
                    {
                        headers.push((header::WWW_AUTHENTICATE, v));
                    }
                }
                Err(e) => {
                    telemetry::record_challenge_error(
                        "mpp/subscription",
                        "configured",
                        &e.to_string(),
                    );
                    return GateDecision::Respond(GateResponse::json(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Bytes::from_static(br#"{"error":"subscription_misconfigured"}"#),
                    ));
                }
            }
            if let Ok(Some(authsrv)) =
                authenticate::build_handler(spec, defaults.clone(), subdomain, &canonical)
                && let Ok(ac) = authsrv.challenge()
                && let Ok(w) = format_www_authenticate(&ac)
                && let Ok(v) = HeaderValue::from_str(&w)
            {
                headers.push((header::WWW_AUTHENTICATE, v));
            }
            telemetry::record_402_challenge_sent(
                "mpp/subscription",
                subdomain,
                path,
                req.method.as_str(),
                None,
                "mpp/subscription",
                1,
            );
            let body = match error {
                Some((m, retryable)) => {
                    json!({"error":"verification_failed","message":m,"retryable":retryable})
                }
                None => json!({
                    "error": "payment_required",
                    "message": "This endpoint requires a subscription.",
                    "endpoint": { "method": req.method.as_str(), "path": path },
                }),
            };
            let mut resp = GateResponse::json(
                StatusCode::PAYMENT_REQUIRED,
                serde_json::to_vec(&body).unwrap_or_default(),
            );
            resp.headers.extend(headers);
            GateDecision::Respond(resp)
        };

        // Non-`Payment` Authorization schemes are upstream auth, not a
        // malformed credential — challenge instead of 400 (mirrors evaluate()).
        let Some(auth) = req.authorization.filter(is_payment_authorization) else {
            return challenge_402(None);
        };
        let credential = match parse_authorization(auth) {
            Ok(c) => c,
            Err(e) => {
                return GateDecision::Respond(GateResponse::json(
                    StatusCode::BAD_REQUEST,
                    serde_json::to_vec(
                        &json!({"error":"malformed_credential","message":e.to_string()}),
                    )
                    .unwrap_or_default(),
                ));
            }
        };

        // authenticate-intent: stateless SIWMPP verify, no broadcast.
        if credential.challenge.intent.as_str() == "authenticate" {
            if let Ok(Some(server)) =
                authenticate::build_handler(spec, defaults.clone(), subdomain, &canonical)
                && server.verify(&credential).is_ok()
            {
                return GateDecision::Forward {
                    session: None,
                    receipt: None,
                    upto: None,
                    batch: None,
                    paid_request: Some(PaidRequestTelemetry {
                        protocol: "mpp/subscription",
                        subdomain: subdomain.to_string(),
                        payment: None,
                    }),
                };
            }
            return challenge_402(None);
        }
        if credential.challenge.intent.as_str() != "subscription" {
            return challenge_402(None);
        }

        // subscription-intent: activation (broadcasts).
        let server = match sub::build_handler(spec, defaults.clone(), description) {
            Ok(s) => s,
            Err(e) => {
                return GateDecision::Respond(GateResponse::json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    serde_json::to_vec(
                        &json!({"error":"subscription_misconfigured","message":e.to_string()}),
                    )
                    .unwrap_or_default(),
                ));
            }
        };
        match server.verify_credential(&credential).await {
            Ok(receipt_kind) => {
                let mut headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
                if let Ok(rs) = format_receipt(&receipt_kind)
                    && let Ok(v) = HeaderValue::from_str(&rs)
                {
                    headers.push((HeaderName::from_static(PAYMENT_RECEIPT_HEADER), v));
                }
                if let Ok(Some(authsrv)) =
                    authenticate::build_handler(spec, defaults.clone(), subdomain, &canonical)
                    && let Ok(ac) = authsrv.challenge()
                    && let Ok(w) = format_www_authenticate(&ac)
                    && let Ok(v) = HeaderValue::from_str(&w)
                {
                    headers.push((header::WWW_AUTHENTICATE, v));
                }
                GateDecision::Forward {
                    session: None,
                    receipt: Some(ReceiptAnnotation {
                        headers,
                        reference: Some(receipt_kind.base().reference.clone()),
                    }),
                    upto: None,
                    batch: None,
                    paid_request: Some(PaidRequestTelemetry {
                        protocol: "mpp/subscription",
                        subdomain: subdomain.to_string(),
                        payment: None,
                    }),
                }
            }
            Err(e) => {
                telemetry::record_settlement_error(
                    "mpp/subscription",
                    subdomain,
                    path,
                    &e.message,
                    e.retryable,
                );
                challenge_402(Some((&e.message, e.retryable)))
            }
        }
    }

    /// Verify an MPP `charge` credential across the configured MPPs. On success,
    /// forward with a receipt; on failure, re-challenge with 402.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    async fn charge_verify(
        &self,
        api: &pay_types::metering::ApiSpec,
        meter: &pay_types::metering::Metering,
        description: Option<&str>,
        resource: Option<&str>,
        auth: &str,
        subdomain: &str,
        path: &str,
        req: &GateRequest<'_>,
    ) -> GateDecision {
        let mpps = self.state.mpps();
        if mpps.is_empty() {
            return GateDecision::Respond(GateResponse::json(
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::to_vec(&json!({
                    "error": "payment_backend_unconfigured",
                    "message": "This endpoint requires payment, but no payment backend is configured.",
                }))
                .unwrap_or_default(),
            ));
        }
        let credential = match parse_authorization(auth) {
            Ok(c) => c,
            Err(e) => {
                return GateDecision::Respond(GateResponse::json(
                    StatusCode::BAD_REQUEST,
                    serde_json::to_vec(&json!({
                        "error": "malformed_credential", "message": e.to_string()
                    }))
                    .unwrap_or_default(),
                ));
            }
        };

        let props = metering::RequestProperties {
            body_size: req.content_length,
            ..Default::default()
        };
        let variant = variant_hint_from_path(path);
        let amount = crate::server::payment::charge_amount_from_price(
            metering::resolve_price(meter, &props, variant.as_deref(), None).as_ref(),
        );
        // Reconstruct a URI for split-rule query params (splits price off the request).
        let uri = reconstruct_uri(path, req.query);
        let external_id = match mpp_charge_payment_external_id(&credential, resource) {
            Ok(external_id) => external_id,
            Err(e) => {
                telemetry::record_settlement_error("mpp/charge", subdomain, path, &e, false);
                return GateDecision::Respond(GateResponse::json(
                    StatusCode::PAYMENT_REQUIRED,
                    serde_json::to_vec(&json!({
                        "error": "verification_failed",
                        "message": e,
                        "retryable": false,
                    }))
                    .unwrap_or_default(),
                ));
            }
        };

        let mut last_error = None;
        for mpp in &mpps {
            // Audit: verify against the challenge WE would issue (rebuilt from our
            // own price + splits), not the values echoed in the credential.
            let expected = match mpp.charge_with_options(
                &amount,
                ChargeOptions {
                    description,
                    // Must match the original challenge; for resource-backed
                    // routes this is the validated resource memo echoed by the
                    // credential, including the per-challenge suffix.
                    external_id: external_id.as_deref(),
                    splits: crate::server::payment::resolve_charge_splits(
                        mpp, meter, api, &uri, &amount,
                    ),
                    ..Default::default()
                },
            ) {
                Ok(ch) => match ch.request.decode() {
                    Ok(r) => r,
                    Err(e) => {
                        last_error = Some(VerificationError::new(format!(
                            "decode expected charge: {e}"
                        )));
                        continue;
                    }
                },
                Err(e) => {
                    last_error = Some(VerificationError::new(format!(
                        "rebuild expected charge: {e}"
                    )));
                    continue;
                }
            };
            match mpp
                .verify_credential_with_expected(&credential, &expected)
                .await
            {
                Ok(receipt) => {
                    let reference = receipt.reference.clone();
                    let payment = crate::server::payment::decode_payment_amount(
                        &credential,
                        mpp.decimals() as u8,
                    );
                    telemetry::record_payment_collected(
                        "mpp/charge",
                        subdomain,
                        path,
                        payment.as_ref(),
                        &reference,
                    );
                    if let Some(wallet) = self.state.fee_payer_wallet().cloned() {
                        let (sd, p) = (subdomain.to_string(), path.to_string());
                        tokio::spawn(async move {
                            wallet.observe("payment_verified", &sd, &p).await;
                        });
                    }
                    let mut headers = Vec::new();
                    if let Some(url) = crate::explorer::tx_url(mpp.network(), &reference)
                        && let Ok(v) = HeaderValue::from_str(&url)
                    {
                        headers.push((PAYMENT_RECEIPT_URL, v));
                    }
                    if let Ok(rh) = format_receipt(&ReceiptKind::Charge(receipt))
                        && let Ok(v) = HeaderValue::from_str(&rh)
                    {
                        headers.push((HeaderName::from_static(PAYMENT_RECEIPT_HEADER), v));
                    }
                    return GateDecision::Forward {
                        session: None,
                        receipt: Some(ReceiptAnnotation {
                            headers,
                            reference: Some(reference),
                        }),
                        upto: None,
                        batch: None,
                        paid_request: Some(PaidRequestTelemetry {
                            protocol: "mpp/charge",
                            subdomain: subdomain.to_string(),
                            payment,
                        }),
                    };
                }
                Err(e) => last_error = Some(e),
            }
        }

        let error = last_error.unwrap_or_else(|| VerificationError::new("MPP not configured"));
        let message = crate::server::payment::readable_verification_message(&error);
        telemetry::record_settlement_error(
            "mpp/charge",
            subdomain,
            path,
            &message,
            error.retryable,
        );
        GateDecision::Respond(GateResponse::json(
            StatusCode::PAYMENT_REQUIRED,
            serde_json::to_vec(&json!({
                "error": "verification_failed",
                "message": message,
                "retryable": error.retryable,
            }))
            .unwrap_or_default(),
        ))
    }
}

/// Resolve the default `upto` voucher (base units) settled on a successful
/// serve. With a configured `min` (USD) and a positive ceiling, convert via the
/// ceiling's own scale — `max_amount / ceiling_usd` is base-units-per-USD, so
/// `min_usd * that` equals `parse_units(min_usd, decimals)` without re-deriving
/// the mint decimals — clamped to the ceiling. No `min` (or a degenerate
/// ceiling) settles the full ceiling, preserving the prior behavior.
/// Whether an `Authorization` header value carries the MPP `Payment` scheme
/// (vs. Bearer/Basic/… tokens meant for the upstream).
fn is_payment_authorization(auth: &&str) -> bool {
    auth.len() >= 8 && auth[..8].eq_ignore_ascii_case("payment ")
}

fn upto_settle_amount(min_usd: Option<f64>, ceiling_usd: f64, max_amount: u64) -> u64 {
    match min_usd {
        Some(min_usd) if min_usd >= 0.0 && ceiling_usd > 0.0 => {
            let units_per_usd = max_amount as f64 / ceiling_usd;
            ((min_usd * units_per_usd).round() as u64).min(max_amount)
        }
        _ => max_amount,
    }
}

/// Answer a batch request whose authorization was already charged and served.
///
/// The settlement result is returned verbatim, so a client that lost the
/// original response learns what it was charged and can carry on from the
/// right cumulative base.
fn batch_replay_response(
    batch: &X402BatchSettlement,
    settlement: &pay_kit::x402::batch_settlement::BatchSettlementResponse,
    cached: Option<&pay_kit::core::store::CachedUpstreamResponse>,
) -> GateResponse {
    let mut resp = if let Some(cached) = cached {
        let mut response =
            GateResponse::new(StatusCode::from_u16(cached.status).unwrap_or(StatusCode::OK))
                .body(cached.body.clone());
        if let Some(content_type) = &cached.content_type {
            response = response.header(header::CONTENT_TYPE, content_type);
        }
        for (name, value) in &cached.headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                response.headers.push((name, value));
            }
        }
        response
    } else {
        GateResponse::json(
            StatusCode::OK,
            serde_json::to_vec(&json!({
                "status": "already_settled",
                "message": "this authorization was already charged; its payment result is attached",
            }))
            .unwrap_or_default(),
        )
    };
    if let Ok(v) = HeaderValue::from_str("true") {
        resp.headers
            .push((HeaderName::from_static("payment-replay"), v));
    }
    if let Ok((name, value)) = batch.settlement_header(settlement)
        && let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        )
    {
        resp.headers.push((n, v));
    }
    resp
}

/// Build the bounded, end-to-end portion of an upstream response that is safe
/// to reproduce for an idempotent batch authorization replay.
pub fn batch_cached_response(
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
) -> pay_kit::core::store::CachedUpstreamResponse {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let headers = headers
        .iter()
        .filter(|(name, _)| is_replayable_batch_response_header(name))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    pay_kit::core::store::CachedUpstreamResponse {
        status: status.as_u16(),
        content_type,
        headers,
        body: body.to_vec(),
    }
}

fn is_replayable_batch_response_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "accept-ranges"
            | "cache-control"
            | "content-security-policy"
            | "content-security-policy-report-only"
            | "content-disposition"
            | "content-encoding"
            | "content-language"
            | "content-location"
            | "content-range"
            | "cross-origin-embedder-policy"
            | "cross-origin-opener-policy"
            | "cross-origin-resource-policy"
            | "etag"
            | "expires"
            | "last-modified"
            | "location"
            | "permissions-policy"
            | "referrer-policy"
            | "reporting-endpoints"
            | "strict-transport-security"
            | "vary"
            | "x-content-type-options"
            | "x-frame-options"
            | "x-permitted-cross-domain-policies"
            | "x-xss-protection"
    )
}

/// Commit an x402 `batch-settlement` voucher after the resource was served
/// (the adapter's post-response hook).
///
/// This is the step that charges the client, so it runs only on a successful
/// serve. On failure the outcome is dropped instead: the watermark never
/// advances, the channel's in-flight guard is released, and the client may
/// retry the identical voucher.
///
/// No on-chain transaction is involved for a steady-state voucher — the
/// operator redeems accumulated vouchers in batches out of band. A `deposit`
/// broadcasts its `open`/`top_up` here, which is why this can fail after the
/// resource was already served; that loss is logged, not surfaced.
pub async fn settle_batch<S: PaymentState>(
    state: &S,
    forward: BatchForward,
    served_ok: bool,
    cached: Option<pay_kit::core::store::CachedUpstreamResponse>,
) -> Option<(HeaderName, HeaderValue)> {
    if !served_ok {
        release_batch(state, forward).await;
        return None;
    }
    let header = commit_batch(state, &forward).await;
    if let Some(cached) = cached {
        cache_batch_response(state, &forward, cached).await;
    }
    header
}

/// Commit a successfully served batch authorization while retaining its
/// outcome long enough for a streaming adapter to cache the completed body.
pub async fn commit_batch<S: PaymentState>(
    state: &S,
    forward: &BatchForward,
) -> Option<(HeaderName, HeaderValue)> {
    let batch = state.x402_batch()?;
    let telemetry_context = &forward.telemetry;
    let channel_id = forward.outcome.channel_id.clone();
    let channel_config = forward.outcome.payload().channel_config();
    let currency = channel_config.token.clone();
    let client_id = channel_config.payer.clone();
    let opens_channel = match forward.outcome.payload() {
        pay_kit::x402::batch_settlement::BatchPayload::Deposit { deposit, .. } => {
            matches!(
                pay_kit::x402::batch_settlement::setup_form_from_transaction(
                    &deposit.transaction,
                    &pay_kit::core::payment_channels::default_program_id(),
                ),
                Ok(pay_kit::x402::batch_settlement::SetupForm::Open)
            )
        }
        _ => false,
    };
    // The crash boundary: recorded before the charge so a retry can only
    // finish it, never serve again. A failure to record is not a reason to
    // abandon the charge — the upstream already answered — so it is logged and
    // the charge attempted regardless.
    if let Err(e) = batch.mark_handler_succeeded(&forward.outcome).await {
        telemetry::record_settlement_error(
            "x402/batch",
            &telemetry_context.subdomain,
            &telemetry_context.path,
            &e.to_string(),
            false,
        );
    }
    match batch.finish_commit(&forward.outcome).await {
        Ok(settlement) => {
            telemetry::record_payment_collected(
                "x402/batch",
                &telemetry_context.subdomain,
                &telemetry_context.path,
                telemetry_context.payment.as_ref(),
                &channel_id,
            );
            if let Some(channel_state) = settlement
                .extra
                .as_ref()
                .and_then(|extra| extra.channel_state.as_ref())
            {
                if let Some(cumulative) = channel_state
                    .charged_cumulative_amount
                    .as_deref()
                    .and_then(|value| value.parse().ok())
                {
                    telemetry::record_payment_channel_voucher_cumulative_for_protocol(
                        "x402/batch",
                        &channel_id,
                        &currency,
                        &settlement.network,
                        cumulative,
                    );
                }
                if let Some(charged) = settlement
                    .extra
                    .as_ref()
                    .and_then(|extra| extra.charged_amount.as_deref())
                    .and_then(|value| value.parse().ok())
                {
                    telemetry::record_payment_channel_voucher_accepted_for_protocol(
                        "x402/batch",
                        &currency,
                        &settlement.network,
                        charged,
                    );
                }
                if opens_channel && let Ok(escrowed) = channel_state.balance.parse() {
                    telemetry::record_payment_channel_opened_for_protocol(
                        "x402/batch",
                        &settlement.transaction,
                        &channel_id,
                        &client_id,
                        &currency,
                        &settlement.network,
                        escrowed,
                    );
                }
            }
            match batch.settlement_header(&settlement) {
                Ok((name, value)) => Some((
                    HeaderName::from_bytes(name.as_bytes()).ok()?,
                    HeaderValue::from_str(&value).ok()?,
                )),
                Err(e) => {
                    telemetry::record_settlement_error(
                        "x402/batch",
                        &telemetry_context.subdomain,
                        &telemetry_context.path,
                        &e.to_string(),
                        true,
                    );
                    None
                }
            }
        }
        Err(e) => {
            // The resource was already served; the uncommitted charge is the
            // operator's loss and worth alerting on.
            telemetry::record_settlement_error(
                "x402/batch",
                &telemetry_context.subdomain,
                &telemetry_context.path,
                &e.to_string(),
                true,
            );
            None
        }
    }
}

/// Release an authorization whose resource response was unsuccessful.
pub async fn release_batch<S: PaymentState>(state: &S, forward: BatchForward) {
    let Some(batch) = state.x402_batch() else {
        return;
    };
    if let Err(e) = batch.release_authorization(*forward.outcome).await {
        telemetry::record_settlement_error(
            "x402/batch",
            &forward.telemetry.subdomain,
            &forward.telemetry.path,
            &e.to_string(),
            false,
        );
    }
}

/// Persist a completed upstream representation after its payment commitment.
/// This is best effort: the client already received the original response.
pub async fn cache_batch_response<S: PaymentState>(
    state: &S,
    forward: &BatchForward,
    cached: pay_kit::core::store::CachedUpstreamResponse,
) {
    let Some(batch) = state.x402_batch() else {
        return;
    };
    if let Err(error) = batch.cache_response(&forward.outcome, cached).await {
        tracing::warn!(
            %error,
            channel_id = %forward.outcome.channel_id,
            "failed to cache x402 batch response"
        );
    }
}

/// Settle an x402 `upto` channel after the resource was served (the adapter's
/// post-response hook). Debits `settle_amount` (the configured `min`, or the
/// full ceiling when unset — clamped to `open.max_amount`) on a successful
/// serve, refunds the full deposit (settle `0`) on failure, and returns the
/// `PAYMENT-RESPONSE` receipt header to set on the response.
///
/// Routes through the shared batched-settlement worker (`settle_actual_deferred`):
/// concurrent settlements pack into one operator-signed tx that is **sent
/// without waiting for confirmation**, with the background worker confirming +
/// retrying. This takes the multi-second confirm poll off the response path —
/// the client's funds are locked by the confirmed `open`, so a late or failed
/// background confirm is an operator-retry concern (the channel store sweeps
/// it), not a client error. Settlement errors are logged, not surfaced (the
/// resource was already served).
pub async fn settle_upto<S: PaymentState>(
    state: &S,
    open: VerifiedUptoOpen,
    settle_amount: u64,
    served_ok: bool,
    telemetry_context: UptoPaymentTelemetry,
) -> Option<(HeaderName, HeaderValue)> {
    let upto = state.x402_upto()?;
    // Settle the configured voucher (clamped to the ceiling) on success, full
    // refund (`0`) on failure.
    let amount = if served_ok {
        settle_amount.min(open.max_amount)
    } else {
        0
    };
    let amount_usd = served_ok
        .then(|| upto_collected_amount_usd(telemetry_context.ceiling_usd, amount, open.max_amount))
        .flatten();
    match upto.settle_actual_deferred(&open, amount).await {
        Ok(settlement) => {
            tracing::Span::current().record("tx_sig", settlement.transaction.as_str());
            if let Some(ui_amount) = amount_usd {
                telemetry::record_payment_collected(
                    "x402/upto",
                    &telemetry_context.subdomain,
                    &telemetry_context.path,
                    Some(&telemetry::PaymentAmount {
                        currency: "USD".to_string(),
                        ui_amount,
                    }),
                    &settlement.transaction,
                );
            }
            match upto.settlement_header(&settlement) {
                Ok((name, value)) => Some((
                    HeaderName::from_bytes(name.as_bytes()).ok()?,
                    HeaderValue::from_str(&value).ok()?,
                )),
                Err(e) => {
                    telemetry::record_settlement_error(
                        "x402/upto",
                        &telemetry_context.subdomain,
                        &telemetry_context.path,
                        &e.to_string(),
                        true,
                    );
                    None
                }
            }
        }
        Err(e) => {
            telemetry::record_settlement_error(
                "x402/upto",
                &telemetry_context.subdomain,
                &telemetry_context.path,
                &e.to_string(),
                true,
            );
            None
        }
    }
}

/// Settle an x402 `upto` channel using post-response usage extraction.
///
/// When the response did not successfully serve, this always settles `0`
/// (refund). When usage extraction fails under `missing_usage: error`, it also
/// refunds so funds are not stranded.
pub async fn settle_upto_metered<S: PaymentState>(
    state: &S,
    open: VerifiedUptoOpen,
    plan: metering::UptoSettlementPlan,
    served_ok: bool,
    response_headers: &http::HeaderMap,
    response_body: Option<&[u8]>,
    telemetry_context: UptoPaymentTelemetry,
) -> Option<(HeaderName, HeaderValue)> {
    if !served_ok {
        return settle_upto(state, open, 0, false, telemetry_context).await;
    }

    let amount = match metering::upto_actual_amount_from_response(
        &plan,
        open.max_amount,
        response_headers,
        response_body,
    ) {
        Ok(actual) => actual.base_units,
        Err(e) => {
            telemetry::record_settlement_error(
                "x402/upto",
                &telemetry_context.subdomain,
                &telemetry_context.path,
                &e.to_string(),
                false,
            );
            0
        }
    };

    settle_upto(state, open, amount, true, telemetry_context).await
}

fn upto_collected_amount_usd(
    ceiling_usd: f64,
    settled_base_units: u64,
    maximum_base_units: u64,
) -> Option<f64> {
    (settled_base_units > 0 && maximum_base_units > 0)
        .then_some(ceiling_usd * settled_base_units as f64 / maximum_base_units as f64)
}

/// Reconstruct a minimal URI from path + query for split-rule resolution.
fn reconstruct_uri(path: &str, query: Option<&str>) -> http::Uri {
    format!(
        "/{}{}",
        path,
        query.map(|q| format!("?{q}")).unwrap_or_default()
    )
    .parse()
    .unwrap_or_default()
}

fn x402_exact_payment_memo(
    x402: &X402,
    pay_header: &str,
    resource: Option<&str>,
) -> Result<Option<String>, String> {
    let Some(resource) = resource.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(None);
    };
    let envelope = match x402.parse_payment_signature(pay_header) {
        Ok(envelope) => envelope,
        Err(_) => return Ok(None),
    };
    let Some(memo) = envelope
        .accepted
        .as_ref()
        .and_then(|accepted| accepted.get("extra"))
        .and_then(|extra| extra.get("memo"))
        .and_then(|memo| memo.as_str())
    else {
        return Ok(None);
    };
    if crate::server::payment::resource_memo_matches(
        memo,
        resource,
        pay_kit::x402::exact::MAX_MEMO_BYTES,
    ) {
        Ok(Some(memo.to_string()))
    } else {
        Err("x402 exact payment memo does not match endpoint resource".to_string())
    }
}

fn mpp_charge_payment_external_id(
    credential: &PaymentCredential,
    resource: Option<&str>,
) -> Result<Option<String>, String> {
    let Some(resource) = resource.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(None);
    };
    let request: ChargeRequest = credential
        .challenge
        .request
        .decode()
        .map_err(|e| format!("MPP charge credential request decode failed: {e}"))?;
    let external_id = request
        .external_id
        .as_deref()
        .ok_or_else(|| "MPP charge credential missing expected resource externalId".to_string())?;
    if crate::server::payment::resource_memo_matches(
        external_id,
        resource,
        pay_kit::mpp::protocol::solana::MAX_MEMO_BYTES,
    ) {
        Ok(Some(external_id.to_string()))
    } else {
        Err("MPP charge credential externalId does not match endpoint resource".to_string())
    }
}

/// Path-only variant hint (e.g. `/models/{name}:action` → `name`).
fn variant_hint_from_path(path: &str) -> Option<String> {
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

fn session_receipt_annotation(network: &str, reference: String) -> ReceiptAnnotation {
    let mut headers = Vec::new();
    if let Some(url) = crate::explorer::tx_url(network, &reference)
        && let Ok(value) = HeaderValue::from_str(&url)
    {
        headers.push((PAYMENT_RECEIPT_URL, value));
    }
    ReceiptAnnotation {
        headers,
        reference: Some(reference),
    }
}

/// Process a session credential and map the outcome to a [`GateDecision`].
async fn session_authorized(
    sm: &SessionMpp,
    handle: Option<Arc<SessionMpp>>,
    credential: PaymentCredential,
    meter: &pay_types::metering::Metering,
    req: &GateRequest<'_>,
    subdomain: &str,
    path: &str,
) -> GateDecision {
    match sm.process_credential(credential).await {
        Ok(SessionOutcome::Active { state, signature }) => {
            if sm.voucher_signer() == pay_kit::mpp::SessionVoucherSigner::Client {
                let mut response = GateResponse::json(
                    StatusCode::PAYMENT_REQUIRED,
                    serde_json::to_vec(&json!({
                        "error": "session_voucher_required",
                        "message": "The channel is open; submit a client-signed voucher before requesting paid service.",
                        "channelId": state.channel_id,
                    }))
                    .unwrap_or_default(),
                );
                if let Some(reference) = signature {
                    response
                        .headers
                        .extend(session_receipt_annotation(sm.network(), reference).headers);
                }
                return GateDecision::Respond(response);
            }
            let Some(handle) = handle else {
                return GateDecision::Respond(GateResponse::json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Bytes::from_static(br#"{"error":"session_backend_unavailable"}"#),
                ));
            };
            let available_base_units = state.deposit.saturating_sub(state.cumulative);
            if available_base_units == 0 {
                return GateDecision::Respond(GateResponse::json(
                    StatusCode::PAYMENT_REQUIRED,
                    serde_json::to_vec(&json!({
                        "error": "session_cap_exhausted",
                        "message": "The session spending cap has been exhausted; open a new session.",
                        "channelId": state.channel_id,
                    }))
                    .unwrap_or_default(),
                ));
            }
            let reservation = match handle
                .reserve_delegated_capacity(&state.channel_id, available_base_units)
                .await
            {
                Ok(Some(reservation)) => reservation,
                Ok(None) => {
                    return GateDecision::Respond(GateResponse::json(
                        StatusCode::PAYMENT_REQUIRED,
                        Bytes::from_static(br#"{"error":"session_capacity_reserved","message":"Another request is currently using this session capacity."}"#),
                    ));
                }
                Err(error) => {
                    tracing::warn!(
                        channel_id = %state.channel_id,
                        %error,
                        "failed to wake delegated session channel"
                    );
                    return GateDecision::Respond(GateResponse::json(
                        StatusCode::PAYMENT_REQUIRED,
                        Bytes::from_static(br#"{"error":"session_close_pending","message":"The session channel is closing; open a new session."}"#),
                    ));
                }
            };
            let props = metering::RequestProperties {
                body_size: req.content_length,
                ..Default::default()
            };
            let variant = variant_hint_from_path(path);
            let ceiling_usd = available_base_units as f64 / 10_f64.powi(sm.decimals() as i32);
            let settlement = metering::UptoSettlementPlan {
                metering: meter.clone(),
                variant_hint: variant,
                request_properties: props,
                ceiling_usd,
                inferred_usage: None,
            };
            GateDecision::Forward {
                session: Some(Box::new(SessionForward::delegated(
                    handle,
                    state.channel_id,
                    state.cumulative,
                    settlement,
                    available_base_units,
                    reservation,
                ))),
                receipt: signature
                    .map(|reference| session_receipt_annotation(sm.network(), reference)),
                upto: None,
                batch: None,
                paid_request: Some(PaidRequestTelemetry {
                    protocol: "mpp/session",
                    subdomain: subdomain.to_string(),
                    payment: None,
                }),
            }
        }
        Ok(SessionOutcome::Voucher {
            channel_id,
            cumulative,
        }) => GateDecision::Forward {
            session: handle.map(|h| {
                Box::new(SessionForward {
                    handle: h,
                    channel_id,
                    committed_base_units: cumulative,
                    settlement: None,
                    available_base_units: 0,
                    _reservation: None,
                })
            }),
            receipt: None,
            upto: None,
            batch: None,
            paid_request: Some(PaidRequestTelemetry {
                protocol: "mpp/session",
                subdomain: subdomain.to_string(),
                payment: None,
            }),
        },
        Ok(SessionOutcome::Closed { signature, .. }) => {
            let receipt_url = signature
                .as_deref()
                .and_then(|s| crate::explorer::tx_url(sm.network(), s));
            let body = json!({
                "status": "closed",
                "signature": signature,
                "transactionId": signature,
                "receiptUrl": receipt_url,
            });
            let mut resp = GateResponse::json(
                StatusCode::OK,
                serde_json::to_vec(&body).unwrap_or_default(),
            );
            if let Some(url) = receipt_url {
                resp = resp.header(PAYMENT_RECEIPT_URL, url);
            }
            GateDecision::Respond(resp)
        }
        Err(e) => {
            telemetry::record_settlement_error(
                "mpp/session",
                subdomain,
                path,
                &e.to_string(),
                true,
            );
            GateDecision::Respond(GateResponse::json(
                StatusCode::PAYMENT_REQUIRED,
                serde_json::to_vec(&json!({
                    "error": "session_failed",
                    "message": e.to_string(),
                    "retryable": true,
                }))
                .unwrap_or_default(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ceiling $0.10 at 6 decimals == 100_000 base units (USDC).
    const CEILING_USD: f64 = 0.10;
    const CEILING_BASE: u64 = 100_000;

    /// A client that lost a successful batch response gets the payment result
    /// back, not a conflict.
    ///
    /// The scheme requires the recorded response for an already-accepted
    /// commitment; answering `409` instead would leave a paid request
    /// permanently unrecoverable, since the client cannot re-present the
    /// voucher for a charge that already landed.
    #[test]
    fn a_replayed_batch_authorization_returns_its_payment_result() {
        use pay_kit::x402::batch_settlement::{BatchSettlementExtra, BatchSettlementResponse};

        let settlement = BatchSettlementResponse {
            success: true,
            error_reason: None,
            payer: Some("Ez3nFYs9GJMDRnHNRSFRDNvJqHUCLxLHJ9YnHLnPUxxx".to_string()),
            transaction: String::new(),
            network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string(),
            amount: String::new(),
            extra: Some(BatchSettlementExtra {
                commitment_id: Some("chan:5000".to_string()),
                charged_amount: Some("1000".to_string()),
                channel_state: None,
            }),
        };
        let batch = match test_batch_handler() {
            Some(batch) => batch,
            // The handler needs a signer; without one there is nothing to
            // format a settlement header with.
            None => return,
        };

        let resp = batch_replay_response(&batch, &settlement, None);

        assert_eq!(
            resp.status,
            StatusCode::OK,
            "a replay is the original outcome, not a conflict"
        );
        assert_ne!(resp.status, StatusCode::CONFLICT);
        let header = |name: &str| {
            resp.headers
                .iter()
                .find(|(n, _)| n.as_str().eq_ignore_ascii_case(name))
                .map(|(_, v)| v.to_str().unwrap_or_default().to_string())
        };
        // The charged amount travels back so the client can resynchronize.
        let encoded = header("payment-response").expect("settlement header attached");
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            encoded.as_bytes(),
        )
        .expect("base64 settlement header");
        let parsed: serde_json::Value = serde_json::from_slice(&decoded).expect("settlement json");
        assert_eq!(parsed["extra"]["chargedAmount"], "1000");
        assert_eq!(parsed["extra"]["commitmentId"], "chan:5000");
        // And the client is told the body is not the resource.
        assert_eq!(header("payment-replay").as_deref(), Some("true"));
    }

    #[test]
    fn a_replayed_batch_authorization_restores_the_cached_resource() {
        use pay_kit::core::store::CachedUpstreamResponse;
        use pay_kit::x402::batch_settlement::BatchSettlementResponse;

        let Some(batch) = test_batch_handler() else {
            return;
        };
        let settlement = BatchSettlementResponse {
            success: true,
            error_reason: None,
            payer: None,
            transaction: String::new(),
            network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".to_string(),
            amount: "1".to_string(),
            extra: None,
        };
        let cached = CachedUpstreamResponse {
            status: 201,
            content_type: Some("application/json".to_string()),
            headers: vec![
                (
                    "content-security-policy".to_string(),
                    "default-src 'none'".to_string(),
                ),
                ("etag".to_string(), "\"result-42\"".to_string()),
            ],
            body: br#"{"result":42}"#.to_vec(),
        };

        let resp = batch_replay_response(&batch, &settlement, Some(&cached));

        assert_eq!(resp.status, StatusCode::CREATED);
        assert_eq!(resp.body, Bytes::from_static(br#"{"result":42}"#));
        assert!(resp.headers.iter().any(|(name, value)| {
            name == header::CONTENT_TYPE && value == HeaderValue::from_static("application/json")
        }));
        assert!(resp.headers.iter().any(|(name, value)| {
            name == header::CONTENT_SECURITY_POLICY
                && value == HeaderValue::from_static("default-src 'none'")
        }));
        assert!(resp.headers.iter().any(|(name, value)| {
            name == header::ETAG && value == HeaderValue::from_static("\"result-42\"")
        }));
    }

    #[test]
    fn cached_batch_response_keeps_end_to_end_headers_only() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(header::ETAG, HeaderValue::from_static("\"v1\""));
        headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert(
            HeaderName::from_static("payment-response"),
            HeaderValue::from_static("attempt-specific"),
        );

        let cached = batch_cached_response(StatusCode::CREATED, &headers, b"resource");

        assert_eq!(cached.status, StatusCode::CREATED.as_u16());
        assert_eq!(cached.content_type.as_deref(), Some("application/json"));
        assert_eq!(
            cached.headers,
            vec![("etag".to_string(), "\"v1\"".to_string())]
        );
        assert_eq!(cached.body, b"resource");
    }

    /// A batch handler over an in-memory store, or `None` when this build
    /// cannot make a signer for one.
    fn test_batch_handler() -> Option<X402BatchSettlement> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(sk.as_bytes());
        keypair[32..].copy_from_slice(sk.verifying_key().as_bytes());
        let signer = pay_kit::solana_keychain::MemorySigner::from_bytes(&keypair).ok()?;
        let mut cfg = pay_kit::x402::server::BatchConfig::new(
            "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            "devnet",
            std::sync::Arc::new(signer),
        );
        cfg.withdraw_delay = 900;
        X402BatchSettlement::new(cfg).ok()
    }

    #[test]
    fn session_receipt_links_to_the_authorizing_transaction() {
        let receipt = session_receipt_annotation("mainnet", "open_signature".to_string());

        assert_eq!(receipt.reference.as_deref(), Some("open_signature"));
        assert_eq!(receipt.headers.len(), 1);
        assert_eq!(receipt.headers[0].0, PAYMENT_RECEIPT_URL);
        assert_eq!(
            receipt.headers[0].1.to_str().unwrap(),
            "https://pay.sh/receipt/open_signature"
        );
    }

    #[test]
    fn only_payment_scheme_counts_as_credential() {
        // Upstream auth (Claude Code's ANTHROPIC_AUTH_TOKEN, API bearer
        // tokens) must fall through to the 402 challenge, not 400.
        assert!(!is_payment_authorization(&"Bearer ollama"));
        assert!(!is_payment_authorization(&"Basic dXNlcjpwdw=="));
        assert!(!is_payment_authorization(&"Payment")); // no payload, no space
        assert!(is_payment_authorization(&"Payment eyJjaGFsbGVuZ2UiOnt9fQ"));
        assert!(is_payment_authorization(&"payment abc")); // scheme is case-insensitive
    }

    #[test]
    fn upto_voucher_defaults_to_full_ceiling_without_min() {
        assert_eq!(
            upto_settle_amount(None, CEILING_USD, CEILING_BASE),
            CEILING_BASE
        );
    }

    #[test]
    fn upto_voucher_uses_configured_min() {
        // $0.01 of a $0.10 ceiling -> 10_000 base units (exactly parse_units).
        assert_eq!(
            upto_settle_amount(Some(0.01), CEILING_USD, CEILING_BASE),
            10_000
        );
        // $0.037 -> 37_000.
        assert_eq!(
            upto_settle_amount(Some(0.037), CEILING_USD, CEILING_BASE),
            37_000
        );
    }

    #[test]
    fn upto_voucher_clamps_min_to_ceiling() {
        // A min above the ceiling never over-debits the channel.
        assert_eq!(
            upto_settle_amount(Some(0.50), CEILING_USD, CEILING_BASE),
            CEILING_BASE
        );
    }

    #[test]
    fn upto_voucher_handles_zero_min_and_degenerate_ceiling() {
        assert_eq!(upto_settle_amount(Some(0.0), CEILING_USD, CEILING_BASE), 0);
        // A non-positive ceiling can't scale a min -> fall back to the ceiling.
        assert_eq!(
            upto_settle_amount(Some(0.01), 0.0, CEILING_BASE),
            CEILING_BASE
        );
    }

    #[test]
    fn upto_collected_amount_reports_the_debited_fraction_of_the_ceiling() {
        assert_eq!(
            upto_collected_amount_usd(0.10, 25_000, 100_000),
            Some(0.025)
        );
        assert_eq!(upto_collected_amount_usd(0.10, 0, 100_000), None);
        assert_eq!(upto_collected_amount_usd(0.10, 1, 0), None);
    }

    #[test]
    fn x402_exact_payment_memo_accepts_resource_nonce_memo() {
        let x402 = x402_test_server();
        let accepted = x402_accepted_with_memo(&x402, Some("fortune#012"));
        let header = x402_signature_header(Some(accepted));

        assert_eq!(
            x402_exact_payment_memo(&x402, &header, Some("fortune"))
                .unwrap()
                .as_deref(),
            Some("fortune#012")
        );
    }

    #[test]
    fn x402_exact_payment_memo_rejects_wrong_resource() {
        let x402 = x402_test_server();
        let accepted = x402_accepted_with_memo(&x402, Some("other#012"));
        let header = x402_signature_header(Some(accepted));

        assert!(
            x402_exact_payment_memo(&x402, &header, Some("fortune"))
                .unwrap_err()
                .contains("does not match")
        );
    }

    #[test]
    fn x402_exact_payment_memo_falls_back_when_accepted_memo_is_absent() {
        let x402 = x402_test_server();
        let accepted = x402_accepted_with_memo(&x402, None);
        let header = x402_signature_header(Some(accepted));

        assert_eq!(
            x402_exact_payment_memo(&x402, &header, Some("fortune")).unwrap(),
            None
        );
    }

    #[test]
    fn x402_exact_payment_memo_falls_back_to_process_payment_for_missing_accepted() {
        let x402 = x402_test_server();
        let header = x402_signature_header(None);

        assert_eq!(
            x402_exact_payment_memo(&x402, &header, Some("fortune")).unwrap(),
            None
        );
    }

    #[test]
    fn mpp_charge_payment_external_id_accepts_resource_nonce_memo() {
        let credential = mpp_credential_with_external_id(Some("fortune#012"));

        assert_eq!(
            mpp_charge_payment_external_id(&credential, Some("fortune"))
                .unwrap()
                .as_deref(),
            Some("fortune#012")
        );
    }

    #[test]
    fn mpp_charge_payment_external_id_accepts_legacy_static_resource() {
        let credential = mpp_credential_with_external_id(Some("fortune"));

        assert_eq!(
            mpp_charge_payment_external_id(&credential, Some("fortune"))
                .unwrap()
                .as_deref(),
            Some("fortune")
        );
    }

    #[test]
    fn mpp_charge_payment_external_id_rejects_wrong_resource() {
        let credential = mpp_credential_with_external_id(Some("other#012"));

        assert!(
            mpp_charge_payment_external_id(&credential, Some("fortune"))
                .unwrap_err()
                .contains("does not match")
        );
    }

    fn mpp_credential_with_external_id(external_id: Option<&str>) -> PaymentCredential {
        let request = ChargeRequest {
            amount: "1".to_string(),
            currency: "USDC".to_string(),
            external_id: external_id.map(str::to_string),
            ..Default::default()
        };
        let challenge = pay_kit::mpp::PaymentChallenge::new(
            "challenge-id",
            "pay",
            "solana",
            "charge",
            pay_kit::mpp::Base64UrlJson::from_typed(&request).unwrap(),
        );
        PaymentCredential::new(
            challenge.to_echo(),
            json!({"type": "transaction", "transaction": "deadbeef"}),
        )
    }

    fn x402_test_server() -> X402 {
        X402::new(pay_kit::x402::server::Config {
            recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            currencies: vec![pay_kit::x402::server::CurrencyConfig {
                currency: "USDC".to_string(),
                decimals: 6,
                token_program: None,
            }],
            network: "devnet".to_string(),
            rpc_url: Some("http://localhost:8899".to_string()),
            resource: "fortune".to_string(),
            description: Some("Fortune".to_string()),
            max_age: Some(60),
            fee_payer_key: None,
        })
        .unwrap()
    }

    fn x402_accepted_with_memo(x402: &X402, memo: Option<&str>) -> serde_json::Value {
        let (_, required) = x402
            .payment_required_header(
                "1",
                ExactOptions {
                    memo,
                    ..Default::default()
                },
            )
            .unwrap();
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, required).unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        envelope
            .get("accepts")
            .and_then(|accepts| accepts.as_array())
            .and_then(|accepts| accepts.first())
            .cloned()
            .unwrap()
    }

    fn x402_signature_header(accepted: Option<serde_json::Value>) -> String {
        let mut envelope = json!({
            "x402Version": pay_kit::x402::X402_VERSION_V2,
            "payload": {
                "signature": "5UfDuX6nSqMzMR8W7n6K3b1GKLmaqEisBFCcYPRLjNHrCbVQJF3BVjkE7aQJMQ2Kx"
            }
        });
        if let Some(accepted) = accepted {
            envelope["accepted"] = accepted;
        }
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(&envelope).unwrap(),
        )
    }

    fn req<'a>(method: &'a Method, path: &'a str) -> GateRequest<'a> {
        GateRequest {
            method,
            path,
            host: Some("api.example.com"),
            accept: None,
            authorization: None,
            content_length: None,
            query: None,
            x402_payment: None,
        }
    }

    // A PaymentState with no APIs → everything is Passthrough.
    #[derive(Clone)]
    struct EmptyState;
    impl PaymentState for EmptyState {
        fn apis(&self) -> &[pay_types::metering::ApiSpec] {
            &[]
        }
        fn mpp(&self) -> Option<&pay_kit::mpp::server::Mpp> {
            None
        }
    }

    #[tokio::test]
    async fn discovery_and_control_plane_passthrough() {
        let gate = PaymentGate::new(EmptyState);
        for path in [
            "__402/health",
            "openapi.json",
            ".well-known/pay-skills.json",
        ] {
            assert!(matches!(
                gate.evaluate(&req(&Method::GET, path)).await,
                GateDecision::Passthrough
            ));
        }
    }

    #[tokio::test]
    async fn unknown_subdomain_passthrough() {
        let gate = PaymentGate::new(EmptyState);
        assert!(matches!(
            gate.evaluate(&req(&Method::GET, "v1/anything")).await,
            GateDecision::Passthrough
        ));
    }
}
