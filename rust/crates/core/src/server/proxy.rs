//! HTTP reverse proxy — forwards requests to upstream APIs.
//!
//! Resolves the upstream from `ApiSpec.routing`, forwards headers and body,
//! returns the upstream response. Strips hop-by-hop and payment headers.
//!
//! For `Respond` routing, returns 200 directly (no upstream call).

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::Response;
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use pay_types::metering::{
    AccessTokenFetchConfig, AccessTokenInjectConfig, AccessTokenResponseConfig, ApiSpec,
    AuthConfig, HmacAlgorithm, HmacCanonicalComponent, HmacCanonicalConfig, HmacDigestAlgorithm,
    HmacEncoding, HmacPrepareBinding, HmacPrepareValue, HmacQueryStyle, HmacSignatureConfig,
    HmacStringEncoding, HmacTargetType, HmacTimestampFormat, HttpMethod, RoutingConfig,
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rand::RngCore;
use serde_json::json;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::server::session_stream::{self, SessionStreamContext};
use crate::server::{metering, payment, telemetry};

/// Headers to strip when forwarding to upstream. `pub` so the pingora data plane
/// (`pay-proxy`) shares the exact same list rather than duplicating it.
pub const STRIP_HEADERS: &[&str] = &[
    "host",
    "connection",
    "transfer-encoding",
    "authorization",
    "payment-signature",
    "payment-required",
    // x402 v1 payment credential — must never reach a third-party upstream,
    // which could log or leak it (the gate accepts the credential via either
    // `PAYMENT-SIGNATURE` or `X-PAYMENT`).
    "x-payment",
];

/// Percent-encode every ASCII byte except RFC 3986 unreserved characters.
const RFC3986_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Resolve the effective routing for a request path.
///
/// This intentionally ignores the HTTP method. Metering/payment logic handles
/// method-sensitive gating separately, while routing overrides remain path-based
/// so browser payment-link and redirect flows can still inherit the endpoint's
/// transport behavior even when the browser uses `GET` against a non-GET
/// metered endpoint.
pub fn resolve_routing<'a>(api: &'a ApiSpec, path: &str) -> &'a RoutingConfig {
    let trimmed = path.trim_start_matches('/');
    for ep in &api.endpoints {
        if ep.path == trimmed
            && let Some(ref r) = ep.routing
        {
            return r;
        }
    }
    &api.routing
}

/// Does the endpoint's upstream auth digest the **request body** (an HMAC /
/// AccessToken `prepare` binding with `body_digest`)? Such schemes can only be
/// signed correctly when the full body is available before the upstream connect.
///
/// The axum path always has the buffered body, so it's fine there. The pingora
/// data plane streams the body unbuffered and signs against an empty placeholder,
/// which would silently produce a wrong signature — it uses this to refuse such
/// requests loudly instead.
pub fn routing_signs_request_body(api: &ApiSpec, path: &str) -> bool {
    use pay_types::metering::{AuthConfig, HmacPrepareValue};
    let prepares = match resolve_routing(api, path).auth() {
        Some(AuthConfig::Hmac { prepare, .. } | AuthConfig::AccessToken { prepare, .. }) => prepare,
        _ => return false,
    };
    prepares
        .iter()
        .any(|b| matches!(b.value, HmacPrepareValue::BodyDigest { .. }))
}

/// Forward a request to the upstream API defined in the spec.
///
/// - Builds the upstream URL from `api.routing` + request path
/// - Forwards all headers except hop-by-hop and payment headers
/// - Forwards the request body as-is
/// - Returns the upstream response (status, headers, body)
///
/// For `Respond` routing, returns 200 with `{"status":"ok"}`.
// A direct `Response` error preserves the proxy's intentionally constructed
// HTTP response for the axum caller.
#[allow(clippy::result_large_err)]
pub async fn forward_request(
    api: &ApiSpec,
    method: Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    forward_request_with_session_metering(api, method, uri, headers, body, None).await
}

/// Forward a request and optionally meter the streamed response against an open
/// session. The plain [`forward_request`] wrapper keeps existing callers and
/// tests on the unmetered path.
#[tracing::instrument(
    name = "proxy_forward",
    skip(api, headers, body, session_context),
    fields(subdomain = %api.subdomain, method = %method, path = %uri.path())
)]
// A direct `Response` error preserves the proxy's intentionally constructed
// HTTP response for the axum caller.
#[allow(clippy::result_large_err)]
pub async fn forward_request_with_session_metering(
    api: &ApiSpec,
    method: Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
    session_context: Option<SessionStreamContext>,
) -> Result<Response, Response> {
    let prepared = match prepare_upstream(api, &method, uri, headers, body.as_ref()).await? {
        UpstreamPlan::Respond(resp) => return Ok(resp),
        UpstreamPlan::Forward(prepared) => prepared,
    };

    let client = reqwest::Client::new();
    let mut upstream_req = client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
        prepared.url.clone(),
    );
    for (name, value) in &prepared.headers {
        upstream_req = upstream_req.header(name.as_str(), value);
    }
    let upstream_url = prepared.url.to_string();

    // Forward body. Always set content-length for POST/PUT/PATCH
    // (some upstreams like Google APIs require it even when empty).
    if !body.is_empty() {
        upstream_req = upstream_req.body(body.to_vec());
    } else if matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
        upstream_req = upstream_req.header("content-length", "0");
    }

    let upstream_resp = upstream_req.send().await.map_err(|e| {
        telemetry::record_upstream_error(&api.subdomain, uri.path(), &upstream_url, &e.to_string());
        tracing::error!(error = %e, upstream = %upstream_url, "Upstream request failed");
        error_response(StatusCode::BAD_GATEWAY, &format!("Upstream error: {e}"))
    })?;

    // Build response.
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if status.is_server_error() {
        telemetry::record_upstream_error(
            &api.subdomain,
            uri.path(),
            &upstream_url,
            &format!("upstream returned {status}"),
        );
    }
    let mut response_headers = HeaderMap::new();
    // Skip headers that reqwest handles (it auto-decompresses gzip).
    let skip_response_headers = ["content-encoding", "content-length", "transfer-encoding"];
    for (name, value) in upstream_resp.headers() {
        let name_lower = name.as_str();
        if skip_response_headers.contains(&name_lower) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            axum::http::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            response_headers.insert(n, v);
        }
    }

    let mut resp = Response::builder().status(status);
    for (name, value) in &response_headers {
        resp = resp.header(name, value);
    }

    let content_type = response_headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let is_sse = content_type
        .split(';')
        .any(|part| part.trim().eq_ignore_ascii_case("text/event-stream"));

    let stream = upstream_resp.bytes_stream();
    if let Some(meter) = build_session_stream_meter(api, &method, uri, headers, session_context) {
        return Ok(resp
            .body(Body::from_stream(session_stream::meter_response_stream(
                stream, meter, is_sse,
            )))
            .unwrap());
    }

    Ok(resp.body(Body::from_stream(stream)).unwrap())
}

/// Outcome of preparing an upstream request: either a locally-built response
/// (respond-mode / not-found) or a fully-prepared upstream request ready to be
/// sent (reqwest by axum) or proxied natively (pingora).
pub enum UpstreamPlan {
    Respond(Response),
    Forward(PreparedUpstreamRequest),
}

/// Resolve routing, build the upstream URL (with path rewrites), forward+strip
/// headers, and inject auth — everything up to (but not including) sending the
/// request. Framework-neutral: the result is consumed by axum's reqwest send and
/// by the pingora gate's native proxying alike.
// A direct `Response` error preserves status, headers, and body for both
// framework adapters without a lossy intermediate error type.
#[allow(clippy::result_large_err)]
pub async fn prepare_upstream(
    api: &ApiSpec,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<UpstreamPlan, Response> {
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(uri.path());

    let routing = resolve_routing(api, uri.path());

    // Respond mode — no upstream call.
    if routing.is_respond() {
        use crate::server::metering::find_endpoint_by_path;
        let path_trimmed = uri.path().trim_start_matches('/');
        if find_endpoint_by_path(api, path_trimmed).is_some() {
            return Ok(UpstreamPlan::Respond(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"status":"ok"}"#))
                    .unwrap(),
            ));
        }
        return Ok(UpstreamPlan::Respond(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"error":"not_found"}"#))
                .unwrap(),
        ));
    }

    // Build the upstream URL (with path rewrites) and prepare the forwarded
    // request state before converting it into a reqwest request.
    let upstream_url = routing
        .upstream_url(path_and_query)
        .expect("Proxy routing must have a URL");
    let mut prepared = PreparedUpstreamRequest::new(&upstream_url).map_err(|e| {
        telemetry::record_upstream_error(&api.subdomain, uri.path(), &upstream_url, &e);
        error_response(StatusCode::BAD_GATEWAY, &e)
    })?;

    tracing::debug!(
        subdomain = %api.subdomain,
        upstream = %prepared.url,
        "Forwarding request"
    );

    // Forward headers.
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if STRIP_HEADERS.contains(&name_str) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            prepared.add_forwarded_header(name_str, v);
        }
    }

    // Inject auth into the prepared upstream request.
    match routing.auth() {
        Some(
            AuthConfig::Header { .. } | AuthConfig::QueryParam { .. } | AuthConfig::Hmac { .. },
        ) => {
            apply_prepared_request_auth(
                &mut prepared,
                method,
                body,
                routing.auth().expect("routing auth checked above"),
            )
            .map_err(|e| {
                telemetry::record_upstream_error(
                    &api.subdomain,
                    uri.path(),
                    prepared.url.as_str(),
                    &e,
                );
                error_response(StatusCode::BAD_GATEWAY, &e)
            })?;
        }
        Some(AuthConfig::Oauth2 {
            token_url,
            scopes,
            audience,
            client_id_from_env,
            client_secret_from_env,
            headers,
        }) => {
            match oauth2_token(
                token_url,
                scopes,
                audience.as_deref(),
                client_id_from_env.as_deref(),
                client_secret_from_env.as_deref(),
            )
            .await
            {
                Ok(token) => {
                    prepared.set_header("authorization", format!("Bearer {token}"));
                    for (header_name, env_ref) in headers {
                        if let Ok(val) = std::env::var(&env_ref.from_env) {
                            prepared.set_header(header_name, val);
                        }
                    }
                }
                Err(e) => {
                    telemetry::record_upstream_error(
                        &api.subdomain,
                        uri.path(),
                        prepared.url.as_str(),
                        &format!("OAuth2 token error: {e}"),
                    );
                    tracing::error!(error = %e, "Failed to fetch OAuth2 token");
                    return Err(error_response(
                        StatusCode::BAD_GATEWAY,
                        &format!("OAuth2 token error: {e}"),
                    ));
                }
            }
        }
        Some(AuthConfig::AccessToken {
            prepare,
            fetch,
            inject,
        }) => {
            apply_access_token_auth(&mut prepared, method, body, prepare, fetch, inject)
                .await
                .map_err(|e| {
                    telemetry::record_upstream_error(
                        &api.subdomain,
                        uri.path(),
                        prepared.url.as_str(),
                        &e,
                    );
                    error_response(StatusCode::BAD_GATEWAY, &e)
                })?;
        }
        _ => {}
    }

    Ok(UpstreamPlan::Forward(prepared))
}

fn build_session_stream_meter(
    api: &ApiSpec,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    session_context: Option<SessionStreamContext>,
) -> Option<session_stream::SessionStreamMeter> {
    let context = session_context?;
    let match_method = if *method == Method::HEAD {
        "GET"
    } else {
        method.as_str()
    };
    let path = uri.path().trim_start_matches('/');
    let endpoint = metering::find_endpoint(api, match_method, path)?;
    let metering = endpoint.metering.as_ref()?;
    let props = payment::extract_request_properties(headers, path);
    let variant_hint = payment::extract_variant_hint(path);

    match session_stream::meter_from_config(metering, &props, variant_hint.as_deref(), context) {
        Ok(Some(meter)) => Some(meter),
        Ok(None) => None,
        Err(error) => {
            tracing::debug!(%error, path, "session stream metering disabled for endpoint");
            None
        }
    }
}

/// Resolve the API spec from a Host header subdomain.
pub fn resolve_api<'a>(apis: &'a [ApiSpec], host: &str) -> Option<&'a ApiSpec> {
    let subdomain = host.split('.').next().unwrap_or("");
    apis.iter().find(|a| a.subdomain == subdomain)
}

pub fn error_response(status: StatusCode, message: &str) -> Response {
    let body = json!({
        "error": status.as_str(),
        "message": message,
    });

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedUpstreamRequest {
    pub url: reqwest::Url,
    pub headers: Vec<(String, String)>,
}

impl PreparedUpstreamRequest {
    /// Parse the routed upstream URL into a mutable request shape that can be
    /// amended by auth code before we build the final `reqwest` request.
    fn new(upstream_url: &str) -> Result<Self, String> {
        let url =
            reqwest::Url::parse(upstream_url).map_err(|e| format!("Invalid upstream URL: {e}"))?;
        Ok(Self {
            url,
            headers: Vec::new(),
        })
    }

    fn add_forwarded_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }

    fn set_header(&mut self, name: &str, value: impl Into<String>) {
        self.headers
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value.into()));
    }

    fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn append_query_param(&mut self, name: &str, value: &str) {
        self.url.query_pairs_mut().append_pair(name, value);
    }

    fn set_query_param(&mut self, name: &str, value: &str) {
        let existing: Vec<(String, String)> = self
            .url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .filter(|(key, _)| key != name)
            .collect();
        self.url.set_query(None);
        {
            let mut pairs = self.url.query_pairs_mut();
            for (key, existing_value) in existing {
                pairs.append_pair(&key, &existing_value);
            }
            pairs.append_pair(name, value);
        }
    }
}

/// Apply a direct auth scheme to a mutable upstream request.
///
/// This helper is intentionally limited to schemes that operate entirely on the
/// already-prepared request. Token-fetching flows are handled separately.
struct HmacAuthConfigRef<'a> {
    algorithm: &'a HmacAlgorithm,
    secret_from_env: &'a str,
    secret_suffix: Option<&'a str>,
    key_id_from_env: Option<&'a str>,
    prepare: &'a [HmacPrepareBinding],
    canonical: &'a HmacCanonicalConfig,
    signature: &'a HmacSignatureConfig,
}

fn apply_prepared_request_auth(
    prepared: &mut PreparedUpstreamRequest,
    method: &Method,
    body: &[u8],
    auth: &AuthConfig,
) -> Result<(), String> {
    match auth {
        AuthConfig::Header {
            key,
            prefix,
            value_from_env,
        } => {
            // Same loud-failure rule as QueryParam — silently sending an
            // empty header value masks the real config problem behind a
            // confusing upstream 401/403.
            let secret = std::env::var(value_from_env).map_err(|_| {
                format!(
                    "Proxy auth misconfigured: env var `{value_from_env}` is not set, \
                     can't inject the `{key}` header into the upstream request. \
                     Export it in the shell that runs `pay gate api`."
                )
            })?;
            if secret.trim().is_empty() {
                return Err(format!(
                    "Proxy auth misconfigured: env var `{value_from_env}` is set but empty, \
                     can't inject the `{key}` header into the upstream request."
                ));
            }
            let value = match prefix {
                Some(p) => format!("{p}{secret}"),
                None => secret,
            };
            prepared.set_header(key, value);
            Ok(())
        }
        AuthConfig::QueryParam {
            key,
            value_from_env,
        } => {
            // Silently appending `?{key}=` (empty) when the env var is
            // unset trips upstream auth checks with cryptic errors like
            // the provider's `"missing api key"`. Fail loudly so operators
            // notice the missing config at the first request instead of
            // chasing it through upstream logs.
            let secret = std::env::var(value_from_env).map_err(|_| {
                format!(
                    "Proxy auth misconfigured: env var `{value_from_env}` is not set, \
                     can't inject `?{key}=...` into the upstream request. \
                     Export it in the shell that runs `pay gate api`."
                )
            })?;
            if secret.trim().is_empty() {
                return Err(format!(
                    "Proxy auth misconfigured: env var `{value_from_env}` is set but empty, \
                     can't inject `?{key}=...` into the upstream request."
                ));
            }
            prepared.append_query_param(key, &secret);
            Ok(())
        }
        AuthConfig::Hmac {
            algorithm,
            secret_from_env,
            secret_suffix,
            key_id_from_env,
            prepare,
            canonical,
            signature,
        } => apply_hmac_auth(
            prepared,
            method,
            body,
            &HmacAuthConfigRef {
                algorithm,
                secret_from_env,
                secret_suffix: secret_suffix.as_deref(),
                key_id_from_env: key_id_from_env.as_deref(),
                prepare,
                canonical,
                signature,
            },
        ),
        AuthConfig::Oauth2 { .. } => Err(
            "Nested oauth2 auth is not supported when preparing another upstream request"
                .to_string(),
        ),
        AuthConfig::AccessToken { .. } => Err(
            "Nested access_token auth is not supported when preparing another upstream request"
                .to_string(),
        ),
    }
}

/// Apply a cached access-token flow to the main upstream request.
async fn apply_access_token_auth(
    prepared: &mut PreparedUpstreamRequest,
    _method: &Method,
    body: &[u8],
    prepare: &[HmacPrepareBinding],
    fetch: &AccessTokenFetchConfig,
    inject: &AccessTokenInjectConfig,
) -> Result<(), String> {
    for binding in prepare {
        let value = resolve_hmac_prepare_value(&prepared.url, body, &binding.value)?;
        apply_hmac_target(prepared, &binding.target.kind, &binding.target.name, &value);
    }

    let token = access_token(fetch).await?;
    let rendered = render_access_token_template(&inject.template, &token)?;
    apply_hmac_target(
        prepared,
        &inject.target.kind,
        &inject.target.name,
        &rendered,
    );
    Ok(())
}

/// Apply generic HMAC request signing to the prepared upstream request.
///
/// The sequence is:
/// 1. resolve the configured secret/key id from the environment
/// 2. apply all `prepare` bindings to the mutable request
/// 3. build the canonical string from the post-prepare request state
/// 4. compute the HMAC and write the rendered signature to its destination
fn apply_hmac_auth(
    prepared: &mut PreparedUpstreamRequest,
    method: &Method,
    body: &[u8],
    auth: &HmacAuthConfigRef<'_>,
) -> Result<(), String> {
    let secret = std::env::var(auth.secret_from_env)
        .map_err(|_| format!("HMAC secret env var not set: {}", auth.secret_from_env))?;
    let key_id = match auth.key_id_from_env {
        Some(env_name) => Some(
            std::env::var(env_name)
                .map_err(|_| format!("HMAC key ID env var not set: {env_name}"))?,
        ),
        None => None,
    };

    for binding in auth.prepare {
        let value = resolve_hmac_prepare_value(&prepared.url, body, &binding.value)?;
        apply_hmac_target(prepared, &binding.target.kind, &binding.target.name, &value);
    }

    let canonical_string = build_hmac_canonical_string(prepared, method, auth.canonical)?;
    let signing_secret = match auth.secret_suffix {
        Some(suffix) => format!("{secret}{suffix}"),
        None => secret,
    };
    let signature_bytes = compute_hmac_signature_bytes(
        auth.algorithm,
        signing_secret.as_bytes(),
        canonical_string.as_bytes(),
    )?;
    let encoded_signature = encode_bytes(signature_bytes.as_ref(), &auth.signature.encoding);
    let rendered_signature = render_hmac_template(
        &auth.signature.destination.template,
        encoded_signature.as_str(),
        key_id.as_deref(),
    )?;

    apply_hmac_target(
        prepared,
        &auth.signature.destination.kind,
        &auth.signature.destination.name,
        &rendered_signature,
    );
    Ok(())
}

/// Write a resolved value to either a header or query parameter.
fn apply_hmac_target(
    prepared: &mut PreparedUpstreamRequest,
    kind: &HmacTargetType,
    name: &str,
    value: &str,
) {
    match kind {
        HmacTargetType::Header => prepared.set_header(name, value),
        HmacTargetType::QueryParam => prepared.set_query_param(name, value),
    }
}

/// Resolve one `prepare` binding against the final upstream URL and raw body.
fn resolve_hmac_prepare_value(
    upstream_url: &reqwest::Url,
    body: &[u8],
    value: &HmacPrepareValue,
) -> Result<String, String> {
    match value {
        HmacPrepareValue::Literal { value } => Ok(value.clone()),
        HmacPrepareValue::Env { from_env } => {
            std::env::var(from_env).map_err(|_| format!("HMAC prepare env var not set: {from_env}"))
        }
        HmacPrepareValue::UpstreamHost {} => host_header_value(upstream_url),
        HmacPrepareValue::Timestamp { format } => Ok(match format {
            HmacTimestampFormat::Rfc1123Gmt => current_gmt_date(),
            HmacTimestampFormat::Iso8601Zulu => current_iso8601_zulu(),
            HmacTimestampFormat::UnixSeconds => Utc::now().timestamp().to_string(),
        }),
        HmacPrepareValue::UuidV4 {} => Ok(random_uuid_v4()),
        HmacPrepareValue::RandomHex { bytes } => Ok(random_hex(*bytes as usize)),
        HmacPrepareValue::BodyDigest {
            algorithm,
            encoding,
        } => Ok(encode_bytes(
            digest_bytes(algorithm, body).as_ref(),
            encoding,
        )),
    }
}

/// Render the canonical string that becomes the HMAC message.
///
/// Header lookups are case-insensitive and operate on the post-prepare header
/// set. Query lookups operate on the final upstream URL after any prepare-time
/// query mutations.
fn build_hmac_canonical_string(
    prepared: &PreparedUpstreamRequest,
    method: &Method,
    canonical: &HmacCanonicalConfig,
) -> Result<String, String> {
    let mut parts = Vec::with_capacity(canonical.components.len());

    for component in &canonical.components {
        let part = match component {
            HmacCanonicalComponent::Method {} => method.as_str().to_string(),
            HmacCanonicalComponent::Path {} => prepared.url.path().to_string(),
            HmacCanonicalComponent::Query { style, encoding } => {
                canonical_query_component(&prepared.url, style, encoding)?
            }
            HmacCanonicalComponent::Header { name } => prepared
                .header_value(name)
                .map(str::to_string)
                .ok_or_else(|| format!("HMAC canonical header `{name}` is missing"))?,
            HmacCanonicalComponent::Headers {
                names,
                join_with,
                format,
            } => {
                let mut rendered = Vec::with_capacity(names.len());
                for name in names {
                    let value = prepared
                        .header_value(name)
                        .ok_or_else(|| format!("HMAC canonical header `{name}` is missing"))?;
                    rendered.push(render_named_value_template(format, name, value)?);
                }
                rendered.join(join_with)
            }
            HmacCanonicalComponent::Literal { value } => value.clone(),
        };
        parts.push(part);
    }

    Ok(parts.join(&canonical.join_with))
}

/// Render the final query string for canonicalization.
///
/// `raw` preserves the exact query string order and encoding already present on
/// the upstream URL. `sorted_pairs` reorders pairs by name and then value using
/// the raw `k=v` substrings.
fn canonical_query_component(
    url: &reqwest::Url,
    style: &HmacQueryStyle,
    encoding: &HmacStringEncoding,
) -> Result<String, String> {
    let raw_query = url
        .query()
        .filter(|query| !query.is_empty())
        .ok_or_else(|| "HMAC canonical query is missing".to_string())?;
    let rendered = match style {
        HmacQueryStyle::Raw => raw_query.to_string(),
        HmacQueryStyle::SortedPairs => {
            let mut pairs = parse_raw_query_pairs(raw_query);
            pairs.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
            pairs
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("&")
        }
    };
    Ok(match encoding {
        HmacStringEncoding::None => rendered,
        HmacStringEncoding::PercentRfc3986 => percent_encode_rfc3986(&rendered),
    })
}

/// Split a raw query string into `name=value` pairs without decoding it.
fn parse_raw_query_pairs(raw_query: &str) -> Vec<(String, String)> {
    raw_query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (name.to_string(), value.to_string()),
            None => (pair.to_string(), String::new()),
        })
        .collect()
}

/// Compute the raw HMAC bytes for the configured hash algorithm.
fn compute_hmac_signature_bytes(
    algorithm: &HmacAlgorithm,
    secret: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, String> {
    match algorithm {
        HmacAlgorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(secret)
                .map_err(|e| format!("Invalid HMAC secret: {e}"))?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        HmacAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                .map_err(|e| format!("Invalid HMAC secret: {e}"))?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        HmacAlgorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(secret)
                .map_err(|e| format!("Invalid HMAC secret: {e}"))?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
    }
}

/// Compute a raw body digest for `prepare.value.from: body_digest`.
fn digest_bytes(algorithm: &HmacDigestAlgorithm, body: &[u8]) -> Vec<u8> {
    match algorithm {
        HmacDigestAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            hasher.update(body);
            hasher.finalize().to_vec()
        }
        HmacDigestAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(body);
            hasher.finalize().to_vec()
        }
        HmacDigestAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(body);
            hasher.finalize().to_vec()
        }
    }
}

/// Encode raw bytes as either base64 or lowercase hex.
fn encode_bytes(bytes: &[u8], encoding: &HmacEncoding) -> String {
    match encoding {
        HmacEncoding::Base64 => base64::engine::general_purpose::STANDARD.encode(bytes),
        HmacEncoding::Hex => bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
    }
}

/// Render the configured signature destination template.
fn render_hmac_template(
    template: &str,
    signature: &str,
    key_id: Option<&str>,
) -> Result<String, String> {
    render_template(template, |token| match token {
        "signature" => Some(signature.to_string()),
        "key_id" => key_id.map(str::to_string),
        _ => None,
    })
}

/// Render the configured access-token destination template.
fn render_access_token_template(template: &str, token: &str) -> Result<String, String> {
    render_template(template, |placeholder| match placeholder {
        "token" => Some(token.to_string()),
        _ => None,
    })
}

/// Render a `headers` canonical component template using `{name}` and
/// `{value}` substitutions.
fn render_named_value_template(template: &str, name: &str, value: &str) -> Result<String, String> {
    render_template(template, |token| match token {
        "name" => Some(name.to_string()),
        "value" => Some(value.to_string()),
        _ => None,
    })
}

/// Render a simple `{token}` template and error on unmatched or unresolved
/// placeholders.
fn render_template(
    template: &str,
    resolve: impl Fn(&str) -> Option<String>,
) -> Result<String, String> {
    let mut rendered = String::with_capacity(template.len());
    let mut current: Option<String> = None;

    for ch in template.chars() {
        match (&mut current, ch) {
            (None, '{') => current = Some(String::new()),
            (None, '}') => return Err("template contains unmatched `}`".to_string()),
            (None, other) => rendered.push(other),
            (Some(_), '{') => return Err("template contains nested `{`".to_string()),
            (Some(token), '}') => {
                let replacement = resolve(token.as_str()).ok_or_else(|| {
                    format!("template contains unknown or unresolved token `{{{token}}}`")
                })?;
                rendered.push_str(&replacement);
                current = None;
            }
            (Some(token), other) => token.push(other),
        }
    }

    if current.is_some() {
        return Err("template contains unterminated `{...` token".to_string());
    }

    Ok(rendered)
}

fn current_gmt_date() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn current_iso8601_zulu() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn random_hex(byte_count: usize) -> String {
    let mut bytes = vec![0u8; byte_count];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn random_uuid_v4() -> String {
    Uuid::new_v4().to_string()
}

fn percent_encode_rfc3986(input: &str) -> String {
    utf8_percent_encode(input, RFC3986_ENCODE_SET).to_string()
}

fn host_header_value(url: &reqwest::Url) -> Result<String, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "HMAC upstream_host requires a host in the upstream URL".to_string())?;
    match url.port() {
        Some(port) => Ok(format!("{host}:{port}")),
        None => Ok(host.to_string()),
    }
}

// =============================================================================
// Generic access token cache
// =============================================================================

#[derive(PartialEq, Eq, Hash)]
struct AccessTokenKey {
    config: String,
}

static ACCESS_TOKEN_CACHE: std::sync::OnceLock<Arc<RwLock<HashMap<AccessTokenKey, CachedToken>>>> =
    std::sync::OnceLock::new();

fn access_token_cache() -> &'static Arc<RwLock<HashMap<AccessTokenKey, CachedToken>>> {
    ACCESS_TOKEN_CACHE.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

/// Fetch an access token using a nested HTTP request, reusing a cached token
/// until shortly before expiry.
async fn access_token(fetch: &AccessTokenFetchConfig) -> Result<String, String> {
    let key = AccessTokenKey {
        config: serde_json::to_string(fetch)
            .map_err(|e| format!("Access token cache key serialization failed: {e}"))?,
    };

    {
        let cache = access_token_cache().read().await;
        if let Some(cached) = cache.get(&key)
            && cached.expires_at > std::time::Instant::now() + std::time::Duration::from_secs(30)
        {
            return Ok(cached.access_token.clone());
        }
    }

    let fetched = fetch_access_token(fetch).await?;
    let ttl = fetched
        .expires_in_secs
        .saturating_sub(fetch.response.refresh_skew_seconds);
    let expires_at = std::time::Instant::now() + std::time::Duration::from_secs(ttl);

    {
        let mut cache = access_token_cache().write().await;
        cache.insert(
            key,
            CachedToken {
                access_token: fetched.access_token.clone(),
                expires_at,
            },
        );
    }

    Ok(fetched.access_token)
}

async fn fetch_access_token(fetch: &AccessTokenFetchConfig) -> Result<FetchedToken, String> {
    let mut prepared = PreparedUpstreamRequest::new(&fetch.url)?;
    let method = axum_method_from_spec(&fetch.method);

    for binding in &fetch.prepare {
        let value = resolve_hmac_prepare_value(&prepared.url, &[], &binding.value)?;
        apply_hmac_target(
            &mut prepared,
            &binding.target.kind,
            &binding.target.name,
            &value,
        );
    }

    if let Some(auth) = fetch.auth.as_deref() {
        apply_prepared_request_auth(&mut prepared, &method, &[], auth)?;
    }

    let client = reqwest::Client::new();
    let mut request = client.request(
        reqwest_method_from_spec(&fetch.method),
        prepared.url.clone(),
    );
    for (name, value) in &prepared.headers {
        request = request.header(name.as_str(), value);
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("Access token request failed: {e}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| format!("Access token response read failed: {e}"))?;
    if !status.is_success() {
        return Err(format!("Access token request failed with {status}: {text}"));
    }

    let body: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("Invalid access token response: {e}"))?;
    let access_token =
        json_pointer_string(&body, &fetch.response.token_json_pointer, "access token")?;
    let expires_in_secs = access_token_ttl_seconds(&body, &fetch.response)?;

    Ok(FetchedToken {
        access_token,
        expires_in_secs,
    })
}

fn access_token_ttl_seconds(
    body: &serde_json::Value,
    response: &AccessTokenResponseConfig,
) -> Result<u64, String> {
    if let Some(pointer) = &response.expires_in_json_pointer {
        return json_pointer_u64(body, pointer, "access token expiry")
            .map(|seconds| seconds.max(1));
    }

    let expires_at = json_pointer_u64(
        body,
        response
            .expires_at_json_pointer
            .as_ref()
            .ok_or_else(|| "Access token response missing expiry pointer".to_string())?,
        "access token expiry timestamp",
    )?;

    match response.expires_at_format {
        pay_types::metering::AccessTokenExpiryFormat::UnixSeconds => {
            let now = Utc::now().timestamp().max(0) as u64;
            Ok(expires_at.saturating_sub(now).max(1))
        }
    }
}

fn json_pointer_string(
    body: &serde_json::Value,
    pointer: &str,
    label: &str,
) -> Result<String, String> {
    body.pointer(pointer)
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("Missing or invalid {label} at JSON Pointer `{pointer}`"))
}

fn json_pointer_u64(body: &serde_json::Value, pointer: &str, label: &str) -> Result<u64, String> {
    body.pointer(pointer)
        .and_then(|value| value.as_u64())
        .ok_or_else(|| format!("Missing or invalid {label} at JSON Pointer `{pointer}`"))
}

fn reqwest_method_from_spec(method: &HttpMethod) -> reqwest::Method {
    match method {
        HttpMethod::Get => reqwest::Method::GET,
        HttpMethod::Post => reqwest::Method::POST,
        HttpMethod::Put => reqwest::Method::PUT,
        HttpMethod::Patch => reqwest::Method::PATCH,
        HttpMethod::Delete => reqwest::Method::DELETE,
    }
}

fn axum_method_from_spec(method: &HttpMethod) -> Method {
    match method {
        HttpMethod::Get => Method::GET,
        HttpMethod::Post => Method::POST,
        HttpMethod::Put => Method::PUT,
        HttpMethod::Patch => Method::PATCH,
        HttpMethod::Delete => Method::DELETE,
    }
}

// =============================================================================
// GCP OAuth2 token cache
// =============================================================================

/// Cached OAuth2 token with expiry.
struct CachedToken {
    access_token: String,
    expires_at: std::time::Instant,
}

/// A freshly-fetched token with the provider-reported lifetime.
struct FetchedToken {
    access_token: String,
    expires_in_secs: u64,
}

/// Cache key: one entry per distinct (token_url, scopes, audience, client_id)
/// tuple. The metadata server returns different tokens for different scope
/// sets (and different audiences in identity mode), and standard OAuth2
/// providers key tokens by client. Caching them all under a single slot would
/// cause one upstream's token to evict another's.
#[derive(PartialEq, Eq, Hash)]
struct TokenKey {
    token_url: String,
    scopes: Vec<String>,
    audience: Option<String>,
    client_id: Option<String>,
}

static OAUTH2_TOKEN_CACHE: std::sync::OnceLock<Arc<RwLock<HashMap<TokenKey, CachedToken>>>> =
    std::sync::OnceLock::new();

fn token_cache() -> &'static Arc<RwLock<HashMap<TokenKey, CachedToken>>> {
    OAUTH2_TOKEN_CACHE.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

/// Fetch an OAuth2 access token, using a cached value if still valid.
async fn oauth2_token(
    token_url: &str,
    scopes: &[String],
    audience: Option<&str>,
    client_id_env: Option<&str>,
    client_secret_env: Option<&str>,
) -> Result<String, String> {
    let key = TokenKey {
        token_url: token_url.to_string(),
        scopes: scopes.to_vec(),
        audience: audience.map(str::to_string),
        client_id: client_id_env.and_then(|e| std::env::var(e).ok()),
    };

    // Check cache — require at least 30s of remaining life to avoid races
    // with in-flight upstream requests.
    {
        let cache = token_cache().read().await;
        if let Some(cached) = cache.get(&key)
            && cached.expires_at > std::time::Instant::now() + std::time::Duration::from_secs(30)
        {
            return Ok(cached.access_token.clone());
        }
    }

    let fetched = fetch_oauth2_token(
        token_url,
        scopes,
        audience,
        client_id_env,
        client_secret_env,
    )
    .await?;

    // Refresh 60s before the provider-reported expiry. Providers (especially
    // the GCP metadata server) may return a token that's already partially
    // used, so NEVER assume a fixed ~1h lifetime — always honour `expires_in`.
    let refresh_margin = 60;
    let ttl = fetched.expires_in_secs.saturating_sub(refresh_margin);
    let expires_at = std::time::Instant::now() + std::time::Duration::from_secs(ttl);

    {
        let mut cache = token_cache().write().await;
        cache.insert(
            key,
            CachedToken {
                access_token: fetched.access_token.clone(),
                expires_at,
            },
        );
    }

    Ok(fetched.access_token)
}

async fn fetch_oauth2_token(
    token_url: &str,
    scopes: &[String],
    audience: Option<&str>,
    client_id_env: Option<&str>,
    client_secret_env: Option<&str>,
) -> Result<FetchedToken, String> {
    let client = reqwest::Client::new();

    // Special: GCP metadata server.
    if token_url == "gcp_metadata" {
        return fetch_gcp_metadata_token(&client, scopes).await;
    }
    if token_url == "gcp_metadata_identity" {
        let audience = audience.ok_or_else(|| {
            "oauth2.audience is required for token_url `gcp_metadata_identity`".to_string()
        })?;
        return fetch_gcp_metadata_identity_token(&client, audience).await;
    }

    // Standard OAuth2 client_credentials grant.
    let client_id = client_id_env
        .and_then(|e| std::env::var(e).ok())
        .ok_or("OAuth2 client_id env var not set")?;
    let client_secret = client_secret_env
        .and_then(|e| std::env::var(e).ok())
        .ok_or("OAuth2 client_secret env var not set")?;

    let mut params = vec![
        ("grant_type", "client_credentials".to_string()),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];
    if !scopes.is_empty() {
        params.push(("scope", scopes.join(" ")));
    }

    let resp = client
        .post(token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("OAuth2 token request failed: {e}"))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Invalid OAuth2 response: {e}"))?;

    let access_token = body["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("No access_token in response: {body}"))?;
    let expires_in_secs = body["expires_in"].as_u64().unwrap_or(3600);

    Ok(FetchedToken {
        access_token,
        expires_in_secs,
    })
}

/// Fetch token from GCP metadata server (Cloud Run / GCE).
/// Falls back to Application Default Credentials for local dev.
async fn fetch_gcp_metadata_token(
    client: &reqwest::Client,
    scopes: &[String],
) -> Result<FetchedToken, String> {
    let scopes_param = scopes.join(",");

    // 1. Metadata server.
    let url = format!(
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes={scopes_param}"
    );
    if let Ok(resp) = client
        .get(&url)
        .header("Metadata-Flavor", "Google")
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
        && resp.status().is_success()
        && let Ok(body) = resp.json::<serde_json::Value>().await
        && let Some(token) = body["access_token"].as_str()
    {
        tracing::debug!("OAuth2 token from GCP metadata server");
        // The metadata server returns its own cached token and only mints a
        // fresh one shortly before expiry, so `expires_in` is the remaining
        // lifetime of that shared token — not a fresh 1h window.
        let expires_in_secs = body["expires_in"].as_u64().unwrap_or(3600);
        return Ok(FetchedToken {
            access_token: token.to_string(),
            expires_in_secs,
        });
    }

    // 2. Application Default Credentials (local dev).
    let adc_path = std::env::var("GOOGLE_APPLICATION_CREDENTIALS").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.config/gcloud/application_default_credentials.json")
    });
    let adc_content = std::fs::read_to_string(&adc_path)
        .map_err(|e| format!("No metadata server and can't read ADC at {adc_path}: {e}"))?;
    let adc: serde_json::Value =
        serde_json::from_str(&adc_content).map_err(|e| format!("Invalid ADC: {e}"))?;

    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", adc["client_id"].as_str().unwrap_or_default()),
            (
                "client_secret",
                adc["client_secret"].as_str().unwrap_or_default(),
            ),
            (
                "refresh_token",
                adc["refresh_token"].as_str().unwrap_or_default(),
            ),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await
        .map_err(|e| format!("ADC token refresh failed: {e}"))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Invalid token response: {e}"))?;

    let access_token = body["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("No access_token: {body}"))?;
    let expires_in_secs = body["expires_in"].as_u64().unwrap_or(3600);

    tracing::debug!("OAuth2 token from ADC");
    Ok(FetchedToken {
        access_token,
        expires_in_secs,
    })
}

/// Fetch an audience-bound OIDC identity token from the GCP metadata server
/// (Cloud Run / GCE), used to invoke IAM-protected services such as private
/// Cloud Run. Unlike access tokens there is no ADC fallback: user credentials
/// cannot mint audience-bound identity tokens.
async fn fetch_gcp_metadata_identity_token(
    client: &reqwest::Client,
    audience: &str,
) -> Result<FetchedToken, String> {
    let resp = client
        .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity")
        .query(&[("audience", audience)])
        .header("Metadata-Flavor", "Google")
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
        .map_err(|e| {
            format!(
                "GCP metadata server unreachable ({e}): identity tokens require running on GCP (Cloud Run/GCE); there is no ADC fallback"
            )
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "GCP metadata identity endpoint returned {status}: {body}"
        ));
    }

    let token = resp
        .text()
        .await
        .map_err(|e| format!("Failed to read identity token: {e}"))?;
    let token = token.trim().to_string();

    // The /identity endpoint returns a raw JWT with no expiry envelope —
    // read the remaining lifetime from the token's own `exp` claim.
    let exp = jwt_exp_claim(&token)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("System clock before UNIX epoch: {e}"))?
        .as_secs();

    tracing::debug!("OIDC identity token from GCP metadata server");
    Ok(FetchedToken {
        access_token: token,
        expires_in_secs: exp.saturating_sub(now),
    })
}

/// Extract the `exp` claim (unix seconds) from a JWT without verifying the
/// signature — the token is opaque to us; only its remaining lifetime matters
/// for the cache.
fn jwt_exp_claim(jwt: &str) -> Result<u64, String> {
    let mut segments = jwt.split('.');
    let payload_b64 = match (segments.next(), segments.next(), segments.next()) {
        (Some(_), Some(payload), Some(_)) => payload,
        _ => return Err("identity token is not a JWT (expected 3 dot-separated segments)".into()),
    };
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("identity token payload is not base64url: {e}"))?;
    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|e| format!("identity token payload is not JSON: {e}"))?;
    claims["exp"]
        .as_u64()
        .ok_or_else(|| "identity token has no numeric `exp` claim".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pay_types::metering::{
        AccessTokenFetchConfig, AccessTokenInjectConfig, AccessTokenResponseConfig,
        HmacCanonicalComponent, HmacCanonicalConfig, HmacDigestAlgorithm, HmacEncoding,
        HmacPrepareBinding, HmacPrepareValue, HmacQueryStyle, HmacSignatureConfig,
        HmacSignatureDestination, HmacStringEncoding, HmacTarget, HmacTargetType,
        HmacTimestampFormat, HttpMethod, RoutingConfig,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    fn make_api(subdomain: &str) -> ApiSpec {
        ApiSpec {
            name: "test".to_string(),
            subdomain: subdomain.to_string(),
            title: "Test".to_string(),
            description: "".to_string(),
            category: pay_types::metering::ApiCategory::AiMl,
            version: "1.0".to_string(),
            env: std::collections::HashMap::new(),
            routing: RoutingConfig::Proxy {
                url: "https://api.example.com".to_string(),
                path_rewrites: vec![],
                auth: None,
            },
            accounting: pay_types::metering::AccountingMode::Pooled,
            endpoints: vec![],
            free_tier: None,
            quotas: None,
            notes: None,
            operator: None,
            session: None,
            batch_settlement: None,
            recipients: std::collections::HashMap::new(),
        }
    }

    fn api_with_auth(auth: Option<AuthConfig>) -> ApiSpec {
        let mut api = make_api("test");
        if let RoutingConfig::Proxy { auth: a, .. } = &mut api.routing {
            *a = auth.map(Box::new);
        }
        api
    }

    #[test]
    fn routing_signs_request_body_detects_body_digest() {
        // Alibaba-style HMAC includes a Content-MD5 `BodyDigest` prepare binding,
        // so it signs the request body → unsupported on the streaming data plane.
        let api = api_with_auth(Some(alibaba_hmac_auth_config(true)));
        assert!(routing_signs_request_body(&api, "v1/anything"));
    }

    #[test]
    fn routing_signs_request_body_false_when_body_untouched() {
        // No upstream auth at all.
        assert!(!routing_signs_request_body(
            &make_api("test"),
            "v1/anything"
        ));
        // Header auth never reads the body.
        let header = api_with_auth(Some(AuthConfig::Header {
            key: "Authorization".to_string(),
            prefix: Some("Bearer ".to_string()),
            value_from_env: "_TEST_KEY".to_string(),
        }));
        assert!(!routing_signs_request_body(&header, "v1/anything"));
    }

    fn alibaba_hmac_auth_config(fixed_values: bool) -> AuthConfig {
        let date_value = if fixed_values {
            HmacPrepareValue::Literal {
                value: "Wed, 26 Aug 2015 17:01:00 GMT".to_string(),
            }
        } else {
            HmacPrepareValue::Timestamp {
                format: HmacTimestampFormat::Rfc1123Gmt,
            }
        };
        let nonce_value = if fixed_values {
            HmacPrepareValue::Literal {
                value: "test-nonce".to_string(),
            }
        } else {
            HmacPrepareValue::RandomHex { bytes: 16 }
        };

        AuthConfig::Hmac {
            algorithm: HmacAlgorithm::Sha1,
            secret_from_env: "_TEST_ALIBABA_ACCESS_KEY_SECRET".to_string(),
            secret_suffix: None,
            key_id_from_env: Some("_TEST_ALIBABA_ACCESS_KEY_ID".to_string()),
            prepare: vec![
                HmacPrepareBinding {
                    target: HmacTarget {
                        kind: HmacTargetType::Header,
                        name: "Accept".to_string(),
                    },
                    value: HmacPrepareValue::Literal {
                        value: "application/json".to_string(),
                    },
                },
                HmacPrepareBinding {
                    target: HmacTarget {
                        kind: HmacTargetType::Header,
                        name: "Content-Type".to_string(),
                    },
                    value: HmacPrepareValue::Literal {
                        value: "application/json;charset=utf-8".to_string(),
                    },
                },
                HmacPrepareBinding {
                    target: HmacTarget {
                        kind: HmacTargetType::Header,
                        name: "Content-MD5".to_string(),
                    },
                    value: HmacPrepareValue::BodyDigest {
                        algorithm: HmacDigestAlgorithm::Md5,
                        encoding: HmacEncoding::Base64,
                    },
                },
                HmacPrepareBinding {
                    target: HmacTarget {
                        kind: HmacTargetType::Header,
                        name: "Date".to_string(),
                    },
                    value: date_value,
                },
                HmacPrepareBinding {
                    target: HmacTarget {
                        kind: HmacTargetType::Header,
                        name: "Host".to_string(),
                    },
                    value: HmacPrepareValue::UpstreamHost {},
                },
                HmacPrepareBinding {
                    target: HmacTarget {
                        kind: HmacTargetType::Header,
                        name: "x-acs-signature-nonce".to_string(),
                    },
                    value: nonce_value,
                },
                HmacPrepareBinding {
                    target: HmacTarget {
                        kind: HmacTargetType::Header,
                        name: "x-acs-signature-method".to_string(),
                    },
                    value: HmacPrepareValue::Literal {
                        value: "HMAC-SHA1".to_string(),
                    },
                },
                HmacPrepareBinding {
                    target: HmacTarget {
                        kind: HmacTargetType::Header,
                        name: "x-acs-version".to_string(),
                    },
                    value: HmacPrepareValue::Literal {
                        value: "2019-01-02".to_string(),
                    },
                },
            ],
            canonical: HmacCanonicalConfig {
                join_with: "\n".to_string(),
                components: vec![
                    HmacCanonicalComponent::Method {},
                    HmacCanonicalComponent::Header {
                        name: "Accept".to_string(),
                    },
                    HmacCanonicalComponent::Header {
                        name: "Content-MD5".to_string(),
                    },
                    HmacCanonicalComponent::Header {
                        name: "Content-Type".to_string(),
                    },
                    HmacCanonicalComponent::Header {
                        name: "Date".to_string(),
                    },
                    HmacCanonicalComponent::Headers {
                        names: vec![
                            "x-acs-signature-method".to_string(),
                            "x-acs-signature-nonce".to_string(),
                            "x-acs-version".to_string(),
                        ],
                        join_with: "\n".to_string(),
                        format: "{name}:{value}".to_string(),
                    },
                    HmacCanonicalComponent::Path {},
                ],
            },
            signature: HmacSignatureConfig {
                encoding: HmacEncoding::Base64,
                destination: HmacSignatureDestination {
                    kind: HmacTargetType::Header,
                    name: "Authorization".to_string(),
                    template: "acs {key_id}:{signature}".to_string(),
                },
            },
        }
    }

    fn isi_access_token_auth_config(token_url: &str) -> AuthConfig {
        AuthConfig::AccessToken {
            prepare: vec![HmacPrepareBinding {
                target: HmacTarget {
                    kind: HmacTargetType::QueryParam,
                    name: "appkey".to_string(),
                },
                value: HmacPrepareValue::Env {
                    from_env: "_TEST_ISI_APP_KEY".to_string(),
                },
            }],
            fetch: AccessTokenFetchConfig {
                url: token_url.to_string(),
                method: HttpMethod::Get,
                prepare: vec![
                    HmacPrepareBinding {
                        target: HmacTarget {
                            kind: HmacTargetType::QueryParam,
                            name: "AccessKeyId".to_string(),
                        },
                        value: HmacPrepareValue::Env {
                            from_env: "_TEST_ISI_ACCESS_KEY_ID".to_string(),
                        },
                    },
                    HmacPrepareBinding {
                        target: HmacTarget {
                            kind: HmacTargetType::QueryParam,
                            name: "Action".to_string(),
                        },
                        value: HmacPrepareValue::Literal {
                            value: "CreateToken".to_string(),
                        },
                    },
                    HmacPrepareBinding {
                        target: HmacTarget {
                            kind: HmacTargetType::QueryParam,
                            name: "Format".to_string(),
                        },
                        value: HmacPrepareValue::Literal {
                            value: "JSON".to_string(),
                        },
                    },
                    HmacPrepareBinding {
                        target: HmacTarget {
                            kind: HmacTargetType::QueryParam,
                            name: "RegionId".to_string(),
                        },
                        value: HmacPrepareValue::Literal {
                            value: "ap-southeast-1".to_string(),
                        },
                    },
                    HmacPrepareBinding {
                        target: HmacTarget {
                            kind: HmacTargetType::QueryParam,
                            name: "SignatureMethod".to_string(),
                        },
                        value: HmacPrepareValue::Literal {
                            value: "HMAC-SHA1".to_string(),
                        },
                    },
                    HmacPrepareBinding {
                        target: HmacTarget {
                            kind: HmacTargetType::QueryParam,
                            name: "SignatureNonce".to_string(),
                        },
                        value: HmacPrepareValue::Literal {
                            value: "4e1c1a27-4eaa-4df1-bf8f-78d4e5b79c3d".to_string(),
                        },
                    },
                    HmacPrepareBinding {
                        target: HmacTarget {
                            kind: HmacTargetType::QueryParam,
                            name: "SignatureVersion".to_string(),
                        },
                        value: HmacPrepareValue::Literal {
                            value: "1.0".to_string(),
                        },
                    },
                    HmacPrepareBinding {
                        target: HmacTarget {
                            kind: HmacTargetType::QueryParam,
                            name: "Timestamp".to_string(),
                        },
                        value: HmacPrepareValue::Literal {
                            value: "2019-04-18T08:32:31Z".to_string(),
                        },
                    },
                    HmacPrepareBinding {
                        target: HmacTarget {
                            kind: HmacTargetType::QueryParam,
                            name: "Version".to_string(),
                        },
                        value: HmacPrepareValue::Literal {
                            value: "2019-07-17".to_string(),
                        },
                    },
                ],
                auth: Some(Box::new(AuthConfig::Hmac {
                    algorithm: HmacAlgorithm::Sha1,
                    secret_from_env: "_TEST_ISI_ACCESS_KEY_SECRET".to_string(),
                    secret_suffix: Some("&".to_string()),
                    key_id_from_env: None,
                    prepare: vec![],
                    canonical: HmacCanonicalConfig {
                        join_with: "".to_string(),
                        components: vec![
                            HmacCanonicalComponent::Method {},
                            HmacCanonicalComponent::Literal {
                                value: "&%2F&".to_string(),
                            },
                            HmacCanonicalComponent::Query {
                                style: HmacQueryStyle::SortedPairs,
                                encoding: HmacStringEncoding::PercentRfc3986,
                            },
                        ],
                    },
                    signature: HmacSignatureConfig {
                        encoding: HmacEncoding::Base64,
                        destination: HmacSignatureDestination {
                            kind: HmacTargetType::QueryParam,
                            name: "Signature".to_string(),
                            template: "{signature}".to_string(),
                        },
                    },
                })),
                response: AccessTokenResponseConfig {
                    token_json_pointer: "/Token/Id".to_string(),
                    expires_at_json_pointer: Some("/Token/ExpireTime".to_string()),
                    expires_in_json_pointer: None,
                    expires_at_format: pay_types::metering::AccessTokenExpiryFormat::UnixSeconds,
                    refresh_skew_seconds: 60,
                },
            },
            inject: AccessTokenInjectConfig {
                target: HmacTarget {
                    kind: HmacTargetType::Header,
                    name: "X-NLS-Token".to_string(),
                },
                template: "{token}".to_string(),
            },
        }
    }

    #[test]
    fn resolve_api_finds_matching_subdomain() {
        let apis = vec![make_api("vision"), make_api("translate")];
        let result = resolve_api(&apis, "vision.agents.solana.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().subdomain, "vision");
    }

    #[test]
    fn resolve_api_no_match() {
        let apis = vec![make_api("vision")];
        let result = resolve_api(&apis, "translate.agents.solana.com");
        assert!(result.is_none());
    }

    #[test]
    fn resolve_api_empty_list() {
        let apis: Vec<ApiSpec> = vec![];
        assert!(resolve_api(&apis, "vision.agents.solana.com").is_none());
    }

    #[test]
    fn error_response_has_correct_status() {
        let resp = error_response(StatusCode::BAD_GATEWAY, "upstream error");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn error_response_has_json_content_type() {
        let resp = error_response(StatusCode::INTERNAL_SERVER_ERROR, "oops");
        let ct = resp.headers().get("content-type").unwrap();
        assert_eq!(ct, "application/json");
    }

    #[test]
    fn strip_headers_contains_expected() {
        assert!(STRIP_HEADERS.contains(&"host"));
        assert!(STRIP_HEADERS.contains(&"authorization"));
        assert!(STRIP_HEADERS.contains(&"connection"));
        // x402 credential headers must never be forwarded upstream.
        assert!(STRIP_HEADERS.contains(&"payment-signature"));
        assert!(STRIP_HEADERS.contains(&"x-payment"));
    }

    #[test]
    fn generic_hmac_reproduces_alibaba_signature() {
        let body = br#"{"FormatType":"text","SourceLanguage":"en","TargetLanguage":"zh","SourceText":"Hello"}"#;
        let mut prepared = PreparedUpstreamRequest::new(
            "https://mt.cn-hangzhou.aliyuncs.com/api/translate/web/general",
        )
        .unwrap();
        let auth = alibaba_hmac_auth_config(true);
        let AuthConfig::Hmac {
            algorithm,
            secret_from_env,
            secret_suffix,
            key_id_from_env,
            prepare,
            canonical,
            signature,
        } = &auth
        else {
            panic!("expected HMAC auth config");
        };

        unsafe { std::env::set_var("_TEST_ALIBABA_ACCESS_KEY_ID", "test-id") };
        unsafe { std::env::set_var("_TEST_ALIBABA_ACCESS_KEY_SECRET", "test-secret") };

        apply_hmac_auth(
            &mut prepared,
            &Method::POST,
            body,
            &HmacAuthConfigRef {
                algorithm,
                secret_from_env,
                secret_suffix: secret_suffix.as_deref(),
                key_id_from_env: key_id_from_env.as_deref(),
                prepare,
                canonical,
                signature,
            },
        )
        .unwrap();

        unsafe { std::env::remove_var("_TEST_ALIBABA_ACCESS_KEY_ID") };
        unsafe { std::env::remove_var("_TEST_ALIBABA_ACCESS_KEY_SECRET") };

        assert_eq!(
            prepared.header_value("Content-MD5"),
            Some("jCZbaw/l8wB5VbGcfBmH0w==")
        );
        assert_eq!(
            prepared.header_value("Host"),
            Some("mt.cn-hangzhou.aliyuncs.com")
        );
        assert_eq!(
            prepared.header_value("Authorization").unwrap(),
            "acs test-id:3GVRsoc2POHOKxGKNukivfy9cbE="
        );
    }

    #[test]
    fn canonical_query_component_supports_raw_and_sorted_pairs() {
        let raw = canonical_query_component(
            &reqwest::Url::parse("https://example.com/v1/test?b=2&a=1&a=0").unwrap(),
            &HmacQueryStyle::Raw,
            &HmacStringEncoding::None,
        )
        .unwrap();
        let sorted = canonical_query_component(
            &reqwest::Url::parse("https://example.com/v1/test?b=2&a=1&a=0").unwrap(),
            &HmacQueryStyle::SortedPairs,
            &HmacStringEncoding::None,
        )
        .unwrap();

        assert_eq!(raw, "b=2&a=1&a=0");
        assert_eq!(sorted, "a=0&a=1&b=2");
    }

    #[test]
    fn canonical_query_component_supports_percent_encoded_rendering() {
        let encoded = canonical_query_component(
            &reqwest::Url::parse("https://example.com/v1/test?text=hello%20world&lang=en").unwrap(),
            &HmacQueryStyle::SortedPairs,
            &HmacStringEncoding::PercentRfc3986,
        )
        .unwrap();

        assert_eq!(encoded, "lang%3Den%26text%3Dhello%2520world");
    }

    #[test]
    fn random_uuid_v4_generates_rfc4122_version_4_uuid() {
        let uuid = Uuid::parse_str(&random_uuid_v4()).expect("generated UUID should parse");
        assert_eq!(uuid.get_version(), Some(uuid::Version::Random));
        assert_eq!(uuid.get_variant(), uuid::Variant::RFC4122);
    }

    #[test]
    fn encode_bytes_supports_base64_and_hex() {
        assert_eq!(encode_bytes(b"abc", &HmacEncoding::Base64), "YWJj");
        assert_eq!(encode_bytes(b"abc", &HmacEncoding::Hex), "616263");
    }

    #[test]
    fn build_hmac_canonical_string_rejects_missing_header_component() {
        let prepared = PreparedUpstreamRequest::new("https://example.com/v1/check").unwrap();
        let canonical = HmacCanonicalConfig {
            join_with: "\n".to_string(),
            components: vec![HmacCanonicalComponent::Header {
                name: "Date".to_string(),
            }],
        };

        let err = build_hmac_canonical_string(&prepared, &Method::GET, &canonical).unwrap_err();
        assert!(err.contains("header `Date` is missing"));
    }

    /// Spin up a one-shot axum server, return its base URL.
    async fn spawn_upstream(handler: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let handle = tokio::spawn(async move {
            axum::serve(listener, handler).await.ok();
        });
        // Give the server a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        (url, handle)
    }

    #[tokio::test]
    async fn forward_request_get() {
        let app = axum::Router::new().route(
            "/v1/test",
            axum::routing::get(|| async { "hello from upstream" }),
        );
        let (base_url, _handle) = spawn_upstream(app).await;

        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: base_url.clone(),
                path_rewrites: vec![],
                auth: None,
            },
            ..make_api("test")
        };

        let uri: Uri = format!("{base_url}/v1/test").parse().unwrap();
        let result =
            forward_request(&api, Method::GET, &uri, &HeaderMap::new(), Bytes::new()).await;

        let resp = result.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"hello from upstream");
    }

    #[tokio::test]
    async fn forward_request_injects_cached_access_token_auth() {
        let token_calls = Arc::new(AtomicUsize::new(0));
        let token_query = Arc::new(Mutex::new(String::new()));
        let token_calls_capture = Arc::clone(&token_calls);
        let token_query_capture = Arc::clone(&token_query);
        let token_app = axum::Router::new().route(
            "/",
            axum::routing::get(move |uri: axum::http::Uri| {
                let token_calls_capture = Arc::clone(&token_calls_capture);
                let token_query_capture = Arc::clone(&token_query_capture);
                async move {
                    token_calls_capture.fetch_add(1, Ordering::SeqCst);
                    *token_query_capture.lock().unwrap() =
                        uri.query().unwrap_or_default().to_string();
                    axum::Json(serde_json::json!({
                        "Token": {
                            "Id": "isi-token-123",
                            "ExpireTime": 4_102_444_800u64
                        }
                    }))
                }
            }),
        );
        let (token_base_url, _token_handle) = spawn_upstream(token_app).await;

        #[derive(Debug, Default)]
        struct CapturedIsiRequest {
            token: Option<String>,
            query: String,
        }

        let captured_request = Arc::new(Mutex::new(CapturedIsiRequest::default()));
        let captured_request_clone = Arc::clone(&captured_request);
        let upstream_app = axum::Router::new().route(
            "/stream/v1/tts",
            axum::routing::get(
                move |uri: axum::http::Uri, headers: axum::http::HeaderMap| {
                    let captured_request_clone = Arc::clone(&captured_request_clone);
                    async move {
                        let mut guard = captured_request_clone.lock().unwrap();
                        guard.token = headers
                            .get("x-nls-token")
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_string);
                        guard.query = uri.query().unwrap_or_default().to_string();
                        "ok"
                    }
                },
            ),
        );
        let (upstream_base_url, _upstream_handle) = spawn_upstream(upstream_app).await;

        unsafe { std::env::set_var("_TEST_ISI_APP_KEY", "app-key-123") };
        unsafe { std::env::set_var("_TEST_ISI_ACCESS_KEY_ID", "test-id") };
        unsafe { std::env::set_var("_TEST_ISI_ACCESS_KEY_SECRET", "test-secret") };

        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: upstream_base_url.clone(),
                path_rewrites: vec![],
                auth: Some(Box::new(isi_access_token_auth_config(&token_base_url))),
            },
            ..make_api("test")
        };

        let first_uri: Uri = format!("{upstream_base_url}/stream/v1/tts?text=hello")
            .parse()
            .unwrap();
        let second_uri: Uri = format!("{upstream_base_url}/stream/v1/tts?text=hello-again")
            .parse()
            .unwrap();

        let first = forward_request(
            &api,
            Method::GET,
            &first_uri,
            &HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .unwrap();
        let second = forward_request(
            &api,
            Method::GET,
            &second_uri,
            &HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .unwrap();

        unsafe { std::env::remove_var("_TEST_ISI_APP_KEY") };
        unsafe { std::env::remove_var("_TEST_ISI_ACCESS_KEY_ID") };
        unsafe { std::env::remove_var("_TEST_ISI_ACCESS_KEY_SECRET") };

        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(token_calls.load(Ordering::SeqCst), 1);

        let token_query = token_query.lock().unwrap().clone();
        assert!(token_query.contains("Action=CreateToken"));
        assert!(token_query.contains("AccessKeyId=test-id"));
        assert!(token_query.contains("SignatureMethod=HMAC-SHA1"));
        assert!(token_query.contains("Signature="));

        let captured = captured_request.lock().unwrap();
        assert_eq!(captured.token.as_deref(), Some("isi-token-123"));
        assert!(captured.query.contains("text=hello-again"));
        assert!(captured.query.contains("appkey=app-key-123"));
    }

    #[tokio::test]
    async fn forward_request_post_with_body() {
        let app = axum::Router::new().route(
            "/v1/echo",
            axum::routing::post(|body: String| async move { format!("echo: {body}") }),
        );
        let (base_url, _handle) = spawn_upstream(app).await;

        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: base_url.clone(),
                path_rewrites: vec![],
                auth: None,
            },
            ..make_api("test")
        };

        let uri: Uri = format!("{base_url}/v1/echo").parse().unwrap();
        let body = Bytes::from("test payload");
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/plain".parse().unwrap());

        let result = forward_request(&api, Method::POST, &uri, &headers, body).await;

        let resp = result.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"echo: test payload");
    }

    #[tokio::test]
    async fn forward_request_strips_auth_header() {
        use std::sync::{Arc, Mutex};

        let received_headers: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured = received_headers.clone();

        let app = axum::Router::new().route(
            "/v1/check",
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let keys: Vec<String> = headers.keys().map(|k| k.to_string()).collect();
                captured.lock().unwrap().extend(keys);
                async { "ok" }
            }),
        );
        let (base_url, _handle) = spawn_upstream(app).await;

        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: base_url.clone(),
                path_rewrites: vec![],
                auth: None,
            },
            ..make_api("test")
        };

        let uri: Uri = format!("{base_url}/v1/check").parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer secret".parse().unwrap());
        headers.insert("x-custom", "kept".parse().unwrap());

        let result = forward_request(&api, Method::GET, &uri, &headers, Bytes::new()).await;
        assert!(result.is_ok());

        let fwd = received_headers.lock().unwrap();
        assert!(!fwd.contains(&"authorization".to_string()));
        assert!(fwd.contains(&"x-custom".to_string()));
    }

    #[tokio::test]
    async fn forward_request_preserves_status_code() {
        let app = axum::Router::new().route(
            "/v1/notfound",
            axum::routing::get(|| async { (StatusCode::NOT_FOUND, "nope") }),
        );
        let (base_url, _handle) = spawn_upstream(app).await;

        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: base_url.clone(),
                path_rewrites: vec![],
                auth: None,
            },
            ..make_api("test")
        };

        let uri: Uri = format!("{base_url}/v1/notfound").parse().unwrap();
        let result =
            forward_request(&api, Method::GET, &uri, &HeaderMap::new(), Bytes::new()).await;

        assert_eq!(result.unwrap().status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn forward_request_upstream_down() {
        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: "http://127.0.0.1:1".to_string(),
                path_rewrites: vec![],
                auth: None,
            }, // nothing listening
            ..make_api("test")
        };

        let uri: Uri = "http://127.0.0.1:1/v1/test".parse().unwrap();
        let result =
            forward_request(&api, Method::GET, &uri, &HeaderMap::new(), Bytes::new()).await;

        // Should return an error response (502 Bad Gateway)
        let err_resp = result.unwrap_err();
        assert_eq!(err_resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn forward_request_preserves_query_string() {
        let app = axum::Router::new().route(
            "/v1/search",
            axum::routing::get(|uri: axum::http::Uri| async move {
                uri.query().unwrap_or("none").to_string()
            }),
        );
        let (base_url, _handle) = spawn_upstream(app).await;

        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: base_url.clone(),
                path_rewrites: vec![],
                auth: None,
            },
            ..make_api("test")
        };

        let uri: Uri = format!("{base_url}/v1/search?q=hello&limit=10")
            .parse()
            .unwrap();
        let result =
            forward_request(&api, Method::GET, &uri, &HeaderMap::new(), Bytes::new()).await;

        let resp = result.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let qs = String::from_utf8(body.to_vec()).unwrap();
        assert!(qs.contains("q=hello"));
        assert!(qs.contains("limit=10"));
    }

    #[tokio::test]
    async fn forward_request_with_path_rewrite() {
        use pay_types::metering::PathRewrite;

        // Upstream expects the operator's project ID in the path.
        let app = axum::Router::new().route(
            "/v3/projects/operator-proj/translate",
            axum::routing::post(|| async { "translated" }),
        );
        let (base_url, _handle) = spawn_upstream(app).await;

        // SAFETY: test-only, single-threaded
        unsafe { std::env::set_var("_TEST_FWD_PROJECT", "operator-proj") };
        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: base_url.clone(),
                path_rewrites: vec![PathRewrite {
                    prefix: "v3/projects/{projectId}".to_string(),
                    env: "_TEST_FWD_PROJECT".to_string(),
                }],
                auth: None,
            },
            ..make_api("test")
        };

        // Client sends their own project ID — rewrite substitutes it.
        let uri: Uri = format!("{base_url}/v3/projects/client-proj/translate")
            .parse()
            .unwrap();
        let result =
            forward_request(&api, Method::POST, &uri, &HeaderMap::new(), Bytes::new()).await;

        let resp = result.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"translated");

        unsafe { std::env::remove_var("_TEST_FWD_PROJECT") };
    }

    #[tokio::test]
    async fn forward_request_injects_header_auth() {
        let auth_header: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&auth_header);
        let app = axum::Router::new().route(
            "/v1/check",
            axum::routing::get(move |headers: axum::http::HeaderMap| {
                let captured = Arc::clone(&captured);
                async move {
                    *captured.lock().unwrap() = headers
                        .get("x-api-key")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    "ok"
                }
            }),
        );
        let (base_url, _handle) = spawn_upstream(app).await;

        // SAFETY: test-only env mutation scoped to this test.
        unsafe { std::env::set_var("_TEST_PROXY_AUTH", "secret-123") };
        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: base_url,
                path_rewrites: vec![],
                auth: Some(Box::new(AuthConfig::Header {
                    key: "x-api-key".to_string(),
                    prefix: Some("Bearer ".to_string()),
                    value_from_env: "_TEST_PROXY_AUTH".to_string(),
                })),
            },
            ..make_api("test")
        };

        let uri: Uri = "/v1/check".parse().unwrap();
        let result =
            forward_request(&api, Method::GET, &uri, &HeaderMap::new(), Bytes::new()).await;

        unsafe { std::env::remove_var("_TEST_PROXY_AUTH") };

        assert_eq!(result.unwrap().status(), StatusCode::OK);
        assert_eq!(
            auth_header.lock().unwrap().as_deref(),
            Some("Bearer secret-123")
        );
    }

    #[tokio::test]
    async fn forward_request_injects_hmac_auth() {
        #[derive(Debug, Clone, Default)]
        struct CapturedRequest {
            authorization: Option<String>,
            content_md5: Option<String>,
            date: Option<String>,
            host: Option<String>,
            signature_nonce: Option<String>,
            signature_method: Option<String>,
            version: Option<String>,
        }

        let captured_headers: Arc<Mutex<CapturedRequest>> =
            Arc::new(Mutex::new(CapturedRequest::default()));
        let captured = Arc::clone(&captured_headers);
        let app = axum::Router::new().route(
            "/v1/secure",
            axum::routing::post(move |headers: axum::http::HeaderMap| {
                let captured = Arc::clone(&captured);
                async move {
                    let mut guard = captured.lock().unwrap();
                    guard.authorization = headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    guard.content_md5 = headers
                        .get("content-md5")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    guard.date = headers
                        .get("date")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    guard.host = headers
                        .get("host")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    guard.signature_nonce = headers
                        .get("x-acs-signature-nonce")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    guard.signature_method = headers
                        .get("x-acs-signature-method")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    guard.version = headers
                        .get("x-acs-version")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    "ok"
                }
            }),
        );
        let (base_url, _handle) = spawn_upstream(app).await;

        unsafe { std::env::set_var("_TEST_ALIBABA_ACCESS_KEY_ID", "test-id") };
        unsafe { std::env::set_var("_TEST_ALIBABA_ACCESS_KEY_SECRET", "test-secret") };

        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: base_url.clone(),
                path_rewrites: vec![],
                auth: Some(Box::new(alibaba_hmac_auth_config(false))),
            },
            ..make_api("test")
        };

        let uri: Uri = "/v1/secure".parse().unwrap();
        let body =
            Bytes::from_static(br#"{"FormatType":"text","SourceLanguage":"en","TargetLanguage":"zh","SourceText":"Hello"}"#);
        let result =
            forward_request(&api, Method::POST, &uri, &HeaderMap::new(), body.clone()).await;

        let resp = result.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let captured = captured_headers.lock().unwrap().clone();
        let mut expected = PreparedUpstreamRequest::new(&format!("{base_url}/v1/secure")).unwrap();
        let auth = alibaba_hmac_auth_config(true);
        let AuthConfig::Hmac {
            algorithm,
            secret_from_env,
            secret_suffix,
            key_id_from_env,
            prepare,
            canonical,
            signature,
        } = &auth
        else {
            panic!("expected HMAC auth config");
        };
        expected.set_header("Date", captured.date.as_deref().unwrap());
        expected.set_header(
            "x-acs-signature-nonce",
            captured.signature_nonce.as_deref().unwrap(),
        );
        let replay_auth = AuthConfig::Hmac {
            algorithm: algorithm.clone(),
            secret_from_env: secret_from_env.clone(),
            secret_suffix: secret_suffix.clone(),
            key_id_from_env: key_id_from_env.clone(),
            prepare: prepare
                .iter()
                .map(|binding| match binding.target.name.as_str() {
                    "Date" => HmacPrepareBinding {
                        target: binding.target.clone(),
                        value: HmacPrepareValue::Literal {
                            value: captured.date.clone().unwrap(),
                        },
                    },
                    "x-acs-signature-nonce" => HmacPrepareBinding {
                        target: binding.target.clone(),
                        value: HmacPrepareValue::Literal {
                            value: captured.signature_nonce.clone().unwrap(),
                        },
                    },
                    _ => binding.clone(),
                })
                .collect(),
            canonical: canonical.clone(),
            signature: signature.clone(),
        };
        let AuthConfig::Hmac {
            algorithm,
            secret_from_env,
            secret_suffix,
            key_id_from_env,
            prepare,
            canonical,
            signature,
        } = &replay_auth
        else {
            unreachable!();
        };
        apply_hmac_auth(
            &mut expected,
            &Method::POST,
            body.as_ref(),
            &HmacAuthConfigRef {
                algorithm,
                secret_from_env,
                secret_suffix: secret_suffix.as_deref(),
                key_id_from_env: key_id_from_env.as_deref(),
                prepare,
                canonical,
                signature,
            },
        )
        .unwrap();

        unsafe { std::env::remove_var("_TEST_ALIBABA_ACCESS_KEY_ID") };
        unsafe { std::env::remove_var("_TEST_ALIBABA_ACCESS_KEY_SECRET") };

        assert_eq!(
            captured.authorization.as_deref(),
            expected.header_value("Authorization")
        );
        assert_eq!(
            captured.content_md5.as_deref(),
            expected.header_value("Content-MD5")
        );
        assert_eq!(captured.host.as_deref(), expected.header_value("Host"));
        assert_eq!(captured.signature_method.as_deref(), Some("HMAC-SHA1"));
        assert_eq!(captured.version.as_deref(), Some("2019-01-02"));
        assert!(captured.date.is_some());
        assert!(captured.signature_nonce.is_some());
    }

    #[tokio::test]
    async fn forward_request_injects_hmac_signature_into_query_param() {
        let app = axum::Router::new().route(
            "/v1/check",
            axum::routing::get(|uri: axum::http::Uri| async move {
                uri.query().unwrap_or_default().to_string()
            }),
        );
        let (base_url, _handle) = spawn_upstream(app).await;

        unsafe { std::env::set_var("_TEST_HMAC_QUERY_SECRET", "query-secret") };
        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: base_url.clone(),
                path_rewrites: vec![],
                auth: Some(Box::new(AuthConfig::Hmac {
                    algorithm: HmacAlgorithm::Sha256,
                    secret_from_env: "_TEST_HMAC_QUERY_SECRET".to_string(),
                    secret_suffix: None,
                    key_id_from_env: None,
                    prepare: vec![],
                    canonical: HmacCanonicalConfig {
                        join_with: "\n".to_string(),
                        components: vec![
                            HmacCanonicalComponent::Method {},
                            HmacCanonicalComponent::Path {},
                        ],
                    },
                    signature: HmacSignatureConfig {
                        encoding: HmacEncoding::Hex,
                        destination: HmacSignatureDestination {
                            kind: HmacTargetType::QueryParam,
                            name: "sig".to_string(),
                            template: "{signature}".to_string(),
                        },
                    },
                })),
            },
            ..make_api("test")
        };

        let uri: Uri = format!("{base_url}/v1/check?existing=1").parse().unwrap();
        let result =
            forward_request(&api, Method::GET, &uri, &HeaderMap::new(), Bytes::new()).await;

        unsafe { std::env::remove_var("_TEST_HMAC_QUERY_SECRET") };

        let resp = result.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let query = String::from_utf8(body.to_vec()).unwrap();
        assert!(query.contains("existing=1"));
        assert!(query.contains("sig="));
    }

    #[tokio::test]
    async fn forward_request_hmac_missing_canonical_header_returns_bad_gateway() {
        let app = axum::Router::new().route("/v1/check", axum::routing::get(|| async { "ok" }));
        let (base_url, _handle) = spawn_upstream(app).await;

        unsafe { std::env::set_var("_TEST_HMAC_MISSING_SECRET", "secret") };
        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: base_url.clone(),
                path_rewrites: vec![],
                auth: Some(Box::new(AuthConfig::Hmac {
                    algorithm: HmacAlgorithm::Sha256,
                    secret_from_env: "_TEST_HMAC_MISSING_SECRET".to_string(),
                    secret_suffix: None,
                    key_id_from_env: None,
                    prepare: vec![],
                    canonical: HmacCanonicalConfig {
                        join_with: "\n".to_string(),
                        components: vec![HmacCanonicalComponent::Header {
                            name: "Date".to_string(),
                        }],
                    },
                    signature: HmacSignatureConfig {
                        encoding: HmacEncoding::Hex,
                        destination: HmacSignatureDestination {
                            kind: HmacTargetType::Header,
                            name: "Authorization".to_string(),
                            template: "{signature}".to_string(),
                        },
                    },
                })),
            },
            ..make_api("test")
        };

        let uri: Uri = format!("{base_url}/v1/check").parse().unwrap();
        let result =
            forward_request(&api, Method::GET, &uri, &HeaderMap::new(), Bytes::new()).await;

        unsafe { std::env::remove_var("_TEST_HMAC_MISSING_SECRET") };

        let error = result.unwrap_err();
        assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(error.into_body(), 2048).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["message"]
                .as_str()
                .unwrap_or_default()
                .contains("header `Date` is missing")
        );
    }

    #[tokio::test]
    async fn forward_request_injects_query_param_auth() {
        let app = axum::Router::new().route(
            "/v1/check",
            axum::routing::get(|uri: axum::http::Uri| async move {
                uri.query().unwrap_or_default().to_string()
            }),
        );
        let (base_url, _handle) = spawn_upstream(app).await;

        // SAFETY: test-only env mutation scoped to this test.
        unsafe { std::env::set_var("_TEST_PROXY_QUERY_AUTH", "qp-secret") };
        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: base_url,
                path_rewrites: vec![],
                auth: Some(Box::new(AuthConfig::QueryParam {
                    key: "api_key".to_string(),
                    value_from_env: "_TEST_PROXY_QUERY_AUTH".to_string(),
                })),
            },
            ..make_api("test")
        };

        let uri: Uri = "/v1/check?existing=1".parse().unwrap();
        let result =
            forward_request(&api, Method::GET, &uri, &HeaderMap::new(), Bytes::new()).await;

        unsafe { std::env::remove_var("_TEST_PROXY_QUERY_AUTH") };

        let resp = result.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let query = String::from_utf8(body.to_vec()).unwrap();
        assert!(query.contains("existing=1"));
        assert!(query.contains("api_key=qp-secret"));
    }

    #[tokio::test]
    async fn forward_request_sets_content_length_for_empty_post() {
        let app = axum::Router::new().route(
            "/v1/empty",
            axum::routing::post(|headers: axum::http::HeaderMap| async move {
                headers
                    .get("content-length")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string()
            }),
        );
        let (base_url, _handle) = spawn_upstream(app).await;

        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: base_url,
                path_rewrites: vec![],
                auth: None,
            },
            ..make_api("test")
        };

        let uri: Uri = "/v1/empty".parse().unwrap();
        let result =
            forward_request(&api, Method::POST, &uri, &HeaderMap::new(), Bytes::new()).await;

        let resp = result.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"0");
    }

    #[tokio::test]
    async fn forward_request_oauth2_missing_env_returns_bad_gateway() {
        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: "https://api.example.com".to_string(),
                path_rewrites: vec![],
                auth: Some(Box::new(AuthConfig::Oauth2 {
                    token_url: "https://oauth.example.com/token".to_string(),
                    scopes: vec!["scope-a".to_string()],
                    audience: None,
                    client_id_from_env: Some("_TEST_MISSING_CLIENT_ID".to_string()),
                    client_secret_from_env: Some("_TEST_MISSING_CLIENT_SECRET".to_string()),
                    headers: HashMap::new(),
                })),
            },
            ..make_api("test")
        };

        let uri: Uri = "/v1/protected".parse().unwrap();
        let result =
            forward_request(&api, Method::GET, &uri, &HeaderMap::new(), Bytes::new()).await;

        let err = result.unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(err.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["message"]
                .as_str()
                .unwrap()
                .contains("client_id env var not set")
        );
    }

    #[tokio::test]
    async fn forward_request_oauth2_identity_without_audience_returns_bad_gateway() {
        let api = ApiSpec {
            routing: RoutingConfig::Proxy {
                url: "https://api.example.com".to_string(),
                path_rewrites: vec![],
                auth: Some(Box::new(AuthConfig::Oauth2 {
                    token_url: "gcp_metadata_identity".to_string(),
                    scopes: vec![],
                    audience: None,
                    client_id_from_env: None,
                    client_secret_from_env: None,
                    headers: HashMap::new(),
                })),
            },
            ..make_api("test")
        };

        let uri: Uri = "/v1/protected".parse().unwrap();
        let result =
            forward_request(&api, Method::GET, &uri, &HeaderMap::new(), Bytes::new()).await;

        let err = result.unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(err.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["message"]
                .as_str()
                .unwrap()
                .contains("oauth2.audience is required")
        );
    }

    // ── jwt_exp_claim ────────────────────────────────────────────────────

    fn make_jwt(payload: &serde_json::Value) -> String {
        let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let header = encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let body = encode(payload.to_string().as_bytes());
        format!("{header}.{body}.signature")
    }

    #[test]
    fn jwt_exp_claim_reads_exp() {
        let jwt = make_jwt(&serde_json::json!({
            "aud": "https://svc-xyz.a.run.app",
            "exp": 1_754_100_000u64,
            "iat": 1_754_096_400u64,
        }));
        assert_eq!(jwt_exp_claim(&jwt).unwrap(), 1_754_100_000);
    }

    #[test]
    fn jwt_exp_claim_rejects_non_jwt() {
        let err = jwt_exp_claim("not-a-jwt").unwrap_err();
        assert!(err.contains("3 dot-separated segments"), "got: {err}");
    }

    #[test]
    fn jwt_exp_claim_rejects_missing_exp() {
        let jwt = make_jwt(&serde_json::json!({"aud": "https://svc.example"}));
        let err = jwt_exp_claim(&jwt).unwrap_err();
        assert!(err.contains("no numeric `exp` claim"), "got: {err}");
    }

    // ── resolve_routing ──────────────────────────────────────────────────

    #[test]
    fn resolve_routing_uses_api_default() {
        let api = make_api("test");
        let r = resolve_routing(&api, "/v1/test");
        assert!(r.is_proxy());
    }

    #[test]
    fn resolve_routing_endpoint_override() {
        let mut api = make_api("test");
        api.endpoints.push(pay_types::metering::Endpoint {
            method: pay_types::metering::HttpMethod::Post,
            path: "v1/pay".to_string(),
            description: None,
            resource: None,
            routing: Some(RoutingConfig::Respond {}),
            metering: None,
            subscription: None,
        });
        // Endpoint with override → Respond
        let r = resolve_routing(&api, "/v1/pay");
        assert!(r.is_respond());
        // Other path → falls back to API default (Proxy)
        let r2 = resolve_routing(&api, "/v1/other");
        assert!(r2.is_proxy());
    }

    #[test]
    fn resolve_routing_endpoint_no_override_uses_default() {
        let mut api = make_api("test");
        api.endpoints.push(pay_types::metering::Endpoint {
            method: pay_types::metering::HttpMethod::Get,
            path: "v1/health".to_string(),
            description: None,
            resource: None,
            routing: None, // no override
            metering: None,
            subscription: None,
        });
        let r = resolve_routing(&api, "/v1/health");
        assert!(r.is_proxy());
    }

    #[test]
    fn resolve_routing_keeps_endpoint_override_for_browser_get_on_post_path() {
        let mut api = make_api("test");
        api.endpoints.push(pay_types::metering::Endpoint {
            method: pay_types::metering::HttpMethod::Post,
            path: "v1/shared".to_string(),
            description: None,
            resource: None,
            routing: Some(RoutingConfig::Respond {}),
            metering: None,
            subscription: None,
        });
        api.endpoints.push(pay_types::metering::Endpoint {
            method: pay_types::metering::HttpMethod::Get,
            path: "v1/shared".to_string(),
            description: None,
            resource: None,
            routing: None,
            metering: None,
            subscription: None,
        });

        assert!(resolve_routing(&api, "/v1/shared").is_respond());
    }

    // ── forward_request with Respond routing ─────────────────────────────

    #[tokio::test]
    async fn forward_request_respond_mode_known_endpoint() {
        let mut api = make_api("test");
        api.routing = RoutingConfig::Respond {};
        api.endpoints.push(pay_types::metering::Endpoint {
            method: pay_types::metering::HttpMethod::Get,
            path: "v1/test".to_string(),
            description: None,
            resource: None,
            routing: None,
            metering: None,
            subscription: None,
        });

        let uri: Uri = "/v1/test".parse().unwrap();
        let result =
            forward_request(&api, Method::GET, &uri, &HeaderMap::new(), Bytes::new()).await;

        let resp = result.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn forward_request_respond_mode_unknown_path() {
        let mut api = make_api("test");
        api.routing = RoutingConfig::Respond {};

        let uri: Uri = "/v1/unknown".parse().unwrap();
        let result =
            forward_request(&api, Method::GET, &uri, &HeaderMap::new(), Bytes::new()).await;

        let resp = result.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn forward_request_respond_endpoint_override() {
        let app = axum::Router::new().route(
            "/v1/proxy-me",
            axum::routing::get(|| async { "from upstream" }),
        );
        let (base_url, _handle) = spawn_upstream(app).await;

        let mut api = make_api("test");
        api.routing = RoutingConfig::Proxy {
            url: base_url,
            path_rewrites: vec![],
            auth: None,
        };
        // Add an endpoint that overrides to Respond
        api.endpoints.push(pay_types::metering::Endpoint {
            method: pay_types::metering::HttpMethod::Post,
            path: "v1/respond-only".to_string(),
            description: None,
            resource: None,
            routing: Some(RoutingConfig::Respond {}),
            metering: None,
            subscription: None,
        });

        // Respond endpoint returns 200 directly
        let uri: Uri = "/v1/respond-only".parse().unwrap();
        let result =
            forward_request(&api, Method::POST, &uri, &HeaderMap::new(), Bytes::new()).await;
        let resp = result.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");

        // Proxy endpoint still forwards upstream
        let uri2: Uri = "/v1/proxy-me".parse().unwrap();
        let result2 =
            forward_request(&api, Method::GET, &uri2, &HeaderMap::new(), Bytes::new()).await;
        let resp2 = result2.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let body2 = axum::body::to_bytes(resp2.into_body(), 1024).await.unwrap();
        assert_eq!(&body2[..], b"from upstream");
    }
}
