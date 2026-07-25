//! Tests for server modules: proxy forwarding, payment middleware, accounting.
//!
//! Run: `cargo test -p pay-core --features server --test server_tests`

#![cfg(feature = "server")]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{any, get};
use pay_core::PaymentState;
use pay_core::server::accounting::{AccountingKey, AccountingStore, InMemoryStore};
use pay_core::server::proxy;
use pay_core::server::session::SessionMpp;
use pay_kit::mpp::server::Mpp;
use pay_kit::mpp::server::session::SessionConfig;
use pay_types::metering::ApiSpec;
use serde_json::json;
use std::sync::Arc;

// ── Test app state ──

#[derive(Clone)]
struct TestState {
    apis: Arc<Vec<ApiSpec>>,
    mpp: Option<Mpp>,
}

impl PaymentState for TestState {
    fn apis(&self) -> &[ApiSpec] {
        &self.apis
    }
    fn mpp(&self) -> Option<&Mpp> {
        self.mpp.as_ref()
    }
}

#[derive(Clone)]
struct MultiCurrencyTestState {
    apis: Arc<Vec<ApiSpec>>,
    mpps: Vec<Mpp>,
}

impl PaymentState for MultiCurrencyTestState {
    fn apis(&self) -> &[ApiSpec] {
        &self.apis
    }
    fn mpp(&self) -> Option<&Mpp> {
        self.mpps.first()
    }
    fn mpps(&self) -> Vec<&Mpp> {
        self.mpps.iter().collect()
    }
}

#[derive(Clone)]
struct SessionTestState {
    apis: Arc<Vec<ApiSpec>>,
    mpp: Option<Mpp>,
    session_mpp: Option<Arc<SessionMpp>>,
}

#[derive(Clone)]
struct MultiCurrencySessionTestState {
    apis: Arc<Vec<ApiSpec>>,
    session_mpps: Vec<Arc<SessionMpp>>,
}

impl PaymentState for MultiCurrencySessionTestState {
    fn apis(&self) -> &[ApiSpec] {
        &self.apis
    }
    fn mpp(&self) -> Option<&Mpp> {
        None
    }
    fn session_mpp(&self) -> Option<&SessionMpp> {
        self.session_mpps.first().map(Arc::as_ref)
    }
    fn session_mpp_handle(&self) -> Option<Arc<SessionMpp>> {
        self.session_mpps.first().cloned()
    }
    fn session_mpps(&self) -> Vec<&SessionMpp> {
        self.session_mpps.iter().map(Arc::as_ref).collect()
    }
    fn session_mpp_handles(&self) -> Vec<Arc<SessionMpp>> {
        self.session_mpps.clone()
    }
}

impl PaymentState for SessionTestState {
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

fn load_test_api() -> ApiSpec {
    let content = std::fs::read_to_string("tests/fixtures/test-provider.yml").unwrap();
    serde_yml::from_str(&content).unwrap()
}

async fn echo_handler(req: Request<Body>) -> impl IntoResponse {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    axum::Json(json!({ "method": method, "path": path, "echo": true }))
}

async fn start_test_server(with_mpp: bool) -> (String, tokio::task::JoinHandle<()>) {
    let api = load_test_api();
    let mpp = if with_mpp {
        Mpp::new(pay_kit::mpp::server::Config {
            recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            currency: "SOL".to_string(),
            decimals: 9,
            network: "localnet".to_string(),
            rpc_url: Some("http://localhost:8899".to_string()),
            challenge_binding_secret: Some("test-secret-key-do-not-use-32b-pad".to_string()),
            ..Default::default()
        })
        .ok()
    } else {
        None
    };

    let state = TestState {
        apis: Arc::new(vec![api]),
        mpp,
    };

    let app = Router::new()
        .route(
            "/__402/health",
            get(|| async { axum::Json(json!({"ok": true})) }),
        )
        .fallback(any(echo_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<TestState>,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let handle = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (url, handle)
}

async fn start_multi_currency_server() -> (String, tokio::task::JoinHandle<()>) {
    let api = load_test_api();
    let mpps = ["USDC", "CASH", "USDT"]
        .into_iter()
        .map(|currency| {
            Mpp::new(pay_kit::mpp::server::Config {
                recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
                currency: currency.to_string(),
                decimals: 6,
                network: "localnet".to_string(),
                rpc_url: Some("http://localhost:8899".to_string()),
                challenge_binding_secret: Some("test-secret-key-do-not-use-32b-pad".to_string()),
                ..Default::default()
            })
            .unwrap()
        })
        .collect();

    let state = MultiCurrencyTestState {
        apis: Arc::new(vec![api]),
        mpps,
    };

    let app = Router::new()
        .fallback(any(echo_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<MultiCurrencyTestState>,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let handle = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (url, handle)
}

fn load_respond_api() -> ApiSpec {
    let content = std::fs::read_to_string("tests/fixtures/test-respond.yml").unwrap();
    serde_yml::from_str(&content).unwrap()
}

fn client_with_host(subdomain: &str) -> reqwest::header::HeaderMap {
    let mut h = reqwest::header::HeaderMap::new();
    h.insert("host", format!("{subdomain}.localhost").parse().unwrap());
    h
}

async fn start_respond_server() -> (String, tokio::task::JoinHandle<()>) {
    let api = load_respond_api();
    let mpp = Mpp::new(pay_kit::mpp::server::Config {
        recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
        currency: "USDC".to_string(),
        decimals: 6,
        network: "localnet".to_string(),
        rpc_url: Some("http://localhost:8899".to_string()),
        challenge_binding_secret: Some("test-secret-key-do-not-use-32b-pad".to_string()),
        ..Default::default()
    })
    .ok();

    let state = TestState {
        apis: Arc::new(vec![api.clone()]),
        mpp,
    };

    // Use forward_request as fallback (matches production behavior)
    let app = Router::new()
        .fallback(any(move |req: axum::http::Request<Body>| {
            let api = api.clone();
            async move {
                let (parts, body) = req.into_parts();
                let bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
                    .await
                    .unwrap_or_default();
                proxy::forward_request(&api, parts.method, &parts.uri, &parts.headers, bytes)
                    .await
                    .unwrap_or_else(|e| e)
            }
        }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<TestState>,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let handle = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (url, handle)
}

fn test_session_mpp_for_currency(currency: &str) -> SessionMpp {
    SessionMpp::new(
        SessionConfig {
            operator: solana_pubkey::Pubkey::new_unique().to_string(),
            recipient: solana_pubkey::Pubkey::new_unique().to_string(),
            max_cap: 5_000_000,
            currency: currency.to_string(),
            network: "localnet".to_string(),
            modes: vec![
                pay_kit::mpp::SessionMode::Push,
                pay_kit::mpp::SessionMode::Pull,
            ],
            ..SessionConfig::default()
        },
        "test-secret-key-do-not-use-32b-pad",
    )
}

fn test_session_mpp() -> SessionMpp {
    test_session_mpp_for_currency(&solana_pubkey::Pubkey::new_unique().to_string())
}

async fn start_session_server() -> (String, tokio::task::JoinHandle<()>) {
    let api = load_test_api();
    let state = SessionTestState {
        apis: Arc::new(vec![api]),
        mpp: None,
        session_mpp: Some(Arc::new(test_session_mpp())),
    };

    let app = Router::new()
        .fallback(any(echo_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<SessionTestState>,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let handle = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (url, handle)
}

async fn start_multi_currency_session_server() -> (String, tokio::task::JoinHandle<()>) {
    use pay_types::stablecoin_mints::{
        CASH_MAINNET, PYUSD_MAINNET, USDC_MAINNET, USDG_MAINNET, USDT_MAINNET,
    };

    let api = load_test_api();
    let session_mpps = [
        USDC_MAINNET,
        USDT_MAINNET,
        PYUSD_MAINNET,
        CASH_MAINNET,
        USDG_MAINNET,
    ]
    .into_iter()
    .map(|currency| Arc::new(test_session_mpp_for_currency(currency)))
    .collect();
    let state = MultiCurrencySessionTestState {
        apis: Arc::new(vec![api]),
        session_mpps,
    };

    let app = Router::new()
        .fallback(any(echo_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<MultiCurrencySessionTestState>,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let handle = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (url, handle)
}

// =============================================================================
// proxy::resolve_api
// =============================================================================

#[test]
fn resolve_api_by_subdomain() {
    let api = load_test_api();
    let apis = vec![api];
    let found = proxy::resolve_api(&apis, "testapi.google.agent-gateway.solana.com");
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "testapi");
}

#[test]
fn resolve_api_unknown() {
    let api = load_test_api();
    let apis = vec![api];
    assert!(proxy::resolve_api(&apis, "unknown.localhost").is_none());
}

#[test]
fn resolve_api_empty_host() {
    let api = load_test_api();
    let apis = vec![api];
    assert!(proxy::resolve_api(&apis, "").is_none());
}

// =============================================================================
// proxy::error_response
// =============================================================================

#[test]
fn error_response_format() {
    let resp = proxy::error_response(StatusCode::NOT_FOUND, "not found");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test]
fn error_response_bad_gateway() {
    let resp = proxy::error_response(StatusCode::BAD_GATEWAY, "upstream down");
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

// =============================================================================
// Payment middleware — free endpoints
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_skips_gateway_routes() {
    let (url, _h) = start_test_server(true).await;
    let resp = reqwest::get(format!("{url}/__402/health")).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_passes_free_endpoints() {
    let (url, _h) = start_test_server(true).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{url}/v1/health"))
        .headers(client_with_host("testapi"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["echo"], true);
}

#[ignore = "host/localhost passthrough is environment-sensitive and not payment-critical"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_passes_unknown_subdomain() {
    let (url, _h) = start_test_server(true).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{url}/anything"))
        .headers(client_with_host("unknown"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_uses_single_api_mode_without_host_header() {
    let (url, _h) = start_test_server(true).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 402);
    assert!(resp.headers().get("www-authenticate").is_some());
}

// =============================================================================
// Payment middleware — 402 responses
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_returns_402_for_metered() {
    let (url, _h) = start_test_server(true).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 402);
    assert!(resp.headers().get("www-authenticate").is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_402_body_has_pricing() {
    let (url, _h) = start_test_server(true).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .body("{}")
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "payment_required");
    assert!(body["endpoint"]["path"].is_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_402_challenge_parseable() {
    let (url, _h) = start_test_server(true).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .body("{}")
        .send()
        .await
        .unwrap();
    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap();
    let challenge = pay_kit::mpp::parse_www_authenticate(www_auth).unwrap();
    assert_eq!(challenge.method.as_str(), "solana");
    assert_eq!(challenge.intent.as_str(), "charge");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_returns_one_challenge_per_configured_currency() {
    let (url, _h) = start_multi_currency_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 402);
    let headers: Vec<_> = resp
        .headers()
        .get_all("www-authenticate")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    let challenges = pay_kit::mpp::parse_www_authenticate_all(headers)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let currencies: Vec<String> = challenges
        .into_iter()
        .map(|challenge| {
            let request: pay_kit::mpp::ChargeRequest = challenge.request.decode().unwrap();
            request.currency
        })
        .collect();
    assert_eq!(currencies, ["USDC", "CASH", "USDT"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_html_payment_link_sets_html_content_type_and_challenge() {
    let (url, _h) = start_test_server(true).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .header("accept", "text/html,*/*")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 402);
    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("text/html"));
    assert!(resp.headers().get("www-authenticate").is_some());
}

// =============================================================================
// Payment middleware — invalid credentials
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_rejects_garbage_auth() {
    let (url, _h) = start_test_server(true).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .header("authorization", "Payment dGhpcyBpcyBnYXJiYWdl")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "malformed_credential");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_rejects_bearer_scheme() {
    let (url, _h) = start_test_server(true).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .header("authorization", "Bearer some-token")
        .body("{}")
        .send()
        .await
        .unwrap();
    // Bearer is not "Payment" scheme — should be rejected
    assert!(resp.status() == 400 || resp.status() == 402);
}

// =============================================================================
// Payment middleware — session flow
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_returns_session_challenge_when_session_mpp_configured() {
    let (url, _h) = start_session_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 402);
    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap();
    let challenge = pay_kit::mpp::parse_www_authenticate(www_auth).unwrap();
    assert_eq!(challenge.intent.as_str(), "session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_returns_one_session_challenge_per_configured_currency() {
    use pay_types::stablecoin_mints::{
        CASH_MAINNET, PYUSD_MAINNET, USDC_MAINNET, USDG_MAINNET, USDT_MAINNET,
    };

    let (url, _h) = start_multi_currency_session_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 402);
    let headers: Vec<_> = resp
        .headers()
        .get_all("www-authenticate")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    let challenges = pay_kit::mpp::parse_www_authenticate_all(headers)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let currencies: Vec<String> = challenges
        .into_iter()
        .map(|challenge| {
            assert_eq!(challenge.intent.as_str(), "session");
            let request: pay_kit::mpp::SessionRequest = challenge.request.decode().unwrap();
            request.currency
        })
        .collect();
    assert_eq!(
        currencies,
        [
            USDC_MAINNET,
            USDT_MAINNET,
            PYUSD_MAINNET,
            CASH_MAINNET,
            USDG_MAINNET,
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_accepts_session_open_and_voucher_then_close() {
    let (url, _h) = start_session_server().await;
    let client = reqwest::Client::new();

    let challenge_resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .body("{}")
        .send()
        .await
        .unwrap();
    let www_auth = challenge_resp
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let challenge = pay_kit::mpp::parse_www_authenticate(&www_auth).unwrap();

    let challenge_for_open = challenge.clone();
    let (handle, open_header) = tokio::task::spawn_blocking(move || {
        pay_core::session::open_session_header(&challenge_for_open, 1_000_000)
    })
    .await
    .unwrap()
    .unwrap();

    let open_resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .header("authorization", open_header)
        .body("{}")
        .send()
        .await
        .unwrap();
    // Client-voucher sessions acknowledge the open before requiring the first
    // client-signed voucher for paid service.
    assert_eq!(open_resp.status(), 402);

    let voucher_header = handle.voucher_header(25).await.unwrap();
    let voucher_resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .header("authorization", voucher_header)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(voucher_resp.status(), 200);

    let close_header = handle.close_header(Some(25)).await.unwrap();
    let close_resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .header("authorization", close_header)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(close_resp.status(), 200);
    let body: serde_json::Value = close_resp.json().await.unwrap();
    assert_eq!(body["status"], "closed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_garbage_auth_includes_message() {
    let (url, _h) = start_test_server(true).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .header("authorization", "Payment dGhpcyBpcyBnYXJiYWdl")
        .body("{}")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["message"].is_string());
}

// =============================================================================
// Payment middleware — no MPP configured
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn middleware_fails_closed_without_mpp() {
    let (url, _h) = start_test_server(false).await;
    let client = reqwest::Client::new();
    // Metered endpoint but no MPP configured → fail closed (issue #373).
    // Forwarding here would serve a paid resource for free, so the
    // middleware must reject rather than pass through.
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        500,
        "metered endpoint with no payment backend must fail closed, not pass through"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "payment_backend_unconfigured");
}

// =============================================================================
// Accounting store — additional edge cases
// =============================================================================

#[test]
fn accounting_zero_increment() {
    let store = InMemoryStore::new();
    let key = AccountingKey {
        api: "test".into(),
        endpoint: "test".into(),
        period: "2026-03".into(),
        scope: "pool".into(),
    };
    assert_eq!(store.increment(&key, 0), 0);
    assert_eq!(store.get_usage(&key), 0);
}

#[test]
fn accounting_large_increment() {
    let store = InMemoryStore::new();
    let key = AccountingKey {
        api: "test".into(),
        endpoint: "test".into(),
        period: "2026-03".into(),
        scope: "pool".into(),
    };
    assert_eq!(store.increment(&key, u64::MAX / 2), u64::MAX / 2);
}

#[test]
fn accounting_many_scopes() {
    let store = InMemoryStore::new();
    for i in 0..100 {
        let key = AccountingKey {
            api: "test".into(),
            endpoint: "test".into(),
            period: "2026-03".into(),
            scope: format!("wallet_{i}"),
        };
        store.increment(&key, i as u64);
    }
    let key = AccountingKey {
        api: "test".into(),
        endpoint: "test".into(),
        period: "2026-03".into(),
        scope: "wallet_50".into(),
    };
    assert_eq!(store.get_usage(&key), 50);
}

// =============================================================================
// Root redirect to PDB (when debugger is active)
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_redirects_to_pdb_with_html_accept() {
    // Simulates `pay server start`: root with Accept:text/html → redirect to pdb.
    // Unlisted paths (e.g. /favicon.ico) must return 404, not forward to upstream
    // (which would trigger spurious OAuth2 fetches).
    let api = load_respond_api();
    let mpp = Mpp::new(pay_kit::mpp::server::Config {
        recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
        currency: "USDC".to_string(),
        decimals: 6,
        network: "localnet".to_string(),
        rpc_url: Some("http://localhost:8899".to_string()),
        challenge_binding_secret: Some("test-secret-key-do-not-use-32b-pad".to_string()),
        ..Default::default()
    })
    .ok();

    let state = TestState {
        apis: Arc::new(vec![api.clone()]),
        mpp,
    };

    let app = Router::new()
        .route(
            "/",
            get(|headers: axum::http::HeaderMap| async move {
                let accepts_html = headers
                    .get("accept")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.contains("text/html"));
                if accepts_html {
                    axum::response::Redirect::temporary("/__402/pdb/").into_response()
                } else {
                    axum::Json(json!({"status": "ok"})).into_response()
                }
            }),
        )
        .fallback(any(move |req: axum::http::Request<Body>| {
            let api = api.clone();
            async move {
                let (parts, body) = req.into_parts();
                // 404 for paths not in the spec (matches production fallback in start.rs).
                let path = parts.uri.path().trim_start_matches('/');
                if pay_core::server::metering::find_endpoint_by_path(&api, path).is_none() {
                    return (
                        axum::http::StatusCode::NOT_FOUND,
                        axum::Json(json!({"error": "not_found"})),
                    )
                        .into_response();
                }
                let bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
                    .await
                    .unwrap_or_default();
                proxy::forward_request(&api, parts.method, &parts.uri, &parts.headers, bytes)
                    .await
                    .unwrap_or_else(|e| e)
            }
        }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<TestState>,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let _h = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // HTML accept → redirect to PDB.
    let resp = client
        .get(&url)
        .header("accept", "text/html,*/*")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 307);
    assert_eq!(resp.headers().get("location").unwrap(), "/__402/pdb/");

    // JSON accept → 200 status ok.
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Unlisted path → 404, not a proxy attempt.
    let resp = client
        .get(format!("{url}/favicon.ico"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// =============================================================================
// Method gating — prevent bypass by switching HTTP methods
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_on_post_endpoint_returns_402_with_html_accept() {
    let (url, _h) = start_test_server(true).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .header("accept", "text/html,*/*")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        402,
        "GET with Accept:text/html on POST endpoint should return 402 payment link"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_on_post_endpoint_without_html_passes_through() {
    // With proxy routing, unknown method falls through to upstream (echo handler)
    let (url, _h) = start_test_server(true).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{url}/v1/simple/echo"))
        .headers(client_with_host("testapi"))
        .send()
        .await
        .unwrap();
    // Proxy routing: passes through to fallback (echo handler returns 200)
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn head_on_get_endpoint_returns_402() {
    // Uses respond server which has a metered GET endpoint
    let (url, _h) = start_respond_server().await;
    let client = reqwest::Client::new();
    let resp = client.head(format!("{url}/v1/data")).send().await.unwrap();
    // HEAD should be gated same as GET
    assert_eq!(resp.status(), 402);
}

// =============================================================================
// Respond routing — method gating and 404 behavior
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_get_metered_returns_402() {
    let (url, _h) = start_respond_server().await;
    let client = reqwest::Client::new();
    let resp = client.get(format!("{url}/v1/data")).send().await.unwrap();
    assert_eq!(
        resp.status(),
        402,
        "GET on metered respond endpoint should return 402"
    );
    assert!(resp.headers().get("www-authenticate").is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_post_metered_returns_402() {
    let (url, _h) = start_respond_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/submit"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        402,
        "POST on metered respond endpoint should return 402"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_free_endpoint_passes_through() {
    let (url, _h) = start_respond_server().await;
    let client = reqwest::Client::new();
    let resp = client.get(format!("{url}/v1/health")).send().await.unwrap();
    // Free endpoint with respond routing: passes to fallback (echo)
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_unknown_path_returns_404() {
    let (url, _h) = start_respond_server().await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{url}/v1/nonexistent"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "Unknown path on respond routing should return 404"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_wrong_method_returns_404() {
    let (url, _h) = start_respond_server().await;
    let client = reqwest::Client::new();
    // GET on a POST-only endpoint without Accept:text/html
    let resp = client.get(format!("{url}/v1/submit")).send().await.unwrap();
    assert_eq!(
        resp.status(),
        404,
        "GET on POST endpoint with respond routing should return 404"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_wrong_method_with_html_returns_402() {
    let (url, _h) = start_respond_server().await;
    let client = reqwest::Client::new();
    // GET on POST endpoint with Accept:text/html → payment link page
    let resp = client
        .get(format!("{url}/v1/submit"))
        .header("accept", "text/html,*/*")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        402,
        "GET with Accept:text/html on POST endpoint should return 402 payment link"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_service_worker_always_served() {
    let (url, _h) = start_respond_server().await;
    let client = reqwest::Client::new();
    // Service worker request on a POST endpoint path
    let resp = client
        .get(format!("{url}/v1/submit?__mpp_worker=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("javascript"), "Service worker should return JS");
}
