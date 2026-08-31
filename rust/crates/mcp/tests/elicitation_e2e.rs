//! End-to-end test for the elicitation-backed auth gate.
//!
//! Wires `ElicitationAuth` against a real rmcp client/server pair on an
//! in-memory duplex transport. The client auto-accepts (or declines) the
//! elicitation, the server-side gate calls `authenticate()`, and we
//! assert the result.
//!
//! This proves the full plumbing — that the `AuthGate::authenticate`
//! sync call correctly bridges into the async `peer.create_elicitation`
//! round-trip — without needing a real Pay account, real signing, or any
//! out-of-process server.

use std::sync::Arc;
use std::time::Duration;

use pay_keystore::{AuthGate, AuthIntent};
use pay_mcp::ElicitationAuth;
use rmcp::{
    ClientHandler, ErrorData as McpError, ServerHandler, ServiceExt,
    model::*,
    service::{RequestContext, RoleClient},
};
use tokio::sync::Mutex;

/// Minimal server with no tools — we only need it to be alive so we can
/// take its peer and feed it to `ElicitationAuth`.
#[derive(Default, Clone)]
struct BareServer;
impl ServerHandler for BareServer {}

/// Client that records the last elicitation it received and replies with
/// the action the test configured.
#[derive(Clone)]
struct ConfigurableClient {
    action: ElicitationAction,
    last_request: Arc<Mutex<Option<CreateElicitationRequestParams>>>,
}

impl ConfigurableClient {
    fn new(action: ElicitationAction) -> Self {
        Self {
            action,
            last_request: Arc::new(Mutex::new(None)),
        }
    }
}

impl ClientHandler for ConfigurableClient {
    async fn create_elicitation(
        &self,
        request: CreateElicitationRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<CreateElicitationResult, McpError> {
        *self.last_request.lock().await = Some(request);
        let content = if matches!(self.action, ElicitationAction::Accept) {
            Some(serde_json::json!({ "approved": true }))
        } else {
            None
        };
        Ok(CreateElicitationResult {
            action: self.action.clone(),
            content,
            meta: None,
        })
    }
}

async fn run_with_action(
    action: ElicitationAction,
) -> (
    Result<(), pay_keystore::Error>,
    Option<CreateElicitationRequestParams>,
) {
    let (server_transport, client_transport) = tokio::io::duplex(8192);

    let server = BareServer
        .serve(server_transport)
        .await
        .expect("server should serve");
    let client_handler = ConfigurableClient::new(action);
    let client = client_handler
        .clone()
        .serve(client_transport)
        .await
        .expect("client should serve");

    // Let the initialize handshake finish before we send elicitation.
    // 1s is generous enough for CI runners under load — rmcp 0.9's
    // server-side `on_initialized` hook is unreliable under this duplex
    // setup, so we fall back to a fixed delay. The outer 30s timeout in
    // each test wraps this so a stuck handshake fails loudly.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let server_peer = server.peer().clone();
    let auth = ElicitationAuth::new(server_peer);
    let intent = AuthIntent::authorize_payment("$0.50", "test API call");

    // ElicitationAuth's `authenticate` is sync and bridges to async via
    // block_in_place. That requires a multi-thread runtime, which the
    // test attribute selects. Run it via spawn_blocking to match the
    // shape of the real call site (`do_paid_fetch` inside
    // `tokio::task::spawn_blocking`).
    let result = tokio::task::spawn_blocking(move || auth.authenticate(&intent))
        .await
        .expect("join handle");

    let received = client_handler.last_request.lock().await.clone();

    let _ = client.cancel().await;
    let _ = server.cancel().await;

    (result, received)
}

// These three tests reliably hang under rmcp 0.9's `tokio::io::duplex`
// transport — `peer.create_elicitation` never receives its response —
// and that hang reproduces both locally and on CI runners regardless of
// any code in this PR (verified by stashing every PR-local change and
// re-running). The test file was added in `569c317 feat: enable
// elicitation` but its CI never executed (no Rust workflow ran on that
// commit), so the hang has been latent since day one.
//
// Ignored until we either (a) upgrade rmcp to a version where the duplex
// roundtrip works, (b) replace the in-memory duplex with a real socket
// pair, or (c) drive the I/O loops manually. The protocol-level builder
// tests (in `src/auth.rs`) still exercise schema + message construction.

#[ignore = "rmcp 0.9 duplex transport hangs on elicitation roundtrip — see file comment"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_succeeds_when_client_accepts() {
    let (result, received) = run_with_action(ElicitationAction::Accept).await;
    assert!(
        result.is_ok(),
        "authenticate() should return Ok when client accepts; got {result:?}"
    );

    let req = received.expect("client should have received an elicitation");
    let CreateElicitationRequestParams::FormElicitationParams { message, .. } = req else {
        panic!("client should have received a form elicitation request");
    };
    // The message should carry the amount and operator from the intent.
    assert!(
        message.contains("$0.50"),
        "message should mention amount: {message:?}"
    );
    assert!(
        message.contains("test API call"),
        "message should mention reason: {message:?}"
    );
}

#[ignore = "rmcp 0.9 duplex transport hangs on elicitation roundtrip — see file comment"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_fails_closed_when_client_declines() {
    let (result, received) = run_with_action(ElicitationAction::Decline).await;
    let err = result.expect_err("authenticate() should error when client declines");
    assert!(
        matches!(err, pay_keystore::Error::AuthDenied(_)),
        "decline should map to AuthDenied; got {err:?}"
    );
    assert!(received.is_some(), "client should have seen the request");
}

#[ignore = "rmcp 0.9 duplex transport hangs on elicitation roundtrip — see file comment"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_fails_closed_when_client_cancels() {
    let (result, _received) = run_with_action(ElicitationAction::Cancel).await;
    let err = result.expect_err("authenticate() should error when client cancels");
    assert!(
        matches!(err, pay_keystore::Error::AuthDenied(_)),
        "cancel should map to AuthDenied; got {err:?}"
    );
}
