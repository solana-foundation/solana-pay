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

use pay_keystore::{AuthGate, AuthIntent};
use pay_mcp::ElicitationAuth;
use rmcp::{
    ClientHandler, ErrorData as McpError, ServerHandler,
    model::*,
    service::{RequestContext, RoleClient, RoleServer, serve_directly},
};
use std::sync::Arc;
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
    last_request: Arc<Mutex<Option<ElicitRequestParams>>>,
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
        request: ElicitRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, McpError> {
        *self.last_request.lock().await = Some(request);
        let content = if matches!(self.action, ElicitationAction::Accept) {
            Some(serde_json::json!({ "approved": true }))
        } else {
            None
        };
        let result = ElicitResult::new(self.action.clone());
        Ok(match content {
            Some(content) => result.with_content(content),
            None => result,
        })
    }
}

async fn run_with_action(
    action: ElicitationAction,
) -> (Result<(), pay_keystore::Error>, Option<ElicitRequestParams>) {
    let (server_transport, client_transport) = tokio::io::duplex(8192);

    let client_handler = ConfigurableClient::new(action);
    let client_info = ClientInfo::new(
        ClientCapabilities::builder().enable_elicitation().build(),
        Implementation::new("pay-mcp-test-client", "0.0.0"),
    )
    .with_protocol_version(ProtocolVersion::V_2025_06_18);
    let server_info = ServerInfo::new(ServerCapabilities::default())
        .with_protocol_version(ProtocolVersion::V_2025_06_18);
    let server =
        serve_directly::<RoleServer, _, _, _, _>(BareServer, server_transport, Some(client_info));
    let client = serve_directly::<RoleClient, _, _, _, _>(
        client_handler.clone(),
        client_transport,
        Some(server_info.into()),
    );

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_succeeds_when_client_accepts() {
    let (result, received) = run_with_action(ElicitationAction::Accept).await;
    assert!(
        result.is_ok(),
        "authenticate() should return Ok when client accepts; got {result:?}"
    );

    let req = received.expect("client should have received an elicitation");
    // The message should carry the amount and operator from the intent.
    let ElicitRequestParams::FormElicitationParams { message, .. } = req else {
        panic!("expected form elicitation");
    };
    assert!(
        message.contains("$0.50"),
        "message should mention amount: {message:?}"
    );
    assert!(
        message.contains("test API call"),
        "message should mention reason: {message:?}"
    );
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_fails_closed_when_client_cancels() {
    let (result, _received) = run_with_action(ElicitationAction::Cancel).await;
    let err = result.expect_err("authenticate() should error when client cancels");
    assert!(
        matches!(err, pay_keystore::Error::AuthDenied(_)),
        "cancel should map to AuthDenied; got {err:?}"
    );
}
