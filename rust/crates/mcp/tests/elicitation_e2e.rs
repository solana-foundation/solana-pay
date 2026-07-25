//! End-to-end test for the elicitation-backed auth gate.
//!
//! Wires `ElicitationAuth` against a real rmcp client/server pair on a
//! bounded in-memory duplex connection. The client auto-accepts (or declines) the
//! elicitation, the server-side gate calls `authenticate()`, and we
//! assert the result.
//!
//! This proves the full plumbing: the `AuthGate::authenticate` sync call
//! correctly bridges into the async `peer.create_elicitation` round-trip,
//! without needing a real Pay account, real signing, or any
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

const STEP_TIMEOUT: Duration = Duration::from_secs(5);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const AUTH_TIMEOUT: Duration = Duration::from_secs(2);

/// Minimal server with no tools. We only need it to be alive so we can
/// take its peer and feed it to `ElicitationAuth`.
#[derive(Default, Clone)]
struct BareServer;
impl ServerHandler for BareServer {}

/// Client that records the last elicitation it received and replies with
/// the action the test configured.
#[derive(Clone)]
struct ConfigurableClient {
    action: ElicitationAction,
    last_request: Arc<Mutex<Option<CreateElicitationRequestParam>>>,
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
    fn get_info(&self) -> ClientInfo {
        ClientInfo {
            capabilities: ClientCapabilities::builder().enable_elicitation().build(),
            ..ClientInfo::default()
        }
    }

    async fn create_elicitation(
        &self,
        request: CreateElicitationRequestParam,
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
        })
    }
}

async fn run_with_action(
    action: ElicitationAction,
) -> (
    Result<(), pay_keystore::Error>,
    Option<CreateElicitationRequestParam>,
) {
    let (server_transport, client_transport) = tokio::io::duplex(8192);

    // `serve()` performs the MCP initialize handshake before it returns. The
    // server side must therefore run concurrently with the client side. The old
    // harness awaited it before starting the client, which deadlocked at
    // initialization.
    let server_task = tokio::spawn(async move {
        tokio::time::timeout(STEP_TIMEOUT, BareServer.serve(server_transport))
            .await
            .expect("server initialize handshake timed out")
            .expect("server should serve")
    });

    let client_handler = ConfigurableClient::new(action);
    let client = tokio::time::timeout(STEP_TIMEOUT, client_handler.clone().serve(client_transport))
        .await
        .expect("client initialize handshake timed out")
        .expect("client should serve");
    let server = tokio::time::timeout(STEP_TIMEOUT, server_task)
        .await
        .expect("server task timed out after client initialized")
        .expect("server task should not panic");
    assert!(
        server
            .peer()
            .peer_info()
            .and_then(|info| info.capabilities.elicitation.as_ref())
            .is_some(),
        "test client must advertise elicitation support"
    );

    let server_peer = server.peer().clone();
    let auth = ElicitationAuth::with_timeout(server_peer, AUTH_TIMEOUT);
    let intent = AuthIntent::authorize_payment("$0.50", "test API call");

    // ElicitationAuth's `authenticate` is sync and bridges to async via
    // block_in_place. That requires a multi-thread runtime, which the
    // test attribute selects. Run it via spawn_blocking to match the
    // shape of the real call site (`do_paid_fetch` inside
    // `tokio::task::spawn_blocking`).
    let mut auth_task = tokio::task::spawn_blocking(move || auth.authenticate(&intent));
    let result = match tokio::time::timeout(STEP_TIMEOUT, &mut auth_task).await {
        Ok(join_result) => join_result.expect("auth task should not panic"),
        Err(_) => {
            // A started `spawn_blocking` task cannot be aborted. Close both
            // transports, then prove the task unwinds within the cleanup budget.
            // The gate's explicit two-second deadline is the final fail-closed
            // bound if the transport does not respond to cancellation.
            let _ = tokio::time::timeout(CLEANUP_TIMEOUT, client.cancel()).await;
            let _ = tokio::time::timeout(CLEANUP_TIMEOUT, server.cancel()).await;
            let cleanup_result = tokio::time::timeout(CLEANUP_TIMEOUT, &mut auth_task)
                .await
                .expect("timed-out auth task did not unwind after transport cancellation")
                .expect("timed-out auth task should not panic");
            assert!(
                cleanup_result.is_err(),
                "timed-out authorization must fail closed after cancellation"
            );
            panic!("elicitation auth round-trip timed out");
        }
    };

    let received = client_handler.last_request.lock().await.clone();

    tokio::time::timeout(CLEANUP_TIMEOUT, client.cancel())
        .await
        .expect("client cleanup timed out")
        .expect("client service should stop cleanly");
    tokio::time::timeout(CLEANUP_TIMEOUT, server.cancel())
        .await
        .expect("server cleanup timed out")
        .expect("server service should stop cleanly");

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
    assert!(
        req.message.contains("$0.50"),
        "message should mention amount: {:?}",
        req.message
    );
    assert!(
        req.message.contains("test API call"),
        "message should mention reason: {:?}",
        req.message
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
    let (result, received) = run_with_action(ElicitationAction::Cancel).await;
    let err = result.expect_err("authenticate() should error when client cancels");
    assert!(
        matches!(err, pay_keystore::Error::AuthDenied(_)),
        "cancel should map to AuthDenied; got {err:?}"
    );
    assert!(received.is_some(), "client should have seen the request");
}
