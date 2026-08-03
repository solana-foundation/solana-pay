//! [`AuthGate`] backed by MCP elicitation.
//!
//! When the connected MCP client advertises the `elicitation` capability
//! AND no local platform biometric is available, pay-mcp installs this
//! gate so signing confirmations flow through the LLM client's UI (Claude
//! Desktop dialog, Hermes approval prompt, Telegram message, etc.) instead
//! of the (missing) platform biometric prompt.
//!
//! When a local biometric IS available (Touch ID, Windows Hello, polkit),
//! the platform gate is preferred — a native prompt is faster and more
//! familiar than a round-trip through the MCP client UI. The install-site
//! check lives in `mcp/src/tools/curl.rs::make_auth_override`; set
//! `PAY_FORCE_ELICITATION=1` to override and route every approval through
//! the MCP client anyway.
//!
//! The [`AuthGate`] trait is synchronous, but rmcp's elicitation call is
//! `async`. Payment work runs on a blocking thread and sends approval requests
//! through a broker polled by the original tool-handler task. That preserves
//! MCP 2026-07-28 request association (SEP-2260) while the blocking signer
//! waits just like a native Touch ID prompt. The direct peer backend remains
//! for older MCP sessions and compatibility tests.
//!
//! All failure modes map to [`pay_keystore::Error::AuthDenied`]: declined
//! responses, cancelled responses, transport errors, and timeouts. The
//! caller treats any non-Accept outcome as "user did not approve".

use std::time::Duration;

use pay_keystore::{AuthGate, AuthIntent, Error as KeystoreError};
use rmcp::Peer;
use rmcp::model::{ElicitRequestParams, ElicitResult, ElicitationAction, ElicitationSchema};
use rmcp::service::RoleServer;
use tokio::sync::mpsc;

/// Outer deadline for a single elicitation round-trip, including the
/// human's response time. Matches Hermes' gateway approval default so
/// users on async surfaces (Telegram, Slack) have time to respond.
const ELICITATION_TIMEOUT: Duration = Duration::from_secs(300);

/// Ask the connected MCP client before Pay reads a local file into an HTTP
/// request body. This is deliberately separate from wallet authorization:
/// the user must first approve sharing the file, then may separately approve
/// a payment if the destination returns a 402 challenge.
pub async fn confirm_file_upload(
    peer: &Peer<RoleServer>,
    path: &str,
    bytes: u64,
    method: &str,
    destination: &str,
) -> Result<(), String> {
    let params = build_file_upload_request(path, bytes, method, destination);
    let outcome = tokio::time::timeout(ELICITATION_TIMEOUT, peer.create_elicitation(params))
        .await
        .map_err(|_| "Timed out waiting for approval to send the local file.".to_string())?
        .map_err(|error| format!("Could not request approval to send the local file: {error}"))?;

    match outcome.action {
        ElicitationAction::Accept => {
            let explicitly_denied = outcome
                .content
                .as_ref()
                .and_then(|value| value.get("approved"))
                .and_then(|value| value.as_bool())
                .map(|approved| !approved)
                .unwrap_or(false);
            if explicitly_denied {
                Err("The user declined to send the local file.".to_string())
            } else {
                Ok(())
            }
        }
        ElicitationAction::Decline => Err("The user declined to send the local file.".to_string()),
        ElicitationAction::Cancel => Err("The user cancelled sending the local file.".to_string()),
        _ => Err("The MCP client returned an unsupported approval action.".to_string()),
    }
}

/// `AuthGate` that asks the connected MCP client for approval via
/// `elicitation/create` instead of a platform biometric prompt.
pub struct ElicitationAuth {
    backend: ElicitationBackend,
}

enum ElicitationBackend {
    Direct(Peer<RoleServer>),
    Broker(mpsc::UnboundedSender<BrokerRequest>),
}

pub(crate) struct BrokerRequest {
    params: ElicitRequestParams,
    reply: std::sync::mpsc::SyncSender<Result<ElicitResult, rmcp::ServiceError>>,
}

impl ElicitationAuth {
    /// Construct a direct gate for MCP sessions older than 2026-07-28.
    ///
    /// MCP 2026-07-28 requires request association; Pay's tool handler uses
    /// the internal broker backend for those sessions.
    pub fn new(peer: Peer<RoleServer>) -> Self {
        Self {
            backend: ElicitationBackend::Direct(peer),
        }
    }

    pub(crate) fn via_broker(sender: mpsc::UnboundedSender<BrokerRequest>) -> Self {
        Self {
            backend: ElicitationBackend::Broker(sender),
        }
    }
}

impl AuthGate for ElicitationAuth {
    fn authenticate(&self, intent: &AuthIntent) -> Result<(), KeystoreError> {
        let params = build_request(intent);
        let outcome = match &self.backend {
            ElicitationBackend::Direct(peer) => {
                let peer = peer.clone();
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(request_elicitation(&peer, params))
                })
            }
            ElicitationBackend::Broker(sender) => {
                let (reply, response) = std::sync::mpsc::sync_channel(1);
                if sender.send(BrokerRequest { params, reply }).is_err() {
                    Err(rmcp::ServiceError::TransportClosed)
                } else {
                    response
                        .recv_timeout(ELICITATION_TIMEOUT)
                        .unwrap_or_else(|_| {
                            Err(rmcp::ServiceError::Timeout {
                                timeout: ELICITATION_TIMEOUT,
                            })
                        })
                }
            }
        };

        interpret_elicitation_outcome(outcome)
    }

    fn is_available(&self) -> bool {
        // We don't ping the peer here — `authenticate()` would surface a
        // transport failure as AuthDenied anyway, and is_available() is
        // called from contexts where blocking is undesirable.
        true
    }
}

async fn request_elicitation(
    peer: &Peer<RoleServer>,
    params: ElicitRequestParams,
) -> Result<ElicitResult, rmcp::ServiceError> {
    tokio::time::timeout(ELICITATION_TIMEOUT, peer.create_elicitation(params))
        .await
        .map_err(|_| rmcp::ServiceError::Timeout {
            timeout: ELICITATION_TIMEOUT,
        })?
}

/// Run blocking payment work while servicing its approval requests on the
/// originating MCP task. MCP 2026-07-28 requires this association (SEP-2260),
/// so the blocking signer never calls the peer directly.
pub(crate) async fn spawn_blocking_with_elicitation<T, F>(
    peer: &Peer<RoleServer>,
    operation: F,
) -> Result<T, tokio::task::JoinError>
where
    T: Send + 'static,
    F: FnOnce(mpsc::UnboundedSender<BrokerRequest>) -> T + Send + 'static,
{
    let (sender, mut requests) = mpsc::unbounded_channel();
    let mut operation = tokio::task::spawn_blocking(move || operation(sender));
    loop {
        tokio::select! {
            result = &mut operation => return result,
            request = requests.recv() => {
                let Some(request) = request else {
                    return operation.await;
                };
                let result = request_elicitation(peer, request.params).await;
                let _ = request.reply.send(result);
            }
        }
    }
}

/// Map the result of an elicitation round-trip to an auth decision.
///
/// Pure and transport-free so the decision logic can be unit-tested without
/// a live rmcp peer (the full round-trip is covered by `tests/elicitation_e2e`).
/// Any non-`Accept` outcome is treated as "user did not approve":
/// - `Decline` / `Cancel` → [`KeystoreError::AuthDenied`],
/// - a transport/timeout error → `AuthDenied`,
/// - even an `Accept` that carries `content.approved=false` → `AuthDenied`.
///
/// `Accept` is the primary authoritative signal. The explicit
/// `approved=false` guard shouldn't trigger (the schema declares `approved`
/// as a required bool, so a form-rendering client can't produce `Accept`
/// with a negative answer), but a buggy or hostile client might — and we'd
/// rather deny than admit on conflicting input.
fn interpret_elicitation_outcome(
    outcome: Result<ElicitResult, rmcp::ServiceError>,
) -> Result<(), KeystoreError> {
    match outcome {
        Ok(res) => match res.action {
            ElicitationAction::Accept => {
                let explicitly_denied = res
                    .content
                    .as_ref()
                    .and_then(|v| v.get("approved"))
                    .and_then(|v| v.as_bool())
                    .map(|b| !b)
                    .unwrap_or(false);
                if explicitly_denied {
                    return Err(KeystoreError::AuthDenied(
                        "MCP client returned Accept but content.approved=false".to_string(),
                    ));
                }
                Ok(())
            }
            ElicitationAction::Decline => Err(KeystoreError::AuthDenied(
                "user declined the request via the MCP client".to_string(),
            )),
            ElicitationAction::Cancel => Err(KeystoreError::AuthDenied(
                "user cancelled the request via the MCP client".to_string(),
            )),
            _ => Err(KeystoreError::AuthDenied(
                "MCP client returned an unsupported elicitation action".to_string(),
            )),
        },
        Err(err) => Err(KeystoreError::AuthDenied(format!(
            "elicitation transport failed: {err}"
        ))),
    }
}

/// Build the `elicitation/create` request body for an [`AuthIntent`].
///
/// Per the design decisions for v1:
/// - **Schema is structured** (boolean `approved` + optional `limit_label`),
///   so clients that render forms can present a confirmation UI; clients
///   that fall back to yes/no still get the message text.
/// - **Per-call only**: no server-side state binds approvals across calls.
fn build_request(intent: &AuthIntent) -> ElicitRequestParams {
    // Builder validates required fields against declared properties.
    // The combination below is statically sound; `expect` would only
    // fire if rmcp's validation contract changes in a future release.
    let schema = ElicitationSchema::builder()
        .required_bool("approved")
        .build()
        .expect("required_bool registers `approved` in properties");

    ElicitRequestParams::FormElicitationParams {
        meta: None,
        message: intent.message().to_string(),
        requested_schema: schema,
    }
}

fn build_file_upload_request(
    path: &str,
    bytes: u64,
    method: &str,
    destination: &str,
) -> ElicitRequestParams {
    let schema = ElicitationSchema::builder()
        .required_bool("approved")
        .build()
        .expect("required_bool registers `approved` in properties");
    ElicitRequestParams::FormElicitationParams {
        meta: None,
        message: format!(
            "Allow Pay to read and send `{path}` ({bytes} bytes) in an HTTP {method} request to {destination}? The file is read once after approval; the exact snapshot may be reused only to retry this same request after a 402 payment challenge."
        ),
        requested_schema: schema,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(request: &ElicitRequestParams) -> (&str, &ElicitationSchema) {
        match request {
            ElicitRequestParams::FormElicitationParams {
                message,
                requested_schema,
                ..
            } => (message, requested_schema),
            _ => panic!("expected form elicitation"),
        }
    }

    #[test]
    fn build_request_carries_intent_message() {
        let intent = AuthIntent::authorize_payment("$0.50", "accessing API api.example.com");
        let req = build_request(&intent);
        let (message, _) = form(&req);
        assert!(
            message.contains("$0.50"),
            "message should include amount: {message:?}",
        );
        assert!(
            message.contains("api.example.com"),
            "message should include operator: {message:?}",
        );
    }

    #[test]
    fn build_request_includes_approved_boolean_field() {
        let intent = AuthIntent::default_payment();
        let req = build_request(&intent);
        let (_, schema) = form(&req);
        // The schema must include an `approved` property so even
        // form-rendering clients have a concrete confirmation field.
        let json = serde_json::to_value(schema).expect("schema should serialize");
        let props = json.get("properties").expect("schema has properties");
        assert!(
            props.get("approved").is_some(),
            "schema should expose `approved` boolean: {json}",
        );
    }

    #[test]
    fn file_upload_request_names_the_file_destination_and_size() {
        let req = build_file_upload_request(
            "/workspace/photo.png",
            1_024,
            "POST",
            "https://api.example.com/upload",
        );
        let (message, _) = form(&req);
        assert!(message.contains("/workspace/photo.png"));
        assert!(message.contains("1024 bytes"));
        assert!(message.contains("POST"));
        assert!(message.contains("https://api.example.com/upload"));
    }

    fn result(action: ElicitationAction, content: Option<serde_json::Value>) -> ElicitResult {
        let result = ElicitResult::new(action);
        match content {
            Some(content) => result.with_content(content),
            None => result,
        }
    }

    #[test]
    fn accept_without_content_is_approved() {
        let out = interpret_elicitation_outcome(Ok(result(ElicitationAction::Accept, None)));
        assert!(out.is_ok());
    }

    #[test]
    fn accept_with_approved_true_is_approved() {
        let res = result(
            ElicitationAction::Accept,
            Some(serde_json::json!({ "approved": true })),
        );
        assert!(interpret_elicitation_outcome(Ok(res)).is_ok());
    }

    #[test]
    fn accept_with_approved_false_is_denied() {
        // Defense-in-depth: an Accept that nonetheless carries approved=false
        // must be denied, not admitted.
        let res = result(
            ElicitationAction::Accept,
            Some(serde_json::json!({ "approved": false })),
        );
        assert!(matches!(
            interpret_elicitation_outcome(Ok(res)),
            Err(KeystoreError::AuthDenied(_))
        ));
    }

    #[test]
    fn decline_is_denied() {
        assert!(matches!(
            interpret_elicitation_outcome(Ok(result(ElicitationAction::Decline, None))),
            Err(KeystoreError::AuthDenied(_))
        ));
    }

    #[test]
    fn cancel_is_denied() {
        assert!(matches!(
            interpret_elicitation_outcome(Ok(result(ElicitationAction::Cancel, None))),
            Err(KeystoreError::AuthDenied(_))
        ));
    }

    #[test]
    fn transport_error_is_denied() {
        let out = interpret_elicitation_outcome(Err(rmcp::ServiceError::Timeout {
            timeout: Duration::from_secs(1),
        }));
        assert!(matches!(out, Err(KeystoreError::AuthDenied(_))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn broker_bridges_blocking_auth_to_async_approval() {
        let (sender, mut requests) = mpsc::unbounded_channel();
        let auth = ElicitationAuth::via_broker(sender);
        let intent = AuthIntent::authorize_payment("$0.01", "broker test");
        let operation = tokio::task::spawn_blocking(move || auth.authenticate(&intent));

        let request = requests.recv().await.expect("broker request");
        request
            .reply
            .send(Ok(ElicitResult::new(ElicitationAction::Accept)
                .with_content(serde_json::json!({ "approved": true }))))
            .unwrap();

        assert!(operation.await.unwrap().is_ok());
    }
}
