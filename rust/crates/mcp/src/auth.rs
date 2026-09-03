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
//! `async`. We bridge with [`tokio::task::block_in_place`] + the current
//! [`tokio::runtime::Handle`] — the entire pay-mcp server runs on a
//! multi-threaded Tokio runtime, so the calling thread can yield to the
//! runtime while we wait on the elicitation round-trip. This is the same
//! shape that platform gates already use (Touch ID is also a blocking
//! "wait for a human" call from Rust's view; the difference is purely
//! plumbing).
//!
//! All failure modes map to [`pay_keystore::Error::AuthDenied`]: declined
//! responses, cancelled responses, transport errors, and timeouts. The
//! caller treats any non-Accept outcome as "user did not approve".

use std::time::Duration;

use pay_keystore::{AuthGate, AuthIntent, Error as KeystoreError};
use rmcp::Peer;
use rmcp::model::{
    CreateElicitationRequestParams, CreateElicitationResult, ElicitationAction, ElicitationSchema,
};
use rmcp::service::RoleServer;
use tokio::runtime::Handle;

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
    }
}

/// `AuthGate` that asks the connected MCP client for approval via
/// `elicitation/create` instead of a platform biometric prompt.
pub struct ElicitationAuth {
    peer: Peer<RoleServer>,
}

impl ElicitationAuth {
    /// Construct a new gate bound to the active MCP session's peer.
    ///
    /// The peer is cheap to clone — it holds an inner `Arc` — so callers
    /// usually take a clone out of the rmcp tool-call context and hand it
    /// here per signing operation.
    pub fn new(peer: Peer<RoleServer>) -> Self {
        Self { peer }
    }
}

impl AuthGate for ElicitationAuth {
    fn authenticate(&self, intent: &AuthIntent) -> Result<(), KeystoreError> {
        let params = build_request(intent);
        let peer = self.peer.clone();

        // Bridge sync → async. `block_in_place` permits blocking on the
        // current multi-threaded runtime worker without starving other
        // tasks; `Handle::current().block_on` drives the elicitation
        // future to completion. Equivalent to how the macOS Touch ID
        // gate blocks the calling thread on `LAContext.evaluatePolicy`.
        let outcome: Result<CreateElicitationResult, rmcp::ServiceError> =
            tokio::task::block_in_place(|| {
                Handle::current().block_on(async move {
                    tokio::time::timeout(ELICITATION_TIMEOUT, peer.create_elicitation(params))
                        .await
                        .map_err(|_| rmcp::ServiceError::Timeout {
                            timeout: ELICITATION_TIMEOUT,
                        })?
                })
            });

        interpret_elicitation_outcome(outcome)
    }

    fn is_available(&self) -> bool {
        // We don't ping the peer here — `authenticate()` would surface a
        // transport failure as AuthDenied anyway, and is_available() is
        // called from contexts where blocking is undesirable.
        true
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
    outcome: Result<CreateElicitationResult, rmcp::ServiceError>,
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
fn build_request(intent: &AuthIntent) -> CreateElicitationRequestParams {
    // Builder validates required fields against declared properties.
    // The combination below is statically sound; `expect` would only
    // fire if rmcp's validation contract changes in a future release.
    let schema = ElicitationSchema::builder()
        .required_bool("approved")
        .build()
        .expect("required_bool registers `approved` in properties");

    CreateElicitationRequestParams::FormElicitationParams {
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
) -> CreateElicitationRequestParams {
    let schema = ElicitationSchema::builder()
        .required_bool("approved")
        .build()
        .expect("required_bool registers `approved` in properties");
    CreateElicitationRequestParams::FormElicitationParams {
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

    #[test]
    fn build_request_carries_intent_message() {
        let intent = AuthIntent::authorize_payment("$0.50", "accessing API api.example.com");
        let req = build_request(&intent);
        let CreateElicitationRequestParams::FormElicitationParams { message, .. } = req else {
            panic!("expected a form elicitation request");
        };
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
        let CreateElicitationRequestParams::FormElicitationParams {
            requested_schema, ..
        } = req
        else {
            panic!("expected a form elicitation request");
        };
        // The schema must include an `approved` property so even
        // form-rendering clients have a concrete confirmation field.
        let json = serde_json::to_value(&requested_schema).expect("schema should serialize");
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
        let CreateElicitationRequestParams::FormElicitationParams { message, .. } = req else {
            panic!("expected a form elicitation request");
        };
        assert!(message.contains("/workspace/photo.png"));
        assert!(message.contains("1024 bytes"));
        assert!(message.contains("POST"));
        assert!(message.contains("https://api.example.com/upload"));
    }

    fn result(
        action: ElicitationAction,
        content: Option<serde_json::Value>,
    ) -> CreateElicitationResult {
        CreateElicitationResult {
            action,
            content,
            meta: None,
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
}
