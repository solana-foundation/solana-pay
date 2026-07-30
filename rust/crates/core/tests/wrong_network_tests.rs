//! End-to-end test for the SDK's "wrong network" rejection.
//!
//! Validates that when the pay-server is configured for the sandbox network
//! and a client signs a transaction against a real cluster (or vice versa),
//! the SDK's `check_network_blockhash` fires *before* any RPC simulation
//! and the resulting verification error is surfaced through the payment
//! middleware as a `verification_failed` 402 body whose `message` carries
//! the explicit "expected X, received Y" context.
//!
//! This is the cross-repo integration test for the change in
//! `pay-kit/rust/crates/mpp/src/server/mod.rs::check_network_blockhash` —
//! exercising it through pay-core's HTTP middleware (not just the SDK
//! function in isolation, which is unit-tested in the SDK itself).
//!
//! Run: `cargo test -p pay-core --features server --test wrong_network_tests`

#![cfg(feature = "server")]

use axum::Router;
use axum::body::Body;
use axum::http::Request;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::any;
use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey};
use pay_core::PaymentState;
use pay_kit::mpp::server::Mpp;
use pay_kit::mpp::{ChargeRequest, format_authorization, parse_www_authenticate};
use pay_types::metering::ApiSpec;
use serde_json::Value;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;
use std::str::FromStr;
use std::sync::Arc;

// ── Test app state ──────────────────────────────────────────────────────────

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

async fn echo_handler(_req: Request<Body>) -> impl IntoResponse {
    axum::Json(serde_json::json!({"upstream": "ok"}))
}

/// Build a pay-core test server with the given network slug. The server
/// uses an unreachable RPC URL so the test fails fast if the SDK *doesn't*
/// reject the credential pre-broadcast (i.e. if the network check is
/// silently bypassed, the test will hang/time-out on the broadcast attempt
/// instead of giving a misleading green).
async fn start_server_with_network(network: &str) -> (String, tokio::task::JoinHandle<()>) {
    let api: ApiSpec =
        serde_yml::from_str(&std::fs::read_to_string("tests/fixtures/test-paywall.yml").unwrap())
            .unwrap();

    let mpp = Mpp::new(pay_kit::mpp::server::Config {
        recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
        currency: "SOL".to_string(),
        decimals: 9,
        network: network.to_string(),
        // Unreachable RPC — the test must error before any RPC call.
        rpc_url: Some("http://127.0.0.1:1/never".to_string()),
        challenge_binding_secret: Some("test-secret-key-do-not-use-32b-pad".to_string()),
        ..Default::default()
    })
    .unwrap();

    let state = TestState {
        apis: Arc::new(vec![api]),
        mpp: Some(mpp),
    };

    let app = Router::new()
        .fallback(any(echo_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<TestState>,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (url, handle)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Build a real signed Solana Transaction with a chosen blockhash, then
/// wrap it as the `transaction` payload of an MPP credential and return
/// the Authorization header value.
///
/// The transaction itself doesn't need to be valid on-chain — the SDK
/// rejects it on the network/blockhash mismatch before doing any
/// instruction inspection or RPC simulation.
fn build_credential_with_blockhash(
    challenge: &pay_kit::mpp::PaymentChallenge,
    payer: &SigningKey,
    recent_blockhash: Hash,
) -> String {
    let payer_pk_bytes = payer.verifying_key().to_bytes();
    let payer_pk = Pubkey::new_from_array(payer_pk_bytes);
    let recipient = Pubkey::from_str("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY").unwrap();

    // Minimal System Program transfer instruction. Content is irrelevant —
    // the SDK rejects on the blockhash before reading instructions.
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes()); // Transfer = 2
    data.extend_from_slice(&1_000_000u64.to_le_bytes()); // 0.001 SOL
    let ix = Instruction {
        program_id: Pubkey::from_str("11111111111111111111111111111111").unwrap(),
        accounts: vec![
            AccountMeta::new(payer_pk, true),
            AccountMeta::new(recipient, false),
        ],
        data,
    };

    let message = Message::new_with_blockhash(&[ix], Some(&payer_pk), &recent_blockhash);
    let mut tx = Transaction::new_unsigned(message);

    // Sign the transaction message with the payer's ed25519 key directly.
    // We bypass the async SolanaSigner trait because the test is sync and
    // only needs one signature.
    let msg_data = tx.message_data();
    let sig = payer.sign(&msg_data);
    tx.signatures = vec![solana_signature::Signature::from(sig.to_bytes())];

    let tx_bytes = bincode::serialize(&tx).unwrap();
    let tx_b64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);

    let payload = serde_json::json!({
        "type": "transaction",
        "transaction": tx_b64,
    });
    let credential = pay_kit::mpp::PaymentCredential::new(challenge.to_echo(), payload);
    format_authorization(&credential).unwrap()
}

/// Generate a fresh ed25519 keypair for the test "client".
fn fresh_payer() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

/// A blockhash whose first base58 characters START with the Surfpool
/// prefix. Constructed by base58-decoding the literal Surfpool-shaped
/// string into 32 raw bytes (right-padded with zeros if needed) — that's
/// what ends up in `tx.message.recent_blockhash`, and the SDK re-encodes
/// it for the prefix check.
fn surfpool_blockhash_from_prefix() -> Hash {
    let s = "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad";
    let bytes = bs58::decode(s).into_vec().expect("base58 decode");
    let mut arr = [0u8; 32];
    let take = bytes.len().min(32);
    let off = 32 - take;
    arr[off..].copy_from_slice(&bytes[..take]);
    Hash::new_from_array(arr)
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Server is configured for `network: "mainnet"` and the client signs a
/// transaction with a Surfpool-prefixed (localnet) blockhash. Expect a
/// 402 response whose JSON body contains `verification_failed` with
/// "expected mainnet / received localnet" context.
///
/// This is the actual bug case from the user report: somebody on a
/// real-money server gets a credential signed against a Surfpool RPC.
/// The check must fire BEFORE the RPC simulate (the test server points
/// at an unreachable URL specifically to fail-loud if the check is
/// silently bypassed).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mainnet_server_rejects_surfpool_blockhash() {
    let (url, _h) = start_server_with_network("mainnet").await;

    // Step 1: get a fresh challenge from the server.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .header("host", "testapi.localhost")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 402, "expected initial 402");
    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .expect("www-authenticate header")
        .to_str()
        .unwrap()
        .to_string();
    let challenge = parse_www_authenticate(&www_auth).expect("parse challenge");

    // Sanity: the challenge advertises mainnet.
    let req: ChargeRequest = challenge.request.decode().unwrap();
    let advertised_network = req
        .method_details
        .as_ref()
        .and_then(|v| v.get("network"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(advertised_network, "mainnet");

    // Step 2: build a credential whose embedded transaction has a
    // Surfpool-prefixed (localnet) blockhash. This is what a misconfigured
    // client signs when it points at the local Surfpool RPC by mistake.
    let payer = fresh_payer();
    let auth_header =
        build_credential_with_blockhash(&challenge, &payer, surfpool_blockhash_from_prefix());

    // Step 3: send it back. The SDK must reject before reaching the bogus
    // RPC URL, so the response arrives in milliseconds — not after an
    // RPC connect timeout.
    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client
            .post(format!("{url}/v1/simple/echo"))
            .header("host", "testapi.localhost")
            .header("authorization", &auth_header)
            .body("{}")
            .send(),
    )
    .await
    .expect("retry must complete fast — if this times out, the SDK didn't reject pre-broadcast")
    .unwrap();

    assert_eq!(resp.status(), 402, "expected 402 verification_failed");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"].as_str(),
        Some("verification_failed"),
        "body should be verification_failed shape: {body}"
    );
    let message = body["message"].as_str().unwrap_or("");
    // The SDK message names both sides of the mismatch + an actionable hint.
    assert!(
        message.contains("Signed against localnet"),
        "missing received-side in: {message}"
    );
    assert!(
        message.contains("server expects mainnet"),
        "missing expected-side in: {message}"
    );
    assert!(
        message.contains("re-sign"),
        "missing actionable hint in: {message}"
    );
    // The bracketed code prefix must NOT leak into the user-facing
    // message — the structured `code` field is for that.
    assert!(
        !message.contains("[wrong-network]"),
        "SDK leaked debug-style code prefix into Display: {message}"
    );
}

/// Same shape but for `devnet` server — the prefix check should fire
/// for any non-localnet network slug, not just mainnet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn devnet_server_rejects_surfpool_blockhash() {
    let (url, _h) = start_server_with_network("devnet").await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .header("host", "testapi.localhost")
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
        .unwrap()
        .to_string();
    let challenge = parse_www_authenticate(&www_auth).unwrap();

    let payer = fresh_payer();
    let auth_header =
        build_credential_with_blockhash(&challenge, &payer, surfpool_blockhash_from_prefix());

    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client
            .post(format!("{url}/v1/simple/echo"))
            .header("host", "testapi.localhost")
            .header("authorization", &auth_header)
            .body("{}")
            .send(),
    )
    .await
    .expect("retry must complete fast")
    .unwrap();

    assert_eq!(resp.status(), 402);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"].as_str(), Some("verification_failed"));
    let message = body["message"].as_str().unwrap_or("");
    assert!(
        message.contains("server expects devnet"),
        "missing expected-side in: {message}"
    );
    assert!(
        message.contains("Signed against localnet"),
        "missing received-side in: {message}"
    );
}

/// Negative test: a localnet-configured server MUST accept a Surfpool-
/// prefixed blockhash, since `localnet` is the one network where the
/// prefix is legitimate. Without this test we'd have no protection
/// against an over-eager check that rejects valid sandbox traffic.
///
/// We deliberately use a non-existent recipient instruction so the
/// downstream `verify_transaction_pre_broadcast` will fail — but with
/// a *different* error code than `wrong-network`. That proves the
/// blockhash check let the credential through and the failure came
/// from a later stage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn localnet_server_accepts_surfpool_blockhash() {
    let (url, _h) = start_server_with_network("localnet").await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .header("host", "testapi.localhost")
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
        .unwrap()
        .to_string();
    let challenge = parse_www_authenticate(&www_auth).unwrap();

    let payer = fresh_payer();
    let auth_header =
        build_credential_with_blockhash(&challenge, &payer, surfpool_blockhash_from_prefix());

    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client
            .post(format!("{url}/v1/simple/echo"))
            .header("host", "testapi.localhost")
            .header("authorization", &auth_header)
            .body("{}")
            .send(),
    )
    .await
    .expect("retry must complete fast")
    .unwrap();

    // The SDK rejects later in the pipeline (amount mismatch, bad
    // recipient, or sim/broadcast failure) — but NOT with the
    // wrong-network shape. We assert the absence of the wrong-network
    // marker phrases rather than asserting on a specific success path,
    // because the post-blockhash steps depend on RPC reachability and
    // we don't want the test brittle on RPC behavior.
    if resp.status() == 402 {
        let body: Value = resp.json().await.unwrap();
        let message = body["message"].as_str().unwrap_or("");
        assert!(
            !message.contains("Signed against localnet"),
            "blockhash check should NOT fire on localnet: {message}"
        );
        assert!(
            !message.contains("server expects"),
            "blockhash check should NOT fire on localnet: {message}"
        );
    }
}

// Note: the runner's `classify_402` body parser also routes the same JSON
// shape into `RunOutcome::PaymentRejected` so the CLI can render its
// notice. That parser is unit-tested directly in `runner.rs::tests::*`
// (9 cases covering happy path, missing fields, wrong error, non-JSON,
// edge strings, and precedence over a fresh challenge), so we don't need
// a third HTTP-level test here — it would only re-exercise the same
// parser through `fetch::fetch`, and `fetch::fetch` only does GET while
// our metered fixture endpoints are POST.
