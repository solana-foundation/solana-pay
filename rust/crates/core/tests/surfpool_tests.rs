//! Integration tests using surfpool-sdk (embedded Solana validator).
//!
//! Tests the client modules (balance, send, dev) and server modules
//! (payment middleware) against a real Solana runtime — no external
//! process needed.
//!
//! Run: `cargo test -p pay-core --features server --test surfpool_tests`

#![cfg(feature = "server")]

use pay_core::client;
use serial_test::serial;
use surfpool_sdk::{Keypair, Signer, Surfnet};

static SURFNET: tokio::sync::OnceCell<Surfnet> = tokio::sync::OnceCell::const_new();

// =============================================================================
// Helpers
// =============================================================================

async fn start_surfnet() -> &'static Surfnet {
    SURFNET
        .get_or_init(|| async {
            Surfnet::builder()
                .offline(true)
                .airdrop_sol(10_000_000_000)
                .start()
                .await
                .expect("Failed to start Surfnet")
        })
        .await
}

async fn submit_sol_transfer(
    rpc_url: &str,
    payer: &Keypair,
    recipient: &str,
    lamports: u64,
) -> String {
    use pay_kit::mpp::solana_keychain::SolanaSigner;
    use pay_kit::mpp::solana_keychain::memory::MemorySigner;
    use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;
    use solana_message::Message;
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;
    use solana_system_interface::instruction as system_instruction;
    use solana_transaction::Transaction;

    let signer = MemorySigner::from_bytes(&payer.to_bytes()).unwrap();
    let sender = signer.pubkey();
    let recipient = recipient.parse::<Pubkey>().unwrap();
    let rpc = RpcClient::new(rpc_url.to_string());
    let blockhash = rpc.get_latest_blockhash().unwrap();
    let ix = system_instruction::transfer(&sender, &recipient, lamports);
    let message = Message::new_with_blockhash(&[ix], Some(&sender), &blockhash);
    let mut tx = Transaction::new_unsigned(message);
    let sig_bytes = signer.sign_message(&tx.message_data()).await.unwrap();
    let sig = Signature::from(<[u8; 64]>::from(sig_bytes));
    let signer_index = tx
        .message
        .account_keys
        .iter()
        .position(|key| key == &sender)
        .unwrap();
    tx.signatures[signer_index] = sig;
    rpc.send_and_confirm_transaction(&tx).unwrap().to_string()
}

// =============================================================================
// balance
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn balance_funded_account() {
    let surfnet = start_surfnet().await;
    let account = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&account.pubkey(), 10_000_000_000)
        .unwrap();
    let pubkey = account.pubkey().to_string();

    let rpc = surfnet.rpc_url().to_string();
    let pk = pubkey.clone();
    let balances = client::balance::get_balances(&rpc, &pk).await.unwrap();
    assert!(
        balances.sol_lamports >= 10_000_000_000,
        "Expected >= 10 SOL, got {}",
        balances.sol_lamports
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn balance_empty_account() {
    let surfnet = start_surfnet().await;
    let empty = Keypair::new();

    let rpc = surfnet.rpc_url().to_string();
    let pk = empty.pubkey().to_string();
    let balances = client::balance::get_balances(&rpc, &pk).await.unwrap();
    assert_eq!(balances.sol_lamports, 0);
    assert!(balances.tokens.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn balance_diff_received() {
    let surfnet = start_surfnet().await;
    let account = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&account.pubkey(), 10_000_000_000)
        .unwrap();
    let pubkey = account.pubkey().to_string();

    let rpc = surfnet.rpc_url().to_string();
    let pk = pubkey.clone();
    let before = client::balance::get_balances(&rpc, &pk).await.unwrap();

    // Fund more SOL
    surfnet
        .cheatcodes()
        .fund_sol(&account.pubkey(), 15_000_000_000)
        .unwrap();

    let after = client::balance::get_balances(&rpc, &pk).await.unwrap();
    let diff = after.diff_received(&before);
    assert!(diff.sol_lamports > 0, "Should have received more SOL");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn balance_invalid_pubkey() {
    let surfnet = start_surfnet().await;
    let rpc = surfnet.rpc_url().to_string();
    let result = client::balance::get_balances(&rpc, "not-a-pubkey").await;
    assert!(result.is_err());
}

// =============================================================================
// dev
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn sandbox_setup_keypair() {
    let surfnet = start_surfnet().await;

    let rpc = surfnet.rpc_url().to_string();
    let kp = client::sandbox::setup_sandbox_keypair(&rpc).await;
    assert!(kp.is_ok(), "setup_sandbox_keypair failed: {:?}", kp.err());

    let kp = kp.unwrap();
    assert!(!kp.pubkey.is_empty());
    assert!(!kp.path.is_empty());

    // Verify the keypair is funded
    let rpc2 = surfnet.rpc_url().to_string();
    let dpk = kp.pubkey.clone();
    let balance = client::balance::get_balances(&rpc2, &dpk).await.unwrap();
    assert!(
        balance.sol_lamports >= 100_000_000_000,
        "Should have 100 SOL, got {}",
        balance.sol_lamports
    );
}

// =============================================================================
// Payment middleware with real Solana (full 402 → pay → 200 flow)
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn full_payment_flow_with_surfnet() {
    use axum::Router;
    use axum::middleware;
    use axum::routing::any;
    use pay_core::PaymentState;
    use pay_kit::mpp::server::Mpp;
    use pay_kit::mpp::solana_keychain::memory::MemorySigner;
    use pay_types::metering::ApiSpec;
    use std::sync::Arc;

    #[derive(Clone)]
    struct S {
        apis: Arc<Vec<ApiSpec>>,
        mpp: Option<Mpp>,
    }
    impl PaymentState for S {
        fn apis(&self) -> &[ApiSpec] {
            &self.apis
        }
        fn mpp(&self) -> Option<&Mpp> {
            self.mpp.as_ref()
        }
    }

    let surfnet = start_surfnet().await;
    let recipient = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let api: ApiSpec =
        serde_yml::from_str(&std::fs::read_to_string("tests/fixtures/test-provider.yml").unwrap())
            .unwrap();

    let mpp = Mpp::new(pay_kit::mpp::server::Config {
        recipient: recipient.pubkey().to_string(),
        currency: "SOL".to_string(),
        decimals: 9,
        // Surfpool is a localnet implementation. Its prefixed blockhash
        // is acceptable for `network: localnet` per the SDK's
        // asymmetric check (the only place SURFNET-prefixed hashes
        // are valid).
        network: "localnet".to_string(),
        rpc_url: Some(surfnet.rpc_url().to_string()),
        challenge_binding_secret: Some("test-secret-key-do-not-use-32b-pad".to_string()),
        ..Default::default()
    })
    .unwrap();

    let state = S {
        apis: Arc::new(vec![api]),
        mpp: Some(mpp.clone()),
    };

    let app = Router::new()
        .fallback(any(|| async {
            axum::Json(serde_json::json!({"ok": true}))
        }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<S>,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = reqwest::Client::new();

    // Step 1: Get 402
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
    let challenge = pay_kit::mpp::parse_www_authenticate(&www_auth).unwrap();

    // Step 2: Build payment
    let payer = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&payer.pubkey(), 2_000_000_000)
        .unwrap();
    let signer = MemorySigner::from_bytes(&payer.to_bytes()).unwrap();
    let rpc =
        pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient::new(surfnet.rpc_url().to_string());
    let auth = pay_kit::mpp::client::build_credential_header(&signer, &rpc, &challenge)
        .await
        .unwrap();

    // Step 3: Pay and get 200
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .header("host", "testapi.localhost")
        .header("authorization", &auth)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("payment-receipt").is_some());
}

// =============================================================================
// Replay protection — the same authorization header cannot be used twice.
//
// This test answers: "is MPP replay a real issue in pay, or already covered
// upstream by solana-mpp?" (relevant to PR #359 which adds a duplicate replay
// cache in pay-core).
//
// Result: solana-mpp's built-in `signature_consumed` check (charge.rs ~545) is
// keyed on the on-chain transaction signature and rejects the second use. The
// pay-core middleware does not need its own replay store.
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn replayed_authorization_is_rejected() {
    use axum::Router;
    use axum::middleware;
    use axum::routing::any;
    use pay_core::PaymentState;
    use pay_kit::mpp::server::Mpp;
    use pay_kit::mpp::solana_keychain::memory::MemorySigner;
    use pay_types::metering::ApiSpec;
    use std::sync::Arc;

    #[derive(Clone)]
    struct S {
        apis: Arc<Vec<ApiSpec>>,
        mpp: Option<Mpp>,
    }
    impl PaymentState for S {
        fn apis(&self) -> &[ApiSpec] {
            &self.apis
        }
        fn mpp(&self) -> Option<&Mpp> {
            self.mpp.as_ref()
        }
    }

    let surfnet = start_surfnet().await;
    let recipient = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let api: ApiSpec =
        serde_yml::from_str(&std::fs::read_to_string("tests/fixtures/test-provider.yml").unwrap())
            .unwrap();

    let mpp = Mpp::new(pay_kit::mpp::server::Config {
        recipient: recipient.pubkey().to_string(),
        currency: "SOL".to_string(),
        decimals: 9,
        network: "localnet".to_string(),
        rpc_url: Some(surfnet.rpc_url().to_string()),
        challenge_binding_secret: Some("test-secret-key-do-not-use-32b-pad".to_string()),
        ..Default::default()
    })
    .unwrap();

    let state = S {
        apis: Arc::new(vec![api]),
        mpp: Some(mpp.clone()),
    };

    let app = Router::new()
        .fallback(any(|| async {
            axum::Json(serde_json::json!({"ok": true}))
        }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<S>,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = reqwest::Client::new();

    // Step 1: Get a 402 challenge.
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
    let challenge = pay_kit::mpp::parse_www_authenticate(&www_auth).unwrap();

    // Step 2: Build a payment credential.
    let payer = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&payer.pubkey(), 2_000_000_000)
        .unwrap();
    let signer = MemorySigner::from_bytes(&payer.to_bytes()).unwrap();
    let rpc =
        pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient::new(surfnet.rpc_url().to_string());
    let auth = pay_kit::mpp::client::build_credential_header(&signer, &rpc, &challenge)
        .await
        .unwrap();

    // Step 3: First call with the credential succeeds.
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .header("host", "testapi.localhost")
        .header("authorization", &auth)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "first call should succeed");
    assert!(resp.headers().get("payment-receipt").is_some());

    // Step 4: Replay with the *same* authorization header. mpp-sdk's replay
    // protection (charge.rs `signature_consumed` check) should reject it.
    let resp = client
        .post(format!("{url}/v1/simple/echo"))
        .header("host", "testapi.localhost")
        .header("authorization", &auth)
        .body("{}")
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(
        status, 402,
        "replayed credential must not be accepted (got {status}): {body}"
    );
    assert!(
        body.to_lowercase().contains("consumed")
            || body.to_lowercase().contains("already")
            || body.to_lowercase().contains("verification"),
        "expected replay rejection in body, got: {body}"
    );

    // Step 5: Replay against a *different* metered path with the same
    // credential. The challenge HMAC pinned the original resource, so this
    // should also be rejected (credential mismatch or signature consumed).
    // Skipping `/v1/simple/other` because non-metered paths bypass the MPP
    // middleware entirely; using `/v1/translate` which is metered.
    let resp = client
        .post(format!("{url}/v1/translate"))
        .header("host", "testapi.localhost")
        .header("authorization", &auth)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        402,
        "replayed credential on a different metered route must not be accepted"
    );
}

// =============================================================================
// Session intent — push mode full lifecycle (challenge → open → voucher → close)
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn push_session_full_flow() {
    use axum::Router;
    use axum::middleware;
    use axum::routing::any;
    use pay_core::PaymentState;
    use pay_core::server::session::SessionMpp;
    use pay_kit::mpp::client::session::ActiveSession;
    use pay_kit::mpp::server::session::SessionConfig;
    use pay_kit::mpp::solana_keychain::memory::MemorySigner;
    use pay_kit::mpp::{
        PaymentCredential, SessionMode, format_authorization, parse_www_authenticate,
    };
    use pay_types::metering::ApiSpec;
    use std::sync::Arc;

    // ── App state ──────────────────────────────────────────────────────────
    #[derive(Clone)]
    struct S {
        apis: Arc<Vec<ApiSpec>>,
        session_mpp: Arc<SessionMpp>,
    }
    impl PaymentState for S {
        fn apis(&self) -> &[ApiSpec] {
            &self.apis
        }
        fn mpp(&self) -> Option<&pay_kit::mpp::server::Mpp> {
            None
        }
        fn session_mpp(&self) -> Option<&SessionMpp> {
            Some(&self.session_mpp)
        }
    }

    // ── Infrastructure ─────────────────────────────────────────────────────
    let surfnet = start_surfnet().await;
    let rpc_url = surfnet.rpc_url().to_string();

    let operator = Keypair::new();
    let recipient = Keypair::new();

    // Fund the client that will "deposit" into the session channel.
    let client_kp = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&client_kp.pubkey(), 2_000_000_000)
        .unwrap();

    let api: ApiSpec =
        serde_yml::from_str(&std::fs::read_to_string("tests/fixtures/test-provider.yml").unwrap())
            .unwrap();

    // 1 USDC cap (6 decimals). rpc_url enables on-chain signature verification.
    let session_mpp = SessionMpp::new(
        SessionConfig {
            operator: operator.pubkey().to_string(),
            recipient: recipient.pubkey().to_string(),
            max_cap: 1_000_000,
            currency: "USDC".to_string(),
            decimals: 6,
            network: "localnet".to_string(),
            modes: vec![SessionMode::Push],
            rpc_url: Some(rpc_url.clone()),
            ..Default::default()
        },
        "test-session-secret",
    );

    let state = S {
        apis: Arc::new(vec![api]),
        session_mpp: Arc::new(session_mpp),
    };

    let app = Router::new()
        .fallback(any(|| async {
            axum::Json(serde_json::json!({"ok": true}))
        }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<S>,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let http = reqwest::Client::new();

    // ── Step 1: 402 session challenge ──────────────────────────────────────
    let resp = http
        .post(format!("{url}/v1/simple/echo"))
        .header("host", "testapi.localhost")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 402, "expected 402, got {}", resp.status());

    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .expect("missing www-authenticate header")
        .to_str()
        .unwrap()
        .to_string();

    let challenge = parse_www_authenticate(&www_auth).unwrap();
    assert_eq!(
        challenge.intent.as_str(),
        "session",
        "expected session intent"
    );
    assert_eq!(challenge.method.as_str(), "solana");

    // ── Step 2: Open session ───────────────────────────────────────────────
    // Session key: any Ed25519 keypair — signs vouchers, never touches chain.
    let session_kp = Keypair::new();
    let session_signer: Box<dyn pay_kit::mpp::solana_keychain::SolanaSigner> =
        Box::new(MemorySigner::from_bytes(&session_kp.to_bytes()).unwrap());

    // Submit a real SOL transfer to surfpool as a stand-in for the Fiber
    // channel open. The server verifies this tx is confirmed on-chain before
    // accepting the open.
    let open_tx_sig = submit_sol_transfer(
        &rpc_url,
        &client_kp,
        &operator.pubkey().to_string(),
        10_000_000,
    )
    .await;

    // Channel ID is any valid Solana pubkey (would be the real Fiber channel
    // in production; here it's just a key for the in-memory store).
    let channel_id = Keypair::new().pubkey();
    let mut active = ActiveSession::new(channel_id, session_signer);

    let deposit = 1_000_000u64; // 1 USDC
    let open_action = active.open_action(deposit, &open_tx_sig);
    let auth =
        format_authorization(&PaymentCredential::new(challenge.to_echo(), open_action)).unwrap();

    let resp = http
        .post(format!("{url}/v1/simple/echo"))
        .header("host", "testapi.localhost")
        .header("authorization", &auth)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        402,
        "open should acknowledge with 402, got {}: {}",
        resp.status(),
        resp.text().await.unwrap()
    );

    // ── Step 3: Voucher (subsequent API call) ──────────────────────────────
    let voucher_action = active.voucher_action(1_000).await.unwrap(); // 0.001 USDC
    let auth =
        format_authorization(&PaymentCredential::new(challenge.to_echo(), voucher_action)).unwrap();

    let resp = http
        .post(format!("{url}/v1/simple/echo"))
        .header("host", "testapi.localhost")
        .header("authorization", &auth)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "voucher should return 200, got {}",
        resp.status()
    );

    // Second voucher — watermark advances
    let voucher_action = active.voucher_action(1_000).await.unwrap();
    let auth =
        format_authorization(&PaymentCredential::new(challenge.to_echo(), voucher_action)).unwrap();

    let resp = http
        .post(format!("{url}/v1/simple/echo"))
        .header("host", "testapi.localhost")
        .header("authorization", &auth)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "second voucher should return 200");

    // ── Step 4: Close session ──────────────────────────────────────────────
    let close_action = active.close_action(None).await.unwrap();
    let auth =
        format_authorization(&PaymentCredential::new(challenge.to_echo(), close_action)).unwrap();

    let resp = http
        .post(format!("{url}/v1/simple/echo"))
        .header("host", "testapi.localhost")
        .header("authorization", &auth)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "close should return 200, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["status"], "closed",
        "expected closed status, got {body}"
    );
}

// =============================================================================
// MPP build_credential (pay_core::client::mpp)
// =============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn mpp_build_credential_with_surfnet() {
    use axum::Router;
    use axum::middleware;
    use axum::routing::any;
    use pay_core::PaymentState;

    use pay_kit::mpp::server::Mpp;
    use pay_types::metering::ApiSpec;
    use std::sync::Arc;

    #[derive(Clone)]
    struct S {
        apis: Arc<Vec<ApiSpec>>,
        mpp: Option<Mpp>,
    }
    impl PaymentState for S {
        fn apis(&self) -> &[ApiSpec] {
            &self.apis
        }
        fn mpp(&self) -> Option<&Mpp> {
            self.mpp.as_ref()
        }
    }

    let surfnet = start_surfnet().await;
    let recipient = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let api: ApiSpec =
        serde_yml::from_str(&std::fs::read_to_string("tests/fixtures/test-provider.yml").unwrap())
            .unwrap();

    let mpp = Mpp::new(pay_kit::mpp::server::Config {
        recipient: recipient.pubkey().to_string(),
        currency: "SOL".to_string(),
        decimals: 9,
        // Surfpool is a localnet implementation. Its prefixed blockhash
        // is acceptable for `network: localnet` per the SDK's
        // asymmetric check (the only place SURFNET-prefixed hashes
        // are valid).
        network: "localnet".to_string(),
        rpc_url: Some(surfnet.rpc_url().to_string()),
        challenge_binding_secret: Some("test-secret-key-do-not-use-32b-pad".to_string()),
        ..Default::default()
    })
    .unwrap();

    let state = S {
        apis: Arc::new(vec![api]),
        mpp: Some(mpp),
    };

    let app = Router::new()
        .fallback(any(|| async {
            axum::Json(serde_json::json!({"ok": true}))
        }))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            pay_core::server::payment::payment_middleware::<S>,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Step 1: Get a 402 challenge
    let http = reqwest::Client::new();
    let resp = http
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
    let challenge = client::mpp::parse(&www_auth).unwrap();

    // Step 2: Create a funded payer (the new network-aware path takes
    // raw secret bytes via a MemoryAccountsStore, no temp file needed).
    let payer = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&payer.pubkey(), 2_000_000_000)
        .unwrap();

    // Step 3: Build credential using pay_core's network-aware path.
    //
    // Inject the test payer into a MemoryAccountsStore as an ephemeral
    // account mapped to `localnet` — that's how the new
    // `build_credential(challenge, store, network_override, account_override, resource_url)` API
    // resolves the wallet (no more `active_account_name: &str`).
    //
    // build_credential creates its own tokio runtime, so we drive it
    // from a blocking thread.
    let rpc_url = surfnet.rpc_url().to_string();
    let challenge_clone = challenge.clone();
    let payer_bytes = payer.to_bytes().to_vec();
    let payer_pubkey = payer.pubkey().to_string();
    let auth = tokio::task::spawn_blocking(move || {
        // SAFETY: test-only env manipulation, runs before any other
        // threads in this closure.
        unsafe { std::env::set_var("PAY_RPC_URL", &rpc_url) };

        let mut file = pay_core::accounts::AccountsFile::default();
        file.upsert(
            "localnet",
            "default",
            pay_core::accounts::Account {
                keystore: pay_core::accounts::Keystore::Ephemeral,
                active: false,
                auth_required: Some(false),
                pubkey: Some(payer_pubkey),
                vault: None,
                account: None,
                path: None,
                secret_key_b58: Some(bs58::encode(&payer_bytes).into_string()),
                created_at: Some("2026-04-10T00:00:00Z".to_string()),
                subscriptions: std::collections::BTreeMap::new(),
            },
        );
        let store = pay_core::accounts::MemoryAccountsStore::with_file(file);

        let result =
            client::mpp::build_credential(&challenge_clone, &store, Some("localnet"), None, None);
        unsafe { std::env::remove_var("PAY_RPC_URL") };
        result
    })
    .await
    .unwrap();

    assert!(auth.is_ok(), "build_credential failed: {:?}", auth.err());
    let (auth, ephemeral) = auth.unwrap();
    assert!(!auth.is_empty());
    assert!(
        ephemeral.is_none(),
        "should be a cache hit (we pre-populated the store)"
    );

    // Step 4: Use the credential — should get 200
    let resp = http
        .post(format!("{url}/v1/simple/echo"))
        .header("host", "testapi.localhost")
        .header("authorization", &auth)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
