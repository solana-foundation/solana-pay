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
        serde_yml::from_str(&std::fs::read_to_string("tests/fixtures/test-paywall.yml").unwrap())
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
        serde_yml::from_str(&std::fs::read_to_string("tests/fixtures/test-paywall.yml").unwrap())
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
    use pay_kit::mpp::program::payment_channels::generated::generated::{
        accounts::Channel, types::SettlementWatermarks,
    };
    use pay_kit::mpp::server::session::SessionConfig;
    use pay_kit::mpp::solana_keychain::memory::MemorySigner;
    use pay_kit::mpp::{PaymentCredential, format_authorization, parse_www_authenticate};
    use pay_types::metering::ApiSpec;
    use std::str::FromStr;
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
    // The final session wire makes the server the broadcaster of the client's
    // open transaction: `process_open` re-broadcasts the payload transaction
    // and verifies the resulting on-chain channel account. Surfpool cannot run
    // the tabs program, so this test fronts the session server
    // with a canned JSON-RPC endpoint (the same pattern as pay-kit's own
    // full-path open tests) while everything above it — pay's payment
    // middleware, the challenge binding, the real client-side opener,
    // vouchers, and close — runs for real.
    let operator = Keypair::new();
    let recipient = Keypair::new();
    let client_kp = Keypair::new();
    let session_kp = Keypair::new();

    let api: ApiSpec =
        serde_yml::from_str(&std::fs::read_to_string("tests/fixtures/test-paywall.yml").unwrap())
            .unwrap();

    // Deterministic open parameters so the canned channel account below
    // matches what the real client-side opener derives from the challenge.
    let deposit = 1_000_000u64; // 1 USDC
    let salt = 42u64;
    let grace_period = 900u32;
    let challenged_slot = 33u64;
    let challenged_blockhash = solana_hash::Hash::new_from_array([7; 32]);
    let mint = solana_pubkey::Pubkey::from_str(pay_kit::mpp::mints::USDC_MAINNET).unwrap();
    let token_program =
        solana_pubkey::Pubkey::from_str(pay_kit::mpp::programs::TOKEN_PROGRAM).unwrap();
    let program_id = pay_kit::mpp::program::payment_channels::default_program_id();
    let open_params = pay_kit::mpp::program::payment_channels::OpenChannelParams {
        payer: client_kp.pubkey(),
        // The client-side opener pins rentPayer == fee payer == payer.
        rent_payer: client_kp.pubkey(),
        payee: recipient.pubkey(),
        mint,
        authorized_signer: session_kp.pubkey(),
        salt,
        open_slot: challenged_slot,
        deposit,
        grace_period,
        recipients: vec![],
        token_program,
        program_id,
    };
    let channel_id =
        pay_kit::mpp::program::payment_channels::derive_channel_addresses(&open_params).channel;
    let (_, bump) = pay_kit::mpp::program::payment_channels::find_channel_pda(
        &open_params.payer,
        &open_params.payee,
        &open_params.mint,
        &open_params.authorized_signer,
        open_params.salt,
        open_params.open_slot,
        &open_params.program_id,
    );
    let channel = Channel {
        discriminator: 1,
        version: 1,
        bump,
        status: 0,
        salt,
        deposit,
        settlement: SettlementWatermarks {
            settled: 0,
            payout_watermark: 0,
        },
        closure_started_at: 0,
        payer_withdrawn_at: 0,
        grace_period,
        distribution_hash: pay_kit::mpp::program::payment_channels::distribution_hash(&[]),
        payer: client_kp.pubkey(),
        payee: recipient.pubkey(),
        authorized_signer: session_kp.pubkey(),
        mint,
        rent_payer: client_kp.pubkey(),
        open_slot: challenged_slot,
    };
    let channel_data = borsh::to_vec(&channel).unwrap();

    // Canned Solana JSON-RPC: acknowledge the broadcast, report it finalized,
    // and serve the channel account the verified open would have created.
    let rpc_owner = program_id.to_string();
    let rpc_channel_data = channel_data.clone();
    let rpc_app = Router::new().route(
        "/",
        axum::routing::post(move |body: axum::Json<serde_json::Value>| {
            let channel_data = rpc_channel_data.clone();
            let owner = rpc_owner.clone();
            async move {
                use base64::Engine as _;
                let result = match body["method"].as_str().unwrap_or_default() {
                    "sendTransaction" => serde_json::json!(
                        pay_kit::mpp::program::payment_channels::decode_transaction(
                            body["params"][0].as_str().unwrap()
                        )
                        .unwrap()
                        .signatures[0]
                            .to_string()
                    ),
                    "getSignatureStatuses" => serde_json::json!({
                        "context": { "slot": 34 },
                        "value": [{
                            "slot": 34,
                            "confirmations": null,
                            "err": null,
                            "confirmationStatus": "finalized",
                            "status": { "Ok": null }
                        }]
                    }),
                    "getAccountInfo" => serde_json::json!({
                        "context": { "slot": 34 },
                        "value": {
                            "data": [
                                base64::engine::general_purpose::STANDARD.encode(&channel_data),
                                "base64"
                            ],
                            "executable": false,
                            "lamports": 1_000_000u64,
                            "owner": owner,
                            "rentEpoch": 0,
                            "space": channel_data.len()
                        }
                    }),
                    other => panic!("unexpected RPC method {other}"),
                };
                axum::Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": body["id"].clone(),
                    "result": result
                }))
            }
        }),
    );
    let rpc_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_url = format!("http://{}", rpc_listener.local_addr().unwrap());
    tokio::spawn(async { axum::serve(rpc_listener, rpc_app).await.unwrap() });

    // The challenge advertises the open-transaction context from this cache;
    // the client binds its open transaction to the same values.
    let blockhash_cache = pay_kit::mpp::blockhash::BlockhashCache::new();
    blockhash_cache.set(challenged_blockhash.to_string(), 100, challenged_slot);

    let session_mpp = SessionMpp::new(
        SessionConfig {
            operator: operator.pubkey().to_string(),
            recipient: recipient.pubkey().to_string(),
            currency: "USDC".to_string(),
            decimals: 6,
            network: "localnet".to_string(),
            grace_period_seconds: grace_period,
            rpc_url: Some(rpc_url.clone()),
            ..Default::default()
        },
        "test-session-secret",
    )
    .with_blockhash_cache(blockhash_cache);

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
    let session_signer: Box<dyn pay_kit::mpp::solana_keychain::SolanaSigner> =
        Box::new(MemorySigner::from_bytes(&session_kp.to_bytes()).unwrap());
    let payer_signer = MemorySigner::from_bytes(&client_kp.to_bytes()).unwrap();

    // The real client-side opener: derives the channel from the challenge,
    // builds the open transaction against the challenged `recentBlockhash`
    // and `recentSlot`, and signs it with the payer key.
    let challenged_request: pay_kit::mpp::SessionRequest = challenge.request.decode().unwrap();
    let opened = pay_kit::mpp::client::create_payment_channel_session_opener(
        &challenged_request,
        &payer_signer,
        session_signer,
        None, // bind to the challenged recentBlockhash
        pay_kit::mpp::client::PaymentChannelSessionOpenOptions {
            open: pay_kit::mpp::client::PaymentChannelOpenOptions {
                deposit: Some(deposit),
                grace_period: Some(grace_period),
                salt: Some(salt),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        opened.open.channel_id, channel_id,
        "client-derived channel must match the canned RPC account"
    );
    let mut active = opened.session;
    let auth =
        format_authorization(&PaymentCredential::new(challenge.to_echo(), opened.action)).unwrap();

    let resp = http
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
        "open should acknowledge with 402, got {}: {}",
        status, body
    );
    assert!(
        body.contains("session_voucher_required"),
        "open should request the first voucher, got: {body}"
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
    // A client-voucher close must carry the final voucher; sign one last
    // increment covering the closing request.
    let close_action = active.close_action(Some(1_000)).await.unwrap();
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
        serde_yml::from_str(&std::fs::read_to_string("tests/fixtures/test-paywall.yml").unwrap())
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
