//! End-to-end-shaped tests for the subscription intent.
//!
//! v0 covers the pieces pay owns end-to-end without an on-chain settlement
//! step:
//!
//! - Server builds a 402 challenge from a `SubscriptionEndpoint` config.
//! - Client classifies the challenge as `SubscriptionChallenge`.
//! - Client decodes the challenge into typed fields.
//! - Receipt parsing pulls subscription extensions out of a base64url
//!   `Payment-Receipt` header.
//! - `AccountsFile::upsert_subscription` round-trips the persisted entry.
//!
//! The on-chain activation broadcast + server-side verify path are not yet
//! implemented — when they land, this file is the natural home for a true
//! Surfpool-backed flow.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use pay_core::accounts::{
    Account, AccountsFile, AccountsStore, Keystore, MemoryAccountsStore, Subscription,
    SubscriptionStatus,
};
use pay_core::client::subscription as sub_client;
use pay_core::runner::{RunOutcome, classify_402};
use pay_core::server::subscription as sub_server;
use pay_types::metering::SubscriptionEndpoint;

const PLAN: &str = "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT";
const OPERATOR: &str = "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h";

fn spec() -> SubscriptionEndpoint {
    SubscriptionEndpoint {
        period: "30d".into(),
        price_usd: Some(9.99),
        amount_base_units: None,
        currency: "USDC".into(),
        expires_at: None,
        plan_id: Some(PLAN.into()),
        plan_id_numeric: Some(42),
        plan_bump: Some(254),
        plan_created_at: Some(1_770_000_000),
        puller: None,
        recipient: None,
        free_trial_days: None,
    }
}

fn defaults<'a>() -> sub_server::OperatorDefaults<'a> {
    sub_server::OperatorDefaults {
        puller: OPERATOR,
        recipient: OPERATOR,
        network: "localnet",
        rpc_url: "http://localhost:8899",
        challenge_binding_secret: Some("test-secret-key-do-not-use-32b-pad"),
        realm: Some("test-realm"),
        fee_payer: false,
        fee_payer_signer: None,
    }
}

#[test]
fn ag9_demo_spec_is_valid_and_sandbox_only() {
    let spec: pay_types::metering::ApiSpec =
        serde_yml::from_str(include_str!("../../../ag9-subscription-demo.yaml"))
            .expect("demo spec should parse");
    assert!(pay_types::metering::validate_api_spec(&spec).is_empty());
    assert_eq!(
        spec.operator
            .as_ref()
            .and_then(|operator| operator.network.as_deref()),
        Some("localnet")
    );
    let subscription = spec.endpoints[0]
        .subscription
        .as_ref()
        .expect("subscription endpoint");
    assert_eq!(subscription.period, "1d");
    assert_eq!(subscription.price_usd, Some(0.10));
}

#[test]
fn server_built_challenge_round_trips_through_client_classify_and_decode() {
    // 1. Server builds the challenge.
    let challenge = sub_server::build_challenge(&spec(), defaults(), None).expect("challenge");
    let www_auth =
        pay_kit::mpp::format_www_authenticate(&challenge).expect("format WWW-Authenticate");

    // 2. Classify the 402 — it must route to SubscriptionChallenge.
    let headers = vec![("www-authenticate".to_string(), www_auth)];
    let outcome = classify_402(&headers, None, "https://example.com/api/v1/pro/feed");
    let challenge = match outcome {
        RunOutcome::SubscriptionChallenge { challenge, .. } => challenge,
        other => panic!("expected SubscriptionChallenge, got {other:?}"),
    };

    // 3. Client decodes the challenge into typed fields. This verifies the
    //    server's `methodDetails` shape matches what the client expects —
    //    they were authored independently and could drift.
    let decoded = sub_client::decode(&challenge).expect("decode");
    assert_eq!(decoded.method_details.plan_id, PLAN);
    assert_eq!(decoded.method_details.puller, OPERATOR);
    assert_eq!(decoded.amount_base_units, "9990000");
    assert_eq!(decoded.period_count, 30);
    assert_eq!(decoded.currency_label, "USDC");
    assert_eq!(decoded.decimals, 6);
}

#[test]
fn receipt_parser_extracts_subscription_extensions() {
    let payload = serde_json::json!({
        "method": "solana",
        "status": "success",
        "timestamp": "2026-05-29T12:03:10Z",
        "reference": "5J8signature",
        "subscriptionId": "BXQGmO5VwTrl5RfFr6Y8XQZ4nPj9QqMOiKkRn3pZ4ZE",
        "planId": PLAN,
        "periodIndex": "0",
        "periodStartTs": "2026-05-29T12:03:10Z",
        "periodEndTs": "2026-06-28T12:03:10Z",
    });
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let parsed = sub_client::parse_subscription_receipt(&header).expect("receipt");

    assert_eq!(parsed.reference, "5J8signature");
    assert_eq!(
        parsed.extensions.subscription_id,
        "BXQGmO5VwTrl5RfFr6Y8XQZ4nPj9QqMOiKkRn3pZ4ZE"
    );
    assert_eq!(parsed.extensions.plan_id, PLAN);
    assert_eq!(parsed.extensions.period_index, "0");
}

#[test]
fn persistence_round_trip_through_memory_store() {
    // Seed an account under `localnet/default` so the subscription has an
    // owner to attach to. The fields don't need to be realistic — the
    // upsert path validates only that `(network, account_name)` exists.
    let mut file = AccountsFile::default();
    file.upsert(
        "localnet",
        "default",
        Account {
            keystore: Keystore::Ephemeral,
            active: true,
            auth_required: Some(false),
            pubkey: Some("LocalSubscriber11111111111111111111111111111".to_string()),
            vault: None,
            account: None,
            path: None,
            secret_key_b58: Some("test-secret-bytes".to_string()),
            created_at: Some("2026-05-29T00:00:00Z".to_string()),
            subscriptions: std::collections::BTreeMap::new(),
        },
    );

    let store = MemoryAccountsStore::with_file(file);

    let subscription = Subscription {
        subscription_id: "BXQGmO5VwTrl5RfFr6Y8XQZ4nPj9QqMOiKkRn3pZ4ZE".to_string(),
        plan_id: PLAN.to_string(),
        program_id: None,
        mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
        currency: Some("USDC".to_string()),
        amount_per_period: "9990000".to_string(),
        period_unit: "day".to_string(),
        period_count: 30,
        recipient: OPERATOR.to_string(),
        puller: OPERATOR.to_string(),
        network: "localnet".to_string(),
        status: SubscriptionStatus::Active,
        activated_at: "2026-05-29T12:03:10Z".to_string(),
        activation_signature: "5J8signature".to_string(),
        last_charged_period: Some(0),
        expires_at: None,
        resource_url: Some("http://localhost:8080/api/v1/pro/feed".to_string()),
        description: Some("Pro feed".to_string()),
        authenticate_token: None,
        authenticate_expires_at: None,
    };

    let mut file = store.load().unwrap();
    file.upsert_subscription("localnet", "default", subscription.clone())
        .expect("upsert");
    store.save(&file).unwrap();

    // Re-load and confirm round-trip.
    let loaded = store.load().unwrap();
    let stored = loaded
        .find_subscription("localnet", "default", &subscription.subscription_id)
        .expect("subscription should be present");
    assert_eq!(stored, &subscription);

    // `all_subscriptions` surfaces the row across the iterator.
    let collected: Vec<_> = loaded
        .all_subscriptions()
        .map(|(net, name, sub)| {
            (
                net.to_string(),
                name.to_string(),
                sub.subscription_id.clone(),
            )
        })
        .collect();
    assert_eq!(collected.len(), 1);
    assert_eq!(collected[0].0, "localnet");
    assert_eq!(collected[0].1, "default");
}

#[test]
fn server_subscription_resolve_amount_matches_client_decoded_amount() {
    // Cross-check: the server-side base-unit conversion lines up with what
    // the client extracts from the challenge JSON. If these ever drift we
    // get silent over/under-charging — pin them with a single assertion.
    let (server_amount, decimals, _mint) =
        sub_server::resolve_amount(&spec()).expect("server amount");
    assert_eq!(decimals, 6);

    let challenge = sub_server::build_challenge(&spec(), defaults(), None).expect("challenge");
    let decoded = sub_client::decode(&challenge).expect("decode");

    assert_eq!(server_amount, decoded.amount_base_units);
}
