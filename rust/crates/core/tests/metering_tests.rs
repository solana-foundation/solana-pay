//! Metering engine tests.
//!
//! Tests the price resolution logic against every metering pattern
//! defined in the test paywall YAML.
//!
//! Run: `cargo test -p pay-core --features server --test metering_tests`

use pay_core::server::metering::{self, MeteringContext, RequestProperties, ResolvedPrice};
use pay_core::{AccountingKey, AccountingStore, InMemoryStore};
use pay_types::metering::{AccountingMode, ApiSpec};
use std::path::Path;

fn load_test_api() -> ApiSpec {
    let content = std::fs::read_to_string(Path::new("tests/fixtures/test-paywall.yml")).unwrap();
    serde_yml::from_str(&content).unwrap()
}

fn price_for(p: &Option<ResolvedPrice>, direction: &str) -> f64 {
    p.as_ref()
        .unwrap()
        .dimensions
        .iter()
        .find(|d| d.direction == direction)
        .map(|d| d.price_usd)
        .unwrap_or(-1.0)
}

fn single_price(p: &Option<ResolvedPrice>) -> f64 {
    p.as_ref().unwrap().dimensions[0].price_usd
}

// =============================================================================
// Fixture loading
// =============================================================================

#[test]
fn fixture_loads() {
    let api = load_test_api();
    assert_eq!(api.name, "testapi");
    assert!(api.endpoints.len() > 10);
}

// =============================================================================
// Endpoint matching
// =============================================================================

#[test]
fn match_exact_path() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "GET", "v1/health");
    assert!(ep.is_some());
    assert_eq!(ep.unwrap().path, "v1/health");
}

#[test]
fn match_wildcard_segment() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/models/pro:generate");
    assert!(ep.is_some());
    assert_eq!(ep.unwrap().path, "v1/models/{modelId}:generate");
}

#[test]
fn match_wildcard_any_value() {
    let api = load_test_api();
    assert!(metering::find_endpoint(&api, "POST", "v1/models/anything:generate").is_some());
    assert!(metering::find_endpoint(&api, "POST", "v1/models/x:generate").is_some());
    assert!(metering::find_endpoint(&api, "GET", "v1/models/some-model").is_some());
}

#[test]
fn no_match_wrong_method() {
    let api = load_test_api();
    assert!(metering::find_endpoint(&api, "DELETE", "v1/health").is_none());
    assert!(metering::find_endpoint(&api, "GET", "v1/simple/echo").is_none());
}

#[test]
fn no_match_nonexistent_path() {
    let api = load_test_api();
    assert!(metering::find_endpoint(&api, "GET", "v1/does/not/exist").is_none());
}

#[test]
fn no_match_partial_path() {
    let api = load_test_api();
    assert!(metering::find_endpoint(&api, "GET", "v1").is_none());
    assert!(metering::find_endpoint(&api, "GET", "v1/models/a/b/c").is_none());
}

#[test]
fn match_preserves_action_suffix() {
    let api = load_test_api();
    // :generate should match, :chat should match a different endpoint
    let gen_ep = metering::find_endpoint(&api, "POST", "v1/models/x:generate").unwrap();
    let chat = metering::find_endpoint(&api, "POST", "v1/models/x:chat").unwrap();
    assert!(gen_ep.path.contains("generate"));
    assert!(chat.path.contains("chat"));
    assert_ne!(gen_ep.path, chat.path);
}

// =============================================================================
// Free endpoints
// =============================================================================

#[test]
fn free_endpoint_no_metering() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "GET", "v1/health").unwrap();
    assert!(ep.metering.is_none());
}

#[test]
fn free_endpoint_list() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "GET", "v1/models").unwrap();
    assert!(ep.metering.is_none());
}

#[test]
fn free_endpoint_returns_none_price() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "GET", "v1/health").unwrap();
    assert!(ep.metering.is_none());
    // No metering → resolve_price should not be called, but if it were:
    // there's no Metering struct to pass.
}

// =============================================================================
// Flat price
// =============================================================================

#[test]
fn flat_price_single_value() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/simple/echo").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, None);
    assert_eq!(single_price(&price), 0.001);
}

#[test]
fn flat_price_ignores_request_properties() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/simple/echo").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        body_size: Some(999_999),
        context_length: Some(500_000),
        input_tokens: Some(1_000_000),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, None, None);
    assert_eq!(single_price(&price), 0.001);
}

// =============================================================================
// Volume tiers
// =============================================================================

#[test]
fn volume_402_quote_uses_first_non_free() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/volume/annotate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    // No accounting context → 402 quote → first non-free tier
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, None);
    assert_eq!(single_price(&price), 1.50);
}

#[test]
fn volume_free_tier_with_accounting() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/volume/annotate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let store = InMemoryStore::new();
    let ctx = MeteringContext {
        api_name: "testapi",
        endpoint_path: "v1/volume/annotate",
        accounting_mode: &AccountingMode::Pooled,
        store: &store,
        wallet: None,
    };
    // Usage = 0 → free tier
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, Some(&ctx));
    assert_eq!(single_price(&price), 0.0);
}

#[test]
fn volume_standard_tier_with_accounting() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/volume/annotate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let store = InMemoryStore::new();
    let key = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/volume/annotate".to_string(),
        period: pay_core::current_period(),
        scope: "pool".to_string(),
    };
    store.increment(&key, 1001);
    let ctx = MeteringContext {
        api_name: "testapi",
        endpoint_path: "v1/volume/annotate",
        accounting_mode: &AccountingMode::Pooled,
        store: &store,
        wallet: None,
    };
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, Some(&ctx));
    assert_eq!(single_price(&price), 1.50);
}

#[test]
fn volume_discount_tier_with_accounting() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/volume/annotate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let store = InMemoryStore::new();
    let key = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/volume/annotate".to_string(),
        period: pay_core::current_period(),
        scope: "pool".to_string(),
    };
    store.increment(&key, 5_000_001);
    let ctx = MeteringContext {
        api_name: "testapi",
        endpoint_path: "v1/volume/annotate",
        accounting_mode: &AccountingMode::Pooled,
        store: &store,
        wallet: None,
    };
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, Some(&ctx));
    assert_eq!(single_price(&price), 1.00);
}

#[test]
fn volume_tier_boundary_exact() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/volume/annotate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let store = InMemoryStore::new();
    let key = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/volume/annotate".to_string(),
        period: pay_core::current_period(),
        scope: "pool".to_string(),
    };
    // Exactly at boundary: 1000 → still free (up_to is inclusive)
    store.increment(&key, 1000);
    let ctx = MeteringContext {
        api_name: "testapi",
        endpoint_path: "v1/volume/annotate",
        accounting_mode: &AccountingMode::Pooled,
        store: &store,
        wallet: None,
    };
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, Some(&ctx));
    assert_eq!(single_price(&price), 0.0);

    // 5_000_000 → still standard (up_to is inclusive)
    store.increment(&key, 5_000_000 - 1000);
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, Some(&ctx));
    assert_eq!(single_price(&price), 1.50);
}

// =============================================================================
// Per-agent vs pooled accounting
// =============================================================================

#[test]
fn per_agent_isolation() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/volume/annotate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let store = InMemoryStore::new();

    let key_a = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/volume/annotate".to_string(),
        period: pay_core::current_period(),
        scope: "wallet_aaa".to_string(),
    };
    let key_b = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/volume/annotate".to_string(),
        period: pay_core::current_period(),
        scope: "wallet_bbb".to_string(),
    };

    store.increment(&key_a, 500); // free tier
    store.increment(&key_b, 2000); // standard tier

    let ctx_a = MeteringContext {
        api_name: "testapi",
        endpoint_path: "v1/volume/annotate",
        accounting_mode: &AccountingMode::PerAgent,
        store: &store,
        wallet: Some("wallet_aaa"),
    };
    let ctx_b = MeteringContext {
        api_name: "testapi",
        endpoint_path: "v1/volume/annotate",
        accounting_mode: &AccountingMode::PerAgent,
        store: &store,
        wallet: Some("wallet_bbb"),
    };

    let price_a = metering::resolve_price(meter, &RequestProperties::default(), None, Some(&ctx_a));
    let price_b = metering::resolve_price(meter, &RequestProperties::default(), None, Some(&ctx_b));

    assert_eq!(single_price(&price_a), 0.0); // agent A is free
    assert_eq!(single_price(&price_b), 1.50); // agent B is standard
}

#[test]
fn pooled_mode_uses_pool_scope() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/volume/annotate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let store = InMemoryStore::new();

    let pool_key = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/volume/annotate".to_string(),
        period: pay_core::current_period(),
        scope: "pool".to_string(),
    };
    store.increment(&pool_key, 2000);

    // Even though wallet is specified, pooled mode uses "pool" scope.
    let ctx = MeteringContext {
        api_name: "testapi",
        endpoint_path: "v1/volume/annotate",
        accounting_mode: &AccountingMode::Pooled,
        store: &store,
        wallet: Some("wallet_aaa"),
    };
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, Some(&ctx));
    assert_eq!(single_price(&price), 1.50);
}

// =============================================================================
// Conditional tiers (context_length)
// =============================================================================

#[test]
fn conditional_short_context() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/conditional/generate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        context_length: Some(100_000),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, None, None);
    assert_eq!(price_for(&price, "input"), 1.00);
    assert_eq!(price_for(&price, "output"), 4.00);
}

#[test]
fn conditional_long_context() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/conditional/generate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        context_length: Some(300_000),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, None, None);
    assert_eq!(price_for(&price, "input"), 2.00);
    assert_eq!(price_for(&price, "output"), 8.00);
}

#[test]
fn conditional_exact_boundary() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/conditional/generate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    // Exactly 200000 → should match <= 200000 (first tier)
    let props = RequestProperties {
        context_length: Some(200_000),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, None, None);
    assert_eq!(price_for(&price, "input"), 1.00);
}

#[test]
fn conditional_boundary_plus_one() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/conditional/generate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        context_length: Some(200_001),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, None, None);
    assert_eq!(price_for(&price, "input"), 2.00);
}

#[test]
fn conditional_unknown_property_permissive() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/conditional/generate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    // No context_length → condition passes permissively → first tier
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, None);
    assert_eq!(price_for(&price, "input"), 1.00);
}

#[test]
fn conditional_zero_context() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/conditional/generate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        context_length: Some(0),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, None, None);
    assert_eq!(price_for(&price, "input"), 1.00); // 0 <= 200000
}

// =============================================================================
// Variants
// =============================================================================

#[test]
fn variant_pro() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/models/pro:generate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let price = metering::resolve_price(meter, &RequestProperties::default(), Some("pro"), None);
    assert_eq!(price_for(&price, "input"), 5.00);
    assert_eq!(price_for(&price, "output"), 15.00);
}

#[test]
fn variant_flash() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/models/flash:generate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let price = metering::resolve_price(meter, &RequestProperties::default(), Some("flash"), None);
    assert_eq!(price_for(&price, "input"), 0.50);
    assert_eq!(price_for(&price, "output"), 1.50);
}

#[test]
fn variant_lite() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/models/lite:generate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let price = metering::resolve_price(meter, &RequestProperties::default(), Some("lite"), None);
    assert_eq!(price_for(&price, "input"), 0.10);
    assert_eq!(price_for(&price, "output"), 0.30);
}

#[test]
fn variant_unknown_defaults_to_first() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/models/unknown:generate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let price =
        metering::resolve_price(meter, &RequestProperties::default(), Some("unknown"), None);
    // Falls back to first variant (pro) — most expensive, safest
    assert_eq!(price_for(&price, "input"), 5.00);
}

#[test]
fn variant_no_hint_defaults_to_first() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/models/x:generate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, None);
    assert_eq!(price_for(&price, "input"), 5.00);
}

#[test]
fn variant_partial_match() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/models/x:generate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    // "flash-v2" contains "flash"
    let price =
        metering::resolve_price(meter, &RequestProperties::default(), Some("flash-v2"), None);
    assert_eq!(price_for(&price, "input"), 0.50);
}

// =============================================================================
// Variant + conditional combo
// =============================================================================

#[test]
fn variant_conditional_expensive_short() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/models/expensive:chat").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        context_length: Some(64_000),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, Some("expensive"), None);
    assert_eq!(price_for(&price, "input"), 2.00);
    assert_eq!(price_for(&price, "output"), 10.00);
}

#[test]
fn variant_conditional_expensive_long() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/models/expensive:chat").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        context_length: Some(200_000),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, Some("expensive"), None);
    assert_eq!(price_for(&price, "input"), 4.00);
    assert_eq!(price_for(&price, "output"), 10.00);
}

#[test]
fn variant_conditional_cheap_ignores_context() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/models/cheap:chat").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        context_length: Some(999_999),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, Some("cheap"), None);
    assert_eq!(price_for(&price, "input"), 0.10);
    assert_eq!(price_for(&price, "output"), 0.40);
}

// =============================================================================
// SKU-based
// =============================================================================

#[test]
fn sku_returns_placeholder() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/places/search").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    assert_eq!(meter.sku_tiers.len(), 3);
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, None);
    assert!(price.is_some());
}

// =============================================================================
// Body size condition
// =============================================================================

#[test]
fn body_size_small() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/upload").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        body_size: Some(1000),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, None, None);
    assert_eq!(single_price(&price), 0.01);
}

#[test]
fn body_size_large() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/upload").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        body_size: Some(10_000_000),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, None, None);
    assert_eq!(single_price(&price), 0.10);
}

#[test]
fn body_size_exact_boundary() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/upload").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    // Exactly 1MB → should match <= 1MB
    let props = RequestProperties {
        body_size: Some(1_048_576),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, None, None);
    assert_eq!(single_price(&price), 0.01);
}

#[test]
fn body_size_one_over_boundary() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/upload").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        body_size: Some(1_048_577),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, None, None);
    assert_eq!(single_price(&price), 0.10);
}

// =============================================================================
// Batch size condition
// =============================================================================

#[test]
fn batch_small() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/batch/embed").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        batch_size: Some(50),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, None, None);
    assert_eq!(single_price(&price), 0.001);
}

#[test]
fn batch_large() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/batch/embed").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        batch_size: Some(500),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, None, None);
    assert_eq!(single_price(&price), 0.0005);
}

#[test]
fn batch_exact_boundary() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/batch/embed").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let props = RequestProperties {
        batch_size: Some(100),
        ..Default::default()
    };
    let price = metering::resolve_price(meter, &props, None, None);
    assert_eq!(single_price(&price), 0.001);
}

// =============================================================================
// Multi-dimension (input + output)
// =============================================================================

#[test]
fn multi_dimension_both() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/completions").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, None);
    let p = price.unwrap();
    assert_eq!(p.dimensions.len(), 2);
    assert_eq!(price_for(&Some(p.clone()), "input"), 0.50);
    assert_eq!(price_for(&Some(p), "output"), 1.50);
}

// =============================================================================
// Accounting store edge cases
// =============================================================================

#[test]
fn accounting_period_reset_changes_tier() {
    let store = InMemoryStore::new();
    let key = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/volume/annotate".to_string(),
        period: "2026-03".to_string(),
        scope: "pool".to_string(),
    };
    store.increment(&key, 5_000_001);
    assert_eq!(store.get_usage(&key), 5_000_001);

    store.reset_period("2026-03");
    assert_eq!(store.get_usage(&key), 0);
}

#[test]
fn accounting_different_endpoints_independent() {
    let store = InMemoryStore::new();
    let period = pay_core::current_period();

    let key_a = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/simple/echo".to_string(),
        period: period.clone(),
        scope: "pool".to_string(),
    };
    let key_b = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/volume/annotate".to_string(),
        period,
        scope: "pool".to_string(),
    };

    store.increment(&key_a, 100);
    store.increment(&key_b, 200);

    assert_eq!(store.get_usage(&key_a), 100);
    assert_eq!(store.get_usage(&key_b), 200);
}

#[test]
fn accounting_different_periods_independent() {
    let store = InMemoryStore::new();
    let key_march = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/volume/annotate".to_string(),
        period: "2026-03".to_string(),
        scope: "pool".to_string(),
    };
    let key_april = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/volume/annotate".to_string(),
        period: "2026-04".to_string(),
        scope: "pool".to_string(),
    };

    store.increment(&key_march, 5_000_001);
    store.increment(&key_april, 500);

    assert_eq!(store.get_usage(&key_march), 5_000_001);
    assert_eq!(store.get_usage(&key_april), 500);
}

#[test]
fn accounting_increment_is_atomic() {
    let store = InMemoryStore::new();
    let key = AccountingKey {
        api: "test".to_string(),
        endpoint: "test".to_string(),
        period: "2026-03".to_string(),
        scope: "pool".to_string(),
    };

    assert_eq!(store.increment(&key, 10), 10);
    assert_eq!(store.increment(&key, 5), 15);
    assert_eq!(store.increment(&key, 1), 16);
    assert_eq!(store.get_usage(&key), 16);
}

// =============================================================================
// Translation (per-character with volume)
// =============================================================================

#[test]
fn translate_402_quote() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/translate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, None);
    // First non-free tier: $20.00/1M chars
    assert_eq!(single_price(&price), 20.00);
}

#[test]
fn translate_free_tier() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/translate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let store = InMemoryStore::new();
    let ctx = MeteringContext {
        api_name: "testapi",
        endpoint_path: "v1/translate",
        accounting_mode: &AccountingMode::Pooled,
        store: &store,
        wallet: None,
    };
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, Some(&ctx));
    assert_eq!(single_price(&price), 0.0);
}

#[test]
fn translate_discount_tier() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/translate").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let store = InMemoryStore::new();
    let key = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/translate".to_string(),
        period: pay_core::current_period(),
        scope: "pool".to_string(),
    };
    store.increment(&key, 250_000_001);
    let ctx = MeteringContext {
        api_name: "testapi",
        endpoint_path: "v1/translate",
        accounting_mode: &AccountingMode::Pooled,
        store: &store,
        wallet: None,
    };
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, Some(&ctx));
    assert_eq!(single_price(&price), 10.00);
}

// =============================================================================
// Per-minute (speech)
// =============================================================================

#[test]
fn transcribe_402_quote() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/audio/transcribe").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, None);
    assert_eq!(single_price(&price), 0.016);
}

#[test]
fn transcribe_volume_discount() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/audio/transcribe").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let store = InMemoryStore::new();
    let key = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/audio/transcribe".to_string(),
        period: pay_core::current_period(),
        scope: "pool".to_string(),
    };
    store.increment(&key, 1_000_001);
    let ctx = MeteringContext {
        api_name: "testapi",
        endpoint_path: "v1/audio/transcribe",
        accounting_mode: &AccountingMode::Pooled,
        store: &store,
        wallet: None,
    };
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, Some(&ctx));
    assert_eq!(single_price(&price), 0.004);
}

// =============================================================================
// Per-page (document)
// =============================================================================

#[test]
fn document_process_402() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/documents/process").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, None);
    assert_eq!(single_price(&price), 1.50);
}

#[test]
fn document_process_discount() {
    let api = load_test_api();
    let ep = metering::find_endpoint(&api, "POST", "v1/documents/process").unwrap();
    let meter = ep.metering.as_ref().unwrap();
    let store = InMemoryStore::new();
    let key = AccountingKey {
        api: "testapi".to_string(),
        endpoint: "v1/documents/process".to_string(),
        period: pay_core::current_period(),
        scope: "pool".to_string(),
    };
    store.increment(&key, 5_000_001);
    let ctx = MeteringContext {
        api_name: "testapi",
        endpoint_path: "v1/documents/process",
        accounting_mode: &AccountingMode::Pooled,
        store: &store,
        wallet: None,
    };
    let price = metering::resolve_price(meter, &RequestProperties::default(), None, Some(&ctx));
    assert_eq!(single_price(&price), 0.60);
}
