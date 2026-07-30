//! Synthesise a catalog JSON for a running `pay gate api` instance so a
//! local MCP agent can discover its endpoints via the same code path
//! that consumes CDN-hosted catalogs.
//!
//! The route lives at `/.well-known/pay-skills.json` (RFC 8615); the
//! shape mirrors what the public `catalog.pay.sh` CDN emits, so the
//! standard `parse_catalog` / `load_skills` plumbing handles it
//! unchanged. One [`Service`](super::Service) is emitted per server,
//! FQN'd as `local/<subdomain>` so it slots alongside (rather than
//! shadowing) the public catalog entries.
//!
//! The route MUST be unauthenticated — it's a discovery surface, not a
//! billable endpoint.

use pay_types::metering::ApiSpec;
use pay_types::registry::ServiceMeta;
use serde_json::{Value, json};

use super::Endpoint;

/// Well-known path the running server exposes the synthesised catalog
/// under. Mirrors the IETF `/.well-known/` convention so any tool that
/// expects discovery metadata there finds it.
pub const WELL_KNOWN_PATH: &str = "/.well-known/pay-skills.json";

/// Schema version we emit. Mirrors `catalog.pay.sh`'s `"1"`.
const SCHEMA_VERSION: &str = "1";

/// Build a catalog JSON document advertising a single running
/// `pay gate api` instance.
///
/// `base_url` is the URL the agent will use to hit the API itself
/// (typically `http://127.0.0.1:<port>`); endpoints are emitted with
/// paths relative to that. `openapi_url`, when supplied, points at the
/// server's `/openapi.json` route so consumers that prefer the OpenAPI
/// discovery shape have something to fetch.
pub fn synthesize_catalog(api: &ApiSpec, base_url: &str, openapi_url: Option<&str>) -> Value {
    let fqn = format!("local/{}", api.subdomain);

    let endpoints: Vec<Endpoint> = api
        .endpoints
        .iter()
        .map(|ep| Endpoint {
            method: format!("{:?}", ep.method).to_uppercase(),
            path: ep.path.trim_start_matches('/').to_string(),
            full_path: format!(
                "{}/{}",
                base_url.trim_end_matches('/'),
                ep.path.trim_start_matches('/')
            ),
            resource: ep.resource.clone(),
            description: ep.description.clone().unwrap_or_default(),
            pricing: pricing_value(ep),
        })
        .collect();

    let endpoint_count = endpoints.len() as u32;
    let has_metering = api.endpoints.iter().any(|ep| ep.metering.is_some());
    let has_free_tier = api
        .endpoints
        .iter()
        .any(|ep| ep.metering.is_none() && ep.subscription.is_none());

    let (min_price_usd, max_price_usd) = endpoints_price_bounds(api);

    let meta = ServiceMeta {
        title: api.title.clone(),
        description: api.description.clone(),
        use_case: None,
        category: api.category.as_str().to_string(),
        service_url: base_url.to_string(),
        sandbox_service_url: None,
    };

    let mut provider = json!({
        "fqn": fqn,
        "endpoint_count": endpoint_count,
        "has_metering": has_metering,
        "has_free_tier": has_free_tier,
        "min_price_usd": min_price_usd,
        "max_price_usd": max_price_usd,
        "sha": "",
        "endpoints": endpoints,
    });
    // Flatten the ServiceMeta fields onto the provider object the same
    // way `#[serde(flatten)]` would on the `Service` struct.
    if let Value::Object(ref mut obj) = provider {
        if let Value::Object(meta_obj) = serde_json::to_value(&meta).unwrap_or(Value::Null) {
            for (k, v) in meta_obj {
                obj.insert(k, v);
            }
        }
        if let Some(url) = openapi_url {
            obj.insert("openapi_url".to_string(), Value::String(url.to_string()));
        }
    }

    json!({
        "schema_version": SCHEMA_VERSION,
        "generated_at": rfc3339_now(),
        "base_url": base_url,
        "provider_count": 1,
        "providers": [provider],
    })
}

/// Extract a pricing payload mirroring what the public catalog uses —
/// `{"usd": <number>}` for metered endpoints, omitted for free, a
/// shape-hint string for subscription gating.
fn pricing_value(ep: &pay_types::metering::Endpoint) -> Option<Value> {
    if let Some(m) = &ep.metering {
        let price = m
            .dimensions
            .first()
            .and_then(|d| d.tiers.first())
            .map(|t| t.price_usd)
            .unwrap_or(0.0);
        return Some(json!({ "usd": price }));
    }
    if let Some(sub) = &ep.subscription {
        return Some(json!({
            "subscription": {
                "period": sub.period,
                "price_usd": sub.price_usd,
            }
        }));
    }
    None
}

/// `(min, max)` price across metered endpoints in USD. Both 0.0 when no
/// endpoint is metered — matches what the CDN does for free-only
/// providers so the search index doesn't choke on `null`.
fn endpoints_price_bounds(api: &ApiSpec) -> (f64, f64) {
    let prices: Vec<f64> = api
        .endpoints
        .iter()
        .filter_map(|ep| ep.metering.as_ref())
        .filter_map(|m| m.dimensions.first())
        .filter_map(|d| d.tiers.first())
        .map(|t| t.price_usd)
        .collect();
    if prices.is_empty() {
        return (0.0, 0.0);
    }
    let min = prices.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = prices.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    (min, max)
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_api() -> ApiSpec {
        let yaml = r#"
name: helius
subdomain: helius
title: "Helius Solana RPC"
description: "Solana JSON-RPC + Helius DAS"
category: data
version: v1
routing:
  type: proxy
  url: https://example.com
endpoints:
  - method: POST
    path: ""
    resource: rpc
    description: "Solana JSON-RPC root"
"#;
        serde_yml::from_str(yaml).expect("valid spec fixture")
    }

    #[test]
    fn synthesize_catalog_round_trips_through_parse_catalog() {
        let api = make_api();
        let doc = synthesize_catalog(&api, "http://127.0.0.1:1402", None);
        let raw = serde_json::to_string(&doc).unwrap();
        // `parse_catalog` is the same entrypoint `load_skills` uses, so
        // if this round-trips we know an MCP agent can consume the
        // synthesized doc unchanged.
        let parsed = super::super::parse_catalog(&raw).expect("parses");
        assert_eq!(parsed.providers.len(), 1);
        assert_eq!(parsed.providers[0].fqn, "local/helius");
        assert_eq!(parsed.providers[0].endpoint_count, 1);
    }

    #[test]
    fn synthesize_catalog_fqn_namespaces_under_local() {
        let api = make_api();
        let doc = synthesize_catalog(&api, "http://127.0.0.1:1402", None);
        let fqn = doc["providers"][0]["fqn"].as_str().unwrap();
        // Local FQN must not collide with the public `helius/...` slot.
        assert!(fqn.starts_with("local/"));
    }

    #[test]
    fn synthesize_catalog_attaches_openapi_url_when_supplied() {
        let api = make_api();
        let doc = synthesize_catalog(
            &api,
            "http://127.0.0.1:1402",
            Some("http://127.0.0.1:1402/openapi.json"),
        );
        let openapi_url = doc["providers"][0]["openapi_url"].as_str().unwrap();
        assert!(openapi_url.ends_with("/openapi.json"));
    }
}
