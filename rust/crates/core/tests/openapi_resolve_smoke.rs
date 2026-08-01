//! Smoke test: hit a real OpenAPI doc and verify resolver returns expected endpoints.
//! Network-dependent; gated under `network_tests` feature for CI control.

#[cfg(feature = "network_tests")]
#[test]
fn stabledomains_openapi_resolves() {
    use pay_core::skills::openapi::resolve_endpoints;
    use pay_types::registry::OpenapiSource;

    let src = OpenapiSource::Url {
        url: "https://stabledomains.dev/openapi.json".into(),
    };
    let endpoints = resolve_endpoints(&src, "https://stabledomains.dev")
        .expect("resolver should succeed against live stabledomains openapi");
    let by_path: std::collections::HashSet<_> = endpoints
        .iter()
        .map(|e| (&*e.spec.method, &*e.spec.path))
        .collect();
    assert!(by_path.contains(&("POST", "api/register")));
    assert!(by_path.contains(&("POST", "api/domain/dns")));
    assert!(by_path.contains(&("POST", "api/domain/renew")));
}
