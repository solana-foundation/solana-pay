//! Types for the pay-skills registry — provider, affiliate, and aggregator specs.
//!
//! These represent the YAML frontmatter in `.md` files submitted to the
//! pay-skills registry. Used by:
//! - `pay skills build` (validation + index generation)
//! - `pay skills create` MCP tool (schema generation + validation)

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const KNOWN_CATEGORIES: &[&str] = &[
    "ai_ml",
    "cloud",
    "compute",
    "data",
    "devtools",
    "finance",
    "identity",
    "maps",
    "media",
    "messaging",
    "other",
    "productivity",
    "search",
    "security",
    "shopping",
    "storage",
    "translation",
];

pub const AFFILIATE_TYPES: &[&str] = &["agent", "cli", "platform"];
const TUNNEL_HOST_SUFFIXES: &[&str] = &[
    ".ngrok.io",
    ".ngrok-free.app",
    ".trycloudflare.com",
    ".loca.lt",
    ".localtunnel.me",
    ".localhost.run",
    ".serveo.net",
];

/// Common metadata shared across all service representations (frontmatter,
/// index entries, runtime catalog, search results, detail views).
///
/// Embed with `#[serde(flatten)]` to avoid repeating these fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ServiceMeta {
    /// Human-readable title.
    #[serde(default)]
    pub title: String,
    /// One-sentence description (max 255 chars). Powers search.
    #[serde(default)]
    pub description: String,
    /// Hint for LLMs: when should this skill be used? (max 255 chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_case: Option<String>,
    /// Category. One of: ai_ml, cloud, compute, data, devtools, finance,
    /// identity, maps, media, messaging, other, productivity, search,
    /// security, shopping, storage, translation.
    #[serde(default)]
    pub category: String,
    /// Live URL where the API is reachable (production).
    #[serde(default)]
    pub service_url: String,
    /// Optional sandbox/testnet URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_service_url: Option<String>,
}

/// Provider frontmatter — the YAML block in a provider `.md` file.
///
/// Endpoints can be declared in one of two mutually-exclusive ways:
/// - inline `endpoints:` list (legacy form, used by providers without an
///   OpenAPI doc — e.g. the Cloud Run Google proxies),
/// - `openapi:` source that points to (or inlines) an OpenAPI 3 document; the
///   resolver walks `paths × methods` to synthesize the endpoint list.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProviderFrontmatter {
    /// API name — must match the filename (without `.md`).
    pub name: String,
    #[serde(flatten)]
    pub meta: ServiceMeta,
    /// API version (e.g. "v1", "v2").
    #[serde(default)]
    pub version: String,
    /// Structured OpenAPI source resolved by `pay skills probe`/build.
    ///
    /// Mutually exclusive with `endpoints:`. When set, the resolver fetches /
    /// reads the document, walks `paths × methods`, and synthesizes endpoint
    /// specs that the prober then probes for stablecoin gating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openapi: Option<OpenapiSource>,
    /// Opt-in to affiliate referrals.
    #[serde(default)]
    pub affiliate_policy: Option<AffiliatePolicy>,
    /// API endpoints — required when `openapi:` is not set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<EndpointSpec>,
}

/// Pointer to (or inline copy of) an OpenAPI document.
///
/// Exactly one variant must be set. Variants are flattened into the parent
/// `openapi:` mapping so spec authors can write any of:
///
/// ```yaml
/// # Absolute URL — fetched as-is
/// openapi:
///   url: https://example.com/openapi.json
///
/// # Relative URL — resolved against service_url at fetch time
/// openapi:
///   url: openapi.json
///
/// # Local filesystem path — only valid for `pay gate api --openapi`,
/// # rejected by the pay-skills registry validator
/// openapi:
///   path: ./openapi.json
///
/// # Inline document — useful for small specs that change rarely
/// openapi:
///   content: |
///     { "openapi": "3.1.0", ... }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged, deny_unknown_fields)]
pub enum OpenapiSource {
    /// Absolute (`https://...`) or relative URL. The pay-skills resolver
    /// fetches absolute URLs as-is and resolves relative URLs against the
    /// provider's `service_url`. The pay-server gateway uses the same
    /// semantics for its `--openapi` flag.
    Url { url: String },
    /// Local filesystem path, used by `pay gate api --openapi` to read
    /// a doc co-located with the YAML on disk. The pay-skills registry
    /// validator rejects this variant — registry providers must use `url:`
    /// so consumers can fetch the doc remotely.
    Path { path: String },
    /// Inline OpenAPI document (typically a YAML `|` block of JSON).
    Content { content: String },
}

/// Affiliate referral policy on a provider.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AffiliatePolicy {
    pub enabled: bool,
    #[serde(default)]
    pub default_percent: Option<f64>,
    /// Restrict to specific affiliate slugs. Omit to accept all.
    #[serde(default)]
    pub allow: Option<Vec<String>>,
}

/// A single API endpoint in the registry.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EndpointSpec {
    /// HTTP method (GET, POST, PUT, PATCH, DELETE).
    pub method: String,
    /// URL path (e.g. "v1/search").
    pub path: String,
    /// What this endpoint does (max 120 chars, start with a verb).
    pub description: String,
    /// Resource group for organizing endpoints (e.g. "jobs", "datasets").
    #[serde(default)]
    pub resource: Option<String>,
    /// Pricing config. Omit for free endpoints.
    #[serde(default)]
    pub pricing: Option<serde_json::Value>,
}

/// Affiliate frontmatter.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AffiliateFrontmatter {
    pub name: String,
    pub title: String,
    /// One of: agent, cli, platform.
    #[serde(rename = "type")]
    pub affiliate_type: String,
    /// Solana wallet address (base58 pubkey).
    pub account: String,
    /// Contact email or URL — required because money is involved.
    pub contact: String,
    #[serde(default)]
    pub url: Option<String>,
    /// Solana network: mainnet or devnet.
    #[serde(default = "default_network")]
    pub network: String,
}

fn default_network() -> String {
    "mainnet".to_string()
}

/// Aggregator frontmatter.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AggregatorFrontmatter {
    pub name: String,
    pub title: String,
    pub url: String,
    pub contact: String,
    #[serde(default)]
    pub description: Option<String>,
    /// URL to their skills.json equivalent (metadata only).
    #[serde(default)]
    pub catalog_url: Option<String>,
}

// ── Probe types ───────────────────────────────────────────────────────────

/// An endpoint to probe: method, path, and whether it's metered.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProbeEndpoint {
    pub method: String,
    pub path: String,
    pub metered: bool,
    /// JSON body to send during probing (e.g. derived from an OpenAPI example
    /// or generated from a schema). Used for POST/PUT/PATCH only — GET probes
    /// ignore it. `None` falls back to a minimal `{}` body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// A provider with its service URL and endpoints, ready for probing.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProbeProvider {
    pub fqn: String,
    pub service_url: String,
    pub endpoints: Vec<ProbeEndpoint>,
}

// ── Schema ─────────────────────────────────────────────────────────────────

/// Generate JSON Schema for `ProviderFrontmatter` as a pretty-printed string.
pub fn provider_json_schema() -> String {
    let schema = schemars::schema_for!(ProviderFrontmatter);
    serde_json::to_string_pretty(&schema).unwrap_or_default()
}

// ── Validation ─────────────────────────────────────────────────────────────

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn valid_base58(s: &str) -> bool {
    (32..=44).contains(&s.len()) && s.bytes().all(|b| BASE58_ALPHABET.contains(&b))
}

pub fn validate_provider(spec: &ProviderFrontmatter, fqn: &str) -> Vec<String> {
    let mut errs = Vec::new();
    let m = &spec.meta;

    validate_fqn_segments(fqn, &mut errs);

    // ── Title ──
    if m.title.trim().is_empty() {
        errs.push(format!("{fqn}: missing required field `title`\n"));
    } else if contains_placeholder(&m.title) {
        errs.push(format!(
            "{fqn}: title contains an unresolved placeholder\n  got: \"{}\"\n",
            m.title
        ));
    }

    // ── Category ──
    if !KNOWN_CATEGORIES.contains(&m.category.as_str()) {
        errs.push(format!(
            "{fqn}: unknown category `{}`\n  valid categories: {}\n",
            m.category,
            KNOWN_CATEGORIES.join(", ")
        ));
    }

    // ── Description (min 64, max 255) ──
    if contains_placeholder(&m.description) {
        errs.push(format!(
            "{fqn}: description contains an unresolved placeholder\n  got: \"{}\"\n",
            m.description
        ));
    }
    if m.description.len() < 64 {
        errs.push(format!(
            "{fqn}: description too short ({} chars, min 64)\n  got: \"{}\"\n",
            m.description.len(),
            m.description
        ));
    }
    if m.description.len() > 255 {
        errs.push(format!(
            "{fqn}: description too long ({} chars, max 255)\n  got: \"{}...\"\n",
            m.description.len(),
            &m.description[..80]
        ));
    }

    // ── use_case (required, 32-255 chars) ──
    match &m.use_case {
        None => {
            errs.push(format!(
                "{fqn}: missing required field `use_case`\n  \
                 add a use_case field (32-255 chars) describing when this API should be used\n"
            ));
        }
        Some(uc) if contains_placeholder(uc) => {
            errs.push(format!(
                "{fqn}: use_case contains an unresolved placeholder\n  got: \"{uc}\"\n"
            ));
        }
        Some(uc) if uc.len() < 32 => {
            errs.push(format!(
                "{fqn}: use_case too short ({} chars, min 32)\n  got: \"{uc}\"\n",
                uc.len()
            ));
        }
        Some(uc) if uc.len() > 255 => {
            errs.push(format!(
                "{fqn}: use_case too long ({} chars, max 255)\n  got: \"{}...\"\n",
                uc.len(),
                &uc[..80]
            ));
        }
        _ => {}
    }

    // ── service_url (HTTPS only, domain names only) ──
    validate_registry_url(fqn, "service_url", &m.service_url, true, &mut errs);
    if let Some(url) = &m.sandbox_service_url {
        validate_registry_url(fqn, "sandbox_service_url", url, false, &mut errs);
    }

    // ── openapi: vs endpoints: (mutually exclusive, exactly one required) ──
    let has_openapi = spec.openapi.is_some();
    let has_endpoints = !spec.endpoints.is_empty();
    match (has_openapi, has_endpoints) {
        (true, true) => errs.push(format!(
            "{fqn}: cannot set both `openapi` and `endpoints`\n  \
             pick one — `openapi` is resolved at probe time, `endpoints` is inline\n"
        )),
        (false, false) => errs.push(format!(
            "{fqn}: must set either `openapi` or `endpoints`\n  \
             add an `openapi: {{ path|content: ... }}` mapping or at least one endpoint\n"
        )),
        _ => {}
    }
    if let Some(src) = &spec.openapi {
        for err in validate_openapi_source(src, fqn) {
            errs.push(err);
        }
    }
    for (i, ep) in spec.endpoints.iter().enumerate() {
        let label = if ep.path.is_empty() {
            format!("endpoint[{i}]")
        } else {
            format!("endpoint[{i}] {} {}", ep.method, ep.path)
        };

        if ep.method.is_empty() {
            errs.push(format!(
                "{fqn}: {label} — missing `method` (GET, POST, PUT, PATCH, DELETE)\n"
            ));
        }
        if ep.path.is_empty() {
            errs.push(format!("{fqn}: endpoint[{i}] — missing `path`\n"));
        }
        if ep.description.len() < 32 {
            errs.push(format!(
                "{fqn}: {label} — description too short ({} chars, min 32)\n  got: \"{}\"\n",
                ep.description.len(),
                ep.description
            ));
        }
        if contains_placeholder(&ep.description) {
            errs.push(format!(
                "{fqn}: {label} — description contains an unresolved placeholder\n  got: \"{}\"\n",
                ep.description
            ));
        }
        if ep.description.len() > 255 {
            errs.push(format!(
                "{fqn}: {label} — description too long ({} chars, max 255)\n  got: \"{}...\"\n",
                ep.description.len(),
                &ep.description[..80]
            ));
        }

        // ── Pricing precision ──
        if let Some(pricing) = &ep.pricing {
            validate_pricing_precision(pricing, fqn, &label, &mut errs);
        }
    }
    errs
}

/// Check that `price_usd / scale` doesn't produce more decimals than
/// stablecoin tokens support (6 for USDC/USDT).
fn validate_pricing_precision(
    pricing: &serde_json::Value,
    fqn: &str,
    label: &str,
    errs: &mut Vec<String>,
) {
    const MIN_REPRESENTABLE: f64 = 0.000001; // 10^-6

    let Some(dims) = pricing.get("dimensions").and_then(|v| v.as_array()) else {
        return;
    };
    for dim in dims {
        let scale = dim
            .get("scale")
            .and_then(|v| v.as_u64())
            .unwrap_or(1)
            .max(1);
        let Some(tiers) = dim.get("tiers").and_then(|v| v.as_array()) else {
            continue;
        };
        for tier in tiers {
            let price = tier
                .get("price_usd")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            if price == 0.0 {
                continue;
            }
            let per_unit = price / scale as f64;
            if per_unit > 0.0 && per_unit < MIN_REPRESENTABLE {
                errs.push(format!(
                    "{fqn}: {label} — price_usd ${price} / scale {scale} = ${per_unit:.12}/unit, \
                     below minimum ${MIN_REPRESENTABLE} for 6-decimal tokens. Reduce scale or increase price_usd.\n"
                ));
            }
        }
    }
}

/// Validate an `OpenapiSource` value's contents (HTTPS, non-empty, sane shape).
///
/// Mutual-exclusion of variants is enforced by `serde(deny_unknown_fields)` on
/// the untagged enum, so we only need to check that the chosen variant carries
/// a non-empty value and uses HTTPS where applicable.
fn validate_openapi_source(src: &OpenapiSource, fqn: &str) -> Vec<String> {
    let mut errs = Vec::new();
    match src {
        OpenapiSource::Url { url } => {
            errs.push(format!(
                "{fqn}: openapi.url is not allowed in the public registry\n  \
                 got: `{url}`\n  \
                 commit the spec next to PAY.md and use `openapi: {{ path: openapi.json }}` \
                 (or `content:` for tiny specs)\n"
            ));
        }
        OpenapiSource::Path { path } => {
            if path.trim().is_empty() {
                errs.push(format!("{fqn}: openapi.path is empty\n"));
            } else {
                let p = std::path::Path::new(path);
                if p.is_absolute() {
                    errs.push(format!(
                        "{fqn}: openapi.path must be relative to PAY.md\n  got: `{path}`\n"
                    ));
                }
                if path.split('/').any(|part| part == "..") {
                    errs.push(format!(
                        "{fqn}: openapi.path must not escape the provider directory\n  got: `{path}`\n"
                    ));
                }
            }
            // Path is resolved relative to the provider's PAY.md at build
            // time; the resolved doc gets inlined into the published dist
            // so consumers don't need filesystem access.
        }
        OpenapiSource::Content { content } => {
            if content.trim().is_empty() {
                errs.push(format!("{fqn}: openapi.content is empty\n"));
            }
        }
    }
    errs
}

fn validate_fqn_segments(fqn: &str, errs: &mut Vec<String>) {
    if fqn.trim().is_empty() {
        errs.push("provider fqn is empty\n".to_string());
        return;
    }
    for segment in fqn.split('/') {
        if segment.is_empty() {
            errs.push(format!("{fqn}: FQN contains an empty path segment\n"));
            continue;
        }
        if !is_url_safe_segment(segment) {
            errs.push(format!(
                "{fqn}: FQN segment `{segment}` must be lowercase and URL-safe\n  \
                 use lowercase letters, digits, and single hyphens (for example `market-data`)\n"
            ));
        }
    }
}

fn is_url_safe_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    !bytes.is_empty()
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        && !segment.contains("--")
}

fn contains_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    ["todo", "fixme", "tbd", "{{", "<todo>", "your-"]
        .iter()
        .any(|needle| lower.contains(needle))
}

fn validate_registry_url(
    fqn: &str,
    field: &str,
    url: &str,
    required: bool,
    errs: &mut Vec<String>,
) {
    if url.trim().is_empty() {
        if required {
            errs.push(format!("{fqn}: missing required field `{field}`\n"));
        } else {
            errs.push(format!("{fqn}: {field} is empty\n"));
        }
        return;
    }
    if !url.starts_with("https://") {
        errs.push(format!(
            "{fqn}: {field} must start with https://\n  got: `{url}`\n"
        ));
        return;
    }

    let Some(host) = url_host(url) else {
        errs.push(format!(
            "{fqn}: {field} must include a production hostname\n  got: `{url}`\n"
        ));
        return;
    };

    let host_lower = host.to_ascii_lowercase();
    if url_has_ip_address(url)
        || host_lower == "localhost"
        || host_lower.ends_with(".localhost")
        || host_lower.ends_with(".local")
    {
        errs.push(format!(
            "{fqn}: {field} must use a production domain name, not localhost or an IP address\n  got: `{url}`\n"
        ));
        return;
    }

    if TUNNEL_HOST_SUFFIXES
        .iter()
        .any(|suffix| host_lower.ends_with(suffix))
    {
        errs.push(format!(
            "{fqn}: {field} must not use a tunnel or temporary preview domain\n  got: `{url}`\n"
        ));
    }
}

/// Check if a URL uses an IP address instead of a domain name.
fn url_has_ip_address(url: &str) -> bool {
    let Some(host) = url_host(url) else {
        return false;
    };
    if host.starts_with('[') && host.ends_with(']') {
        return true;
    }
    host.parse::<std::net::IpAddr>().is_ok()
}

fn url_host(url: &str) -> Option<&str> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host_port = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if host_port.is_empty() {
        return None;
    }
    if let Some(end) = host_port.strip_prefix('[').and_then(|rest| rest.find(']')) {
        let end = end + 1;
        return Some(&host_port[..=end]);
    }
    let host = host_port.split(':').next().unwrap_or("");
    (!host.is_empty()).then_some(host)
}

pub fn validate_affiliate(spec: &AffiliateFrontmatter, name: &str) -> Vec<String> {
    let mut errs = Vec::new();
    if !valid_base58(&spec.account) {
        errs.push(format!(
            "affiliate/{name}: invalid account `{}` (must be base58 Solana pubkey, 32-44 chars)",
            spec.account
        ));
    }
    if !AFFILIATE_TYPES.contains(&spec.affiliate_type.as_str()) {
        errs.push(format!(
            "affiliate/{name}: unknown type `{}` (valid: {})",
            spec.affiliate_type,
            AFFILIATE_TYPES.join(", ")
        ));
    }
    errs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_spec() -> ProviderFrontmatter {
        ProviderFrontmatter {
            name: "test-api".into(),
            meta: ServiceMeta {
                title: "Test API".into(),
                description: "A test API for validating things — long enough to pass the 64-char minimum requirement.".into(),
                use_case: Some("testing validation logic, verifying CI checks work correctly".into()),
                category: "data".into(),
                service_url: "https://api.example.com".into(),
                sandbox_service_url: None,
            },
            version: "v1".into(),
            openapi: None,
            affiliate_policy: None,
            endpoints: vec![EndpointSpec {
                method: "POST".into(),
                path: "v1/search".into(),
                description: "Search items by keyword with filtering and pagination support".into(),
                resource: None,
                pricing: None,
            }],
        }
    }

    #[test]
    fn valid_spec_passes() {
        let errs = validate_provider(&valid_spec(), "test/test-api");
        assert!(errs.is_empty(), "expected no errors, got: {errs:?}");
    }

    #[test]
    fn provider_json_schema_contains_provider_shape() {
        let schema = provider_json_schema();
        let value: serde_json::Value = serde_json::from_str(&schema).unwrap();
        assert!(value["definitions"]["EndpointSpec"].is_object());
        assert!(schema.contains("ProviderFrontmatter"));
    }

    #[test]
    fn provider_yaml_pricing_precision_rejected() {
        let yaml = r#"
name: tiny-api
title: Tiny API
description: Tiny prices that exercise provider YAML validation and registry checks.
use_case: validating provider registry YAML pricing precision before publishing
category: data
service_url: https://api.example.com
endpoints:
  - method: POST
    path: v1/tiny
    description: Search datasets by keyword with filtering and pagination support
    pricing:
      dimensions:
        - scale: 2000000
          tiers:
            - price_usd: 1.0
"#;
        let spec: ProviderFrontmatter = serde_yml::from_str(yaml).unwrap();
        let errs = validate_provider(&spec, "test/tiny-api");
        assert!(
            errs.iter().any(|e| e.contains("below minimum $0.000001")),
            "expected pricing precision error, got: {errs:?}"
        );
    }

    #[test]
    fn provider_pricing_precision_allows_unpriced_and_exact_micro_prices() {
        let mut spec = valid_spec();
        spec.endpoints = vec![
            EndpointSpec {
                method: "GET".into(),
                path: "v1/free".into(),
                description: "Fetch free metadata without charging the caller for usage".into(),
                resource: None,
                pricing: Some(serde_json::json!({})),
            },
            EndpointSpec {
                method: "POST".into(),
                path: "v1/exact".into(),
                description: "Create a priced request at the minimum token precision boundary"
                    .into(),
                resource: None,
                pricing: Some(serde_json::json!({
                    "dimensions": [
                        {
                            "scale": 0,
                            "tiers": [
                                { "price_usd": 0.0 },
                                { "price_usd": 0.000001 }
                            ]
                        },
                        {
                            "scale": 1
                        }
                    ]
                })),
            },
        ];
        let errs = validate_provider(&spec, "test/test-api");
        assert!(errs.is_empty(), "expected no errors, got: {errs:?}");
    }

    #[test]
    fn category_service_url_and_endpoint_presence_are_required() {
        let mut spec = valid_spec();
        spec.meta.category = "unknown".into();
        spec.meta.service_url = String::new();
        spec.endpoints = vec![];

        let errs = validate_provider(&spec, "test/test-api");
        assert!(
            errs.iter().any(|e| e.contains("unknown category")),
            "expected category error, got: {errs:?}"
        );
        assert!(
            errs.iter()
                .any(|e| e.contains("missing required field `service_url`")),
            "expected service_url error, got: {errs:?}"
        );
        assert!(
            errs.iter()
                .any(|e| e.contains("must set either `openapi` or `endpoints`")),
            "expected endpoint-presence error, got: {errs:?}"
        );
    }

    #[test]
    fn openapi_url_rejected_even_without_inline_endpoints() {
        let mut spec = valid_spec();
        spec.endpoints = vec![];
        spec.openapi = Some(OpenapiSource::Url {
            url: "https://api.example.com/openapi.json".into(),
        });
        let errs = validate_provider(&spec, "test/test-api");
        assert!(
            errs.iter()
                .any(|e| e.contains("openapi.url is not allowed")),
            "expected committed-spec rejection, got: {errs:?}"
        );
    }

    #[test]
    fn openapi_relative_url_rejected() {
        let mut spec = valid_spec();
        spec.endpoints = vec![];
        spec.openapi = Some(OpenapiSource::Url {
            url: "openapi.json".into(),
        });
        let errs = validate_provider(&spec, "test/test-api");
        assert!(
            errs.iter()
                .any(|e| e.contains("openapi.url is not allowed")),
            "expected committed-spec rejection, got: {errs:?}"
        );
    }

    #[test]
    fn openapi_path_passes_validation() {
        // `path:` resolves relative to the provider's PAY.md at build time;
        // the resolved doc is inlined into the published dist.
        let mut spec = valid_spec();
        spec.endpoints = vec![];
        spec.openapi = Some(OpenapiSource::Path {
            path: "openapi.json".into(),
        });
        let errs = validate_provider(&spec, "test/test-api");
        assert!(errs.is_empty(), "expected no errors, got: {errs:?}");
    }

    #[test]
    fn openapi_path_empty_is_rejected() {
        let mut spec = valid_spec();
        spec.endpoints = vec![];
        spec.openapi = Some(OpenapiSource::Path { path: "".into() });
        let errs = validate_provider(&spec, "test/test-api");
        assert!(
            errs.iter().any(|e| e.contains("openapi.path is empty")),
            "expected empty-path rejection, got: {errs:?}"
        );
    }

    #[test]
    fn openapi_with_inline_content_passes() {
        let mut spec = valid_spec();
        spec.endpoints = vec![];
        spec.openapi = Some(OpenapiSource::Content {
            content: "{\"openapi\":\"3.1.0\",\"paths\":{}}".into(),
        });
        let errs = validate_provider(&spec, "test/test-api");
        assert!(errs.is_empty(), "expected no errors, got: {errs:?}");
    }

    #[test]
    fn openapi_and_endpoints_together_are_rejected() {
        let mut spec = valid_spec();
        // valid_spec has one endpoint already
        spec.openapi = Some(OpenapiSource::Path {
            path: "openapi.json".into(),
        });
        let errs = validate_provider(&spec, "test/test-api");
        assert!(
            errs.iter()
                .any(|e| e.contains("cannot set both `openapi` and `endpoints`")),
            "expected mutual-exclusion error, got: {errs:?}"
        );
    }

    #[test]
    fn openapi_http_url_rejected_as_remote_source() {
        let mut spec = valid_spec();
        spec.endpoints = vec![];
        spec.openapi = Some(OpenapiSource::Url {
            url: "http://api.example.com/openapi.json".into(),
        });
        let errs = validate_provider(&spec, "test/test-api");
        assert!(
            errs.iter()
                .any(|e| e.contains("openapi.url is not allowed")),
            "expected committed-spec rejection, got: {errs:?}"
        );
    }

    #[test]
    fn openapi_url_with_non_https_scheme_rejected() {
        let mut spec = valid_spec();
        spec.endpoints = vec![];
        spec.openapi = Some(OpenapiSource::Url {
            url: "ftp://api.example.com/openapi.json".into(),
        });
        let errs = validate_provider(&spec, "test/test-api");
        assert!(
            errs.iter()
                .any(|e| e.contains("openapi.url is not allowed")),
            "expected committed-spec rejection, got: {errs:?}"
        );
    }

    #[test]
    fn openapi_yaml_url_form_parses() {
        let yaml = r#"
name: oa-api
title: OpenAPI URL form
description: Provider that ships an OpenAPI doc out-of-band; resolved at probe time by the prober.
use_case: validating that the openapi.url form parses end-to-end through serde_yml in tests
category: data
service_url: https://api.example.com
openapi:
  url: https://api.example.com/openapi.json
"#;
        let spec: ProviderFrontmatter = serde_yml::from_str(yaml).unwrap();
        match spec.openapi {
            Some(OpenapiSource::Url { url }) => {
                assert_eq!(url, "https://api.example.com/openapi.json")
            }
            other => panic!("expected OpenapiSource::Url, got {other:?}"),
        }
        assert!(spec.endpoints.is_empty());
    }

    #[test]
    fn openapi_yaml_path_form_parses() {
        let yaml = r#"
name: oa-api
title: OpenAPI path form
description: Provider that hosts its OpenAPI doc on the same origin as service_url at a relative path.
use_case: validating that the openapi.path form parses correctly through serde_yml in tests
category: data
service_url: https://api.example.com
openapi:
  path: openapi.json
"#;
        let spec: ProviderFrontmatter = serde_yml::from_str(yaml).unwrap();
        match spec.openapi {
            Some(OpenapiSource::Path { path }) => assert_eq!(path, "openapi.json"),
            other => panic!("expected OpenapiSource::Path, got {other:?}"),
        }
    }

    #[test]
    fn openapi_yaml_content_form_parses_inline_json() {
        let yaml = "
name: oa-api
title: OpenAPI inline form
description: Provider that inlines its OpenAPI doc directly into the spec via a YAML literal block.
use_case: validating that the openapi.content form parses inline JSON through serde_yml in tests
category: data
service_url: https://api.example.com
openapi:
  content: |
    {
      \"openapi\": \"3.1.0\",
      \"paths\": {}
    }
";
        let spec: ProviderFrontmatter = serde_yml::from_str(yaml).unwrap();
        match spec.openapi {
            Some(OpenapiSource::Content { content }) => {
                assert!(content.contains("\"openapi\": \"3.1.0\""));
                assert!(content.contains("\"paths\""));
            }
            other => panic!("expected OpenapiSource::Content, got {other:?}"),
        }
    }

    #[test]
    fn endpoint_method_and_path_are_required() {
        let mut spec = valid_spec();
        spec.endpoints[0].method = String::new();
        spec.endpoints[0].path = String::new();

        let errs = validate_provider(&spec, "test/test-api");
        assert!(
            errs.iter().any(|e| e.contains("missing `method`")),
            "expected method error, got: {errs:?}"
        );
        assert!(
            errs.iter().any(|e| e.contains("missing `path`")),
            "expected path error, got: {errs:?}"
        );
    }

    #[test]
    fn affiliate_yaml_defaults_network_and_validates_fields() {
        let yaml = r#"
name: partner
title: Partner
type: agent
account: "11111111111111111111111111111111"
contact: ops@example.com
"#;
        let spec: AffiliateFrontmatter = serde_yml::from_str(yaml).unwrap();
        assert_eq!(spec.network, "mainnet");
        assert!(validate_affiliate(&spec, "partner").is_empty());

        let mut invalid = spec;
        invalid.account = "0".into();
        invalid.affiliate_type = "vendor".into();
        let errs = validate_affiliate(&invalid, "partner");
        assert!(
            errs.iter().any(|e| e.contains("invalid account")),
            "expected account error, got: {errs:?}"
        );
        assert!(
            errs.iter().any(|e| e.contains("unknown type")),
            "expected type error, got: {errs:?}"
        );
    }

    #[test]
    fn aggregator_and_probe_types_roundtrip() {
        let aggregator = AggregatorFrontmatter {
            name: "agg".into(),
            title: "Aggregator".into(),
            url: "https://agg.example.com".into(),
            contact: "ops@example.com".into(),
            description: Some("Catalog operator".into()),
            catalog_url: Some("https://agg.example.com/skills.json".into()),
        };
        let yaml = serde_yml::to_string(&aggregator).unwrap();
        let parsed: AggregatorFrontmatter = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(parsed.catalog_url, aggregator.catalog_url);

        let provider = ProbeProvider {
            fqn: "test/test-api".into(),
            service_url: "https://api.example.com".into(),
            endpoints: vec![ProbeEndpoint {
                method: "POST".into(),
                path: "v1/search".into(),
                metered: true,
                body: None,
            }],
        };
        let json = serde_json::to_string(&provider).unwrap();
        let parsed: ProbeProvider = serde_json::from_str(&json).unwrap();
        assert!(parsed.endpoints[0].metered);
    }

    #[test]
    fn description_too_short() {
        let mut spec = valid_spec();
        spec.meta.description = "Too short".into();
        let errs = validate_provider(&spec, "t");
        assert!(errs.iter().any(|e| e.contains("min 64")));
    }

    #[test]
    fn description_too_long() {
        let mut spec = valid_spec();
        spec.meta.description = "x".repeat(256);
        let errs = validate_provider(&spec, "t");
        assert!(errs.iter().any(|e| e.contains("max 255")));
    }

    #[test]
    fn use_case_missing() {
        let mut spec = valid_spec();
        spec.meta.use_case = None;
        let errs = validate_provider(&spec, "t");
        assert!(errs.iter().any(|e| e.contains("use_case")));
    }

    #[test]
    fn use_case_too_short() {
        let mut spec = valid_spec();
        spec.meta.use_case = Some("too short".into());
        let errs = validate_provider(&spec, "t");
        assert!(
            errs.iter()
                .any(|e| e.contains("use_case") && e.contains("min 32"))
        );
    }

    #[test]
    fn use_case_too_long() {
        let mut spec = valid_spec();
        spec.meta.use_case = Some("x".repeat(256));
        let errs = validate_provider(&spec, "t");
        assert!(
            errs.iter()
                .any(|e| e.contains("use_case") && e.contains("max 255"))
        );
    }

    #[test]
    fn service_url_http_rejected() {
        let mut spec = valid_spec();
        spec.meta.service_url = "http://api.example.com".into();
        let errs = validate_provider(&spec, "t");
        assert!(errs.iter().any(|e| e.contains("https://")));
    }

    #[test]
    fn service_url_ip_rejected() {
        let mut spec = valid_spec();
        spec.meta.service_url = "https://192.168.1.1/api".into();
        let errs = validate_provider(&spec, "t");
        assert!(errs.iter().any(|e| e.contains("domain name")));
    }

    #[test]
    fn service_url_ipv6_rejected() {
        let mut spec = valid_spec();
        spec.meta.service_url = "https://[::1]/api".into();
        let errs = validate_provider(&spec, "t");
        // [::1] won't parse as IpAddr due to brackets, but it's not a valid domain either
        // The https:// check passes but the IP check handles bare IPs
        assert!(!errs.is_empty());
    }

    #[test]
    fn service_url_domain_accepted() {
        let spec = valid_spec();
        let errs = validate_provider(&spec, "t");
        assert!(!errs.iter().any(|e| e.contains("service_url")));
    }

    #[test]
    fn endpoint_description_too_short() {
        let mut spec = valid_spec();
        spec.endpoints[0].description = "Short".into();
        let errs = validate_provider(&spec, "t");
        assert!(
            errs.iter()
                .any(|e| e.contains("endpoint[0]") && e.contains("min 32"))
        );
    }

    #[test]
    fn endpoint_description_too_long() {
        let mut spec = valid_spec();
        spec.endpoints[0].description = "x".repeat(256);
        let errs = validate_provider(&spec, "t");
        assert!(
            errs.iter()
                .any(|e| e.contains("endpoint[0]") && e.contains("max 255"))
        );
    }

    #[test]
    fn ip_detection() {
        assert!(url_has_ip_address("https://192.168.1.1/api"));
        assert!(url_has_ip_address("https://10.0.0.1:8080/api"));
        assert!(url_has_ip_address("https://127.0.0.1"));
        assert!(!url_has_ip_address("https://api.example.com"));
        assert!(!url_has_ip_address("https://x402.quicknode.com/rpc"));
    }
}
