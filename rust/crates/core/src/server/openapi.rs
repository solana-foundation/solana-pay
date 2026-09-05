//! Serve a filtered + URL-rewritten OpenAPI document at `/openapi.json`.
//!
//! The server loads an OpenAPI 3 or Google Discovery JSON document declared
//! by the operator (via `--openapi` on the CLI or an `openapi:` field in the
//! paywall YAML — both reuse [`pay_types::registry::OpenapiSource`]).
//!
//! Two transforms are applied before the document is exposed to clients:
//!
//! 1. **Filter** — only the endpoints actually proxied by the YAML (`api.endpoints`)
//!    survive. Other paths/methods are stripped so agents see exactly what
//!    they can call through the gateway.
//!
//! 2. **URL rewrite** — `rootUrl` (Discovery), `baseUrl`/`mtlsRootUrl`
//!    (Discovery), and `servers[].url` (OpenAPI 3) are rewritten to point at
//!    the proxy itself, derived from the request `Host` header (with an
//!    optional `--public-url` override) so the gateway can be driven without
//!    knowing the upstream URL.

use std::collections::HashSet;
use std::path::Path;

use pay_types::metering::{
    ApiSpec, Endpoint, HttpMethod, Metering, Scheme, X_PAY_METERING_EXTENSION,
};
use pay_types::registry::OpenapiSource;
use serde_json::{Map, Value, json};

use crate::{Error, Result};

/// Load the document referenced by `source` from disk, an HTTP URL, or
/// inline content.
///
/// `Path` is interpreted relative to `spec_dir` when not absolute — the
/// pay-server filesystem semantics differ from pay-skills (which resolves
/// `Path` against `service_url` over HTTP). Same enum, context-dependent
/// resolution.
pub fn load_document(source: &OpenapiSource, spec_dir: &Path) -> Result<Value> {
    let raw = match source {
        OpenapiSource::Path { path } => {
            let candidate = Path::new(path);
            let full = if candidate.is_absolute() {
                candidate.to_path_buf()
            } else {
                spec_dir.join(candidate)
            };
            std::fs::read_to_string(&full).map_err(|e| {
                Error::Config(format!("openapi: failed to read {}: {e}", full.display()))
            })?
        }
        OpenapiSource::Url { url } => {
            let resp = reqwest::blocking::get(url)
                .map_err(|e| Error::Config(format!("openapi fetch {url}: {e}")))?;
            if !resp.status().is_success() {
                return Err(Error::Config(format!(
                    "openapi fetch {url} returned {}",
                    resp.status()
                )));
            }
            resp.text()
                .map_err(|e| Error::Config(format!("openapi fetch {url}: {e}")))?
        }
        OpenapiSource::Content { content } => content.clone(),
    };
    serde_json::from_str(&raw)
        .map_err(|e| Error::Config(format!("openapi: document is not valid JSON: {e}")))
}

/// Runtime operator identity for [`synthesize_from_spec`] — the bits the static
/// spec doesn't carry (resolved signer/recipient pubkeys + network).
pub struct DiscoveryContext<'a> {
    /// Network slug (`mainnet`/`devnet`/`testnet`/`localnet`). Used verbatim on
    /// MPP offers; mapped to a CAIP-2 chain id on x402 offers.
    pub network_slug: &'a str,
    /// Operator payment recipient (base58) → offer `payTo`.
    pub pay_to: Option<&'a str>,
    /// Operator fee-payer pubkey (base58) → x402 offer `feePayer`.
    pub fee_payer: Option<&'a str>,
}

/// Synthesize an OpenAPI 3.1 document from the paywall spec itself, for when
/// the operator did not supply an upstream doc (`--openapi` / `openapi:`).
///
/// Mirrors pay-kit's TS `openapiFromExpress`: each declared endpoint becomes an
/// operation carrying an `x-payment-info` extension whose `offers[]` are derived
/// from the metering / subscription pricing. Each offer follows the
/// payment-discovery draft shape (`intent`/`method`/`scheme`/`amount`/`network`/
/// `payTo`, plus `feePayer` on x402, `unitPrice` on session, `planId` on
/// subscription). x402 offers carry a CAIP-2 `network`; MPP offers carry the
/// plain network slug.
pub fn synthesize_from_spec(api: &ApiSpec, ctx: &DiscoveryContext) -> Value {
    // All supported stablecoins are 6-decimal; offers price in base units.
    const USDC_DECIMALS: u32 = 6;
    // Primary display currency = the operator's first configured `usd` currency.
    let currency = api
        .operator
        .as_ref()
        .and_then(|o| o.currencies.get("usd"))
        .and_then(|list| list.first())
        .cloned()
        .unwrap_or_else(|| "USDC".to_string());

    let caip2 = solana_caip2(ctx.network_slug);
    // Session channel cap (the per-call price is the unit price for streaming).
    let session_cap_usd = api.session.as_ref().map(|s| s.cap_usdc);

    let mut paths: Map<String, Value> = Map::new();
    for ep in &api.endpoints {
        let oas_path = format!("/{}", ep.path.trim_start_matches('/'));

        let mut offers: Vec<Value> = Vec::new();
        if let Some(sub) = &ep.subscription {
            offers.push(build_offer(&OfferSpec {
                intent: "subscription",
                method: "mpp",
                scheme: "subscription",
                amount_usd: sub.price_usd,
                capped: false,
                network: ctx.network_slug,
                currency: &currency,
                decimals: USDC_DECIMALS,
                pay_to: ctx.pay_to,
                fee_payer: None,
                unit_price_usd: None,
                plan_id: sub.plan_id.as_deref(),
            }));
        } else if let Some(metering) = &ep.metering {
            let flat = flat_price_usd(metering);
            for scheme in metering.accepted_schemes() {
                let info = scheme_offer_info(scheme);
                // `upto` (a ceiling) and `session` (a channel cap) advertise a
                // capped amount; session also carries the per-delivery unit price.
                let (amount_usd, capped, unit_price_usd) = match scheme {
                    Scheme::MppSession => (session_cap_usd, true, flat),
                    Scheme::X402Upto => (flat, true, None),
                    _ => (flat, false, None),
                };
                offers.push(build_offer(&OfferSpec {
                    intent: info.intent,
                    method: info.method,
                    scheme: info.scheme,
                    amount_usd,
                    capped,
                    network: if info.is_x402 {
                        caip2.as_str()
                    } else {
                        ctx.network_slug
                    },
                    currency: &currency,
                    decimals: USDC_DECIMALS,
                    pay_to: ctx.pay_to,
                    fee_payer: if info.is_x402 { ctx.fee_payer } else { None },
                    unit_price_usd,
                    plan_id: None,
                }));
            }
            // x402 offers first, matching pay-kit's discovery ordering.
            offers.sort_by_key(|o| o.get("method").and_then(Value::as_str) != Some("x402"));
        }

        let mut op = Map::new();
        op.insert(
            "responses".to_string(),
            json!({
                "200": { "description": "Successful response" },
                "402": { "description": "Payment Required" },
            }),
        );
        if let Some(desc) = &ep.description {
            op.insert("summary".to_string(), json!(desc));
        }
        if !offers.is_empty() {
            op.insert(
                "x-payment-info".to_string(),
                json!({ "offers": Value::Array(offers) }),
            );
        }
        if let Some(metering) = &ep.metering
            && let Ok(value) = serde_json::to_value(metering)
        {
            op.insert(X_PAY_METERING_EXTENSION.to_string(), value);
        }

        // Multiple methods can share a path — merge into the same path item.
        let item = paths
            .entry(oas_path)
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(obj) = item.as_object_mut() {
            obj.insert(http_method_key(&ep.method).to_string(), Value::Object(op));
        }
    }

    json!({
        "openapi": "3.1.0",
        "info": { "title": api.title, "version": api.version },
        "paths": Value::Object(paths),
    })
}

/// Lowercase OpenAPI key for an HTTP method.
fn http_method_key(method: &HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "get",
        HttpMethod::Post => "post",
        HttpMethod::Put => "put",
        HttpMethod::Patch => "patch",
        HttpMethod::Delete => "delete",
    }
}

/// Flat per-call USD price: the first tier of the first pricing dimension
/// (falling back to the first variant's first dimension). `None` for free or
/// purely usage-shaped endpoints with no leading flat tier.
fn flat_price_usd(metering: &Metering) -> Option<f64> {
    metering
        .dimensions
        .iter()
        .find_map(|d| d.tiers.first().map(|t| t.price_usd))
        .or_else(|| {
            metering.variants.iter().find_map(|v| {
                v.dimensions
                    .iter()
                    .find_map(|d| d.tiers.first().map(|t| t.price_usd))
            })
        })
}

/// Discovery facets of a per-call [`Scheme`].
struct OfferInfo {
    intent: &'static str,
    method: &'static str,
    scheme: &'static str,
    is_x402: bool,
}

fn scheme_offer_info(scheme: Scheme) -> OfferInfo {
    match scheme {
        Scheme::MppCharge => OfferInfo {
            intent: "charge",
            method: "mpp",
            scheme: "charge",
            is_x402: false,
        },
        Scheme::X402Exact => OfferInfo {
            intent: "charge",
            method: "x402",
            scheme: "exact",
            is_x402: true,
        },
        Scheme::X402Upto => OfferInfo {
            intent: "charge",
            method: "x402",
            scheme: "upto",
            is_x402: true,
        },
        Scheme::MppSession => OfferInfo {
            intent: "session",
            method: "mpp",
            scheme: "session",
            is_x402: false,
        },
        Scheme::X402BatchSettlement => OfferInfo {
            intent: "session",
            method: "x402",
            scheme: "batch-settlement",
            is_x402: true,
        },
    }
}

/// Inputs for [`build_offer`].
struct OfferSpec<'a> {
    intent: &'a str,
    method: &'a str,
    scheme: &'a str,
    amount_usd: Option<f64>,
    /// `true` → render `description` as "up to N USDC" (ceilings / channel caps).
    capped: bool,
    network: &'a str,
    currency: &'a str,
    decimals: u32,
    pay_to: Option<&'a str>,
    fee_payer: Option<&'a str>,
    unit_price_usd: Option<f64>,
    plan_id: Option<&'a str>,
}

/// Build one `x-payment-info` offer matching pay-kit's discovery shape.
fn build_offer(spec: &OfferSpec) -> Value {
    let mut offer = Map::new();
    offer.insert("intent".to_string(), json!(spec.intent));
    offer.insert("method".to_string(), json!(spec.method));
    offer.insert("scheme".to_string(), json!(spec.scheme));
    offer.insert("network".to_string(), json!(spec.network));
    offer.insert("currency".to_string(), json!(spec.currency));
    if let Some(usd) = spec.amount_usd {
        offer.insert(
            "amount".to_string(),
            json!(to_base_units(usd, spec.decimals)),
        );
        let human = format!("{} {}", fmt_usd(usd), spec.currency);
        let description = if spec.capped {
            format!("up to {human}")
        } else {
            human
        };
        offer.insert("description".to_string(), json!(description));
    } else {
        // Payment Discovery requires `amount` even when pricing is dynamic.
        offer.insert("amount".to_string(), Value::Null);
    }
    if let Some(pt) = spec.pay_to {
        offer.insert("payTo".to_string(), json!(pt));
    }
    if let Some(fp) = spec.fee_payer {
        offer.insert("feePayer".to_string(), json!(fp));
    }
    if let Some(up) = spec.unit_price_usd {
        offer.insert(
            "unitPrice".to_string(),
            json!(to_base_units(up, spec.decimals)),
        );
    }
    if let Some(pid) = spec.plan_id {
        offer.insert("planId".to_string(), json!(pid));
    }
    Value::Object(offer)
}

/// USD → integer base-unit string (e.g. `0.01` USDC, 6dp → `"10000"`).
fn to_base_units(usd: f64, decimals: u32) -> String {
    ((usd * 10f64.powi(decimals as i32)).round() as u64).to_string()
}

/// Format a USD amount with minimal digits, no trailing zeros — `1.0` → "1",
/// `0.10` → "0.1", `0.0001` → "0.0001" (matches the TS playground's labels).
fn fmt_usd(usd: f64) -> String {
    format!("{usd}")
}

/// CAIP-2 chain id for a Solana network slug. localnet/surfnet (a mainnet fork)
/// and mainnet both resolve to the mainnet genesis hash.
fn solana_caip2(slug: &str) -> String {
    let genesis = match slug {
        "devnet" => "EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
        "testnet" => "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z",
        _ => "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    };
    format!("solana:{genesis}")
}

/// Strip every operation whose `(METHOD, path)` is not declared in
/// `endpoints`. Mutates the document in place.
///
/// Handles both schemas:
/// - **OpenAPI 3**: prunes methods inside each `paths.<path>` object; drops
///   path entries that end up with no methods.
/// - **Google Discovery**: prunes `methods.<name>` entries inside every
///   resource (recursing through nested `resources.<name>`); drops empty
///   `methods` / `resources` containers.
pub fn filter_to_endpoints(doc: &mut Value, endpoints: &[Endpoint]) {
    // Pre-canonicalize each YAML path so we can match it against openapi
    // paths regardless of placeholder spelling. `bigquery/v2/projects/{projectsId}/queries`
    // and `projects/{projectId}/queries` (after base-path strip) compare
    // equal because we collapse `{anything}` → `{*}`.
    let allowed: HashSet<(String, String)> = endpoints
        .iter()
        .map(|e| {
            (
                http_method_str(&e.method).to_string(),
                canonical_path(&e.path),
            )
        })
        .collect();
    // Loose fallback keys (see `loose_path_key`) so Google's collapsed
    // `{+parent}` paths still match the YAML's expanded ones.
    let allowed_loose: HashSet<(String, String, String)> = endpoints
        .iter()
        .filter_map(|e| {
            loose_path_key(&canonical_path(&e.path))
                .map(|(version, anchor)| (http_method_str(&e.method).to_string(), version, anchor))
        })
        .collect();

    if doc.get("openapi").is_some() || doc.get("swagger").is_some() {
        filter_openapi3(doc, &allowed, &allowed_loose);
    } else if doc
        .get("kind")
        .and_then(|v| v.as_str())
        .is_some_and(|k| k.starts_with("discovery#"))
    {
        filter_discovery(doc, &allowed, &allowed_loose);
    } else {
        // Unknown shape — best effort: try OpenAPI 3 if `paths` is present,
        // otherwise try Discovery if `resources` is present, else leave alone.
        if doc.get("paths").is_some() {
            filter_openapi3(doc, &allowed, &allowed_loose);
        } else if doc.get("resources").is_some() {
            filter_discovery(doc, &allowed, &allowed_loose);
        }
    }

    warn_on_unmatched_endpoints(doc, endpoints);
}

/// Attach each endpoint's full [`Metering`] block to its matching operation or
/// Discovery method as the [`X_PAY_METERING_EXTENSION`] extension, so per-model
/// `variants[]` (and any other settlement detail a live 402 probe can't
/// observe — e.g. x402-upto endpoints advertise only a ceiling) travel with
/// the published spec into pay-skills. The pay-skills build reads this
/// extension into the endpoint's inline pricing (see
/// `skills::openapi::extract_pricing_extension`).
pub fn attach_metering_extension(doc: &mut Value, endpoints: &[Endpoint]) {
    // Map canonical (METHOD, path) → the endpoint's metering, so we can find
    // the right block for each operation regardless of placeholder spelling.
    let mut metering_by_key: std::collections::HashMap<(String, String), &Metering> =
        std::collections::HashMap::new();
    let mut metering_by_loose: std::collections::HashMap<(String, String, String), &Metering> =
        std::collections::HashMap::new();
    for ep in endpoints {
        let Some(metering) = &ep.metering else {
            continue;
        };
        let method = http_method_str(&ep.method).to_string();
        let canon = canonical_path(&ep.path);
        if let Some((version, anchor)) = loose_path_key(&canon) {
            metering_by_loose.insert((method.clone(), version, anchor), metering);
        }
        metering_by_key.insert((method, canon), metering);
    }
    if metering_by_key.is_empty() {
        return;
    }

    let base_path = openapi3_base_path(doc);
    if let Some(paths) = doc.get_mut("paths").and_then(|v| v.as_object_mut()) {
        for (path, item) in paths.iter_mut() {
            let combined = if base_path.is_empty() {
                normalize_path(path)
            } else {
                format!("{}/{}", base_path, path.trim_start_matches('/'))
            };
            let canon = canonical_path(&combined);
            let Some(item_obj) = item.as_object_mut() else {
                continue;
            };
            for method in HTTP_METHODS {
                let Some(op) = item_obj.get_mut(*method).and_then(|v| v.as_object_mut()) else {
                    continue;
                };
                let upper = method.to_uppercase();
                let metering =
                    lookup_metering(&metering_by_key, &metering_by_loose, &upper, &canon);
                let Some(metering) = metering else {
                    continue;
                };
                if let Ok(value) = serde_json::to_value(metering) {
                    op.insert(X_PAY_METERING_EXTENSION.to_string(), value);
                }
            }
        }
    }

    if let Some(obj) = doc.as_object_mut() {
        attach_discovery_metering_extensions(obj, &metering_by_key, &metering_by_loose);
    }
}

fn lookup_metering<'a>(
    by_key: &'a std::collections::HashMap<(String, String), &'a Metering>,
    by_loose: &'a std::collections::HashMap<(String, String, String), &'a Metering>,
    method: &str,
    canon: &str,
) -> Option<&'a Metering> {
    by_key
        .get(&(method.to_string(), canon.to_string()))
        .copied()
        .or_else(|| {
            loose_path_key(canon)
                .and_then(|(version, anchor)| by_loose.get(&(method.to_string(), version, anchor)))
                .copied()
        })
}

fn attach_discovery_metering_extensions(
    container: &mut Map<String, Value>,
    by_key: &std::collections::HashMap<(String, String), &Metering>,
    by_loose: &std::collections::HashMap<(String, String, String), &Metering>,
) {
    if let Some(methods) = container.get_mut("methods").and_then(|v| v.as_object_mut()) {
        for (_, method) in methods.iter_mut() {
            let Some(method_obj) = method.as_object_mut() else {
                continue;
            };
            let http_method = method_obj
                .get("httpMethod")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_uppercase();
            let canon = canonical_path(discovery_method_path(&Value::Object(method_obj.clone())));
            let Some(metering) = lookup_metering(by_key, by_loose, &http_method, &canon) else {
                continue;
            };
            if let Ok(value) = serde_json::to_value(metering) {
                method_obj.insert(X_PAY_METERING_EXTENSION.to_string(), value);
            }
        }
    }

    if let Some(resources) = container
        .get_mut("resources")
        .and_then(|v| v.as_object_mut())
    {
        for (_, resource) in resources.iter_mut() {
            if let Some(resource_obj) = resource.as_object_mut() {
                attach_discovery_metering_extensions(resource_obj, by_key, by_loose);
            }
        }
    }
}

/// Loud guardrail: after filtering, flag any YAML-declared endpoint that has
/// no surviving operation in the served document. A silent drop here is what
/// produced empty `/openapi.json` specs in the first place — a path-shape
/// mismatch (or a stale/empty upstream) leaves the endpoint uncallable while
/// every check still passes. Warn per endpoint, and escalate when the filter
/// wiped out *every* declared endpoint (almost always a spec/match bug, not an
/// intentional empty gateway).
fn warn_on_unmatched_endpoints(doc: &Value, endpoints: &[Endpoint]) {
    if endpoints.is_empty() {
        return;
    }
    let served: HashSet<(String, String)> = collect_doc_operations(doc).into_iter().collect();
    let mut covered = 0usize;
    for e in endpoints {
        let method = http_method_str(&e.method).to_string();
        let canon = canonical_path(&e.path);
        let endpoint_loose = loose_path_key(&canon);
        let hit = served.iter().any(|(m, p)| {
            *m == method
                && (*p == canon
                    || (endpoint_loose.is_some() && loose_path_key(p) == endpoint_loose))
        });
        if hit {
            covered += 1;
        } else {
            tracing::warn!(
                method = %method,
                path = %e.path,
                "openapi filter: declared endpoint has no matching operation in the upstream spec; \
                 it will be absent from /openapi.json (check the upstream path shape or that the \
                 spec actually defines this operation)"
            );
        }
    }
    if covered == 0 {
        tracing::warn!(
            declared = endpoints.len(),
            "openapi filter: NO declared endpoint matched the upstream spec — /openapi.json will \
             expose zero endpoints. This usually means the upstream uses Google's collapsed \
             `{{+parent}}` paths or has an empty `paths` object."
        );
    }
}

/// Enumerate every operation surviving in `doc` as `(METHOD, canonical_path)`,
/// in the same path space the allow-list uses (OpenAPI 3 paths are prefixed
/// with the `servers[0].url` base path; Discovery prefers the expanded
/// `flatPath`). Used only by the post-filter coverage guardrail.
fn collect_doc_operations(doc: &Value) -> Vec<(String, String)> {
    let mut ops = Vec::new();
    if let Some(paths) = doc.get("paths").and_then(|v| v.as_object()) {
        let base_path = openapi3_base_path(doc);
        for (path, item) in paths {
            let Some(item_obj) = item.as_object() else {
                continue;
            };
            let combined = if base_path.is_empty() {
                normalize_path(path)
            } else {
                format!("{}/{}", base_path, path.trim_start_matches('/'))
            };
            let canon = canonical_path(&combined);
            for &method in HTTP_METHODS {
                if item_obj.contains_key(method) {
                    ops.push((method.to_uppercase(), canon.clone()));
                }
            }
        }
    }
    if let Some(resources) = doc.get("resources").and_then(|v| v.as_object()) {
        collect_discovery_operations(resources, &mut ops);
    }
    if let Some(methods) = doc.get("methods").and_then(|v| v.as_object()) {
        collect_discovery_methods(methods, &mut ops);
    }
    ops
}

fn collect_discovery_operations(resources: &Map<String, Value>, ops: &mut Vec<(String, String)>) {
    for (_, resource) in resources {
        let Some(robj) = resource.as_object() else {
            continue;
        };
        if let Some(methods) = robj.get("methods").and_then(|v| v.as_object()) {
            collect_discovery_methods(methods, ops);
        }
        if let Some(nested) = robj.get("resources").and_then(|v| v.as_object()) {
            collect_discovery_operations(nested, ops);
        }
    }
}

fn collect_discovery_methods(methods: &Map<String, Value>, ops: &mut Vec<(String, String)>) {
    for (_, m) in methods {
        let http_method = m
            .get("httpMethod")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_uppercase();
        let path = discovery_method_path(m);
        if !http_method.is_empty() {
            ops.push((http_method, canonical_path(path)));
        }
    }
}

/// Prefer Discovery's expanded `flatPath` over the collapsed `path` so it
/// lines up with the gateway YAML's expanded allow-list. Falls back to `path`.
fn discovery_method_path(method: &Value) -> &str {
    method
        .get("flatPath")
        .and_then(|v| v.as_str())
        .or_else(|| method.get("path").and_then(|v| v.as_str()))
        .unwrap_or("")
}

/// Rewrite the document's base-URL fields to `public_url`, preserving the
/// upstream's path component so that `servers[0].url + paths[i]` still
/// resolves to a route the proxy actually accepts.
///
/// Why preserve the path: Google's BigQuery upstream advertises
/// `servers[0].url = https://bigquery.googleapis.com/bigquery/v2` with
/// `paths: { /projects/.../queries }`. The proxy's allowlist mirrors that —
/// it accepts `/bigquery/v2/projects/.../queries`. If we naively rewrite
/// `servers[0].url` to just `https://bigquery.google.gateway-402.com`, the
/// downstream consumer constructs `https://…/projects/…` (no `/bigquery/v2`)
/// and 404s. Keeping the upstream's `/bigquery/v2` suffix on the proxy URL
/// yields `https://…/bigquery/v2/projects/…` which routes correctly.
///
/// Behavior:
/// - **OpenAPI 3**: each `servers[].url` is replaced with
///   `public_url + <upstream path>`. Upstream-root URLs (no path component)
///   collapse to plain `public_url`.
/// - **Discovery**: `rootUrl`/`baseUrl`/`mtlsRootUrl` are rewritten to
///   `public_url` (with trailing `/`). Discovery composes as
///   `rootUrl + servicePath` so the upstream path is carried by
///   `servicePath`, not the root URL — no preservation needed here.
pub fn rewrite_urls(doc: &mut Value, public_url: &str) {
    let proxy_root = public_url.trim_end_matches('/').to_string();
    let with_slash = format!("{proxy_root}/");

    if let Some(servers) = doc.get_mut("servers").and_then(|v| v.as_array_mut()) {
        for entry in servers {
            let Some(obj) = entry.as_object_mut() else {
                continue;
            };
            let upstream_path = obj
                .get("url")
                .and_then(|v| v.as_str())
                .map(extract_path_component)
                .unwrap_or_default();
            let rewritten = if upstream_path.is_empty() {
                proxy_root.clone()
            } else {
                format!("{proxy_root}/{upstream_path}")
            };
            obj.insert("url".to_string(), Value::String(rewritten));
        }
    }

    let root_obj = match doc.as_object_mut() {
        Some(obj) => obj,
        None => return,
    };
    for key in ["rootUrl", "baseUrl", "mtlsRootUrl"] {
        if root_obj.contains_key(key) {
            root_obj.insert(key.to_string(), Value::String(with_slash.clone()));
        }
    }
}

/// Extract the path component of an absolute URL with no leading/trailing
/// slashes. Returns `""` for root-level URLs (no path or just `/`). Used by
/// `rewrite_urls` to carry the upstream base path onto the proxy URL.
fn extract_path_component(url: &str) -> String {
    let after_scheme = match url.split("://").nth(1) {
        Some(s) => s,
        None => url,
    };
    match after_scheme.find('/') {
        Some(i) => after_scheme[i..]
            .trim_start_matches('/')
            .trim_end_matches('/')
            .to_string(),
        None => String::new(),
    }
}

/// Trim a leading `/` so YAML paths (`v1/foo`) compare equal to OpenAPI/
/// Discovery paths (`/v1/foo`).
fn normalize_path(path: &str) -> String {
    path.trim_start_matches('/').to_string()
}

/// Canonicalize a path for cross-format matching:
/// - trim leading `/`
/// - collapse every `{placeholder}` → `{*}` so `/projects/{projectId}/queries`
///   matches the YAML's `/projects/{projectsId}/queries` (Google OpenAPI 3
///   uses singular, Google Discovery uses plural; we tolerate both).
fn canonical_path(path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    // Hand-rolled `{...}` → `{*}` substitution; no regex dep needed.
    let mut out = String::with_capacity(trimmed.len());
    let mut chars = trimmed.chars();
    while let Some(c) = chars.next() {
        if c == '{' {
            // skip until matching '}'
            for c2 in chars.by_ref() {
                if c2 == '}' {
                    break;
                }
            }
            out.push_str("{*}");
        } else {
            out.push(c);
        }
    }
    out
}

/// A looser match key for bridging Google's collapsed `{+parent}` / `{+name}`
/// resource templates against the gateway YAML's *expanded* paths.
///
/// Google's discovery-derived OpenAPI keys an operation under a single
/// variable that stands in for a whole resource hierarchy, e.g.
/// `/v3/{parent}:translateText`. The proxy YAML, by contrast, must declare the
/// fully-expanded path (`v3/projects/{id}/locations/{id}:translateText`)
/// because the gateway's request allow-list matches real, expanded URLs. Exact
/// [`canonical_path`] matching can't bridge the two: after `{x}` → `{*}`
/// collapse the segment counts still differ (`v3/{*}:translateText` vs
/// `v3/projects/{*}/locations/{*}:translateText`), so every Google "custom
/// verb" endpoint gets silently dropped and the served `/openapi.json` ends up
/// with an empty `paths`.
///
/// The key anchors on the parts that survive both spellings: the leading
/// segment (API version / service prefix) and the **full trailing segment** —
/// the resource plus any Google custom verb (`{*}:translateText`,
/// `currentConditions:lookup`, `supportedLanguages`). Only the *intermediate*
/// hierarchy is discarded, which is exactly the part `{+parent}` collapses.
///
/// Keeping the whole final segment (not just the `:verb`) matters: a generic
/// verb like `:lookup` is shared by many resources, so anchoring on the verb
/// alone would let `history:lookup` masquerade as `currentConditions:lookup`.
///
/// Returns `None` when the trailing segment is a bare placeholder (e.g. a
/// get-by-id `v3/{name}`) or the leading segment is a placeholder, so those
/// fall back to exact matching only and can't be loosely over-matched.
fn loose_path_key(canonical: &str) -> Option<(String, String)> {
    let trimmed = canonical.trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let first = trimmed.split('/').next().unwrap_or("");
    if first.is_empty() || first.contains('{') {
        return None;
    }
    let last = trimmed.rsplit('/').next().unwrap_or("");
    // A placeholder-only final segment (`{*}`, no custom verb) has no stable
    // literal to anchor on — require an exact match for those.
    if last.contains('{') && !last.contains(':') {
        return None;
    }
    Some((first.to_string(), last.to_string()))
}

/// Whether an upstream operation `(method, canon)` is one of the endpoints the
/// gateway exposes. Tries an exact canonical match first, then falls back to
/// the [`loose_path_key`] anchor so Google's collapsed `{+parent}` paths match
/// the YAML's expanded ones.
fn op_matches(
    method: &str,
    canon: &str,
    allowed: &HashSet<(String, String)>,
    allowed_loose: &HashSet<(String, String, String)>,
) -> bool {
    if allowed.contains(&(method.to_string(), canon.to_string())) {
        return true;
    }
    match loose_path_key(canon) {
        Some((version, anchor)) => allowed_loose.contains(&(method.to_string(), version, anchor)),
        None => false,
    }
}

/// Extract the path component of `servers[0].url` in OpenAPI 3 docs.
/// Returns the prefix (without leading/trailing slash) so we can prepend it
/// to each `paths.<path>` key for matching against YAML allowlist entries.
/// Empty string when no servers, no path component, or `/`.
fn openapi3_base_path(doc: &Value) -> String {
    let url = match doc
        .get("servers")
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.first())
        .and_then(|s| s.get("url"))
        .and_then(|v| v.as_str())
    {
        Some(u) => u,
        None => return String::new(),
    };
    let after_scheme = match url.split("://").nth(1) {
        Some(s) => s,
        None => url,
    };
    let path_start = match after_scheme.find('/') {
        Some(i) => i,
        None => return String::new(),
    };
    after_scheme[path_start..]
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string()
}

fn http_method_str(method: &pay_types::metering::HttpMethod) -> &'static str {
    use pay_types::metering::HttpMethod::*;
    match method {
        Get => "GET",
        Post => "POST",
        Put => "PUT",
        Patch => "PATCH",
        Delete => "DELETE",
    }
}

const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "trace",
];

fn filter_openapi3(
    doc: &mut Value,
    allowed: &HashSet<(String, String)>,
    allowed_loose: &HashSet<(String, String, String)>,
) {
    // Compute the base path from servers[0].url so we can match the YAML's
    // proxy-relative paths (e.g. `bigquery/v2/projects/...`) against the
    // openapi's server-relative paths (e.g. `/projects/...`). For bigquery:
    // base_path = "bigquery/v2", openapi_path = "/projects/{projectId}/queries"
    // → combined "bigquery/v2/projects/{*}/queries" which matches the YAML's
    // canonicalized "bigquery/v2/projects/{*}/queries".
    let base_path = openapi3_base_path(doc);

    let Some(paths) = doc.get_mut("paths").and_then(|v| v.as_object_mut()) else {
        return;
    };
    let mut empty_paths: Vec<String> = Vec::new();
    for (path, item) in paths.iter_mut() {
        let combined = if base_path.is_empty() {
            normalize_path(path)
        } else {
            format!("{}/{}", base_path, path.trim_start_matches('/'))
        };
        let canon = canonical_path(&combined);
        let Some(item_obj) = item.as_object_mut() else {
            continue;
        };
        let methods_to_remove: Vec<String> = HTTP_METHODS
            .iter()
            .filter(|m| item_obj.contains_key(**m))
            .filter(|m| !op_matches(&m.to_uppercase(), &canon, allowed, allowed_loose))
            .map(|m| (*m).to_string())
            .collect();
        for m in methods_to_remove {
            item_obj.remove(&m);
        }
        if !item_obj.keys().any(|k| HTTP_METHODS.contains(&k.as_str())) {
            empty_paths.push(path.clone());
        }
    }
    for p in empty_paths {
        paths.remove(&p);
    }
}

fn filter_discovery(
    doc: &mut Value,
    allowed: &HashSet<(String, String)>,
    allowed_loose: &HashSet<(String, String, String)>,
) {
    if let Some(root_obj) = doc.as_object_mut() {
        prune_resources(root_obj, allowed, allowed_loose);
    }
}

/// Strip upstream-auth metadata that doesn't apply to proxy callers. The
/// proxy handles upstream credentials internally (Google OAuth2, API keys,
/// etc.); leaving the auth schemes in the served doc misleads agents into
/// attaching tokens that the proxy won't honor anyway. Removes:
///
/// - `components.securitySchemes` (OpenAPI 3) — drops the bucket entirely.
/// - `security:` arrays at the root and on every operation (OpenAPI 3).
/// - `auth:` block (Google Discovery) at the root.
/// - `scopes:` array on every Discovery method, recursively through nested
///   resources.
pub fn strip_upstream_auth(doc: &mut Value) {
    if let Some(obj) = doc.as_object_mut() {
        // OpenAPI 3 root-level security and securitySchemes bucket.
        obj.remove("security");
        if let Some(components) = obj.get_mut("components").and_then(|v| v.as_object_mut()) {
            components.remove("securitySchemes");
            if components.is_empty() {
                obj.remove("components");
            }
        }
        // Discovery root-level auth block.
        obj.remove("auth");
    }

    // Per-operation security on OpenAPI 3 paths.
    if let Some(paths) = doc.get_mut("paths").and_then(|v| v.as_object_mut()) {
        for (_, item) in paths.iter_mut() {
            let Some(item_obj) = item.as_object_mut() else {
                continue;
            };
            for &method in HTTP_METHODS {
                if let Some(op) = item_obj.get_mut(method).and_then(|v| v.as_object_mut()) {
                    op.remove("security");
                }
            }
        }
    }

    // Per-method `scopes` arrays on Discovery resources, recursively.
    if let Some(resources) = doc.get_mut("resources").and_then(|v| v.as_object_mut()) {
        strip_discovery_method_scopes(resources);
    }
    if let Some(methods) = doc.get_mut("methods").and_then(|v| v.as_object_mut()) {
        for (_, m) in methods.iter_mut() {
            if let Some(mobj) = m.as_object_mut() {
                mobj.remove("scopes");
            }
        }
    }
}

fn strip_discovery_method_scopes(resources: &mut Map<String, Value>) {
    for (_, resource) in resources.iter_mut() {
        let Some(robj) = resource.as_object_mut() else {
            continue;
        };
        if let Some(methods) = robj.get_mut("methods").and_then(|v| v.as_object_mut()) {
            for (_, m) in methods.iter_mut() {
                if let Some(mobj) = m.as_object_mut() {
                    mobj.remove("scopes");
                }
            }
        }
        if let Some(nested) = robj.get_mut("resources").and_then(|v| v.as_object_mut()) {
            strip_discovery_method_scopes(nested);
        }
    }
}

/// Drop schemas / parameters / requestBodies / responses that no surviving
/// operation transitively references. Run *after* [`filter_to_endpoints`]
/// so the reachability seed only includes kept operations — the upstream's
/// dead schema baggage gets cut along with the methods that referenced it.
///
/// Handles both shapes:
/// - **OpenAPI 3**: walks `paths.<path>.<method>` (plus `security:` + the
///   root `tags:`) for `$ref` strings, then BFS-expands through
///   `components.{schemas,parameters,requestBodies,responses,headers,examples,
///   links,callbacks,pathItems}`. Unreferenced sub-entries are removed.
/// - **Google Discovery**: walks `resources.*.methods.*.{request,response,
///   parameters}` for `$ref` strings (each pointing into the top-level
///   `schemas` bucket), BFS-expands through `schemas`, and removes
///   unreferenced top-level schemas.
pub fn prune_unused_components(doc: &mut Value) {
    if doc.get("openapi").is_some() || doc.get("swagger").is_some() {
        prune_openapi3_components(doc);
    } else if doc
        .get("kind")
        .and_then(|v| v.as_str())
        .is_some_and(|k| k.starts_with("discovery#"))
    {
        prune_discovery_schemas(doc);
    } else if doc.get("paths").is_some() {
        // Best-effort fallback for OpenAPI-shaped docs missing the marker.
        prune_openapi3_components(doc);
    } else if doc.get("schemas").is_some() && doc.get("resources").is_some() {
        prune_discovery_schemas(doc);
    }
}

/// Recursively walk a JSON value collecting every `$ref` string.
fn collect_refs(value: &Value, refs: &mut HashSet<String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if k == "$ref" {
                    if let Some(s) = v.as_str() {
                        refs.insert(s.to_string());
                    }
                } else {
                    collect_refs(v, refs);
                }
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_refs(v, refs);
            }
        }
        _ => {}
    }
}

const OPENAPI3_COMPONENT_SUBKEYS: &[&str] = &[
    "schemas",
    "parameters",
    "requestBodies",
    "responses",
    "examples",
    "headers",
    "links",
    "callbacks",
    "pathItems",
];

fn prune_openapi3_components(doc: &mut Value) {
    let mut reachable: HashSet<String> = HashSet::new();

    // Seed: every $ref under the kept paths and root-level fields that may
    // legitimately reference components (`security` is name-based not $ref,
    // skip it; `tags` is name-based too).
    if let Some(paths) = doc.get("paths") {
        collect_refs(paths, &mut reachable);
    }
    // BFS through components: each ref's target may itself reference more.
    let mut frontier: Vec<String> = reachable.iter().cloned().collect();
    while let Some(r) = frontier.pop() {
        let Some(pointer) = r.strip_prefix('#') else {
            continue; // external/file refs not supported
        };
        if let Some(target) = doc.pointer(pointer) {
            let mut new_refs = HashSet::new();
            collect_refs(target, &mut new_refs);
            for nr in new_refs {
                if reachable.insert(nr.clone()) {
                    frontier.push(nr);
                }
            }
        }
    }

    // Prune unreferenced sub-entries from `components.<sub>`.
    let mut drop_components = false;
    if let Some(components) = doc.get_mut("components").and_then(|v| v.as_object_mut()) {
        for sub_key in OPENAPI3_COMPONENT_SUBKEYS {
            let to_remove: Vec<String> = match components.get(*sub_key).and_then(|v| v.as_object())
            {
                Some(sub) => sub
                    .keys()
                    .filter(|k| {
                        let full_ref = format!("#/components/{sub_key}/{k}");
                        !reachable.contains(&full_ref)
                    })
                    .cloned()
                    .collect(),
                None => continue,
            };
            if let Some(sub) = components.get_mut(*sub_key).and_then(|v| v.as_object_mut()) {
                for k in to_remove {
                    sub.remove(&k);
                }
                if sub.is_empty() {
                    components.remove(*sub_key);
                }
            }
        }
        drop_components = components.is_empty();
    }
    if drop_components && let Some(root) = doc.as_object_mut() {
        root.remove("components");
    }
}

fn prune_discovery_schemas(doc: &mut Value) {
    let mut reachable: HashSet<String> = HashSet::new();

    // Seed from kept resources/methods. Discovery `$ref` values are bare
    // schema names (no `#/...` prefix); they index into the top-level
    // `schemas` bucket.
    if let Some(resources) = doc.get("resources") {
        collect_refs(resources, &mut reachable);
    }
    // Top-level `methods` (some discovery docs put methods at the root).
    if let Some(methods) = doc.get("methods") {
        collect_refs(methods, &mut reachable);
    }

    // BFS expand through schemas — each schema may reference others.
    let mut frontier: Vec<String> = reachable.iter().cloned().collect();
    while let Some(name) = frontier.pop() {
        if let Some(schema) = doc.pointer(&format!("/schemas/{name}")) {
            let mut new_refs = HashSet::new();
            collect_refs(schema, &mut new_refs);
            for nr in new_refs {
                if reachable.insert(nr.clone()) {
                    frontier.push(nr);
                }
            }
        }
    }

    // Drop unreferenced schemas; drop the bucket entirely if empty.
    let mut drop_bucket = false;
    if let Some(schemas) = doc.get_mut("schemas").and_then(|v| v.as_object_mut()) {
        let to_remove: Vec<String> = schemas
            .keys()
            .filter(|k| !reachable.contains(*k))
            .cloned()
            .collect();
        for k in to_remove {
            schemas.remove(&k);
        }
        drop_bucket = schemas.is_empty();
    }
    if drop_bucket && let Some(root) = doc.as_object_mut() {
        root.remove("schemas");
    }
}

/// Walk a discovery container (root or nested resource) and prune `methods`
/// and nested `resources` that don't survive the allowlist. Returns `true` if
/// the container has any surviving methods or resources after pruning.
fn prune_resources(
    container: &mut Map<String, Value>,
    allowed: &HashSet<(String, String)>,
    allowed_loose: &HashSet<(String, String, String)>,
) -> bool {
    // Prune methods.
    if let Some(methods) = container.get_mut("methods").and_then(|v| v.as_object_mut()) {
        let to_remove: Vec<String> = methods
            .iter()
            .filter_map(|(name, m)| {
                let http_method = m
                    .get("httpMethod")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_uppercase();
                // Prefer the expanded `flatPath` over the collapsed `path` so
                // it matches the gateway YAML's expanded allow-list.
                let path = discovery_method_path(m);
                if op_matches(&http_method, &canonical_path(path), allowed, allowed_loose) {
                    None
                } else {
                    Some(name.clone())
                }
            })
            .collect();
        for name in to_remove {
            methods.remove(&name);
        }
        if methods.is_empty() {
            container.remove("methods");
        }
    }

    // Recurse into nested resources.
    if let Some(resources) = container
        .get_mut("resources")
        .and_then(|v| v.as_object_mut())
    {
        let names: Vec<String> = resources.keys().cloned().collect();
        for name in names {
            let keep = if let Some(r) = resources.get_mut(&name).and_then(|v| v.as_object_mut()) {
                prune_resources(r, allowed, allowed_loose)
            } else {
                false
            };
            if !keep {
                resources.remove(&name);
            }
        }
        if resources.is_empty() {
            container.remove("resources");
        }
    }

    container.contains_key("methods") || container.contains_key("resources")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ep(method: pay_types::metering::HttpMethod, path: &str) -> Endpoint {
        Endpoint {
            method,
            path: path.to_string(),
            description: Some("test endpoint".to_string()),
            resource: None,
            metering: None,
            routing: None,
            subscription: None,
        }
    }

    use pay_types::metering::HttpMethod::{Get, Post};

    fn metered_ep(
        method: pay_types::metering::HttpMethod,
        path: &str,
        metering: Metering,
    ) -> Endpoint {
        Endpoint {
            metering: Some(metering),
            ..ep(method, path)
        }
    }

    #[test]
    fn synthesized_openapi_carries_variant_descriptions_in_metering_extension() {
        let metering: Metering = serde_json::from_value(json!({
            "schemes": ["x402-upto"],
            "variants": [{
                "param": "model",
                "value": "gemini-2.5-flash",
                "description": "Fast Gemini model for low-latency generation.",
                "dimensions": [
                    { "direction": "input", "unit": "tokens", "scale": 1000000, "tiers": [{ "price_usd": 0.345 }] },
                    { "direction": "output", "unit": "tokens", "scale": 1000000, "tiers": [{ "price_usd": 2.875 }] }
                ]
            }]
        }))
        .unwrap();
        let api = ApiSpec {
            name: "gemini".to_string(),
            subdomain: "gemini".to_string(),
            title: "Gemini".to_string(),
            description: "Gemini".to_string(),
            category: pay_types::metering::ApiCategory::AiMl,
            version: "v1".to_string(),
            env: Default::default(),
            routing: pay_types::metering::RoutingConfig::Respond {},
            accounting: Default::default(),
            endpoints: vec![metered_ep(
                Post,
                "v1beta/models/{modelsId}:generateContent",
                metering,
            )],
            free_tier: None,
            quotas: None,
            notes: None,
            operator: None,
            recipients: Default::default(),
            session: None,
            batch_settlement: None,
        };
        let doc = synthesize_from_spec(
            &api,
            &DiscoveryContext {
                network_slug: "mainnet",
                pay_to: Some("recipient"),
                fee_payer: Some("fee-payer"),
            },
        );

        let op = &doc["paths"]["/v1beta/models/{modelsId}:generateContent"]["post"];
        assert!(op.get("x-payment-info").is_some());
        let variants = op[X_PAY_METERING_EXTENSION]["variants"].as_array().unwrap();
        assert_eq!(variants[0]["value"], "gemini-2.5-flash");
        assert_eq!(
            variants[0]["description"],
            "Fast Gemini model for low-latency generation."
        );
        assert_eq!(variants[0]["dimensions"][1]["tiers"][0]["price_usd"], 2.875);
    }

    #[test]
    fn attach_metering_extension_carries_variants_onto_operations() {
        // Gemini-shaped: a custom-verb POST priced per model via variants.
        let metering: Metering = serde_json::from_value(json!({
            "schemes": ["x402-upto"],
            "variants": [{
                "param": "model",
                "value": "gemini-2.5-flash",
                "description": "Fast Gemini model for low-latency generation.",
                "dimensions": [
                    { "direction": "input", "unit": "tokens", "scale": 1000000, "tiers": [{ "price_usd": 0.345 }] },
                    { "direction": "output", "unit": "tokens", "scale": 1000000, "tiers": [{ "price_usd": 2.875 }] }
                ]
            }]
        }))
        .unwrap();

        let mut doc = json!({
            "openapi": "3.0.3",
            "servers": [{"url": "https://generativelanguage.google.gateway-402.com"}],
            "paths": {
                "/v1beta/models/{modelsId}:generateContent": { "post": { "summary": "generate" } },
                "/v1beta/models": { "get": { "summary": "list" } }
            }
        });
        let endpoints = vec![
            metered_ep(Post, "v1beta/models/{modelsId}:generateContent", metering),
            ep(Get, "v1beta/models"),
        ];
        attach_metering_extension(&mut doc, &endpoints);

        // Priced op carries the variant table verbatim…
        let generate = &doc["paths"]["/v1beta/models/{modelsId}:generateContent"]["post"];
        let variants = generate[X_PAY_METERING_EXTENSION]["variants"]
            .as_array()
            .unwrap();
        assert_eq!(variants[0]["value"], "gemini-2.5-flash");
        assert_eq!(
            variants[0]["description"],
            "Fast Gemini model for low-latency generation."
        );
        assert_eq!(variants[0]["dimensions"][1]["tiers"][0]["price_usd"], 2.875);
        // …and the round-trip parses back through the pay-skills reader shape.
        assert!(
            serde_json::from_value::<Metering>(generate[X_PAY_METERING_EXTENSION].clone()).is_ok()
        );
        // The unmetered list endpoint gets no extension.
        assert!(
            doc["paths"]["/v1beta/models"]["get"]
                .get(X_PAY_METERING_EXTENSION)
                .is_none()
        );
    }

    #[test]
    fn attach_metering_extension_is_a_noop_without_metering() {
        let mut doc = json!({
            "openapi": "3.0.3",
            "paths": { "/v1/thing": { "post": { "summary": "s" } } }
        });
        attach_metering_extension(&mut doc, &[ep(Post, "v1/thing")]);
        assert!(
            doc["paths"]["/v1/thing"]["post"]
                .get(X_PAY_METERING_EXTENSION)
                .is_none()
        );
    }

    #[test]
    fn attach_metering_extension_carries_variants_onto_discovery_methods() {
        let metering: Metering = serde_json::from_value(json!({
            "schemes": ["x402-upto"],
            "variants": [{
                "param": "model",
                "value": "gemini-2.5-flash",
                "description": "Low-latency chat and coding tasks.",
                "dimensions": [
                    { "direction": "input", "unit": "tokens", "scale": 1000000, "tiers": [{ "price_usd": 0.345 }] },
                    { "direction": "output", "unit": "tokens", "scale": 1000000, "tiers": [{ "price_usd": 2.875 }] }
                ]
            }]
        }))
        .unwrap();

        let mut doc = json!({
            "kind": "discovery#restDescription",
            "resources": {
                "models": {
                    "methods": {
                        "generateContent": {
                            "httpMethod": "POST",
                            "path": "v1beta/models/{modelsId}:generateContent",
                            "flatPath": "v1beta/models/{modelsId}:generateContent"
                        },
                        "list": {
                            "httpMethod": "GET",
                            "path": "v1beta/models",
                            "flatPath": "v1beta/models"
                        }
                    }
                }
            }
        });
        let endpoints = vec![
            metered_ep(Post, "v1beta/models/{modelsId}:generateContent", metering),
            ep(Get, "v1beta/models"),
        ];
        attach_metering_extension(&mut doc, &endpoints);

        let generate = &doc["resources"]["models"]["methods"]["generateContent"];
        let variants = generate[X_PAY_METERING_EXTENSION]["variants"]
            .as_array()
            .unwrap();
        assert_eq!(variants[0]["value"], "gemini-2.5-flash");
        assert_eq!(
            variants[0]["description"],
            "Low-latency chat and coding tasks."
        );
        assert_eq!(variants[0]["dimensions"][1]["tiers"][0]["price_usd"], 2.875);
        assert!(
            doc["resources"]["models"]["methods"]["list"]
                .get(X_PAY_METERING_EXTENSION)
                .is_none()
        );
    }

    #[test]
    fn filter_openapi3_keeps_only_allowed_methods() {
        let mut doc = json!({
            "openapi": "3.1.0",
            "servers": [{"url": "https://upstream.example.com/"}],
            "paths": {
                "/v1/keep": { "post": {"summary": "kept"}, "get": {"summary": "removed"} },
                "/v1/drop": { "post": {"summary": "removed-entirely"} }
            }
        });
        let endpoints = vec![ep(Post, "v1/keep")];
        filter_to_endpoints(&mut doc, &endpoints);

        let paths = doc["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 1);
        assert!(paths.contains_key("/v1/keep"));
        let kept = paths["/v1/keep"].as_object().unwrap();
        assert!(kept.contains_key("post"));
        assert!(!kept.contains_key("get"));
    }

    #[test]
    fn filter_discovery_walks_nested_resources_and_methods() {
        let mut doc = json!({
            "kind": "discovery#restDescription",
            "rootUrl": "https://upstream.example.com/",
            "resources": {
                "currentConditions": {
                    "methods": {
                        "lookup": {
                            "httpMethod": "POST",
                            "path": "v1/currentConditions:lookup"
                        }
                    }
                },
                "history": {
                    "methods": {
                        "lookup": {
                            "httpMethod": "POST",
                            "path": "v1/history:lookup"
                        }
                    }
                },
                "mapTypes": {
                    "resources": {
                        "heatmapTiles": {
                            "methods": {
                                "lookup": {
                                    "httpMethod": "GET",
                                    "path": "v1/mapTypes/{mapType}/heatmapTiles/{zoom}/{x}/{y}"
                                }
                            }
                        }
                    }
                }
            }
        });

        let endpoints = vec![
            ep(Post, "v1/currentConditions:lookup"),
            ep(Get, "v1/mapTypes/{mapType}/heatmapTiles/{zoom}/{x}/{y}"),
        ];
        filter_to_endpoints(&mut doc, &endpoints);

        let resources = doc["resources"].as_object().unwrap();
        // history resource should be gone (its only method wasn't allowlisted).
        assert!(!resources.contains_key("history"));
        // currentConditions kept.
        assert!(
            resources["currentConditions"]["methods"]
                .as_object()
                .unwrap()
                .contains_key("lookup")
        );
        // mapTypes nested resource kept (heatmapTiles.lookup was allowlisted).
        assert!(
            resources["mapTypes"]["resources"]["heatmapTiles"]["methods"]
                .as_object()
                .unwrap()
                .contains_key("lookup")
        );
    }

    #[test]
    fn rewrite_urls_preserves_upstream_path_component() {
        // BigQuery shape: upstream advertises a /bigquery/v2 base in
        // servers[0].url and bare `/projects/...` paths. The proxy's
        // allowlist accepts `/bigquery/v2/...`, so the rewritten server
        // must keep the path component or downstream consumers 404.
        let mut doc = json!({
            "openapi": "3.1.0",
            "servers": [
                {"url": "https://bigquery.googleapis.com/bigquery/v2"},
                {"url": "https://other.example.com/"}
            ]
        });
        rewrite_urls(&mut doc, "https://bigquery.proxy.example.com");
        let servers = doc["servers"].as_array().unwrap();
        assert_eq!(
            servers[0]["url"],
            json!("https://bigquery.proxy.example.com/bigquery/v2")
        );
        // Root-level upstream collapses to plain proxy URL.
        assert_eq!(
            servers[1]["url"],
            json!("https://bigquery.proxy.example.com")
        );
    }

    #[test]
    fn rewrite_urls_strips_trailing_slash_on_proxy_url() {
        let mut doc = json!({
            "openapi": "3.1.0",
            "servers": [{"url": "https://upstream.example.com/v1/"}]
        });
        // Trailing slash on public_url should not double up.
        rewrite_urls(&mut doc, "https://proxy.example.com/");
        assert_eq!(
            doc["servers"][0]["url"],
            json!("https://proxy.example.com/v1")
        );
    }

    #[test]
    fn rewrite_urls_updates_discovery_root_and_base_urls() {
        let mut doc = json!({
            "kind": "discovery#restDescription",
            "rootUrl": "https://upstream.example.com/",
            "baseUrl": "https://upstream.example.com/v1/",
            "mtlsRootUrl": "https://upstream.mtls.example.com/"
        });
        rewrite_urls(&mut doc, "https://proxy.example.com/");
        // Trailing slash preserved on rewrite.
        assert_eq!(doc["rootUrl"], json!("https://proxy.example.com/"));
        assert_eq!(doc["baseUrl"], json!("https://proxy.example.com/"));
        assert_eq!(doc["mtlsRootUrl"], json!("https://proxy.example.com/"));
    }

    #[test]
    fn rewrite_urls_is_noop_for_missing_fields() {
        let mut doc = json!({"foo": "bar"});
        rewrite_urls(&mut doc, "https://proxy.example.com");
        assert_eq!(doc, json!({"foo": "bar"}));
    }

    #[test]
    fn rewrite_urls_handles_root_level_upstream_unchanged() {
        // Civicinfo / language / speech / etc. shape: upstream root-level
        // with a trailing slash. Path collapses to empty → bare proxy URL.
        // This is the pre-fix behavior, kept stable for the majority case.
        for upstream in [
            "https://civicinfo.googleapis.com/",
            "https://civicinfo.googleapis.com",
            "https://language.googleapis.com/",
            "https://speech.googleapis.com/",
        ] {
            let mut doc = json!({
                "openapi": "3.0.0",
                "servers": [{"url": upstream}]
            });
            rewrite_urls(&mut doc, "https://proxy.example.com");
            assert_eq!(
                doc["servers"][0]["url"],
                json!("https://proxy.example.com"),
                "root-level upstream `{upstream}` should produce bare proxy URL"
            );
        }
    }

    #[test]
    fn rewrite_urls_handles_multi_segment_upstream_path() {
        // Hypothetical upstream that nests deeper than bigquery.
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com/v3/foo/bar"}]
        });
        rewrite_urls(&mut doc, "https://proxy.example.com");
        assert_eq!(
            doc["servers"][0]["url"],
            json!("https://proxy.example.com/v3/foo/bar")
        );
    }

    #[test]
    fn rewrite_urls_handles_trailing_slash_on_upstream() {
        // `https://x.com/v2/` should produce `proxy/v2`, not `proxy/v2/`.
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://upstream.example.com/v2/"}]
        });
        rewrite_urls(&mut doc, "https://proxy.example.com");
        assert_eq!(
            doc["servers"][0]["url"],
            json!("https://proxy.example.com/v2")
        );
    }

    #[test]
    fn rewrite_urls_handles_url_with_port() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://localhost:8443/api/v2"}]
        });
        rewrite_urls(&mut doc, "https://proxy.example.com:9443");
        assert_eq!(
            doc["servers"][0]["url"],
            json!("https://proxy.example.com:9443/api/v2")
        );
    }

    #[test]
    fn rewrite_urls_mixed_servers_each_keep_their_own_path() {
        // A server array with one path-bearing entry and one root entry —
        // each is rewritten independently, preserving its own path.
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [
                {"url": "https://upstream.example.com/api/v2"},
                {"url": "https://upstream.example.com/"}
            ]
        });
        rewrite_urls(&mut doc, "https://proxy.example.com");
        let servers = doc["servers"].as_array().unwrap();
        assert_eq!(servers[0]["url"], json!("https://proxy.example.com/api/v2"));
        assert_eq!(servers[1]["url"], json!("https://proxy.example.com"));
    }

    /// End-to-end flow modeled on bigquery: load an upstream-shaped doc,
    /// filter it down to a YAML's allowlist, rewrite the URLs, then
    /// reconstruct `servers[0].url + paths[i]` and assert that's the URL
    /// the proxy actually accepts (`/bigquery/v2/projects/.../queries`).
    ///
    /// This is the regression test for the audit failure in pay-skills:
    /// catalog consumers were constructing bare URLs that 404'd because
    /// `rewrite_urls` was stripping the upstream base path.
    #[test]
    fn pipeline_bigquery_shape_constructs_correct_proxy_url() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://bigquery.googleapis.com/bigquery/v2"}],
            "paths": {
                "/projects/{projectId}/queries": {
                    "post": {"summary": "kept"},
                    "get":  {"summary": "drop me"}
                },
                "/projects/{projectId}/datasets": {
                    "get": {"summary": "drop me too"}
                }
            }
        });
        // Mirrors the bigquery.yml allowlist (POST queries only).
        let endpoints = vec![ep(Post, "bigquery/v2/projects/{projectsId}/queries")];
        filter_to_endpoints(&mut doc, &endpoints);
        rewrite_urls(&mut doc, "https://bigquery.proxy.example.com");

        // Server keeps the upstream base path on the proxy URL.
        assert_eq!(
            doc["servers"][0]["url"],
            json!("https://bigquery.proxy.example.com/bigquery/v2")
        );
        // Only the allow-listed POST survives.
        let paths = doc["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 1);
        let queries = paths["/projects/{projectId}/queries"].as_object().unwrap();
        assert!(queries.contains_key("post"));
        assert!(!queries.contains_key("get"));

        // A consumer constructing `servers[0].url + path` lands on the URL
        // the proxy actually accepts.
        let server = doc["servers"][0]["url"].as_str().unwrap();
        let path = paths.keys().next().unwrap();
        assert_eq!(
            format!("{server}{path}"),
            "https://bigquery.proxy.example.com/bigquery/v2/projects/{projectId}/queries"
        );
    }

    /// End-to-end flow modeled on civicinfo: upstream root server, paths
    /// already include the version prefix. The constructed URL must keep
    /// that prefix and not have it duplicated.
    #[test]
    fn pipeline_civicinfo_shape_constructs_correct_proxy_url() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://civicinfo.googleapis.com/"}],
            "paths": {
                "/civicinfo/v2/divisions": {"get": {"summary": "kept"}},
                "/civicinfo/v2/elections": {"get": {"summary": "drop me"}}
            }
        });
        let endpoints = vec![ep(Get, "civicinfo/v2/divisions")];
        filter_to_endpoints(&mut doc, &endpoints);
        rewrite_urls(&mut doc, "https://civicinfo.proxy.example.com");

        // Root-level upstream → bare proxy URL.
        assert_eq!(
            doc["servers"][0]["url"],
            json!("https://civicinfo.proxy.example.com")
        );
        let paths = doc["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 1);
        assert!(paths.contains_key("/civicinfo/v2/divisions"));

        let server = doc["servers"][0]["url"].as_str().unwrap();
        let path = paths.keys().next().unwrap();
        assert_eq!(
            format!("{server}{path}"),
            "https://civicinfo.proxy.example.com/civicinfo/v2/divisions"
        );
    }

    /// End-to-end flow on a service that emits an empty `paths: {}` after
    /// filtering (e.g. the YAML's allowlist doesn't match anything in the
    /// upstream). `rewrite_urls` should still run and produce a sane
    /// servers entry — no panic, no malformed output.
    #[test]
    fn pipeline_handles_empty_paths_after_filter() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://documentai.googleapis.com/"}],
            "paths": {
                "/v1/{name}:reviewDocument": {"post": {}}
            }
        });
        // Allowlist that doesn't match anything (different path shape).
        let endpoints = vec![ep(
            Post,
            "v1/projects/{*}/locations/{*}/processors/{*}:process",
        )];
        filter_to_endpoints(&mut doc, &endpoints);
        rewrite_urls(&mut doc, "https://documentai.proxy.example.com");
        assert_eq!(
            doc["servers"][0]["url"],
            json!("https://documentai.proxy.example.com")
        );
        assert!(doc["paths"].as_object().unwrap().is_empty());
    }

    #[test]
    fn filter_drops_paths_with_no_surviving_methods() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "paths": {
                "/v1/a": { "get": {} },
                "/v1/b": { "get": {} }
            }
        });
        let endpoints = vec![ep(Get, "v1/a")];
        filter_to_endpoints(&mut doc, &endpoints);
        let paths = doc["paths"].as_object().unwrap();
        assert!(paths.contains_key("/v1/a"));
        assert!(!paths.contains_key("/v1/b"));
    }

    #[test]
    fn prune_openapi3_drops_unreferenced_schemas() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "paths": {
                "/v1/keep": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Used"}
                                }
                            }
                        },
                        "responses": {
                            "200": {"$ref": "#/components/responses/Ok"}
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Used":      {"type": "object", "properties": {"nested": {"$ref": "#/components/schemas/Nested"}}},
                    "Nested":    {"type": "string"},
                    "Orphan":    {"type": "object"},
                    "AlsoOrphan":{"type": "object"}
                },
                "responses": {
                    "Ok":         {"description": "ok"},
                    "Unused":     {"description": "unused"}
                },
                "requestBodies": {"DeadBody": {"description": "x"}},
                "parameters":    {"DeadParam": {"name": "p"}}
            }
        });
        prune_unused_components(&mut doc);

        let schemas = doc["components"]["schemas"].as_object().unwrap();
        assert!(schemas.contains_key("Used"));
        assert!(schemas.contains_key("Nested")); // transitive
        assert!(!schemas.contains_key("Orphan"));
        assert!(!schemas.contains_key("AlsoOrphan"));

        let responses = doc["components"]["responses"].as_object().unwrap();
        assert!(responses.contains_key("Ok"));
        assert!(!responses.contains_key("Unused"));

        // Unused buckets dropped entirely.
        assert!(
            !doc["components"]
                .as_object()
                .unwrap()
                .contains_key("requestBodies")
        );
        assert!(
            !doc["components"]
                .as_object()
                .unwrap()
                .contains_key("parameters")
        );
    }

    #[test]
    fn prune_openapi3_drops_components_object_when_empty() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "paths": {"/v1/x": {"get": {}}},
            "components": {
                "schemas": {"Orphan": {"type": "object"}},
                "parameters": {"DeadParam": {"name": "p"}}
            }
        });
        prune_unused_components(&mut doc);
        assert!(!doc.as_object().unwrap().contains_key("components"));
    }

    #[test]
    fn prune_discovery_drops_unreferenced_schemas() {
        let mut doc = json!({
            "kind": "discovery#restDescription",
            "schemas": {
                "Used":     {"type": "object", "properties": {"x": {"$ref": "Nested"}}},
                "Nested":   {"type": "string"},
                "Orphan":   {"type": "object"},
                "Disjoint": {"type": "object", "properties": {"y": {"$ref": "OtherOrphan"}}},
                "OtherOrphan": {"type": "object"}
            },
            "resources": {
                "things": {
                    "methods": {
                        "lookup": {
                            "httpMethod": "POST",
                            "path": "v1/things:lookup",
                            "request":  {"$ref": "Used"},
                            "response": {"$ref": "Used"}
                        }
                    }
                }
            }
        });
        prune_unused_components(&mut doc);
        let schemas = doc["schemas"].as_object().unwrap();
        assert!(schemas.contains_key("Used"));
        assert!(schemas.contains_key("Nested")); // transitive
        assert!(!schemas.contains_key("Orphan"));
        assert!(!schemas.contains_key("Disjoint"));
        assert!(!schemas.contains_key("OtherOrphan"));
    }

    #[test]
    fn strip_auth_drops_openapi3_security_and_scheme_bucket() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "security": [{"oauth2": ["scope.a"]}],
            "paths": {
                "/v1/x": {
                    "post": {
                        "summary": "x",
                        "security": [{"oauth2": ["scope.b"]}]
                    }
                }
            },
            "components": {
                "schemas": {"Foo": {"type": "object"}},
                "securitySchemes": {
                    "oauth2": {"type": "oauth2", "flows": {}}
                }
            }
        });
        strip_upstream_auth(&mut doc);

        // Root-level + per-operation security gone.
        assert!(!doc.as_object().unwrap().contains_key("security"));
        assert!(
            !doc["paths"]["/v1/x"]["post"]
                .as_object()
                .unwrap()
                .contains_key("security")
        );
        // securitySchemes bucket gone (other components survive).
        let comp = doc["components"].as_object().unwrap();
        assert!(!comp.contains_key("securitySchemes"));
        assert!(comp.contains_key("schemas"));
    }

    #[test]
    fn strip_auth_drops_components_when_only_security_schemes_were_left() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "components": {
                "securitySchemes": {"oauth2": {"type": "oauth2"}}
            }
        });
        strip_upstream_auth(&mut doc);
        assert!(!doc.as_object().unwrap().contains_key("components"));
    }

    #[test]
    fn strip_auth_drops_discovery_auth_and_method_scopes() {
        let mut doc = json!({
            "kind": "discovery#restDescription",
            "auth": {
                "oauth2": {"scopes": {"https://example.com/auth/x": {"description": "x"}}}
            },
            "resources": {
                "things": {
                    "methods": {
                        "lookup": {
                            "httpMethod": "POST",
                            "path": "v1/things:lookup",
                            "scopes": ["https://example.com/auth/x"]
                        }
                    },
                    "resources": {
                        "nested": {
                            "methods": {
                                "get": {
                                    "httpMethod": "GET",
                                    "path": "v1/things/nested",
                                    "scopes": ["https://example.com/auth/y"]
                                }
                            }
                        }
                    }
                }
            }
        });
        strip_upstream_auth(&mut doc);

        assert!(!doc.as_object().unwrap().contains_key("auth"));
        // Scopes removed from every method, including nested resources.
        assert!(
            !doc["resources"]["things"]["methods"]["lookup"]
                .as_object()
                .unwrap()
                .contains_key("scopes")
        );
        assert!(
            !doc["resources"]["things"]["resources"]["nested"]["methods"]["get"]
                .as_object()
                .unwrap()
                .contains_key("scopes")
        );
        // Methods themselves are still there (we only stripped scopes, not the methods).
        assert_eq!(
            doc["resources"]["things"]["methods"]["lookup"]["httpMethod"],
            json!("POST")
        );
    }

    #[test]
    fn filter_normalizes_leading_slash_for_path_match() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "paths": { "/v1/x": { "get": {} } }
        });
        // YAML path without leading slash should still match.
        let endpoints = vec![ep(Get, "v1/x")];
        filter_to_endpoints(&mut doc, &endpoints);
        assert!(doc["paths"].as_object().unwrap().contains_key("/v1/x"));
    }

    // ───────────────────────────────────────────────────────────────────
    // loose_path_key — bridging Google's collapsed `{+parent}` templates
    // ───────────────────────────────────────────────────────────────────

    #[test]
    fn loose_key_anchors_on_version_and_custom_verb() {
        // Both the collapsed upstream form and the expanded YAML form reduce
        // to the same (version, final-segment) anchor — only the intermediate
        // hierarchy (`projects/{*}/locations/{*}`) is discarded.
        assert_eq!(
            loose_path_key("v3/{*}:translateText"),
            Some(("v3".into(), "{*}:translateText".into()))
        );
        assert_eq!(
            loose_path_key("v3/projects/{*}/locations/{*}:translateText"),
            Some(("v3".into(), "{*}:translateText".into()))
        );
    }

    #[test]
    fn loose_key_keeps_literal_resource_so_generic_verbs_dont_collide() {
        // `:lookup` is shared by many resources; the resource name must stay
        // in the anchor so they don't masquerade as one another.
        assert_eq!(
            loose_path_key("v1/currentConditions:lookup"),
            Some(("v1".into(), "currentConditions:lookup".into()))
        );
        assert_eq!(
            loose_path_key("v1/history:lookup"),
            Some(("v1".into(), "history:lookup".into()))
        );
        assert_ne!(
            loose_path_key("v1/currentConditions:lookup"),
            loose_path_key("v1/history:lookup")
        );
    }

    #[test]
    fn loose_key_anchors_on_literal_trailing_segment() {
        assert_eq!(
            loose_path_key("v3/{*}/supportedLanguages"),
            Some(("v3".into(), "supportedLanguages".into()))
        );
        assert_eq!(
            loose_path_key("v3/projects/{*}/locations/{*}/supportedLanguages"),
            Some(("v3".into(), "supportedLanguages".into()))
        );
    }

    #[test]
    fn loose_key_is_none_without_a_stable_anchor() {
        // Bare get-by-id: trailing segment is a pure placeholder.
        assert_eq!(loose_path_key("v3/{*}"), None);
        // Leading placeholder: no version/service anchor.
        assert_eq!(loose_path_key("{*}/locations/{*}"), None);
        // Empty.
        assert_eq!(loose_path_key(""), None);
        assert_eq!(loose_path_key("/"), None);
    }

    #[test]
    fn loose_key_tolerates_leading_slash() {
        assert_eq!(
            loose_path_key("/v1/text:synthesize"),
            Some(("v1".into(), "text:synthesize".into()))
        );
    }

    // ───────────────────────────────────────────────────────────────────
    // The Google-Translate regression: collapsed `{+parent}` upstream vs
    // expanded YAML. This is the exact shape that shipped empty `paths`.
    // ───────────────────────────────────────────────────────────────────

    #[test]
    fn filter_openapi3_matches_collapsed_parent_against_expanded_yaml() {
        // Upstream (apis.guru / discovery-derived OpenAPI 3): single `{parent}`
        // variable standing in for the whole resource hierarchy.
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://translation.googleapis.com/"}],
            "paths": {
                "/v3/{parent}:translateText":   { "post": {"summary": "Translate input text."} },
                "/v3/{parent}:detectLanguage":  { "post": {"summary": "Detect the source language."} },
                "/v3/{parent}:batchTranslateText": { "post": {"summary": "Batch translate (not exposed)."} },
                "/v3/{parent}/supportedLanguages": { "get": {"summary": "List supported languages."} }
            }
        });
        // Gateway YAML declares the *expanded* paths.
        let endpoints = vec![
            ep(
                Post,
                "v3/projects/{projectsId}/locations/{locationsId}:translateText",
            ),
            ep(
                Post,
                "v3/projects/{projectsId}/locations/{locationsId}:detectLanguage",
            ),
            ep(
                Get,
                "v3/projects/{projectsId}/locations/{locationsId}/supportedLanguages",
            ),
        ];
        filter_to_endpoints(&mut doc, &endpoints);

        let paths = doc["paths"].as_object().unwrap();
        // The three declared endpoints survive despite the path-shape gap…
        assert!(paths.contains_key("/v3/{parent}:translateText"));
        assert!(paths.contains_key("/v3/{parent}:detectLanguage"));
        assert!(paths.contains_key("/v3/{parent}/supportedLanguages"));
        // …and the undeclared batch endpoint is still dropped.
        assert!(!paths.contains_key("/v3/{parent}:batchTranslateText"));
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn filter_openapi3_does_not_empty_paths_for_translate_shape() {
        // Guards the original bug directly: a non-empty upstream must not
        // filter down to `{}` when every endpoint is declared.
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://translation.googleapis.com/"}],
            "paths": { "/v3/{parent}:translateText": { "post": {"summary": "Translate."} } }
        });
        let endpoints = vec![ep(
            Post,
            "v3/projects/{projectsId}/locations/{locationsId}:translateText",
        )];
        filter_to_endpoints(&mut doc, &endpoints);
        assert!(
            !doc["paths"].as_object().unwrap().is_empty(),
            "translate-shaped spec must not filter down to empty paths"
        );
    }

    #[test]
    fn filter_discovery_prefers_flatpath_over_collapsed_path() {
        // Discovery ships both `path` (collapsed `{+parent}`) and `flatPath`
        // (expanded). Matching must use the expanded `flatPath`.
        let mut doc = json!({
            "kind": "discovery#restDescription",
            "rootUrl": "https://translation.googleapis.com/",
            "resources": {
                "projects": {
                    "resources": {
                        "locations": {
                            "methods": {
                                "translateText": {
                                    "httpMethod": "POST",
                                    "path": "v3/{+parent}:translateText",
                                    "flatPath": "v3/projects/{projectsId}/locations/{locationsId}:translateText"
                                }
                            }
                        }
                    }
                }
            }
        });
        let endpoints = vec![ep(
            Post,
            "v3/projects/{projectsId}/locations/{locationsId}:translateText",
        )];
        filter_to_endpoints(&mut doc, &endpoints);
        assert!(
            doc["resources"]["projects"]["resources"]["locations"]["methods"]
                .as_object()
                .unwrap()
                .contains_key("translateText"),
            "flatPath should let the expanded YAML path match"
        );
    }

    #[test]
    fn filter_discovery_loose_matches_when_only_collapsed_path_present() {
        // Some discovery docs omit `flatPath`; the loose anchor still bridges
        // the collapsed `{+name}` to the expanded YAML path.
        let mut doc = json!({
            "kind": "discovery#restDescription",
            "rootUrl": "https://generativelanguage.googleapis.com/",
            "resources": {
                "models": {
                    "methods": {
                        "generateContent": {
                            "httpMethod": "POST",
                            "path": "v1beta/{+model}:generateContent"
                        }
                    }
                }
            }
        });
        let endpoints = vec![ep(Post, "v1beta/models/{modelsId}:generateContent")];
        filter_to_endpoints(&mut doc, &endpoints);
        assert!(
            doc["resources"]["models"]["methods"]
                .as_object()
                .unwrap()
                .contains_key("generateContent")
        );
    }

    // ───────────────────────────────────────────────────────────────────
    // Loose matching must not over-expose: different verbs / versions stay
    // distinct, and undeclared operations are still dropped.
    // ───────────────────────────────────────────────────────────────────

    #[test]
    fn loose_match_does_not_keep_different_custom_verb() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://translation.googleapis.com/"}],
            "paths": {
                "/v3/{parent}:translateText":  { "post": {} },
                "/v3/{parent}:romanizeText":   { "post": {} }
            }
        });
        // Only translateText declared.
        let endpoints = vec![ep(
            Post,
            "v3/projects/{projectsId}/locations/{locationsId}:translateText",
        )];
        filter_to_endpoints(&mut doc, &endpoints);
        let paths = doc["paths"].as_object().unwrap();
        assert!(paths.contains_key("/v3/{parent}:translateText"));
        assert!(!paths.contains_key("/v3/{parent}:romanizeText"));
    }

    #[test]
    fn loose_match_respects_http_method() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://x.googleapis.com/"}],
            "paths": { "/v3/{parent}:translateText": { "post": {}, "get": {} } }
        });
        // Declared as POST only; the GET on the same path must be stripped.
        let endpoints = vec![ep(
            Post,
            "v3/projects/{projectsId}/locations/{locationsId}:translateText",
        )];
        filter_to_endpoints(&mut doc, &endpoints);
        let item = doc["paths"]["/v3/{parent}:translateText"]
            .as_object()
            .unwrap();
        assert!(item.contains_key("post"));
        assert!(!item.contains_key("get"));
    }

    #[test]
    fn loose_match_keeps_versions_distinct() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://x.googleapis.com/"}],
            "paths": {
                "/v3/{parent}:translateText": { "post": {} },
                "/v2/{parent}:translateText": { "post": {} }
            }
        });
        // Only the v3 endpoint is declared.
        let endpoints = vec![ep(Post, "v3/projects/{p}/locations/{l}:translateText")];
        filter_to_endpoints(&mut doc, &endpoints);
        let paths = doc["paths"].as_object().unwrap();
        assert!(paths.contains_key("/v3/{parent}:translateText"));
        assert!(!paths.contains_key("/v2/{parent}:translateText"));
    }

    #[test]
    fn bare_get_by_id_requires_exact_match_no_loose() {
        // `/v3/{name}` has no literal anchor → loose key is None, so it must
        // NOT be kept just because some other endpoint shares the version.
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://x.googleapis.com/"}],
            "paths": {
                "/v3/{name}": { "get": {} },
                "/v3/{parent}:translateText": { "post": {} }
            }
        });
        let endpoints = vec![ep(Post, "v3/projects/{p}/locations/{l}:translateText")];
        filter_to_endpoints(&mut doc, &endpoints);
        let paths = doc["paths"].as_object().unwrap();
        assert!(!paths.contains_key("/v3/{name}"));
        assert!(paths.contains_key("/v3/{parent}:translateText"));
    }

    #[test]
    fn bare_get_by_id_still_matches_exactly() {
        // When the YAML declares the same collapsed shape, exact match keeps it.
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://x.googleapis.com/"}],
            "paths": { "/v3/{name}": { "get": {} } }
        });
        let endpoints = vec![ep(Get, "v3/{name}")];
        filter_to_endpoints(&mut doc, &endpoints);
        assert!(doc["paths"].as_object().unwrap().contains_key("/v3/{name}"));
    }

    // ───────────────────────────────────────────────────────────────────
    // Existing exact-match behavior must be preserved (no regressions).
    // ───────────────────────────────────────────────────────────────────

    #[test]
    fn bigquery_base_path_exact_match_still_works() {
        // servers[0].url carries `/bigquery/v2`; the YAML path includes it.
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://bigquery.googleapis.com/bigquery/v2"}],
            "paths": {
                "/projects/{projectId}/queries": { "post": {} },
                "/projects/{projectId}/jobs": { "get": {} }
            }
        });
        let endpoints = vec![ep(Post, "bigquery/v2/projects/{projectsId}/queries")];
        filter_to_endpoints(&mut doc, &endpoints);
        let paths = doc["paths"].as_object().unwrap();
        assert!(paths.contains_key("/projects/{projectId}/queries"));
        assert!(!paths.contains_key("/projects/{projectId}/jobs"));
    }

    #[test]
    fn singular_plural_placeholder_names_still_match() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://x.googleapis.com/"}],
            "paths": { "/v2/documents:analyzeSentiment": { "post": {} } }
        });
        // Identical shape, no `{parent}` collapse — exact path stays exact.
        let endpoints = vec![ep(Post, "v2/documents:analyzeSentiment")];
        filter_to_endpoints(&mut doc, &endpoints);
        assert!(
            doc["paths"]
                .as_object()
                .unwrap()
                .contains_key("/v2/documents:analyzeSentiment")
        );
    }

    // ───────────────────────────────────────────────────────────────────
    // collect_doc_operations — the coverage guardrail's view of the doc.
    // ───────────────────────────────────────────────────────────────────

    #[test]
    fn collect_ops_openapi3_applies_base_path() {
        let doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://bigquery.googleapis.com/bigquery/v2"}],
            "paths": { "/projects/{projectId}/queries": { "post": {}, "get": {} } }
        });
        let mut ops = collect_doc_operations(&doc);
        ops.sort();
        assert_eq!(
            ops,
            vec![
                (
                    "GET".to_string(),
                    "bigquery/v2/projects/{*}/queries".to_string()
                ),
                (
                    "POST".to_string(),
                    "bigquery/v2/projects/{*}/queries".to_string()
                ),
            ]
        );
    }

    #[test]
    fn collect_ops_discovery_uses_flatpath() {
        let doc = json!({
            "kind": "discovery#restDescription",
            "resources": {
                "projects": {
                    "methods": {
                        "translate": {
                            "httpMethod": "POST",
                            "path": "v3/{+parent}:translateText",
                            "flatPath": "v3/projects/{projectsId}:translateText"
                        }
                    }
                }
            }
        });
        let ops = collect_doc_operations(&doc);
        assert_eq!(
            ops,
            vec![(
                "POST".to_string(),
                "v3/projects/{*}:translateText".to_string()
            )]
        );
    }

    // ───────────────────────────────────────────────────────────────────
    // Guardrail: warn_on_unmatched_endpoints must not panic and must leave
    // the document untouched. (It only logs.)
    // ───────────────────────────────────────────────────────────────────

    #[test]
    fn guardrail_is_noop_on_document_when_all_covered() {
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://x.googleapis.com/"}],
            "paths": { "/v3/{parent}:translateText": { "post": {} } }
        });
        let endpoints = vec![ep(Post, "v3/projects/{p}/locations/{l}:translateText")];
        // Whole pipeline (filter + guardrail) runs without panicking and keeps
        // the matched endpoint.
        filter_to_endpoints(&mut doc, &endpoints);
        assert_eq!(doc["paths"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn guardrail_tolerates_empty_upstream_paths() {
        // The other failure mode: upstream shipped `paths: {}`. Filtering must
        // not panic; the served doc stays empty (nothing to keep).
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://generativelanguage.googleapis.com/"}],
            "paths": {}
        });
        let endpoints = vec![ep(Post, "v1beta/models/{modelsId}:generateContent")];
        filter_to_endpoints(&mut doc, &endpoints);
        assert!(doc["paths"].as_object().unwrap().is_empty());
    }

    #[test]
    fn empty_endpoints_list_leaves_paths_alone_but_filters_all() {
        // No declared endpoints → allow-list empty → everything is stripped
        // (and the guardrail short-circuits without warning).
        let mut doc = json!({
            "openapi": "3.0.0",
            "servers": [{"url": "https://x.googleapis.com/"}],
            "paths": { "/v1/x": { "get": {} } }
        });
        filter_to_endpoints(&mut doc, &[]);
        assert!(doc["paths"].as_object().unwrap().is_empty());
    }
}
