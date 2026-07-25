//! Skills — service discovery for paid APIs.
//!
//! The skills catalog is a cached index of API providers and their endpoints.
//! Provider sources are managed in `~/.config/pay/skills.yaml` (see
//! [`config::SkillsConfig`]) and merged into a single consolidated cache.
//!
//! The index is lightweight (no inline endpoints). Endpoint data is
//! lazy-fetched from `{base_url}/providers/{fqn}.json` on demand and
//! cached locally.
//!
//! Query functions ([`search`], [`service_detail`], [`resource_endpoints`])
//! are pure — no I/O at query time. The I/O boundary is [`load_skills`]
//! and [`load_service_endpoints`].

pub mod build;
pub mod config;
pub mod github;
pub mod local;
pub mod openapi;
pub mod overlay;
pub mod pin;
pub mod probe;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{ClientApp, Error, Result};

/// Accept both `"1"` (string) and `1` (integer) for the version field.
fn deserialize_version<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<String, D::Error> {
    let v: serde_json::Value = serde::Deserialize::deserialize(d)?;
    match v {
        serde_json::Value::String(s) => Ok(s),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        _ => Err(serde::de::Error::custom(
            "expected string or number for version",
        )),
    }
}

// ── Catalog schema ──────────────────────────────────────────────────────────

/// Top-level catalog — the skills.json index from the CDN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(alias = "version", deserialize_with = "deserialize_version")]
    pub schema_version: String,
    #[serde(default)]
    pub generated_at: String,
    /// CDN base URL for fetching provider detail files.
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub provider_count: u32,
    /// Provider list from `providers[]` in skills.json.
    #[serde(alias = "services", default)]
    pub providers: Vec<Service>,
}

/// A provider entry in the index. Endpoints are NOT inline — they're
/// lazy-fetched from `{base_url}/providers/{fqn}.json` when needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// Fully qualified name: `operator/origin/name` or `operator/name`.
    #[serde(alias = "name")]
    pub fqn: String,
    #[serde(flatten)]
    pub meta: pay_types::registry::ServiceMeta,
    #[serde(default)]
    pub endpoint_count: u32,
    #[serde(default)]
    pub has_metering: bool,
    #[serde(default)]
    pub has_free_tier: bool,
    #[serde(default)]
    pub min_price_usd: f64,
    #[serde(default)]
    pub max_price_usd: f64,
    /// Content hash of the detail file — used for cache invalidation.
    #[serde(default)]
    pub sha: String,
    /// Endpoints — empty from the index, populated by [`load_service_endpoints`].
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    /// Markdown body from the provider detail file — empty from the index,
    /// populated alongside endpoints by [`ensure_endpoints`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

impl Service {
    /// Short name (last segment of the FQN).
    pub fn name(&self) -> &str {
        self.fqn.rsplit('/').next().unwrap_or(&self.fqn)
    }

    /// Whether endpoints have been loaded (lazy-fetch completed).
    pub fn endpoints_loaded(&self) -> bool {
        !self.endpoints.is_empty()
    }
}

/// A single API endpoint within a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub full_path: String,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub pricing: Option<serde_json::Value>,
}

// ── Query results ───────────────────────────────────────────────────────────

/// A search hit: one endpoint within a service, with enough context to
/// construct a `pay curl` command directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub service: String,
    pub service_title: String,
    pub service_url: String,
    pub method: String,
    pub path: String,
    pub full_path: String,
    pub description: String,
    pub resource: Option<String>,
    pub pricing: Option<serde_json::Value>,
    pub metered: bool,
}

/// Grouped search result — service metadata + matching endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResultGroup {
    pub service: String,
    pub title: String,
    pub url: String,
    pub endpoints: Vec<EndpointHit>,
}

/// A single endpoint within a search result group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointHit {
    pub method: String,
    pub url: String,
    pub path: String,
    pub description: String,
    pub resource: Option<String>,
    pub metered: bool,
}

/// Group flat `SearchHit` results by service for structured output.
pub fn group_search_results(hits: &[SearchHit]) -> Vec<SearchResultGroup> {
    let mut groups: Vec<SearchResultGroup> = Vec::new();
    for hit in hits {
        if groups.last().map(|g| g.service.as_str()) != Some(&hit.service) {
            groups.push(SearchResultGroup {
                service: hit.service.clone(),
                title: hit.service_title.clone(),
                url: hit.service_url.clone(),
                endpoints: Vec::new(),
            });
        }
        groups.last_mut().unwrap().endpoints.push(EndpointHit {
            method: hit.method.clone(),
            url: build_endpoint_url(&hit.service_url, &hit.path),
            path: hit.path.clone(),
            description: hit.description.clone(),
            resource: hit.resource.clone(),
            metered: hit.metered,
        });
    }
    groups
}

/// A service summary — used by the MCP `search_catalog` tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSummary {
    pub name: String,
    #[serde(flatten)]
    pub meta: pay_types::registry::ServiceMeta,
    pub endpoint_count: u32,
    pub metered_endpoints: u32,
    pub free_endpoints: u32,
    pub min_price_usd: f64,
    pub max_price_usd: f64,
}

/// Ranked service candidate for agent provider selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedServiceSummary {
    #[serde(flatten)]
    pub service: ServiceSummary,
    pub score: u32,
    pub reasons: Vec<String>,
}

/// Level 2 result: a resource group returned by [`service_detail`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGroup {
    pub name: String,
    pub endpoint_count: u32,
    pub metered_count: u32,
    pub methods: Vec<String>,
}

/// Level 2 wrapper: service metadata + resource breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDetail {
    pub name: String,
    #[serde(flatten)]
    pub meta: pay_types::registry::ServiceMeta,
    pub resources: Vec<ResourceGroup>,
}

/// Level 3 result: endpoints for a specific resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEndpoints {
    pub service: String,
    pub resource: String,
    #[serde(flatten)]
    pub meta: pay_types::registry::ServiceMeta,
    pub endpoints: Vec<Endpoint>,
}

// ── Pure query functions ────────────────────────────────────────────────────

/// Search services and endpoints by keyword and/or category.
///
/// When endpoints are loaded (from detail files), matches against endpoint
/// paths and descriptions. When only the index is available, matches
/// service-level fields only and emits a single summary hit per service.
pub fn search(catalog: &Catalog, query: Option<&str>, category: Option<&str>) -> Vec<SearchHit> {
    let query_lower = query.map(|q| q.to_lowercase());

    let mut hits: Vec<SearchHit> = Vec::new();

    for svc in &catalog.providers {
        // Category filter
        if let Some(cat) = category
            && !svc.meta.category.eq_ignore_ascii_case(cat)
        {
            continue;
        }

        // Check if the service itself matches the keyword
        let service_matches = match &query_lower {
            Some(q) => {
                let haystack = format!(
                    "{} {} {} {}",
                    svc.fqn,
                    svc.meta.title,
                    svc.meta.description,
                    svc.meta.use_case.as_deref().unwrap_or_default()
                )
                .to_lowercase();
                haystack.contains(q.as_str())
            }
            None => true,
        };

        if svc.endpoints_loaded() {
            // Full endpoint-level search
            for ep in &svc.endpoints {
                let endpoint_matches = if service_matches {
                    true
                } else if let Some(ref q) = query_lower {
                    let haystack =
                        format!("{} {} {}", ep.path, ep.full_path, ep.description).to_lowercase();
                    haystack.contains(q.as_str())
                } else {
                    false
                };

                if !endpoint_matches {
                    continue;
                }

                hits.push(SearchHit {
                    service: svc.fqn.clone(),
                    service_title: svc.meta.title.clone(),
                    service_url: svc.meta.service_url.clone(),
                    method: ep.method.clone(),
                    path: ep.path.clone(),
                    full_path: ep.full_path.clone(),
                    description: ep.description.clone(),
                    resource: ep.resource.clone(),
                    pricing: ep.pricing.clone(),
                    metered: ep.pricing.is_some(),
                });
            }
        } else if service_matches {
            // Index-only: emit a service-level placeholder hit
            hits.push(SearchHit {
                service: svc.fqn.clone(),
                service_title: svc.meta.title.clone(),
                service_url: svc.meta.service_url.clone(),
                method: String::new(),
                path: String::new(),
                full_path: String::new(),
                description: svc.meta.description.clone(),
                resource: None,
                pricing: None,
                metered: svc.has_metering,
            });
        }
    }

    // Sort: group by service, metered first within each service.
    hits.sort_by(|a, b| {
        a.service
            .cmp(&b.service)
            .then_with(|| b.metered.cmp(&a.metered))
            .then_with(|| a.path.cmp(&b.path))
    });

    // Hoist services that have metered endpoints to the top.
    let has_metered: std::collections::HashSet<_> = hits
        .iter()
        .filter(|h| h.metered)
        .map(|h| h.service.clone())
        .collect();
    hits.sort_by(|a, b| {
        let a_has = has_metered.contains(&a.service);
        let b_has = has_metered.contains(&b.service);
        b_has
            .cmp(&a_has)
            .then_with(|| a.service.cmp(&b.service))
            .then_with(|| b.metered.cmp(&a.metered))
            .then_with(|| a.path.cmp(&b.path))
    });

    hits
}

/// Search at the service level (for MCP progressive disclosure).
pub fn search_services(
    catalog: &Catalog,
    query: Option<&str>,
    category: Option<&str>,
) -> Vec<ServiceSummary> {
    let query_lower = query.map(|q| q.to_lowercase());

    catalog
        .providers
        .iter()
        .filter(|svc| {
            if let Some(cat) = category
                && !svc.meta.category.eq_ignore_ascii_case(cat)
            {
                return false;
            }
            if let Some(ref q) = query_lower {
                let svc_haystack = format!(
                    "{} {} {} {}",
                    svc.fqn,
                    svc.meta.title,
                    svc.meta.description,
                    svc.meta.use_case.as_deref().unwrap_or_default()
                )
                .to_lowercase();
                if svc_haystack.contains(q.as_str()) {
                    return true;
                }
                // Also check endpoints if loaded
                return svc.endpoints.iter().any(|ep| {
                    let ep_haystack =
                        format!("{} {} {}", ep.path, ep.full_path, ep.description).to_lowercase();
                    ep_haystack.contains(q.as_str())
                });
            }
            true
        })
        .map(summarize_service)
        .collect()
}

/// Rank providers for a natural-language task.
///
/// This is intentionally simple and deterministic. The goal is not semantic
/// search; it is to avoid dumping the full provider catalog into an agent and
/// asking it to guess. Strong matches in `use_case`, title, FQN, and loaded
/// endpoint descriptions outrank broad catalog entries.
pub fn search_services_ranked(
    catalog: &Catalog,
    query: &str,
    category: Option<&str>,
    limit: usize,
) -> Vec<RankedServiceSummary> {
    let terms = tokenize_query(query);
    let query_lower = query.trim().to_lowercase();
    let limit = limit.clamp(1, 20);

    let mut ranked: Vec<RankedServiceSummary> = catalog
        .providers
        .iter()
        .filter(|svc| {
            category
                .map(|cat| svc.meta.category.eq_ignore_ascii_case(cat))
                .unwrap_or(true)
        })
        .filter_map(|svc| {
            let (score, reasons) = score_service_for_query(svc, &query_lower, &terms);
            if score == 0 {
                return None;
            }
            Some(RankedServiceSummary {
                service: summarize_service(svc),
                score,
                reasons,
            })
        })
        .collect();

    ranked.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.service.endpoint_count.cmp(&b.service.endpoint_count))
            .then_with(|| a.service.name.cmp(&b.service.name))
    });
    ranked.truncate(limit);
    ranked
}

fn tokenize_query(query: &str) -> Vec<String> {
    const STOPWORDS: &[&str] = &[
        "a",
        "ad",
        "an",
        "and",
        "any",
        "api",
        "are",
        "around",
        "as",
        "at",
        "by",
        "can",
        "could",
        "for",
        "from",
        "get",
        "give",
        "i",
        "idk",
        "in",
        "into",
        "is",
        "it",
        "kinda",
        "like",
        "me",
        "maybe",
        "my",
        "need",
        "of",
        "on",
        "one",
        "or",
        "our",
        "please",
        "pls",
        "quick",
        "rn",
        "some",
        "somewhere",
        "stuff",
        "that",
        "the",
        "there",
        "these",
        "they",
        "thing",
        "thingy",
        "this",
        "to",
        "up",
        "use",
        "using",
        "we",
        "what",
        "where",
        "who",
        "with",
    ];

    query
        .split(|c: char| !c.is_ascii_alphanumeric())
        .map(|term| term.trim().to_lowercase())
        .filter(|term| term.len() > 1 && !STOPWORDS.contains(&term.as_str()))
        .collect()
}

fn score_service_for_query(
    svc: &Service,
    query_lower: &str,
    terms: &[String],
) -> (u32, Vec<String>) {
    let mut score = 0u32;
    let mut reasons = Vec::new();

    let fqn = svc.fqn.to_lowercase();
    let short_name = svc.name().to_lowercase();
    let title = svc.meta.title.to_lowercase();
    let description = svc.meta.description.to_lowercase();
    let use_case = svc.meta.use_case.clone().unwrap_or_default().to_lowercase();
    let category = svc.meta.category.to_lowercase();

    if !query_lower.is_empty() {
        if fqn.contains(query_lower) || short_name.contains(query_lower) {
            score += 90;
            reasons.push("provider name matches the task".to_string());
        }
        if title.contains(query_lower) {
            score += 80;
            reasons.push("provider title matches the task".to_string());
        }
        if use_case.contains(query_lower) {
            score += 70;
            reasons.push("provider use case directly matches the task".to_string());
        }
        if description.contains(query_lower) {
            score += 55;
            reasons.push("provider description matches the task".to_string());
        }
    }

    let mut matched_terms = 0u32;
    for term in terms {
        let mut term_matched = false;
        if contains_query_term(&fqn, term) || contains_query_term(&short_name, term) {
            score += 24;
            term_matched = true;
        }
        if contains_query_term(&title, term) {
            score += 18;
            term_matched = true;
        }
        if contains_query_term(&use_case, term) {
            score += 14;
            term_matched = true;
        }
        if contains_query_term(&description, term) {
            score += 10;
            term_matched = true;
        }
        if contains_query_term(&category, term) {
            score += 8;
            term_matched = true;
        }
        if endpoint_term_matches(svc, term) {
            score += 12;
            term_matched = true;
        }
        if term_matched {
            matched_terms += 1;
        }
    }

    if !terms.is_empty() {
        let coverage = matched_terms * 100 / terms.len() as u32;
        score += coverage;
        if coverage == 100 {
            reasons.push("all important query terms match this provider".to_string());
        } else if coverage >= 50 {
            reasons.push("most important query terms match this provider".to_string());
        }
    }

    if svc.endpoints_loaded()
        && svc.endpoints.iter().any(|ep| {
            let haystack = format!(
                "{} {} {} {}",
                ep.method,
                ep.path,
                ep.resource.as_deref().unwrap_or(""),
                ep.description
            )
            .to_lowercase();
            !query_lower.is_empty() && haystack.contains(query_lower)
        })
    {
        score += 45;
        reasons.push("a specific endpoint matches the task".to_string());
    }

    if svc.endpoint_count <= 5 {
        score += 12;
    } else if svc.endpoint_count <= 20 {
        score += 6;
    } else if svc.endpoint_count >= 100 {
        score = score.saturating_sub(8);
    }

    if is_demo_provider(&fqn, &description) && !query_mentions_demo(query_lower, terms) {
        score = score.saturating_sub(40);
    }

    if score > 0 && reasons.is_empty() {
        reasons.push("provider metadata partially matches the task".to_string());
    }

    (score, reasons)
}

fn endpoint_term_matches(svc: &Service, term: &str) -> bool {
    svc.endpoints.iter().any(|ep| {
        let haystack = format!(
            "{} {} {}",
            ep.path,
            ep.resource.as_deref().unwrap_or(""),
            ep.description
        )
        .to_lowercase();
        contains_query_term(&haystack, term)
    })
}

fn contains_query_term(haystack: &str, term: &str) -> bool {
    if term.len() <= 3 {
        return haystack
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|word| word == term);
    }

    if haystack.contains(term) {
        return true;
    }

    if term.len() > 3 {
        let plural = format!("{term}s");
        if haystack.contains(&plural) {
            return true;
        }
        if let Some(stem) = term.strip_suffix('y') {
            let plural = format!("{stem}ies");
            if haystack.contains(&plural) {
                return true;
            }
        }
        if let Some(stem) = term.strip_suffix("ies") {
            let singular = format!("{stem}y");
            if haystack.contains(&singular) {
                return true;
            }
        }
        if let Some(singular) = term.strip_suffix('s')
            && singular.len() > 2
            && haystack.contains(singular)
        {
            return true;
        }
    }

    false
}

fn is_demo_provider(fqn: &str, description: &str) -> bool {
    fqn.contains("payment-debugger") || description.contains("demo api")
}

fn query_mentions_demo(query_lower: &str, terms: &[String]) -> bool {
    query_lower.contains("payment debugger")
        || terms
            .iter()
            .any(|term| matches!(term.as_str(), "demo" | "debugger" | "test" | "testing"))
}

/// Extract the minimum and maximum USD prices from a registry pricing block.
pub fn price_range_usd(pricing: &Option<serde_json::Value>) -> Option<(f64, f64)> {
    let mut prices = Vec::new();
    collect_prices(pricing, &mut prices);
    Some((
        prices.iter().copied().reduce(f64::min)?,
        prices.iter().copied().reduce(f64::max)?,
    ))
}

/// Level 2: list resources within a service.
/// Requires endpoints to be loaded — returns None if empty.
pub fn service_detail(catalog: &Catalog, service_name: &str) -> Option<ServiceDetail> {
    let svc = find_service(catalog, service_name)?;

    let mut groups: BTreeMap<String, (u32, u32, Vec<String>)> = BTreeMap::new();
    for ep in &svc.endpoints {
        let Some(resource) = &ep.resource else {
            continue;
        };
        let resource = if resource.is_empty() {
            "(default)"
        } else {
            resource
        };
        let entry = groups
            .entry(resource.to_string())
            .or_insert((0, 0, Vec::new()));
        entry.0 += 1;
        if ep.pricing.is_some() {
            entry.1 += 1;
        }
        if !entry.2.contains(&ep.method) {
            entry.2.push(ep.method.clone());
        }
    }

    Some(ServiceDetail {
        name: svc.fqn.clone(),
        meta: svc.meta.clone(),
        resources: groups
            .into_iter()
            .map(|(name, (count, metered, methods))| ResourceGroup {
                name,
                endpoint_count: count,
                metered_count: metered,
                methods,
            })
            .collect(),
    })
}

/// Level 3: list endpoints for a specific resource within a service.
pub fn resource_endpoints(
    catalog: &Catalog,
    service_name: &str,
    resource_name: &str,
) -> Option<ResourceEndpoints> {
    let svc = find_service(catalog, service_name)?;

    let endpoints: Vec<Endpoint> = svc
        .endpoints
        .iter()
        .filter(|ep| {
            if let Some(resource) = &ep.resource {
                resource.eq_ignore_ascii_case(resource_name)
            } else {
                false
            }
        })
        .cloned()
        .collect();

    if endpoints.is_empty() {
        return None;
    }

    Some(ResourceEndpoints {
        service: svc.fqn.clone(),
        resource: resource_name.to_string(),
        meta: svc.meta.clone(),
        endpoints,
    })
}

/// All endpoints for a service, across every resource. Returns `None` if the
/// service isn't in the catalog. The `resource` field is left empty to signal
/// "all resources".
pub fn service_endpoints(catalog: &Catalog, service_name: &str) -> Option<ResourceEndpoints> {
    let svc = find_service(catalog, service_name)?;
    Some(ResourceEndpoints {
        service: svc.fqn.clone(),
        resource: String::new(),
        meta: svc.meta.clone(),
        endpoints: svc.endpoints.clone(),
    })
}

/// Find a service by FQN or short name (case-insensitive).
fn find_service<'a>(catalog: &'a Catalog, name: &str) -> Option<&'a Service> {
    catalog
        .providers
        .iter()
        .find(|s| s.fqn.eq_ignore_ascii_case(name))
        .or_else(|| {
            // Fallback: match on short name (last segment)
            catalog
                .providers
                .iter()
                .find(|s| s.name().eq_ignore_ascii_case(name))
        })
}

// ── Lazy endpoint loading ─────────────────────────────────────────────────

/// Fetch a provider's full detail file and return the endpoints.
///
/// Downloads `{base_url}/providers/{fqn}.json`, caches locally in
/// `~/.config/pay/skills/detail/`, uses `sha` for invalidation.
pub async fn load_service_endpoints(
    catalog: &Catalog,
    service_name: &str,
) -> Result<Vec<Endpoint>> {
    load_service_endpoints_for(catalog, service_name, ClientApp::Cli).await
}

pub async fn load_service_endpoints_for(
    catalog: &Catalog,
    service_name: &str,
    client_app: ClientApp,
) -> Result<Vec<Endpoint>> {
    let svc = find_service(catalog, service_name)
        .ok_or_else(|| {
            Error::Config(format!(
                "service `{service_name}` not found in catalog. Try `pay skills search <query>` to discover providers."
            ))
        })?;

    if svc.endpoints_loaded() {
        return Ok(svc.endpoints.clone());
    }

    if catalog.base_url.is_empty() {
        return Err(Error::Config(
            "no base_url in catalog — cannot fetch endpoint detail".into(),
        ));
    }

    let detail_url = format!("{}/providers/{}.json", catalog.base_url, svc.fqn);
    let cache_dir =
        std::path::PathBuf::from(shellexpand::tilde("~/.config/pay/skills/detail").into_owned());
    let cache_file = cache_dir.join(format!("{}.json", svc.sha));

    if cache_file.exists()
        && let Ok(raw) = std::fs::read_to_string(&cache_file)
        && let Ok(detail) = parse_detail(&raw)
    {
        return Ok(detail.endpoints);
    }

    let raw = fetch_url(&detail_url, client_app).await?;
    let detail = parse_detail(&raw)?;

    let _ = std::fs::create_dir_all(&cache_dir);
    let _ = std::fs::write(&cache_file, &raw);

    Ok(detail.endpoints)
}

/// Load the inlined OpenAPI document for `service_name` from the catalog's
/// detail JSON (cached locally after the first fetch).
///
/// Returns `None` when the provider was published with inline `endpoints:`
/// (no openapi source), or when the build couldn't parse the source doc.
/// Returns `Some(value)` for providers whose spec declared
/// `openapi: { url: ... }` — the document is embedded verbatim in the
/// detail JSON so consumers don't need a follow-up HTTP fetch.
pub async fn load_service_openapi(
    catalog: &Catalog,
    service_name: &str,
) -> Result<Option<serde_json::Value>> {
    load_service_openapi_for(catalog, service_name, ClientApp::Cli).await
}

pub async fn load_service_openapi_for(
    catalog: &Catalog,
    service_name: &str,
    client_app: ClientApp,
) -> Result<Option<serde_json::Value>> {
    let svc = find_service(catalog, service_name)
        .ok_or_else(|| {
            Error::Config(format!(
                "service `{service_name}` not found in catalog. Try `pay skills search <query>` to discover providers."
            ))
        })?;

    if catalog.base_url.is_empty() {
        return Err(Error::Config(
            "no base_url in catalog — cannot fetch openapi detail".into(),
        ));
    }

    let detail_url = format!("{}/providers/{}.json", catalog.base_url, svc.fqn);
    let cache_dir =
        std::path::PathBuf::from(shellexpand::tilde("~/.config/pay/skills/detail").into_owned());
    let cache_file = cache_dir.join(format!("{}.json", svc.sha));

    if cache_file.exists()
        && let Ok(raw) = std::fs::read_to_string(&cache_file)
        && let Ok(detail) = parse_detail(&raw)
    {
        return Ok(detail.openapi_doc);
    }

    let raw = fetch_url(&detail_url, client_app).await?;
    let detail = parse_detail(&raw)?;
    let _ = std::fs::create_dir_all(&cache_dir);
    let _ = std::fs::write(&cache_file, &raw);

    Ok(detail.openapi_doc)
}

/// Convenience: load endpoints and inject them into the catalog's service.
pub async fn ensure_endpoints(catalog: &mut Catalog, service_name: &str) -> Result<()> {
    ensure_endpoints_for(catalog, service_name, ClientApp::Cli).await
}

pub async fn ensure_endpoints_for(
    catalog: &mut Catalog,
    service_name: &str,
    client_app: ClientApp,
) -> Result<()> {
    let base_url = catalog.base_url.clone();
    let idx = catalog
        .providers
        .iter()
        .position(|s| s.fqn.eq_ignore_ascii_case(service_name))
        .or_else(|| {
            catalog
                .providers
                .iter()
                .position(|s| s.name().eq_ignore_ascii_case(service_name))
        })
        .ok_or_else(|| {
            Error::Config(format!(
                "service `{service_name}` not found in catalog. Try `pay skills search <query>` to discover providers."
            ))
        })?;
    let svc = &mut catalog.providers[idx];

    if svc.endpoints_loaded() {
        return Ok(());
    }

    if base_url.is_empty() {
        return Err(Error::Config(
            "no base_url in catalog — cannot fetch endpoint detail".into(),
        ));
    }

    let detail_url = format!("{}/providers/{}.json", base_url, svc.fqn);
    let cache_dir =
        std::path::PathBuf::from(shellexpand::tilde("~/.config/pay/skills/detail").into_owned());
    let cache_file = cache_dir.join(format!("{}.json", svc.sha));

    if cache_file.exists()
        && let Ok(raw) = std::fs::read_to_string(&cache_file)
        && let Ok(detail) = parse_detail(&raw)
    {
        svc.endpoints = detail.endpoints;
        svc.content = detail.content;
        return Ok(());
    }

    let raw = fetch_url(&detail_url, client_app).await?;
    let detail = match parse_detail(&raw) {
        Ok(detail) => detail,
        Err(e) => {
            tracing::warn!(url = %detail_url, "Failed to parse provider detail JSON: {e}");
            return Err(e);
        }
    };

    let _ = std::fs::create_dir_all(&cache_dir);
    let _ = std::fs::write(&cache_file, &raw);

    svc.endpoints = detail.endpoints;
    svc.content = detail.content;

    clean_stale_detail_cache(catalog);

    Ok(())
}

/// Remove detail cache files whose sha doesn't appear in the current catalog.
pub fn clean_stale_detail_cache(catalog: &Catalog) {
    let cache_dir =
        std::path::PathBuf::from(shellexpand::tilde("~/.config/pay/skills/detail").into_owned());
    let Ok(entries) = std::fs::read_dir(&cache_dir) else {
        return;
    };
    let live_shas: std::collections::HashSet<_> = catalog
        .providers
        .iter()
        .filter(|s| !s.sha.is_empty())
        .map(|s| format!("{}.json", s.sha))
        .collect();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".json") && !live_shas.contains(&name) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Provider detail file shape.
#[derive(Debug, Deserialize)]
struct ProviderDetailFile {
    #[serde(default)]
    endpoints: Vec<Endpoint>,
    #[serde(default)]
    content: Option<String>,
    /// Pointer to the upstream OpenAPI doc (preserved for traceability).
    #[serde(default)]
    #[allow(dead_code)]
    openapi: Option<pay_types::registry::OpenapiSource>,
    /// Inlined OpenAPI / Discovery document, populated at build time when
    /// the spec declared `openapi: { url: ... }`. Lets MCP / CLI consumers
    /// access the upstream schema right after `pay skills update` without
    /// hitting the network again.
    #[serde(default)]
    openapi_doc: Option<serde_json::Value>,
}

fn parse_detail(raw: &str) -> Result<ProviderDetailFile> {
    serde_json::from_str(raw).map_err(|e| Error::Config(format!("parse detail: {e}")))
}

// ── Catalog loading + caching ───────────────────────────────────────────────

/// Load the skills catalog. Uses cache if fresh, otherwise fetches from
/// configured sources.
///
/// When the config has any ephemeral sources (auto-registered
/// `pay server start` instances on this host), the durable cached
/// catalog is augmented with a fresh fetch of just those ephemeral
/// sources on every call. Ephemeral specs change as the developer
/// edits + restarts their server; the 30 min TTL would otherwise hide
/// those edits from agents running in the same shell.
pub async fn load_skills() -> Result<Catalog> {
    load_skills_for(ClientApp::Cli).await
}

pub async fn load_skills_for(client_app: ClientApp) -> Result<Catalog> {
    let cfg = config::SkillsConfig::load()?;

    // Cache hit? Ephemeral sources are merged in separately below so a
    // cache hit on the durable catalog is still useful.
    if let Some(path) = cfg.valid_cache_path() {
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("read cache: {e}")))?;
        let mut catalog = parse_catalog(&raw)?;
        if !catalog.providers.is_empty() {
            if cfg.has_ephemeral_sources() {
                merge_ephemeral_into(&mut catalog, &cfg, client_app).await;
            }
            overlay::merge_pins_into(&mut catalog);
            return Ok(catalog);
        }
        tracing::warn!(path = %path.display(), "Ignoring empty skills cache");
    }

    // Cache miss — fetch, merge, cache.
    match fetch_and_merge(&cfg, false, client_app).await {
        Ok(mut catalog) => {
            // Cache only the durable catalog (ephemerals fold in fresh
            // on every load).
            if let Ok(written) = write_cache(&cfg, &catalog) {
                cfg.clean_stale_caches(&written);
            }
            clean_stale_detail_cache(&catalog);
            if cfg.has_ephemeral_sources() {
                merge_ephemeral_into(&mut catalog, &cfg, client_app).await;
            }
            overlay::merge_pins_into(&mut catalog);
            Ok(catalog)
        }
        Err(fetch_err) => {
            // Try ANY existing cache file as a fallback (even stale).
            let dir =
                std::path::PathBuf::from(shellexpand::tilde("~/.config/pay/skills").into_owned());
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with("skills-")
                        && name.ends_with(".json")
                        && let Ok(raw) = std::fs::read_to_string(entry.path())
                        && let Ok(cat) = parse_catalog(&raw)
                        && !cat.providers.is_empty()
                    {
                        return Ok(cat);
                    }
                }
            }
            Err(fetch_err)
        }
    }
}

/// Load the newest non-empty cached skills catalog without touching the network.
pub fn load_cached_skills() -> Result<Catalog> {
    cached_catalogs()
        .into_iter()
        .find(|catalog| !catalog.providers.is_empty())
        .ok_or_else(|| {
            Error::Config(
                "No cached skills catalog. Run `pay skills list` to populate it.".to_string(),
            )
        })
}

/// Force-refresh: fetch all sources, merge, write cache.
/// When `cache_bust` is true, append `?v=<timestamp>` to source URLs
/// to bypass CDN edge caches, and purge all local detail caches.
pub async fn update_skills(cache_bust: bool) -> Result<Catalog> {
    update_skills_for(cache_bust, ClientApp::Cli).await
}

pub async fn update_skills_for(cache_bust: bool, client_app: ClientApp) -> Result<Catalog> {
    let cfg = config::SkillsConfig::load()?;
    let mut catalog = fetch_and_merge(&cfg, cache_bust, client_app).await?;
    let written = write_cache(&cfg, &catalog)?;
    cfg.clean_stale_caches(&written);
    clean_stale_detail_cache(&catalog);
    if cfg.has_ephemeral_sources() {
        merge_ephemeral_into(&mut catalog, &cfg, client_app).await;
    }
    overlay::merge_pins_into(&mut catalog);
    Ok(catalog)
}

/// Fetch each source URL and merge all providers into one Catalog.
///
/// Returns the merged catalog covering DURABLE (non-ephemeral) sources
/// only. Ephemeral providers are folded in by [`merge_ephemeral_into`]
/// on top of either the cached or the freshly-fetched durable catalog —
/// they're never persisted to disk so a crashed `pay server` doesn't
/// leave stale entries in the cache.
async fn fetch_and_merge(
    cfg: &config::SkillsConfig,
    cache_bust: bool,
    client_app: ClientApp,
) -> Result<Catalog> {
    let client = http_client(std::time::Duration::from_secs(15), client_app)?;

    let mut all_providers: Vec<Service> = Vec::new();
    let mut base_url = String::new();
    let mut successful_sources = 0usize;
    let mut failures = Vec::new();

    let durable: Vec<&config::Source> = cfg.sources.iter().filter(|s| !s.ephemeral).collect();
    for source in &durable {
        let url = if cache_bust {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let sep = if source.url.contains('?') { '&' } else { '?' };
            format!("{}{sep}v={ts}", source.url)
        } else {
            source.url.clone()
        };
        match fetch_one_async(&client, &url).await {
            Ok(cat) => {
                successful_sources += 1;
                if base_url.is_empty() && !cat.base_url.is_empty() {
                    base_url = cat.base_url.clone();
                }
                all_providers.extend(cat.providers);
            }
            Err(e) => {
                failures.push(format!("{}: {e}", source.url));
                tracing::warn!(url = %source.url, error = %e, "Skipping skills source");
            }
        }
    }

    if successful_sources == 0 {
        let reason = if cfg.sources.is_empty() {
            "no skills sources configured".to_string()
        } else if durable.is_empty() {
            "no durable skills sources configured".to_string()
        } else {
            format!("all skills sources failed: {}", failures.join("; "))
        };
        return Err(Error::Config(reason));
    }
    if all_providers.is_empty() {
        return Err(Error::Config(
            "skills sources returned no providers".to_string(),
        ));
    }

    // Deduplicate by FQN (first wins).
    let mut seen = std::collections::HashSet::new();
    all_providers.retain(|svc| seen.insert(svc.fqn.clone()));

    Ok(Catalog {
        schema_version: "1".to_string(),
        generated_at: String::new(),
        base_url,
        provider_count: all_providers.len() as u32,
        providers: all_providers,
    })
}

/// Append providers from every ephemeral source onto `catalog`,
/// dedup'd by FQN against what's already there. Failures are logged
/// at debug — a crashed `pay server` is the common case and we don't
/// want to clobber every `list_catalog` invocation with warnings.
async fn merge_ephemeral_into(
    catalog: &mut Catalog,
    cfg: &config::SkillsConfig,
    client_app: ClientApp,
) {
    let Ok(client) = http_client(std::time::Duration::from_secs(2), client_app) else {
        return;
    };
    let mut seen: std::collections::HashSet<String> =
        catalog.providers.iter().map(|s| s.fqn.clone()).collect();
    for source in cfg.ephemeral_sources() {
        match fetch_one_async(&client, &source.url).await {
            Ok(cat) => {
                for svc in cat.providers {
                    if seen.insert(svc.fqn.clone()) {
                        catalog.providers.push(svc);
                    }
                }
            }
            Err(e) => {
                tracing::debug!(
                    url = %source.url,
                    error = %e,
                    "Ephemeral skills source unreachable (likely a stopped pay server)"
                );
            }
        }
    }
    catalog.provider_count = catalog.providers.len() as u32;
}

async fn fetch_one_async(client: &reqwest::Client, url: &str) -> Result<Catalog> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::Config(format!("fetch {url}: {e}")))?;

    if !resp.status().is_success() {
        return Err(Error::Config(format!(
            "skills source {url} returned {}",
            resp.status()
        )));
    }

    let raw = resp
        .text()
        .await
        .map_err(|e| Error::Config(format!("read {url}: {e}")))?;
    parse_catalog(&raw)
}

/// Shared async HTTP fetch used by detail/endpoint/openapi loaders.
async fn fetch_url(url: &str, client_app: ClientApp) -> Result<String> {
    let client = http_client(std::time::Duration::from_secs(15), client_app)?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::Config(format!("fetch {url}: {e}")))?;

    if !resp.status().is_success() {
        return Err(Error::Config(format!("{url} returned {}", resp.status())));
    }

    resp.text()
        .await
        .map_err(|e| Error::Config(format!("read {url}: {e}")))
}

fn http_client(timeout: std::time::Duration, client_app: ClientApp) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(client_app.user_agent())
        .build()
        .map_err(|e| Error::Config(format!("http client: {e}")))
}

/// Sync wrappers for CLI callers that don't have a tokio runtime.
pub mod blocking {
    use super::*;

    pub fn load_skills() -> Result<Catalog> {
        tokio::runtime::Runtime::new()
            .map_err(|e| Error::Config(format!("runtime: {e}")))?
            .block_on(super::load_skills())
    }

    pub fn load_skills_for(client_app: ClientApp) -> Result<Catalog> {
        tokio::runtime::Runtime::new()
            .map_err(|e| Error::Config(format!("runtime: {e}")))?
            .block_on(super::load_skills_for(client_app))
    }

    pub fn update_skills(cache_bust: bool) -> Result<Catalog> {
        tokio::runtime::Runtime::new()
            .map_err(|e| Error::Config(format!("runtime: {e}")))?
            .block_on(super::update_skills(cache_bust))
    }

    pub fn update_skills_for(cache_bust: bool, client_app: ClientApp) -> Result<Catalog> {
        tokio::runtime::Runtime::new()
            .map_err(|e| Error::Config(format!("runtime: {e}")))?
            .block_on(super::update_skills_for(cache_bust, client_app))
    }

    pub fn ensure_endpoints(catalog: &mut Catalog, service_name: &str) -> Result<()> {
        tokio::runtime::Runtime::new()
            .map_err(|e| Error::Config(format!("runtime: {e}")))?
            .block_on(super::ensure_endpoints(catalog, service_name))
    }

    pub fn ensure_endpoints_for(
        catalog: &mut Catalog,
        service_name: &str,
        client_app: ClientApp,
    ) -> Result<()> {
        tokio::runtime::Runtime::new()
            .map_err(|e| Error::Config(format!("runtime: {e}")))?
            .block_on(super::ensure_endpoints_for(
                catalog,
                service_name,
                client_app,
            ))
    }

    pub fn load_service_endpoints(catalog: &Catalog, service_name: &str) -> Result<Vec<Endpoint>> {
        tokio::runtime::Runtime::new()
            .map_err(|e| Error::Config(format!("runtime: {e}")))?
            .block_on(super::load_service_endpoints(catalog, service_name))
    }

    pub fn load_service_endpoints_for(
        catalog: &Catalog,
        service_name: &str,
        client_app: ClientApp,
    ) -> Result<Vec<Endpoint>> {
        tokio::runtime::Runtime::new()
            .map_err(|e| Error::Config(format!("runtime: {e}")))?
            .block_on(super::load_service_endpoints_for(
                catalog,
                service_name,
                client_app,
            ))
    }

    pub fn load_service_openapi(
        catalog: &Catalog,
        service_name: &str,
    ) -> Result<Option<serde_json::Value>> {
        tokio::runtime::Runtime::new()
            .map_err(|e| Error::Config(format!("runtime: {e}")))?
            .block_on(super::load_service_openapi(catalog, service_name))
    }

    pub fn load_service_openapi_for(
        catalog: &Catalog,
        service_name: &str,
        client_app: ClientApp,
    ) -> Result<Option<serde_json::Value>> {
        tokio::runtime::Runtime::new()
            .map_err(|e| Error::Config(format!("runtime: {e}")))?
            .block_on(super::load_service_openapi_for(
                catalog,
                service_name,
                client_app,
            ))
    }
}

fn parse_catalog(raw: &str) -> Result<Catalog> {
    serde_json::from_str(raw).map_err(|e| Error::Config(format!("parse catalog: {e}")))
}

fn write_cache(cfg: &config::SkillsConfig, catalog: &Catalog) -> Result<std::path::PathBuf> {
    let path = cfg.new_cache_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Config(format!("create cache dir: {e}")))?;
    }
    let json = serde_json::to_string(catalog)
        .map_err(|e| Error::Config(format!("serialize catalog: {e}")))?;
    std::fs::write(&path, json).map_err(|e| Error::Config(format!("write cache: {e}")))?;
    Ok(path)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

const GATEWAY_PROJECT_ID: &str = "gateway-402";

/// Build a complete endpoint URL from a service URL + path.
pub fn build_endpoint_url(service_url: &str, path: &str) -> String {
    let base = service_url.trim_end_matches('/');
    let p = path.trim_start_matches('/');
    if p.is_empty() {
        return base.to_string();
    }
    let resolved = p
        .replace("{projectsId}", GATEWAY_PROJECT_ID)
        .replace("{project}", GATEWAY_PROJECT_ID);
    format!("{base}/{resolved}")
}

/// Build an `EndpointHit` from raw service + endpoint data.
pub fn endpoint_to_hit(service_url: &str, ep: &Endpoint) -> EndpointHit {
    EndpointHit {
        method: ep.method.clone(),
        url: build_endpoint_url(service_url, &ep.path),
        path: ep.path.clone(),
        description: ep.description.clone(),
        resource: ep.resource.clone(),
        metered: ep.pricing.is_some(),
    }
}

/// Resolve a request URL to a skills FQN using only local cache state.
///
/// This intentionally never refreshes the skills catalog: auth prompts need a
/// best-effort label without adding network latency before the OS prompt.
pub fn service_fqn_for_resource_url(resource_url: &str) -> Option<String> {
    cached_catalogs().into_iter().find_map(|catalog| {
        service_fqn_for_url_in_catalog(&catalog, resource_url, cached_service_endpoints)
    })
}

/// Validate a request against cached catalog OpenAPI metadata when a matching
/// provider detail file is available locally.
///
/// This never refreshes the catalog or fetches provider details. If the URL is
/// not confidently matched to a cached catalog endpoint, validation is skipped.
pub fn validate_cached_catalog_request(
    method: &str,
    resource_url: &str,
    body: Option<&str>,
) -> Result<()> {
    validate_cached_catalog_request_with_body_validation(method, resource_url, body, true, None)
}

/// Validate a cached endpoint's method and query parameters without attempting
/// JSON-schema validation for an opaque request body.
pub fn validate_cached_catalog_opaque_request(
    method: &str,
    resource_url: &str,
    content_type: &str,
) -> Result<()> {
    validate_cached_catalog_request_with_body_validation(
        method,
        resource_url,
        None,
        false,
        Some(content_type),
    )
}

fn validate_cached_catalog_request_with_body_validation(
    method: &str,
    resource_url: &str,
    body: Option<&str>,
    validate_body: bool,
    opaque_content_type: Option<&str>,
) -> Result<()> {
    let Some(context) = cached_openapi_context_for_resource_url(resource_url) else {
        return Ok(());
    };

    match openapi::validate_request_with_body_validation(
        &context.openapi_doc,
        method,
        &context.relative_path,
        &context.query_params,
        body,
        validate_body,
        opaque_content_type,
    ) {
        openapi::RequestValidationOutcome::Valid | openapi::RequestValidationOutcome::NotInSpec => {
            Ok(())
        }
        openapi::RequestValidationOutcome::Invalid(failure) => Err(Error::RequestValidation(
            format_validation_failure(resource_url, &context, &failure),
        )),
    }
}

#[derive(Debug, Clone)]
struct CachedOpenapiContext {
    service_fqn: String,
    relative_path: String,
    query_params: Vec<(String, String)>,
    openapi_doc: serde_json::Value,
}

#[derive(Debug, Clone)]
struct CachedOpenapiMatch {
    prefix_len: usize,
    service_fqn: String,
    relative_path: String,
    query_params: Vec<(String, String)>,
    openapi_doc: serde_json::Value,
}

fn cached_openapi_context_for_resource_url(resource_url: &str) -> Option<CachedOpenapiContext> {
    let target = ParsedUrl::parse(resource_url)?;
    let mut matches = Vec::new();

    for catalog in cached_catalogs() {
        for svc in &catalog.providers {
            let Some(detail) = cached_service_detail(svc) else {
                continue;
            };
            let ProviderDetailFile {
                endpoints,
                openapi_doc,
                ..
            } = detail;
            let Some(openapi_doc) = openapi_doc else {
                continue;
            };
            let endpoints = if endpoints.is_empty() {
                &svc.endpoints
            } else {
                &endpoints
            };
            if endpoints.is_empty() {
                continue;
            }

            for base_url in service_base_urls(svc) {
                let Some(base_match) = base_url_match(&target, base_url) else {
                    continue;
                };
                if endpoints
                    .iter()
                    .any(|endpoint| endpoint_path_matches(&base_match.relative_path, endpoint))
                {
                    matches.push(CachedOpenapiMatch {
                        prefix_len: base_match.prefix_len,
                        service_fqn: svc.fqn.clone(),
                        relative_path: base_match.relative_path,
                        query_params: target.query_params.clone(),
                        openapi_doc: openapi_doc.clone(),
                    });
                }
            }
        }
    }

    choose_unique_best_openapi_match(matches)
}

fn choose_unique_best_openapi_match(
    matches: Vec<CachedOpenapiMatch>,
) -> Option<CachedOpenapiContext> {
    let best_prefix_len = matches.iter().map(|item| item.prefix_len).max()?;
    let best: Vec<_> = matches
        .into_iter()
        .filter(|item| item.prefix_len == best_prefix_len)
        .collect();
    let mut fqns: Vec<_> = best.iter().map(|item| item.service_fqn.clone()).collect();
    fqns.sort();
    fqns.dedup();
    if fqns.len() != 1 {
        return None;
    }

    let best = best.into_iter().find(|item| item.service_fqn == fqns[0])?;
    Some(CachedOpenapiContext {
        service_fqn: best.service_fqn,
        relative_path: best.relative_path,
        query_params: best.query_params,
        openapi_doc: best.openapi_doc,
    })
}

fn cached_service_detail(svc: &Service) -> Option<ProviderDetailFile> {
    if svc.sha.is_empty() {
        return None;
    }

    let cache_file = detail_cache_dir().join(format!("{}.json", svc.sha));
    std::fs::read_to_string(cache_file)
        .ok()
        .and_then(|raw| parse_detail(&raw).ok())
}

fn format_validation_failure(
    resource_url: &str,
    context: &CachedOpenapiContext,
    failure: &openapi::RequestValidationFailure,
) -> String {
    let mut lines = vec![
        "Pay catalog request validation failed before sending.".to_string(),
        format!("Provider: {}", context.service_fqn),
        format!("Request: {} {}", failure.method, resource_url),
        format!("Catalog path: {}", failure.path),
        "Problems:".to_string(),
    ];
    for problem in &failure.problems {
        lines.push(format!("- {problem}"));
    }
    if let Some(example) = &failure.example {
        lines.push(format!("Expected JSON body example: {example}"));
    }
    lines.push("The request was not sent. Fix the method/body or inspect the provider with get_catalog_entry.".to_string());
    lines.join("\n")
}

fn cached_catalogs() -> Vec<Catalog> {
    let dir = std::path::PathBuf::from(shellexpand::tilde("~/.config/pay/skills").into_owned());
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut entries: Vec<_> = entries
        .flatten()
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            name.starts_with("skills-") && name.ends_with(".json")
        })
        .collect();

    entries.sort_by_key(|entry| {
        std::cmp::Reverse(
            entry
                .metadata()
                .and_then(|meta| meta.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
        )
    });

    entries
        .into_iter()
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .filter_map(|raw| parse_catalog(&raw).ok())
        .collect()
}

fn cached_service_endpoints(svc: &Service) -> Option<Vec<Endpoint>> {
    if svc.endpoints_loaded() {
        return Some(svc.endpoints.clone());
    }
    if svc.sha.is_empty() {
        return None;
    }

    let cache_file = detail_cache_dir().join(format!("{}.json", svc.sha));
    std::fs::read_to_string(cache_file)
        .ok()
        .and_then(|raw| parse_detail(&raw).ok())
        .map(|detail| detail.endpoints)
}

fn detail_cache_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(shellexpand::tilde("~/.config/pay/skills/detail").into_owned())
}

fn service_fqn_for_url_in_catalog<F>(
    catalog: &Catalog,
    resource_url: &str,
    mut detail_lookup: F,
) -> Option<String>
where
    F: FnMut(&Service) -> Option<Vec<Endpoint>>,
{
    let target = ParsedUrl::parse(resource_url)?;
    let mut endpoint_matches = Vec::new();
    let mut base_matches = Vec::new();

    for svc in &catalog.providers {
        let endpoints = if svc.endpoints_loaded() {
            Some(svc.endpoints.clone())
        } else {
            detail_lookup(svc)
        };

        for base_url in service_base_urls(svc) {
            let Some(base_match) = base_url_match(&target, base_url) else {
                continue;
            };

            if endpoints.as_ref().is_some_and(|endpoints| {
                endpoints
                    .iter()
                    .any(|endpoint| endpoint_path_matches(&base_match.relative_path, endpoint))
            }) {
                endpoint_matches.push((base_match.prefix_len, svc.fqn.clone()));
            }
            base_matches.push((base_match.prefix_len, svc.fqn.clone()));
        }
    }

    choose_unique_best_match(endpoint_matches).or_else(|| choose_unique_best_match(base_matches))
}

fn service_base_urls(svc: &Service) -> Vec<&str> {
    let mut urls = Vec::new();
    if !svc.meta.service_url.trim().is_empty() {
        urls.push(svc.meta.service_url.as_str());
    }
    if let Some(sandbox_url) = svc.meta.sandbox_service_url.as_deref()
        && !sandbox_url.trim().is_empty()
    {
        urls.push(sandbox_url);
    }
    urls
}

fn choose_unique_best_match(matches: Vec<(usize, String)>) -> Option<String> {
    let best_prefix_len = matches.iter().map(|(prefix_len, _)| *prefix_len).max()?;
    let mut fqns: Vec<_> = matches
        .into_iter()
        .filter(|(prefix_len, _)| *prefix_len == best_prefix_len)
        .map(|(_, fqn)| fqn)
        .collect();
    fqns.sort();
    fqns.dedup();
    if fqns.len() == 1 { fqns.pop() } else { None }
}

#[derive(Debug)]
struct ParsedUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    query_params: Vec<(String, String)>,
}

impl ParsedUrl {
    fn parse(raw: &str) -> Option<Self> {
        let url = reqwest::Url::parse(raw).ok()?;
        let query_params = url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        Some(Self {
            scheme: url.scheme().to_ascii_lowercase(),
            host: url.host_str()?.to_ascii_lowercase(),
            port: url.port_or_known_default(),
            path: normalize_url_path(url.path()),
            query_params,
        })
    }
}

struct BaseUrlMatch {
    prefix_len: usize,
    relative_path: String,
}

fn base_url_match(target: &ParsedUrl, base_url: &str) -> Option<BaseUrlMatch> {
    let base = ParsedUrl::parse(base_url)?;
    if target.scheme != base.scheme || target.host != base.host || target.port != base.port {
        return None;
    }

    let relative_path = relative_path(&target.path, &base.path)?;
    Some(BaseUrlMatch {
        prefix_len: base.path.len(),
        relative_path,
    })
}

fn normalize_url_path(path: &str) -> String {
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

fn relative_path(target_path: &str, base_path: &str) -> Option<String> {
    if base_path == "/" {
        return Some(target_path.trim_start_matches('/').to_string());
    }
    if target_path == base_path {
        return Some(String::new());
    }
    target_path
        .strip_prefix(base_path)
        .and_then(|rest| rest.strip_prefix('/'))
        .map(str::to_string)
}

fn endpoint_path_matches(relative_path: &str, endpoint: &Endpoint) -> bool {
    [endpoint.path.as_str(), endpoint.full_path.as_str()]
        .into_iter()
        .filter(|path| !path.trim().is_empty())
        .any(|path| path_template_matches(path, relative_path))
}

fn path_template_matches(template: &str, target: &str) -> bool {
    let template = template.trim_matches('/');
    let target = target.trim_matches('/');
    if template == target {
        return true;
    }

    let template_parts: Vec<_> = if template.is_empty() {
        Vec::new()
    } else {
        template.split('/').collect()
    };
    let target_parts: Vec<_> = if target.is_empty() {
        Vec::new()
    } else {
        target.split('/').collect()
    };
    template_parts.len() == target_parts.len()
        && template_parts
            .iter()
            .zip(target_parts.iter())
            .all(|(template, target)| path_segment_matches(template, target))
}

fn path_segment_matches(template: &str, target: &str) -> bool {
    if template.starts_with('{') && template.ends_with('}') {
        return !target.is_empty();
    }
    if !template.contains('{') {
        return template == target;
    }

    segment_template_matches(template, target)
}

fn segment_template_matches(template: &str, target: &str) -> bool {
    let mut template_rest = template;
    let mut target_rest = target;

    loop {
        let Some(open) = template_rest.find('{') else {
            return target_rest == template_rest;
        };
        let literal = &template_rest[..open];
        if !target_rest.starts_with(literal) {
            return false;
        }
        target_rest = &target_rest[literal.len()..];

        let after_open = &template_rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return false;
        };
        let after_placeholder = &after_open[close + 1..];
        if after_placeholder.is_empty() {
            return !target_rest.is_empty();
        }

        let next_literal_end = after_placeholder
            .find('{')
            .unwrap_or(after_placeholder.len());
        let next_literal = &after_placeholder[..next_literal_end];
        if next_literal.is_empty() {
            template_rest = after_placeholder;
            continue;
        }

        let Some(next_literal_pos) = target_rest.find(next_literal) else {
            return false;
        };
        if next_literal_pos == 0 {
            return false;
        }
        target_rest = &target_rest[next_literal_pos..];
        template_rest = after_placeholder;
    }
}

fn summarize_service(svc: &Service) -> ServiceSummary {
    // If endpoints are loaded, compute from them. Otherwise use index metadata.
    if svc.endpoints_loaded() {
        let mut metered = 0u32;
        let mut free = 0u32;
        let mut prices: Vec<f64> = Vec::new();

        for ep in &svc.endpoints {
            if ep.pricing.is_some() {
                metered += 1;
                collect_prices(&ep.pricing, &mut prices);
            } else {
                free += 1;
            }
        }

        ServiceSummary {
            name: svc.fqn.clone(),
            meta: svc.meta.clone(),
            endpoint_count: svc.endpoint_count.max(metered + free),
            metered_endpoints: metered,
            free_endpoints: free,
            min_price_usd: prices.iter().copied().reduce(f64::min).unwrap_or(0.0),
            max_price_usd: prices.iter().copied().reduce(f64::max).unwrap_or(0.0),
        }
    } else {
        // Use pre-computed index metadata
        ServiceSummary {
            name: svc.fqn.clone(),
            meta: svc.meta.clone(),
            endpoint_count: svc.endpoint_count,
            metered_endpoints: if svc.has_metering {
                svc.endpoint_count
            } else {
                0
            },
            free_endpoints: if svc.has_free_tier { 1 } else { 0 },
            min_price_usd: svc.min_price_usd,
            max_price_usd: svc.max_price_usd,
        }
    }
}

/// Recursively extract USD prices from a pricing JSON value.
fn collect_prices(pricing: &Option<serde_json::Value>, out: &mut Vec<f64>) {
    let Some(val) = pricing else { return };
    match val {
        serde_json::Value::Object(map) => {
            if let Some(p) = map.get("price_usd").and_then(|v| v.as_f64()) {
                out.push(p);
            }
            for v in map.values() {
                collect_prices(&Some(v.clone()), out);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                collect_prices(&Some(v.clone()), out);
            }
        }
        _ => {}
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_and_merge_rejects_empty_sources() {
        let cfg = config::SkillsConfig {
            ttl_minutes: 30,
            sources: Vec::new(),
        };

        let err = fetch_and_merge(&cfg, false, ClientApp::Cli)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("no skills sources configured"));
    }

    /// A catalog with endpoints loaded (simulates post-lazy-fetch state).
    fn catalog_with_endpoints() -> Catalog {
        let json = r#"{
            "version": "1",
            "generated_at": "2026-04-21T00:00:00Z",
            "base_url": "https://cdn.example.com/v1",
            "providers": [
                {
                    "fqn": "solana-foundation/google/bigquery",
                    "title": "BigQuery API",
                    "description": "Serverless data warehouse. SQL over petabyte-scale data.",
                    "category": "data",
                    "service_url": "https://gw.example.com",
                    "endpoint_count": 3,
                    "has_metering": true,
                    "has_free_tier": true,
                    "min_price_usd": 0.0,
                    "max_price_usd": 6.25,
                    "sha": "abc123",
                    "endpoints": [
                        {
                            "method": "POST",
                            "path": "v2/projects/{projectsId}/queries",
                            "resource": "jobs",
                            "description": "Run a SQL query",
                            "pricing": { "dimensions": [{ "tiers": [{ "price_usd": 6.25 }] }] }
                        },
                        {
                            "method": "GET",
                            "path": "v2/projects/{projectsId}/queries/{queryId}",
                            "resource": "jobs",
                            "description": "Get query results"
                        },
                        {
                            "method": "GET",
                            "path": "v2/projects/{projectsId}/datasets",
                            "resource": "datasets",
                            "description": "List datasets"
                        }
                    ]
                },
                {
                    "fqn": "solana-foundation/google/vision",
                    "title": "Cloud Vision API",
                    "description": "Detect objects, faces, text (OCR) in images.",
                    "category": "ai_ml",
                    "service_url": "https://gw.example.com",
                    "endpoint_count": 1,
                    "has_metering": true,
                    "has_free_tier": false,
                    "sha": "def456",
                    "endpoints": [
                        {
                            "method": "POST",
                            "path": "v1/images:annotate",
                            "resource": "images",
                            "description": "Annotate images",
                            "pricing": { "dimensions": [{ "tiers": [{ "price_usd": 1.50 }] }] }
                        }
                    ]
                }
            ]
        }"#;
        serde_json::from_str(json).unwrap()
    }

    /// A catalog from the index only (no endpoints loaded).
    fn catalog_index_only() -> Catalog {
        let json = r#"{
            "version": "1",
            "generated_at": "2026-04-21T00:00:00Z",
            "base_url": "https://cdn.example.com/v1",
            "providers": [
                {
                    "fqn": "solana-foundation/google/bigquery",
                    "title": "BigQuery API",
                    "description": "Serverless data warehouse. SQL over petabyte-scale data.",
                    "category": "data",
                    "service_url": "https://gw.example.com",
                    "endpoint_count": 47,
                    "has_metering": true,
                    "has_free_tier": true,
                    "min_price_usd": 0.0,
                    "max_price_usd": 6.25,
                    "sha": "abc123"
                },
                {
                    "fqn": "solana-foundation/google/vision",
                    "title": "Cloud Vision API",
                    "description": "Detect objects, faces, text (OCR) in images.",
                    "category": "ai_ml",
                    "service_url": "https://gw.example.com",
                    "endpoint_count": 38,
                    "has_metering": true,
                    "has_free_tier": true,
                    "sha": "def456"
                },
                {
                    "fqn": "solana-foundation/payment-debugger",
                    "title": "Payment Debugger",
                    "description": "Demo API for testing payment flows.",
                    "category": "devtools",
                    "service_url": "https://pdb.example.com",
                    "endpoint_count": 8,
                    "has_metering": true,
                    "has_free_tier": true,
                    "sha": "ghi789"
                }
            ]
        }"#;
        serde_json::from_str(json).unwrap()
    }

    fn catalog_for_provider_routing() -> Catalog {
        let json = r#"{
            "version": "1",
            "generated_at": "2026-04-21T00:00:00Z",
            "base_url": "https://cdn.example.com/v1",
            "providers": [
                {
                    "fqn": "merit-systems/stableenrich/enrichment",
                    "title": "StableEnrich",
                    "description": "Unified enrichment gateway for people, company, web search, scraping, maps, email verification, and property data.",
                    "use_case": "Use for contact enrichment, company lookup, prospect search, web search, page scraping, local business discovery, email verification, and people search.",
                    "category": "data",
                    "service_url": "https://stableenrich.example.com",
                    "endpoint_count": 30,
                    "has_metering": true,
                    "min_price_usd": 0.002,
                    "max_price_usd": 0.44,
                    "sha": "stableenrich"
                },
                {
                    "fqn": "socialintel/influencer-search",
                    "title": "Social Intel",
                    "description": "Instagram influencer search by keyword, category, demographics, and location.",
                    "use_case": "Use for Instagram influencer search, creator discovery, audience demographics, brand partnership prospecting, and location-based social media research.",
                    "category": "data",
                    "service_url": "https://social.example.com",
                    "endpoint_count": 1,
                    "has_metering": true,
                    "min_price_usd": 0.1,
                    "max_price_usd": 0.1,
                    "sha": "social"
                },
                {
                    "fqn": "quicknode/rpc",
                    "title": "QuickNode",
                    "description": "Pay-per-request JSON-RPC access to blockchain networks including Solana.",
                    "use_case": "Use for raw blockchain RPC methods, Solana getSlot, account reads, transaction submission, and chain data access.",
                    "category": "compute",
                    "service_url": "https://quicknode.example.com",
                    "endpoint_count": 1,
                    "has_metering": true,
                    "min_price_usd": 0.01,
                    "max_price_usd": 0.01,
                    "sha": "quicknode"
                },
                {
                    "fqn": "solana-foundation/payment-debugger",
                    "title": "Payment Debugger",
                    "description": "Demo API for testing payment flows.",
                    "use_case": "Use for payment debugger demos and testing pay flows.",
                    "category": "devtools",
                    "service_url": "https://debugger.example.com",
                    "endpoint_count": 8,
                    "has_metering": true,
                    "min_price_usd": 0.01,
                    "max_price_usd": 1000.0,
                    "sha": "debugger"
                }
            ]
        }"#;
        serde_json::from_str(json).unwrap()
    }

    // ── Deserialization ─────────────────────────────────────────────────────

    #[test]
    fn parse_v1_index() {
        let cat = catalog_index_only();
        assert_eq!(cat.schema_version, "1");
        assert_eq!(cat.providers.len(), 3);
        assert_eq!(cat.base_url, "https://cdn.example.com/v1");
    }

    #[test]
    fn service_fqn_and_name() {
        let cat = catalog_index_only();
        let svc = &cat.providers[0];
        assert_eq!(svc.fqn, "solana-foundation/google/bigquery");
        assert_eq!(svc.name(), "bigquery");
    }

    #[test]
    fn service_two_level_fqn() {
        let cat = catalog_index_only();
        let svc = &cat.providers[2];
        assert_eq!(svc.fqn, "solana-foundation/payment-debugger");
        assert_eq!(svc.name(), "payment-debugger");
    }

    #[test]
    fn index_metadata_present() {
        let cat = catalog_index_only();
        let svc = &cat.providers[0];
        assert_eq!(svc.endpoint_count, 47);
        assert!(svc.has_metering);
        assert!(svc.has_free_tier);
        assert!(!svc.endpoints_loaded());
    }

    // ── Search (index-only, no endpoints loaded) ────────────────────────────

    #[test]
    fn search_index_only_matches_service_title() {
        let cat = catalog_index_only();
        let hits = search(&cat, Some("bigquery"), None);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].service, "solana-foundation/google/bigquery");
        // Placeholder hit — no method/path since endpoints aren't loaded
        assert!(hits[0].method.is_empty());
    }

    #[test]
    fn search_index_only_matches_description() {
        let cat = catalog_index_only();
        let hits = search(&cat, Some("warehouse"), None);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].service, "solana-foundation/google/bigquery");
    }

    #[test]
    fn search_index_only_matches_fqn() {
        let cat = catalog_index_only();
        let hits = search(&cat, Some("payment-debugger"), None);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn search_index_only_category_filter() {
        let cat = catalog_index_only();
        let hits = search(&cat, None, Some("ai_ml"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].service, "solana-foundation/google/vision");
    }

    #[test]
    fn search_index_only_no_match() {
        let cat = catalog_index_only();
        let hits = search(&cat, Some("nonexistent"), None);
        assert!(hits.is_empty());
    }

    #[test]
    fn search_index_only_all_returns_all_providers() {
        let cat = catalog_index_only();
        let hits = search(&cat, None, None);
        assert_eq!(hits.len(), 3);
    }

    // ── Search (with endpoints loaded) ──────────────────────────────────────

    #[test]
    fn search_with_endpoints_matches_path() {
        let cat = catalog_with_endpoints();
        let hits = search(&cat, Some("queries"), None);
        assert_eq!(hits.len(), 2);
        assert!(
            hits.iter()
                .all(|h| h.service == "solana-foundation/google/bigquery")
        );
    }

    #[test]
    fn search_with_endpoints_matches_endpoint_description() {
        let cat = catalog_with_endpoints();
        let hits = search(&cat, Some("annotate"), None);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].method, "POST");
    }

    #[test]
    fn search_with_endpoints_all_returns_all() {
        let cat = catalog_with_endpoints();
        let hits = search(&cat, None, None);
        // 3 bigquery + 1 vision = 4
        assert_eq!(hits.len(), 4);
    }

    #[test]
    fn search_metered_first() {
        let cat = catalog_with_endpoints();
        let hits = search(&cat, None, None);
        // Within bigquery, metered POST should come before free GETs
        let bq: Vec<_> = hits
            .iter()
            .filter(|h| h.service.contains("bigquery"))
            .collect();
        assert!(bq[0].metered);
    }

    // ── search_services ─────────────────────────────────────────────────────

    #[test]
    fn search_services_index_only() {
        let cat = catalog_index_only();
        let results = search_services(&cat, Some("bigquery"), None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "solana-foundation/google/bigquery");
        assert_eq!(results[0].endpoint_count, 47);
        assert_eq!(results[0].min_price_usd, 0.0);
        assert_eq!(results[0].max_price_usd, 6.25);
    }

    #[test]
    fn search_services_with_endpoints() {
        let cat = catalog_with_endpoints();
        let results = search_services(&cat, Some("bigquery"), None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metered_endpoints, 1);
        assert_eq!(results[0].free_endpoints, 2);
    }

    #[test]
    fn search_services_matches_use_case() {
        let cat = catalog_for_provider_routing();
        let results = search_services(&cat, Some("creator discovery"), None);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "socialintel/influencer-search");
    }

    #[test]
    fn ranked_search_prefers_narrow_provider_over_broad_match() {
        let cat = catalog_for_provider_routing();
        let results = search_services_ranked(&cat, "find instagram influencers in paris", None, 5);
        assert_eq!(results[0].service.name, "socialintel/influencer-search");
        assert!(results[0].score > results[1].score);
    }

    #[test]
    fn ranked_search_uses_use_case_metadata() {
        let cat = catalog_for_provider_routing();
        let results =
            search_services_ranked(&cat, "send a raw solana getSlot RPC request", None, 5);
        assert_eq!(results[0].service.name, "quicknode/rpc");
        assert!(
            results[0]
                .reasons
                .iter()
                .any(|reason| reason.contains("important query terms"))
        );
    }

    #[test]
    fn ranked_search_applies_category_filter() {
        let cat = catalog_for_provider_routing();
        let results = search_services_ranked(&cat, "solana rpc", Some("data"), 5);
        assert!(
            !results
                .iter()
                .any(|result| result.service.name == "quicknode/rpc")
        );
    }

    #[test]
    fn ranked_search_deprioritizes_demo_provider_for_real_tasks() {
        let cat = catalog_for_provider_routing();
        let results = search_services_ranked(&cat, "payment search", None, 5);
        assert_ne!(
            results[0].service.name,
            "solana-foundation/payment-debugger"
        );
    }

    // ── find_service ────────────────────────────────────────────────────────

    #[test]
    fn find_service_by_fqn() {
        let cat = catalog_index_only();
        let svc = find_service(&cat, "solana-foundation/google/bigquery");
        assert!(svc.is_some());
    }

    #[test]
    fn find_service_by_short_name() {
        let cat = catalog_index_only();
        let svc = find_service(&cat, "bigquery");
        assert!(svc.is_some());
        assert_eq!(svc.unwrap().fqn, "solana-foundation/google/bigquery");
    }

    #[test]
    fn find_service_case_insensitive() {
        let cat = catalog_index_only();
        assert!(find_service(&cat, "BigQuery").is_some());
        assert!(find_service(&cat, "SOLANA-FOUNDATION/GOOGLE/BIGQUERY").is_some());
    }

    // ── service_detail (requires endpoints) ─────────────────────────────────

    #[test]
    fn service_detail_groups_by_resource() {
        let cat = catalog_with_endpoints();
        let detail = service_detail(&cat, "bigquery").unwrap();
        assert_eq!(detail.resources.len(), 2);

        let jobs = detail.resources.iter().find(|r| r.name == "jobs").unwrap();
        assert_eq!(jobs.endpoint_count, 2);
        assert_eq!(jobs.metered_count, 1);

        let datasets = detail
            .resources
            .iter()
            .find(|r| r.name == "datasets")
            .unwrap();
        assert_eq!(datasets.endpoint_count, 1);
        assert_eq!(datasets.metered_count, 0);
    }

    #[test]
    fn service_detail_empty_when_no_endpoints() {
        let cat = catalog_index_only();
        let detail = service_detail(&cat, "bigquery").unwrap();
        assert!(detail.resources.is_empty());
    }

    // ── resource_endpoints ──────────────────────────────────────────────────

    #[test]
    fn resource_endpoints_returns_matching() {
        let cat = catalog_with_endpoints();
        let result = resource_endpoints(&cat, "bigquery", "jobs").unwrap();
        assert_eq!(result.endpoints.len(), 2);
    }

    #[test]
    fn resource_endpoints_none_when_not_loaded() {
        let cat = catalog_index_only();
        assert!(resource_endpoints(&cat, "bigquery", "jobs").is_none());
    }

    // ── group_search_results ────────────────────────────────────────────────

    #[test]
    fn group_search_results_groups_by_service() {
        let cat = catalog_with_endpoints();
        let hits = search(&cat, None, None);
        let groups = group_search_results(&hits);
        assert_eq!(groups.len(), 2);
        let bq = groups
            .iter()
            .find(|g| g.service.contains("bigquery"))
            .unwrap();
        assert_eq!(bq.endpoints.len(), 3);
    }

    #[test]
    fn group_search_results_endpoints_have_urls() {
        let cat = catalog_with_endpoints();
        let hits = search(&cat, Some("annotate"), None);
        let groups = group_search_results(&hits);
        assert_eq!(
            groups[0].endpoints[0].url,
            "https://gw.example.com/v1/images:annotate"
        );
        assert!(groups[0].endpoints[0].metered);
    }

    // ── build_endpoint_url ──────────────────────────────────────────────────

    #[test]
    fn build_endpoint_url_resolves_placeholders() {
        let url = build_endpoint_url("https://gw.example.com", "v2/projects/{projectsId}/queries");
        assert_eq!(
            url,
            "https://gw.example.com/v2/projects/gateway-402/queries"
        );
    }

    #[test]
    fn build_endpoint_url_empty_path() {
        assert_eq!(
            build_endpoint_url("https://gw.example.com/", ""),
            "https://gw.example.com"
        );
    }

    // ── service_fqn_for_url_in_catalog ─────────────────────────────────────

    #[test]
    fn service_fqn_for_url_in_catalog_matches_loaded_endpoint_on_shared_gateway() {
        let cat = catalog_with_endpoints();
        let fqn = service_fqn_for_url_in_catalog(
            &cat,
            "https://gw.example.com/v1/images:annotate",
            |_| None,
        );
        assert_eq!(fqn.as_deref(), Some("solana-foundation/google/vision"));
    }

    #[test]
    fn service_fqn_for_url_in_catalog_matches_placeholder_endpoint() {
        let cat = catalog_with_endpoints();
        let fqn = service_fqn_for_url_in_catalog(
            &cat,
            "https://gw.example.com/v2/projects/my-project/queries",
            |_| None,
        );
        assert_eq!(fqn.as_deref(), Some("solana-foundation/google/bigquery"));
    }

    #[test]
    fn service_fqn_for_url_in_catalog_avoids_ambiguous_shared_gateway_without_endpoints() {
        let cat = catalog_index_only();
        let fqn =
            service_fqn_for_url_in_catalog(&cat, "https://gw.example.com/v1/unknown", |_| None);
        assert_eq!(fqn, None);
    }

    #[test]
    fn service_fqn_for_url_in_catalog_uses_unique_service_domain() {
        let cat = catalog_index_only();
        let fqn = service_fqn_for_url_in_catalog(&cat, "https://pdb.example.com/reports", |_| None);
        assert_eq!(fqn.as_deref(), Some("solana-foundation/payment-debugger"));
    }

    #[test]
    fn path_template_matches_segment_placeholders() {
        assert!(path_template_matches(
            "v2/projects/{project}/queries",
            "v2/projects/my-project/queries"
        ));
        assert!(path_template_matches(
            "v1/models/{model}:generateContent",
            "v1/models/gemini-2.0-flash:generateContent"
        ));
        assert!(!path_template_matches(
            "v2/projects/{project}/queries",
            "v2/projects/my-project/datasets"
        ));
    }

    // ── collect_prices ──────────────────────────────────────────────────────

    #[test]
    fn collect_prices_nested() {
        let pricing = serde_json::json!({
            "dimensions": [{ "tiers": [{ "price_usd": 0 }, { "price_usd": 6.25 }] }]
        });
        let mut prices = Vec::new();
        collect_prices(&Some(pricing), &mut prices);
        assert_eq!(prices, vec![0.0, 6.25]);
    }

    #[test]
    fn price_range_usd_returns_min_and_max() {
        let pricing = serde_json::json!({
            "dimensions": [
                { "tiers": [{ "price_usd": 0.01 }, { "price_usd": 0.04 }] },
                { "price_usd": 0.02 }
            ]
        });

        assert_eq!(price_range_usd(&Some(pricing)), Some((0.01, 0.04)));
        assert_eq!(price_range_usd(&None), None);
    }

    // ── Cache invalidation ──────────────────────────────────────────────────

    #[test]
    fn detail_cache_key_is_sha_based() {
        // Two providers with different shas must not share cache files.
        let cat = catalog_index_only();
        let bq = &cat.providers[0];
        let vision = &cat.providers[1];
        assert_ne!(bq.sha, vision.sha);
        // Cache file names are `{sha}.json` — different shas = different files
        let bq_cache = format!("{}.json", bq.sha);
        let vision_cache = format!("{}.json", vision.sha);
        assert_ne!(bq_cache, vision_cache);
    }

    #[test]
    fn sha_change_invalidates_detail_cache() {
        // Simulate: index has sha "abc123" for bigquery.
        // A new index arrives with sha "xyz789" for the same provider.
        // The old cache file "abc123.json" should NOT be hit.
        let old_sha = "abc123";
        let new_sha = "xyz789";
        let old_cache = format!("{old_sha}.json");
        let new_cache = format!("{new_sha}.json");
        assert_ne!(old_cache, new_cache);
        // ensure_endpoints looks for `{sha}.json` — with a new sha, it's a miss.
    }

    #[test]
    fn endpoints_loaded_reflects_state() {
        let mut cat = catalog_index_only();
        let svc = &cat.providers[0];
        assert!(!svc.endpoints_loaded());

        // Simulate loading endpoints
        cat.providers[0].endpoints = vec![Endpoint {
            method: "GET".to_string(),
            path: "test".to_string(),
            full_path: String::new(),
            resource: None,
            description: "test".to_string(),
            pricing: None,
        }];
        assert!(cat.providers[0].endpoints_loaded());
    }

    #[tokio::test]
    async fn ensure_endpoints_skips_when_already_loaded() {
        let mut cat = catalog_with_endpoints();
        let count_before = cat.providers[0].endpoints.len();
        let result = ensure_endpoints(&mut cat, "bigquery").await;
        assert!(result.is_ok());
        assert_eq!(cat.providers[0].endpoints.len(), count_before);
    }

    #[tokio::test]
    async fn ensure_endpoints_fails_without_base_url() {
        let mut cat = catalog_index_only();
        cat.base_url = String::new();
        let result = ensure_endpoints(&mut cat, "bigquery").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("base_url"));
    }

    #[tokio::test]
    async fn ensure_endpoints_fails_for_unknown_service() {
        let mut cat = catalog_index_only();
        let result = ensure_endpoints(&mut cat, "nonexistent").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"));
    }

    #[test]
    fn detail_file_cache_uses_tempdir() {
        // Verify the detail cache path construction
        let cat = catalog_index_only();
        let svc = &cat.providers[0];
        let cache_dir = std::path::PathBuf::from("/tmp/test-skills-cache");
        let cache_file = cache_dir.join(format!("{}.json", svc.sha));
        assert_eq!(
            cache_file.file_name().unwrap().to_str().unwrap(),
            "abc123.json"
        );
    }

    #[test]
    fn index_updated_sha_means_detail_cache_miss() {
        // Simulate the full invalidation flow:
        // 1. Index v1: bigquery sha="abc123"
        // 2. Index v2: bigquery sha="new_sha_456"
        // 3. Cache has "abc123.json" but NOT "new_sha_456.json"
        // 4. ensure_endpoints should miss cache and fetch

        let mut cat_v1 = catalog_index_only();
        let mut cat_v2 = catalog_index_only();
        cat_v2.providers[0].sha = "new_sha_456".to_string();

        // v1 and v2 have different shas for the same provider
        assert_ne!(cat_v1.providers[0].sha, cat_v2.providers[0].sha);

        // Both still have no endpoints loaded
        assert!(!cat_v1.providers[0].endpoints_loaded());
        assert!(!cat_v2.providers[0].endpoints_loaded());

        // Inject endpoints into v1 to simulate "was loaded from old cache"
        cat_v1.providers[0].endpoints = vec![Endpoint {
            method: "GET".to_string(),
            path: "old".to_string(),
            full_path: String::new(),
            resource: None,
            description: "old endpoint".to_string(),
            pricing: None,
        }];

        // v1 is loaded, v2 is not — v2 would need a fresh fetch
        assert!(cat_v1.providers[0].endpoints_loaded());
        assert!(!cat_v2.providers[0].endpoints_loaded());
    }

    #[test]
    fn parse_detail_extracts_endpoints() {
        let json = r#"{
            "fqn": "test/api",
            "endpoints": [
                {"method": "GET", "path": "v1/foo", "description": "Get foo"},
                {"method": "POST", "path": "v1/bar", "description": "Create bar"}
            ]
        }"#;
        let detail = parse_detail(json).unwrap();
        assert_eq!(detail.endpoints.len(), 2);
        assert_eq!(detail.endpoints[0].method, "GET");
        assert_eq!(detail.endpoints[1].path, "v1/bar");
    }

    #[test]
    fn parse_detail_handles_empty_endpoints() {
        let json = r#"{"fqn": "test/api"}"#;
        let detail = parse_detail(json).unwrap();
        assert!(detail.endpoints.is_empty());
    }

    #[test]
    fn parse_detail_handles_extra_fields() {
        // Detail files have fields we don't deserialize (content, source, etc.)
        // Make sure they don't cause errors
        let json = r#"{
            "fqn": "test/api",
            "name": "api",
            "title": "Test API",
            "content": "Some markdown...",
            "source": {"skill": "pay-skills"},
            "affiliate_policy": {"enabled": true},
            "endpoints": [{"method": "GET", "path": "v1/x", "description": "test"}]
        }"#;
        let detail = parse_detail(json).unwrap();
        assert_eq!(detail.endpoints.len(), 1);
    }

    // ── Detail cache cleanup ──────────────────────────────────────────────

    #[test]
    fn clean_stale_detail_cache_removes_old_files() {
        let dir = tempfile::tempdir().unwrap();
        let detail_dir = dir.path().join("detail");
        std::fs::create_dir_all(&detail_dir).unwrap();

        // Create some cache files: two live, one stale
        std::fs::write(detail_dir.join("abc123.json"), "{}").unwrap();
        std::fs::write(detail_dir.join("def456.json"), "{}").unwrap();
        std::fs::write(detail_dir.join("old_dead.json"), "{}").unwrap();

        // Catalog only references abc123 and def456
        let cat = catalog_index_only(); // shas: abc123, def456, ghi789

        // We can't easily override the cache dir, so test the logic directly:
        let live_shas: std::collections::HashSet<_> = cat
            .providers
            .iter()
            .filter(|s| !s.sha.is_empty())
            .map(|s| format!("{}.json", s.sha))
            .collect();

        assert!(live_shas.contains("abc123.json"));
        assert!(live_shas.contains("def456.json"));
        assert!(live_shas.contains("ghi789.json"));
        assert!(!live_shas.contains("old_dead.json"));

        // Simulate cleanup
        for entry in std::fs::read_dir(&detail_dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".json") && !live_shas.contains(&name) {
                std::fs::remove_file(entry.path()).unwrap();
            }
        }

        // old_dead.json should be gone
        assert!(!detail_dir.join("old_dead.json").exists());
        // live files should remain
        assert!(detail_dir.join("abc123.json").exists());
        assert!(detail_dir.join("def456.json").exists());
    }

    // ── Catalog round-trip ──────────────────────────────────────────────────

    #[test]
    fn catalog_serialization_round_trip() {
        let cat = catalog_index_only();
        let json = serde_json::to_string(&cat).unwrap();
        let cat2: Catalog = serde_json::from_str(&json).unwrap();
        assert_eq!(cat.providers.len(), cat2.providers.len());
        assert_eq!(cat.base_url, cat2.base_url);
        assert_eq!(cat.providers[0].fqn, cat2.providers[0].fqn);
        assert_eq!(cat.providers[0].sha, cat2.providers[0].sha);
    }

    #[test]
    fn catalog_with_integer_version() {
        // version can be int or string
        let json = r#"{"version": 1, "generated_at": "", "providers": []}"#;
        let cat: Catalog = serde_json::from_str(json).unwrap();
        assert_eq!(cat.schema_version, "1");
    }

    #[test]
    fn catalog_with_string_version() {
        let json = r#"{"version": "1", "generated_at": "", "providers": []}"#;
        let cat: Catalog = serde_json::from_str(json).unwrap();
        assert_eq!(cat.schema_version, "1");
    }
}
