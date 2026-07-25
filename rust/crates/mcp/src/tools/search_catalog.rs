use rmcp::model::CallToolResult;
use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const ENDPOINT_LOOKUP_MULTIPLIER: usize = 3;
const MAX_ENDPOINTS_PER_CANDIDATE: usize = 5;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Params {
    /// Natural-language task to route to the best provider. Do not use for Pay capability questions.
    #[schemars(
        description = "Actionable user task to route to a provider. Do not use for Pay capability questions like \"what can Pay do?\" or \"does Pay support X?\"; call list_catalog instead."
    )]
    pub query: String,
    /// Optional category filter such as ai_ml, data, finance, maps, media, or search.
    #[schemars(
        description = "Optional category filter such as ai_ml, data, finance, maps, media, or search"
    )]
    #[serde(default)]
    pub category: Option<String>,
    /// Maximum number of candidates to return.
    #[schemars(description = "Maximum number of ranked provider candidates to return, default 5")]
    #[serde(default = "default_max_results")]
    pub max_results: usize,
    /// Force-refresh the catalog from all sources before searching.
    #[schemars(description = "Set to true to force-refresh the catalog from CDN before searching")]
    #[serde(default)]
    pub refresh: bool,
    /// Bypass CDN cache by appending a cache-buster query parameter.
    #[schemars(description = "Set to true to bypass CDN edge cache (appends ?v=<timestamp>)")]
    #[serde(default)]
    pub cache_bust: bool,
}

#[derive(Debug, Serialize)]
struct SearchCatalogResponse {
    query: String,
    candidates: Vec<CandidateEntry>,
    selection_guidance: Vec<String>,
    call_plan_fields: Vec<String>,
    next_step: String,
}

#[derive(Debug, Serialize)]
struct CandidateEntry {
    fqn: String,
    title: String,
    category: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    use_case: Option<String>,
    endpoint_count: u32,
    has_metering: bool,
    min_price_usd: f64,
    max_price_usd: f64,
    score: u32,
    reasons: Vec<String>,
    endpoints: Vec<EndpointEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint_lookup_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct EndpointEntry {
    method: String,
    path: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    description: String,
    metered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_price_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_price_usd: Option<f64>,
    match_score: u32,
}

fn default_max_results() -> usize {
    5
}

pub async fn run(params: Params) -> Result<CallToolResult, rmcp::ErrorData> {
    let query = params.query.trim().to_string();
    if query.is_empty() {
        return Ok(super::tool_error("`query` must describe the user's task"));
    }

    let cache_bust = params.cache_bust;
    let catalog_result = if params.refresh || cache_bust {
        pay_core::skills::update_skills_for(cache_bust, pay_core::ClientApp::Mcp)
            .await
            .map_err(|e| format!("Failed to refresh Pay catalog: {e}"))
    } else {
        pay_core::skills::load_skills_for(pay_core::ClientApp::Mcp)
            .await
            .map_err(|e| format!("Failed to load Pay catalog: {e}"))
    };
    let catalog = match catalog_result {
        Ok(catalog) => catalog,
        Err(message) => return Ok(super::tool_error(message)),
    };

    let max_results = params.max_results.clamp(1, 10);
    let category = params.category.clone();
    let response = build_search_catalog_response(
        catalog,
        query,
        category,
        max_results,
        pay_core::ClientApp::Mcp,
    )
    .await;

    let json = match serde_json::to_string_pretty(&response) {
        Ok(json) => json,
        Err(err) => {
            return Ok(super::tool_error(format!(
                "Failed to serialize response: {err}"
            )));
        }
    };

    Ok(CallToolResult::success(vec![rmcp::model::Content::text(
        json,
    )]))
}

async fn build_search_catalog_response(
    mut catalog: pay_core::skills::Catalog,
    query: String,
    category: Option<String>,
    max_results: usize,
    client_app: pay_core::ClientApp,
) -> SearchCatalogResponse {
    let lookup_limit = (max_results * ENDPOINT_LOOKUP_MULTIPLIER).clamp(max_results, 20);
    let preliminary = pay_core::skills::search_services_ranked(
        &catalog,
        &query,
        category.as_deref(),
        lookup_limit,
    );

    let mut endpoint_errors = HashMap::new();
    for candidate in &preliminary {
        let fqn = candidate.service.name.clone();
        if let Err(err) =
            pay_core::skills::ensure_endpoints_for(&mut catalog, &fqn, client_app).await
        {
            endpoint_errors.insert(fqn, err.to_string());
        }
    }

    let ranked = pay_core::skills::search_services_ranked(
        &catalog,
        &query,
        category.as_deref(),
        max_results,
    );

    let candidates: Vec<CandidateEntry> = ranked
        .into_iter()
        .map(|candidate| {
            let fqn = candidate.service.name;
            let endpoints = catalog
                .providers
                .iter()
                .find(|svc| svc.fqn.eq_ignore_ascii_case(&fqn))
                .map(|svc| endpoint_entries_for_query(svc, &query, MAX_ENDPOINTS_PER_CANDIDATE))
                .unwrap_or_default();

            CandidateEntry {
                endpoint_lookup_error: endpoint_errors.get(&fqn).cloned(),
                fqn,
                title: candidate.service.meta.title,
                category: candidate.service.meta.category,
                description: candidate.service.meta.description,
                use_case: candidate.service.meta.use_case,
                endpoint_count: candidate.service.endpoint_count,
                has_metering: candidate.service.metered_endpoints > 0,
                min_price_usd: candidate.service.min_price_usd,
                max_price_usd: candidate.service.max_price_usd,
                score: candidate.score,
                reasons: candidate.reasons,
                endpoints,
            }
        })
        .collect();
    let next_step = next_step_for_candidates(&candidates);

    SearchCatalogResponse {
        query,
        candidates,
        selection_guidance: selection_guidance(),
        call_plan_fields: call_plan_fields(),
        next_step,
    }
}

fn selection_guidance() -> Vec<String> {
    [
        "For Pay capability or feasibility questions, call list_catalog before answering no; search results alone are not a complete capability check.",
        "Use the top candidate only when its provider and endpoint clearly match the user's task.",
        "Prefer exact endpoint fit over broad provider metadata.",
        "Hard-reject wrong network/currency, unusable method/body shape, invalid 402 challenges, and prices above the user's stated limit.",
        "For close candidates, compare endpoint fit, supported network/currency, usable request shape, freshness/result quality, and total estimated price in that order.",
        "Call get_catalog_entry once for the most likely provider when compact endpoint candidates are insufficient; do not browse every provider.",
        "Ask the user before multi-call exploration, schema probing, broad crawls, unclear pricing, or a provider tie that remains unresolved.",
    ]
    .into_iter()
    .map(ToString::to_string)
    .collect()
}

fn call_plan_fields() -> Vec<String> {
    [
        "provider fqn",
        "endpoint method and exact url",
        "why this endpoint matches",
        "expected paid calls",
        "estimated total spend",
        "smallest useful request body or query",
    ]
    .into_iter()
    .map(ToString::to_string)
    .collect()
}

fn next_step_for_candidates(candidates: &[CandidateEntry]) -> String {
    let Some(top) = candidates.first() else {
        return "No matching provider was found. Retry search_catalog once with refresh=true if the catalog may be stale; otherwise ask the user before using a non-Pay fallback.".to_string();
    };

    if top.endpoint_lookup_error.is_some() || top.endpoints.is_empty() {
        return format!(
            "Inspect `{}` with get_catalog_entry before paying; compact endpoint details were unavailable or incomplete.",
            top.fqn
        );
    }

    if let Some(second) = candidates.get(1)
        && top.score <= second.score.saturating_add(10)
    {
        return format!(
            "Top candidates are close: `{}` ({}) and `{}` ({}). Compare endpoint fit and total estimated price; ask the user if neither clearly wins.",
            top.fqn, top.score, second.fqn, second.score
        );
    }

    format!(
        "If `{}` and one returned endpoint clearly match, make a compact call plan and call curl with the endpoint's exact url. If not, call get_catalog_entry for `{}` before paying.",
        top.fqn, top.fqn
    )
}

fn endpoint_entries_for_query(
    svc: &pay_core::skills::Service,
    query: &str,
    limit: usize,
) -> Vec<EndpointEntry> {
    let terms = tokenize_query(query);
    let query_lower = query.trim().to_lowercase();

    let mut entries: Vec<EndpointEntry> = svc
        .endpoints
        .iter()
        .map(|ep| {
            let match_score = score_endpoint_for_query(ep, &query_lower, &terms);
            let (min_price_usd, max_price_usd) =
                pay_core::skills::price_range_usd(&ep.pricing).unzip();
            EndpointEntry {
                method: ep.method.clone(),
                path: ep.path.clone(),
                url: pay_core::skills::build_endpoint_url(&svc.meta.service_url, &ep.path),
                resource: ep.resource.clone(),
                description: ep.description.clone(),
                metered: ep.pricing.is_some(),
                min_price_usd,
                max_price_usd,
                match_score,
            }
        })
        .collect();

    entries.sort_by(|a, b| {
        b.match_score
            .cmp(&a.match_score)
            .then_with(|| b.metered.cmp(&a.metered))
            .then_with(|| a.path.cmp(&b.path))
    });
    entries.truncate(limit);
    entries
}

fn score_endpoint_for_query(
    ep: &pay_core::skills::Endpoint,
    query_lower: &str,
    terms: &[String],
) -> u32 {
    let path = ep.path.to_lowercase();
    let resource = ep.resource.as_deref().unwrap_or("").to_lowercase();
    let description = ep.description.to_lowercase();
    let haystack = format!("{} {} {} {}", ep.method, path, resource, description).to_lowercase();
    let mut score = if !query_lower.is_empty() && haystack.contains(query_lower) {
        100
    } else {
        0
    };

    for term in terms {
        if contains_query_term(&path, term) {
            score += 24;
        }
        if contains_query_term(&resource, term) {
            score += 16;
        }
        if contains_query_term(&description, term) {
            score += 10;
        }
    }

    score
}

fn contains_query_term(haystack: &str, term: &str) -> bool {
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

fn tokenize_query(query: &str) -> Vec<String> {
    const STOPWORDS: &[&str] = &[
        "a", "an", "and", "api", "by", "for", "from", "get", "i", "in", "into", "me", "need", "of",
        "on", "or", "please", "the", "to", "use", "using", "with",
    ];

    query
        .split(|c: char| !c.is_ascii_alphanumeric())
        .map(|term| term.trim().to_lowercase())
        .filter(|term| term.len() > 1 && !STOPWORDS.contains(&term.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const GLOBAL_CURRENT_BENCHMARK: f64 = 83.722;
    const GLOBAL_CURRENT_TOP1_BENCHMARK: f64 = 77.111;
    const BENCHMARK_EPSILON: f64 = 0.001;

    #[test]
    fn params_default_max_results() {
        let params: Params = serde_json::from_str(r#"{"query": "search influencers"}"#).unwrap();
        assert_eq!(params.max_results, 5);
        assert!(!params.refresh);
    }

    #[test]
    fn params_accept_category_and_limit() {
        let params: Params = serde_json::from_str(
            r#"{"query": "search influencers", "category": "media", "max_results": 3}"#,
        )
        .unwrap();
        assert_eq!(params.category.as_deref(), Some("media"));
        assert_eq!(params.max_results, 3);
    }

    #[tokio::test]
    async fn search_catalog_response_includes_provider_selection_guidance() {
        let response = build_search_catalog_response(
            bench_catalog(),
            "what's the volume of USDC that moved on Solana the past week".to_string(),
            None,
            5,
            pay_core::ClientApp::Cli,
        )
        .await;

        assert!(!response.candidates.is_empty());
        assert!(
            response
                .selection_guidance
                .iter()
                .any(|line| line.contains("endpoint fit"))
        );
        assert!(
            response
                .call_plan_fields
                .iter()
                .any(|field| field == "estimated total spend")
        );
        assert!(response.next_step.contains("call plan") || response.next_step.contains("Compare"));
    }

    #[tokio::test]
    async fn search_catalog_response_handles_empty_results_with_refresh_hint() {
        let response = build_search_catalog_response(
            pay_core::skills::Catalog {
                schema_version: "1".to_string(),
                generated_at: "test".to_string(),
                base_url: String::new(),
                provider_count: 0,
                providers: Vec::new(),
            },
            "no matching service".to_string(),
            None,
            5,
            pay_core::ClientApp::Cli,
        )
        .await;

        assert!(response.candidates.is_empty());
        assert!(response.next_step.contains("refresh=true"));
    }

    #[test]
    fn endpoint_entries_include_price_range_and_urls() {
        let svc = pay_core::skills::Service {
            fqn: "example/search".to_string(),
            meta: pay_types::registry::ServiceMeta {
                service_url: "https://api.example.com".to_string(),
                ..Default::default()
            },
            endpoint_count: 1,
            has_metering: true,
            has_free_tier: false,
            min_price_usd: 0.01,
            max_price_usd: 0.02,
            sha: String::new(),
            endpoints: vec![pay_core::skills::Endpoint {
                method: "POST".to_string(),
                path: "v1/search".to_string(),
                full_path: String::new(),
                resource: Some("search".to_string()),
                description: "Search indexed documents".to_string(),
                pricing: Some(serde_json::json!({
                    "dimensions": [{ "tiers": [{ "price_usd": 0.01 }, { "price_usd": 0.02 }] }]
                })),
            }],
            content: None,
        };

        let endpoints = endpoint_entries_for_query(&svc, "search documents", 5);
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].url, "https://api.example.com/v1/search");
        assert_eq!(endpoints[0].min_price_usd, Some(0.01));
        assert_eq!(endpoints[0].max_price_usd, Some(0.02));
        assert!(endpoints[0].match_score > 0);
    }

    #[tokio::test]
    async fn search_catalog_csv_routing_bench() {
        let cases = parse_routing_cases(include_str!(
            "../../tests/fixtures/provider_routing_cases.csv"
        ));
        assert!(
            cases.len() >= 200,
            "routing benchmark should stay broad; add cases instead of shrinking it"
        );
        assert!(
            cases.iter().all(|case| !case.expected_providers.is_empty()),
            "every routing benchmark case must declare at least one expected provider"
        );
        assert!(
            cases
                .iter()
                .filter(|case| case.expected_providers.len() > 1)
                .count()
                >= 100,
            "routing benchmark should include many ambiguous prompts with multiple acceptable providers"
        );
        let case_count = cases.len() as f64;

        let catalog = bench_catalog();
        let mut report = Vec::with_capacity(cases.len() + 1);
        report.push(csv_record(&[
            "id",
            "prompt",
            "expected_providers",
            "best_expected_rank",
            "case_score",
            "top1_match",
            "actual_provider",
            "actual_endpoint",
            "actual_score",
            "top_candidates",
        ]));

        let mut total_score = 0.0;
        let mut top1_matches = 0usize;
        for case in cases {
            let response = build_search_catalog_response(
                catalog.clone(),
                case.prompt.clone(),
                case.category.clone(),
                5,
                pay_core::ClientApp::Cli,
            )
            .await;
            let actual = response.candidates.first();
            let actual_provider = actual.map(|candidate| candidate.fqn.as_str()).unwrap_or("");
            let actual_endpoint = actual
                .and_then(|candidate| candidate.endpoints.first())
                .map(|endpoint| endpoint.path.as_str())
                .unwrap_or("");
            let actual_score = actual.map(|candidate| candidate.score).unwrap_or_default();
            let expected_rank = response
                .candidates
                .iter()
                .position(|candidate| case.expected_providers.contains(&candidate.fqn))
                .map(|idx| idx + 1);
            let case_score = expected_rank.map(score_for_rank).unwrap_or_default();
            total_score += case_score;
            let expected_providers = case.expected_providers.join("|");
            let top1_match = case
                .expected_providers
                .iter()
                .any(|expected| expected == actual_provider);
            if top1_match {
                top1_matches += 1;
            }
            let top_candidates = response
                .candidates
                .iter()
                .take(3)
                .map(|candidate| format!("{}:{}", candidate.fqn, candidate.score))
                .collect::<Vec<_>>()
                .join(" ");

            report.push(csv_record(&[
                &case.id,
                &case.prompt,
                &expected_providers,
                &expected_rank
                    .map(|rank| rank.to_string())
                    .unwrap_or_else(|| "not_returned".to_string()),
                &format!("{case_score:.3}"),
                if top1_match { "true" } else { "false" },
                actual_provider,
                actual_endpoint,
                &actual_score.to_string(),
                &top_candidates,
            ]));
        }

        let benchmark_score = total_score / case_count;
        let top1_score = top1_matches as f64 * 100.0 / case_count;
        let report_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/pay-provider-routing-bench.csv");
        if let Some(parent) = report_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&report_path, report.join("\n")).unwrap();

        assert!(
            (benchmark_score - GLOBAL_CURRENT_BENCHMARK).abs() < BENCHMARK_EPSILON,
            "provider routing benchmark changed from {GLOBAL_CURRENT_BENCHMARK:.3} to {benchmark_score:.3}; top1 is {top1_score:.3}; report written to {}. Update GLOBAL_CURRENT_BENCHMARK manually after reviewing the CSV.",
            report_path.display(),
        );
        assert!(
            (top1_score - GLOBAL_CURRENT_TOP1_BENCHMARK).abs() < BENCHMARK_EPSILON,
            "provider routing top1 benchmark changed from {GLOBAL_CURRENT_TOP1_BENCHMARK:.3} to {top1_score:.3}; rank-weighted score is {benchmark_score:.3}; report written to {}. Update GLOBAL_CURRENT_TOP1_BENCHMARK manually after reviewing the CSV.",
            report_path.display(),
        );
    }

    fn score_for_rank(rank: usize) -> f64 {
        match rank {
            1 => 100.0,
            2 => 60.0,
            3 => 35.0,
            4 => 20.0,
            5 => 10.0,
            _ => 0.0,
        }
    }

    #[derive(Debug)]
    struct RoutingCase {
        id: String,
        prompt: String,
        expected_providers: Vec<String>,
        category: Option<String>,
    }

    fn parse_routing_cases(raw: &str) -> Vec<RoutingCase> {
        let mut lines = raw.lines().filter(|line| !line.trim().is_empty());
        let header = parse_csv_record(lines.next().expect("csv header"));
        let header_index: BTreeMap<_, _> = header
            .iter()
            .enumerate()
            .map(|(idx, name)| (name.as_str(), idx))
            .collect();

        lines
            .map(|line| {
                let fields = parse_csv_record(line);
                let get = |name: &str| {
                    fields
                        .get(*header_index.get(name).expect("known csv column"))
                        .cloned()
                        .unwrap_or_default()
                };
                let category = get("category");
                RoutingCase {
                    id: get("id"),
                    prompt: get("prompt"),
                    expected_providers: get("expected_providers")
                        .split('|')
                        .map(str::trim)
                        .filter(|provider| !provider.is_empty())
                        .map(ToString::to_string)
                        .collect(),
                    category: (!category.is_empty()).then_some(category),
                }
            })
            .collect()
    }

    fn parse_csv_record(line: &str) -> Vec<String> {
        let mut fields = Vec::new();
        let mut field = String::new();
        let mut chars = line.chars().peekable();
        let mut quoted = false;

        while let Some(ch) = chars.next() {
            match ch {
                '"' if quoted && chars.peek() == Some(&'"') => {
                    field.push('"');
                    chars.next();
                }
                '"' => quoted = !quoted,
                ',' if !quoted => {
                    fields.push(field);
                    field = String::new();
                }
                _ => field.push(ch),
            }
        }

        fields.push(field);
        fields
    }

    fn csv_record(fields: &[&str]) -> String {
        fields
            .iter()
            .map(|field| format!("\"{}\"", field.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn bench_catalog() -> pay_core::skills::Catalog {
        pay_core::skills::Catalog {
            schema_version: "1".to_string(),
            generated_at: "test".to_string(),
            base_url: String::new(),
            provider_count: 25,
            providers: vec![
                service(
                    "socialintel/influencer-search",
                    "Social Intel",
                    "Instagram influencer search by keyword category demographics location creator audience sponsored posts and brand partnership fit.",
                    "Use for Instagram influencer search creator discovery audience demographics sponsored post planning brand partnership prospecting and location based social media research.",
                    "data",
                    vec![endpoint(
                        "POST",
                        "api/influencers/search",
                        "influencers",
                        "Search Instagram influencers creators demographics audience location brand fit",
                        0.10,
                    )],
                ),
                service(
                    "merit-systems/stableenrich/enrichment",
                    "StableEnrich",
                    "Unified enrichment gateway for people company work email web search page scraping maps email verification local business and property data.",
                    "Use for contact enrichment work email lookup company lookup prospect search web search page scraping local business discovery email verification people search property records and place details.",
                    "data",
                    vec![
                        endpoint(
                            "POST",
                            "api/apollo/people-search",
                            "people",
                            "Search prospects people contacts by title company location seniority and industry",
                            0.02,
                        ),
                        endpoint(
                            "POST",
                            "api/apollo/people-enrich",
                            "people",
                            "Enrich person contact by email name domain title company LinkedIn and phone",
                            0.05,
                        ),
                        endpoint(
                            "POST",
                            "api/apollo/org-search",
                            "companies",
                            "Search companies organizations by domain industry location employee count and revenue",
                            0.02,
                        ),
                        endpoint(
                            "POST",
                            "api/apollo/org-enrich",
                            "companies",
                            "Enrich company organization by domain firmographics website industry employees and revenue",
                            0.05,
                        ),
                        endpoint(
                            "POST",
                            "api/exa/search",
                            "web",
                            "Search the web with neural results URLs snippets and relevant pages",
                            0.01,
                        ),
                        endpoint(
                            "POST",
                            "api/exa/answer",
                            "web",
                            "Answer research question from web sources with citations and supporting search results",
                            0.01,
                        ),
                        endpoint(
                            "POST",
                            "api/firecrawl/scrape",
                            "scrape",
                            "Scrape a URL with JavaScript rendering and return clean page content markdown or HTML",
                            0.013,
                        ),
                        endpoint(
                            "POST",
                            "api/firecrawl/search",
                            "scrape",
                            "Search the web and scrape page content for each result",
                            0.025,
                        ),
                        endpoint(
                            "POST",
                            "api/google-maps/text-search/full",
                            "maps",
                            "Search local businesses places restaurants stores by text query ratings hours phone and website",
                            0.08,
                        ),
                        endpoint(
                            "GET",
                            "api/google-maps/place-details/full",
                            "maps",
                            "Get place business details ratings reviews hours contact website and address",
                            0.08,
                        ),
                        endpoint(
                            "POST",
                            "api/hunter/email-verifier",
                            "email",
                            "Verify email deliverability validity status MX and confidence",
                            0.01,
                        ),
                        endpoint(
                            "POST",
                            "api/property/search",
                            "property",
                            "Search property records ownership parcels real estate address and assessor data",
                            0.12,
                        ),
                    ],
                ),
                service(
                    "minerva/identity",
                    "Minerva",
                    "Resolve identities search people enrich contacts validate emails LinkedIn profiles demographics work history education and confidence scores.",
                    "Use for person identity resolution LinkedIn profile matching contact enrichment demographics work history education lookup financial signals people search CRM enrichment email validation and confidence scored identity matching.",
                    "data",
                    vec![
                        endpoint(
                            "POST",
                            "api/minerva/resolve",
                            "identity",
                            "Resolve person identity from name company email to Minerva PID and LinkedIn profile",
                            0.02,
                        ),
                        endpoint(
                            "POST",
                            "api/minerva/enrich",
                            "identity",
                            "Enrich person identity demographics work history education contact info addresses and financial signals",
                            0.05,
                        ),
                        endpoint(
                            "POST",
                            "api/minerva/validate-emails",
                            "identity",
                            "Validate email addresses against identity database match status and last seen timestamps",
                            0.01,
                        ),
                        endpoint(
                            "POST",
                            "api/minerva/person-search",
                            "identity",
                            "Search people using natural language queries and return identifiers and contact channel coverage",
                            0.04,
                        ),
                    ],
                ),
                service(
                    "perplexity/sonar",
                    "Perplexity Sonar",
                    "Real time web grounded answers with citations sources inline references current information beyond training data research synthesis and fact checking support.",
                    "Use for up to date sourced answers current web events inline references fact checking research questions market company research news aware responses and citation backed claims beyond model training data.",
                    "ai_ml",
                    vec![
                        endpoint(
                            "POST",
                            "search",
                            "search",
                            "Search web using Perplexity Sonar and return grounded answers citations and source URLs",
                            0.01,
                        ),
                        endpoint(
                            "POST",
                            "v1/sonar",
                            "chat",
                            "Create synchronous Sonar chat completion with web grounded answer citations",
                            0.10,
                        ),
                    ],
                ),
                service(
                    "quicknode/rpc",
                    "QuickNode",
                    "Pay per request JSON RPC access to blockchain networks including Solana slots blocks accounts transactions and submission.",
                    "Use for raw blockchain RPC methods Solana getSlot account reads block data transaction submission simulation and chain access.",
                    "compute",
                    vec![endpoint(
                        "POST",
                        "rpc",
                        "rpc",
                        "Call raw blockchain JSON RPC methods including Solana getSlot getAccountInfo sendTransaction",
                        0.01,
                    )],
                ),
                service(
                    "allium/blockchain-analytics",
                    "Allium",
                    "Blockchain analytics token prices wallet balances transactions token holders transfers and on chain history across chains.",
                    "Use for wallet balances token prices transaction history token holder analytics address activity portfolio and on chain analytics.",
                    "finance",
                    vec![
                        endpoint(
                            "POST",
                            "api/balances",
                            "balances",
                            "Get wallet token balances portfolio holdings and assets",
                            0.01,
                        ),
                        endpoint(
                            "POST",
                            "api/transactions",
                            "transactions",
                            "Get wallet transaction history transfers swaps and on chain activity",
                            0.01,
                        ),
                        endpoint(
                            "POST",
                            "api/token-prices",
                            "prices",
                            "Get token price history current prices OHLC and market data",
                            0.01,
                        ),
                        endpoint(
                            "POST",
                            "api/token-holders",
                            "holders",
                            "Get token holders ownership distribution and holder analytics",
                            0.01,
                        ),
                    ],
                ),
                service(
                    "merit-systems/stablecrypto/market-data",
                    "StableCrypto",
                    "Crypto market data via CoinGecko DefiLlama Alchemy and Etherscan including prices TVL gas NFTs and protocol data.",
                    "Use for crypto market prices DeFi TVL protocol metrics gas fees NFT metadata token markets and CoinGecko DefiLlama data.",
                    "finance",
                    vec![
                        endpoint(
                            "GET",
                            "api/coingecko/price",
                            "prices",
                            "Get current crypto token price market cap and volume from CoinGecko",
                            0.01,
                        ),
                        endpoint(
                            "GET",
                            "api/coingecko/markets",
                            "markets",
                            "Get crypto market rankings prices volume and market data",
                            0.01,
                        ),
                        endpoint(
                            "GET",
                            "api/defillama/tvl",
                            "defi",
                            "Get DeFi protocol TVL chain TVL and yield metrics from DefiLlama",
                            0.01,
                        ),
                        endpoint(
                            "GET",
                            "api/etherscan/gas",
                            "gas",
                            "Get EVM gas prices and fee estimates",
                            0.01,
                        ),
                        endpoint(
                            "GET",
                            "api/alchemy/nfts",
                            "nfts",
                            "Get NFT metadata collections owners and floor data",
                            0.01,
                        ),
                    ],
                ),
                service(
                    "merit-systems/stablestudio/media-generation",
                    "StableStudio",
                    "AI image and video generation with Sora Veo Grok Flux avatars thumbnails and creative media outputs.",
                    "Use for AI image generation video generation thumbnails avatars product mockups creative visuals and media generation.",
                    "media",
                    vec![
                        endpoint(
                            "POST",
                            "api/images/generate",
                            "images",
                            "Generate AI images illustrations avatars thumbnails and product mockups",
                            0.01,
                        ),
                        endpoint(
                            "POST",
                            "api/video/generate",
                            "video",
                            "Generate AI video clips animations scenes and short video assets",
                            0.01,
                        ),
                    ],
                ),
                service(
                    "merit-systems/stablesocial/social-data",
                    "StableSocial",
                    "Social media data from TikTok Instagram Facebook Reddit profiles posts comments videos and engagement metrics.",
                    "Use for TikTok data Reddit search Instagram profile lookup Facebook pages social media posts comments metrics and public social research.",
                    "media",
                    vec![
                        endpoint(
                            "POST",
                            "api/tiktok/search",
                            "tiktok",
                            "Search TikTok videos creators hashtags engagement and social metrics",
                            0.06,
                        ),
                        endpoint(
                            "POST",
                            "api/reddit/search",
                            "reddit",
                            "Search Reddit posts comments communities and discussion data",
                            0.06,
                        ),
                        endpoint(
                            "POST",
                            "api/instagram/profile",
                            "instagram",
                            "Lookup Instagram public profile posts followers engagement and bio",
                            0.06,
                        ),
                        endpoint(
                            "POST",
                            "api/facebook/page",
                            "facebook",
                            "Lookup Facebook page posts engagement and public profile data",
                            0.06,
                        ),
                    ],
                ),
                service(
                    "solana-foundation/google/bigquery",
                    "BigQuery API",
                    "SQL warehouse public datasets analytics cryptocurrency usage weather patents GitHub Stack Overflow SEC and large data queries.",
                    "Use for SQL queries public datasets analytics market research accurate data facts warehouse tables and BigQuery jobs.",
                    "data",
                    vec![
                        endpoint(
                            "POST",
                            "v2/projects/{projectsId}/queries",
                            "queries",
                            "Run SQL query over BigQuery public datasets warehouse tables and analytics data",
                            0.005,
                        ),
                        endpoint(
                            "GET",
                            "v2/projects/{projectsId}/datasets",
                            "datasets",
                            "List BigQuery datasets tables schemas and metadata",
                            0.0,
                        ),
                    ],
                ),
                service(
                    "solana-foundation/google/vision",
                    "Cloud Vision API",
                    "Analyze images OCR objects faces text labels landmarks logos explicit content and web entities.",
                    "Use for image analysis OCR object detection face detection label detection logo detection landmark recognition and content moderation.",
                    "ai_ml",
                    vec![endpoint(
                        "POST",
                        "v1/images:annotate",
                        "images",
                        "Annotate images with OCR text objects labels faces logos landmarks and moderation",
                        0.001,
                    )],
                ),
                service(
                    "solana-foundation/google/documentai",
                    "Cloud Document AI API",
                    "Extract structured data from PDFs scanned documents invoices receipts contracts forms tax docs and IDs using OCR and ML.",
                    "Use for document OCR invoice extraction receipt parsing contract analysis form processing PDF extraction and structured document fields.",
                    "ai_ml",
                    vec![endpoint(
                        "POST",
                        "v1/projects/{projectsId}/locations/{locationsId}/processors/{processorsId}:process",
                        "documents",
                        "Process document PDF scan invoice receipt contract form with OCR and structured fields",
                        0.6,
                    )],
                ),
                service(
                    "solana-foundation/google/language",
                    "Cloud Natural Language API",
                    "Analyze text entities sentiment syntax content classification categories and language text analytics.",
                    "Use for sentiment analysis named entity recognition content classification text analytics opinion mining and syntax parsing.",
                    "ai_ml",
                    vec![
                        endpoint(
                            "POST",
                            "v1/documents:analyzeSentiment",
                            "sentiment",
                            "Analyze text sentiment emotion polarity and opinion",
                            0.002,
                        ),
                        endpoint(
                            "POST",
                            "v1/documents:analyzeEntities",
                            "entities",
                            "Extract named entities people organizations locations dates and metadata",
                            0.002,
                        ),
                        endpoint(
                            "POST",
                            "v1/documents:classifyText",
                            "classification",
                            "Classify text content into categories taxonomy and topics",
                            0.002,
                        ),
                    ],
                ),
                service(
                    "solana-foundation/google/translate",
                    "Cloud Translation API",
                    "Translate text and documents detect language romanization glossaries adaptive translation and localization.",
                    "Use for translating text language detection multilingual content localization document translation and cross language communication.",
                    "ai_ml",
                    vec![
                        endpoint(
                            "POST",
                            "v3/projects/{project}:translateText",
                            "translate",
                            "Translate text between languages with glossary and localization support",
                            0.02,
                        ),
                        endpoint(
                            "POST",
                            "v3/projects/{project}:detectLanguage",
                            "detect",
                            "Detect language of text and return confidence",
                            0.0,
                        ),
                        endpoint(
                            "POST",
                            "v3/projects/{project}:translateDocument",
                            "documents",
                            "Translate document files PDFs and formatted content",
                            0.08,
                        ),
                    ],
                ),
                service(
                    "solana-foundation/google/speech",
                    "Cloud Speech-to-Text API",
                    "Convert audio to text speech recognition transcription diarization timestamps automatic punctuation and streaming.",
                    "Use for transcribing audio speech to text meeting transcription podcast transcription voice commands and accessibility.",
                    "ai_ml",
                    vec![
                        endpoint(
                            "POST",
                            "v1/speech:recognize",
                            "speech",
                            "Transcribe short audio speech to text with punctuation timestamps and language support",
                            0.004,
                        ),
                        endpoint(
                            "POST",
                            "v1/speech:longrunningrecognize",
                            "speech",
                            "Transcribe long audio files asynchronously with speaker diarization and timestamps",
                            0.016,
                        ),
                    ],
                ),
                service(
                    "solana-foundation/google/texttospeech",
                    "Cloud Text-to-Speech API",
                    "Convert text to natural sounding speech voices SSML MP3 WAV OGG narration accessibility and IVR.",
                    "Use for text to speech voiceover narration audio generation accessibility IVR pronunciation and audiobook audio.",
                    "ai_ml",
                    vec![endpoint(
                        "POST",
                        "v1/text:synthesize",
                        "tts",
                        "Synthesize speech audio from text SSML voice pitch speed MP3 WAV OGG",
                        0.004,
                    )],
                ),
                service(
                    "solana-foundation/google/places",
                    "Places API",
                    "Search places businesses restaurants hotels POIs details hours ratings reviews photos contact info and nearby locations.",
                    "Use for finding restaurants businesses hotels points of interest reviews ratings address autocomplete nearby search and place details.",
                    "maps",
                    vec![
                        endpoint(
                            "POST",
                            "v1/places:searchText",
                            "places",
                            "Search places businesses restaurants hotels stores and POIs by text query",
                            0.001,
                        ),
                        endpoint(
                            "POST",
                            "v1/places:searchNearby",
                            "places",
                            "Search nearby places businesses restaurants and points of interest by location",
                            0.001,
                        ),
                        endpoint(
                            "GET",
                            "v1/places/{placesId}",
                            "places",
                            "Get place details hours ratings reviews photos phone website and address",
                            0.001,
                        ),
                    ],
                ),
                service(
                    "solana-foundation/google/addressvalidation",
                    "Address Validation API",
                    "Validate postal addresses standardize deliverability geocode coordinates USPS verdict and address components.",
                    "Use for verifying shipping addresses geocoding address autocomplete deliverability postal code validation and standardization.",
                    "maps",
                    vec![endpoint(
                        "POST",
                        "v1:validateAddress",
                        "address",
                        "Validate standardize and geocode postal address deliverability USPS and components",
                        0.001,
                    )],
                ),
                service(
                    "solana-foundation/google/factchecktools",
                    "Fact Check Tools API",
                    "Search fact check articles ClaimReview database claims ratings publisher review URLs misinformation and verification.",
                    "Use for verifying claims debunking misinformation checking fact checked statements media literacy and claim ratings.",
                    "search",
                    vec![endpoint(
                        "GET",
                        "v1alpha1/claims:search",
                        "claims",
                        "Search fact check claims articles ratings publishers and review URLs",
                        0.0,
                    )],
                ),
                service(
                    "agentmail/email",
                    "AgentMail",
                    "Agentic email create inboxes send receive messages and manage AI agent mailboxes.",
                    "Use for creating inboxes sending email receiving email agent mailboxes and email automation.",
                    "messaging",
                    vec![
                        endpoint(
                            "POST",
                            "v1/inboxes",
                            "inboxes",
                            "Create email inbox mailbox address for an agent",
                            0.0,
                        ),
                        endpoint(
                            "POST",
                            "v1/messages:send",
                            "messages",
                            "Send email message from an agent inbox",
                            0.0,
                        ),
                        endpoint(
                            "GET",
                            "v1/messages",
                            "messages",
                            "List and read received email messages",
                            0.0,
                        ),
                    ],
                ),
                service(
                    "merit-systems/stablephone/calls",
                    "StablePhone",
                    "AI phone calls voice calls outbound calls status transcripts and phone automation.",
                    "Use for AI phone calls outbound calls voice agents call status transcripts phone outreach and telephony workflows.",
                    "messaging",
                    vec![
                        endpoint(
                            "POST",
                            "api/calls/create",
                            "calls",
                            "Create outbound AI phone call voice agent and call target",
                            0.05,
                        ),
                        endpoint(
                            "GET",
                            "api/calls/status",
                            "calls",
                            "Get phone call status transcript recording and result",
                            0.01,
                        ),
                    ],
                ),
                service(
                    "merit-systems/stableupload/hosting",
                    "StableUpload",
                    "File hosting uploads permanent CDN URLs static site hosting and shareable hosted assets.",
                    "Use for uploading files hosting static sites creating CDN URLs sharing assets and publishing generated files.",
                    "storage",
                    vec![
                        endpoint(
                            "POST",
                            "api/upload/file",
                            "files",
                            "Upload file and return permanent CDN URL",
                            0.02,
                        ),
                        endpoint(
                            "POST",
                            "api/upload/site",
                            "sites",
                            "Upload static website directory and return hosted site URL",
                            0.02,
                        ),
                    ],
                ),
                service(
                    "x402scan/search",
                    "x402scan",
                    "Full text search and registry of indexed x402 payment endpoints APIs resources and payment services.",
                    "Use for finding x402 payment endpoints searching the x402 registry discovering paid APIs and inspecting x402 services.",
                    "search",
                    vec![endpoint(
                        "POST",
                        "search",
                        "search",
                        "Search indexed x402 payment endpoints registry services and resources",
                        0.02,
                    )],
                ),
                service(
                    "crushrewards/pricing",
                    "Crush Rewards",
                    "Competitive pricing data across Amazon Walmart Best Buy Target deals product prices and shopper offers.",
                    "Use for comparing product prices finding deals marketplace pricing competitive shopping and retail price research.",
                    "data",
                    vec![
                        endpoint(
                            "POST",
                            "api/prices/compare",
                            "pricing",
                            "Compare product prices across Amazon Walmart Best Buy Target and retailers",
                            0.02,
                        ),
                        endpoint(
                            "GET",
                            "api/deals/search",
                            "deals",
                            "Search retail deals discounts offers and shopper rewards",
                            0.01,
                        ),
                    ],
                ),
                service(
                    "purch/marketplace",
                    "Purch",
                    "Search and buy products from Amazon Shopify ecommerce marketplace products carts and purchases.",
                    "Use for product search buying products shopping ecommerce marketplace checkout Amazon Shopify and purchase workflows.",
                    "productivity",
                    vec![endpoint(
                        "POST",
                        "api/products/search",
                        "products",
                        "Search products from Amazon Shopify ecommerce marketplace listings",
                        0.01,
                    )],
                ),
            ],
        }
    }

    fn service(
        fqn: &str,
        title: &str,
        description: &str,
        use_case: &str,
        category: &str,
        endpoints: Vec<pay_core::skills::Endpoint>,
    ) -> pay_core::skills::Service {
        let mut prices = endpoints
            .iter()
            .filter_map(|ep| pay_core::skills::price_range_usd(&ep.pricing))
            .flat_map(|(min, max)| [min, max])
            .collect::<Vec<_>>();
        prices.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let has_metering = endpoints.iter().any(|ep| ep.pricing.is_some());
        pay_core::skills::Service {
            fqn: fqn.to_string(),
            meta: pay_types::registry::ServiceMeta {
                title: title.to_string(),
                description: description.to_string(),
                use_case: Some(use_case.to_string()),
                category: category.to_string(),
                service_url: format!("https://{}.example.com", fqn.replace('/', "-")),
                sandbox_service_url: None,
            },
            endpoint_count: endpoints.len() as u32,
            has_metering,
            has_free_tier: endpoints.iter().any(|ep| ep.pricing.is_none()),
            min_price_usd: prices.first().copied().unwrap_or(0.0),
            max_price_usd: prices.last().copied().unwrap_or(0.0),
            sha: String::new(),
            endpoints,
            content: None,
        }
    }

    fn endpoint(
        method: &str,
        path: &str,
        resource: &str,
        description: &str,
        price_usd: f64,
    ) -> pay_core::skills::Endpoint {
        pay_core::skills::Endpoint {
            method: method.to_string(),
            path: path.to_string(),
            full_path: String::new(),
            resource: Some(resource.to_string()),
            description: description.to_string(),
            pricing: (price_usd > 0.0).then(|| {
                serde_json::json!({
                    "dimensions": [{ "tiers": [{ "price_usd": price_usd }] }]
                })
            }),
        }
    }
}
