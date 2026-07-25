use rmcp::model::CallToolResult;
use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Params {
    /// Optional original user question. For "what can I do with Pay?" call this tool and summarize the returned categories.
    #[schemars(
        description = "Optional original user question. For \"what can I do with Pay?\" or \"what Pay APIs are available?\", call this tool with the question and summarize the returned categories."
    )]
    #[serde(default)]
    pub question: Option<String>,
    /// Force-refresh the catalog from all sources before listing.
    #[schemars(
        description = "Usually false. Set true only to force-refresh the catalog from CDN before listing."
    )]
    #[serde(default)]
    pub refresh: bool,
    /// Bypass CDN cache by appending a cache-buster query parameter.
    #[schemars(
        description = "Usually false. Set true only to bypass CDN edge cache when a fresh catalog is required."
    )]
    #[serde(default)]
    pub cache_bust: bool,
    /// Include expanded service metadata outside the category grouping.
    #[schemars(
        description = "Usually false. Set true only when the user asks for the complete raw service list with full use-case metadata."
    )]
    #[serde(default)]
    pub include_details: bool,
}

/// Lightweight entry returned to the LLM for catalog selection.
#[derive(Clone, Debug, Serialize)]
struct CatalogServiceEntry {
    fqn: String,
    title: String,
    description: String,
    category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    use_case: Option<String>,
    endpoint_count: u32,
    has_metering: bool,
}

#[derive(Debug, Serialize)]
struct CategoryProviderEntry {
    fqn: String,
    title: String,
    endpoint_count: u32,
    has_metering: bool,
}

#[derive(Debug, Serialize)]
struct CategoryEntry {
    category: String,
    service_count: usize,
    endpoint_count: u32,
    services: Vec<CategoryProviderEntry>,
}

#[derive(Debug, Serialize)]
struct ListCatalogResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    question: Option<String>,
    display_guidance: &'static str,
    provider_count: usize,
    categories: Vec<CategoryEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    services: Option<Vec<CatalogServiceEntry>>,
    next_step: &'static str,
}

pub async fn run(params: Params) -> Result<CallToolResult, rmcp::ErrorData> {
    let cache_bust = params.cache_bust;
    let catalog_result = if params.refresh || cache_bust {
        pay_core::skills::update_skills_for(cache_bust, pay_core::ClientApp::Mcp)
            .await
            .map_err(|e| format!("Failed to refresh Pay catalog: {e}"))
    } else {
        match pay_core::skills::load_cached_skills() {
            Ok(catalog) => Ok(catalog),
            Err(_) => pay_core::skills::load_skills_for(pay_core::ClientApp::Mcp)
                .await
                .map_err(|e| format!("Failed to load Pay catalog: {e}")),
        }
    };
    let catalog = match catalog_result {
        Ok(catalog) => catalog,
        Err(message) => return Ok(super::tool_error(message)),
    };

    let entries: Vec<CatalogServiceEntry> = catalog
        .providers
        .iter()
        .map(|svc| CatalogServiceEntry {
            fqn: svc.fqn.clone(),
            title: service_title(svc),
            description: svc.meta.description.clone(),
            category: svc.meta.category.clone(),
            use_case: svc.meta.use_case.clone(),
            endpoint_count: svc.endpoint_count,
            has_metering: svc.has_metering,
        })
        .collect();
    let response = build_response(params.question, params.include_details, entries);

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

fn build_response(
    question: Option<String>,
    include_details: bool,
    mut services: Vec<CatalogServiceEntry>,
) -> ListCatalogResponse {
    services.sort_by(|a, b| a.category.cmp(&b.category).then_with(|| a.fqn.cmp(&b.fqn)));

    let mut grouped: BTreeMap<String, CategoryEntry> = BTreeMap::new();
    for service in &services {
        let entry = grouped
            .entry(service.category.clone())
            .or_insert_with(|| CategoryEntry {
                category: service.category.clone(),
                service_count: 0,
                endpoint_count: 0,
                services: Vec::new(),
            });
        entry.service_count += 1;
        entry.endpoint_count += service.endpoint_count;
        entry.services.push(CategoryProviderEntry {
            fqn: service.fqn.clone(),
            title: service.title.clone(),
            endpoint_count: service.endpoint_count,
            has_metering: service.has_metering,
        });
    }

    let provider_count = services.len();
    ListCatalogResponse {
        question,
        display_guidance: "For 'what can I do with Pay?' answers, summarize Pay APIs/skills by category first, then mention representative services. Do not answer from memory. This response is compact by default to keep MCP hosts responsive.",
        provider_count,
        categories: grouped.into_values().collect(),
        services: include_details.then_some(services),
        next_step: "For an actionable task, call search_catalog with the user's real task. For a capability yes/no answer, answer from this full catalog.",
    }
}

fn service_title(service: &pay_core::skills::Service) -> String {
    if service.meta.title.trim().is_empty() {
        service.name().to_string()
    } else {
        service.meta.title.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_default_no_refresh() {
        let json = r#"{}"#;
        let params: Params = serde_json::from_str(json).unwrap();
        assert!(params.question.is_none());
        assert!(!params.refresh);
        assert!(!params.include_details);
    }

    #[test]
    fn params_with_refresh() {
        let json = r#"{"refresh": true}"#;
        let params: Params = serde_json::from_str(json).unwrap();
        assert!(params.refresh);
    }

    #[test]
    fn params_accept_question_for_capability_prompt() {
        let json = r#"{"question":"what can i do with pay?"}"#;
        let params: Params = serde_json::from_str(json).unwrap();

        assert_eq!(params.question.as_deref(), Some("what can i do with pay?"));
    }

    #[test]
    fn response_groups_services_by_category() {
        let response = build_response(
            Some("what can i do with pay?".to_string()),
            false,
            vec![
                CatalogServiceEntry {
                    fqn: "b/two".to_string(),
                    title: "Two".to_string(),
                    description: "Second".to_string(),
                    category: "data".to_string(),
                    use_case: None,
                    endpoint_count: 3,
                    has_metering: true,
                },
                CatalogServiceEntry {
                    fqn: "a/one".to_string(),
                    title: "One".to_string(),
                    description: "First".to_string(),
                    category: "media".to_string(),
                    use_case: None,
                    endpoint_count: 2,
                    has_metering: true,
                },
                CatalogServiceEntry {
                    fqn: "a/zero".to_string(),
                    title: "Zero".to_string(),
                    description: "Zero".to_string(),
                    category: "data".to_string(),
                    use_case: None,
                    endpoint_count: 1,
                    has_metering: false,
                },
            ],
        );

        assert_eq!(response.categories.len(), 2);
        assert_eq!(response.categories[0].category, "data");
        assert_eq!(response.categories[0].service_count, 2);
        assert_eq!(response.categories[0].endpoint_count, 4);
        assert_eq!(response.provider_count, 3);
        assert_eq!(response.categories[0].services[0].fqn, "a/zero");
        assert!(response.services.is_none());
        assert!(response.display_guidance.contains("summarize"));
    }

    #[test]
    fn response_can_include_expanded_services() {
        let response = build_response(
            None,
            true,
            vec![CatalogServiceEntry {
                fqn: "purch/marketplace".to_string(),
                title: "Purch".to_string(),
                description: "Search and buy products from Amazon and Shopify with USDC."
                    .to_string(),
                category: "productivity".to_string(),
                use_case: Some("Use for product search and shopping.".to_string()),
                endpoint_count: 6,
                has_metering: true,
            }],
        );

        let services = response.services.expect("expanded services");
        assert_eq!(response.provider_count, 1);
        assert_eq!(services[0].fqn, "purch/marketplace");
        assert_eq!(
            services[0].use_case.as_deref(),
            Some("Use for product search and shopping.")
        );
    }
}
