use rmcp::model::CallToolResult;
use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Params {
    #[schemars(
        description = "Fully qualified name returned by search_catalog or list_catalog (e.g. 'solana-foundation/google/bigquery')"
    )]
    pub fqn: String,
}

/// Full catalog entry detail returned to the LLM after selection.
#[derive(Debug, Serialize)]
struct CatalogEntryDetail {
    fqn: String,
    title: String,
    description: String,
    service_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_service_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    use_case: Option<String>,
    /// Usage notes from the detail file (markdown body of the .md file).
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    endpoints: Vec<EndpointEntry>,
    next_step: String,
}

#[derive(Debug, Serialize)]
struct EndpointEntry {
    method: String,
    path: String,
    url: String,
    description: String,
    metered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_price_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_price_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pricing: Option<serde_json::Value>,
}

pub async fn run(params: Params) -> Result<CallToolResult, rmcp::ErrorData> {
    let fqn = params.fqn.clone();
    let mut catalog = match pay_core::skills::load_skills_for(pay_core::ClientApp::Mcp).await {
        Ok(catalog) => catalog,
        Err(err) => {
            return Ok(super::tool_error(format!(
                "Failed to load Pay catalog: {err}"
            )));
        }
    };
    if let Err(err) =
        pay_core::skills::ensure_endpoints_for(&mut catalog, &fqn, pay_core::ClientApp::Mcp).await
    {
        return Ok(super::tool_error(format!(
            "Failed to load catalog entry `{fqn}`: {err}"
        )));
    }

    let svc = catalog
        .providers
        .iter()
        .find(|s| s.fqn.eq_ignore_ascii_case(&fqn) || s.name().eq_ignore_ascii_case(&fqn))
        .ok_or_else(|| format!("Service `{fqn}` not found"));
    let svc = match svc {
        Ok(svc) => svc,
        Err(message) => return Ok(super::tool_error(message)),
    };

    let content = svc.content.clone();

    let base_url = &svc.meta.service_url;
    let detail = CatalogEntryDetail {
        fqn: svc.fqn.clone(),
        title: svc.meta.title.clone(),
        description: svc.meta.description.clone(),
        service_url: svc.meta.service_url.clone(),
        sandbox_service_url: svc.meta.sandbox_service_url.clone(),
        use_case: svc.meta.use_case.clone(),
        content,
        endpoints: svc
            .endpoints
            .iter()
            .map(|ep| endpoint_entry_for(base_url, ep))
            .collect(),
        next_step: "Select the endpoint that directly matches the task. Copy its exact `url` into the Pay `curl` tool, make the smallest useful request, and ask before multi-call exploration or unclear pricing.".to_string(),
    };

    let json = match serde_json::to_string_pretty(&detail) {
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

fn endpoint_entry_for(base_url: &str, ep: &pay_core::skills::Endpoint) -> EndpointEntry {
    let (min_price_usd, max_price_usd) = pay_core::skills::price_range_usd(&ep.pricing).unzip();
    EndpointEntry {
        method: ep.method.clone(),
        path: ep.path.clone(),
        url: pay_core::skills::build_endpoint_url(base_url, &ep.path),
        description: ep.description.clone(),
        metered: ep.pricing.is_some(),
        min_price_usd,
        max_price_usd,
        pricing: ep.pricing.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_deserialize() {
        let json = r#"{"fqn": "solana-foundation/google/bigquery"}"#;
        let params: Params = serde_json::from_str(json).unwrap();
        assert_eq!(params.fqn, "solana-foundation/google/bigquery");
    }

    #[test]
    fn params_requires_fqn() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<Params>(json);
        assert!(result.is_err());
    }

    #[test]
    fn endpoint_entry_includes_exact_url_and_price_range() {
        let endpoint = pay_core::skills::Endpoint {
            method: "POST".to_string(),
            path: "v1/search".to_string(),
            full_path: String::new(),
            description: "Search records by keyword with pagination".to_string(),
            resource: Some("search".to_string()),
            pricing: Some(serde_json::json!({
                "dimensions": [
                    {
                        "unit": "requests",
                        "scale": 1,
                        "tiers": [
                            { "price_usd": 0.01 },
                            { "price_usd": 0.04 }
                        ]
                    }
                ]
            })),
        };

        let entry = endpoint_entry_for("https://gateway.example.com/", &endpoint);

        assert_eq!(entry.url, "https://gateway.example.com/v1/search");
        assert!(entry.metered);
        assert_eq!(entry.min_price_usd, Some(0.01));
        assert_eq!(entry.max_price_usd, Some(0.04));
        assert!(entry.pricing.is_some());
    }

    #[test]
    fn catalog_entry_detail_serializes_next_step_guidance() {
        let detail = CatalogEntryDetail {
            fqn: "example/search".to_string(),
            title: "Example Search".to_string(),
            description: "Search example data".to_string(),
            service_url: "https://gateway.example.com".to_string(),
            sandbox_service_url: None,
            use_case: None,
            content: None,
            endpoints: Vec::new(),
            next_step: "Select the endpoint that directly matches the task. Copy its exact `url` into the Pay `curl` tool.".to_string(),
        };

        let json = serde_json::to_value(detail).unwrap();
        assert!(json["next_step"].as_str().unwrap().contains("exact `url`"));
    }
}
