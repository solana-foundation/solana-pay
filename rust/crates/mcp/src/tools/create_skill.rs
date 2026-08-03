use rmcp::model::CallToolResult;
use rmcp::schemars;
use schemars::JsonSchema;
use serde::Deserialize;
use std::path::{Component, Path};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Params {
    /// The full `.md` file content (YAML frontmatter + markdown body).
    #[schemars(
        description = "Full .md file content with YAML frontmatter between --- delimiters, followed by markdown body"
    )]
    pub content: String,

    /// Optional path to write the validated file to disk.
    #[schemars(
        description = "Optional: pay-skills provider path to write after validation. Use providers/<operator>/<name>.md for native APIs or providers/<operator>/<origin>/<name>.md for proxied APIs; filename must match the frontmatter name."
    )]
    pub output_path: Option<String>,
}

#[derive(Debug)]
pub struct ValidatedProvider {
    pub spec: pay_types::registry::ProviderFrontmatter,
}

pub async fn run(params: Params) -> Result<CallToolResult, rmcp::ErrorData> {
    let content = params.content.clone();
    let output_path = params.output_path.clone();

    let result = tokio::task::spawn_blocking(move || validate(&content))
        .await
        .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;

    match result {
        Ok(validated) => {
            let spec_json = serde_json::to_string_pretty(&validated.spec).unwrap_or_default();
            let (metered, free) = endpoint_counts(&validated.spec);
            let mut is_error = false;
            let mut response = format!(
                "Provider spec is valid.\n\n\
                 - endpoints: {} total ({metered} metered, {free} free)\n\
                 - category: {}\n\
                 - service_url: {}\n\n\
                 ```json\n{spec_json}\n```\n",
                validated.spec.endpoints.len(),
                validated.spec.meta.category,
                validated.spec.meta.service_url,
            );

            if let Some(path) = output_path.as_deref() {
                let path_errors = validate_output_path(path, &validated.spec.name);
                if !path_errors.is_empty() {
                    is_error = true;
                    response.push_str("\n## Output path needs attention\n\n");
                    response.push_str("The provider content was valid, but I did not write it because the requested path is not contributor-ready:\n\n");
                    for err in &path_errors {
                        response.push_str(&format!("- {err}\n"));
                    }
                    response.push_str(&format!(
                        "\nUse one of:\n\n```text\n{}\n```\n",
                        recommended_paths(&validated.spec.name)
                    ));
                } else {
                    match std::fs::create_dir_all(
                        std::path::Path::new(path)
                            .parent()
                            .unwrap_or(std::path::Path::new(".")),
                    )
                    .and_then(|_| std::fs::write(path, &params.content))
                    {
                        Ok(_) => {
                            response.push_str(&format!("\nWrote to: {path}\n"));
                            response.push_str(&format!(
                            "\n## Validate before PR\n\n\
                             ```bash\n\
                             pay skills build . --output /tmp/pay-skills-dist\n\
                             pay skills probe . --files {path} --currencies USDC,USDT --timeout 15 --concurrency 5\n\
                             ```\n"
                        ));
                        }
                        Err(e) => {
                            is_error = true;
                            response.push_str(&format!("\nFailed to write to {path}: {e}\n"));
                        }
                    }
                }
            } else {
                response.push_str(&format!(
                    "\n## Next steps\n\n\
                     1. Fork https://github.com/solana-foundation/pay-skills\n\
                     2. Add this file at one of:\n\n\
                     ```text\n{}\n```\n\n\
                     3. Run:\n\n\
                     ```bash\n\
                     pay skills build . --output /tmp/pay-skills-dist\n\
                     pay skills probe . --files providers/<operator>/{}.md --currencies USDC,USDT --timeout 15 --concurrency 5\n\
                     ```\n\n\
                     4. Open a PR. CI will validate the YAML and probe changed paid endpoints.\n",
                    recommended_paths(&validated.spec.name),
                    validated.spec.name
                ));
            }

            if is_error {
                Ok(super::tool_error(response))
            } else {
                Ok(CallToolResult::success(vec![
                    rmcp::model::ContentBlock::text(response),
                ]))
            }
        }
        Err(errors) => {
            let mut response = format!("Validation failed with {} error(s):\n\n", errors.len());
            for err in &errors {
                response.push_str(&format!("- {err}\n"));
            }
            response.push_str(
                "\n## Common fixes\n\n\
                 - Add `use_case` with 32-255 characters; start with `Use for` or `Use when` and list concrete agent trigger tasks.\n\
                 - Keep provider `description` between 64 and 255 characters; summarize capabilities and result shapes, not use cases.\n\
                 - Keep endpoint `description` between 32 and 255 characters.\n\
                 - Use a valid category from the schema.\n\
                 - Use an HTTPS `service_url` with a domain name, not localhost or an IP address.\n\
                 - Omit `pricing` for free endpoints; if `pricing` is present the endpoint must return HTTP 402.\n\
                 - For non-zero prices, make sure `price_usd / scale >= 0.000001`.\n",
            );
            let schema_json = pay_types::registry::provider_json_schema();
            response.push_str(&format!(
                "\n## JSON Schema for provider frontmatter\n\n```json\n{schema_json}\n```\n"
            ));

            Ok(super::tool_error(response))
        }
    }
}

pub fn validate(content: &str) -> Result<ValidatedProvider, Vec<String>> {
    let mut errors = Vec::new();

    let (yaml_str, _body) = match pay_core::skills::build::parse_frontmatter(content) {
        Ok(v) => v,
        Err(e) => {
            errors.push(format!("frontmatter parse error: {e}"));
            return Err(errors);
        }
    };

    if yaml_str.is_empty() {
        errors.push("no YAML frontmatter found — file must start with ---".to_string());
        return Err(errors);
    }

    let spec: pay_types::registry::ProviderFrontmatter = match serde_yml::from_str(&yaml_str) {
        Ok(s) => s,
        Err(e) => {
            errors.push(format!("YAML parse error: {e}"));
            errors
                .push("check that all required fields are present and correctly typed".to_string());
            return Err(errors);
        }
    };

    let validation_errors = pay_types::registry::validate_provider(&spec, &spec.name);
    if !validation_errors.is_empty() {
        return Err(validation_errors);
    }

    if spec.meta.description.len() > 255 {
        errors.push(format!(
            "description is {} chars (max 255): \"{}\"",
            spec.meta.description.len(),
            spec.meta.description
        ));
    }

    if !spec.meta.service_url.starts_with("https://") {
        errors.push(format!(
            "service_url must start with https:// (got \"{}\")",
            spec.meta.service_url
        ));
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(ValidatedProvider { spec })
}

fn endpoint_counts(spec: &pay_types::registry::ProviderFrontmatter) -> (usize, usize) {
    let metered = spec
        .endpoints
        .iter()
        .filter(|ep| ep.pricing.is_some())
        .count();
    let free = spec.endpoints.len().saturating_sub(metered);
    (metered, free)
}

fn recommended_paths(name: &str) -> String {
    format!("providers/<operator>/{name}.md\nproviders/<operator>/<origin>/{name}.md")
}

fn validate_output_path(path: &str, name: &str) -> Vec<String> {
    let mut errors = Vec::new();
    let path_ref = Path::new(path);

    if path_ref.extension().and_then(|e| e.to_str()) != Some("md") {
        errors.push("output_path must end in `.md`".to_string());
    }

    match path_ref.file_stem().and_then(|s| s.to_str()) {
        Some(stem) if stem == name => {}
        Some(stem) => errors.push(format!(
            "filename `{stem}.md` must match frontmatter name `{name}`"
        )),
        None => errors.push("output_path must include a filename".to_string()),
    }

    let components = normal_components(path_ref);
    match components.iter().position(|c| c == "providers") {
        Some(idx) => {
            let tail_len = components.len().saturating_sub(idx + 1);
            if tail_len < 2 {
                errors.push(
                    "output_path must be providers/<operator>/<name>.md or providers/<operator>/<origin>/<name>.md"
                        .to_string(),
                );
            }
        }
        None => errors.push("output_path must be under `providers/`".to_string()),
    }

    errors
}

fn normal_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str().map(str::to_string),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_md() -> &'static str {
        "---\nname: test-api\ntitle: \"Test API\"\ndescription: \"A test API for unit tests — validates that the create_skill tool works correctly end to end\"\nuse_case: \"testing validation logic, verifying CI checks work correctly\"\ncategory: devtools\nservice_url: https://test.example.com\nendpoints:\n  - method: POST\n    path: \"v1/run\"\n    description: \"Run a test suite against the target service and return results\"\n---\n\nSome markdown body.\n"
    }

    #[test]
    fn validate_valid_spec() {
        let result = validate(valid_md());
        assert!(result.is_ok());
        let v = result.unwrap();
        assert_eq!(v.spec.name, "test-api");
        assert_eq!(v.spec.endpoints.len(), 1);
    }

    #[test]
    fn validate_no_frontmatter() {
        let result = validate("Just some text, no frontmatter");
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("frontmatter")));
    }

    #[test]
    fn validate_empty_frontmatter() {
        let result = validate("---\n---\n");
        assert!(result.is_err());
    }

    #[test]
    fn validate_missing_required_fields() {
        let result = validate("---\nname: x\n---\n");
        assert!(result.is_err());
        let errs = result.unwrap_err();
        // Fields default to empty strings, caught by validate_provider
        assert!(!errs.is_empty());
    }

    #[test]
    fn validate_bad_category() {
        let md = "---\nname: x\ntitle: X\ndescription: X\ncategory: nonsense\nservice_url: https://x.com\nendpoints:\n  - method: GET\n    path: v1\n    description: Do thing\n---\n";
        let result = validate(md);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("unknown category")));
    }

    #[test]
    fn validate_no_endpoints() {
        let md = "---\nname: x\ntitle: X\ndescription: X\ncategory: data\nservice_url: https://x.com\nendpoints: []\n---\n";
        let result = validate(md);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("at least one endpoint")));
    }

    #[test]
    fn validate_long_description() {
        let long_desc = "A".repeat(256);
        let md = format!(
            "---\nname: x\ntitle: X\ndescription: \"{long_desc}\"\ncategory: data\nservice_url: https://x.com\nendpoints:\n  - method: GET\n    path: v1\n    description: Do thing\n---\n"
        );
        let result = validate(&md);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("255")));
    }

    #[test]
    fn validate_http_service_url() {
        let md = "---\nname: x\ntitle: X\ndescription: X\ncategory: data\nservice_url: http://insecure.com\nendpoints:\n  - method: GET\n    path: v1\n    description: Do thing\n---\n";
        let result = validate(md);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("https://")));
    }

    #[test]
    fn validate_endpoint_missing_method() {
        let md = "---\nname: x\ntitle: X\ndescription: X\ncategory: data\nservice_url: https://x.com\nendpoints:\n  - path: v1\n    description: Do thing\n---\n";
        let result = validate(md);
        assert!(result.is_err());
    }

    #[test]
    fn validate_endpoint_missing_description() {
        // EndpointSpec.description defaults to "" via serde, which validate_provider catches
        let md = "---\nname: x\ntitle: X\ndescription: X\ncategory: data\nservice_url: https://x.com\nendpoints:\n  - method: GET\n    path: v1\n    description: \"\"\n---\n";
        let result = validate(md);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("description")));
    }

    #[test]
    fn validate_with_pricing() {
        let md = "---\nname: x\ntitle: X\ndescription: \"A data service that provides search capabilities across structured datasets and indexes\"\nuse_case: \"searching structured data, querying indexed datasets\"\ncategory: data\nservice_url: https://x.com\nendpoints:\n  - method: POST\n    path: v1/search\n    description: \"Search datasets by keyword with filtering and pagination support\"\n    pricing:\n      dimensions:\n        - direction: usage\n          unit: requests\n          scale: 1\n          tiers:\n            - price_usd: 0.01\n---\n";
        let result = validate(md);
        assert!(result.is_ok());
        let v = result.unwrap();
        assert!(v.spec.endpoints[0].pricing.is_some());
    }

    #[test]
    fn validate_rejects_pricing_below_stablecoin_precision() {
        let md = "---\nname: x\ntitle: X\ndescription: \"A data service that validates tiny prices are rejected before publishing\"\nuse_case: \"testing pricing precision validation for tiny metered endpoint prices\"\ncategory: data\nservice_url: https://x.com\nendpoints:\n  - method: POST\n    path: v1/search\n    description: \"Search datasets by keyword with filtering and pagination support\"\n    pricing:\n      dimensions:\n        - direction: usage\n          unit: requests\n          scale: 2000000\n          tiers:\n            - price_usd: 1.0\n---\n";
        let result = validate(md);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.contains("below minimum $0.000001")));
    }

    #[test]
    fn validate_with_optional_fields() {
        let md = "---\nname: x\ntitle: X\ndescription: \"A data service with optional fields configured for versioning and affiliate support\"\nuse_case: \"testing optional field handling, verifying affiliate config\"\ncategory: data\nservice_url: https://x.com\nversion: v2\naffiliate_policy:\n  enabled: true\n  default_percent: 10\nendpoints:\n  - method: GET\n    path: v1\n    description: \"Retrieve all available things with optional filtering\"\n    resource: things\n---\n";
        let result = validate(md);
        assert!(result.is_ok());
        let v = result.unwrap();
        assert_eq!(v.spec.version, "v2");
        assert!(v.spec.affiliate_policy.is_some());
        assert_eq!(v.spec.endpoints[0].resource.as_deref(), Some("things"));
    }

    #[test]
    fn params_deserialize() {
        let json = r#"{"content": "---\nname: test\n---\n"}"#;
        let params: Params = serde_json::from_str(json).unwrap();
        assert!(params.content.contains("name: test"));
        assert!(params.output_path.is_none());
    }

    #[test]
    fn params_with_output_path() {
        let json = r#"{"content": "---\n---\n", "output_path": "/tmp/test.md"}"#;
        let params: Params = serde_json::from_str(json).unwrap();
        assert_eq!(params.output_path.unwrap(), "/tmp/test.md");
    }

    #[test]
    fn output_path_accepts_native_and_proxied_provider_paths() {
        assert!(validate_output_path("providers/acme/search.md", "search").is_empty());
        assert!(validate_output_path("providers/acme/google/search.md", "search").is_empty());
    }

    #[test]
    fn output_path_reports_contributor_path_issues() {
        let errs = validate_output_path("tmp/search.yml", "search");
        assert!(errs.iter().any(|e| e.contains("`.md`")));
        assert!(errs.iter().any(|e| e.contains("providers/")));

        let errs = validate_output_path("providers/acme/wrong.md", "search");
        assert!(errs.iter().any(|e| e.contains("must match")));

        let errs = validate_output_path("providers/search.md", "search");
        assert!(errs.iter().any(|e| e.contains("providers/<operator>")));
    }

    #[test]
    fn endpoint_counts_separates_metered_and_free_endpoints() {
        let mut spec = validate(valid_md()).unwrap().spec;
        spec.endpoints.push(pay_types::registry::EndpointSpec {
            method: "GET".into(),
            path: "v1/free".into(),
            description: "Fetch a free health check response from the service".into(),
            resource: None,
            pricing: None,
        });
        spec.endpoints[0].pricing = Some(serde_json::json!({
            "dimensions": [{"scale": 1, "tiers": [{"price_usd": 0.01}]}]
        }));

        assert_eq!(endpoint_counts(&spec), (1, 1));
    }
}
