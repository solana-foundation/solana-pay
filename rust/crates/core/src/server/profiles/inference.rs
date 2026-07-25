//! OpenAI-compatible inference protocol profiles.

use pay_types::metering::{ApiSpec, HttpMethod, OpenAiSurface};

use super::{ProfileEndpoint, append_endpoint};

const ENDPOINTS: &[ProfileEndpoint] = &[
    ProfileEndpoint {
        method: HttpMethod::Post,
        path: "v1/responses",
        description: "Create a model response.",
        resource: None,
        kind: "chat",
        input_tokens: Some("/usage/input_tokens"),
        output_tokens: Some("/usage/output_tokens"),
    },
    ProfileEndpoint {
        method: HttpMethod::Post,
        path: "v1/chat/completions",
        description: "Create a chat completion.",
        resource: None,
        kind: "chat",
        input_tokens: Some("/usage/prompt_tokens"),
        output_tokens: Some("/usage/completion_tokens"),
    },
    ProfileEndpoint {
        method: HttpMethod::Post,
        path: "v1/embeddings",
        description: "Create vector embeddings.",
        resource: None,
        kind: "embeddings",
        input_tokens: Some("/usage/prompt_tokens"),
        output_tokens: None,
    },
    ProfileEndpoint {
        method: HttpMethod::Get,
        path: "v1/models",
        description: "List available models.",
        resource: None,
        kind: "other",
        input_tokens: None,
        output_tokens: None,
    },
    ProfileEndpoint {
        method: HttpMethod::Post,
        path: "v1/completions",
        description: "Create a legacy text completion.",
        resource: None,
        kind: "completion",
        input_tokens: Some("/usage/prompt_tokens"),
        output_tokens: Some("/usage/completion_tokens"),
    },
];

/// All operations known to `openai-compatible@v1`, including the legacy
/// Completions surface. A configured profile may select a subset.
pub fn openai_compatible_endpoints() -> &'static [ProfileEndpoint] {
    ENDPOINTS
}

/// Profile metadata for a concrete path, if it belongs to the OpenAI-compatible
/// v1 surface.
pub fn openai_endpoint(path: &str) -> Option<&'static ProfileEndpoint> {
    let path = path.trim_start_matches('/');
    ENDPOINTS.iter().find(|endpoint| endpoint.path == path)
}

pub(super) fn expand(
    api: &mut ApiSpec,
    version: &str,
    surfaces: &[OpenAiSurface],
) -> Result<(), String> {
    if version != "v1" {
        return Err(format!(
            "unsupported openai-compatible profile version `{version}`; expected `v1`"
        ));
    }
    for surface in surfaces {
        append_endpoint(api, endpoint_for_surface(*surface));
    }
    Ok(())
}

fn endpoint_for_surface(surface: OpenAiSurface) -> &'static ProfileEndpoint {
    let path = match surface {
        OpenAiSurface::Responses => "v1/responses",
        OpenAiSurface::ChatCompletions => "v1/chat/completions",
        OpenAiSurface::Embeddings => "v1/embeddings",
        OpenAiSurface::Models => "v1/models",
        OpenAiSurface::Completions => "v1/completions",
    };
    openai_endpoint(path).expect("every OpenAI surface has profile metadata")
}

#[cfg(test)]
mod tests {
    use super::super::load_yaml;

    const BASE: &str = r#"
name: local-ai
subdomain: local-ai
title: Local AI
description: OpenAI-compatible local inference.
category: ai_ml
version: v1
profile:
  type: openai-compatible
  version: v1
routing:
  type: proxy
  url: http://127.0.0.1:8000
"#;

    #[test]
    fn default_profile_expands_recommended_surfaces() {
        let api = load_yaml(BASE).unwrap();
        let paths: Vec<_> = api
            .endpoints
            .iter()
            .map(|endpoint| endpoint.path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "v1/responses",
                "v1/chat/completions",
                "v1/embeddings",
                "v1/models",
            ]
        );
    }

    #[test]
    fn explicit_endpoint_overrides_profile_default() {
        let yaml = format!(
            "{BASE}\nendpoints:\n  - method: POST\n    path: v1/responses\n    description: Priced response\n    metering:\n      dimensions:\n        - direction: usage\n          unit: requests\n          scale: 1\n          tiers: [{{ price_usd: 0.01 }}]\n"
        );
        let api = load_yaml(&yaml).unwrap();
        let responses: Vec<_> = api
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.path == "v1/responses")
            .collect();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].description.as_deref(), Some("Priced response"));
        assert!(responses[0].metering.is_some());
    }

    #[test]
    fn selected_surfaces_and_version_are_enforced() {
        let selected = BASE.replace(
            "  version: v1\n",
            "  version: v1\n  surfaces: [responses, models, completions]\n",
        );
        let api = load_yaml(&selected).unwrap();
        let paths: Vec<_> = api
            .endpoints
            .iter()
            .map(|endpoint| endpoint.path.as_str())
            .collect();
        assert_eq!(paths, ["v1/responses", "v1/models", "v1/completions"]);

        let unsupported = BASE.replace("  version: v1\n", "  version: v2\n");
        assert!(
            load_yaml(&unsupported)
                .unwrap_err()
                .contains("expected `v1`")
        );
    }
}
