//! Inference provider implementations for `pay serve inference`.
//!
//! Each built-in local inference server (Ollama, LM Studio, llama.cpp, vLLM,
//! exo) implements [`InferenceProvider`] in its own file with its constants
//! and tests. Users extend or override the built-ins (matched by slug) via
//! `~/.config/pay/inference-providers.yml`, which loads as
//! [`CustomProvider`]s implementing the same trait.

pub mod catalog;
pub mod custom;
pub mod exo;
pub mod llama_cpp;
pub mod lm_studio;
pub mod ollama;
pub mod vllm;

use std::sync::Arc;

use serde::Deserialize;

pub use custom::CustomProvider;

/// Conventional chat-completions path for OpenAI-compatible providers.
pub const OPENAI_CHAT_COMPLETIONS_PATH: &str = "v1/chat/completions";

/// One monetizable endpoint of a provider's API surface.
#[derive(Debug, Clone, Deserialize)]
pub struct PaidEndpoint {
    pub method: pay_types::metering::HttpMethod,
    pub path: String,
}

/// The chat-API wire dialect a provider speaks. `pay claude` drives the
/// Anthropic `v1/messages` surface today; anything else needs the (future)
/// protocol translator in front of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Anthropic,
    OpenAiCompat,
    GeminiNative,
    Unknown,
}

impl std::fmt::Display for Dialect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Dialect::Anthropic => "anthropic",
            Dialect::OpenAiCompat => "openai-compat",
            Dialect::GeminiNative => "gemini-native",
            Dialect::Unknown => "unknown",
        })
    }
}

/// Aggregate price range across a provider's metered endpoints, for picker
/// rows and other compact UI ("requests" today, "tokens" once providers
/// adopt token metering).
#[derive(Debug, Clone, PartialEq)]
pub struct PricingHint {
    /// Preformatted display price supplied by another Pay gateway. When set,
    /// [`Display`] returns this verbatim.
    pub display: Option<String>,
    pub min_usd: f64,
    pub max_usd: f64,
    /// Billing unit the prices are quoted in (e.g. `requests`, `tokens`).
    pub unit: String,
    /// Matched pricing variant value (e.g. `gemini-2.5-flash` or `default`),
    /// when the provider prices through catalog variants.
    pub variant: Option<String>,
    /// Optional description of the matched pricing variant, when the catalog
    /// provided one.
    pub description: Option<String>,
    /// Explicit per-1M-token input/output rates `(input, output)`, when the
    /// price is quoted per token direction. When `Some`, the display renders
    /// `in $X · out $Y /1M tok`; the min/max fields stay populated (the two
    /// rates) so range-based consumers keep working.
    pub io: Option<(f64, f64)>,
}

impl std::fmt::Display for PricingHint {
    /// With `io`: `in $0.15 · out $0.60 /1M tok`. Otherwise `$0.0100/req`,
    /// or `$0.0000–0.0100/req` when prices vary.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(display) = &self.display {
            return f.write_str(display);
        }
        if let Some((input, output)) = self.io {
            return write!(f, "in ${input:.2} · out ${output:.2} /1M tok");
        }
        let unit = match self.unit.as_str() {
            "requests" => "req",
            "tokens" => "tok",
            other => other,
        };
        if (self.min_usd - self.max_usd).abs() < f64::EPSILON {
            write!(f, "${:.4}/{unit}", self.min_usd)
        } else {
            write!(f, "${:.4}–{:.4}/{unit}", self.min_usd, self.max_usd)
        }
    }
}

/// A local inference server the gateway can discover, front, and meter.
#[async_trait::async_trait]
pub trait InferenceProvider: Send + Sync {
    fn slug(&self) -> &str;
    fn title(&self) -> &str;
    /// Well-known ports probed during discovery, in order.
    fn ports(&self) -> &[u16];
    /// Brand color hex for UI badges.
    fn color(&self) -> Option<&str>;
    /// Provider-specific positive identification (bare 200s never match).
    /// Returns the server version when the response carries one:
    /// `Some(version)` on a positive match (`Some(None)` when the response
    /// has no version), `None` when nothing matched.
    async fn identify(&self, client: &reqwest::Client, base_url: &str) -> Option<Option<String>>;
    async fn list_models(&self, client: &reqwest::Client, base_url: &str) -> Vec<String>;
    /// Endpoints that get metered when the gateway runs with `--price-usd`
    /// (method + path, no leading slash — gate convention). Anything not
    /// listed stays free passthrough.
    fn paid_endpoints(&self) -> Vec<PaidEndpoint>;
    /// `chat` | `completion` | `embeddings` | `other` for a request path.
    fn endpoint_kind(&self, path: &str) -> &'static str {
        default_endpoint_kind(path)
    }
    /// Chat-API wire dialect. Local servers are overwhelmingly
    /// OpenAI-compatible; providers that serve `v1/messages` (what
    /// `pay claude` drives) override to [`Dialect::Anthropic`].
    fn dialect(&self) -> Dialect {
        Dialect::OpenAiCompat
    }
    /// Price range across metered endpoints, when known (hosted catalog
    /// providers). Local providers are unpriced until fronted by a gateway.
    fn pricing_hint(&self) -> Option<PricingHint> {
        None
    }
    /// Price for a specific model, when the provider prices per model
    /// (catalog `variants[]`). Defaults to the model-agnostic
    /// [`Self::pricing_hint`]; `model = None` also falls back to it.
    fn pricing_hint_for_model(&self, _model: Option<&str>) -> Option<PricingHint> {
        self.pricing_hint()
    }
}

/// Built-in providers in probe priority order. Order matters: when two
/// providers share a port (8080 is contested in the wild), the first entry
/// whose identify probe passes claims it.
pub fn builtin_providers() -> Vec<Arc<dyn InferenceProvider>> {
    vec![
        Arc::new(ollama::Ollama),
        Arc::new(lm_studio::LmStudio),
        Arc::new(llama_cpp::LlamaCpp),
        Arc::new(vllm::Vllm),
        Arc::new(exo::Exo),
    ]
}

/// Default endpoint-kind mapping shared by the OpenAI-compatible surface.
/// `chat` is checked first — `/v1/chat/completions` contains both markers —
/// and `/v1/messages` (Anthropic-compat) is a chat endpoint too. Covers
/// Ollama's native paths as well (`/api/chat`, `/api/generate`,
/// `/api/embed`) and llama.cpp's (`/completion`, `/infill`, `/embedding`).
pub fn default_endpoint_kind(path: &str) -> &'static str {
    if let Some(endpoint) = pay_core::server::profiles::openai_endpoint(path) {
        return endpoint.kind;
    }
    let path = path.to_ascii_lowercase();
    if path.contains("chat") || path.contains("messages") {
        "chat"
    } else if path.contains("embed") {
        "embeddings"
    } else if path.contains("completion") || path.contains("generate") || path.contains("infill") {
        "completion"
    } else {
        "other"
    }
}

/// A POST paid endpoint (all inference calls are POSTs).
pub(crate) fn post(path: &str) -> PaidEndpoint {
    PaidEndpoint {
        method: pay_types::metering::HttpMethod::Post,
        path: path.to_string(),
    }
}

/// Known OpenAI-compatible paid endpoints, sourced from the versioned profile.
pub(crate) fn openai_paid_endpoints() -> Vec<PaidEndpoint> {
    pay_core::server::profiles::openai_compatible_endpoints()
        .iter()
        .filter(|endpoint| matches!(endpoint.method, pay_types::metering::HttpMethod::Post))
        .map(|endpoint| PaidEndpoint {
            method: endpoint.method.clone(),
            path: endpoint.path.to_string(),
        })
        .collect()
}

/// GET `base_url + path`, returning the body only on a 2xx response.
pub(crate) async fn get_body(
    client: &reqwest::Client,
    base_url: &str,
    path: &str,
) -> Option<String> {
    let resp = client.get(format!("{base_url}{path}")).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.text().await.ok()
}

/// GET `base_url + path` and parse the body as JSON.
pub(crate) async fn get_json(
    client: &reqwest::Client,
    base_url: &str,
    path: &str,
) -> Option<serde_json::Value> {
    let body = get_body(client, base_url, path).await?;
    serde_json::from_str(&body).ok()
}

/// Identify by JSON key: passes when GET `path` returns JSON with `key` at
/// the top level. The response's `version` field (when present) is reported
/// as the server version. A JSON-key match keeps generic dev servers on
/// contested ports from false-positiving on bare 200s.
pub(crate) async fn identify_json_key(
    client: &reqwest::Client,
    base_url: &str,
    path: &str,
    key: &str,
) -> Option<Option<String>> {
    let json = get_json(client, base_url, path).await?;
    json.get(key)?;
    Some(
        json.get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    )
}

/// Model names from a JSON endpoint: the array at `json_pointer` (e.g.
/// `/models`, `/data`), taking `name_key` (e.g. `name`, `id`) of each item.
pub(crate) async fn models_from_json(
    client: &reqwest::Client,
    base_url: &str,
    path: &str,
    json_pointer: &str,
    name_key: &str,
) -> Vec<String> {
    let Some(json) = get_json(client, base_url, path).await else {
        return Vec::new();
    };
    json.pointer(json_pointer)
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get(name_key)?.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// OpenAI-compatible model listing: `/v1/models` → `data[].id`.
pub(crate) async fn openai_models(client: &reqwest::Client, base_url: &str) -> Vec<String> {
    models_from_json(client, base_url, "/v1/models", "/data", "id").await
}

#[cfg(test)]
pub(crate) mod test_support {
    use axum::Router;
    use axum::routing::get;

    pub(crate) fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Serve `routes` on an ephemeral port; returns the port.
    pub(crate) async fn stub(routes: Vec<(&'static str, &'static str)>) -> u16 {
        let mut router = Router::new();
        for (path, body) in routes {
            router = router.route(path, get(move || async move { body.to_string() }));
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        port
    }

    pub(crate) fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(400))
            .build()
            .unwrap()
    }

    pub(crate) fn base_url(port: u16) -> String {
        format!("http://127.0.0.1:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_are_registered_in_probe_priority_order() {
        let providers = builtin_providers();
        let slugs: Vec<&str> = providers.iter().map(|p| p.slug()).collect();
        assert_eq!(
            slugs,
            vec!["ollama", "lm-studio", "llama-cpp", "vllm", "exo"]
        );
    }

    #[test]
    fn builtin_paid_endpoints_follow_gate_conventions() {
        for provider in builtin_providers() {
            for endpoint in provider.paid_endpoints() {
                assert!(
                    matches!(endpoint.method, pay_types::metering::HttpMethod::Post),
                    "{}: inference calls are POSTs",
                    provider.slug()
                );
                assert!(
                    !endpoint.path.starts_with('/'),
                    "{}: paid paths follow the gate's no-leading-slash convention",
                    provider.slug()
                );
            }
        }
    }

    #[test]
    fn dialect_defaults_to_openai_compat_except_ollama() {
        for provider in builtin_providers() {
            let expected = if provider.slug() == "ollama" {
                // Ollama serves both surfaces; `pay claude` drives
                // v1/messages, so it counts as Anthropic-dialect.
                Dialect::Anthropic
            } else {
                Dialect::OpenAiCompat
            };
            assert_eq!(provider.dialect(), expected, "{}", provider.slug());
        }
    }

    #[test]
    fn pricing_hint_defaults_to_none_for_local_providers() {
        for provider in builtin_providers() {
            assert_eq!(provider.pricing_hint(), None, "{}", provider.slug());
        }
    }

    #[test]
    fn pricing_hint_display_is_compact() {
        let flat = PricingHint {
            display: None,
            min_usd: 0.01,
            max_usd: 0.01,
            unit: "requests".to_string(),
            variant: None,
            description: None,
            io: None,
        };
        assert_eq!(flat.to_string(), "$0.0100/req");

        let range = PricingHint {
            display: None,
            min_usd: 0.0,
            max_usd: 0.01,
            unit: "requests".to_string(),
            variant: None,
            description: None,
            io: None,
        };
        assert_eq!(range.to_string(), "$0.0000–0.0100/req");

        let tokens = PricingHint {
            display: None,
            min_usd: 0.0007,
            max_usd: 0.0007,
            unit: "tokens".to_string(),
            variant: None,
            description: None,
            io: None,
        };
        assert_eq!(tokens.to_string(), "$0.0007/tok");
    }

    #[test]
    fn pricing_hint_display_renders_in_out_when_present() {
        let io = PricingHint {
            display: None,
            min_usd: 0.15,
            max_usd: 0.60,
            unit: "tokens".to_string(),
            variant: None,
            description: None,
            io: Some((0.15, 0.60)),
        };
        assert_eq!(io.to_string(), "in $0.15 · out $0.60 /1M tok");
    }

    #[test]
    fn dialect_display_names() {
        assert_eq!(Dialect::Anthropic.to_string(), "anthropic");
        assert_eq!(Dialect::OpenAiCompat.to_string(), "openai-compat");
        assert_eq!(Dialect::GeminiNative.to_string(), "gemini-native");
        assert_eq!(Dialect::Unknown.to_string(), "unknown");
    }

    #[test]
    fn default_endpoint_kind_mapping() {
        assert_eq!(default_endpoint_kind("/v1/chat/completions"), "chat");
        assert_eq!(default_endpoint_kind("/v1/messages"), "chat");
        assert_eq!(default_endpoint_kind("/v1/completions"), "completion");
        assert_eq!(default_endpoint_kind("/v1/embeddings"), "embeddings");
        assert_eq!(default_endpoint_kind("/api/tags"), "other");
    }
}
