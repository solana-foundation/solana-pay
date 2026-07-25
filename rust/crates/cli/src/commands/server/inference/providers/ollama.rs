//! Ollama — native API on :11434 plus OpenAI- and Anthropic-compat surfaces.

use super::{
    Dialect, InferenceProvider, PaidEndpoint, identify_json_key, models_from_json,
    openai_paid_endpoints, post,
};

pub struct Ollama;

const PORTS: &[u16] = &[11434];

#[async_trait::async_trait]
impl InferenceProvider for Ollama {
    fn slug(&self) -> &str {
        "ollama"
    }
    fn title(&self) -> &str {
        "Ollama"
    }
    fn ports(&self) -> &[u16] {
        PORTS
    }
    fn color(&self) -> Option<&str> {
        Some("#22c55e")
    }
    async fn identify(&self, client: &reqwest::Client, base_url: &str) -> Option<Option<String>> {
        identify_json_key(client, base_url, "/api/version", "version").await
    }
    async fn list_models(&self, client: &reqwest::Client, base_url: &str) -> Vec<String> {
        models_from_json(client, base_url, "/api/tags", "/models", "name").await
    }
    fn paid_endpoints(&self) -> Vec<PaidEndpoint> {
        let mut paid = vec![post("api/chat"), post("api/generate"), post("api/embed")];
        paid.extend(openai_paid_endpoints());
        // Anthropic-compat endpoint — what Claude Code (`pay claude`) drives.
        paid.push(post("v1/messages"));
        paid
    }
    // endpoint_kind: the shared default already maps /api/chat → chat,
    // /api/generate → completion, /api/embed → embeddings.

    /// Ollama serves both surfaces; `pay claude` drives v1/messages, so
    /// Anthropic is the dialect that matters here.
    fn dialect(&self) -> Dialect {
        Dialect::Anthropic
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{base_url, client, rt, stub};
    use super::*;

    #[test]
    fn identify_reads_version_from_api_version() {
        rt().block_on(async {
            let port = stub(vec![("/api/version", r#"{"version":"0.9.1"}"#)]).await;
            let version = Ollama.identify(&client(), &base_url(port)).await;
            assert_eq!(version, Some(Some("0.9.1".to_string())));
        });
    }

    #[test]
    fn identify_rejects_generic_200() {
        rt().block_on(async {
            let port = stub(vec![("/api/version", "<html>hello</html>")]).await;
            assert_eq!(Ollama.identify(&client(), &base_url(port)).await, None);
        });
    }

    #[test]
    fn list_models_parses_api_tags() {
        rt().block_on(async {
            let port = stub(vec![(
                "/api/tags",
                r#"{"models":[{"name":"llama3.2:3b"},{"name":"nomic-embed-text"}]}"#,
            )])
            .await;
            let models = Ollama.list_models(&client(), &base_url(port)).await;
            assert_eq!(models, vec!["llama3.2:3b", "nomic-embed-text"]);
        });
    }

    #[test]
    fn paid_endpoints_cover_native_openai_and_anthropic_surfaces() {
        let paths: Vec<String> = Ollama
            .paid_endpoints()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert_eq!(
            paths,
            [
                "api/chat",
                "api/generate",
                "api/embed",
                "v1/responses",
                "v1/chat/completions",
                "v1/embeddings",
                "v1/completions",
                "v1/messages",
            ]
        );
    }

    #[test]
    fn endpoint_kind_table() {
        for (path, kind) in [
            ("/api/chat", "chat"),
            ("/api/generate", "completion"),
            ("/api/embed", "embeddings"),
            ("/v1/responses", "chat"),
            ("/v1/chat/completions", "chat"),
            ("/v1/completions", "completion"),
            ("/v1/embeddings", "embeddings"),
            ("/v1/messages", "chat"),
            ("/api/tags", "other"),
        ] {
            assert_eq!(Ollama.endpoint_kind(path), kind, "{path}");
        }
    }
}
