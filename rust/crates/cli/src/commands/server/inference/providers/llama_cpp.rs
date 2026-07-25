//! llama.cpp (`llama-server`) — native endpoints plus the OpenAI-compat
//! surface, usually on the contested :8080.

use super::{
    InferenceProvider, PaidEndpoint, identify_json_key, openai_models, openai_paid_endpoints, post,
};

pub struct LlamaCpp;

const PORTS: &[u16] = &[8080];

#[async_trait::async_trait]
impl InferenceProvider for LlamaCpp {
    fn slug(&self) -> &str {
        "llama-cpp"
    }
    fn title(&self) -> &str {
        "llama.cpp"
    }
    fn ports(&self) -> &[u16] {
        PORTS
    }
    fn color(&self) -> Option<&str> {
        Some("#f59e0b")
    }
    async fn identify(&self, client: &reqwest::Client, base_url: &str) -> Option<Option<String>> {
        // /props is llama-server-specific; a JSON-key match keeps generic dev
        // servers on :8080 from false-positiving.
        identify_json_key(client, base_url, "/props", "default_generation_settings").await
    }
    async fn list_models(&self, client: &reqwest::Client, base_url: &str) -> Vec<String> {
        openai_models(client, base_url).await
    }
    fn paid_endpoints(&self) -> Vec<PaidEndpoint> {
        let mut paid = openai_paid_endpoints();
        paid.extend([post("completion"), post("infill"), post("embedding")]);
        paid
    }
    // endpoint_kind: the shared default already maps /completion and /infill
    // → completion, /embedding → embeddings.
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{base_url, client, rt, stub};
    use super::*;

    #[test]
    fn identify_matches_props_payload() {
        rt().block_on(async {
            let port = stub(vec![("/props", r#"{"default_generation_settings":{}}"#)]).await;
            assert_eq!(
                LlamaCpp.identify(&client(), &base_url(port)).await,
                Some(None)
            );
        });
    }

    #[test]
    fn identify_rejects_generic_200() {
        rt().block_on(async {
            // A dev server answering 200 HTML on every llama.cpp probe path.
            let port = stub(vec![
                ("/props", "<html>hello</html>"),
                ("/v1/models", "<html>hello</html>"),
            ])
            .await;
            assert_eq!(LlamaCpp.identify(&client(), &base_url(port)).await, None);
        });
    }

    #[test]
    fn list_models_parses_v1_models() {
        rt().block_on(async {
            let port = stub(vec![("/v1/models", r#"{"data":[{"id":"qwen2.5-7b"}]}"#)]).await;
            let models = LlamaCpp.list_models(&client(), &base_url(port)).await;
            assert_eq!(models, vec!["qwen2.5-7b"]);
        });
    }

    #[test]
    fn paid_endpoints_add_native_paths_to_openai_surface() {
        let paths: Vec<String> = LlamaCpp
            .paid_endpoints()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert_eq!(
            paths,
            [
                "v1/responses",
                "v1/chat/completions",
                "v1/embeddings",
                "v1/completions",
                "completion",
                "infill",
                "embedding",
            ]
        );
    }

    #[test]
    fn endpoint_kind_table() {
        for (path, kind) in [
            ("/v1/responses", "chat"),
            ("/v1/chat/completions", "chat"),
            ("/completion", "completion"),
            ("/infill", "completion"),
            ("/embedding", "embeddings"),
            ("/props", "other"),
        ] {
            assert_eq!(LlamaCpp.endpoint_kind(path), kind, "{path}");
        }
    }
}
