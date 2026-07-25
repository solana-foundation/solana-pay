//! LM Studio — local server on :1234 with its own `/api/v0` REST API plus
//! the OpenAI-compat surface.

use super::{
    InferenceProvider, PaidEndpoint, identify_json_key, openai_models, openai_paid_endpoints,
};

pub struct LmStudio;

const PORTS: &[u16] = &[1234];

#[async_trait::async_trait]
impl InferenceProvider for LmStudio {
    fn slug(&self) -> &str {
        "lm-studio"
    }
    fn title(&self) -> &str {
        "LM Studio"
    }
    fn ports(&self) -> &[u16] {
        PORTS
    }
    fn color(&self) -> Option<&str> {
        Some("#6366f1")
    }
    async fn identify(&self, client: &reqwest::Client, base_url: &str) -> Option<Option<String>> {
        // /api/v0 is LM Studio's own REST API — unambiguous; fall back to the
        // OpenAI-compat model list.
        if let Some(version) = identify_json_key(client, base_url, "/api/v0/models", "data").await {
            return Some(version);
        }
        identify_json_key(client, base_url, "/v1/models", "data").await
    }
    async fn list_models(&self, client: &reqwest::Client, base_url: &str) -> Vec<String> {
        openai_models(client, base_url).await
    }
    fn paid_endpoints(&self) -> Vec<PaidEndpoint> {
        openai_paid_endpoints()
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{base_url, client, rt, stub};
    use super::*;

    #[test]
    fn identify_prefers_api_v0_then_falls_back_to_v1() {
        rt().block_on(async {
            let native = stub(vec![("/api/v0/models", r#"{"data":[]}"#)]).await;
            assert_eq!(
                LmStudio.identify(&client(), &base_url(native)).await,
                Some(None)
            );

            let compat_only = stub(vec![("/v1/models", r#"{"data":[]}"#)]).await;
            assert_eq!(
                LmStudio.identify(&client(), &base_url(compat_only)).await,
                Some(None)
            );
        });
    }

    #[test]
    fn identify_rejects_generic_200() {
        rt().block_on(async {
            let port = stub(vec![
                ("/api/v0/models", "<html>hello</html>"),
                ("/v1/models", "<html>hello</html>"),
            ])
            .await;
            assert_eq!(LmStudio.identify(&client(), &base_url(port)).await, None);
        });
    }

    #[test]
    fn list_models_parses_v1_models() {
        rt().block_on(async {
            let port = stub(vec![(
                "/v1/models",
                r#"{"data":[{"id":"qwen2.5-7b-instruct"},{"id":"gemma-3-4b"}]}"#,
            )])
            .await;
            let models = LmStudio.list_models(&client(), &base_url(port)).await;
            assert_eq!(models, vec!["qwen2.5-7b-instruct", "gemma-3-4b"]);
        });
    }

    #[test]
    fn paid_endpoints_are_the_openai_compat_surface() {
        let paths: Vec<String> = LmStudio
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
            ]
        );
    }

    #[test]
    fn endpoint_kind_table() {
        for (path, kind) in [
            ("/v1/responses", "chat"),
            ("/v1/chat/completions", "chat"),
            ("/v1/completions", "completion"),
            ("/v1/embeddings", "embeddings"),
            ("/v1/models", "other"),
        ] {
            assert_eq!(LmStudio.endpoint_kind(path), kind, "{path}");
        }
    }
}
