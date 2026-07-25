//! exo — distributed inference cluster with an OpenAI-compat API on :52415.

use super::{
    InferenceProvider, PaidEndpoint, identify_json_key, openai_models, openai_paid_endpoints,
};

pub struct Exo;

const PORTS: &[u16] = &[52415];

#[async_trait::async_trait]
impl InferenceProvider for Exo {
    fn slug(&self) -> &str {
        "exo"
    }
    fn title(&self) -> &str {
        "exo"
    }
    fn ports(&self) -> &[u16] {
        PORTS
    }
    fn color(&self) -> Option<&str> {
        Some("#e879f9")
    }
    async fn identify(&self, client: &reqwest::Client, base_url: &str) -> Option<Option<String>> {
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
    fn identify_matches_v1_models_data() {
        rt().block_on(async {
            let port = stub(vec![("/v1/models", r#"{"data":[{"id":"llama-3.2-3b"}]}"#)]).await;
            assert_eq!(Exo.identify(&client(), &base_url(port)).await, Some(None));
        });
    }

    #[test]
    fn identify_rejects_generic_200() {
        rt().block_on(async {
            let port = stub(vec![("/v1/models", "<html>hello</html>")]).await;
            assert_eq!(Exo.identify(&client(), &base_url(port)).await, None);
        });
    }

    #[test]
    fn list_models_parses_v1_models() {
        rt().block_on(async {
            let port = stub(vec![("/v1/models", r#"{"data":[{"id":"llama-3.2-3b"}]}"#)]).await;
            let models = Exo.list_models(&client(), &base_url(port)).await;
            assert_eq!(models, vec!["llama-3.2-3b"]);
        });
    }

    #[test]
    fn paid_endpoints_are_the_openai_compat_surface() {
        let paths: Vec<String> = Exo.paid_endpoints().into_iter().map(|e| e.path).collect();
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
            assert_eq!(Exo.endpoint_kind(path), kind, "{path}");
        }
    }
}
