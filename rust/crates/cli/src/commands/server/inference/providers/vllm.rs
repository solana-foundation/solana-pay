//! vLLM — OpenAI-compat server on :8000 with a `/version` endpoint.

use super::{
    InferenceProvider, PaidEndpoint, identify_json_key, openai_models, openai_paid_endpoints,
};

pub struct Vllm;

const PORTS: &[u16] = &[8000];

#[async_trait::async_trait]
impl InferenceProvider for Vllm {
    fn slug(&self) -> &str {
        "vllm"
    }
    fn title(&self) -> &str {
        "vLLM"
    }
    fn ports(&self) -> &[u16] {
        PORTS
    }
    fn color(&self) -> Option<&str> {
        Some("#38bdf8")
    }
    async fn identify(&self, client: &reqwest::Client, base_url: &str) -> Option<Option<String>> {
        identify_json_key(client, base_url, "/version", "version").await
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
    fn identify_reads_version_endpoint() {
        rt().block_on(async {
            let port = stub(vec![("/version", r#"{"version":"0.8.4"}"#)]).await;
            let version = Vllm.identify(&client(), &base_url(port)).await;
            assert_eq!(version, Some(Some("0.8.4".to_string())));
        });
    }

    #[test]
    fn identify_rejects_generic_200() {
        rt().block_on(async {
            let port = stub(vec![("/version", "<html>hello</html>")]).await;
            assert_eq!(Vllm.identify(&client(), &base_url(port)).await, None);
        });
    }

    #[test]
    fn list_models_parses_v1_models() {
        rt().block_on(async {
            let port = stub(vec![(
                "/v1/models",
                r#"{"data":[{"id":"meta-llama/Llama-3.1-8B-Instruct"}]}"#,
            )])
            .await;
            let models = Vllm.list_models(&client(), &base_url(port)).await;
            assert_eq!(models, vec!["meta-llama/Llama-3.1-8B-Instruct"]);
        });
    }

    #[test]
    fn paid_endpoints_are_the_openai_compat_surface() {
        let paths: Vec<String> = Vllm.paid_endpoints().into_iter().map(|e| e.path).collect();
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
            ("/version", "other"),
        ] {
            assert_eq!(Vllm.endpoint_kind(path), kind, "{path}");
        }
    }
}
