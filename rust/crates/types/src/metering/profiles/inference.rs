//! OpenAI-compatible inference profile types.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Endpoint groups understood by the `openai-compatible` profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OpenAiSurface {
    /// `POST /v1/responses`, the recommended generation API for new projects.
    Responses,
    /// `POST /v1/chat/completions`, retained for compatible clients.
    ChatCompletions,
    /// `POST /v1/embeddings`.
    Embeddings,
    /// `GET /v1/models` discovery.
    Models,
    /// `POST /v1/completions`, a legacy compatibility surface.
    Completions,
}

pub(super) fn default_surfaces() -> Vec<OpenAiSurface> {
    vec![
        OpenAiSurface::Responses,
        OpenAiSurface::ChatCompletions,
        OpenAiSurface::Embeddings,
        OpenAiSurface::Models,
    ]
}
