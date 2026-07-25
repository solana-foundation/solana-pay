//! Typed configuration for built-in, versioned API profiles.

mod inference;
mod iptv;

pub use inference::OpenAiSurface;
pub use iptv::XtreamSurface;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use self::inference::default_surfaces as default_openai_surfaces;
use self::iptv::default_surfaces as default_xtream_surfaces;

/// Versioned, reusable protocol surface expanded into an API spec at load
/// time. Provider credentials, routing, pricing, and payout configuration stay
/// on the surrounding spec; a profile contributes only wire-level API
/// knowledge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ApiProfile {
    /// The HTTP surface shared by OpenAI and compatible inference servers.
    OpenaiCompatible {
        /// Profile contract version. The first supported version is `v1`.
        version: String,
        /// Protocol surfaces to expose. Omission selects the recommended v1
        /// set: Responses, Chat Completions, Embeddings, and Models.
        #[serde(default = "default_openai_surfaces")]
        surfaces: Vec<OpenAiSurface>,
    },
    /// The Xtream Codes IPTV metadata and playback surface.
    XtreamCodes {
        /// Profile contract version. The first supported version is `v1`.
        version: String,
        /// Protocol surfaces to expose. Omission selects the player API plus
        /// live, movie, and series playback. Catch-up is opt-in because some
        /// panels expose upstream credentials in timeshift redirects.
        #[serde(default = "default_xtream_surfaces")]
        surfaces: Vec<XtreamSurface>,
    },
}
