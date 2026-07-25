//! Xtream Codes-compatible IPTV profile types.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Endpoint groups understood by the `xtream-codes` profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum XtreamSurface {
    /// `GET /player_api.php` for account, catalog, and EPG metadata.
    PlayerApi,
    /// `GET /live/{username}/{password}/{stream}`.
    Live,
    /// `GET /movie/{username}/{password}/{stream}`.
    Movie,
    /// `GET /series/{username}/{password}/{episode}`.
    Series,
    /// `GET /timeshift/{username}/{password}/{duration}/{start}/{stream}`.
    Timeshift,
}

pub(super) fn default_surfaces() -> Vec<XtreamSurface> {
    vec![
        XtreamSurface::PlayerApi,
        XtreamSurface::Live,
        XtreamSurface::Movie,
        XtreamSurface::Series,
    ]
}
