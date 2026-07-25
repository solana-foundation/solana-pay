//! Xtream Codes-compatible IPTV protocol profiles.

use pay_types::metering::{ApiSpec, HttpMethod, XtreamSurface};

use super::{ProfileEndpoint, append_endpoint};

const ENDPOINTS: &[ProfileEndpoint] = &[
    ProfileEndpoint {
        method: HttpMethod::Get,
        path: "player_api.php",
        description: "Access account, catalog, and EPG metadata.",
        resource: Some("api"),
        kind: "other",
        input_tokens: None,
        output_tokens: None,
    },
    ProfileEndpoint {
        method: HttpMethod::Get,
        path: "live/{username}/{password}/{stream}",
        description: "Resolve a live channel stream.",
        resource: Some("stream"),
        kind: "other",
        input_tokens: None,
        output_tokens: None,
    },
    ProfileEndpoint {
        method: HttpMethod::Get,
        path: "movie/{username}/{password}/{stream}",
        description: "Resolve a movie stream.",
        resource: Some("stream"),
        kind: "other",
        input_tokens: None,
        output_tokens: None,
    },
    ProfileEndpoint {
        method: HttpMethod::Get,
        path: "series/{username}/{password}/{episode}",
        description: "Resolve a series episode stream.",
        resource: Some("stream"),
        kind: "other",
        input_tokens: None,
        output_tokens: None,
    },
    ProfileEndpoint {
        method: HttpMethod::Get,
        path: "timeshift/{username}/{password}/{duration}/{start}/{stream}",
        description: "Resolve a catch-up stream.",
        resource: Some("stream"),
        kind: "other",
        input_tokens: None,
        output_tokens: None,
    },
];

/// All operations known to `xtream-codes@v1`. The default profile omits
/// timeshift because some panels expose upstream credentials in its redirect.
pub fn xtream_codes_endpoints() -> &'static [ProfileEndpoint] {
    ENDPOINTS
}

pub(super) fn expand(
    api: &mut ApiSpec,
    version: &str,
    surfaces: &[XtreamSurface],
) -> Result<(), String> {
    if version != "v1" {
        return Err(format!(
            "unsupported xtream-codes profile version `{version}`; expected `v1`"
        ));
    }
    for surface in surfaces {
        append_endpoint(api, endpoint_for_surface(*surface));
    }
    Ok(())
}

fn endpoint_for_surface(surface: XtreamSurface) -> &'static ProfileEndpoint {
    let path = match surface {
        XtreamSurface::PlayerApi => "player_api.php",
        XtreamSurface::Live => "live/{username}/{password}/{stream}",
        XtreamSurface::Movie => "movie/{username}/{password}/{stream}",
        XtreamSurface::Series => "series/{username}/{password}/{episode}",
        XtreamSurface::Timeshift => "timeshift/{username}/{password}/{duration}/{start}/{stream}",
    };
    ENDPOINTS
        .iter()
        .find(|endpoint| endpoint.path == path)
        .expect("every Xtream surface has profile metadata")
}

#[cfg(test)]
mod tests {
    use super::super::load_yaml;

    const BASE: &str = r#"
name: xtream-gate
subdomain: acme-tv
title: ACME TV
description: Stablecoin-gated access to an Xtream IPTV panel.
category: media
version: v1
profile:
  type: xtream-codes
  version: v1
routing:
  type: proxy
  url: http://panel.example.com:8080
"#;

    #[test]
    fn profile_expands_safe_default_surface() {
        let api = load_yaml(BASE).unwrap();
        let paths: Vec<_> = api
            .endpoints
            .iter()
            .map(|endpoint| endpoint.path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "player_api.php",
                "live/{username}/{password}/{stream}",
                "movie/{username}/{password}/{stream}",
                "series/{username}/{password}/{episode}",
            ]
        );
        assert_eq!(api.endpoints[0].resource.as_deref(), Some("api"));
        assert!(
            api.endpoints[1..]
                .iter()
                .all(|endpoint| endpoint.resource.as_deref() == Some("stream"))
        );

        assert!(
            crate::server::metering::find_endpoint(
                &api,
                "GET",
                "live/alice/throwaway/2012600.m3u8"
            )
            .is_some()
        );
        assert!(
            crate::server::metering::find_endpoint(
                &api,
                "GET",
                "series/alice/throwaway/2066378.avi"
            )
            .is_some()
        );
        assert!(
            crate::server::metering::find_endpoint(
                &api,
                "GET",
                "timeshift/alice/throwaway/120/2026-07-15:20-00/497001.m3u8"
            )
            .is_none()
        );
    }

    #[test]
    fn profile_supports_overrides_and_opt_in_timeshift() {
        let selected = BASE.replace(
            "  version: v1\n",
            "  version: v1\n  surfaces: [player-api, live, timeshift]\n",
        );
        let selected = format!(
            "{selected}\nendpoints:\n  - method: GET\n    path: live/{{username}}/{{password}}/{{stream}}\n    description: Priced live stream\n    metering:\n      dimensions:\n        - direction: usage\n          unit: requests\n          scale: 1\n          tiers: [{{ price_usd: 0.05 }}]\n"
        );
        let api = load_yaml(&selected).unwrap();
        let paths: Vec<_> = api
            .endpoints
            .iter()
            .map(|endpoint| endpoint.path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "live/{username}/{password}/{stream}",
                "player_api.php",
                "timeshift/{username}/{password}/{duration}/{start}/{stream}",
            ]
        );
        assert_eq!(
            api.endpoints[0].description.as_deref(),
            Some("Priced live stream")
        );
        assert!(api.endpoints[0].metering.is_some());

        let unsupported = BASE.replace("  version: v1\n", "  version: v2\n");
        assert!(
            load_yaml(&unsupported)
                .unwrap_err()
                .contains("unsupported xtream-codes profile version `v2`")
        );
    }
}
