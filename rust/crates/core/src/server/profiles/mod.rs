//! Versioned API profiles compiled into ordinary [`ApiSpec`] values.
//!
//! Each service family owns its protocol surface in a separate module. The
//! compiler runs once while loading YAML; the payment gate and proxy continue
//! to consume the generic endpoint types used by handwritten specs.

mod inference;
mod iptv;

pub use inference::{openai_compatible_endpoints, openai_endpoint};
pub use iptv::xtream_codes_endpoints;

use pay_types::metering::{ApiProfile, ApiSpec, Endpoint, HttpMethod};
use serde::Deserialize;

/// One endpoint supplied by a built-in API profile.
#[derive(Debug, Clone)]
pub struct ProfileEndpoint {
    /// HTTP method used by the protocol operation.
    pub method: HttpMethod,
    /// Canonical path without a leading slash.
    pub path: &'static str,
    /// Human-readable operation description used in expanded specs.
    pub description: &'static str,
    /// Logical resource group used by the generic API spec.
    pub resource: Option<&'static str>,
    /// Request category used by inference telemetry.
    pub kind: &'static str,
    /// JSON pointer for billed input tokens, when the operation reports them.
    pub input_tokens: Option<&'static str>,
    /// JSON pointer for billed output tokens, when the operation reports them.
    pub output_tokens: Option<&'static str>,
}

/// Parse a YAML API document, expand its optional profile, and return the
/// generic spec consumed by the gateway.
pub fn load_yaml(contents: &str) -> Result<ApiSpec, String> {
    load_yaml_with_profile(contents).map(|(api, _)| api)
}

/// Parse and expand a YAML API document while retaining the selected profile
/// for startup integrations such as decentralized provider registration.
pub fn load_yaml_with_profile(contents: &str) -> Result<(ApiSpec, Option<ApiProfile>), String> {
    let document: ApiSpecDocument =
        serde_yml::from_str(contents).map_err(|error| error.to_string())?;
    let mut api = document.api;
    if let Some(profile) = document.profile.as_ref() {
        expand(&mut api, profile)?;
    }
    Ok((api, document.profile))
}

/// Expand a profile into `api`. Explicit endpoints win by method and path, so
/// operators can attach pricing or override descriptions without duplicating
/// the rest of the standard surface.
pub fn expand(api: &mut ApiSpec, profile: &ApiProfile) -> Result<(), String> {
    match profile {
        ApiProfile::OpenaiCompatible { version, surfaces } => {
            inference::expand(api, version, surfaces)
        }
        ApiProfile::XtreamCodes { version, surfaces } => iptv::expand(api, version, surfaces),
    }
}

#[derive(Debug, Deserialize)]
struct ApiSpecDocument {
    #[serde(default)]
    profile: Option<ApiProfile>,
    #[serde(flatten)]
    api: ApiSpec,
}

fn append_endpoint(api: &mut ApiSpec, endpoint: &ProfileEndpoint) {
    if !has_endpoint(api, endpoint) {
        api.endpoints.push(Endpoint {
            method: endpoint.method.clone(),
            path: endpoint.path.to_string(),
            description: Some(endpoint.description.to_string()),
            resource: endpoint.resource.map(str::to_string),
            routing: None,
            metering: None,
            subscription: None,
        });
    }
}

fn has_endpoint(api: &ApiSpec, candidate: &ProfileEndpoint) -> bool {
    api.endpoints.iter().any(|endpoint| {
        method_name(&endpoint.method) == method_name(&candidate.method)
            && endpoint.path.trim_start_matches('/') == candidate.path
    })
}

fn method_name(method: &HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
    }
}
