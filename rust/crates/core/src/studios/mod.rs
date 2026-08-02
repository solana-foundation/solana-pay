//! Studio registry — v0 static config naming which studios receive RFQ
//! fan-out from the MCP `request_capability` tool (commission-flow
//! draft-00, concrete delta 3). One entry per studio; `~/.config/pay/studios.yaml`
//! overrides the shipped default so a local `scarced` dev instance can stand
//! in for the production endpoint during development.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{ClientApp, Error, Result};

const STUDIOS_CONFIG_FILE: &str = "~/.config/pay/studios.yaml";

const DEFAULT_STUDIO_NAME: &str = "scarce";
const DEFAULT_RFQ_URL: &str = "https://scarce.sh/api/v1/rfqs";

const SUBMIT_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_TIMEOUT: Duration = Duration::from_secs(10);

/// One studio the registry will fan an RFQ out to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Studio {
    /// Display name (e.g. "scarce").
    pub name: String,
    /// `POST` target that accepts the `NewCapabilityRequest` wire body (mirrors
    /// `scarce-studio`'s `studio-types::NewRfq` / `schemas/rfq.json`) and
    /// returns the captured RFQ record.
    pub rfq_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StudioRegistry {
    #[serde(default)]
    pub studios: Vec<Studio>,
}

impl Default for StudioRegistry {
    fn default() -> Self {
        Self {
            studios: vec![Studio {
                name: DEFAULT_STUDIO_NAME.to_string(),
                rfq_url: DEFAULT_RFQ_URL.to_string(),
            }],
        }
    }
}

impl StudioRegistry {
    pub fn load() -> Result<Self> {
        let path = config_path();
        if !path.exists()
            || std::fs::read_to_string(&path)
                .map(|raw| raw.trim().is_empty())
                .unwrap_or(true)
        {
            let cfg = Self::default();
            let _ = cfg.save(); // persist so the user can see/edit it
            return Ok(cfg);
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
        serde_yml::from_str(&raw)
            .map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Config(format!("mkdir: {e}")))?;
        }
        let yaml =
            serde_yml::to_string(self).map_err(|e| Error::Config(format!("serialize: {e}")))?;
        std::fs::write(&path, yaml)
            .map_err(|e| Error::Config(format!("write {}: {e}", path.display())))
    }
}

fn config_path() -> PathBuf {
    PathBuf::from(shellexpand::tilde(STUDIOS_CONFIG_FILE).into_owned())
}

/// Wire shape POSTed to a studio's `rfq_url`. Kept as a plain DTO here
/// rather than a cross-repo dependency on `scarce-studio`'s `studio-types`
/// crate; a field mismatch surfaces as a 422 from the studio, which
/// [`submit_to_registry`] reports verbatim rather than papering over.
#[derive(Debug, Clone, Serialize)]
pub struct NewCapabilityRequest {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monetization: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub competition: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_ceiling: Option<BudgetAmount>,
    /// Buyer identity, Nostr side. The studio requires at least one of
    /// `buyer_npub` / `buyer_solana_pubkey`; the MCP intake path attributes
    /// with the Solana key the engagement would be funded with and never
    /// collects an npub.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer_npub: Option<String>,
    /// Buyer identity, Solana side — the local Pay wallet's pubkey.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub buyer_solana_pubkey: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BudgetAmount {
    pub amount: u64,
    pub mint: String,
}

/// Outcome of POSTing a capability-request RFQ to one studio.
#[derive(Debug, Clone, Serialize)]
pub struct StudioSubmission {
    pub studio: String,
    pub rfq_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rfq: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// POST `request` to every registered studio. Independent per studio —
/// one being unreachable or rejecting the submission never fails the
/// others (commission-flow draft-00 step 3: "quotes return by deadline or
/// silently decline").
pub async fn submit_to_registry(
    registry: &StudioRegistry,
    request: &NewCapabilityRequest,
    client_app: ClientApp,
) -> Result<Vec<StudioSubmission>> {
    let client = reqwest::Client::builder()
        .timeout(SUBMIT_TIMEOUT)
        .user_agent(client_app.user_agent())
        .build()
        .map_err(|e| Error::Config(format!("http client: {e}")))?;

    let mut submissions = Vec::with_capacity(registry.studios.len());
    for studio in &registry.studios {
        submissions.push(submit_one(&client, studio, request).await);
    }
    Ok(submissions)
}

async fn submit_one(
    client: &reqwest::Client,
    studio: &Studio,
    request: &NewCapabilityRequest,
) -> StudioSubmission {
    let base = StudioSubmission {
        studio: studio.name.clone(),
        rfq_url: studio.rfq_url.clone(),
        rfq: None,
        error: None,
    };
    match client.post(&studio.rfq_url).json(request).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(rfq) => StudioSubmission {
                rfq: Some(rfq),
                ..base
            },
            Err(e) => StudioSubmission {
                error: Some(format!("invalid response body: {e}")),
                ..base
            },
        },
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            StudioSubmission {
                error: Some(format!("{status}: {body}")),
                ..base
            }
        }
        Err(e) => StudioSubmission {
            error: Some(e.to_string()),
            ..base
        },
    }
}

/// Poll one studio's free quote-status read for `rfq_id`, derived from
/// `rfq_url`'s base (`.../api/v1/rfqs` → `.../api/v1/rfqs/{id}/quote`).
/// Returns `Ok(None)` while the studio hasn't quoted yet (404).
pub async fn poll_quote(
    client_app: ClientApp,
    rfq_url: &str,
    rfq_id: &str,
) -> Result<Option<serde_json::Value>> {
    let client = reqwest::Client::builder()
        .timeout(POLL_TIMEOUT)
        .user_agent(client_app.user_agent())
        .build()
        .map_err(|e| Error::Config(format!("http client: {e}")))?;
    let quote_url = format!("{}/{}/quote", rfq_url.trim_end_matches('/'), rfq_id);
    let resp = client
        .get(&quote_url)
        .send()
        .await
        .map_err(|e| Error::Config(format!("fetch {quote_url}: {e}")))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(Error::Config(format!(
            "{quote_url} returned {}",
            resp.status()
        )));
    }
    resp.json()
        .await
        .map(Some)
        .map_err(|e| Error::Config(format!("parse {quote_url}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_has_scarce_entry() {
        let registry = StudioRegistry::default();
        assert_eq!(registry.studios.len(), 1);
        assert_eq!(registry.studios[0].name, DEFAULT_STUDIO_NAME);
        assert_eq!(registry.studios[0].rfq_url, DEFAULT_RFQ_URL);
    }

    #[test]
    fn new_capability_request_omits_absent_optional_fields() {
        let request = NewCapabilityRequest {
            query: "solana priority fee forecast api".to_string(),
            product: None,
            monetization: None,
            competition: vec![],
            budget_ceiling: None,
            buyer_npub: None,
            buyer_solana_pubkey: Some("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T".to_string()),
        };
        let json = serde_json::to_value(&request).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("product"));
        assert!(!obj.contains_key("monetization"));
        assert!(!obj.contains_key("competition"));
        assert!(!obj.contains_key("budget_ceiling"));
        // Absent identity halves must be omitted, not serialized as null —
        // the studio's `NewRfq` treats explicit null as a present-but-invalid
        // value for the schema regex.
        assert!(!obj.contains_key("buyer_npub"));
        assert_eq!(
            obj["buyer_solana_pubkey"],
            "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T"
        );
        assert_eq!(obj["query"], "solana priority fee forecast api");
    }

    #[test]
    fn new_capability_request_includes_present_optional_fields() {
        let request = NewCapabilityRequest {
            query: "q".to_string(),
            product: Some("a live forecast endpoint".to_string()),
            monetization: Some("per-call".to_string()),
            competition: vec!["incumbent/api".to_string()],
            budget_ceiling: Some(BudgetAmount {
                amount: 10_000_000,
                mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            }),
            buyer_npub: Some(
                "npub1cscv4empnwmfyurd6utlwmq3h3dzpesjyhtttt6rk69hndk9w0nqr65xpy".to_string(),
            ),
            buyer_solana_pubkey: None,
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(
            json["buyer_npub"],
            "npub1cscv4empnwmfyurd6utlwmq3h3dzpesjyhtttt6rk69hndk9w0nqr65xpy"
        );
        assert_eq!(json["product"], "a live forecast endpoint");
        assert_eq!(json["competition"][0], "incumbent/api");
        assert_eq!(json["budget_ceiling"]["amount"], 10_000_000);
        assert_eq!(
            json["budget_ceiling"]["mint"],
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        );
    }
}
