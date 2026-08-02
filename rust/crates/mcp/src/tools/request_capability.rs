//! `request_capability` — ask the studio registry to build a capability
//! `search_catalog`/`list_catalog` couldn't find (commission-flow draft-00).
//!
//! Never auto-invoked: the first elicitation is consent to run the
//! interview at all, a second (independent) safety net on top of
//! `search_catalog`'s next-step text only *naming* this tool rather than
//! calling it. v0 collects only the fields the studio's `NewRfq` wire shape
//! already accepts (query/product/monetization/competition/budget_ceiling/
//! buyer_npub); the richer cost-metrics interview (freshness, volume,
//! upstream deps, WTP band) lands once the studio side adds a `brief`
//! object to `schemas/rfq.json` — `NewRfq` is `deny_unknown_fields`, so
//! sending those fields today would 422.

use std::time::Duration;

use pay_core::studios::{BudgetAmount, NewCapabilityRequest, StudioRegistry, StudioSubmission};
use rmcp::Peer;
use rmcp::model::{
    CallToolResult, Content, CreateElicitationRequestParam, ElicitationAction, ElicitationSchema,
};
use rmcp::schemars;
use rmcp::service::RoleServer;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Outer deadline for a single elicitation round-trip, matching the
/// existing auth-gate elicitation timeout (`mcp/src/auth.rs`).
const ELICITATION_TIMEOUT: Duration = Duration::from_secs(300);
/// How many times to check for a quote before telling the user to check
/// back later. Kept short — an MCP tool call shouldn't hang for the
/// arbitrary time a studio may take to review and quote an RFQ.
const QUOTE_POLL_ATTEMPTS: u32 = 3;
const QUOTE_POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Params {
    /// The capability the user wanted that no existing Pay provider covers.
    #[schemars(
        description = "The task or capability the user wanted that search_catalog/list_catalog found no usable provider for. Only call this after a real catalog miss and only when the user wants to request a new one; do not call speculatively."
    )]
    pub query: String,
}

pub async fn run(
    params: Params,
    peer: Peer<RoleServer>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let query = params.query.trim().to_string();
    if query.is_empty() {
        return Ok(super::tool_error(
            "`query` must describe the missing capability",
        ));
    }

    match ask_consent(&peer, &query).await {
        Ok(true) => {}
        Ok(false) => {
            return Ok(CallToolResult::success(vec![Content::text(
                "The user declined to request this capability.".to_string(),
            )]));
        }
        Err(message) => return Ok(super::tool_error(message)),
    }

    let brief = match ask_brief(&peer, &query).await {
        Ok(brief) => brief,
        Err(message) => return Ok(super::tool_error(message)),
    };

    let request = NewCapabilityRequest {
        query: query.clone(),
        product: brief.product,
        monetization: brief.monetization,
        competition: brief.competition,
        budget_ceiling: brief.budget_ceiling,
        buyer_npub: brief.buyer_npub,
    };

    let registry = match StudioRegistry::load() {
        Ok(registry) => registry,
        Err(e) => {
            return Ok(super::tool_error(format!(
                "Failed to load studio registry: {e}"
            )));
        }
    };
    if registry.studios.is_empty() {
        return Ok(super::tool_error(
            "No studios are registered in ~/.config/pay/studios.yaml.",
        ));
    }

    let submissions =
        match pay_core::studios::submit_to_registry(&registry, &request, pay_core::ClientApp::Mcp)
            .await
        {
            Ok(submissions) => submissions,
            Err(e) => {
                return Ok(super::tool_error(format!(
                    "Failed to submit capability request: {e}"
                )));
            }
        };

    let results = poll_for_quotes(submissions).await;
    let next_step = next_step_for(&results);

    let response = serde_json::json!({
        "query": query,
        "submissions": results,
        "next_step": next_step,
    });

    let json = match serde_json::to_string_pretty(&response) {
        Ok(json) => json,
        Err(e) => {
            return Ok(super::tool_error(format!(
                "Failed to serialize response: {e}"
            )));
        }
    };

    Ok(CallToolResult::success(vec![Content::text(json)]))
}

async fn ask_consent(peer: &Peer<RoleServer>, query: &str) -> Result<bool, String> {
    let schema = ElicitationSchema::builder()
        .required_bool("proceed")
        .build()
        .expect("required_bool registers `proceed` in properties");
    let params = CreateElicitationRequestParam {
        message: format!(
            "Pay found no existing provider for \"{query}\". Start a capability-request interview to ask the studio registry for a custom-built endpoint? This submits a public demand record (RFQ) attributed to your identity; no payment is taken yet."
        ),
        requested_schema: schema,
    };

    let outcome = tokio::time::timeout(ELICITATION_TIMEOUT, peer.create_elicitation(params))
        .await
        .map_err(|_| "Timed out waiting for capability-request consent.".to_string())?
        .map_err(|e| format!("Could not obtain capability-request consent: {e}"))?;

    Ok(matches!(outcome.action, ElicitationAction::Accept)
        && outcome
            .content
            .as_ref()
            .and_then(|v| v.get("proceed"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
}

struct Brief {
    product: Option<String>,
    monetization: Option<String>,
    competition: Vec<String>,
    budget_ceiling: Option<BudgetAmount>,
    buyer_npub: String,
}

async fn ask_brief(peer: &Peer<RoleServer>, query: &str) -> Result<Brief, String> {
    let schema = ElicitationSchema::builder()
        .required_string("buyer_npub")
        .optional_string("product")
        .optional_string("monetization")
        .optional_string("competition")
        .optional_number("budget_ceiling_amount", 0.0, 1_000_000_000.0)
        .optional_string("budget_ceiling_mint")
        .title("Capability brief")
        .description(format!(
            "Tell the studio what you need built for: \"{query}\""
        ))
        .build()
        .map_err(|e| format!("failed to build brief schema: {e}"))?;

    let params = CreateElicitationRequestParam {
        message: "Describe what you want built. `buyer_npub` is your Nostr identity (e.g. your Buzz npub) — the studio attributes the demand record to it. Everything else is optional signal that helps the studio quote.".to_string(),
        requested_schema: schema,
    };

    let outcome = tokio::time::timeout(ELICITATION_TIMEOUT, peer.create_elicitation(params))
        .await
        .map_err(|_| "Timed out waiting for the capability brief.".to_string())?
        .map_err(|e| format!("Could not obtain the capability brief: {e}"))?;

    match outcome.action {
        ElicitationAction::Accept => {}
        ElicitationAction::Decline => {
            return Err("The user declined to provide a capability brief.".to_string());
        }
        ElicitationAction::Cancel => {
            return Err("The user cancelled the capability brief.".to_string());
        }
    }

    let content = outcome.content.unwrap_or_default();

    let buyer_npub = str_field(&content, "buyer_npub").unwrap_or_default();
    if buyer_npub.is_empty() {
        return Err("`buyer_npub` is required to attribute the capability request.".to_string());
    }

    let product = str_field(&content, "product");
    let monetization = str_field(&content, "monetization");
    let competition = str_field(&content, "competition")
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let budget_amount = content
        .get("budget_ceiling_amount")
        .and_then(|v| v.as_f64());
    let budget_mint = str_field(&content, "budget_ceiling_mint");
    let budget_ceiling = match (budget_amount, budget_mint) {
        (Some(amount), Some(mint)) if amount > 0.0 => Some(BudgetAmount {
            amount: amount.round() as u64,
            mint,
        }),
        _ => None,
    };

    Ok(Brief {
        product,
        monetization,
        competition,
        budget_ceiling,
        buyer_npub,
    })
}

fn str_field(content: &serde_json::Value, key: &str) -> Option<String> {
    content
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[derive(Debug, Serialize)]
struct SubmissionResult {
    studio: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rfq_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quote: Option<serde_json::Value>,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn poll_for_quotes(submissions: Vec<StudioSubmission>) -> Vec<SubmissionResult> {
    let mut results = Vec::with_capacity(submissions.len());
    for submission in submissions {
        results.push(poll_one(submission).await);
    }
    results
}

async fn poll_one(submission: StudioSubmission) -> SubmissionResult {
    let StudioSubmission {
        studio,
        rfq_url,
        rfq,
        error,
    } = submission;

    let Some(rfq) = rfq else {
        return SubmissionResult {
            studio,
            rfq_id: None,
            quote: None,
            status: "failed",
            error,
        };
    };

    let Some(id) = rfq.get("id").and_then(|v| v.as_str()).map(str::to_string) else {
        return SubmissionResult {
            studio,
            rfq_id: None,
            quote: None,
            status: "failed",
            error: Some("studio response was missing the rfq id".to_string()),
        };
    };

    for attempt in 0..QUOTE_POLL_ATTEMPTS {
        match pay_core::studios::poll_quote(pay_core::ClientApp::Mcp, &rfq_url, &id).await {
            Ok(Some(quote)) => {
                return SubmissionResult {
                    studio,
                    rfq_id: Some(id),
                    quote: Some(quote),
                    status: "quoted",
                    error: None,
                };
            }
            Ok(None) => {
                if attempt + 1 < QUOTE_POLL_ATTEMPTS {
                    tokio::time::sleep(QUOTE_POLL_INTERVAL).await;
                }
            }
            Err(e) => {
                return SubmissionResult {
                    studio,
                    rfq_id: Some(id),
                    quote: None,
                    status: "failed",
                    error: Some(e.to_string()),
                };
            }
        }
    }

    SubmissionResult {
        studio,
        rfq_id: Some(id),
        quote: None,
        status: "pending",
        error: None,
    }
}

fn next_step_for(results: &[SubmissionResult]) -> &'static str {
    if results.iter().all(|r| r.status == "failed") {
        "Every studio was unreachable or rejected the submission; show the user the errors and ask before retrying."
    } else if results.iter().any(|r| r.status == "quoted") {
        "A studio returned a quote. Present price, timeline, and terms to the user before accepting; do not fund automatically."
    } else {
        "No studio has quoted yet. Tell the user the capability request was submitted and to check back later; do not resubmit the same query."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_reject_empty_query() {
        let params: Params = serde_json::from_str(r#"{"query": ""}"#).unwrap();
        assert!(params.query.trim().is_empty());
    }

    #[test]
    fn next_step_all_failed() {
        let results = vec![SubmissionResult {
            studio: "scarce".to_string(),
            rfq_id: None,
            quote: None,
            status: "failed",
            error: Some("connection refused".to_string()),
        }];
        assert!(next_step_for(&results).contains("unreachable"));
    }

    #[test]
    fn next_step_quoted_takes_priority() {
        let results = vec![
            SubmissionResult {
                studio: "a".to_string(),
                rfq_id: Some("1".to_string()),
                quote: None,
                status: "pending",
                error: None,
            },
            SubmissionResult {
                studio: "b".to_string(),
                rfq_id: Some("2".to_string()),
                quote: Some(serde_json::json!({"price": 1})),
                status: "quoted",
                error: None,
            },
        ];
        assert!(next_step_for(&results).contains("quote"));
    }

    #[test]
    fn next_step_pending_when_nothing_failed_or_quoted() {
        let results = vec![SubmissionResult {
            studio: "scarce".to_string(),
            rfq_id: Some("1".to_string()),
            quote: None,
            status: "pending",
            error: None,
        }];
        assert!(next_step_for(&results).contains("check back later"));
    }

    #[test]
    fn str_field_trims_and_treats_blank_as_absent() {
        let content = serde_json::json!({"a": "  hello  ", "b": "   ", "c": 3});
        assert_eq!(str_field(&content, "a").as_deref(), Some("hello"));
        assert_eq!(str_field(&content, "b"), None);
        assert_eq!(str_field(&content, "c"), None);
        assert_eq!(str_field(&content, "missing"), None);
    }
}
