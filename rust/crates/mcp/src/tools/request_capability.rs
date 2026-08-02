//! `request_capability` — ask the studio registry to build a capability
//! `search_catalog`/`list_catalog` couldn't find (commission-flow draft-00).
//!
//! Never auto-invoked: a single elicitation is both the pitch and the
//! consent gate — Accept submits, Decline/Cancel walks away with nothing
//! sent. The buyer is attributed by the Solana pubkey of the local Pay
//! wallet (the key the engagement would be funded with), never prompted
//! for. v0 sends only the fields the studio's `NewRfq` wire shape accepts;
//! the richer cost-metrics brief (freshness, volume, upstream deps) lands
//! once the studio side's `brief` object ships — `NewRfq` is
//! `deny_unknown_fields`, so sending those fields today would 422.

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

/// The account whose pubkey attributes the request — same default network
/// as `get_balance`.
const WALLET_NETWORK: &str = "mainnet";
/// Mainnet USDC — `budget_usd` is denominated in it (minor units = 1e-6).
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const USDC_PER_MINOR_UNIT: f64 = 1_000_000.0;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Params {
    /// The capability the user wanted that no existing Pay provider covers.
    #[schemars(
        description = "The task or capability the user wanted that search_catalog/list_catalog found no usable provider for. The tool asks the user before anything is sent, so calling it on a suspected miss is safe."
    )]
    pub query: String,
}

/// Why a capability request didn't produce a submission. Split so callers
/// with a graceful fallback (search_catalog's plain text hint) can treat a
/// failed elicitation round-trip — commonly a client with no elicitation
/// support — differently from a real error worth surfacing.
pub(crate) enum CapabilityRequestError {
    Elicitation(String),
    Other(String),
}

impl CapabilityRequestError {
    pub(crate) fn into_message(self) -> String {
        match self {
            Self::Elicitation(message) | Self::Other(message) => message,
        }
    }
}

pub(crate) enum CapabilityRequestOutcome {
    Declined,
    Submitted(serde_json::Value),
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

    match run_capability_request(&peer, &query, 0).await {
        Ok(CapabilityRequestOutcome::Declined) => Ok(CallToolResult::success(vec![Content::text(
            "The user declined to request this capability.".to_string(),
        )])),
        Ok(CapabilityRequestOutcome::Submitted(response)) => {
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
        Err(error) => Ok(super::tool_error(error.into_message())),
    }
}

/// One elicitation (pitch + optional details/budget, Accept = consent),
/// then submit to every registered studio and poll for quotes. Shared by
/// [`run`] (direct call) and `search_catalog`'s miss path. The wallet is
/// resolved before prompting so a missing `pay setup` fails fast instead
/// of interviewing the user and then erroring.
pub(crate) async fn run_capability_request(
    peer: &Peer<RoleServer>,
    query: &str,
    weak_candidates: usize,
) -> Result<CapabilityRequestOutcome, CapabilityRequestError> {
    let buyer_solana_pubkey = wallet_pubkey().map_err(CapabilityRequestError::Other)?;

    let Some(brief) = ask_to_build(peer, query, weak_candidates).await? else {
        return Ok(CapabilityRequestOutcome::Declined);
    };

    let request = NewCapabilityRequest {
        query: query.to_string(),
        product: brief.details,
        monetization: None,
        competition: vec![],
        budget_ceiling: brief.budget_usd.and_then(budget_from_usd),
        buyer_npub: None,
        buyer_solana_pubkey: Some(buyer_solana_pubkey),
    };

    let registry = StudioRegistry::load().map_err(|e| {
        CapabilityRequestError::Other(format!("Failed to load studio registry: {e}"))
    })?;
    if registry.studios.is_empty() {
        return Err(CapabilityRequestError::Other(
            "No studios are registered in ~/.config/pay/studios.yaml.".to_string(),
        ));
    }

    let submissions =
        pay_core::studios::submit_to_registry(&registry, &request, pay_core::ClientApp::Mcp)
            .await
            .map_err(|e| {
                CapabilityRequestError::Other(format!("Failed to submit capability request: {e}"))
            })?;

    let results = poll_for_quotes(submissions).await;
    let next_step = next_step_for(&results);

    Ok(CapabilityRequestOutcome::Submitted(serde_json::json!({
        "query": query,
        "submissions": results,
        "next_step": next_step,
    })))
}

/// The Solana pubkey the request is attributed to — read-only account
/// metadata, no keypair load and no signing prompt.
fn wallet_pubkey() -> Result<String, String> {
    let accounts = pay_core::accounts::AccountsFile::load()
        .map_err(|e| format!("Failed to load Pay accounts: {e}"))?;
    let Some((_name, account)) = accounts.account_for_network(WALLET_NETWORK) else {
        return Err(format!(
            "No Pay account is configured for {WALLET_NETWORK}; run `pay setup` first — the capability request is attributed to your wallet."
        ));
    };
    account
        .pubkey
        .clone()
        .ok_or_else(|| "Pay account has no pubkey. Run `pay setup` again.".to_string())
}

struct BriefInput {
    details: Option<String>,
    budget_usd: Option<f64>,
}

/// The single prompt: sell the gap, collect optional signal, and take
/// Accept as consent to submit. Returns `Ok(None)` on Decline/Cancel.
async fn ask_to_build(
    peer: &Peer<RoleServer>,
    query: &str,
    weak_candidates: usize,
) -> Result<Option<BriefInput>, CapabilityRequestError> {
    let schema = ElicitationSchema::builder()
        .optional_string_with("details", |s| {
            s.title("What should it do?").description(
                "Anything the builders should know — inputs, outputs, must-haves. Leave empty to send your search as the brief.",
            )
        })
        .optional_number_with("budget_usd", |n| {
            n.range(0.0, 1_000_000.0)
                .title("Budget ceiling (USD)")
                .description("Rough signal for quoting — not a commitment, nothing is charged.")
        })
        .title("Let's get it built")
        .build()
        .map_err(|e| {
            CapabilityRequestError::Other(format!("failed to build capability-request schema: {e}"))
        })?;

    let params = CreateElicitationRequestParam {
        message: pitch(query, weak_candidates),
        requested_schema: schema,
    };

    let outcome = tokio::time::timeout(ELICITATION_TIMEOUT, peer.create_elicitation(params))
        .await
        .map_err(|_| {
            CapabilityRequestError::Elicitation(
                "Timed out waiting for the capability-request prompt.".to_string(),
            )
        })?
        .map_err(|e| {
            CapabilityRequestError::Elicitation(format!(
                "Could not prompt for a capability request: {e}"
            ))
        })?;

    if !matches!(outcome.action, ElicitationAction::Accept) {
        return Ok(None);
    }

    let content = outcome.content.unwrap_or_default();
    Ok(Some(BriefInput {
        details: str_field(&content, "details"),
        budget_usd: content.get("budget_usd").and_then(|v| v.as_f64()),
    }))
}

fn pitch(query: &str, weak_candidates: usize) -> String {
    let gap = if weak_candidates == 0 {
        format!("Nothing in Pay's catalog can do \"{query}\" yet — you've found a gap.")
    } else {
        format!(
            "Nothing in Pay's catalog truly fits \"{query}\" (only {weak_candidates} loose keyword matches, listed in the results) — you've found a gap."
        )
    };
    format!(
        "{gap} Want it to exist? Accept and the studio network is asked to build and deploy an API tailored to your exact need — one you can monetize once it's live. Both fields are optional. Asking is free: the request goes to studios under your Pay wallet, and nothing is charged unless you later accept a quote."
    )
}

fn budget_from_usd(usd: f64) -> Option<BudgetAmount> {
    (usd.is_finite() && usd > 0.0).then(|| BudgetAmount {
        amount: (usd * USDC_PER_MINOR_UNIT).round() as u64,
        mint: USDC_MINT.to_string(),
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

    #[test]
    fn budget_from_usd_converts_to_usdc_minor_units() {
        let budget = budget_from_usd(12.5).unwrap();
        assert_eq!(budget.amount, 12_500_000);
        assert_eq!(budget.mint, USDC_MINT);
    }

    #[test]
    fn budget_from_usd_rejects_non_positive_and_non_finite() {
        assert!(budget_from_usd(0.0).is_none());
        assert!(budget_from_usd(-3.0).is_none());
        assert!(budget_from_usd(f64::NAN).is_none());
        assert!(budget_from_usd(f64::INFINITY).is_none());
    }

    #[test]
    fn pitch_mentions_weak_matches_only_when_present() {
        let clean = pitch("solana priority fee forecasts", 0);
        assert!(clean.contains("can do"));
        assert!(!clean.contains("loose keyword"));
        let noisy = pitch("solana priority fee forecasts", 5);
        assert!(noisy.contains("5 loose keyword matches"));
        for message in [&clean, &noisy] {
            assert!(message.contains("monetize"));
            assert!(message.contains("nothing is charged"));
        }
    }
}
