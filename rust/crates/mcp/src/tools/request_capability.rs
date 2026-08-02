//! `request_capability` — ask the studio registry to build a capability
//! `search_catalog`/`list_catalog` couldn't find (commission-flow draft-00).
//!
//! Never auto-invoked: a single elicitation is both the pitch and the
//! consent gate — Accept submits, Decline/Cancel walks away with nothing
//! sent. The prompt is two free-form questions (what to build, what they'd
//! use today); after Accept the client's own model (MCP sampling, briefed
//! by `request_capability_brief.md`) turns those answers into the
//! structured brief — no typed form fields, no schema the user has to fit.
//! The buyer is attributed by the Solana pubkey of the local Pay wallet
//! (the key the engagement would be funded with), never prompted for.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pay_core::studios::{BudgetAmount, NewCapabilityRequest, StudioRegistry, StudioSubmission};
use rmcp::Peer;
use rmcp::model::{
    CallToolResult, Content, CreateElicitationRequestParam, CreateMessageRequestParam,
    ElicitationAction, ElicitationSchema, LoggingLevel, LoggingMessageNotificationParam,
    ProgressNotificationParam, ProgressToken, Role, SamplingMessage,
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
/// Ceiling on the client-side sampling round-trip that structures the
/// brief — local inference can be slow, but not unbounded; on timeout the
/// raw answers ship instead.
const SAMPLING_TIMEOUT: Duration = Duration::from_secs(60);
const SAMPLING_MAX_TOKENS: u32 = 600;
/// How often the in-flight status line rotates during a long stage.
const STATUS_ROTATION_INTERVAL: Duration = Duration::from_secs(4);

/// The elicitation pitch is a short YC-style hook, never a wall of text:
/// hard cap 256 chars, with the quoted need truncated so any query fits.
const PITCH_MAX_CHARS: usize = 256;
const PITCH_NEED_MAX_CHARS: usize = 48;

/// System prompt for the sampling call that structures the free-form
/// answers (see module docs).
const BRIEF_SKILL: &str = include_str!("request_capability_brief.md");

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
    progress_token: Option<ProgressToken>,
) -> Result<CallToolResult, rmcp::ErrorData> {
    let query = params.query.trim().to_string();
    if query.is_empty() {
        return Ok(super::tool_error(
            "`query` must describe the missing capability",
        ));
    }

    match run_capability_request(&peer, progress_token, &query).await {
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

/// One elicitation (pitch + two optional free-form questions, Accept =
/// consent), a sampling pass that structures the answers, then submit to
/// every registered studio and poll for quotes. Shared by [`run`] (direct
/// call) and `search_catalog`'s miss path. The wallet is resolved before
/// prompting so a missing `pay setup` fails fast instead of interviewing
/// the user and then erroring.
pub(crate) async fn run_capability_request(
    peer: &Peer<RoleServer>,
    progress_token: Option<ProgressToken>,
    query: &str,
) -> Result<CapabilityRequestOutcome, CapabilityRequestError> {
    let buyer_solana_pubkey = wallet_pubkey().map_err(CapabilityRequestError::Other)?;

    let Some(brief) = ask_to_build(peer, query).await? else {
        return Ok(CapabilityRequestOutcome::Declined);
    };

    let status = Status::new(peer.clone(), progress_token);

    // Nothing typed means nothing to extract — the query itself is the
    // whole brief, so skip the model round-trip.
    let structured = if brief.build.is_none() && brief.today.is_none() {
        StructuredBrief::default()
    } else {
        with_rotating_status(
            &status,
            &[
                "Reading your brief…",
                "Pulling out scope, comparables, and budget…",
                "Writing the request studios will quote…",
            ],
            structure_brief(peer, query, &brief),
        )
        .await
    };

    let request = NewCapabilityRequest {
        query: query.to_string(),
        product: structured.product.or_else(|| brief.build.clone()),
        monetization: structured.monetization,
        competition: if structured.competition.is_empty() {
            brief.today.clone().into_iter().collect()
        } else {
            structured.competition
        },
        budget_ceiling: structured.budget_usd.and_then(budget_from_usd),
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

    let submissions = with_rotating_status(
        &status,
        &["Pitching it to the studio network…"],
        pay_core::studios::submit_to_registry(&registry, &request, pay_core::ClientApp::Mcp),
    )
    .await
    .map_err(|e| {
        CapabilityRequestError::Other(format!("Failed to submit capability request: {e}"))
    })?;

    let results = with_rotating_status(
        &status,
        &[
            "Waiting for studios to respond…",
            "Checking for early quotes…",
        ],
        poll_for_quotes(submissions),
    )
    .await;
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
    build: Option<String>,
    today: Option<String>,
}

/// The single prompt: sell the gap, collect two free-form answers, and
/// take Accept as consent to submit. Both answers are plain text on
/// purpose — a model structures them afterwards, so the user never fights
/// a form. Returns `Ok(None)` on Decline/Cancel.
async fn ask_to_build(
    peer: &Peer<RoleServer>,
    query: &str,
) -> Result<Option<BriefInput>, CapabilityRequestError> {
    let schema = ElicitationSchema::builder()
        .optional_string_with("build", |s| {
            s.title("What do we want to build?").description(
                "Say it like you'd pitch a friend — \"an API that forecasts Solana priority fees an hour ahead\". Any detail helps: inputs, outputs, budget.",
            )
        })
        .optional_string_with("today", |s| {
            s.title("What service or app would you use today to achieve that?").description(
                "Even a clunky workaround — \"I'd eyeball Jito's dashboard\". It shows studios the bar to beat.",
            )
        })
        .title("Build something people want")
        .build()
        .map_err(|e| {
            CapabilityRequestError::Other(format!("failed to build capability-request schema: {e}"))
        })?;

    let params = CreateElicitationRequestParam {
        message: pitch(query),
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
        build: str_field(&content, "build"),
        today: str_field(&content, "today"),
    }))
}

fn pitch(query: &str) -> String {
    let need = truncate_chars(query, PITCH_NEED_MAX_CHARS);
    let pitch = format!(
        "No API in Pay does \"{need}\" yet — you just found real demand.\nStudios can build & ship it: a live API, published under you, earning on every call.\nAsking is free; nothing's charged unless you accept a quote."
    );
    debug_assert!(pitch.chars().count() <= PITCH_MAX_CHARS);
    pitch
}

/// Char-boundary-safe truncation with an ellipsis, counting chars (not
/// bytes) to match the pitch's char budget.
fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct StructuredBrief {
    product: Option<String>,
    competition: Vec<String>,
    budget_usd: Option<f64>,
    monetization: Option<String>,
}

fn supports_sampling(peer: &Peer<RoleServer>) -> bool {
    peer.peer_info()
        .is_some_and(|info| info.capabilities.sampling.is_some())
}

/// Structure the free-form answers with the client's own model (MCP
/// sampling), briefed by [`BRIEF_SKILL`]. Best-effort: returns the empty
/// brief when the client can't sample, times out, or replies with
/// something that isn't the JSON the skill asked for — the raw answers
/// still ship in that case.
async fn structure_brief(
    peer: &Peer<RoleServer>,
    query: &str,
    brief: &BriefInput,
) -> StructuredBrief {
    if !supports_sampling(peer) {
        return StructuredBrief::default();
    }
    let prompt = format!(
        "Catalog search that missed: {query}\n\nWhat do we want to build:\n{}\n\nWhat would they use today:\n{}",
        brief.build.as_deref().unwrap_or("(no answer)"),
        brief.today.as_deref().unwrap_or("(no answer)"),
    );
    let request = CreateMessageRequestParam {
        messages: vec![SamplingMessage {
            role: Role::User,
            content: Content::text(prompt),
        }],
        model_preferences: None,
        system_prompt: Some(BRIEF_SKILL.to_string()),
        include_context: None,
        temperature: None,
        max_tokens: SAMPLING_MAX_TOKENS,
        stop_sequences: None,
        metadata: None,
    };
    let Ok(Ok(result)) = tokio::time::timeout(SAMPLING_TIMEOUT, peer.create_message(request)).await
    else {
        return StructuredBrief::default();
    };
    result
        .message
        .content
        .as_text()
        .and_then(|t| parse_structured_brief(&t.text))
        .unwrap_or_default()
}

/// Tolerates fences or prose around the JSON object the skill asked for.
fn parse_structured_brief(raw: &str) -> Option<StructuredBrief> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    serde_json::from_str(raw.get(start..=end)?).ok()
}

/// Best-effort in-flight status line: MCP progress notifications when the
/// client sent a `progressToken` with the call, logging notifications
/// otherwise. Clients may ignore either — nothing here can fail the
/// request.
struct Status {
    peer: Peer<RoleServer>,
    token: Option<ProgressToken>,
    step: AtomicU64,
}

impl Status {
    fn new(peer: Peer<RoleServer>, token: Option<ProgressToken>) -> Self {
        Self {
            peer,
            token,
            step: AtomicU64::new(0),
        }
    }

    async fn send(&self, message: &str) {
        // Progress must be monotonically increasing per the MCP spec.
        let step = self.step.fetch_add(1, Ordering::Relaxed) + 1;
        match &self.token {
            Some(token) => {
                let _ = self
                    .peer
                    .notify_progress(ProgressNotificationParam {
                        progress_token: token.clone(),
                        progress: step as f64,
                        total: None,
                        message: Some(message.to_string()),
                    })
                    .await;
            }
            None => {
                let _ = self
                    .peer
                    .notify_logging_message(LoggingMessageNotificationParam {
                        level: LoggingLevel::Info,
                        logger: Some("request_capability".to_string()),
                        data: serde_json::Value::String(message.to_string()),
                    })
                    .await;
            }
        }
    }
}

/// Run `fut` while rotating through `messages` on a timer, so the user
/// sees what's happening during a long stage instead of a frozen spinner.
async fn with_rotating_status<T>(
    status: &Status,
    messages: &[&str],
    fut: impl Future<Output = T>,
) -> T {
    status.send(messages[0]).await;
    tokio::pin!(fut);
    let mut interval = tokio::time::interval(STATUS_ROTATION_INTERVAL);
    interval.tick().await; // the first tick completes immediately
    let mut next = 1usize;
    loop {
        tokio::select! {
            out = &mut fut => return out,
            _ = interval.tick() => {
                status.send(messages[next % messages.len()]).await;
                next += 1;
            }
        }
    }
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
    fn pitch_stays_short_and_multiline() {
        let short = pitch("solana priority fee forecasts");
        assert!(short.contains("solana priority fee forecasts"));
        let long = pitch(&"x".repeat(500));
        for message in [&short, &long] {
            assert!(
                message.chars().count() <= PITCH_MAX_CHARS,
                "pitch is {} chars",
                message.chars().count()
            );
            assert_eq!(message.matches('\n').count(), 2);
        }
    }

    #[test]
    fn truncate_chars_is_char_boundary_safe() {
        assert_eq!(truncate_chars("héllo", 10), "héllo");
        assert_eq!(truncate_chars("héllo wörld", 6), "héllo…");
        assert_eq!(truncate_chars("日本語のテキスト", 4), "日本語…");
    }

    #[test]
    fn parse_structured_brief_tolerates_fences_and_prose() {
        let fenced = "Here you go:\n```json\n{\"product\": \"fee forecast API\", \"competition\": [\"Jito dashboard\"], \"budget_usd\": 50}\n```";
        let brief = parse_structured_brief(fenced).unwrap();
        assert_eq!(brief.product.as_deref(), Some("fee forecast API"));
        assert_eq!(brief.competition, vec!["Jito dashboard"]);
        assert_eq!(brief.budget_usd, Some(50.0));
        assert_eq!(brief.monetization, None);

        // Partial objects deserialize with defaults; garbage does not.
        assert!(parse_structured_brief("{}").is_some());
        assert!(parse_structured_brief("no json here").is_none());
        assert!(parse_structured_brief("{not json}").is_none());
    }
}
