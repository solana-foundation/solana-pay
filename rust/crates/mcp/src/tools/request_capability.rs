//! `request_capability` — refine a catalog miss locally, then submit a
//! quote-ready RFQ to the configured studio registry.
//!
//! This is one resumable MCP tool call. MRTR keeps elicitation, local-model
//! refinement, read-only catalog research, validation, and submission inside
//! the original `tools/call`; no second tool call or hidden ACP session is
//! required.

#![allow(deprecated)] // Sampling is the standard MRTR inference input in MCP 2026-07-28.

use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pay_core::studios::{
    BudgetAmount, CapabilityBrief, NewCapabilityRequest, StudioRegistry, StudioSubmission,
};
use rand::RngCore;
use rmcp::Peer;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, CreateMessageRequest,
    CreateMessageRequestParams, CreateMessageResult, ElicitRequest, ElicitRequestParams,
    ElicitResult, ElicitationAction, ElicitationSchema, InputRequest, InputRequiredResult,
    InputResponses, LoggingLevel, LoggingMessageNotificationParam, ProgressNotificationParam,
    ProgressToken, RequestStateCodec, SamplingMessage, SamplingMessageContentBlock, SealOptions,
    Tool, ToolAnnotations, ToolChoice,
};
use rmcp::schemars;
use rmcp::service::RoleServer;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const STATE_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_REFINEMENT_ROUNDS: u8 = 6;
const SAMPLING_MAX_TOKENS: u32 = 1_600;
const QUOTE_POLL_ATTEMPTS: u32 = 3;
const QUOTE_POLL_INTERVAL: Duration = Duration::from_secs(2);
const STATUS_ROTATION_INTERVAL: Duration = Duration::from_secs(4);
const PITCH_MAX_CHARS: usize = 256;
const PITCH_NEED_MAX_CHARS: usize = 48;
const BRIEF_SKILL: &str = include_str!("request_capability_brief.md");
const WALLET_NETWORK: &str = "mainnet";
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const USDC_PER_MINOR_UNIT: f64 = 1_000_000.0;
const INTAKE_RESPONSE: &str = "capability_intake";
const REFINEMENT_RESPONSE: &str = "capability_refinement";
const RESEARCH_SEARCH_TOOL: &str = "search_pay_catalog";
const RESEARCH_ENTRY_TOOL: &str = "inspect_pay_catalog_entry";

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Params {
    /// The capability the user wanted that no existing Pay provider covers.
    #[schemars(
        description = "The task or capability the user wanted that search_catalog/list_catalog found no usable provider for. The tool itself asks for consent and completes refinement before anything reaches a studio."
    )]
    pub query: String,
}

#[derive(Clone)]
pub struct MrtrState {
    codec: RequestStateCodec,
    consumed: Arc<Mutex<HashSet<String>>>,
}

impl Default for MrtrState {
    fn default() -> Self {
        let mut key = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self {
            codec: RequestStateCodec::new(key),
            consumed: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FlowState {
    id: String,
    query: String,
    buyer_solana_pubkey: String,
    stage: Stage,
    build: Option<String>,
    today: Option<String>,
    messages: Vec<SamplingMessage>,
    refinement_round: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Stage {
    AwaitingIntake,
    Refining,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RefinedCapability {
    product: String,
    #[serde(default)]
    monetization: Option<String>,
    #[serde(default)]
    competition: Vec<String>,
    #[serde(default)]
    budget_usd: Option<f64>,
    brief: CapabilityBrief,
    #[serde(default)]
    sources: Vec<ResearchSource>,
    #[serde(default)]
    assumptions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ResearchSource {
    label: String,
    #[serde(default)]
    url: Option<String>,
    finding: String,
}

impl RefinedCapability {
    fn validation_errors(&self) -> Vec<String> {
        let mut errors = self.brief.validation_errors();
        if self.product.trim().is_empty() {
            errors.push("product must be non-empty".to_string());
        }
        for (index, value) in self.competition.iter().enumerate() {
            if value.trim().is_empty() {
                errors.push(format!("competition[{index}] must be non-empty"));
            }
        }
        if self
            .budget_usd
            .is_some_and(|value| !value.is_finite() || value <= 0.0)
        {
            errors.push("budget_usd must be a positive finite number when present".to_string());
        }
        for (index, source) in self.sources.iter().enumerate() {
            if source.label.trim().is_empty() {
                errors.push(format!("sources[{index}].label must be non-empty"));
            }
            if source.finding.trim().is_empty() {
                errors.push(format!("sources[{index}].finding must be non-empty"));
            }
        }
        errors
    }
}

/// Drive one MRTR round. The caller must pass the complete `tools/call`
/// params because the generated rmcp router intentionally strips the echoed
/// `requestState` and `inputResponses` before invoking a tool method.
pub async fn run_mrtr(
    request: CallToolRequestParams,
    peer: Peer<RoleServer>,
    state: &MrtrState,
) -> Result<CallToolResponse, rmcp::ErrorData> {
    let query = match parse_query(&request) {
        Ok(query) => query,
        Err(message) => return Ok(tool_error(message).into()),
    };
    if query.is_empty() {
        return Ok(tool_error("`query` must describe the missing capability").into());
    }
    let buyer_solana_pubkey = match wallet_pubkey() {
        Ok(pubkey) => pubkey,
        Err(message) => return Ok(tool_error(message).into()),
    };
    run_mrtr_for_wallet(request, Some(peer), state, query, buyer_solana_pubkey).await
}

async fn run_mrtr_for_wallet(
    request: CallToolRequestParams,
    peer: Option<Peer<RoleServer>>,
    state: &MrtrState,
    query: String,
    buyer_solana_pubkey: String,
) -> Result<CallToolResponse, rmcp::ErrorData> {
    let associated_data = associated_data(&request.name, &query, &buyer_solana_pubkey);
    let progress_token = request
        .meta
        .as_ref()
        .and_then(|meta| meta.get_progress_token());

    let Some(sealed) = request.request_state.as_deref() else {
        if request.input_responses.is_some() {
            return Ok(tool_error("MRTR inputResponses were provided without requestState").into());
        }
        let flow = FlowState {
            id: random_id(),
            query,
            buyer_solana_pubkey,
            stage: Stage::AwaitingIntake,
            build: None,
            today: None,
            messages: Vec::new(),
            refinement_round: 0,
        };
        return input_required(
            state,
            &associated_data,
            &flow,
            INTAKE_RESPONSE,
            intake_request(&flow.query),
        );
    };

    let mut flow: FlowState = match state
        .codec
        .open_json_with(sealed, associated_data.as_bytes())
    {
        Ok(flow) => flow,
        Err(error) => {
            return Ok(tool_error(format!(
                "Capability refinement state is invalid or expired: {error}. Start the request again."
            ))
            .into());
        }
    };
    if flow.query != query || flow.buyer_solana_pubkey != buyer_solana_pubkey {
        return Ok(tool_error(
            "Capability refinement state does not match this tool call or Pay wallet.",
        )
        .into());
    }
    let responses = match request.input_responses.as_ref() {
        Some(responses) => responses,
        None => return Ok(tool_error("MRTR retry is missing inputResponses").into()),
    };

    match flow.stage {
        Stage::AwaitingIntake => {
            let response: ElicitResult = match response_as(responses, INTAKE_RESPONSE) {
                Ok(response) => response,
                Err(message) => return Ok(tool_error(message).into()),
            };
            if !matches!(response.action, ElicitationAction::Accept) {
                return Ok(CallToolResult::success(vec![ContentBlock::text(
                    "The user declined to request this capability.",
                )])
                .into());
            }
            let content = response.content.unwrap_or_default();
            flow.build = str_field(&content, "build");
            flow.today = str_field(&content, "today");
            flow.stage = Stage::Refining;
            flow.messages = vec![SamplingMessage::user_text(refinement_seed(&flow))];
            input_required(
                state,
                &associated_data,
                &flow,
                REFINEMENT_RESPONSE,
                sampling_request(&flow),
            )
        }
        Stage::Refining => {
            let response: CreateMessageResult = match response_as(responses, REFINEMENT_RESPONSE) {
                Ok(response) => response,
                Err(message) => return Ok(tool_error(message).into()),
            };
            if let Err(message) = response.validate() {
                return Ok(
                    tool_error(format!("Invalid local refinement response: {message}")).into(),
                );
            }
            flow.messages.push(response.message.clone());

            let tool_uses: Vec<_> = response
                .message
                .content
                .iter()
                .filter_map(SamplingMessageContentBlock::as_tool_use)
                .cloned()
                .collect();
            if !tool_uses.is_empty() {
                if flow.refinement_round >= MAX_REFINEMENT_ROUNDS {
                    return Ok(round_limit_error().into());
                }
                let mut results = Vec::with_capacity(tool_uses.len());
                for tool_use in tool_uses {
                    let content = execute_research_tool(&tool_use.name, &tool_use.input).await;
                    results.push(SamplingMessageContentBlock::tool_result(
                        tool_use.id,
                        vec![ContentBlock::text(content)],
                    ));
                }
                flow.messages.push(SamplingMessage::new_multiple(
                    rmcp::model::Role::User,
                    results,
                ));
                flow.refinement_round += 1;
                return input_required(
                    state,
                    &associated_data,
                    &flow,
                    REFINEMENT_RESPONSE,
                    sampling_request(&flow),
                );
            }

            let raw = response
                .message
                .content
                .iter()
                .filter_map(SamplingMessageContentBlock::as_text)
                .map(|text| text.text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let refined = parse_refined_capability(&raw);
            let validation = match refined {
                Ok(refined) => {
                    let errors = refined.validation_errors();
                    if errors.is_empty() {
                        Ok(refined)
                    } else {
                        Err(errors)
                    }
                }
                Err(message) => Err(vec![message]),
            };
            let refined = match validation {
                Ok(refined) => refined,
                Err(errors) => {
                    if flow.refinement_round >= MAX_REFINEMENT_ROUNDS {
                        return Ok(round_limit_error().into());
                    }
                    flow.messages.push(SamplingMessage::user_text(format!(
                        "The candidate brief failed local validation. Correct every issue and return the complete JSON object again:\n- {}",
                        errors.join("\n- ")
                    )));
                    flow.refinement_round += 1;
                    return input_required(
                        state,
                        &associated_data,
                        &flow,
                        REFINEMENT_RESPONSE,
                        sampling_request(&flow),
                    );
                }
            };

            let registry =
                match prepare_submission_registry(state, &flow.id, StudioRegistry::load()) {
                    Ok(registry) => registry,
                    Err(error) => return Ok(error.into()),
                };
            let Some(peer) = peer else {
                return Ok(
                    tool_error("MRTR test flow reached studio submission without a peer").into(),
                );
            };
            submit_refined(flow, refined, registry, peer, progress_token).await
        }
    }
}

fn parse_query(request: &CallToolRequestParams) -> Result<String, String> {
    let arguments = request.arguments.clone().unwrap_or_default();
    if request.name == "request_capability" {
        let params: Params = serde_json::from_value(serde_json::Value::Object(arguments))
            .map_err(|error| format!("Invalid request_capability parameters: {error}"))?;
        return Ok(params.query.trim().to_string());
    }
    arguments
        .get("query")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|query| !query.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "`query` must describe the missing capability".to_string())
}

fn input_required(
    state: &MrtrState,
    associated_data: &str,
    flow: &FlowState,
    key: &str,
    request: InputRequest,
) -> Result<CallToolResponse, rmcp::ErrorData> {
    let sealed = state
        .codec
        .seal_json_with(
            flow,
            &SealOptions::new()
                .associated_data(associated_data.as_bytes())
                .ttl(STATE_TTL),
        )
        .map_err(|error| rmcp::ErrorData::internal_error(error.to_string(), None))?;
    let mut requests = BTreeMap::new();
    requests.insert(key.to_string(), request);
    Ok(InputRequiredResult::new(Some(requests), Some(sealed)).into())
}

fn intake_request(query: &str) -> InputRequest {
    let schema = ElicitationSchema::builder()
        .optional_string_with("build", |field| {
            field.title("What do we want to build?").description(
                "Say it like you'd pitch a friend — “an API that forecasts Solana priority fees an hour ahead.” Any detail helps: inputs, outputs, budget.",
            )
        })
        .optional_string_with("today", |field| {
            field.title("What would you use today?").description(
                "Even a clunky workaround — “I'd eyeball Jito's dashboard.” It shows the studios the bar to beat.",
            )
        })
        .title("Build something people want")
        .build()
        .expect("static capability intake schema is valid");
    InputRequest::Elicitation(ElicitRequest::new(
        ElicitRequestParams::FormElicitationParams {
            meta: None,
            message: pitch(query),
            requested_schema: schema,
        },
    ))
}

fn sampling_request(flow: &FlowState) -> InputRequest {
    let params = CreateMessageRequestParams::new(flow.messages.clone(), SAMPLING_MAX_TOKENS)
        .with_system_prompt(BRIEF_SKILL)
        .with_tools(research_tools())
        .with_tool_choice(ToolChoice::auto());
    InputRequest::CreateMessage(CreateMessageRequest::new(params))
}

fn refinement_seed(flow: &FlowState) -> String {
    let schema = serde_json::to_string_pretty(&schemars::schema_for!(RefinedCapability))
        .expect("RefinedCapability schema serializes");
    format!(
        "Catalog search that missed:\n{}\n\nWhat the user wants to build:\n{}\n\nWhat they would use today:\n{}\n\nReturn one object matching this exact JSON Schema:\n{}",
        flow.query,
        flow.build
            .as_deref()
            .unwrap_or("(no answer — infer conservatively from the query)"),
        flow.today
            .as_deref()
            .unwrap_or("(no answer — record unknowns as assumptions)"),
        schema,
    )
}

fn research_tools() -> Vec<Tool> {
    let annotations = ToolAnnotations::new()
        .read_only(true)
        .destructive(false)
        .idempotent(true)
        .open_world(false);
    vec![
        Tool::new(
            RESEARCH_SEARCH_TOOL,
            "Search the local Pay catalog to confirm this capability is missing and identify adjacent services. This performs no paid API call.",
            schema_object(serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": { "query": { "type": "string", "minLength": 1 } },
                "required": ["query"]
            })),
        )
        .with_annotations(annotations.clone()),
        Tool::new(
            RESEARCH_ENTRY_TOOL,
            "Inspect one local Pay catalog entry, including its declared endpoints and pricing. This performs no paid API call.",
            schema_object(serde_json::json!({
                "type": "object",
                "additionalProperties": false,
                "properties": { "fqn": { "type": "string", "minLength": 1 } },
                "required": ["fqn"]
            })),
        )
        .with_annotations(annotations),
    ]
}

fn schema_object(value: serde_json::Value) -> rmcp::model::JsonObject {
    value
        .as_object()
        .expect("static schema is an object")
        .clone()
}

async fn execute_research_tool(name: &str, input: &rmcp::model::JsonObject) -> String {
    let catalog = match pay_core::skills::load_skills_for(pay_core::ClientApp::Mcp).await {
        Ok(catalog) => catalog,
        Err(error) => return format!("research tool failed to load the Pay catalog: {error}"),
    };
    match name {
        RESEARCH_SEARCH_TOOL => {
            let Some(query) = input.get("query").and_then(|value| value.as_str()) else {
                return "research tool error: `query` must be a non-empty string".to_string();
            };
            let ranked = pay_core::skills::search_services_ranked(&catalog, query, None, 5);
            capped_json(&serde_json::json!({ "query": query, "candidates": ranked }))
        }
        RESEARCH_ENTRY_TOOL => {
            let Some(fqn) = input.get("fqn").and_then(|value| value.as_str()) else {
                return "research tool error: `fqn` must be a non-empty string".to_string();
            };
            match catalog
                .providers
                .iter()
                .find(|service| service.fqn.eq_ignore_ascii_case(fqn))
            {
                Some(service) => capped_json(service),
                None => format!("No Pay catalog entry named `{fqn}` exists."),
            }
        }
        other => format!(
            "research tool `{other}` is not allowed; use {RESEARCH_SEARCH_TOOL} or {RESEARCH_ENTRY_TOOL}"
        ),
    }
}

fn capped_json(value: &impl Serialize) -> String {
    const MAX_CHARS: usize = 12_000;
    match serde_json::to_string_pretty(value) {
        Ok(value) => truncate_chars(&value, MAX_CHARS),
        Err(error) => format!("research result serialization failed: {error}"),
    }
}

fn parse_refined_capability(raw: &str) -> Result<RefinedCapability, String> {
    let value: serde_json::Value = serde_json::from_str(raw.trim())
        .map_err(|error| format!("refinement output is not valid JSON: {error}"))?;
    reject_tagged_variant_extras(&value, "freshness")?;
    reject_tagged_variant_extras(&value, "state")?;
    serde_json::from_value(value)
        .map_err(|error| format!("refinement output does not match the required schema: {error}"))
}

/// Serde's internally tagged enums accept unknown variant fields even when a
/// surrounding struct denies unknowns. Enforce the strict wire boundary
/// explicitly for the two tagged Brief fields.
fn reject_tagged_variant_extras(value: &serde_json::Value, field: &str) -> Result<(), String> {
    let Some(object) = value
        .get("brief")
        .and_then(|brief| brief.get(field))
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };
    let kind = object.get("kind").and_then(serde_json::Value::as_str);
    let allowed: &[&str] = match (field, kind) {
        ("freshness", Some("realtime")) | ("state", Some("none" | "cache")) => &["kind"],
        ("freshness", Some("cached")) => &["kind", "ttl_seconds"],
        ("freshness", Some("scheduled")) => &["kind", "cron"],
        ("state", Some("durable")) => &["kind", "gib"],
        _ => return Ok(()), // serde reports a missing or unknown tag precisely.
    };
    let extras: Vec<_> = object
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .cloned()
        .collect();
    if extras.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "brief.{field} contains unknown field(s): {}",
            extras.join(", ")
        ))
    }
}

fn response_as<T: for<'de> Deserialize<'de>>(
    responses: &InputResponses,
    key: &str,
) -> Result<T, String> {
    let value = responses
        .get(key)
        .ok_or_else(|| format!("MRTR retry is missing the `{key}` response"))?;
    serde_json::from_value(value.clone())
        .map_err(|error| format!("MRTR `{key}` response is invalid: {error}"))
}

fn associated_data(tool: &str, query: &str, pubkey: &str) -> String {
    format!("tools/call:{tool}\0wallet:{pubkey}\0query:{query}")
}

fn random_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn consume_once(state: &MrtrState, id: &str) -> bool {
    state
        .consumed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(id.to_string())
}

fn prepare_submission_registry(
    state: &MrtrState,
    flow_id: &str,
    registry: pay_core::Result<StudioRegistry>,
) -> std::result::Result<StudioRegistry, CallToolResult> {
    let registry =
        registry.map_err(|error| tool_error(format!("Failed to load studio registry: {error}")))?;
    if registry.studios.is_empty() {
        return Err(tool_error(
            "No studios are registered in ~/.config/pay/studios.yaml.",
        ));
    }
    if !consume_once(state, flow_id) {
        return Err(tool_error(
            "This capability refinement was already submitted or attempted; start a new request instead of replaying it.",
        ));
    }
    Ok(registry)
}

fn round_limit_error() -> CallToolResult {
    tool_error(format!(
        "Local capability refinement did not produce a valid brief within {MAX_REFINEMENT_ROUNDS} rounds. Nothing was sent to a studio."
    ))
}

fn tool_error(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

async fn submit_refined(
    flow: FlowState,
    refined: RefinedCapability,
    registry: StudioRegistry,
    peer: Peer<RoleServer>,
    progress_token: Option<ProgressToken>,
) -> Result<CallToolResponse, rmcp::ErrorData> {
    let request = NewCapabilityRequest {
        query: flow.query.clone(),
        product: Some(refined.product.clone()),
        monetization: refined.monetization.clone(),
        competition: refined.competition.clone(),
        budget_ceiling: refined.budget_usd.and_then(budget_from_usd),
        buyer_npub: None,
        buyer_solana_pubkey: Some(flow.buyer_solana_pubkey),
        brief: Some(refined.brief.clone()),
    };
    let status = Status::new(peer, progress_token);
    let submissions = match with_rotating_status(
        &status,
        &["Sending the quote-ready brief to studios…"],
        pay_core::studios::submit_to_registry(&registry, &request, pay_core::ClientApp::Mcp),
    )
    .await
    {
        Ok(submissions) => submissions,
        Err(error) => {
            return Ok(tool_error(format!("Failed to submit capability request: {error}")).into());
        }
    };
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
    let response = serde_json::json!({
        "query": flow.query,
        "refinement": {
            "product": refined.product,
            "brief": refined.brief,
            "sources": refined.sources,
            "assumptions": refined.assumptions,
        },
        "submissions": results,
        "next_step": next_step,
    });
    Ok(CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&response).map_err(|error| {
            rmcp::ErrorData::internal_error(format!("failed to serialize response: {error}"), None)
        })?,
    )])
    .into())
}

fn wallet_pubkey() -> Result<String, String> {
    let accounts = pay_core::accounts::AccountsFile::load()
        .map_err(|error| format!("Failed to load Pay accounts: {error}"))?;
    let Some((_name, account)) = accounts.account_for_network(WALLET_NETWORK) else {
        return Err(format!(
            "No Pay account is configured for {WALLET_NETWORK}; run `pay setup` first."
        ));
    };
    account
        .pubkey
        .clone()
        .ok_or_else(|| "Pay account has no pubkey. Run `pay setup` again.".to_string())
}

fn pitch(query: &str) -> String {
    let need = truncate_chars(query, PITCH_NEED_MAX_CHARS);
    let pitch = format!(
        "No API in Pay does \"{need}\" yet — you just found real demand.\nStudios can build & ship it: a live API, published under you, earning on every call.\nAsking is free; nothing's charged unless you accept a quote."
    );
    debug_assert!(pitch.chars().count() <= PITCH_MAX_CHARS);
    pitch
}

fn truncate_chars(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut output: String = value.chars().take(max.saturating_sub(1)).collect();
    output.push('…');
    output
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
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

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
        let step = self.step.fetch_add(1, Ordering::Relaxed) + 1;
        match &self.token {
            Some(token) => {
                let _ = self
                    .peer
                    .notify_progress(
                        ProgressNotificationParam::new(token.clone(), step as f64)
                            .with_message(message),
                    )
                    .await;
            }
            None => {
                let _ = self
                    .peer
                    .notify_logging_message(
                        LoggingMessageNotificationParam::new(
                            LoggingLevel::Info,
                            serde_json::Value::String(message.to_string()),
                        )
                        .with_logger("request_capability"),
                    )
                    .await;
            }
        }
    }
}

async fn with_rotating_status<T>(
    status: &Status,
    messages: &[&str],
    future: impl Future<Output = T>,
) -> T {
    status.send(messages[0]).await;
    tokio::pin!(future);
    let mut interval = tokio::time::interval(STATUS_ROTATION_INTERVAL);
    interval.tick().await;
    let mut next = 1;
    loop {
        tokio::select! {
            output = &mut future => return output,
            _ = interval.tick() => {
                status.send(messages[next % messages.len()]).await;
                next += 1;
            }
        }
    }
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
    let Some(id) = rfq
        .get("id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
    else {
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
            Ok(None) if attempt + 1 < QUOTE_POLL_ATTEMPTS => {
                tokio::time::sleep(QUOTE_POLL_INTERVAL).await;
            }
            Ok(None) => {}
            Err(error) => {
                return SubmissionResult {
                    studio,
                    rfq_id: Some(id),
                    quote: None,
                    status: "failed",
                    error: Some(error.to_string()),
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
    if results.iter().all(|result| result.status == "failed") {
        "Every studio was unreachable or rejected the submission; show the user the errors and ask before retrying."
    } else if results.iter().any(|result| result.status == "quoted") {
        "A studio returned a quote. Present price, timeline, and terms before accepting; do not fund automatically."
    } else {
        "No studio has quoted yet. Tell the user the quote-ready request was submitted and to check back later; do not resubmit it."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(query: &str) -> CallToolRequestParams {
        CallToolRequestParams::new("request_capability")
            .with_arguments(schema_object(serde_json::json!({ "query": query })))
    }

    #[tokio::test]
    async fn mrtr_retries_same_call_from_intake_to_refinement() {
        let state = MrtrState::default();
        let query = "forecast neighborhood pizza demand";
        let wallet = "wallet".to_string();

        let first = run_mrtr_for_wallet(request(query), None, &state, query.into(), wallet.clone())
            .await
            .unwrap();
        let CallToolResponse::InputRequired(first) = first else {
            panic!("initial call should require intake");
        };
        assert!(
            first
                .input_requests
                .as_ref()
                .is_some_and(|requests| requests.contains_key(INTAKE_RESPONSE))
        );

        let mut responses = InputResponses::new();
        responses.insert(
            INTAKE_RESPONSE.into(),
            serde_json::to_value(ElicitResult::new(ElicitationAction::Accept).with_content(
                serde_json::json!({
                    "build": "a hyperlocal pizza delivery API",
                    "today": "Uber Eats"
                }),
            ))
            .unwrap(),
        );
        let retry = request(query)
            .with_request_state(first.request_state.unwrap())
            .with_input_responses(responses);
        let second = run_mrtr_for_wallet(retry, None, &state, query.into(), wallet)
            .await
            .unwrap();
        let CallToolResponse::InputRequired(second) = second else {
            panic!("accepted intake should require local refinement");
        };
        let request = second
            .input_requests
            .as_ref()
            .and_then(|requests| requests.get(REFINEMENT_RESPONSE))
            .expect("refinement request");
        assert!(matches!(request, InputRequest::CreateMessage(_)));
        assert!(second.request_state.is_some());
    }

    #[tokio::test]
    async fn mrtr_decline_completes_without_refinement() {
        let state = MrtrState::default();
        let query = "forecast neighborhood pizza demand";
        let wallet = "wallet".to_string();
        let first = run_mrtr_for_wallet(request(query), None, &state, query.into(), wallet.clone())
            .await
            .unwrap();
        let CallToolResponse::InputRequired(first) = first else {
            panic!("initial call should require intake");
        };
        let mut responses = InputResponses::new();
        responses.insert(
            INTAKE_RESPONSE.into(),
            serde_json::to_value(ElicitResult::new(ElicitationAction::Decline)).unwrap(),
        );
        let retry = request(query)
            .with_request_state(first.request_state.unwrap())
            .with_input_responses(responses);
        let result = run_mrtr_for_wallet(retry, None, &state, query.into(), wallet)
            .await
            .unwrap();
        let CallToolResponse::Complete(result) = result else {
            panic!("declined intake should complete");
        };
        assert_eq!(result.is_error, Some(false));
        assert!(state.consumed.lock().unwrap().is_empty());
    }

    #[test]
    fn pitch_stays_short_and_multiline() {
        for message in [
            pitch("solana priority fee forecasts"),
            pitch(&"x".repeat(500)),
        ] {
            assert!(message.chars().count() <= PITCH_MAX_CHARS);
            assert_eq!(message.matches('\n').count(), 2);
        }
    }

    #[test]
    fn request_state_is_bound_and_single_use() {
        let state = MrtrState::default();
        let flow = FlowState {
            id: "one".into(),
            query: "q".into(),
            buyer_solana_pubkey: "wallet".into(),
            stage: Stage::AwaitingIntake,
            build: None,
            today: None,
            messages: vec![],
            refinement_round: 0,
        };
        let token = state
            .codec
            .seal_json_with(
                &flow,
                &SealOptions::new().associated_data(b"bound").ttl(STATE_TTL),
            )
            .unwrap();
        assert!(
            state
                .codec
                .open_json_with::<FlowState>(&token, b"bound")
                .is_ok()
        );
        assert!(
            state
                .codec
                .open_json_with::<FlowState>(&token, b"other")
                .is_err()
        );
        assert!(consume_once(&state, "one"));
        assert!(!consume_once(&state, "one"));
    }

    #[test]
    fn registry_validation_precedes_submission_replay_consumption() {
        let state = MrtrState::default();

        let malformed = prepare_submission_registry(
            &state,
            "one",
            Err(pay_core::Error::Config("malformed registry".to_string())),
        );
        assert!(malformed.is_err());
        assert!(state.consumed.lock().unwrap().is_empty());

        let empty =
            prepare_submission_registry(&state, "one", Ok(StudioRegistry { studios: vec![] }));
        assert!(empty.is_err());
        assert!(state.consumed.lock().unwrap().is_empty());

        assert!(prepare_submission_registry(&state, "one", Ok(StudioRegistry::default())).is_ok());
        assert!(prepare_submission_registry(&state, "one", Ok(StudioRegistry::default())).is_err());
    }

    #[test]
    fn invalid_brief_collects_actionable_errors() {
        let value = serde_json::json!({
            "product": " ",
            "brief": {
                "example_exchange": { "request": {}, "response": {} },
                "freshness": { "kind": "cached", "ttl_seconds": 0 },
                "volume": { "calls_per_month": 0, "avg_request_bytes": 0, "avg_response_bytes": 1 },
                "compute_class": "cpu",
                "state": { "kind": "durable", "gib": 0 },
                "interface": "request_response"
            }
        });
        let refined: RefinedCapability = serde_json::from_value(value).unwrap();
        let errors = refined.validation_errors();
        assert!(errors.iter().any(|error| error.contains("product")));
        assert!(errors.iter().any(|error| error.contains("ttl_seconds")));
        assert!(errors.iter().any(|error| error.contains("calls_per_month")));
        assert!(errors.iter().any(|error| error.contains("state.gib")));
    }

    #[test]
    fn parser_rejects_unknown_fields() {
        let raw = r#"{
            "product":"x",
            "brief": {
                "example_exchange":{"request":{},"response":{}},
                "freshness":{"kind":"realtime"},
                "volume":{"calls_per_month":1,"avg_request_bytes":0,"avg_response_bytes":1},
                "compute_class":"proxy",
                "state":{"kind":"none"},
                "interface":"request_response"
            },
            "surprise": true
        }"#;
        assert!(parse_refined_capability(raw).is_err());

        let nested = raw
            .replace(
                "\"freshness\":{\"kind\":\"realtime\"}",
                "\"freshness\":{\"kind\":\"realtime\",\"surprise\":true}",
            )
            .replace(",\n            \"surprise\": true", "");
        assert!(parse_refined_capability(&nested).is_err());
        assert!(parse_refined_capability(&format!("Here is the brief:\n{raw}")).is_err());
    }
}
