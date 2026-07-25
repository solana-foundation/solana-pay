//! Data types for the Payment Debugger — direct port of `pdb/api/types.ts`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ── Protocol & Status ──

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Mpp,
    X402,
    Session,
    /// Plain HTTP exchange with no payment protocol involved — used by
    /// `AllExchanges` mode (e.g. `pay serve inference` passthrough traffic).
    Http,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlowStatus {
    PaymentRequired,
    PaymentReceived,
    ResourceDelivered,
    Failed,
    /// Request forwarded upstream, response not yet complete
    /// (`AllExchanges` mode only).
    InProgress,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepStatus {
    Completed,
    InProgress,
    Pending,
}

// ── Flow Step (sequence diagram) ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowStep {
    pub key: String,
    pub label: String,
    pub status: StepStatus,
    pub ts: Option<String>,
}

// ── Flow Event (log panel) ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowEvent {
    pub ts: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

// ── Session Channel ──

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionState {
    Opening,
    Open,
    Settling,
    Closed,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSplit {
    pub recipient: String,
    pub bps: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub state: SessionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_voucher_delta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deposit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cumulative: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voucher_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub splits: Vec<SessionSplit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opened_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

// ── Inference (local AI gateway) ──

/// Live inference telemetry attached to a flow by `pay serve inference`.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InferenceInfo {
    /// Provider slug, e.g. `ollama`.
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// `chat` | `completion` | `embeddings` | `other`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_kind: Option<String>,
    pub streamed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_prompt: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_completion: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttft_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_per_sec: Option<f64>,
}

/// Discovered local inference provider, broadcast to UIs on (re)probe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSummary {
    pub slug: String,
    pub title: String,
    pub base_url: String,
    pub up: bool,
    pub models: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Brand color hex, e.g. `#22c55e`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Per-model price/description metadata for display. `models` remains the
    /// compatibility field; this mirrors it when pricing data is known.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_pricing: Vec<ModelPricingSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelPricingSummary {
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ── Payment Flow ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentFlow {
    pub id: String,
    pub protocol: Protocol,
    /// Sub-scheme within the protocol — e.g. `charge`/`session`/`subscription`
    /// for MPP, `exact`/`upto`/`batch-settlement` for x402. Rendered as the
    /// `PROTOCOL:SCHEME` label (`MPP:CHARGE`). `None` falls back to the protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    pub resource: String,
    pub status: FlowStatus,
    pub client_ip: String,
    pub started_at: String,
    pub updated_at: String,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    pub steps: Vec<FlowStep>,
    pub events: Vec<FlowEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inference: Option<InferenceInfo>,
}

// ── Connections (aggregated activity) ──

/// Aggregated activity for one logical client connection — keyed by payer
/// wallet when traffic is paid, otherwise by client ip/host. Totals are
/// folded in at exchange completion; stablecoin amounts aggregate 1:1 into
/// USD across currencies (USDC/USDT/CASH…).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSummary {
    /// Stable id, e.g. `conn-1`.
    pub id: String,
    /// Payer wallet pubkey when this connection has paid traffic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    pub client_ip: String,
    /// Provider slug of the most recent exchange.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Distinct models seen (bounded).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    pub requests: u64,
    pub ok: u64,
    pub failed: u64,
    pub tokens_prompt: u64,
    pub tokens_completion: u64,
    /// Total settled across all stablecoins, in USD.
    pub paid_usd: f64,
    pub started_at: String,
    pub updated_at: String,
}

// ── SSE Messages ──

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SseMessage {
    #[serde(rename_all = "camelCase")]
    Init {
        viewer_ip: String,
    },
    Snapshot {
        flows: Vec<PaymentFlow>,
    },
    #[serde(rename_all = "camelCase")]
    FlowCreated {
        flow: PaymentFlow,
    },
    #[serde(rename_all = "camelCase")]
    FlowUpdated {
        flow: PaymentFlow,
    },
    ProviderStatus {
        providers: Vec<ProviderSummary>,
    },
    /// One connection's aggregates changed (sent on each completed exchange).
    ConnectionUpdated {
        connection: ConnectionSummary,
    },
    /// Full connection list — replayed to new SSE subscribers.
    ConnectionsSnapshot {
        connections: Vec<ConnectionSummary>,
    },
}

// ── Log Entry (internal, fed to correlation engine) ──

/// Start-of-request notification for `AllExchanges` mode — creates an
/// `in-progress` flow immediately so long-running requests (LLM generations)
/// are visible before the response completes. `id` must match the `LogEntry`
/// ingested at completion.
#[derive(Debug, Clone)]
pub struct ExchangeStart {
    pub id: u64,
    pub ts: String,
    pub method: String,
    pub path: String,
    pub client_ip: String,
    /// Carries a `Payment`-scheme Authorization header — the paid retry of
    /// an earlier 402 challenge; attaches to the pending challenge flow
    /// instead of opening a new one.
    pub payment_retry: bool,
    pub inference: Option<InferenceInfo>,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub id: u64,
    pub ts: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub ms: u64,
    pub req_headers: HashMap<String, String>,
    pub res_headers: HashMap<String, String>,
    pub res_body: Option<String>,
    pub client_ip: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // The TS mirror (web-ui/api/types.ts) depends on these exact wire shapes.

    #[test]
    fn provider_status_message_wire_format() {
        let msg = SseMessage::ProviderStatus {
            providers: vec![ProviderSummary {
                slug: "ollama".into(),
                title: "Ollama".into(),
                base_url: "http://127.0.0.1:11434".into(),
                up: true,
                models: vec!["llama3.2:3b".into()],
                version: Some("0.9.1".into()),
                color: Some("#22c55e".into()),
                model_pricing: vec![ModelPricingSummary {
                    model: "llama3.2:3b".into(),
                    variant: Some("llama3.2:3b".into()),
                    price: Some("in $0.10 · out $0.20 /1M tok".into()),
                    description: Some("Small local chat model.".into()),
                }],
            }],
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(json["type"], "provider-status");
        let p = &json["providers"][0];
        assert_eq!(p["slug"], "ollama");
        assert_eq!(p["baseUrl"], "http://127.0.0.1:11434");
        assert_eq!(p["up"], true);
        assert_eq!(p["version"], "0.9.1");
        assert_eq!(p["modelPricing"][0]["model"], "llama3.2:3b");
        assert_eq!(p["modelPricing"][0]["variant"], "llama3.2:3b");
        assert_eq!(
            p["modelPricing"][0]["price"],
            "in $0.10 · out $0.20 /1M tok"
        );
        assert_eq!(
            p["modelPricing"][0]["description"],
            "Small local chat model."
        );
    }

    #[test]
    fn inference_info_wire_format() {
        let info = InferenceInfo {
            provider: "ollama".into(),
            model: Some("llama3.2:3b".into()),
            endpoint_kind: Some("chat".into()),
            streamed: true,
            tokens_prompt: Some(12),
            tokens_completion: Some(214),
            ttft_ms: Some(182),
            tokens_per_sec: Some(41.2),
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&info).unwrap()).unwrap();
        assert_eq!(json["endpointKind"], "chat");
        assert_eq!(json["tokensPrompt"], 12);
        assert_eq!(json["tokensCompletion"], 214);
        assert_eq!(json["ttftMs"], 182);
        assert_eq!(json["tokensPerSec"], 41.2);
        // Empty optionals are omitted, not null.
        let sparse = serde_json::to_string(&InferenceInfo {
            provider: "x".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(sparse, r#"{"provider":"x","streamed":false}"#);
    }

    #[test]
    fn in_progress_status_and_http_protocol_wire_format() {
        assert_eq!(
            serde_json::to_string(&FlowStatus::InProgress).unwrap(),
            r#""in-progress""#
        );
        assert_eq!(serde_json::to_string(&Protocol::Http).unwrap(), r#""http""#);
    }
}
