//! Flow correlation engine — port of `pdb/api/correlation.ts`.
//!
//! Groups HTTP log entries into payment flows by correlating 402 challenges
//! with subsequent payment retries from the same client+path.

use std::collections::{HashMap, VecDeque};

use base64::Engine;
use tokio::sync::broadcast;

use crate::types::*;

const FLOW_TIMEOUT_MS: u64 = 60_000;
const MAX_FLOWS: usize = 200;
const X402_PAYMENT_RESPONSE_HEADER: &str = "payment-response";
const X402_LEGACY_PAYMENT_RESPONSE_HEADER: &str = "x-payment-response";

#[derive(Debug, Clone, Copy)]
enum Phase {
    Challenge,
    Retry,
}

/// What the engine turns log entries into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CorrelationMode {
    /// Only 402 challenges / payment retries become flows (Payment Debugger).
    #[default]
    PaymentFlows,
    /// Every exchange becomes a flow immediately (`pay gate inference`).
    /// Payment challenge/retry *correlation* is not applied in this mode —
    /// each HTTP exchange is one flow; unifying the two models is deferred
    /// until the inference gateway grows payment gating.
    AllExchanges,
}

pub struct FlowCorrelation {
    flows: Vec<PaymentFlow>,
    /// Maps `"clientIp::path"` → index into `flows`.
    flow_index: HashMap<String, usize>,
    /// `AllExchanges` mode: maps in-flight log id → flow id (stable across
    /// ring-buffer eviction, unlike indices).
    open_exchanges: HashMap<u64, String>,
    /// `AllExchanges` mode: per-connection aggregates, keyed by payer wallet
    /// (paid traffic) or client ip/host (unpaid). Bounded.
    connections: HashMap<String, ConnectionSummary>,
    /// `AllExchanges` mode: 402-challenged exchanges awaiting their paid
    /// retry, keyed `"clientIp::path"` → flow ids, oldest first. A QUEUE, not
    /// a single slot: parallel requests to the same path (Claude fans out)
    /// produce several pending challenges at once, and each retry must pair
    /// with one of them — a single slot orphaned the older challenge, which
    /// then sat until the 60s timeout marked it failed.
    pending_challenges: HashMap<String, VecDeque<String>>,
    connection_id_counter: u64,
    flow_id_counter: u64,
    mode: CorrelationMode,
    tx: broadcast::Sender<SseMessage>,
}

impl FlowCorrelation {
    pub fn new(tx: broadcast::Sender<SseMessage>) -> Self {
        Self::with_mode(tx, CorrelationMode::PaymentFlows)
    }

    pub fn with_mode(tx: broadcast::Sender<SseMessage>, mode: CorrelationMode) -> Self {
        Self {
            flows: Vec::new(),
            flow_index: HashMap::new(),
            open_exchanges: HashMap::new(),
            connections: HashMap::new(),
            pending_challenges: HashMap::new(),
            connection_id_counter: 0,
            flow_id_counter: 0,
            mode,
            tx,
        }
    }

    pub fn snapshot(&self) -> Vec<PaymentFlow> {
        self.flows.clone()
    }

    /// Oldest pending challenge flow for this client+path still awaiting its
    /// paid retry (FIFO so concurrent challenges drain in arrival order).
    fn pop_pending_challenge(&mut self, client_ip: &str, path: &str) -> Option<String> {
        let key = flow_key(client_ip, path);
        let queue = self.pending_challenges.get_mut(&key)?;
        let flow_id = queue.pop_front();
        if queue.is_empty() {
            self.pending_challenges.remove(&key);
        }
        flow_id
    }

    /// Current connection aggregates, most recently active first.
    pub fn connections_snapshot(&self) -> Vec<ConnectionSummary> {
        let mut connections: Vec<ConnectionSummary> = self.connections.values().cloned().collect();
        connections.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        connections
    }

    pub fn ingest(&mut self, entry: LogEntry) {
        if is_internal_path(&entry.path) {
            return;
        }

        if self.mode == CorrelationMode::AllExchanges {
            if !is_browser_noise(&entry.path) {
                self.ingest_exchange(entry);
            }
            return;
        }

        let Some((protocol, phase)) = self.detect(&entry) else {
            return;
        };

        match phase {
            Phase::Challenge => self.create_flow(&entry, protocol),
            Phase::Retry => self.handle_retry(&entry, protocol),
        }
    }

    // ── AllExchanges mode ──

    /// Open an `in-progress` flow at request time so slow requests are
    /// visible while they run. No-op in `PaymentFlows` mode.
    ///
    /// A payment retry of a pending 402 challenge attaches to the existing
    /// challenge flow (one row per logical request) instead of opening a
    /// second one.
    pub fn begin_exchange(&mut self, start: ExchangeStart) {
        if self.mode != CorrelationMode::AllExchanges
            || is_internal_path(&start.path)
            || is_browser_noise(&start.path)
        {
            return;
        }

        if start.payment_retry
            && let Some(flow_id) = self.pop_pending_challenge(&start.client_ip, &start.path)
            && let Some(flow) = self.flows.iter_mut().find(|f| f.id == flow_id)
        {
            self.open_exchanges.insert(start.id, flow_id);
            flow.status = FlowStatus::PaymentReceived;
            flow.updated_at = start.ts.clone();
            if let Some(incoming) = start.inference {
                flow.inference = Some(match flow.inference.take() {
                    Some(existing) => merge_inference(existing, incoming),
                    None => incoming,
                });
            }
            flow.events.push(FlowEvent {
                ts: start.ts,
                message: "Paid retry".into(),
                detail: Some("Payment credential attached".into()),
            });
            update_steps(flow);
            let _ = self.tx.send(SseMessage::FlowUpdated { flow: flow.clone() });
            return;
        }

        self.flow_id_counter += 1;
        let id = format!("flow-{}", self.flow_id_counter);
        self.open_exchanges.insert(start.id, id.clone());

        let flow = PaymentFlow {
            id,
            protocol: Protocol::Http,
            scheme: None,
            resource: start.path.clone(),
            status: FlowStatus::InProgress,
            client_ip: start.client_ip,
            started_at: start.ts.clone(),
            updated_at: start.ts.clone(),
            duration_ms: 0,
            amount: None,
            payer: None,
            session: None,
            steps: exchange_steps(&start.ts),
            events: vec![FlowEvent {
                ts: start.ts,
                message: format!("{} {}", start.method, start.path),
                detail: Some("Request forwarded upstream".into()),
            }],
            challenge_headers: None,
            payment_headers: None,
            response_headers: None,
            response_body: None,
            inference: start.inference,
        };

        self.add_flow(flow.clone());
        let _ = self.tx.send(SseMessage::FlowCreated { flow });
    }

    /// Live telemetry update for an in-flight exchange (running token counts,
    /// TTFT). Merged field-wise onto the flow's existing inference data —
    /// present incoming fields win, absent ones keep what the flow already
    /// knows (the request-time update carries provider/endpoint kind, the
    /// stream observer carries model/tokens). No-op once completed.
    pub fn update_exchange(&mut self, log_id: u64, inference: InferenceInfo) {
        let Some(flow_id) = self.open_exchanges.get(&log_id).cloned() else {
            return;
        };
        let Some(flow) = self.flows.iter_mut().find(|f| f.id == flow_id) else {
            return;
        };
        flow.inference = Some(match flow.inference.take() {
            Some(existing) => merge_inference(existing, inference),
            None => inference,
        });
        flow.updated_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        // Keep the row's duration ticking while the request runs — the UI
        // renders durationMs live on each flow-updated.
        if let Some(elapsed) = elapsed_ms(&flow.started_at, &flow.updated_at) {
            flow.duration_ms = elapsed;
        }
        let _ = self.tx.send(SseMessage::FlowUpdated { flow: flow.clone() });
    }

    /// Completion path for `AllExchanges` mode: close the in-flight flow
    /// opened by `begin_exchange`, or record a completed one-shot flow if no
    /// start was seen (e.g. traffic that bypassed the start hook).
    fn ingest_exchange(&mut self, entry: LogEntry) {
        let open_flow_id = self.open_exchanges.remove(&entry.id);

        let Some(flow_id) = open_flow_id else {
            self.create_completed_exchange(&entry);
            return;
        };
        let Some(flow) = self.flows.iter_mut().find(|f| f.id == flow_id) else {
            // Evicted from the ring buffer while in flight.
            self.create_completed_exchange(&entry);
            return;
        };

        let now = &entry.ts;

        // A 402 with a payment challenge is not a failure — it's the handshake
        // half of a paid request. Park the flow as payment-required and let
        // the paid retry attach to it (`begin_exchange`), so challenge +
        // retry render as ONE row with the 4-step payment diagram.
        if entry.status == 402
            && let Some(protocol) = payment_challenge_protocol(&entry)
        {
            let started = flow.started_at.clone();
            flow.protocol = protocol;
            flow.scheme = flow_scheme(&entry, protocol, None);
            flow.status = FlowStatus::PaymentRequired;
            flow.updated_at = now.clone();
            flow.challenge_headers = Some(entry.res_headers.clone());
            flow.amount = extract_amount(&entry);
            flow.steps = build_steps(&protocol);
            flow.steps[0].ts = Some(started);
            flow.events.push(FlowEvent {
                ts: now.clone(),
                message: "402 Payment Gate".into(),
                detail: Some(challenge_event_detail(protocol, &entry)),
            });
            update_steps(flow);
            let key = flow_key(&flow.client_ip, &flow.resource);
            let flow_id = flow.id.clone();
            let updated = flow.clone();
            self.pending_challenges
                .entry(key)
                .or_default()
                .push_back(flow_id);
            let _ = self.tx.send(SseMessage::FlowUpdated { flow: updated });
            return; // handshake — connections aggregate on the paid retry
        }

        flow.status = exchange_status(entry.status);
        flow.updated_at = now.clone();
        flow.duration_ms = elapsed_ms(&flow.started_at, now).unwrap_or(entry.ms);
        flow.response_headers = Some(entry.res_headers.clone());
        flow.response_body = entry.res_body.clone();
        // A settled MPP payment on this exchange — drives the stablecoin
        // series in the TUI/web charts.
        if let Some(amount) = paid_exchange_amount(&entry) {
            flow.amount = Some(amount);
            flow.payer = extract_payer(&entry.req_headers);
        }
        // Merged challenge+retry flows carry the 4-step payment diagram;
        // plain exchanges keep their 2-step one.
        if flow.steps.len() == 4 {
            update_steps(flow);
        } else {
            complete_exchange_steps(flow, now);
        }
        flow.events.push(FlowEvent {
            ts: now.clone(),
            message: format!("{} — completed in {}ms", entry.status, flow.duration_ms),
            detail: entry
                .res_body
                .as_deref()
                .map(|b| truncate(b, 2000).to_string()),
        });

        let completed = flow.clone();
        let _ = self.tx.send(SseMessage::FlowUpdated {
            flow: completed.clone(),
        });
        self.record_connection(&entry, &completed);
    }

    /// Fold a completed exchange into its connection's aggregates and
    /// broadcast the updated summary. 402 challenges are protocol handshake,
    /// not client activity — skipped entirely (the paid retry is what
    /// counts). Connection key: payer wallet for paid traffic, client
    /// ip/host otherwise.
    fn record_connection(&mut self, entry: &LogEntry, flow: &PaymentFlow) {
        const MAX_CONNECTIONS: usize = 100;
        const MAX_MODELS: usize = 8;

        if entry.status == 402 {
            return;
        }
        let key = flow.payer.clone().unwrap_or_else(|| flow.client_ip.clone());

        if !self.connections.contains_key(&key) && self.connections.len() >= MAX_CONNECTIONS {
            // Evict the least recently active.
            if let Some(oldest) = self
                .connections
                .iter()
                .min_by(|a, b| a.1.updated_at.cmp(&b.1.updated_at))
                .map(|(k, _)| k.clone())
            {
                self.connections.remove(&oldest);
            }
        }
        self.connection_id_counter += 1;
        let next_id = format!("conn-{}", self.connection_id_counter);
        let connection = self
            .connections
            .entry(key)
            .or_insert_with(|| ConnectionSummary {
                id: next_id,
                payer: None,
                client_ip: flow.client_ip.clone(),
                provider: None,
                models: Vec::new(),
                requests: 0,
                ok: 0,
                failed: 0,
                tokens_prompt: 0,
                tokens_completion: 0,
                paid_usd: 0.0,
                started_at: flow.updated_at.clone(),
                updated_at: flow.updated_at.clone(),
            });

        connection.requests += 1;
        if matches!(flow.status, FlowStatus::ResourceDelivered) {
            connection.ok += 1;
        } else {
            connection.failed += 1;
        }
        if let Some(payer) = &flow.payer {
            connection.payer = Some(payer.clone());
        }
        if let Some(inference) = &flow.inference {
            connection.provider = Some(inference.provider.clone());
            connection.tokens_prompt += inference.tokens_prompt.unwrap_or(0);
            connection.tokens_completion += inference.tokens_completion.unwrap_or(0);
            if let Some(model) = &inference.model
                && !connection.models.contains(model)
                && connection.models.len() < MAX_MODELS
            {
                connection.models.push(model.clone());
            }
        }
        if let Some(usd) = paid_exchange_usd(entry) {
            connection.paid_usd += usd;
        }
        connection.updated_at = flow.updated_at.clone();

        let connection = connection.clone();
        let _ = self.tx.send(SseMessage::ConnectionUpdated { connection });
    }

    fn create_completed_exchange(&mut self, entry: &LogEntry) {
        self.flow_id_counter += 1;
        let id = format!("flow-{}", self.flow_id_counter);
        let now = &entry.ts;
        let amount = paid_exchange_amount(entry);
        let payer = amount
            .is_some()
            .then(|| extract_payer(&entry.req_headers))
            .flatten();

        let mut flow = PaymentFlow {
            id,
            protocol: Protocol::Http,
            scheme: None,
            resource: entry.path.clone(),
            status: exchange_status(entry.status),
            client_ip: entry.client_ip.clone(),
            started_at: now.clone(),
            updated_at: now.clone(),
            duration_ms: entry.ms,
            amount,
            payer,
            session: None,
            steps: exchange_steps(now),
            events: vec![
                FlowEvent {
                    ts: now.clone(),
                    message: format!("{} {}", entry.method, entry.path),
                    detail: Some("Request forwarded upstream".into()),
                },
                FlowEvent {
                    ts: now.clone(),
                    message: format!("{} — completed in {}ms", entry.status, entry.ms),
                    detail: entry
                        .res_body
                        .as_deref()
                        .map(|b| truncate(b, 2000).to_string()),
                },
            ],
            challenge_headers: None,
            payment_headers: None,
            response_headers: Some(entry.res_headers.clone()),
            response_body: entry.res_body.clone(),
            inference: None,
        };
        complete_exchange_steps(&mut flow, now);

        self.add_flow(flow.clone());
        let _ = self.tx.send(SseMessage::FlowCreated { flow: flow.clone() });
        self.record_connection(entry, &flow);
    }

    pub fn cleanup(&mut self) {
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;

        for flow in &mut self.flows {
            if flow.status != FlowStatus::PaymentRequired {
                continue;
            }
            let started = chrono::DateTime::parse_from_rfc3339(&flow.started_at)
                .map(|d| d.timestamp_millis() as u64);
            if let Ok(started_ms) = started
                && now_ms.saturating_sub(started_ms) > FLOW_TIMEOUT_MS
            {
                flow.status = FlowStatus::Failed;
                flow.updated_at =
                    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                flow.duration_ms = now_ms.saturating_sub(started_ms);
                flow.events.push(FlowEvent {
                    ts: flow.updated_at.clone(),
                    message: "Flow timed out — no payment received within 60s".into(),
                    detail: None,
                });
                update_steps(flow);
                let _ = self.tx.send(SseMessage::FlowUpdated { flow: flow.clone() });
            }
        }
        // Timed-out challenges must not accept a (very) late retry.
        let flows = &self.flows;
        for queue in self.pending_challenges.values_mut() {
            queue.retain(|flow_id| {
                flows
                    .iter()
                    .any(|f| &f.id == flow_id && f.status == FlowStatus::PaymentRequired)
            });
        }
        self.pending_challenges.retain(|_, queue| !queue.is_empty());
    }

    // ── Detection ──

    fn detect(&self, entry: &LogEntry) -> Option<(Protocol, Phase)> {
        // 402 challenges
        if entry.status == 402 {
            if let Some(www_auth) = entry.res_headers.get("www-authenticate")
                && www_auth.starts_with("Payment")
            {
                let protocol = if is_session_challenge(entry) {
                    Protocol::Session
                } else {
                    Protocol::Mpp
                };
                return Some((protocol, Phase::Challenge));
            }
            if has_x402_challenge(entry) {
                return Some((Protocol::X402, Phase::Challenge));
            }
            return None;
        }

        // Payment retries
        if is_session_authorization(entry.req_headers.get("authorization")) {
            return Some((Protocol::Session, Phase::Retry));
        }
        if entry.res_headers.contains_key("payment-receipt") {
            return Some((Protocol::Mpp, Phase::Retry));
        }
        // v1 (`X-PAYMENT`) and v2 (`PAYMENT-SIGNATURE` request / `PAYMENT-RESPONSE`
        // settlement); header keys are normalized to lowercase.
        if entry.req_headers.contains_key("x-payment")
            || entry
                .req_headers
                .contains_key(X402_LEGACY_PAYMENT_RESPONSE_HEADER)
            || entry.req_headers.contains_key("payment-signature")
            || entry.res_headers.contains_key(X402_PAYMENT_RESPONSE_HEADER)
        {
            return Some((Protocol::X402, Phase::Retry));
        }

        None
    }

    // ── Flow creation ──

    fn create_flow(&mut self, entry: &LogEntry, protocol: Protocol) {
        // Dedup re-issued challenges: clients (and the playground UI) often probe
        // an endpoint, get a 402, then probe again before paying. Without this
        // each 402 spawns its own `payment-required` row, and the eventual
        // payment merges only the most recent — orphaning the earlier orange
        // rows. Refresh the existing pending flow instead of creating a duplicate.
        if let Some(idx) = self.find_pending_flow(&entry.client_ip, &entry.path) {
            let flow = &mut self.flows[idx];
            flow.updated_at = entry.ts.clone();
            let _ = self.tx.send(SseMessage::FlowUpdated { flow: flow.clone() });
            return;
        }

        self.flow_id_counter += 1;
        let id = format!("flow-{}", self.flow_id_counter);
        let now = &entry.ts;

        let mut steps = build_steps(&protocol);
        steps[0].status = StepStatus::Completed;
        steps[0].ts = Some(now.clone());
        steps[1].status = StepStatus::Completed;
        steps[1].ts = Some(now.clone());
        steps[2].status = StepStatus::InProgress;

        let challenge_detail = challenge_event_detail(protocol, entry);

        let amount = if matches!(protocol, Protocol::Session) {
            None
        } else {
            extract_amount(entry)
        };
        let session = if matches!(protocol, Protocol::Session) {
            session_from_challenge(entry)
        } else {
            None
        };

        let flow = PaymentFlow {
            id,
            protocol,
            scheme: flow_scheme(entry, protocol, None),
            resource: entry.path.clone(),
            status: FlowStatus::PaymentRequired,
            client_ip: entry.client_ip.clone(),
            started_at: now.clone(),
            updated_at: now.clone(),
            duration_ms: 0,
            amount,
            payer: None,
            session,
            steps,
            events: vec![
                FlowEvent {
                    ts: now.clone(),
                    message: format!("{} {}", entry.method, entry.path),
                    detail: Some("Client request received".into()),
                },
                FlowEvent {
                    ts: now.clone(),
                    message: "402 Payment Gate".into(),
                    detail: Some(challenge_detail),
                },
            ],
            challenge_headers: Some(entry.res_headers.clone()),
            payment_headers: None,
            response_headers: None,
            response_body: None,
            inference: None,
        };

        self.add_flow(flow.clone());
        let _ = self.tx.send(SseMessage::FlowCreated { flow });
    }

    // ── Payment retry ──

    fn handle_retry(&mut self, entry: &LogEntry, protocol: Protocol) {
        // Exact match (IP + path), then path-only fallback.
        let idx = self.find_pending_flow(&entry.client_ip, &entry.path);

        let Some(idx) = idx else {
            if matches!(protocol, Protocol::Session) && self.merge_session_delivery(entry) {
                return;
            }
            self.create_standalone_delivery(entry, protocol);
            return;
        };

        let flow = &mut self.flows[idx];
        if flow.status != FlowStatus::PaymentRequired {
            if matches!(protocol, Protocol::Session) && self.merge_session_delivery(entry) {
                return;
            }
            self.create_standalone_delivery(entry, protocol);
            return;
        }

        // The challenge for a dual-scheme endpoint (e.g. mpp + x402) is created
        // from whichever offer header detect() saw first (www-authenticate →
        // mpp). The retry reveals the scheme the client actually used, so adopt
        // it — otherwise an x402 payment shows under the mpp challenge's label.
        let scheme = flow_scheme(entry, protocol, self.flows[idx].challenge_headers.as_ref());
        let flow = &mut self.flows[idx];
        flow.protocol = protocol;
        flow.scheme = scheme;

        let now = &entry.ts;
        let session_update = if matches!(protocol, Protocol::Session) {
            session_from_authorization(entry, flow.session.as_ref())
        } else {
            None
        };
        flow.payment_headers = Some(entry.req_headers.clone());
        flow.payer = extract_payer(&entry.req_headers);
        flow.response_headers = Some(entry.res_headers.clone());
        flow.response_body = entry.res_body.clone();
        flow.updated_at = now.clone();
        flow.duration_ms = entry.ms;

        if entry.status >= 200 && entry.status < 300 {
            flow.status = FlowStatus::ResourceDelivered;
            if session_update.is_some() {
                flow.session = session_update.clone();
            }
            let detail = match protocol {
                Protocol::Mpp | Protocol::Http => format!(
                    "payment-receipt: {}",
                    truncate(
                        entry
                            .res_headers
                            .get("payment-receipt")
                            .map(|s| s.as_str())
                            .unwrap_or(""),
                        120
                    )
                ),
                Protocol::Session => session_event_detail(session_update.as_ref())
                    .unwrap_or_else(|| "session action verified".into()),
                Protocol::X402 => "x-payment-response verified".into(),
            };
            flow.events.push(FlowEvent {
                ts: now.clone(),
                message: if matches!(protocol, Protocol::Session) {
                    session_accepted_message(session_update.as_ref())
                } else {
                    "Payment accepted".into()
                },
                detail: Some(detail),
            });
            flow.events.push(FlowEvent {
                ts: now.clone(),
                message: "200 Resource Delivered".into(),
                detail: entry
                    .res_body
                    .as_deref()
                    .map(|b| truncate(b, 2000).to_string()),
            });
        } else {
            flow.status = FlowStatus::Failed;
            if let Some(mut session) = session_update {
                session.state = SessionState::Failed;
                flow.session = Some(session);
            }
            flow.events.push(FlowEvent {
                ts: now.clone(),
                message: format!("Payment retry failed with {}", entry.status),
                detail: entry
                    .res_body
                    .as_deref()
                    .map(|b| truncate(b, 2000).to_string()),
            });
        }

        update_steps(flow);
        let _ = self.tx.send(SseMessage::FlowUpdated { flow: flow.clone() });
    }

    // ── Standalone delivery (no matching 402 found) ──

    fn create_standalone_delivery(&mut self, entry: &LogEntry, protocol: Protocol) {
        self.flow_id_counter += 1;
        let id = format!("flow-{}", self.flow_id_counter);
        let now = &entry.ts;

        let mut steps = build_steps(&protocol);
        for step in &mut steps {
            step.status = StepStatus::Completed;
            step.ts = Some(now.clone());
        }
        let session = if matches!(protocol, Protocol::Session) {
            session_from_authorization(entry, None)
        } else {
            None
        };

        let flow = PaymentFlow {
            id,
            protocol,
            scheme: flow_scheme(entry, protocol, None),
            resource: entry.path.clone(),
            status: FlowStatus::ResourceDelivered,
            client_ip: entry.client_ip.clone(),
            started_at: now.clone(),
            updated_at: now.clone(),
            duration_ms: entry.ms,
            amount: None,
            payer: extract_payer(&entry.req_headers),
            session: session.clone(),
            steps,
            events: vec![FlowEvent {
                ts: now.clone(),
                message: if matches!(protocol, Protocol::Session) {
                    session_accepted_message(session.as_ref())
                } else {
                    format!("{} {} → {}", entry.method, entry.path, entry.status)
                },
                detail: Some(if matches!(protocol, Protocol::Session) {
                    session_event_detail(session.as_ref())
                        .unwrap_or_else(|| "Session flow completed (challenge not captured)".into())
                } else {
                    "Payment flow completed (challenge not captured)".into()
                }),
            }],
            challenge_headers: None,
            payment_headers: None,
            response_headers: Some(entry.res_headers.clone()),
            response_body: entry.res_body.clone(),
            inference: None,
        };

        self.add_flow(flow.clone());
        let _ = self.tx.send(SseMessage::FlowCreated { flow });
    }

    fn merge_session_delivery(&mut self, entry: &LogEntry) -> bool {
        let preliminary = match session_from_authorization(entry, None) {
            Some(session) => session,
            None => return false,
        };
        if !matches!(
            preliminary.action.as_deref(),
            Some("commit") | Some("voucher")
        ) {
            return false;
        }
        let Some(session_id) = preliminary.session_id.as_deref() else {
            return false;
        };

        let Some(idx) = self.flows.iter().rposition(|flow| {
            matches!(flow.protocol, Protocol::Session)
                && flow.resource == entry.path
                && flow
                    .session
                    .as_ref()
                    .and_then(|session| session.session_id.as_deref())
                    == Some(session_id)
        }) else {
            return false;
        };

        let flow = &mut self.flows[idx];
        let now = &entry.ts;
        let Some(mut session_update) = session_from_authorization(entry, flow.session.as_ref())
        else {
            return false;
        };

        flow.payment_headers = Some(entry.req_headers.clone());
        if let Some(payer) = extract_payer(&entry.req_headers) {
            flow.payer = Some(payer);
        }
        flow.response_headers = Some(entry.res_headers.clone());
        flow.response_body = entry.res_body.clone();
        flow.updated_at = now.clone();
        flow.duration_ms = elapsed_ms(&flow.started_at, now)
            .unwrap_or_else(|| flow.duration_ms.saturating_add(entry.ms));

        if entry.status >= 200 && entry.status < 300 {
            flow.status = FlowStatus::ResourceDelivered;
            flow.events.push(FlowEvent {
                ts: now.clone(),
                message: session_accepted_message(Some(&session_update)),
                detail: session_event_detail(Some(&session_update)),
            });
        } else {
            flow.status = FlowStatus::Failed;
            session_update.state = SessionState::Failed;
            flow.events.push(FlowEvent {
                ts: now.clone(),
                message: format!("Session retry failed with {}", entry.status),
                detail: entry
                    .res_body
                    .as_deref()
                    .map(|body| truncate(body, 2000).to_string()),
            });
        }

        flow.session = Some(session_update);
        update_steps(flow);
        let _ = self.tx.send(SseMessage::FlowUpdated { flow: flow.clone() });
        true
    }

    // ── Helpers ──

    /// Index of the open (`payment-required`) flow for this client+path —
    /// exact `ip::path` match first, then the most recent path-only match.
    /// Shared by retry correlation and challenge dedup.
    fn find_pending_flow(&self, client_ip: &str, path: &str) -> Option<usize> {
        self.flow_index
            .get(&flow_key(client_ip, path))
            .copied()
            .filter(|&i| self.flows[i].status == FlowStatus::PaymentRequired)
            .or_else(|| {
                self.flows
                    .iter()
                    .rposition(|f| f.resource == path && f.status == FlowStatus::PaymentRequired)
            })
    }

    fn add_flow(&mut self, flow: PaymentFlow) {
        let key = flow_key(&flow.client_ip, &flow.resource);
        let idx = self.flows.len();
        self.flows.push(flow);
        self.flow_index.insert(key, idx);

        if self.flows.len() > MAX_FLOWS {
            let removed = self.flows.remove(0);
            self.flow_index
                .remove(&flow_key(&removed.client_ip, &removed.resource));
            // Shift all indices down by 1
            for v in self.flow_index.values_mut() {
                *v = v.saturating_sub(1);
            }
        }
    }
}

// ── Pure helpers ──

fn flow_key(client_ip: &str, path: &str) -> String {
    format!("{client_ip}::{path}")
}

/// Field-wise merge of inference telemetry: incoming wins where present.
fn merge_inference(existing: InferenceInfo, incoming: InferenceInfo) -> InferenceInfo {
    InferenceInfo {
        provider: if incoming.provider.is_empty() {
            existing.provider
        } else {
            incoming.provider
        },
        model: incoming.model.or(existing.model),
        endpoint_kind: incoming.endpoint_kind.or(existing.endpoint_kind),
        streamed: incoming.streamed || existing.streamed,
        tokens_prompt: incoming.tokens_prompt.or(existing.tokens_prompt),
        tokens_completion: incoming.tokens_completion.or(existing.tokens_completion),
        ttft_ms: incoming.ttft_ms.or(existing.ttft_ms),
        tokens_per_sec: incoming.tokens_per_sec.or(existing.tokens_per_sec),
    }
}

/// 2xx/3xx delivered, everything else failed. (402 cannot occur on
/// passthrough inference routes in v1 — no metered endpoints.)
fn exchange_status(status: u16) -> FlowStatus {
    if (200..400).contains(&status) {
        FlowStatus::ResourceDelivered
    } else {
        FlowStatus::Failed
    }
}

/// Two-step diagram for plain exchanges: request → response.
fn exchange_steps(ts: &str) -> Vec<FlowStep> {
    vec![
        FlowStep {
            key: "request".into(),
            label: "Request".into(),
            status: StepStatus::Completed,
            ts: Some(ts.to_string()),
        },
        FlowStep {
            key: "delivery".into(),
            label: "Response".into(),
            status: StepStatus::InProgress,
            ts: None,
        },
    ]
}

fn complete_exchange_steps(flow: &mut PaymentFlow, ts: &str) {
    if let Some(step) = flow.steps.iter_mut().find(|s| s.key == "delivery") {
        step.status = match flow.status {
            FlowStatus::Failed => StepStatus::Pending,
            _ => StepStatus::Completed,
        };
        step.ts = (!matches!(flow.status, FlowStatus::Failed)).then(|| ts.to_string());
    }
}

/// Sub-scheme label for a flow, derived from the entry's headers (and the
/// stored challenge headers for a retry). Drives the `PROTOCOL:SCHEME` label.
fn flow_scheme(
    entry: &LogEntry,
    protocol: Protocol,
    challenge_headers: Option<&HashMap<String, String>>,
) -> Option<String> {
    match protocol {
        Protocol::Session => Some("session".to_string()),
        Protocol::Mpp => Some(mpp_intent(entry).unwrap_or_else(|| "charge".to_string())),
        Protocol::X402 => {
            Some(x402_scheme(entry, challenge_headers).unwrap_or_else(|| "exact".to_string()))
        }
        Protocol::Http => None,
    }
}

/// MPP intent (`charge`/`session`/`subscription`) from the challenge
/// `www-authenticate` header or the retry `authorization` credential.
fn mpp_intent(entry: &LogEntry) -> Option<String> {
    if let Some(header) = entry.res_headers.get("www-authenticate") {
        let params = parse_header_params(header.trim_start_matches("Payment").trim());
        if let Some(intent) = params.get("intent") {
            return Some(intent.clone());
        }
    }
    payment_credential_from_authorization(entry.req_headers.get("authorization"))
        .and_then(|c| value_string(c.get("challenge").and_then(|ch| ch.get("intent"))))
}

/// x402 scheme (`exact`/`upto`/`batch-settlement`) from the retry
/// `payment-signature` payload or the (this/stored) challenge `payment-required`
/// offer.
fn x402_scheme(
    entry: &LogEntry,
    challenge_headers: Option<&HashMap<String, String>>,
) -> Option<String> {
    for key in ["payment-signature", "x-payment"] {
        if let Some(value) = entry.req_headers.get(key)
            && let Some(scheme) = x402_scheme_from_payment(value)
        {
            return Some(scheme);
        }
    }
    for headers in [Some(&entry.res_headers), challenge_headers]
        .into_iter()
        .flatten()
    {
        for key in ["payment-required", "x-payment-required"] {
            if let Some(value) = headers.get(key)
                && let Some(scheme) = x402_scheme_from_required(value)
            {
                return Some(scheme);
            }
        }
    }
    None
}

/// `accepts[0].scheme` from a base64 `PAYMENT-REQUIRED` challenge envelope.
fn x402_scheme_from_required(encoded: &str) -> Option<String> {
    let json = decode_json_value(encoded)?;
    let offers = json.get("accepts").or_else(|| json.get("offers"))?;
    value_string(offers.as_array()?.first()?.get("scheme"))
}

/// Scheme from a base64 `PAYMENT-SIGNATURE` payment envelope — `accepted.scheme`
/// (canonical x402 v2), a top-level `scheme`, or `upto` inferred from a
/// payment-channel payload (`channelId`/`profile`).
fn x402_scheme_from_payment(encoded: &str) -> Option<String> {
    let json = decode_json_value(encoded)?;
    if let Some(scheme) = value_string(json.get("accepted").and_then(|a| a.get("scheme"))) {
        return Some(scheme);
    }
    if let Some(scheme) = value_string(json.get("scheme")).filter(|s| !s.is_empty()) {
        return Some(scheme);
    }
    let payload = json.get("payload")?;
    (payload.get("channelId").is_some() || payload.get("profile").is_some())
        .then(|| "upto".to_string())
}

fn is_internal_path(path: &str) -> bool {
    path.starts_with("/__402")
}

/// The response is an MPP `Payment` 402 challenge (vs. a plain upstream 402).
fn has_mpp_challenge(entry: &LogEntry) -> bool {
    entry
        .res_headers
        .get("www-authenticate")
        .is_some_and(|h| h.starts_with("Payment"))
}

fn has_x402_challenge(entry: &LogEntry) -> bool {
    entry.path.starts_with("/x402/")
        // v1 (`X-PAYMENT-REQUIRED`) and v2 (`PAYMENT-REQUIRED`); header keys
        // are normalized to lowercase.
        || entry.res_headers.contains_key("x-payment-required")
        || entry.res_headers.contains_key("payment-required")
        || is_x402_body(&entry.res_body)
}

fn payment_challenge_protocol(entry: &LogEntry) -> Option<Protocol> {
    if has_mpp_challenge(entry) {
        return Some(if is_session_challenge(entry) {
            Protocol::Session
        } else {
            Protocol::Mpp
        });
    }
    has_x402_challenge(entry).then_some(Protocol::X402)
}

fn challenge_event_detail(protocol: Protocol, entry: &LogEntry) -> String {
    match protocol {
        // Http never reaches payment challenge creation; grouped with Mpp only
        // for exhaustiveness.
        Protocol::Mpp | Protocol::Http | Protocol::Session => format!(
            "www-authenticate: {}",
            truncate(
                entry
                    .res_headers
                    .get("www-authenticate")
                    .map(|s| s.as_str())
                    .unwrap_or(""),
                120,
            )
        ),
        Protocol::X402 => {
            let value = entry
                .res_headers
                .get("payment-required")
                .or_else(|| entry.res_headers.get("x-payment-required"))
                .map(|s| s.as_str())
                .unwrap_or("");
            format!("payment-required: {}", truncate(value, 120))
        }
    }
}

/// Browser plumbing aimed at the gateway itself (opening the web UI makes
/// the browser probe these against the root) — not inference traffic, so
/// `AllExchanges` mode keeps it out of the flow list. The requests still
/// forward; they're just not recorded.
fn is_browser_noise(path: &str) -> bool {
    path == "/"
        || path == "/favicon.ico"
        || path == "/robots.txt"
        || path.starts_with("/apple-touch-icon")
}

fn is_x402_body(body: &Option<String>) -> bool {
    let Some(body) = body else { return false };
    body.contains("x402Version")
}

fn build_steps(protocol: &Protocol) -> Vec<FlowStep> {
    let payment_label = match protocol {
        Protocol::Mpp | Protocol::X402 | Protocol::Http => "Paid Request",
        Protocol::Session => "Open / Voucher",
    };
    let challenge_label = match protocol {
        Protocol::Session => "402 Session Intent",
        Protocol::Mpp | Protocol::X402 | Protocol::Http => "402 Payment Gate",
    };
    vec![
        FlowStep {
            key: "request".into(),
            label: "Initial Request".into(),
            status: StepStatus::Pending,
            ts: None,
        },
        FlowStep {
            key: "challenge".into(),
            label: challenge_label.into(),
            status: StepStatus::Pending,
            ts: None,
        },
        FlowStep {
            key: "payment".into(),
            label: payment_label.into(),
            status: StepStatus::Pending,
            ts: None,
        },
        FlowStep {
            key: "delivery".into(),
            label: "Resource Delivered".into(),
            status: StepStatus::Pending,
            ts: None,
        },
    ]
}

fn update_steps(flow: &mut PaymentFlow) {
    let completed_count = match flow.status {
        // InProgress only occurs on exchange flows, which manage their own
        // 2-step diagram via `complete_exchange_steps`; treat like a fresh
        // payment flow if it ever reaches here.
        FlowStatus::PaymentRequired | FlowStatus::InProgress => 2,
        FlowStatus::PaymentReceived => 3,
        FlowStatus::ResourceDelivered => 4,
        FlowStatus::Failed => {
            for step in &mut flow.steps {
                if matches!(step.status, StepStatus::InProgress) {
                    step.status = StepStatus::Pending;
                }
            }
            return;
        }
    };

    for (i, step) in flow.steps.iter_mut().enumerate() {
        if i < completed_count {
            step.status = StepStatus::Completed;
            if step.ts.is_none() {
                step.ts = Some(flow.updated_at.clone());
            }
        } else if i == completed_count {
            step.status = StepStatus::InProgress;
        } else {
            step.status = StepStatus::Pending;
        }
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() > max { &s[..max] } else { s }
}

fn elapsed_ms(start: &str, end: &str) -> Option<u64> {
    let start = chrono::DateTime::parse_from_rfc3339(start).ok()?;
    let end = chrono::DateTime::parse_from_rfc3339(end).ok()?;
    u64::try_from(
        end.timestamp_millis()
            .saturating_sub(start.timestamp_millis()),
    )
    .ok()
}

/// Extract a human-readable amount from the 402 challenge headers.
/// MPP: parses the base64 `request` param from `www-authenticate`.
/// x402: parses the JSON response body for `amount`.
fn extract_amount(entry: &LogEntry) -> Option<String> {
    // MPP: www-authenticate header contains request="<base64>"
    if let Some(www_auth) = entry.res_headers.get("www-authenticate")
        && let Some(start) = www_auth.find("request=\"")
    {
        let rest = &www_auth[start + 9..];
        if let Some(end) = rest.find('"')
            && let Some(json) = decode_json_value(&rest[..end])
            && let Some(amount) = challenge_request_amount(&json)
        {
            return Some(amount);
        }
    }

    // x402: response body JSON
    if let Some(body) = &entry.res_body
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(body)
        && let Some(amount) = json["amount"].as_str()
    {
        return Some(amount.to_string());
    }

    x402_required_amount(&entry.res_headers)
}

/// Human-readable amount from a decoded MPP challenge `request` object.
fn challenge_request_amount(request: &serde_json::Value) -> Option<String> {
    let amount = request["amount"]
        .as_str()
        .or_else(|| request["cap"].as_str())
        .unwrap_or("0");
    let decimals = request["methodDetails"]["decimals"]
        .as_u64()
        .or_else(|| request["decimals"].as_u64())
        .unwrap_or(6);
    let raw = amount.parse::<u64>().ok()?;
    if raw == u64::MAX {
        return Some("unbounded".to_string());
    }
    let value = raw as f64 / 10f64.powi(decimals as i32);
    Some(format!("{:.4} USDC", value))
}

fn x402_required_amount(headers: &HashMap<String, String>) -> Option<String> {
    for key in ["payment-required", "x-payment-required"] {
        let Some(required) = headers.get(key).and_then(|h| decode_json_value(h)) else {
            continue;
        };
        let Some(offers) = required.get("accepts").or_else(|| required.get("offers")) else {
            continue;
        };
        let Some(amount) = offers
            .as_array()
            .and_then(|offers| offers.first())
            .and_then(|offer| offer.get("amount"))
            .and_then(|value| value_string(Some(value)))
        else {
            continue;
        };
        if let Some(formatted) = format_stable_amount(&amount) {
            return Some(formatted);
        }
    }
    None
}

fn format_stable_amount(raw: &str) -> Option<String> {
    let raw = raw.parse::<u64>().ok()?;
    Some(format!("{:.4} USDC", stable_usd_from_base_units(raw)))
}

fn stable_usd_from_base_units(raw: u64) -> f64 {
    raw as f64 / 1_000_000.0
}

/// Settled amount for a paid exchange (`AllExchanges` mode): a 2xx response
/// whose request carried a payment credential and whose response carries a
/// settlement receipt.
fn paid_exchange_amount(entry: &LogEntry) -> Option<String> {
    paid_exchange_request(entry)
        .and_then(|request| challenge_request_amount(&request))
        .or_else(|| x402_settlement_amount(entry))
}

/// Numeric USD value of a paid exchange — stablecoins aggregate 1:1 into USD
/// across currencies (USDC/USDT/CASH…). `None` for unpaid/unbounded.
fn paid_exchange_usd(entry: &LogEntry) -> Option<f64> {
    if let Some(request) = paid_exchange_request(entry) {
        let raw = request["amount"]
            .as_str()
            .or_else(|| request["cap"].as_str())?
            .parse::<u64>()
            .ok()?;
        if raw == u64::MAX {
            return None;
        }
        let decimals = request["methodDetails"]["decimals"]
            .as_u64()
            .or_else(|| request["decimals"].as_u64())
            .unwrap_or(6);
        return Some(raw as f64 / 10f64.powi(decimals as i32));
    }

    x402_settlement_response(entry)
        .and_then(|receipt| value_string(receipt.get("amount")))
        .and_then(|amount| amount.parse::<u64>().ok())
        .map(stable_usd_from_base_units)
}

/// Decoded challenge `request` payload from a settled (2xx) paid exchange.
fn paid_exchange_request(entry: &LogEntry) -> Option<serde_json::Value> {
    if !(200..300).contains(&entry.status) {
        return None;
    }
    let credential = payment_credential_from_authorization(entry.req_headers.get("authorization"))?;
    let request = credential.get("challenge")?.get("request")?;
    match request {
        serde_json::Value::String(encoded) => decode_json_value(encoded),
        value @ serde_json::Value::Object(_) => Some(value.clone()),
        _ => None,
    }
}

fn x402_settlement_response(entry: &LogEntry) -> Option<serde_json::Value> {
    if !(200..300).contains(&entry.status) {
        return None;
    }
    for key in [
        X402_PAYMENT_RESPONSE_HEADER,
        X402_LEGACY_PAYMENT_RESPONSE_HEADER,
    ] {
        if let Some(value) = entry.res_headers.get(key)
            && let Some(json) = decode_json_value(value)
        {
            return Some(json);
        }
    }
    None
}

fn x402_settlement_amount(entry: &LogEntry) -> Option<String> {
    x402_settlement_response(entry)
        .and_then(|receipt| value_string(receipt.get("amount")))
        .and_then(|amount| format_stable_amount(&amount))
}

/// Extract the payer's pubkey from the payment authorization header.
///
/// MPP format: `Payment <base64url-json>` where JSON contains a
/// `payload.transaction` (base64 Solana tx — first signer is the payer).
fn extract_payer(headers: &HashMap<String, String>) -> Option<String> {
    extract_mpp_payer(headers).or_else(|| extract_x402_payer(headers))
}

fn extract_mpp_payer(headers: &HashMap<String, String>) -> Option<String> {
    let auth = headers.get("authorization")?;
    let token = auth
        .strip_prefix("Payment ")
        .or_else(|| {
            // Also try case-insensitive match
            let lower = auth.to_lowercase();
            if lower.starts_with("payment ") {
                Some(&auth[8..])
            } else {
                None
            }
        })?
        .trim();

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(token))
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;

    // Try payload.transaction (base64 Solana tx).
    // When feePayer is true, account_keys[0] is the server's fee payer.
    // The actual client/payer is the second signer (the one who signed
    // the token transfer). We find them by looking at which signatures
    // are non-zero (the client signs, the fee payer slot is zeroed out
    // for the server to fill in later).
    if let Some(tx_b64) = json["payload"]["transaction"].as_str() {
        let tx_bytes = base64::engine::general_purpose::STANDARD
            .decode(tx_b64)
            .ok()?;
        let tx: solana_transaction::Transaction = bincode::deserialize(&tx_bytes).ok()?;

        // Find the first account key whose signature is non-zero
        // (the client-signed key). The fee payer signature is typically
        // all zeros because the server fills it in after verification.
        let zero_sig = [0u8; 64];
        for (i, sig) in tx.signatures.iter().enumerate() {
            if sig.as_ref() != zero_sig && i < tx.message.account_keys.len() {
                return Some(tx.message.account_keys[i].to_string());
            }
        }
        // Fallback: first account key
        let pubkey = tx.message.account_keys.first()?;
        return Some(pubkey.to_string());
    }

    // Try source field (if the SDK sets it)
    json["source"].as_str().map(|s| s.to_string())
}

fn extract_x402_payer(headers: &HashMap<String, String>) -> Option<String> {
    for key in ["payment-signature", "x-payment"] {
        if let Some(json) = headers.get(key).and_then(|value| decode_json_value(value)) {
            return value_string(json.get("payload").and_then(|p| p.get("from")))
                .or_else(|| value_string(json.get("payload").and_then(|p| p.get("payer"))))
                .or_else(|| value_string(json.get("payer")))
                .or_else(|| value_string(json.get("source")));
        }
    }
    None
}

fn is_session_challenge(entry: &LogEntry) -> bool {
    entry
        .res_headers
        .get("www-authenticate")
        .and_then(|header| payment_challenge_from_header(header))
        .and_then(|params| params.get("intent").cloned())
        .is_some_and(|intent| intent == "session")
}

fn session_from_challenge(entry: &LogEntry) -> Option<SessionInfo> {
    let challenge = entry
        .res_headers
        .get("www-authenticate")
        .and_then(|header| payment_challenge_from_header(header))?;
    if challenge.get("intent").map(String::as_str) != Some("session") {
        return None;
    }
    let request = challenge
        .get("request")
        .and_then(|encoded| decode_json_value(encoded))?;
    let mode = request
        .get("modes")
        .and_then(|modes| modes.as_array())
        .and_then(|modes| {
            modes
                .iter()
                .filter_map(|mode| mode.as_str())
                .find(|mode| *mode == "push" || *mode == "pull")
        })
        .map(str::to_string);

    Some(SessionInfo {
        session_id: None,
        state: SessionState::Opening,
        action: None,
        mode,
        currency: value_string(request.get("currency")),
        decimals: request
            .get("decimals")
            .and_then(|v| v.as_u64())
            .and_then(|v| u8::try_from(v).ok()),
        cap: value_string(request.get("cap")),
        min_voucher_delta: value_string(request.get("minVoucherDelta")),
        deposit: None,
        approved_amount: None,
        cumulative: None,
        delta: None,
        voucher_count: None,
        authorized_signer: None,
        owner: None,
        payer: None,
        recipient: value_string(request.get("recipient")),
        splits: session_splits(request.get("splits")),
        delivery_id: None,
        opened_at: None,
        updated_at: Some(entry.ts.clone()),
    })
}

fn is_session_authorization(auth: Option<&String>) -> bool {
    payment_credential_from_authorization(auth)
        .and_then(|credential| {
            credential
                .get("challenge")
                .and_then(|challenge| challenge.get("intent"))
                .and_then(|intent| intent.as_str())
                .map(str::to_string)
        })
        .is_some_and(|intent| intent == "session")
}

fn session_from_authorization(
    entry: &LogEntry,
    previous: Option<&SessionInfo>,
) -> Option<SessionInfo> {
    let credential = payment_credential_from_authorization(entry.req_headers.get("authorization"))?;
    let challenge = credential.get("challenge")?;
    if challenge.get("intent").and_then(|v| v.as_str()) != Some("session") {
        return None;
    }
    let payload = credential.get("payload")?;
    let action = session_action(payload.get("action"));
    let receipt = parse_commit_receipt(entry.res_body.as_deref());
    let voucher_data = payload
        .get("voucher")
        .and_then(|voucher| voucher.get("data"));
    let cumulative = receipt
        .as_ref()
        .and_then(|r| r.cumulative.clone())
        .or_else(|| value_string(voucher_data.and_then(|d| d.get("cumulativeAmount"))))
        .or_else(|| value_string(voucher_data.and_then(|d| d.get("cumulative"))))
        .or_else(|| previous.and_then(|s| s.cumulative.clone()));
    let session_id = receipt
        .as_ref()
        .and_then(|r| r.session_id.clone())
        .or_else(|| value_string(payload.get("channelId")))
        .or_else(|| value_string(payload.get("tokenAccount")))
        .or_else(|| value_string(voucher_data.and_then(|d| d.get("channelId"))))
        .or_else(|| previous.and_then(|s| s.session_id.clone()));
    let has_voucher = voucher_data.is_some();
    let state = if entry.status >= 200 && entry.status < 300 {
        if action.as_deref() == Some("close") {
            SessionState::Closed
        } else {
            SessionState::Open
        }
    } else {
        SessionState::Failed
    };

    let previous_vouchers = previous.and_then(|s| s.voucher_count).unwrap_or(0);
    let action_is_open = action.as_deref() == Some("open");

    Some(SessionInfo {
        session_id,
        state,
        action,
        mode: session_mode(payload.get("mode")).or_else(|| previous.and_then(|s| s.mode.clone())),
        currency: previous.and_then(|s| s.currency.clone()),
        decimals: previous.and_then(|s| s.decimals),
        cap: previous.and_then(|s| s.cap.clone()),
        min_voucher_delta: previous.and_then(|s| s.min_voucher_delta.clone()),
        deposit: value_string(payload.get("deposit"))
            .or_else(|| previous.and_then(|s| s.deposit.clone())),
        approved_amount: value_string(payload.get("approvedAmount"))
            .or_else(|| previous.and_then(|s| s.approved_amount.clone())),
        cumulative,
        delta: receipt
            .as_ref()
            .and_then(|r| r.amount.clone())
            .or_else(|| previous.and_then(|s| s.delta.clone())),
        voucher_count: Some(previous_vouchers + if has_voucher { 1 } else { 0 }),
        authorized_signer: value_string(payload.get("authorizedSigner"))
            .or_else(|| previous.and_then(|s| s.authorized_signer.clone())),
        owner: value_string(payload.get("owner"))
            .or_else(|| previous.and_then(|s| s.owner.clone())),
        payer: value_string(payload.get("payer"))
            .or_else(|| value_string(credential.get("source")))
            .or_else(|| previous.and_then(|s| s.payer.clone())),
        recipient: previous.and_then(|s| s.recipient.clone()),
        splits: previous.map(|s| s.splits.clone()).unwrap_or_default(),
        delivery_id: receipt
            .as_ref()
            .and_then(|r| r.delivery_id.clone())
            .or_else(|| value_string(payload.get("deliveryId")))
            .or_else(|| previous.and_then(|s| s.delivery_id.clone())),
        opened_at: previous
            .and_then(|s| s.opened_at.clone())
            .or_else(|| action_is_open.then(|| entry.ts.clone())),
        updated_at: Some(entry.ts.clone()),
    })
}

fn session_accepted_message(session: Option<&SessionInfo>) -> String {
    match session.and_then(|s| s.action.as_deref()) {
        Some("open") => "Session channel opened".into(),
        Some("voucher") => "Session voucher accepted".into(),
        Some("commit") => "Session delivery committed".into(),
        Some("topUp") => "Session channel topped up".into(),
        Some("close") => "Session channel closed".into(),
        _ => "Session action accepted".into(),
    }
}

fn session_event_detail(session: Option<&SessionInfo>) -> Option<String> {
    let session = session?;
    let parts = [
        session
            .session_id
            .as_ref()
            .map(|id| format!("session={}", shorten(id))),
        session.mode.as_ref().map(|mode| format!("mode={mode}")),
        session
            .cumulative
            .as_ref()
            .map(|cumulative| format!("cumulative={cumulative}")),
        session.delta.as_ref().map(|delta| format!("delta={delta}")),
        session
            .delivery_id
            .as_ref()
            .map(|delivery| format!("delivery={}", shorten(delivery))),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    (!parts.is_empty()).then(|| parts.join(" · "))
}

fn payment_challenge_from_header(header: &str) -> Option<HashMap<String, String>> {
    let challenge = header
        .split("\nPayment ")
        .map(|part| {
            if part.starts_with("Payment ") {
                part.to_string()
            } else {
                format!("Payment {part}")
            }
        })
        .find(|part| part.starts_with("Payment ") && part.contains("intent=\"session\""))
        .or_else(|| header.starts_with("Payment ").then(|| header.to_string()))?;
    Some(parse_header_params(
        challenge.trim_start_matches("Payment ").trim(),
    ))
}

fn payment_credential_from_authorization(auth: Option<&String>) -> Option<serde_json::Value> {
    let auth = auth?;
    if !auth.to_ascii_lowercase().starts_with("payment ") {
        return None;
    }
    decode_json_value(auth.get(8..)?.trim())
}

fn parse_header_params(value: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for segment in value.split(',') {
        let Some((key, raw_value)) = segment.trim().split_once('=') else {
            continue;
        };
        let parsed = raw_value
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        params.insert(key.trim().to_string(), parsed);
    }
    params
}

fn decode_json_value(encoded: &str) -> Option<serde_json::Value> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .ok()?;
    serde_json::from_slice(&decoded).ok()
}

struct CommitReceiptView {
    amount: Option<String>,
    cumulative: Option<String>,
    delivery_id: Option<String>,
    session_id: Option<String>,
}

fn parse_commit_receipt(body: Option<&str>) -> Option<CommitReceiptView> {
    let parsed: serde_json::Value = serde_json::from_str(body?).ok()?;
    if parsed.get("sessionId").is_none() && parsed.get("cumulative").is_none() {
        return None;
    }
    Some(CommitReceiptView {
        amount: value_string(parsed.get("amount")),
        cumulative: value_string(parsed.get("cumulative")),
        delivery_id: value_string(parsed.get("deliveryId")),
        session_id: value_string(parsed.get("sessionId")),
    })
}

fn session_splits(value: Option<&serde_json::Value>) -> Vec<SessionSplit> {
    value
        .and_then(|value| value.as_array())
        .map(|splits| {
            splits
                .iter()
                .filter_map(|split| {
                    let recipient = value_string(split.get("recipient"))?;
                    let bps = split
                        .get("bps")
                        .and_then(|value| value.as_u64())
                        .and_then(|value| u16::try_from(value).ok())?;
                    Some(SessionSplit {
                        recipient,
                        bps,
                        label: value_string(split.get("label")),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn session_action(value: Option<&serde_json::Value>) -> Option<String> {
    match value.and_then(|value| value.as_str()) {
        Some("open" | "voucher" | "commit" | "topUp" | "close") => {
            value.and_then(|value| value.as_str()).map(str::to_string)
        }
        _ => None,
    }
}

fn session_mode(value: Option<&serde_json::Value>) -> Option<String> {
    match value.and_then(|value| value.as_str()) {
        Some("push" | "pull") => value.and_then(|value| value.as_str()).map(str::to_string),
        _ => None,
    }
}

fn value_string(value: Option<&serde_json::Value>) -> Option<String> {
    match value? {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn shorten(value: &str) -> String {
    if value.len() > 16 {
        format!("{}…{}", &value[..6], &value[value.len() - 6..])
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(method: &str, path: &str, status: u16) -> LogEntry {
        LogEntry {
            id: 1,
            ts: "2026-04-02T00:00:00.000Z".into(),
            method: method.into(),
            path: path.into(),
            status,
            ms: 50,
            req_headers: HashMap::new(),
            res_headers: HashMap::new(),
            res_body: None,
            client_ip: "127.0.0.1".into(),
        }
    }

    fn encode_json(value: serde_json::Value) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string().as_bytes())
    }

    fn session_challenge_header() -> String {
        let request = encode_json(serde_json::json!({
            "cap": "1000000",
            "currency": "USDC",
            "decimals": 6,
            "operator": "operator",
            "recipient": "recipient",
            "minVoucherDelta": "1",
            "modes": ["push"],
            "splits": [{"recipient": "split-recipient", "bps": 1000}]
        }));
        format!(
            "Payment realm=\"test\", method=\"solana\", intent=\"session\", request=\"{request}\""
        )
    }

    fn session_authorization(payload: serde_json::Value) -> String {
        let credential = encode_json(serde_json::json!({
            "challenge": {"intent": "session"},
            "payload": payload,
            "source": "payer-wallet"
        }));
        format!("Payment {credential}")
    }

    #[test]
    fn challenge_creates_flow() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::new(tx);

        let mut entry = make_entry("GET", "/mpp/quote/GOOG", 402);
        entry
            .res_headers
            .insert("www-authenticate".into(), "Payment realm=\"test\"".into());

        engine.ingest(entry);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, FlowStatus::PaymentRequired);
        assert_eq!(flows[0].resource, "/mpp/quote/GOOG");
        assert_eq!(flows[0].events.len(), 2);
    }

    #[test]
    fn retry_completes_flow() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::new(tx);

        // Challenge
        let mut challenge = make_entry("GET", "/mpp/quote/GOOG", 402);
        challenge
            .res_headers
            .insert("www-authenticate".into(), "Payment realm=\"test\"".into());
        engine.ingest(challenge);

        // Retry
        let mut retry = make_entry("GET", "/mpp/quote/GOOG", 200);
        retry
            .res_headers
            .insert("payment-receipt".into(), "receipt-data".into());
        engine.ingest(retry);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, FlowStatus::ResourceDelivered);
    }

    #[test]
    fn internal_paths_skipped() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::new(tx);

        engine.ingest(make_entry("GET", "/__402/pdb/logs", 200));
        engine.ingest(make_entry("GET", "/__402/health", 200));

        assert!(engine.snapshot().is_empty());
    }

    #[test]
    fn x402_challenge_detected() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::new(tx);

        let mut entry = make_entry("GET", "/x402/joke", 402);
        entry.res_body = Some(r#"{"x402Version":"1","amount":"1000"}"#.into());
        engine.ingest(entry);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1);
        assert!(matches!(flows[0].protocol, Protocol::X402));
    }

    #[test]
    fn session_challenge_creates_session_flow() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::new(tx);

        let mut entry = make_entry("POST", "/v1/generate", 402);
        entry
            .res_headers
            .insert("www-authenticate".into(), session_challenge_header());

        engine.ingest(entry);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1);
        assert!(matches!(flows[0].protocol, Protocol::Session));
        assert_eq!(flows[0].steps[1].label, "402 Session Intent");
        assert_eq!(flows[0].amount, None);
        let session = flows[0].session.as_ref().expect("session metadata");
        assert!(matches!(session.state, SessionState::Opening));
        assert_eq!(session.currency.as_deref(), Some("USDC"));
        assert_eq!(session.splits.len(), 1);
    }

    #[test]
    fn session_open_retry_marks_channel_open() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::new(tx);

        let mut challenge = make_entry("POST", "/v1/generate", 402);
        challenge
            .res_headers
            .insert("www-authenticate".into(), session_challenge_header());
        engine.ingest(challenge);

        let mut retry = make_entry("POST", "/v1/generate", 200);
        retry.req_headers.insert(
            "authorization".into(),
            session_authorization(serde_json::json!({
                "action": "open",
                "mode": "push",
                "channelId": "channel-111",
                "deposit": "1000000",
                "authorizedSigner": "session-signer",
                "signature": "open-signature"
            })),
        );
        engine.ingest(retry);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, FlowStatus::ResourceDelivered);
        let session = flows[0].session.as_ref().expect("session metadata");
        assert!(matches!(session.state, SessionState::Open));
        assert_eq!(session.action.as_deref(), Some("open"));
        assert_eq!(session.session_id.as_deref(), Some("channel-111"));
        assert_eq!(session.deposit.as_deref(), Some("1000000"));
    }

    #[test]
    fn session_commit_retry_merges_into_delivered_session_flow() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::new(tx);

        let mut challenge = make_entry("POST", "/v1/generate", 402);
        challenge
            .res_headers
            .insert("www-authenticate".into(), session_challenge_header());
        engine.ingest(challenge);

        let mut open = make_entry("POST", "/v1/generate", 200);
        open.req_headers.insert(
            "authorization".into(),
            session_authorization(serde_json::json!({
                "action": "open",
                "mode": "push",
                "channelId": "channel-111",
                "deposit": "1000000",
                "authorizedSigner": "session-signer",
                "signature": "open-signature"
            })),
        );
        engine.ingest(open);

        let mut commit = make_entry("POST", "/v1/generate", 200);
        commit.req_headers.insert(
            "authorization".into(),
            session_authorization(serde_json::json!({
                "action": "commit",
                "deliveryId": "delivery-1",
                "voucher": {
                    "data": {
                        "channelId": "channel-111",
                        "cumulativeAmount": "25",
                        "expiresAt": 4102444800_u64
                    },
                    "signature": "voucher-signature"
                }
            })),
        );
        commit.res_body = Some(
            serde_json::json!({
                "deliveryId": "delivery-1",
                "sessionId": "channel-111",
                "amount": "25",
                "cumulative": "25",
                "status": "committed"
            })
            .to_string(),
        );
        engine.ingest(commit);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, FlowStatus::ResourceDelivered);
        assert!(
            flows[0]
                .events
                .iter()
                .any(|event| event.message == "Session delivery committed")
        );
        let session = flows[0].session.as_ref().expect("session metadata");
        assert_eq!(session.action.as_deref(), Some("commit"));
        assert_eq!(session.session_id.as_deref(), Some("channel-111"));
        assert_eq!(session.cumulative.as_deref(), Some("25"));
        assert_eq!(session.delta.as_deref(), Some("25"));
        assert_eq!(session.delivery_id.as_deref(), Some("delivery-1"));
        assert_eq!(session.voucher_count, Some(1));
        assert_eq!(session.currency.as_deref(), Some("USDC"));
    }

    #[test]
    fn standalone_delivery_when_no_challenge() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::new(tx);

        let mut entry = make_entry("GET", "/mpp/quote/GOOG", 200);
        entry
            .res_headers
            .insert("payment-receipt".into(), "receipt-data".into());
        engine.ingest(entry);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, FlowStatus::ResourceDelivered);
    }

    #[test]
    fn duplicate_challenges_dedup_into_one_flow() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::new(tx);

        // Three 402 probes for the same endpoint before paying.
        for _ in 0..3 {
            let mut e = make_entry("GET", "/api/v1/joke", 402);
            e.res_headers.insert(
                "www-authenticate".into(),
                "Payment realm=\"t\", intent=\"charge\"".into(),
            );
            engine.ingest(e);
        }

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1, "re-issued challenges must not orphan rows");
        assert_eq!(flows[0].status, FlowStatus::PaymentRequired);
        assert_eq!(flows[0].scheme.as_deref(), Some("charge"));
    }

    #[test]
    fn mpp_charge_then_pay_is_one_flow_labeled_charge() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::new(tx);

        let mut ch = make_entry("GET", "/api/v1/joke", 402);
        ch.res_headers.insert(
            "www-authenticate".into(),
            "Payment realm=\"t\", intent=\"charge\"".into(),
        );
        engine.ingest(ch);

        let mut rt = make_entry("GET", "/api/v1/joke", 200);
        rt.req_headers
            .insert("authorization".into(), "Payment abc".into());
        rt.res_headers
            .insert("payment-receipt".into(), "receipt".into());
        engine.ingest(rt);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, FlowStatus::ResourceDelivered);
        assert!(matches!(flows[0].protocol, Protocol::Mpp));
        assert_eq!(flows[0].scheme.as_deref(), Some("charge"));
    }

    #[test]
    fn retry_adopts_actual_x402_scheme_over_mpp_challenge() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::new(tx);

        // Dual-scheme endpoint: the 402 carries both www-authenticate (mpp) and
        // payment-required (x402); detect() labels the challenge mpp.
        let mut ch = make_entry("GET", "/api/v1/fortune", 402);
        ch.res_headers.insert(
            "www-authenticate".into(),
            "Payment realm=\"t\", intent=\"charge\"".into(),
        );
        ch.res_headers.insert(
            "payment-required".into(),
            encode_json(serde_json::json!({
                "x402Version": 1,
                "accepts": [{ "scheme": "exact", "amount": "10000" }]
            })),
        );
        engine.ingest(ch);
        assert!(matches!(engine.snapshot()[0].protocol, Protocol::Mpp));

        // The client pays with x402 → the flow must adopt x402:exact, not stay mpp.
        let mut rt = make_entry("GET", "/api/v1/fortune", 200);
        rt.req_headers.insert(
            "payment-signature".into(),
            encode_json(serde_json::json!({
                "x402Version": 2,
                "payload": {},
                "accepted": { "scheme": "exact" }
            })),
        );
        rt.res_headers
            .insert(X402_PAYMENT_RESPONSE_HEADER.into(), "sig".into());
        engine.ingest(rt);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1, "x402 retry merges, not standalone");
        assert!(matches!(flows[0].protocol, Protocol::X402));
        assert_eq!(flows[0].scheme.as_deref(), Some("exact"));
        assert_eq!(flows[0].status, FlowStatus::ResourceDelivered);
    }

    #[test]
    fn x402_upto_scheme_inferred_from_channel_payload() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::new(tx);

        let mut ch = make_entry("POST", "/api/v1/summarize", 402);
        ch.res_headers.insert(
            "payment-required".into(),
            encode_json(serde_json::json!({
                "x402Version": 2,
                "accepts": [{ "scheme": "upto", "amount": "100000" }]
            })),
        );
        engine.ingest(ch);

        let flows = engine.snapshot();
        assert!(matches!(flows[0].protocol, Protocol::X402));
        assert_eq!(flows[0].scheme.as_deref(), Some("upto"));
    }

    #[test]
    fn max_flows_eviction() {
        let (tx, _rx) = broadcast::channel(256);
        let mut engine = FlowCorrelation::new(tx);

        for i in 0..=MAX_FLOWS {
            let mut entry = make_entry("GET", &format!("/path/{i}"), 402);
            entry
                .res_headers
                .insert("www-authenticate".into(), "Payment realm=\"test\"".into());
            entry.client_ip = format!("10.0.0.{}", i % 256);
            engine.ingest(entry);
        }

        assert_eq!(engine.snapshot().len(), MAX_FLOWS);
    }

    // ── AllExchanges mode ────────────────────────────────────────────────

    fn make_start(id: u64, method: &str, path: &str) -> ExchangeStart {
        ExchangeStart {
            id,
            ts: "2026-04-02T00:00:00.000Z".into(),
            method: method.into(),
            path: path.into(),
            client_ip: "127.0.0.1".into(),
            payment_retry: false,
            inference: Some(InferenceInfo {
                provider: "ollama".into(),
                model: Some("llama3.2:3b".into()),
                streamed: true,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn all_exchanges_start_then_complete() {
        let (tx, mut rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        engine.begin_exchange(make_start(7, "POST", "/v1/chat/completions"));

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, FlowStatus::InProgress);
        assert!(matches!(flows[0].protocol, Protocol::Http));
        assert_eq!(
            flows[0].inference.as_ref().unwrap().provider,
            "ollama".to_string()
        );
        assert!(matches!(
            rx.try_recv().unwrap(),
            SseMessage::FlowCreated { .. }
        ));

        let mut done = make_entry("POST", "/v1/chat/completions", 200);
        done.id = 7;
        done.ts = "2026-04-02T00:00:02.500Z".into();
        engine.ingest(done);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1, "completion must not create a second flow");
        assert_eq!(flows[0].status, FlowStatus::ResourceDelivered);
        assert_eq!(
            flows[0].duration_ms, 2500,
            "duration from start ts, not entry.ms"
        );
        // Inference survives completion.
        assert_eq!(
            flows[0].inference.as_ref().unwrap().model.as_deref(),
            Some("llama3.2:3b")
        );
        assert!(matches!(
            rx.try_recv().unwrap(),
            SseMessage::FlowUpdated { .. }
        ));
    }

    #[test]
    fn all_exchanges_failure_marks_failed() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        engine.begin_exchange(make_start(1, "GET", "/v1/models"));
        let mut done = make_entry("GET", "/v1/models", 500);
        done.id = 1;
        engine.ingest(done);

        assert_eq!(engine.snapshot()[0].status, FlowStatus::Failed);
    }

    #[test]
    fn all_exchanges_update_streams_telemetry() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        engine.begin_exchange(make_start(3, "POST", "/v1/chat/completions"));
        engine.update_exchange(
            3,
            InferenceInfo {
                provider: "ollama".into(),
                model: Some("llama3.2:3b".into()),
                streamed: true,
                tokens_completion: Some(42),
                ttft_ms: Some(180),
                tokens_per_sec: Some(41.2),
                ..Default::default()
            },
        );

        let flow = &engine.snapshot()[0];
        assert_eq!(flow.status, FlowStatus::InProgress);
        let inf = flow.inference.as_ref().unwrap();
        assert_eq!(inf.tokens_completion, Some(42));
        assert_eq!(inf.ttft_ms, Some(180));

        // After completion the update is a no-op (exchange no longer open).
        let mut done = make_entry("POST", "/v1/chat/completions", 200);
        done.id = 3;
        engine.ingest(done);
        engine.update_exchange(
            3,
            InferenceInfo {
                provider: "changed".into(),
                ..Default::default()
            },
        );
        assert_eq!(
            engine.snapshot()[0].inference.as_ref().unwrap().provider,
            "ollama"
        );
    }

    #[test]
    fn update_exchange_merges_field_wise() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        // Request-time info: provider + endpoint kind, nothing else.
        engine.begin_exchange(ExchangeStart {
            inference: Some(InferenceInfo {
                provider: "ollama".into(),
                endpoint_kind: Some("chat".into()),
                ..Default::default()
            }),
            ..make_start(9, "POST", "/v1/chat/completions")
        });

        // Stream-observer update: usage only, empty provider.
        engine.update_exchange(
            9,
            InferenceInfo {
                provider: String::new(),
                model: Some("llama3.2:3b".into()),
                streamed: true,
                tokens_completion: Some(10),
                ..Default::default()
            },
        );

        let inf = engine.snapshot()[0].inference.clone().unwrap();
        assert_eq!(inf.provider, "ollama", "provider must survive usage merge");
        assert_eq!(inf.endpoint_kind.as_deref(), Some("chat"));
        assert_eq!(inf.model.as_deref(), Some("llama3.2:3b"));
        assert!(inf.streamed);
        assert_eq!(inf.tokens_completion, Some(10));
    }

    fn charge_authorization(amount: &str, decimals: u64) -> String {
        // Mirrors pay-kit's PaymentCredential: the challenge is echoed back
        // with its base64url `request` payload (amount + methodDetails).
        let request = encode_json(serde_json::json!({
            "amount": amount,
            "currency": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "methodDetails": {"decimals": decimals, "network": "localnet"},
            "recipient": "F82JMeQmD7Lfbh6vCJWsz2ABJ5AAthhVjUyqzgHyUtog"
        }));
        let credential = encode_json(serde_json::json!({
            "challenge": {
                "id": "ch-1", "realm": "test", "method": "solana",
                "intent": "charge", "request": request
            },
            // `source` is extract_payer's fallback when the payload carries
            // no transaction (a stub one would short-circuit the fallback).
            "source": "payer-wallet-1",
            "payload": {"type": "transaction"}
        }));
        format!("Payment {credential}")
    }

    fn x402_required(amount: &str) -> String {
        encode_json(serde_json::json!({
            "x402Version": 2,
            "accepts": [{
                "scheme": "upto",
                "network": "solana-localnet",
                "amount": amount,
                "asset": "USDC",
            }]
        }))
    }

    fn x402_payment_signature(payer: &str) -> String {
        encode_json(serde_json::json!({
            "x402Version": 2,
            "accepted": {"scheme": "upto"},
            "payload": {
                "from": payer,
                "channelId": "channel-1",
                "maxAmount": "100000",
            }
        }))
    }

    fn x402_payment_response(amount: &str) -> String {
        encode_json(serde_json::json!({
            "success": true,
            "payer": "payer-wallet-x402",
            "transaction": "settlement-signature-x402",
            "network": "solana-localnet",
            "amount": amount,
        }))
    }

    #[test]
    fn all_exchanges_paid_completion_sets_amount() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        engine.begin_exchange(make_start(4, "POST", "/v1/messages"));
        let mut done = make_entry("POST", "/v1/messages", 200);
        done.id = 4;
        done.req_headers
            .insert("authorization".into(), charge_authorization("1000", 6));
        engine.ingest(done);

        let flows = engine.snapshot();
        assert_eq!(flows[0].status, FlowStatus::ResourceDelivered);
        assert_eq!(
            flows[0].amount.as_deref(),
            Some("0.0010 USDC"),
            "settled charge must surface as the flow amount (drives the \
             stablecoin chart)"
        );
    }

    #[test]
    fn all_exchanges_failed_paid_retry_has_no_amount() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        engine.begin_exchange(make_start(5, "POST", "/v1/messages"));
        let mut done = make_entry("POST", "/v1/messages", 500);
        done.id = 5;
        done.req_headers
            .insert("authorization".into(), charge_authorization("1000", 6));
        engine.ingest(done);

        assert_eq!(engine.snapshot()[0].amount, None, "nothing settled on 5xx");
    }

    #[test]
    fn all_exchanges_unpaid_completion_has_no_amount() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        // Bearer token (Claude's upstream auth) is not a payment.
        let mut done = make_entry("POST", "/v1/messages", 200);
        done.req_headers
            .insert("authorization".into(), "Bearer ollama".into());
        engine.ingest(done);

        assert_eq!(engine.snapshot()[0].amount, None);
    }

    #[test]
    fn all_exchanges_completion_without_start_creates_completed_flow() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        engine.ingest(make_entry("GET", "/api/tags", 200));

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, FlowStatus::ResourceDelivered);
        assert!(matches!(flows[0].protocol, Protocol::Http));
    }

    #[test]
    fn challenge_and_paid_retry_merge_into_one_flow() {
        let (tx, _rx) = broadcast::channel(64);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        // Unpaid request → 402 MPP challenge: one flow, payment-required.
        engine.begin_exchange(make_start(1, "POST", "/v1/messages"));
        let mut challenge = make_entry("POST", "/v1/messages", 402);
        challenge.id = 1;
        challenge.res_headers.insert(
            "www-authenticate".into(),
            "Payment realm=\"t\", intent=\"charge\"".into(),
        );
        engine.ingest(challenge);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, FlowStatus::PaymentRequired);
        assert_eq!(flows[0].steps.len(), 4, "payment diagram from here on");

        // Paid retry: attaches to the SAME flow — no second row.
        engine.begin_exchange(ExchangeStart {
            payment_retry: true,
            ..make_start(2, "POST", "/v1/messages")
        });
        assert_eq!(engine.snapshot().len(), 1, "retry must not open a new row");
        assert_eq!(engine.snapshot()[0].status, FlowStatus::PaymentReceived);

        let mut done = make_entry("POST", "/v1/messages", 200);
        done.id = 2;
        done.req_headers
            .insert("authorization".into(), charge_authorization("1000", 6));
        engine.ingest(done);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1, "challenge + retry = one merged row");
        let flow = &flows[0];
        assert_eq!(flow.status, FlowStatus::ResourceDelivered);
        assert_eq!(flow.amount.as_deref(), Some("0.0010 USDC"));
        assert!(flow.payer.is_some());
        assert!(flow.challenge_headers.is_some());
        assert!(
            flow.steps
                .iter()
                .all(|s| matches!(s.status, StepStatus::Completed)),
            "all four payment steps completed"
        );
        // One connection aggregate, counted once (the paid completion).
        let connections = engine.connections_snapshot();
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].requests, 1);
        assert!((connections[0].paid_usd - 0.001).abs() < 1e-9);
    }

    #[test]
    fn x402_challenge_and_paid_retry_merge_and_record_settlement() {
        let (tx, _rx) = broadcast::channel(64);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        engine.begin_exchange(make_start(1, "POST", "/v1/messages"));
        let mut challenge = make_entry("POST", "/v1/messages", 402);
        challenge.id = 1;
        challenge
            .res_headers
            .insert("payment-required".into(), x402_required("100000"));
        engine.ingest(challenge);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1);
        assert!(matches!(flows[0].protocol, Protocol::X402));
        assert_eq!(flows[0].scheme.as_deref(), Some("upto"));
        assert_eq!(flows[0].amount.as_deref(), Some("0.1000 USDC"));
        assert_eq!(flows[0].status, FlowStatus::PaymentRequired);

        engine.begin_exchange(ExchangeStart {
            payment_retry: true,
            ..make_start(2, "POST", "/v1/messages")
        });
        assert_eq!(engine.snapshot().len(), 1);
        assert_eq!(engine.snapshot()[0].status, FlowStatus::PaymentReceived);

        let mut done = make_entry("POST", "/v1/messages", 200);
        done.id = 2;
        done.req_headers.insert(
            "payment-signature".into(),
            x402_payment_signature("payer-wallet-x402"),
        );
        done.res_headers.insert(
            X402_PAYMENT_RESPONSE_HEADER.into(),
            x402_payment_response("1234"),
        );
        engine.ingest(done);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1, "challenge + x402 retry = one row");
        let flow = &flows[0];
        assert_eq!(flow.status, FlowStatus::ResourceDelivered);
        assert_eq!(flow.amount.as_deref(), Some("0.0012 USDC"));
        assert_eq!(flow.payer.as_deref(), Some("payer-wallet-x402"));
        assert!(
            flow.response_headers
                .as_ref()
                .unwrap()
                .contains_key(X402_PAYMENT_RESPONSE_HEADER)
        );

        let connections = engine.connections_snapshot();
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].payer.as_deref(), Some("payer-wallet-x402"));
        assert_eq!(connections[0].requests, 1);
        assert!((connections[0].paid_usd - 0.001234).abs() < 1e-12);
    }

    #[test]
    fn concurrent_challenges_each_pair_with_a_retry() {
        // Claude fans out parallel requests to the same path: two challenges
        // are pending at once. A single-slot pending map orphaned the older
        // one (it timed out as a failed, model-less row) — the queue must
        // pair every retry with a challenge.
        let (tx, _rx) = broadcast::channel(64);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        for id in [1u64, 2] {
            engine.begin_exchange(make_start(id, "POST", "/v1/messages"));
            let mut challenge = make_entry("POST", "/v1/messages", 402);
            challenge.id = id;
            challenge.res_headers.insert(
                "www-authenticate".into(),
                "Payment realm=\"t\", intent=\"charge\"".into(),
            );
            engine.ingest(challenge);
        }
        assert_eq!(engine.snapshot().len(), 2);
        assert!(
            engine
                .snapshot()
                .iter()
                .all(|f| f.status == FlowStatus::PaymentRequired)
        );

        for id in [11u64, 12] {
            engine.begin_exchange(ExchangeStart {
                payment_retry: true,
                ..make_start(id, "POST", "/v1/messages")
            });
            let mut done = make_entry("POST", "/v1/messages", 200);
            done.id = id;
            done.req_headers
                .insert("authorization".into(), charge_authorization("1000", 6));
            engine.ingest(done);
        }

        let flows = engine.snapshot();
        assert_eq!(flows.len(), 2, "two logical requests, two rows");
        assert!(
            flows
                .iter()
                .all(|f| f.status == FlowStatus::ResourceDelivered),
            "no orphaned challenge left to time out"
        );
        assert_eq!(engine.connections_snapshot()[0].requests, 2);
    }

    #[test]
    fn plain_upstream_402_still_fails_without_merge() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        // A 402 from the upstream itself (no MPP challenge header).
        engine.begin_exchange(make_start(1, "POST", "/v1/messages"));
        let mut done = make_entry("POST", "/v1/messages", 402);
        done.id = 1;
        engine.ingest(done);

        assert_eq!(engine.snapshot()[0].status, FlowStatus::Failed);
    }

    #[test]
    fn retry_without_pending_challenge_opens_its_own_flow() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        // e.g. gateway restarted between challenge and retry.
        engine.begin_exchange(ExchangeStart {
            payment_retry: true,
            ..make_start(1, "POST", "/v1/messages")
        });
        let flows = engine.snapshot();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].status, FlowStatus::InProgress);
    }

    #[test]
    fn connections_aggregate_paid_activity() {
        let (tx, _rx) = broadcast::channel(64);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        // Two paid turns from the same wallet, plus the 402 handshakes.
        for (id, prompt, completion) in [(1u64, 12, 200), (3, 30, 400)] {
            // 402 challenge exchange — protocol handshake, must not count.
            let mut challenge = make_entry("POST", "/v1/messages", 402);
            challenge.id = id.wrapping_mul(100);
            engine.ingest(challenge);

            engine.begin_exchange(ExchangeStart {
                inference: Some(InferenceInfo {
                    provider: "ollama".into(),
                    model: Some("gemma4:latest".into()),
                    tokens_prompt: Some(prompt),
                    tokens_completion: Some(completion),
                    ..Default::default()
                }),
                ..make_start(id, "POST", "/v1/messages")
            });
            let mut done = make_entry("POST", "/v1/messages", 200);
            done.id = id;
            done.req_headers
                .insert("authorization".into(), charge_authorization("1000", 6));
            engine.ingest(done);
        }

        let connections = engine.connections_snapshot();
        assert_eq!(connections.len(), 1, "same payer wallet = one connection");
        let conn = &connections[0];
        assert!(conn.payer.is_some(), "paid traffic keys by payer");
        assert_eq!(conn.requests, 2, "402 handshakes excluded");
        assert_eq!(conn.ok, 2);
        assert_eq!(conn.failed, 0);
        assert_eq!(conn.tokens_prompt, 42);
        assert_eq!(conn.tokens_completion, 600);
        assert!((conn.paid_usd - 0.002).abs() < 1e-9, "2 × $0.001 settled");
        assert_eq!(conn.provider.as_deref(), Some("ollama"));
        assert_eq!(conn.models, vec!["gemma4:latest"]);
    }

    #[test]
    fn connections_unpaid_traffic_groups_by_client() {
        let (tx, mut rx) = broadcast::channel(64);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        engine.ingest(make_entry("GET", "/api/tags", 200));
        engine.ingest(make_entry("GET", "/api/tags", 500));

        let connections = engine.connections_snapshot();
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].payer, None);
        assert_eq!(connections[0].client_ip, "127.0.0.1");
        assert_eq!(connections[0].requests, 2);
        assert_eq!(connections[0].ok, 1);
        assert_eq!(connections[0].failed, 1);
        assert_eq!(connections[0].paid_usd, 0.0);

        // ConnectionUpdated broadcast after each completion.
        let mut updates = 0;
        while let Ok(msg) = rx.try_recv() {
            if matches!(msg, SseMessage::ConnectionUpdated { .. }) {
                updates += 1;
            }
        }
        assert_eq!(updates, 2);
    }

    #[test]
    fn connection_summary_wire_format() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);
        let mut done = make_entry("POST", "/v1/messages", 200);
        done.req_headers
            .insert("authorization".into(), charge_authorization("1000", 6));
        engine.ingest(done);

        let msg = SseMessage::ConnectionsSnapshot {
            connections: engine.connections_snapshot(),
        };
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
        assert_eq!(json["type"], "connections-snapshot");
        let conn = &json["connections"][0];
        assert_eq!(conn["clientIp"], "127.0.0.1");
        assert_eq!(conn["tokensPrompt"], 0);
        assert_eq!(conn["tokensCompletion"], 0);
        assert!((conn["paidUsd"].as_f64().unwrap() - 0.001).abs() < 1e-9);
        assert!(conn["requests"].as_u64() == Some(1));
    }

    #[test]
    fn all_exchanges_browser_noise_skipped() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        engine.begin_exchange(make_start(1, "GET", "/favicon.ico"));
        engine.ingest(make_entry("GET", "/apple-touch-icon.png", 404));
        engine.ingest(make_entry("GET", "/apple-touch-icon-precomposed.png", 404));
        engine.ingest(make_entry("GET", "/robots.txt", 404));
        engine.ingest(make_entry("GET", "/", 307));
        assert!(
            engine.snapshot().is_empty(),
            "browser probes must not chart"
        );

        // Provider-root-adjacent real paths still record.
        engine.ingest(make_entry("GET", "/api/tags", 200));
        assert_eq!(engine.snapshot().len(), 1);
    }

    #[test]
    fn all_exchanges_internal_paths_skipped() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        engine.begin_exchange(make_start(1, "GET", "/__402/pdb/logs"));
        engine.ingest(make_entry("GET", "/__402/health", 200));

        assert!(engine.snapshot().is_empty());
    }

    #[test]
    fn payment_flows_mode_ignores_begin_exchange() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::new(tx);

        engine.begin_exchange(make_start(1, "GET", "/v1/models"));
        assert!(engine.snapshot().is_empty());

        // And plain 200s still create nothing (debugger behavior unchanged).
        engine.ingest(make_entry("GET", "/v1/models", 200));
        assert!(engine.snapshot().is_empty());
    }

    #[test]
    fn all_exchanges_open_flow_survives_eviction_pressure() {
        let (tx, _rx) = broadcast::channel(16);
        let mut engine = FlowCorrelation::with_mode(tx, CorrelationMode::AllExchanges);

        engine.begin_exchange(make_start(0, "POST", "/v1/chat/completions"));
        // Flood the ring buffer past MAX_FLOWS so the open flow is evicted.
        for i in 1..=(MAX_FLOWS as u64 + 10) {
            let mut e = make_entry("GET", &format!("/spam/{i}"), 200);
            e.id = i;
            engine.ingest(e);
        }

        // Completing the evicted exchange must not panic or corrupt state —
        // it falls back to a fresh completed flow.
        let mut done = make_entry("POST", "/v1/chat/completions", 200);
        done.id = 0;
        engine.ingest(done);

        let flows = engine.snapshot();
        assert_eq!(flows.len(), MAX_FLOWS);
        let last = flows.last().unwrap();
        assert_eq!(last.resource, "/v1/chat/completions");
        assert_eq!(last.status, FlowStatus::ResourceDelivered);
    }

    // ── extract_payer ────────────────────────────────────────────────────

    #[test]
    fn extract_payer_returns_none_for_empty_headers() {
        let headers = HashMap::new();
        assert!(extract_payer(&headers).is_none());
    }

    #[test]
    fn extract_payer_returns_none_for_non_payment_auth() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer some-token".to_string());
        assert!(extract_payer(&headers).is_none());
    }

    #[test]
    fn extract_payer_returns_none_for_invalid_base64() {
        let mut headers = HashMap::new();
        headers.insert(
            "authorization".to_string(),
            "Payment !!!not-base64!!!".to_string(),
        );
        assert!(extract_payer(&headers).is_none());
    }

    #[test]
    fn extract_payer_returns_none_for_invalid_json() {
        let mut headers = HashMap::new();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not json at all");
        headers.insert("authorization".to_string(), format!("Payment {b64}"));
        assert!(extract_payer(&headers).is_none());
    }

    #[test]
    fn extract_payer_returns_none_when_no_transaction_in_payload() {
        let mut headers = HashMap::new();
        let json = serde_json::json!({
            "challenge": {"id": "test"},
            "payload": {"signature": "abc123"}
        });
        let b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.to_string().as_bytes());
        headers.insert("authorization".to_string(), format!("Payment {b64}"));
        // Falls through to source field check, which is also absent
        assert!(extract_payer(&headers).is_none());
    }

    #[test]
    fn extract_payer_uses_source_field_as_fallback() {
        let mut headers = HashMap::new();
        let json = serde_json::json!({
            "challenge": {"id": "test"},
            "source": "MyWalletPubkey123",
            "payload": {"signature": "abc123"}
        });
        let b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.to_string().as_bytes());
        headers.insert("authorization".to_string(), format!("Payment {b64}"));
        assert_eq!(
            extract_payer(&headers).as_deref(),
            Some("MyWalletPubkey123")
        );
    }

    #[test]
    fn extract_payer_from_real_transaction() {
        // Build a minimal valid Solana transaction with a known signer.
        use solana_transaction::Transaction;

        let fee_payer = solana_pubkey::Pubkey::new_unique();
        let user_key = solana_pubkey::Pubkey::new_unique();

        // Build a message with fee_payer first, user_key second
        let instruction = solana_instruction::Instruction::new_with_bytes(
            solana_pubkey::Pubkey::new_unique(), // program
            &[],
            vec![
                solana_instruction::AccountMeta::new(fee_payer, true),
                solana_instruction::AccountMeta::new(user_key, true),
            ],
        );
        let blockhash = solana_hash::Hash::default();
        let message = solana_message::Message::new_with_blockhash(
            &[instruction],
            Some(&fee_payer),
            &blockhash,
        );

        // Create tx with placeholder signatures (fee_payer=zero, user=nonzero)
        let tx = Transaction {
            signatures: vec![
                solana_signature::Signature::default(), // fee payer: all zeros
                solana_signature::Signature::new_unique(), // user: non-zero
            ],
            message,
        };

        let tx_bytes = bincode::serialize(&tx).unwrap();
        let tx_b64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);

        let json = serde_json::json!({
            "challenge": {"id": "test"},
            "payload": {"type": "transaction", "transaction": tx_b64}
        });
        let b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.to_string().as_bytes());

        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), format!("Payment {b64}"));

        let payer = extract_payer(&headers);
        // Should return user_key (non-zero sig), not fee_payer (zero sig)
        assert_eq!(payer.as_deref(), Some(user_key.to_string().as_str()));
    }

    #[test]
    fn extract_payer_fallback_when_all_sigs_zero() {
        // If all signatures are zero, fallback to first account key
        use solana_transaction::Transaction;

        let key = solana_pubkey::Pubkey::new_unique();
        let instruction = solana_instruction::Instruction::new_with_bytes(
            solana_pubkey::Pubkey::new_unique(),
            &[],
            vec![solana_instruction::AccountMeta::new(key, true)],
        );
        let message = solana_message::Message::new_with_blockhash(
            &[instruction],
            Some(&key),
            &solana_hash::Hash::default(),
        );
        let tx = Transaction {
            signatures: vec![solana_signature::Signature::default()],
            message,
        };

        let tx_bytes = bincode::serialize(&tx).unwrap();
        let tx_b64 = base64::engine::general_purpose::STANDARD.encode(&tx_bytes);

        let json = serde_json::json!({
            "challenge": {"id": "test"},
            "payload": {"type": "transaction", "transaction": tx_b64}
        });
        let b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.to_string().as_bytes());

        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), format!("Payment {b64}"));

        let payer = extract_payer(&headers);
        assert_eq!(payer.as_deref(), Some(key.to_string().as_str()));
    }
}
