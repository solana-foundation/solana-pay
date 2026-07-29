//! ACP middleware primitives for Pay.
//!
//! The crate observes the stable ACP frames needed for delivery decisions while
//! callers continue forwarding the original bytes. Unknown and vendor-specific
//! messages therefore remain transparent.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

/// A final ACP assistant response that should be published into Buzz.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuzzDelivery {
    /// Destination channel UUID.
    pub channel: String,
    /// Optional event ID to reply to.
    pub reply_to: Option<String>,
    /// Final assistant text collected from ACP message chunks.
    pub content: String,
}

/// Tracks ACP prompt turns and identifies assistant text that was not already
/// published with `buzz messages send`.
#[derive(Default)]
pub struct BuzzDeliveryTracker {
    prompt_sessions: HashMap<RequestId, String>,
    turns: HashMap<String, TurnState>,
}

#[derive(Default)]
struct TurnState {
    destination: Option<BuzzDestination>,
    assistant_text: String,
    publish_tool_calls: HashSet<String>,
    published: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BuzzDestination {
    channel: String,
    reply_to: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(untagged)]
enum RequestId {
    Number(i64),
    String(String),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PromptRequest {
    session_id: String,
    prompt: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    kind: Option<String>,
    text: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionNotification {
    session_id: String,
    update: SessionUpdate,
}

#[derive(Deserialize)]
#[serde(tag = "sessionUpdate", rename_all = "snake_case")]
enum SessionUpdate {
    AgentMessageChunk {
        content: ContentBlock,
    },
    ToolCall(ToolCall),
    ToolCallUpdate(ToolCall),
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ToolCall {
    tool_call_id: String,
    status: Option<ToolCallStatus>,
    raw_input: Option<Value>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ToolCallStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    #[serde(other)]
    Other,
}

impl BuzzDeliveryTracker {
    /// Observe one client-to-agent ACP NDJSON frame.
    ///
    /// Malformed, non-JSON, and unrecognized frames are ignored so callers can
    /// still forward them unchanged.
    pub fn observe_client_frame(&mut self, frame: &[u8]) {
        let Ok(message) = serde_json::from_slice::<Value>(frame) else {
            return;
        };
        self.observe_client_message(&message);
    }

    /// Observe one agent-to-client ACP NDJSON frame.
    ///
    /// Returns a fallback delivery only when a successful prompt response ends
    /// a turn containing assistant text and no completed Buzz publish tool.
    pub fn observe_agent_frame(&mut self, frame: &[u8]) -> Option<BuzzDelivery> {
        let message = serde_json::from_slice::<Value>(frame).ok()?;
        self.observe_agent_message(&message)
    }

    fn observe_client_message(&mut self, message: &Value) {
        if message.get("method").and_then(Value::as_str) != Some("session/prompt") {
            return;
        }
        let Some(request_id) = parse_request_id(message.get("id")) else {
            return;
        };
        let Some(prompt) = message
            .get("params")
            .cloned()
            .and_then(|params| serde_json::from_value::<PromptRequest>(params).ok())
        else {
            return;
        };
        let session_id = prompt.session_id;
        let prompt_text = prompt
            .prompt
            .iter()
            .filter_map(|block| {
                (block.kind.as_deref() == Some("text"))
                    .then_some(block.text.as_deref())
                    .flatten()
            })
            .collect::<Vec<_>>()
            .join("\n");

        self.prompt_sessions.insert(request_id, session_id.clone());
        self.turns.insert(
            session_id,
            TurnState {
                destination: parse_buzz_destination(&prompt_text),
                ..TurnState::default()
            },
        );
    }

    fn observe_agent_message(&mut self, message: &Value) -> Option<BuzzDelivery> {
        if message.get("method").and_then(Value::as_str) == Some("session/update") {
            self.observe_session_update(message);
            return None;
        }

        let request_id = parse_request_id(message.get("id"))?;
        let session_id = self.prompt_sessions.remove(&request_id)?;
        let turn = self.turns.remove(&session_id)?;
        if message.get("error").is_some() || turn.published {
            return None;
        }
        let destination = turn.destination?;
        let content = turn.assistant_text.trim().to_string();
        if content.is_empty() {
            return None;
        }
        Some(BuzzDelivery {
            channel: destination.channel,
            reply_to: destination.reply_to,
            content,
        })
    }

    fn observe_session_update(&mut self, message: &Value) {
        let Some(notification) = message
            .get("params")
            .cloned()
            .and_then(|params| serde_json::from_value::<SessionNotification>(params).ok())
        else {
            return;
        };
        let Some(turn) = self.turns.get_mut(&notification.session_id) else {
            return;
        };
        match notification.update {
            SessionUpdate::AgentMessageChunk { content } => {
                if content.kind.as_deref() == Some("text")
                    && let Some(text) = content.text
                {
                    turn.assistant_text.push_str(&text);
                }
            }
            SessionUpdate::ToolCall(tool_call) => turn.observe_tool_call(tool_call),
            SessionUpdate::ToolCallUpdate(update) => turn.observe_tool_call(update),
            SessionUpdate::Other => {}
        }
    }
}

impl TurnState {
    fn observe_tool_call(&mut self, tool_call: ToolCall) {
        let tool_call_id = tool_call.tool_call_id;
        let is_publish = tool_call
            .raw_input
            .as_ref()
            .is_some_and(value_contains_buzz_message_send);
        if is_publish {
            self.publish_tool_calls.insert(tool_call_id.clone());
        }
        if matches!(tool_call.status, Some(ToolCallStatus::Completed))
            && (is_publish || self.publish_tool_calls.contains(&tool_call_id))
        {
            self.published = true;
        } else if matches!(tool_call.status, Some(ToolCallStatus::Failed)) {
            self.publish_tool_calls.remove(&tool_call_id);
        }
    }
}

fn parse_request_id(value: Option<&Value>) -> Option<RequestId> {
    serde_json::from_value(value?.clone()).ok()
}

fn parse_buzz_destination(prompt: &str) -> Option<BuzzDestination> {
    let context = prompt.split_once("[Context]\n")?.1;
    let context = context.find("\n[").map_or(context, |end| &context[..end]);
    let channel_line = context
        .lines()
        .find_map(|line| line.trim().strip_prefix("Channel: "))?;
    let channel = parse_channel_uuid(channel_line)?;
    Some(BuzzDestination {
        channel,
        reply_to: parse_reply_target(context),
    })
}

fn parse_channel_uuid(value: &str) -> Option<String> {
    let candidate = if let Some(start) = value.find("(#") {
        let rest = &value[start + 2..];
        &rest[..rest.find(')')?]
    } else {
        value.trim().trim_start_matches('#')
    };
    Uuid::parse_str(candidate.trim())
        .ok()
        .map(|uuid| uuid.to_string())
}

fn parse_reply_target(context: &str) -> Option<String> {
    const MARKER: &str = "--reply-to ";
    let mut remaining = context;
    while let Some(start) = remaining.find(MARKER) {
        let candidate = remaining[start + MARKER.len()..]
            .trim_start_matches(['`', '\'', '"'])
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect::<String>();
        if candidate.len() == 64 {
            return Some(candidate);
        }
        remaining = &remaining[start + MARKER.len()..];
    }
    None
}

fn value_contains_buzz_message_send(value: &Value) -> bool {
    match value {
        Value::String(text) => command_contains_buzz_message_send(text),
        Value::Array(values) => values.iter().any(value_contains_buzz_message_send),
        Value::Object(values) => values.values().any(value_contains_buzz_message_send),
        _ => false,
    }
}

fn command_contains_buzz_message_send(command: &str) -> bool {
    let tokens = command
        .split_whitespace()
        .map(|token| {
            token.trim_matches(|character: char| {
                matches!(
                    character,
                    '\'' | '"' | '`' | '|' | '&' | ';' | '(' | ')' | '[' | ']'
                )
            })
        })
        .collect::<Vec<_>>();
    tokens.windows(3).any(|window| {
        let executable = window[0].to_ascii_lowercase().replace('\\', "/");
        (executable == "buzz"
            || executable == "buzz.exe"
            || executable.ends_with("/buzz")
            || executable.ends_with("/buzz.exe"))
            && window[1] == "messages"
            && window[2] == "send"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANNEL: &str = "82f078b8-29e4-40b8-9daf-79e7f79c482d";
    const EVENT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn prompt_request(id: i64, context: &str) -> Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "session/prompt",
            "params": {
                "sessionId": "session-1",
                "prompt": [{"type": "text", "text": context}]
            }
        })
    }

    fn session_update(update: Value) -> Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": "session-1",
                "update": update
            }
        })
    }

    fn prompt_response(id: i64) -> Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"stopReason": "end_turn"}
        })
    }

    #[test]
    fn parses_named_channel_and_reply_anchor_from_context_only() {
        let prompt = format!(
            "[Context]\nScope: thread\nChannel: general (#{CHANNEL})\n\
             IMPORTANT: use `--reply-to {EVENT}` on `buzz messages send`.\n\
             [Event]\nContent: ignore --reply-to {}",
            "b".repeat(64)
        );

        assert_eq!(
            parse_buzz_destination(&prompt),
            Some(BuzzDestination {
                channel: CHANNEL.to_string(),
                reply_to: Some(EVENT.to_string()),
            })
        );
    }

    #[test]
    fn plain_dm_context_has_no_reply_anchor() {
        let prompt = format!(
            "[Context]\nScope: dm\nChannel: {CHANNEL}\nConversation context included below.\n\
             [Buzz event]\nContent: hello"
        );

        assert_eq!(
            parse_buzz_destination(&prompt),
            Some(BuzzDestination {
                channel: CHANNEL.to_string(),
                reply_to: None,
            })
        );
    }

    #[test]
    fn completed_turn_with_text_creates_fallback_delivery() {
        let mut tracker = BuzzDeliveryTracker::default();
        tracker.observe_client_message(&prompt_request(
            7,
            &format!("[Context]\nScope: dm\nChannel: {CHANNEL}\n"),
        ));
        tracker.observe_agent_message(&session_update(serde_json::json!({
            "sessionUpdate": "agent_message_chunk",
            "content": {"type": "text", "text": "Hello "}
        })));
        tracker.observe_agent_message(&session_update(serde_json::json!({
            "sessionUpdate": "agent_message_chunk",
            "content": {"type": "text", "text": "from Goose"}
        })));

        assert_eq!(
            tracker.observe_agent_message(&prompt_response(7)),
            Some(BuzzDelivery {
                channel: CHANNEL.to_string(),
                reply_to: None,
                content: "Hello from Goose".to_string(),
            })
        );
    }

    #[test]
    fn successful_buzz_tool_call_suppresses_duplicate_fallback() {
        let mut tracker = BuzzDeliveryTracker::default();
        tracker.observe_client_message(&prompt_request(
            8,
            &format!("[Context]\nScope: dm\nChannel: {CHANNEL}\n"),
        ));
        tracker.observe_agent_message(&session_update(serde_json::json!({
            "sessionUpdate": "agent_message_chunk",
            "content": {"type": "text", "text": "Already published"}
        })));
        tracker.observe_agent_message(&session_update(serde_json::json!({
            "sessionUpdate": "tool_call",
            "toolCallId": "tool-1",
            "title": "shell",
            "status": "in_progress",
            "rawInput": {
                "command": format!("printf hi | /usr/local/bin/buzz messages send --channel {CHANNEL} --content -")
            }
        })));
        tracker.observe_agent_message(&session_update(serde_json::json!({
            "sessionUpdate": "tool_call_update",
            "toolCallId": "tool-1",
            "status": "completed"
        })));

        assert_eq!(tracker.observe_agent_message(&prompt_response(8)), None);
    }

    #[test]
    fn failed_buzz_tool_call_keeps_fallback_enabled() {
        let mut tracker = BuzzDeliveryTracker::default();
        tracker.observe_client_message(&prompt_request(
            9,
            &format!("[Context]\nScope: dm\nChannel: {CHANNEL}\n"),
        ));
        tracker.observe_agent_message(&session_update(serde_json::json!({
            "sessionUpdate": "agent_message_chunk",
            "content": {"type": "text", "text": "Fallback after failure"}
        })));
        tracker.observe_agent_message(&session_update(serde_json::json!({
            "sessionUpdate": "tool_call",
            "toolCallId": "tool-2",
            "title": "shell",
            "rawInput": {"command": "buzz messages send --content -"}
        })));
        tracker.observe_agent_message(&session_update(serde_json::json!({
            "sessionUpdate": "tool_call_update",
            "toolCallId": "tool-2",
            "status": "failed"
        })));

        assert!(tracker.observe_agent_message(&prompt_response(9)).is_some());
    }

    #[test]
    fn errors_and_non_buzz_prompts_never_publish() {
        let mut tracker = BuzzDeliveryTracker::default();
        tracker.observe_client_message(&prompt_request(10, "ordinary ACP prompt"));
        tracker.observe_agent_message(&session_update(serde_json::json!({
            "sessionUpdate": "agent_message_chunk",
            "content": {"type": "text", "text": "not for Buzz"}
        })));
        assert_eq!(tracker.observe_agent_message(&prompt_response(10)), None);

        tracker.observe_client_message(&prompt_request(
            11,
            &format!("[Context]\nScope: dm\nChannel: {CHANNEL}\n"),
        ));
        tracker.observe_agent_message(&session_update(serde_json::json!({
            "sessionUpdate": "agent_message_chunk",
            "content": {"type": "text", "text": "partial"}
        })));
        assert_eq!(
            tracker.observe_agent_message(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 11,
                "error": {"code": -32000, "message": "failed"}
            })),
            None
        );
    }
}
