//! Anthropic Messages API ⇄ OpenAI chat-completions translation.
//!
//! Claude Code speaks the Anthropic `/v1/messages` surface; most upstreams
//! (vLLM, LM Studio, llama.cpp, Alibaba Model Studio's compatible-mode)
//! speak OpenAI chat completions. The payer proxy uses these pure
//! functions to translate the request before sending (so the 402 pay-retry
//! replays the *translated* body) and the response — buffered JSON or
//! incremental SSE — on the way back.
//!
//! Everything operates on `serde_json::Value` so unknown fields never
//! break translation; unmapped fields are dropped (see module tests for
//! the covered surface). Known-lossy: image/document blocks, `thinking`
//! blocks, `metadata`, and Anthropic beta query params.

use serde_json::{Value, json};

// ── Request: Anthropic → OpenAI ─────────────────────────────────────────────

/// Translate an Anthropic `/v1/messages` request body into an OpenAI
/// `chat/completions` body.
pub(crate) fn anthropic_to_openai_request(anthropic: &Value) -> Value {
    let mut messages: Vec<Value> = Vec::new();

    if let Some(system) = anthropic.get("system") {
        let text = system_text(system);
        if !text.is_empty() {
            messages.push(json!({ "role": "system", "content": text }));
        }
    }

    for msg in anthropic
        .get("messages")
        .and_then(|m| m.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[])
    {
        translate_message(msg, &mut messages);
    }

    let mut openai = json!({ "messages": messages });

    for key in ["model", "max_tokens", "temperature", "top_p"] {
        if let Some(value) = anthropic.get(key) {
            openai[key] = value.clone();
        }
    }
    if let Some(stop) = anthropic.get("stop_sequences")
        && !stop.as_array().is_none_or(|s| s.is_empty())
    {
        openai["stop"] = stop.clone();
    }
    if anthropic.get("stream").and_then(|s| s.as_bool()) == Some(true) {
        openai["stream"] = json!(true);
        // Ask for the final usage chunk so `message_delta` can report
        // output tokens (supported by OpenAI, vLLM, LM Studio, llama.cpp,
        // and Model Studio's compatible mode).
        openai["stream_options"] = json!({ "include_usage": true });
    }
    if let Some(tools) = anthropic.get("tools").and_then(|t| t.as_array())
        && !tools.is_empty()
    {
        openai["tools"] = Value::Array(tools.iter().map(translate_tool).collect());
    }
    if let Some(tool_choice) = anthropic.get("tool_choice")
        && let Some(mapped) = translate_tool_choice(tool_choice)
    {
        openai["tool_choice"] = mapped;
    }

    openai
}

/// Anthropic `system` is a string or an array of text blocks.
fn system_text(system: &Value) -> String {
    match system {
        Value::String(text) => text.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(|block| block.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// One Anthropic message → one or more OpenAI messages. `tool_result`
/// blocks split out into `role:"tool"` messages (emitted first so they
/// directly follow the assistant `tool_calls` turn, as OpenAI requires).
fn translate_message(msg: &Value, out: &mut Vec<Value>) {
    let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user");
    match msg.get("content") {
        Some(Value::String(text)) => out.push(json!({ "role": role, "content": text })),
        Some(Value::Array(blocks)) if role == "assistant" => {
            let mut text_parts: Vec<&str> = Vec::new();
            let mut tool_calls: Vec<Value> = Vec::new();
            for block in blocks {
                match block.get("type").and_then(|t| t.as_str()) {
                    Some("text") => {
                        if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                            text_parts.push(text);
                        }
                    }
                    Some("tool_use") => tool_calls.push(json!({
                        "id": block.get("id").cloned().unwrap_or_else(|| json!("")),
                        "type": "function",
                        "function": {
                            "name": block.get("name").cloned().unwrap_or_else(|| json!("")),
                            "arguments": serde_json::to_string(
                                block.get("input").unwrap_or(&json!({}))
                            )
                            .unwrap_or_else(|_| "{}".to_string()),
                        },
                    })),
                    // `thinking`, images, … — lossy.
                    _ => {}
                }
            }
            let mut message = json!({ "role": "assistant" });
            message["content"] = if text_parts.is_empty() {
                Value::Null
            } else {
                Value::String(text_parts.join("\n"))
            };
            if !tool_calls.is_empty() {
                message["tool_calls"] = Value::Array(tool_calls);
            }
            out.push(message);
        }
        Some(Value::Array(blocks)) => {
            let mut text_parts: Vec<&str> = Vec::new();
            for block in blocks {
                match block.get("type").and_then(|t| t.as_str()) {
                    Some("text") => {
                        if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                            text_parts.push(text);
                        }
                    }
                    Some("tool_result") => out.push(json!({
                        "role": "tool",
                        "tool_call_id": block
                            .get("tool_use_id")
                            .cloned()
                            .unwrap_or_else(|| json!("")),
                        "content": tool_result_text(block.get("content")),
                    })),
                    // Images, documents, … — lossy.
                    _ => {}
                }
            }
            if !text_parts.is_empty() {
                out.push(json!({ "role": role, "content": text_parts.join("\n") }));
            }
        }
        _ => {}
    }
}

/// Stringify a `tool_result` content field (string, block array, or any
/// JSON) into the plain string OpenAI `role:"tool"` messages carry.
fn tool_result_text(content: Option<&Value>) -> String {
    match content {
        None => String::new(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => {
            let texts: Vec<&str> = blocks
                .iter()
                .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .collect();
            if texts.is_empty() {
                serde_json::to_string(blocks).unwrap_or_default()
            } else {
                texts.join("\n")
            }
        }
        Some(other) => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn translate_tool(tool: &Value) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": tool.get("name").cloned().unwrap_or_else(|| json!("")),
            "description": tool.get("description").cloned().unwrap_or_else(|| json!("")),
            "parameters": tool
                .get("input_schema")
                .cloned()
                .unwrap_or_else(|| json!({ "type": "object" })),
        },
    })
}

fn translate_tool_choice(tool_choice: &Value) -> Option<Value> {
    match tool_choice.get("type").and_then(|t| t.as_str())? {
        "auto" => Some(json!("auto")),
        "any" => Some(json!("required")),
        "none" => Some(json!("none")),
        "tool" => Some(json!({
            "type": "function",
            "function": { "name": tool_choice.get("name").cloned().unwrap_or_else(|| json!("")) },
        })),
        _ => None,
    }
}

// ── Response (non-stream): OpenAI → Anthropic ───────────────────────────────

/// Translate an OpenAI `chat.completion` body into an Anthropic message
/// envelope.
pub(crate) fn openai_to_anthropic_response(openai: &Value) -> Value {
    let message = openai.pointer("/choices/0/message");
    let mut content: Vec<Value> = Vec::new();

    if let Some(text) = message
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        && !text.is_empty()
    {
        content.push(json!({ "type": "text", "text": text }));
    }

    let mut saw_tool_use = false;
    if let Some(tool_calls) = message
        .and_then(|m| m.get("tool_calls"))
        .and_then(|t| t.as_array())
    {
        for (i, tc) in tool_calls.iter().enumerate() {
            saw_tool_use = true;
            content.push(json!({
                "type": "tool_use",
                "id": tc
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("toolu_{i}")),
                "name": tc.pointer("/function/name").cloned().unwrap_or_else(|| json!("")),
                "input": parse_tool_arguments(tc.pointer("/function/arguments")),
            }));
        }
    }

    let finish_reason = openai
        .pointer("/choices/0/finish_reason")
        .and_then(|f| f.as_str());

    json!({
        "id": openai
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("msg_translated"),
        "type": "message",
        "role": "assistant",
        "model": openai.get("model").and_then(|v| v.as_str()).unwrap_or(""),
        "content": content,
        "stop_reason": map_finish_reason(finish_reason, saw_tool_use),
        "stop_sequence": null,
        "usage": {
            "input_tokens": openai
                .pointer("/usage/prompt_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            "output_tokens": openai
                .pointer("/usage/completion_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
        },
    })
}

/// OpenAI tool-call arguments are a JSON *string*; Anthropic `tool_use`
/// input is an object. Unparseable arguments degrade to `{}`.
fn parse_tool_arguments(arguments: Option<&Value>) -> Value {
    match arguments {
        Some(Value::String(raw)) => serde_json::from_str(raw).unwrap_or_else(|_| json!({})),
        // Some compat servers already send an object.
        Some(Value::Object(map)) => Value::Object(map.clone()),
        _ => json!({}),
    }
}

/// stop→end_turn, length→max_tokens, tool_calls→tool_use. A turn that
/// produced tool calls maps to `tool_use` regardless — Claude Code needs
/// that signal to run the tools.
fn map_finish_reason(finish_reason: Option<&str>, saw_tool_use: bool) -> &'static str {
    match finish_reason {
        Some("length") => "max_tokens",
        Some("tool_calls") | Some("function_call") => "tool_use",
        _ if saw_tool_use => "tool_use",
        _ => "end_turn",
    }
}

// ── Stream: OpenAI SSE → Anthropic SSE ──────────────────────────────────────

/// Which Anthropic content block is currently open.
enum Block {
    Text { index: usize },
    Tool { index: usize, openai_index: u64 },
}

impl Block {
    fn index(&self) -> usize {
        match self {
            Block::Text { index } | Block::Tool { index, .. } => *index,
        }
    }
}

/// Incremental OpenAI-SSE → Anthropic-SSE translator.
///
/// Feed raw upstream bytes through [`push`](Self::push) as they arrive
/// (chunks may split SSE lines — and even UTF-8 code points — anywhere;
/// a byte carry-over buffer reassembles them) and flush with
/// [`finish`](Self::finish) at end of stream. Emits the Anthropic event
/// sequence `message_start → content_block_start/delta/stop… →
/// message_delta → message_stop`.
pub(crate) struct StreamTranslator {
    buffer: Vec<u8>,
    started: bool,
    finished: bool,
    message_id: Option<String>,
    model: Option<String>,
    input_tokens: u64,
    output_tokens: Option<u64>,
    finish_reason: Option<String>,
    saw_tool_use: bool,
    block: Option<Block>,
    next_index: usize,
}

impl StreamTranslator {
    pub(crate) fn new() -> Self {
        Self {
            buffer: Vec::new(),
            started: false,
            finished: false,
            message_id: None,
            model: None,
            input_tokens: 0,
            output_tokens: None,
            finish_reason: None,
            saw_tool_use: false,
            block: None,
            next_index: 0,
        }
    }

    /// Feed upstream bytes; returns translated Anthropic SSE bytes (empty
    /// when the chunk didn't complete any upstream line).
    pub(crate) fn push(&mut self, chunk: &[u8]) -> String {
        self.buffer.extend_from_slice(chunk);
        let mut out = String::new();
        while let Some(pos) = self.buffer.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim_end_matches(['\r', '\n']);
            let Some(payload) = line.strip_prefix("data:") else {
                continue; // `event:` lines, comments, blank separators
            };
            let payload = payload.trim();
            if payload == "[DONE]" {
                out.push_str(&self.finalize());
            } else if let Ok(chunk_json) = serde_json::from_str::<Value>(payload) {
                out.push_str(&self.handle_chunk(&chunk_json));
            }
        }
        out
    }

    /// Flush at upstream end-of-stream: closes any open block and emits
    /// `message_delta` + `message_stop` if the upstream never sent
    /// `[DONE]`. Idempotent.
    pub(crate) fn finish(&mut self) -> String {
        self.finalize()
    }

    fn handle_chunk(&mut self, chunk: &Value) -> String {
        if self.finished {
            return String::new();
        }

        if self.message_id.is_none()
            && let Some(id) = chunk.get("id").and_then(|v| v.as_str())
        {
            self.message_id = Some(id.to_string());
        }
        if self.model.is_none()
            && let Some(model) = chunk.get("model").and_then(|v| v.as_str())
        {
            self.model = Some(model.to_string());
        }
        if let Some(usage) = chunk.get("usage").filter(|u| !u.is_null()) {
            if let Some(prompt) = usage.get("prompt_tokens").and_then(|v| v.as_u64()) {
                self.input_tokens = prompt;
            }
            if let Some(completion) = usage.get("completion_tokens").and_then(|v| v.as_u64()) {
                self.output_tokens = Some(completion);
            }
        }

        let mut out = String::new();
        if !self.started {
            self.started = true;
            out.push_str(&sse_event(
                "message_start",
                &json!({
                    "type": "message_start",
                    "message": {
                        "id": self
                            .message_id
                            .clone()
                            .unwrap_or_else(|| "msg_translated".to_string()),
                        "type": "message",
                        "role": "assistant",
                        "model": self.model.clone().unwrap_or_default(),
                        "content": [],
                        "stop_reason": null,
                        "stop_sequence": null,
                        "usage": { "input_tokens": self.input_tokens, "output_tokens": 0 },
                    },
                }),
            ));
        }

        if let Some(delta) = chunk.pointer("/choices/0/delta") {
            if let Some(text) = delta.get("content").and_then(|c| c.as_str())
                && !text.is_empty()
            {
                out.push_str(&self.ensure_text_block());
                let index = self.block.as_ref().map(Block::index).unwrap_or(0);
                out.push_str(&sse_event(
                    "content_block_delta",
                    &json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": { "type": "text_delta", "text": text },
                    }),
                ));
            }
            if let Some(tool_calls) = delta.get("tool_calls").and_then(|t| t.as_array()) {
                for tc in tool_calls {
                    out.push_str(&self.handle_tool_call_delta(tc));
                }
            }
        }

        if let Some(reason) = chunk
            .pointer("/choices/0/finish_reason")
            .and_then(|f| f.as_str())
        {
            self.finish_reason = Some(reason.to_string());
        }

        out
    }

    fn handle_tool_call_delta(&mut self, tc: &Value) -> String {
        let openai_index = tc.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
        let mut out = String::new();

        let same_block = matches!(
            self.block,
            Some(Block::Tool { openai_index: open, .. }) if open == openai_index
        );
        if !same_block {
            out.push_str(&self.close_block());
            let index = self.next_index;
            self.next_index += 1;
            self.block = Some(Block::Tool {
                index,
                openai_index,
            });
            self.saw_tool_use = true;
            out.push_str(&sse_event(
                "content_block_start",
                &json!({
                    "type": "content_block_start",
                    "index": index,
                    "content_block": {
                        "type": "tool_use",
                        "id": tc
                            .get("id")
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                            .unwrap_or_else(|| format!("toolu_{openai_index}")),
                        "name": tc.pointer("/function/name").cloned().unwrap_or_else(|| json!("")),
                        "input": {},
                    },
                }),
            ));
        }

        if let Some(fragment) = tc.pointer("/function/arguments").and_then(|a| a.as_str())
            && !fragment.is_empty()
        {
            let index = self.block.as_ref().map(Block::index).unwrap_or(0);
            out.push_str(&sse_event(
                "content_block_delta",
                &json!({
                    "type": "content_block_delta",
                    "index": index,
                    "delta": { "type": "input_json_delta", "partial_json": fragment },
                }),
            ));
        }

        out
    }

    fn ensure_text_block(&mut self) -> String {
        if matches!(self.block, Some(Block::Text { .. })) {
            return String::new();
        }
        let mut out = self.close_block();
        let index = self.next_index;
        self.next_index += 1;
        self.block = Some(Block::Text { index });
        out.push_str(&sse_event(
            "content_block_start",
            &json!({
                "type": "content_block_start",
                "index": index,
                "content_block": { "type": "text", "text": "" },
            }),
        ));
        out
    }

    fn close_block(&mut self) -> String {
        match self.block.take() {
            Some(block) => sse_event(
                "content_block_stop",
                &json!({ "type": "content_block_stop", "index": block.index() }),
            ),
            None => String::new(),
        }
    }

    fn finalize(&mut self) -> String {
        if self.finished || !self.started {
            self.finished = true;
            return String::new();
        }
        self.finished = true;
        let mut out = self.close_block();
        out.push_str(&sse_event(
            "message_delta",
            &json!({
                "type": "message_delta",
                "delta": {
                    "stop_reason": map_finish_reason(self.finish_reason.as_deref(), self.saw_tool_use),
                    "stop_sequence": null,
                },
                "usage": { "output_tokens": self.output_tokens.unwrap_or(0) },
            }),
        ));
        out.push_str(&sse_event(
            "message_stop",
            &json!({ "type": "message_stop" }),
        ));
        out
    }
}

fn sse_event(name: &str, data: &Value) -> String {
    format!("event: {name}\ndata: {data}\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Request translation ────────────────────────────────────────────────

    #[test]
    fn request_maps_system_string_scalars_and_stop_sequences() {
        let anthropic = json!({
            "model": "qwen-max",
            "max_tokens": 512,
            "temperature": 0.2,
            "top_p": 0.9,
            "stop_sequences": ["END"],
            "stream": true,
            "system": "You are terse.",
            "messages": [{ "role": "user", "content": "hi" }],
        });
        let openai = anthropic_to_openai_request(&anthropic);

        assert_eq!(openai["model"], "qwen-max");
        assert_eq!(openai["max_tokens"], 512);
        assert_eq!(openai["temperature"], 0.2);
        assert_eq!(openai["top_p"], 0.9);
        assert_eq!(openai["stop"], json!(["END"]));
        assert_eq!(openai["stream"], true);
        assert_eq!(openai["stream_options"], json!({ "include_usage": true }));
        assert_eq!(
            openai["messages"],
            json!([
                { "role": "system", "content": "You are terse." },
                { "role": "user", "content": "hi" },
            ])
        );
        assert!(openai.get("system").is_none());
        assert!(openai.get("stop_sequences").is_none());
    }

    #[test]
    fn request_maps_system_content_block_array() {
        let anthropic = json!({
            "model": "m",
            "system": [
                { "type": "text", "text": "Line one." },
                { "type": "text", "text": "Line two." },
            ],
            "messages": [{ "role": "user", "content": [{ "type": "text", "text": "go" }] }],
        });
        let openai = anthropic_to_openai_request(&anthropic);
        assert_eq!(
            openai["messages"],
            json!([
                { "role": "system", "content": "Line one.\nLine two." },
                { "role": "user", "content": "go" },
            ])
        );
        assert!(openai.get("stream").is_none(), "stream not requested");
    }

    #[test]
    fn request_round_trips_tool_use_and_tool_result_turns() {
        let anthropic = json!({
            "model": "m",
            "messages": [
                { "role": "user", "content": "What's the weather in SF?" },
                { "role": "assistant", "content": [
                    { "type": "text", "text": "Let me check." },
                    { "type": "tool_use", "id": "toolu_01", "name": "get_weather",
                      "input": { "city": "SF" } },
                ]},
                { "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "toolu_01",
                      "content": [{ "type": "text", "text": "68F, sunny" }] },
                    { "type": "text", "text": "and Oakland?" },
                ]},
            ],
        });
        let openai = anthropic_to_openai_request(&anthropic);
        let messages = openai["messages"].as_array().unwrap();

        assert_eq!(
            messages[0],
            json!({ "role": "user", "content": "What's the weather in SF?" })
        );
        assert_eq!(messages[1]["role"], "assistant");
        assert_eq!(messages[1]["content"], "Let me check.");
        assert_eq!(
            messages[1]["tool_calls"],
            json!([{
                "id": "toolu_01",
                "type": "function",
                "function": { "name": "get_weather", "arguments": "{\"city\":\"SF\"}" },
            }])
        );
        // tool message directly follows the assistant tool_calls turn.
        assert_eq!(
            messages[2],
            json!({ "role": "tool", "tool_call_id": "toolu_01", "content": "68F, sunny" })
        );
        assert_eq!(
            messages[3],
            json!({ "role": "user", "content": "and Oakland?" })
        );
    }

    #[test]
    fn request_maps_tools_and_every_tool_choice_variant() {
        let anthropic = json!({
            "model": "m",
            "messages": [],
            "tools": [{
                "name": "get_weather",
                "description": "Get weather",
                "input_schema": { "type": "object", "properties": { "city": { "type": "string" } } },
            }],
            "tool_choice": { "type": "tool", "name": "get_weather" },
        });
        let openai = anthropic_to_openai_request(&anthropic);
        assert_eq!(
            openai["tools"],
            json!([{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get weather",
                    "parameters": { "type": "object", "properties": { "city": { "type": "string" } } },
                },
            }])
        );
        assert_eq!(
            openai["tool_choice"],
            json!({ "type": "function", "function": { "name": "get_weather" } })
        );

        assert_eq!(
            translate_tool_choice(&json!({ "type": "auto" })),
            Some(json!("auto"))
        );
        assert_eq!(
            translate_tool_choice(&json!({ "type": "any" })),
            Some(json!("required"))
        );
        assert_eq!(
            translate_tool_choice(&json!({ "type": "none" })),
            Some(json!("none"))
        );
        assert_eq!(translate_tool_choice(&json!({ "type": "wat" })), None);
    }

    #[test]
    fn tool_result_content_stringifies_all_shapes() {
        assert_eq!(tool_result_text(None), "");
        assert_eq!(tool_result_text(Some(&json!("plain"))), "plain");
        assert_eq!(
            tool_result_text(Some(&json!([{ "type": "text", "text": "a" },
                                          { "type": "text", "text": "b" }]))),
            "a\nb"
        );
        // Non-text blocks fall back to raw JSON so nothing is silently lost.
        assert_eq!(
            tool_result_text(Some(&json!([{ "type": "image", "source": {} }]))),
            r#"[{"source":{},"type":"image"}]"#
        );
        assert_eq!(
            tool_result_text(Some(&json!({ "ok": true }))),
            r#"{"ok":true}"#
        );
    }

    // ── Non-stream response translation ────────────────────────────────────

    #[test]
    fn response_maps_text_usage_and_identity() {
        let openai = json!({
            "id": "chatcmpl-42",
            "object": "chat.completion",
            "model": "qwen-max",
            "choices": [{
                "index": 0,
                "message": { "role": "assistant", "content": "Hello!" },
                "finish_reason": "stop",
            }],
            "usage": { "prompt_tokens": 12, "completion_tokens": 3 },
        });
        let anthropic = openai_to_anthropic_response(&openai);

        assert_eq!(anthropic["id"], "chatcmpl-42");
        assert_eq!(anthropic["type"], "message");
        assert_eq!(anthropic["role"], "assistant");
        assert_eq!(anthropic["model"], "qwen-max");
        assert_eq!(
            anthropic["content"],
            json!([{ "type": "text", "text": "Hello!" }])
        );
        assert_eq!(anthropic["stop_reason"], "end_turn");
        assert_eq!(anthropic["stop_sequence"], Value::Null);
        assert_eq!(anthropic["usage"]["input_tokens"], 12);
        assert_eq!(anthropic["usage"]["output_tokens"], 3);
    }

    #[test]
    fn response_maps_tool_calls_with_parsed_and_unparseable_arguments() {
        let openai = json!({
            "id": "c",
            "model": "m",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [
                        { "id": "call_1", "type": "function",
                          "function": { "name": "get_weather", "arguments": "{\"city\":\"SF\"}" } },
                        { "type": "function",
                          "function": { "name": "broken", "arguments": "{not json" } },
                    ],
                },
                "finish_reason": "tool_calls",
            }],
        });
        let anthropic = openai_to_anthropic_response(&openai);
        assert_eq!(
            anthropic["content"],
            json!([
                { "type": "tool_use", "id": "call_1", "name": "get_weather",
                  "input": { "city": "SF" } },
                { "type": "tool_use", "id": "toolu_1", "name": "broken", "input": {} },
            ])
        );
        assert_eq!(anthropic["stop_reason"], "tool_use");
    }

    #[test]
    fn response_maps_every_finish_reason() {
        for (finish, expected) in [
            ("stop", "end_turn"),
            ("length", "max_tokens"),
            ("tool_calls", "tool_use"),
            ("content_filter", "end_turn"),
        ] {
            let openai = json!({
                "choices": [{ "message": { "content": "x" }, "finish_reason": finish }],
            });
            assert_eq!(
                openai_to_anthropic_response(&openai)["stop_reason"],
                expected,
                "finish_reason={finish}"
            );
        }
        // A turn that produced tool calls is tool_use even on "stop".
        let openai = json!({
            "choices": [{
                "message": { "tool_calls": [{ "id": "c", "function": { "name": "f", "arguments": "{}" } }] },
                "finish_reason": "stop",
            }],
        });
        assert_eq!(
            openai_to_anthropic_response(&openai)["stop_reason"],
            "tool_use"
        );
    }

    // ── Stream translation ─────────────────────────────────────────────────

    fn parse_events(sse: &str) -> Vec<(String, Value)> {
        let mut events = Vec::new();
        let mut name: Option<String> = None;
        for line in sse.lines() {
            if let Some(n) = line.strip_prefix("event: ") {
                name = Some(n.to_string());
            } else if let Some(d) = line.strip_prefix("data: ") {
                events.push((
                    name.take().expect("data line without event name"),
                    serde_json::from_str(d).expect("event data must be JSON"),
                ));
            }
        }
        events
    }

    const TEXT_STREAM: &str = concat!(
        "data: {\"id\":\"chatcmpl-7\",\"model\":\"qwen-max\",\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"},\"finish_reason\":null}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":null}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2}}\n\n",
        "data: [DONE]\n\n",
    );

    #[test]
    fn stream_translates_text_deltas_into_exact_anthropic_sequence() {
        let mut translator = StreamTranslator::new();
        let mut out = translator.push(TEXT_STREAM.as_bytes());
        out.push_str(&translator.finish());

        let events = parse_events(&out);
        let names: Vec<&str> = events.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );

        assert_eq!(events[0].1["message"]["id"], "chatcmpl-7");
        assert_eq!(events[0].1["message"]["model"], "qwen-max");
        assert_eq!(
            events[1].1["content_block"],
            json!({ "type": "text", "text": "" })
        );
        assert_eq!(
            events[2].1["delta"],
            json!({ "type": "text_delta", "text": "Hel" })
        );
        assert_eq!(
            events[3].1["delta"],
            json!({ "type": "text_delta", "text": "lo" })
        );
        assert_eq!(events[4].1["index"], 0);
        assert_eq!(events[5].1["delta"]["stop_reason"], "end_turn");
        assert_eq!(events[5].1["usage"]["output_tokens"], 2);
    }

    #[test]
    fn stream_translates_tool_call_deltas() {
        let chunks = concat!(
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"Checking\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_9\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"city\\\":\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"SF\\\"}\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let mut translator = StreamTranslator::new();
        let mut out = translator.push(chunks.as_bytes());
        out.push_str(&translator.finish());

        let events = parse_events(&out);
        let names: Vec<&str> = events.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "message_start",
                "content_block_start", // text
                "content_block_delta", // "Checking"
                "content_block_stop",  // text closed by tool block
                "content_block_start", // tool_use
                "content_block_delta", // input_json_delta
                "content_block_delta", // input_json_delta
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );

        assert_eq!(
            events[4].1["content_block"],
            json!({ "type": "tool_use", "id": "call_9", "name": "get_weather", "input": {} })
        );
        assert_eq!(events[4].1["index"], 1);
        let fragments: String = events[5].1["delta"]["partial_json"]
            .as_str()
            .unwrap()
            .to_string()
            + events[6].1["delta"]["partial_json"].as_str().unwrap();
        assert_eq!(fragments, "{\"city\":\"SF\"}");
        assert_eq!(events[8].1["delta"]["stop_reason"], "tool_use");
    }

    #[test]
    fn stream_reassembles_lines_split_across_arbitrary_chunk_boundaries() {
        // Feed the same canned stream 7 bytes at a time — every SSE line
        // is split mid-JSON — and require the identical event sequence.
        let mut whole = StreamTranslator::new();
        let mut expected = whole.push(TEXT_STREAM.as_bytes());
        expected.push_str(&whole.finish());

        let mut split = StreamTranslator::new();
        let mut out = String::new();
        for chunk in TEXT_STREAM.as_bytes().chunks(7) {
            out.push_str(&split.push(chunk));
        }
        out.push_str(&split.finish());

        assert_eq!(out, expected);
        assert!(!parse_events(&out).is_empty());
    }

    #[test]
    fn stream_without_done_marker_is_flushed_by_finish() {
        let mut translator = StreamTranslator::new();
        let mut out = translator.push(
            "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"hi\"},\"finish_reason\":null}]}\n\n"
                .as_bytes(),
        );
        out.push_str(&translator.finish());
        // finish() must be idempotent.
        assert_eq!(translator.finish(), "");

        let names: Vec<String> = parse_events(&out).into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            [
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );
    }

    #[test]
    fn empty_stream_produces_no_events() {
        let mut translator = StreamTranslator::new();
        assert_eq!(translator.push(b""), "");
        assert_eq!(translator.finish(), "");
    }
}
