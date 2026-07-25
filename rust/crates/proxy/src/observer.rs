//! Response stream observer — extracts inference telemetry (model, token
//! usage, TTFT, tokens/sec) from upstream response bodies as they flow
//! through the gate, without buffering streams.
//!
//! Understands three shapes, scanned opportunistically:
//! - OpenAI-compatible SSE (`data: {json}` lines; final chunk may carry
//!   `usage` when the client asked for `stream_options.include_usage`)
//! - Ollama-native NDJSON (one JSON object per line, `eval_count` /
//!   `prompt_eval_count` on the `done: true` object)
//! - plain JSON bodies (non-streamed completions, `usage` / `eval_count`)
//!
//! Only pattern-scans complete lines; per-line and whole-body buffers are
//! bounded, so a runaway stream can't grow memory.

use std::time::Instant;

use pay_core::InferenceUsage;

/// Longest SSE/NDJSON line we'll buffer for parsing; longer lines are
/// dropped unparsed (token deltas are tiny — a line this long is payload,
/// not telemetry).
const MAX_LINE_BYTES: usize = 64 * 1024;
/// Cap for buffering non-streamed JSON bodies.
const MAX_BODY_BYTES: usize = 256 * 1024;
/// Minimum interval between live `record_exchange_update` emissions.
const EMIT_INTERVAL_MS: u128 = 1_000;

pub struct StreamObserver {
    pub usage: InferenceUsage,
    first_chunk_at: Option<Instant>,
    /// Partial trailing line of a streamed body.
    line_buf: Vec<u8>,
    /// Whole body of a non-streamed response (bounded).
    body_buf: Vec<u8>,
    body_overflow: bool,
    /// Count of content-bearing stream events — the live approximation of
    /// completion tokens until an authoritative count arrives.
    events: u64,
    authoritative: bool,
    last_emit: Option<Instant>,
}

impl StreamObserver {
    pub fn new(streamed: bool) -> Self {
        Self {
            usage: InferenceUsage {
                streamed,
                ..Default::default()
            },
            first_chunk_at: None,
            line_buf: Vec::new(),
            body_buf: Vec::new(),
            body_overflow: false,
            events: 0,
            authoritative: false,
            last_emit: None,
        }
    }

    /// Feed one upstream body chunk. `request_start` anchors TTFT.
    pub fn on_chunk(&mut self, chunk: &[u8], request_start: Instant) {
        let now = Instant::now();
        if self.first_chunk_at.is_none() {
            self.first_chunk_at = Some(now);
            self.usage.ttft_ms = Some(request_start.elapsed().as_millis() as u64);
        }

        if self.usage.streamed {
            self.scan_stream_chunk(chunk);
            self.refresh_rate(now);
        } else if !self.body_overflow {
            if self.body_buf.len() + chunk.len() > MAX_BODY_BYTES {
                self.body_overflow = true;
                self.body_buf.clear();
            } else {
                self.body_buf.extend_from_slice(chunk);
            }
        }
    }

    /// End of stream — parse a buffered non-streamed body and flush the
    /// trailing line of a streamed one.
    pub fn finish(&mut self) {
        if self.usage.streamed {
            if !self.line_buf.is_empty() && self.line_buf.len() <= MAX_LINE_BYTES {
                let line = std::mem::take(&mut self.line_buf);
                self.apply_line(&line);
            }
            self.refresh_rate(Instant::now());
        } else if !self.body_buf.is_empty() {
            let body = std::mem::take(&mut self.body_buf);
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
                apply_json(
                    &mut self.usage,
                    &json,
                    &mut self.events,
                    &mut self.authoritative,
                );
            }
        }
    }

    /// Rate-limits live emissions (~1/s). Callers emit when this is true.
    pub fn should_emit(&mut self) -> bool {
        let now = Instant::now();
        match self.last_emit {
            Some(last) if now.duration_since(last).as_millis() < EMIT_INTERVAL_MS => false,
            _ => {
                self.last_emit = Some(now);
                true
            }
        }
    }

    fn scan_stream_chunk(&mut self, chunk: &[u8]) {
        for byte in chunk {
            if *byte == b'\n' {
                let line = std::mem::take(&mut self.line_buf);
                if line.len() <= MAX_LINE_BYTES {
                    self.apply_line(&line);
                }
            } else if self.line_buf.len() <= MAX_LINE_BYTES {
                self.line_buf.push(*byte);
            }
        }
    }

    fn apply_line(&mut self, line: &[u8]) {
        let Ok(text) = std::str::from_utf8(line) else {
            return;
        };
        let payload = text
            .trim()
            .strip_prefix("data:")
            .map(str::trim)
            .unwrap_or_else(|| text.trim());
        if payload.is_empty() || payload == "[DONE]" {
            return;
        }
        let Ok(json) = serde_json::from_str::<serde_json::Value>(payload) else {
            return;
        };
        apply_json(
            &mut self.usage,
            &json,
            &mut self.events,
            &mut self.authoritative,
        );
    }

    /// tokens/sec over the generation window (first token → now), from the
    /// best completion count available.
    fn refresh_rate(&mut self, now: Instant) {
        if !self.authoritative {
            self.usage.tokens_completion = (self.events > 0).then_some(self.events);
        }
        let (Some(first), Some(tokens)) = (self.first_chunk_at, self.usage.tokens_completion)
        else {
            return;
        };
        let secs = now.duration_since(first).as_secs_f64();
        if secs > 0.05 && tokens > 1 {
            self.usage.tokens_per_sec = Some(round1(tokens as f64 / secs));
        }
    }
}

/// Fold one JSON payload (stream event or whole body) into `usage`.
fn apply_json(
    usage: &mut InferenceUsage,
    json: &serde_json::Value,
    events: &mut u64,
    authoritative: &mut bool,
) {
    if usage.model.is_none() {
        // Anthropic `message_start` nests the model under `message`.
        let model = json
            .get("model")
            .or_else(|| json.pointer("/message/model"))
            .or_else(|| json.pointer("/response/model"))
            .and_then(|v| v.as_str());
        if let Some(model) = model {
            usage.model = Some(model.to_string());
        }
    }

    // Usage objects: OpenAI-compat (`prompt_tokens`/`completion_tokens`),
    // Anthropic (`input_tokens`/`output_tokens` — top-level on plain bodies
    // and `message_delta` events, nested under `message` on `message_start`;
    // output counts are cumulative, so later values overwrite).
    for u in [
        json.get("usage"),
        json.pointer("/message/usage"),
        json.pointer("/response/usage"),
    ]
    .into_iter()
    .flatten()
    .filter(|u| !u.is_null())
    {
        if let Some(prompt) = u
            .get("prompt_tokens")
            .or_else(|| u.get("input_tokens"))
            .and_then(|v| v.as_u64())
        {
            usage.tokens_prompt = Some(prompt);
        }
        if let Some(completion) = u
            .get("completion_tokens")
            .or_else(|| u.get("output_tokens"))
            .and_then(|v| v.as_u64())
        {
            usage.tokens_completion = Some(completion);
            *authoritative = true;
        }
    }

    // Ollama-native counters (final `done: true` object or plain body).
    if let Some(prompt) = json.get("prompt_eval_count").and_then(|v| v.as_u64()) {
        usage.tokens_prompt = Some(prompt);
    }
    if let Some(completion) = json.get("eval_count").and_then(|v| v.as_u64()) {
        usage.tokens_completion = Some(completion);
        *authoritative = true;
    }

    // Content-bearing stream events approximate completion tokens (~1 token
    // per delta) until an authoritative count lands. `/message/content` must
    // be a non-empty string (Ollama NDJSON deltas) — Anthropic's
    // `message_start` carries an empty content ARRAY that must not count.
    let has_content = json
        .pointer("/choices/0/delta")
        .is_some_and(|d| !d.is_null())
        || json
            .pointer("/message/content")
            .and_then(|c| c.as_str())
            .is_some_and(|c| !c.is_empty())
        || json.get("response").is_some_and(|r| r.is_string())
        || (json.get("type").and_then(|t| t.as_str()) == Some("response.output_text.delta")
            && json.get("delta").is_some_and(|delta| delta.is_string()))
        || json.get("type").and_then(|t| t.as_str()) == Some("content_block_delta");
    if has_content {
        *events += 1;
    }
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start() -> Instant {
        Instant::now()
    }

    fn feed_all(observer: &mut StreamObserver, body: &str) {
        let anchor = start();
        observer.on_chunk(body.as_bytes(), anchor);
        observer.finish();
    }

    #[test]
    fn openai_sse_stream_with_final_usage() {
        let mut obs = StreamObserver::new(true);
        let stream = concat!(
            "data: {\"model\":\"llama3.2:3b\",\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{}}],\"finish_reason\":\"stop\"}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":214}}\n\n",
            "data: [DONE]\n\n",
        );
        feed_all(&mut obs, stream);

        assert_eq!(obs.usage.model.as_deref(), Some("llama3.2:3b"));
        assert_eq!(obs.usage.tokens_prompt, Some(12));
        assert_eq!(obs.usage.tokens_completion, Some(214), "authoritative wins");
        assert!(obs.usage.streamed);
        assert!(obs.usage.ttft_ms.is_some());
    }

    #[test]
    fn openai_sse_stream_without_usage_approximates_from_deltas() {
        let mut obs = StreamObserver::new(true);
        let stream = concat!(
            "data: {\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"b\"}}]}\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"c\"}}]}\n",
            "data: [DONE]\n",
        );
        feed_all(&mut obs, stream);

        assert_eq!(
            obs.usage.tokens_completion,
            Some(3),
            "one content delta ≈ one token"
        );
    }

    #[test]
    fn responses_sse_reads_nested_completed_usage() {
        let mut obs = StreamObserver::new(true);
        let stream = concat!(
            "event: response.output_text.delta\n",
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hello\"}\n\n",
            "event: response.completed\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-test\",\"usage\":{\"input_tokens\":21,\"output_tokens\":13}}}\n\n",
        );
        feed_all(&mut obs, stream);

        assert_eq!(obs.usage.model.as_deref(), Some("gpt-test"));
        assert_eq!(obs.usage.tokens_prompt, Some(21));
        assert_eq!(obs.usage.tokens_completion, Some(13));
    }

    #[test]
    fn ollama_ndjson_final_object_is_authoritative() {
        let mut obs = StreamObserver::new(true);
        let stream = concat!(
            "{\"model\":\"llama3.2:3b\",\"message\":{\"role\":\"assistant\",\"content\":\"He\"},\"done\":false}\n",
            "{\"message\":{\"role\":\"assistant\",\"content\":\"llo\"},\"done\":false}\n",
            "{\"done\":true,\"prompt_eval_count\":5,\"eval_count\":42}\n",
        );
        feed_all(&mut obs, stream);

        assert_eq!(obs.usage.model.as_deref(), Some("llama3.2:3b"));
        assert_eq!(obs.usage.tokens_prompt, Some(5));
        assert_eq!(obs.usage.tokens_completion, Some(42));
    }

    #[test]
    fn sse_line_split_across_chunks() {
        let mut obs = StreamObserver::new(true);
        let anchor = start();
        obs.on_chunk(b"data: {\"model\":\"m\",\"usage\":{\"prompt_tok", anchor);
        obs.on_chunk(b"ens\":7,\"completion_tokens\":9}}\n", anchor);
        obs.finish();

        assert_eq!(obs.usage.tokens_prompt, Some(7));
        assert_eq!(obs.usage.tokens_completion, Some(9));
    }

    #[test]
    fn anthropic_sse_stream_reports_input_output_tokens() {
        // The shape Claude Code actually drives (`POST /v1/messages`,
        // stream). Input tokens ride message_start (nested), output tokens
        // ride message_delta events cumulatively.
        let mut obs = StreamObserver::new(true);
        let stream = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"gemma4:latest\",\"content\":[],\"usage\":{\"input_tokens\":17,\"output_tokens\":1}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"!\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":11}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        feed_all(&mut obs, stream);

        assert_eq!(obs.usage.model.as_deref(), Some("gemma4:latest"));
        assert_eq!(obs.usage.tokens_prompt, Some(17));
        assert_eq!(
            obs.usage.tokens_completion,
            Some(11),
            "authoritative output_tokens beats the content_block_delta approximation"
        );
    }

    #[test]
    fn non_streamed_anthropic_body() {
        let mut obs = StreamObserver::new(false);
        feed_all(
            &mut obs,
            r#"{"id":"msg_1","type":"message","role":"assistant","model":"gemma4:latest","content":[{"type":"text","text":"Hi!"}],"stop_reason":"end_turn","usage":{"input_tokens":17,"output_tokens":11}}"#,
        );
        assert_eq!(obs.usage.model.as_deref(), Some("gemma4:latest"));
        assert_eq!(obs.usage.tokens_prompt, Some(17));
        assert_eq!(obs.usage.tokens_completion, Some(11));
    }

    #[test]
    fn anthropic_message_start_empty_content_does_not_count_as_event() {
        let mut obs = StreamObserver::new(true);
        // Only a message_start (empty content array) and a stop — no deltas,
        // no usage. The approximation must stay at zero.
        let stream = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"model\":\"m\",\"content\":[]}}\n",
            "data: {\"type\":\"message_stop\"}\n",
        );
        feed_all(&mut obs, stream);
        assert_eq!(obs.usage.tokens_completion, None);
    }

    #[test]
    fn non_streamed_openai_body() {
        let mut obs = StreamObserver::new(false);
        feed_all(
            &mut obs,
            r#"{"model":"qwen2.5-7b","choices":[{"message":{"content":"hi"}}],"usage":{"prompt_tokens":3,"completion_tokens":8}}"#,
        );
        assert_eq!(obs.usage.model.as_deref(), Some("qwen2.5-7b"));
        assert_eq!(obs.usage.tokens_prompt, Some(3));
        assert_eq!(obs.usage.tokens_completion, Some(8));
        assert!(!obs.usage.streamed);
    }

    #[test]
    fn non_streamed_ollama_body() {
        let mut obs = StreamObserver::new(false);
        feed_all(
            &mut obs,
            r#"{"model":"stub:1b","message":{"role":"assistant","content":"hey"},"done":true,"prompt_eval_count":5,"eval_count":4}"#,
        );
        assert_eq!(obs.usage.tokens_prompt, Some(5));
        assert_eq!(obs.usage.tokens_completion, Some(4));
    }

    #[test]
    fn oversized_body_is_dropped_not_buffered() {
        let mut obs = StreamObserver::new(false);
        let anchor = start();
        let big = vec![b'x'; MAX_BODY_BYTES + 1];
        obs.on_chunk(&big, anchor);
        obs.finish();
        assert_eq!(obs.usage.tokens_completion, None);
        assert!(obs.body_buf.is_empty(), "overflow must free the buffer");
    }

    #[test]
    fn oversized_stream_line_is_skipped() {
        let mut obs = StreamObserver::new(true);
        let anchor = start();
        let mut line = b"data: {\"choices\":[{\"delta\":{\"content\":\"".to_vec();
        line.extend(vec![b'x'; MAX_LINE_BYTES]);
        line.extend(b"\"}}]}\n");
        obs.on_chunk(&line, anchor);
        obs.on_chunk(
            b"data: {\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2}}\n",
            anchor,
        );
        obs.finish();
        // The oversized line was dropped, but scanning recovered on the next line.
        assert_eq!(obs.usage.tokens_completion, Some(2));
    }

    #[test]
    fn garbage_body_yields_no_usage() {
        let mut obs = StreamObserver::new(false);
        feed_all(&mut obs, "<html>definitely not json</html>");
        assert_eq!(
            obs.usage,
            InferenceUsage {
                streamed: false,
                ttft_ms: obs.usage.ttft_ms,
                ..Default::default()
            }
        );
    }

    #[test]
    fn emit_throttle_allows_first_then_blocks() {
        let mut obs = StreamObserver::new(true);
        assert!(obs.should_emit());
        assert!(
            !obs.should_emit(),
            "second call within 1s must be throttled"
        );
    }
}
