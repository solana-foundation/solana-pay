//! Session-aware streaming metering for proxied HTTP responses.
//!
//! The proxy uses this module to observe provider streams, rate the cumulative
//! usage through the YAML-derived session meter, and apply backpressure until
//! the client has committed a voucher for the newly delivered watermark.

use std::error::Error as StdError;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use futures_util::{Stream, StreamExt};
use pay_types::metering::{BillingUnit, MeterDimension, MeterDirection, Metering};
use serde_json::Value;

use crate::server::gate::SessionForward;
use crate::server::metering::{
    RequestProperties, provider_token_quantity, quota_tokens_per_unit, resolve_variant,
};
use crate::server::session::SessionMpp;
use crate::server::session_metering::{
    GateMode, Result as MeteringResult, SessionGateDecision, SessionMeterDimension,
    SessionMeterSpec, SessionMeteringContext, SessionUsageGate, StablecoinSettlement,
    UsageObservation, spec_from_metering,
};

const COMMIT_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const COMMIT_POLL_INTERVAL: Duration = Duration::from_millis(50);
const LIFECYCLE_TOUCH_INTERVAL: Duration = Duration::from_secs(30);

type BoxError = Box<dyn StdError + Send + Sync>;

/// Session data attached by the payment middleware to a paid upstream retry.
#[derive(Clone)]
pub struct SessionStreamContext {
    session_mpp: Arc<SessionMpp>,
    session_id: String,
    baseline_base_units: u64,
}

impl SessionStreamContext {
    pub fn new(
        session_mpp: Arc<SessionMpp>,
        session_id: impl Into<String>,
        baseline_base_units: u64,
    ) -> Self {
        Self {
            session_mpp,
            session_id: session_id.into(),
            baseline_base_units,
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn baseline_base_units(&self) -> u64 {
        self.baseline_base_units
    }

    pub fn committed_base_units(&self) -> u64 {
        self.session_mpp
            .committed_watermark(&self.session_id)
            .unwrap_or(self.baseline_base_units)
            .max(self.baseline_base_units)
    }

    pub fn settlement(&self) -> StablecoinSettlement {
        StablecoinSettlement::new(self.session_mpp.decimals())
    }

    pub fn min_voucher_delta(&self) -> u64 {
        self.session_mpp.min_voucher_delta()
    }

    pub fn touch_channel_unconfirmed(&self) {
        self.session_mpp
            .touch_channel_unconfirmed(self.session_id.clone());
    }
}

#[derive(Debug, Clone, Default)]
pub struct SessionUsageHints {
    quota_units: Vec<QuotaUnitHint>,
}

#[derive(Debug, Clone, Copy)]
struct QuotaUnitHint {
    direction: MeterDirection,
    tokens_per_unit: u64,
}

impl SessionUsageHints {
    pub fn from_metering(
        metering: &Metering,
        variant_hint: Option<&str>,
        request_properties: &RequestProperties,
    ) -> Self {
        let dimensions = select_meter_dimensions(metering, variant_hint).unwrap_or(&[]);
        let quota_units = dimensions
            .iter()
            .filter_map(|dimension| {
                if dimension.unit != BillingUnit::QuotaUnits {
                    return None;
                }
                let tokens_per_unit = quota_tokens_per_unit(dimension, request_properties)?;
                Some(QuotaUnitHint {
                    direction: dimension.direction,
                    tokens_per_unit,
                })
            })
            .collect();

        Self { quota_units }
    }

    fn tokens_per_quota_unit(&self, direction: MeterDirection) -> Option<u64> {
        self.quota_units
            .iter()
            .find(|hint| hint.direction == direction)
            .map(|hint| hint.tokens_per_unit)
    }
}

/// Builds a stream meter from the current YAML metering config.
pub fn meter_from_config(
    metering: &Metering,
    request_properties: &RequestProperties,
    variant_hint: Option<&str>,
    context: SessionStreamContext,
) -> MeteringResult<Option<SessionStreamMeter>> {
    let spec = spec_from_metering(
        metering,
        SessionMeteringContext::new()
            .with_request_properties(request_properties)
            .with_optional_variant_hint(variant_hint),
    )?;

    if !has_stream_observable_dimension(&spec) {
        return Ok(None);
    }

    let hints = SessionUsageHints::from_metering(metering, variant_hint, request_properties);
    SessionStreamMeter::new(spec, hints, context).map(Some)
}

pub struct SessionStreamMeter {
    context: SessionStreamContext,
    gate: SessionUsageGate,
    accumulator: StreamUsageAccumulator,
    current: UsageObservation,
    next_lifecycle_touch: Instant,
}

/// Server-authorized meter for a delegated session response stream.
///
/// The meter owns the session's capacity lease for the lifetime of the body.
/// Each cumulative usage increase is signed and persisted before the bytes
/// that exposed it are released to the client.
pub(crate) struct DelegatedSessionStreamMeter {
    forward: SessionForward,
    gate: SessionUsageGate,
    accumulator: StreamUsageAccumulator,
    current: UsageObservation,
    priced_context_length: Option<u64>,
    clamp_reprice_to_authorized: bool,
    authorization_exhausted: bool,
    next_lifecycle_touch: Instant,
}

impl DelegatedSessionStreamMeter {
    pub(crate) fn from_forward(forward: SessionForward) -> Result<Self, BoxError> {
        let plan = forward.settlement.as_deref().ok_or_else(|| {
            box_error(std::io::Error::other(
                "delegated stream forward is missing its settlement plan",
            ))
        })?;
        let spec = spec_from_metering(
            &plan.metering,
            SessionMeteringContext::new()
                .with_request_properties(&plan.request_properties)
                .with_optional_variant_hint(plan.variant_hint.as_deref()),
        )
        .map_err(box_error)?;
        let hints = SessionUsageHints::from_metering(
            &plan.metering,
            plan.variant_hint.as_deref(),
            &plan.request_properties,
        );
        let settlement = StablecoinSettlement::new(forward.handle.decimals());
        // A delegated signer is local to the gateway, so there is no reason to
        // release chargeable output while waiting to batch a client voucher.
        // Stablecoin precision still naturally batches sub-base-unit usage.
        let gate = SessionUsageGate::new(spec.clone(), settlement, forward.committed_base_units, 1)
            .map_err(box_error)?;
        let current = zero_observation(&spec);
        let priced_context_length = plan.request_properties.context_length;
        Ok(Self {
            forward,
            gate,
            accumulator: StreamUsageAccumulator::new(spec, hints),
            current,
            priced_context_length,
            clamp_reprice_to_authorized: false,
            authorization_exhausted: false,
            next_lifecycle_touch: Instant::now() + LIFECYCLE_TOUCH_INTERVAL,
        })
    }

    pub(crate) fn supports(forward: &SessionForward) -> bool {
        let Some(plan) = forward.settlement.as_deref() else {
            return false;
        };
        spec_from_metering(
            &plan.metering,
            SessionMeteringContext::new()
                .with_request_properties(&plan.request_properties)
                .with_optional_variant_hint(plan.variant_hint.as_deref()),
        )
        .is_ok_and(|spec| has_stream_observable_dimension(&spec))
    }

    fn observe_chunk(
        &mut self,
        chunk: &[u8],
        is_sse: bool,
    ) -> Result<Option<SessionGateDecision>, BoxError> {
        let output_chars_before = self.accumulator.output_chars;
        if !self.accumulator.observe_chunk(chunk, is_sse) {
            return Ok(None);
        }
        if self.authorization_exhausted {
            return Err(box_error(std::io::Error::other(format!(
                "delegated session {} exhausted its authorization",
                self.forward.channel_id
            ))));
        }
        if let Some(context_length) = self.accumulator.observed_input_tokens()
            && self.priced_context_length != Some(context_length)
        {
            let usage_only_chunk = self.accumulator.output_chars == output_chars_before;
            self.reprice_for_context_length(context_length, usage_only_chunk)?;
        }
        self.current = self.accumulator.observation();
        self.gate
            .observe(self.current.clone(), GateMode::Streaming)
            .map(Some)
            .map_err(box_error)
    }

    fn finish(&mut self) -> MeteringResult<Option<SessionGateDecision>> {
        if !self.accumulator.has_observation() || self.authorization_exhausted {
            return Ok(None);
        }
        self.gate
            .observe(self.current.clone(), GateMode::Final)
            .map(Some)
    }

    async fn settle(&mut self, decision: SessionGateDecision) -> Result<(), BoxError> {
        let clamp_reprice_to_authorized = std::mem::take(&mut self.clamp_reprice_to_authorized);
        if !decision.requires_voucher() {
            return Ok(());
        }
        let requested_target = decision.target_cumulative_base_units();
        let committed = self.gate.committed_base_units();
        let authorized = self
            .forward
            .committed_base_units
            .saturating_add(self.forward.available_base_units);
        let target = if clamp_reprice_to_authorized {
            requested_target.min(authorized)
        } else {
            requested_target
        };
        let exhausted_by_reprice = clamp_reprice_to_authorized && requested_target > authorized;
        if target > authorized {
            return Err(box_error(std::io::Error::other(format!(
                "delegated session {} requires cumulative {target}, above authorized {authorized}",
                self.forward.channel_id
            ))));
        }
        let amount = target.saturating_sub(committed);
        if amount == 0 {
            self.authorization_exhausted |= exhausted_by_reprice;
            return Ok(());
        }
        let accepted = self
            .forward
            .handle
            .authorize_delegated_usage(&self.forward.channel_id, amount)
            .await
            .map_err(box_error)?;
        self.gate.record_commit(accepted.cumulative);
        self.authorization_exhausted |= exhausted_by_reprice;
        Ok(())
    }

    fn reprice_for_context_length(
        &mut self,
        context_length: u64,
        usage_only_chunk: bool,
    ) -> Result<(), BoxError> {
        let plan = self.forward.settlement.as_deref().ok_or_else(|| {
            box_error(std::io::Error::other(
                "delegated stream meter lost its settlement plan",
            ))
        })?;
        let mut properties = plan.request_properties;
        properties.context_length = Some(context_length);
        let spec = spec_from_metering(
            &plan.metering,
            SessionMeteringContext::new()
                .with_request_properties(&properties)
                .with_optional_variant_hint(plan.variant_hint.as_deref()),
        )
        .map_err(box_error)?;
        let hints = SessionUsageHints::from_metering(
            &plan.metering,
            plan.variant_hint.as_deref(),
            &properties,
        );
        let committed = self.gate.committed_base_units();
        let mut gate = SessionUsageGate::new(
            spec.clone(),
            StablecoinSettlement::new(self.forward.handle.decimals()),
            self.forward.committed_base_units,
            1,
        )
        .map_err(box_error)?;
        gate.record_commit(committed);
        self.accumulator.reconfigure(spec, hints);
        self.gate = gate;
        self.priced_context_length = Some(context_length);
        self.clamp_reprice_to_authorized = usage_only_chunk;
        Ok(())
    }

    fn touch_channel_if_due(&mut self) {
        let now = Instant::now();
        if now < self.next_lifecycle_touch {
            return;
        }
        self.forward
            .handle
            .touch_channel_unconfirmed(self.forward.channel_id.clone());
        self.next_lifecycle_touch = now + LIFECYCLE_TOUCH_INTERVAL;
    }
}

impl SessionStreamMeter {
    pub fn new(
        spec: SessionMeterSpec,
        hints: SessionUsageHints,
        context: SessionStreamContext,
    ) -> MeteringResult<Self> {
        let gate = SessionUsageGate::new(
            spec.clone(),
            context.settlement(),
            context.baseline_base_units(),
            context.min_voucher_delta(),
        )?;
        let current = zero_observation(&spec);
        Ok(Self {
            context,
            gate,
            accumulator: StreamUsageAccumulator::new(spec, hints),
            current,
            next_lifecycle_touch: Instant::now() + LIFECYCLE_TOUCH_INTERVAL,
        })
    }

    pub fn observe_chunk(
        &mut self,
        chunk: &[u8],
        is_sse: bool,
    ) -> MeteringResult<Option<SessionGateDecision>> {
        if !self.accumulator.observe_chunk(chunk, is_sse) {
            return Ok(None);
        }

        self.current = self.accumulator.observation();
        self.gate
            .observe(self.current.clone(), GateMode::Streaming)
            .map(Some)
    }

    pub fn finish(&mut self) -> MeteringResult<Option<SessionGateDecision>> {
        if !self.accumulator.has_observation() {
            return Ok(None);
        }
        self.gate
            .observe(self.current.clone(), GateMode::Final)
            .map(Some)
    }

    fn record_commit(&mut self, committed_base_units: u64) {
        self.gate.record_commit(committed_base_units);
    }

    fn touch_channel_if_due(&mut self) {
        let now = Instant::now();
        if now < self.next_lifecycle_touch {
            return;
        }
        self.context.touch_channel_unconfirmed();
        self.next_lifecycle_touch = now + LIFECYCLE_TOUCH_INTERVAL;
    }
}

/// Wrap an upstream byte stream with session metering backpressure.
pub fn meter_response_stream<S>(
    stream: S,
    mut meter: SessionStreamMeter,
    is_sse: bool,
) -> impl Stream<Item = Result<Bytes, BoxError>> + Send + 'static
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
{
    async_stream::try_stream! {
        futures_util::pin_mut!(stream);
        while let Some(next) = stream.next().await {
            let chunk = next.map_err(box_error)?;
            meter.touch_channel_if_due();
            let decision = meter.observe_chunk(&chunk, is_sse).map_err(box_error)?;
            if let Some(decision) = decision {
                settle_decision(&mut meter, decision).await?;
            }
            // Do not release the bytes that crossed the voucher threshold
            // until the corresponding cumulative commit is durable.
            yield chunk;
        }

        if let Some(decision) = meter.finish().map_err(box_error)? {
            settle_decision(&mut meter, decision).await?;
        }
    }
}

/// Wrap a delegated-session response stream without buffering it.
///
/// Chargeable chunks remain behind the payment gate until the gateway's
/// cumulative voucher has been persisted. Dropping the returned stream drops
/// the owned meter and releases its exclusive capacity lease.
pub(crate) fn meter_delegated_response_stream<S, E>(
    stream: S,
    mut meter: DelegatedSessionStreamMeter,
    is_sse: bool,
) -> impl Stream<Item = Result<Bytes, BoxError>> + Send + 'static
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: StdError + Send + Sync + 'static,
{
    async_stream::try_stream! {
        futures_util::pin_mut!(stream);
        while let Some(next) = stream.next().await {
            let chunk = next.map_err(box_error)?;
            meter.touch_channel_if_due();
            let decision = meter.observe_chunk(&chunk, is_sse)?;
            if let Some(decision) = decision {
                meter.settle(decision).await?;
            }
            yield chunk;
        }

        if let Some(decision) = meter.finish().map_err(box_error)? {
            meter.settle(decision).await?;
        }
    }
}

async fn settle_decision(
    meter: &mut SessionStreamMeter,
    decision: SessionGateDecision,
) -> Result<(), BoxError> {
    if !decision.requires_voucher() {
        return Ok(());
    }

    let target = decision.target_cumulative_base_units();
    let committed = wait_for_commit(&meter.context, target).await?;
    meter.record_commit(committed);
    Ok(())
}

async fn wait_for_commit(context: &SessionStreamContext, target: u64) -> Result<u64, BoxError> {
    let wait = async {
        loop {
            let committed = context.committed_base_units();
            if committed >= target {
                return Ok(committed);
            }
            tokio::time::sleep(COMMIT_POLL_INTERVAL).await;
        }
    };

    tokio::time::timeout(COMMIT_WAIT_TIMEOUT, wait)
        .await
        .map_err(|_| {
            box_error(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "timed out waiting for session {} voucher at cumulative {}",
                    context.session_id(),
                    target
                ),
            ))
        })?
}

#[derive(Debug, Clone)]
struct StreamUsageAccumulator {
    spec: SessionMeterSpec,
    hints: SessionUsageHints,
    sse: SseUsageDecoder,
    output_bytes: u64,
    output_chars: u64,
    output_words: u64,
    input_tokens: u64,
    output_tokens: u64,
    request_seen: bool,
    observed: bool,
}

impl StreamUsageAccumulator {
    fn new(spec: SessionMeterSpec, hints: SessionUsageHints) -> Self {
        Self {
            spec,
            hints,
            sse: SseUsageDecoder::default(),
            output_bytes: 0,
            output_chars: 0,
            output_words: 0,
            input_tokens: 0,
            output_tokens: 0,
            request_seen: false,
            observed: false,
        }
    }

    fn observe_chunk(&mut self, chunk: &[u8], is_sse: bool) -> bool {
        self.output_bytes = self.output_bytes.saturating_add(chunk.len() as u64);
        self.request_seen = true;

        let mut changed = false;
        if observes_unit(&self.spec, BillingUnit::Bytes) {
            changed = true;
        }

        if is_sse {
            changed |= self.observe_sse_chunk(chunk);
        } else if observes_unit(&self.spec, BillingUnit::Characters) {
            let text = String::from_utf8_lossy(chunk);
            self.output_chars = self
                .output_chars
                .saturating_add(text.chars().count() as u64);
            self.output_words = self.output_words.saturating_add(count_words(&text));
            changed = true;
        }

        self.observed |= changed;
        changed
    }

    fn observe_sse_chunk(&mut self, chunk: &[u8]) -> bool {
        let Ok(events) = self.sse.push_chunk(chunk) else {
            return false;
        };

        let mut changed = false;
        for event in events {
            let Some(data) = event.data else {
                continue;
            };
            if data.trim() == "[DONE]" {
                continue;
            }
            let Ok(value) = serde_json::from_str::<Value>(&data) else {
                continue;
            };

            let text_chars = streamed_text_char_count(&value);
            if text_chars > 0 {
                self.output_chars = self.output_chars.saturating_add(text_chars);
                self.output_words = self
                    .output_words
                    .saturating_add(streamed_text_word_count(&value));
                changed = true;
            }

            if let Some(input) = provider_token_quantity(&value, MeterDirection::Input) {
                self.input_tokens = self.input_tokens.max(input);
                changed = true;
            }

            if let Some(output) = provider_token_quantity(&value, MeterDirection::Output) {
                self.output_tokens = self.output_tokens.max(output);
                changed = true;
            }
        }

        changed
    }

    fn observation(&self) -> UsageObservation {
        let mut observation = UsageObservation::new();
        for dimension in &self.spec.dimensions {
            let amount = self.dimension_amount(dimension);
            observation.set(dimension.direction, dimension.unit, amount);
        }
        observation
    }

    fn dimension_amount(&self, dimension: &SessionMeterDimension) -> u64 {
        match (dimension.direction, dimension.unit) {
            (MeterDirection::Usage, BillingUnit::Requests) => u64::from(self.request_seen),
            (MeterDirection::Output, BillingUnit::Bytes) => self.output_bytes,
            (MeterDirection::Output, BillingUnit::Characters) => self.output_chars,
            (MeterDirection::Input, BillingUnit::Tokens) => self.input_tokens,
            (MeterDirection::Output, BillingUnit::Tokens) => {
                self.output_tokens.max(self.output_words)
            }
            (MeterDirection::Input, BillingUnit::QuotaUnits) => self
                .hints
                .tokens_per_quota_unit(MeterDirection::Input)
                .map(|scale| ceil_div_u64(self.input_tokens, scale))
                .unwrap_or(self.input_tokens),
            (MeterDirection::Output, BillingUnit::QuotaUnits) => {
                let output_tokens = self.output_tokens.max(self.output_words);
                self.hints
                    .tokens_per_quota_unit(MeterDirection::Output)
                    .map(|scale| ceil_div_u64(output_tokens, scale))
                    .unwrap_or(output_tokens)
            }
            _ => 0,
        }
    }

    fn has_observation(&self) -> bool {
        self.observed
    }

    fn observed_input_tokens(&self) -> Option<u64> {
        (self.input_tokens > 0).then_some(self.input_tokens)
    }

    fn reconfigure(&mut self, spec: SessionMeterSpec, hints: SessionUsageHints) {
        self.spec = spec;
        self.hints = hints;
    }
}

#[derive(Debug, Clone, Default)]
struct SseUsageDecoder {
    buffer: String,
}

#[derive(Debug, Clone)]
struct SseUsageEvent {
    data: Option<String>,
}

impl SseUsageDecoder {
    fn push_chunk(&mut self, chunk: &[u8]) -> Result<Vec<SseUsageEvent>, std::str::Utf8Error> {
        let text = std::str::from_utf8(chunk)?;
        self.buffer
            .push_str(&text.replace("\r\n", "\n").replace('\r', "\n"));

        let mut events = vec![];
        while let Some(index) = self.buffer.find("\n\n") {
            let block = self.buffer[..index].to_string();
            self.buffer.drain(..index + 2);
            events.push(parse_sse_event(&block));
        }
        Ok(events)
    }
}

fn parse_sse_event(block: &str) -> SseUsageEvent {
    let mut data = vec![];
    for line in block.lines() {
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        if field == "data" {
            data.push(value.strip_prefix(' ').unwrap_or(value));
        }
    }
    SseUsageEvent {
        data: (!data.is_empty()).then(|| data.join("\n")),
    }
}

fn zero_observation(spec: &SessionMeterSpec) -> UsageObservation {
    let mut observation = UsageObservation::new();
    for dimension in &spec.dimensions {
        observation.set(dimension.direction, dimension.unit, 0);
    }
    observation
}

fn has_stream_observable_dimension(spec: &SessionMeterSpec) -> bool {
    spec.dimensions.iter().any(|dimension| {
        matches!(
            (dimension.direction, dimension.unit),
            (MeterDirection::Output, BillingUnit::Bytes)
                | (MeterDirection::Output, BillingUnit::Characters)
                | (MeterDirection::Output, BillingUnit::Tokens)
                | (MeterDirection::Output, BillingUnit::QuotaUnits)
        )
    })
}

fn observes_unit(spec: &SessionMeterSpec, unit: BillingUnit) -> bool {
    spec.dimensions
        .iter()
        .any(|dimension| dimension.unit == unit && dimension.direction == MeterDirection::Output)
}

fn select_meter_dimensions<'a>(
    metering: &'a Metering,
    variant_hint: Option<&str>,
) -> Option<&'a [MeterDimension]> {
    if !metering.variants.is_empty() {
        if let Some(variant) = resolve_variant(&metering.variants, variant_hint) {
            return Some(&variant.dimensions);
        }
        if !metering.dimensions.is_empty() {
            return Some(&metering.dimensions);
        }
        return metering
            .variants
            .first()
            .map(|variant| variant.dimensions.as_slice());
    }

    (!metering.dimensions.is_empty()).then_some(&metering.dimensions)
}

fn streamed_text_char_count(value: &Value) -> u64 {
    streamed_texts(value)
        .map(|text| text.chars().count() as u64)
        .sum()
}

fn streamed_text_word_count(value: &Value) -> u64 {
    streamed_texts(value).map(count_words).sum()
}

fn streamed_texts(value: &Value) -> impl Iterator<Item = &str> {
    let gemini = value
        .get("candidates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|candidate| {
            candidate
                .get("content")
                .and_then(|content| content.get("parts"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|part| part.get("text").and_then(Value::as_str));
    let openai = value
        .get("choices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|choice| {
            choice
                .get("delta")
                .and_then(|delta| delta.get("content"))
                .and_then(Value::as_str)
                .or_else(|| choice.get("text").and_then(Value::as_str))
        });
    let top_level_delta = value
        .get("delta")
        .and_then(|delta| {
            delta
                .as_str()
                .or_else(|| delta.get("text").and_then(Value::as_str))
        })
        .into_iter();

    gemini.chain(openai).chain(top_level_delta)
}

fn count_words(text: &str) -> u64 {
    text.split_whitespace().count() as u64
}

fn ceil_div_u64(value: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    value.saturating_add(divisor - 1) / divisor
}

fn box_error<E>(error: E) -> BoxError
where
    E: StdError + Send + Sync + 'static,
{
    Box::new(error)
}

trait OptionalVariantHint<'a> {
    fn with_optional_variant_hint(self, hint: Option<&'a str>) -> Self;
}

impl<'a> OptionalVariantHint<'a> for SessionMeteringContext<'a> {
    fn with_optional_variant_hint(self, hint: Option<&'a str>) -> Self {
        match hint {
            Some(hint) => self.with_variant_hint(hint),
            None => self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::session::SessionHandle;
    use crate::server::metering::parse_tokens_per_quota_unit;
    use crate::server::session::test_channel_state;
    use pay_kit::mpp::blockhash::BlockhashCache;
    use pay_kit::mpp::server::session::{SessionConfig, VoucherSigner};
    use pay_kit::mpp::solana_keychain::{SolanaSigner, memory::MemorySigner};
    use pay_kit::mpp::store::{ChannelStore, MemoryChannelStore};
    use pay_types::metering::{MeterDimension, PriceTier};

    fn dimension(
        direction: MeterDirection,
        unit: BillingUnit,
        notes: Option<&str>,
    ) -> MeterDimension {
        MeterDimension {
            direction,
            unit,
            scale: 1,
            period: None,
            tiers: vec![PriceTier {
                up_to: None,
                price_usd: 0.000001,
                condition: None,
                notes: notes.map(str::to_string),
                splits: vec![],
            }],
            meter: None,
        }
    }

    fn metering(dimensions: Vec<MeterDimension>) -> Metering {
        Metering {
            dimensions,
            variants: vec![],
            sku_tiers: vec![],
            splits: vec![],
            schemes: None,
            min_usd: None,
            upto: None,
        }
    }

    fn stream_test_signer() -> Box<dyn SolanaSigner> {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let mut keypair = [0_u8; 64];
        keypair[..32].copy_from_slice(signing_key.as_bytes());
        keypair[32..].copy_from_slice(verifying_key.as_bytes());
        Box::new(MemorySigner::from_bytes(&keypair).unwrap())
    }

    #[test]
    fn parses_quota_unit_hint_from_current_yaml_notes() {
        assert_eq!(
            parse_tokens_per_quota_unit("10 input tokens per quota unit; official price"),
            Some(10)
        );
        assert_eq!(
            parse_tokens_per_quota_unit("1,000 output tokens per quota unit"),
            Some(1_000)
        );
    }

    #[test]
    fn quota_unit_hints_follow_the_selected_conditional_tier() {
        let mut quota = dimension(
            MeterDirection::Input,
            BillingUnit::QuotaUnits,
            Some("4 input tokens per quota unit"),
        );
        quota.tiers[0].condition = Some(pay_types::metering::MeterCondition::ContextLength {
            op: pay_types::metering::CompareOp::Lte,
            value: 200_000,
        });
        quota.tiers.push(PriceTier {
            up_to: None,
            price_usd: 0.000001,
            condition: Some(pay_types::metering::MeterCondition::ContextLength {
                op: pay_types::metering::CompareOp::Gt,
                value: 200_000,
            }),
            notes: Some("2 input tokens per quota unit".to_string()),
            splits: vec![],
        });
        let properties = RequestProperties {
            context_length: Some(250_000),
            ..Default::default()
        };

        let hints = SessionUsageHints::from_metering(&metering(vec![quota]), None, &properties);

        assert_eq!(hints.tokens_per_quota_unit(MeterDirection::Input), Some(2));
    }

    #[test]
    fn sse_accumulator_observes_gemini_usage_metadata() {
        let spec = SessionMeterSpec::new([
            SessionMeterDimension::required(MeterDirection::Input, BillingUnit::QuotaUnits, 1, 3),
            SessionMeterDimension::required(MeterDirection::Output, BillingUnit::QuotaUnits, 1, 5),
        ]);
        let hints = SessionUsageHints::from_metering(
            &metering(vec![
                dimension(
                    MeterDirection::Input,
                    BillingUnit::QuotaUnits,
                    Some("10 input tokens per quota unit"),
                ),
                dimension(
                    MeterDirection::Output,
                    BillingUnit::QuotaUnits,
                    Some("2 output tokens per quota unit"),
                ),
            ]),
            None,
            &RequestProperties::default(),
        );
        let mut accumulator = StreamUsageAccumulator::new(spec, hints);

        let changed = accumulator.observe_chunk(
            br#"data: {"usageMetadata":{"promptTokenCount":27,"candidatesTokenCount":448}}

"#,
            true,
        );
        let observation = accumulator.observation();

        assert!(changed);
        assert_eq!(
            observation.get(MeterDirection::Input, BillingUnit::QuotaUnits),
            Some(3)
        );
        assert_eq!(
            observation.get(MeterDirection::Output, BillingUnit::QuotaUnits),
            Some(224)
        );
    }

    #[test]
    fn sse_accumulator_observes_openai_compatible_usage() {
        let spec = SessionMeterSpec::new([
            SessionMeterDimension::required(MeterDirection::Input, BillingUnit::QuotaUnits, 1, 3),
            SessionMeterDimension::required(MeterDirection::Output, BillingUnit::QuotaUnits, 1, 5),
        ]);
        let hints = SessionUsageHints::from_metering(
            &metering(vec![
                dimension(
                    MeterDirection::Input,
                    BillingUnit::QuotaUnits,
                    Some("4 input tokens per quota unit"),
                ),
                dimension(
                    MeterDirection::Output,
                    BillingUnit::QuotaUnits,
                    Some("2 output tokens per quota unit"),
                ),
            ]),
            None,
            &RequestProperties::default(),
        );
        let mut accumulator = StreamUsageAccumulator::new(spec, hints);

        let changed = accumulator.observe_chunk(
            br#"data: {"usage":{"prompt_tokens":8,"completion_tokens":5,"total_tokens":13}}

"#,
            true,
        );
        let observation = accumulator.observation();

        assert!(changed);
        assert_eq!(
            observation.get(MeterDirection::Input, BillingUnit::QuotaUnits),
            Some(2)
        );
        assert_eq!(
            observation.get(MeterDirection::Output, BillingUnit::QuotaUnits),
            Some(3)
        );
    }

    #[test]
    fn sse_accumulator_observes_responses_and_anthropic_usage() {
        let spec = SessionMeterSpec::new([
            SessionMeterDimension::required(MeterDirection::Input, BillingUnit::Tokens, 1, 1),
            SessionMeterDimension::required(MeterDirection::Output, BillingUnit::Tokens, 1, 1),
        ]);

        for chunk in [
            br#"data: {"type":"response.completed","response":{"usage":{"input_tokens":8,"output_tokens":5}}}

"#
            .as_slice(),
            br#"data: {"type":"message_start","message":{"usage":{"input_tokens":8,"output_tokens":0}}}

data: {"type":"message_delta","usage":{"output_tokens":5}}

"#
            .as_slice(),
        ] {
            let mut accumulator =
                StreamUsageAccumulator::new(spec.clone(), SessionUsageHints::default());

            assert!(accumulator.observe_chunk(chunk, true));
            assert_eq!(accumulator.observed_input_tokens(), Some(8));
            assert_eq!(
                accumulator
                    .observation()
                    .get(MeterDirection::Output, BillingUnit::Tokens),
                Some(5)
            );
        }
    }

    #[test]
    fn sse_accumulator_uses_openai_delta_words_as_live_output_floor() {
        let spec = SessionMeterSpec::new([SessionMeterDimension::required(
            MeterDirection::Output,
            BillingUnit::Tokens,
            1,
            1,
        )]);
        let mut accumulator = StreamUsageAccumulator::new(spec, SessionUsageHints::default());

        let changed = accumulator.observe_chunk(
            br#"data: {"choices":[{"delta":{"content":"one two three"}}]}

"#,
            true,
        );

        assert!(changed);
        assert_eq!(
            accumulator
                .observation()
                .get(MeterDirection::Output, BillingUnit::Tokens),
            Some(3)
        );
    }

    #[test]
    fn sse_accumulator_excludes_gemini_tool_prompt_tokens_from_output() {
        let spec = SessionMeterSpec::new([SessionMeterDimension::required(
            MeterDirection::Output,
            BillingUnit::QuotaUnits,
            1,
            5,
        )]);
        let hints = SessionUsageHints::from_metering(
            &metering(vec![dimension(
                MeterDirection::Output,
                BillingUnit::QuotaUnits,
                Some("1 output tokens per quota unit"),
            )]),
            None,
            &RequestProperties::default(),
        );
        let mut accumulator = StreamUsageAccumulator::new(spec, hints);

        let changed = accumulator.observe_chunk(
            br#"data: {"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":3,"thoughtsTokenCount":2,"toolUsePromptTokenCount":20,"totalTokenCount":35}}

"#,
            true,
        );

        assert!(changed);
        assert_eq!(
            accumulator
                .observation()
                .get(MeterDirection::Output, BillingUnit::QuotaUnits),
            Some(5)
        );
    }

    #[test]
    fn sse_accumulator_uses_text_words_as_live_output_floor() {
        let spec = SessionMeterSpec::new([SessionMeterDimension::required(
            MeterDirection::Output,
            BillingUnit::QuotaUnits,
            1,
            5,
        )]);
        let hints = SessionUsageHints::from_metering(
            &metering(vec![dimension(
                MeterDirection::Output,
                BillingUnit::QuotaUnits,
                Some("2 output tokens per quota unit"),
            )]),
            None,
            &RequestProperties::default(),
        );
        let mut accumulator = StreamUsageAccumulator::new(spec, hints);

        let changed = accumulator.observe_chunk(
            br#"data: {"candidates":[{"content":{"parts":[{"text":"one two three four"}]}}]}

"#,
            true,
        );

        assert!(changed);
        assert_eq!(
            accumulator
                .observation()
                .get(MeterDirection::Output, BillingUnit::QuotaUnits),
            Some(2)
        );
    }

    #[test]
    fn request_only_metering_is_not_stream_observable() {
        let spec = SessionMeterSpec::new([SessionMeterDimension::required(
            MeterDirection::Usage,
            BillingUnit::Requests,
            1,
            10_000,
        )]);

        assert!(!has_stream_observable_dimension(&spec));
    }

    fn stream_test_blockhash_cache() -> BlockhashCache {
        let cache = BlockhashCache::new();
        cache.set(
            "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxxxx11x".to_string(),
            42,
            123,
        );
        cache
    }

    #[tokio::test]
    async fn chargeable_stream_chunk_waits_for_matching_commit() {
        let store: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::new());
        let session = Arc::new(
            SessionMpp::new_with_channel_store(
                SessionConfig {
                    operator: solana_pubkey::Pubkey::new_unique().to_string(),
                    recipient: solana_pubkey::Pubkey::new_unique().to_string(),
                    suggested_deposit: Some(1_000),
                    currency: solana_pubkey::Pubkey::new_unique().to_string(),
                    network: "localnet".to_string(),
                    min_voucher_delta: 1,
                    ..SessionConfig::default()
                },
                "stream-test-secret",
                Arc::clone(&store),
            )
            .with_blockhash_cache(stream_test_blockhash_cache()),
        );
        let challenge = session.challenge(None).unwrap();
        let channel = solana_pubkey::Pubkey::new_unique();
        let signer = stream_test_signer();
        let authorized_signer = signer.pubkey().to_string();
        let handle = SessionHandle::new(channel, signer, challenge.clone());
        let channel_id = channel.to_string();
        store
            .put_channel(
                &channel_id,
                test_channel_state(
                    &channel_id,
                    1_000,
                    &authorized_signer,
                    "client",
                    &challenge.id,
                    solana_pubkey::Pubkey::new_unique().to_string(),
                    None,
                ),
            )
            .await
            .unwrap();
        let context = SessionStreamContext::new(session.clone(), channel_id, 0);
        let spec = SessionMeterSpec::new([SessionMeterDimension::required(
            MeterDirection::Output,
            BillingUnit::Bytes,
            1,
            1,
        )]);
        let meter = SessionStreamMeter::new(spec, SessionUsageHints::default(), context).unwrap();
        let upstream =
            futures_util::stream::iter([Ok::<_, reqwest::Error>(Bytes::from_static(b"paid"))]);
        let metered = meter_response_stream(upstream, meter, false);
        futures_util::pin_mut!(metered);

        assert!(
            tokio::time::timeout(Duration::from_millis(50), metered.next())
                .await
                .is_err(),
            "chargeable output must remain withheld while its commit is pending"
        );

        let voucher = handle.voucher_header(4).await.unwrap();
        session.process(&voucher).await.unwrap();
        let released = tokio::time::timeout(Duration::from_secs(1), metered.next())
            .await
            .expect("stream should resume after the commit")
            .expect("stream should yield the withheld chunk")
            .expect("upstream chunk should remain successful");

        assert_eq!(released, Bytes::from_static(b"paid"));
    }

    #[tokio::test]
    async fn delegated_stream_releases_each_chunk_after_its_voucher() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let mut operator_keypair = [0_u8; 64];
        operator_keypair[..32].copy_from_slice(signing_key.as_bytes());
        operator_keypair[32..].copy_from_slice(verifying_key.as_bytes());
        let operator: Arc<dyn SolanaSigner> =
            Arc::new(MemorySigner::from_bytes(&operator_keypair).unwrap());
        let config = SessionConfig {
            operator: operator.pubkey().to_string(),
            recipient: solana_pubkey::Pubkey::new_unique().to_string(),
            suggested_deposit: Some(1_000),
            currency: solana_pubkey::Pubkey::new_unique().to_string(),
            network: "localnet".to_string(),
            min_voucher_delta: 1,
            voucher_signer: VoucherSigner::Operator,
            ..SessionConfig::default()
        };
        let store: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::new());
        let session = Arc::new(
            SessionMpp::new_with_channel_store(
                config,
                "delegated-stream-test-secret",
                Arc::clone(&store),
            )
            .with_blockhash_cache(stream_test_blockhash_cache())
            .with_payment_channel_signer(Arc::clone(&operator)),
        );
        let challenge = session.challenge(None).unwrap();
        let channel_id = solana_pubkey::Pubkey::new_unique().to_string();
        store
            .put_channel(
                &channel_id,
                test_channel_state(
                    &channel_id,
                    1_000,
                    operator.pubkey().to_string(),
                    "operator",
                    &challenge.id,
                    solana_pubkey::Pubkey::new_unique().to_string(),
                    None,
                ),
            )
            .await
            .unwrap();
        let reservation = session
            .reserve_delegated_capacity(&channel_id, 1_000)
            .await
            .unwrap()
            .expect("session capacity should be available");
        let forward = SessionForward::delegated(
            session.clone(),
            channel_id.clone(),
            0,
            crate::server::metering::UptoSettlementPlan {
                metering: metering(vec![MeterDimension {
                    direction: MeterDirection::Output,
                    unit: BillingUnit::Tokens,
                    scale: 1,
                    period: None,
                    tiers: vec![
                        PriceTier {
                            up_to: None,
                            price_usd: 0.000001,
                            condition: Some(pay_types::metering::MeterCondition::ContextLength {
                                op: pay_types::metering::CompareOp::Lte,
                                value: 2,
                            }),
                            notes: None,
                            splits: vec![],
                        },
                        PriceTier {
                            up_to: None,
                            price_usd: 0.000005,
                            condition: Some(pay_types::metering::MeterCondition::ContextLength {
                                op: pay_types::metering::CompareOp::Gt,
                                value: 2,
                            }),
                            notes: None,
                            splits: vec![],
                        },
                    ],
                    meter: None,
                }]),
                variant_hint: None,
                request_properties: RequestProperties::default(),
                ceiling_usd: 0.001,
                inferred_usage: None,
            },
            10,
            reservation,
        );
        let meter = DelegatedSessionStreamMeter::from_forward(forward).unwrap();
        let release_second = Arc::new(tokio::sync::Notify::new());
        let upstream_release = Arc::clone(&release_second);
        let upstream = async_stream::stream! {
            yield Ok::<_, std::io::Error>(Bytes::from_static(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"one two three\"}}]}\n\n"
            ));
            upstream_release.notified().await;
            yield Ok::<_, std::io::Error>(Bytes::from_static(
                b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":3}}\n\n"
            ));
        };
        let metered = meter_delegated_response_stream(upstream, meter, true);
        futures_util::pin_mut!(metered);

        let first = tokio::time::timeout(Duration::from_secs(1), metered.next())
            .await
            .expect("first chunk must not wait for upstream EOF")
            .expect("stream should yield its first chunk")
            .expect("first chunk should remain successful");
        assert_eq!(
            first,
            Bytes::from_static(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"one two three\"}}]}\n\n"
            )
        );
        assert_eq!(session.committed_watermark(&channel_id), Some(3));

        assert!(
            tokio::time::timeout(Duration::from_millis(50), metered.next())
                .await
                .is_err(),
            "second chunk should still be waiting on the upstream"
        );
        release_second.notify_one();
        let second = tokio::time::timeout(Duration::from_secs(1), metered.next())
            .await
            .expect("second chunk should resume")
            .expect("stream should yield its second chunk")
            .expect("second chunk should remain successful");
        assert_eq!(
            second,
            Bytes::from_static(
                b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":3}}\n\n"
            )
        );
        assert_eq!(
            session.committed_watermark(&channel_id),
            Some(10),
            "retroactive repricing must collect the remaining authorization without failing the stream"
        );
        assert!(
            metered.next().await.is_none(),
            "a clamped usage-only reprice must complete cleanly"
        );
    }
}
