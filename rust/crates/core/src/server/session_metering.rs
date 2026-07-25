//! Integer metering primitives for payment-channel sessions.
//!
//! This module is intentionally pure: it has no HTTP, provider, clock, or
//! voucher dependencies. The proxy can feed it provider-specific observations
//! and use the returned base-unit deltas to decide when a new voucher is needed.

use super::metering::{RequestProperties, resolve_variant, select_price_tier};
use pay_types::metering::{BillingUnit, MeterDimension, MeterDirection, Metering};
use thiserror::Error;

const MICRO_USD_PER_USD: u128 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SessionMeteringError {
    #[error("session meter spec must contain at least one dimension")]
    EmptySpec,
    #[error("session metering does not support sku_tiers")]
    UnsupportedSkuTiers,
    #[error("metering config has no dimensions for session billing")]
    NoDimensions,
    #[error("dimension {direction:?}/{unit:?} has no tiers")]
    NoPriceTier {
        direction: MeterDirection,
        unit: BillingUnit,
    },
    #[error("price_usd must be finite and non-negative")]
    InvalidPrice,
    #[error("price_usd is not exactly representable as microUSD")]
    InexactMicroUsdPrice,
    #[error("dimension {direction:?}/{unit:?} has scale 0")]
    InvalidScale {
        direction: MeterDirection,
        unit: BillingUnit,
    },
    #[error("missing required observation for {direction:?}/{unit:?}")]
    MissingRequiredObservation {
        direction: MeterDirection,
        unit: BillingUnit,
    },
    #[error(
        "non-monotonic observation for {direction:?}/{unit:?}: current {current} < previous {previous}"
    )]
    NonMonotonicUsage {
        direction: MeterDirection,
        unit: BillingUnit,
        previous: u64,
        current: u64,
    },
    #[error("integer overflow while rating {context}")]
    Overflow { context: &'static str },
}

pub type Result<T> = std::result::Result<T, SessionMeteringError>;

#[derive(Debug, Clone, Copy, Default)]
pub struct SessionMeteringContext<'a> {
    pub variant_hint: Option<&'a str>,
    pub request_properties: Option<&'a RequestProperties>,
}

impl<'a> SessionMeteringContext<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_variant_hint(mut self, hint: &'a str) -> Self {
        self.variant_hint = Some(hint);
        self
    }

    pub fn with_request_properties(mut self, properties: &'a RequestProperties) -> Self {
        self.request_properties = Some(properties);
        self
    }
}

/// A session meter spec with integer prices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMeterSpec {
    pub dimensions: Vec<SessionMeterDimension>,
}

impl SessionMeterSpec {
    pub fn new(dimensions: impl Into<Vec<SessionMeterDimension>>) -> Self {
        Self {
            dimensions: dimensions.into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.dimensions.is_empty() {
            return Err(SessionMeteringError::EmptySpec);
        }

        for dimension in &self.dimensions {
            if dimension.scale == 0 {
                return Err(SessionMeteringError::InvalidScale {
                    direction: dimension.direction,
                    unit: dimension.unit,
                });
            }
        }

        Ok(())
    }
}

pub fn spec_from_metering(
    metering: &Metering,
    context: SessionMeteringContext<'_>,
) -> Result<SessionMeterSpec> {
    if !metering.sku_tiers.is_empty() {
        return Err(SessionMeteringError::UnsupportedSkuTiers);
    }

    let dimensions = select_dimensions(metering, context.variant_hint)?;
    let properties = context
        .request_properties
        .cloned()
        .unwrap_or_else(RequestProperties::default);

    let spec = SessionMeterSpec::new(
        dimensions
            .iter()
            .map(|dimension| dimension_from_metering(dimension, &properties))
            .collect::<Result<Vec<_>>>()?,
    );
    spec.validate()?;
    Ok(spec)
}

/// Price for one billable usage dimension.
///
/// `price_micro_usd` is charged per `scale` units. For example, Gemini-style
/// output pricing of $0.000005 per 2 tokens is represented as:
/// `scale = 2`, `price_micro_usd = 5`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMeterDimension {
    pub direction: MeterDirection,
    pub unit: BillingUnit,
    pub scale: u64,
    pub price_micro_usd: u64,
    pub required: bool,
}

impl SessionMeterDimension {
    pub fn required(
        direction: MeterDirection,
        unit: BillingUnit,
        scale: u64,
        price_micro_usd: u64,
    ) -> Self {
        Self {
            direction,
            unit,
            scale,
            price_micro_usd,
            required: true,
        }
    }

    pub fn optional(
        direction: MeterDirection,
        unit: BillingUnit,
        scale: u64,
        price_micro_usd: u64,
    ) -> Self {
        Self {
            direction,
            unit,
            scale,
            price_micro_usd,
            required: false,
        }
    }
}

/// A cumulative provider usage snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageObservation {
    samples: Vec<UsageSample>,
}

impl UsageObservation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, direction: MeterDirection, unit: BillingUnit, amount: u64) -> Self {
        self.set(direction, unit, amount);
        self
    }

    pub fn set(&mut self, direction: MeterDirection, unit: BillingUnit, amount: u64) {
        if let Some(sample) = self
            .samples
            .iter_mut()
            .find(|sample| sample.direction == direction && sample.unit == unit)
        {
            sample.amount = amount;
            return;
        }

        self.samples.push(UsageSample {
            direction,
            unit,
            amount,
        });
    }

    pub fn get(&self, direction: MeterDirection, unit: BillingUnit) -> Option<u64> {
        self.samples
            .iter()
            .find(|sample| sample.direction == direction && sample.unit == unit)
            .map(|sample| sample.amount)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageSample {
    pub direction: MeterDirection,
    pub unit: BillingUnit,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatedUsageDelta {
    pub previous_micro_usd: u64,
    pub current_micro_usd: u64,
    pub delta_micro_usd: u64,
    pub lines: Vec<RatedDimensionDelta>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatedDimensionDelta {
    pub direction: MeterDirection,
    pub unit: BillingUnit,
    pub previous_units: u64,
    pub current_units: u64,
    pub previous_micro_usd: u64,
    pub current_micro_usd: u64,
    pub delta_micro_usd: u64,
    pub scale: u64,
    pub price_micro_usd: u64,
}

/// Rate a cumulative usage observation by subtracting cumulative rated values.
///
/// This is the crucial behavior for streaming: a provider may emit usage in
/// small chunks, but rounding must happen against cumulative usage. If one token
/// arrives at a time and the meter bills per two tokens, the second token should
/// not cause another rounded charge.
pub fn rate_observation(
    spec: &SessionMeterSpec,
    previous: &UsageObservation,
    current: &UsageObservation,
) -> Result<RatedUsageDelta> {
    spec.validate()?;

    let mut previous_total = 0u64;
    let mut current_total = 0u64;
    let mut lines = Vec::with_capacity(spec.dimensions.len());

    for dimension in &spec.dimensions {
        let previous_units = previous
            .get(dimension.direction, dimension.unit)
            .unwrap_or_default();
        let current_units = match current.get(dimension.direction, dimension.unit) {
            Some(value) => value,
            None if dimension.required => {
                return Err(SessionMeteringError::MissingRequiredObservation {
                    direction: dimension.direction,
                    unit: dimension.unit,
                });
            }
            None => 0,
        };

        if current_units < previous_units {
            return Err(SessionMeteringError::NonMonotonicUsage {
                direction: dimension.direction,
                unit: dimension.unit,
                previous: previous_units,
                current: current_units,
            });
        }

        let previous_micro_usd = rate_units(previous_units, dimension)?;
        let current_micro_usd = rate_units(current_units, dimension)?;
        let delta_micro_usd = current_micro_usd.checked_sub(previous_micro_usd).ok_or(
            SessionMeteringError::Overflow {
                context: "dimension delta",
            },
        )?;

        previous_total = previous_total.checked_add(previous_micro_usd).ok_or(
            SessionMeteringError::Overflow {
                context: "previous total",
            },
        )?;
        current_total =
            current_total
                .checked_add(current_micro_usd)
                .ok_or(SessionMeteringError::Overflow {
                    context: "current total",
                })?;

        lines.push(RatedDimensionDelta {
            direction: dimension.direction,
            unit: dimension.unit,
            previous_units,
            current_units,
            previous_micro_usd,
            current_micro_usd,
            delta_micro_usd,
            scale: dimension.scale,
            price_micro_usd: dimension.price_micro_usd,
        });
    }

    let delta_micro_usd =
        current_total
            .checked_sub(previous_total)
            .ok_or(SessionMeteringError::Overflow {
                context: "total delta",
            })?;

    Ok(RatedUsageDelta {
        previous_micro_usd: previous_total,
        current_micro_usd: current_total,
        delta_micro_usd,
        lines,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateMode {
    Streaming,
    Final,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUsageGate {
    spec: SessionMeterSpec,
    settlement: StablecoinSettlement,
    baseline_base_units: u64,
    committed_base_units: u64,
    min_voucher_delta: u64,
    last_observation: UsageObservation,
}

impl SessionUsageGate {
    pub fn new(
        spec: SessionMeterSpec,
        settlement: StablecoinSettlement,
        baseline_base_units: u64,
        min_voucher_delta: u64,
    ) -> Result<Self> {
        spec.validate()?;
        Ok(Self {
            spec,
            settlement,
            baseline_base_units,
            committed_base_units: baseline_base_units,
            min_voucher_delta,
            last_observation: UsageObservation::new(),
        })
    }

    pub fn observe(
        &mut self,
        current: UsageObservation,
        mode: GateMode,
    ) -> Result<SessionGateDecision> {
        let rated = rate_voucher_delta(
            &self.spec,
            self.settlement,
            &self.last_observation,
            &current,
        )?;
        let total_rated = rate_voucher_delta(
            &self.spec,
            self.settlement,
            &UsageObservation::new(),
            &current,
        )?;
        self.last_observation = current;

        let target_cumulative = self
            .baseline_base_units
            .checked_add(total_rated.current_base_units)
            .ok_or(SessionMeteringError::Overflow {
                context: "gate target cumulative",
            })?;
        let outstanding = target_cumulative.saturating_sub(self.committed_base_units);
        let threshold = self.min_voucher_delta.max(1);

        if outstanding == 0 || (mode == GateMode::Streaming && outstanding < threshold) {
            return Ok(SessionGateDecision::Continue {
                rated,
                target_cumulative_base_units: target_cumulative,
                committed_base_units: self.committed_base_units,
                outstanding_base_units: outstanding,
            });
        }

        Ok(SessionGateDecision::VoucherRequired {
            rated,
            target_cumulative_base_units: target_cumulative,
            committed_base_units: self.committed_base_units,
            outstanding_base_units: outstanding,
        })
    }

    pub fn record_commit(&mut self, committed_base_units: u64) {
        self.committed_base_units = self.committed_base_units.max(committed_base_units);
    }

    pub fn committed_base_units(&self) -> u64 {
        self.committed_base_units
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionGateDecision {
    Continue {
        rated: RatedVoucherDelta,
        target_cumulative_base_units: u64,
        committed_base_units: u64,
        outstanding_base_units: u64,
    },
    VoucherRequired {
        rated: RatedVoucherDelta,
        target_cumulative_base_units: u64,
        committed_base_units: u64,
        outstanding_base_units: u64,
    },
}

impl SessionGateDecision {
    pub fn requires_voucher(&self) -> bool {
        matches!(self, Self::VoucherRequired { .. })
    }

    pub fn target_cumulative_base_units(&self) -> u64 {
        match self {
            Self::Continue {
                target_cumulative_base_units,
                ..
            }
            | Self::VoucherRequired {
                target_cumulative_base_units,
                ..
            } => *target_cumulative_base_units,
        }
    }

    pub fn outstanding_base_units(&self) -> u64 {
        match self {
            Self::Continue {
                outstanding_base_units,
                ..
            }
            | Self::VoucherRequired {
                outstanding_base_units,
                ..
            } => *outstanding_base_units,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StablecoinSettlement {
    pub decimals: u8,
}

impl StablecoinSettlement {
    pub const fn new(decimals: u8) -> Self {
        Self { decimals }
    }

    pub const fn usdc() -> Self {
        Self { decimals: 6 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatedVoucherDelta {
    pub usage: RatedUsageDelta,
    pub previous_base_units: u64,
    pub current_base_units: u64,
    pub delta_base_units: u64,
}

/// Rate usage and convert the cumulative totals into USD-stablecoin base units.
///
/// Conversion is cumulative for the same reason rating is cumulative: a token
/// with coarser precision should not overcharge every stream chunk.
pub fn rate_voucher_delta(
    spec: &SessionMeterSpec,
    settlement: StablecoinSettlement,
    previous: &UsageObservation,
    current: &UsageObservation,
) -> Result<RatedVoucherDelta> {
    let usage = rate_observation(spec, previous, current)?;
    let previous_base_units = micro_usd_to_base_units_ceil(usage.previous_micro_usd, settlement)?;
    let current_base_units = micro_usd_to_base_units_ceil(usage.current_micro_usd, settlement)?;
    let delta_base_units = current_base_units.checked_sub(previous_base_units).ok_or(
        SessionMeteringError::Overflow {
            context: "voucher base-unit delta",
        },
    )?;

    Ok(RatedVoucherDelta {
        usage,
        previous_base_units,
        current_base_units,
        delta_base_units,
    })
}

pub fn micro_usd_to_base_units_ceil(
    amount_micro_usd: u64,
    settlement: StablecoinSettlement,
) -> Result<u64> {
    let multiplier =
        10u128
            .checked_pow(settlement.decimals as u32)
            .ok_or(SessionMeteringError::Overflow {
                context: "settlement multiplier",
            })?;
    let numerator = (amount_micro_usd as u128).checked_mul(multiplier).ok_or(
        SessionMeteringError::Overflow {
            context: "microUSD to base-unit numerator",
        },
    )?;
    let base_units = ceil_div(numerator, MICRO_USD_PER_USD)?;
    u64::try_from(base_units).map_err(|_| SessionMeteringError::Overflow {
        context: "base-unit conversion",
    })
}

fn rate_units(units: u64, dimension: &SessionMeterDimension) -> Result<u64> {
    if dimension.scale == 0 {
        return Err(SessionMeteringError::InvalidScale {
            direction: dimension.direction,
            unit: dimension.unit,
        });
    }

    let billable_blocks = ceil_div(units as u128, dimension.scale as u128)?;
    let amount = billable_blocks
        .checked_mul(dimension.price_micro_usd as u128)
        .ok_or(SessionMeteringError::Overflow {
            context: "dimension rating",
        })?;
    u64::try_from(amount).map_err(|_| SessionMeteringError::Overflow {
        context: "dimension rating",
    })
}

fn select_dimensions<'a>(
    metering: &'a Metering,
    variant_hint: Option<&str>,
) -> Result<&'a [MeterDimension]> {
    if !metering.variants.is_empty() {
        if let Some(variant) = resolve_variant(&metering.variants, variant_hint) {
            return Ok(&variant.dimensions);
        }

        if !metering.dimensions.is_empty() {
            return Ok(&metering.dimensions);
        }

        return metering
            .variants
            .first()
            .map(|variant| variant.dimensions.as_slice())
            .ok_or(SessionMeteringError::NoDimensions);
    }

    if metering.dimensions.is_empty() {
        return Err(SessionMeteringError::NoDimensions);
    }

    Ok(&metering.dimensions)
}

fn dimension_from_metering(
    dimension: &MeterDimension,
    properties: &RequestProperties,
) -> Result<SessionMeterDimension> {
    if dimension.scale == 0 {
        return Err(SessionMeteringError::InvalidScale {
            direction: dimension.direction,
            unit: dimension.unit,
        });
    }

    let tier =
        select_price_tier(dimension, properties).ok_or(SessionMeteringError::NoPriceTier {
            direction: dimension.direction,
            unit: dimension.unit,
        })?;
    let price_micro_usd = price_usd_to_micro_usd(tier.price_usd)?;
    Ok(SessionMeterDimension::required(
        dimension.direction,
        dimension.unit,
        dimension.scale,
        price_micro_usd,
    ))
}

fn price_usd_to_micro_usd(price_usd: f64) -> Result<u64> {
    if !price_usd.is_finite() || price_usd < 0.0 {
        return Err(SessionMeteringError::InvalidPrice);
    }

    let micro_usd = price_usd * MICRO_USD_PER_USD as f64;
    let rounded = micro_usd.round();
    if (micro_usd - rounded).abs() > 1e-6 {
        return Err(SessionMeteringError::InexactMicroUsdPrice);
    }
    if rounded > u64::MAX as f64 {
        return Err(SessionMeteringError::Overflow {
            context: "price_usd conversion",
        });
    }
    Ok(rounded as u64)
}

fn ceil_div(numerator: u128, denominator: u128) -> Result<u128> {
    if denominator == 0 {
        return Err(SessionMeteringError::Overflow {
            context: "division by zero",
        });
    }
    numerator
        .checked_add(denominator - 1)
        .map(|value| value / denominator)
        .ok_or(SessionMeteringError::Overflow {
            context: "ceil division",
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pay_types::metering::PriceTier;

    fn gemini_spec() -> SessionMeterSpec {
        SessionMeterSpec::new([
            SessionMeterDimension::required(MeterDirection::Input, BillingUnit::Tokens, 10, 3),
            SessionMeterDimension::required(MeterDirection::Output, BillingUnit::Tokens, 2, 5),
        ])
    }

    fn one_tier_dimension(
        direction: MeterDirection,
        unit: BillingUnit,
        scale: u64,
        price_usd: f64,
    ) -> MeterDimension {
        MeterDimension {
            direction,
            unit,
            scale,
            period: None,
            tiers: vec![PriceTier {
                up_to: None,
                price_usd,
                condition: None,
                notes: None,
                splits: vec![],
            }],
            meter: None,
        }
    }

    fn metering_with_dimensions(dimensions: Vec<MeterDimension>) -> Metering {
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

    #[test]
    fn adapter_converts_flat_agent_gateway_request_pricing() {
        let metering = metering_with_dimensions(vec![one_tier_dimension(
            MeterDirection::Usage,
            BillingUnit::Requests,
            1,
            0.01,
        )]);

        let spec = spec_from_metering(&metering, SessionMeteringContext::new()).unwrap();

        assert_eq!(spec.dimensions[0].price_micro_usd, 10_000);
        let current = UsageObservation::new().with(MeterDirection::Usage, BillingUnit::Requests, 1);
        let rated = rate_voucher_delta(
            &spec,
            StablecoinSettlement::usdc(),
            &UsageObservation::new(),
            &current,
        )
        .unwrap();
        assert_eq!(rated.current_base_units, 10_000);
    }

    #[test]
    fn adapter_loads_agent_gateway_gemini_yaml_shape() {
        let api: pay_types::metering::ApiSpec = serde_yml::from_str(
            r#"
name: generativelanguage
subdomain: generativelanguage
title: "Generative Language API"
description: "Gemini API"
category: ai_ml
version: v1beta
routing:
  type: proxy
  url: https://generativelanguage.googleapis.com/
endpoints:
  - method: POST
    path: "v1beta/models/{modelsId}:streamGenerateContent"
    description: "Stream generated content."
    metering:
      variants:
        - param: model
          value: gemini-2.5-flash
          dimensions:
            - direction: input
              unit: quota_units
              scale: 1
              tiers:
                - price_usd: 0.000003
            - direction: output
              unit: quota_units
              scale: 1
              tiers:
                - price_usd: 0.000005
"#,
        )
        .unwrap();
        let metering = api.endpoints[0].metering.as_ref().unwrap();

        let spec = spec_from_metering(
            metering,
            SessionMeteringContext::new()
                .with_variant_hint("v1beta/models/gemini-2.5-flash:streamGenerateContent"),
        )
        .unwrap();

        assert_eq!(spec.dimensions.len(), 2);
        assert_eq!(spec.dimensions[0].unit, BillingUnit::QuotaUnits);
        assert_eq!(spec.dimensions[0].price_micro_usd, 3);
        assert_eq!(spec.dimensions[1].price_micro_usd, 5);
    }

    #[test]
    fn adapter_selects_variant_by_hint() {
        let metering = Metering {
            dimensions: vec![],
            variants: vec![
                pay_types::metering::MeterVariant {
                    param: "model".to_string(),
                    value: "gemini-2.5-pro".to_string(),
                    description: None,
                    dimensions: vec![one_tier_dimension(
                        MeterDirection::Output,
                        BillingUnit::Tokens,
                        1,
                        0.000010,
                    )],
                },
                pay_types::metering::MeterVariant {
                    param: "model".to_string(),
                    value: "gemini-2.5-flash".to_string(),
                    description: None,
                    dimensions: vec![one_tier_dimension(
                        MeterDirection::Output,
                        BillingUnit::QuotaUnits,
                        1,
                        0.000005,
                    )],
                },
            ],
            sku_tiers: vec![],
            splits: vec![],
            schemes: None,
            min_usd: None,
            upto: None,
        };

        let spec = spec_from_metering(
            &metering,
            SessionMeteringContext::new().with_variant_hint("models/gemini-2.5-flash"),
        )
        .unwrap();

        assert_eq!(spec.dimensions[0].unit, BillingUnit::QuotaUnits);
        assert_eq!(spec.dimensions[0].price_micro_usd, 5);
    }

    #[test]
    fn adapter_uses_explicit_default_variant_for_unknown_hint() {
        let metering = Metering {
            dimensions: vec![],
            variants: vec![
                pay_types::metering::MeterVariant {
                    param: "model".to_string(),
                    value: "qwen-turbo".to_string(),
                    description: None,
                    dimensions: vec![one_tier_dimension(
                        MeterDirection::Usage,
                        BillingUnit::Requests,
                        1,
                        0.001,
                    )],
                },
                pay_types::metering::MeterVariant {
                    param: "model".to_string(),
                    value: "default".to_string(),
                    description: None,
                    dimensions: vec![one_tier_dimension(
                        MeterDirection::Usage,
                        BillingUnit::Requests,
                        1,
                        0.100,
                    )],
                },
            ],
            sku_tiers: vec![],
            splits: vec![],
            schemes: None,
            min_usd: None,
            upto: None,
        };

        let spec = spec_from_metering(
            &metering,
            SessionMeteringContext::new().with_variant_hint("missing"),
        )
        .unwrap();

        assert_eq!(spec.dimensions[0].price_micro_usd, 100_000);
    }

    #[test]
    fn adapter_evaluates_conditional_tiers() {
        let metering = metering_with_dimensions(vec![MeterDimension {
            direction: MeterDirection::Input,
            unit: BillingUnit::Tokens,
            scale: 1,
            period: None,
            tiers: vec![
                PriceTier {
                    up_to: None,
                    price_usd: 0.000002,
                    condition: Some(pay_types::metering::MeterCondition::ContextLength {
                        op: pay_types::metering::CompareOp::Lte,
                        value: 200_000,
                    }),
                    notes: None,
                    splits: vec![],
                },
                PriceTier {
                    up_to: None,
                    price_usd: 0.000004,
                    condition: Some(pay_types::metering::MeterCondition::ContextLength {
                        op: pay_types::metering::CompareOp::Gt,
                        value: 200_000,
                    }),
                    notes: None,
                    splits: vec![],
                },
            ],
            meter: None,
        }]);
        let props = RequestProperties {
            context_length: Some(250_000),
            ..Default::default()
        };

        let spec = spec_from_metering(
            &metering,
            SessionMeteringContext::new().with_request_properties(&props),
        )
        .unwrap();

        assert_eq!(spec.dimensions[0].price_micro_usd, 4);
    }

    #[test]
    fn adapter_uses_first_non_free_tier_for_volume_tiers() {
        let metering = metering_with_dimensions(vec![MeterDimension {
            direction: MeterDirection::Usage,
            unit: BillingUnit::Characters,
            scale: 1_000_000,
            period: None,
            tiers: vec![
                PriceTier {
                    up_to: Some(1_000_000),
                    price_usd: 0.0,
                    condition: None,
                    notes: None,
                    splits: vec![],
                },
                PriceTier {
                    up_to: None,
                    price_usd: 30.0,
                    condition: None,
                    notes: None,
                    splits: vec![],
                },
            ],
            meter: None,
        }]);

        let spec = spec_from_metering(&metering, SessionMeteringContext::new()).unwrap();

        assert_eq!(spec.dimensions[0].price_micro_usd, 30_000_000);
    }

    #[test]
    fn adapter_rejects_sub_micro_usd_prices() {
        let metering = metering_with_dimensions(vec![one_tier_dimension(
            MeterDirection::Input,
            BillingUnit::Tokens,
            1,
            0.0000001,
        )]);

        let err = spec_from_metering(&metering, SessionMeteringContext::new()).unwrap_err();

        assert!(matches!(err, SessionMeteringError::InexactMicroUsdPrice));
    }

    #[test]
    fn adapter_rejects_sku_tiers_for_session_hot_path() {
        let metering = Metering {
            dimensions: vec![],
            variants: vec![],
            sku_tiers: vec![pay_types::metering::SkuTier {
                sku: "places".to_string(),
                level: pay_types::metering::SkuLevel::Essentials,
            }],
            splits: vec![],
            schemes: None,
            min_usd: None,
            upto: None,
        };

        let err = spec_from_metering(&metering, SessionMeteringContext::new()).unwrap_err();

        assert!(matches!(err, SessionMeteringError::UnsupportedSkuTiers));
    }

    #[test]
    fn rates_gemini_style_dimensions_in_micro_usd() {
        let current = UsageObservation::new()
            .with(MeterDirection::Input, BillingUnit::Tokens, 27)
            .with(MeterDirection::Output, BillingUnit::Tokens, 448);

        let rated = rate_observation(&gemini_spec(), &UsageObservation::new(), &current).unwrap();

        assert_eq!(rated.current_micro_usd, 1129);
        assert_eq!(rated.delta_micro_usd, 1129);
        assert_eq!(rated.lines[0].current_micro_usd, 9);
        assert_eq!(rated.lines[1].current_micro_usd, 1120);
    }

    #[test]
    fn rates_cumulative_snapshots_without_per_chunk_over_rounding() {
        let spec = SessionMeterSpec::new([SessionMeterDimension::required(
            MeterDirection::Output,
            BillingUnit::Tokens,
            2,
            5,
        )]);

        let zero = UsageObservation::new();
        let one = UsageObservation::new().with(MeterDirection::Output, BillingUnit::Tokens, 1);
        let two = UsageObservation::new().with(MeterDirection::Output, BillingUnit::Tokens, 2);
        let three = UsageObservation::new().with(MeterDirection::Output, BillingUnit::Tokens, 3);

        assert_eq!(
            rate_observation(&spec, &zero, &one)
                .unwrap()
                .delta_micro_usd,
            5
        );
        assert_eq!(
            rate_observation(&spec, &one, &two).unwrap().delta_micro_usd,
            0
        );
        assert_eq!(
            rate_observation(&spec, &two, &three)
                .unwrap()
                .delta_micro_usd,
            5
        );
    }

    #[test]
    fn rejects_non_monotonic_observations() {
        let spec = SessionMeterSpec::new([SessionMeterDimension::required(
            MeterDirection::Output,
            BillingUnit::Tokens,
            1,
            1,
        )]);
        let previous = UsageObservation::new().with(MeterDirection::Output, BillingUnit::Tokens, 2);
        let current = UsageObservation::new().with(MeterDirection::Output, BillingUnit::Tokens, 1);

        let err = rate_observation(&spec, &previous, &current).unwrap_err();

        assert!(matches!(
            err,
            SessionMeteringError::NonMonotonicUsage {
                previous: 2,
                current: 1,
                ..
            }
        ));
    }

    #[test]
    fn rejects_missing_required_observations() {
        let err = rate_observation(
            &gemini_spec(),
            &UsageObservation::new(),
            &UsageObservation::new(),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            SessionMeteringError::MissingRequiredObservation {
                direction: MeterDirection::Input,
                unit: BillingUnit::Tokens
            }
        ));
    }

    #[test]
    fn treats_missing_optional_observations_as_zero() {
        let spec = SessionMeterSpec::new([SessionMeterDimension::optional(
            MeterDirection::Output,
            BillingUnit::Tokens,
            1,
            1,
        )]);

        let rated =
            rate_observation(&spec, &UsageObservation::new(), &UsageObservation::new()).unwrap();

        assert_eq!(rated.current_micro_usd, 0);
        assert_eq!(rated.delta_micro_usd, 0);
    }

    #[test]
    fn converts_micro_usd_to_usdc_base_units() {
        assert_eq!(
            micro_usd_to_base_units_ceil(487, StablecoinSettlement::usdc()).unwrap(),
            487
        );
    }

    #[test]
    fn converts_cumulatively_for_coarser_assets() {
        let spec = SessionMeterSpec::new([SessionMeterDimension::required(
            MeterDirection::Usage,
            BillingUnit::Requests,
            1,
            1,
        )]);
        let previous =
            UsageObservation::new().with(MeterDirection::Usage, BillingUnit::Requests, 1);
        let current = UsageObservation::new().with(MeterDirection::Usage, BillingUnit::Requests, 2);

        let rated =
            rate_voucher_delta(&spec, StablecoinSettlement::new(2), &previous, &current).unwrap();

        assert_eq!(rated.previous_base_units, 1);
        assert_eq!(rated.current_base_units, 1);
        assert_eq!(rated.delta_base_units, 0);
    }

    #[test]
    fn rejects_empty_specs_and_zero_scales() {
        let err = SessionMeterSpec::new([]).validate().unwrap_err();
        assert!(matches!(err, SessionMeteringError::EmptySpec));

        let spec = SessionMeterSpec::new([SessionMeterDimension::required(
            MeterDirection::Usage,
            BillingUnit::Requests,
            0,
            1,
        )]);
        let err = spec.validate().unwrap_err();
        assert!(matches!(err, SessionMeteringError::InvalidScale { .. }));
    }

    #[test]
    fn gate_requires_voucher_when_streaming_outstanding_reaches_min_delta() {
        let mut gate =
            SessionUsageGate::new(gemini_spec(), StablecoinSettlement::usdc(), 100, 10).unwrap();
        let current = UsageObservation::new()
            .with(MeterDirection::Input, BillingUnit::Tokens, 27)
            .with(MeterDirection::Output, BillingUnit::Tokens, 2);

        let decision = gate.observe(current, GateMode::Streaming).unwrap();

        assert!(decision.requires_voucher());
        assert_eq!(decision.target_cumulative_base_units(), 114);
        assert_eq!(decision.outstanding_base_units(), 14);
    }

    #[test]
    fn gate_allows_small_streaming_delta_but_requires_it_on_final() {
        let spec = SessionMeterSpec::new([SessionMeterDimension::required(
            MeterDirection::Usage,
            BillingUnit::Requests,
            1,
            5,
        )]);
        let mut gate = SessionUsageGate::new(spec, StablecoinSettlement::usdc(), 0, 10).unwrap();
        let current = UsageObservation::new().with(MeterDirection::Usage, BillingUnit::Requests, 1);

        let streaming = gate.observe(current.clone(), GateMode::Streaming).unwrap();
        let final_decision = gate.observe(current, GateMode::Final).unwrap();

        assert!(!streaming.requires_voucher());
        assert!(final_decision.requires_voucher());
        assert_eq!(final_decision.outstanding_base_units(), 5);
    }

    #[test]
    fn gate_records_commit_and_continues_for_same_usage() {
        let mut gate =
            SessionUsageGate::new(gemini_spec(), StablecoinSettlement::usdc(), 100, 1).unwrap();
        let current = UsageObservation::new()
            .with(MeterDirection::Input, BillingUnit::Tokens, 27)
            .with(MeterDirection::Output, BillingUnit::Tokens, 448);

        let first = gate.observe(current.clone(), GateMode::Streaming).unwrap();
        assert!(first.requires_voucher());
        gate.record_commit(first.target_cumulative_base_units());
        let second = gate.observe(current, GateMode::Streaming).unwrap();

        assert!(!second.requires_voucher());
        assert_eq!(second.outstanding_base_units(), 0);
    }
}
