use std::collections::HashMap;
use std::time::Duration;

use base64::Engine as _;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{MeterProviderBuilder, PeriodicReader, SdkMeterProvider};
use opentelemetry_semantic_conventions::SCHEMA_URL;
use opentelemetry_semantic_conventions::attribute::SERVICE_VERSION;
use tracing_opentelemetry::MetricsLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub struct TelemetryGuard {
    meter_provider: Option<SdkMeterProvider>,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.meter_provider.take()
            && let Err(error) = provider.shutdown()
        {
            eprintln!("OTLP metric shutdown failed: {error:?}");
        }
    }
}

#[derive(Debug, Default)]
pub struct SettleSessionsMetrics {
    pub scheme: &'static str,
    pub outcome: &'static str,
    pub channels_scanned: usize,
    pub watermark_planned: usize,
    pub idle_close_planned: usize,
    pub idle_closed: usize,
    pub finalized: usize,
    pub transactions: usize,
    pub skipped: usize,
    pub failures: usize,
    pub opened_zero_settlements: usize,
    pub unsealed: usize,
    pub rent_unclaimed: usize,
    pub stablecoin_settled_base_units: u64,
    pub stablecoin_undistributed_base_units: u64,
    pub stablecoin_distributed_base_units: u64,
    pub stablecoin_unsettled_base_units: u64,
    pub redis_chain_mismatches: usize,
    pub lease_contended: usize,
    pub duration_seconds: f64,
    pub claims: usize,
    pub payouts: usize,
    pub closes_finalized: usize,
    pub reclaims: usize,
}

pub fn init(service_name: &str) -> TelemetryGuard {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,pay_worker=info"));

    match direct_otlp_config() {
        Ok(Some(config)) => match init_otlp(service_name, &config, filter.clone()) {
            Ok(meter_provider) => TelemetryGuard {
                meter_provider: Some(meter_provider),
            },
            Err(error) => {
                init_json(filter);
                tracing::warn!(%error, "direct OTLP metrics unavailable");
                TelemetryGuard {
                    meter_provider: None,
                }
            }
        },
        Ok(None) => {
            init_json(filter);
            TelemetryGuard {
                meter_provider: None,
            }
        }
        Err(error) => {
            init_json(filter);
            tracing::warn!(%error, "direct OTLP metrics are misconfigured");
            TelemetryGuard {
                meter_provider: None,
            }
        }
    }
}

pub fn record_settle_sessions(metrics: &SettleSessionsMetrics) {
    tracing::info!(
        gauge.pay_jobs_settle_channels_runs = 1_u64,
        gauge.pay_jobs_settle_channels_duration_seconds = metrics.duration_seconds,
        gauge.pay_jobs_settle_channels_channels_scanned = metrics.channels_scanned as u64,
        gauge.pay_jobs_settle_channels_transactions = metrics.transactions as u64,
        gauge.pay_jobs_settle_channels_failures = metrics.failures as u64,
        gauge.pay_jobs_settle_channels_claim_channels = metrics.claims as u64,
        gauge.pay_jobs_settle_channels_payout_channels = metrics.payouts as u64,
        gauge.pay_jobs_settle_channels_close_channels = metrics.closes_finalized as u64,
        gauge.pay_jobs_settle_channels_reclaim_channels = metrics.reclaims as u64,
        scheme = metrics.scheme,
        outcome = metrics.outcome,
        metric_group = "pay_jobs_settle_channels",
        "payment-channel lifecycle metrics",
    );

    // Preserve the existing session instruments while dashboards migrate to
    // the scheme-labelled, channel-generic metrics above.
    if metrics.scheme != "mpp/session" {
        return;
    }
    tracing::info!(
        gauge.pay_jobs_settle_sessions_runs = 1_u64,
        gauge.pay_jobs_settle_sessions_duration_seconds = metrics.duration_seconds,
        gauge.pay_jobs_settle_sessions_channels_scanned = metrics.channels_scanned as u64,
        gauge.pay_jobs_settle_sessions_watermark_planned = metrics.watermark_planned as u64,
        gauge.pay_jobs_settle_sessions_idle_close_planned = metrics.idle_close_planned as u64,
        gauge.pay_jobs_settle_sessions_idle_closed = metrics.idle_closed as u64,
        gauge.pay_jobs_settle_sessions_finalized = metrics.finalized as u64,
        gauge.pay_jobs_settle_sessions_transactions = metrics.transactions as u64,
        gauge.pay_jobs_settle_sessions_skipped = metrics.skipped as u64,
        gauge.pay_jobs_settle_sessions_failures = metrics.failures as u64,
        gauge.pay_jobs_settle_sessions_opened_zero_settlements =
            metrics.opened_zero_settlements as u64,
        gauge.pay_jobs_settle_sessions_unsealed = metrics.unsealed as u64,
        gauge.pay_jobs_settle_sessions_rent_unclaimed = metrics.rent_unclaimed as u64,
        gauge.pay_jobs_settle_sessions_stablecoin_settled_base_units =
            metrics.stablecoin_settled_base_units,
        gauge.pay_jobs_settle_sessions_stablecoin_undistributed_base_units =
            metrics.stablecoin_undistributed_base_units,
        gauge.pay_jobs_settle_sessions_stablecoin_distributed_base_units =
            metrics.stablecoin_distributed_base_units,
        gauge.pay_jobs_settle_sessions_stablecoin_unsettled_base_units =
            metrics.stablecoin_unsettled_base_units,
        gauge.pay_jobs_settle_sessions_redis_chain_mismatches =
            metrics.redis_chain_mismatches as u64,
        gauge.pay_jobs_settle_sessions_lease_contended = metrics.lease_contended as u64,
        outcome = metrics.outcome,
        metric_group = "pay_jobs_settle_sessions",
        "settle-sessions metrics",
    );
}

/// Record the authoritative on-chain settled watermark for one supported
/// stablecoin channel.
///
/// The channel id is intentionally a metric attribute: Grafana joins this
/// worker-side watermark to the proxy's latest accepted voucher watermark.
pub fn record_settle_sessions_channel_settled(channel_id: &str, settled_base_units: u64) {
    record_channel_settled("mpp/session", channel_id, settled_base_units);
}

pub fn record_channel_settled(scheme: &str, channel_id: &str, settled_base_units: u64) {
    tracing::info!(
        gauge.pay_jobs_settle_channels_channel_settled_base_units = settled_base_units,
        channel_id,
        scheme,
        metric_group = "pay_jobs_settle_channels",
        "payment-channel watermark",
    );
    if scheme != "mpp/session" {
        return;
    }
    tracing::info!(
        gauge.pay_jobs_settle_sessions_channel_settled_base_units = settled_base_units,
        channel_id,
        metric_group = "pay_jobs_settle_sessions",
        "settle-sessions channel watermark",
    );
}

/// Record the authoritative on-chain distributed payout watermark for one
/// supported stablecoin channel.
pub fn record_settle_sessions_channel_distributed(channel_id: &str, distributed_base_units: u64) {
    record_channel_distributed("mpp/session", channel_id, distributed_base_units);
}

pub fn record_channel_distributed(scheme: &str, channel_id: &str, distributed_base_units: u64) {
    tracing::info!(
        gauge.pay_jobs_settle_channels_channel_distributed_base_units = distributed_base_units,
        channel_id,
        scheme,
        metric_group = "pay_jobs_settle_channels",
        "payment-channel payout watermark",
    );
    if scheme != "mpp/session" {
        return;
    }
    tracing::info!(
        gauge.pay_jobs_settle_sessions_channel_distributed_base_units = distributed_base_units,
        channel_id,
        metric_group = "pay_jobs_settle_sessions",
        "settle-sessions channel payout watermark",
    );
}

/// Record whether a channel still holds escrowed funds on-chain.
pub fn record_settle_sessions_channel_escrow_active(channel_id: &str, active: bool) {
    record_channel_escrow_active("mpp/session", channel_id, active);
}

pub fn record_channel_escrow_active(scheme: &str, channel_id: &str, active: bool) {
    tracing::info!(
        gauge.pay_jobs_settle_channels_channel_escrow_active = u64::from(active),
        channel_id,
        scheme,
        metric_group = "pay_jobs_settle_channels",
        "payment-channel escrow state",
    );
    if scheme != "mpp/session" {
        return;
    }
    tracing::info!(
        gauge.pay_jobs_settle_sessions_channel_escrow_active = u64::from(active),
        channel_id,
        metric_group = "pay_jobs_settle_sessions",
        "settle-sessions channel escrow state",
    );
}

#[derive(Debug, PartialEq, Eq)]
struct DirectOtlpConfig {
    metrics_endpoint: String,
    authorization: String,
}

fn direct_otlp_config() -> Result<Option<DirectOtlpConfig>, String> {
    let endpoint = optional_env("GRAFANA_CLOUD_OTLP_ENDPOINT");
    let username = optional_env("GRAFANA_CLOUD_OTLP_USERNAME");
    let token = optional_env("GRAFANA_CLOUD_OTLP_TOKEN");

    if endpoint.is_none() && username.is_none() && token.is_none() {
        return Ok(None);
    }

    let endpoint = endpoint.ok_or_else(|| {
        "GRAFANA_CLOUD_OTLP_ENDPOINT is required when OTLP is enabled".to_string()
    })?;
    let username = username.ok_or_else(|| {
        "GRAFANA_CLOUD_OTLP_USERNAME is required when OTLP is enabled".to_string()
    })?;
    let token = token
        .ok_or_else(|| "GRAFANA_CLOUD_OTLP_TOKEN is required when OTLP is enabled".to_string())?;
    let credentials =
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{token}"));

    Ok(Some(DirectOtlpConfig {
        metrics_endpoint: metrics_endpoint(&endpoint),
        authorization: format!("Basic {credentials}"),
    }))
}

fn init_otlp(
    service_name: &str,
    config: &DirectOtlpConfig,
    filter: EnvFilter,
) -> Result<SdkMeterProvider, String> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(config.metrics_endpoint.clone())
        .with_headers(HashMap::from([(
            "Authorization".to_string(),
            config.authorization.clone(),
        )]))
        .build()
        .map_err(|error| format!("failed to create OTLP metric exporter: {error}"))?;
    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(15))
        .build();
    let meter_provider = MeterProviderBuilder::default()
        .with_resource(resource(service_name))
        .with_reader(reader)
        .build();
    global::set_meter_provider(meter_provider.clone());

    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(false)
                .with_span_list(false),
        )
        .with(MetricsLayer::new(meter_provider.clone()))
        .init();

    Ok(meter_provider)
}

fn resource(service_name: &str) -> Resource {
    let service_name = optional_env("OTEL_SERVICE_NAME")
        .or_else(|| optional_env("CLOUD_RUN_JOB"))
        .unwrap_or_else(|| service_name.to_string());
    let deployment = optional_env("DEPLOYMENT_ENVIRONMENT").unwrap_or_else(|| "local".to_string());
    let instance_id = service_instance_id();
    Resource::builder()
        .with_service_name(service_name)
        .with_schema_url(
            [
                KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
                KeyValue::new("service.instance.id", instance_id),
                KeyValue::new("service.namespace", "pay.sh"),
                KeyValue::new("deployment.environment.name", deployment),
            ],
            SCHEMA_URL,
        )
        .build()
}

fn service_instance_id() -> String {
    if let Some(execution) = optional_env("CLOUD_RUN_EXECUTION") {
        let task_index = optional_env("CLOUD_RUN_TASK_INDEX").unwrap_or_else(|| "0".to_string());
        let task_attempt =
            optional_env("CLOUD_RUN_TASK_ATTEMPT").unwrap_or_else(|| "0".to_string());
        return format!("{execution}:{task_index}:{task_attempt}");
    }

    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("local:{}:{started_at}", std::process::id())
}

fn init_json(filter: EnvFilter) {
    tracing_subscriber::fmt()
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .with_env_filter(filter)
        .init();
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn metrics_endpoint(endpoint: &str) -> String {
    let endpoint = endpoint.trim().trim_end_matches('/');
    if endpoint.ends_with("/v1/metrics") {
        endpoint.to_string()
    } else {
        format!("{endpoint}/v1/metrics")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_endpoint_appends_signal_path() {
        assert_eq!(
            metrics_endpoint("https://otlp.example.com/otlp"),
            "https://otlp.example.com/otlp/v1/metrics"
        );
    }

    #[test]
    fn metrics_endpoint_preserves_existing_signal_path() {
        assert_eq!(
            metrics_endpoint("https://otlp.example.com/otlp/v1/metrics/"),
            "https://otlp.example.com/otlp/v1/metrics"
        );
    }
}
