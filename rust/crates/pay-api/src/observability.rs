use std::time::Duration;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{MeterProviderBuilder, PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use opentelemetry_semantic_conventions::SCHEMA_URL;
use opentelemetry_semantic_conventions::attribute::SERVICE_VERSION;
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpEndpoints {
    pub traces: String,
    pub metrics: String,
}

pub struct LoggingGuard {
    _otel: Option<OtelGuard>,
}

pub struct OtelGuard {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(error) = self.tracer_provider.shutdown() {
            tracing::warn!(?error, "OTLP trace shutdown failed");
        }
        if let Err(error) = self.meter_provider.shutdown() {
            tracing::warn!(?error, "OTLP metric shutdown failed");
        }
    }
}

pub fn init() -> LoggingGuard {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let sidecar = std::env::var("PAY_API_OTLP_SIDECAR")
        .ok()
        .filter(|value| !value.trim().is_empty());

    if let Some(sidecar) = sidecar {
        match init_otlp(&sidecar, filter.clone()) {
            Ok(guard) => return LoggingGuard { _otel: Some(guard) },
            Err(error) => {
                init_fmt(filter);
                tracing::warn!(%error, "falling back to structured stdout logging");
                return LoggingGuard { _otel: None };
            }
        }
    }

    init_fmt(filter);
    LoggingGuard { _otel: None }
}

pub fn init_otlp(sidecar: &str, filter: EnvFilter) -> Result<OtelGuard, String> {
    let endpoints = endpoints_from_sidecar(sidecar);
    let tracer_provider = init_tracer_provider(&endpoints)?;
    let meter_provider = init_meter_provider(&endpoints)?;
    let tracer = tracer_provider.tracer("pay-api");

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .with(MetricsLayer::new(meter_provider.clone()))
        .with(OpenTelemetryLayer::new(tracer))
        .init();

    Ok(OtelGuard {
        tracer_provider,
        meter_provider,
    })
}

pub fn endpoints_from_sidecar(sidecar: &str) -> OtlpEndpoints {
    let base = normalize_sidecar_base(sidecar);
    OtlpEndpoints {
        traces: format!("{base}/v1/traces"),
        metrics: format!("{base}/v1/metrics"),
    }
}

fn normalize_sidecar_base(sidecar: &str) -> String {
    let trimmed = sidecar.trim().trim_end_matches('/');
    if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    }
}

fn init_fmt(filter: EnvFilter) {
    let json = std::env::var("LOG_FORMAT")
        .map(|value| value.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    if json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

fn init_tracer_provider(endpoints: &OtlpEndpoints) -> Result<SdkTracerProvider, String> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(endpoints.traces.clone())
        .build()
        .map_err(|error| format!("failed to create OTLP span exporter: {error}"))?;

    let provider = SdkTracerProvider::builder()
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            1.0,
        ))))
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource())
        .with_batch_exporter(exporter)
        .build();

    global::set_tracer_provider(provider.clone());
    Ok(provider)
}

fn init_meter_provider(endpoints: &OtlpEndpoints) -> Result<SdkMeterProvider, String> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(endpoints.metrics.clone())
        .build()
        .map_err(|error| format!("failed to create OTLP metric exporter: {error}"))?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(15))
        .build();

    let provider = MeterProviderBuilder::default()
        .with_resource(resource())
        .with_reader(reader)
        .build();

    global::set_meter_provider(provider.clone());
    Ok(provider)
}

fn resource() -> Resource {
    let service_name = std::env::var("K_SERVICE").unwrap_or_else(|_| "pay-api".to_string());
    let deployment = std::env::var("PAY_ENV").unwrap_or_else(|_| {
        std::env::var("K_REVISION")
            .map(|_| "cloud-run".to_string())
            .unwrap_or_else(|_| "local".to_string())
    });

    Resource::builder()
        .with_service_name(service_name)
        .with_schema_url(
            [
                KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
                KeyValue::new("deployment.environment", deployment),
            ],
            SCHEMA_URL,
        )
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_from_host_port_use_http_otlp_paths() {
        assert_eq!(
            endpoints_from_sidecar("127.0.0.1:4318"),
            OtlpEndpoints {
                traces: "http://127.0.0.1:4318/v1/traces".to_string(),
                metrics: "http://127.0.0.1:4318/v1/metrics".to_string(),
            }
        );
    }

    #[test]
    fn endpoints_from_url_preserve_scheme() {
        assert_eq!(
            endpoints_from_sidecar("https://collector.example.com"),
            OtlpEndpoints {
                traces: "https://collector.example.com/v1/traces".to_string(),
                metrics: "https://collector.example.com/v1/metrics".to_string(),
            }
        );
    }

    #[test]
    fn endpoints_trim_trailing_slash() {
        assert_eq!(
            endpoints_from_sidecar("http://collector:4318/"),
            OtlpEndpoints {
                traces: "http://collector:4318/v1/traces".to_string(),
                metrics: "http://collector:4318/v1/metrics".to_string(),
            }
        );
    }
}
