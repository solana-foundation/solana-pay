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
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OtlpEndpoints {
    pub traces: String,
    pub metrics: String,
}

pub(crate) struct OtelGuard {
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(err) = self.tracer_provider.shutdown() {
            eprintln!("OTLP trace shutdown failed: {err:?}");
        }
        if let Err(err) = self.meter_provider.shutdown() {
            eprintln!("OTLP metric shutdown failed: {err:?}");
        }
    }
}

pub(crate) fn init_otlp(sidecar: &str, filter: EnvFilter) -> Result<OtelGuard, String> {
    // Install the W3C trace-context propagator so the proxy can parent its
    // spans to a calling client's trace (e.g. pay-bench) — one shared trace.
    global::set_text_map_propagator(opentelemetry_sdk::propagation::TraceContextPropagator::new());

    let endpoints = endpoints_from_sidecar(sidecar);
    let tracer_provider = init_tracer_provider(&endpoints)?;
    let meter_provider = init_meter_provider(&endpoints)?;
    let tracer = tracer_provider.tracer("pay-server");
    let console_filter = std::env::var("PAY_CONSOLE_LOG")
        .map(EnvFilter::new)
        .unwrap_or_else(|_| EnvFilter::new(filter.to_string()))
        // Metric carrier events must reach `MetricsLayer`, but serializing them
        // to stderr adds several synchronous writes to every paid request.
        .add_directive("pay::metrics=off".parse().expect("valid log directive"));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(std::io::stderr)
                .with_filter(console_filter),
        )
        .with(MetricsLayer::new(meter_provider.clone()))
        .with(OpenTelemetryLayer::new(tracer))
        .init();

    pay_core::server::telemetry::record_metric_baselines();
    meter_provider
        .force_flush()
        .map_err(|error| format!("failed to export initial metric baselines: {error:?}"))?;

    Ok(OtelGuard {
        tracer_provider,
        meter_provider,
    })
}

pub(crate) fn endpoints_from_sidecar(sidecar: &str) -> OtlpEndpoints {
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

fn init_tracer_provider(endpoints: &OtlpEndpoints) -> Result<SdkTracerProvider, String> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(endpoints.traces.clone())
        .build()
        .map_err(|e| format!("failed to create OTLP span exporter: {e}"))?;

    let sample_ratio = trace_sample_ratio()?;
    let provider = SdkTracerProvider::builder()
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            sample_ratio,
        ))))
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource())
        .with_batch_exporter(exporter)
        .build();

    global::set_tracer_provider(provider.clone());
    Ok(provider)
}

fn trace_sample_ratio() -> Result<f64, String> {
    let value = std::env::var("PAY_OTEL_TRACE_SAMPLE_RATIO").ok();
    parse_trace_sample_ratio(value.as_deref())
}

fn parse_trace_sample_ratio(value: Option<&str>) -> Result<f64, String> {
    let Some(value) = value else { return Ok(1.0) };
    let ratio = value.parse::<f64>().map_err(|error| {
        format!("PAY_OTEL_TRACE_SAMPLE_RATIO must be a number from 0 to 1: {error}")
    })?;
    if !(0.0..=1.0).contains(&ratio) {
        return Err("PAY_OTEL_TRACE_SAMPLE_RATIO must be between 0 and 1".to_string());
    }
    Ok(ratio)
}

fn init_meter_provider(endpoints: &OtlpEndpoints) -> Result<SdkMeterProvider, String> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(endpoints.metrics.clone())
        .build()
        .map_err(|e| format!("failed to create OTLP metric exporter: {e}"))?;

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
    let service_name = std::env::var("K_SERVICE").unwrap_or_else(|_| "pay-server".to_string());
    let revision = std::env::var("K_REVISION").unwrap_or_else(|_| "local".to_string());
    let instance_id = format!("{revision}:{}", uuid::Uuid::new_v4());
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
                KeyValue::new("service.instance.id", instance_id),
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

    #[test]
    fn trace_sample_ratio_is_validated() {
        assert_eq!(parse_trace_sample_ratio(None).unwrap(), 1.0);
        assert_eq!(parse_trace_sample_ratio(Some("0.001")).unwrap(), 0.001);
        assert!(parse_trace_sample_ratio(Some("1.1")).is_err());
        assert!(parse_trace_sample_ratio(Some("not-a-number")).is_err());
    }
}
