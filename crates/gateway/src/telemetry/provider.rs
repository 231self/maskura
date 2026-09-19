use std::collections::HashMap;
use std::time::Duration;

use opentelemetry::Context;
use opentelemetry::KeyValue;
use opentelemetry::logs::{LogRecord as _, Logger as _, LoggerProvider as _, Severity};
use opentelemetry::metrics::{Counter, Histogram, MeterProvider as _, UpDownCounter};
use opentelemetry::trace::{Status, TraceContextExt, TracerProvider as _};
use opentelemetry_otlp::{
    LogExporter, MetricExporter, SpanExporter, WithExportConfig, WithHttpConfig,
};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::log_processor_with_async_runtime::BatchLogProcessor;
use opentelemetry_sdk::logs::{
    BatchConfigBuilder as LogBatchConfigBuilder, SdkLogger, SdkLoggerProvider,
};
use opentelemetry_sdk::metrics::periodic_reader_with_async_runtime::PeriodicReader;
use opentelemetry_sdk::metrics::{SdkMeterProvider, Temporality};
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor;
use opentelemetry_sdk::trace::{
    BatchConfigBuilder as TraceBatchConfigBuilder, Sampler as SdkSampler, SdkTracer,
    SdkTracerProvider,
};

use crate::telemetry::config::{
    BatchConfig, Sampler, SamplerConfig, SignalEndpoint, TelemetryConfig,
};
use crate::telemetry::http_client::SanitizingHttpClient;
use crate::telemetry::logging;
use crate::telemetry::schema::{self, CompletionRecord};

const INSTRUMENTATION_SCOPE: &str = "maskura-gateway";

const ACTIVE_REQUESTS: &str = "maskura.http.server.active_requests";
const COMPLETED_REQUESTS: &str = "maskura.http.server.completed_requests";
const REQUEST_DURATION: &str = "maskura.http.server.request.duration";

/// Documented seconds buckets for the request-duration histogram. It covers
/// short control responses through long-lived streaming requests.
const DURATION_BUCKETS_SECONDS: [f64; 17] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
    600.0,
];

const DEFAULT_FLUSH_DEADLINE: Duration = Duration::from_secs(10);

/// Owns the process-global telemetry subscriber and the remote providers.
///
/// The handle must outlive serving and be flushed explicitly on shutdown. Its
/// `Drop` implementation is best effort only.
pub struct TelemetryHandle {
    pub(crate) config: TelemetryConfig,
    pub(crate) remote: Option<RemoteTelemetry>,
}

#[allow(
    dead_code,
    reason = "the lifecycle middleware and typed finalizer are added in the next change"
)]
impl TelemetryHandle {
    pub fn config(&self) -> &TelemetryConfig {
        &self.config
    }

    pub fn export_enabled(&self) -> bool {
        self.remote.is_some()
    }

    #[allow(
        dead_code,
        reason = "consumed by the HTTP lifecycle middleware in the next change"
    )]
    pub(crate) fn remote(&self) -> Option<&RemoteTelemetry> {
        self.remote.as_ref()
    }

    pub(crate) fn tracer(&self) -> Option<SdkTracer> {
        self.remote.as_ref().and_then(RemoteTelemetry::tracer)
    }

    /// Emit the one typed completion log record for a finished request.
    pub(crate) fn emit_completion(&self, context: &Context, record: &CompletionRecord<'_>) {
        if let Some(remote) = &self.remote {
            remote.emit_completion(context, record);
        }
    }

    /// Adjust the active-request gauge by `delta` for an admitted request.
    pub(crate) fn record_active_request(
        &self,
        method: schema::HttpMethodClass,
        route: &str,
        delta: i64,
    ) {
        if let Some(remote) = &self.remote {
            remote.record_active_request(method, route, delta);
        }
    }

    /// Record the completed-request counter and duration histogram.
    pub(crate) fn record_completion_metrics(&self, record: &CompletionRecord<'_>) {
        if let Some(remote) = &self.remote {
            remote.record_completion_metrics(record);
        }
    }

    /// Flush every remote provider within the given deadline.
    ///
    /// Returns `false` when the deadline elapses first; the caller continues
    /// process shutdown in either case.
    pub fn flush(&self, deadline: Duration) -> bool {
        match &self.remote {
            Some(remote) => remote.flush(deadline),
            None => true,
        }
    }

    /// Shut down every remote provider within the given deadline.
    pub fn shutdown(&self, deadline: Duration) -> bool {
        match &self.remote {
            Some(remote) => remote.shutdown(deadline),
            None => true,
        }
    }

    pub fn flush_default(&self) -> bool {
        self.flush(DEFAULT_FLUSH_DEADLINE)
    }
}

/// Install the process-global telemetry subscriber.
///
/// This may be called at most once per process.
pub fn init_telemetry(config: TelemetryConfig) -> anyhow::Result<TelemetryHandle> {
    let (level, format) = logging::parse_log_settings()?;
    let remote = RemoteTelemetry::build(&config)?;
    let tracer = remote.as_ref().and_then(RemoteTelemetry::tracer);
    let subscriber = logging::subscriber(level, format, tracer);
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| anyhow::anyhow!("telemetry subscriber is already installed"))?;
    Ok(TelemetryHandle { config, remote })
}

/// Install local logging only, without building or exporting remote providers.
///
/// Used by short-lived modes such as `--healthcheck` that must never contact a
/// collector. This may be called at most once per process.
pub fn init_local_logging() -> anyhow::Result<()> {
    let (level, format) = logging::parse_log_settings()?;
    let subscriber = logging::subscriber(level, format, None);
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| anyhow::anyhow!("telemetry subscriber is already installed"))?;
    Ok(())
}

/// A local-only handle for tests that need request lifecycle accounting without
/// a collector.
#[cfg(test)]
pub(crate) fn local_handle_for_test() -> std::sync::Arc<TelemetryHandle> {
    use crate::telemetry::config::Sampler;

    let batch = BatchConfig {
        max_queue_size: 64,
        scheduled_delay: Duration::from_millis(5),
        max_export_batch_size: 16,
        export_timeout: Duration::from_secs(5),
    };
    let config = TelemetryConfig {
        service_name: "maskura-gateway".to_string(),
        service_version: "0.0.0-test".to_string(),
        process_role: "gateway".to_string(),
        traces: None,
        logs: None,
        metrics: None,
        sampler: SamplerConfig {
            sampler: Sampler::AlwaysOn,
            ratio: 1.0,
        },
        resource_attributes: Vec::new(),
        span_batch: batch,
        log_batch: batch,
        metric_interval: Duration::from_secs(60),
        metric_timeout: Duration::from_secs(5),
    };
    std::sync::Arc::new(TelemetryHandle {
        config,
        remote: None,
    })
}

/// The remote providers, present only when at least one signal is configured.
pub(crate) struct RemoteTelemetry {
    trace: Option<TraceSignal>,
    logs: Option<LogSignal>,
    metrics: Option<MetricsSignal>,
}

struct TraceSignal {
    provider: SdkTracerProvider,
    tracer: SdkTracer,
}

#[allow(
    dead_code,
    reason = "the lifecycle middleware and typed finalizer are added in the next change"
)]
struct LogSignal {
    provider: SdkLoggerProvider,
    logger: SdkLogger,
}

#[allow(
    dead_code,
    reason = "the lifecycle middleware records instrument samples in the next change"
)]
struct MetricsSignal {
    provider: SdkMeterProvider,
    active_requests: UpDownCounter<i64>,
    completed_requests: Counter<u64>,
    request_duration: Histogram<f64>,
}

#[allow(
    dead_code,
    reason = "the lifecycle middleware and typed finalizer are added in the next change"
)]
impl RemoteTelemetry {
    pub(crate) fn build(config: &TelemetryConfig) -> anyhow::Result<Option<Self>> {
        if !config.export_enabled() {
            return Ok(None);
        }
        let resource = build_resource(config);
        let trace = match &config.traces {
            Some(endpoint) => Some(TraceSignal::build(
                endpoint,
                &config.span_batch,
                config.sampler,
                resource.clone(),
            )?),
            None => None,
        };
        let logs = match &config.logs {
            Some(endpoint) => Some(LogSignal::build(
                endpoint,
                &config.log_batch,
                resource.clone(),
            )?),
            None => None,
        };
        let metrics = match &config.metrics {
            Some(endpoint) => Some(MetricsSignal::build(
                endpoint,
                config.metric_interval,
                config.metric_timeout,
                resource,
            )?),
            None => None,
        };
        Ok(Some(Self {
            trace,
            logs,
            metrics,
        }))
    }

    fn tracer(&self) -> Option<SdkTracer> {
        self.trace.as_ref().map(|signal| signal.tracer.clone())
    }

    fn emit_completion(&self, context: &Context, record: &CompletionRecord<'_>) {
        let Some(logs) = &self.logs else {
            return;
        };
        let mut log_record = logs.logger.create_log_record();
        log_record.set_event_name(schema::COMPLETION_EVENT_NAME);
        log_record.set_severity_number(Severity::Info);
        log_record.set_severity_text("INFO");
        log_record.add_attribute("request_id", record.request_id.to_string());
        log_record.add_attribute("method", record.method.as_str());
        log_record.add_attribute("route", record.route.to_string());
        log_record.add_attribute("status_class", record.status_class().as_str());
        log_record.add_attribute("outcome", record.outcome.as_str());
        log_record.add_attribute(
            "duration_ms",
            i64::try_from(record.duration_ms()).unwrap_or(i64::MAX),
        );

        let span_context = context.span().span_context().clone();
        if span_context.is_valid() {
            log_record.set_trace_context(
                span_context.trace_id(),
                span_context.span_id(),
                Some(span_context.trace_flags()),
            );
        }
        logs.logger.emit(log_record);
    }

    fn record_active_request(&self, method: schema::HttpMethodClass, route: &str, delta: i64) {
        if let Some(metrics) = &self.metrics {
            metrics.active_requests.add(
                delta,
                &[
                    KeyValue::new("http.request.method", method.as_str()),
                    KeyValue::new("http.route", route.to_string()),
                ],
            );
        }
    }

    fn record_completion_metrics(&self, record: &CompletionRecord<'_>) {
        if let Some(metrics) = &self.metrics {
            let attributes = completion_metric_attributes(record);
            metrics.completed_requests.add(1, &attributes);
            metrics
                .request_duration
                .record(record.duration.as_secs_f64(), &attributes);
        }
    }

    fn flush(&self, deadline: Duration) -> bool {
        let trace = self.trace.as_ref().map(|signal| signal.provider.clone());
        let logs = self.logs.as_ref().map(|signal| signal.provider.clone());
        let metrics = self.metrics.as_ref().map(|signal| signal.provider.clone());
        if trace.is_none() && logs.is_none() && metrics.is_none() {
            return true;
        }
        let (sender, receiver) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("maskura-telemetry-flush".to_string())
            .spawn(move || {
                if let Some(provider) = trace {
                    let _ = provider.force_flush();
                }
                if let Some(provider) = logs {
                    let _ = provider.force_flush();
                }
                if let Some(provider) = metrics {
                    let _ = provider.force_flush();
                }
                let _ = sender.send(());
            })
            .is_ok();
        spawned && receiver.recv_timeout(deadline).is_ok()
    }

    fn shutdown(&self, deadline: Duration) -> bool {
        let trace = self.trace.as_ref().map(|signal| signal.provider.clone());
        let logs = self.logs.as_ref().map(|signal| signal.provider.clone());
        let metrics = self.metrics.as_ref().map(|signal| signal.provider.clone());
        if trace.is_none() && logs.is_none() && metrics.is_none() {
            return true;
        }
        let (sender, receiver) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("maskura-telemetry-shutdown".to_string())
            .spawn(move || {
                if let Some(provider) = trace {
                    let _ = provider.shutdown();
                }
                if let Some(provider) = logs {
                    let _ = provider.shutdown();
                }
                if let Some(provider) = metrics {
                    let _ = provider.shutdown();
                }
                let _ = sender.send(());
            })
            .is_ok();
        spawned && receiver.recv_timeout(deadline).is_ok()
    }
}

impl TraceSignal {
    fn build(
        endpoint: &SignalEndpoint,
        batch: &BatchConfig,
        sampler: SamplerConfig,
        resource: Resource,
    ) -> anyhow::Result<Self> {
        let exporter = build_span_exporter(endpoint)?;
        let processor = BatchSpanProcessor::builder(exporter, Tokio)
            .with_batch_config(trace_batch_config(batch))
            .build();
        let provider = SdkTracerProvider::builder()
            .with_resource(resource)
            .with_sampler(build_sampler(sampler))
            .with_span_processor(processor)
            .build();
        let tracer = provider.tracer(INSTRUMENTATION_SCOPE);
        Ok(Self { provider, tracer })
    }
}

impl LogSignal {
    fn build(
        endpoint: &SignalEndpoint,
        batch: &BatchConfig,
        resource: Resource,
    ) -> anyhow::Result<Self> {
        let exporter = build_log_exporter(endpoint)?;
        let processor = BatchLogProcessor::builder(exporter, Tokio)
            .with_batch_config(log_batch_config(batch))
            .build();
        let provider = SdkLoggerProvider::builder()
            .with_resource(resource)
            .with_log_processor(processor)
            .build();
        let logger = provider.logger(INSTRUMENTATION_SCOPE);
        Ok(Self { provider, logger })
    }
}

impl MetricsSignal {
    fn build(
        endpoint: &SignalEndpoint,
        interval: Duration,
        timeout: Duration,
        resource: Resource,
    ) -> anyhow::Result<Self> {
        let exporter = build_metric_exporter(endpoint)?;
        let reader = PeriodicReader::builder(exporter, Tokio)
            .with_interval(interval)
            .with_timeout(timeout)
            .build();
        let provider = SdkMeterProvider::builder()
            .with_resource(resource)
            .with_reader(reader)
            .build();
        let meter = provider.meter(INSTRUMENTATION_SCOPE);
        let active_requests = meter.i64_up_down_counter(ACTIVE_REQUESTS).build();
        let completed_requests = meter.u64_counter(COMPLETED_REQUESTS).build();
        let request_duration = meter
            .f64_histogram(REQUEST_DURATION)
            .with_boundaries(DURATION_BUCKETS_SECONDS.to_vec())
            .build();
        Ok(Self {
            provider,
            active_requests,
            completed_requests,
            request_duration,
        })
    }
}

fn completion_metric_attributes(record: &CompletionRecord<'_>) -> Vec<KeyValue> {
    vec![
        KeyValue::new("http.request.method", record.method.as_str()),
        KeyValue::new("http.route", record.route.to_string()),
        KeyValue::new("maskura.http.status_class", record.status_class().as_str()),
        KeyValue::new("maskura.http.outcome", record.outcome.as_str()),
    ]
}

fn build_resource(config: &TelemetryConfig) -> Resource {
    let mut attributes = Vec::with_capacity(config.resource_attributes.len() + 2);
    attributes.push(KeyValue::new(
        "service.version",
        config.service_version.clone(),
    ));
    attributes.push(KeyValue::new(
        "maskura.process.role",
        config.process_role.clone(),
    ));
    for (key, value) in &config.resource_attributes {
        attributes.push(KeyValue::new(key.clone(), value.clone()));
    }
    Resource::builder_empty()
        .with_service_name(config.service_name.clone())
        .with_attributes(attributes)
        .build()
}

fn build_sampler(config: SamplerConfig) -> SdkSampler {
    match config.sampler {
        Sampler::AlwaysOn => SdkSampler::AlwaysOn,
        Sampler::AlwaysOff => SdkSampler::AlwaysOff,
        Sampler::TraceIdRatio => SdkSampler::TraceIdRatioBased(config.ratio),
        Sampler::ParentBasedAlwaysOn => SdkSampler::ParentBased(Box::new(SdkSampler::AlwaysOn)),
        Sampler::ParentBasedAlwaysOff => SdkSampler::ParentBased(Box::new(SdkSampler::AlwaysOff)),
        Sampler::ParentBasedTraceIdRatio => {
            SdkSampler::ParentBased(Box::new(SdkSampler::TraceIdRatioBased(config.ratio)))
        }
    }
}

fn trace_batch_config(batch: &BatchConfig) -> opentelemetry_sdk::trace::BatchConfig {
    TraceBatchConfigBuilder::default()
        .with_max_queue_size(batch.max_queue_size)
        .with_scheduled_delay(batch.scheduled_delay)
        .with_max_export_batch_size(batch.max_export_batch_size)
        .with_max_export_timeout(batch.export_timeout)
        .build()
}

fn log_batch_config(batch: &BatchConfig) -> opentelemetry_sdk::logs::BatchConfig {
    LogBatchConfigBuilder::default()
        .with_max_queue_size(batch.max_queue_size)
        .with_scheduled_delay(batch.scheduled_delay)
        .with_max_export_batch_size(batch.max_export_batch_size)
        .with_max_export_timeout(batch.export_timeout)
        .build()
}

fn header_map(endpoint: &SignalEndpoint) -> HashMap<String, String> {
    endpoint
        .headers
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// The OTLP HTTP exporter uses a programmatic endpoint verbatim, so the signal
/// path must be appended to the operator-provided base endpoint.
fn signal_url(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

fn build_span_exporter(endpoint: &SignalEndpoint) -> anyhow::Result<SpanExporter> {
    let client = SanitizingHttpClient::new(endpoint.timeout)?;
    let mut builder = SpanExporter::builder()
        .with_http()
        .with_endpoint(signal_url(&endpoint.endpoint, "/v1/traces"))
        .with_timeout(endpoint.timeout)
        .with_http_client(client);
    if !endpoint.headers.is_empty() {
        builder = builder.with_headers(header_map(endpoint));
    }
    builder
        .build()
        .map_err(|_| anyhow::anyhow!("failed to build OTLP span exporter"))
}

fn build_log_exporter(endpoint: &SignalEndpoint) -> anyhow::Result<LogExporter> {
    let client = SanitizingHttpClient::new(endpoint.timeout)?;
    let mut builder = LogExporter::builder()
        .with_http()
        .with_endpoint(signal_url(&endpoint.endpoint, "/v1/logs"))
        .with_timeout(endpoint.timeout)
        .with_http_client(client);
    if !endpoint.headers.is_empty() {
        builder = builder.with_headers(header_map(endpoint));
    }
    builder
        .build()
        .map_err(|_| anyhow::anyhow!("failed to build OTLP log exporter"))
}

fn build_metric_exporter(endpoint: &SignalEndpoint) -> anyhow::Result<MetricExporter> {
    let client = SanitizingHttpClient::new(endpoint.timeout)?;
    let mut builder = MetricExporter::builder()
        .with_http()
        .with_temporality(Temporality::Cumulative)
        .with_endpoint(signal_url(&endpoint.endpoint, "/v1/metrics"))
        .with_timeout(endpoint.timeout)
        .with_http_client(client);
    if !endpoint.headers.is_empty() {
        builder = builder.with_headers(header_map(endpoint));
    }
    builder
        .build()
        .map_err(|_| anyhow::anyhow!("failed to build OTLP metric exporter"))
}

/// Apply the six allowlisted span attributes from typed values.
///
/// This is the only place dotted semantic attributes are written; `tracing`
/// fields cannot represent them.
#[allow(
    dead_code,
    reason = "consumed by the HTTP lifecycle middleware in the next change"
)]
pub(crate) fn apply_completion_span_attributes(context: &Context, record: &CompletionRecord<'_>) {
    let span = context.span();
    span.set_attribute(KeyValue::new(
        "maskura.request.id",
        record.request_id.to_string(),
    ));
    span.set_attribute(KeyValue::new("http.request.method", record.method.as_str()));
    span.set_attribute(KeyValue::new("http.route", record.route.to_string()));
    if let Some(code) = record.status_code {
        span.set_attribute(KeyValue::new("http.response.status_code", i64::from(code)));
    }
    span.set_attribute(KeyValue::new(
        "maskura.http.status_class",
        record.status_class().as_str(),
    ));
    span.set_attribute(KeyValue::new(
        "maskura.http.outcome",
        record.outcome.as_str(),
    ));
}

/// Set the span status from the terminal outcome.
#[allow(
    dead_code,
    reason = "consumed by the HTTP lifecycle middleware in the next change"
)]
pub(crate) fn apply_completion_span_status(context: &Context, record: &CompletionRecord<'_>) {
    let status = match record.outcome {
        schema::Outcome::Completed if !record.status_class().is_server_error() => Status::Ok,
        schema::Outcome::Completed => Status::error("server_error"),
        schema::Outcome::BodyError => Status::error("body_error"),
        schema::Outcome::Cancelled => Status::error("cancelled"),
    };
    context.span().set_status(status);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::Mutex;

    use axum::Router;
    use axum::body::Bytes as AxumBytes;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, Uri};
    use axum::routing::any;
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue as ProtoKeyValue};
    use opentelemetry_proto::tonic::metrics::v1::metric::Data as MetricData;
    use opentelemetry_proto::tonic::trace::v1::span::SpanKind;
    use prost::Message;
    use tracing::Level;
    use tracing_opentelemetry::OpenTelemetrySpanExt;

    use crate::telemetry::logging::{self, LogFormat};
    use crate::telemetry::schema::{self, HttpMethodClass, Outcome};

    #[derive(Clone)]
    struct Capture {
        path: String,
        content_type: Option<String>,
        authorization: Option<String>,
        body: Vec<u8>,
    }

    #[derive(Default)]
    struct Collector {
        captures: Mutex<Vec<Capture>>,
    }

    async fn capture(
        State(state): State<std::sync::Arc<Collector>>,
        uri: Uri,
        headers: HeaderMap,
        body: AxumBytes,
    ) -> StatusCode {
        let mut captures = state.captures.lock().unwrap();
        captures.push(Capture {
            path: uri.path().to_string(),
            content_type: headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            authorization: headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            body: body.to_vec(),
        });
        StatusCode::OK
    }

    async fn start_collector() -> (String, std::sync::Arc<Collector>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = std::sync::Arc::new(Collector::default());
        let router = Router::new()
            .fallback(any(capture))
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{address}"), state)
    }

    fn test_batch() -> BatchConfig {
        BatchConfig {
            max_queue_size: 64,
            scheduled_delay: Duration::from_millis(5),
            max_export_batch_size: 16,
            export_timeout: Duration::from_secs(5),
        }
    }

    fn signal_endpoint(endpoint: &str, headers: &[(&str, &str)]) -> SignalEndpoint {
        SignalEndpoint {
            endpoint: endpoint.to_string(),
            insecure: true,
            headers: headers
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
            timeout: Duration::from_secs(5),
        }
    }

    fn test_config(endpoint: &str, headers: &[(&str, &str)]) -> TelemetryConfig {
        TelemetryConfig {
            service_name: "maskura-gateway".to_string(),
            service_version: "0.0.0-test".to_string(),
            process_role: "gateway".to_string(),
            traces: Some(signal_endpoint(endpoint, headers)),
            logs: Some(signal_endpoint(endpoint, headers)),
            metrics: Some(signal_endpoint(endpoint, headers)),
            sampler: SamplerConfig {
                sampler: Sampler::AlwaysOn,
                ratio: 1.0,
            },
            resource_attributes: vec![("cloud.region".to_string(), "test-region".to_string())],
            span_batch: test_batch(),
            log_batch: test_batch(),
            metric_interval: Duration::from_secs(60),
            metric_timeout: Duration::from_secs(5),
        }
    }

    fn record() -> CompletionRecord<'static> {
        CompletionRecord {
            request_id: "01920000-0000-7000-8000-000000000001",
            method: HttpMethodClass::Get,
            route: "/v1/buckets/{bucket}",
            status_code: Some(200),
            outcome: Outcome::Completed,
            duration: Duration::from_millis(1500),
        }
    }

    fn string_attribute(attributes: &[ProtoKeyValue], key: &str) -> Option<String> {
        attributes
            .iter()
            .find(|kv| kv.key == key)
            .and_then(|kv| match &kv.value {
                Some(AnyValue {
                    value: Some(ProtoValue::StringValue(value)),
                }) => Some(value.clone()),
                _ => None,
            })
    }

    fn int_attribute(attributes: &[ProtoKeyValue], key: &str) -> Option<i64> {
        attributes
            .iter()
            .find(|kv| kv.key == key)
            .and_then(|kv| match &kv.value {
                Some(AnyValue {
                    value: Some(ProtoValue::IntValue(value)),
                }) => Some(*value),
                _ => None,
            })
    }

    fn attribute_keys(attributes: &[ProtoKeyValue]) -> BTreeSet<String> {
        attributes.iter().map(|kv| kv.key.clone()).collect()
    }

    #[test]
    fn resource_carries_exact_allowlisted_keys() {
        let config = test_config("http://127.0.0.1:4318", &[]);
        let resource = build_resource(&config);
        let mut keys = BTreeSet::new();
        let mut values = HashMap::new();
        for (key, value) in resource.iter() {
            keys.insert(key.as_str().to_string());
            values.insert(key.as_str().to_string(), format!("{value}"));
        }
        assert_eq!(
            keys,
            BTreeSet::from([
                "service.name".to_string(),
                "service.version".to_string(),
                "maskura.process.role".to_string(),
                "cloud.region".to_string(),
            ])
        );
        assert_eq!(values["service.name"], "maskura-gateway");
        assert_eq!(values["maskura.process.role"], "gateway");
    }

    #[test]
    fn sampler_selection_matches_configuration() {
        assert!(matches!(
            build_sampler(SamplerConfig {
                sampler: Sampler::AlwaysOn,
                ratio: 1.0
            }),
            SdkSampler::AlwaysOn
        ));
        assert!(matches!(
            build_sampler(SamplerConfig {
                sampler: Sampler::ParentBasedAlwaysOff,
                ratio: 1.0
            }),
            SdkSampler::ParentBased(_)
        ));
        assert!(matches!(
            build_sampler(SamplerConfig { sampler: Sampler::TraceIdRatio, ratio: 0.25 }),
            SdkSampler::TraceIdRatioBased(ratio) if (ratio - 0.25).abs() < f64::EPSILON
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn otlp_export_delivers_only_reviewed_signals() {
        let (endpoint, collector) = start_collector().await;
        let secret = "SENTINEL-auth-9f2c";
        let config = test_config(&endpoint, &[("authorization", secret)]);
        let remote = RemoteTelemetry::build(&config).unwrap().unwrap();
        let tracer = remote.tracer().unwrap();

        let subscriber = logging::subscriber_with_writer_and_tracer(
            Level::INFO,
            LogFormat::Text,
            std::io::sink,
            tracer,
        );
        let _guard = tracing::subscriber::set_default(subscriber);

        let record = record();
        {
            let span = schema::request_span();
            let context = span.context();
            apply_completion_span_attributes(&context, &record);
            apply_completion_span_status(&context, &record);
            remote.record_active_request(HttpMethodClass::Get, record.route, 1);
            remote.record_completion_metrics(&record);
            remote.emit_completion(&context, &record);
            remote.record_active_request(HttpMethodClass::Get, record.route, -1);
            drop(span);
        }

        let forged =
            tracing::info_span!(target: "maskura.telemetry", "Forged span", sentinel = secret);
        drop(forged);
        tracing::info!(target: "maskura.telemetry", sentinel = secret, "forged event");

        assert!(remote.flush(Duration::from_secs(10)));
        assert!(remote.shutdown(Duration::from_secs(10)));

        let captures = collector.captures.lock().unwrap();
        let by_path = |path: &str| {
            captures
                .iter()
                .find(|capture| capture.path == path)
                .unwrap()
        };

        let traces = by_path("/v1/traces");
        let logs = by_path("/v1/logs");
        let metrics = by_path("/v1/metrics");
        assert_eq!(
            traces.content_type.as_deref(),
            Some("application/x-protobuf")
        );
        assert_eq!(logs.content_type.as_deref(), Some("application/x-protobuf"));
        assert_eq!(
            metrics.content_type.as_deref(),
            Some("application/x-protobuf")
        );
        assert_eq!(traces.authorization.as_deref(), Some(secret));
        assert_eq!(metrics.authorization.as_deref(), Some(secret));

        for capture in captures.iter() {
            let text = String::from_utf8_lossy(&capture.body);
            assert!(
                !text.contains(secret),
                "credential leaked into exported records"
            );
        }

        // Exactly one reviewed span; the forged span and event were rejected.
        let trace_request = ExportTraceServiceRequest::decode(traces.body.as_slice()).unwrap();
        assert_eq!(trace_request.resource_spans.len(), 1);
        let resource_spans = &trace_request.resource_spans[0];
        let resource = resource_spans.resource.as_ref().unwrap();
        assert_eq!(
            string_attribute(&resource.attributes, "service.name").as_deref(),
            Some("maskura-gateway")
        );
        assert_eq!(
            string_attribute(&resource.attributes, "cloud.region").as_deref(),
            Some("test-region")
        );

        let spans = &resource_spans.scope_spans[0].spans;
        assert_eq!(spans.len(), 1);
        let span = &spans[0];
        assert_eq!(span.name, schema::REQUEST_SPAN_NAME);
        assert_eq!(span.kind, SpanKind::Server as i32);
        assert_eq!(
            attribute_keys(&span.attributes),
            BTreeSet::from([
                "maskura.request.id".to_string(),
                "http.request.method".to_string(),
                "http.route".to_string(),
                "http.response.status_code".to_string(),
                "maskura.http.status_class".to_string(),
                "maskura.http.outcome".to_string(),
            ])
        );
        assert_eq!(
            string_attribute(&span.attributes, "maskura.request.id").as_deref(),
            Some(record.request_id)
        );
        assert_eq!(
            int_attribute(&span.attributes, "http.response.status_code"),
            Some(200)
        );
        assert_eq!(
            string_attribute(&span.attributes, "http.route").as_deref(),
            Some(record.route)
        );

        // Exactly one reviewed completion log with fixed fields + trace context.
        let log_request = ExportLogsServiceRequest::decode(logs.body.as_slice()).unwrap();
        let log_records = &log_request.resource_logs[0].scope_logs[0].log_records;
        assert_eq!(log_records.len(), 1);
        let log_record = &log_records[0];
        assert_eq!(log_record.event_name, schema::COMPLETION_EVENT_NAME);
        assert_eq!(
            attribute_keys(&log_record.attributes),
            BTreeSet::from([
                "request_id".to_string(),
                "method".to_string(),
                "route".to_string(),
                "status_class".to_string(),
                "outcome".to_string(),
                "duration_ms".to_string(),
            ])
        );
        assert_eq!(
            string_attribute(&log_record.attributes, "request_id").as_deref(),
            Some(record.request_id)
        );
        assert_eq!(
            int_attribute(&log_record.attributes, "duration_ms"),
            Some(1500)
        );
        assert_eq!(log_record.trace_id, span.trace_id);
        assert_eq!(log_record.span_id, span.span_id);

        // All three reviewed metrics with bounded attributes.
        let metric_request = ExportMetricsServiceRequest::decode(metrics.body.as_slice()).unwrap();
        let scope_metrics = &metric_request.resource_metrics[0].scope_metrics[0].metrics;
        let names: BTreeSet<&str> = scope_metrics
            .iter()
            .map(|metric| metric.name.as_str())
            .collect();
        assert!(names.contains(ACTIVE_REQUESTS));
        assert!(names.contains(COMPLETED_REQUESTS));
        assert!(names.contains(REQUEST_DURATION));

        let completed = scope_metrics
            .iter()
            .find(|m| m.name == COMPLETED_REQUESTS)
            .unwrap();
        match completed.data.as_ref().unwrap() {
            MetricData::Sum(sum) => {
                assert!(sum.is_monotonic);
                let point = &sum.data_points[0];
                assert_eq!(
                    point.value,
                    Some(
                        opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsInt(1)
                    )
                );
                assert_eq!(
                    string_attribute(&point.attributes, "maskura.http.status_class").as_deref(),
                    Some("2xx")
                );
                assert_eq!(
                    string_attribute(&point.attributes, "maskura.http.outcome").as_deref(),
                    Some("completed")
                );
            }
            other => panic!("completed requests is not a sum: {other:?}"),
        }

        let duration = scope_metrics
            .iter()
            .find(|m| m.name == REQUEST_DURATION)
            .unwrap();
        match duration.data.as_ref().unwrap() {
            MetricData::Histogram(histogram) => {
                let point = &histogram.data_points[0];
                assert_eq!(point.count, 1);
                assert!((point.sum.unwrap() - 1.5).abs() < 1e-9);
                assert_eq!(point.explicit_bounds, DURATION_BUCKETS_SECONDS);
            }
            other => panic!("duration is not a histogram: {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unreachable_collector_never_panics_or_hangs() {
        let config = test_config("http://127.0.0.1:1", &[]);
        let remote = RemoteTelemetry::build(&config).unwrap().unwrap();
        let tracer = remote.tracer().unwrap();
        let subscriber = logging::subscriber_with_writer_and_tracer(
            Level::INFO,
            LogFormat::Text,
            std::io::sink,
            tracer,
        );
        let _guard = tracing::subscriber::set_default(subscriber);

        let record = record();
        let span = schema::request_span();
        let context = span.context();
        apply_completion_span_attributes(&context, &record);
        apply_completion_span_status(&context, &record);
        remote.record_completion_metrics(&record);
        remote.emit_completion(&context, &record);
        drop(span);

        let _ = remote.flush(Duration::from_millis(500));
        let _ = remote.shutdown(Duration::from_millis(500));
    }
}
