use std::io;
use std::sync::Arc;

use opentelemetry_sdk::trace::SdkTracer;
use tracing::subscriber::Interest;
use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Context, Filter, SubscriberExt};
use tracing_subscriber::{Layer, registry};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LogFormat {
    Text,
    Json,
}

/// Targets whose diagnostics may embed configured endpoints, headers, or other
/// unreviewed transport detail. They are never written locally.
const SUPPRESSED_TARGETS: [&str; 15] = [
    "opentelemetry",
    "opentelemetry_sdk",
    "opentelemetry_otlp",
    "opentelemetry_http",
    "opentelemetry_proto",
    "tracing_opentelemetry",
    "reqwest",
    "hyper",
    "h2",
    "rustls",
    "aws_smithy",
    "aws_runtime",
    "aws_sdk",
    "sqlx",
    "sea_orm",
];

fn is_suppressed(target: &str) -> bool {
    SUPPRESSED_TARGETS
        .iter()
        .any(|prefix| target.starts_with(prefix))
}

fn is_maskura_target(target: &str) -> bool {
    target.starts_with("maskura")
}

#[derive(Clone, Copy)]
struct LocalFilter {
    app_level: Level,
}

impl LocalFilter {
    fn allows(&self, metadata: &Metadata<'_>) -> bool {
        let target = metadata.target();
        if is_suppressed(target) {
            return false;
        }
        let ceiling = if is_maskura_target(target) {
            self.app_level
        } else {
            Level::WARN
        };
        *metadata.level() <= ceiling
    }
}

impl<S: Subscriber> Filter<S> for LocalFilter {
    fn enabled(&self, metadata: &Metadata<'_>, _context: &Context<'_, S>) -> bool {
        self.allows(metadata)
    }

    fn callsite_enabled(&self, metadata: &'static Metadata<'static>) -> Interest {
        if self.allows(metadata) {
            Interest::always()
        } else {
            Interest::never()
        }
    }
}

pub(crate) fn parse_log_settings() -> anyhow::Result<(Level, LogFormat)> {
    let level = match std::env::var("MASKURA_LOG_LEVEL")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .as_deref()
    {
        None | Some("info") => Level::INFO,
        Some("error") => Level::ERROR,
        Some("warn") => Level::WARN,
        Some("debug") => Level::DEBUG,
        Some(_) => anyhow::bail!("invalid MASKURA_LOG_LEVEL"),
    };
    let format = match std::env::var("MASKURA_LOG_FORMAT")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .as_deref()
    {
        None | Some("text") => LogFormat::Text,
        Some("json") => LogFormat::Json,
        Some(_) => anyhow::bail!("invalid MASKURA_LOG_FORMAT"),
    };
    Ok((level, format))
}

pub(crate) fn subscriber(
    level: Level,
    format: LogFormat,
    tracer: Option<SdkTracer>,
) -> Arc<dyn Subscriber + Send + Sync> {
    subscriber_inner(level, format, io::stdout, tracer)
}

#[cfg(test)]
pub(crate) fn subscriber_with_writer<W>(
    level: Level,
    format: LogFormat,
    writer: W,
) -> Arc<dyn Subscriber + Send + Sync>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    subscriber_inner(level, format, writer, None)
}

#[cfg(test)]
pub(crate) fn subscriber_with_writer_and_tracer<W>(
    level: Level,
    format: LogFormat,
    writer: W,
    tracer: SdkTracer,
) -> Arc<dyn Subscriber + Send + Sync>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    subscriber_inner(level, format, writer, Some(tracer))
}

/// Accepts only the exact module-owned request-span callsite.
///
/// Every event and every other span is rejected, so generic `tracing` data can
/// never reach the OTLP trace exporter.
#[derive(Clone, Copy)]
struct RequestSpanFilter;

fn is_request_span(metadata: &Metadata<'_>) -> bool {
    metadata.is_span()
        && metadata.target() == crate::telemetry::schema::TELEMETRY_TARGET
        && metadata.name() == crate::telemetry::schema::REQUEST_SPAN_NAME
}

impl<S: Subscriber> Filter<S> for RequestSpanFilter {
    fn enabled(&self, metadata: &Metadata<'_>, _context: &Context<'_, S>) -> bool {
        is_request_span(metadata)
    }

    fn callsite_enabled(&self, metadata: &'static Metadata<'static>) -> Interest {
        if is_request_span(metadata) {
            Interest::always()
        } else {
            Interest::never()
        }
    }
}

fn trace_layer<S>(tracer: SdkTracer) -> impl Layer<S> + Send + Sync
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a> + Send + Sync,
{
    tracing_opentelemetry::layer()
        .with_tracer(tracer)
        .with_location(false)
        .with_threads(false)
        .with_target(false)
        .with_level(false)
        .with_tracked_inactivity(false)
        .with_error_fields_to_exceptions(false)
        .with_error_events_to_status(false)
        .with_error_events_to_exceptions(false)
        .with_error_records_to_exceptions(false)
        .with_filter(RequestSpanFilter)
}

fn subscriber_inner<W>(
    level: Level,
    format: LogFormat,
    writer: W,
    tracer: Option<SdkTracer>,
) -> Arc<dyn Subscriber + Send + Sync>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let filter = LocalFilter { app_level: level };
    match (format, tracer) {
        (LogFormat::Text, Some(tracer)) => Arc::new(
            registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(writer)
                        .with_filter(filter),
                )
                .with(trace_layer(tracer)),
        ),
        (LogFormat::Json, Some(tracer)) => Arc::new(
            registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_writer(writer)
                        .with_filter(filter),
                )
                .with(trace_layer(tracer)),
        ),
        (LogFormat::Text, None) => Arc::new(
            registry().with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(writer)
                    .with_filter(filter),
            ),
        ),
        (LogFormat::Json, None) => Arc::new(
            registry().with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(writer)
                    .with_filter(filter),
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Capture {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Capture;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn run(level: Level, format: LogFormat, body: impl FnOnce()) -> String {
        let capture = Capture::default();
        let dispatch = subscriber_with_writer(level, format, capture.clone());
        tracing::subscriber::with_default(dispatch, body);
        capture.contents()
    }

    #[test]
    fn text_format_writes_maskura_events() {
        let output = run(Level::INFO, LogFormat::Text, || {
            tracing::info!(target: "maskura_gateway::server", "hello text");
        });
        assert!(output.contains("hello text"));
        assert!(output.contains("maskura_gateway::server"));
    }

    #[test]
    fn json_format_emits_parseable_records() {
        let output = run(Level::INFO, LogFormat::Json, || {
            tracing::info!(target: "maskura_gateway::server", extra = "value", "hello json");
        });
        let line = output.lines().next().expect("one json record");
        let value: serde_json::Value = serde_json::from_str(line).expect("valid json");
        assert_eq!(value["fields"]["message"], "hello json");
        assert_eq!(value["target"], "maskura_gateway::server");
    }

    #[test]
    fn application_level_suppresses_below_threshold() {
        let output = run(Level::WARN, LogFormat::Text, || {
            tracing::info!(target: "maskura_gateway::server", "quiet info");
            tracing::warn!(target: "maskura_gateway::server", "loud warn");
        });
        assert!(!output.contains("quiet info"));
        assert!(output.contains("loud warn"));
    }

    #[test]
    fn dependency_targets_are_capped_at_warn() {
        let output = run(Level::DEBUG, LogFormat::Text, || {
            tracing::debug!(target: "third_party::client", "quiet dependency debug");
            tracing::warn!(target: "third_party::client", "loud dependency warn");
        });
        assert!(!output.contains("quiet dependency debug"));
        assert!(output.contains("loud dependency warn"));
    }

    #[test]
    fn telemetry_and_transport_targets_are_fully_suppressed() {
        let output = run(Level::DEBUG, LogFormat::Text, || {
            tracing::warn!(target: "opentelemetry_sdk::trace", "otel warning");
            tracing::warn!(target: "reqwest::connect", "reqwest warning");
            tracing::error!(target: "hyper::client", "hyper error");
        });
        assert!(!output.contains("otel warning"));
        assert!(!output.contains("reqwest warning"));
        assert!(!output.contains("hyper error"));
    }
}
