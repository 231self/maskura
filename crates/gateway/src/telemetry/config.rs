use std::fmt;
use std::time::Duration;

const DEFAULT_EXPORT_TIMEOUT_MS: u64 = 10_000;
const MAX_EXPORT_TIMEOUT_MS: u64 = 300_000;
const MIN_EXPORT_TIMEOUT_MS: u64 = 1;

const DEFAULT_BATCH_QUEUE: usize = 2048;
const MAX_BATCH_QUEUE: usize = 100_000;
const DEFAULT_BATCH_DELAY_MS: u64 = 5_000;
const MAX_BATCH_DELAY_MS: u64 = 60_000;
const MIN_BATCH_DELAY_MS: u64 = 1;
const DEFAULT_BATCH_SIZE: usize = 512;
const DEFAULT_METRIC_INTERVAL_MS: u64 = 60_000;
const MIN_METRIC_INTERVAL_MS: u64 = 1_000;
const MAX_METRIC_INTERVAL_MS: u64 = 3_600_000;

const MAX_HEADER_PAIRS: usize = 32;
const MAX_ATTRIBUTE_VALUE_LEN: usize = 256;
const RESERVED_RESOURCE_KEYS: [&str; 3] =
    ["service.name", "service.version", "maskura.process.role"];
const ALLOWED_RESOURCE_KEYS: [&str; 6] = [
    "service.namespace",
    "service.instance.id",
    "deployment.environment.name",
    "cloud.provider",
    "cloud.region",
    "cloud.availability_zone",
];

/// A remote signal that can be exported over OTLP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    Traces,
    Logs,
    Metrics,
}

/// A supported trace sampler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sampler {
    AlwaysOn,
    AlwaysOff,
    TraceIdRatio,
    ParentBasedAlwaysOn,
    ParentBasedAlwaysOff,
    ParentBasedTraceIdRatio,
}

/// A validated sampler selection and its optional ratio argument.
#[derive(Clone, Copy, Debug)]
pub struct SamplerConfig {
    pub sampler: Sampler,
    pub ratio: f64,
}

impl Default for SamplerConfig {
    fn default() -> Self {
        Self {
            sampler: Sampler::ParentBasedTraceIdRatio,
            ratio: 0.1,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[allow(
    dead_code,
    reason = "consumed by the OTLP provider builder added in the next change"
)]
pub(crate) struct BatchConfig {
    pub max_queue_size: usize,
    pub scheduled_delay: Duration,
    pub max_export_batch_size: usize,
    pub export_timeout: Duration,
}

impl BatchConfig {
    fn new(
        queue: Option<&str>,
        delay_ms: Option<&str>,
        batch: Option<&str>,
        timeout_ms: Option<&str>,
    ) -> anyhow::Result<Self> {
        let max_queue_size = parse_bounded_usize(
            queue,
            DEFAULT_BATCH_QUEUE,
            1,
            MAX_BATCH_QUEUE,
            "OTEL batch queue",
        )?;
        let scheduled_delay = parse_bounded_ms(
            delay_ms,
            DEFAULT_BATCH_DELAY_MS,
            MIN_BATCH_DELAY_MS,
            MAX_BATCH_DELAY_MS,
            "OTEL batch delay",
        )?;
        let max_export_batch_size = parse_bounded_usize(
            batch,
            DEFAULT_BATCH_SIZE,
            1,
            MAX_BATCH_QUEUE,
            "OTEL batch size",
        )?;
        if max_export_batch_size > max_queue_size {
            anyhow::bail!("invalid OTEL batch configuration");
        }
        let export_timeout = parse_bounded_ms(
            timeout_ms,
            DEFAULT_EXPORT_TIMEOUT_MS,
            MIN_EXPORT_TIMEOUT_MS,
            MAX_EXPORT_TIMEOUT_MS,
            "OTEL batch export timeout",
        )?;
        Ok(Self {
            max_queue_size,
            scheduled_delay,
            max_export_batch_size,
            export_timeout,
        })
    }
}

#[derive(Clone)]
#[allow(
    dead_code,
    reason = "endpoint and insecure are consumed by the OTLP provider builder added in the next change"
)]
pub(crate) struct SignalEndpoint {
    pub endpoint: String,
    pub insecure: bool,
    pub headers: Vec<(String, String)>,
    pub timeout: Duration,
}

impl fmt::Debug for SignalEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignalEndpoint")
            .field("endpoint", &"<redacted>")
            .field("insecure", &self.insecure)
            .field("headers", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Validated telemetry configuration.
///
/// Construct with [`TelemetryConfig::from_env`]. Endpoints, headers, and
/// resource values are never rendered by `Debug`, `Display`, or error messages.
#[derive(Clone)]
#[allow(
    dead_code,
    reason = "several fields are consumed by the OTLP provider builder added in the next change"
)]
pub struct TelemetryConfig {
    pub(crate) service_name: String,
    pub(crate) service_version: String,
    pub(crate) process_role: String,
    pub(crate) traces: Option<SignalEndpoint>,
    pub(crate) logs: Option<SignalEndpoint>,
    pub(crate) metrics: Option<SignalEndpoint>,
    pub(crate) sampler: SamplerConfig,
    pub(crate) resource_attributes: Vec<(String, String)>,
    pub(crate) span_batch: BatchConfig,
    pub(crate) log_batch: BatchConfig,
    pub(crate) metric_interval: Duration,
    pub(crate) metric_timeout: Duration,
}

impl fmt::Debug for TelemetryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelemetryConfig")
            .field("traces", &self.traces.is_some())
            .field("logs", &self.logs.is_some())
            .field("metrics", &self.metrics.is_some())
            .field("sampler", &self.sampler)
            .finish_non_exhaustive()
    }
}

impl TelemetryConfig {
    /// Parse telemetry configuration from the process environment.
    ///
    /// Export is disabled unless an OTLP endpoint is configured. Malformed
    /// explicit configuration fails with a fixed message that never echoes the
    /// offending endpoint, header, or resource value.
    pub fn from_env(
        service_name: &'static str,
        service_version: &'static str,
        process_role: &'static str,
    ) -> anyhow::Result<Self> {
        let service_name = match non_empty_var("OTEL_SERVICE_NAME") {
            Some(value) => {
                validate_ascii_value(&value, "invalid OTEL service name")?;
                value
            }
            None => service_name.to_string(),
        };

        let general_endpoint = non_empty_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        let general_protocol = non_empty_var("OTEL_EXPORTER_OTLP_PROTOCOL");
        let general_insecure = optional_bool("OTEL_EXPORTER_OTLP_INSECURE")?;
        let general_headers = non_empty_var("OTEL_EXPORTER_OTLP_HEADERS");
        let general_timeout = non_empty_var("OTEL_EXPORTER_OTLP_TIMEOUT");

        let traces = SignalEndpoint::resolve(
            Signal::Traces,
            general_endpoint.as_deref(),
            general_protocol.as_deref(),
            general_insecure,
            general_headers.as_deref(),
            general_timeout.as_deref(),
        )?;
        let logs = SignalEndpoint::resolve(
            Signal::Logs,
            general_endpoint.as_deref(),
            general_protocol.as_deref(),
            general_insecure,
            general_headers.as_deref(),
            general_timeout.as_deref(),
        )?;
        let metrics = SignalEndpoint::resolve(
            Signal::Metrics,
            general_endpoint.as_deref(),
            general_protocol.as_deref(),
            general_insecure,
            general_headers.as_deref(),
            general_timeout.as_deref(),
        )?;

        let sampler = resolve_sampler()?;
        let resource_attributes = resolve_resource_attributes()?;
        let span_batch = BatchConfig::new(
            non_empty_var("OTEL_BSP_MAX_QUEUE_SIZE").as_deref(),
            non_empty_var("OTEL_BSP_SCHEDULE_DELAY").as_deref(),
            non_empty_var("OTEL_BSP_MAX_EXPORT_BATCH_SIZE").as_deref(),
            non_empty_var("OTEL_BSP_EXPORT_TIMEOUT").as_deref(),
        )?;
        let log_batch = BatchConfig::new(
            non_empty_var("OTEL_BLRP_MAX_QUEUE_SIZE").as_deref(),
            non_empty_var("OTEL_BLRP_SCHEDULE_DELAY").as_deref(),
            non_empty_var("OTEL_BLRP_MAX_EXPORT_BATCH_SIZE").as_deref(),
            non_empty_var("OTEL_BLRP_EXPORT_TIMEOUT").as_deref(),
        )?;
        let metric_interval = parse_bounded_ms(
            non_empty_var("OTEL_METRIC_EXPORT_INTERVAL").as_deref(),
            DEFAULT_METRIC_INTERVAL_MS,
            MIN_METRIC_INTERVAL_MS,
            MAX_METRIC_INTERVAL_MS,
            "invalid OTEL metric export interval",
        )?;
        let metric_timeout = parse_bounded_ms(
            non_empty_var("OTEL_METRIC_EXPORT_TIMEOUT").as_deref(),
            DEFAULT_EXPORT_TIMEOUT_MS,
            MIN_EXPORT_TIMEOUT_MS,
            MAX_EXPORT_TIMEOUT_MS,
            "invalid OTEL metric export timeout",
        )?;

        Ok(Self {
            service_name,
            service_version: service_version.to_string(),
            process_role: process_role.to_string(),
            traces,
            logs,
            metrics,
            sampler,
            resource_attributes,
            span_batch,
            log_batch,
            metric_interval,
            metric_timeout,
        })
    }

    pub fn export_enabled(&self) -> bool {
        self.traces.is_some() || self.logs.is_some() || self.metrics.is_some()
    }

    pub fn signal_enabled(&self, signal: Signal) -> bool {
        match signal {
            Signal::Traces => self.traces.is_some(),
            Signal::Logs => self.logs.is_some(),
            Signal::Metrics => self.metrics.is_some(),
        }
    }
}

impl SignalEndpoint {
    fn resolve(
        signal: Signal,
        general_endpoint: Option<&str>,
        general_protocol: Option<&str>,
        general_insecure: Option<bool>,
        general_headers: Option<&str>,
        general_timeout: Option<&str>,
    ) -> anyhow::Result<Option<Self>> {
        let exporter = non_empty_var(signal.exporter_var());
        if let Some(value) = exporter.as_deref() {
            match value {
                "otlp" => {}
                "none" => return Ok(None),
                _ => anyhow::bail!("invalid OTEL exporter selection"),
            }
        }

        let endpoint =
            non_empty_var(signal.endpoint_var()).or_else(|| general_endpoint.map(str::to_string));
        let Some(endpoint) = endpoint else {
            return Ok(None);
        };

        let protocol =
            non_empty_var(signal.protocol_var()).or_else(|| general_protocol.map(str::to_string));
        let protocol = protocol.as_deref().unwrap_or("http/protobuf");
        if protocol != "http/protobuf" {
            anyhow::bail!("unsupported OTEL protocol; only http/protobuf is accepted");
        }

        let insecure = optional_bool(signal.insecure_var())?
            .or(general_insecure)
            .unwrap_or(false);
        let scheme_https = endpoint.starts_with("https://");
        let scheme_http = endpoint.starts_with("http://");
        if !scheme_https && !scheme_http {
            anyhow::bail!("invalid OTLP endpoint; an http or https URL is required");
        }
        if scheme_http && !insecure {
            anyhow::bail!("plaintext OTLP endpoint requires an explicit insecure flag");
        }
        if scheme_https && insecure {
            anyhow::bail!("HTTPS OTLP endpoint cannot be marked insecure");
        }
        if scheme_https || scheme_http {
            let host = endpoint
                .split_once("://")
                .map(|(_, rest)| rest)
                .unwrap_or_default();
            if host.is_empty() || host.starts_with('/') {
                anyhow::bail!("invalid OTLP endpoint; a host is required");
            }
        }

        let mut headers = parse_headers(general_headers)?;
        if let Some(specific) = non_empty_var(signal.headers_var()) {
            headers.extend(parse_headers(Some(&specific))?);
        }

        let timeout_ms =
            non_empty_var(signal.timeout_var()).or_else(|| general_timeout.map(str::to_string));
        let timeout = parse_bounded_ms(
            timeout_ms.as_deref(),
            DEFAULT_EXPORT_TIMEOUT_MS,
            MIN_EXPORT_TIMEOUT_MS,
            MAX_EXPORT_TIMEOUT_MS,
            "invalid OTEL export timeout",
        )?;

        Ok(Some(Self {
            endpoint,
            insecure,
            headers,
            timeout,
        }))
    }
}

impl Signal {
    fn exporter_var(self) -> &'static str {
        match self {
            Signal::Traces => "OTEL_TRACES_EXPORTER",
            Signal::Logs => "OTEL_LOGS_EXPORTER",
            Signal::Metrics => "OTEL_METRICS_EXPORTER",
        }
    }

    fn endpoint_var(self) -> &'static str {
        match self {
            Signal::Traces => "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            Signal::Logs => "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
            Signal::Metrics => "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
        }
    }

    fn protocol_var(self) -> &'static str {
        match self {
            Signal::Traces => "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
            Signal::Logs => "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
            Signal::Metrics => "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
        }
    }

    fn insecure_var(self) -> &'static str {
        match self {
            Signal::Traces => "OTEL_EXPORTER_OTLP_TRACES_INSECURE",
            Signal::Logs => "OTEL_EXPORTER_OTLP_LOGS_INSECURE",
            Signal::Metrics => "OTEL_EXPORTER_OTLP_METRICS_INSECURE",
        }
    }

    fn headers_var(self) -> &'static str {
        match self {
            Signal::Traces => "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
            Signal::Logs => "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
            Signal::Metrics => "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
        }
    }

    fn timeout_var(self) -> &'static str {
        match self {
            Signal::Traces => "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT",
            Signal::Logs => "OTEL_EXPORTER_OTLP_LOGS_TIMEOUT",
            Signal::Metrics => "OTEL_EXPORTER_OTLP_METRICS_TIMEOUT",
        }
    }
}

fn non_empty_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn optional_bool(name: &str) -> anyhow::Result<Option<bool>> {
    match non_empty_var(name).as_deref() {
        None => Ok(None),
        Some("true") => Ok(Some(true)),
        Some("false") => Ok(Some(false)),
        Some(_) => anyhow::bail!("invalid boolean telemetry setting"),
    }
}

fn parse_bounded_usize(
    value: Option<&str>,
    default: usize,
    min: usize,
    max: usize,
    error: &'static str,
) -> anyhow::Result<usize> {
    match value {
        None => Ok(default),
        Some(raw) => {
            let parsed: usize = raw.parse().map_err(|_| anyhow::anyhow!(error))?;
            if parsed < min || parsed > max {
                anyhow::bail!(error);
            }
            Ok(parsed)
        }
    }
}

fn parse_bounded_ms(
    value: Option<&str>,
    default: u64,
    min: u64,
    max: u64,
    error: &'static str,
) -> anyhow::Result<Duration> {
    match value {
        None => Ok(Duration::from_millis(default)),
        Some(raw) => {
            let parsed: u64 = raw.parse().map_err(|_| anyhow::anyhow!(error))?;
            if parsed < min || parsed > max {
                anyhow::bail!(error);
            }
            Ok(Duration::from_millis(parsed))
        }
    }
}

fn parse_headers(value: Option<&str>) -> anyhow::Result<Vec<(String, String)>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let mut headers = Vec::new();
    for pair in value.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some((name, header_value)) = pair.split_once('=') else {
            anyhow::bail!("invalid OTEL headers syntax");
        };
        let name = name.trim();
        if name.is_empty() || !name.bytes().all(is_http_token_byte) {
            anyhow::bail!("invalid OTEL headers syntax");
        }
        if header_value
            .bytes()
            .any(|byte| byte == b'\r' || byte == b'\n')
        {
            anyhow::bail!("invalid OTEL headers syntax");
        }
        headers.push((name.to_string(), header_value.trim().to_string()));
        if headers.len() > MAX_HEADER_PAIRS {
            anyhow::bail!("invalid OTEL headers syntax");
        }
    }
    Ok(headers)
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn resolve_sampler() -> anyhow::Result<SamplerConfig> {
    let name = non_empty_var("OTEL_TRACES_SAMPLER");
    let arg = non_empty_var("OTEL_TRACES_SAMPLER_ARG");
    let sampler = match name.as_deref() {
        None => Sampler::ParentBasedTraceIdRatio,
        Some("always_on") => Sampler::AlwaysOn,
        Some("always_off") => Sampler::AlwaysOff,
        Some("traceidratio") => Sampler::TraceIdRatio,
        Some("parentbased_always_on") => Sampler::ParentBasedAlwaysOn,
        Some("parentbased_always_off") => Sampler::ParentBasedAlwaysOff,
        Some("parentbased_traceidratio") => Sampler::ParentBasedTraceIdRatio,
        Some(_) => anyhow::bail!("unsupported OTEL trace sampler"),
    };
    let ratio = match arg {
        None => 0.1_f64,
        Some(raw) => raw
            .parse::<f64>()
            .map_err(|_| anyhow::anyhow!("invalid OTEL trace sampler argument"))?,
    };
    if !(ratio > 0.0 && ratio <= 1.0) {
        anyhow::bail!("invalid OTEL trace sampler argument");
    }
    Ok(SamplerConfig { sampler, ratio })
}

fn resolve_resource_attributes() -> anyhow::Result<Vec<(String, String)>> {
    let Some(raw) = non_empty_var("OTEL_RESOURCE_ATTRIBUTES") else {
        return Ok(Vec::new());
    };
    let mut attributes: Vec<(String, String)> = Vec::new();
    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some((key, value)) = pair.split_once('=') else {
            anyhow::bail!("invalid OTEL resource attributes");
        };
        let key = key.trim();
        if RESERVED_RESOURCE_KEYS.contains(&key) || !ALLOWED_RESOURCE_KEYS.contains(&key) {
            anyhow::bail!("disallowed OTEL resource attribute");
        }
        validate_ascii_value(value, "invalid OTEL resource attribute value")?;
        if attributes.iter().any(|(existing, _)| existing == key) {
            anyhow::bail!("duplicate OTEL resource attribute");
        }
        attributes.push((key.to_string(), value.trim().to_string()));
    }
    Ok(attributes)
}

fn validate_ascii_value(value: &str, error: &'static str) -> anyhow::Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_ATTRIBUTE_VALUE_LEN
        || !trimmed.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        anyhow::bail!(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    const ENV_VARS: [&str; 37] = [
        "OTEL_SERVICE_NAME",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_PROTOCOL",
        "OTEL_EXPORTER_OTLP_INSECURE",
        "OTEL_EXPORTER_OTLP_HEADERS",
        "OTEL_EXPORTER_OTLP_TIMEOUT",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
        "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
        "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
        "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
        "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
        "OTEL_EXPORTER_OTLP_TRACES_INSECURE",
        "OTEL_EXPORTER_OTLP_LOGS_INSECURE",
        "OTEL_EXPORTER_OTLP_METRICS_INSECURE",
        "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
        "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
        "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
        "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT",
        "OTEL_EXPORTER_OTLP_LOGS_TIMEOUT",
        "OTEL_EXPORTER_OTLP_METRICS_TIMEOUT",
        "OTEL_TRACES_EXPORTER",
        "OTEL_LOGS_EXPORTER",
        "OTEL_METRICS_EXPORTER",
        "OTEL_RESOURCE_ATTRIBUTES",
        "OTEL_TRACES_SAMPLER",
        "OTEL_TRACES_SAMPLER_ARG",
        "OTEL_BSP_MAX_QUEUE_SIZE",
        "OTEL_BSP_SCHEDULE_DELAY",
        "OTEL_BSP_MAX_EXPORT_BATCH_SIZE",
        "OTEL_BSP_EXPORT_TIMEOUT",
        "OTEL_BLRP_MAX_QUEUE_SIZE",
        "OTEL_BLRP_SCHEDULE_DELAY",
        "OTEL_BLRP_MAX_EXPORT_BATCH_SIZE",
        "OTEL_BLRP_EXPORT_TIMEOUT",
        "OTEL_METRIC_EXPORT_INTERVAL",
        "OTEL_METRIC_EXPORT_TIMEOUT",
    ];

    struct EnvScope {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvScope {
        fn new(vars: &[(&str, &str)]) -> Self {
            let saved = ENV_VARS
                .iter()
                .map(|name| (*name, std::env::var(name).ok()))
                .collect();
            for name in ENV_VARS {
                unsafe { std::env::remove_var(name) };
            }
            for (name, value) in vars {
                unsafe { std::env::set_var(name, value) };
            }
            Self { saved }
        }
    }

    impl Drop for EnvScope {
        fn drop(&mut self) {
            for (name, value) in &self.saved {
                match value {
                    Some(value) => unsafe { std::env::set_var(name, value) },
                    None => unsafe { std::env::remove_var(name) },
                }
            }
        }
    }

    fn config() -> TelemetryConfig {
        TelemetryConfig::from_env("maskura-gateway", "0.7.8", "gateway").unwrap()
    }

    #[test]
    fn export_is_disabled_without_an_endpoint() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _scope = EnvScope::new(&[]);
        let config = config();
        assert!(!config.export_enabled());
        assert!(!config.signal_enabled(Signal::Traces));
        assert!(!config.signal_enabled(Signal::Logs));
        assert!(!config.signal_enabled(Signal::Metrics));
        assert_eq!(config.service_name, "maskura-gateway");
        assert_eq!(config.process_role, "gateway");
        assert_eq!(config.sampler.sampler, Sampler::ParentBasedTraceIdRatio);
        assert!((config.sampler.ratio - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn general_endpoint_enables_all_signals() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _scope = EnvScope::new(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4318")]);
        let config = config();
        assert!(config.export_enabled());
        assert!(config.signal_enabled(Signal::Traces));
        assert!(config.signal_enabled(Signal::Logs));
        assert!(config.signal_enabled(Signal::Metrics));
    }

    #[test]
    fn signal_endpoint_enables_only_that_signal() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _scope =
            EnvScope::new(&[("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "https://collector:4318")]);
        let config = config();
        assert!(!config.signal_enabled(Signal::Traces));
        assert!(config.signal_enabled(Signal::Logs));
        assert!(!config.signal_enabled(Signal::Metrics));
    }

    #[test]
    fn exporter_none_disables_one_signal() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _scope = EnvScope::new(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4318"),
            ("OTEL_METRICS_EXPORTER", "none"),
        ]);
        let config = config();
        assert!(config.signal_enabled(Signal::Traces));
        assert!(config.signal_enabled(Signal::Logs));
        assert!(!config.signal_enabled(Signal::Metrics));
    }

    #[test]
    fn rejects_non_http_protobuf_protocol() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _scope = EnvScope::new(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4318"),
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc"),
        ]);
        assert!(TelemetryConfig::from_env("s", "1", "r").is_err());
    }

    #[test]
    fn plaintext_requires_explicit_insecure() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _scope = EnvScope::new(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")]);
        assert!(TelemetryConfig::from_env("s", "1", "r").is_err());

        let _scope = EnvScope::new(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318"),
            ("OTEL_EXPORTER_OTLP_INSECURE", "true"),
        ]);
        assert!(TelemetryConfig::from_env("s", "1", "r").is_ok());
    }

    #[test]
    fn https_rejects_insecure_flag() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _scope = EnvScope::new(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4318"),
            ("OTEL_EXPORTER_OTLP_INSECURE", "true"),
        ]);
        assert!(TelemetryConfig::from_env("s", "1", "r").is_err());
    }

    #[test]
    fn parses_headers_and_timeout() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _scope = EnvScope::new(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4318"),
            (
                "OTEL_EXPORTER_OTLP_HEADERS",
                "authorization=Bearer abc,x-tenant=one",
            ),
            ("OTEL_EXPORTER_OTLP_TIMEOUT", "2500"),
        ]);
        let config = config();
        let traces = config.traces.unwrap();
        assert_eq!(traces.headers.len(), 2);
        assert_eq!(traces.headers[0].0, "authorization");
        assert_eq!(traces.timeout, Duration::from_millis(2500));
    }

    #[test]
    fn rejects_malformed_headers() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _scope = EnvScope::new(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4318"),
            ("OTEL_EXPORTER_OTLP_HEADERS", "not-a-pair"),
        ]);
        assert!(TelemetryConfig::from_env("s", "1", "r").is_err());
    }

    #[test]
    fn sampler_and_ratio_are_validated() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _scope = EnvScope::new(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4318"),
            ("OTEL_TRACES_SAMPLER", "traceidratio"),
            ("OTEL_TRACES_SAMPLER_ARG", "0.25"),
        ]);
        let config = config();
        assert_eq!(config.sampler.sampler, Sampler::TraceIdRatio);
        assert!((config.sampler.ratio - 0.25).abs() < f64::EPSILON);

        let _scope = EnvScope::new(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4318"),
            ("OTEL_TRACES_SAMPLER_ARG", "0"),
        ]);
        assert!(TelemetryConfig::from_env("s", "1", "r").is_err());
    }

    #[test]
    fn resource_allowlist_is_enforced() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _scope = EnvScope::new(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4318"),
            (
                "OTEL_RESOURCE_ATTRIBUTES",
                "cloud.region=us-east-1,cloud.provider=aws",
            ),
        ]);
        let config = config();
        assert_eq!(config.resource_attributes.len(), 2);

        let _scope = EnvScope::new(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4318"),
            (
                "OTEL_RESOURCE_ATTRIBUTES",
                "maskura.workspace=secret-workspace",
            ),
        ]);
        assert!(TelemetryConfig::from_env("s", "1", "r").is_err());

        let _scope = EnvScope::new(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4318"),
            ("OTEL_RESOURCE_ATTRIBUTES", "service.name=override"),
        ]);
        assert!(TelemetryConfig::from_env("s", "1", "r").is_err());
    }

    #[test]
    fn secrets_never_appear_in_errors_or_debug() {
        let _guard = ENV_LOCK.lock().unwrap();
        let sentinel = "SENTINEL-abc123-def456";
        let _scope = EnvScope::new(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector:4318"),
            (
                "OTEL_EXPORTER_OTLP_HEADERS",
                &format!("authorization={sentinel}"),
            ),
        ]);
        let config = config();
        let debug = format!("{config:?}");
        assert!(!debug.contains(sentinel), "Debug leaked a header value");
        assert!(debug.contains("traces: true"));

        let _scope =
            EnvScope::new(&[("OTEL_EXPORTER_OTLP_ENDPOINT", &format!("ftp://{sentinel}"))]);
        let error = TelemetryConfig::from_env("s", "1", "r").unwrap_err();
        assert!(!format!("{error}").contains(sentinel));
    }
}
