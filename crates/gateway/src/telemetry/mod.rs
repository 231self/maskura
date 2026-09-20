//! Safe OpenTelemetry observability for the gateway.
//!
//! This module owns the OTLP trust boundary: it validates configuration, builds
//! local and remote providers, instruments the fully composed router, and
//! accounts for the full response lifecycle. Remote records are restricted to a
//! fixed allowlist so customer paths, queries, headers, credentials, and error
//! text can never reach a collector.
//!
//! Design:
//! `docs/superpowers/specs/2026-09-19-safe-otel-observability-design.md`.

pub mod config;
mod http;
mod http_client;
mod logging;
mod provider;
#[allow(
    dead_code,
    reason = "consumed by the OTLP provider builder and HTTP instrumentation added in later changes"
)]
mod schema;
mod serve;

pub use config::{Sampler, SamplerConfig, TelemetryConfig};
pub use http::instrument_router;
pub use provider::{TelemetryHandle, init_local_logging, init_telemetry};
pub use serve::serve_with_telemetry;
