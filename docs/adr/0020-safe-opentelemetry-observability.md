# ADR 0020: Safe OpenTelemetry observability

- Status: Accepted
- Date: 2026-09-20

## Context

The gateway emitted reviewed `tracing` events, but each process installed a
fixed formatter with no request correlation, no runtime format controls, no
OpenTelemetry exporters, and no operational metrics. Operators could not
correlate a request end to end, and there was no sanctioned way to ship traces,
logs, or HTTP RED metrics to a collector.

Telemetry is high-risk in an S3 data plane: concrete request paths, query
strings, authorization headers, API and MCP credentials, presigned URLs, user
agents, and raw error text are all capable of carrying customer or credential
data. A generic exporter that forwards `tracing` fields would leak them.

## Decision

Add server-owned correlation and a fixed-schema OTLP HTTP/protobuf export path,
isolated behind an explicit trust boundary.

- **Server-owned correlation.** The outermost middleware, applied only after the
  complete router is composed, removes any inbound `x-maskura-request-id`,
  ignores `traceparent`/`tracestate`, generates a UUIDv7 request ID, and returns
  it on every Axum-produced response. Protocol errors rejected by Hyper before
  Axum admission are outside the boundary.
- **One reviewed span.** A single module-owned `HTTP request` server span is
  created with `parent: None`. It carries only six allowlisted attributes
  (`maskura.request.id`, `http.request.method`, `http.route`,
  `http.response.status_code`, `maskura.http.status_class`,
  `maskura.http.outcome`). Because `tracing` field names cannot contain dots, the
  dotted attributes are written directly on the OTel span from typed enums.
  `http.route` is the matched template or `unmatched`.
- **Typed completion log.** One `http.server.request.completed` record is emitted
  directly through a private logger with exactly `request_id`, `method`,
  `route`, `status_class`, `outcome`, and `duration_ms`, plus trace/span IDs from
  the server-owned span. Generic `tracing` events never enter OTLP logs.
- **Bounded metrics.** `maskura.http.server.active_requests` (up/down),
  `maskura.http.server.completed_requests` (counter), and
  `maskura.http.server.request.duration` (seconds histogram) use only
  normalized method, matched route, status class, and outcome. Active-request
  increment and decrement use the identical method+route attribute set.
- **Strict resource.** The resource always carries `service.name`,
  `service.version`, and `maskura.process.role`, plus an allowlisted set of
  optional attributes; any other key, duplicate reserved key, or unbounded value
  fails startup.
- **Async sanitizing client.** Maskura implements `SanitizingHttpClient` against
  `opentelemetry_http::HttpClient` using the workspace's existing async Reqwest
  0.12, so no second Reqwest version or blocking client is introduced. Transport
  errors are opaque and collector response bodies are stripped. The SDK's
  async-runtime batch span/log processors and async-runtime periodic reader are
  enabled and constructed with `runtime::Tokio`; the default thread-based
  processors cannot drive an async HTTP client.
- **Failure isolation.** Export is disabled unless an endpoint is configured.
  Collector failures occur in background workers and never affect request
  futures, health, readiness, billing, or reconciliation. Shutdown drains within
  a fixed deadline, drops the serve future at the deadline, then flushes within
  its own deadline; either timeout logs one fixed local warning.
- **Local controls.** `MASKURA_LOG_FORMAT=text|json` and
  `MASKURA_LOG_LEVEL=error|warn|info|debug` apply only to Maskura targets;
  dependency targets stay capped at WARN and OTEL/HTTP-client targets are fully
  suppressed, including WARN and ERROR.

## Rejected alternatives

- OpenTelemetry 0.31: its SDK log-export pipeline is gated behind
  `spec_unstable_logs_enabled`, so logs could not be exported ungated.
- Enabling the OTLP crates' built-in Reqwest features: they pull Reqwest 0.13,
  creating two incompatible `HttpClient` type identities against the workspace's
  0.12.28.
- A generic `tracing` to OTLP appender: it would forward application events and
  arbitrary fields, which cannot be bounded to a reviewed schema.
- A public `/metrics` or Prometheus endpoint: it would add an unauthenticated
  surface and a second export format.

## Consequences

The code contract is vendor-neutral OTLP HTTP/protobuf. Collector vendor,
production endpoint, credentials, retention, and alert rules are deferred to a
separately reviewed operations change; enabling export is not implied by merging
code. Later phases (presigned delegation, ingress deadlines, panic containment,
restrictive hosted CORS, and a shared internal error taxonomy) remain separate
increments.
