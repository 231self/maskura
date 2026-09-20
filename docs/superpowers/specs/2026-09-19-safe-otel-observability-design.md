# Safe OpenTelemetry observability design

Status: Approved

Date: 2026-09-19

Related: private issue `231self/maskura-private#234`, public PR #167

## Problem

The gateway emits reviewed `tracing` events, but each process installs a fixed
human-readable INFO subscriber. There are no request spans, universal request
IDs, runtime format controls, OpenTelemetry exporters, or operational metrics.
Existing operation and receipt IDs serve durable metering and idempotency; they
do not identify every HTTP attempt and cannot be reused as request IDs.

Adding a generic HTTP trace layer or exporting every existing log is unsafe.
Concrete S3 paths contain customer bucket and object identities. Headers and
queries can contain credentials and signed URLs. Local startup logs may contain
operator paths, and the zero-configuration local appliance has one deliberate
first-start credential-log exception. None of those values may reach a remote
telemetry backend.

## Goals

- Give every Axum-admitted HTTP request a server-generated correlation ID.
- Export safe server-root traces, dedicated completion logs, and HTTP RED
  metrics over OTLP HTTP/protobuf.
- Measure the full response-body lifecycle, including streaming completion,
  body errors, and client cancellation.
- Keep every exported field and metric attribute on an explicit allowlist.
- Use standard OTEL exporter, service, resource, timeout, and sampler variables
  where they do not weaken Maskura's security boundary.
- Keep export disabled unless an OTLP endpoint is explicitly configured.
- Preserve request availability when a collector is unavailable.
- Fail startup on malformed explicit telemetry configuration without echoing
  endpoints, headers, or resource values.
- Provide one public initialization API used first by `maskura-gateway` and
  later by the private `s4-control` embedding.
- Preserve useful local text logs and add safe JSON output with constrained
  level controls.

## Non-goals

- Prometheus or a public `/metrics` endpoint.
- Exporting all existing application or dependency logs.
- Continuing caller-provided `traceparent` or `tracestate` context.
- Adding customer, user, workspace, credential, bucket, object, provider,
  endpoint, plugin, operation, or receipt identities to telemetry attributes.
- Storage, reconciliation, authentication, billing, or pipeline-runtime
  metrics in this increment.
- Replacing durable usage, receipt, audit, or pipeline-cost evidence with
  telemetry.
- Making collector availability part of gateway readiness.

## Security invariants

1. **Server-owned context.** Request and trace identities are generated inside
   Maskura. Inbound request IDs and W3C trace context are ignored.
2. **Template routes only.** Telemetry uses an Axum matched route template or
   the constant `unmatched`; it never reads a concrete URI for recording.
3. **Dedicated remote logs.** The lifecycle finalizer constructs OTEL log
   records directly from a typed fixed schema. Generic `tracing` events never
   enter the OTLP log pipeline.
4. **No generic event attachment.** The OTEL trace layer accepts only the exact
   request-span metadata and field set; it rejects all events. Existing request,
   startup, SDK, database, and background spans/events remain local until
   separately reviewed.
5. **Bounded attributes.** Metric labels and span/log categorical fields come
   from fixed enums or application-owned route templates.
6. **Secrets stay opaque.** Exporter headers and endpoint values have redacted
   `Debug` output and are never included in validation or transport errors.
7. **Telemetry is not authority.** Traces, logs, and metrics can be sampled,
   delayed, duplicated, or lost without changing request, billing, audit, or
   recovery outcomes.
8. **Exporter failure is off-path.** Collector failures never fail, delay, or
   cancel a customer request.

## Public module boundary

Add `s4_gateway::telemetry` with these public concepts:

```rust
pub struct TelemetryConfig { /* redacted fields */ }

impl TelemetryConfig {
    pub fn from_env(
        service_name: &'static str,
        service_version: &'static str,
        process_role: &'static str,
    ) -> anyhow::Result<Self>;
}

pub struct TelemetryHandle { /* tracer, logger, and meter providers */ }

pub fn init_telemetry(config: TelemetryConfig) -> anyhow::Result<TelemetryHandle>;

pub fn instrument_router(
    router: axum::Router,
    telemetry: &TelemetryHandle,
) -> axum::Router;
```

`TelemetryHandle` owns all providers and exposes a bounded explicit shutdown
operation. Its `Drop` implementation is best effort only. Binaries must retain
the handle until serving and background work stop, then invoke explicit
shutdown.

The module also owns the request middleware, response-body wrapper, safe
completion schema, and HTTP instruments. Each final process calls
`instrument_router` only after it has merged every engine and process-specific
route. This is load-bearing: an inner layer added by `build_router` would not
cover private routes merged later by `s4-control`. When exporters are disabled,
request IDs and local completion events still work while OTEL providers use
no-op exporters.

The module remains inside `maskura-gateway` rather than creating a one-caller
workspace crate. It has two process consumers: the public gateway binary and
the private control-plane embedding.

Internally, construction is split from process-global installation. A builder
returns the subscriber layers, providers, instruments, and shutdown state;
`init_telemetry` installs that subscriber globally. Unit tests use scoped
dispatches and injected in-memory exporters, so repeated tests do not compete
for the one process-global subscriber slot.

## Configuration

### OTEL enablement

No remote exporter is created unless at least one of these is present:

- `OTEL_EXPORTER_OTLP_ENDPOINT`
- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`
- `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`
- `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`

The general endpoint enables all signals unless a signal-specific exporter is
set to `none`. A signal-specific endpoint enables only that signal when no
general endpoint exists.

Supported standard variables are:

| Area | Variables | Rules |
|---|---|---|
| Protocol | `OTEL_EXPORTER_OTLP_PROTOCOL` and signal-specific protocol variables | Only `http/protobuf` is accepted. Any other explicit value fails startup. |
| Transport security | `OTEL_EXPORTER_OTLP_INSECURE` and signal-specific insecure variables | Defaults to `false`; HTTP endpoints require explicit `true`. HTTPS with `true` is rejected. |
| Headers | General and signal-specific `OTEL_EXPORTER_OTLP_*HEADERS` | Passed to the exporter, never rendered or logged. Invalid syntax fails with a fixed message. |
| Timeouts | General and signal-specific OTLP timeout variables | Positive bounded durations only. |
| Exporters | `OTEL_TRACES_EXPORTER`, `OTEL_LOGS_EXPORTER`, `OTEL_METRICS_EXPORTER` | `otlp` and `none` only. |
| Service | `OTEL_SERVICE_NAME` | Optional non-empty bounded ASCII value; defaults to the process-provided name. |
| Resource | `OTEL_RESOURCE_ATTRIBUTES` | Parsed strictly and restricted to the allowlist below. |
| Sampling | `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | Supported values are listed below. |
| Batching | Standard batch span/log processor queue, delay, batch, and timeout variables | Positive bounded values only. |
| Metrics | `OTEL_METRIC_EXPORT_INTERVAL`, `OTEL_METRIC_EXPORT_TIMEOUT` | Positive bounded values only. |

The resource always contains process-provided `service.name`,
`service.version`, and `maskura.process.role`. Operator resource attributes may
use only:

- `service.namespace`
- `service.instance.id`
- `deployment.environment.name`
- `cloud.provider`
- `cloud.region`
- `cloud.availability_zone`

Duplicate reserved keys or any other key fail startup. Values must be bounded
printable ASCII and are never copied into local diagnostics.

Supported samplers are `always_on`, `always_off`, `traceidratio`,
`parentbased_always_on`, `parentbased_always_off`, and
`parentbased_traceidratio`. The default is `parentbased_traceidratio` with
ratio `0.1`. Because inbound parent context is ignored, every public HTTP
request is created with `parent: None`. Any future reviewed child spans on the
dedicated telemetry target inherit the root decision; existing application
spans are not remotely exported.

### Local logs

Maskura-specific local controls are intentionally separate from OTLP settings:

- `MASKURA_LOG_FORMAT=text|json`, default `text`
- `MASKURA_LOG_LEVEL=error|warn|info|debug`, default `info`

The selected level applies only to Maskura-owned targets. Dependency targets
remain capped at WARN so an operator cannot accidentally enable verbose AWS,
HTTP, TLS, SQL, or exporter diagnostics containing unreviewed values. The MCP
stdio binary continues writing local logs to stderr.

## Subscriber and provider composition

`init_telemetry` installs one `tracing_subscriber::Registry` with independent
per-layer filters:

1. A text or JSON local formatting layer receives Maskura events at the
   configured level and dependencies at WARN or above.
2. A `tracing-opentelemetry` layer receives only a span whose metadata is the
   exact module-owned request-span callsite (target `maskura.telemetry`, name
   `HTTP request`, kind server). The filter rejects every event and every other
   span. Because `tracing` field names cannot contain dots, the span carries no
   exported fields; the six dotted semantic attributes are set directly on the
   OTel span through `opentelemetry::trace::Span::set_attribute` from typed
   enums, so no arbitrary field name can reach the exporter.
3. The typed lifecycle finalizer writes one OTEL log record directly through a
   private `Logger`, with explicit trace/span context and the fixed fields below.
   It separately emits the equivalent reviewed local `tracing` event.

The tracer, logger, and meter providers share the same validated resource and
OTLP HTTP client configuration but own separate batch processors and exporters.
No endpoint or header value is stored in an error type that implements a
revealing `Display` or `Debug`.

The first implementation pins this family:

- `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`, and
  `opentelemetry-http` 0.32
- `tracing-opentelemetry` 0.33, which depends on `opentelemetry` 0.32

0.32 is chosen deliberately over 0.31: in 0.31 the SDK log-export pipeline is
gated behind the `spec_unstable_logs_enabled` flag, while 0.32 ships the logs
signal ungated. It is also chosen over the built-in Reqwest client features:
`opentelemetry-http` 0.32 pulls Reqwest 0.13, but the workspace pins 0.12.28.
Installing the crate's `reqwest` features would create two incompatible
`HttpClient` type identities.

Instead, Maskura implements `SanitizingHttpClient` directly against the
`opentelemetry_http::HttpClient` trait using the workspace's existing async
Reqwest 0.12 client, and injects it with the OTLP exporter's
`with_http_client`. Default features are disabled. `opentelemetry-otlp` enables
only `http-proto`, `trace`, `metrics`, and `logs`; `opentelemetry-http` enables
no client feature; SDK `internal-logs` and gRPC are not enabled. Because
`HttpClient::send_bytes` is async in 0.32, collector I/O runs on SDK-owned
runtime tasks with no extra blocking thread and no second Reqwest version. The
default thread-based batch processors cannot drive an async HTTP client, so the
SDK's async-runtime trace batch processor, async-runtime log batch processor, and
async-runtime periodic metric reader features are enabled and constructed with
`opentelemetry_sdk::runtime::Tokio`. Provider construction therefore requires a
Tokio runtime; the public process and every private command build providers
inside their runtime. The trace layer explicitly disables target, thread,
source-location, level, tracked-inactivity, and automatic error/exception
enrichment. Trace events are disabled entirely; completion is represented by
final span attributes/status and the separate typed OTEL log record.

A `SanitizingHttpClient` wraps the OTLP HTTP client. It maps transport errors to
an opaque error and strips collector response bodies before the exporter can
render them. OTEL and HTTP-client dependency targets are fully suppressed from
the local formatting layer, including WARN and ERROR. Initialization, flush,
and shutdown map SDK errors to fixed local categories such as
`telemetry.export_failed` with only the signal kind. Raw transport errors,
collector response bodies, URLs, headers, and resource values are discarded.

## Request lifecycle

### Admission

The outermost router middleware, applied after final route composition:

1. Removes any inbound `x-maskura-request-id` value.
2. Ignores `traceparent` and `tracestate`; they are neither parsed nor logged.
3. Generates a UUIDv7 request ID.
4. Normalizes the request method to `GET`, `HEAD`, `PUT`, `POST`, `DELETE`,
   `OPTIONS`, `PATCH`, or `OTHER`.
5. Reads only Axum's application-owned matched route template. Absence becomes
   `unmatched`.
6. Increments active requests and starts a new `HTTP request` server span with
   `parent: None` on the dedicated target.
7. Creates a synchronous RAII finalizer before awaiting the handler and
   instruments the handler future with the server span.

The middleware must enclose unsupported-S3 rejection, CORS, authentication,
dashboard, health, readiness, hosted MCP, private control-plane, and fallback
responses so every Axum-produced response carries correlation. Protocol errors
rejected by Hyper before Axum admission are outside this boundary. The layer
must not change route matching or body limits.

### Response

When response headers are available, the middleware:

- replaces any handler-supplied `x-maskura-request-id` with the generated ID,
- records the exact bounded HTTP status code on the trace,
- derives a fixed `1xx` through `5xx` status class for logs and metrics, and
- transfers the RAII finalizer and final span handle into a response-body
  wrapper.

If the handler future is dropped before producing response headers, the
pre-response finalizer records `status_class=none`, outcome `cancelled`, and
decrements the active count. No request ID can be returned because no response
exists.

The wrapper enters the request span while polling the body and while finalizing.
The same finalizer explicitly enters the span before emitting completion from
either the pre-response guard or body `Drop`, so all completion paths receive
the same trace/span correlation. It finalizes exactly once:

| Trigger | Outcome | Span status |
|---|---|---|
| Clean end-of-stream | `completed` | Error only for 5xx |
| Body returns an error | `body_error` | Error |
| Body is dropped before end-of-stream | `cancelled` | Error |

Finalization decrements active requests, increments completed requests,
records full-lifecycle duration, emits one dedicated safe completion event, and
drops the final span handle. A body that is never polled still finalizes as
cancelled when dropped.

After yielding a successful frame, the wrapper also checks the wrapped body's
`is_end_stream()`. If true, it finalizes as completed immediately; it does not
require a consumer to perform an extra poll returning `None`. Trailers remain
part of the wrapped body lifecycle.

This duration includes request handling and response streaming until EOF or
drop. It does not claim to measure client receipt after the final frame leaves
the process.

## Signal schemas

### Trace span

Span name: `HTTP request`

Allowlisted attributes:

- `maskura.request.id`
- `http.request.method`
- `http.route`
- `http.response.status_code`
- `maskura.http.status_class`
- `maskura.http.outcome`

No network peer, host, URL, query, user agent, content length, customer,
operation, receipt, or exception attributes are recorded.

These six attributes are written with `Span::set_attribute` from typed enums
and the application-owned route template, not from `tracing` fields. The trace
layer contributes no automatic target, thread, source location, level,
exception, event, or error-record attributes.

### Completion log

Event name: `http.server.request.completed`

Allowlisted fields:

- `request_id`
- `method`
- `route`
- `status_class`
- `outcome`
- `duration_ms`, saturated to a documented integer ceiling

Trace and span IDs are supplied from the active server span's OTEL context
rather than copied from caller input. The log has one fixed event name and no
arbitrary message or error text.
`status_class` also permits the fixed value `none` for cancellation before a
response exists.

### Metrics

The first metric set is:

- `maskura.http.server.active_requests`: signed up/down counter
- `maskura.http.server.completed_requests`: monotonic counter
- `maskura.http.server.request.duration`: seconds histogram

The active-request instrument uses only normalized method and matched route
template, because status and outcome do not exist at admission; decrement uses
the identical attribute set. Completed requests and duration additionally use
status class and outcome. Request IDs and all tenant/object identities are
forbidden because they create unbounded cardinality and disclose customer
activity.

The histogram uses explicit documented buckets suited to control and streaming
requests. Its count is expected to match the completed counter for each
attribute set.

## Shutdown and failure semantics

Public serving adds bounded graceful process shutdown. On SIGTERM or Ctrl-C it
stops accepting requests and gives Axum a fixed drain interval. At the drain
deadline it drops the serve future so stalled connections and bodies cannot
block process exit, then flushes logger, meter, and tracer providers within a
second fixed deadline. Either timeout produces one fixed local warning and
process exit continues; shutdown never prints buffered record contents.

Private processes use the same handle. Short-lived commands such as
`reconcile-once` explicitly flush before exit. Long-running serving and worker
commands flush after their own shutdown paths.

Configuration errors occur before listener binding or external mutation.
Collector DNS, connection, timeout, HTTP, or decoding failures occur in batch
workers and do not affect request futures, health, readiness, billing, or
reconciliation.

## Testing

### Configuration tests

- absent endpoints produce no-op exporters,
- general and signal-specific endpoint precedence,
- `none` disables one signal,
- HTTP/protobuf is accepted and gRPC/unknown protocols fail,
- HTTPS is the default; plaintext HTTP requires the matching explicit insecure
  flag,
- sampler names and ratio boundaries,
- resource allowlist, duplicates, lengths, and control characters,
- local format and constrained levels,
- endpoint/header/resource values never appear in `Debug`, `Display`, or errors.

Environment-mutating tests use the repository's serialized environment-test
pattern and restore every value.

### Lifecycle tests

- success, authentication denial, unsupported S3 operation, CORS response,
  health, readiness, and unmatched routes return valid request IDs,
- caller request IDs are replaced,
- retries have distinct request IDs even when durable operation IDs are stable,
- route attributes are templates rather than concrete paths,
- handler-future cancellation before response headers finalizes exactly once,
- EOF, body error, and body drop finalize exactly once,
- a final successful frame followed by `is_end_stream() == true` completes
  without requiring another poll,
- active counts return to zero and completed count equals histogram count,
- 5xx/body failures set trace error status while 4xx remains a normal server
  result,
- exporter absence does not alter response behavior.

### Adversarial export tests

Use in-memory trace, log, and metric exporters. Send requests containing unique
secret-shaped sentinels in concrete paths, queries, authorization headers, API
credentials, MCP credentials, presigned URLs, user agents, and injected body
errors. Serialize every exported record and assert that no sentinel appears.
Assert exact allowlisted keys and bounded categorical values.

Emit existing and forged dedicated-target events/spans containing a sentinel.
Prove that local capture still works as configured, the exact callsite filter
rejects unapproved spans, the trace exporter receives no events, and generic
events never enter OTEL logs.

### OTLP integration test

A loopback mock collector accepts explicitly insecure OTLP HTTP/protobuf traces,
logs, and metrics.
The test verifies:

- correct signal endpoints and content type,
- all three protobuf payloads decode,
- configured authorization headers arrive at the collector but never enter
  local or exported records,
- flush delivers queued records,
- collector failure leaves HTTP responses unchanged,
- shutdown respects its deadline.

### Local log tests

- text and JSON output parse as documented,
- application level selection works,
- dependency DEBUG/INFO remains suppressed,
- the dedicated completion event contains only its fixed schema,
- the local-only zero-configuration credential behavior remains unchanged and
  is never eligible for remote log export.

## Documentation

Implementation adds an ADR covering the telemetry trust boundary and signal
schemas. `docs/security.md` extends its logging policy to all exported signals.
`docs/reference/configuration.md` lists every supported variable, default,
allowlist, and failure mode. Public examples use placeholder collector values
and never include real endpoints or authorization headers.

## Rollout

1. Public PR #167 is merged (merge commit `25b5c4ee`; `main` at `v0.7.8`), so
   the reviewed log sanitization policy is the base.
2. Implement and release the public gateway telemetry API and middleware
   (release target `v0.7.9`).
3. Verify all public local, OTLP mock, E2E, SDK, dependency, and CI gates.
4. Pin that exact public revision in `s4-control`.
5. Replace the private process formatter with the public initializer for serve,
   validation, and reconciliation roles.
6. Run private tests with export disabled and against a non-production mock
   collector.
7. Configure a production collector only through a separately reviewed
   operations change. Enabling export is not implied by merging code.

No rollout step changes hosted admission, customer exposure, or product gates.

## Open decisions

None. Collector vendor, production endpoint, credentials, retention, and alert
rules are deliberately deferred to the separately reviewed operations rollout;
the code contract is vendor-neutral OTLP HTTP/protobuf.
