# Safe OpenTelemetry observability implementation plan

Status: In progress (Tasks 1-6 complete; Task 7 local acceptance done, private handoff pending release)

**Goal:** Add safe OTLP HTTP/protobuf traces, dedicated logs, and HTTP RED
metrics to every Axum-admitted gateway request without exporting customer data
or making collector health part of request availability.

**Design:**
`docs/superpowers/specs/2026-09-19-safe-otel-observability-design.md`

## Resume state (read this first)

- Base: public `main` = merge commit `25b5c4eebcb603a9049569446affa4733846816a`
  (PR #167), workspace version **v0.7.8**. Release target for this change is
  **v0.7.9**.
- Public workspace:
  `/Users/amitmor/ExternalProjects/maskura/.worktrees/otel-observability-design`,
  change `xlstqomp` at `26e45e00` (local, not pushed).
- Private tracking: issue `231self/maskura-private#234` (In Progress); #233 is
  closed. Execution log entry is in the private workspace
  `.worktrees/security-log-sanitization-log` change `nmwvxxxu` at `1cbbd6d8`.
- Toolchain: `export PATH="$HOME/.rustup/toolchains/1.97.0-aarch64-apple-darwin/bin:$PATH"`.
- Test seam rule: provider/exporter/filter/logging/lifecycle tests are
  `#[cfg(test)]` unit tests inside `crates/gateway/src/telemetry/`. Only the
  spawned-binary test lives under `crates/gateway/tests/`. Do not add a public
  test-only API; do not call `init_telemetry` from unit tests.
- Verification rhythm per task: `cargo fmt --check`, the task's focused
  `cargo test -p maskura-gateway ...`, then
  `cargo clippy -p maskura-gateway --all-targets -- -D warnings`. The justfile
  exports `RUSTFLAGS=-D warnings`. A macOS `linker_messages` note (`__eh_frame
  section too large`) is a benign link-time message that does not appear on the
  Linux CI.

### Facts already proven (do not re-derive)

- Dependency family: OpenTelemetry `0.32` (`opentelemetry`, `opentelemetry_sdk`,
  `opentelemetry-otlp`, `opentelemetry-http`) with `tracing-opentelemetry 0.33`.
  `tracing-subscriber` now enables `json`.
  - 0.31 was rejected: its SDK log-export pipeline is gated by
    `spec_unstable_logs_enabled`.
  - The crates' built-in `reqwest` features were rejected: they pull Reqwest
    0.13 while the workspace pins 0.12.28. Implement the sanitizing client over
    the workspace's existing async Reqwest 0.12 and inject it with
    `with_http_client`. Do **not** enable `reqwest`/`reqwest-blocking` on any
    OTEL crate.
  - A lockfile check confirmed a single Reqwest 0.12 line; a scratch crate
    confirmed the custom `HttpClient` plus all three OTLP HTTP providers compile
    and all three `opentelemetry-proto` signal decoders pass.
- Dev-dependencies for the mock collector:
  `opentelemetry-proto = { version = "0.32", default-features = false, features = ["gen-tonic-messages", "trace", "logs", "metrics"] }`
  and `prost = "0.14"`. The three signal features are required.
- `opentelemetry_http::HttpClient::send_bytes` is `async` and the trait is
  `#[async_trait]`; the impl must be annotated `#[async_trait::async_trait]`.
- The request span must use `tracing::info_span!(target: "maskura.telemetry",
  "HTTP request", otel.kind = "server")`. `tracing-opentelemetry` consumes
  `otel.kind` to set the OTel span kind and does **not** export it as an
  attribute.
- `tracing` field names cannot contain dots, so the six dotted semantic
  attributes are set on the OTel span via `Span::set_attribute` from typed
  enums, not as span fields.
- `tracing::Dispatch` does not implement `Subscriber`; local subscriber builders
  return `Arc<dyn Subscriber + Send + Sync>`. `Interest` comes from
  `tracing::subscriber::Interest`.
- `tracing` macros in this repo put structured fields **before** the message
  (`info!(target: "t", field = value, "message")`).
- Local logging test capture uses a custom `MakeWriter` (`Capture`) collecting
  into `Arc<Mutex<Vec<u8>>>`.

### Already implemented and green

- `crates/gateway/src/telemetry/config.rs` — `TelemetryConfig::from_env`,
  `Sampler`/`SamplerConfig`, `BatchConfig`, `SignalEndpoint`. 12 tests.
- `crates/gateway/src/telemetry/schema.rs` — `HttpMethodClass`, `StatusClass`,
  `Outcome`, `CompletionRecord`, `MAX_DURATION_MS = 86_400_000`,
  `request_span()`, `UNMATCHED_ROUTE`, `TELEMETRY_TARGET`,
  `REQUEST_SPAN_NAME`, `COMPLETION_EVENT_NAME`. 4 tests.
- `crates/gateway/src/telemetry/logging.rs` — `LogFormat`,
  `parse_log_settings` (`MASKURA_LOG_LEVEL`, `MASKURA_LOG_FORMAT`),
  `subscriber`, `subscriber_with_writer`, `LocalFilter` (Maskura level,
  dependency WARN cap, OTEL/HTTP target suppression). 5 tests.
- `crates/gateway/src/telemetry/provider.rs` — `TelemetryHandle { config }`,
  `init_telemetry`.
- `crates/gateway/src/telemetry/mod.rs` — module wiring; `schema` is
  `#[allow(dead_code)]` (reason: consumed by later changes).
- `Cargo.toml`, `crates/gateway/Cargo.toml` — dependencies as above.
- 21/21 telemetry tests pass; gateway clippy `-D warnings` and `cargo fmt
  --check` clean.

## Task 3: Construct sanitized OTLP providers

Status: complete.

Actuals discovered while implementing (also recorded in the design):
- The default thread-based batch processors cannot drive an async HTTP client,
  so `opentelemetry_sdk` now enables
  `experimental_trace_batch_span_processor_with_async_runtime`,
  `experimental_logs_batch_log_processor_with_async_runtime`, and
  `experimental_metrics_periodicreader_with_async_runtime`, and constructs them
  with `opentelemetry_sdk::runtime::Tokio`. Provider construction therefore
  needs a Tokio runtime (public `main` and private commands are inside one).
- A programmatic OTLP endpoint is used verbatim, so the provider appends
  `/v1/traces`, `/v1/logs`, and `/v1/metrics` to the operator base endpoint.
- The tracing-opentelemetry layer disables location, threads, target, level,
  tracked-inactivity, and all error/exception enrichment so the exported span
  carries only the six allowlisted attributes.
- `CompletionRecord` now carries `status_code: Option<u16>` (the trace keeps the
  exact code; the log and metrics use the derived status class).

Implemented in `crates/gateway/src/telemetry/`:
- `http_client.rs`: `SanitizingHttpClient` with opaque errors and stripped
  response bodies.
- `provider.rs`: `RemoteTelemetry` (independent trace/log/metric signals),
  resource with the fixed keys + allowlist, sampler mapping, bounded batch
  configs, `/v1/*` endpoints, typed completion log, active/completed/duration
  instruments, and bounded flush/shutdown on a dedicated thread.
- `logging.rs`: optional request-span-only trace layer.
- `schema.rs`: `status_code` + derived status class.

Verification: 29 telemetry unit/integration tests, including a loopback mock
collector that decodes all three protobuf payloads, asserts the exact span/log
attribute key sets and metric values, proves the configured authorization header
arrives but never enters a body, and proves forged spans/events are rejected.
Unreachable collector never panics or hangs. Gateway clippy `-D warnings` and
fmt clean.

## Task 4: Implement full HTTP lifecycle instrumentation

Status: complete.

**Files:** `crates/gateway/src/telemetry/http.rs` (new),
`crates/gateway/src/telemetry/mod.rs`.

1. Unit-test router with template paths, unmatched fallback, immediate and
   delayed handlers, streaming bodies, injected body errors, and a body whose
   final frame reports `is_end_stream() == true`.
2. Named cases: success, authentication denial, unsupported S3 rejection, CORS
   preflight/response, health, readiness, unmatched; UUIDv7 response IDs
   replacing caller/handler IDs; ignored inbound `traceparent`/`tracestate`;
   root span (`parent: None`); route-template attributes; retries with stable
   operation IDs but distinct request IDs.
3. Adversarial sentinels in concrete path, query, `Authorization`, API
   credential headers, `maskura_mcp_` credentials, presigned URL params, user
   agent, and injected body-error text; assert none appear in any span/log/metric
   attribute.
4. Exactly-once tests: clean EOF, final-frame `is_end_stream`, body error, body
   drop, handler-future drop before headers. Outcome tests: 4xx normal status,
   5xx/body error set error status, active count returns to zero, injected
   collector failure leaves the response byte-for-byte unchanged.
5. Implement the pre-response RAII finalizer: increment active requests before
   awaiting the handler; use exactly method+route on increment and decrement.
6. Start the span with `parent: None`, instrument the handler future, and move
   the finalizer plus final span handle into a pinned body wrapper after headers.
7. In every finalization path, enter the span, set the six attributes via
   `Span::set_attribute`, set status, update completed/duration metrics, emit the
   typed remote log + local event, decrement active, and close exactly once.
   `Drop` paths must enter the span first.
8. Implement `instrument_router(Router, &TelemetryHandle)` and document that it
   must be applied only to a fully composed router.

## Task 5: Adopt telemetry in the public gateway process

Status: complete.

**Files:** `crates/gateway/src/main.rs`,
`crates/gateway/src/telemetry/mod.rs`, `crates/gateway/tests/telemetry_process.rs`.

1. Factor `serve_with_shutdown(router, listener, shutdown)` plus a bounded drain
   that drops the serve future at the deadline; unit-test with a stalled body
   that the drain deadline is enforced and flush starts only afterward within
   its own bound.
2. Replace the fixed INFO formatter in `main.rs` with `TelemetryConfig::from_env`
   + `init_telemetry` before state construction; stay local-only when export is
   disabled.
3. Apply `instrument_router` after `build_router`.
4. Add SIGTERM/Ctrl-C handling driving the bounded shutdown helper.
5. `--healthcheck` stays local-logging only (no collector traffic, no provider
   shutdown wait unless an exporter was configured).
6. Spawned-binary test via `env!("CARGO_BIN_EXE_maskura-gateway")`: export
   disabled, `/ready` then request-ID assertions on `/health`, `/ready`,
   unmatched, and one S3 response; SIGTERM; exit within the deadline.

## Task 6: Document and version the public contract

Status: complete.

**Files:** `docs/adr/0020-safe-opentelemetry-observability.md` (new),
`docs/security.md`, `docs/reference/configuration.md`, `Cargo.toml`,
`Cargo.lock`, generated SDK/version surfaces.

1. ADR 0020: trust boundary, exact schemas, private-route layering requirement,
   failure semantics, rejected alternatives (0.31 log gate; built-in Reqwest).
2. Extend `docs/security.md` to remote traces/logs/metrics, forbidden values,
   explicit insecure-transport risk.
3. `docs/reference/configuration.md`: every variable, precedence, default,
   allowlist, bound, startup failure, shutdown behavior, safe placeholder.
4. Bump public release surfaces from v0.7.8 to **v0.7.9**; regenerate SDKs with
   `just build-sdks`.
5. `python3 scripts/check-release-contract.py` and
   `python3 scripts/check-public-copy.py`.

## Task 7: Public acceptance and private handoff

Status: local acceptance done; spawned-binary test and private `s4-control` pin pending the released revision.

**Public acceptance (same change):**

1. `cargo fmt --check`; `cargo clippy --locked --all-targets -- -D warnings`;
   `bash scripts/build-plugins.sh`; `cargo test --locked --workspace`;
   `bash scripts/e2e-local.sh`.
2. Exact CI SDK commands: `bash scripts/generate-sdks.sh`;
   `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=sdks/python python3 -m pytest -q sdks/python/test/test_highlevel_attach.py sdks/python/test/test_highlevel_crypto.py`;
   `cd sdks/typescript && npm install --ignore-scripts --no-package-lock && npm run build && node --test test/*.test.cjs`.
3. `just check-evidence`, `just deny`, `just audit`, `just audit-dependencies`.
4. Review in-memory/mock-collector artifacts for exact schema and sentinel
   absence; retain sanitized evidence only.
5. Open the public PR referencing #234; keep #234 In Progress.

**Private handoff (separate jj workspace, after the public release):**

6. Pin the exact released public revision; bump the private crate version.
7. Per-role behavior:
   - `serve`: instrument only after all engine + SaaS + MCP routes are merged;
     flush on the bounded shutdown path.
   - `reconcile-once`, `reconciliation-status`, `validation-worker`,
     `validation-worker-status`, `launch-alerts`: initialize and explicitly
     flush before exit.
   - validator child stdio mode and validator self-test: local logging only,
     never remote export.
8. Replace the `run_server` formatter with the public initializer; keep
   validator child/self-test on a local-only initializer.
9. Private tests: export-disabled startup + non-production mock collector;
   per-role flush-before-exit.
10. Run private gates (`just pre-push`); move #234 to Review only when the
    private pin/integration revision is ready with reproducible evidence.
