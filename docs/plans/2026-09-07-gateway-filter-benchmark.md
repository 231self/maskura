# Gateway Filter Pipeline Performance Benchmark

Status: planned
Scope: self-hosted OSS `maskura:filter` plugin pipeline only
Repositories: public `231self/maskura` (gateway + Wasm runtime + filters)

## Objective

Measure the performance cost of writing objects through the Maskura gateway so
the overhead of each Wasm filter plugin — and of the pipeline itself — is a
published, reproducible number rather than an anecdote. Concretely, answer:

- What is the fixed cost of routing an object through the pipeline at all
  (explicit pass-through vs. a single `noop` filter, which isolates the cost of
  the fresh per-object Wasm store + executor scheduling)?
- What is the marginal per-byte and per-record cost of each built-in filter
  (`pii-default`, `email-detect`, `ssn-detect`, `card-detect`,
  `envelope-encrypt`, `stable-encrypt`), individually and as ordered chains?
- How much do the crypto filters cost per detected field (RSA-OAEP wrap +
  AES-256-GCM for `envelope-encrypt`, AES-SIV for `stable-encrypt`), and how
  much do they expand the object?
- What is the end-to-end throughput/latency penalty of writing through Maskura
  versus writing directly to the storage backend?

The result is a benchmark harness plus a `docs/benchmarks.md` with tables whose
headline is a "cost multiplier vs. noop" per plugin.

## Current-State Findings

- The write path is `server.rs` `PUT` → resolve pipeline → `snapshot_for` →
  `streaming_single_put`. The pipeline itself is executed by
  `PipelineSession::route_from` in `crates/gateway/src/plugin_registry.rs:1254`,
  one `transform` call per enabled plugin per record.
- Each object gets a fresh per-object pipeline on a dedicated `WasmExecutor`
  (`crates/wasm-runtime/src/executor.rs`), whose default worker count is
  `min(available_parallelism, 4)`. Throughput is worker-bound.
- The registry already instruments execution: `control.rs` emits
  `PipelineEvidence { revision, fingerprint, components, fuel_consumed,
  duration_ms, spool_mode }` per operation (`crates/gateway/src/control.rs:259`),
  and `PipelineSession` exposes `fuel_consumed()`, `input_bytes()`, and
  `output_bytes()`. Wasmtime fuel is a deterministic, hardware-independent proxy
  for guest CPU, so it is the primary cross-machine metric.
- `scripts/build-plugins.sh` builds seven components into
  `target/components/*.component.wasm`: `noop`, `pii-default`, `email-detect`,
  `ssn-detect`, `card-detect`, `envelope-encrypt`, `stable-encrypt`.
- The self-hosted plugin set is controlled by `MASKURA_PLUGINS_DIR` (legacy
  `MASKURA_PLUGINS_DIR`), loaded at startup (`server.rs:725`); an empty directory is
  the operator's explicit pass-through choice.
- `just bench-rss` already runs `tests/streaming_rss.rs`, which asserts a 1 GiB
  source grows peak RSS by at most 128 MiB — the memory-bound harness to reuse.
- The release profile is size-optimized (`opt-level = "s"`), and the pipeline
  comment notes one RSA-2048 OAEP wrap costs ~25M wasm instructions against a
  `DEFAULT_PIPELINE_FUEL` of 1e9 (`plugin_registry.rs:26`). Both facts shape
  what the harness must measure and how.

## Decisions

1. Benchmark at two tiers: a deterministic in-process micro-benchmark (isolates
   per-plugin cost, no I/O) and an end-to-end harness against local MinIO
   (measures the full "through Maskura" cost).
2. Use Wasmtime **fuel** as the primary cost metric (fuel/byte, fuel/detected
   field), reported alongside wall-clock latency, throughput, output expansion,
   and peak RSS. Duration alone is not reproducible across machines.
3. `noop` is a mandatory distinct row from explicit pass-through, because it
   isolates the fixed per-object store/executor overhead.
4. Sweep PII density (0/1/10/100%), record size (1 KB / 64 KB / 1 MB), and format
   (`text/plain`, `jsonl`, `csv`), and — e2e only — executor concurrency.
5. Add a dedicated release-like benchmark profile with `opt-level = 3` (the
   production `release` profile is `opt-level = "s"`); benchmark Wasm guests are
   built with the production `build-plugins.sh` path unchanged so numbers reflect
   shipped artifacts.
6. Report fuel-exhaustion and memory/expansion limits as first-class results for
   high-density `envelope-encrypt` payloads, not as afterthoughts.
7. Keep the harness self-contained: it must not require a cloud account, Supabase,
   or the private control plane. Local MinIO via `local/docker-compose.yml` and
   `maskura` are the only infra.

## Ordered Implementation

### 1. Add the micro-benchmark harness

**Files:** `crates/wasm-runtime/benches/` (or `crates/gateway/benches/`), with a
criterion bench; a shared payload generator module.

- Load each `target/components/*.component.wasm`, build a `PipelineSnapshot`, and
  drive `PipelineSession::process` with synthetic records across the density/size/
  format sweep.
- Record per-configuration: `fuel_consumed()`, wall time, `input_bytes()`,
  `output_bytes()`, and derive fuel/byte, fuel/detected-field, ns/record, and
  expansion factor.
- Include pass-through (empty chain) and `noop` rows, plus the
  `pii-default` → `envelope-encrypt` two-stage chain.

**Verify:** numbers are stable across repeated runs on the same machine; fuel/byte
is identical across machines for the same component and payload; the noop row
isolates a measurable fixed cost.

### 2. Add the end-to-end harness and load generator

**Files:** `scripts/bench-e2e.sh` (or similar), a generator script, and a small
table-rendering step.

- Reuse `local/docker-compose.yml` MinIO + gateway (`just dev-up`). Switch the
  plugin set by pointing `MASKURA_PLUGINS_DIR` at a directory containing the
  chosen `target/components/*.component.wasm` subset.
- Baseline runs: direct-to-MinIO (no gateway), gateway pass-through, and gateway
  `noop`. Then each real filter and the two-stage chain.
- Generate payloads with configurable PII density/format/size; drive uploads with
  `maskura` (or curl + SigV4) at fixed concurrency, timing each object.
- Collect the gateway's emitted `PipelineEvidence` (fuel + duration) from usage
  events/logs and emit CSV + markdown tables.

**Verify:** the e2e latency/throughput for `noop` minus pass-through is consistent
with the micro-benchmark fixed cost; expansion and fuel numbers reconcile with
Tier 1; peak RSS stays within the `streaming_rss.rs` bound under the sweep.

### 3. Publish the results

**Files:** `docs/benchmarks.md` (and a `just bench` entry if a single command
emerges).

- Document methodology, environment, and how to reproduce.
- Publish the tables with the "cost multiplier vs. noop" headline per plugin,
  plus fixed-overhead, expansion, and fuel-exhaustion notes.

**Verify:** a reviewer can reproduce the tables from a clean checkout with
`just build-plugins` + the benchmark commands, with no cloud credentials.

## Verification Gates

- `just check` stays green (harness compiles under `-D warnings`).
- The micro-benchmark runs deterministically and its fuel/byte figure is
  reproducible across machines.
- The e2e harness runs against local MinIO only and requires no secrets.
- `envelope-encrypt` high-density results include a documented fuel-exhaustion
  outcome (or a raised `MASKURA_WASM_FUEL` with the rationale).
- Reported expansion for `envelope-encrypt` matches the measured
  `output_bytes`/`input_bytes` ratio.

## Success Criteria

- A table exists that quotes, per plugin, the cost multiplier versus `noop` for
  CPU (fuel), latency, throughput, and output expansion.
- The fixed cost of running the pipeline is separately quantified (pass-through
  vs. `noop`).
- Anyone can reproduce every number from a clean checkout with local tooling
  only.

## Open Decisions

None. Selecting `criterion` versus a lighter custom timer, and the exact benchmark
crate location, are implementation details to settle when the harness lands.
