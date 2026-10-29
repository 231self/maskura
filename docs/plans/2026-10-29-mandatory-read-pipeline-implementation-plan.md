# Mandatory read pipeline — implementation plan

Date: 2026-10-29
Design: `docs/plans/2026-10-29-mandatory-read-pipeline-design.md` (approved)
Rule: test-first per stage; each stage is one PR through the usual gate
(`just pre-push`) and merge chain. Reads-only mandate — **writes are
unchanged in every stage.**

## Stage 1 — Resolver semantics: unassigned read scope is an error

The read path can only deny-on-unassigned if resolution distinguishes
"assigned passthrough" from "nothing assigned".

- `crates/gateway/src/pipeline.rs` — `StaticPipelineResolver::resolution`
  (today: `let explicit_passthrough = steps.is_empty();`, doc comment "An
  empty enabled set is the operator's explicit pass-through choice"):
  - **Read direction:** empty enabled set becomes a resolution error
    (unassigned). The doc comment is rewritten to the new contract.
  - **Write direction:** behavior unchanged (empty set = store as-is).
  - `PipelineResolution`'s existing rule ("an empty chain is legal only when
    `explicit_passthrough` is true") is unchanged and stays the invariant.
- `crates/gateway/src/pipeline_config.rs` — `SignedTomlPipelineResolver`:
  for the read direction, a scope that is `None` at every level of the
  hierarchy (global → bucket → workspace → workspace/bucket) resolves to
  **error**, not to the static catalog or an empty chain. A found scope with
  `explicit_passthrough = true` resolves to passthrough; a found scope with
  steps resolves to steps. Extend `validate_pipeline` to reject a read scope
  with zero enabled steps and `explicit_passthrough = false` at load time
  (fail closed at startup, not at first GET).
- Hosted twin (`maskura-private`): the hosted pipeline resolver gets the same
  read semantics; unassigned hosted read → deny.
- Tests: resolver unit tests per direction — read: {steps, explicit, empty}
  → {ok, ok, error}; write: unchanged snapshot; config validation rejects the
  empty-non-explicit read scope.

## Stage 2 — Enforcement core: every read is a pipeline application

- `crates/gateway/src/server/s3_objects.rs`:
  - Delete `wants_transformed_read`. The GET flow resolves the read pipeline
    once and branches: `explicit_passthrough` → the existing raw-serving code
    (this assignment is the only route into it); resolved steps → the existing
    transformed path; resolution error → `AccessDenied`-class S3 XML with no
    detail (internal telemetry records the reason).
  - Surfaces per the design table: `Range`/`partNumber` denied under protected
    scopes; `versionId` GET runs the pipeline against that version; `COPY`
    source is a read; `HEAD` keeps the transformed-metadata rule; presigned
    backend (`x-maskura-backend-url`) denies under protected scopes.
  - Unsupported formats: the preflight rejection becomes the terminal answer —
    no raw fallback anywhere (it never existed on the transformed path; the
    raw path is no longer client-reachable).
- Integration tests (both repos): the scope × surface × format matrix from the
  design — {unassigned, protected, `explicit_passthrough`} × {GET, Range,
  partNumber, version GET, COPY source, HEAD, presigned backend} × {supported
  format, unsupported binary} asserting served/denied per the table.
- Existing tests that send `x-maskura-process: read` to select protection
  (`s3_frontdoor_test/pipeline.rs`, `server/lifecycle.rs`) flip to the new
  semantics: protection is the default; the header is irrelevant.

## Stage 3 — Header and global-mode retirement

- `crates/gateway/src/customer_headers.rs`: remove the `PROCESS` alias and its
  tests (flip to "unknown header is ignored" where a test asserts behavior).
- `crates/gateway/src/sigv4.rs`: remove `x-maskura-process` from the signed
  header list; update the signing tests that include it.
- `crates/customer-config/src/config.rs`: remove `StreamingReadMode` and
  `MASKURA_STREAMING_READ_MODE` (`off`/`passthrough`/`transformed`);
  `transformed_read_spool` stays as the serving knob alongside
  `MASKURA_PREFIX_SAFE_COMPONENT_HASHES`. Config parsing tests follow.
- **Handover — `crates/mcp/**` (another agent's territory):** the stdio client
  stops sending `x-maskura-process` (`crates/mcp/src/main.rs:212`) and the
  hosted MCP tool's `process` parameter becomes inert (kept for wire
  compatibility; `process: false` no longer means raw). Coordinate or hand
  this over; do not land blind.

## Stage 4 — Onboarding and dashboard (hosted)

- The guided onboarding/workspace flow gains one step: "assign a read pipeline
  (or explicitly pass through)" — the first read policy is a deliberate act.
- Dashboard copy that describes raw reads/passthrough is rewritten to the
  invariant (stale-div and table rules from the UI guide apply).
- Web tests (146-test contract) updated with any copy change.

## Stage 5 — ADR and docs

- New ADR in `docs/adr/` (next number): **Mandatory read pipeline** — the
  invariant, the deleted header, the retired mode, deny-unassigned, the
  presigned-backend consequence, and the supersession of "raw passthrough for
  unsupported binaries" documentation.
- `docs/security.md` §5 rewrite to the invariant; website format/read copy
  rewritten in the same change.

## Stage 6 — Canary proof (hosted)

- The s4 canary workspace receives its first **assigned** read pipeline as
  part of the pending policy-enrollment ceremony work.
- Live verification: an unassigned read denies; a protected read serves only
  the projection; an `explicit_passthrough` scope serves stored bytes; record
  results in the canary runbook (`docs/runbooks/policy-enrollment-canary.md`).

## Ordering and dependencies

1 → 2 → 3 are the public-repo core (3 may merge with 2 if size allows).
4 and 5 are hosted/docs and can proceed in parallel with 3.
6 last, after the hosted twin carries 1–3.

Explicitly out of scope (design's deferred list): ETL tool, SQL sources,
credential classes, AWS isolation onboarding, drift detection.
