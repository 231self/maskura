# Mandatory read pipeline — design

Date: 2026-10-29
Status: design approved by the owner; awaiting implementation plan
Scope: public `maskura` repo (gateway read path) and the hosted twin in
`maskura-private` (read path + dashboard copy)

## Problem

Every read today is an opt-in. `wants_transformed_read`
(`crates/gateway/src/server/s3_objects.rs`) returns true only when the client
sends `x-maskura-process: read`; without it, `GET` serves the stored bytes
unchanged. The transformed path itself is strong (metadata preflight,
version/ETag binding, no raw fallback, prefix-safe streaming or encrypted
spool), but **entry is client-elected**. A global switch
(`MASKURA_STREAMING_READ_MODE`) is the only server-side control, and it is a
deployment-wide knob, not a policy.

This fails the invariant an external review identified as the product's core
promise: *an agent-scoped credential must never be able to retrieve an
unprocessed representation of a protected object*. Today it can — by simply
not asking for protection.

The owner's directive: no second place to author unprotected reads. Pipeline
assignment is that surface. An unprotected read is the no-op pipeline
(`explicit_passthrough`), authored where pipelines are already assigned.

## Invariant

> Every object read applies the resolved read pipeline for its
> workspace/bucket scope. A read the pipeline cannot fully serve is denied.
> The only read that serves stored bytes is one whose resolved pipeline is an
> explicit passthrough assignment. No client header, query parameter, or
> request shape selects a representation.

## Decisions (settled with the owner)

1. **Mandatory read pipeline.** Reads and pipeline application are the same
   act. The client never chooses whether to be protected.
2. **Deny closed, no exception grammar.** There is no `passthrough_formats`
   or similar escape syntax in code or config. Per-need raw (e.g. a video
   bucket) is an `explicit_passthrough` assignment at bucket/workspace scope
   in the existing resolution hierarchy — visible in the policy document,
   recorded in evidence like any other assignment.
3. **Unassigned read scope denies.** Silence is never passthrough. A fresh
   workspace with no read assignment cannot `GET` until it authors one.
   Onboarding gains one guided step ("assign a read pipeline, or explicitly
   pass through").
4. **Implementation approach: delete the raw read path.** The transformed-read
   machinery becomes the read path. The raw-serving code survives only behind
   the `explicit_passthrough` assignment branch.

## Detailed design

### Enforcement core

`get_object` resolves `PipelineResolution` (workspace + bucket + `read`) once
per request through the existing `PipelineResolver`, then:

- `explicit_passthrough == true` → serve stored bytes (the surviving raw
  branch; the assignment is the authorization).
- resolved steps → the existing fail-closed transformed path serves the
  projection (metadata preflight, version/ETag binding, prefix-safe streaming
  or encrypted spool, no raw fallback).
- **no resolution** → deny.

`PipelineResolution` already enforces that an empty chain is legal only with
`explicit_passthrough` — so the resolver change is precise: every resolution
path (static OSS catalog, config file scopes, hosted assignments) must yield
non-empty enabled steps, `explicit_passthrough`, or an error. Concretely, the
OSS static resolver ("catalog's enabled plugins in order") counts as an
assignment only when it resolves to at least one enabled step or an explicit
passthrough; zero enabled plugins is unassigned and therefore denies reads.

`wants_transformed_read` is deleted. The notion "transformed read" dissolves:
there is only *read*.

Error semantics stay as today's transformed-read refusals: unsupported request
shapes return `InvalidRequest`-class S3 XML with a bounded message; scope
denials return `AccessDenied`-class with no detail. No upstream error text
reaches the client (existing error-envelope rule).

### Alternate surfaces — one rule, applied everywhere

| Surface | Protected scope | `explicit_passthrough` scope |
|---|---|---|
| `GET` object | pipeline projection | stored bytes |
| `GET` of a format the pipeline cannot decode | denied — never raw passthrough | served (it is raw) |
| `GET` + `Range` / `partNumber` | denied | served (it is raw) |
| `GET` with `versionId` | pipeline against that version (binding exists) | stored bytes of that version |
| `COPY` source | piped as a read | stored bytes |
| `HEAD` | denied until transformed metadata exists (current rule kept) | served |
| Presigned-HTTP backend (`x-maskura-backend-url`) | denied — no safe metadata preflight is possible | allowed (raw is the assignment) |
| List / metadata operations | unchanged — outside the object-data claim, as the policy-gate docs already scope it | unchanged |

Product consequence, stated deliberately: a presigned-HTTP backend is
**incompatible with protected scopes**. Workspaces that need both must scope
them apart (presigned bucket at `explicit_passthrough`, protected data under
a resolved pipeline).

### Config surface

- `MASKURA_STREAMING_READ_MODE` (`off` / `passthrough` / `transformed`)
  **retires**. It was a global author of unprotected reads.
- Serving strategy knobs survive, as performance configuration rather than
  security gates: `MASKURA_PREFIX_SAFE_COMPONENT_HASHES` (direct streaming for
  declared prefix-safe components) and `MASKURA_TRANSFORMED_READ_SPOOL=encrypted`
  (spool for snapshots containing unsafe components). A protected scope with
  an unsafe component and no spool denies reads — fail closed, operator's
  configuration choice.
- No new config grammar. `explicit_passthrough` in the existing pipeline config
  (`pipeline_config.rs` scopes: global, bucket, workspace, workspace/bucket)
  is the only way to serve raw.

### API, SigV4, clients

- `x-maskura-process` is removed from `customer_headers` and the SigV4
  signed-header list (`sigv4.rs`). If a client still sends it, it is ignored —
  never a mode selector. No compatibility shim (no customers, no flag day).
- The MCP stdio client (`crates/mcp/`) sends `x-maskura-process: read` today
  and stops. **Handover note:** `crates/mcp/**` is another agent's territory;
  this change is coordinated or handed over rather than landed blind. The
  hosted MCP tool surface (`maskura_get_object(process: true)`) keeps its
  parameter for wire compatibility but the parameter becomes inert: the
  pipeline applies either way, and `process: false` can no longer mean raw.
- Header-alias tests flip to "ignored" semantics.

### Evidence and policy claims

Usage receipts and policy evidence already bind to the resolved pipeline
fingerprint (`policy_generation`, assignment id). The mandate strengthens the
ADR-0022 claim without changing its shape: the fingerprint now covers *every*
read, not just opted-in ones.

### Docs and ADR

- New ADR in `docs/adr/` (this changes a trust boundary; the ADR rule
  applies): **Mandatory read pipeline** — records the invariant, the deleted
  header and retired mode, the deny-unassigned default, the presigned-backend
  consequence, and supersedes the documentation that describes raw passthrough
  as a fallback for unsupported binaries.
- `docs/security.md` §5 and the website copy ("raw passthrough for unsupported
  binaries") are rewritten to the invariant.

### Testing

Matrix in both repos: scope × surface × format —
{unassigned, protected, `explicit_passthrough`} × {GET, Range, partNumber,
version GET, COPY source, HEAD, presigned backend} × {supported format,
unsupported binary} — asserting served/denied per the table. Unit tests on
resolver semantics (empty chain without `explicit_passthrough` is an error),
integration tests on the S3 surface, and the web suite follows any dashboard
copy change (146-test contract).

### Repos and rollout

Lands in both repos: public `maskura` (gateway read path, ADR, docs) and
`maskura-private` (hosted twin + dashboard copy). No customers — direct
cutover, no deprecation window. The s4 canary workspace receives the first
assigned read pipeline as part of the pending policy-enrollment ceremony, so
the canary proves the invariant live.

## Relationship to the external review

Closes: P0 "mandatory read policies per credential" (the credential-class
vocabulary is deliberately not adopted; the workspace/bucket pipeline
assignment is the enforcement unit) and P0 "deny-by-default for unsupported
and alternate read paths" (the surfaces table).

Does not close (separate efforts, explicitly out of scope here): AWS isolation
onboarding and verification (review P0 #3), agent identity / tenant-scoped
policies (P1), IAM/bucket-policy drift detection (P1), eBPF workload discovery
(P2).

## Out of scope / deferred

- **ETL tool (DB ↔ object store with filtering/encryption/redaction).**
  Discussed and parked as a separate future design; it must be designed
  against this invariant (no unfiltered ETL mode exists).
- **SQL/database as a data source.** Held per the review's sequencing advice
  until this invariant is live.
- **Credential classes** (agent/application/administrator). The per-key flags
  or classes can be layered on the pipeline-assignment model later without
  breaking it.
- Writes are unchanged; the mandate is read-side.
