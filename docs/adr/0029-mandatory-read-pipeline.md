# ADR 0029: Mandatory read pipeline

- Status: Accepted
- Date: 2026-10-29

## Context

Reads were opt-in. A `GET` served the stored bytes unless the client sent
`x-maskura-process: read`; the transformed-read path itself was fail-closed
(metadata preflight, version/ETag binding, no raw fallback), but entry into it
was client-elected. A deployment-wide switch (`MASKURA_STREAMING_READ_MODE`)
was the only server-side control, and the auto-local appliance silently
defaulted to raw passthrough. Unsupported formats had documented raw
passthrough; `Range`/`partNumber` and `HEAD` served stored bytes without a
pipeline; presigned-HTTP backends were raw-only. An agent-scoped credential
could therefore retrieve an unprocessed representation of a protected object
by simply not asking for protection — and the "agent should not even know
there is a raw mode" property did not hold.

Options considered:

1. **Per-credential raw-read flags or credential classes**
   (agent/application/administrator). Powerful, but adds a second place to
   author unprotected reads beside pipeline assignment, and a class is just a
   bundle of per-key flags.
2. **Keep client election with better defaults.** Leaves the bypass in the
   client's hands.
3. **Pipeline assignment as the single authoring surface** (chosen). Every
   read applies the resolved read pipeline; an unprotected read is the no-op
   pipeline — an authored `explicit_passthrough` assignment in the same
   hierarchical config that assigns every other pipeline.

## Decision

> Every object read applies the resolved read pipeline for its
> workspace/bucket scope. A read the pipeline cannot fully serve is denied.
> The only read that serves stored bytes is one whose resolved pipeline is an
> explicit passthrough assignment. No client header, query parameter, or
> request shape selects a representation.

- `get_object` and `s3_head` resolve the read pipeline once per request. An
  `explicit_passthrough` resolution is the only route to the stored bytes;
  any other resolution serves the projection; a resolution error denies
  (`AccessDenied` for unassigned scopes, before object lookup — no existence
  oracle). Silence is never passthrough: an empty enabled catalog or an
  unassigned scope denies reads.
- Surfaces follow one rule. `Range`/`partNumber` and formats the pipeline
  cannot decode are denied under protected scopes — unsupported binaries are
  never raw passthrough. `HEAD` is denied before the policy gate under
  protected scopes (transformed metadata is not available) and served under
  passthrough. Presigned-HTTP backends cannot provide the stored-metadata
  preflight a protected read needs, so they are **incompatible with protected
  scopes** and deny there; they remain usable under explicit passthrough
  scopes. `COPY` source remains `501 NotImplemented`. List and metadata
  operations stay outside the object-data claim.
- Policy-gate kinds become assignment-driven: pipeline reads present
  `ProcessedGet`, passthrough reads present `RawGet` (the frozen resolution is
  carried only where a pipeline executes), and every read's usage
  authorization binds the resolved policy identity — the fingerprint now
  covers every read.
- The client-elected entry and its global switch are retired:
  `wants_transformed_read` is deleted, `x-maskura-process` is removed from the
  header-alias registry and the SigV4 request-semantic headers (inert if still
  sent), and `MASKURA_STREAMING_READ_MODE` is removed from config, gateway
  state, error surfaces, and the auto-local default. The hosted MCP tool's
  `process` flag is retained for wire compatibility and is inert.
- The streaming pipeline config grammar is unchanged: `explicit_passthrough`
  (already part of the signed TOML schema) is the sole raw-serving authoring
  construct, at global, bucket, workspace, or workspace/bucket scope.

## Consequences

- The product invariant an external review identified — *an agent-scoped
  credential can never retrieve an unprocessed representation of a protected
  object* — now holds structurally: there is no client-reachable raw route
  outside an authored passthrough assignment, and every assignment is visible
  in the policy document and bound into evidence.
- Deny-by-default closes the unsupported-format, alternate-surface, and
  presigned-bypass classes as a matter of rule rather than documentation.
- Fresh workspaces and self-hosted installs must author a read pipeline before
  the first `GET` (the enabled catalog counts as an assignment; zero enabled
  plugins is unassigned and denies). The zero-config local appliance keeps
  working out of the box: its enabled default component resolves a one-step
  read pipeline, so local reads serve that projection — raw local serving now
  requires an explicit passthrough assignment.
- Presigned-HTTP backend customers must scope raw buckets apart from protected
  data (explicit passthrough for the former).
- Supersedes the read-selection parts of the earlier surface: the
  `x-maskura-process` documentation and the `MASKURA_STREAMING_READ_MODE`
  gate (including the configuration surface described in ADR 0019) are
  retired. ADR 0019's storage decision stands.
- Tests carry the semantics: raw-mechanics suites run under authored
  passthrough scopes, pipeline suites under protected scopes, and a
  `read_mandate` matrix asserts the denial rows directly.

Details and the staged plan: `docs/plans/2026-10-29-mandatory-read-pipeline-design.md`
and `docs/plans/2026-10-29-mandatory-read-pipeline-implementation-plan.md`.
