# ADR 0021: Signed TOML pipeline configuration

- Status: Accepted
- Date: 2026-09-21

## Context

**Trust-boundary clarification (2026-09-23):**
[ADR 0022](0022-policy-approval-and-execution-trust-boundary.md) scopes this ADR's
operator-resistance language to artifact authenticity enforced by a trusted
gateway. A valid configuration signature is not evidence of which binary or
configuration a remote operator actually ran. The existing encoding, signing,
and resolver decisions below remain in force.

Self-hosted Maskura selected pipeline plugins from one process-global catalog
(`PluginRegistry`): every enabled plugin ran, in catalog order, for every PUT and
every opt-in transformed GET. There was no declarative, per-workspace/bucket way
to define processing chains, and the hosted control plane's relational pipelines
were not portable to OSS.

Operators need to author, review, and version a chain of processing as data —
"codeless pipelines" — and the hosted dashboard needs to produce the same
artifact for portability. Any tenant-defined policy must be verifiably authentic
(ADR-0003) and must never be silently changeable by an operator.

Options considered:

- **Extend the catalog's enable/order state.** Already possible, but gives no
  per-scope selection, no per-step config or grants, and no authenticity.
- **Deserialize directly into the execution types (`PipelineResolution`).**
  Requires hand-authoring content hashes and hosted-only identity fields.
- **A signed, hierarchical TOML file** resolved through the existing
  `PipelineResolver` seam, with a CLI (and the dashboard) to author and sign it.

## Decision

Adopt a signed TOML pipeline file as the OSS source of truth, resolved through
`PipelineResolver`.

- **Hierarchical scopes**: default `write`/`read`, `buckets.<bucket>`,
  `workspaces.<id>`, and `workspaces.<id>.buckets.<bucket>`. Precedence is
  `workspace+bucket > workspace > bucket > default`; a chain **replaces** rather
  than merges, and an unassigned direction fails closed.
- **Dedicated, ordered write and read chains** per scope. There are no named
  pipelines and no assignment table.
- **`(source, name, version)` plugin identity**, written as
  `<source-uri>:<name>[:<version>]`. OSS resolves references against locally
  loaded `file://` components; an omitted version means the highest matching
  semantic version. Remote component fetch is not implemented. Filesystem
  components may carry adjacent `*.plugin.toml` version/world metadata; legacy
  components default to version `0.1.0` and the current transformer world.
  Name/version references trust the source to keep versions immutable; a digest
  name pins the component bytes cryptographically across restarts.
- **Ed25519 over canonical CBOR** of the parsed, validated model (the ADR-0003
  construction); TOML whitespace and comments are not signed. The SHA-256 of
  that body is the immutable `PipelineLocator.revision`.
- **Fail closed at startup**: every declared scope and step, including disabled
  and shadowed steps, is resolved before the gateway starts. Unknown keys,
  sources, components, versions, digests, unsupported worlds or grants, bad
  signatures, implicit empty chains, and ambiguous identities are hard errors.
- **Layered operator configuration**: `[wasm] pipelines_file`,
  `pipeline_trust_roots`, and `pipeline_allow_unsigned` use the normal TOML plus
  environment override model. The unsigned override logs a prominent warning
  and labels the revision `unsigned-dev`.
- Implemented in `maskura-pipeline-config` and
  `crates/gateway/src/pipeline_config.rs`; authored and signed with
  `maskura pipelines`.

The full design is recorded in
`docs/plans/2026-09-20-signed-toml-pipeline-config-design.md`.

## Consequences

- Pipeline selection is immutable per request: the resolution (revision +
  fingerprint) freezes after authentication, and multipart uploads execute the
  exact revision they started with.
- Editing a comment or whitespace does not invalidate the signature or change the
  revision; a semantic change does both.
- The same file is the hosted dashboard's portable export, so OSS and hosted
  share one schema; the private configuration can extend it with
  `#[serde(flatten)]`.
- Sensitive request context is deny-by-default and grantable only per step.
- The catalog remains a catalog, not a policy; the file — not catalog order —
  decides which steps run.
- Typed binary adapters such as Avro use their schema-aware binary transform
  pipeline rather than these byte-oriented WASM chains.
- Deferred: prefix and content-type routing (requires extending the resolver
  input), remote component fetch, and hot reload.
