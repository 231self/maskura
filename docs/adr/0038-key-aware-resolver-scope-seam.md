# ADR 0038: Key-aware resolver seam for signed byte-preserving scopes

- Status: Accepted
- Date: 2026-11-27

## Context

ADR 0036 made byte-preserving storage scopes an operator setting
(`MASKURA_BYTE_PRESERVING_SCOPES`). That is correct for a self-hosted
deployment, where one operator owns the server and its buckets. It cannot
serve a hosted multi-tenant deployment:

1. The setting is process-wide. It cannot say *which workspace's* bucket is
   covered, and bucket names can collide across tenants.
2. The hosted policy gate accepts only resolutions that match the workspace's
   signed effective state. The engine's locally built scope resolution
   (revision `byte-preserving-scope-v1`, local plugin limits) is not a signed
   route, so the gate denies it.
3. The pipeline resolver trait resolves by workspace + bucket + direction. It
   has no key, so prefix scopes cannot be expressed inside `resolve`.

The hosted control plane needs a way to answer, per request key, with a
resolution built from the workspace's signed declaration — and the engine
needs to execute that resolution exactly like any approved pipeline.

## Decision

Extend `PipelineResolver` with one defaulted, key-aware method:

```rust
async fn resolve_for_key(
    &self,
    workspace_id: &str,
    bucket: &str,
    key: &str,
    direction: PipelineDirection,
) -> Result<Option<PipelineResolution>, MaskuraError> { Ok(None) }
```

- `Some(resolution)` wins over both the operator env scope and `resolve`. The
  resolution must already carry the signed route's locator, fingerprint, and
  limits; `Gateway::resolve_for_key` verifies the fingerprint exactly like
  `Gateway::resolve`.
- `None` means "no key-aware scope"; the existing behavior is unchanged.
- The default implementation returns `None`, so every existing implementor
  (including the self-hosted `StaticPipelineResolver`) is untouched.

Handler-level precedence in `resolve_request_pipeline`:

1. the resolver's signed key-aware resolution;
2. the operator env scope's local passthrough resolution (ADR 0036);
3. the normal `resolve`.

The helper returns a `ScopedResolution { resolution, byte_preserving }`. The
flag drives the managed-destination fail-closed rejection for **both** scope
sources: a covered request whose destination resolves to managed storage is
rejected with `CONFIG_INVALID` (managed storage keeps its transforms).

Pre-resolution dispatch coverage (Iceberg classification skip, multipart
table-unit rejection, streaming format-dispatch skip) uses
`byte_preserving_covers_async`: the env scope first (cheap, local), then the
resolver's key-aware scope. Coverage is never selected by client input.

## Consequences

- The hosted control plane implements `resolve_for_key` from its signed
  per-workspace declaration (private repo: `workspace_catalog_scopes` +
  normalized prefix child table, staged owner publication). The policy gate
  needs no new acceptance path: the resolution matches the signed route
  through the existing comparison.
- Self-hosted behavior is byte-identical; the env path and all ADR 0036/0037
  tests remain green.
- A write request may consult the resolver twice (dispatch coverage, then
  resolution). Implementations should cache the signed state; correctness
  does not depend on caching.
- The trait change is additive and defaulted: no breaking change for
  downstream implementors.

## Verification

- Frontdoor tests with a stub signed-scope resolver: byte-exact catalog
  round trip with the Iceberg gate closed and no env scope; uncovered
  table-shaped keys keep the gate verdict; when both sources cover a key, the
  recorded authorization carries the resolver's revision, never the env
  scope's local revision.
- The full existing gateway suites remain green.