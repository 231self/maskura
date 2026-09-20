# Gateway large-file modularization design

Status: Approved

Date: 2026-09-20

Related: `crates/gateway/src/server.rs`, `crates/gateway/src/managed.rs`,
`crates/gateway/src/lib.rs`

## Problem

`crates/gateway/src/server.rs` is 14,343 lines and holds the entire HTTP
surface of the gateway: state construction, authentication, S3 object and
multipart handlers, the workspace-leasing/fencing machinery, the demo
endpoints, the dashboard/admin handlers, OpenAPI, the router, and roughly half
its lines in tests. It is one flat module with no internal `mod` splits.

A single file this large is hard to navigate, hard to review, and hard to hold
in context. It is the largest file in the crate, but not the only large one:

| File | Lines |
|---|---|
| `server.rs` | 14,343 |
| `managed.rs` | 13,348 |
| `service_storage.rs` | 4,747 |
| `multipart_staging.rs` | 4,606 |
| `file_multipart_repository.rs` | 4,053 |
| `store.rs` | 3,792 |
| `transaction/s3.rs` | 3,448 |
| `backend.rs` | 2,759 |
| `plugin_registry.rs` | 2,624 |

This increment addresses `server.rs` only. The others are deliberately out of
scope until this pattern is proven.

### Current structure of `server.rs`

Production code and tests are interleaved, not layered:

- Production helpers and handlers occupy lines ~1–8,047.
- A large `#[cfg(test)] mod tests {` opens at `server.rs:8049`.
- More `#[cfg(test)] mod *_tests` blocks and free `#[test]` functions follow,
  interleaved with live production code:
  - `reject_unsupported_s3_operations` at `server.rs:11521`,
  - `default_listen_addr` at `server.rs:12245`,
  - `build_router` at `server.rs:13617`,
  - `mod mcp_token_response_tests` at `server.rs:13684`, and further test
    modules after that.

There is therefore no single line where "production ends and tests begin";
test relocation has to be done per area.

### Public surface that must be preserved

Consumers import through the module path `maskura_gateway::server`:

- `crates/gateway/src/main.rs:9` — `use maskura_gateway::server::{build_router, build_state, default_listen_addr};`
- `crates/gateway/tests/{db_keys_test.rs, local_filesystem_multipart.rs, s3_multipart_conformance.rs, s3_frontdoor_test.rs, router_test.rs}` — `use maskura_gateway::server::{...};`
- `crates/mcp/tests/stdio_e2e.rs`
- `crates/gateway/tests/s3_frontdoor_test.rs:6387` references `maskura_gateway::server::MAX_INVOCATION_RESPONSE_BYTES`.

No external file should need to change: `server.rs` keeps re-exporting every
currently-public item.

## Goals

- Reduce `server.rs` to a small public façade and a set of single-purpose
  child modules under `crates/gateway/src/server/`.
- Preserve the public API and behavior exactly: no logic changes, no
  signature changes, no changed responses.
- Keep every intermediate state compiling and green, so each step is a small,
  reviewable, revertable change.
- Make each module answer three questions on its own: what it does, how it is
  used, and what it depends on.
- Leave the two-phase path explicit: extract production first, relocate tests
  second.

## Non-goals

- Not refactoring `managed.rs`, `service_storage.rs`, `multipart_staging.rs`,
  `file_multipart_repository.rs`, `store.rs`, `transaction/s3.rs`,
  `backend.rs`, or `plugin_registry.rs`. (Reassess after `server.rs`.)
- Not changing internal logic, error handling, or the S3 wire behavior.
- Not adopting a mechanical line-count policy or a lint cap.
- Not introducing new abstractions, traits, or crate boundaries.
- Not moving tests into `crates/gateway/tests/` integration tests.

## Invariants

1. **Behavior is unchanged.** Every PR is pure movement plus the minimum
   visibility change needed to compile. No test is edited in the production
   extraction phase.
2. **The public path is stable.** `maskura_gateway::server::{build_router,
   build_state, default_listen_addr, AppState, ...}` continue to resolve, via
   `pub use`/`pub(crate) use` re-exports in `server.rs`.
3. **Tests keep compiling.** Unit tests stay in-crate under `#[cfg(test)]`;
   because `server.rs` re-exports the moved items, existing `use super::...`
   paths in `server.rs` tests resolve unchanged.
4. **Each step is independently green.** `just check` passes on every PR.
5. **Each PR is revertable.** Pure moves make `jj backout` clean.
6. **One area per PR.** No PR mixes two areas, and no PR both moves production
   code and relocates tests.

## Design

### Target layout

`server.rs` remains the public façade: module doc comment, re-exports of the
public surface, and the OpenAPI aggregation entry point. Each domain moves to
`crates/gateway/src/server/<area>.rs`, matching the existing submodule
directory convention already used by `crates/gateway/src/transaction/` and
`crates/gateway/src/entity/`.

### Area map

Production items, grouped by domain (line numbers are current anchors):

| Module | Contents |
|---|---|
| `server/state.rs` | `AppState` (`:113`), `StatePipelineTemplate` (`:685`), `InvocationLimits` (`:13267`), `Auth` (`:159`), `TrustedInvocationContext` (`:167`), config/limits helpers and constants (`:638`–`:1073`), `StreamingReadMode` (`:881`), `build_state` (`:12583`), `build_state_with_pipeline_template` (`:12606`) |
| `server/auth.rs` | operation identity/usage types (`:178`–`:281`), metering (`:300`–`:600`), header/SigV4 auth (`:1942`–`:2460`) |
| `server/admin.rs` | dashboard DTOs (`:1074`–`:1199`) and handlers (`:11900`–`:13616`) |
| `server/openapi.rs` | `ApiDoc` (`:1199`) and the `utoipa` paths/schemas aggregation |
| `server/demo.rs` | demo pipeline/limiter types and limits (`:653`–`:881`); redact/process endpoints and DTOs (`:2477`–`:2997`) |
| `server/workspace_lease.rs` | `:3167`–`:3885`, `:5521`–`:5767` |
| `server/s3_objects.rs` | `:1152`, `:1222`–`:1941`, `:6860`–`:7600` |
| `server/s3_upload.rs` | `:3016`–`:3166`, `:3886`–`:4377`, `:7604`+ |
| `server/multipart.rs` | `:604`–`:652`, `:4378`–`:6693` |
| `server/read_transform.rs` | `:6694`–`:7603` |
| `server/routing.rs` | `reject_unsupported_s3_operations` (`:11521`), `default_listen_addr` (`:12245`), `build_router` (`:13617`) |

Items that do not obviously belong to a single area (shared small helpers) are
placed with their primary caller and re-exported; the first PR (`state.rs`)
establishes the visibility/export convention the rest follow.

### Extraction mechanics

For each area PR:

1. Create `server/<area>.rs` and move the area's items and their attributes
   (`#[utoipa::path]`, `#[derive]`, `#[cfg(test)]`) verbatim.
2. Bump visibility only as far as compilation requires. A child module's
   private items are not visible to the parent, so items used by `server.rs`,
   by `build_router`, or by tests become `pub(crate)` (or `pub` where already
   part of the public surface). This is the only permitted "cleanup".
3. Add re-exports in `server.rs`: `pub use <area>::*;` for the public surface,
   `pub(crate) use <area>::…;` for crate-internal items. This keeps external
   consumers and the in-file tests compiling unchanged.
4. Run `just check`. Do not edit any test.
5. Commit as a single move-only change; open one PR.

### Test relocation (second phase)

After production extraction, relocate each area's tests in its own small PR:
move the area's `#[cfg(test)] mod tests` / `mod *_tests` blocks and free
`#[test]` functions into `server/<area>/tests.rs` (or
`server/<area>_tests.rs`), keeping them in-crate under `#[cfg(test)]`, and fix
`super::` paths as part of the move. Large in-crate integration tests
(`crates/gateway/tests/s3_frontdoor_test.rs` and friends) are outside
`server.rs` and are not part of this phase.

### Delivery order

1. `server/state.rs`
2. `server/demo.rs`
3. `server/admin.rs`
4. `server/openapi.rs`
5. `server/auth.rs`
6. `server/workspace_lease.rs`
7. `server/multipart.rs`
8. `server/read_transform.rs`
9. `server/s3_objects.rs`
10. `server/s3_upload.rs`
11. `server/routing.rs`

The test-relocation phase mirrors the same order.

### Verification

- Every PR: `just check` (format, lint, plugins, tests).
- Before any push: `just pre-push`.
- No new functionality means no new tests are required; the existing suite is
  the correctness oracle for the moves.

## Risks and mitigations

- **Visibility creep.** Child-module privacy forces some `pub(crate)` bumps.
  Mitigation: bump only what compilation demands.
- **Interleaved tests.** Tests are not one block. Mitigation: extract by
  ownership, not line range; tests are a separate phase.
- **Hidden coupling.** Mitigation: order starts with isolated areas; shared
  helpers stay with their primary caller and are re-exported.
- **OpenAPI drift.** Mitigation: keep `ApiDoc` in `openapi.rs`, import
  handlers/types, and confirm the generated schema is unchanged.

## Testing

- The full existing gateway test suite must pass unchanged after every PR.
- The generated OpenAPI document must be unchanged.
- No test file is edited during the production-extraction phase.

## Open decisions

None. Scope is `server.rs` only; after it lands, reassess whether to apply the
same pattern to the other large files listed in the problem statement.
