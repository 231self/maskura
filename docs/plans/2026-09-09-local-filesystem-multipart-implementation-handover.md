# Local filesystem multipart implementation handover

## Purpose

This document is the resume point for implementing durable S3 multipart support
in standalone local FileStore mode. The implementation session became unstable
during long-running delegated tasks, so continuation should use small,
foreground steps and validate each existing change before starting another.

The authoritative architecture and full verification criteria remain:

- `docs/plans/2026-09-08-local-filesystem-multipart-phase-2.md`
- `docs/adr/0013-durable-local-multipart-storage.md`
- `docs/adr/0012-local-filesystem-object-storage.md`

## Goal

`MASKURA_STORAGE_MODE=local` plus `MASKURA_MULTIPART_MODE=staged` must support
restart-safe S3 multipart upload with one mounted directory and without
Postgres, MinIO, cloud credentials, an external staging bucket, or an
operator-supplied wrapping key.

The completed system must preserve:

- encrypted source-part staging;
- ownership and quota enforcement before body polling;
- durable part replacement and cleanup outboxes;
- completion leases and monotonically fenced publication;
- exact completion replay without rerunning randomized transforms;
- atomic FileStore visibility and overwrite behavior;
- exact operation proof across crashes, overwrite, and delete;
- fail-closed startup on corrupt or insecure local state;
- one active gateway process per FileStore root;
- existing hosted Postgres/S3 and managed-storage behavior;
- bounded recurring recovery and cleanup;
- general S3 and multipart conformance through unmodified clients.

## Explicit Non-Goals

- Distributed or multi-process access to one FileStore root.
- S3 versioning, ACLs, bucket policy, lifecycle, object lock, or replication.
- `UploadPartCopy`.
- Replacing hosted Postgres/S3 multipart persistence.
- Claiming AWS multipart ETag semantics for transformed output.

## Workspace And VCS

Work only in:

```text
/Users/amitmor/ExternalProjects/maskura/.worktrees/filesystem-storage
```

This is a jj workspace on local bookmark `feat/filesystem-storage`. Use jj only
for VCS mutations. The implementation uses describe-first changes. Before each
new task:

```bash
jj st
jj log -r '@ | @-' -n 2 --no-graph
jj new
jj describe -m "<description>"
jj st
jj log -r '@ | @-' -n 2 --no-graph
```

Do not push until the complete plan passes its final gates.

## Build Hygiene

The active feature workspace has one warm Cargo target directory of roughly
13 GiB. No duplicate root target directory was found. Keep it warm rather than
running `cargo clean` or moving it mid-implementation.

Always expose the Cargo-installed toolchain first:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

The active toolchain currently has `rustup`, `wasm32-unknown-unknown`, and
`wasm32-wasip1`. `mdbook v0.5.4` is installed at `~/.cargo/bin/mdbook`.

The earlier missing-filter failure was environmental and is resolved:

```bash
just build-filters
```

now succeeds.

## Completed Change Stack

These described jj changes are complete ancestors of the current work:

| Change ID | Description | Result |
| --- | --- | --- |
| `svlrpuzo` | `feat(storage): stream FileStore reads and add S3 conformance coverage` | Full/range streaming reads, race hardening, FileStore S3 scenarios |
| `lroyqusq` | `docs(storage): design durable local multipart storage` | Approved plan and ADR 0013 |
| `lwwxnpol` | `refactor(storage): add filesystem durability primitives` | Atomic snapshots, event logs, compaction, root lock, fault tests |
| `qnqvuuxs` | `feat(storage): lock the local storage runtime` | Root lock retained before FileStore cleanup |
| `xttvlsuz` | `feat(storage): persist exact FileStore commit proofs` | Additive metadata v2, prepared/committed proof, exact probe/backfill/retire |
| `lvmlnutw` | `feat(storage): persist the local multipart wrapping key` | Root-scoped mode-0600 wrapping key and restart decryption |
| `woqkzrsv` | `feat(storage): add local multipart artifact storage` | Provider-neutral artifact readers and durable local encrypted artifacts |
| `pwyzuvwx` | `feat(storage): add durable multipart publishing permits` | Shared `PUBLISHING` permit/list/reference contracts and SQL migration |
| `qnsxtotn` | `feat(storage): add the file multipart event reducer` | Pure V1 reducer and invariant/replay tests |
| `vlttqyou` | `feat(storage): persist local multipart upload state` | Complete `FileMultipartRepository` and restart/concurrency tests |
| `vuqklvwt` | `feat(storage): persist the local operation journal` | Complete `FileOperationJournal`, claims, references, retirement |
| `tsryppnw` | `refactor(storage): require explicit sink commit authority` | Typed sink authority; no parameterless completion bypass |
| `nsllvqqu` | `feat(storage): coordinate fenced multipart publication` | Permit-first coordinator, exact local recovery, retirement ordering |

Focused tests and all-target clippy passed at each completed boundary. The
Postgres test wrappers compiled, but live database bodies were skipped because
`DATABASE_URL` was not configured. Migration
`20260909000001_multipart_publishing_permits.sql` still requires a live
`sqlx migrate info` and Postgres execution before final completion.

## Current Working Change

Current jj change:

```text
nxzqrknr feat(storage): start durable local multipart services
```

This is partial Task 12. Do not abandon or regenerate it.

Current modified files:

```text
crates/gateway/src/file_multipart_repository.rs
crates/gateway/src/file_staging_artifact.rs
crates/gateway/src/file_store.rs
crates/gateway/src/local_storage.rs
crates/gateway/src/multipart_staging.rs
crates/gateway/src/server.rs
```

Current diff size is approximately 628 insertions and 159 deletions. It already
contains:

- `MultipartPersistenceMode::{Reject, LocalStaged, HostedStaged}`;
- coherent local versus hosted startup validation;
- local wrapping, repository, artifact store, operation journal, and FileStore
  construction from one `LocalStorageRuntime`;
- `MultipartCompletionCoordinator` construction with local proof support;
- `MultipartRecoveryRuntime` and a bounded startup `run_once` call;
- root-scoped local key-store placement;
- worker storage in `MultipartPersistenceBundle`;
- tests named `local_staged_persistence_requires_no_hosted_dependencies` and
  `multipart_recovery_orders_artifacts_before_expiry_and_retries_on_next_run`;
- FileStore proof validation/backfill helpers and bounded repository recovery
  helpers.

Current validation:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo check --locked -p s4-gateway
```

passes. No `TODO`, `todo!`, or `unimplemented!` markers were found. Task 12 has
not yet passed its focused tests, clippy, or full frontdoor suite.

## Immediate Resume Steps

### 1. Finish and validate Task 12

Read the current diff before editing:

```bash
jj diff
```

Then run the smallest focused gates:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all -- --check
cargo test --locked -p s4-gateway local_staged_persistence_requires_no_hosted_dependencies
cargo test --locked -p s4-gateway multipart_recovery_orders_artifacts_before_expiry_and_retries_on_next_run
cargo test --locked -p s4-gateway local_storage::tests
cargo test --locked -p s4-gateway file_multipart_repository
cargo test --locked -p s4-gateway file_journal
cargo test --locked -p s4-gateway multipart
cargo clippy --locked -p s4-gateway --all-targets -- -D warnings
```

Fix failures in the current six files only unless the compiler demonstrates a
missing contract change. Confirm specifically:

- local staged mode creates no AWS staging client or Postgres repository;
- hosted staged mode still requires every existing external dependency;
- startup recovery runs before `AppState` is returned;
- periodic worker ownership is retained for the state lifetime and cancels on
  shutdown/drop;
- artifact reconciliation occurs before upload expiry/accounting release;
- `PUBLISHING` mismatches remain pending rather than being deleted;
- recovery batches are bounded and unresolved work is retried;
- default multipart mode remains `Reject`;
- no temporary `allow(dead_code)` remains for APIs consumed by Task 12.

After focused gates pass, run:

```bash
just build-filters
cargo test --locked -p s4-gateway --test s3_frontdoor_test
```

Only then start a new jj change.

### 2. Task 13: multipart listing and validation

Description:

```text
feat(s3): complete multipart listing and validation
```

Implement:

- `GET /bucket?uploads` dispatch before ordinary object listing;
- ListMultipartUploads authorization, prefix/delimiter grouping,
  key/upload-ID markers, `max-uploads`, URL encoding, stable pagination, and S3
  XML fields;
- ListParts `part-number-marker` and `max-parts` pagination;
- zero-byte final part;
- five MiB minimum for selected non-final parts;
- five GiB per-part and five TiB source/output limits;
- initiation metadata, tags, representation headers, and supported checksum
  propagation into FileStore metadata and GET/HEAD;
- canonical `NoSuchUpload`, `InvalidPart`, `InvalidPartOrder`,
  `EntityTooSmall`, `InvalidArgument`, and `MalformedXML` errors;
- explicit `NotImplemented` for `UploadPartCopy`.

Add table-driven router tests before changing handlers. Reuse the shared
repository list contract rather than enumerating filesystem state in handlers.

### 3. Task 14: no-service local multipart integration

Description:

```text
test(storage): cover standalone local multipart lifecycle
```

Add `crates/gateway/tests/local_filesystem_multipart.rs`. Build state through a
pure/local constructor where possible; do not use process-global environment in
parallel tests.

Cover create, out-of-order part upload, replacement, ListParts,
ListMultipartUploads, complete, GET/HEAD, exact replay, conflicting replay,
abort, metadata/tags/checksums, filtering, and restart after every
client-visible phase. The test must run with no `DATABASE_URL`, S3 endpoint,
staging credentials, or configured KEK.

Inspect every file under the temporary root and assert known plaintext PII is
absent from artifacts, logs, snapshots, proofs, key records, and metadata.

### 4. Task 15: deterministic crash and retirement matrix

Description:

```text
test(storage): cover local multipart crash recovery
```

Use existing `cfg(test)` fault hooks. Restart at every boundary in the crash
table in the authoritative Phase 2 plan, including event append/sync,
generation rename/directory sync, metadata rename/directory sync, proof,
journal commit, replay result, artifact deletion, and retirement.

Prove:

- prior object or exact complete replacement is always visible;
- no partial object becomes visible;
- stale completion workers cannot publish after takeover;
- committed randomized transforms are not rerun;
- torn tails repair, while complete corrupt frames fail closed;
- retirement never removes a live proof/reference.

### 5. Task 16: S3 conformance and SDK interoperability

Description:

```text
test(s3): add local multipart conformance coverage
```

Extend the original LocalStack/MinIO-derived scenarios without copying MinIO
AGPL source. Cover multipart happy path, part replacement, list pagination,
completion errors, atomic overwrite, abort, replay, difficult keys, and restart.

Run an unmodified Rust AWS SDK multipart flow against a real TCP listener.
Retain optional AWS CLI and boto3 coverage when installed.

### 6. Task 17: configuration, CLI, and final documentation

Description:

```text
docs(storage): complete standalone multipart rollout
```

Update `maskura local init`, customer configuration, `docs/security.md`, ADR
implementation status, local CLI output, and the broader MinIO-replacement
plan. One durable volume must contain keys, objects, `.maskura` state, and the
wrapping key without losing existing key data.

Document locking, backup/key loss, encrypted staging, event-log repair,
publication recovery, retention order, unsupported S3 features, and downgrade
limitations.

## Final Verification

Run these only after Tasks 12 through 17 pass focused gates:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
just build-filters
just check
just deny
just audit
mdbook build docs
```

With a configured local Postgres test database, also run:

```bash
sqlx migrate info
cargo test --locked -p s4-gateway --test db_keys_test
```

Finally verify:

```bash
jj st
jj log -r 'ancestors(@, 20)' --no-graph
```

Do not claim full plan completion if the live Postgres migration/tests, local
restart integration, deterministic crash matrix, AWS SDK multipart flow, deny,
audit, or docs build are skipped.

## Known Risks To Review

- Task 12 was generated by an interrupted worker. Compilation passes, but
  runtime lifecycle and recovery ordering require direct review.
- The SQL migration compiles through `sqlx::migrate!`, but has not run against
  live Postgres in this workspace.
- macOS emits an existing non-fatal compact-unwind linker warning because the
  gateway test binary is very large.
- Direct `FileStore::new` remains available for compatibility and tests;
  production local startup must always use locked `LocalStorageRuntime`.
- Do not reintroduce AWS SDK stream types into `StagingArtifactStore`.
- Do not add an untyped or parameterless sink-completion bypass.
- Do not infer commit success from object-key existence; require exact operation
  and generation proof.
- Do not delete `PUBLISHING` state or artifacts while exact publication remains
  inconclusive.
