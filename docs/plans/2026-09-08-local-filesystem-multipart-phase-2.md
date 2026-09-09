# Local filesystem multipart storage: Phase 2

## Status

Design approved on 2026-09-08. Implementation has not started.

This is the required Phase 2 follow-up to
`2026-09-08-local-filesystem-storage-minio-replacement.md`. It replaces the
older assumption that a `FileOperationJournal` alone is sufficient for local
multipart support.

## Objective

Provide restart-safe S3 multipart operations in standalone local mode without
Postgres, MinIO, cloud credentials, or an operator-supplied wrapping secret.
Preserve the existing authenticated, encrypted staging and transformation
pipeline while making filesystem persistence an implementation of shared
backend-neutral contracts.

The supported deployment is one active gateway process per FileStore root. It
targets MinIO's standalone single-node operational shape, not MinIO's
distributed multi-node mode.

## Current-State Findings

- Client multipart and destination multipart are separate state machines.
  `MultipartRepository` owns client uploads, parts, quota, completion fencing,
  replay, expiry, and cleanup. `OperationJournal` owns destination transaction
  recovery.
- Hosted `MASKURA_MULTIPART_MODE=staged` requires Postgres, durable key wrapping,
  and a separate S3-compatible artifact store. Standalone local staged mode uses
  the FileStore-root file repository, `FileOperationJournal`, encrypted local
  artifacts, and its persisted wrapping key instead.
- The current multipart handlers and transformation-at-completion pipeline are
  already backend-neutral. Completion can construct `FileSinkTransaction`, but
  local startup cannot construct durable multipart staging.
- `FileSinkTransaction` atomically publishes a complete object, but it has no
  durable operation identity. A crash after `sink.complete()` and before
  `MultipartRepository::complete_completion()` can cause a retry to rerun a
  randomized transform and overwrite the first committed result.
- FileStore startup deletes regular files under bucket `tmp` directories before
  any multipart journal can claim them. Multipart artifacts need a separate
  namespace and recovery must run before orphan deletion.
- The existing Postgres multipart repository already defines ownership,
  outbox, quota, lease, fencing, replay, tombstone, and cleanup semantics. A
  second FileStore-native protocol would duplicate these security-sensitive
  rules.
- The existing operation reconciler has no production bulk scheduler. Local
  recovery needs a bounded recurring worker in addition to startup repair.
- Current S3 conformance coverage is broad for memory and Postgres/S3 paths.
  FileStore-specific multipart lifecycle, restart, crash-window, and atomic
  visibility coverage does not exist.

## Decisions

### Reuse backend-neutral multipart contracts

Implement `FileMultipartRepository`, `FileStagingArtifactStore`, and
`FileOperationJournal` behind the existing traits. Do not add a parallel set of
local-only multipart handlers or duplicate the completion pipeline.

Introduce a `MultipartPersistence` construction bundle so startup selects a
coherent repository, artifact store, wrapping provider, journal, fenced commit
coordinator, and cleanup worker. Handlers consume trait objects and do not
branch on persistence location.

Add shared contract tests for every implementation:

- `MultipartRepository`: ownership, part replacement, quota accounting,
  outbox transitions, lifecycle CAS, lease takeover, fencing, replay, expiry,
  and cleanup.
- `StagingArtifactStore`: atomic put, streaming get, idempotent delete, complete
  listing, and orphan reconciliation.
- `OperationJournal`: state transitions, expected-state CAS, immutable parts and
  evidence, claims, restart, and corruption handling.
- Fenced destination commit: prepare, publish, probe, and retire by
  deterministic operation identity and typed authority.

### Filesystem layout

Store internal state beneath the mounted FileStore root and outside visible
bucket namespaces:

```text
<root>/
  buckets/
    ... existing visible object layout ...
  .maskura/
    root.lock
    wrapping.key
    multipart/
      uploads/<upload-id>/snapshot.json
      uploads/<upload-id>/events.log
      artifacts/<upload-id>/<part-number>/<attempt-id>.part
      tmp/<uuid>.tmp
    journal/
      operations/<operation-id>/snapshot.json
      operations/<operation-id>/events.log
      tmp/<uuid>.tmp
    commits/
      <operation-id>.json
      tmp/<uuid>.tmp
```

All dynamic path components are parsed typed identifiers or validated bounded
integers. User-provided bucket names, keys, metadata, and artifact keys never
become path components in this namespace.

Directories use owner-only permissions where supported. State, key, artifact,
and temporary files use mode `0600`. Implementations reject symlinks and
non-regular canonical files. Every successful mutation follows:

1. Serialize a versioned envelope containing an integrity checksum.
2. Create a unique temporary file in the destination filesystem.
3. Write all bytes and `sync_all` the file.
4. Atomically rename it to the canonical path.
5. Sync the parent directory before reporting success.

No error may roll in-memory state back after the canonical rename succeeds.
A rename is not considered durably acknowledged until its parent directory is
synced. If that sync fails, the result is mutation-unknown and startup reloads
the canonical state rather than rolling it back. Corrupt canonical state fails
startup closed and is never replaced with empty state.

High-frequency repository and journal transitions use an append-only framed
event log instead of rewriting the full snapshot. Each frame contains schema
version `1`, monotonic sequence, payload length, canonical JSON payload, and a
SHA-256 checksum over the header and payload. A trailing incomplete frame is a
torn append and is discarded; a complete frame with a bad checksum fails
closed. Under the state mutation mutex, every append uses `write_all` followed
by `sync_data` before updating observable in-memory state or returning success.
Append or sync failure is mutation-unknown: the implementation reloads and
validates the snapshot plus log under the same mutex before accepting another
operation and does not assume either rollback or persistence.

Compaction writes and syncs a complete snapshot, atomically publishes it, syncs
the directory, then replaces the event log. Compaction runs after 256 events or
4 MiB of log data. Snapshot and log replay are each capped at 32 MiB, audit
history at 256 entries, parts at 10,000, and evidence at 4,096 records per
operation. A compacted snapshot records its final event sequence; replay skips
duplicate older events if a crash leaves the prior log in place. Startup
durably truncates an ignored torn tail before allowing another append. Unknown
schema versions require an explicit migration and fail closed.

### Single active process

The local-storage runtime always holds an OS advisory exclusive lock on
`.maskura/root.lock` for the gateway lifetime, whether multipart is enabled or
not. Startup fails if another process holds the lock. This makes all FileStore
mutation serialization, repository CAS, and completion fencing valid across
the supported process model without pretending to provide distributed
coordination.

Low-level `FileStore` construction remains independently testable through an
explicit test-only unlocked constructor. The gateway-owned local-storage
runtime owns the process lock.

### Durable local wrapping key

On first multipart-enabled local startup, generate a random 256-bit wrapping
key with the operating-system CSPRNG. While holding the root lock, write it to a
unique mode-`0600` temporary file, sync the file, atomically publish it only if
the canonical key is absent, and sync the parent directory. A crash can leave a
complete temporary candidate but never a partial canonical key. Existing
canonical key material is validated and never overwritten.

The local wrapping key is part of the durable data volume and must be backed up
with it. Loss of the key makes encrypted staged parts unrecoverable and fails
startup closed. The key is never logged, returned through an API, or stored in
multipart snapshots.

### File multipart repository

Use one compacted snapshot plus framed event log per upload rather than
rewriting one global file or one growing upload document. The state contains
the complete authoritative upload identity, part attempts, completion
fingerprint and lease, fencing token, durable destination commit permit, stored
result, destination operation reference, expiry, accounting values, and
bounded cleanup audit entries.

One in-process mutation mutex serializes file-backed repository methods.
Global and tenant quota totals are reconstructed from validated upload
snapshots at startup and maintained atomically with per-upload mutations.
`begin_part` persists its `PENDING` reservation before request-body polling.
`commit_part` atomically promotes the attempt, retires any replaced current
attempt, and updates accounting. Artifact deletion remains outbox-driven and
idempotent.

Expand the shared repository contract with:

- authorized upload enumeration for ListMultipartUploads, including stable
  prefix, delimiter, key-marker, upload-ID-marker, and maximum pagination;
- a durable `begin_destination_commit` CAS that changes a completion from
  leased `COMPLETING` to `PUBLISHING` and returns a fencing-token-bound permit;
- `record_destination_commit` and `complete_completion` operations that accept
  only the current permit;
- terminal retirement that verifies no part, artifact, journal, or commit-proof
  references remain.

`PUBLISHING` cannot be taken over by an ordinary lease expiry. Recovery must
first prove the exact destination committed or prove publication absent, then
advance or abort that permit. This is the explicit contract that prevents a
worker from passing a lease check, losing ownership, and publishing anyway.

The file implementation preserves the existing repository limits, including
16 active uploads per tenant, parts `1..=10_000`, explicit per-upload and
aggregate byte quotas, monotonic completion fencing tokens, and 24-hour
terminal replay tombstones.

### Local encrypted artifact store

Reuse `EncryptedPartWriter` and `EncryptedPartReader` unchanged. A completed
encrypted spool file is atomically renamed into the internal artifact
namespace on the same filesystem. Cross-device moves are not allowed.

Refactor `StagingArtifactStore::get` to return a bounded boxed async reader (or
an equivalent provider-neutral body), not `aws_sdk_s3::primitives::ByteStream`.
The S3, memory, and file implementations adapt their native streams to that
type. `get` streams the canonical artifact. `delete` is idempotent. `list` walks the
complete controlled namespace and returns modification times for orphan grace
period enforcement. Multipart artifacts never share bucket `tmp` directories.

### Operation journal

Use one compacted snapshot plus checksummed framed event log per operation.
Each state contains the operation record, its multipart-upload reference,
sorted parts, and ordered evidence. Mutations are serialized and enforce the
existing transition matrix, expected-state CAS, terminal immutability,
committed-metadata invariant, immutable part retry identity, immutable evidence
identity, parent existence, and bounds.

Expand the shared journal contract with bounded terminal retirement using an
expected terminal state and expected multipart-upload reference. Claims are persisted before return. The single-process root lock supplies the
cross-process exclusion that the current journal trait cannot express.
Terminal journal records are retained until the multipart replay tombstone and
all referenced artifacts and commit proofs have been retired.

### Backend-neutral fenced destination commit

Extend the transaction/sink boundary with an explicit fenced destination commit
contract keyed by deterministic operation ID:

- `prepare`: consume the repository's durable `PUBLISHING` permit and bind the
  expected destination, digest, size, and backend-owned evidence.
- `publish`: publish only under that permit and return exact committed metadata
  plus opaque backend-owned proof.
- `probe`: determine whether that exact operation committed, remained prepared,
  or is absent using backend-owned proof rather than a generic generation model.
- `retire`: remove proof only after the repository and journal reference graph
  permits retirement.

The sink contract gains a fenced completion entry point accepting typed
`DestinationCommitAuthority`. Ordinary single PUT continues through explicit
unfenced local authority where atomic rename is sufficient; client multipart
must supply the durable repository permit. Sinks that cannot validate required
authority are rejected before mutation. FileStore implements proof with
operation-aware object metadata and immutable commit receipts. S3 keeps
provider upload/version evidence through `TransactionBackend`, adapted to the
same orchestration rather than duplicating its existing provider probe model.

### Local completion protocol

The local commit coordinator consumes the durable `PUBLISHING` permit and then
holds the FileStore mutation guard continuously across pointer publication,
commit-receipt persistence, and journal commit. Ordinary PUT, multipart PUT,
object DELETE, and bucket DELETE all use that same FileStore guard and must
backfill any missing receipt for the current pointer before changing it.

1. Persist journal `INTENT` with immutable destination and multipart-upload
   identity before any destination mutation.
2. Persist journal `OPEN` and the local prepared-publication identity.
3. Persist expected output and precommit usage/pipeline evidence needed to
   reconstruct the complete replay result.
4. Atomically acquire the repository `PUBLISHING` permit from the current
   completion lease and fencing token.
5. Persist journal state `COMPLETING` from `OPEN`.
6. Acquire the FileStore mutation guard and validate the same permit.
7. Persist a prepared manifest containing operation ID, destination,
   expected digest, expected size, and fence.
8. Sync and rename the composed object generation, then sync `objects/`.
9. Atomically publish current object metadata containing operation ID,
   generation ID, and fence.
10. Sync the metadata directory; a failure is mutation-unknown.
11. Persist and sync an immutable commit receipt containing ETag, source/output
    sizes and digests, pipeline evidence, usage evidence identity, and
    backend-owned generation proof.
12. Persist destination journal state `COMMITTED` with exact stored metadata.
13. Release the FileStore mutation guard.
14. Record the destination commit against the current repository permit.
15. Persist the full multipart completion replay result through
    `complete_completion` using that permit.

An ordinary completion lease cannot be taken over after `PUBLISHING` is
durable. A stale worker cannot acquire that permit after takeover, and a sink
without the current typed permit cannot publish.

Before replacing or deleting any operation-aware current object, FileStore
ensures its commit receipt is durable. Bucket deletion verifies no unresolved
operation-aware object remains. This preserves exact proof across later PUT,
DELETE, or bucket deletion. Single-PUT objects have no multipart operation
identity and continue using the Phase 1 path.

### Crash-state decisions

| Crash boundary | Durable evidence | Recovery result |
| --- | --- | --- |
| Before part reservation | No attempt | No artifact is owned; request retries normally |
| After `PENDING`, before artifact rename | Pending attempt | Reconciler releases reservation after artifact absence is proven |
| After artifact rename, before `commit_part` | Pending attempt plus artifact | Reconciler deletes artifact, then releases accounting |
| After part promotion, before old artifact delete | Current and retired attempts | Current remains readable; retired artifact is deleted idempotently |
| Before generation rename | Completing journal plus prepared manifest | Prior visible object remains; recovery proves publication absent before aborting the `PUBLISHING` permit |
| After generation rename, before `objects/` sync | Prepared manifest; directory entry uncertain | Reload determines whether generation exists; prior visible object remains |
| After `objects/` sync, before metadata rename | Durable unreferenced generation | Prior visible object remains; generation is reclaimed |
| After metadata rename, before metadata-directory sync | Pointer durability uncertain | Reload pointer and exact operation identity; never infer from object key alone |
| After metadata-directory sync, before receipt | Durable current pointer identifies operation while FileStore guard blocks PUT/DELETE | Create and sync exact receipt before releasing guard |
| After receipt rename, before receipt-directory sync | Pointer plus receipt entry of uncertain durability | Reload and validate receipt or recreate it from the exact current pointer |
| After receipt sync, before journal commit | Exact durable receipt | Journal is advanced to committed idempotently |
| After journal commit, before completion replay result | Committed journal and receipt | Retry recovers stored object metadata and completes repository state |
| After completion result, before artifact cleanup | Completed tombstone plus artifacts | Exact result replays; periodic worker removes artifacts and accounting |

Recovery never infers success merely because some object exists at the key. It
requires the exact deterministic operation identity and generation.

### Startup and recurring recovery

Startup performs these steps before binding the listener:

1. Acquire the root lock.
2. Load or initialize the wrapping key.
3. Load and validate multipart, journal, and commit-proof snapshots.
4. Repair receipts from operation-aware current metadata pointers.
5. Reconcile `PENDING`, `RETIRED`, terminal, and unknown artifacts.
6. Reconcile eligible local destination operations.
7. Remove only unowned recognized temporary files.
8. Construct `AppState` and begin serving.

A bounded worker runs every 60 seconds. It expires open uploads, deletes
outbox-owned artifacts, removes unknown artifacts after the existing grace
period, repairs commit receipts, claims eligible destination operations,
retires terminal uploads, and garbage-collects unreferenced proofs. Work is
processed in bounded batches and unresolved records remain eligible for later
runs.

The worker does not rerun a transform without a client completion retry. An
expired precommit `COMPLETING` lease becomes available to an identical retry. A
`PUBLISHING` permit must be reconciled to exact committed or exact absent state
before it can advance. A proven committed destination is completed and replayed
without transforming again.

### S3 multipart compatibility

Keep Maskura's transformation semantics while implementing the observable S3
multipart contract:

- CreateMultipartUpload.
- UploadPart with replacement and part numbers `1..=10_000`.
- Zero-byte parts, five GiB maximum part size, and five TiB maximum assembled
  source and transformed stored size.
- ListParts with marker and maximum pagination.
- ListMultipartUploads with prefix, delimiter, key/upload markers, and maximum
  pagination.
- CompleteMultipartUpload with strict ascending, non-contiguous parts.
- Five MiB minimum for every selected non-final source part.
- Initiation content headers, user metadata, tags, and supported checksum mode
  survive completion into FileStore metadata and GET/HEAD responses.
- Supported multipart checksum values are validated and replayed consistently.
- Exact completion replay and conflicting completion rejection.
- Atomic publication and atomic replacement of an existing object.
- Abort without changing an existing destination object.
- Canonical `NoSuchUpload`, `InvalidPart`, `InvalidPartOrder`,
  `EntityTooSmall`, and `MalformedXML` responses.

Multipart ETags identify Maskura's transformed stored output. They do not claim
to be AWS's source-part MD5 aggregate because filters can change bytes during
completion.

`UploadPartCopy`, versioning, ACLs, lifecycle, object lock, replication, and
distributed multipart coordination remain explicitly unsupported in this
phase and return the existing S3 `NotImplemented` response where routed.

## Ordered Implementation

Each task is one independently reviewed jj change. Start the next task with
`jj new`, describe it before implementation, and verify `jj st` plus
`jj log -r '@ | @-' -n 2` after every jj mutation. Do not combine persistence
primitives, repository state, destination publication, and startup wiring into
one change.

### 1. Filesystem durability primitives

- Add `crates/gateway/src/filesystem_persistence.rs` and export it internally
  from `crates/gateway/src/lib.rs`.
- Implement unique same-directory temporary files, owner-only permissions,
  atomic snapshot publication, required parent-directory sync, checksummed
  framed event append/replay, torn-tail repair, compaction, and an exclusive OS
  root lock. Add a focused file-locking dependency only if the standard library
  cannot express the required nonblocking advisory lock on every supported OS.
- Add deterministic pre/post-write, rename, append, sync, and compaction fault
  hooks under `cfg(test)`.
- Tests: `atomic_snapshot_preserves_previous_value_before_rename`,
  `post_rename_sync_failure_is_mutation_unknown`,
  `event_log_replays_synced_frames_in_sequence`,
  `event_log_repairs_only_a_torn_tail`,
  `event_log_rejects_checksum_or_sequence_corruption`,
  `compaction_crashes_replay_exactly_once`, and
  `root_lock_rejects_a_second_owner_and_releases_on_drop`.
- Gate: `cargo test --locked -p s4-gateway filesystem_persistence::tests` and
  `cargo clippy --locked -p s4-gateway --all-targets -- -D warnings`.

### 2. Locked local-storage runtime

- Add `crates/gateway/src/local_storage.rs` with `LocalStorageRuntime`, owning
  the root path, root lock, FileStore, and internal path construction.
- Acquire the lock before FileStore cleanup or any internal component opens.
  Production local startup retains the runtime in `AppState`; only explicit
  test constructors may open an unlocked store.
- Update `crates/gateway/src/file_store.rs` and startup construction in
  `crates/gateway/src/server.rs` without changing hosted resolution.
- Tests: same-root rejection, different-root concurrency, failed-open lock
  release, lock-before-cleanup ordering, and startup fail-closed behavior.
- Gate: focused `local_storage::tests` and the startup boundary tests.

### 3. Versioned FileStore metadata and exact commit proofs

- Extend the existing private metadata schema additively. Retain the existing
  `data_file`, `key`, `content_type`, `etag`, and `size` field meanings so Phase
  1 objects remain readable. Add defaulted schema version, representation
  headers, user metadata, tags, checksum state, operation ID, generation ID,
  and completion fence.
- Add prepared manifests and immutable proofs beneath `.maskura/commits/` plus
  exact `publish_transaction`, `probe_commit`, proof backfill, and retirement
  operations. Finding another object at the key is never proof.
- Ordinary overwrite, object DELETE, and bucket DELETE use the same mutation
  guard and backfill proof before changing an operation-aware pointer.
- Tests: legacy metadata read, operation-aware publish, every rename/sync crash
  boundary, proof recovery from current metadata, proof survival after
  overwrite/delete, mismatched-operation rejection, metadata restart, and
  proof retirement without object deletion.
- Gate: `file_store::tests` and `transaction::file::tests`.

### 4. Root-scoped wrapping key

- Add `FileKeyWrapping` in `crates/gateway/src/key_cipher.rs`, initialized only
  through `LocalStorageRuntime` while holding the root lock.
- Generate a CSPRNG 256-bit key, publish a versioned key record atomically with
  mode `0600`, and never replace malformed, unreadable, or insecure canonical
  material. Preserve any explicitly injected durable hosted wrapping provider.
- Tests: restricted permissions, concurrent/restart identity, malformed-key
  startup failure, explicit-provider precedence, and decrypting a pre-restart
  staged artifact after restart.
- Gate: focused key-cipher and encrypted-part restart tests.

### 5. Provider-neutral artifact streams

- Refactor `StagingArtifactStore` in
  `crates/gateway/src/multipart_staging.rs` so artifact open returns a bounded
  boxed async reader rather than an AWS SDK `ByteStream`.
- Adapt S3 and memory stores with no behavior change. Extract a shared artifact
  contract suite.
- Add `crates/gateway/src/file_staging_artifact.rs` implementing atomic local
  artifact put, streaming open, idempotent delete, complete stable list, path
  validation, symlink rejection, and restart behavior.
- Gate: shared artifact contract against memory/file, focused S3 adapter test,
  and current staged multipart integration tests.

### 6. Durable shared multipart and journal contracts

- Expand `MultipartRepository` with authorized upload enumeration, durable
  `COMPLETING -> PUBLISHING` permit acquisition, permit validation, exact
  destination-commit recording, proven-absence release, publishing recovery
  listing, and reference-safe terminal retirement.
- Expand `OperationJournal` with an optional client multipart upload reference
  and expected-reference terminal retirement.
- Add typed list request/page and `DestinationCommitPermit` models in shared
  code. `complete_completion` accepts the permit, not a raw fencing token.
- Add an additive SQL migration and SeaORM entity fields for `PUBLISHING`,
  operation cross-references, and publication timestamps. Existing rows remain
  valid with null references; never backfill guessed operation IDs.
- Run shared behavior tests against memory and Postgres before adding file
  implementations. Include stale permits, takeover exclusion, proven-absence
  release, authorized marker pagination, live-reference retirement rejection,
  and journal cross-reference CAS.
- Gate: `sqlx migrate info`, focused `db_keys_test`, multipart repository tests,
  and journal tests.

### 7. File multipart event reducer

- Add `crates/gateway/src/file_multipart_repository.rs` with explicit version-1
  snapshot and event types covering every repository transition.
- Keep reducer validation independent from I/O. Reject illegal lifecycle,
  fencing regression, quota overflow/underflow, unknown references, and
  conflicting duplicate identities; exact duplicate events are idempotent.
- Tests: full lifecycle replay, pending outbox/quota replay, exact duplicate,
  snapshot-plus-log equivalence, compaction crashes, and corruption failure.
- Gate: reducer and persistence test modules only.

### 8. File multipart repository adapter

- Implement the complete `MultipartRepository` contract over the reducer and
  event log under one async mutation mutex. Append and sync before publishing
  in-memory state; reload after mutation-unknown outcomes.
- Preserve reservation-before-body-polling, replacement accounting, selected
  part validation, durable fencing, replay, expiry, audit, and bounded
  retirement.
- Run one shared contract suite against memory, file, and configured Postgres.
- Add restart tests at every part, completion, permit, expiry, and retirement
  transition.
- Gate: `file_repository_contract` and focused file repository tests.

### 9. File operation journal adapter

- Add `crates/gateway/src/transaction/file_journal.rs` using the shared event
  log and snapshot primitives.
- Implement every journal mutation, durable claims-before-return, multipart
  cross-reference, exact state CAS, evidence/part immutability, restart, and
  terminal retirement.
- Run the shared journal contract against memory, file, and configured
  Postgres. Include lease restart and `COMMIT_UNKNOWN` recovery tests.
- Gate: `file_journal_contract` and focused file journal tests.

### 10. Explicit fenced sink completion

- Add typed `DestinationCommitAuthority` to the transaction boundary. Ordinary
  single PUT passes explicit unfenced local authority; client multipart must
  pass a durable permit. Do not retain a parameterless completion bypass.
- Update `FileSinkTransaction`, `DirectS3Sink`, managed wrappers, spool paths,
  and call sites. File validates the permit immediately before its mutation
  guard publishes; S3/managed bind the permit operation to their existing
  durable operation identity.
- Tests: missing/mismatched/stale permit rejection, immediate pre-rename
  recheck, explicit single-PUT authority, foreign S3 operation rejection, and
  exactly-once propagation through managed wrappers.
- Gate: file, S3 transaction, managed, and existing router PUT tests.

### 11. Multipart publication coordinator and retirement graph

- Extract backend-neutral completion orchestration to
  `crates/gateway/src/multipart_completion.rs`.
- Persist intent/open, expected output and usage evidence, then acquire
  `PUBLISHING`, invoke fenced sink completion, record exact destination commit,
  and finally persist the replay result.
- Recovery advances from exact file proof or terminal journal, releases only
  after exact absence, and leaves inconclusive publication pending.
- Encode retirement order: tombstone expiry, artifact removal, proof
  retirement, terminal journal retirement, destination-reference clear, upload
  retirement.
- Tests cover each ordering boundary and prove randomized output is never
  regenerated after a committed publication.
- Gate: focused coordinator tests plus existing Postgres/S3 durable multipart
  test.

### 12. Local startup and recurring recovery

- Replace independent startup booleans with a coherent
  `MultipartPersistenceMode` and bundle construction in
  `crates/gateway/src/server.rs`.
- In local staged mode construct FileStore, file repository, file artifact
  store, file journal, generated wrapping provider, and coordinator from the
  same locked root. Hosted/Postgres mode retains all current external
  prerequisites and never falls back to local state.
- Run lock, key, state validation, proof repair, artifact reconciliation,
  publishing reconciliation, and expiry before listener readiness. Expose
  one-shot bounded worker methods and start recurring workers afterward.
- Tests: local-only dependency success, unchanged hosted validation, corrupt
  startup failure, reconciliation-before-ready, recurring retry, and proof
  that local startup constructs no Postgres/S3 staging client.
- Gate: customer-config and focused startup/recovery tests.

### 13. Multipart listing and validation surface

- Extend `S3Query` and routing for ListMultipartUploads before ListObjects.
  Implement repository-authorized prefix/delimiter, key/upload markers,
  `max-uploads`, URL encoding, stable truncation, and XML response fields.
- Complete ListParts marker/maximum pagination, zero-byte final part handling,
  five MiB non-final minimum, five GiB part limit, five TiB assembled source
  and output limits, metadata/tag/checksum propagation, and canonical errors.
- Keep `UploadPartCopy` explicitly `NotImplemented`.
- Gate: focused route/XML/error tests and existing object-listing regressions.

### 14. No-service local multipart integration

- Add `crates/gateway/tests/local_filesystem_multipart.rs` using one temporary
  root and no database, external endpoint, cloud credential, staging bucket, or
  configured KEK.
- Cover create, out-of-order upload, replacement, ListParts,
  ListMultipartUploads, completion, GET/HEAD, exact replay, conflict, abort,
  metadata/tags/checksums, PII filtering, and restart between client-visible
  phases.
- Inspect internal files to prove plaintext PII never appears in artifacts,
  logs, snapshots, proofs, keys, or metadata.
- Gate: the complete new integration target.

### 15. Deterministic crash and retirement matrix

- Use test-only fault hooks to restart after every part outbox, permit,
  generation rename/sync, metadata rename/sync, proof, journal commit, replay
  result, artifact deletion, and retirement boundary in the Decisions table.
- Add stale-worker/takeover concurrency and torn-tail versus complete-frame
  corruption tests.
- Gate: all `restart_` and fault-injection tests in the local multipart target.

### 16. General S3 conformance and SDK interoperability

- Extend the existing original LocalStack/MinIO-derived FileStore scenarios
  with multipart happy path, errors, pagination, replacement, atomic overwrite,
  abort, replay, and restart.
- Run an unmodified Rust AWS SDK multipart flow against a real TCP listener;
  retain opt-in AWS CLI and boto3 coverage where those clients are installed.
- Fix only behavior promised by ADR 0012/0013. Do not pull versioning, ACL,
  policy, lifecycle, copy, or distributed features into this phase.
- Gate: FileStore conformance and SDK tests.

### 17. Configuration, CLI, documentation, and final gates

- Update `maskura local init` to mount and reuse one durable data volume for
  keys, objects, `.maskura` state, and the wrapping key, without configuring
  Postgres, MinIO, staging credentials, or an explicit KEK. Preserve existing
  key data during the path transition.
- Update customer configuration, security documentation, ADR implementation
  status, local CLI output, and the broader MinIO-replacement plan. Document
  locking, backup/key loss, encrypted artifacts, event-log repair, publishing
  recovery, retention order, and downgrade limits.
- Preserve the existing MinIO compose/e2e flow as external S3 validation.
- Gate: customer-config tests, CLI argument tests, `mdbook build docs`,
  `just check`, `just deny`, and `just audit`.

## Verification Gates

- Shared contract suites pass for memory/Postgres/file repositories and
  journals, and memory/S3/file artifact stores.
- Every persisted transition has restart tests at the boundary before and
  after canonical rename.
- Corrupt snapshots, unknown versions, unsafe permissions, symlinks, duplicate
  identities, and invalid state transitions fail closed without replacement.
- Two gateways cannot concurrently acquire one FileStore root.
- Part reservation occurs before body polling and failed uploads have no quota
  or artifact leak.
- Part replacement, abort, expiry, and terminal retirement converge after
  repeated crashes.
- A stale completion fencing token cannot publish after takeover.
- PUT, DELETE, and bucket DELETE cannot erase exact commit proof during the
  pointer-to-receipt crash window.
- Every crash point in the completion table preserves either the prior object
  or the exact complete new generation; no partial object is visible.
- A committed randomized transformation is recovered without rerunning it.
- Local multipart create/upload/list/complete/get/replay/abort survives gateway
  restart without Postgres or an S3 staging service.
- LocalStack- and MinIO/Mint-derived core multipart scenarios pass using
  original repository-owned tests.
- An unmodified AWS SDK completes multipart upload against local mode.
- Existing Postgres/S3 staged multipart and managed-storage suites remain
  behaviorally unchanged.
- Large multipart completion remains bounded by existing streaming and spool
  limits; no whole-object in-memory assembly is introduced.
- `just check`, `just deny`, and `just audit` pass.
- `mdbook build docs` passes.

## Success Criteria

- `MASKURA_STORAGE_MODE=local` can enable durable staged multipart with one
  mounted directory and no Postgres, MinIO, cloud credentials, or configured
  wrapping secret.
- The gateway fails startup if the root is already active, required state is
  corrupt, or staged artifacts cannot be decrypted.
- Multipart ownership, quotas, outbox cleanup, fencing, replay, and expiry match
  the shared repository contract.
- Destination publication is atomic and exact completion can be proven after a
  crash or later overwrite.
- Recovery is bounded, recurring, idempotent, and runs before destructive temp
  cleanup or listener startup.
- Hosted Postgres/S3 and managed backends continue using the same generic
  orchestration without local filesystem knowledge leaking into handlers.
- S3 clients can create, upload, replace, list, complete, replay, abort, and
  retrieve multipart objects through the local endpoint.

## Open Decisions

None. The approved choices are generated local wrapping key, one active gateway
per FileStore root, reuse of the existing staged multipart protocol,
provider-neutral artifact readers, durable `PUBLISHING` permits, backend-owned
commit proof, and version-1 checksummed event logs with bounded compaction.
