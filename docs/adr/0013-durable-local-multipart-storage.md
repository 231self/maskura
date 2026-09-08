# ADR 0013: Durable local multipart storage

- Status: Accepted
- Date: 2026-09-08

## Context

ADR 0012 introduced a single-node FileStore for ordinary S3 object operations
and deferred multipart until durable journaling existed. The current multipart
pipeline uses two independent persistence boundaries: `MultipartRepository`
owns client uploads, encrypted parts, quotas, completion fencing, replay, and
cleanup, while `OperationJournal` owns destination transaction recovery.

Adding only a file operation journal would leave local multipart dependent on
Postgres and an external S3 staging service. It would also leave a crash window
between FileStore publication and durable completion replay state. A safe local
implementation needs coordinated lifecycle persistence, encrypted artifact
storage, exact destination commit proof, startup recovery, and cleanup.

The alternatives were a separate FileStore-native multipart protocol, an
embedded database, and file-backed implementations of the existing generic
contracts. A native protocol would duplicate security-sensitive multipart
logic. An embedded database would add a second database architecture solely
for local mode.

## Decision

Implement local multipart through file-backed implementations of the existing
backend-neutral contracts:

- `FileMultipartRepository` for upload lifecycle, quota, outbox, fencing,
  replay, expiry, and audit state.
- `FileStagingArtifactStore` for encrypted source-part artifacts.
- `FileOperationJournal` for destination transaction state and recovery.
- A backend-neutral fenced destination commit interface using durable
  `PUBLISHING` permits and backend-owned exact proof.

Store this internal state beneath `<FileStore root>/.maskura/`, separate from
visible bucket data. Use version-1 checksummed framed event logs with bounded
compacted per-upload and per-operation snapshots, owner-only permissions,
unique temporary files, file sync, atomic rename, and directory sync. Corrupt
durable state fails startup closed.

Generate and persist a local 256-bit wrapping key under the FileStore root on
first use. The mounted data volume and wrapping key form one backup and recovery
unit.

Support one active gateway process per FileStore root and enforce it in the
local-storage runtime with an OS exclusive lock held for the runtime lifetime,
whether multipart is enabled or not. Multi-process and distributed filesystem
coordination are outside this backend's contract.

The repository durably changes an owned completion lease to a fencing-bound
`PUBLISHING` permit before destination mutation; publishing completions cannot
be taken over by ordinary lease expiry. Serialize FileStore multipart
publication, metadata-directory sync, commit receipt, and journal commit under
the same FileStore mutation guard used by ordinary PUT and DELETE. Object
metadata records deterministic operation and generation identity, and
immutable commit receipts preserve exact proof across crashes, replacement,
and deletion. Recovery requires exact operation identity; finding an arbitrary
object at the same key is not proof of completion.

Run validation and reconciliation before serving traffic, followed by a
bounded recurring cleanup and recovery worker. Multipart HTTP handlers and the
transformation pipeline remain persistence-neutral.

## Consequences

- Standalone local mode can provide durable multipart uploads with one mounted
  volume and without Postgres, MinIO, cloud credentials, or an operator-managed
  wrapping secret.
- The local wrapping key is security-critical backup material. Losing it makes
  incomplete encrypted multipart uploads unrecoverable.
- A second process using the same root fails startup rather than risking split
  ownership or stale fencing.
- Filesystem state and recovery logic are substantial, but shared contract
  tests prevent local behavior from drifting from Postgres/S3 multipart
  semantics.
- Existing hosted and managed implementations retain their persistence
  backends and gain reusable fenced-commit orchestration rather than FileStore
  branches in request handlers. Artifact reads become provider-neutral rather
  than exposing AWS SDK stream types in the shared trait.
- This decision does not add replication, distributed locking, versioning,
  lifecycle policies, ACLs, or other advanced MinIO features.
- Implementation details and crash-state requirements are specified in
  `docs/plans/2026-09-08-local-filesystem-multipart-phase-2.md`.
