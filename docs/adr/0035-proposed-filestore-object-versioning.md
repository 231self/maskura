# ADR 0035: FileStore object versioning

- Status: Accepted
- Date: 2026-11-13

## Context

Before this change, the Docker local appliance persisted current object bytes
and metadata, but did not expose persistent S3 object history. `?versioning`
and `?versions` were rejected
with `501 NotImplemented`. Internally version-named data files and multipart
commit proofs support atomic publication/recovery; they do not establish
customer-addressable S3 versions. Superseded data files could be removed.

The requested scope is durable versioning for **Docker/FileStore only**. Atomic
create-only writes and bucket/prefix access policies were removed from this
delivery scope and remain [known gaps](../known-gaps.md). Managed storage,
customer S3 backends, presigned proxying and the memory store are unchanged.

## Decision

Adopt an opt-in local bucket versioning contract with durable bucket settings,
retained object versions, concrete opaque version IDs returned on successful
versioned PUT/multipart completion, and exact-version GET/HEAD across restart.
Unversioned buckets retain their existing behavior.

Storage approaches considered:

- Extend the existing FileStore layout with one atomic, newest-first per-key
  manifest (schema 3). Its first entry defines latest; there is no separately
  committed latest index. This preserves the standalone mounted-volume model
  without another service or cross-index commit boundary.
- Introduce a separate local metadata database. This adds a dependency and a
  second durability/recovery boundary; no such dependency is selected here.
- Delegate versioning to an external S3 provider. This does not meet the
  standalone Docker/FileStore scope.

The implementation must preserve these invariants:

- Each retained version binds its stored bytes and representation metadata,
  including content type, ETag and supported customer metadata.
- Publication, history retention and latest selection have a reviewed durable
  commit/recovery protocol. A process-local lock alone is insufficient proof of
  crash consistency; incomplete history must not be acknowledged as committed.
- Existing process-root ownership, multipart fencing and commit-unknown semantics
  remain intact. Recovery/replayed completion must identify the same committed
  version instead of creating another version or mistaking a later write for it.
- Exact-version reads use existing authentication, authorization and applicable
  read processing. A version selector provides no raw-storage bypass and must
  never silently fall back to the latest object.
- Legacy current objects stay readable. Startup cleanup must distinguish retained
  versions, recovery evidence and actual disposable files.

The owner approved delete markers, explicit version deletion, version enumeration
and Enabled/Suspended/null-version semantics on 2026-11-13. The
[storage/API design](../superpowers/specs/2026-11-13-filestore-versioning-design.md)
specifies legacy-object treatment, publication/recovery and the exact lifecycle
contract. Bucket configuration and history publication share the mutation guard;
PUT and multipart use the state at publication, not initiation. Owned mutation
tasks retain the guard if a caller stops waiting. Manifests are bounded to 16 MiB;
configuration files and configuration XML bodies to 16 KiB. Bounds and corruption
fail closed. No automatic expiry or history garbage collection is added.

Exact-version object reads keep the existing pipeline. Processed Iceberg table
reads reject S3 version selectors: the table walker cannot bind all referenced
objects to a historical table snapshot. Explicit passthrough object reads remain
available only under an authorized passthrough assignment.

Before promotion, native candidate, native-child and published-replay image runs
must execute four unmodified AWS CLI versioning rows through the existing owned
release-feedback boundary. Source-bound receipts now require all 35 rows (the
prior 29 core and two signed rows plus four versioning rows), with unchanged
cleanup/ownership/resource requirements. Historical receipts remain historical
evidence; they cannot qualify a new build missing the new rows.

## Consequences

Retained history increases volume usage, backup size and recovery complexity.
Versioning alone does not enforce create-only reservations, prevent authorized
deletion, or provide object lock, retention policies or bucket IAM.

[The delivery plan](../plans/2026-11-13-filestore-versioning.md) records the design
gates, executed tests and published-image verification. Implementation shipped
in v0.7.35; both native Linux images passed all 35 feedback cases before publication
and during published-child replay. Full S3 compatibility is
not claimed. This record extends the current-object and multipart contracts in
ADRs [0012](0012-local-filesystem-object-storage.md),
[0013](0013-durable-local-multipart-storage.md),
[0019](0019-zero-config-local-s3-appliance.md) and
[0030](0030-batch-delete-objects.md). Their non-versioning decisions remain in
force. Pre-versioning binaries cannot read schema-3 manifests: back up the entire
stopped volume before upgrading; do not downgrade a mutated volume in place.
