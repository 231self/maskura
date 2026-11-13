# Known S3 compatibility gaps

Last reviewed: 2026-11-13, against v0.7.34 and the unreleased FileStore change.

These are unresolved capabilities. The v0.7.34 S3 corrections and published-image
qualification do not establish support for them. See the current
[compatibility matrix](minio-compatibility.md) for implemented operations.

| Gap | Current state / evidence | Delivery scope |
| --- | --- | --- |
| Released persistent S3 object versioning | v0.7.34 rejects `?versioning` and `?versions`. The v0.7.35 candidate persists FileStore settings/history and serves exact versions, markers, suspension/null semantics and paginated listing. Selected source suites and real-TCP SDK restart tests pass; dependency audits pass after minimal QUIC fixes. Native packaged qualification and publication remain pending. | **Docker/FileStore only**; [plan and evidence](plans/2026-11-13-filestore-versioning.md), [ADR 0035](adr/0035-proposed-filestore-object-versioning.md). No released image supports this change yet. Other destinations remain unsupported. |
| Atomic create-only writes | `If-None-Match: *` is not enforced as an atomic write condition. Conditional GET/HEAD handling in `server/s3_objects.rs` does not supply write exclusion. The reported two successful overwriting writes have not been independently rerun for this documentation update. | Deferred from the current scope. Future acceptance must prove existing keys return `412 PreconditionFailed` and concurrent create-only writers have exactly one winner, including applicable multipart paths. |
| Enforced bucket/prefix access policies | `server/routing.rs` rejects the bucket-policy API with `501 NotImplemented`. Existing authentication/workspace and pipeline-policy gates do not establish S3 bucket-policy support or the requested worker-specific prefix restrictions. | Deferred from the current scope. Future acceptance must prove worker credentials cannot overwrite/delete protected reservations, receipts or claims, bypass required conditional writes, or change their policy to grant themselves access. |

## Versioning boundaries

The requested slice includes durable bucket settings, retained versions,
concrete version IDs and exact-version GET/HEAD across restarts. Other storage
modes are excluded. The owner subsequently approved standard delete markers,
Enabled/Suspended/null-version behavior, exact-version deletion and paginated
version listing. The [written design](superpowers/specs/2026-11-13-filestore-versioning-design.md)
records the approved storage/API contract. The compatibility matrix separates
unreleased source capability from released image support. Processed Iceberg
table reads reject S3 version selectors rather than walking latest table state.

Version history alone cannot make reservations, receipts or claims immutable.
Do not depend on versioning for create-only coordination, enforced
retention or protection from credentials authorized to mutate objects. Clients
needing those guarantees must use a storage/authorization system that already
enforces them.

Packaged restart qualification remains a release gate. There is no automatic
retention, lifecycle expiry or history garbage collection. Back up the entire
stopped volume before upgrading: old binaries cannot read new history manifests,
so in-place downgrade of a mutated volume is unsupported.
