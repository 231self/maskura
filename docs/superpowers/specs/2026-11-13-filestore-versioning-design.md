# Docker/FileStore S3 versioning design

Status: owner-approved on 2026-11-13; local implementation and selected source
regressions passed; dependency gate repaired, packaged qualification pending.
Date: 2026-11-13
Related: [ADR 0035](../../adr/0035-proposed-filestore-object-versioning.md) and
[delivery plan](../../plans/2026-11-13-filestore-versioning.md).

## Scope and compatibility

Implement persistent S3 versioning in the single-node Docker/FileStore appliance.
Managed, direct-S3, presigned and memory modes gain no versioning capability.
Atomic create-only writes, bucket policies, retention/object lock, MFA Delete,
replication and copy remain outside this change. Existing authentication,
authorization, write validation and read processing continue to apply.
Processed Iceberg table reads reject S3 version selectors because their walker
follows current table references; they never return a latest-table preview for
an exact-version request.

The owner approved the standard lifecycle on 2026-11-13: Enabled/Suspended bucket
states, concrete version IDs, exact-version reads/deletes, delete markers and
paginated version listing. Previously unversioned objects have version ID `null`.

## Durable representation

Use one versioned per-key manifest at the existing hashed metadata path, containing
an ordered newest-first list of all retained version metadata. Each entry has its
opaque version ID, delete-marker flag, modification time, supported representation
metadata and, for data versions, immutable content filename/size/ETag. The first
entry is latest. There is no separately committed history or latest index.

Continue reading existing metadata schemas 1/2 as a singleton null data version.
On first versioned mutation, persist the equivalent manifest plus the mutation;
never rewrite historical object bytes to migrate them. Reject unknown schemas,
duplicate version IDs, mismatched keys/filenames and malformed marker entries.
Write new manifests using a new schema version so older code fails closed rather
than interpreting a historical manifest as an unversioned current object.

Bucket configuration uses its own schema-versioned durable file. Missing config
means never-versioned; it does not mean Suspended. Configuration changes and object
publication share FileStore's mutation guard. The state at the publication
linearization point determines PUT/multipart version semantics, including uploads
initiated before a state change. Do not add a metadata database or Postgres
dependency to the appliance.

The complete manifest is rewritten for each mutation. This trades write cost and
metadata growth for a single authoritative visibility commit. Bound serialized
per-key manifests to 16 MiB and configuration files/XML bodies to 16 KiB. Check
file length before bounded reading and serialized size before publication; a
write exceeding the manifest bound fails without dropping history. Deletions
that reduce a valid manifest remain possible at the bound.
Do not add automatic history expiry or garbage collection in this slice.

## Publication, deletion and recovery

1. Validate/finish the existing pipeline and verify output before publication.
2. Under the mutation guard, load bucket state and the authoritative manifest,
   preserve/backfill any multipart commit proof needed before replacing entries,
   and assign a unique version ID for an Enabled publication. Never derive latest
   ordering from timestamps or compare opaque IDs to establish order.
3. Sync the new content file and its containing directory before publishing the
   manifest. Write/sync a temporary manifest, rename it atomically, and sync its
   directory before acknowledging success. A post-rename sync failure is
   commit-unknown, never a definite rollback or successful acknowledgement.
4. Only after the durable manifest commit may files belonging to replaced null
   versions or explicitly deleted versions be removed. Failed cleanup can leave
   unreachable files but cannot remove data still referenced by a live manifest.
   Startup temporary cleanup must never remove retained version files.

Version deletion atomically removes only the chosen manifest entry, exposing the
next entry if latest was removed. Keep an empty manifest as a durable absence
tombstone when necessary; it contributes no versions to listing or bucket-empty
checks. Readers acquire a stable selected metadata/file handle under the mutation
guard before content deletion can unlink it. Exact reads never retry as latest.

Multipart commit proof schema evolves compatibly to retain the published version
ID. The same ID must appear in completion responses, persisted completion results,
recovery probes and successful completion replay, including after overwrite or
deletion. Before replacing/removing an operation-bearing entry, retain its exact
commit proof. Startup reconciliation considers retained versions, not just latest.
Legacy proofs remain readable; operation/generation/fence matching stays mandatory.
Proof retirement does not delete retained customer versions.

Once publication starts, request cancellation cannot discard the mutation guard
or interrupt the durability/proof sequence while a detached filesystem write
continues. An owned completion task retains the guard through terminal state;
the caller may stop waiting without claiming rollback. Test this cancellation
boundary explicitly. A crash can leave unreachable content; no successful
response may depend on an unsynced metadata rename.
FileStore clones also retain the shared process-root lock. Dropping the request
and surrounding local runtime cannot release root ownership before an owned
publication finishes.

## S3 lifecycle and API contract

| Operation/state | Behavior |
| --- | --- |
| GET bucket `?versioning` | Authenticated local operation; empty configuration for never-versioned, otherwise Enabled or Suspended. |
| PUT bucket `?versioning` | Bounded, strictly parsed XML; accept Enabled/Suspended, reject MFA Delete and unsupported/duplicate fields without mutation; persist before success. Missing bucket stays missing. |
| PUT/complete, never-versioned | Existing overwrite behavior; current object is the null version. |
| PUT/complete, Enabled | Append a unique non-null version, retaining all earlier entries; return `x-amz-version-id` on both PUT and multipart completion. Preserve the standard completion XML shape. |
| PUT/complete, Suspended | Replace the null entry, retain non-null entries, make the new null data version latest; return `x-amz-version-id: null`. |
| Ordinary DELETE, Enabled | Create a new uniquely versioned delete marker, even if no data exists; return 204, delete-marker header and marker version ID. |
| Ordinary DELETE, Suspended | Replace any null entry with a null delete marker, retain non-null history; return the marker metadata. |
| Ordinary DELETE, never-versioned | Preserve current unversioned behavior. |
| GET/HEAD without selector | Latest data with its version identity; latest marker yields 404 with delete-marker/version headers. Ordinary object listing omits marker-hidden keys. |
| GET/HEAD `?versionId=...` | Select exactly the authorized local key/version. Missing version yields `NoSuchVersion`; an explicitly selected marker yields 405 with marker/version and modification-time headers. No fallback. |
| DELETE `?versionId=...` | Permanently delete exactly that data version or marker; idempotent 204 for absent versions. Report selected version ID and marker flag when applicable. |
| POST bucket `?delete` | Preserve batch bounds/checksum/authorization. Apply ordinary or explicit-version deletion per entry; return marker/version fields as applicable, and permit multiple versions of one key as distinct entries. |
| GET bucket `?versions` | XML version/marker listing, sorted keys and newest-first within each key; support prefix, delimiter, max-keys, key-marker/version-id-marker and URL encoding. Return correct latest flags and next markers. |
| DELETE bucket | Reject while any retained data version or delete marker exists, even if ordinary object listing is empty. |

Validate decoded selector names, duplicates, empty/invalid version IDs and illegal
method/path/subresource combinations before mutation. A version-id marker requires
a key marker. Listing continuation resumes strictly after its key/version pair;
invalid marker combinations return a closed S3 error. Listing defaults/caps at
1,000 entries and supports max-keys=0. Common prefixes count toward the listing
limit. No claim of a multi-request snapshot under concurrent mutation.

Route versioning operations explicitly; retain pre-dispatch rejection of all
unrelated unsupported APIs. A versioning request on a non-FileStore destination
must return a closed unsupported error without changing its routing/backend state.
The handlers must resolve actual authenticated storage mode; the mere presence of
a configured FileStore does not grant local access. Version selectors cannot turn
hosted reads into local reads or raw-storage reads.

## Verification and rollout gates

Add unit and real-HTTP tests for each lifecycle row, both state transitions,
legacy migration, metadata preservation, malformed XML/selectors, signed/auth
denials, concurrency, marker/list pagination and same-key batch versions. Exercise
single PUT plus multipart completion/replay across store and gateway restart.
Inject persistence failures before and after manifest/config rename and directory
sync; verify retained history, exact commit-unknown handling, recovery identity and
safe cleanup. Test resource bounds and unknown/corrupt schemas without data loss.

Run focused regressions and the repository gates, then use an unmodified SDK
against the packaged image on a persistent disposable Docker volume. Restart and
verify every captured version through GET/HEAD, marker deletion, suspension and
listing. Qualify Linux AMD64/ARM64 images before publishing architecture-wide
support. Existing unversioned and other-backend regression suites must remain green.

Development-environment checks do not replace fresh release qualification.

Focused storage, transaction, protocol and real-TCP SDK tests have run; the
delivery plan records exact evidence and remaining gates. No versioning release,
deployed capability or performance target is claimed by this design.
