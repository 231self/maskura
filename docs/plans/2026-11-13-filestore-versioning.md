# Docker/FileStore persistent S3 versioning

Status: v0.7.35 published and independently verified on 2026-11-13.
Date: 2026-11-13
Scope: Docker local appliance backed by a persistent FileStore volume.
Decision: [ADR 0035](../adr/0035-proposed-filestore-object-versioning.md).
Design: [storage/API contract](../superpowers/specs/2026-11-13-filestore-versioning-design.md).
Current limitations: [known gaps](../known-gaps.md).

## Requested outcome

- Persist local bucket versioning configuration across gateway/container restart.
- Preserve earlier versions when a versioned object is overwritten by single PUT
  or completed multipart upload.
- Return concrete opaque version IDs in the appropriate S3 response headers/XML.
- Resolve exact-version GET/HEAD after restart, with the correct version's bytes
  and supported metadata; reject an absent version without returning latest.
- Preserve existing authentication, read processing, validation-before-commit,
  multipart recovery and single-root ownership guarantees.

This scope excludes managed storage, customer S3 backends, presigned proxying,
memory-store versioning, atomic `If-None-Match: *` writes, bucket policies, object
lock, replication and automatic retention/expiry. Target release: v0.7.35.
This plan is separate from the unfinished private Wasm integration.

## Design gates before implementation

- [x] Owner approved standard S3 ordinary DELETE markers, batch handling and
  bucket non-emptiness based on retained data versions/markers on 2026-11-13.
- [x] Owner included Enabled/Suspended states, S3 `null` versions, exact-version
  deletion and paginated `ListObjectVersions` in this delivery.
- [x] Owner approved the written storage/API design on 2026-11-13.
- [x] Specify treatment of objects created before versioning is enabled and of
  uploads initiated before a bucket versioning-state change.
- [x] Review the on-disk metadata schema, history/latest publication order, fsync
  boundaries, startup validation and recovery for each interrupted mutation.
- [x] Specify current-version ordering under concurrent PUT/completion/delete,
  reader consistency and version-stable recovery/replay after commit-unknown.
- [x] Review exact-version authentication/authorization and read transformations,
  including preventing a selector from bypassing workspace/backend resolution.
- [x] Define storage accounting, disk-full behavior and safe cleanup. Retained
  history must not be collected as stale temp data; no silent expiry of versions.

## Delivery sequence

Execution checklist (tests are recorded only after actual execution):

- [x] Durable history/configuration, legacy loading and lifecycle unit regressions.
- [x] Version identity through single PUT/multipart commit and recovery.
- [x] Strict local-only S3 configuration, selectors, version listing and deletes.
- [x] Batch version deletion and existing authorization/read-processing fences.
- [x] Fault/cancellation/restart and unmodified SDK integration evidence.
- [x] Repository gates and native candidate packaged Linux qualification.
- [x] Published native-child replay, promotion and final artifact verification.

1. **Freeze the contract.** Resolve the lifecycle gates above; review ADR 0035
   and a source-bound design. Keep the current compatibility matrix unchanged
   until actual implementation and tests support a new claim.
2. **Implement durable FileStore state.** Extend `file_store.rs` and the existing
   filesystem persistence/local runtime path. Retain per-version bytes/metadata,
   durable bucket state and crash-consistent latest selection. Preserve legacy
   readability, root locking and fail-closed corrupt-state handling.
3. **Integrate publication and recovery.** Extend `transaction/file.rs`, typed
   stored metadata and multipart publication/recovery as needed. Commit proof
   identity must bind the returned version. Successful completion replay and
   restart reconciliation must not generate additional versions.
4. **Wire the local S3 surface.** Add explicit bounded bucket-versioning dispatch
   in `server/routing.rs` and bucket handlers; carry version IDs through upload
   responses and object GET/HEAD resolution. Keep other backend modes outside
   this support claim. Implement or reject lifecycle operations per the contract.
5. **Qualify and document.** Execute the matrix below, then update ADRs 0012/0013/
   0019/0030 as affected, Docker usage, the S3 compatibility table and known gaps
   with exact tested evidence. Release and published-image verification are
   separate steps; documentation/source changes alone do not deliver the feature.

## Required acceptance evidence

| Area | Required result |
| --- | --- |
| Bucket configuration | Authenticated configuration read/write, malformed/unsupported settings rejected without mutation, missing-bucket errors, persistence across reopen/restart. |
| Single PUT | Write A then B; distinct concrete IDs; latest is B; exact A/B GET and HEAD preserve bytes/metadata/ETags after restart. |
| Multipart | Completion produces a concrete ID; earlier versions survive; replay/recovery returns the original committed ID with no duplicate history. |
| Concurrency | Concurrent successful overwrites retain every committed version with unique IDs and one consistent latest ordering; this does not promise one-winner create-only writes. |
| Failure/recovery | Inject faults at publication/fsync boundaries and disk-full/cancellation paths; no partial acknowledged history, lost committed versions, false success or unsafe cleanup. |
| Exact reads | Absent, malformed and foreign selectors cannot return latest, cross a scope boundary or bypass read processing; GET/HEAD identify the same selected version. |
| Lifecycle | Exercise approved delete-marker/deletion/listing/suspension/null semantics, or explicit rejection for deferred operations, including batch and bucket deletion. |
| Compatibility | Existing unversioned FileStore behavior and old-volume readability pass; managed/direct-S3/presigned/memory regressions remain green. |
| Packaged Docker | Unmodified SDK over real HTTP: enable, write A/B, capture IDs, restart the container on the same owned volume, read exact A/B via GET/HEAD. Qualify each published architecture before claiming image support. |

Start with focused FileStore/transaction tests, then `s3_frontdoor_test`,
`s3_multipart_conformance`, `local_filesystem_multipart` and `s3_protocol` as
applicable. Add registered restart/fault/SDK cases rather than relying on source
inspection or mocks. Run repository format/lint/test and guarded publication gates
before release. Only synthetic fixtures and owned disposable volumes are used.

## Executed source evidence (2026-11-13)

Focused warnings-denied runs passed:

- 35 FileStore tests, including concurrent retained overwrites, legacy loading,
  history corruption/config bounds, persistence faults, cancelled configuration
  and PUT waiters, a full 16 MiB history bound with deletion still available,
  configuration fault boundaries, and exact multipart proof recovery behind a newer marker.
- Four FileSink tests, 16 batch-delete units and three versioning protocol units.
- Six versioning frontdoor tests, including an unmodified Rust AWS SDK over
  loopback TCP. Configuration, both exact GET/HEAD versions, paired listing
  markers and delete-marker lifecycle survive gateway restart.
- Formatting and workspace all-target Clippy passed with warnings denied.
- Initial full gateway library suite: **789 passed**, zero failed/ignored.
  After the two shutdown/root-lock regressions, **791 passed**.
- Final complete frontdoor suite (one test thread): **170 passed**, zero failed,
  two existing ignored cases (optional boto3 batch interoperability and soak).
- Protected historical reads redact the selected version's bytes and preserve its
  local source version ID; protected HEAD remains denied. Iceberg exact-version
  table processing rejects before walking latest references (two HTTP tests).
- All three local-filesystem multipart tests passed, including retained
  completion identity through overwrite, restart and repeated completion replay.
- All 12 S3 protocol tests and seven multipart conformance tests passed.
- `just check-evidence`, the mdBook build, changed Markdown local-link checks and
  a bounded added-line secret-pattern review passed.

Broader tests initially found an interrupted-layout startup regression, corrected
by tolerating an absent metadata directory during proof backfill. The same run
also required two additional real test components. A parallel frontdoor run
exposed a transformed-read timing failure that passed alone; the complete final
frontdoor rerun used one test thread and passed. This does not establish that the
parallel timing issue is resolved.

The initial focused run passed **981 tests across the five listed Rust suites**,
with the two frontdoor ignores above. Subsequent complete workspace validation
is recorded below.

The dependency audit initially blocked publication: RustSec reported RUSTSEC-2026-0523 and
RUSTSEC-2026-0524 for `quinn-proto 0.11.18`, and RUSTSEC-2026-0538 for
`quinn-udp 0.5.15`. Both versions were inherited from the base lockfile. The owner
then authorized completion through publishing. Minimal lock updates to
`quinn-proto 0.11.19` and `quinn-udp 0.5.16` cleared the complete Rust/Python/npm/
pinning audit. No advisory exception or gate bypass was added.

The protected PR and merged-source CI runs passed full workspace/security checks,
real disk-exhaustion qualification and packaged Linux AMD64/ARM64 restart tests.
Published-child replay and final publication verification also passed. Retained
bytes consume ordinary volume capacity; writes never evict history to free space.
There is no performance/large-bucket scaling claim: listing materializes bucket
history, and each mutation rewrites its bounded per-key manifest.

## v0.7.35 publication gates

- Version-bound SDK regeneration and full workspace formatting/lint/tests passed
  locally: **1,553 passed, zero failed, 18 ignored registrations** on macOS,
  including both shutdown/root-ownership regressions.
  The dedicated Linux-only ENOSPC case is executed separately, never counted as a
  local macOS pass. Database/native-image evidence remains the CI gate's job.
- Execute the real ENOSPC test on an isolated 8 MiB tmpfs in Linux CI and both
  native release jobs. The targeted command requires exactly one non-ignored
  passing test; the default suite's ignored registration is not evidence.
- Require all 35 source-bound image feedback rows before merge/push/promotion:
  29 existing core rows, two signed rows, and four actual AWS CLI versioning rows
  covering exact restart reads, multipart replay, marker/suspension lifecycle and
  paginated listing/batch deletion. Repeat against published native children.
- Merge only after the protected aggregate check passes; use the existing
  tag-on-version-bump/reusable release workflow.
- Verify both native child receipts, canonical index identity, anonymous access,
  checksums, public artifacts and successful post-publication verification.

The versioning image and release are published. Qualification ran on native
GitHub runners; no Spot resource was launched.

### Verified pre-publication evidence

- [PR #275](https://github.com/231self/maskura/pull/275) merged only after the
  protected aggregate passed for head `f789deffaad2b7a993a87c881d4d819085934a25`.
- [PR CI run 43456678641](https://github.com/231self/maskura/actions/runs/43456678641)
  qualified both native candidate images with all 35 source-bound rows and all
  cleanup facts true. Its tested merge tree matches the PR head exactly.
- The same run executed the dedicated real-ENOSPC case on the isolated 8 MiB
  tmpfs: one passed, zero failed, zero ignored.
- [Main CI run 43459387165](https://github.com/231self/maskura/actions/runs/43459387165)
  passed on merge commit `b3d407cd5a2670123c9d380e53ad1cd9d2446ba2`, also the
  `v0.7.35` tag target. The release source tree matches the qualified PR tree.
- [Release workflow 43459387364](https://github.com/231self/maskura/actions/runs/43459387364)
  passed native-child qualification/replay, promotion and final release verification.

### Independently verified publication

- [v0.7.35 release](https://github.com/231self/maskura/releases/tag/v0.7.35),
  source `b3d407cd5a2670123c9d380e53ad1cd9d2446ba2`.
- Canonical index:
  `sha256:8c6bab97c44c767707d82352795184854435c4c01cc000c0dad9d7eef9878b95`.
  Anonymous registry reads of `v0.7.35` and `latest` resolve to that same index,
  with exactly the two qualified Linux AMD64/ARM64 children.
- Both native release jobs executed the isolated 8 MiB real-ENOSPC test:
  one passed, zero failed, zero ignored per architecture.
- Both native-child and published-replay receipts contain all 35 passing cases
  and all cleanup facts true. Their source, harness, image configuration and
  child digests match the public `QUALIFIED_IMAGE_CHILDREN.json`.
- All 14 public assets match their GitHub SHA-256 digests; all 13 entries in
  `SHA256SUMS` match the downloaded files. Image configuration labels bind both
  children to the release source and version.
- GitHub attestation verification passed for all 13 checksummed artifacts and
  the canonical image, enforcing the release-workflow signer, exact release
  source digest and GitHub-hosted runners.
- The v0.7.34 tag, release notes and original asset identities/digests remain
  unchanged.

These results qualify the recorded FileStore surface. Atomic create-only writes,
bucket/prefix policies, non-FileStore versioning and object-lock/retention remain
outside this release's support claim.
