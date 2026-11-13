# S3 feedback release-content audit

Status: corrective v0.7.34 published and independently verified after genuine final-source qualification and published native replay. All 14 public release assets and canonical/index/latest bindings verified. Historical v0.7.33 unchanged; reporter-environment acceptance is not claimed.
Date: 2026-11-11
Last verified: 2026-11-13
Target: historical public v0.7.33; corrective release v0.7.34

## Current qualification and release state

[CI run 43379562176](https://github.com/231self/maskura/actions/runs/43379562176)
passed all checks for PR head `e0f4576e`. The checked-out merge source was
`a4c8bad241b7d57e821b0d59ec2e334276aaa16d`; its closed receipt independently
confirms all 13 exact managed cases, seven controls, zero ignores, successful
case cleanup, and removal of every recorded host mount. Both negative TLS cases
passed the actual SDK certificate-cause/no-dispatch checks. This is the first
complete standard-runner managed qualification in this audit.

The same run's native AMD64 and ARM64 candidate receipts each report 31/31
packaged FileStore rows and seven true cleanup checks. Their scope remains
`packaged-filestore-core`; neither receipt alone claims the full feedback matrix.
All other CI jobs, including Postgres, interoperability, E2E, SDK, security and
CodeQL, passed. PR #271 was merged as `bc15b206cab38d2da313806efbf17e2018ef6874`.

The v0.7.34 update synchronized workspace/lock and SDK metadata plus release-facing
image references; the OpenAPI schema and transitive dependency graph were unchanged.
PR #273 merged as `79e1f67843e1cdd26ce32fbd26fcdac7bbc28f8e`, and the new `v0.7.34`
tag points to that exact final source. Version-PR CI run `43381984648` and final-main
CI run `43399086206` both passed all checks.

[Release workflow 43399086123](https://github.com/231self/maskura/actions/runs/43399086123)
passed final-tag managed qualification (13 exact cases, seven controls, zero ignores,
complete cleanup) before publishing the native children. Each architecture then
passed 31 packaged FileStore rows and seven cleanup checks both before push and
after pulling its published digest on the same native runner. The protected proof,
provenance and logged-out verification stages also passed.

Independent readback verified the final managed receipt, both native/replay receipt
pairs, their source/version/harness bindings, the public two-child index, each
child's image/config identity and source/version labels, and equality of the
version tag and `latest` to the canonical digest. All 14 public release assets were
downloaded anonymously and their checksums verified, including CLI/MCP binaries for
Linux AMD64/ARM64 and macOS ARM64, the gateway, plugins, both SDKs, SBOM and receipt
metadata. [Release v0.7.34](https://github.com/231self/maskura/releases/tag/v0.7.34)
is published; the closed [verification summary](../reference/s3-feedback-release-audit-2026-11-11/release-v0.7.34.json)
records the immutable digests and scope.

Canonical image:
`ghcr.io/231self/maskura/maskura@sha256:dbac45fc128bf75e7e7060aa2a474c102d08ed8713434a3a7c7c131e1a94b021`.
Historical v0.7.33 still points to source `adff2635fa38c82b84b04ebffbf76098f771def7`
and image digest `sha256:a5fea3c997678821884492836921742805570a52345a3f713da0282a539b79cb`.
The historical failed-attempt records below remain failures. Packaged receipts
retain their `packaged-filestore-core` scope, and no reporter-environment acceptance
or execution-attestation claim is made by this audit.

Run `43257251690` (head `a9c225d1`) failed preparation: the guarded open
preflight succeeded but all three file-argument mirrors reported
`coordinator-script-policy`. This isolates the observed failure to the launch
path, not the interactive flag or plan mount. A fixed `-c` bootstrap and an
init-only file-launch preflight are pending native CI qualification. No managed
cases or cleanup acceptance are claimed for that run.

Run `43266767139` (head `e733e906`) reached `no_guard=coordinator-identity`
and `full=coordinator-plan`, proving coordinator startup but not plan acceptance.
Preparation creates mirror plans as the runner user whereas the real warden
creates them as root; the coordinator requires root ownership. The next mirror
verifies root ownership to match the actual campaign. No managed cases or
cleanup acceptance are claimed for that run.

Run `43269118146` (head `f0cbcf0e`) passed preparation with
`no_guard=coordinator-identity` and `full=frame-ok`; runtime failed after
coordinator startup with `internal-failure`. Its failure receipt makes no
acceptance or cleanup claim. The next revision adds only closed categories and
stage markers around coordinator binding and cleanup to distinguish the cause.

Run `43274752991` (head `dbb26984`) reached coordinator binding and the first
executor; executor preparation failed with `internal-failure`, and the
coordinator cgroup check returned `resource-missing` after container stop.
Neither acceptance nor cleanup is claimed. Further closed executor diagnostics
are pending; cgroup disappearance is not treated as cleanup proof.

## Release identity

Run `43321455896` (PR head `28e1f4af`) passed the corrected endpoint assertion;
`tls-unrelated-ca` then failed the specific-certificate-cause assertion at line
1763. Local-init cleanup flags were true and host cleanup remained unproved.
The locked HTTP client documents that hyper-rustls nests its `InvalidData`
certificate error inside `io::Error::other`, whose `source()` skips the payload's
own value. A local regression reproduced the missed nested cause before the
fix. Traversal now visits each I/O payload via `get_ref()` and otherwise follows
ordinary sources, retaining the original 16-step bound, exact cause matching,
required `InvalidData` kind and outer `DispatchFailure` assertion. All five pure
TLS endpoint/cause regressions pass, including wrong-kind/transport/alert/wrong-
certificate-cause and excessive-depth rejection. They supply no live TLS or
managed qualification evidence; fresh native CI remains required.

Run `43313723597` (PR head `66fab60f`) identified the remaining failure as
`tls-unrelated-ca`, at the endpoint-equality assertion before the certificate
rejection check. The closed result recorded selected=1, zero pass/summary/complete/
shutdown markers, a `MANAGED_CASE` panic at line 1690, and true local-init cleanup
flags. Host cleanup remained unproved, so the campaign still fails closed.
The service parser canonicalizes root URLs with a trailing slash while the
fixture compared them to an uncanonicalized spelling. The correction compares
the parsed fixture URL and canonical backend to the same numeric HTTPS root,
with regressions for the actual service parser and changed scheme/host/port/
path/query/fragment/credentials. Real client certificate verification, exact
certificate-cause checks and no-dispatch/no-mutation assertions are unchanged.
All other substantive CI jobs passed; the aggregate check failed with managed
qualification. No managed-release acceptance or completed 13-case campaign is
claimed until the corrected source passes fresh native CI.

Run `43311174476` (PR head `a7e215da`, checked-out merge source `b98a823a`)
completed native preparation and the controls, then reached concurrent product
execution. One case failed and host cleanup remained unproved. The closed failed
receipt reports zero qualified cases and no acceptance/cleanup claim; it does not
retain a per-case breakdown, so the specific failure is not yet identified.
The next diagnostic change logs only already validated, case-bound failed-init
facts (case ID, status/counts, local cleanup flags and allowlisted panic locations)
before the existing acceptance rejection. No raw output or private descriptor
fields are exposed and acceptance criteria are unchanged. Both image-smoke jobs,
Postgres and security checks passed in this run; managed qualification remains
the release blocker.

### Disposable Linux development reproduction

A subsequent kernel-policy startup failure was isolated to deadline argument
serialization, separate from process identity. Python float addition produced
more than nine fractional digits; the native guard correctly rejected that
grammar. A 200-invocation development probe reproduced 42 argument rejections,
all exactly correlated with that excess precision. The controller now floors
the original campaign deadline to nine decimal digits without extending or
renewing it; native parser bounds are unchanged. This final correction has local
regression coverage but has not yet been executed in a full native campaign.

Development testing ended before all 13 product cases could be exercised. The
original temporary environment was disposed of; no replacement or lifetime
extension was used. Disposal does not repair failed attempts' unproved cleanup.
Fresh final-source standard-runner qualification remains required.

The intermittent HTTP identity failure was narrowed to `uid` alone: PID, PGID
and birth matched on an exited/zombie process. A separate native probe confirmed
Linux changes proc-file ownership to root at zombie transition while effective
UID stays unchanged. Local readback now pins the process directory and validates
the effective UID from bounded `status` alongside `stat`; all identity mismatch,
signal authorization, zombie/reaping and cleanup checks remain strict. The first
instrumented HTTP retry passed with its own cleanup; full sequential development
verification and fresh final-source standard-runner qualification remain pending.

CI run `43290591715` (head `b88493ea`) progressed past the corrected capability
readback and coordinator teardown, then failed the first control. On the
disposable development host, native tracing of a tiny synthetic script identified
CPython's denied `ioctl(FIOCLEX)` as the file-launch failure; the narrow allowance
only sets close-on-exec. The existing exhaustive native ioctl self-test and
explicit FIONCLEX denial remain part of validation.

Native development also exposed the successful-case teardown ordering issue:
owned BPF detach now occurs only after independently proved init-only membership
and listener closure, but before releasing the trusted wait-stop init. The
corrected isolation control passed with its own cleanup proved. The deliberately
killed before-start control additionally needed discard-only stdout to accept a
bounded partial libtest prefix; stderr and product acceptance parsing remain
unchanged. Before-start and descendant controls then passed with their own
cleanup. A strict-provider attempt failed a schema check, followed by a passing
development attempt; repeat testing is required, not assumed. No full managed
product campaign or final-source release qualification is claimed by these
instrumented, sequential development runs.

A separately authorized native development environment reproduced the two
remaining harness failures against source `8fd864c3` without a Rust rebuild.
Docker's actual capability readback uses the `CAP_` spelling; the old exact
comparison incorrectly rejected the correct executor capability set. The fix
accepts only either complete spelling of the same exact three-capability set;
mixed spellings, missing/extra capabilities and SYS_ADMIN remain rejected.

Docker teardown also deletes the original cgroup before `cgroup.procs` can be
reopened. Pre-opened `cgroup.procs`/`cgroup.events` return ENODEV; the pinned
directory has a kernel deleted marker and the pinned pidfd reports exit. Native
development checks of the corrected verifier accepted the actual Docker
configuration, rejected an added capability, rejected cleanup while the init
was alive, then proved pinned-cgroup deletion and owned container absence after
stop. These are harness development regressions, **not** the 13 managed product
cases and not release qualification. Fresh standard-runner CI remains required.

Run `43282563873` (head `730d516d`) found a non-absolute mountinfo root with
an absolute target; the coordinator pidfd was exited but its cgroup did not
report zero links. Parsing now retains unrelated non-path roots while requiring
an absolute, parent-free root for the selected source, preserving overlap and
ownership checks. The missing cgroup is still not treated as cleanup proof.

Run `43280331109` (head `077058c0`) identified the case-mount failure as
`host-mount-path-invalid`; cgroup cleanup remained unproved. A subsequent
diagnostic records only fixed path-invariant booleans and, when available,
whether the pinned cgroup is unlinked and pidfd exited. These facts are not
themselves a cleanup claim.

Run `43277552509` (head `3b0693f6`) validated the executor descriptor and
created its inputs, but failed during the case host mount. Coordinator cgroup
cleanup again returned `resource-missing`. No managed-case acceptance or
cleanup is claimed. Fixed, allowlisted host-mount diagnostics are pending.

Run `43272021598` (head `89548c02`) validated the first coordinator frame and
binding, then failed the first control with `case-or-cleanup-failed` and
`coordinator-cleanup-unproved`. No case acceptance or cleanup is claimed.
Closed stage and exception-class diagnostics were added to isolate both failures;
no raw exception text is retained.

- Tag/source: `adff2635fa38c82b84b04ebffbf76098f771def7`.
- Image: `ghcr.io/231self/maskura/maskura:v0.7.33`.
- Index digest: `sha256:a5fea3c997678821884492836921742805570a52345a3f713da0282a539b79cb`.
- Linux amd64 manifest: `sha256:3426baead9ba424c6cf509b06a4af4d97ec7959f11284d225ffe8c6107cfe07e`.
- Linux arm64 manifest: `sha256:9048977c30a295bf2188a044b8a643106152774772dfae63492283d03fb6e504`.

Anonymous registry reads confirm `latest` points to this same index. The old
`ghcr.io/231self/s4/s4:latest` points elsewhere; do not conflate namespaces.
v0.7.32 has a different digest, but v0.7.33 has not been republished with the
unmerged feedback work. Publication alone did not prove those fixes shipped.

## Audited reported scope

The retained November 9 feedback handoff covers batch deletion, custom metadata
round-trip and an uncorrelated external catalog/purge failure. A separate
multipart-initiation Content-Type fix was copied into that local candidate.
The reporter's exact backend/SDK/request and current 400 response body are not
verified here. Do not invent them or claim all 400 responses have one cause.

## Release-source findings

| Area | Included in v0.7.33? | Evidence and boundary |
|---|---|---|
| Basic S3 DeleteObjects | Yes | PR #261 merged as `9e14b73808ff89ab22cc903f8bf13a957d069174`; bucket POST routes to per-key gated deletion. Quiet/per-key error behavior exists. Not proof of the reporter's exact SDK. |
| Signed streaming/checksum handling | Existing support included | `read_verified_body` and existing integrity/SigV4 machinery verify supported modes. Do not mislabel the whole decoder as an unpublished fix. |
| Supplied batch Content-MD5 validation | No | Released `s3_batch_delete.rs` goes from verified body to XML parsing without the candidate's explicit `ContentMd5Verifier` check. Body verification and this MD5 check are distinct. |
| Multipart with absent initiation Content-Type | No | PR #263 was closed without merge. Released `multipart_snapshot` stores only a supplied type; completion still rejects a missing type with `InvalidRequest`. |
| Memory custom metadata round-trip | No | Released memory sink/store preserve bytes/type/ETag, not the candidate's metadata bundle/readback path. |
| FileStore single-PUT custom metadata | No | Single PUT calls `commit_temp`, whose released implementation installs empty metadata maps. Existing multipart metadata support is separate. |
| Direct-S3 custom metadata publication | No | Released direct-S3 expected object/journal metadata is constructed with content-type only. Existing provider read forwarding cannot repair write-side loss. |
| Managed custom metadata publication | No | Released coordinator/child recipes carry content type/generation, not the candidate's complete customer/representation metadata. |
| Metadata namespace separation/reserved-name rejection | No | Released multipart metadata shares a flat namespace between customer and representation names; the candidate's versioned codec is absent. This is not a demonstrated customer exploit claim. |
| Metadata-bound recovery/reconciliation/repair | No | Existing recovery exists, but the candidate's exact customer/representation checks are absent from provider reconciliation and managed recipe/child/repair-source validation. |
| Decoded aws-chunked representation cleanup | No | The decoder exists, but released multipart representation metadata still captures aws-chunked transport encoding. No runtime claim is made from this source finding alone. |
| Transformed-read custom metadata exposure | Deliberately withheld | The response allowlist excludes custom metadata. The candidate adds privacy regression coverage, not permission to disclose unprotected metadata. Do not broaden this contract as a shortcut. |
| External catalog/purge failure | Unverified | No sanitized request correlation establishes that it was a gateway request or a gateway defect. Not fixed, not attributed, not blamed on caching. |

The unreleased candidate is change `qqnnlvlm` at
`a28aa10e209c699b28ef731104776b752d14e663`, with 35 changed files. It is not a
merged PR or image. Preserve its work; do not replace current source wholesale
with the older tree. Its historical audit failures and later fixture-isolation
review pause are not current release qualification.

## Packaged-image verification

Use the immutable index above on an owned local ARM64 appliance with a fresh
volume/network, synthetic credentials/objects, loopback-only ports and bounded
resource usage. Never use customer buckets or existing credentials/spools.

Check FileStore single PUT metadata before/after process restart; the four
initiation/completion Content-Type combinations; valid batch deletion; and wrong
Content-MD5 rejection before deletion. Retain only statuses, closed error codes
and assertion booleans, not response bodies, generated credentials or object IDs.
These HTTP checks are not unmodified-SDK, managed-provider or customer acceptance.

The first isolated probe stopped at its owned Docker port-mapping step before
issuing any product request; its container, volume and network were verified
removed. It provides no product pass/failure result. The corrected fixture is a
separate recorded attempt; assertions are unchanged.

The next attempt exercised the protocol cases but used its pre-restart ephemeral
port for the restart check. The final corrected attempt re-resolved the owned
port after restart and proved Docker had changed that allocation. This was a
fixture issue, not evidence of appliance restart failure. Both earlier attempts
remain preserved independently; neither is presented as a completed qualification.

### Completed immutable-image observations

The final ARM64 run completed all nine observations against the exact published
index. Its negative observations are genuine product failures, not green tests:

| Synthetic check | Observed result |
|---|---|
| FileStore single PUT → GET | HTTP 200; exact body preserved; custom metadata missing. |
| FileStore single PUT → HEAD | HTTP 200; custom metadata missing. |
| Multipart, no initiation type, no completion transport type | HTTP 400 `InvalidRequest`; missing-initiation-type error. |
| Multipart, no initiation type, XML completion transport type | Same HTTP 400; completion's transport type does not repair the frozen snapshot. |
| Multipart, explicit initiation type, no completion transport type | HTTP 200; GET bytes and original representation type preserved. |
| Multipart, explicit initiation type, XML completion transport type | HTTP 200; GET bytes and original representation type preserved. |
| Batch delete with wrong Content-MD5 | HTTP 200; synthetic target actually deleted, with no per-key error. |
| Batch delete with valid Content-MD5 | HTTP 200; present and absent keys both answered as deleted. |
| FileStore GET after actual process restart | HTTP 200; exact body preserved; custom metadata still missing. |

All owned container/volume/network removals and closed loopback port were
verified. Coordinator independently checked helper/report identities, expected
observations, recorded process-group exits and absence of all audit-labelled
containers/volumes/networks. No customer data, actual provider or existing
credential/spool was used.

- Full local report SHA256: `ef11ceb15a507e74d797dea18ad8d27f34257b31a5afa953f713426a46ae7321`.
- Executed helper SHA256: `38854ff928f8dbe14091538a0ff2ed1b1aa02acd2840bf21a1752637d8118081`.
- Direct-S3/managed/memory findings above remain release-source evidence, not
  packaged-image backend tests. No unmodified SDK or reporter environment pass
  is claimed.

## Correction and release requirements

1. Maintain this issue-to-regression-to-commit-to-image matrix; do not claim a
   local patch, merged unrelated PR or published artifact resolves the report.
2. Integrate the missing bounded fixes onto the current release lineage, retaining
   its security fixes, final-validation hooks and legitimate read/policy controls.
3. Independently review fixture isolation and qualify memory/FileStore/direct/
   managed metadata, multipart/recovery/repair and SDK behavior. Historical
   substituted-plugin or partial mock results are not a full image proof.
4. Run required correctness/security gates and image-level reproductions before
   publishing a new version. Never silently move v0.7.33 or weaken auth, policy,
   transformed-read privacy, transaction or checksum rules to make a test green.
5. Keep the external purge investigation explicitly unverified until correlation
   evidence exists. No customer data, deletes, paid infrastructure or outreach.

## Open evidence

- Exact current failing request/400 response and reporter backend/SDK.
- Fresh qualification and release of all missing feedback fixes.

## Corrective source checkpoint

The missing corrections have been ported onto the v0.7.33 lineage in this
dedicated workspace, rather than replacing current files with the older tree.
The returned candidate changes 31 Rust files; exact-file formatting and
conflict-marker checks passed. Its production and test source is under
independent review. Compilation, runtime regressions, complete gates and a
corrective candidate image remain unverified. This checkpoint is not a release.

The port preserves current final-output validation hooks, cancellation/deadline
handling, panic containment and lifecycle code. It adds reserved-name rejection
before sink acquisition and memory/FileStore rejected-overwrite regressions.
Fixture spool isolation is retained, optional boto3 children clear their
environment, and absent transformer fixtures remain explicit failures rather
than substituted components. Tests requiring process-global fixture environment
still need the reviewed cleared-environment serialized launcher; DB fixtures
require owned disposable databases.

Independent source review then identified four corrections required before
qualification, so the returned port is not accepted as complete:

1. Provider completion probing must not copy/rewrite mismatched customer or
   representation metadata and report success. Only the genuine multipart
   initiation state missing late-bound completion fields may be finalized.
2. Avro/Lance single-PUT branches must capture metadata and reject reserved names
   before sink acquisition, matching ordinary PUT and multipart behavior.
3. Managed recovery must validate child metadata against the frozen parent recipe
   and physical identity before invoking provider reconciliation, not only during
   the later transactional finalization.
4. Format selection must not discard parameters from an explicitly supplied
   representation Content-Type on single PUT or completed multipart publication.

Focused real-path regression source is being added for these findings, including
zero-provider-mutation assertions for mismatched recovery and parameterized
Content-Type HEAD/GET round-trips. These are source-review findings; they have
not yet been reproduced or qualified at runtime. Full managed HTTP + Postgres +
provider lifecycle and decoded aws-chunked batch-MD5 coverage remain explicit
acceptance gaps, not inferred passes from unit metadata matchers.

The follow-up coding pass has returned source corrections for all four findings
and expanded the candidate to 32 Rust files. Independent finite re-review found
all four resolved at source level, including actual adapter/service-level
negative-test paths; it found no remaining concrete blocker within that review.
The corrections and added regressions subsequently passed the compile-only
checkpoint below; the regression tests remain unrun. The added
decoded aws-chunked batch-MD5 test is now source coverage, not runtime evidence.
The full managed HTTP + Postgres + provider lifecycle remains outstanding.
Standalone Parquet is not supported by this correction, and Iceberg table-root
writes retain their separate metadata contract rather than being claimed fixed.

## Compile-only qualification checkpoint

The corrected candidate passes workspace formatting, the actual SQLite guard,
locked/offline gateway all-target/all-feature Cargo check, and matching Clippy
with warnings denied on Rust1.97.0. The successful frozen attempt completed in
165.879 seconds. Tests were typechecked, not executed. A prior attempt reached
check successfully but Clippy found one test mutex guard crossing an await;
an explicit lexical block now ends the guard before that await, with every
assertion unchanged. The fresh attempt reran all four phases successfully.

Coordinator independently verified all377 current/frozen inputs, all six phase
exits and log identities (including the before/after tracked inventories), every
recorded owned process-group absence and unchanged protected-default metadata.
Qualification used an owned config-empty Cargo HOME, frozen source, offline
dependencies, the shared heavy-build lock, bounded deadlines and periodic12-GiB
free-space guard. The deny-default compiler sandbox retained its file/network
barriers; diagnosed bootstrap access was limited to the root directory itself
and the operator-owned OS OpenSSL configuration. Positive bootstrap and synthetic
forbidden-read/write/external/localhost-network controls passed before compilation.
No existing credential or spool body was read, modified or hashed.

- Compile-only report SHA256:
  `02c1555bdd5e74b6a6fa45fe4d7973ac69ce609bf2f1ec0daed5ca3b4b59515b`.
- Frozen source-manifest SHA256:
  `e8aa5a788fb97688e55d5920e9486d71f66ee68da1ac5ff0c344cbc6904b783e`.

This is not a runtime, unmodified-SDK, managed HTTP+Postgres+provider lifecycle,
full release-gate or candidate-image pass. Those remain required before publishing
a new corrective version. v0.7.33 remains unchanged and is not claimed fixed.

## First local runtime checkpoint

The first executed local unit selection completed with41 passed, one failed and
zero ignored. All compiler/runtime positive and synthetic file/network-denial
controls passed. The failed test was
`logical_recovery_rejects_child_metadata_before_any_provider_request`.
A separate exact-case diagnostic reproduced its failure at the setup call to
`begin_physical_write`, before its security assertions: the fixture requested
`Unversioned + Optional`, which the existing exact-history admission guard
correctly rejects for a logical-parent-bound child. The fixture now requests
`Enabled + Optional`; production guards and every zero-provider-request,
unchanged-child and absent-authority assertion are unchanged. Fresh compilation
and runtime qualification of this one-field fixture correction are pending.
The earlier41/42 result is retained and is not presented as a green suite.

The genuine TEST transformer was separately built offline from the frozen
workspace/SDK/WIT inputs, componentized with the repository-pinned WASI adapter
and validated. Coordinator checked all14 phase exits/log identities and the
component code hash
`91132273cc42959120e141826cafbc3169a2d282295bd1d6a16d7db3acbdf0b1`.
That build did not instantiate the component or install/replace the shared test
artifact; it is not integration, SDK or packaged-image acceptance.

Coverage review confirms no existing test combines authenticated managed HTTP,
Postgres authority/journal and a provider lifecycle. Test-only local-TLS/provider
regressions are drafted separately, not integrated or executed. Their fixture
contracts, actual Postgres work and TLS verification must be qualified without
weakening normal identity/TLS guards. The21 local router/multipart cases,
explicit unmodified-SDK checks, full managed lifecycle and corrective-image
matrix remain outstanding.

## Corrected local runtime and explicit SDK qualification

The earlier checkpoints above are historical. The one-field fixture correction
subsequently passed fresh formatting, the SQLite guard, and locked/offline
all-target/all-feature gateway check and Clippy. Coordinator verified all377
current/frozen inputs and all six phase exits, log hashes and process-group
absences. Compile report SHA256:
`6db51a6a33ce775c74d248c7dec25398329a69c710c4dfcb1ab694b98c3854ea`;
source-manifest SHA256:
`b57f04f98802e71bf133e971d325372264e9e4af5a4c4c33826855e431c0b4a3`.

The full local runtime selection then passed **63 tests**:42 unit,17 isolated
frontdoor, two multipart conformance and two durable-filesystem cases. There
were zero selected failures, skips or ignores. This includes the previously
failing recovery test with its unchanged zero-provider-request assertions and
the decoded aws-chunked batch-MD5 regression. The genuine source-built TEST
transformer was copied only into the owned frozen test tree; shared components
were not replaced. Coordinator verified all377 inputs, exact test events and
summaries, all39 owned phase-group absences/log hashes and derived code hashes.
The run took250.236 seconds; minimum free space was88.12GiB. Runtime report
SHA256: `ba769c2ec2ab5ce8417e036832b13b278d1a6a8582693818749d38a824f4f3b2`.

Three additional existing SDK cases subsequently executed and passed, each in
a separate cleared-environment process with exact enumeration and zero selected
ignores:

- `batch_delete::boto3_delete_objects_interoperates_with_gateway`, explicitly
  selected using `--ignored --exact`.
- `misc::available_aws_cli_and_boto3_interoperate`.
- `external_aws_cli_and_boto3_multipart_interoperate`.

Both opt-in cases received `MASKURA_RUN_EXTERNAL_CLIENT_INTEROP=1`. These used
AWS CLI2.39.1 and unchanged boto3/botocore1.44.0 public SDK code. They retain the
existing path-style, retry and checksum settings: in particular the multipart
AWS CLI case uses `request_checksum_calculation=when_required`. This is not a
claim about every SDK default or the reporter's exact configuration.

The first SDK preflight stopped before requests on its16-MiB code-reader bound;
only the known public AWS CLI index received a bounded64-MiB streaming-hash
exception. The repository source-input bound remains16MiB. A subsequent
preflight identified existing SDK bytecode caches; all163 were verified equal
to unoptimized in-memory compilation of the pinned source without rewriting
them. Earlier attempts remain preserved. The successful continuation retained
the original1800-second deadline, including diagnosis and repair time.

Coordinator independently verified all three passes, ten security controls,
377 source inputs, qualified native binaries,2209 SDK source files, source-equal
caches, installed CLI code and eight staged components. All21 phase groups
across the successful run and preserved preflights are absent; protected
credential/spool metadata is unchanged. The run took208.842 seconds including
repairs, with88.87GiB minimum free space. SDK report SHA256:
`774888a59d74210ec40b9f22d464189b0e3e149e58be4c711ec3e66801de0836`.

These are synthetic loopback source-level tests, not upstream SDK attestation,
external-provider qualification, full managed HTTP+Postgres+provider evidence,
packaged-image verification or customer acceptance. The managed local-TLS
integration draft remains outside the repository pending review, compilation
and mandatory explicit execution. Complete release/security gates, synchronized
new-version surfaces and corrective-image regressions remain required before
publication. v0.7.33 has not been retagged and is not claimed corrected.

## Managed qualification integration checkpoint — 2026-11-12

The coordinator found a stale completed qualification handoff and independently
verified the actual R2 execution: all 28 phases passed, all 56 recorded log hashes
matched, and every recorded owned process group was absent. Formatting, the
SQLite guard, all-target/all-feature gateway check and warnings-denied Clippy,
five socket-free Python mocks and both normal Rust fixture-contract tests passed.
These results supplement the earlier 63 local regression passes and three
explicit SDK cases; they are not execution of the managed lifecycle cases.

Independent final review accepted the exact formatted, compiled protocol source
without further fixes. Its source-manifest SHA256 is
`61eddd38153084d96955386d91f32d1dbc65b9a3c5ca852e90def1994b2e7fa6`;
the reviewed protocol patch SHA256 is
`dded839bc2cb5a63c98e4ee3dac9c3e68099292cc0618bb4bf7e4c64053e051a`.

The five reviewed files are now **incorporated in the public working candidate**,
byte-for-byte from that accepted compiled source:

- `crates/gateway/tests/db_keys_test/main.rs`
- `crates/gateway/tests/db_keys_test/managed_release.rs`
- `crates/gateway/tests/db_keys_test/managed_release_fixture.rs`
- `scripts/tests/managed_release_tls.py`
- `scripts/tests/test_managed_release_tls.py`

The 375 original compiled inputs other than `main.rs` and this audit document
remain byte-identical, including seven fixture payloads checked by exact byte
equality without payload hashing. All original production inputs are preserved.
Earlier statements that this integration remained outside the repository are
historical and superseded by this checkpoint. Incorporation does not modify the
frozen qualification source or artifacts, establish managed execution evidence,
retag v0.7.33 or authorize publication.

Four subsequent managed campaign attempts **stopped before product execution**.
The first exposed invalid numeric-IP syntax in the runtime adapter's Seatbelt
profile. Reviewed portability corrections retained exact loopback ports, used a
common monotonic clock across interpreter self-exec without renewing the original
deadline, and replaced Darwin's unsupported `SO_ACCEPTCONN` query with a strict
native TCP-state check. These are separate from the accepted product-test source.

The latest attempt reached the real isolation precontrols, then stopped on nested
sandbox initialization. Exact-policy reproduction and PID-scoped kernel denial
records identify `forbidden-sandbox-reinit`; explicit operation spelling is not
accepted by this host's profile compiler. Minimal allow-default nesting succeeds,
but that is not evidence that the required deny-default nesting works. No safe
operation-specific correction has been established. Neither removing the outer
policy nor switching it to allow-default is an accepted qualification shortcut.

The coordinator independently verified the latest failed process group absent,
all 91 reserved ports refusing connections, and the shared lock available and
released. All 13 managed product cases remain unrun, with zero product passes.
No product or Postgres case was reached; the failed controls are not a product
failure result or managed acceptance. The original campaign deadline remains
nonrenewing, including diagnosis time.

After incorporation, actual public-workspace `cargo fmt --check` and
`cargo clippy --locked --offline --all-targets -- -D warnings` passed. Clippy used
two build jobs and completed in 171.862 seconds; its shared lock was released.
`just check-evidence` also passed, including 4 image-smoke tooling tests, 7 proof
tooling tests and 25 feedback-tooling tests, under OS network denial. These 36
tests validate tooling, not native images or managed product behavior. Dependency
security gates and the approved publication-workflow safeguards are separate
workstreams; neither is claimed complete here.

The 31 packaged native cases remain **not yet run on either amd64 or arm64**.
[ADR 0033](../adr/0033-native-feedback-qualification-before-image-promotion.md)
defines their release qualification and immutable-digest promotion requirements;
the decision and tooling are not evidence of a completed run. Required local
pre-push correctness/security gates, a synchronized new-version bump, the PR,
both native CI legs and published-digest qualification remain outstanding.

No full feedback matrix, coverage of every upstream SDK configuration,
reporter-environment acceptance or causal resolution of the external catalog/purge
report is claimed.
Signing UploadPart is not proof of signed multipart-initiation decoding or
snapshot cleanup. v0.7.33 remains unchanged; the corrective candidate is not yet
published.

## Publication safeguard follow-up — 2026-11-12

The approved bounded workflow correction adds an authenticated early publication
guard before build or registry mutation, verifies the existing release tag resolves
to the built source, refuses existing published or draft releases, and serializes
same-version workflow runs. API errors and incomplete bounded scans fail closed.
AWS CLI provisioning now precedes native smoke on both architectures, and candidate
feedback receipts are retained separately by architecture and run attempt. ADR 0033
records these choices and their limits, including external publishers and partial
publication recovery, which this guard does not control.

Parent verification passed the updated `just check-evidence` under OS network
denial: 4 smoke-tooling, 7 proof-tooling, 25 feedback-tooling, 18 publication-guard
and 5 socket-free TLS tests (59 total). Both workflow YAML documents parsed.
A read-only live invocation of the actual publication guard verified v0.7.33's
source binding and refused its existing release with `release-already-exists`.
It performed no GitHub or registry mutation and is not a successful-publication
or native-image qualification result.

All eight dependency/pinning commands also passed before the newly approved
security patch. The Rust audit nevertheless retained an allowed informational
`unsound` warning, RUSTSEC-2026-0486, for rustix 1.1.4. The approved compatible
patch to 1.1.6 is now applied: only its version and checksum changed; all other
660 package records and dependency edges are unchanged. No advisory exception
was added. The updated lockfile SHA256 is
`2057c7ca0917158bd3767125b34bdaafb418088afc82eeabd255f79c714d54a6`.

Actual `just pre-push` then passed in the public working copy in 72.412 seconds,
including fresh formatting, all-target warnings-denied Clippy, the 59 evidence
tests, guard tests, Rust/Python/npm dependency audits and immutable-input scans.
The owner process group was absent and the shared lock released afterward.
The rustix advisory was no longer reported. Existing duplicate-dependency and
unused-exception notices remain warnings under the unchanged policy.

Earlier compiler and product-runtime evidence remains bound to its original
inputs; it does not qualify this changed dependency for managed or packaged
execution. Native candidate CI and the missing managed acceptance must use the
updated source and lockfile.

The original managed campaign's 3600-second deadline has now expired. Its failed
attempts and cleanup evidence remain preserved, with zero managed product passes.
No continuation may silently start a fresh budget or treat tooling tests as the
missing 13-case managed acceptance. A draft PR may advance review and native
candidate CI, but is not permission to merge, bump, tag or release this candidate.

## Draft PR and first native CI results — 2026-11-12

The described corrective candidate was pushed through the required `just push`
gate and published as draft [PR #271](https://github.com/231self/maskura/pull/271),
head `98f9876794fc97be69531c1a776ea188dddce8b0`. The independently checked remote
bookmark matched that commit. No main, version tag, registry artifact or release
was changed.

[CI run 43212229238](https://github.com/231self/maskura/actions/runs/43212229238)
completed with overall **failure**. Workspace tests, SDK drift, end-to-end,
unmodified-client interop, formatting, lint, security, dependency review and all
CodeQL jobs passed. Neither native packaged leg is qualified: both built their
native image and passed boot smoke, then failed the packaged-feedback step.
Protected proof and successful candidate-receipt upload were skipped afterward.

The Postgres job reported 31 passes, one failure and 15 ignores. The failing
selector was `multipart::router_staged_multipart_flow_is_durable_and_idempotent`:
startup correctly refused managed mode off after an earlier recovery fixture
left its own authority rows in the shared test database. The source-grounded
correction is scoped fixture cleanup, not weakening that production guard. The
13 separately owned managed-release product cases remain ignored, not passed.

Both packaged runner summaries reported failure with zero retained rows. Source
inspection found that partial rows were copied only after the core suite
succeeded, while boundary errors were collapsed into a generic failure. Thus
the zero counts do not establish whether no product requests ran or a product
assertion failed. The underlying runtime cause remains unknown. Approved
corrections retain partial rows and closed failure categories, and upload a
sanitized failure receipt without making a failed run eligible for promotion.

Both approved corrections are now incorporated. The fixture removes only its
own identities with SeaORM and checks that an unrelated owned positive control
survives. The Postgres CI job explicitly runs recovery followed by router startup
and repeats its full suite against the same fresh service. The runner retains
partial core/signed rows and allowlisted failure fields; failed receipts still
cannot validate or seal as successful qualification. The upload remains
fail-closed on a missing receipt, and protected proof still cannot run after a
failed producer. Parent `just pre-push` passed with fresh Clippy/security checks
and 71 evidence tests (including 37 feedback tests). Fresh native/DB CI results
are still required; authored assertions and tooling tests are not those results.

The separately selected replacement for the blocked Mac
managed launcher is a native Linux design on a fresh disposable GitHub runner.
Only design work is approved; implementation and a new bounded managed campaign
require their own clear approval. The expired Mac campaign remains closed.

The owner has authorized publishing the corrective release once the current PR
passes CI; no further release-approval prompt is required. This does not turn
skipped required storage cases into passes or waive immutable-source, native
image, dependency-security and published-digest qualification requirements.

## Second CI result and connector correction (2026-11-12)

Run `43218945917` completed against PR head
`6d2b091474657d3f496ce8a856b4b805aefc27c1`. Postgres job `131185237169`
passed against one fresh job-owned service: initial full target 32 passed / 0
failed / 15 ignored; exact recovery 1 / 0 / 0; exact router 1 / 0 / 0; repeated
full target 32 / 0 / 15. Both exact selectors genuinely executed. This verifies
fixture cleanup and repeatability, not the 13 ignored managed cases. The
production off-mode authority guard remains unchanged.

All jobs except both native packaged-feedback legs and aggregate `check` passed.
Both native failure receipts contain zero case rows, all seven cleanup checks
true, and closed failure `numeric-loopback-publication` at stage `start`.
Their source is synthetic merge revision
`1eb1699d7d86385051580523496b79bcb38a9e04`, not the PR head. Docker 28.0.4 does
not program host publication for these internal networks. The existing guard
correctly rejected missing connectivity; no FileStore assertion ran.

The owner separately approved an owned, bounded host-loopback connector to the
independently verified private container endpoint. This additive change retains
the internal network and replaces only the incompatible Docker publication.
Endpoint/container/network births and membership, RFC1918 IPAM, loopback binding,
bounded concurrency/buffering/wire/deadlines, restart endpoint revalidation and
worker/socket/refusal cleanup are explicit requirements. The relay source now
participates in the harness hash; failed receipts remain rejected. All 31 product
assertions and the seven cleanup acceptance checks remain unchanged. Fresh native
AMD64/ARM64 CI must establish actual success; offline tests are not qualification.

This connector correction is published independently of the unfinished Linux
storage-check backend. The owner separately approved that implementation and
bounded fresh-runner execution, but all 13 managed cases remain unqualified and
must actually pass before release. The expired Mac campaign remains closed,
private schema expansion stays paused, and v0.7.33 remains untouched.

## Verified native candidate pass (2026-11-12)

CI run `43229853337` is fully green for PR head
`9427e06fd72c062bf1ccfb0dfd657e6fdaa5cbb3`. Its actual receipts and images bind
synthetic merge source `7c0890a03de6a630928848601569869dcbcc0cb4`, not that PR
head. AMD64 job `131221966608` completed in 14m52s and ARM64 job `131221966588`
in 17m49s. Each independently retained candidate receipt has exactly 31 passing
expected rows and all seven cleanup facts true. The harness identity includes
the relay source and matches the executed source. Both native protected-pipeline
proof steps also succeeded.

The candidate image IDs are
`sha256:6dc2dee3c6e1933862f85ae0e6eb5bc30915eed1bc733c766de7b34e88ed6333`
(AMD64) and
`sha256:79a8dfe7fdc23136f0d6aa81a4e09f10a11cf3d59cf0fdd8de652e824e1e33ae`
(ARM64). These are loaded candidate artifact identities, not published registry
digests. Phase remains `candidate`, scope `packaged-filestore-core`, and
`full_feedback_matrix_passed=false`. This closes the connector gap for that
candidate source; it establishes neither published replay nor acceptance of the
13 ignored managed cases. Final synchronized release source still needs fresh
managed/native qualification and immutable published-digest verification.

## First managed Linux run (2026-11-12)

CI run `43237274215` executed the new required `managed-release` job against
PR head `eb108d492478b4a4f50687898d6fa4c0b844e559` (receipt source is the run's
merge revision `3ce93cfd892beb59bb57197c5c827137c846b8a6`). Every other job
passed; the aggregate `check` correctly failed with it.

The preparation phase **succeeded in ~6.5 minutes** inside its 20-minute cap:
both native C guards compiled with `-Werror`, their `--self-test` suites passed
on Linux (first actual native compilation), the Rust test artifact and Wasm
components built at default runner parallelism, pinned images pulled, the
runtime image built, and the `ld.so --list` ABI check passed. Admission,
ownership and input-mount setup also passed: the runtime failure was the closed
code `channel-eof` in under one second — the coordinator container's attach
stream ended before its first frame, so zero managed cases ran and no cleanup
or acceptance is claimed.

The failed receipt retains `failure_category` plus (new) `adapter_exit`,
`container_started` and `container_exit`; runtime stage labels and fixed
coordinator/guard startup frames were added so a rerun localizes the empty
stream to guard failure, coordinator startup phase, interpreter crash, adapter
failure or a never-started container — all without exporting exception text,
OCI errors, paths or plan contents. This is an instrumented fail-closed attempt,
not qualification; all 13 cases remain unqualified.

The instrumented rerun, CI run `43242973058`, again failed only
`managed-release` (all other jobs passed). Its closed receipt gives the exact
cause: `failure_category: "coordinator-arguments"`, `container_started: true`,
`adapter_exit: 2`, `container_exit: 2` — preparation passed again (~6.5 min),
admission and input mounts passed, the coordinator container started, and
CPython exited 2 before writing a frame. That is either "can't open file" for
`coordinator.py` or an interpreter-level argument rejection; argparse failures
inside `main()` would now emit a frame and exit 11, so they are excluded. The
next revision adds two independent closed kill-shots: exact
`Config.Entrypoint`/`Config.Cmd` verification after `docker create`
(`coordinator-entrypoint-unproved` catches a silently unapplied override), and
a bounded fixed-marker classifier over the adapter's startup stderr
(`coordinator-script-unopened`, `coordinator-argparse-uncaught`,
`coordinator-interpreter-traceback`, `coordinator-interpreter-argv`,
`coordinator-stderr-unclassified`, `coordinator-adapter-error`,
`coordinator-runtime-error`). The classified bytes are discarded after mapping;
only the enum enters step logs and receipts. Zero managed cases have run in
either attempt; no cleanup or acceptance is claimed.

Run `43249132962` (head `cdb3e11a675d`) confirmed the path: entrypoint
verification passed, the container started, and stderr classified as
`coordinator-script-unopened` — CPython could not open the main script. Run
`43252978351` (head `10950d4f130d`) then split the question with a guarded
prep-phase preflight: **the file opens fine in the exact runtime context**
(`opened=True mode='444' uid=0 gid=0 dir_mode='555'`), yet the runtime
coordinator still failed with `coordinator-script-policy` (Errno 1, EPERM).
Since image, guard, seccomp profile and UID are identical, the difference must
be one of the three runtime-only container elements: `--interactive`, the plan
bind mount, or file-argument versus `-c` invocation. The next revision adds a
mirror preflight that reproduces the exact runtime container during
preparation and bisects across `no_interactive` and `no_plan_mount` variants,
each bounded and reporting only closed outcome codes. Still zero managed cases
run; release remains gated.
