# S3 feedback release-content audit

Status: corrective source and reviewed managed qualification files incorporated locally; completed local qualifications verified. Not published or customer-resolved; managed execution and native packaged qualification remain outstanding.
Date: 2026-11-11
Target: public v0.7.33

## Release identity

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
