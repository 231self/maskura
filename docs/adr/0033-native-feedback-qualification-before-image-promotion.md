# ADR 0033: Native feedback qualification before image promotion

- Status: Accepted
- Date: 2026-11-12

## Context

Publication of v0.7.33 did not establish delivery of the S3 feedback corrections.
Its immutable packaged image reproduced missing single-PUT custom metadata,
multipart initiation without Content-Type failing at completion, and deletion
despite an incorrect supplied Content-MD5. Source tests, image boot smoke and
successful publication are different evidence.

The existing release pipeline already builds on native amd64 and arm64 runners,
but its required pre-merge candidate job covered only amd64. Later release steps
also resolved mutable architecture/version tags instead of carrying qualified
child digests through index assembly and promotion.

This record supplements ADR 0015's release orchestration and ADR 0014's artifact
provenance. It does not replace their security, attestation, anonymous-access or
release-notification requirements.

## Decision

Extend the existing required `release-image-smoke` candidate job into a native
amd64/arm64 matrix. Each leg builds and loads an unpublished image, resolves its
local image ID once, and runs the existing smoke, packaged FileStore feedback
regressions and protected-pipeline proof against that ID. The aggregate `check`
must fail if either native leg fails, is cancelled or is skipped. Do not use QEMU
as native qualification.

Provision AWS CLI before the first packaged smoke on both native architectures;
candidate proof dependencies are installed before smoke as well. Retain each
successful candidate's structured feedback receipt as an architecture/run-attempt
specific immutable Actions artifact, without overwrite conflicts on job reruns.
A missing receipt fails upload; failed producers are not hidden
by an unconditional upload step. Receipt retention is not a claim that the later
protected proof passed.

Attempted failed producers also retain a sanitized failure receipt, using an
explicit non-cancelled success-or-failure condition. Closed stage/action/case
categories and partial assertion rows aid diagnosis without publishing bodies,
credentials or upstream exception text. These receipts remain failed evidence:
they cannot satisfy the exact passing-case set, cleanup or promotion contracts.

Before any build or registry mutation, the release `contract` job authenticates
with the workflow's `contents: write` GitHub token and checks that the requested
existing tag resolves to `GITHUB_SHA`. Lightweight tags are checked directly;
annotated tags are peeled through at most eight distinct tag objects. Missing,
cyclic, malformed or differently targeted tags fail closed. Labels and receipts
continue to bind the unchanged `GITHUB_SHA`.

Publication requires an exact HTTP 404 from the release-by-tag API and a complete
authenticated release-list scan without that tag, including drafts. At most twenty
100-release pages are scanned; an incomplete scan refuses publication. Existing
releases, authentication errors, transient errors, malformed responses and transport
failures are never treated as absence. API bodies and CLI diagnostics are not
printed. Both native builds and the macOS build depend on this early contract;
index assembly, promotion and GitHub Release creation remain downstream.

Serialize release workflows by repository and normalized release-tag reference,
using the same key for tag pushes and reusable calls and `cancel-in-progress: false`.
A subsequent same-version run rechecks the contract after the active publisher
finishes, rather than cancelling it or republishing an existing release. The late
best-effort release-existence skip is removed.

The packaged regression runner exercises 29 core cases and two signed transport
cases. It checks metadata and representation round-trips, reserved-name rejection,
multipart initiation/completion Content-Type combinations, supplied-MD5 rejection
before deletion, signed checksum/MD5 cross-negatives, decoded PUT/part output and
restart persistence. Authentication, policy, transformation privacy and integrity
checks are not disabled to obtain a pass. Official packaged components are kept
separate from source-test-only components.

Each native release leg must pass the same regressions before pushing its image.
Capture the immutable child digest from the push, pull that digest on the same
native runner, bind it to the tested local image ID and replay the regressions.
Receipts bind source revision, version, architecture, image ID, child digest,
regression-harness hash, exact case set and successful owned-resource cleanup.
Missing or mismatched evidence fails closed.

Assemble the version index only from the two qualified child digest references.
Verify the raw index digest and its exact linux/amd64 and linux/arm64 children
against the receipts before protected proof, provenance and promotion. Promote
`latest` from the verified canonical index digest, not a mutable version tag;
require the resulting digest to match. Artifact extraction likewise uses the
qualified amd64 child digest.

The runner uses only owned synthetic storage, credentials and loopback requests.
It retains absolute deadlines, resource limits, ownership checks, captured-child
cleanup and successful structured resource-absence inventories. Permission or
transport errors are not proof that a resource or listener is absent.

## Consequences

- Pre-tag qualification requires both native architectures. Candidate images are
  not published by the PR job; native published children are checked again before
  index promotion.
- Receipts cannot turn boot smoke, mocks, skipped cases or a mutable tag into
  delivery evidence. Changes to the tested source or harness require matching
  qualification rather than reusing an older receipt.
- Native runner capacity and the runner's Docker/storage capabilities are real
  prerequisites. An unavailable capability fails the gate instead of reducing
  the coverage or resource constraints.
- The publication guard is not a transaction with GitHub or the registry. Version
  concurrency serializes this workflow only, not manual/external publishers, and
  does not recover a partially published failed run or enforce registry tag
  immutability. Operators must not publish concurrently outside this workflow.
  Different versions are not serialized; `latest` remains completion-ordered.
  It relies on the workflow token retaining draft-release visibility; release
  histories beyond the bounded scan require a separately reviewed adjustment,
  never an absence assumption or a bypass for old tags.
- The packaged runner is not the complete feedback matrix: memory, direct S3,
  managed/Postgres, protected pipelines, crash recovery, unmodified SDKs and the
  reporter's environment need their own evidence. In particular, signed multipart
  initiation decoding/snapshot cleanup is not exercised by signing UploadPart.
  Receipts retain these exclusions and `full_feedback_matrix_passed=false`.
- This decision and its workflow implementation do not prove that any corrective
  candidate or published image has passed. Actual results and remaining release
  requirements belong in the S3 feedback release audit.
- Existing v0.7.33 tags and artifacts remain unchanged. Corrections ship under a
  new synchronized version only after the required qualification succeeds.
