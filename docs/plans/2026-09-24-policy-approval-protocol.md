# Policy approval protocol (Slice 1, corrected after security review)

Status: local library implementation; review fixes incorporated; no hosted enforcement deployed
Date: 2026-09-24
Scope: public `maskura-pipeline-config`; hosted ceremony/storage/rollout remain later slices

Related: [ADR 0022: trust boundary](../adr/0022-policy-approval-and-execution-trust-boundary.md),
[ADR 0023: approval verification](../adr/0023-policy-approval-verification.md),
[ADR 0021: existing signed files](../adr/0021-signed-toml-pipeline-configuration.md).
Private parent: `docs/plans/2026-09-23-customer-signed-policy-manifests.md` in `s4-private`.

This revision replaces the initial Slice 1 draft, including its incorrect raw
ES256 signature encoding, unsigned envelope-receipt metadata, metadata-only
state digests, and trust in post-rotation bundles. It provides approval evidence
relative to independently pinned keys and trusted-gateway enforcement, not
execution attestation. Protocol status is not proof of deployment.

## 1. Versions and canonical representation

- Existing `PipelineFile` schema/signing remain version 1 (canonical-CBOR /
  Ed25519, excluding `signature`). The optional `[policy]` section is included
  in that body's digest. Older parsers reject this unknown field.
- **ReceiptBody and Checkpoint are version 2**. Draft version-1 receipts and
  checkpoints are rejected rather than grandfathered into approval history.
- `EffectiveState`, `TrustBundle`, and `ChallengeContext` have version 1.
- New bodies serialize via sorted JSON-object keys into CBOR, matching the
  existing Maskura lexical-key convention. This is Maskura's versioned encoding,
  not a claim that lexical ordering is RFC 8949 length-first deterministic CBOR.
- Digests are SHA-256, represented as 64 lowercase hex characters. Vectors in
  `receipt_tests.rs` pin genesis trust, resolved state, activation, rotation,
  and checkpoint digests. Unknown fields/versions fail closed.

No customer has a deployed approval-v1 history to migrate. The old policy crate
is not removed by this slice. Existing Ed25519 export signatures are distinct
from customer WebAuthn approval signatures.

## 2. Standing envelope

The existing optional `PipelineFile.policy` model retains workspace identity,
destination ID, bucket allowlist, key-prefix routes (`fail = "reject"`), allowed
component/configuration hashes, monotonic envelope version, validity interval,
and resource bounds. Empty allowlists authorize nothing in the corresponding
dimension; empty component lists permit no components. Structural validation is
not request-path enforcement.

The envelope artifact digest is `PipelineFile::revision()` of the **immutable
approved snapshot**, including `[policy]` and the chains snapshot at rotation.
The chains are signed context, not permanent constraints on later publications.
The active effective state is independently approved by each activation receipt.
Validity is `[not_before, expires_at)` with an explicitly supplied clock-skew
allowance; an offline approval signature alone does not establish current validity.

Envelope activation now approves the **entire ReceiptBody digest**, not just the
envelope artifact digest. Its version, sequence, predecessor, state, epoch, and
authority digest are therefore all cryptographically bound.

## 3. Exact resolved-state commitment

`effective_state.rs` defines the shared serialized projection used for approval
and, in the enforcing slice, comparison with the actual frozen runtime state.
The full projection travels in every receipt; `effective_state_digest` must equal
its canonical digest. It is not computed from portable export metadata.

| Projection | Bound values |
|---|---|
| State | schema version, immutable workspace, deployment audience, full destination map and effective route list |
| Destination | ID (map key), storage mode, concrete HTTPS endpoint, physical bucket, region, optional IAM role, immutable configuration digest |
| Route | customer bucket, key prefix, operation, destination ID, assignment ID, revision ID, resolution fingerprint, explicit pass-through, format/adapter implementation digest |
| Limits | record/source-object/output-object bytes, memory, fuel, deadline, table entries, stack bytes, maximum steps |
| Ordered step | exact component-byte digest, immutable plugin-version ID, WIT world, enabled state, canonical JSON config, explicit grants, prefix-read capability |

The destination configuration digest additionally commits to the immutable
normalized storage configuration, including credential/key-version references
and managed-placement policy; it must not hash or export raw secrets. The later
storage adapter must construct this from the same frozen configuration used for
execution, not a mutable row ID. Endpoint/bucket changes already change the
projection directly even when destination IDs remain unchanged.

Routes represent expanded effective assignments. Within the workspace and
bucket, select the exact operation and longest matching key prefix; duplicate
bucket/prefix/operation tuples are invalid. Unlisted operations/scopes are denied.
List uses the requested list prefix; a broader prefix must not disclose keys
outside the approved scope. Steps preserve order; disabled steps remain signed.
Non-byte formats require an adapter implementation digest. Hosted MCP must map
to the same typed operation and checks. Per-request presigned destinations must
match an approved concrete destination; arbitrary destinations are not authorized
merely by specifying `presigned` mode.

The library checks projection structure and digest integrity. Building the
projection from real gateway resolution, checking it against envelope bounds,
and enforcing it across every operation are **Slice 3 work**. Do not advertise
runtime protection before that integration exists.

## 4. ReceiptBody v2

The authoritative Rust fields are in `receipt.rs`. Every statement carries:

- Version, purpose, action, workspace, audience.
- Full `EffectiveState` and its digest.
- Active envelope artifact digest and version.
- Current signer epoch and `authority_digest` of the pre-activation trust bundle.
- Contiguous sequence, `prev_receipt_sha256` (also the signed expected head).
- `issued_at`, frozen at begin; not a trusted completion timestamp.
- For signer replacement only: the full replacement `TrustCredential` (including
  credential ID, COSE public key, algorithm, label and next authorization epoch),
  plus `replaced_credential_id` naming the credential to retire.

Purpose/action combinations:

| Purpose | Action | WebAuthn kind | Additional rule |
|---|---|---|---|
| `policy_envelope` | `activate` | `envelope` | Version advances; artifact changes; initial receipt must be an envelope activation |
| `pipeline_export` | `activate` or `rollback` | `receipt` | Same active envelope; rollback is a fresh activation of resolved old content |
| `signer_authority` | `replace_signer` | `signer` | Same active envelope and resolved configuration; two assertions over the same complete receipt digest |

All kinds use `artifact_digest = SHA256(canonical ReceiptBody)`. No receipt has
unsigned sequence, predecessor, epoch, timestamp, or version metadata.
Assignments, storage rebinding, pass-through and plugin edits must produce a new
resolved state and activation, even if portable export bytes did not change.

## 5. WebAuthn assertions

`ChallengeContext` binds version, kind, nonce, ceremony ID, user/session, audience,
workspace, artifact digest, and short validity window. Its canonical CBOR bytes
are passed as the WebAuthn challenge; the browser base64url-encodes those bytes
inside `clientDataJSON`. Verification requires the exact canonical encoding,
including rejecting trailing bytes. Login has no workspace/artifact; approval
kinds require both. Fresh issuance and single-use consumption are server duties.

`WebAuthnProof` retains credential ID, exact `clientDataJSON`, authenticator data,
and **ASN.1 DER ES256 signature bytes** (base64url without padding). The signature
is over `authenticatorData || SHA256(clientDataJSON)` using ECDSA/SHA-256. Raw
64-byte COSE-style `r || s` signatures are rejected; see
[WebAuthn 6.5.5](https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types).

Verification checks:

1. Bounded proof sizes, required JSON fields and `type = "webauthn.get"`.
2. Exact allowed HTTPS origin and RP hash. Cross-origin ceremonies are unsupported:
   `crossOrigin: true` or any non-null `topOrigin` is rejected; omitted
   `crossOrigin` means false. Duplicate recognized client-data fields fail parsing.
3. Expected kind, workspace, audience and complete artifact digest.
4. UP and UV set, AT clear, valid backup flags, and well-formed extension data.
   Zero signature counters remain legal; they are not replay defenses.
5. DER signature verification with the credential key from the trusted authority.

COSE parsing accepts EC2/ES256/P-256 with valid curve coordinates, rejects
duplicate labels, private-key material, trailing bytes and oversized keys.
There is no hardware/manufacturer attestation requirement.

The independent W3C Level-3 §16.2 fixture tests the same DER/message/key verifier
used in production code. Its challenge is a generic WebAuthn random challenge,
not a Maskura approval statement, so it is not presented as a complete hosted
ceremony test. Synthetic full approval tests use DER too.

`verify_assertion` is an **offline evidence verifier**, not an online login API.
The live ceremony must also compare the exact server-issued challenge and
user/session/credential, check completion time, and consume it atomically. The
receipt verifier checks only `challenge.issued_at <= receipt.issued_at <
challenge.expires_at`; this does not prove when an assertion was actually made.

## 6. Trust continuity and chain reduction

Start a full chain from an independently pinned genesis `TrustBundle` (epoch 1,
nonempty active credential set). Never fetch an updated service bundle and treat
its replacement key/epoch claims as continuity evidence.

For each receipt:

1. Require the next sequence and exact predecessor digest (genesis is 64 zeros).
2. Require its epoch and `authority_digest` to match the reducer's current state.
3. Verify the current authorized credential's assertion over the entire body.
4. For envelope activation, advance the version; otherwise preserve the current
   envelope digest/version. An envelope activation must precede other actions.
5. For signer replacement, verify that the named retired credential is currently
   authorized, the replacement has a new ID and key, and its start epoch is
   exactly current+1. Verify the counter-proof against the **key in the signed
   statement**, with the exact replacement credential ID. Both assertions must
   bind that same body and the current resolved configuration.
6. Only then advance the epoch, revoke the named retired credential, and add the
   replacement. An authorized backup can retire a lost key without revoking itself.

This rejects epoch jumps, old-key appends after rotation, mismatched counter-proof
IDs, and substituted replacement keys. Earlier receipts remain valid history
because they are checked against the authority in effect at their chain position.
No current/latest-history conclusion follows just from valid signatures.

Trust credentials have **one authoritative serialized public key**. Lookup and
validation parse that value; there is no mutable second cached key. Direct Serde
deserialization and the JSON helper establish the same verification behavior.

Loss of all authorized keys is not a signed transition. It requires explicit
acceptance of a new independently pinned root and marked trust discontinuity.
`trust_resets` are annotations on that pinned root, not authority for crossing
from one root to another. This slice does not implement a reset or recovery UI.

## 7. Checkpoint v2

A checkpoint retained independently by the customer contains the verified head
sequence/digest, workspace, active envelope digest/version, effective-state digest,
original root-bundle digest, post-head authorization bundle, and local verification
time. `ChainReport::checkpoint` constructs it from a successful verification.

A suffix uses this retained authorization state and version high-water mark; it
does not reset to whatever epoch a receipt claims. Scope/RP/origins/root binding
must match the original pinned root. Checked arithmetic rejects overflow.
An empty suffix returns the existing checkpoint without claiming freshness.

**The entire checkpoint is trusted input**, not a structure whose presence alone
makes it trustworthy. Never automatically accept a server-provided checkpoint.
Without an independent recent observation, neither a valid chain nor an extension
proves that a newer tail was not withheld. Output reports the verified head and
derived authority, not a misleading “current/latest” history flag.

## 8. Remaining hosted work and acceptance

The shared library is still unwired to live policy publication. Later slices must:

- Select and verify deployed Supabase/passkey capabilities and canonical RP/origins;
  issue session-bound MFA and action-bound approval ceremonies with `webauthn-rs`.
- Make begin/complete idempotent, freeze candidates before approval, recheck all
  authority/state at completion, and activate transactionally with consumed challenges.
- Construct `EffectiveState` from actual immutable resolution and storage bindings;
  reject uncovered PUT/GET/HEAD/LIST/DELETE, multipart, MCP and format-adapter paths.
- Compare runtime state to approval, enforce envelope/object/session limits and
  validity, and retain frozen state across multipart operations and policy changes.
- Add Publish-modal UX and offline CLI verification without introducing new S3
  onboarding requirements. Inventory tenants and stage enrollment before cutover.

Regression tests cover the seven review findings, backup-authorized rotation,
checkpoint suffixes, version regression, draft rejection, sequence overflow,
resolved-state mutation, DER compatibility and cross-origin rejection. The schema
is reviewable and testable; this is not a claim of complete production security
coverage or a replacement for browser/device and database integration testing.
