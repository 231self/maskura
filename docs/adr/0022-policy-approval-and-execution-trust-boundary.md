# ADR 0022: Policy approval and the execution trust boundary

- Status: Accepted
- Date: 2026-09-23

## Context

Signed configuration establishes artifact authenticity relative to trusted
signing keys. It does not establish which binary ran, which configuration that
binary used for an operation, or whether plaintext was copied during processing.
An operator controlling the gateway can replace both the processing code and
its local verifier while continuing to serve a correctly signed artifact.

ADR 0002 selected a Nitro/TLS-in-enclave deployment, and ADR 0006 described its
development-attestation counterpart. These historical decisions must not imply
that the current gateway provides independently attested execution. The policy
approval design also must not inherit that infrastructure as a prerequisite.

Options considered:

- Hardware-attested execution with independently verified code/channel binding.
- Mathematical computation proofs, including an asynchronous batched service.
- Customer-verifiable approval evidence with enforcement by a trusted gateway.

## Decision

Adopt the third, explicitly scoped trust model. Defer independent execution
attestation to a much later product stage. Hardware attestation and batched
computation proofs are not the current implementation direction. This decision
supersedes [ADR 0002](0002-nitro-enclaves.md) and
[ADR 0006](0006-dev-attestation-never-production.md); their text remains as
historical context.

Retain the hosted design for standing policy envelopes, synchronous approval of
effective-state changes, and purpose-separated passkey login MFA and policy
approval. The gate requires a valid customer approval before activation and checks
the exact approved effective state and envelope bounds in the trusted gateway.
The dated refinements below distinguish historical rollout state, deployed Slice 5
enrollment/recovery, and accepted but unshipped staged-publication hardening.
Accepting an architectural decision is not evidence of implementation or deployment.

For that exact-state check, a hosted request freezes its selected assignment ID
in the pipeline locator and a versioned fingerprint; a revision alone cannot
distinguish two assignments targeting the same pipeline. Static OSS locators and
historical persisted snapshots keep their prior fingerprint interpretation.
Policy-aware hosted enforcement must reject a missing assignment identity where
an assignment was required; looking up a mutable assignment after the freeze
cannot establish which assignment the request originally selected.

Existing canonical-CBOR/Ed25519 configuration signatures under
[ADR 0021](0021-signed-toml-pipeline-configuration.md) remain artifact-authenticity
evidence. Neither those signatures nor WebAuthn approval receipts are
per-operation execution proofs. This narrows the operator-resistance language
in ADRs 0003 and 0021 without changing their existing signing formats. Future
changes to WebAuthn schemas, signer lifecycle, and enforcement rollout need their own
implementation evidence and protocol specification; trust-root lineage and
per-lineage receipt-head retention are decided in
[ADR 0024](0024-trust-root-lineage-and-receipt-head-retention.md).

Ordinary S3 onboarding remains endpoint + access key + secret. TLS/SigV4 does
not attest server code. Native scale-to-zero remains a product constraint;
there is no new protected-worker, client adapter, attestation-gated CA, external
witness, or proof-generation service required by this decision.

### Slice 3 refinement: approval evidence and request-path enforcement (2026-10-10)

The gate above is now specified in detail and partially built. This section
records the Slice 3 trust-boundary decisions the original record lacked. It
narrows nothing above; execution attestation stays deferred exactly as before.

**Consumption, not possession (D8).** A bound approval verdict that execution
can discard is not authorization. The gate verifies the request and returns a
binding; the data plane consumes it. At the storage-execution seam the engine
re-verifies the request-time destination selection against the frozen binding
before commit (`consume_policy` / `binding_matches_selection` in
`crates/gateway/src/policy_gate.rs`); any drift answers `policy.denied`.
Execution drives from the verified binding — the frozen destination, the frozen
per-key managed placement targets, and the verified limits — and never
re-resolves a mutable row after verification.

**Frozen multipart state.** Staged uploads persist the verdict admitted at
create time (`MultipartSnapshot.verified_policy`) and continue under it across
envelope rotation and expiry; later part/complete/abort operations re-check the
frozen binding against their own fresh resolution (`consume_frozen_policy`).
Session limits compose as `min(create-time, current)` at completion, so
execution never exceeds either the original admission or current policy.

**Canonical-CBOR evidence.** `ReceiptBody` and `Checkpoint` are schema-versioned
(v2) and digested as SHA-256 over Maskura's versioned canonical encoding: a
sorted-JSON-keys serde-then-CBOR convention
(`crates/pipeline-config/src/canonical.rs`) — explicitly not RFC 8949 canonical
CBOR. Unknown fields and unknown schema versions fail closed. WebAuthn approval
evidence is ASN.1 DER ES256 over `authenticatorData || SHA256(clientDataJSON)`,
with the challenge bound to the complete receipt digest, so an assertion cannot
be moved onto a different statement. These are customer approval evidence and
consistency records, not per-operation execution proofs.

**Evidence schema versioning.** The durable frozen verdict is schema-versioned
(`VerifiedPolicy.schema_version`, currently 1). Pre-versioning evidence reads as
0 with identical semantics; readers fail closed (`policy.tampered`) on newer
versions — unknown future evidence is never silently accepted or reinterpreted.

**Recovery and trust reset.** Loss of all authorized keys requires a new
independently pinned root and is recorded as a marked discontinuity, never as
cryptographic continuity: a reset never signs an old-chain receipt, the old
chain and its retained head stay separately verifiable, and a server-served
trust bundle is never an independent pin. A customer must accept a new root out
of band ([ADR 0023](0023-policy-approval-verification.md),
[ADR 0024](0024-trust-root-lineage-and-receipt-head-retention.md)).

**Enforcement surface.** Enforcement is per workspace behind a
policy-enforcement state, forward-only `inactive` → `enforced`. `inactive` is
inert and behaviorally identical to the OSS engine. `enforced` fails closed:
without a valid customer approval the request is rejected with
`policy.unprovisioned`, never allowed. Other mismatches surface as `policy.denied`
(state/bounds mismatch, unlisted operation or prefix), `policy.expired`
(validity lapse), and `policy.tampered` (chain/digest or evidence-schema
mismatch); all are typed S3 XML `<Code>` values on HTTP 403. Approved state is
matched by digest against the exact frozen resolution — assignment-bound
fingerprint, step digests and config hashes, grants, limits, envelope lockfile
membership, and the v2 destination topology including the selected physical
targets — so a revision or a mutable-row lookup cannot stand in for the frozen
selection. For v1, managed storage is the only enforced destination mode;
concrete/BYO destinations fail closed at provisioning until their destination
wiring lands. Every S3 data-plane handler passes through the gate seam,
including hosted MCP object operations dispatched in process (MCP tool
listing/metadata is outside this claim).

**Historical status and deployment state (2026-10-10).** This is the rollout
snapshot at that date, not the current enrollment status; see Slice 5 below.
Three states must not be
conflated. (1) **Shipped in the public engine**: the `PolicyGate` seam and typed
policy errors (v0.7.16), the v2 effective-state/destination bindings and shared
digest preimages (v0.7.19–v0.7.20), and verdict consumption — check/use at
storage execution, create-time multipart freeze, `min(create-time, current)`
limits, and verdict evidence schema versioning (v0.7.21–v0.7.22). With no gate
configured these mechanisms are inert and OSS behavior is byte-identical.
(2) **The hosted enforcement gate is deploying now**, per workspace, behind the
policy-enforcement state; the gate that verifies approval evidence and returns a
bound verdict runs in the hosted control plane, and while a workspace's state is
`inactive` it is inert. (3) **No workspace is enforced.** Flipping a workspace
to `enforced` is a separate enrollment/cutover step that has not been performed
and is not authorized by shipping the gate. Nothing in this record is execution
attestation: a compromised gateway can still serve unapproved bytes in real
time; that serving contradicts the signed record and is forensically visible
afterwards — detection, not prevention.

**Slice 4 note: customer verification shipped (2026-10-12).** The
customer-facing half of the boundary is now implemented and public: the
EvidenceBundle v1 export format, a fail-closed verification facade over the
shared protocol types, and the `maskura policy` CLI group with a
customer-controlled trust store (see
[docs/policy-verification.md](../policy-verification.md) and ADR 0023's status
note). The claim stays exactly "customer-verifiable approval history against
customer-retained checkpoints" — **not** execution attestation and **not**
witness-verified. The external consistency witness (A3) remains a separately
gated program: artifacts may carry witness acknowledgement records, but they
parse only, absence is never blocking, and reports always carry
`witness: not-witness-verified`. This slice is enforcement-neutral; the
deployment states above are unchanged and no workspace is enforced.

### Slice 5 enrollment and recovery refinement (2026-10-14)

**Deployment status (updated 2026-10-16):** the shared backup-authority protocol
is merged in v0.7.25. Hosted enrollment/recovery and dashboard changes are deployed
and accepted in hosted control 0.5.44. This confirms the Slice 5 flow below, not
staged publication, fleet-wide enrollment, witness verification, or execution assurance.

The first landed customer state approval atomically advances the receipt head
and transitions absent or `inactive` workspace enforcement to `enforced`.
The authenticated approver and first activation time are retained on later
approvals. Customer publish and rollback require completed enrollment;
internal system-default seeding is unchanged. There is no operator flip or
recovery bypass that clears enforcement.

The dashboard sequence is signer bootstrap → signed standing envelope → signed
effective state. A separately registered passkey can become the single backup
through a signed `AddSigner` transition with existing-authority approval and
the exact new key's counter-proof ([ADR 0025](0025-signed-backup-policy-authority.md)).
The backup can authorize replacement of a lost primary; login recovery codes
are not policy-signing authority. Multi-owner recovery is deferred.

Loss of all policy keys starts a new root, not a continuation of the old chain.
Explicit dashboard acceptance requires owner/full passkey step-up and the
exact current root fingerprint. It retains browser-local old-root history,
does not establish CLI pins, and does not mutate enforcement. Customer-controlled
CLI import/confirmation remains separate. After reset the data plane stays
fail-closed until the new root's signed envelope and state land.

In that deployed release, configuration mutation still precedes its approval
receipt: enforcement rejects the resulting mismatched state. Atomic staging is
the accepted, unshipped hardening decision below. External witnesses remain
separately gated and execution assurance remains unassessed; neither is supplied
by enrollment or recovery.

### Atomic filter-state publication refinement (2026-10-16)

**Decision accepted; implementation not shipped or deployed.** This section
specifies the target contract, not behavior available in hosted control 0.5.44.
The existing mutation-first limitation remains until implementation and exact-release
deployment acceptance establish otherwise.

**Durable immutable review.** For an enforced workspace, stage a separate durable
candidate rather than changing serving configuration before approval. Freeze the
operation, proposed effective state, exact receipt body, component/config digests,
prospective publication/assignment identities, baseline preconditions and
purpose-bound ceremony. Draft authoring remains separate. Review holds no database
transaction or locks while the owner signs. Candidate payloads cannot be edited;
changes require a fresh candidate and review. Pending work and retained terminal
metadata must be bounded, and component holds retain bytes without authorizing
retired or revoked components.

**Atomic landing.** Completion must freshly reauthorize the owner, session, full
passkey step-up and signer under shared writer/revocation fences, recheck expiry
after lock waits, and verify the proof against the stored body. Reject changed
draft, assignment, head, root, authority, envelope or storage preconditions as
stale; never silently rebase. Shared projection logic must match the frozen
proposal both before mutation and against the actual written rows. Publish the
configuration, receipt and authorization head, consume the ceremony and retain
the committed result in one database transaction, or roll everything back.
All competing effective-state and authority writers must share the fencing
discipline; a lock used only by the completion endpoint is insufficient.

**Coverage and retry semantics.** Stage draft publication, forward rollback as a
new generation, default/bucket assignment changes and bucket-assignment removal,
including inherited outcomes. Retirement is refused with a typed error in this
slice. Legacy/alternate mutation routes must refuse before mutation rather than
bypass staging. Initial enrollment retains its existing signed activation flow.
Pending review, cancellation and expiry leave the previous valid approved state
serving; they do not extend envelope validity or undo revocation. A committed
operation cannot be cancelled. Idempotent issuance and exact authenticated
completion replay return the original candidate/result without another generation
or receipt. After a lost response, reconcile committed status or retry the exact
proof; never automatically compensate, restage or generate a new publication.
Current authorization remains required for status/replay, and a new login session
cannot complete a pending ceremony bound to an old session.

**Protocol compatibility.** No public signed-schema change is currently needed:
existing receipt actions and `EffectiveState` bind the publication/rollback
outcome. Private candidate/intent metadata is immutably associated with that exact
signed body and cannot alter its effect. Preserve v2/v3 receipt verification,
EvidenceBundle v1 and compatibility with the published v0.7.25 CLI. These are
implementation requirements, not a claim that staged exports have passed
acceptance. A newly discovered signed-semantic change requires explicit protocol
review, not a silent extension or relaxed verification.

**Admission and exclusions.** Atomic writers do not turn request admission's
multiple reads into one database snapshot: a reader straddling the commit may
briefly fail closed on an old-resolution/new-head mismatch. Denial-free admission
is not promised, and accepting an arbitrary previous receipt is not a workaround.
Frozen multipart create-time admission and `min(create-time, current)` limits
remain unchanged. Storage/probe rebinding is excluded; a concurrent storage
identity/epoch change invalidates the candidate, and an invalid live approval
continues to deny. This decision adds no witness, execution assurance, multi-owner
recovery, new prefix routing or cryptographic algorithm.

Compensating after a mutation was rejected because it exposes an unapproved state
and races with other changes. Holding a transaction across human approval was
rejected because locks/timeouts are not a durable review or recovery mechanism.
Deployment must be verified separately, including atomic-failure, stale/replay,
serving-during-review and verifier-compatibility checks. After enabling this
contract, operational rollback must retain compatible enforcing behavior or hold
mutations fail-closed, not return to a mutation-first binary.

## Consequences

- The operator, deployed gateway, host environment, and local enforcement state
  remain trusted during processing. Wasm sandboxing constrains plugins, not the
  administrator of the host runtime.
- Envelope encryption keeps decryption keys client-side, but plaintext is
  available during gateway processing. This is not end-to-end confidentiality
  against the gateway operator or proof of absence of extra plaintext copies.
- Offline approval verification requires independently trusted signer keys and
  authorized key transitions. A server-only key registry is not an independent
  trust anchor. Login recovery does not alone establish signing continuity.
- Signature validity does not prove honest display of the policy to the human.
  Passkey prompts do not display the full approved configuration.
- Hash chains establish consistency against retained checkpoints; they do not
  alone establish complete or latest history, or prevent split views. Verifiers
  must disclose these limits; this decision does not select a witness service.
- No approval artifact establishes per-operation transformation correctness,
  exhaustive PII detection, absence of extra processing, or durable storage.
  Storage acknowledgments retain their separate documented semantics.
- Documentation must distinguish deployed behavior, planned approval controls,
  and deferred execution assurance. Use “customer approval evidence and
  trusted-gateway enforcement,” not “operator-proof” or “end-to-end attested.”
- Release provenance and executable integration checks remain useful and
  distinct: they do not identify what a remote service ran for an individual
  customer operation.
- Enforcement is opt-in per workspace and forward-only; an `inactive` workspace
  sees identical behavior to the OSS engine, and only an
  `enforced` workspace's requests can be refused for missing or mismatched
  approval evidence.
- Fail-closed evidence evolution costs compatibility: unknown fields and newer
  schema versions are rejected rather than ignored, so older readers refuse
  evidence they cannot fully interpret. New evidence fields require a deliberate
  schema-version bump and migration story.
- Multipart continuity is a bounded carve-out: in-flight uploads keep their
  create-time admission across rotation/expiry, but tightening still applies
  through `min(create-time, current)` limits and fresh per-request enforcement.
