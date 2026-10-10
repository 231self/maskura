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
approval. These are **planned capabilities**, not a claim of current deployment.
The planned gate requires a valid customer approval before activation and checks
the exact approved effective state and envelope bounds in the trusted gateway.
Deployment status as of 2026-10-10 — what has shipped, what is deploying, and
what remains future — is recorded in the Slice 3 refinement below and must be
kept distinct in every claim.

For that exact-state check, a hosted request freezes its selected assignment ID
in the pipeline locator and a versioned fingerprint; a revision alone cannot
distinguish two assignments targeting the same pipeline. Static OSS locators and
historical persisted snapshots keep their prior fingerprint interpretation.
Policy-aware hosted enforcement must reject a missing assignment identity where
an assignment was required; looking up a mutable assignment after the freeze
cannot establish which assignment the request originally selected.

Existing canonical-CBOR/Ed25519 configuration signatures under
[ADR 0021](0021-signed-toml-pipeline-configuration.md) remain artifact-authenticity
evidence. Neither those signatures nor future WebAuthn approval receipts are
per-operation execution proofs. This narrows the operator-resistance language
in ADRs 0003 and 0021 without changing their existing signing formats. Future
WebAuthn schemas, signer lifecycle, and enforcement rollout need their own
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

**Status and deployment state (2026-10-10).** Three states must not be
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
  (every workspace today) sees identical behavior to the OSS engine, and only an
  `enforced` workspace's requests can be refused for missing or mismatched
  approval evidence.
- Fail-closed evidence evolution costs compatibility: unknown fields and newer
  schema versions are rejected rather than ignored, so older readers refuse
  evidence they cannot fully interpret. New evidence fields require a deliberate
  schema-version bump and migration story.
- Multipart continuity is a bounded carve-out: in-flight uploads keep their
  create-time admission across rotation/expiry, but tightening still applies
  through `min(create-time, current)` limits and fresh per-request enforcement.
