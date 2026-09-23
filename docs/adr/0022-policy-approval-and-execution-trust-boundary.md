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

Existing canonical-CBOR/Ed25519 configuration signatures under
[ADR 0021](0021-signed-toml-pipeline-configuration.md) remain artifact-authenticity
evidence. Neither those signatures nor future WebAuthn approval receipts are
per-operation execution proofs. This narrows the operator-resistance language
in ADRs 0003 and 0021 without changing their existing signing formats. Future
WebAuthn schemas, signer lifecycle, and enforcement rollout need their own
implementation evidence and protocol specification.

Ordinary S3 onboarding remains endpoint + access key + secret. TLS/SigV4 does
not attest server code. Native scale-to-zero remains a product constraint;
there is no new protected-worker, client adapter, attestation-gated CA, external
witness, or proof-generation service required by this decision.

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
