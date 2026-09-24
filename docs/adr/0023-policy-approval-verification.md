# ADR 0023: Complete policy approval statements and authorization-state verification

- Status: Accepted
- Date: 2026-09-24

## Context

The initial shared approval-library draft passed its unit tests but did not
establish the intended approval contract: it expected raw ES256 signatures,
left envelope-receipt metadata unsigned, relied on updated trust bundles for
successor keys, and hashed export metadata instead of resolved runtime state.

The corrected library must support independent approval verification under
[ADR 0022's trusted-gateway boundary](0022-policy-approval-and-execution-trust-boundary.md).
It must not imply that approval signatures prove execution.

## Decision

- Use WebAuthn-standard DER ES256 assertions. Require exact origin/RP/purpose
  binding and reject cross-origin approval ceremonies. Retain zero-counter support.
- Version approval receipts and customer checkpoints as **v2**, rejecting the
  unshipped v1 draft. Every assertion binds the complete receipt body, including
  envelope digest/version, sequence, predecessor, epoch and pre-activation
  authority digest. Existing Ed25519 signed-file formats remain unchanged.
- Include a versioned, typed `EffectiveState` projection covering ordered exact
  component identities, configs/grants, expanded operation routes, resource limits,
  adapter identity, and concrete immutable destination bindings. Export name/version
  references and download checksums alone are insufficient.
- Verify full history from independently pinned genesis authority, deriving each
  successor only from an authorized transition. The old authorized key signs the
  complete replacement credential/public key and retired credential identity; the
  replacement key countersigns the same statement and current effective state.
  An authorized backup may retire a lost credential. No updated server bundle is
  accepted as transition evidence.
- Carry post-head authorization state, envelope high-water mark, effective-state
  digest, and root binding in independently retained checkpoints. Suffix verification
  resumes that state machine, including revocation and epoch checks.
- Keep one serialized source of truth for credential keys. Verification must not
  use a cached key that can diverge from the bundle's fingerprint.

The concrete contract and tests are described in the
[corrected Slice 1 protocol](../plans/2026-09-24-policy-approval-protocol.md).

## Consequences

- These shared-library corrections are implemented locally without enabling hosted
  MFA, publication enforcement, recovery, or runtime gating. Those integrations
  still require their database, browser and request-path acceptance tests.
- Revoked credentials cannot append by claiming an old epoch. Previously approved
  artifacts remain verifiable at their historical chain positions.
- A lost-all-keys recovery is a new independently accepted root, not cryptographic
  continuity; login recovery codes cannot authorize it on their own.
- Customers must retain trust material independently. A valid prefix/extension
  does not establish latest history or completeness, and a downloaded checkpoint
  is not automatically a trust anchor.
- Runtime adapters must populate and compare the resolved projection rather than
  silently treating existing portable exports as exact-state approvals. Missing
  operation/format/storage coverage must fail closed at enforcement activation.
- This decision adds no hardware attestation, computation proofs, external witness
  service, or additional S3-client onboarding requirement.
