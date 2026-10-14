# ADR 0025: Signed addition of a backup policy authority

- Status: Accepted
- Date: 2026-10-14

## Context

Slice 5 requires one backup signing authority for single-owner recovery. The
receipt protocol described by ADRs 0023 and 0024 supports replacing a signer,
but replacement retires an existing credential. Adding a backup only in the
hosted database would make the new authority unverifiable from the customer's
pinned root. Replacing the primary with the backup would defeat the requirement
to retain both keys. Expanding the initial root instead would require repinning
and would not provide an ordered, authorized addition to an existing lineage.

## Decision

Use receipt schema **v3** with an explicit `SignerAuthority` / `AddSigner`
transition. The complete new credential is carried in the existing `replacement`
wire field (now the new-authority field for both transition actions).
`replaced_credential_id` must be absent for addition. The receipt binds the
workspace, audience, existing envelope, approved effective state, predecessor,
sequence, current authority digest, current epoch, and new credential.

An already authorized signer provides `proof`; the exact new credential provides
`counter_proof`, both over the complete receipt digest. Credential IDs and public
keys cannot reuse any existing authority, including revoked keys. Verification
advances the epoch by exactly one, appends the new credential, and retains every
existing credential's status. The new key is authorized only from that next
epoch. Addition cannot change the configuration or envelope it re-approves.

Readers retain **v2** verification and canonical digest derivation unchanged.
`AddSigner` is accepted only in v3; unknown versions and invalid action/field
combinations fail closed. Writers use v3. Published v2 golden vectors remain
unchanged. EvidenceBundle v1 and Checkpoint v2 remain unchanged containers; their
receipt/authority contents are verified using the appropriate protocol rules.
Older clients reject v3 instead of silently treating addition as replacement.
Signer-transition evidence always requires linkage to pinned/retained history;
a server-carried post-state alone never establishes new authority.

Hosted implementation must land the receipt, head advance, and signer row in one
transaction with the existing head lock. It must enforce at most two active
policy signers per root (primary plus one backup) under that lock, not merely at
begin or in the UI. Existing-factor authorization and proof by the new key are
required; login recovery codes alone never confer policy authority.

Lost-primary replacement remains a `ReplaceSigner` transition: the authorized
backup approves, the successor proves possession, and the signed retired ID
names the lost primary rather than the backup. Enforcement never becomes inactive
during addition, replacement, or trust reset. Losing all authorized keys still
requires an independently accepted new root with an explicit discontinuity.

## Consequences

- Customers can verify the backup's authorization from retained history rather
  than trusting a server-edited signer list.
- The public protocol must be released and hosted code repinned before hosted
  addition is available. Protocol support alone does not claim that the hosted
  ceremony or recovery UI is deployed.
- Hosted signer uniqueness must allow two active credentials per root while
  preserving immutable identity and forward-only retirement. This supersedes
  ADR 0024's **one-active-signer** restriction, not its lineage/head-retention
  model. Bootstrap still emits no receipt; its preimage remains unchanged.
- No operator-only recovery backdoor, multi-owner recovery, witness assurance,
  or execution attestation is introduced.
