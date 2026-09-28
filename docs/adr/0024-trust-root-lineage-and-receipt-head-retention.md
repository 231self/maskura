# ADR 0024: Trust-root lineage and per-lineage receipt-head retention

- Status: Accepted
- Date: 2026-09-29

## Context

[ADR 0022](0022-policy-approval-and-execution-trust-boundary.md) introduced
customer-signed policy approval evidence (envelopes, receipts) and reserved
signer lifecycle, trust roots, and enforcement rollout for later implementation.
[ADR 0023](0023-policy-approval-verification.md) fixed the approval-statement
and verification contract. Slice 3 now needs durable state for the remaining
pieces: a signing registry, trust roots that survive a lost-all-keys reset, the
per-request receipt-chain head, and the enforcement cutover flag.

Two requirements collide on the receipt-chain head table:

1. The row-locked `seq` assignment point and the per-request `signer_epoch`
   check must operate on a single mutable active head per workspace.
2. A trust reset (all authorized keys lost) starts a new independently pinned
   root, and every prior root **and its head** must remain immutable, separately
   verifiable evidence.

A `workspace_id`-primary-keyed head table satisfies (1) but cannot itself hold
"immutable archived heads per lineage" (2) — one row per workspace cannot retain
one frozen head per retired root. Keying the live head on
`(workspace_id, root_id)` satisfies (2) but turns the hot seq-assignment row
into a composite and makes "which head is active" implicit.

## Decision

**Active head + per-lineage archive.** The schema keeps `policy_receipt_heads`
as a single `workspace_id` primary-keyed **active-head pointer** whose `root_id`
column is the active-root pointer (changed only inside the trust-reset
transaction). A companion `policy_receipt_heads_archive(workspace_id, root_id,
receipt_id, seq, head_digest, signer_epoch, updated_at, archived_at)` holds one
**frozen** row per superseded lineage. A reset copies the prior head into the
archive exactly as it stood; `policy_receipt_heads_archive_guard` then rejects
every update or delete.

The rest of the Slice-3 schema follows the same immutable-evidence discipline
(Slice-2 trigger style):

- `policy_trust_roots` — permanent lineage records (`genesis_bundle_digest`,
  `previous_root_id?`, `previous_head_digest?`, `recorded_by`, `created_at`).
  `previous_root_id`/`previous_head_digest` are an **unsigned discontinuity
  annotation** naming what was retained, not continuity evidence; a new root
  never extends an old chain. `recorded_by` is the authenticated operator
  action, not proof of customer acceptance. No update, no delete.
- `policy_signers` — identity and COSE key immutable, status forward-only
  (`active → superseded | revoked`), never deleted, one active signer per
  `(workspace, root)`. `signer_epoch` increments per authorized transition
  within a root and restarts at 1 for a new root.
- `policy_enforcement_state` — `inactive → enforced` once at cutover,
  forward-only and permanent.
- Slice-2 `policy_envelopes` / `policy_receipts` gain `root_id`; envelope
  versions and receipt sequences are unique per `(workspace_id, root_id)` so a
  reset restarts each at 1 rather than colliding across roots.

The design rationale is recorded normatively in the Slice-3 protocol
specification §8 (the record ADR 0022 defers schema detail to); this ADR
captures the lasting storage/trust-boundary choice.

## Consequences

- **Enables:** the hot seq-assignment path stays a single-row update on
  `policy_receipt_heads`; evidence retention across resets is first-class and
  immutable, so a customer can independently verify any prior root's head
  without trusting a service-provided reset bundle.
- **Costs:** one extra table and a copy step in the reset transaction; `root_id`
  must be threaded through envelope/receipt writers and the verification path;
  the active-root pointer lives on the head row, so "which lineage is active" is
  only answerable by reading `policy_receipt_heads`.
- **Trust posture:** a lost-all-keys reset is an explicit discontinuity — a new
  genesis root that a customer must pin out of band — never a forged
  continuation. This is enforced by construction (no old-chain signature is
  emitted for a reset) and by the immutable lineage rows.
