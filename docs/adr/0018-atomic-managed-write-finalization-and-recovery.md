# ADR 0018: Atomic managed-write finalization and recovery

- Status: Accepted
- Date: 2026-09-16

## Context

Managed PUT completion previously consumed the physical write intent before a
separate transaction published logical authority and released the workspace
mutation slot. A crash between those transactions removed the recovery witness
while leaving the logical operation and reservation non-terminal.

Recovery cannot safely rebuild authority from current placement or provider
configuration. The admitted metadata, placement, copy statuses, selected
provider version, and complete superseded-version history are immutable facts.

## Decision

Persist a versioned publication recipe during logical admission and retain the
physical intent until the parent is terminal. Logical PUT commit atomically
verifies exact child evidence, records the full physical-version set, publishes
authority from the recipe, transfers quota, releases the workspace slot, marks
the operation committed, and deletes the intent last.

Logical abort is also one repository transaction. It requires either durable
proof that no child could start or a terminal child journal with exact absence,
then deletes the intent last while releasing the reservation and marking the
parent proven aborted. Standalone physical reconciliation excludes every intent
owned by a non-terminal logical parent.

Stale PUT recovery uses renewable owner/token/expiry claims. Finalization and
abort validate the matching unexpired claim; request-time operations remain
valid only when no recovery claim exists. Deterministically missing or corrupt
evidence enters `RECOVERY_BLOCKED`; persistence, concurrency, and lease races
remain retryable. Legacy rows without recipes are never inferred.

All participating transactions use the lock order namespace, logical operation,
workspace usage, current authority, then physical intent.

## Consequences

- A crash after provider commit retains enough immutable evidence for exact,
  idempotent finalization.
- Request/recovery and recovery/recovery races have a single durable winner.
- Ambiguous legacy or provider outcomes retain capacity and require operator
  review instead of publishing guessed authority or proving an unsafe abort.
- The workspace-wide mutation slot can still block unrelated keys while an
  operation is recovery-blocked; per-object isolation remains separate work.
