# Managed write finalization and recovery design

Status: Approved

Date: 2026-09-16

Related: private issue `231self/maskura-private#191`, ADR 0017, ADR 0018

## Problem

A managed `PUT` currently commits in two database transactions after the
provider accepts the object:

1. `commit_physical_write` inserts exact provider-version rows and deletes the
   physical write intent.
2. `commit_logical_put` publishes object authority, transfers reserved bytes to
   allocated bytes, clears the workspace mutation slot, and marks the logical
   operation `COMMITTED`.

A process restart between those transactions leaves the logical operation in
`COMPLETING`, but removes the physical intent used by existing reconciliation.
The logical operation is therefore invisible to the intent- and lease-based
reconcilers. Its workspace-wide `active_operation_id` remains set, so every
later managed write in that workspace fails.

The remaining durable rows are not sufficient to reconstruct authority safely.
They omit the admitted placement version, replica binding/status, canonical
authority metadata, and an unambiguous selected provider version. Existing
authority may belong to the prior generation during an overwrite. Recovery
must not infer any of these facts from current configuration or row existence.

## Goals

- A normal process loss at every managed-write boundary converges to exactly
  one of `COMMITTED` or `PROVEN_ABORTED`.
- No provider mutation starts without all immutable publication facts being
  durable.
- A logical write's physical ledger, authority publication, quota transfer,
  workspace-slot release, and terminal state commit atomically.
- Request-time and recovery paths call the same idempotent finalizer.
- Recovery is driven from logical operations, not solely from physical intents
  or workspace route leases.
- Genuinely unprovable outcomes become explicit `RECOVERY_BLOCKED` work with a
  retained reservation, alerting, and sanitized diagnostics. They never remain
  silently in `COMPLETING`.
- Existing self-hosted and non-managed writes retain their behavior.

## Non-goals

- This increment does not replace the workspace-wide mutation slot. Per-object
  mutation fencing is a follow-up once crash-safe finalization is deployed.
- This increment does not move the managed ledger out of PostgreSQL.
- This increment does not change external usage-settlement ownership.
- Recovery never guesses from current placement, current provider config, row
  order, timestamps, or an existing authority from another generation.

## Invariants

1. **Durable recipe before mutation.** Before creating a provider version, the
   logical operation contains an immutable authority publication recipe.
2. **Retained witness.** A physical write intent remains durable until the
   parent logical operation is terminal. Provider-version rows alone never
   replace the recovery witness before logical finalization.
3. **One finalizer.** Logical child writes use one repository transaction to
   replace the physical intent with exact versions, publish authority, enqueue
   repairs, transfer quota, clear `active_operation_id`, and mark the logical
   operation `COMMITTED`.
4. **Exact provider result.** Finalization requires the child journal's durable
   selected version, superseded versions, and `version_history_complete=true`.
5. **Idempotence.** Replaying the same finalization returns the same committed
   operation. A different recipe or child result conflicts.
6. **Fail closed on ambiguity.** Missing/corrupt facts, incomplete version
   history, fence changes, CAS changes, or provider ambiguity retain capacity
   and become `RECOVERY_BLOCKED`.
7. **Claimed recovery.** Only one process may recover a logical operation at a
   time; expired recovery claims are stealable.

## Durable model

### Publication recipe

Add these immutable fields directly to `managed_logical_operations`:

- admitted placement version,
- primary and optional replica backend IDs,
- canonical authority metadata,
- intended primary and replica copy statuses after a primary-only direct PUT,
- recipe version for future compatible evolution.

The existing row already stores logical identity, generation, fences, prior
authority CAS/size, primary child ID/location, and request/receipt identity.
Output digest and size remain in immutable logical usage evidence.

The recipe is written in the same admission transaction that reserves capacity
and acquires the workspace mutation slot. A provider child cannot begin if the
recipe is absent.

### Recovery claim and state

Add recovery owner/token/expiry fields to the logical operation. Claims use a
compare-and-set update and can be renewed during provider reconciliation.

Add `RECOVERY_BLOCKED` to the logical state machine. It is non-terminal for
operator/reconciler purposes but is distinct from in-flight `COMPLETING` and
must carry a bounded sanitized reason. It retains the operation's reservation
and workspace slot in this increment.

The existing partial index on non-terminal logical operations remains the
recovery work queue.

## Atomic finalizer

Introduce this repository operation:

```rust
async fn finalize_logical_put(
    operation_id: Uuid,
    physical_lease: &PhysicalWriteLease,
    result: ExactPhysicalCommit,
) -> Result<ManagedOperationCommit, ManagedError>;
```

`ExactPhysicalCommit` contains the selected provider version, superseded
versions, and complete-history proof copied from the terminal child journal.

Inside one PostgreSQL transaction the finalizer:

1. Locks the logical operation, namespace, workspace usage, current authority,
   and physical intent.
2. Validates state, recovery/request ownership, recipe version, fences, child
   identity/location, evidence, CAS, and exact provider result.
3. Inserts/idempotently verifies all exact physical-version rows.
4. Publishes authority from the admitted recipe plus durable digest, size, and
   selected version.
5. Enqueues replica and replaced-generation cleanup repairs exactly once.
6. Transfers reserved bytes to physical allocation and updates visible bytes.
7. Clears `active_operation_id` and marks the logical operation `COMMITTED`.
8. Deletes the physical intent last, in the same transaction.

Any failure rolls back every database effect, leaving the logical operation,
physical intent, reservation, and child journal available for retry.

`commit_physical_write` remains available only for writes with no logical
parent. A logical child's request path must use the finalizer.

## Request path

1. Admission atomically persists the logical operation, publication recipe,
   reservation, and workspace mutation slot.
2. The child physical intent and durable journal are created before provider
   mutation.
3. Output evidence moves the logical operation to `COMPLETING`.
4. Provider completion commits the child journal with exact version history.
5. The outer managed sink calls `finalize_logical_put`; the inner sink does not
   independently consume the physical intent.
6. Only a committed finalizer result is returned as a successful managed PUT.

## Recovery path

A startup and periodic pass scans stale non-terminal logical operations, claims
them, and follows durable evidence:

- `INTENT` with no reservation/child: prove logical abort.
- `OPEN` with no child journal or physical intent and proven no version: prove
  logical abort.
- A live/non-terminal child: run existing exact provider reconciliation, then
  reload durable state.
- Child `PROVEN_ABORTED` with no physical version: delete/settle the physical
  intent and prove logical abort in a coordinated idempotent path.
- Child `COMMITTED` with complete exact version history: call the atomic
  finalizer, whether the physical intent is pending or this is an explicitly
  recognized legacy split-window row.
- Missing recipe, missing terminal child result, incomplete history, generation
  mismatch, CAS conflict, or changed namespace/routing fence: set
  `RECOVERY_BLOCKED`, retain reservation/slot, and emit sanitized evidence.

Recovery retries transient failures. It never derives authority from current
configuration or an authority belonging to another generation.

## Legacy rows and rollout

1. Add nullable recipe/claim fields and the new state in a schema migration.
2. New admissions require a complete recipe immediately after deployment.
3. Pre-migration non-terminal rows are inspected once:
   - proven absence may abort;
   - rows already carrying a complete recipe from a partially deployed release
     use normal recovery;
   - every other row becomes `RECOVERY_BLOCKED` and alerts rather than
     reconstructing missing publication facts.
4. Deploy reconciliation before relying on the finalizer path.
5. Canary a forced restart after provider commit and before finalization.
6. Confirm no row remains in `COMPLETING` beyond the stale threshold and that
   reservation/authority/version accounting converges exactly once.

Rollback disables new recovery claims and restores the previous request path;
the additive schema remains. Rollback must not delete recipe or claim evidence.

## Testing

Repository and database-backed tests must cover:

- crash after terminal child commit but before finalization,
- crash while the finalizer transaction is in progress,
- request/recovery and recovery/recovery races,
- unversioned, versioned, zero-byte, and overwrite writes,
- selected-versus-superseded version validation,
- changed placement after admission (recovery uses the recipe),
- changed authority CAS and namespace/routing fences (fail closed),
- child proven-aborted and exact-absence recovery,
- missing recipe/journal or incomplete version history -> `RECOVERY_BLOCKED`,
- idempotent authority CAS, quota transfer, physical rows, and repairs,
- a recovered failure followed by a successful write in the same workspace.

An end-to-end canary must pause after child commit, terminate the process,
restart, and prove automatic convergence plus a subsequent successful write.

## Per-object isolation follow-up

The current workspace-global `active_operation_id` deliberately serializes all
managed mutations. Even with deterministic recovery, a genuinely ambiguous
operation can therefore block unrelated keys while it is `RECOVERY_BLOCKED`.

A separate follow-up will replace the single slot with per-object mutation
fences plus aggregate atomic reservations. The resulting policy is:

- the ambiguous logical key remains fail-closed,
- unrelated keys in the workspace continue,
- namespace purge and routing-epoch changes still fence the whole workspace,
- aggregate quota remains authoritative in PostgreSQL.

This follow-up depends on the finalizer and recovery recipe; it is not folded
into the first repair PR.

## Lock order

Repository transactions that participate in admission, finalization, or abort
acquire row locks in this order: namespace, logical operation, workspace usage,
current authority (when applicable), and physical intent. New code must not
acquire one of these rows and then move backwards in that order.

## Legacy operator policy

Legacy non-terminal PUT rows without a complete publication recipe are not
eligible for inferred publication. Recovery may abort one only when durable
child evidence proves no provider mutation; otherwise it enters
`RECOVERY_BLOCKED` and retains its reservation and workspace slot for operator
review. There is intentionally no general legacy split-window inference path.

## Open decisions

None for the first increment. The approved policy is automatic convergence for
provable outcomes, explicit fail-closed blocking for genuinely ambiguous
outcomes, and per-object isolation as the next increment.
