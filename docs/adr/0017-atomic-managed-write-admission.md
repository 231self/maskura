# ADR 0017: Atomic managed-write admission

- Status: Accepted
- Date: 2026-09-16

## Context

A managed write was admitted in steps, each in its own database transaction:
`insert_logical_operation` committed a logical operation in the `Intent` state,
then the caller read the workspace usage and `reserve_logical_operation`
reserved provider exposure. If the reservation failed, the caller called
`prove_logical_abort` to drive the already-committed `Intent` row to
`ProvenAborted`.

That sequence exists only because the repository methods each open their own
transaction. It spends database round trips on the hosted hot path (the
ledger is the dominant cost of a managed `PUT`) and introduces an intermediate
state — a committed `Intent` row with no reservation — that exists solely to be
cleaned up. Reconciliation (`pending_logical_operations`) treats any operation
that is not `Committed`/`ProvenAborted` as pending, so that intermediate state
is also visible to recovery.

The physical provider mutation (the S3 write) happens only later, in the
streaming sink, after admission succeeds. Nothing in admission mutates the
provider.

## Decision

Admit a managed write atomically. `admit_logical_operation(intent,
reservation_cap)` inserts the logical operation and reserves its provider
exposure in **one** transaction, clamping the reservation to the workspace's
available physical headroom (the same clamp the caller applied). The caller
now makes a single call, and no longer calls `prove_logical_abort` on
admission failure.

When admission fails (quota, or another managed mutation holding the
workspace's single mutation slot), the transaction rolls back and **no**
logical operation row is committed.

The durable-preflight invariant is unchanged: the logical operation is still
persisted before any provider mutation, because the provider write happens
after admission succeeds. The `Intent` state remains reachable for operations
that are inserted by other paths, and `prove_logical_abort` still handles the
`sink_begin_failed` case, where the operation is admitted (open and reserved)
but the sink fails to start and its reservation must be released.

## Consequences

- Removes one transaction, a repeated namespace lock, and a usage read per
  managed `PUT` (roughly four database round trips on the hosted hot path).
- Eliminates the "committed `Intent` row with no reservation" state. A failed
  admission leaves nothing to reconcile instead of requiring an explicit
  `prove_logical_abort`; reconciliation no longer has to reason about it.
- Behaviour change: a failed admission is no longer recorded as a
  `ProvenAborted` logical operation. This is intentional — admission never
  reached a provider mutation, so there is nothing to prove aborted — but any
  operator or metric that counted those rows will stop seeing them.
- The in-memory repository keeps the two-step implementation (it has no
  round-trip cost) but exposes the same atomic contract.
- Covered by `postgres_managed_admission_is_atomic`, which asserts that a
  second admission while a mutation is in progress fails with
  `MutationInProgress` and leaves no logical operation behind.
