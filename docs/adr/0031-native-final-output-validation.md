# ADR 0031: Native final-output validation for single PUT

- Status: Accepted
- Date: 2026-11-10

## Context

An embedding server can need to reject a protected output before its destination
transaction commits. Re-running a pipeline or validating a separately serialized
representation cannot establish that the validated bytes are the stored bytes.
Validation after an acknowledged write is too late. A general staged-write API
would expose a substantially broader transaction surface.

## Decision

The implementation adds an optional trusted native factory to an
isolated request-local server-state clone. It receives the actual authenticated
context, authorization grant, resolved pipeline, policy verdict and selected
destination. Each PUT gets a fresh, one-shot session. Its observer receives the
ordered serialized output sent to the sink, and its finalizer must succeed after
plugin finalization and output verification and before commit. No HTTP header
installs, selects or disables the factory; no receipt or plugin contract changes.

The embedding process must explicitly install the static panic reporter before
using the factory and must not replace it later. The ordinary server does not
change its panic policy. Reporter output omits panic payloads, backtraces and
source locations; caught callback errors map to closed generic responses.
In the opt-in PUT handler, mapped errors omit the object key, policy denials
keep their policy code but use a generic message, and transaction failure
details are not forwarded or logged as dynamic error text. Other routing and
embedding code retains its own error and logging responsibilities.

The validated path accepts JSON and text single PUTs. It rejects upload-part
PUTs, binary and table candidates, and FileStore before reading the body.
FileStore single PUT cannot currently provide the conservative commit-state
behavior this path requires. Multipart creation and completion and other routes
are not intercepted. The factory-absent path retains its existing behavior.
This is not an all-writes interception mechanism: the host must keep the
factory on a request-local clone used only for the intended single PUT.

A supervisor retains the request operation and its sink after a caller drops the
HTTP future. Precommit cancellation and callback failure run the existing
pipeline cancellation and awaited sink abort before releasing the reservation;
abort failure and ambiguous or confirmed commit preserve it. The validator uses
the same original pipeline deadline, including after plugin finish. Once commit
starts it is not interrupted and relabeled as a rollback.
Managed usage-evidence persistence may itself move the sink into a conservative
commit-unknown state; cancellation racing that transition preserves authority
for reconciliation rather than asserting a successful abort.

## Consequences

Native callbacks are trusted cooperative code, not a sandbox. A synchronous
callback that hangs cannot be preempted by an async deadline: its operation and
resources remain owned until it returns. A callback can itself print or leak
data. Callback implementations must not detach native work that outlives the
callback future or session, and must not retain output bytes after abort or
finalization. The supervisor owns the engine pipeline and sink cleanup, not
unknown background work spawned by a native callback; pending callback futures
can be dropped on cancellation. Abort, double panic, runtime shutdown and process death are not graceful
callback failures and require the host's existing protected execution and
reconciliation controls, including appropriate core-dump protections. The
process owner must not replace the static hook.

Transaction journals and settlement evidence are backend-dependent; this seam
does not add a durable journal or prove read-back, distributed revocation, or
uniform recovery. It does not establish that any particular embedding service
has deployed or enabled validation. Integration and regression proof remain
required before publication.
