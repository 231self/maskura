# ADR 0009: Durable Async Write Acknowledgements

- Status: Accepted
- Date: 2026-09-07

## Context

Maskura currently acknowledges an object write only after filtering and the
authoritative storage commit finish. This synchronous contract is simple and
durable, but its latency includes the complete transform and provider path.

Two planning documents proposed incompatible meanings for asynchronous writes.
One used `full-async` for an in-memory, fire-and-forget operation acknowledged
before transformation. The other required every hosted asynchronous
acknowledgement to identify a durable, recoverable write job. Reusing `async`
for both contracts would make a successful response ambiguous and could cause
clients to mistake accepted-but-losable work for a durable write.

## Decision

Maskura has three write acknowledgement modes:

- `sync` is the default. The existing S3 success response remains final and is
  returned only after the configured storage commit policy publishes the
  authoritative object generation.
- `half_async` returns `202 Accepted` only after transformed output, its
  authenticated encryption metadata, the immutable target plan, and the
  operation's ordering fence are durably persisted.
- `async` returns `202 Accepted` only after source bytes or an equally durable
  source reference, the immutable transform and target plan, and the
  operation's ordering fence are durably persisted.

Both asynchronous modes return a stable job ID and operation ID. An
authenticated status resource is authoritative; resumable events may mirror
durable state but cannot replace status lookup. Workers use leases and fencing,
preserve receive order for one object key, publish at most one authoritative
generation, and recover accepted work after process or machine failure.

Metering and billing occur exactly once after authoritative commit, not when a
job is accepted. Failed, cancelled, or abandoned jobs are not billed. Retry is
keyed by operation and target identity and may not create another visible
version.

The canonical request policy name is `x-maskura-write-mode`; the permanent
compatibility alias is `x-s4-write-mode`. A request may only select a mode
allowed by authenticated workspace policy. `DELETE` remains synchronous until
its post-acknowledgement semantics receive a separate decision.

Hosted Maskura does not provide lossy fire-and-forget writes. If a self-hosted
best-effort queue is ever added, it must be named `best_effort`, be disabled by
default, and use a response contract that cannot be confused with durable job
acceptance.

## Consequences

- A `202` from Maskura means the write can be recovered without relying on the
  accepting process or machine.
- Async modes require encrypted durable staging, normalized job and target
  state, quota admission, retry/dead-letter policy, status retention, and
  cancellation semantics before either mode can be enabled.
- Existing S3 clients remain on `sync` and retain their current final-response
  behavior.
- The lower-latency `half_async` mode requires transformation to finish before
  acknowledgement; `async` shifts transformation to workers but consumes
  durable source-staging capacity.
- In-memory fire-and-forget behavior cannot be marketed or configured as an
  asynchronous durability mode.
