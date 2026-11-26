# ADR 0037: Conditional object writes (`If-Match` / `If-None-Match`)

- Status: Accepted
- Date: 2026-11-26

## Context

Maskura implemented conditional **reads** (version/ETag binding) but ignored
`If-Match` and `If-None-Match` on writes. An external catalog needs
create-if-absent and compare-and-swap writes to guard its first commit and its
concurrent updates; silently ignoring the headers would let a stale write win.
AWS S3 supports both conditions natively on `PutObject` and
`CompleteMultipartUpload`, and the SDK in use (`aws-sdk-s3` 1.146) exposes
them.

## Decision

Honor standard S3 conditional-write headers on **single `PutObject`** and
**`CompleteMultipartUpload`**, in and out of byte-preserving scopes:

- `If-None-Match: *` — publish only when no current object exists.
- `If-Match: <etag>` — publish only when the current object matches.
- `If-Match: *` — publish only when an object exists.
- Both headers in one request, or an unsupported `If-None-Match` value, is
  `400 InvalidRequest`.

The precondition constrains the **current** stored object, never the written
bytes. It is evaluated at the commit point, atomically:

- **FileStore / MemoryStore:** compare-and-swap under the store's mutation
  lock, in the same critical section that publishes. A mismatch stores
  nothing.
- **S3-compatible backends:** the native conditional header on the publishing
  `PutObject` / `CompleteMultipartUpload`. A `412` is definitive.
- **Managed service storage, presigned HTTP, and any backend that cannot
  enforce the condition:** `501 NotImplemented` when a conditional header is
  present. Emulating the check with a read-then-write would be racy.

A mismatch returns `412 PreconditionFailed`, releases the usage reservation,
and leaves the previous object unchanged.

### Retry and recovery

- A definitive `412` transitions the operation to `PROVEN_ABORTED`; the
  multipart upload is aborted. Nothing is retried.
- Conditional writes are not idempotent under retry. After an **ambiguous**
  provider outcome the sink stops retrying and reconciles by observation, so
  the same condition can neither fail because our own write committed nor
  overwrite a newer object.
- The precondition is part of the multipart completion fingerprint: a retry
  that declares a different condition is a different operation.
- No operation-journal schema change is required. Recovery never re-publishes
  a direct write; it observes the destination. The existing expected
  digest/size/metadata comparison decides the outcome.

## Consequences

- Headers that were previously ignored are now enforced. That is the S3
  contract clients already assume; the only visible change is a `412` (or
  `501` on managed/presigned backends) where a request previously overwrote
  unconditionally.
- ETag comparison tolerates the optional `W/` prefix and HTTP quoting so
  `If-Match: "abc"`, `If-Match: abc`, and `If-Match: W/"abc"` agree with the
  stored tag.
- `If-None-Match: *` treats a delete marker as "no current object", matching
  S3's current-version semantics.
- The conditional-write verdict is reported as the S3 `PreconditionFailed`
  error document (HTTP 412) and is not billable.
