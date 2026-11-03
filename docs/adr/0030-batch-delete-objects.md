# ADR 0030: Batch delete via S3 DeleteObjects

- Status: Accepted
- Date: 2026-11-03

## Context

`POST /{bucket}?delete` (S3 Multi-Object Delete) was rejected at routing:
`"delete"` lived in `UNSUPPORTED_S3_SUBRESOURCES` and every request carrying
it answered `501 NotImplemented`. Deletes were strictly one key per request,
while every existing SDK already speaks DeleteObjects (`boto3 delete_objects`,
the AWS SDKs), so clients that clean up prefixes had no batch contract at all.

The options were: an S3-faithful DeleteObjects surface; a Maskura-specific
batch RPC (JSON, dashboard/MCP only); or async deletion jobs. The hosted side
already has a separate compliance-scale deletion surface (feature-gated
`data-deletion` job API + `NamespacePurgeRequest`) — that is deliberately not
this; this is the per-object data-plane API. A Maskura-specific RPC would
carry adoption cost for zero compatibility gain.

The policy-approval surface (ADR 0022) presents one verdict per data-plane
operation. Any batch design had to decide whether a batch is one authorization
or many, and what the evidence claim becomes.

## Decision

**The batch is an envelope over the existing single-key gated delete path.**
Per key: authorization grant → policy verdict → storage delete → usage
receipt — the exact, unchanged single-delete pipeline
(`crates/gateway/src/server/s3_batch_delete.rs`). The new code is XML parsing,
the response envelope, and the loop.

- **Surface.** `POST /{bucket}?delete` parses `<Delete><Quiet>` and
  `<Object><Key>` and returns the standard `<DeleteResult>` with per-key
  `<Deleted><Key>` and `<Error><Key><Code><Message>` entries; `Quiet`
  suppresses `<Deleted>` entries only. Caps: 1000 keys / 128 KiB (S3's own
  limits). No `VersionId`, no MFA Delete — versioning is an unsupported
  subresource and versioned-delete requests fail closed as `MalformedXML`.
- **Per-key results, systemic preconditions.** A policy-denied or failed key
  lands in `<Error>` (same typed code the single-key path surfaces) while the
  other keys proceed; every key is answered. Systemic failures — bad auth,
  malformed XML, oversized bodies — fail the request as typed S3 errors
  before any key is touched. The batch is idempotent: a missing key reports
  `<Deleted>`, so retries and double-batches are safe.
- **Evidence stays per operation.** Each key presents its own
  `PolicyOperation::Delete` verdict and produces its own usage receipt
  (`UsageRoute::DeleteObject`). A 1000-key batch is 1000 auditable deletes,
  not one opaque one. There is no batch verdict and no averaged
  authorization: the ADR 0022 policy-claim surface extends to batches as N of
  the existing per-operation claims.
- **Bounded, fail-closed parsing.** The request body is parsed by a strict
  minimal grammar parser (the `CompleteMultipartUpload` precedent, no general
  XML resolver): DTDs, entity declarations, comments, and CDATA are rejected
  outright, only XML's predefined and numeric character references are
  decoded, and unknown elements and attributes fail the whole request.
- **Sequencing.** Keys are processed sequentially (correctness first);
  bounded concurrency is a documented follow-up if 1000-key latency matters.

## Consequences

- SDK-visible batch delete with zero client adoption cost; the routing guard
  now allows `?delete` only on `POST /{bucket}` and keeps every other
  method/path carrying it at `501`.
- Receipt volume scales with keys (up to 1000 receipts per request) —
  accepted for evidence honesty; batched receipt inserts are a possible
  metering optimization.
- Batch latency ≈ N × single-delete latency (sequential), which is acceptable
  for cleanup workloads; bounded concurrency is the named follow-up.
- Out of scope and unchanged: async/job deletion (the hosted `data-deletion`
  machinery), prefix deletes, versioned deletes, MFA Delete, and an MCP batch
  tool (a cheap follow-up once the handler exists).
