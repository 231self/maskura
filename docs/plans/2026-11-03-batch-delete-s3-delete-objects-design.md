# Batch delete via S3 DeleteObjects — design

Date: 2026-11-03
Status: approved by the owner; implementation starts in a fresh session
Scope: public `maskura` repo (gateway S3 surface); hosted twin surfaces follow

## Problem

`POST /{bucket}?delete` (S3 Multi-Object Delete) is rejected at routing
(`"delete"` in `UNSUPPORTED_S3_SUBRESOURCES` → 501). Deletes are strictly one
key per request. Every existing SDK already speaks DeleteObjects
(`boto3 delete_objects`, aws-sdk), so the right batch contract is the one
clients already call — the product's bet is S3 compatibility.

The hosted side already has a separate compliance-scale deletion surface
(feature-gated `data-deletion` job API + `NamespacePurgeRequest`) — that is
not this; this is the per-object data-plane API.

## Decision

**The batch is an envelope over the existing single-key gated path.** Per key:
policy verdict → receipt → metering event → storage delete — the exact,
unchanged single-delete pipeline. The new code is XML parsing, the response
envelope, and the loop. No new authorization mode, no batch verdict, no
evidence-format change.

> A DeleteObjects batch of N keys is N policy-gated, receipted deletes
> presented under one S3 request. There is no averaged authorization and no
> silent outcome: every key lands in the response as `<Deleted>` or
> `<Error>`.

### Surface

- `POST /{bucket}?delete`: parse `<Delete><Quiet>` and `<Object><Key>` from
  the XML body; caps at **1000 keys / 128 KiB** (S3's own limits); return the
  standard `<DeleteResult>` with per-key `<Deleted><Key>` and
  `<Error><Key><Code><Message>` entries. `Quiet` suppresses `<Deleted>`
  entries. No `VersionId`, no `MFA Delete` (versioning is an unsupported
  subresource — consistent).

### Semantics (S3-faithful, fail-closed)

- **Per-key results**: a policy-denied key lands in `<Error>` (e.g.
  `AccessDenied`, no detail) while other keys proceed. A batch never silently
  drops or silently succeeds a key.
- **Systemic failures fail the request before any key is touched**: bad auth,
  malformed XML, oversized body (>1000 keys / >128 KiB) → typed S3 error,
  no partial deletion.
- **Idempotent**: deleting a missing key returns `<Deleted>` (S3 behavior);
  retries and double-batches are safe.
- **Evidence stays per operation**: each key produces its own receipt and
  usage event (`UsageRoute::DeleteObject`). A 1000-key batch is 1000
  auditable deletes, not one opaque one.

### Implementation

1. **Routing** (`crates/gateway/src/server/routing.rs`): remove `"delete"`
   from `UNSUPPORTED_S3_SUBRESOURCES`; dispatch `POST /{bucket}?delete` to a
   new `s3_delete_objects` handler.
2. **Handler** (`crates/gateway/src/server/`): bounded XML parse (fail closed
   on malformed/oversized) → sequential loop over keys through the existing
   delete path's gate/authorization/storage/journal steps → assemble the
   `<DeleteResult>` envelope. Sequential first (correctness); bounded
   concurrency is a documented follow-up if 1000-key latency matters.
3. **Backends**: managed (transactional deletes + operation journal exist),
   file/local through the same storage delete, presigned only under
   explicit-passthrough scopes (as everywhere since ADR 0029).
4. **Tests** (test-first):
   - policy-gate matrix row: N `Delete` verdicts per batch; a mixed batch
     with one denied key produces per-key outcomes (denied key in `<Error>`,
     others `<Deleted>`); the coverage test's operation set gains N×Delete.
   - filestore conformance: quiet mode; missing key = `<Deleted>`;
     partial denial; exactly-1000 accepted; 1001 rejected; oversized body
     rejected before any deletion; idempotent re-delete.
   - unit: XML parse (malformed, entity attacks, duplicate keys), envelope
     shape, caps.
5. **Docs**: `security.md` (batch = N gated operations, per-key evidence);
   the policy-claim note (ADR 0022 surface extended to batches — one
   paragraph in the ADR 0029 successors list or a short ADR); site/API copy;
   hosted twin where surfaced.

## Consequences

- SDK-visible batch delete with zero client adoption cost.
- Receipt volume scales with keys (1000 receipts per max request) — accepted
  for evidence honesty; monitor metering latency, batched inserts are a
  possible optimization.
- Sequential per-key deletes mean batch latency ≈ N × single-delete latency —
  acceptable for cleanup workloads; bounded concurrency is the named
  follow-up.

## Out of scope

- Async/job semantics (that is the hosted `data-deletion` machinery).
- Prefix deletes, versioned deletes, MFA Delete.
- MCP batch tool (cheap follow-up once the handler exists).

## Conventions for the implementing session

- jj repo; never `git` mutations; `just pre-push` gate before every push;
  PR + merge chain (`gh api repos/231self/maskura/pulls`, update-branch laps).
- Multi-agent safety: work in an isolated jj workspace (`.worktrees/…`),
  never the main checkout; `crates/mcp/**` is another agent's territory.
- Test discipline: `just test`-level coverage locally (not just pre-push);
  the s3_frontdoor fixtures (`explicit_passthrough_test_state`,
  `spooled_test_state`) exist for read-pipeline semantics; deletes need no
  pipeline fixture.
- Full local verification before PR: `cargo test -p maskura-gateway` incl.
  the `s3_frontdoor_test` suite and the db suite with a fresh
  `DATABASE_URL`.
