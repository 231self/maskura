# BYO (single-tenant) S3 streaming write without Postgres

Status: planned
Scope: self-hosted OSS gateway, direct S3 data plane
Repositories: public `231self/maskura` (gateway)

## Objective

Let the release gateway stream S3 writes in single-tenant ("bring your own
backend", `S3_ENDPOINT`) mode without requiring Postgres. Today the streaming
write path hard-requires a *durable* operation journal, and the only durable
journal is Postgres — so BYO streaming is rejected in release builds and only
works in debug. The fix adds a durable-enough journal that needs no database,
so BYO streaming works safely in production single-tenant deployments.

## Current-State Findings

- The streaming gate is `direct_journal_allowed` (`crates/gateway/src/server.rs:3103`):
  `BackendKind::GlobalS3` (single-tenant `S3_ENDPOINT`) is only accepted when the
  journal `is_durable()`, or in debug builds (`cfg!(debug_assertions)`) with
  `auth_disabled && explicit_single_tenant`.
- `validate_production_journal` (`crates/gateway/src/transaction/mod.rs:941`) bails
  with "production streaming writes require a durable operation journal; configure
  DATABASE_URL" when streaming is requested against a non-durable journal.
- The in-memory journal is debug/test-only: `InMemoryOperationJournal` is gated
  `#[cfg(any(test, debug_assertions))]` (`crates/gateway/src/transaction/journal.rs:640`),
  and startup installs it only under `#[cfg(debug_assertions)]` when `auth_disabled`
  (`server.rs:11117`). In release without `DATABASE_URL`, `operation_journal` stays
  `None` and streaming is rejected outright.
- The journal is the reconciliation source of truth: the gateway records an
  operation *intent* before streaming so that a crash mid-stream can later be
  reconciled (abort/complete the multipart upload). Durability is required for
  real crash-safety, not as a formality.
- `BackendCapabilities` for direct streaming are already satisfied by
  `MASKURA_STREAMING_S3_PROVIDER=aws|minio|r2|b2` (`server.rs:944`); only the
  durable-journal requirement blocks BYO streaming.
- A durable-enough file precedent already exists: `FileKeyStore`
  (`crates/gateway/src/key_cipher.rs`) persists keys to a JSON file. A
  file-backed journal follows the same shape.

## Decisions

1. Add a `FileOperationJournal` that persists operation records to a local file
   (atomic temp-file rename + fsync) and reports `is_durable() == true`. It is
   durable across restarts on a single node — the right tradeoff for BYO.
2. Startup journal resolution: `DATABASE_URL` → `PostgresOperationJournal`
   (unchanged); otherwise, when streaming is requested in single-tenant mode →
   `FileOperationJournal` from a new `MASKURA_JOURNAL_FILE` (default next to the
   keys file); otherwise `None`.
3. Keep the in-memory journal debug/test-only and do **not** relax the release
   gate to accept a non-durable journal — that would silently trade away
   crash-reconciliation safety.
4. On startup, load the file journal and resume reconciliation of any incomplete
   operations via the existing `claim_reconcilable` path.

## Ordered Implementation

### 1. Add `FileOperationJournal`

**Files:** `crates/gateway/src/transaction/journal.rs` (plus a serde schema for
operation records, parts, evidence, and lease state).

- Persist operation records with an append/rewrite-on-transition strategy:
  write to a temp file, `fsync`, rename atomically over the journal file.
- Implement all `OperationJournal` methods; `is_durable()` returns `true`.
- Preserve the transition matrix (`OperationState::can_transition_to`) and the
  COMMITTED-requires-metadata invariant.

**Verify:** a unit test suite mirroring the Postgres journal's tests — transition
matrix, part/evidence dedup, crash-mid-write recovery, and durability across a
re-open of the journal.

### 2. Wire startup resolution

**Files:** `crates/gateway/src/server.rs` (journal construction near line 11086).

- Add `MASKURA_JOURNAL_FILE` (with legacy alias) via `customer_env`.
- When no `DATABASE_URL` but streaming is requested in explicit single-tenant
  mode, construct `FileOperationJournal` and log it; keep the debug in-memory
  fallback for debug builds.

**Verify:** release boot with `S3_ENDPOINT` + `MASKURA_STREAMING_S3_PROVIDER=minio`
+ `MASKURA_JOURNAL_FILE` logs "Operation journal: file" and no longer rejects
streaming PUTs.

### 3. Startup reconciliation

**Files:** `crates/gateway/src/server.rs` (or wherever the reconciler is seeded).

- After constructing the file journal, claim and reconcile incomplete operations
  so a crashed BYO deployment cleans up orphaned multipart uploads on restart.

**Verify:** start a streaming PUT, kill the gateway mid-stream, restart, and
observe the incomplete upload aborted (no orphaned parts left in the backend).

### 4. Documentation

**Files:** `AGENTS.md` (storage/journal section), `docs/security.md` if it lists
journal requirements.

- Record that single-tenant streaming uses a durable file journal when Postgres
  is absent, and that this is single-node durable (not HA).

**Verify:** `just check` green.

## Verification Gates

- `just check` passes (`-D warnings`).
- A **release** gateway with `S3_ENDPOINT` + `MASKURA_STREAMING_S3_PROVIDER=minio`
  + `MASKURA_JOURNAL_FILE` streams a PUT (HTTP 200) without Postgres.
- Kill-mid-stream → restart → incomplete upload reconciled.
- `FileOperationJournal` unit tests cover the transition matrix and crash
  recovery.

## Success Criteria

- BYO single-tenant streaming writes work in release builds with no `DATABASE_URL`.
- Crash-reconciliation safety is preserved (durable journal, not a silent
  non-durable downgrade).
- The Tier-2 end-to-end benchmark (`scripts/bench-e2e.sh`) can run against the
  release gateway using the file journal.

## Open Decisions

- Journal file format: append-only JSONL vs. single JSON document rewritten on
  transition (single document is simpler; JSONL scales better).
- Default `MASKURA_JOURNAL_FILE` location (alongside `MASKURA_KEYS_FILE` vs. a
  dedicated data dir).
- Whether to also gate a non-durable in-memory release path behind an explicit
  opt-in flag (rejected by default for safety).
