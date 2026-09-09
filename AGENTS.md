# Maskura development conventions

## Version Control

This is a **jj** repository. Do not use `git` directly for mutations.

```bash
jj st                # show working copy status
jj log               # show commit history
jj commit -m "msg"   # commit working copy changes
jj git push          # push to origin
jj git fetch         # fetch from origin
```

All commits require a description (-m). Avoid interactive flags.
Verify with `jj st` and `jj log` after each mutation.

Author identity: commit as `amit231self <amit@231self.com>` (jj user config).
Never append AI `Co-Authored-By` / `Generated with <tool>` trailers (Claude,
Codex, etc.) to commit messages — they pollute GitHub's contributors graph.
`main` history is shared and must never be force-rewritten except by the
owner after an explicit, documented decision.

## Build

- `just check` — format, lint, test
- `just check-fmt` — `cargo fmt --check`
- `just check-lint` — `cargo clippy --all-targets -- -D warnings`
- `just test` — `cargo test --workspace`
- `just build-filters` — build the Wasm filter component
- `just build-sdks` — generate Python + TypeScript client SDKs from OpenAPI spec
- `just deny` — run cargo-deny
- `just audit` — run cargo-audit

## Code Conventions

- Rust 2024 edition.
- No warnings allowed in production code (RUSTFLAGS = -D warnings).
- Crate boundaries at security/protocol seams, not one crate per noun.
- If a crate has one caller and no independent tests, merge it.
- No functionality is added without extensive unit tests.
- Prefer specialized libraries over raw regex for PII detection (email, card validation).

- **Architecture decisions belong in the public repo's ADRs.** When work
  changes a lasting choice (interfaces, trust boundaries, storage, security,
  deployment), create a new `docs/adr/NNNN-*.md` or update/supersede the
  affected record in the same change, following the template and rules in
  `OWNERS.md` ("Architecture Decision Records"). Never silently let an ADR go
  stale relative to the code.

## Database

- Relational modeling with normalized Postgres relations.
- JSONB only for opaque provider payloads, signed manifests, and audit details.
- Store money as integer minor units, byte usage as BIGINT.
- Use **SeaORM** for all database access: entities in `src/entity/` (derive
  `DeriveEntityModel`) + the SeaORM query builder. Never raw `sqlx::query(...)`
  strings in application code.
- All queries go through `Entity::find`/`insert`/`update`/`delete`/`update_many` etc.
- Database migrations are `.sql` files (schema only), managed by `sqlx::migrate!` —
  never applied manually via `psql` or `docker exec`.
- Migration files live in `migrations/` at the crate or workspace root, versioned sequentially.
- Run `sqlx migrate run` to apply; test migrations with `sqlx migrate info` before commit.

## API Design

- Frontend-to-backend APIs must be typed end-to-end.
- Define shared types in a dedicated crate or generate from OpenAPI/Smithy schemas.
- Use `serde` derive for all request/response types.
- API errors use a single typed envelope: `{ code, message, details? }`.
- Never pass raw upstream errors or stack traces to clients.
- S3 data-plane responses use proper S3 XML error documents.

## Architecture Decisions

Document every infrastructure, auth, storage, and deployment choice so automations stay in line.

### Auth

- **Supabase Auth (GoTrue)** for user signup, login, magic-link emails, and session management.
- Supabase JS client in the dashboard browser app; `jsonwebtoken` crate in the gateway validates JWTs.
- API keys (S3 access key + secret) and MCP tokens are separate from user sessions. Each stores immutable `workspace_id` execution scope plus `user_id` dashboard ownership. Legacy unbound credentials fail authentication rather than resolving a current/default workspace.
- Gateway verifies API keys on S3 routes via `x-maskura-access-key` / `x-maskura-secret-key` headers or `Authorization: Bearer <access_key>:<secret>`.

### Database

- **Supabase Postgres** (local: supabase CLI Docker containers).
- ORM: `sea-orm` (built on `sqlx`). Queries use entities (`crates/gateway/src/entity/`) and the SeaORM query builder — no raw SQL strings in code. `sqlx::migrate!` runs the `.sql` schema migrations.
- Migration files in workspace-root `migrations/`, versioned sequentially (`YYYYMMDDHHMMSS_description.sql`). The gateway runs `sqlx::migrate!()` at startup.
- `sqlx migrate run` applies; `sqlx migrate info` checks status. Never use `psql` or `docker exec` directly.
- **API keys and MCP tokens are persisted in Postgres** when `DATABASE_URL` is set (`PostgresKeyStore`); otherwise the in-memory/file stores are used. All implement `KeyRepository` and persist an immutable workspace-bound principal. Migration `20260907000002` leaves ambiguous legacy rows unbound and therefore unusable for authentication.

### Hosted MCP

- Shared typed MCP schemas, results, tool definitions/aliases, dispatch, and list parsing live in `maskura-mcp-protocol` and are re-exported as `s4_gateway::mcp`.
- Hosted adapters authenticate externally and call `s4_gateway::server::invoke_mcp` with an atomically resolved `AuthenticatedMcpPrincipal`, server operation UUID, bounded typed request, timeout, and cancellation token.
- Trusted invocation uses task-local context unavailable to HTTP clients and runs the existing S3 authorization, filtering, storage, transaction, and metering handlers. It never uses loopback HTTP or synthesized auth headers.

### Storage (Object Data)

- **Storage resolution order**: explicit `x-maskura-storage-mode: managed`, per-object
  presigned URL (`x-maskura-backend-url`), per-workspace configuration, then configured
  Maskura service storage. Only explicit single-tenant mode may continue to global
  `S3_ENDPOINT` and then in-memory storage.

- **Presigned URL proxy**: User generates a presigned PUT/GET URL for their bucket with their own SDK. Sends it as `x-maskura-backend-url`. Maskura validates the API key, filters PII, and forwards to the presigned URL. No backend credentials are stored. Platform-agnostic (S3, R2, B2, MinIO).

- **Per-workspace backend**: `WorkspaceStorageRepository` maps authenticated users
  to canonical, unchanged `WorkspaceId` values and returns `managed`,
  `s3_compatible` (static credentials), or `aws_role` (IAM role ARN + region +
  optional `external_id`, assumed via STS per request). There is no per-user
  `BackendRegistry` contract.

- **Tenant storage boundary**: Multi-tenant startup requires non-empty
  `S4_SERVICE_BUCKETS` and rejects `S3_ENDPOINT`. Missing workspace configuration
  defaults to managed storage; repository or required-managed failures fail closed.
  Persisted workspace endpoints require an operator-trusted provider allowlist;
  the SDK resolves DNS again, so tenants must not control allowed provider DNS.
  Per-workspace and presigned clients disable proxies. Presigned HTTP is opt-in
  only for source `GET`; presigned `PUT`/`DELETE` stay HTTPS-only. AWS SDK clients
  make one attempt; transaction layers own their bounded retries.

- **Maskura service storage**: "Just works" mode. Users write PII-cleansed data without configuring any backend. Maskura manages dedicated buckets across multiple cloud providers. Objects are distributed via consistent hashing (150 virtual nodes per backend), dual-written to primary + replica, and read from the replica on primary miss. The operator-only `S4_SERVICE_BUCKETS` setting remains unchanged. Implementation: `crates/gateway/src/service_storage.rs`.

- **Multi-cloud write strategies — progress** (how concurrent multi-cloud writes work today, and the variants we track):

  | Strategy | Status | Behavior in Maskura today |
  |----------|--------|----------------------|
  | Dispersed writes across providers | ✅ implemented | Consistent-hash ring (150 vnodes/backend) assigns each key a primary + one replica, so keys spread across all configured backends; a provider is just an S3-compatible endpoint label (`S4_SERVICE_BUCKETS`) |
  | Active-active writes | ✅ implemented | `put` dual-writes primary + replica concurrently (`tokio::join!`); a replica write failure is logged and does not fail the request |
  | Active-read / passive-read (fail-over) | ✅ implemented | `get` reads the primary; on miss/error it falls back to the replica (`"primary miss for {key}, trying replica"`) |
  | Provider-agnostic R/W | ✅ implemented | No cloud-specific code — every backend is a plain S3-compatible endpoint (AWS, R2, B2, MinIO, …); consistent hashing, dual-write, and fail-over all operate on endpoints only |
  | Active-active reads (read both, compare / use fastest) | 🔲 planned | Would issue reads to primary + replica in parallel and return the first success (or verify equality) — a latency/consistency trade-off, not yet needed |
  | Quorum / consistency checking | 🔲 planned | e.g. write to N-of-M, verify digest across replicas on read; useful once object integrity is a requirement |
  | Regional fail-over / cross-region promotion | 🔲 planned | Promote replica to primary on sustained primary outage (today fail-over is per-request, not a topology change) |
  | Erasure / sharded dispersal | 🔲 not planned | Sharding a single object across providers (e.g. Reed-Solomon) — heavy, low value for PII-cleansed data |

  Anything not in the "✅ implemented" rows is a future consideration, not currently built.

- Objects are NOT persisted in Postgres — only metadata (keys, usage receipts) goes there.

### CLI (`maskura`)

- Binary crate at `crates/s4ctl/`. Full-featured CLI for Maskura operations; `s4ctl` remains an alias.
- Subcommands: `login`, `logout`, `whoami`, `key {create,list,revoke}`, `backend {get,set-aws,set-r2,set-b2,set-minio,presign}`, `put`, `get`, `list`, `health`, `local {init,down}`, `test upload`. `set-aws` configures an `aws_role` backend (role ARN + region + optional external ID).
- Auth from the preserved `~/.config/s4/config.json`, `MASKURA_ACCESS_KEY`/`MASKURA_SECRET_KEY` (with permanent `S4_*` aliases), or demo mode.
- Key expiry support: `--expiry never|30d|90d|1y` (or raw seconds).
- Backend presign: generates presigned URLs via local AWS CLI for use with the Maskura proxy.

### OpenAPI & SDK Generation

- OpenAPI 3.1 spec auto-generated from Rust types via `utoipa` + `utoipa-swagger-ui`.
- Served at `/openapi.json` (raw spec) and `/docs` (Swagger UI).
- `utoipa::ToSchema` on all API types, including API key workspace scope and hosted MCP credential UUID/workspace fields.
- `#[utoipa::path(...)]` annotations on all dashboard API handlers.
- `just build-sdks` extracts spec, runs `openapi-generator` (Docker) to produce Python and TypeScript SDKs in `sdks/python/` and `sdks/typescript/`.
- Schema is the single source of truth — SDKs always in sync with server changes.
- `scripts/generate-sdks.sh` re-applies the hand-written high-level client from `sdks/overlay/<lang>/` after each generation, so it survives regeneration:
  - `s4_client/highlevel.py` / `highlevel.ts` — `MaskuraClient` with `S4Client` compatibility, `put_object`/`get_object` S3 data-plane helpers, hybrid X25519 + ML-KEM-768 key generation, public-key attachment, and client-side hybrid decryption.
  - The decrypt helpers retain dual-algorithm reads for historical RSA envelopes. New key generation is hybrid by default; explicit legacy RSA generation helpers exist only for pre-hybrid compatibility.

### Web Dashboard

- Single-page HTML/JS served inline from the gateway binary at `/`.
- Uses Supabase JS client from CDN for auth. No React/Vite build step needed for the gateway crate.
- Dashboard JS calls `/dashboard/api/*` on the gateway for key management and object listing.

### Deployment

- Single internal Rust binary (`s4-gateway`). No separate frontend server in dev.
- **Local**: `restart-dev.sh` builds filters + gateway, kills stale port, nohup-launches.

### Secrets & Config

- All secrets via environment variables, never in source or committed config.
- `LISTEN_ADDR`, `S3_ENDPOINT`, `DATABASE_URL`, `SUPABASE_JWT_SECRET`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and the explicit customer/operator settings documented in `docs/security.md`.
- Local dev uses Supabase CLI default credentials.

### Key Formats

- API key IDs: `s4_<32-hex>` (UUID without dashes).
- API key secrets: `s4s_<32-hex>`. Revealed once on creation, hashed with SHA-256 for storage.
- S3 requests authenticate with the plaintext secret (like AWS SigV4 secret key).

### Wasm Filter Plugins

- **Plugin pipeline**: Enabled plugins run in order. Output of plugin N becomes input of plugin N+1.
- **Plugin registry** (`crates/gateway/src/plugin_registry.rs`): Stores metadata (id, name, version, enabled) and component bytes. Supports import, enable/disable, remove, reorder.
- **Runtime import**: `POST /dashboard/api/plugins` with `.wasm` body + `x-maskura-plugin-name` header.
- **Runtime toggle**: `PUT /dashboard/api/plugins/{id}` with `{"enabled": true/false}`.
- **Auto-load**: `MASKURA_PLUGINS_DIR` loads all `.wasm` files from a directory at startup.
- **WIT interface** (`wit/s4-filter/world.wit`): `begin(Context)`, `transform(Vec<u8>) → Decision`, `finish()`. Context carries `format`, `content-type`, `policy-version`. Decision variants: `Emit`, `Drop`, `Reject`.
- **Sandbox**: 64 MiB memory, 10K table entries, 512 KiB stack. No host imports; pure byte-in/byte-out. `MASKURA_WASM_FUEL` (default 1B) sets the per-session instruction budget. The baseline `FilterEngine::new` default is 10M; crypto filters require the larger pipeline budget.
- **Default plugin**: `filters/pii-default/` — detects emails (via `@`), credit cards (Luhn check, 13-19 digits), SSNs (9 digits, SSA range validation). Redacts to `[REDACTED_EMAIL]`, `[REDACTED_CARD]`, `[REDACTED_SSN]`.

### Envelope encryption per field

- New encrypted writes use the `X25519+ML-KEM-768/AES-256-GCM` envelope in
  `crates/gateway/src/hybrid.rs` and `filters/envelope-encrypt/`.
- Public keys are `MASKURA HYBRID PUBLIC KEY` PEM blocks. Current gateways
  reject legacy RSA public keys for new writes.
- The client keeps the matching private key; Maskura never receives it.
- The gateway sees plaintext transiently while the selected transform executes
  inside the per-session Wasm sandbox. The encrypted output does not persist
  that plaintext.
- Each field uses fresh encapsulation material and AES-256-GCM authenticated
  encryption. The `enc_dek` field carries an X25519 ephemeral public key plus
  the ML-KEM-768 ciphertext.
- Existing `RSA-OAEP/AES-256-GCM` objects remain a legacy read compatibility
  case. The public high-level SDK helpers decrypt both algorithms and generate
  only hybrid keys by default.
- `filters/stable-encrypt/` is a separate, opt-in AES-SIV transform for stable
  matching keys.

The normative construction, key sizes, client-tooling status, and security
properties are in `docs/encryption.md` and ADR 0011.
