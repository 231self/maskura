# Local filesystem storage (FileStore) — Maskura as an open-source MinIO replacement

Status: implemented (Phase 1 and Phase 2)
Scope: self-hosted OSS gateway, durable local object storage, S3 data plane
Repositories: public `231self/maskura` (gateway)
Synced against: public `main` after PR #116 and `s4-private` @ `9992d6cd` (PR #93)

## Objective

Let the gateway run as a standalone S3-compatible object store backed by local
disk — a drop-in MinIO replacement — with **no Postgres, no MinIO, and no cloud
credentials**. Two zero-dependency deployment shapes become possible:

1. **Local durable storage** — `docker run -v /data:/data <image>` stores objects
   in the mounted volume (this plan: a new `FileStore` backend).
2. **Bring-your-own cloud** — point the gateway at AWS/R2/B2/… credentials
   (already works today; no code required).

Maskura's differentiator over MinIO is unchanged: the transform pipeline (PII
redaction, envelope encryption — now hybrid X25519 + ML-KEM-768 per PR #108 —
per-field stable encryption) sits on the data path, so the S3 endpoint both
stores objects *and* scrubs/encrypts them.

## TODO: advanced MinIO parity

The standalone Docker path is complete for the basic S3 object, bucket, listing,
and multipart operations documented below. Full MinIO feature parity remains a
separate follow-up and must not be implied by the local replacement quickstart.
Track implementation and conformance coverage for:

- object versioning and delete markers;
- ACLs, bucket policies, and IAM-equivalent authorization;
- SSE-S3/SSE-KMS and customer-managed encryption headers;
- lifecycle rules, retention, WORM, and object locking;
- event notifications, replication, and remaining advanced copy/tagging APIs.

Each item needs an explicit compatibility test against a pinned MinIO release
before it is advertised as supported.

## Historical findings before implementation

- The release image (`Dockerfile.release`) contains only the gateway binary and
  Wasm components — MinIO is **not** part of the runtime. MinIO appears only in
  `local/docker-compose.yml`, the e2e/smoke scripts, and dev docs.
- The gateway is already fully S3-API compatible and provider-agnostic. The
  resolver returns one of four backends (`ResolvedBackend`, `backend.rs:159`):
  `PresignedHttp`, `S3 { PerUserS3 | GlobalS3 }`, `Managed(ServiceStorage)`, and
  `Memory(MemoryStore)`. None is cloud- or MinIO-specific.
- There is **no durable filesystem object store**. What exists is not it:
  - `MemoryStore` (`store.rs:87`) — in-memory HashMap, dev fallback, not durable.
  - `FileKeyStore` (`store.rs:923`) — JSON file for **API keys only**, not objects.
  - `read_spool.rs` / `transaction/spool.rs` — encrypted temp staging for
    transformed reads, not a persistent object store.
- The read/head/delete/list paths already have `Memory` match arms that a `File`
  arm would mirror exactly: `open_object` (`server.rs:1751`), `s3_delete`
  (`server.rs:8898`), `s3_list_objects` (`server.rs:9435`, `server.rs:10098`),
  plus the metadata/kind reporting arms (`server.rs:4125`, `server.rs:4501`).
- The write path is abstracted behind `ObjectSinkTransaction` (`transaction/mod.rs`).
  `MemorySinkTransaction` (`transaction/memory.rs`) is the exact template: buffer
  chunks, hash, `verify_output` (size + SHA-256), then atomically publish on
  `complete()`. A `FileSinkTransaction` spools those chunks to a temp file instead
  of memory, removing the memory bound.
- CreateBucket / DeleteBucket are currently hard-rejected
  (`s3_bucket_put`/`s3_bucket_delete`, `server.rs:10124`/`10140` return
  `bucket_not_allowed`) — a concrete MinIO-parity gap (`mc mb` / `aws s3 mb`).
- The single-tenant fallback today lands on `Memory` when there is no `S3_ENDPOINT`
  and no `S4_SERVICE_BUCKETS` (`backend.rs:435`). `FileStore` slots into this same
  fallback when storage mode is `local`.
- **Layered TOML config landed (PR #110).** `Config` and `StorageConfig`
  (`s3_endpoint`, `s3_region`, `service_buckets`, `single_tenant`) now live in
  `crates/customer-config/src/config.rs` (`StorageConfig` at `config.rs:55`),
  parsed via `Config::from_file`/`from_toml_str` with `apply_env_overrides`
  (`config.rs:218`) and `validate` (`config.rs:372`). However, `build_state`
  (`server.rs:10982`) does **not** consume the TOML `Config` yet — it still reads
  env directly (`std::env::var("S3_ENDPOINT")` at `server.rs:11002`), and the OSS
  binary (`main.rs`) does not load a config file. FileStore settings must be added
  to `StorageConfig` *and* read in `build_state` the same way `s3_endpoint` /
  `service_buckets` are today.
- **Customer `S4_*` / `x-s4-*` env aliases are abandoned (PR #110).** Every
  customer setting is `MASKURA_*` only (`crates/customer-config/src/lib.rs`);
  operator-only `S4_*` names (`S4_SERVICE_BUCKETS`, `S4_MANAGED_*`,
  `S4_MULTIPART_STAGING_*`, `S4_SIGV4_*`, `S4_PRESIGNED_HTTP_*`,
  `S4_WORKSPACE_ENDPOINT_*`) remain canonical. New FileStore env vars must be
  `MASKURA_*`.
- `FeaturesConfig` already carries a `dev_memory_streaming` flag and
  `LimitsConfig.dev_memory_max_object_bytes` — FileStore is a durable, production
  upgrade of that dev-only memory path, so it should follow the same shape.

## Decisions

1. **New `FileStore`** — a durable object store mirroring `MemoryStore`'s API
   (`put`/`get`/`head`/`metadata`/`delete`/`list_keys`, `store.rs:102-166`) but
   persisting each object as `<data_dir>/<bucket>/<key>` plus a JSON sidecar
   `<data_dir>/<bucket>/<key>.s4meta` (content-type, etag, size, mtime). Writes are
   atomic: temp file → `fsync` → `rename` (the `FileKeyStore::persist_snapshot`
   pattern, `store.rs:990`). Key→path mapping is traversal-safe (`..`, absolute,
   and NUL rejected).
2. **New `FileSinkTransaction`** (`transaction/file.rs`) implementing
   `ObjectSinkTransaction`: `write(chunk)` appends to a temp file (streaming to
   disk, no whole-object memory), `verify_output` checks size + SHA-256,
   `complete()` renames the temp file into place and writes the sidecar, `abort()`
   removes the temp file. Mirror of `MemorySinkTransaction`
   (`transaction/memory.rs`).
3. **New backend variant** `ResolvedBackend::File(Arc<FileStore>)` and
   `BackendKind::File` (`backend.rs:40`, `backend.rs:159`). Resolution: storage
   mode `local` (single-tenant, no `S3_ENDPOINT`, no `S4_SERVICE_BUCKETS`) selects
   `File` instead of the current `Memory` fallback (`backend.rs:435`).
4. **Configuration**: `MASKURA_STORAGE_MODE=local` and `MASKURA_LOCAL_STORAGE_DIR`
   (default `./data`; `/data` in the container image). Fails closed at startup if
   the directory is absent or unwritable. Add `local_dir` (and a `mode` selector)
   to `StorageConfig` (`config.rs:55`) with an override in `apply_env_overrides`
   (`config.rs:218`) registered as a `MASKURA_*` alias in `lib.rs`; read the same
   values in `build_state` (`server.rs:11002`) until `build_state` is threaded
   through `Config`.
5. **Bucket operations in File mode**: `PUT /{bucket}` creates the bucket directory,
   `DELETE /{bucket}` removes it recursively (fails on non-empty per S3 semantics).
   Non-File modes keep rejecting, unchanged.
6. **Zero-config auth path stays as-is**: `AUTH_DISABLED=true` plus in-memory or
   `MASKURA_KEYS_FILE` keys is the drop-in shape; API-key/Supabase auth remains for
   production. No auth changes in this plan.
7. **Single-PUT crash safety via rename, not the durable journal.** A single-object
   PUT to `FileStore` is atomic because of the temp-file rename; it does not need
   the Postgres/`FileOperationJournal` machinery that multipart reconciliation
   requires. `validate_streaming_backend` (`server.rs:3486`) gains a `File` arm
   that returns `Ok(())` unconditionally (a durable backend, unlike the dev-gated
   `Memory` arm at `server.rs:3522`), and `begin_streaming_sink`
   (`server.rs:3185`) constructs the `FileSinkTransaction` for it without touching
   `operation_journal`.
8. **Out of scope for the single-node backend** (tracked as a parity matrix in
   docs, not implemented):
   object versioning, SSE-S3/SSE-C, lifecycle rules, bucket policy/IAM, object
   tagging, event notifications, replication, and WORM/locking. Durable multipart
   is implemented separately under ADR 0013 and is enabled explicitly with
   `MASKURA_MULTIPART_MODE=staged`.

## Sequencing (Phases)

**Phase 1 — single-PUT FileStore (implemented).** PUT/GET/HEAD/DELETE/LIST and
bucket Create/Delete on local disk, via `FileStore` + `FileSinkTransaction`, with
a `File` streaming arm that needs no durable journal (rename atomicity). This
ships the standalone MinIO-replacement shape for ordinary objects.

**Phase 2 — multipart FileStore (implemented).** `CreateMultipartUpload` /
`UploadPart` / `CompleteMultipartUpload` use encrypted local artifacts,
file-backed repository state, fenced publication, exact replay, and atomic
FileStore visibility. The `FileOperationJournal` and local multipart repository
reconcile crashes before serving traffic and through bounded recurring cleanup.

## Ordered Implementation

### 1. `FileStore` storage layer

**Files:** new `crates/gateway/src/file_store.rs` (or extend `store.rs`).

- `FileStore { root: PathBuf }` with async `tokio::fs` methods mirroring
  `MemoryStore` (`put`/`get`/`head`/`metadata`/`delete`/`list_keys`), reading and
  writing the `.s4meta` sidecars.
- Traversal-safe key mapping and bucket-name validation; atomic temp-file +
  `fsync` + `rename`; sidecar excluded from `list_keys`.

**Verify:** unit tests for round-trip, overwrite, delete, list (sidecar filtered),
missing key, atomic rename (no partial object after a simulated crash), and
rejection of `..`/absolute/NUL keys.

### 2. `FileSinkTransaction` write path

**Files:** new `crates/gateway/src/transaction/file.rs`.

- Implement `ObjectSinkTransaction` with a temp-file sink, streaming SHA-256,
  `verify_output`, and rename-on-`complete` into `FileStore`. On `abort`, remove
  the temp file and release any spool reservation.

**Verify:** unit tests mirroring `MemorySinkTransaction`'s: capacity, output
mismatch on size/digest, commit-then-finished, abort, and commit-then-idempotency.

### 3. Backend wiring (resolver + kind + match arms)

**Files:** `crates/gateway/src/backend.rs`, `crates/gateway/src/server.rs`.

- Add `BackendKind::File` and `ResolvedBackend::File`.
- In `BackendResolver` (`backend.rs:246`), return `File` for storage mode `local`.
- Add `File` arms to `open_object` (`server.rs:1751`), `s3_delete` (`server.rs:8898`),
  `s3_list_objects` (`server.rs:9435`, `server.rs:10098`), the kind/metadata
  reporters (`server.rs:4125`, `server.rs:4501`), and `validate_streaming_backend`
  (`server.rs:3486`).

**Verify:** `backend.rs` resolver tests assert `BackendKind::File` for local mode;
a PUT/GET/HEAD/DELETE/LIST round-trip through the HTTP frontdoor against `FileStore`.

### 4. Startup wiring + configuration

**Files:** `crates/gateway/src/server.rs` (build_state, `server.rs:10982`),
`crates/customer-config/src/config.rs` (`StorageConfig` + `apply_env_overrides`),
`crates/customer-config/src/lib.rs` (new `MASKURA_*` alias),
`crates/gateway/src/main.rs`, `local/Dockerfile` / `Dockerfile.release` (env default).

- Add `local_dir: Option<String>` (and a `mode` selector) to `StorageConfig`
  (`config.rs:55`) with a `MASKURA_LOCAL_STORAGE_DIR`/`MASKURA_STORAGE_MODE`
  override in `apply_env_overrides` (`config.rs:218`), registered as a `MASKURA_*`
  alias in `lib.rs`.
- In `build_state` (`server.rs:10982`), read the same values env-first (matching
  the current `S3_ENDPOINT`/`S4_SERVICE_BUCKETS` pattern at `server.rs:11002`),
  construct `FileStore`, and pass it into `BackendResolver::new`
  (`server.rs:1214`); fail closed on an unwritable directory.
- Set `MASKURA_LOCAL_STORAGE_DIR=/data` and a writable `/data` VOLUME in the image.

**Verify:** release boot with `MASKURA_STORAGE_MODE=local` + a mounted dir logs
"Storage: local filesystem"; boot with an unwritable dir fails with a clear error.

### 5. Bucket Create/Delete in File mode

**Files:** `crates/gateway/src/server.rs` (`s3_bucket_put`/`s3_bucket_delete`,
`server.rs:10124`/`10140`).

- In File mode, `PUT /{bucket}` creates the directory; `DELETE /{bucket}` removes
  it (409 on non-empty). Keep non-File modes rejecting.

**Verify:** `aws s3 mb` / `mc mb` and `aws s3 rb` succeed against File mode;
`DeleteBucket` on a non-empty bucket returns the correct S3 error.

### 6. Standalone image + dev parity + docs

**Files:** `local/docker-compose.yml`, `justfile`, `README.md`, new
`docs/parity.md` (or a section in `docs/benchmarks.md`), `AGENTS.md`.

- Add a minimal standalone compose/service (or document a plain `docker run`)
  with only a volume and `MASKURA_STORAGE_MODE=local` — no MinIO service.
- Document the MinIO-parity matrix (supported vs. deferred operations).
- Keep `just dev-up`/`just e2e` MinIO-based as the *cloud*-storage validation
  path, or migrate them to File mode; at minimum add a File-mode smoke test.

**Verify:** `just check` green; a plain `docker run -v` round-trips PUT/GET with
`aws s3`/`mc` and no MinIO container.

### 7. ADR + tests

**Files:** new `docs/adr/0012-*.md` (supersede numbering once merged),
`crates/gateway/tests/*` for frontdoor File-mode coverage.

- ADR records the lasting choice: local durable storage backend, metadata
  sidecar layout, rename-based atomicity, and the storage-mode selection rule.
- Frontdoor test exercises the full S3 data plane against `FileStore` (no MinIO).

**Verify:** `just check` and the new frontdoor test pass.

## Verification Gates

- `just check` passes (`-D warnings`).
- A **release** gateway with `MASKURA_STORAGE_MODE=local` and a mounted directory
  serves PUT/GET/HEAD/DELETE/LIST and bucket Create/Delete with no Postgres, no
  MinIO, and no cloud credentials.
- Objects survive a gateway restart (durability), and a kill-mid-write leaves no
  partial object (rename atomicity).
- `docker run -v /data:/data` is interoperable with `aws s3`/`mc`.
- `FileStore` + `FileSinkTransaction` unit tests cover round-trip, overwrite,
  delete, list, crash atomicity, and output-mismatch.

## Success Criteria

- Maskura is a usable S3-compatible endpoint backed by local disk: one container,
  one volume, zero external services.
- The existing transform pipeline still runs on every PUT/GET, so the endpoint is
  a "self-cleaning" object store (the MinIO-replacement differentiator).
- The MinIO-parity matrix is documented, and the deferred items (versioning, SSE,
  lifecycle, policy, tagging, notifications, replication, and object locking) are
  explicitly listed with owners/tracking.

## Open Decisions

- **ETag algorithm** — MD5 of stored bytes (S3 parity, enables `If-Match`/`If-None-Match`
  and `mc` checksums) vs. the current UUID vs. SHA-256. MD5 is preferred for
  MinIO/drop-in parity.
- **Metadata layout** — per-object `.s4meta` sidecar (chosen) vs. per-bucket JSON
  index vs. extended attributes. Sidecar is portable (works on macOS Docker and
  non-Linux filesystems); xattr is cleaner but Linux-only.
- **Storage-mode representation** — a dedicated `mode` enum (`local`/`s3`/`managed`)
  vs. an inferred mode from which of `s3_endpoint`/`service_buckets`/`local_dir`
  is set (mirrors the existing mutually-exclusive `validate_combinations` at
  `config.rs:542`).
- **Default `MASKURA_LOCAL_STORAGE_DIR`** — `./data` in dev vs. `/data` in the
  container (both provisioned in their respective images).
- **Whether `just dev-up`/`e2e` keep MinIO** as the cloud-storage validation path,
  or switch fully to File mode (leaving cloud validation to `S4_SERVICE_BUCKETS`
  or the B2 demo).
