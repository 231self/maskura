# Zero-config local S3 — Maskura as a dead-simple MinIO replacement

Status: planned
Scope: self-hosted OSS gateway, durable local object storage, release image, CLI, docs
Repositories: public `231self/maskura` (gateway, image, CLI)
Synced against: public `main` @ `a8d6a202` (v0.7.5)

## Objective

Make the published container a drop-in local object store with one command and
no configuration:

```bash
docker run -p 127.0.0.1:9000:9000 -v maskura-data:/data \
  ghcr.io/231self/maskura/maskura:latest
```

This must work with an unmodified `aws s3` CLI (SigV4), persist across restarts,
and preserve uploaded bytes by default. MinIO has shut down its free Docker
image, so the bar is "one container, one volume, zero external services, zero
env vars required."

The durable `FileStore` backend already exists (see
`2026-09-08-local-filesystem-storage-minio-replacement.md`, Phase 1 + Phase 2
implemented). This plan closes the gap between that backend and a genuinely
zero-config, safe, MinIO-shaped *release* experience. It deliberately changes
one prior default: the transform pipeline no longer runs automatically.

## Current-State Findings

The bare command does not start a usable service today:

- The release image sets only `LISTEN_ADDR`, component paths, and the key file
  (`Dockerfile.release:12-18`). It sets none of the local-storage or auth
  settings.
- Without `AUTH_DISABLED=true` or explicit single-tenant mode, startup enters
  multi-tenant validation and is rejected for missing `S4_SERVICE_BUCKETS`
  (`crates/gateway/src/server.rs` `validate_storage_boundary_startup`).
- Ordinary `GET` returns `501 NotImplemented` unless
  `MASKURA_STREAMING_READ_MODE=passthrough` (default `off`).
- The five settings that make local mode work today are exactly what
  `maskura local init` passes: `AUTH_DISABLED=true`, `MASKURA_STORAGE_MODE=local`,
  `MASKURA_LOCAL_STORAGE_DIR=/data`, `MASKURA_MULTIPART_MODE=staged`,
  `MASKURA_STREAMING_READ_MODE=passthrough`.

Compatibility problems found while exercising a real `aws s3` client:

- **Unsupported subresources misroute before dispatch.** `S3Query` recognizes
  only listing/multipart fields and does not deny unknown fields
  (`crates/gateway/src/server.rs`), so `?tagging`, `?versioning`, `?policy`,
  `?location`, `?acl`, `?delete`, etc. can silently become the wrong operation —
  `PUT /bucket?versioning` becomes CreateBucket, `PUT /key?tagging` can
  overwrite the object, `DELETE /bucket?policy` can DeleteBucket.
- **CopyObject is not rejected.** Only `UploadPart` inspects
  `x-amz-copy-source`; ordinary PutObject does not, so a CopyObject can enter
  the transformed PUT path or overwrite the destination with empty input.
- **Bucket semantics are non-S3-like.** PutObject implicitly creates missing
  buckets; ListObjects on a missing bucket returns an empty list; repeated
  CreateBucket succeeds; missing DeleteBucket returns 204 instead of
  `NoSuchBucket`.
- **Metadata is inconsistent.** Multipart-completed objects preserve selected
  metadata; ordinary PutObject preserves only content type. User metadata,
  tags, cache-control, disposition, and encoding are dropped on single-part PUT.
- **`Content-MD5` is not validated** on ordinary PutObject (only UploadPart).
- **No release test** exercises the standalone path. `release-image-smoke.sh`
  tests only a MinIO + Postgres deployment; `examples/prove-maskura.sh` uses
  the published image but with five explicit settings and no restart check.
- **GHCR public visibility is best-effort** (`release.yml`) and never verified
  by an unauthenticated pull, so a release can be announced but unpullable.
- **No healthcheck/readiness.** `/health` is liveness-only; the image has no
  `HEALTHCHECK`, so Compose cannot gate on readiness.
- **CLI/docs disagree.** `maskura local init` uses legacy `s4-local` bucket,
  auth-disabled mode, and `s4-local-keys` volume, while the README/proof use
  `maskura-local`/`maskura-local-keys`; `maskura health` ignores the URL saved
  by `local init` and probes a hardcoded `:9000`.

## Decisions

1. **Conditional auto-local profile in the existing image.** When no hosted or
   external storage configuration is present (`S4_SERVICE_BUCKETS`,
   `S3_ENDPOINT`, `DATABASE_URL`, `MASKURA_STORAGE_MODE`, or an explicit
   profile override), the gateway starts as a single-node local S3 appliance:
   listen on `0.0.0.0:9000`, store under `/data`, staged multipart, passthrough
   reads. Explicit hosted/external settings retain today's behavior and the
   internal `8080` contract. No separate image or tag.

2. **Bytes are preserved by default.** Auto-local mode runs with an empty
   pipeline (no transform). The Wasm pipeline (PII redaction, envelope and
   stable encryption) remains available but must be explicitly enabled. This is
   a deliberate change from the "self-cleaning store" default and is what makes
   Maskura a true byte-compatible MinIO replacement.

3. **Generated root credentials with env override.** On first start the gateway
   bootstraps one root principal and prints the access key + secret once to the
   container log. `MASKURA_ROOT_USER` and `MASKURA_ROOT_PASSWORD` override it;
   both must be set together, and a partially-set pair is a hard startup error
   (never a guess). The generated secret is persisted inside `/data` and reused
   on later starts without re-printing. The one-time disclosure is a documented
   exception to the "never log secrets" rule, scoped to local-appliance
   initialization.

4. **SigV4 is required; `AUTH_DISABLED` is not used for the appliance.** The
   root principal authenticates through the existing SigV4 path, so an
   unmodified `aws s3` CLI works with `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`
   set to the printed values. Auto-local mode does not open an unauthenticated
   endpoint.

5. **Canonical `maskura` bucket** is created on first initialization (only in
   auto-local mode), so the first `aws s3 cp s3://maskura/...` succeeds without
   a prior `mb`. Explicit bucket creation remains supported and required for any
   other bucket.

6. **Initial S3 compatibility contract.** Path-style SigV4 clients get: bucket
   create/list/head/delete; object put/get/head/delete; list-v2 with prefix and
   delimiters; byte ranges; standard + user metadata persistence; `Content-MD5`
   and checksum validation; staged multipart upload/abort; presigned core
   operations; correct `NoSuchBucket`/`NoSuchKey`/bucket-exists semantics. This
   is a durable single-node S3 core, not AWS/MinIO feature parity.

7. **Unsupported operations fail closed and never mutate state.** Before
   method/path dispatch, recognized S3 subresources are classified explicitly.
   Unsupported APIs — tagging, policies, ACLs, versioning, lifecycle, retention,
   legal hold, multi-delete (`?delete`), CopyObject, and UploadPartCopy — return
   an S3 XML `NotImplemented` and must not create, overwrite, or delete data.

8. **Bucket/object semantics are corrected** to S3 behavior: missing bucket →
   `NoSuchBucket`; PutObject does not implicitly create buckets; repeated
   CreateBucket returns the appropriate duplicate-bucket response; DeleteBucket
   on a missing bucket returns `NoSuchBucket`; single-part PUT persists the same
   metadata set as multipart.

9. **Release gate is made blocking and covers the advertised command.** Public
   GHCR visibility is a hard step; after publication, the workflow performs an
   unauthenticated pull of the version tag and `latest` before creating the
   GitHub release.

10. **Readiness + healthcheck.** `/health` stays liveness; add `/ready` (local
    storage/journal/disk checks) and an OCI `HEALTHCHECK` so Compose can gate on
    readiness.

11. **CLI `local init` is aligned** to the appliance: authenticated local mode,
    `maskura` bucket, `maskura-local-keys` volume, and `maskura health` uses the
    URL saved by `local init`.

12. **Compose/`just dev-up` default to FileStore.** The MinIO-backed path is
    demoted to an isolated differential/cloud-validation test and removed from
    the customer quickstart.

## Out of scope (tracked as parity matrix, not implemented)

Object versioning and delete markers, ACLs, bucket policies, IAM, SSE-C/KMS,
lifecycle, WORM/locking, event notifications, replication, and advanced copy/
tagging APIs. Each is deferred until it has an explicit conformance test against
a pinned MinIO release.

## Ordered Implementation

### 1. Auto-local startup profile + port selection

**Files:** `crates/gateway/src/server.rs`, `crates/gateway/src/main.rs`,
`crates/customer-config/src/config.rs`, `Dockerfile.release`.

- Add a `Profile`/mode resolution step that detects "no hosted/external storage
  configured" and selects the local-appliance defaults (9000, `/data`, staged
  multipart, passthrough reads, empty pipeline).
- Preserve current defaults whenever hosted/external settings or an explicit
  override are present (internal `8080` contract unchanged).
- Image gains the entrypoint/`ENV` wiring needed to run the appliance with no
  `-e` flags, while still honoring explicit `-e` overrides.

**Verify:** bare `docker run` reaches readiness; `docker run -e S3_ENDPOINT=...`
and `-e S4_SERVICE_BUCKETS=...` keep today's startup and port behavior.

### 2. Root credential bootstrap

**Files:** `crates/gateway/src/server.rs` (key store), `crates/gateway/src/store.rs`.

- On first init with no persisted root key, generate (or accept via
  `MASKURA_ROOT_USER`/`MASKURA_ROOT_PASSWORD`) a root principal, persist it
  inside `/data`, and print it once.
- Reject a partially-set credential pair at startup.
- Root principal authenticates through the existing SigV4 path; auto-local mode
  never uses `AUTH_DISABLED`.

**Verify:** first start prints credentials; restart reuses them silently; env
override works; partial override fails; `aws s3` with the printed values succeeds.

### 3. Canonical bucket + corrected bucket/object semantics

**Files:** `crates/gateway/src/file_store.rs`, `crates/gateway/src/server.rs`.

- Create `maskura` bucket on first auto-local init.
- Missing bucket → `NoSuchBucket`; no implicit bucket creation on PUT; repeated
  CreateBucket and missing DeleteBucket follow S3 responses; DeleteBucket on a
  non-empty bucket returns the right error.

**Verify:** front-door tests for each semantic; `aws s3 mb/rb/ls` behave
correctly; PUT to an uncreated non-canonical bucket fails with `NoSuchBucket`.

### 4. Metadata parity + `Content-MD5` on ordinary PUT

**Files:** `crates/gateway/src/server.rs`, `crates/gateway/src/file_store.rs`,
`crates/gateway/src/transaction/file.rs`.

- Persist the same metadata set for single-part PUT as multipart (content type,
  encoding, `x-amz-meta-*`, cache-control, disposition, language).
- Validate `Content-MD5` and `x-amz-checksum-*` on ordinary PUT with the same
  rigor as UploadPart.

**Verify:** PUT → HEAD round-trips metadata; a wrong `Content-MD5` is rejected;
  checksum mismatches are rejected.

### 5. Fail-closed dispatch for unsupported operations

**Files:** `crates/gateway/src/server.rs`.

- Classify subresources before dispatch; reject unknown subresources and
  CopyObject/UploadPartCopy with XML `NotImplemented` and zero state mutation.

**Verify:** for each unsupported subresource and copy op, assert the response
code/XML and that no object/bucket was created, overwritten, or deleted.

### 6. Readiness endpoint + OCI healthcheck

**Files:** `crates/gateway/src/server.rs`, `Dockerfile.release`.

- Add `/ready` with local storage/journal/disk checks; add `HEALTHCHECK` to the
  image using `/ready`.

**Verify:** `/ready` reflects storage health; Compose `--wait` gates on readiness.

### 7. Release gate hardening

**Files:** `.github/workflows/release.yml`, `scripts/release-image-smoke.sh`.

- Add an assembled-image smoke test for the exact zero-config command: reach
  readiness, generated credentials, default bucket, unchanged-byte round-trip,
  multipart upload, restart persistence against the same volume, and credential
  override.
- Make GHCR public-visibility setup a hard step; verify an unauthenticated pull
  of the version tag and `latest` before creating the release.

**Verify:** smoke test passes in CI; a failed visibility step fails the release.

### 8. CLI `local init` + `maskura health` alignment

**Files:** `crates/s4ctl/src/main.rs`.

- `local init` uses authenticated local mode, the `maskura` bucket, and
  `maskura-local-keys` volume; `maskura health` reads the URL saved by
  `local init`.

**Verify:** `maskura local init` → `maskura put`/`get`/`health` round-trip.

### 9. Compose + docs + ADR

**Files:** `local/docker-compose.yml`, `justfile`, `README.md`,
`docs/security.md`, `docs/proofs.md`, `docs/parity.md`, `AGENTS.md`, new ADR.

- Default compose/`just dev-up` to FileStore; keep MinIO only as an isolated
  differential test.
- Document the auto-local contract, generated credentials, override vars, port
  9000, the canonical bucket, the parity matrix, and the one-time secret
  disclosure exception.
- ADR records the lasting choices: auto-local profile, byte-preserving default,
  root credential bootstrap, and fail-closed unsupported-operation handling.

## Verification Gates

- `just check` passes (`-D warnings`); new unit + front-door tests cover profile
  resolution, credential bootstrap/override, bucket/object semantics, metadata,
  checksums, and non-mutating rejection.
- A real-TCP FileStore suite using the AWS SDK and AWS CLI covers the agreed
  core operations.
- The assembled-image smoke test passes the exact zero-config command with
  restart persistence, multipart, and credential override.
- GHCR public-visibility setup is blocking and followed by an unauthenticated
  pull of both tags.

## Success Criteria

- One command, one volume, zero env vars: an unmodified `aws s3` CLI works
  against the published image with no prior configuration.
- Uploaded bytes are preserved by default; the transform pipeline is opt-in.
- Unsupported S3 operations return `NotImplemented` and never mutate data.
- The release cannot be announced without a verified public, anonymous-pullable
  image that passes the standalone smoke test.

## Open Decisions

- **Root credential mapping.** Whether `MASKURA_ROOT_USER`/`MASKURA_ROOT_PASSWORD`
  map onto a persisted Maskura API key (reusing the key repository and SigV4
  verification) or a separate first-class root verifier. Leaning toward the
  persisted-key approach to reuse existing verification; length/format
  constraints on the key ID/secret are relaxed for the root principal.
- **Port override naming.** Whether an explicit `LISTEN_ADDR`/port env var
  should also be honored in auto-local mode (yes, planned; exact name TBD).
- **Pipeline opt-in surface.** The exact mechanism for enabling the transform
  pipeline in auto-local mode (existing `MASKURA_FILTER_COMPONENT` vs. a new
  profile setting).
