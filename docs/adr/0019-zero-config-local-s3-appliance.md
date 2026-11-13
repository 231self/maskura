# ADR 0019: Zero-config local S3 appliance

- Status: Accepted
- Date: 2026-09-17

## Context

> **Note (ADR 0029):** the `MASKURA_STREAMING_READ_MODE` surface described in
> this record was retired; reads are governed by the resolved read pipeline.
> The zero-config byte-preserving contract is implemented as a distinct
> server-authored read assignment, not an unassigned read. This assignment is
> restricted to the authenticated local root and local file backend. Explicit
> pipeline or component configuration, custom plugin directories, disabled
> authentication, and non-local profiles do not receive it. Catalog edits
> invalidate this default assignment until restart; they never silently turn an
> unassigned protected read into passthrough. See ADR 0029.

MinIO retired its free Docker distribution, leaving self-hosters who used
`docker run minio/minio` without an obvious drop-in replacement. Maskura already
shipped the durable local `FileStore` (ADR 0012) and local staged multipart
(ADR 0013), but reaching them required five explicit environment variables and
the default read path returned `501 NotImplemented` until
`MASKURA_STREAMING_READ_MODE=passthrough` was set. A bare `docker run` of the
published image failed at startup.

## Decision

When no hosted or external storage configuration is present, the gateway boots
as a zero-config local S3 appliance instead of failing startup.

- **Auto-local trigger.** The appliance activates only when none of
  `MASKURA_SERVICE_BUCKETS`, `S3_ENDPOINT`, `DATABASE_URL`,
  `MASKURA_STORAGE_MODE`, `MASKURA_LOCAL_STORAGE_DIR`, or `MASKURA_SINGLE_TENANT`
  is set. Any explicit deployment signal opts out, so a cloud or hosted
  deployment can never silently degrade into a local store.
- **Defaults.** Local durable storage under `/data`, staged multipart, and
  passthrough reads, listening on `9000` (the MinIO convention). Hosted and
  explicit deployments keep the historical `8080` default.
- **Byte preservation.** The Wasm pipeline is disabled (an explicit
  pass-through), so uploaded bytes are stored and returned unchanged. PII
  redaction and encryption remain available but opt-in, reversing the previous
  "self-cleaning store" default.
- **Read identity and isolation.** The server establishes a named, fingerprinted
  local default read assignment. It is not selected by a request, cannot read a
  presigned or other external backend, and becomes invalid when the plugin
  catalog is changed. Configured pipelines retain their own resolution rules.
- **Root credential.** A SigV4 root principal is bootstrapped on first start:
  `MASKURA_ROOT_USER`/`MASKURA_ROOT_PASSWORD` override it (both must be set
  together), otherwise a strong pair is generated, persisted inside the data
  volume, and printed once. Auth is not bypassed: requests must still sign with
  the root credential.
- **Canonical bucket.** A `maskura` bucket is created on first initialization
  so the first `aws s3 cp s3://maskura/...` works without a prior `mb`.
- **S3 semantics.** Buckets are explicit: `PutObject` to a missing bucket
  returns `NoSuchBucket`; `CreateBucket` on an existing bucket returns
  `BucketAlreadyExists`; `DeleteBucket` on a missing bucket returns
  `NoSuchBucket`.
- **Fail-closed dispatch.** Recognized-but-unsupported S3 subresources
  (`?tagging`, `?policy`, `?acl`, …) and
  `x-amz-copy-source` (CopyObject/UploadPartCopy) return `501 NotImplemented`
  before method/path dispatch, so they can never be misrouted into a destructive
  operation.
  ADR 0030 adds guarded batch delete; ADR 0035 adds guarded local versioning
  dispatch while keeping other destinations unsupported.
- **Readiness.** A `/ready` endpoint and an OCI `HEALTHCHECK` are added so
  Compose can gate on readiness, not just liveness.

## Consequences

- `docker run -p 127.0.0.1:9000:9000 -v maskura-data:/data
  ghcr.io/231self/maskura/maskura:latest` yields a working single-node S3
  endpoint with no further configuration.
- The generated root secret is disclosed once in first-start container output.
  This is a deliberate, documented exception to the "never log secrets" rule,
  scoped to local-appliance initialization; later starts reuse the persisted
  credential silently.
- The appliance is single-node and byte-preserving; it is not a claim of full
  AWS S3 or historical MinIO feature parity. Local versioning is added by
  [ADR 0035](0035-proposed-filestore-object-versioning.md), with packaged
  qualification pending. ACLs, policies,
  tagging, lifecycle, and copy remain unsupported and fail closed.
