# ADR 0012: Local filesystem object storage

- Status: Accepted
- Date: 2026-09-08

## Context

Maskura exposes an S3-compatible data plane but previously needed either an
external S3-compatible service (commonly MinIO), a cloud bucket, or the
development-only in-memory store. A self-hosted deployment could not persist
objects with only the gateway container and a mounted volume.

The local backend must preserve the write pipeline's all-or-nothing visibility:

## Decision

Add `FileStore`, enabled for explicit single-tenant deployments by
`MASKURA_LOCAL_STORAGE_DIR`.

- Object content is written as a unique temp file, fsynced, and renamed to a
  version-named data file.
- A per-key metadata JSON file atomically points to that data file. Renaming the
  metadata is the visibility commit, so readers observe the old complete object
  or the new complete object.
- Keys are hashed for on-disk metadata lookup, avoiding path traversal and the
  `foo` versus `foo/bar` namespace collision. Metadata retains the original key,
  content type, MD5 S3 ETag, and size.
- `FileSinkTransaction` streams transformed output to disk and commits through
  `FileStore`; single PUT does not use an operation journal because local rename
  gives crash-safe atomic object visibility.
- FileStore supports core bucket and object operations. Durable multipart is a
  separate persistence and recovery architecture defined by
  [ADR 0013](0013-durable-local-multipart-storage.md); it remains unavailable
  until that implementation's gates pass.

## Consequences

- A gateway can be a standalone local S3 endpoint with a mounted volume and no
  MinIO, Postgres, or cloud credentials.
- This is a single-node backend. It has no replication, versioning, lifecycle
  rules, or bucket IAM. ADR 0013 adds an exclusive process lock and defines
  future multipart support without changing the single-node boundary.
- Orphaned temp files are removed at FileStore startup. A crash after a data-file
  rename but before its metadata commit can leave unreferenced data, but cannot
  make a partial object visible.

## Alternatives considered

- Keep MinIO mandatory for durable local mode: rejected because it adds an
  unnecessary service and undermines standalone deployment.
- Store object bytes in Postgres: rejected because object data does not belong
  in the relational control plane and scales poorly for large bodies.
- Use filesystem extended attributes for metadata: rejected because they are not
  portable across Docker host filesystems. JSON metadata is portable and
  inspectable.
