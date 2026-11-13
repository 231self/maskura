# S3 data-plane compatibility

Maskura's zero-config Docker image is a single-node S3-compatible endpoint
intended as a local MinIO replacement. This page lists the S3 **data-plane**
operations it implements and points at the test that covers each one.

It covers data-plane verbs and the local versioning extension below. Other bucket subresources —
ACLs, policies, tagging, lifecycle, notifications, object lock, and the rest —
are out of scope and handled fail-closed; see [Limits](#limits) and
[ADR 0019](adr/0019-zero-config-local-s3-appliance.md).

Every `Supported` and `Local appliance only` row links to a test in this
repository, and the [How to run the evidence](#how-to-run-the-evidence) section
lists the exact commands. Treat this table as derived output: if the dispatch in
`crates/gateway/src/server.rs` or a cited test changes, update this page in the
same change.

## Status legend

| Status | Meaning |
|--------|---------|
| **Supported** | Implemented on the local appliance. |
| **Local appliance only** | Implemented for the durable local `FileStore`; on a configured workspace or backend the request returns `403 AccessDenied`. |
| **Not implemented** | Recognized and rejected before dispatch with `501 NotImplemented`, without touching state. |
| **Not routed** | No route exists for the request; it does not reach a handler. |

## FileStore versioning (v0.7.35)

The following ships in **v0.7.35 for Docker/FileStore only**. Both native Linux
images passed all 35 source-bound feedback cases before publication and again
against the published children, including four unmodified AWS CLI versioning
cases. See the [delivery evidence](plans/2026-11-13-filestore-versioning.md).

| Operation | Local appliance behavior | Evidence |
| --- | --- | --- |
| Get/PutBucketVersioning | Durable Enabled/Suspended; never-versioned reads return an empty configuration. Strict bounded XML rejects MFA Delete/unsupported fields. | [Protocol units](../crates/gateway/src/server/s3_versioning.rs), [HTTP and unmodified SDK restart tests](../crates/gateway/tests/s3_frontdoor_test/versioning.rs) |
| Versioned PUT and exact GET/HEAD | Retained versions and concrete IDs; exact reads preserve the selected metadata across restart. Existing protected read rules apply. | [Storage tests](../crates/gateway/src/file_store/versioning.rs), [HTTP/SDK tests](../crates/gateway/tests/s3_frontdoor_test/versioning.rs) |
| ListObjectVersions | Key order, newest-first versions/markers, prefix/delimiter, paired markers, max-keys and URL encoding. | [Protocol implementation/tests](../crates/gateway/src/server/s3_versioning.rs), [HTTP pages](../crates/gateway/tests/s3_frontdoor_test/versioning.rs) |
| DeleteObject/DeleteObjects | Ordinary DELETE creates markers in Enabled/Suspended buckets; explicit versions are permanently deleted. Multiple versions of one key may be batched. | [Lifecycle/batch tests](../crates/gateway/tests/s3_frontdoor_test/versioning.rs) |
| Versioned multipart | Publication uses bucket state at commit; recovery and replay retain the original version ID. | [Storage recovery](../crates/gateway/src/file_store/versioning.rs), [multipart restart/replay test](../crates/gateway/tests/local_filesystem_multipart.rs) |

These operations resolve the authenticated destination; non-FileStore destinations
return `501 NotImplemented` for version operations. Retained versions and markers
keep a bucket non-empty. Processed Iceberg exact-version table reads are unsupported.
There is no automatic history expiry, object lock or create-only write guarantee.

## Operations

| Operation | Request | Status | Evidence | Notes |
|-----------|---------|--------|----------|-------|
| ListBuckets | `GET /` | Supported | [`s3_frontdoor_test::list_buckets_at_root`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Browsers get the dashboard on the same path; S3 clients get the XML. |
| CreateBucket | `PUT /{bucket}` | Local appliance only | [`s3_frontdoor_test::filestore_conformance_bucket_object_lifecycle_survives_restart`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs), [`s3_frontdoor_test::create_bucket_is_rejected`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Existing bucket → `BucketAlreadyExists`; a configured backend → `403 AccessDenied`. |
| DeleteBucket | `DELETE /{bucket}` | Local appliance only | [`s3_frontdoor_test::filestore_conformance_bucket_object_lifecycle_survives_restart`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs), [`file_store::delete_and_bucket_lifecycle_require_empty_bucket`](https://github.com/231self/maskura/blob/main/crates/gateway/src/file_store.rs) | Empty bucket → `204`; non-empty → `409 BucketNotEmpty`; missing → `NoSuchBucket`. |
| HeadBucket | `HEAD /{bucket}` | Local appliance only | [`s3_frontdoor_test::filestore_list_and_head_on_missing_bucket_return_no_such_bucket`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Served by the `GET /{bucket}` route (body stripped). Missing bucket → `404 NoSuchBucket`, existing → `200`. |
| ListObjects (v1) | `GET /{bucket}` | Supported | [`s3_frontdoor_test::list_objects_returns_keys_and_prefixes`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs), [`s3_frontdoor_test::filestore_list_and_head_on_missing_bucket_return_no_such_bucket`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Prefix, delimiter, and pagination. Missing bucket → `NoSuchBucket`. |
| ListObjectsV2 | `GET /{bucket}?list-type=2` | Supported | [`s3_frontdoor_test::memory_list_continuations_are_opaque_bound_and_tamper_resistant`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs), [`s3_frontdoor_test::filestore_list_and_head_on_missing_bucket_return_no_such_bucket`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Opaque, bound continuation tokens; `continuation-token` requires `list-type=2`. Missing bucket → `NoSuchBucket`. |
| PutObject | `PUT /{bucket}/{key}` | Supported | [`s3_frontdoor_test::put_get_roundtrip_filters_pii`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs), [`s3_frontdoor_test::unmodified_rust_sdk_default_put_is_accepted`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | With no plugins configured, bytes are stored unchanged. |
| GetObject | `GET /{bucket}/{key}` | Supported | [`s3_frontdoor_test::streaming_memory_get_preserves_range_and_head_metadata`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs), [`s3_frontdoor_test::conditional_get_and_head_preserve_object_identity_without_a_body`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Supports `Range` and conditional request headers. |
| HeadObject | `HEAD /{bucket}/{key}` | Supported | [`s3_frontdoor_test::head_and_delete_remain_available`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Metadata only; no body. |
| DeleteObject | `DELETE /{bucket}/{key}` | Supported | [`s3_frontdoor_test::head_and_delete_remain_available`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Missing key → `404 NoSuchKey`. |
| CreateMultipartUpload | `POST /{bucket}/{key}?uploads` | Supported | [`s3_multipart_conformance::sdk_multipart_lifecycle_completes_over_real_tcp`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_multipart_conformance.rs) | Staged and durable; requires the local staged multipart store (enabled on the appliance). An absent initiation Content-Type defaults to `application/octet-stream`; part/completion transport headers do not replace the frozen representation type. |
| UploadPart | `PUT /{bucket}/{key}?partNumber&uploadId` | Supported | [`s3_multipart_conformance::sdk_multipart_lifecycle_completes_over_real_tcp`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_multipart_conformance.rs), [`local_filesystem_multipart::local_filesystem_multipart_lifecycle_over_http`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/local_filesystem_multipart.rs) | Parts persist across restart. |
| CompleteMultipartUpload | `POST /{bucket}/{key}?uploadId` | Supported | [`s3_multipart_conformance::http_conformance_completion_errors_pagination_helpers_and_replay`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_multipart_conformance.rs) | Completion replaces any existing single-PUT object atomically. |
| AbortMultipartUpload | `DELETE /{bucket}/{key}?uploadId` | Supported | [`s3_multipart_conformance::sdk_multipart_abort_list_uploads_and_no_such_upload`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_multipart_conformance.rs) | Unknown upload → `NoSuchUpload`. |
| ListParts | `GET /{bucket}/{key}?uploadId` | Supported | [`local_filesystem_multipart::local_filesystem_multipart_lifecycle_over_http`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/local_filesystem_multipart.rs) | Full part listing with pagination fields. |
| ListMultipartUploads | `GET /{bucket}?uploads` | Supported | [`s3_multipart_conformance::sdk_multipart_abort_list_uploads_and_no_such_upload`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_multipart_conformance.rs) | In-progress uploads for the bucket. |
| CopyObject | `PUT /{bucket}/{key}` + `x-amz-copy-source` | Not implemented | [`s3_protocol::s3_not_implemented_returns_501`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_protocol.rs), [`crates/gateway/src/server.rs`](https://github.com/231self/maskura/blob/main/crates/gateway/src/server.rs) (`x-amz-copy-source` pre-dispatch gate) | Rejected before the body is polled. |
| UploadPartCopy | `PUT ?partNumber&uploadId` + `x-amz-copy-source` | Not implemented | [`crates/gateway/src/server.rs`](https://github.com/231self/maskura/blob/main/crates/gateway/src/server.rs) (`s3_upload_part` copy-source check) | Rejected before any part is stored. |
| DeleteObjects (batch) | `POST /{bucket}?delete` | Supported | [`s3_frontdoor_test::filestore_batch_delete_answers_every_key_and_is_idempotent`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/batch_delete.rs) | Per-key `<Deleted>`/`<Error>` (N gated deletes, one usage receipt per key); ≤1000 keys / 128 KiB; `Quiet` supported; missing unversioned key → `<Deleted>`. Malformed, oversized or invalid Content-MD5 requests fail before mutation. The local extension above accepts `VersionId`; ordinary versioned retries create additional markers. |
| SelectObjectContent | `POST /{bucket}/{key}?select` | Not implemented | [`s3_protocol::s3_not_implemented_returns_501`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_protocol.rs), [`crates/gateway/src/server.rs`](https://github.com/231self/maskura/blob/main/crates/gateway/src/server.rs) (`select` subresource gate) | Rejected before dispatch. |

## Object metadata

Customer `x-amz-meta-*` values are retained on ordinary PUT and multipart
publication across memory, FileStore, direct S3, and managed storage. FileStore
persists them across reopen. Representation headers and customer names use
separate internal namespaces; provider-reserved transaction names are rejected
before acquiring a write sink. Decoded `aws-chunked` transport framing is not a
stored representation encoding.

Protected/transformed GETs deliberately withhold custom metadata: metadata is
outside the transformed-body protection boundary. There is no request-header
bypass to retrieve an unprotected representation. Historical ambiguous metadata
cannot be reconstructed after it has already been lost; see
[ADR 0013](adr/0013-durable-local-multipart-storage.md) and
[ADR 0018](adr/0018-atomic-managed-write-finalization-and-recovery.md) for the
snapshot and recovery contracts.
The local versioning extension preserves the selected source's
`x-amz-version-id` on successful transformed GETs; it does not restore stored
ETags/checksums, custom metadata, ranges or protected HEAD support.

## How to run the evidence

The Rust suites that back the table:

```bash
cargo test -p maskura-gateway --test s3_frontdoor_test
cargo test -p maskura-gateway --test s3_multipart_conformance
cargo test -p maskura-gateway --test local_filesystem_multipart
cargo test -p maskura-gateway --test s3_protocol
cargo test -p maskura-gateway file_store::
```

Unmodified AWS CLI and boto3 interoperability (requires `aws` and `boto3` on
`PATH`):

```bash
just interop
```

The published container is proven black-box (including the AWS CLI round trip)
by `just proof`; see [Run the claims](proofs.md).

## Limits

Non-FileStore versioning, create-only writes and access-policy gaps are tracked
in [Known S3 compatibility gaps](known-gaps.md). Versioning is limited to Docker/FileStore.

The appliance is a single-node, byte-preserving local store, not a claim of full
AWS S3 or historical MinIO feature parity. With no plugins configured (the
default), uploaded bytes are stored and returned unchanged, including arbitrary
binary objects. The Wasm transform pipeline (PII redaction, encryption) remains
opt-in and applies to record-oriented formats (text, JSON, JSONL, CSV, TSV).

Other bucket subresources — ACLs, bucket and
object tagging, policies, lifecycle, encryption config, website, CORS,
replication, object-lock, legal-hold, notifications, logging, request-payment —
are recognized and rejected with `501 NotImplemented` before method/path
dispatch, so they can never be misrouted into a destructive operation. See
[ADR 0019](adr/0019-zero-config-local-s3-appliance.md).
