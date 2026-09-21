# S3 data-plane compatibility

Maskura's zero-config Docker image is a single-node S3-compatible endpoint
intended as a local MinIO replacement. This page lists the S3 **data-plane**
operations it implements and points at the test that covers each one.

It intentionally covers data-plane verbs only. Bucket subresources — versioning,
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

## Operations

| Operation | Request | Status | Evidence | Notes |
|-----------|---------|--------|----------|-------|
| ListBuckets | `GET /` | Supported | [`s3_frontdoor_test::list_buckets_at_root`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Browsers get the dashboard on the same path; S3 clients get the XML. |
| CreateBucket | `PUT /{bucket}` | Local appliance only | [`s3_frontdoor_test::filestore_conformance_bucket_object_lifecycle_survives_restart`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs), [`s3_frontdoor_test::create_bucket_is_rejected`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Existing bucket → `BucketAlreadyExists`; a configured backend → `403 AccessDenied`. |
| DeleteBucket | `DELETE /{bucket}` | Local appliance only | [`s3_frontdoor_test::filestore_conformance_bucket_object_lifecycle_survives_restart`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs), [`file_store::delete_and_bucket_lifecycle_require_empty_bucket`](https://github.com/231self/maskura/blob/main/crates/gateway/src/file_store.rs) | Empty bucket → `204`; non-empty → `409 BucketNotEmpty`; missing → `NoSuchBucket`. |
| HeadBucket | `HEAD /{bucket}` | Not routed | [`crates/gateway/src/server.rs`](https://github.com/231self/maskura/blob/main/crates/gateway/src/server.rs) (router: no `HEAD /{bucket}`) | Returns `405 Method Not Allowed`. |
| ListObjects (v1) | `GET /{bucket}` | Supported | [`s3_frontdoor_test::list_objects_returns_keys_and_prefixes`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Prefix, delimiter, and pagination. |
| ListObjectsV2 | `GET /{bucket}?list-type=2` | Supported | [`s3_frontdoor_test::memory_list_continuations_are_opaque_bound_and_tamper_resistant`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Opaque, bound continuation tokens; `continuation-token` requires `list-type=2`. |
| PutObject | `PUT /{bucket}/{key}` | Supported | [`s3_frontdoor_test::put_get_roundtrip_filters_pii`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs), [`s3_frontdoor_test::unmodified_rust_sdk_default_put_is_accepted`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | With no plugins configured, bytes are stored unchanged. |
| GetObject | `GET /{bucket}/{key}` | Supported | [`s3_frontdoor_test::streaming_memory_get_preserves_range_and_head_metadata`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs), [`s3_frontdoor_test::conditional_get_and_head_preserve_object_identity_without_a_body`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Supports `Range` and conditional request headers. |
| HeadObject | `HEAD /{bucket}/{key}` | Supported | [`s3_frontdoor_test::head_and_delete_remain_available`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Metadata only; no body. |
| DeleteObject | `DELETE /{bucket}/{key}` | Supported | [`s3_frontdoor_test::head_and_delete_remain_available`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_frontdoor_test/main.rs) | Missing key → `404 NoSuchKey`. |
| CreateMultipartUpload | `POST /{bucket}/{key}?uploads` | Supported | [`s3_multipart_conformance::sdk_multipart_lifecycle_completes_over_real_tcp`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_multipart_conformance.rs) | Staged and durable; requires the local staged multipart store (enabled on the appliance). |
| UploadPart | `PUT /{bucket}/{key}?partNumber&uploadId` | Supported | [`s3_multipart_conformance::sdk_multipart_lifecycle_completes_over_real_tcp`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_multipart_conformance.rs), [`local_filesystem_multipart::local_filesystem_multipart_lifecycle_over_http`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/local_filesystem_multipart.rs) | Parts persist across restart. |
| CompleteMultipartUpload | `POST /{bucket}/{key}?uploadId` | Supported | [`s3_multipart_conformance::http_conformance_completion_errors_pagination_helpers_and_replay`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_multipart_conformance.rs) | Completion replaces any existing single-PUT object atomically. |
| AbortMultipartUpload | `DELETE /{bucket}/{key}?uploadId` | Supported | [`s3_multipart_conformance::sdk_multipart_abort_list_uploads_and_no_such_upload`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_multipart_conformance.rs) | Unknown upload → `NoSuchUpload`. |
| ListParts | `GET /{bucket}/{key}?uploadId` | Supported | [`local_filesystem_multipart::local_filesystem_multipart_lifecycle_over_http`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/local_filesystem_multipart.rs) | Full part listing with pagination fields. |
| ListMultipartUploads | `GET /{bucket}?uploads` | Supported | [`s3_multipart_conformance::sdk_multipart_abort_list_uploads_and_no_such_upload`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_multipart_conformance.rs) | In-progress uploads for the bucket. |
| CopyObject | `PUT /{bucket}/{key}` + `x-amz-copy-source` | Not implemented | [`s3_protocol::s3_not_implemented_returns_501`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_protocol.rs), [`crates/gateway/src/server.rs`](https://github.com/231self/maskura/blob/main/crates/gateway/src/server.rs) (`x-amz-copy-source` pre-dispatch gate) | Rejected before the body is polled. |
| UploadPartCopy | `PUT ?partNumber&uploadId` + `x-amz-copy-source` | Not implemented | [`crates/gateway/src/server.rs`](https://github.com/231self/maskura/blob/main/crates/gateway/src/server.rs) (`s3_upload_part` copy-source check) | Rejected before any part is stored. |
| DeleteObjects (batch) | `POST /{bucket}?delete` | Not routed | [`crates/gateway/src/server.rs`](https://github.com/231self/maskura/blob/main/crates/gateway/src/server.rs) (no `POST /{bucket}` route; `delete` is a gated subresource) | Returns `405 Method Not Allowed`. |
| SelectObjectContent | `POST /{bucket}/{key}?select` | Not implemented | [`s3_protocol::s3_not_implemented_returns_501`](https://github.com/231self/maskura/blob/main/crates/gateway/tests/s3_protocol.rs), [`crates/gateway/src/server.rs`](https://github.com/231self/maskura/blob/main/crates/gateway/src/server.rs) (`select` subresource gate) | Rejected before dispatch. |

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

The appliance is a single-node, byte-preserving local store, not a claim of full
AWS S3 or historical MinIO feature parity. With no plugins configured (the
default), uploaded bytes are stored and returned unchanged, including arbitrary
binary objects. The Wasm transform pipeline (PII redaction, encryption) remains
opt-in and applies to record-oriented formats (text, JSON, JSONL, CSV, TSV).

Bucket subresources that are not data-plane verbs — versioning, ACLs, bucket and
object tagging, policies, lifecycle, encryption config, website, CORS,
replication, object-lock, legal-hold, notifications, logging, request-payment —
are recognized and rejected with `501 NotImplemented` before method/path
dispatch, so they can never be misrouted into a destructive operation. See
[ADR 0019](adr/0019-zero-config-local-s3-appliance.md).
