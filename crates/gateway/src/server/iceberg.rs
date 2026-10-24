//! HTTP dispatch glue for the Iceberg table-format adapter (ADR 0028).
//!
//! The dispatch points in [`s3_upload`] and [`s3_objects`] consult this
//! module before any per-object format dispatch: a processed request that
//! could touch a table unit must be classified against the *stored* table
//! layout first, because a per-object transform of one data file or one
//! manifest is exactly the half-transformed table state the adapter forbids.
//!
//! Surface (maskura table unit semantics, ADR 0028 §3/§7):
//!
//! - **table-root processed write** — a single `PutObject` whose key is a
//!   table metadata document (`<root>/metadata/<version>-*.metadata.json`).
//!   The body is the source table state; the gateway transforms every data
//!   file of every retained snapshot and commits a new snapshot with one
//!   atomic `version-hint` swap. Gate closed (default): 501 before the body
//!   is read, nothing stored.
//! - **table-root processed read** — a processed `GetObject` of the current
//!   table metadata document: complete-output staging of the transformed
//!   table state (a preview; nothing is stored), never a raw fallback.
//!   `Range` and `partNumber` are rejected before any walk.
//! - **everything smaller** — a processed operation on a manifest layer, the
//!   version pointer, or a data file inside a table root fails closed with
//!   the named `unsupported.table_operation` error, **whether or not the
//!   feature gate is open** (the gate governs table-root processing only).
//! - **raw per-object GET/HEAD/byte-range** — untouched *unprocessed*
//!   passthrough over the stored representation (this module never runs).
//! - **multipart** — table operations are single-object only in v1;
//!   multipart create/completion of table-unit keys fails closed.

use axum::http::header;
use maskura_error::{MaskuraError, codes};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::*;
use crate::iceberg::detect::{self, ContentRole, TableTarget};
use crate::iceberg::metadata::{self, TableRoot};
use crate::iceberg::store::{BackendTableStore, FileTableStore, MemoryTableStore, S3TableStore};
use crate::iceberg::walker::{self, TableOperation, WalkLimits};
use crate::iceberg::{UnsupportedDataFileTransform, key_shape, merge_table_signals};
use crate::transaction::StoredObjectMeta;

pub(crate) fn content_type_of(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
}

/// Cheap, body-free signal check: could this request touch a table unit?
fn is_candidate(key: &str, content_type: Option<&str>) -> bool {
    key_shape(key).is_table_candidate() || detect::claims_table_media_type(content_type)
}

/// The request's bucket-scoped table store, or `None` for backends without
/// direct object IO (managed storage, presigned proxies).
fn table_store(backend: &ResolvedBackend, bucket: &str) -> Option<BackendTableStore> {
    match backend {
        ResolvedBackend::File(store) => Some(BackendTableStore::File(FileTableStore::new(
            store.clone(),
            bucket.to_string(),
        ))),
        ResolvedBackend::Memory(store) => Some(BackendTableStore::Memory(MemoryTableStore::new(
            store.clone(),
            bucket.to_string(),
        ))),
        ResolvedBackend::S3 { client, .. } => Some(BackendTableStore::S3(S3TableStore::new(
            client.clone(),
            bucket.to_string(),
        ))),
        ResolvedBackend::Managed(_) | ResolvedBackend::PresignedHttp(_) => None,
    }
}

fn backend_unsupported() -> MaskuraError {
    MaskuraError::new(
        codes::UNSUPPORTED_TABLE_OPERATION,
        "Iceberg table operations require a backend with direct object IO (file, memory, or S3); managed and presigned backends fail closed",
    )
}

/// Classifies a processed request against the stored table layout.
///
/// Returns `Ok(None)` when the request is not table-related and the normal
/// per-object dispatch should proceed.
async fn classify(
    store: Option<&BackendTableStore>,
    bucket: &str,
    key: &str,
    claims_table: bool,
) -> Result<Option<TableTarget>, MaskuraError> {
    let shape = key_shape(key);
    let Some(store) = store else {
        // Without object IO the layout cannot be probed. A root-document name
        // is still an unambiguous table unit and fails closed; anything else
        // is left to the normal dispatch.
        if shape.metadata_json_name {
            return Err(backend_unsupported());
        }
        return Ok(None);
    };
    let target = detect::classify_key(store, bucket, key, claims_table).await?;
    Ok(match target {
        TableTarget::None => None,
        target => Some(target),
    })
}

fn walk_limits(state: &AppState) -> WalkLimits {
    // Both caps are clamped to 64 MiB before the width cast, so the value
    // fits `usize` on every supported target.
    WalkLimits {
        max_source_bytes: state.source_body_limits.max_bytes.min(64 * 1024 * 1024) as usize,
        max_output_bytes: state.max_pipeline_output_bytes.min(64 * 1024 * 1024) as usize,
        max_objects: 10_000,
    }
}

/// The request-body cap as `usize` (saturating on narrow targets).
fn max_body_bytes(state: &AppState) -> usize {
    usize::try_from(state.source_body_limits.max_bytes).unwrap_or(usize::MAX)
}

fn gate_closed_write(key: &str) -> StreamingPutError {
    StreamingPutError::Unsupported(format!(
        "Iceberg processing is disabled for {key}; set MASKURA_ENABLE_ICEBERG=true"
    ))
}

fn table_operation_error(error: MaskuraError) -> StreamingPutError {
    StreamingPutError::Pipeline(error)
}

/// Table dispatch for a single `PutObject`.
///
/// Returns `None` when the request is not table-related; the caller then
/// runs the normal per-object dispatch. Ordering is deliberate and
/// gate-independent where the ADR's matrix rows demand it:
///
/// 1. a processed write to a strict sub-unit of a stored table root fails
///    closed with `unsupported.table_operation` whether or not the table
///    surface is enabled (the named partial-operation row);
/// 2. only a table-root write consults `MASKURA_ENABLE_ICEBERG`, and with the
///    gate closed it rejects 501 before a single body byte is polled;
/// 3. the `body` is read only once the gate is confirmed open.
pub(crate) async fn streaming_iceberg_single_put(
    state: &AppState,
    authentication: &mut Option<HeaderAuthentication>,
    backend: &ResolvedBackend,
    usage: AuthorizedUsage<'_>,
    headers: &HeaderMap,
    body: &mut axum::body::Body,
    key: &str,
) -> Option<
    Result<
        (
            Auth,
            StoredObjectMeta,
            u64,
            u64,
            Option<crate::control::PipelineEvidence>,
        ),
        StreamingPutError,
    >,
> {
    if !is_candidate(key, content_type_of(headers)) {
        return None;
    }
    let bucket = usage.grant.bucket().to_string();
    let store = table_store(backend, &bucket);
    let target = match classify(store.as_ref(), &bucket, key, claims_table(headers)).await {
        Ok(Some(TableTarget::RootMetadata { root, version })) => (root, version),
        Ok(Some(TableTarget::SubUnit { .. })) => {
            return Some(Err(table_operation_error(sub_unit_error(key))));
        }
        Ok(None | Some(TableTarget::None)) => return None,
        Err(error) => return Some(Err(table_operation_error(error))),
    };
    if !state.binary_iceberg_enabled {
        return Some(Err(gate_closed_write(key)));
    }
    let (root, version) = target;
    let store = store.expect("root classification requires a store");

    // The gate is open and this is the table root document: read the body
    // (with the usual integrity verification), then run the table operation.
    let limits = walk_limits(state);
    let (auth, body_bytes) = match read_verified_body(
        authentication
            .take()
            .expect("the table dispatch consumes authentication exactly once"),
        std::mem::take(body),
        max_body_bytes(state),
    )
    .await
    {
        Ok(result) => result,
        Err(VerifiedBodyError::TooLarge) => {
            return Some(Err(StreamingPutError::InputTooLarge));
        }
        Err(VerifiedBodyError::Transport) => return Some(Err(StreamingPutError::Transport)),
        Err(VerifiedBodyError::Integrity(error)) => {
            return Some(Err(StreamingPutError::Integrity(error)));
        }
    };

    let outcome = table_root_put(&auth, &store, &root, version, key, &body_bytes, limits).await;
    match outcome {
        Ok((meta, output_bytes)) => {
            let source_bytes = body_bytes.len() as u64;
            Some(Ok((auth, meta, source_bytes, output_bytes, None)))
        }
        Err(error) => Some(Err(StreamingPutError::Pipeline(error))),
    }
}

/// The table-root processed write: validate the request document against the
/// current committed state, walk the whole table, and commit.
async fn table_root_put(
    _auth: &Auth,
    store: &BackendTableStore,
    root: &TableRoot,
    version: u64,
    key: &str,
    body_bytes: &[u8],
    limits: WalkLimits,
) -> Result<(StoredObjectMeta, u64), MaskuraError> {
    let document = metadata::parse_json_document(body_bytes, limits.max_source_bytes)?;
    let content = if metadata::metadata_json_shape(&Value::Object(document.clone())) {
        ContentRole::TableMetadata
    } else {
        ContentRole::Other
    };
    merge_table_signals(
        &TableTarget::RootMetadata {
            root: root.clone(),
            version,
        },
        content,
    )?;

    let (base_version, source_key, source_document) =
        walker::current_metadata(store, root, limits).await?;
    if version != base_version + 1 {
        return Err(metadata::unsupported_table_operation(format!(
            "table metadata version {version} does not follow the current version {base_version}"
        )));
    }
    // Compare-and-swap: the request body must be the state the walk
    // transforms — never a stale or foreign document.
    if source_document != document {
        return Err(metadata::unsupported_table_operation(
            "the request body is not the current table state; the commit is refused",
        ));
    }

    let token = uuid::Uuid::now_v7().simple().to_string();
    let operation = TableOperation {
        root,
        source_metadata: &document,
        source_metadata_key: &source_key,
        base_version,
        new_version: version,
        new_metadata_key: key,
        token: &token,
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    };
    let outcome =
        walker::walk_and_prepare(store, &mut UnsupportedDataFileTransform, &operation, limits)
            .await?;
    let output_bytes: u64 = outcome
        .object_writes
        .iter()
        .map(|write| write.bytes.len() as u64)
        .sum();
    let metadata_digest = hex::encode(Sha256::digest(
        outcome
            .object_writes
            .iter()
            .find(|write| write.key == key)
            .map(|write| write.bytes.as_slice())
            .unwrap_or_default(),
    ));
    let report = walker::commit(store, root, outcome, limits).await?;
    if !report.cleanup_failures.is_empty() {
        tracing::warn!(
            snapshot_id = report.new_snapshot_id,
            pending = report.cleanup_failures.len(),
            "iceberg commit cleanup incomplete; replaced plaintext objects remain as orphans"
        );
    }
    Ok((
        StoredObjectMeta {
            etag: Some(format!("\"{metadata_digest}\"")),
            version_id: None,
            superseded_version_ids: Vec::new(),
            version_history_complete: true,
        },
        output_bytes,
    ))
}

fn claims_table(headers: &HeaderMap) -> bool {
    detect::claims_table_media_type(content_type_of(headers))
}

fn sub_unit_error(key: &str) -> MaskuraError {
    metadata::unsupported_table_operation(format!(
        "processed operations on {key:?} are not supported: it is a strict sub-unit of a table root; process the table root instead (unsupported.table_operation)"
    ))
}

/// Table dispatch for a processed `GetObject`.
///
/// Returns `None` when the request is not table-related (the normal dispatch
/// proceeds). Failures never fall back to the raw stored bytes. As on the
/// write side, a processed read of a strict sub-unit fails closed with
/// `unsupported.table_operation` before the feature gate is consulted.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn iceberg_transformed_read_response(
    state: &AppState,
    auth: &Auth,
    headers: &HeaderMap,
    params: &S3Query,
    _metadata_headers: &HeaderMap,
    backend: &ResolvedBackend,
    bucket: &str,
    key: &str,
) -> Option<(axum::response::Response, Option<u64>)> {
    if !is_candidate(key, content_type_of(headers)) {
        return None;
    }
    let store = table_store(backend, bucket);
    let (root, version) = match classify(store.as_ref(), bucket, key, claims_table(headers)).await {
        Ok(Some(TableTarget::RootMetadata { root, version })) => (root, version),
        Ok(Some(TableTarget::SubUnit { .. })) => {
            return Some((
                transformed_read_error_response(
                    key,
                    TransformedReadError::Pipeline(sub_unit_error(key)),
                ),
                None,
            ));
        }
        Ok(None | Some(TableTarget::None)) => return None,
        Err(error) => {
            return Some((
                transformed_read_error_response(key, TransformedReadError::Pipeline(error)),
                None,
            ));
        }
    };
    if !state.binary_iceberg_enabled {
        return Some((
            transformed_read_error_response(
                key,
                TransformedReadError::InvalidRequest(
                    "Iceberg processing is disabled; set MASKURA_ENABLE_ICEBERG=true".to_string(),
                ),
            ),
            None,
        ));
    }
    let store = store.expect("root classification requires a store");

    // Range / part-number / content-encoding are rejected before any walk,
    // exactly like the other binary adapters' processed reads.
    if headers.contains_key(header::RANGE) {
        return Some((
            transformed_read_error_response(
                key,
                TransformedReadError::InvalidRequest(
                    "Range is not supported for transformed reads".to_string(),
                ),
            ),
            None,
        ));
    }
    if params.part_number.is_some() {
        return Some((
            transformed_read_error_response(
                key,
                TransformedReadError::InvalidRequest(
                    "part-number reads are not supported for transformed reads".to_string(),
                ),
            ),
            None,
        ));
    }
    // Complete-output staging is mandatory; without the encrypted spool the
    // processed read fails closed — never a raw fallback.
    if !state.transformed_read_spool_enabled {
        return Some((
            transformed_read_error_response(
                key,
                TransformedReadError::Capacity(
                    "unsafe transformed reads require MASKURA_TRANSFORMED_READ_SPOOL=encrypted"
                        .to_string(),
                ),
            ),
            None,
        ));
    }

    match table_root_read(&store, &root, version, key, walk_limits(state)).await {
        Ok((output, content_type)) => {
            let cancellation = maskura_wasm_runtime::CancellationToken::new();
            match serve_spooled_bytes(state, output, cancellation).await {
                Ok((body, content_length)) => {
                    let mut response = axum::response::Response::builder().status(StatusCode::OK);
                    response.headers_mut().expect("headers").insert(
                        "x-maskura-iceberg-preview",
                        header::HeaderValue::from_static("1"),
                    );
                    if let Ok(value) = content_type.parse() {
                        response
                            .headers_mut()
                            .expect("headers")
                            .insert(header::CONTENT_TYPE, value);
                    }
                    if let Ok(value) = content_length.to_string().parse() {
                        response
                            .headers_mut()
                            .expect("headers")
                            .insert(header::CONTENT_LENGTH, value);
                    }
                    harden_object_response_headers(response.headers_mut().expect("headers"));
                    let _ = auth;
                    Some((response.body(body).expect("body"), None))
                }
                Err(error) => Some((transformed_read_error_response(key, error), None)),
            }
        }
        Err(error) => Some((
            transformed_read_error_response(key, TransformedReadError::Pipeline(error)),
            None,
        )),
    }
}

/// The table-root processed read: a complete-output preview of the transform
/// (the metadata document that a commit would produce), with nothing stored.
async fn table_root_read(
    store: &BackendTableStore,
    root: &TableRoot,
    version: u64,
    key: &str,
    limits: WalkLimits,
) -> Result<(Vec<u8>, String), MaskuraError> {
    let (base_version, source_key, source_document) =
        walker::current_metadata(store, root, limits).await?;
    if version != base_version {
        return Err(metadata::unsupported_table_operation(format!(
            "processed table reads address the current table state (version {base_version}), not version {version}"
        )));
    }
    let content = if metadata::metadata_json_shape(&Value::Object(source_document.clone())) {
        ContentRole::TableMetadata
    } else {
        ContentRole::Other
    };
    merge_table_signals(
        &TableTarget::RootMetadata {
            root: root.clone(),
            version,
        },
        content,
    )?;

    let token = uuid::Uuid::now_v7().simple().to_string();
    let operation = TableOperation {
        root,
        source_metadata: &source_document,
        source_metadata_key: &source_key,
        base_version,
        new_version: base_version + 1,
        new_metadata_key: key,
        token: &token,
        timestamp_ms: chrono::Utc::now().timestamp_millis(),
    };
    // The production data-file seam is the fail-closed stub: a table with
    // data files cannot be previewed until the Parquet codec (ADR 0027) is
    // wired. The walk's metadata machinery runs fully for tables without
    // data files.
    let outcome =
        walker::walk_and_prepare(store, &mut UnsupportedDataFileTransform, &operation, limits)
            .await?;
    let output = walker::preview_document(&outcome);
    Ok((output, metadata::METADATA_CONTENT_TYPE.to_string()))
}

/// Multipart create/completion rejection for table-unit keys.
///
/// Table operations are single-object `PutObject`s in v1; a multipart upload
/// of a table unit cannot produce a consistent table state and fails closed
/// before staging or publishing anything. The rejection is independent of the
/// feature gate: a table unit must not fall through to per-object processing
/// whether or not the table surface is enabled.
pub(crate) async fn multipart_table_rejection(
    _state: &AppState,
    backend: &ResolvedBackend,
    bucket: &str,
    key: &str,
    content_type: Option<&str>,
) -> Option<MaskuraError> {
    if !is_candidate(key, content_type) {
        return None;
    }
    let store = table_store(backend, bucket);
    // Classification failures (Delta/Hive layouts, conflicting signals) are
    // themselves fail-closed rejections: a table unit must never fall through
    // to per-object processing on a detection error.
    let target = match classify(
        store.as_ref(),
        bucket,
        key,
        detect::claims_table_media_type(content_type),
    )
    .await
    {
        Ok(target) => target,
        Err(error) => return Some(error),
    };
    match target {
        Some(TableTarget::RootMetadata { .. }) | Some(TableTarget::SubUnit { .. }) => {
            Some(metadata::unsupported_table_operation(
                "multipart uploads are not supported for Iceberg table operations; use a single-object PutObject",
            ))
        }
        _ => None,
    }
}
