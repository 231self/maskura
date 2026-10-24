//! Table metadata JSON: validation, typed views, and rewrite mechanics.
//!
//! The metadata document is the root of the Iceberg metadata tree (ADR 0028):
//! `metadata JSON → snapshot → manifest list → manifests → data files`. The
//! rewrite path manipulates the document as a [`serde_json::Value`] so fields
//! this layer does not model (and fields added by future format versions) are
//! carried through verbatim instead of being reinterpreted.

use maskura_error::{MaskuraError, codes};
use serde_json::{Map, Value, json};

/// The table root as a bucket + key prefix (always `/`-terminated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableRoot {
    pub bucket: String,
    pub prefix: String,
}

impl TableRoot {
    /// Joins a table-relative object name onto the root prefix.
    pub fn key(&self, relative: &str) -> String {
        format!("{}{}", self.prefix, relative)
    }

    /// Maps a table-file URI (`s3://bucket/<key>`) onto a store key under this
    /// root.
    ///
    /// v1 accepts only S3-style URIs naming the request's own bucket, and only
    /// keys under the table root (the root's own key — the metadata `location`
    /// — counts as inside). Anything else — foreign buckets, other schemes,
    /// keys escaping the root — fails closed: the walk never guesses where a
    /// referenced file lives.
    pub fn key_from_uri(&self, uri: &str) -> Result<String, MaskuraError> {
        let (bucket, key) = split_s3_uri(uri).ok_or_else(|| {
            unsupported_table_operation(format!(
                "table file URI {uri:?} is not an s3:// URI in bucket {:?}",
                self.bucket
            ))
        })?;
        let root_stem = self.prefix.trim_end_matches('/');
        let inside = key == root_stem || key.starts_with(&self.prefix) || self.prefix.is_empty();
        if bucket != self.bucket || !inside {
            return Err(unsupported_table_operation(format!(
                "table file URI {uri:?} escapes the table root {}/{:?}",
                self.bucket, self.prefix
            )));
        }
        Ok(key)
    }
}

/// Splits `s3://`, `s3a://`, or `s3n://` URIs into `(bucket, key)`.
pub fn split_s3_uri(uri: &str) -> Option<(String, String)> {
    let rest = uri
        .strip_prefix("s3://")
        .or_else(|| uri.strip_prefix("s3a://"))
        .or_else(|| uri.strip_prefix("s3n://"))?;
    let (bucket, key) = rest.split_once('/')?;
    if bucket.is_empty() || key.is_empty() {
        return None;
    }
    Some((bucket.to_string(), key.to_string()))
}

/// Builds the canonical `s3://` URI for a store key in `bucket`.
pub fn s3_uri(bucket: &str, key: &str) -> String {
    format!("s3://{bucket}/{key}")
}

pub(crate) fn unsupported_table_operation(message: impl Into<String>) -> MaskuraError {
    MaskuraError::new(codes::UNSUPPORTED_TABLE_OPERATION, message.into())
}

pub(crate) fn unsupported_format(message: impl Into<String>) -> MaskuraError {
    MaskuraError::new(codes::UNSUPPORTED_FORMAT, message.into())
}

/// A snapshot entry's typed view over the metadata JSON.
#[derive(Debug, Clone)]
pub struct SnapshotView {
    pub snapshot_id: i64,
    pub parent_snapshot_id: Option<i64>,
    pub sequence_number: Option<i64>,
    pub timestamp_ms: i64,
    pub manifest_list: String,
    /// The source summary (scrubbed to `operation` on rewrite).
    pub summary: Map<String, Value>,
    pub schema_id: Option<i64>,
}

/// The validated parts of a table metadata document the walk needs.
#[derive(Debug, Clone)]
pub struct TableMetadataView {
    pub format_version: u32,
    pub location: String,
    pub current_snapshot_id: Option<i64>,
    pub current_schema_id: i64,
    pub snapshots: Vec<SnapshotView>,
    pub last_sequence_number: i64,
}

fn required<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a Value, MaskuraError> {
    object.get(field).ok_or_else(|| {
        unsupported_table_operation(format!(
            "table metadata is missing required field {field:?}"
        ))
    })
}

fn required_i64(object: &Map<String, Value>, field: &str) -> Result<i64, MaskuraError> {
    required(object, field)?.as_i64().ok_or_else(|| {
        unsupported_table_operation(format!("table metadata field {field:?} must be an integer"))
    })
}

fn optional_i64(object: &Map<String, Value>, field: &str) -> Result<Option<i64>, MaskuraError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or_else(|| {
            unsupported_table_operation(format!(
                "table metadata field {field:?} must be an integer"
            ))
        }),
    }
}

impl TableMetadataView {
    /// Validates the metadata document and extracts the walk's view.
    ///
    /// Every rule here fails closed: unknown `format-version`s, missing
    /// structural fields, a `current-snapshot-id` that names no retained
    /// snapshot, table-level statistics files, and v2 snapshots without
    /// sequence numbers are all named errors rather than best-effort parses.
    pub fn parse(document: &Map<String, Value>) -> Result<Self, MaskuraError> {
        let object = document;
        let format_version = required_i64(object, "format-version")?;
        let format_version = u32::try_from(format_version)
            .map_err(|_| unsupported_format("table metadata has an invalid format-version"))?;
        if !(1..=2).contains(&format_version) {
            return Err(unsupported_format(format!(
                "table format-version {format_version} is not supported (v1 non-goals: ORC, Delta, Hive)"
            )));
        }
        let location = required(object, "location")?
            .as_str()
            .ok_or_else(|| unsupported_table_operation("table metadata location must be a string"))?
            .to_string();
        if split_s3_uri(&location).is_none() {
            return Err(unsupported_table_operation(format!(
                "table location {location:?} is not an s3:// URI"
            )));
        }
        // Structural detection signals (ADR 0028 §Detection) double as the
        // validation contract: the walk only starts from documents that carry
        // the full metadata shape. `current-snapshot-id` and `metadata-log`
        // are corroborating signals — a freshly created table has neither
        // (pyiceberg omits both), and its document must still validate.
        for field in [
            "format-version",
            "schemas",
            "current-schema-id",
            "partition-specs",
            "default-spec-id",
            "snapshots",
            "location",
        ] {
            if !object.contains_key(field) {
                return Err(unsupported_table_operation(format!(
                    "table metadata is missing required field {field:?}"
                )));
            }
        }
        // Table-level statistics files are an explicit v1 non-goal: they are
        // another plaintext-statistics surface and another unit kind.
        for field in ["statistics", "partition-statistics"] {
            if let Some(Value::Array(entries)) = object.get(field)
                && !entries.is_empty()
            {
                return Err(unsupported_table_operation(format!(
                    "table metadata field {field:?} is not empty: table statistics files are not supported in v1"
                )));
            }
        }

        let current_snapshot_id = optional_i64(object, "current-snapshot-id")?;
        let mut snapshots = Vec::new();
        if let Value::Array(entries) = required(object, "snapshots")? {
            for entry in entries {
                let entry = entry.as_object().ok_or_else(|| {
                    unsupported_table_operation("snapshot entries must be JSON objects")
                })?;
                let snapshot_id = required_i64(entry, "snapshot-id")?;
                let timestamp_ms = required_i64(entry, "timestamp-ms")?;
                let manifest_list = required(entry, "manifest-list")?
                    .as_str()
                    .ok_or_else(|| {
                        unsupported_table_operation("snapshot manifest-list must be a string")
                    })?
                    .to_string();
                let sequence_number = optional_i64(entry, "sequence-number")?;
                if format_version >= 2 && sequence_number.is_none() {
                    return Err(unsupported_table_operation(format!(
                        "snapshot {snapshot_id} has no sequence-number in a v{format_version} table"
                    )));
                }
                let summary = match entry.get("summary") {
                    Some(Value::Object(summary)) => summary.clone(),
                    Some(Value::Null) | None => Map::new(),
                    Some(_) => {
                        return Err(unsupported_table_operation(
                            "snapshot summary must be a JSON object",
                        ));
                    }
                };
                snapshots.push(SnapshotView {
                    snapshot_id,
                    parent_snapshot_id: optional_i64(entry, "parent-snapshot-id")?,
                    sequence_number,
                    timestamp_ms,
                    manifest_list,
                    summary,
                    schema_id: optional_i64(entry, "schema-id")?,
                });
            }
        }
        if let Some(current) = current_snapshot_id
            && !snapshots
                .iter()
                .any(|snapshot| snapshot.snapshot_id == current)
        {
            return Err(unsupported_table_operation(format!(
                "current-snapshot-id {current} names no retained snapshot"
            )));
        }
        let current_schema_id = required_i64(object, "current-schema-id")?;
        let last_sequence_number = snapshots
            .iter()
            .filter_map(|snapshot| snapshot.sequence_number)
            .max()
            .unwrap_or(0);

        Ok(Self {
            format_version,
            location,
            current_snapshot_id,
            current_schema_id,
            snapshots,
            last_sequence_number,
        })
    }
}

/// The `metadata/<version>-<token>.metadata.json` naming rule.
///
/// Returns the file's version number. v1 requires the conventional
/// `metadata/` layout with the zero-padded numeric version prefix the
/// reference implementations write (`00003-<uuid>.metadata.json`).
pub fn metadata_file_version(key: &str) -> Option<u64> {
    let name = key.rsplit('/').next()?;
    let rest = name.strip_suffix(".metadata.json")?;
    let (version, token) = rest.split_once('-')?;
    if version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit()) || token.is_empty()
    {
        return None;
    }
    version.parse().ok()
}

/// Derives the table root from a table metadata document key.
///
/// `R/metadata/00003-x.metadata.json` → `R/`. Keys that are not inside a
/// `metadata/` directory have no derivable root.
pub fn table_root_for_metadata_key(bucket: &str, key: &str) -> Option<TableRoot> {
    let (prefix, rest) = key.rsplit_once("metadata/")?;
    if rest.is_empty() || rest.contains('/') {
        return None;
    }
    Some(TableRoot {
        bucket: bucket.to_string(),
        prefix: prefix.to_string(),
    })
}

/// The next metadata file's zero-padded name token for a version.
pub fn metadata_file_name(version: u64, token: &str) -> String {
    format!("{version:05}-{token}.metadata.json")
}

/// The version number encoded in a `version-hint.text` body.
pub fn parse_version_hint(body: &str) -> Result<u64, MaskuraError> {
    let trimmed = body.trim();
    trimmed.parse().map_err(|_| {
        unsupported_table_operation(format!(
            "version-hint.text does not hold a version number: {trimmed:?}"
        ))
    })
}

/// Validates the metadata-JSON *shape* used for structural detection.
///
/// This is the detection signal set from ADR 0028: `format-version`,
/// `schemas`, `current-snapshot-id`, and `metadata-log` are what a table
/// metadata document carries. `current-snapshot-id` may be null (fresh table)
/// and `metadata-log` may be absent; the shape check is about key presence.
pub fn metadata_json_shape(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.get("format-version").is_some_and(Value::is_number)
        && object.get("schemas").is_some_and(Value::is_array)
        && object.contains_key("snapshots")
        && object.contains_key("location")
}

/// Snapshot summary keys the rewrite copies.
///
/// Only `operation` survives from a source summary; everything else —
/// including any `partition.<field>.min`/`max` bounds a writer embedded in
/// the summary — is dropped, never copied.
const SUMMARY_OPERATION_VALUES: &[&str] = &["append", "replace", "overwrite", "delete", "create"];

/// Recomputed per-snapshot totals produced by the rewrite.
pub fn rewritten_summary(
    operation: &str,
    total_data_files: u64,
    total_records: u64,
    total_files_size: u64,
) -> Map<String, Value> {
    let mut summary = Map::new();
    summary.insert("operation".into(), json!(operation));
    summary.insert(
        "total-data-files".into(),
        json!(total_data_files.to_string()),
    );
    summary.insert("total-records".into(), json!(total_records.to_string()));
    summary.insert(
        "total-files-size".into(),
        json!(total_files_size.to_string()),
    );
    summary.insert("total-delete-files".into(), json!("0"));
    summary.insert("total-position-deletes".into(), json!("0"));
    summary.insert("total-equality-deletes".into(), json!("0"));
    summary
}

/// The one summary key the rewrite copies from a source snapshot summary.
///
/// Everything else — including any `partition.<field>.min`/`max` bounds a
/// writer embedded in the summary — is dropped, never copied.
pub fn summary_operation(source: &Map<String, Value>) -> String {
    let operation = source
        .get("operation")
        .and_then(Value::as_str)
        .filter(|operation| SUMMARY_OPERATION_VALUES.contains(operation))
        .unwrap_or("replace");
    operation.to_string()
}

/// A snapshot entry in the rewritten `snapshots[]` list.
pub struct RewrittenSnapshot {
    pub snapshot_id: i64,
    pub parent_snapshot_id: Option<i64>,
    pub sequence_number: i64,
    pub timestamp_ms: i64,
    pub manifest_list_key: String,
    pub summary: Map<String, Value>,
    pub schema_id: Option<i64>,
}

impl RewrittenSnapshot {
    /// Serializes the entry as the metadata JSON object shape.
    ///
    /// v1 tables carry no `sequence-number` field on snapshot entries; the
    /// rewrite never invents fields the format version does not declare.
    pub fn to_json(&self, bucket: &str, format_version: u32) -> Value {
        let mut entry = Map::new();
        entry.insert("snapshot-id".into(), json!(self.snapshot_id));
        if let Some(parent) = self.parent_snapshot_id {
            entry.insert("parent-snapshot-id".into(), json!(parent));
        }
        if format_version >= 2 {
            entry.insert("sequence-number".into(), json!(self.sequence_number));
        }
        entry.insert("timestamp-ms".into(), json!(self.timestamp_ms));
        entry.insert(
            "manifest-list".into(),
            json!(s3_uri(bucket, &self.manifest_list_key)),
        );
        entry.insert("summary".into(), Value::Object(self.summary.clone()));
        if let Some(schema_id) = self.schema_id {
            entry.insert("schema-id".into(), json!(schema_id));
        }
        Value::Object(entry)
    }
}

/// Builds the committed metadata document from the source document.
///
/// - `snapshots[]` becomes the re-materialized retained snapshots plus the new
///   snapshot, in source order with the new snapshot appended;
/// - `current-snapshot-id` points at the new snapshot;
/// - `snapshot-log` / `metadata-log` are appended to, never rewritten;
/// - branch `refs` that pointed at the old current snapshot re-point at the
///   new one (tag refs keep their snapshot ids, which are preserved);
/// - `last-sequence-number` advances to the new snapshot's sequence;
/// - every other field — schemas, partition specs, sort orders, properties,
///   unknown future fields — is carried through verbatim.
#[allow(clippy::too_many_arguments)]
pub fn build_committed_metadata(
    source: &Map<String, Value>,
    view: &TableMetadataView,
    bucket: &str,
    rewritten: &[RewrittenSnapshot],
    new_snapshot_id: i64,
    new_snapshot_sequence: i64,
    new_snapshot_timestamp_ms: i64,
    new_snapshot_manifest_list_key: &str,
    new_summary: Map<String, Value>,
    source_metadata_key: &str,
) -> Value {
    let mut document = source.clone();

    let snapshots: Vec<Value> = rewritten
        .iter()
        .map(|snapshot| snapshot.to_json(bucket, view.format_version))
        .chain(std::iter::once({
            let mut entry = Map::new();
            entry.insert("snapshot-id".into(), json!(new_snapshot_id));
            if let Some(parent) = view.current_snapshot_id {
                entry.insert("parent-snapshot-id".into(), json!(parent));
            }
            if view.format_version >= 2 {
                entry.insert("sequence-number".into(), json!(new_snapshot_sequence));
            }
            entry.insert("timestamp-ms".into(), json!(new_snapshot_timestamp_ms));
            entry.insert(
                "manifest-list".into(),
                json!(s3_uri(bucket, new_snapshot_manifest_list_key)),
            );
            entry.insert("summary".into(), Value::Object(new_summary));
            entry.insert("schema-id".into(), json!(view.current_schema_id));
            Value::Object(entry)
        }))
        .collect();
    document.insert("snapshots".into(), Value::Array(snapshots));
    document.insert("current-snapshot-id".into(), json!(new_snapshot_id));
    document.insert("last-updated-ms".into(), json!(new_snapshot_timestamp_ms));
    if view.format_version >= 2 {
        document.insert("last-sequence-number".into(), json!(new_snapshot_sequence));
    }

    // snapshot-log: append the new snapshot; existing entries are the
    // snapshot history and are never rewritten (snapshot expiry is an
    // explicit prior step, never an implicit side effect).
    if let Some(Value::Array(log)) = document.get_mut("snapshot-log") {
        log.push(json!({
            "snapshot-id": new_snapshot_id,
            "timestamp-ms": new_snapshot_timestamp_ms,
        }));
    }

    // metadata-log: the source document is superseded by this commit.
    let metadata_log = document
        .entry("metadata-log")
        .or_insert_with(|| Value::Array(Vec::new()));
    if let Value::Array(log) = metadata_log {
        log.push(json!({
            "metadata-file": s3_uri(bucket, source_metadata_key),
            "timestamp-ms": new_snapshot_timestamp_ms,
        }));
    }

    // refs: branch refs at the old current snapshot follow the new one.
    if let Some(Value::Object(refs)) = document.get_mut("refs") {
        for reference in refs.values_mut() {
            let Some(reference) = reference.as_object_mut() else {
                continue;
            };
            let is_branch = reference
                .get("type")
                .and_then(Value::as_str)
                .is_none_or(|kind| kind == "branch");
            if is_branch
                && reference.get("snapshot-id").and_then(Value::as_i64) == view.current_snapshot_id
            {
                reference.insert("snapshot-id".into(), json!(new_snapshot_id));
            }
        }
    }

    Value::Object(document)
}

/// The version-hint pointer body for a committed metadata version.
pub fn version_hint_body(version: u64) -> String {
    format!("{version}\n")
}

/// Contents-type for stored table metadata documents.
pub const METADATA_CONTENT_TYPE: &str = "application/vnd.apache.iceberg.table-metadata+json";
/// Content-type for stored manifest layer objects (Avro OCF).
pub const MANIFEST_CONTENT_TYPE: &str = "application/avro";
/// Content-type for the `version-hint.text` pointer.
pub const VERSION_HINT_CONTENT_TYPE: &str = "text/plain";

/// Stable naming for rewritten manifest-layer objects.
pub fn rewritten_manifest_name(token: &str) -> String {
    format!("{token}.avro")
}

/// Bounded JSON metadata parsing used by both detection and the walk.
pub fn parse_json_document(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<Map<String, Value>, MaskuraError> {
    if bytes.len() > max_bytes {
        return Err(MaskuraError::new(
            codes::LIMIT_INPUT_BYTES,
            "table metadata document exceeds its size limit",
        ));
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|error| {
        unsupported_table_operation(format!("table metadata is not valid JSON: {error}"))
    })?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| unsupported_table_operation("table metadata must be a JSON object"))
}
