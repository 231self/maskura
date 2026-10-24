//! Manifest list and manifest reading and rewriting (the statistics
//! discipline of ADR 0028).
//!
//! Manifest Avro files are read with the shipped Avro stack (the same
//! `apache_avro` OCF reader, bounds, and IR converters the Avro codec uses)
//! but rewritten by this layer: every output manifest is a fresh OCF written
//! against the *source* schema object, so Iceberg `field-id` attributes and
//! logical types survive untouched.
//!
//! What the rewrite does to a manifest entry's `data_file` record:
//!
//! - `file_path` → the content-hash output key (no value-derived path parts);
//! - `file_size_in_bytes` / `record_count` → the transformed file's facts;
//! - `column_sizes`, `value_counts`, `null_value_counts`, `nan_value_counts`,
//!   `lower_bounds`, `upper_bounds`, `split_offsets`, `key_metadata`,
//!   `equality_ids` → **dropped to null**. Plaintext statistics are never
//!   copied into a rewritten manifest (Iceberg permits null bounds);
//! - `partition` → transformed as data through the typed value transform, and
//!   the result is re-validated against the declared partition schema (a
//!   type-changing transform fails closed).
//!
//! Manifest *list* entries get the same treatment: `partitions`
//! (`partition_summaries`) and `key_metadata` are dropped — they carry
//! plaintext partition bounds — and the added/existing/deleted file and row
//! counts are recomputed from the rewritten entries.
//!
//! The bounded Maskura IR cannot represent Iceberg's `map<int, …>` statistics
//! columns (IR map keys are UTF-8 strings), so record surgery runs on raw
//! Avro values; only the `partition` tuple — plain scalars — passes through
//! the typed IR/value transform.

use std::collections::{BTreeMap, BTreeSet};

use apache_avro::{DeflateSettings, Reader, Writer, schema::Schema, types::Value as AvroValue};
use maskura_error::MaskuraError;
use serde_json::{Value as JsonValue, json};

use crate::binary_ir::{BinaryIrLimits, SchemaIr, SchemaNode, ValueIr};
use crate::iceberg::data_file::{DataFileFormat, DataFileTransform};
use crate::iceberg::metadata::{split_s3_uri, unsupported_format, unsupported_table_operation};

/// The kind of manifest-layer object, from the Avro schema fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestLayerKind {
    /// The `manifest_file` record stream a snapshot points at.
    ManifestList,
    /// The `manifest_entry` record stream a manifest list entry points at.
    Manifest,
}

/// Structural Avro schema fingerprint for manifest layers.
///
/// The fingerprint is the record name plus the required field set the Iceberg
/// spec fixes for each layer (`manifest_path`/`manifest_length` for manifest
/// lists; `status`/`data_file` for manifests). Anything else is not a
/// manifest layer — including the layouts this v1 rejects later (delete-file
/// records fail closed at the walk, not at detection).
pub fn manifest_layer_kind(schema: &Schema) -> Option<ManifestLayerKind> {
    let Schema::Record(record) = schema else {
        return None;
    };
    let has = |wanted: &str| record.fields.iter().any(|field| field.name == wanted);
    match record.name.name() {
        "manifest_file" if has("manifest_path") && has("manifest_length") => {
            Some(ManifestLayerKind::ManifestList)
        }
        "manifest_entry" if has("status") && has("data_file") => Some(ManifestLayerKind::Manifest),
        _ => None,
    }
}

/// Looks up a named field's schema inside a record schema.
fn schema_record_field<'a>(schema: &'a Schema, name: &str) -> Option<&'a Schema> {
    match schema {
        Schema::Record(record) => record
            .fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| &field.schema),
        _ => None,
    }
}

/// The non-null branch of a possibly-nullable field schema.
fn value_schema(schema: &Schema) -> &Schema {
    match schema {
        Schema::Union(union) => union
            .variants()
            .iter()
            .find(|variant| !matches!(variant, Schema::Null))
            .unwrap_or(schema),
        schema => schema,
    }
}

/// Wraps a replacement value exactly the way the field's schema declares it:
/// nullable unions are written as a union branch, required fields raw.
fn slot_value(field_schema: &Schema, value: Option<AvroValue>) -> AvroValue {
    match field_schema {
        Schema::Union(union) => {
            let variants = union.variants();
            let null_branch = variants.iter().position(|v| matches!(v, Schema::Null));
            match (null_branch, value) {
                (Some(index), None) => AvroValue::Union(index as u32, Box::new(AvroValue::Null)),
                (_, Some(value)) => {
                    let value_branch = variants
                        .iter()
                        .position(|v| !matches!(v, Schema::Null))
                        .unwrap_or(0);
                    AvroValue::Union(value_branch as u32, Box::new(value))
                }
                (None, None) => AvroValue::Null,
            }
        }
        _ => value.unwrap_or(AvroValue::Null),
    }
}

fn avro_error(detail: impl std::fmt::Display) -> MaskuraError {
    unsupported_format(format!("Iceberg manifest Avro is unreadable: {detail}"))
}

fn read_ocf(bytes: &[u8]) -> Result<(Schema, Vec<AvroValue>), MaskuraError> {
    let reader = Reader::new(bytes).map_err(avro_error)?;
    let schema = reader.writer_schema().clone();
    let records = reader
        .collect::<Result<Vec<AvroValue>, _>>()
        .map_err(avro_error)?;
    Ok((schema, records))
}

fn write_ocf(schema: &Schema, records: &[AvroValue]) -> Result<Vec<u8>, MaskuraError> {
    let mut writer = Writer::with_codec(
        schema,
        Vec::new(),
        apache_avro::Codec::Deflate(DeflateSettings::default()),
    )
    .map_err(avro_error)?;
    for record in records {
        writer.append_value(record.clone()).map_err(avro_error)?;
    }
    writer.into_inner().map_err(avro_error)
}

/// One decoded manifest entry's typed view (the raw record is kept for
/// rewrite surgery).
pub struct ManifestEntry {
    pub record: AvroValue,
    pub status: i32,
    pub file_uri: String,
    pub file_format: String,
    pub data_file_content: i32,
    pub record_count: i64,
}

/// A decoded manifest file (one `manifest_entry` OCF).
pub struct ManifestFile {
    pub schema: Schema,
    pub entries: Vec<ManifestEntry>,
}

/// One decoded manifest-list entry's typed view.
pub struct ManifestListEntry {
    pub record: AvroValue,
    pub manifest_uri: String,
}

/// A decoded manifest list (one `manifest_file` OCF).
pub struct ManifestListFile {
    pub schema: Schema,
    pub entries: Vec<ManifestListEntry>,
}

fn record_get<'a>(record: &'a AvroValue, name: &str) -> Option<&'a AvroValue> {
    match record {
        AvroValue::Record(fields) => fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value),
        _ => None,
    }
}

fn record_get_mut<'a>(record: &'a mut AvroValue, name: &str) -> Option<&'a mut AvroValue> {
    match record {
        AvroValue::Record(fields) => fields
            .iter_mut()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value),
        _ => None,
    }
}

fn unwrap_union(value: &AvroValue) -> &AvroValue {
    match value {
        AvroValue::Union(_, inner) => inner,
        value => value,
    }
}

/// Replaces a record field's value, matching the field schema's shape.
fn set_record_field(
    record: &mut AvroValue,
    record_schema: &Schema,
    name: &str,
    value: Option<AvroValue>,
) {
    let Some(field_schema) = schema_record_field(record_schema, name) else {
        // The field is absent from this schema generation (v1 has no
        // `nan_value_counts`); leave it absent rather than invent schema.
        return;
    };
    if let Some(slot) = record_get_mut(record, name) {
        *slot = slot_value(field_schema, value);
    }
}

fn field_string(record: &AvroValue, name: &str) -> Result<String, MaskuraError> {
    match record_get(record, name).map(unwrap_union) {
        Some(AvroValue::String(value)) => Ok(value.clone()),
        _ => Err(unsupported_table_operation(format!(
            "manifest record field {name:?} must be a string"
        ))),
    }
}

fn field_i64(record: &AvroValue, name: &str) -> Result<i64, MaskuraError> {
    match record_get(record, name).map(unwrap_union) {
        Some(AvroValue::Long(value)) => Ok(*value),
        Some(AvroValue::Int(value)) => Ok(i64::from(*value)),
        _ => Err(unsupported_table_operation(format!(
            "manifest record field {name:?} must be an integer"
        ))),
    }
}

fn field_i32_opt(record: &AvroValue, name: &str) -> Result<Option<i32>, MaskuraError> {
    match record_get(record, name).map(unwrap_union) {
        None | Some(AvroValue::Null) => Ok(None),
        Some(AvroValue::Int(value)) => Ok(Some(*value)),
        _ => Err(unsupported_table_operation(format!(
            "manifest record field {name:?} must be an integer"
        ))),
    }
}

/// Decodes one manifest OCF into typed entries.
pub fn read_manifest(bytes: &[u8]) -> Result<ManifestFile, MaskuraError> {
    let (schema, records) = read_ocf(bytes)?;
    if manifest_layer_kind(&schema) != Some(ManifestLayerKind::Manifest) {
        return Err(unsupported_table_operation(
            "manifest object does not carry the manifest_entry Avro schema",
        ));
    }
    let mut entries = Vec::with_capacity(records.len());
    for record in records {
        let status = field_i64(&record, "status")?;
        let status = i32::try_from(status)
            .map_err(|_| unsupported_table_operation("manifest entry status is out of range"))?;
        let data_file = record_get(&record, "data_file")
            .ok_or_else(|| unsupported_table_operation("manifest entry has no data_file record"))?;
        let file_uri = field_string(data_file, "file_path")?;
        let file_format = field_string(data_file, "file_format")?;
        let data_file_content = field_i32_opt(data_file, "content")?.unwrap_or(0);
        let record_count = field_i64(data_file, "record_count")?;
        if record_count < 0 {
            return Err(unsupported_table_operation(
                "manifest entry record_count must not be negative",
            ));
        }
        entries.push(ManifestEntry {
            record,
            status,
            file_uri,
            file_format,
            data_file_content,
            record_count,
        });
    }
    Ok(ManifestFile { schema, entries })
}

/// Decodes one manifest-list OCF into typed entries.
pub fn read_manifest_list(bytes: &[u8]) -> Result<ManifestListFile, MaskuraError> {
    let (schema, records) = read_ocf(bytes)?;
    if manifest_layer_kind(&schema) != Some(ManifestLayerKind::ManifestList) {
        return Err(unsupported_table_operation(
            "manifest-list object does not carry the manifest_file Avro schema",
        ));
    }
    let mut entries = Vec::with_capacity(records.len());
    for record in records {
        let manifest_uri = field_string(&record, "manifest_path")?;
        entries.push(ManifestListEntry {
            record,
            manifest_uri,
        });
    }
    Ok(ManifestListFile { schema, entries })
}

/// The transformed file's facts keyed by source store key.
#[derive(Debug, Clone)]
pub struct TransformedFile {
    /// The output object's store key (content-hash path).
    pub key: String,
    /// The output object's size in bytes.
    pub size: u64,
    /// The output file's true record count.
    pub record_count: u64,
    /// The output format (transforms are format-preserving).
    pub format: DataFileFormat,
}

/// Recomputed manifest-file counts (the manifest-list entry rewrite).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ManifestCounts {
    pub added_files: i64,
    pub existing_files: i64,
    pub deleted_files: i64,
    pub added_rows: i64,
    pub existing_rows: i64,
    pub deleted_rows: i64,
}

impl ManifestCounts {
    fn record(&mut self, status: i32, record_count: i64) {
        match status {
            1 => {
                self.added_files += 1;
                self.added_rows += record_count;
            }
            2 => {
                self.deleted_files += 1;
                self.deleted_rows += record_count;
            }
            _ => {
                self.existing_files += 1;
                self.existing_rows += record_count;
            }
        }
    }
}

/// The partition record's schema pair, navigated from the manifest schema.
pub fn partition_schema(manifest_schema: &Schema) -> Result<(SchemaIr, SchemaNode), MaskuraError> {
    let data_file = schema_record_field(manifest_schema, "data_file")
        .ok_or_else(|| unsupported_table_operation("manifest schema has no data_file record"))?;
    let partition = schema_record_field(data_file, "partition")
        .ok_or_else(|| unsupported_table_operation("manifest schema has no partition record"))?;
    let schema = crate::avro::schema_from_avro(partition, BinaryIrLimits::default())?;
    let node = schema.root.clone();
    Ok((schema, node))
}

/// Rewrites one manifest: mapped content-hash paths, transformed partition
/// values, and dropped plaintext statistics.
///
/// The output OCF is written against the source schema object — the same
/// record names, field ids, and logical types the table declared.
///
/// Tombstoned entries whose deleted file is already gone are dropped: no
/// reader needs a tombstone for an object that no longer exists, and keeping
/// its plaintext path (often a value-derived Hive partition path) in a
/// rewritten manifest would leak.
pub fn rewrite_manifest<D: DataFileTransform>(
    source: &ManifestFile,
    path_map: &BTreeMap<String, TransformedFile>,
    dropped_tombstones: &BTreeSet<String>,
    transform: &mut D,
    bucket: &str,
) -> Result<(Vec<u8>, ManifestCounts), MaskuraError> {
    let (partition_ir, partition_node) = partition_schema(&source.schema)?;
    let data_file_schema = schema_record_field(&source.schema, "data_file")
        .ok_or_else(|| unsupported_table_operation("manifest schema has no data_file record"))?;
    let mut counts = ManifestCounts::default();
    let mut output = Vec::with_capacity(source.entries.len());
    for entry in &source.entries {
        let entry_key = split_s3_uri(&entry.file_uri)
            .map(|(_, key)| key)
            .unwrap_or_else(|| entry.file_uri.clone());
        if entry.status == 2 && dropped_tombstones.contains(&entry_key) {
            continue;
        }
        let transformed = path_map.get(&entry_key).ok_or_else(|| {
            unsupported_table_operation(format!(
                "manifest references data file {} that the operation does not cover",
                entry.file_uri
            ))
        })?;
        let mut record = entry.record.clone();
        let data_file = record_get_mut(&mut record, "data_file")
            .ok_or_else(|| unsupported_table_operation("manifest entry has no data_file record"))?;

        // Path and size discipline: content-hash output key only — no
        // value-derived path components.
        set_record_field(
            data_file,
            data_file_schema,
            "file_path",
            Some(AvroValue::String(format!(
                "s3://{bucket}/{}",
                transformed.key
            ))),
        );
        let file_size = i64::try_from(transformed.size)
            .map_err(|_| unsupported_table_operation("transformed data file is too large"))?;
        set_record_field(
            data_file,
            data_file_schema,
            "file_size_in_bytes",
            Some(AvroValue::Long(file_size)),
        );
        let record_count = i64::try_from(transformed.record_count)
            .map_err(|_| unsupported_table_operation("transformed record count is out of range"))?;
        set_record_field(
            data_file,
            data_file_schema,
            "record_count",
            Some(AvroValue::Long(record_count)),
        );

        // Statistics discipline: plaintext statistics are never copied.
        for field in [
            "column_sizes",
            "value_counts",
            "null_value_counts",
            "nan_value_counts",
            "lower_bounds",
            "upper_bounds",
            "split_offsets",
            "key_metadata",
            "equality_ids",
        ] {
            set_record_field(data_file, data_file_schema, field, None);
        }

        // Partition values are transformed as data, then re-validated against
        // the declared partition schema: a transform that changes the value's
        // type (or drops it) fails closed.
        if record_get(data_file, "partition").is_some() {
            let partition_value = record_get(data_file, "partition").expect("checked").clone();
            let partition_ir_value =
                crate::avro::avro_value_to_ir(partition_value, &partition_node)?;
            match transform.transform_value(ValueIr::new(partition_ir_value), &partition_ir)? {
                Some(transformed_value) => {
                    transformed_value
                        .validate(&partition_ir, BinaryIrLimits::default())
                        .map_err(|_| {
                            unsupported_table_operation(
                                "the transform changed a manifest partition value's type",
                            )
                        })?;
                    let rewritten =
                        crate::avro::ir_value_to_avro(&transformed_value.root, &partition_node)?;
                    set_record_field(data_file, data_file_schema, "partition", Some(rewritten));
                }
                None => {
                    return Err(unsupported_table_operation(
                        "the transform dropped a manifest partition value",
                    ));
                }
            }
        }

        counts.record(entry.status, record_count);
        output.push(record);
    }
    let bytes = write_ocf(&source.schema, &output)?;
    Ok((bytes, counts))
}

/// Per-manifest facts the manifest-list rewrite needs.
pub struct RewrittenManifest {
    /// The new manifest object's store key.
    pub key: String,
    /// The new manifest object's length in bytes.
    pub length: u64,
    pub counts: ManifestCounts,
}

/// Rewrites one manifest list: mapped manifest paths and lengths, recomputed
/// counts, and dropped plaintext partition summaries.
pub fn rewrite_manifest_list(
    source: &ManifestListFile,
    rewritten: &[RewrittenManifest],
    bucket: &str,
) -> Result<Vec<u8>, MaskuraError> {
    if source.entries.len() != rewritten.len() {
        return Err(unsupported_table_operation(
            "manifest list rewrite lost or gained entries",
        ));
    }
    let mut output = Vec::with_capacity(source.entries.len());
    for (entry, manifest) in source.entries.iter().zip(rewritten) {
        let mut record = entry.record.clone();
        set_record_field(
            &mut record,
            &source.schema,
            "manifest_path",
            Some(AvroValue::String(format!("s3://{bucket}/{}", manifest.key))),
        );
        let length = i64::try_from(manifest.length)
            .map_err(|_| unsupported_table_operation("rewritten manifest is too large"))?;
        set_record_field(
            &mut record,
            &source.schema,
            "manifest_length",
            Some(AvroValue::Long(length)),
        );
        // Counts are recomputed from the rewritten entries — never copied.
        for (name, value) in [
            ("added_files_count", manifest.counts.added_files),
            ("added_data_files_count", manifest.counts.added_files),
            ("existing_files_count", manifest.counts.existing_files),
            ("existing_data_files_count", manifest.counts.existing_files),
            ("deleted_files_count", manifest.counts.deleted_files),
            ("deleted_data_files_count", manifest.counts.deleted_files),
            ("added_rows_count", manifest.counts.added_rows),
            ("existing_rows_count", manifest.counts.existing_rows),
            ("deleted_rows_count", manifest.counts.deleted_rows),
        ] {
            set_count_field(&mut record, &source.schema, name, value);
        }
        // Plaintext partition bounds and key metadata are dropped.
        for field in ["partitions", "partition_summaries", "key_metadata"] {
            set_record_field(&mut record, &source.schema, field, None);
        }
        output.push(record);
    }
    write_ocf(&source.schema, &output)
}

/// Sets an integer count field at the width the field schema declares.
fn set_count_field(record: &mut AvroValue, record_schema: &Schema, name: &str, value: i64) {
    let Some(field_schema) = schema_record_field(record_schema, name) else {
        return;
    };
    let raw = match value_schema(field_schema) {
        Schema::Int => AvroValue::Int(i32::try_from(value).unwrap_or(i32::MAX)),
        _ => AvroValue::Long(value),
    };
    set_record_field(record, record_schema, name, Some(raw));
}

/// The canonical `manifest_file` schema for the empty manifest list a
/// zero-snapshot table commits (Iceberg spec field ids).
pub fn empty_manifest_list_schema(format_version: u32) -> Result<Schema, MaskuraError> {
    let schema_json = match format_version {
        1 => json!({
            "type": "record", "name": "manifest_file", "fields": [
                {"field-id": 500, "name": "manifest_path", "type": "string"},
                {"field-id": 501, "name": "manifest_length", "type": "long"},
                {"field-id": 502, "name": "partition_spec_id", "type": "int"},
                {"field-id": 503, "name": "added_snapshot_id", "type": "long"},
                {"field-id": 504, "name": "added_files_count", "type": ["null", "int"], "default": null},
                {"field-id": 505, "name": "existing_files_count", "type": ["null", "int"], "default": null},
                {"field-id": 506, "name": "deleted_files_count", "type": ["null", "int"], "default": null},
                {"field-id": 512, "name": "added_rows_count", "type": ["null", "long"], "default": null},
                {"field-id": 513, "name": "existing_rows_count", "type": ["null", "long"], "default": null},
                {"field-id": 514, "name": "deleted_rows_count", "type": ["null", "long"], "default": null},
                {"field-id": 507, "name": "partitions", "type": ["null", {"type": "array", "element-id": 508, "items": {"type": "record", "name": "r508", "fields": [
                    {"field-id": 509, "name": "contains_null", "type": "boolean"},
                    {"field-id": 518, "name": "contains_nan", "type": ["null", "boolean"], "default": null},
                    {"field-id": 510, "name": "lower_bound", "type": ["null", "bytes"], "default": null},
                    {"field-id": 511, "name": "upper_bound", "type": ["null", "bytes"], "default": null}
                ]}}], "default": null},
                {"field-id": 519, "name": "key_metadata", "type": ["null", "bytes"], "default": null}
            ]
        }),
        2 => json!({
            "type": "record", "name": "manifest_file", "fields": [
                {"field-id": 500, "name": "manifest_path", "type": "string"},
                {"field-id": 501, "name": "manifest_length", "type": "long"},
                {"field-id": 502, "name": "partition_spec_id", "type": "int"},
                {"field-id": 517, "name": "content", "type": "int"},
                {"field-id": 515, "name": "sequence_number", "type": "long"},
                {"field-id": 516, "name": "min_sequence_number", "type": "long"},
                {"field-id": 503, "name": "added_snapshot_id", "type": "long"},
                {"field-id": 504, "name": "added_files_count", "type": "int"},
                {"field-id": 505, "name": "existing_files_count", "type": "int"},
                {"field-id": 506, "name": "deleted_files_count", "type": "int"},
                {"field-id": 512, "name": "added_rows_count", "type": "long"},
                {"field-id": 513, "name": "existing_rows_count", "type": "long"},
                {"field-id": 514, "name": "deleted_rows_count", "type": "long"},
                {"field-id": 507, "name": "partitions", "type": ["null", {"type": "array", "element-id": 508, "items": {"type": "record", "name": "r508", "fields": [
                    {"field-id": 509, "name": "contains_null", "type": "boolean"},
                    {"field-id": 518, "name": "contains_nan", "type": ["null", "boolean"], "default": null},
                    {"field-id": 510, "name": "lower_bound", "type": ["null", "bytes"], "default": null},
                    {"field-id": 511, "name": "upper_bound", "type": ["null", "bytes"], "default": null}
                ]}}], "default": null},
                {"field-id": 519, "name": "key_metadata", "type": ["null", "bytes"], "default": null}
            ]
        }),
        _ => return Err(unsupported_format("unknown table format-version")),
    };
    Schema::parse_str(&serde_json::to_string(&schema_json).map_err(avro_error)?).map_err(avro_error)
}

/// Writes an empty manifest list (a zero-snapshot table's new snapshot).
pub fn write_empty_manifest_list(format_version: u32) -> Result<Vec<u8>, MaskuraError> {
    let schema = empty_manifest_list_schema(format_version)?;
    write_ocf(&schema, &[])
}

/// Serialized-JSON helper for tests and detection fingerprints.
pub fn schema_to_json(schema: &Schema) -> Result<JsonValue, MaskuraError> {
    serde_json::to_value(schema).map_err(avro_error)
}
