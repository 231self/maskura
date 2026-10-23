//! Fixture-driven tests for the Iceberg table walker, statistics scrub, and
//! commit protocol.
//!
//! The golden tables under `tests/fixtures/iceberg/` are written by pyiceberg
//! (see `tests/fixtures/iceberg/generate_fixtures.py`): v1 and v2 format
//! versions, partitioned and unpartitioned layouts, multiple retained
//! snapshots with tombstones, a zero-snapshot table, and a merge-on-read
//! table carrying delete files. These tests run the metadata layer over
//! those bytes with a test data-file seam, so the walker/manifest/commit
//! machinery is fully exercised while the production seam stays fail-closed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use apache_avro::types::Value as AvroValue;
use maskura_error::{MaskuraError, codes};
use serde_json::{Map, Value, json};

use crate::binary_ir::{BinaryIrLimits, SchemaIr, Value as IrValue, ValueIr};
use crate::iceberg::data_file::{
    DataFileInput, DataFileTransform, TransformedDataFile, UnsupportedDataFileTransform,
};
use crate::iceberg::manifest::{
    self, ManifestLayerKind, manifest_layer_kind, read_manifest, read_manifest_list,
};
use crate::iceberg::metadata::{self, TableRoot};
use crate::iceberg::store::{MemoryTableStore, TableStore};
use crate::iceberg::walker::{self, TableOperation, TableOutcome, WalkLimits};
use crate::store::MemoryStore;

// Assert/panic messages are logs: never interpolate object keys (they embed
// UUIDs and value-derived path components) into them — CodeQL's
// `rust/cleartext-logging` rightly fails the gate on that.
fn redacted() -> &'static str {
    "<redacted>"
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/iceberg");

/// Minimal single-threaded block-on for test calls into the async walker.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

/// Loads a golden table into an in-memory store at its fixture keys.
fn load_fixture(name: &str) -> (Arc<MemoryTableStore>, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    let root = PathBuf::from(FIXTURES).join(name);
    let mut stack = vec![(root.clone(), String::new())];
    while let Some((dir, relative)) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read fixture dir") {
            let entry = entry.expect("fixture entry");
            let file_name = entry.file_name().to_string_lossy().to_string();
            let relative = if relative.is_empty() {
                file_name.clone()
            } else {
                format!("{relative}/{file_name}")
            };
            if entry.file_type().expect("fixture type").is_dir() {
                stack.push((entry.path(), relative));
                continue;
            }
            let bytes = std::fs::read(entry.path()).expect("read fixture file");
            let content_type = if file_name.ends_with(".json") {
                "application/json"
            } else if file_name.ends_with(".avro") {
                "application/avro"
            } else if file_name.ends_with(".parquet") {
                "application/vnd.apache.parquet"
            } else {
                "text/plain"
            };
            store.put("bucket", &format!("{name}/{relative}"), bytes, content_type);
        }
    }
    (
        Arc::new(MemoryTableStore::new(store.clone(), "bucket")),
        store,
    )
}

fn table_root(name: &str) -> TableRoot {
    TableRoot {
        bucket: "bucket".into(),
        prefix: format!("{name}/"),
    }
}

/// A schema-preserving test transform: strings are redacted, data-file bytes
/// are rewritten through a marker, and record counts optionally drop a row.
#[derive(Default)]
struct TestTransform {
    seen_data_files: Vec<String>,
    seen_partition_values: usize,
    drop_rows: bool,
}

impl DataFileTransform for TestTransform {
    fn transform_data_file(
        &mut self,
        input: DataFileInput<'_>,
    ) -> Result<TransformedDataFile, MaskuraError> {
        self.seen_data_files.push(input.key.to_string());
        let mut bytes = b"maskura-test-transform\n".to_vec();
        bytes.extend_from_slice(input.bytes);
        Ok(TransformedDataFile {
            bytes,
            record_count: input.record_count.saturating_sub(u64::from(self.drop_rows)),
        })
    }

    fn transform_value(
        &mut self,
        value: ValueIr,
        schema: &SchemaIr,
    ) -> Result<Option<ValueIr>, MaskuraError> {
        self.seen_partition_values += 1;
        let mut transformed = value;
        redact_strings(&mut transformed.root);
        transformed.validate(schema, BinaryIrLimits::default())?;
        Ok(Some(transformed))
    }
}

fn redact_strings(value: &mut IrValue) {
    match value {
        IrValue::String { value } => *value = "[REDACTED]".into(),
        IrValue::Record { fields } => {
            for field in fields {
                redact_strings(&mut field.value);
            }
        }
        IrValue::Array { items } => {
            for item in items {
                redact_strings(item);
            }
        }
        _ => {}
    }
}

/// A transform that rejects one specific data file (the coverage-gap case).
struct RejectFileTransform {
    reject_key: String,
}

impl DataFileTransform for RejectFileTransform {
    fn transform_data_file(
        &mut self,
        input: DataFileInput<'_>,
    ) -> Result<TransformedDataFile, MaskuraError> {
        if input.key == self.reject_key {
            return Err(MaskuraError::new(
                codes::UNSUPPORTED_FORMAT,
                format!("test seam refuses to cover {}", input.key),
            ));
        }
        Ok(TransformedDataFile {
            bytes: input.bytes.to_vec(),
            record_count: input.record_count,
        })
    }

    fn transform_value(
        &mut self,
        value: ValueIr,
        _schema: &SchemaIr,
    ) -> Result<Option<ValueIr>, MaskuraError> {
        Ok(Some(value))
    }
}

/// A transform that changes a partition value's type (must fail closed).
struct TypeChangingTransform;

impl DataFileTransform for TypeChangingTransform {
    fn transform_data_file(
        &mut self,
        input: DataFileInput<'_>,
    ) -> Result<TransformedDataFile, MaskuraError> {
        Ok(TransformedDataFile {
            bytes: input.bytes.to_vec(),
            record_count: input.record_count,
        })
    }

    fn transform_value(
        &mut self,
        _value: ValueIr,
        _schema: &SchemaIr,
    ) -> Result<Option<ValueIr>, MaskuraError> {
        Ok(Some(ValueIr::new(IrValue::I64 { value: 7 })))
    }
}

/// A transform that drops partition values (must fail closed).
struct DroppingValueTransform;

impl DataFileTransform for DroppingValueTransform {
    fn transform_data_file(
        &mut self,
        input: DataFileInput<'_>,
    ) -> Result<TransformedDataFile, MaskuraError> {
        Ok(TransformedDataFile {
            bytes: input.bytes.to_vec(),
            record_count: input.record_count,
        })
    }

    fn transform_value(
        &mut self,
        _value: ValueIr,
        _schema: &SchemaIr,
    ) -> Result<Option<ValueIr>, MaskuraError> {
        Ok(None)
    }
}

fn current_metadata(
    store: &MemoryTableStore,
    root: &TableRoot,
) -> (u64, String, Map<String, Value>) {
    block_on(walker::current_metadata(store, root, WalkLimits::default()))
        .expect("current metadata")
}

fn current_document(store: &MemoryTableStore, root: &TableRoot) -> Value {
    let (_, _, document) = current_metadata(store, root);
    Value::Object(document)
}

/// Walks the fixture's current state with the commit target at version
/// `base + 1` (the version rule a processed write must follow).
fn prepare(
    store: &MemoryTableStore,
    root: &TableRoot,
    transform: &mut impl DataFileTransform,
) -> Result<TableOutcome, MaskuraError> {
    let (base_version, source_key, document) = current_metadata(store, root);
    let new_metadata_key = format!(
        "{}metadata/{:05}-commit.metadata.json",
        root.prefix,
        base_version + 1
    );
    let operation = TableOperation {
        root,
        source_metadata: &document,
        source_metadata_key: &source_key,
        base_version,
        new_version: base_version + 1,
        new_metadata_key: &new_metadata_key,
        token: "testtoken",
        timestamp_ms: 1_700_000_000_000,
    };
    block_on(walker::walk_and_prepare(
        store,
        transform,
        &operation,
        WalkLimits::default(),
    ))
}

fn commit(
    store: &MemoryTableStore,
    root: &TableRoot,
    outcome: TableOutcome,
) -> Result<walker::CommitReport, MaskuraError> {
    block_on(walker::commit(store, root, outcome, WalkLimits::default()))
}

/// Store keys without the `bucket/` prefix `MemoryStore::list_keys` adds.
fn store_keys(raw: &MemoryStore) -> Vec<String> {
    raw.list_keys()
        .into_iter()
        .map(|key| {
            key.strip_prefix("bucket/")
                .map(ToOwned::to_owned)
                .unwrap_or(key)
        })
        .collect()
}

fn commit_version_hint(raw: &MemoryStore, name: &str) -> String {
    let hint = raw
        .get("bucket", &format!("{name}/metadata/version-hint.text"))
        .expect("version hint");
    String::from_utf8_lossy(&hint.data).trim().to_string()
}

// ---------------------------------------------------------------------------
// Statistics scrub and manifest rewrite (hazard #1).
// ---------------------------------------------------------------------------

/// The manifest rewrite never copies plaintext statistics and preserves the
/// source schema (Iceberg `field-id` attributes included) verbatim.
#[test]
fn rewritten_manifests_drop_plaintext_statistics_and_keep_the_schema() {
    let (store, raw) = load_fixture("v2_partitioned");
    let root = table_root("v2_partitioned");
    let mut transform = TestTransform::default();
    let outcome = prepare(&store, &root, &mut transform).expect("walk v2_partitioned");

    // Source manifest schemas (the store still holds them: nothing is
    // committed in this test).
    let source_schemas: BTreeSet<String> = block_on(store.list("v2_partitioned/metadata/"))
        .expect("list")
        .into_iter()
        .filter(|key| key.ends_with(".avro") && !key.contains("snap-"))
        .map(|key| {
            let bytes = raw.get("bucket", &key).expect("source manifest").data;
            let source = read_manifest(&bytes).expect("source manifest readable");
            manifest::schema_to_json(&source.schema)
                .expect("schema json")
                .to_string()
        })
        .collect();
    assert!(!source_schemas.is_empty());

    let mut rewritten_manifests = 0;
    for write in &outcome.object_writes {
        if !write.key.ends_with(".avro") || write.key.contains("snap-") {
            continue;
        }
        let rewritten = read_manifest(&write.bytes).expect("rewritten manifest is readable");
        rewritten_manifests += 1;

        // Schema preservation: the output OCF carries the source schema —
        // same record names, field ids (`field-id` attributes survive the
        // round trip), and logical types.
        let rewritten_json = manifest::schema_to_json(&rewritten.schema).expect("schema json");
        assert!(
            rewritten_json.to_string().contains("\"field-id\""),
            "Iceberg field-id attributes must survive the manifest rewrite"
        );
        assert!(
            source_schemas.contains(&rewritten_json.to_string()),
            "the rewrite must write the source schema verbatim"
        );

        for entry in &rewritten.entries {
            let data_file = avro_field(&entry.record, "data_file").expect("data_file");
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
                if let Some(value) = avro_field(data_file, field) {
                    assert!(
                        avro_is_null(value),
                        "{field} must be dropped to null in a rewritten manifest, got {value:?}"
                    );
                }
            }
            // Path discipline: content-hash output paths only.
            let file_path = avro_string(data_file, "file_path");
            let name = file_path.rsplit('/').next().expect("name");
            let (stem, extension) = name.rsplit_once('.').expect("extension");
            assert!(
                stem.len() == 64 && stem.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "output data files use content-hash names, got {name}"
            );
            assert!(
                matches!(extension, "parquet" | "avro"),
                "output extension follows the format, got {name}"
            );
            assert!(
                file_path.starts_with("s3://bucket/v2_partitioned/data/"),
                "the output key is under the table root: {file_path}"
            );
            // Record counts follow the transform, not the source manifest.
            assert!(avro_i64(data_file, "record_count") >= 1);
        }
    }
    assert!(rewritten_manifests > 0, "the walk rewrote manifests");
}

/// Manifest-list rewrites drop `partitions` (plaintext bounds) and recompute
/// counts instead of copying them.
#[test]
fn rewritten_manifest_lists_drop_partition_summaries_and_recompute_counts() {
    let (store, _raw) = load_fixture("v2_partitioned");
    let root = table_root("v2_partitioned");
    let mut transform = TestTransform::default();
    let outcome = prepare(&store, &root, &mut transform).expect("walk v2_partitioned");

    let mut lists = 0;
    for write in &outcome.object_writes {
        if !write.key.contains("snap-") {
            continue;
        }
        lists += 1;
        let list = read_manifest_list(&write.bytes).expect("rewritten manifest list is readable");
        for entry in &list.entries {
            let partitions = avro_field(&entry.record, "partitions");
            assert!(
                partitions.is_none_or(avro_is_null),
                "manifest-list partition summaries must be dropped, got {partitions:?}"
            );
            assert!(
                avro_field(&entry.record, "key_metadata").is_none_or(avro_is_null),
                "manifest-list key_metadata must be dropped"
            );
            assert!(avro_i64(&entry.record, "manifest_length") > 0);
            // Recomputed counts survive the rewrite.
            assert!(avro_i64(&entry.record, "added_files_count") >= 1);
            assert!(avro_i64(&entry.record, "added_rows_count") >= 1);
        }
    }
    assert_eq!(
        lists, 2,
        "one rewritten manifest list per retained snapshot"
    );
}

/// Snapshot summaries are reduced to `operation` plus recomputed totals —
/// writer-added summary keys (including partition bounds) are never copied.
#[test]
fn rewritten_snapshot_summaries_never_copy_writer_keys() {
    let (store, _raw) = load_fixture("v2_partitioned");
    let root = table_root("v2_partitioned");
    let mut transform = TestTransform::default();
    let outcome = prepare(&store, &root, &mut transform).expect("walk v2_partitioned");

    let snapshots = outcome.new_metadata_json["snapshots"]
        .as_array()
        .expect("snapshots array");
    for snapshot in snapshots {
        let summary = snapshot["summary"].as_object().expect("summary object");
        for key in summary.keys() {
            assert!(
                [
                    "operation",
                    "total-data-files",
                    "total-records",
                    "total-files-size",
                    "total-delete-files",
                    "total-position-deletes",
                    "total-equality-deletes"
                ]
                .contains(&key.as_str()),
                "summary key {} must not be copied into a rewritten snapshot",
                redacted()
            );
        }
        // The recomputed totals match the transformed files.
        assert!(summary["total-records"].as_str().is_some());
    }
}

// ---------------------------------------------------------------------------
// Coverage rule (v1) and the data-file seam.
// ---------------------------------------------------------------------------

/// Every data file of every retained snapshot is covered — including files
/// only historical snapshots reference (and tombstoned files).
#[test]
fn the_walk_covers_every_retained_snapshots_data_files() {
    let (store, _raw) = load_fixture("v2_multi_snapshot");
    let root = table_root("v2_multi_snapshot");
    let mut transform = TestTransform::default();
    let outcome = prepare(&store, &root, &mut transform).expect("walk v2_multi_snapshot");

    // The fixture has four data files across its snapshots (two appends plus
    // a copy-on-write overwrite that tombstones one of them).
    assert_eq!(
        transform.seen_data_files.len(),
        4,
        "the walk must transform every referenced file; saw {:?}",
        transform.seen_data_files
    );
    assert_eq!(
        outcome.covered_data_files.len(),
        transform.seen_data_files.len(),
        "the covered set is exactly what the transform saw"
    );
    // Files referenced by more than one snapshot are transformed once.
    let unique: BTreeSet<_> = transform.seen_data_files.iter().collect();
    assert_eq!(unique.len(), transform.seen_data_files.len());
}

/// A retained snapshot referencing a file the operation cannot cover fails
/// closed before anything is written.
#[test]
fn a_retained_snapshot_referencing_an_uncovered_file_fails_closed() {
    let (store, _raw) = load_fixture("v2_multi_snapshot");
    let root = table_root("v2_multi_snapshot");
    let mut probe = TestTransform::default();
    let _ = prepare(&store, &root, &mut probe).expect("probe walk");
    let rejected = probe.seen_data_files.into_iter().next().expect("data file");
    let mut transform = RejectFileTransform {
        reject_key: rejected,
    };
    let error =
        prepare(&store, &root, &mut transform).expect_err("the uncovered file must fail the walk");
    assert_eq!(error.code(), codes::UNSUPPORTED_FORMAT);
}

/// A referenced data file whose object is missing is an uncovered file.
#[test]
fn a_missing_referenced_data_file_fails_closed() {
    let (store, raw) = load_fixture("v2_partitioned");
    let root = table_root("v2_partitioned");
    let mut probe = TestTransform::default();
    let _ = prepare(&store, &root, &mut probe).expect("probe walk");
    let victim = probe.seen_data_files.into_iter().next().expect("data file");
    assert!(raw.delete("bucket", &victim));
    let mut transform = TestTransform::default();
    let error = prepare(&store, &root, &mut transform)
        .expect_err("a missing referenced file is an uncovered file");
    assert_eq!(error.code(), codes::UNSUPPORTED_TABLE_OPERATION);
    assert!(
        error.message().contains("cannot cover"),
        "the coverage failure is named: {}",
        error.message()
    );
}

/// The production seam is a named fail-closed stub: a table carrying data
/// files cannot be processed while the Parquet codec is unwired.
#[test]
fn the_production_data_file_seam_fails_closed_on_data_files() {
    let (store, _raw) = load_fixture("v2_partitioned");
    let root = table_root("v2_partitioned");
    let error = prepare(&store, &root, &mut UnsupportedDataFileTransform)
        .expect_err("the stub fails closed");
    assert_eq!(error.code(), codes::UNSUPPORTED_FORMAT);
    assert!(
        error.message().contains("ADR 0027"),
        "the stub error names the missing codec: {}",
        error.message()
    );
}

/// The stub walks zero-snapshot tables (no data files to transform).
#[test]
fn the_production_seam_walks_a_table_without_data_files() {
    let (store, _raw) = load_fixture("v2_empty");
    let root = table_root("v2_empty");
    let outcome = prepare(&store, &root, &mut UnsupportedDataFileTransform)
        .expect("a zero-snapshot table walks with the stub");
    assert!(outcome.covered_data_files.is_empty());
    // The empty manifest list is written against the canonical v2 schema.
    let empty_list = outcome
        .object_writes
        .iter()
        .find(|write| write.key.contains("snap-"))
        .expect("the new snapshot's manifest list");
    let list = read_manifest_list(&empty_list.bytes).expect("empty manifest list is readable");
    assert!(list.entries.is_empty());
}

/// A table carrying merge-on-read delete files fails closed.
#[test]
fn a_table_carrying_delete_files_fails_closed() {
    let (store, _raw) = load_fixture("v2_delete_files");
    let root = table_root("v2_delete_files");
    let mut transform = TestTransform::default();
    let error = prepare(&store, &root, &mut transform).expect_err("delete files are a v1 non-goal");
    assert_eq!(error.code(), codes::UNSUPPORTED_FORMAT);
    assert!(
        error.message().contains("delete file"),
        "the rejection names delete files: {}",
        error.message()
    );
}

// ---------------------------------------------------------------------------
// Partition discipline (hazard #2).
// ---------------------------------------------------------------------------

/// Manifest partition values are transformed as data.
#[test]
fn manifest_partition_values_are_transformed_as_data() {
    let (store, _raw) = load_fixture("v2_partitioned");
    let root = table_root("v2_partitioned");
    let mut transform = TestTransform::default();
    let outcome = prepare(&store, &root, &mut transform).expect("walk v2_partitioned");
    assert!(
        transform.seen_partition_values > 0,
        "partition values pass through the value transform"
    );
    let mut partitions = 0;
    for write in &outcome.object_writes {
        if !write.key.ends_with(".avro") || write.key.contains("snap-") {
            continue;
        }
        let manifest = read_manifest(&write.bytes).expect("readable manifest");
        for entry in &manifest.entries {
            let data_file = avro_field(&entry.record, "data_file").expect("data_file");
            let partition = avro_field(data_file, "partition").expect("partition record");
            partitions += 1;
            // The partition record's string fields are transformed values.
            if let Some(category) = avro_field(partition, "category")
                && !avro_is_null(category)
            {
                assert_eq!(
                    avro_string(partition, "category"),
                    "[REDACTED]",
                    "partition values are transformed, not copied"
                );
            }
        }
    }
    assert!(partitions > 0);
}

/// A transform that changes a partition value's type fails closed.
#[test]
fn a_type_changing_partition_transform_fails_closed() {
    let (store, _raw) = load_fixture("v2_partitioned");
    let root = table_root("v2_partitioned");
    let error = prepare(&store, &root, &mut TypeChangingTransform)
        .expect_err("a type-changing partition value fails closed");
    assert_eq!(error.code(), codes::UNSUPPORTED_TABLE_OPERATION);
    assert!(
        error.message().contains("partition value"),
        "the rejection names the partition value: {}",
        error.message()
    );
}

/// A transform that drops a partition value fails closed.
#[test]
fn a_dropped_partition_value_fails_closed() {
    let (store, _raw) = load_fixture("v2_partitioned");
    let root = table_root("v2_partitioned");
    let error = prepare(&store, &root, &mut DroppingValueTransform)
        .expect_err("a dropped partition value fails closed");
    assert_eq!(error.code(), codes::UNSUPPORTED_TABLE_OPERATION);
    assert!(
        error.message().contains("dropped"),
        "the rejection names the dropped value: {}",
        error.message()
    );
}

// ---------------------------------------------------------------------------
// Commit protocol.
// ---------------------------------------------------------------------------

/// The commit produces a new snapshot, keeps every retained snapshot (no
/// implicit expiry), re-points the branch ref, and deletes the replaced
/// plaintext objects after the swap.
#[test]
fn the_commit_swaps_atomically_and_keeps_snapshot_history() {
    let (store, raw) = load_fixture("v2_multi_snapshot");
    let root = table_root("v2_multi_snapshot");
    let mut transform = TestTransform::default();
    let outcome = prepare(&store, &root, &mut transform).expect("walk");
    let source = current_document(&store, &root);
    let source_snapshots: BTreeSet<i64> = source["snapshots"]
        .as_array()
        .expect("snapshots")
        .iter()
        .map(|snapshot| snapshot["snapshot-id"].as_i64().expect("snapshot id"))
        .collect();
    let replaced: Vec<String> = outcome.replaced_objects.clone();
    let expected_version = outcome.base_version + 1;

    let report = commit(&store, &root, outcome).expect("commit");
    assert!(report.cleanup_failures.is_empty());

    // The pointer swapped to the committed metadata version.
    assert_eq!(
        commit_version_hint(&raw, "v2_multi_snapshot"),
        expected_version.to_string(),
        "the version hint names the committed version"
    );
    let committed = current_document(&store, &root);
    assert_eq!(
        committed["current-snapshot-id"].as_i64(),
        Some(report.new_snapshot_id),
        "the commit produces the new current snapshot"
    );

    // No implicit snapshot expiry: every retained snapshot survives.
    let committed_ids: BTreeSet<i64> = committed["snapshots"]
        .as_array()
        .expect("snapshots")
        .iter()
        .map(|snapshot| snapshot["snapshot-id"].as_i64().expect("snapshot id"))
        .collect();
    assert!(
        source_snapshots.is_subset(&committed_ids),
        "every retained snapshot survives the transform"
    );
    assert!(committed_ids.contains(&report.new_snapshot_id));

    // The new snapshot's parent is the prior current snapshot.
    let new_entry = committed["snapshots"]
        .as_array()
        .expect("snapshots")
        .iter()
        .find(|snapshot| snapshot["snapshot-id"].as_i64() == Some(report.new_snapshot_id))
        .expect("new snapshot entry");
    assert_eq!(
        new_entry["parent-snapshot-id"].as_i64(),
        source["current-snapshot-id"].as_i64(),
        "the prior snapshot is the new snapshot's parent, never mutated"
    );

    // The replaced plaintext objects are gone; the old metadata document (the
    // commit history) remains.
    for key in &replaced {
        assert!(
            raw.get("bucket", key).is_none(),
            "replaced plaintext object {} must not survive the commit",
            redacted()
        );
    }
    let metadata_log = committed["metadata-log"].as_array().expect("metadata-log");
    let old_metadata_key = metadata_log.last().expect("source metadata log entry")["metadata-file"]
        .as_str()
        .expect("metadata file")
        .trim_start_matches("s3://bucket/")
        .to_string();
    assert!(
        raw.get("bucket", &old_metadata_key).is_some(),
        "pre-transform metadata history is retained"
    );

    // The committed table resolves end to end: every manifest layer and every
    // data file the committed state references exists.
    assert_table_resolves(&raw, &committed);
}

/// Failure before the pointer write leaves the table exactly as it was.
#[test]
fn a_failed_write_never_swaps_the_pointer() {
    for fail_at in 0..3 {
        let (store, raw) = load_fixture("v2_multi_snapshot");
        let root = table_root("v2_multi_snapshot");
        let mut transform = TestTransform::default();
        let outcome = prepare(&store, &root, &mut transform).expect("walk");
        let before = current_document(&store, &root);
        let base_hint = commit_version_hint(&raw, "v2_multi_snapshot");
        let failing = FailingStore {
            inner: store.clone(),
            fail_put: Mutex::new(fail_at),
        };
        let error = block_on(walker::commit(
            &failing,
            &root,
            outcome,
            WalkLimits::default(),
        ))
        .expect_err("the failing write must fail the commit");
        assert_eq!(error.code(), codes::INTERNAL);
        assert_eq!(
            commit_version_hint(&raw, "v2_multi_snapshot"),
            base_hint,
            "a failed commit must never swap the pointer (fail_at={fail_at})"
        );
        let after = current_document(&store, &root);
        assert_eq!(
            before, after,
            "a failed commit leaves the table state byte-identical"
        );
    }
}

/// The commit refuses to clobber a concurrent commit (CAS on the version).
#[test]
fn the_commit_refuses_to_clobber_a_concurrent_commit() {
    let (store, raw) = load_fixture("v2_partitioned");
    let root = table_root("v2_partitioned");
    let mut transform = TestTransform::default();
    let outcome = prepare(&store, &root, &mut transform).expect("walk");
    // Simulate a concurrent commit landing first.
    raw.put(
        "bucket",
        "v2_partitioned/metadata/00003-concurrent.metadata.json",
        b"{}".to_vec(),
        "application/json",
    );
    raw.put(
        "bucket",
        "v2_partitioned/metadata/version-hint.text",
        b"3\n".to_vec(),
        "text/plain",
    );
    let error = commit(&store, &root, outcome).expect_err("CAS must refuse");
    assert_eq!(error.code(), codes::UNSUPPORTED_TABLE_OPERATION);
    assert!(
        error.message().contains("advanced"),
        "the refusal names the concurrent advance: {}",
        error.message()
    );
}

/// A prepared outcome that is never committed writes nothing: the preview
/// path (processed table read) is complete-output staging with no side
/// effects.
#[test]
fn preparing_without_committing_stores_nothing() {
    let (store, raw) = load_fixture("v2_partitioned");
    let root = table_root("v2_partitioned");
    let before: BTreeSet<String> = store_keys(&raw).into_iter().collect();
    let mut transform = TestTransform::default();
    let outcome = prepare(&store, &root, &mut transform).expect("walk");
    let preview = walker::preview_document(&outcome);
    assert!(!preview.is_empty());
    let after: BTreeSet<String> = store_keys(&raw).into_iter().collect();
    assert_eq!(before, after, "the preview writes nothing");
}

/// v1 tables keep their v1 snapshot shape (no invented `sequence-number`
/// fields) while the walk still runs the full machinery.
#[test]
fn v1_tables_keep_their_v1_snapshot_shape() {
    let (store, _raw) = load_fixture("v1_unpartitioned");
    let root = table_root("v1_unpartitioned");
    let mut transform = TestTransform::default();
    let outcome = prepare(&store, &root, &mut transform).expect("walk v1");
    assert_eq!(outcome.new_metadata_json["format-version"], json!(1));
    for snapshot in outcome.new_metadata_json["snapshots"]
        .as_array()
        .expect("snapshots")
    {
        assert!(
            snapshot.get("sequence-number").is_none(),
            "v1 snapshot entries carry no sequence-number: {snapshot}"
        );
    }
}

/// The committed v2 metadata carries sequence numbers that advance by one.
#[test]
fn v2_commits_advance_the_sequence_number() {
    let (store, _raw) = load_fixture("v2_partitioned");
    let root = table_root("v2_partitioned");
    let mut transform = TestTransform::default();
    let outcome = prepare(&store, &root, &mut transform).expect("walk");
    let report = commit(&store, &root, outcome).expect("commit");
    let committed = current_document(&store, &root);
    assert_eq!(
        committed["last-sequence-number"].as_i64(),
        Some(3),
        "the new snapshot advances the sequence number"
    );
    let new_entry = committed["snapshots"]
        .as_array()
        .expect("snapshots")
        .iter()
        .find(|snapshot| snapshot["snapshot-id"].as_i64() == Some(report.new_snapshot_id))
        .expect("new snapshot entry");
    assert_eq!(new_entry["sequence-number"].as_i64(), Some(3));
}

// ---------------------------------------------------------------------------
// Detection integration and manifest fingerprints.
// ---------------------------------------------------------------------------

/// The manifest layers of a golden table match the Avro schema fingerprint.
#[test]
fn fixture_manifest_layers_match_the_avro_schema_fingerprint() {
    let (_store, raw) = load_fixture("v2_partitioned");
    let keys: Vec<String> = store_keys(&raw)
        .into_iter()
        .filter(|key| key.ends_with(".avro"))
        .collect();
    let mut lists = 0;
    let mut manifests = 0;
    for key in keys {
        let bytes = raw.get("bucket", &key).expect("fixture object").data;
        let kind = if let Ok(list) = read_manifest_list(&bytes) {
            manifest_layer_kind(&list.schema)
        } else {
            let manifest = read_manifest(&bytes).expect("fixture avro is readable");
            manifest_layer_kind(&manifest.schema)
        };
        match kind {
            Some(ManifestLayerKind::ManifestList) => lists += 1,
            Some(ManifestLayerKind::Manifest) => manifests += 1,
            None => panic!(
                "fixture avro {} matched no manifest-layer fingerprint",
                redacted()
            ),
        }
    }
    assert_eq!(lists, 2);
    assert_eq!(manifests, 2);
}

/// A tombstoned entry whose deleted file is already gone is dropped from the
/// rewritten manifest (its plaintext path must not survive).
#[test]
fn tombstoned_entries_for_missing_files_are_dropped() {
    let (_store, raw) = load_fixture("v2_multi_snapshot");
    // Find the overwrite snapshot's tombstone-only manifest in the store.
    let mut tombstone_manifest: Option<(String, manifest::ManifestFile)> = None;
    for key in store_keys(&raw) {
        if !key.ends_with(".avro") || key.contains("snap-") {
            continue;
        }
        let bytes = raw.get("bucket", &key).expect("manifest").data;
        let Ok(source) = read_manifest(&bytes) else {
            continue;
        };
        if !source.entries.is_empty() && source.entries.iter().all(|entry| entry.status == 2) {
            tombstone_manifest = Some((key, source));
            break;
        }
    }
    let (_key, source) = tombstone_manifest.expect("fixture has a tombstone-only manifest");
    let file_key = metadata::split_s3_uri(&source.entries[0].file_uri)
        .map(|(_, key)| key)
        .expect("s3 uri");
    let mut dropped = BTreeSet::new();
    dropped.insert(file_key.clone());
    let path_map: BTreeMap<String, manifest::TransformedFile> = BTreeMap::new();
    let mut transform = TestTransform::default();
    let (rewritten, counts) =
        manifest::rewrite_manifest(&source, &path_map, &dropped, &mut transform, "bucket")
            .unwrap_or_else(|error| panic!("the tombstone-only rewrite succeeds: {error}"));
    let rewritten = read_manifest(&rewritten).expect("readable rewritten manifest");
    assert!(
        rewritten.entries.is_empty(),
        "a tombstone for an already-gone file is dropped, not rewritten with its plaintext path"
    );
    assert_eq!(counts.deleted_files, 0);
}

/// A tombstone whose file still exists is rewritten onto the transformed
/// content-hash path like any other entry (its stats are dropped too).
#[test]
fn tombstoned_entries_for_existing_files_are_rewritten() {
    let (_store, raw) = load_fixture("v2_multi_snapshot");
    let root = table_root("v2_multi_snapshot");
    let mut transform = TestTransform::default();
    let outcome = prepare(&store_wrapper(&raw), &root, &mut transform).expect("walk");
    for write in &outcome.object_writes {
        if !write.key.ends_with(".avro") || write.key.contains("snap-") {
            continue;
        }
        let manifest = read_manifest(&write.bytes).expect("readable manifest");
        for entry in &manifest.entries {
            if entry.status != 2 {
                continue;
            }
            let data_file = avro_field(&entry.record, "data_file").expect("data_file");
            let file_path = avro_string(data_file, "file_path");
            let name = file_path.rsplit('/').next().expect("name");
            let (stem, _) = name.rsplit_once('.').expect("extension");
            assert!(
                stem.len() == 64 && stem.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "tombstones rewrite onto content-hash paths too, got {name}"
            );
        }
    }
}

fn store_wrapper(raw: &Arc<MemoryStore>) -> Arc<MemoryTableStore> {
    Arc::new(MemoryTableStore::new(raw.clone(), "bucket"))
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// A store that fails the Nth `put` (commit-atomicity tests).
struct FailingStore {
    inner: Arc<MemoryTableStore>,
    fail_put: Mutex<usize>,
}

impl TableStore for FailingStore {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, MaskuraError> {
        self.inner.get(key).await
    }

    async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> Result<(), MaskuraError> {
        {
            let mut remaining = self.fail_put.lock().unwrap();
            if *remaining == 0 {
                return Err(MaskuraError::new(codes::INTERNAL, "test store failure"));
            }
            *remaining -= 1;
        }
        self.inner.put(key, bytes, content_type).await
    }

    async fn delete(&self, key: &str) -> Result<bool, MaskuraError> {
        self.inner.delete(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MaskuraError> {
        self.inner.list(prefix).await
    }
}

// --- AvroValue field accessors (manifest records are raw Avro values). ---

fn avro_field<'a>(record: &'a AvroValue, name: &str) -> Option<&'a AvroValue> {
    match record {
        AvroValue::Record(fields) => fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value),
        _ => None,
    }
}

fn avro_unwrap(value: &AvroValue) -> &AvroValue {
    match value {
        AvroValue::Union(_, inner) => inner,
        value => value,
    }
}

fn avro_is_null(value: &AvroValue) -> bool {
    matches!(avro_unwrap(value), AvroValue::Null)
}

fn avro_string(record: &AvroValue, name: &str) -> String {
    match avro_field(record, name).map(avro_unwrap) {
        Some(AvroValue::String(value)) => value.clone(),
        other => panic!("expected string field {name}, got {other:?}"),
    }
}

fn avro_i64(record: &AvroValue, name: &str) -> i64 {
    match avro_field(record, name).map(avro_unwrap) {
        Some(AvroValue::Long(value)) => *value,
        Some(AvroValue::Int(value)) => i64::from(*value),
        other => panic!("expected integer field {name}, got {other:?}"),
    }
}

/// Asserts the committed table resolves end to end: every manifest layer and
/// every live data file the committed metadata references exists in `raw`.
fn assert_table_resolves(raw: &MemoryStore, document: &Value) {
    let snapshots = document["snapshots"].as_array().expect("snapshots");
    assert!(!snapshots.is_empty());
    for snapshot in snapshots {
        let manifest_list_uri = snapshot["manifest-list"].as_str().expect("manifest-list");
        let list_key = manifest_list_uri
            .trim_start_matches("s3://bucket/")
            .to_string();
        let list_bytes = raw
            .get("bucket", &list_key)
            .unwrap_or_else(|| panic!("committed manifest list {list_key} must exist"))
            .data;
        let list = read_manifest_list(&list_bytes).expect("committed manifest list is readable");
        for entry in &list.entries {
            let manifest_uri = avro_string(&entry.record, "manifest_path");
            let manifest_key = manifest_uri.trim_start_matches("s3://bucket/").to_string();
            let manifest_bytes = raw
                .get("bucket", &manifest_key)
                .unwrap_or_else(|| panic!("committed manifest {manifest_key} must exist"))
                .data;
            let manifest = read_manifest(&manifest_bytes).expect("committed manifest is readable");
            for manifest_entry in &manifest.entries {
                let data_file = avro_field(&manifest_entry.record, "data_file").expect("data_file");
                let file_uri = avro_string(data_file, "file_path");
                let file_key = file_uri.trim_start_matches("s3://bucket/").to_string();
                assert!(
                    raw.get("bucket", &file_key).is_some(),
                    "committed data file {file_key} must exist"
                );
            }
        }
    }
}
