//! The table walker and commit protocol (ADR 0028 §3–§6).
//!
//! The unit of work is the **table root**: the walk starts at the table
//! metadata document and descends snapshot → manifest list → manifests →
//! data files. Every data file referenced by **every retained snapshot** is
//! transformed (the v1 coverage rule — anything the operation cannot cover
//! fails closed before a byte is written), manifests are rewritten with
//! plaintext statistics dropped, and the commit is one atomic `version-hint`
//! pointer swap producing a new snapshot. The prior snapshot is never
//! mutated: every object the operation writes is new, and retained snapshots
//! are re-materialized onto the rewritten manifest layer so that covering
//! their files actually removes the plaintext.
//!
//! Post-swap cleanup deletes the replaced plaintext objects (data files and
//! manifest layers). Snapshot expiry is an explicit prior step, never an
//! implicit side effect: no retained snapshot entry is dropped here.

use std::collections::{BTreeMap, BTreeSet};

use maskura_error::{MaskuraError, codes};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::iceberg::data_file::{DataFileFormat, DataFileInput, DataFileTransform};
use crate::iceberg::manifest::{self, RewrittenManifest, TransformedFile};
use crate::iceberg::metadata::{
    self, MANIFEST_CONTENT_TYPE, METADATA_CONTENT_TYPE, TableMetadataView, TableRoot,
    VERSION_HINT_CONTENT_TYPE, parse_version_hint, unsupported_format, unsupported_table_operation,
    version_hint_body,
};
use crate::iceberg::store::TableStore;

/// Bounded walk budgets. Everything the walk reads or writes is capped; a
/// table beyond the budget fails closed rather than being partially covered.
#[derive(Debug, Clone, Copy)]
pub struct WalkLimits {
    /// Per-object read cap (metadata documents, manifests, data files).
    pub max_source_bytes: usize,
    /// Per-object write cap for transformed data files.
    pub max_output_bytes: usize,
    /// Maximum number of objects the walk may read.
    pub max_objects: usize,
}

impl Default for WalkLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 64 * 1024 * 1024,
            max_output_bytes: 64 * 1024 * 1024,
            max_objects: 10_000,
        }
    }
}

/// One object the operation writes.
#[derive(Debug, Clone)]
pub struct PendingWrite {
    pub key: String,
    pub bytes: Vec<u8>,
    pub content_type: &'static str,
}

/// The walk's inputs.
pub struct TableOperation<'a> {
    /// The table root (bucket + prefix) as addressed by the request.
    pub root: &'a TableRoot,
    /// The source metadata document (the walk's entry point).
    pub source_metadata: &'a Map<String, Value>,
    /// The source metadata document's store key (for `metadata-log`).
    pub source_metadata_key: &'a str,
    /// The metadata version the walk started from.
    pub base_version: u64,
    /// The version number of the metadata the commit will produce.
    pub new_version: u64,
    /// The committed metadata document's store key (the request key).
    pub new_metadata_key: &'a str,
    /// Naming token for new manifest-layer objects.
    pub token: &'a str,
    /// Commit timestamp for the new snapshot.
    pub timestamp_ms: i64,
}

/// The complete outcome of a table operation.
///
/// `object_writes` + `pointer_write` are the entire commit; `replaced_objects`
/// are the plaintext objects the commit deletes *after* the swap succeeds.
/// A preview (processed read) materializes the same outputs and discards
/// them — complete-output staging with nothing stored.
#[derive(Debug)]
pub struct TableOutcome {
    pub new_metadata_json: Value,
    pub new_snapshot_id: i64,
    pub object_writes: Vec<PendingWrite>,
    pub pointer_write: PendingWrite,
    pub replaced_objects: Vec<String>,
    pub covered_data_files: BTreeSet<String>,
    /// The version the pointer swap expects to find (the walk's base).
    pub base_version: u64,
}

/// The commit's report (post-swap cleanup is best-effort and auditable).
#[derive(Debug, Default)]
pub struct CommitReport {
    pub new_snapshot_id: i64,
    /// Replaced plaintext objects whose deletion failed; they remain in the
    /// bucket as unreachable orphans and must be retried by an operator.
    pub cleanup_failures: Vec<String>,
}

fn walk_error(message: impl Into<String>) -> MaskuraError {
    unsupported_table_operation(message)
}

async fn read_object<S: TableStore>(
    store: &S,
    key: &str,
    max_bytes: usize,
    read: &mut usize,
    limits: &WalkLimits,
) -> Result<Vec<u8>, MaskuraError> {
    if *read >= limits.max_objects {
        return Err(walk_error("table walk exceeds its object budget"));
    }
    *read += 1;
    let bytes = store
        .get(key)
        .await?
        .ok_or_else(|| walk_error(format!("table object {key:?} is missing")))?;
    if bytes.len() > max_bytes {
        return Err(MaskuraError::new(
            codes::LIMIT_INPUT_BYTES,
            format!("table object {key:?} exceeds its size limit"),
        ));
    }
    Ok(bytes)
}

/// Discover the current committed metadata document.
///
/// Resolution: `version-hint.text` when present, else the highest
/// `metadata/<version>-*.metadata.json` version. Two live metadata files
/// claiming the same version are a conflicting signal and fail closed.
pub async fn current_metadata<S: TableStore>(
    store: &S,
    root: &TableRoot,
    limits: WalkLimits,
) -> Result<(u64, String, Map<String, Value>), MaskuraError> {
    let metadata_prefix = format!("{}metadata/", root.prefix);
    let keys = store.list(&metadata_prefix).await?;
    let mut versions: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for key in keys {
        let Some(name) = key.rsplit('/').next() else {
            continue;
        };
        if name.ends_with(".metadata.json")
            && let Some(version) = metadata::metadata_file_version(&key)
        {
            versions.entry(version).or_default().push(key);
        }
    }

    let hinted = match store
        .get(&format!("{metadata_prefix}version-hint.text"))
        .await?
    {
        Some(body) => Some(parse_version_hint(&String::from_utf8_lossy(&body))?),
        None => None,
    };
    let version = match hinted {
        Some(version) => {
            if !versions.contains_key(&version) {
                return Err(walk_error(format!(
                    "version-hint.text names version {version}, but no matching metadata document exists"
                )));
            }
            version
        }
        None => *versions
            .keys()
            .next_back()
            .ok_or_else(|| walk_error("table has no metadata documents"))?,
    };
    let candidates = versions.get(&version).expect("version checked");
    if candidates.len() != 1 {
        return Err(walk_error(format!(
            "table has {} metadata documents for version {version}; conflicting signals are rejected",
            candidates.len()
        )));
    }
    let key = candidates[0].clone();
    let mut reads = 0;
    let bytes = read_object(store, &key, limits.max_source_bytes, &mut reads, &limits).await?;
    let document = metadata::parse_json_document(&bytes, limits.max_source_bytes)?;
    Ok((version, key, document))
}

/// Everything the walk learned about one source manifest.
struct ManifestWork {
    key: String,
    source: manifest::ManifestFile,
}

/// Runs the full table walk and prepares the commit.
///
/// Nothing is written here: the outcome carries the complete output set
/// (transformed data files, rewritten manifest layers, the committed
/// metadata document) and the atomic `version-hint` pointer write.
pub async fn walk_and_prepare<S: TableStore, D: DataFileTransform>(
    store: &S,
    transform: &mut D,
    operation: &TableOperation<'_>,
    limits: WalkLimits,
) -> Result<TableOutcome, MaskuraError> {
    let view = TableMetadataView::parse(operation.source_metadata)?;
    let source_map = operation.source_metadata;
    // The document must describe the table the request addresses — never
    // guess at a relocation.
    let location_key = operation.root.key_from_uri(&view.location)?;
    if location_key.trim_end_matches('/') != operation.root.prefix.trim_end_matches('/') {
        return Err(walk_error(format!(
            "table metadata location {} does not name the table root {}/{}",
            view.location, operation.root.bucket, operation.root.prefix
        )));
    }

    let mut reads = 0_usize;

    // ---- Phase 1: enumerate every retained snapshot's manifest layer. ----
    // Coverage is defined over *all* retained snapshots: a file only the old
    // snapshots reference is still plaintext the operation must replace.
    struct SnapshotLayer {
        manifest_list_key: String,
        manifest_list: manifest::ManifestListFile,
        manifest_keys: Vec<String>,
    }
    let mut snapshot_layers: Vec<SnapshotLayer> = Vec::with_capacity(view.snapshots.len());
    let mut manifest_work: BTreeMap<String, ManifestWork> = BTreeMap::new();
    for snapshot in &view.snapshots {
        let manifest_list_key = operation.root.key_from_uri(&snapshot.manifest_list)?;
        let bytes = read_object(
            store,
            &manifest_list_key,
            limits.max_source_bytes,
            &mut reads,
            &limits,
        )
        .await?;
        let manifest_list = manifest::read_manifest_list(&bytes)?;
        let mut manifest_keys = Vec::with_capacity(manifest_list.entries.len());
        for entry in &manifest_list.entries {
            let manifest_key = operation.root.key_from_uri(&entry.manifest_uri)?;
            manifest_keys.push(manifest_key.clone());
            if manifest_work.contains_key(&manifest_key) {
                continue;
            }
            let bytes = read_object(
                store,
                &manifest_key,
                limits.max_source_bytes,
                &mut reads,
                &limits,
            )
            .await?;
            let source = manifest::read_manifest(&bytes)?;
            manifest_work.insert(
                manifest_key.clone(),
                ManifestWork {
                    key: manifest_key,
                    source,
                },
            );
        }
        snapshot_layers.push(SnapshotLayer {
            manifest_list_key,
            manifest_list,
            manifest_keys,
        });
    }

    // ---- Phase 2: the coverage set and the data-file seam. ----
    // Every referenced file of every retained snapshot must exist and
    // transform; anything else fails closed before any output is produced.
    let mut source_files: BTreeMap<String, (DataFileFormat, u64, bool)> = BTreeMap::new();
    for work in manifest_work.values() {
        for entry in &work.source.entries {
            if entry.data_file_content != 0 {
                return Err(unsupported_format(format!(
                    "table carries a merge-on-read delete file ({}); delete files are a v1 non-goal and fail closed",
                    entry.file_uri
                )));
            }
            let format = DataFileFormat::parse(&entry.file_format).ok_or_else(|| {
                unsupported_format(format!(
                    "data file {} has unsupported format {:?}; ORC and other non-Avro/Parquet files are v1 non-goals",
                    entry.file_uri, entry.file_format
                ))
            })?;
            let key = operation.root.key_from_uri(&entry.file_uri)?;
            let slot =
                source_files
                    .entry(key)
                    .or_insert((format, entry.record_count as u64, false));
            slot.2 |= entry.status != 2;
        }
    }

    let mut path_map: BTreeMap<String, TransformedFile> = BTreeMap::new();
    let mut data_file_writes: BTreeMap<String, PendingWrite> = BTreeMap::new();
    let mut dropped_tombstones: BTreeSet<String> = BTreeSet::new();
    for (key, (format, record_count, live)) in &source_files {
        let bytes = match store.get(key).await? {
            Some(bytes) => bytes,
            None if !*live => {
                // Only tombstones reference this file and it is already gone:
                // no reader needs a tombstone for a missing object, and its
                // plaintext path must not survive in a rewritten manifest.
                dropped_tombstones.insert(key.clone());
                continue;
            }
            None => {
                return Err(walk_error(format!(
                    "retained snapshot references data file {key:?} that the operation cannot cover: the object is missing"
                )));
            }
        };
        if bytes.len() > limits.max_source_bytes {
            return Err(MaskuraError::new(
                codes::LIMIT_INPUT_BYTES,
                format!("table object {key:?} exceeds its size limit"),
            ));
        }
        let transformed = transform.transform_data_file(DataFileInput {
            key,
            format: *format,
            record_count: *record_count,
            bytes: &bytes,
            max_output_bytes: limits.max_output_bytes,
        })?;
        if transformed.bytes.len() > limits.max_output_bytes {
            return Err(MaskuraError::new(
                codes::LIMIT_OUTPUT_BYTES,
                format!("transformed data file {key:?} exceeds its size limit"),
            ));
        }
        // Output path discipline: content hash of the transformed bytes —
        // no value-derived path components survive into the rewritten table.
        let digest = hex::encode(Sha256::digest(&transformed.bytes));
        let output_key = format!(
            "{}data/{}.{}",
            operation.root.prefix,
            digest,
            format.extension()
        );
        // Identical transformed outputs share one content-addressed object.
        data_file_writes
            .entry(output_key.clone())
            .or_insert_with(|| PendingWrite {
                key: output_key.clone(),
                bytes: transformed.bytes.clone(),
                content_type: "application/octet-stream",
            });
        path_map.insert(
            key.clone(),
            TransformedFile {
                key: output_key,
                size: transformed.bytes.len() as u64,
                record_count: transformed.record_count,
                format: *format,
            },
        );
    }

    // ---- Phase 3: rewrite every manifest layer. ----
    let mut object_writes: Vec<PendingWrite> = Vec::new();
    for write in data_file_writes.into_values() {
        object_writes.push(write);
    }
    let mut replaced_objects: Vec<String> = Vec::new();

    let mut rewritten_manifests: BTreeMap<String, RewrittenManifest> = BTreeMap::new();
    for work in manifest_work.values_mut() {
        let (rewritten, counts) = manifest::rewrite_manifest(
            &work.source,
            &path_map,
            &dropped_tombstones,
            transform,
            &operation.root.bucket,
        )?;
        let key = format!(
            "{}metadata/{}.avro",
            operation.root.prefix,
            operation.token_for(&work.key)?
        );
        rewritten_manifests.insert(
            work.key.clone(),
            RewrittenManifest {
                length: rewritten.len() as u64,
                key: key.clone(),
                counts,
            },
        );
        replaced_objects.push(work.key.clone());
        object_writes.push(PendingWrite {
            key,
            bytes: rewritten,
            content_type: MANIFEST_CONTENT_TYPE,
        });
    }

    // Per-snapshot totals and re-materialized manifest lists.
    #[derive(Clone, Copy)]
    struct LayerTotals {
        data_files: u64,
        records: u64,
        files_size: u64,
    }
    let mut layer_lists: Vec<(String, LayerTotals)> = Vec::new();
    for (snapshot, layer) in view.snapshots.iter().zip(&snapshot_layers) {
        let rewritten: Vec<RewrittenManifest> = layer
            .manifest_keys
            .iter()
            .map(|key| {
                rewritten_manifests
                    .get(key)
                    .map(|manifest| RewrittenManifest {
                        key: manifest.key.clone(),
                        length: manifest.length,
                        counts: manifest.counts,
                    })
                    .ok_or_else(|| walk_error("manifest rewrite lost a manifest"))
            })
            .collect::<Result<_, _>>()?;
        let list_bytes = manifest::rewrite_manifest_list(
            &layer.manifest_list,
            &rewritten,
            &operation.root.bucket,
        )?;
        let list_key = format!(
            "{}metadata/snap-{}-{}.avro",
            operation.root.prefix, snapshot.snapshot_id, operation.token
        );
        let mut totals = LayerTotals {
            data_files: 0,
            records: 0,
            files_size: 0,
        };
        for manifest_key in &layer.manifest_keys {
            let work = manifest_work
                .get(manifest_key)
                .expect("manifest was collected");
            for entry in &work.source.entries {
                if entry.status == 2 {
                    continue;
                }
                let entry_key = crate::iceberg::metadata::split_s3_uri(&entry.file_uri)
                    .map(|(_, key)| key)
                    .unwrap_or_else(|| entry.file_uri.clone());
                let Some(transformed) = path_map.get(&entry_key) else {
                    continue;
                };
                totals.data_files += 1;
                totals.records += transformed.record_count;
                totals.files_size += transformed.size;
            }
        }
        replaced_objects.push(layer.manifest_list_key.clone());
        object_writes.push(PendingWrite {
            key: list_key.clone(),
            bytes: list_bytes,
            content_type: MANIFEST_CONTENT_TYPE,
        });
        layer_lists.push((list_key, totals));
    }

    // ---- Phase 4: the new snapshot and the committed metadata document. ----
    let new_snapshot_id = loop {
        let candidate = (rand::random::<u64>() >> 1) as i64;
        if candidate != 0 && !view.snapshots.iter().any(|s| s.snapshot_id == candidate) {
            break candidate;
        }
    };
    let new_snapshot_sequence = view.last_sequence_number + 1;

    let rewritten_snapshots: Vec<metadata::RewrittenSnapshot> = view
        .snapshots
        .iter()
        .zip(&layer_lists)
        .map(
            |(snapshot, (list_key, totals))| metadata::RewrittenSnapshot {
                snapshot_id: snapshot.snapshot_id,
                parent_snapshot_id: snapshot.parent_snapshot_id,
                sequence_number: snapshot.sequence_number.unwrap_or(0),
                timestamp_ms: snapshot.timestamp_ms,
                manifest_list_key: list_key.clone(),
                summary: metadata::rewritten_summary(
                    &metadata::summary_operation(&snapshot.summary),
                    totals.data_files,
                    totals.records,
                    totals.files_size,
                ),
                schema_id: Some(snapshot.schema_id.unwrap_or(view.current_schema_id)),
            },
        )
        .collect();

    // The new snapshot's state is the transformed current state: it shares
    // the re-materialized current snapshot's manifest list.
    let current_layer = view
        .current_snapshot_id
        .and_then(|current| {
            view.snapshots
                .iter()
                .position(|snapshot| snapshot.snapshot_id == current)
        })
        .map(|index| &layer_lists[index])
        .map(|(key, totals)| (key.clone(), *totals))
        .unwrap_or((
            String::new(),
            LayerTotals {
                data_files: 0,
                records: 0,
                files_size: 0,
            },
        ));

    let (new_manifest_list_key, new_totals) = if current_layer.0.is_empty() {
        // A zero-snapshot table: the new snapshot carries an empty manifest
        // list written against the canonical spec schema.
        let bytes = manifest::write_empty_manifest_list(view.format_version)?;
        let key = format!(
            "{}metadata/snap-{}-{}.avro",
            operation.root.prefix, new_snapshot_id, operation.token
        );
        object_writes.push(PendingWrite {
            key: key.clone(),
            bytes,
            content_type: MANIFEST_CONTENT_TYPE,
        });
        (
            key,
            LayerTotals {
                data_files: 0,
                records: 0,
                files_size: 0,
            },
        )
    } else {
        current_layer
    };

    let new_summary = metadata::rewritten_summary(
        "replace",
        new_totals.data_files,
        new_totals.records,
        new_totals.files_size,
    );
    let new_metadata_json = metadata::build_committed_metadata(
        source_map,
        &view,
        &operation.root.bucket,
        &rewritten_snapshots,
        new_snapshot_id,
        new_snapshot_sequence,
        operation.timestamp_ms,
        &new_manifest_list_key,
        new_summary,
        operation.source_metadata_key,
    );

    object_writes.push(PendingWrite {
        key: operation.new_metadata_key.to_string(),
        bytes: serde_json::to_vec(&new_metadata_json).map_err(|error| {
            MaskuraError::new(codes::INTERNAL, format!("metadata serialization: {error}"))
        })?,
        content_type: METADATA_CONTENT_TYPE,
    });

    let pointer_write = PendingWrite {
        key: format!("{}metadata/version-hint.text", operation.root.prefix),
        bytes: version_hint_body(operation.new_version).into_bytes(),
        content_type: VERSION_HINT_CONTENT_TYPE,
    };

    for source_key in source_files.keys() {
        if dropped_tombstones.contains(source_key) {
            continue;
        }
        replaced_objects.push(source_key.clone());
    }
    replaced_objects.sort();
    replaced_objects.dedup();

    Ok(TableOutcome {
        new_metadata_json,
        new_snapshot_id,
        object_writes,
        pointer_write,
        replaced_objects,
        covered_data_files: source_files.keys().cloned().collect(),
        base_version: operation.base_version,
    })
}

impl TableOperation<'_> {
    /// Deterministic per-source-manifest naming token for rewritten objects.
    fn token_for(&self, source_manifest_key: &str) -> Result<String, MaskuraError> {
        let digest = Sha256::digest(format!("{}:{}", self.token, source_manifest_key));
        Ok(hex::encode(&digest[..16]))
    }
}

/// Commits a prepared outcome: writes every object, swaps the pointer once,
/// then deletes the replaced plaintext objects.
///
/// Failure before the pointer write leaves the table exactly as it was (the
/// old state stays authoritative; partially written new objects are orphans).
/// The swap re-checks the base version first so a concurrent commit cannot be
/// silently clobbered.
pub async fn commit<S: TableStore>(
    store: &S,
    root: &TableRoot,
    outcome: TableOutcome,
    limits: WalkLimits,
) -> Result<CommitReport, MaskuraError> {
    // CAS, pre-write: the commit refuses to run against a table that moved
    // since the walk started.
    let (current_version, ..) = current_metadata(store, root, limits).await?;
    if current_version != outcome.base_version {
        return Err(walk_error(format!(
            "table advanced to version {current_version} while the operation ran (expected {}); the commit is refused",
            outcome.base_version
        )));
    }

    for write in &outcome.object_writes {
        store
            .put(&write.key, write.bytes.clone(), write.content_type)
            .await?;
    }

    // CAS, pre-swap: the `version-hint` pointer is the atomic commit point;
    // re-read it immediately before swapping so a concurrent commit is never
    // silently clobbered. (Tables without a hint yet have no pointer to race
    // over; the pre-write check above covered the state.)
    let hint_key = &outcome.pointer_write.key;
    if let Some(body) = store.get(hint_key).await? {
        let current_hint = parse_version_hint(&String::from_utf8_lossy(&body))?;
        if current_hint != outcome.base_version {
            return Err(walk_error(format!(
                "table advanced to version {current_hint} while the operation ran (expected {}); the commit is refused",
                outcome.base_version
            )));
        }
    }
    store
        .put(
            &outcome.pointer_write.key,
            outcome.pointer_write.bytes.clone(),
            outcome.pointer_write.content_type,
        )
        .await?;

    // Post-swap cleanup: the plaintext objects this commit replaced must not
    // survive. Failures are collected, not hidden.
    let mut cleanup_failures = Vec::new();
    for key in &outcome.replaced_objects {
        if store.delete(key).await.is_err() {
            cleanup_failures.push(key.clone());
        }
    }

    Ok(CommitReport {
        new_snapshot_id: outcome.new_snapshot_id,
        cleanup_failures,
    })
}

/// Serialized committed metadata for preview responses.
pub fn preview_document(outcome: &TableOutcome) -> Vec<u8> {
    serde_json::to_vec(&outcome.new_metadata_json).unwrap_or_default()
}
