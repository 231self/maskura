//! Structural + layout detection of Iceberg table units (ADR 0028 §2).
//!
//! Detection is conservative and never guesses:
//!
//! - **key shape** — the `metadata/` layout, `version-hint.text`,
//!   `*.metadata.json` naming, table-format extensions, and the Delta
//!   `_delta_log` marker;
//! - **content shape** — the table-metadata JSON signal set (`format-version`,
//!   `schemas`, `current-snapshot-id`, `snapshots`, `location`);
//! - **Avro schema fingerprint** — the manifest-list / manifest record names
//!   and required fields ([`manifest::manifest_layer_kind`]);
//! - **layout probe** — which table root (if any) encloses a key, discovered
//!   from the stored `metadata/` directories above it.
//!
//! Conflicting signals reject ([`merge_table_signals`]); Delta `_delta_log`
//! and Hive partition layouts fail closed as `unsupported.format` — they are
//! table layouts this v1 does not implement, and treating their files as
//! ordinary objects (or as Iceberg) would be guessing.

use maskura_error::MaskuraError;

use crate::iceberg::metadata::{
    TableRoot, metadata_file_version, table_root_for_metadata_key, unsupported_format,
    unsupported_table_operation,
};
use crate::iceberg::store::TableStore;

/// The most ancestors of a request key the layout probe walks.
const MAX_PROBE_DEPTH: usize = 8;

/// Key-shape signals observable without store access.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyShape {
    /// The key lives under a `metadata/` directory.
    pub metadata_dir: bool,
    /// The basename is `version-hint.text`.
    pub version_hint: bool,
    /// The basename is `<version>-*.metadata.json`.
    pub metadata_json_name: bool,
    /// The key lives under a `_delta_log/` directory (Delta Lake marker).
    pub delta_log_dir: bool,
    /// A path segment looks like a Hive partition (`field=value`).
    pub hive_partition_segment: bool,
    /// The basename carries a table data-file extension (avro/orc/parquet).
    pub table_format_extension: bool,
}

impl KeyShape {
    /// Whether the request could touch a table unit and must consult the
    /// table layer before any per-object dispatch.
    pub fn is_table_candidate(self) -> bool {
        self.metadata_dir
            || self.version_hint
            || self.metadata_json_name
            || self.delta_log_dir
            || self.table_format_extension
            || self.hive_partition_segment
    }
}

/// Classifies a request key's naming.
pub fn key_shape(key: &str) -> KeyShape {
    let segments: Vec<&str> = key.split('/').collect();
    let name = segments.last().copied().unwrap_or_default();
    let extension = name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase());
    let metadata_dir = segments.contains(&"metadata");
    KeyShape {
        metadata_dir,
        version_hint: name == "version-hint.text",
        metadata_json_name: metadata_dir
            && name.ends_with(".metadata.json")
            && metadata_file_version(key).is_some(),
        delta_log_dir: segments.contains(&"_delta_log"),
        // Hive partition layouts look like `field=value` *directories*; a
        // filename with `=` in it is not a partition signal.
        hive_partition_segment: segments[..segments.len().saturating_sub(1)]
            .iter()
            .any(|segment| segment.contains('=') && !segment.starts_with('=')),
        table_format_extension: matches!(
            extension.as_deref(),
            Some("avro") | Some("orc") | Some("parquet")
        ),
    }
}

/// Media types that claim table semantics (`application/vnd.apache.iceberg…`,
/// the manifest/data-file formats a table carries).
pub fn claims_table_media_type(content_type: Option<&str>) -> bool {
    let Some(content_type) = content_type else {
        return false;
    };
    let media = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media.starts_with("application/vnd.apache.iceberg")
        || matches!(
            media.as_str(),
            "application/avro"
                | "application/x-avro"
                | "application/vnd.apache.avro+binary"
                | "application/vnd.apache.parquet"
                | "application/x-parquet"
                | "application/vnd.apache.lance"
                | "application/x-lance"
                | "application/vnd.lance"
                | "application/vnd.apache.orc"
        )
}

/// What a processed request targets inside a table layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableTarget {
    /// The table root document: `<root>/metadata/<version>-*.metadata.json`.
    RootMetadata { root: TableRoot, version: u64 },
    /// A strict sub-unit of a table root: manifest layer, version pointer,
    /// data file, or any other object under the root. A processed operation
    /// on anything smaller than the table root fails closed.
    SubUnit { root: TableRoot },
    /// Not table-related.
    None,
}

/// Finds every table root whose `metadata/` directory encloses `key`.
///
/// Probes the bounded set of ancestor prefixes of `key`; a stored
/// `metadata/` directory holding `version-hint.text` or `*.metadata.json`
/// files is a table root. More than one enclosing root is a conflicting
/// signal (nested tables) and fails closed.
pub async fn enclosing_table_roots<S: TableStore>(
    store: &S,
    key: &str,
) -> Result<Vec<TableRoot>, MaskuraError> {
    let mut roots = Vec::new();
    let mut remainder = key;
    for _ in 0..MAX_PROBE_DEPTH {
        let Some((prefix, _rest)) = remainder.rsplit_once('/') else {
            break;
        };
        let metadata_prefix = format!("{prefix}/metadata/");
        let keys = store.list(&metadata_prefix).await?;
        let is_table_root = keys.iter().any(|candidate| {
            let name = candidate.rsplit('/').next().unwrap_or_default();
            name == "version-hint.text" || name.ends_with(".metadata.json")
        });
        if is_table_root {
            roots.push(TableRoot {
                bucket: String::new(),
                prefix: format!("{prefix}/"),
            });
        }
        remainder = prefix;
    }
    Ok(roots)
}

/// Classifies a processed request key against the stored table layout.
///
/// `claims_table` is true when the request's content type (or body) claims
/// table semantics; it tightens the Hive-layout rejection but never widens
/// what is accepted.
pub async fn classify_key<S: TableStore>(
    store: &S,
    bucket: &str,
    key: &str,
    claims_table: bool,
) -> Result<TableTarget, MaskuraError> {
    let shape = key_shape(key);
    if shape.delta_log_dir {
        return Err(unsupported_format(
            "Delta table layouts (_delta_log) are not supported; never guessed",
        ));
    }
    if shape.hive_partition_segment && claims_table {
        return Err(unsupported_format(
            "Hive table layouts (field=value partition directories) are not supported; never guessed",
        ));
    }

    let mut roots = enclosing_table_roots(store, key).await?;
    for root in &mut roots {
        root.bucket = bucket.to_string();
    }

    // A root-document name establishes its own root even before the layout
    // exists (the walk then fails closed if the table state is not there).
    if shape.metadata_json_name
        && let Some(named_root) = table_root_for_metadata_key(bucket, key)
        && let Some(version) = metadata_file_version(key)
    {
        if roots.iter().any(|root| root.prefix != named_root.prefix) {
            return Err(unsupported_table_operation(format!(
                "key {key:?} names a table root that conflicts with an enclosing table layout"
            )));
        }
        return Ok(TableTarget::RootMetadata {
            root: named_root,
            version,
        });
    }

    match roots.len() {
        0 => Ok(TableTarget::None),
        1 => Ok(TableTarget::SubUnit {
            root: roots.remove(0),
        }),
        _ => Err(unsupported_table_operation(format!(
            "key {key:?} is enclosed by {} table roots (nested tables); conflicting signals are rejected",
            roots.len()
        ))),
    }
}

/// The content-role signal used for conflict detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentRole {
    /// The bytes parse as a table metadata JSON document.
    TableMetadata,
    /// The bytes are something else.
    Other,
}

/// Merges the key-shape role with the content role; conflicts fail closed.
///
/// A root-document key whose content is not table metadata (or table metadata
/// at a non-root key) is exactly the "conflicting signals" case `merge_signal`
/// resolves in the record-format path — except here it rejects rather than
/// choosing a winner.
pub fn merge_table_signals(
    target: &TableTarget,
    content: ContentRole,
) -> Result<TableTarget, MaskuraError> {
    match (target, content) {
        (TableTarget::RootMetadata { .. }, ContentRole::TableMetadata) => Ok(target.clone()),
        (TableTarget::RootMetadata { .. }, ContentRole::Other) => Err(unsupported_table_operation(
            "key names a table metadata document but the content is not table metadata; conflicting signals are rejected",
        )),
        (TableTarget::SubUnit { .. }, ContentRole::TableMetadata) => {
            Err(unsupported_table_operation(
                "table metadata content at a table sub-unit key; conflicting signals are rejected",
            ))
        }
        (TableTarget::None, ContentRole::TableMetadata) => Err(unsupported_table_operation(
            "table metadata content outside any table layout; conflicting signals are rejected",
        )),
        (target, ContentRole::Other) => Ok(target.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iceberg::store::MemoryTableStore;
    use crate::store::MemoryStore;
    use std::sync::Arc;

    #[test]
    fn key_shapes_are_classified_structurally() {
        let root_doc = key_shape("t/metadata/00003-abc.metadata.json");
        assert!(
            root_doc.metadata_dir && root_doc.metadata_json_name && root_doc.is_table_candidate()
        );

        let hint = key_shape("t/metadata/version-hint.text");
        assert!(hint.metadata_dir && hint.version_hint);

        let manifest = key_shape("t/metadata/snap-1-0-x.avro");
        assert!(manifest.metadata_dir && manifest.table_format_extension);

        let data_file = key_shape("t/data/category=alpha/00000-0-x.parquet");
        assert!(data_file.table_format_extension);
        assert!(data_file.hive_partition_segment);
        assert!(!data_file.metadata_json_name);

        let plain = key_shape("logs/2024/x.jsonl");
        assert_eq!(plain, KeyShape::default());
        assert!(!plain.is_table_candidate());

        assert!(key_shape("db/_delta_log/00000000000000000001.json").delta_log_dir);
    }

    #[test]
    fn metadata_json_names_require_the_version_prefix() {
        assert!(key_shape("t/metadata/00001-x.metadata.json").metadata_json_name);
        assert!(!key_shape("t/metadata/x.metadata.json").metadata_json_name);
        assert!(!key_shape("t/data/00001-x.metadata.json").metadata_json_name);
    }

    #[tokio::test]
    async fn enclosing_roots_are_discovered_from_the_stored_layout() {
        let store = Arc::new(MemoryStore::new());
        store.put(
            "bucket",
            "t/metadata/00000-a.metadata.json",
            b"{}".to_vec(),
            "application/json",
        );
        let store = MemoryTableStore::new(store, "bucket");

        let roots = enclosing_table_roots(&store, "t/data/category=alpha/x.parquet")
            .await
            .expect("probe");
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].prefix, "t/");

        let roots = enclosing_table_roots(&store, "elsewhere/x.parquet")
            .await
            .expect("probe");
        assert!(roots.is_empty());
    }

    #[tokio::test]
    async fn sub_units_of_a_table_root_fail_closed_classification() {
        let store = Arc::new(MemoryStore::new());
        store.put(
            "bucket",
            "t/metadata/version-hint.text",
            b"0\n".to_vec(),
            "text/plain",
        );
        let store = MemoryTableStore::new(store, "bucket");

        for key in [
            "t/metadata/snap-1.avro",
            "t/metadata/00000-x.avro",
            "t/metadata/version-hint.text",
            "t/data/category=alpha/x.parquet",
            "t/anything.bin",
        ] {
            let target = classify_key(&store, "bucket", key, false)
                .await
                .expect("classify");
            assert!(
                matches!(&target, TableTarget::SubUnit { root } if root.prefix == "t/"),
                "{key} must classify as a table sub-unit, got {target:?}"
            );
        }

        let target = classify_key(&store, "bucket", "t/metadata/00001-x.metadata.json", true)
            .await
            .expect("classify");
        assert!(
            matches!(&target, TableTarget::RootMetadata { root, version: 1 } if root.prefix == "t/"),
            "the root document names its own root: {target:?}"
        );

        let target = classify_key(&store, "bucket", "logs/x.jsonl", false)
            .await
            .expect("classify");
        assert_eq!(target, TableTarget::None);
    }

    #[tokio::test]
    async fn delta_and_hive_layouts_fail_closed() {
        let store = MemoryTableStore::new(Arc::new(MemoryStore::new()), "bucket");
        let error = classify_key(&store, "bucket", "db/_delta_log/00001.json", false)
            .await
            .expect_err("Delta layouts fail closed");
        assert_eq!(error.code(), maskura_error::codes::UNSUPPORTED_FORMAT);

        let error = classify_key(&store, "bucket", "db/dt=2024-01-01/x.parquet", true)
            .await
            .expect_err("Hive layouts fail closed when table semantics are claimed");
        assert_eq!(error.code(), maskura_error::codes::UNSUPPORTED_FORMAT);

        // Without a table claim the same key is an ordinary object path.
        let target = classify_key(&store, "bucket", "db/dt=2024-01-01/x.parquet", false)
            .await
            .expect("classify");
        assert_eq!(target, TableTarget::None);
    }

    #[test]
    fn conflicting_signals_are_rejected_never_guessed() {
        let root = TableTarget::RootMetadata {
            root: TableRoot {
                bucket: "bucket".into(),
                prefix: "t/".into(),
            },
            version: 1,
        };
        assert!(merge_table_signals(&root, ContentRole::TableMetadata).is_ok());
        assert!(merge_table_signals(&root, ContentRole::Other).is_err());
        assert!(
            merge_table_signals(
                &TableTarget::SubUnit {
                    root: TableRoot {
                        bucket: "bucket".into(),
                        prefix: "t/".into(),
                    }
                },
                ContentRole::TableMetadata
            )
            .is_err()
        );
        assert!(merge_table_signals(&TableTarget::None, ContentRole::TableMetadata).is_err());
    }
}
