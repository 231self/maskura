//! Apache Iceberg table-format adapter (default-off, table-aware).
//!
//! Iceberg is not an object format — it is a **table format**: a metadata
//! tree (table metadata JSON → snapshot → manifest list → manifests → data
//! files) laid out across many objects. Applying per-object transforms to
//! Iceberg files is unsafe by construction (manifests carry plaintext column
//! statistics, files cross-reference each other, and paths and partition
//! values encode data), so this adapter is a table-aware layer over the file
//! codecs ([ADR 0028][adr]): the unit of work is the **table root**, data
//! files transform through the Parquet codec seam ([`data_file`]), manifests
//! are read with the shipped Avro stack and rewritten by [`manifest`], and
//! the commit is one atomic `version-hint` pointer swap producing a new
//! snapshot ([`walker`]).
//!
//! [adr]: https://github.com/231self/maskura/blob/main/docs/adr/0028-iceberg-table-format-adapter.md
//!
//! # Fail-closed surface
//!
//! Every rule below is a named error, never a guess:
//!
//! - a processed operation on anything smaller than the table root (one data
//!   file, one manifest, the version pointer) fails closed with
//!   `unsupported.table_operation`;
//! - a table the operation cannot cover in full (any data file of any
//!   retained snapshot missing or untransformable) fails closed before a byte
//!   is written;
//! - merge-on-read delete files, ORC data files, unknown `format-version`s,
//!   Delta `_delta_log` and Hive table layouts, table statistics files, and
//!   the un-wired Parquet data-file seam fail closed with
//!   `unsupported.format`;
//! - conflicting detection signals (root-document naming without table
//!   metadata content, nested table roots, duplicate metadata versions) fail
//!   closed rather than picking a winner.
//!
//! # Commit semantics (the ADR's "cover every retained snapshot" rule)
//!
//! The commit produces a **new snapshot** and never mutates the prior one: no
//! existing object is overwritten. Every data file referenced by **every
//! retained snapshot** is transformed, every retained snapshot is
//! *re-materialized* onto a rewritten manifest layer (same snapshot ids,
//! parents, and timestamps; new manifest-list objects), and the replaced
//! plaintext objects — data files and manifest layers — are deleted after the
//! pointer swap so no plaintext survives as a leak. Snapshot expiry stays an
//! explicit prior step: no retained snapshot entry is dropped here.
//!
//! Pre-transform metadata documents remain in the table's metadata history
//! (`metadata-log`) untouched; if a source writer embedded plaintext bounds
//! in *its* snapshot summaries, expire or rewrite that history explicitly
//! before running a transform.
//!
//! # Feature gate
//!
//! `MASKURA_ENABLE_ICEBERG` (→ `features.enable_iceberg` → the runtime
//! `binary_iceberg_enabled` state) is default-off. With the gate closed,
//! table-root writes are rejected 501 before the body is read and nothing is
//! stored; table-root reads are rejected without disclosing raw bytes. Raw
//! per-object GET/HEAD/byte-range reads stay *unprocessed* passthrough
//! regardless of the gate.

pub mod data_file;
pub mod detect;
pub mod manifest;
pub mod metadata;
pub mod store;
#[cfg(test)]
mod tests;
pub mod walker;

pub use data_file::{
    DataFileFormat, DataFileInput, DataFileTransform, TransformedDataFile,
    UnsupportedDataFileTransform,
};
pub use detect::{
    ContentRole, KeyShape, TableTarget, classify_key, key_shape, merge_table_signals,
};
pub use metadata::TableRoot;
pub use store::{BackendTableStore, FileTableStore, MemoryTableStore, S3TableStore, TableStore};
pub use walker::{
    CommitReport, TableOperation, TableOutcome, WalkLimits, commit, current_metadata,
    walk_and_prepare,
};
