//! The Iceberg data-file seam: "transform one data file".
//!
//! The table walker ([`crate::iceberg::walker`]) never decodes data files
//! itself. It hands each referenced data file's bytes to this seam and
//! rewrites the manifest layer from the reported output facts. The production
//! implementation is the Parquet format adapter ([ADR 0027][parquet-adr]),
//! which is not wired yet; until it lands, [`UnsupportedDataFileTransform`]
//! fails every data file closed with `unsupported.format`, so the metadata
//! machinery (detection, walk, statistics scrub, commit) is exercised with
//! fixtures and test seams only.
//!
//! [parquet-adr]: https://github.com/231self/maskura/blob/main/docs/adr/0027-parquet-format-adapter.md
//!
//! # Contract
//!
//! A transform implementation must:
//!
//! - produce output bytes for the *same* logical table schema (Iceberg v1
//!   tables are schema-preserving through a transform; a schema-changing
//!   transform fails closed at this seam and the manifest rewrite re-validates
//!   the produced partition values against the declared partition schema);
//! - report the output file's true `record_count` (row-filtering transforms
//!   change it, and the rewritten manifest must not copy the source count);
//! - never report source column statistics. The manifest rewrite drops
//!   `lower_bounds`/`upper_bounds`/`value_counts`/`null_value_counts`/
//!   `column_sizes` unconditionally (Iceberg permits null bounds); carrying
//!   plaintext bounds into a rewritten manifest is the leak ADR 0028 forbids.
//!
//! [`transform_value`](DataFileTransform::transform_value) carries logical
//! values that live *outside* data files — the manifest `partition` tuple —
//! through the same policy transform as data ("manifest `partition` values are
//! transformed as data, not metadata").

use maskura_error::{MaskuraError, codes};

use crate::binary_ir::{SchemaIr, ValueIr};

/// The data-file formats the v1 table walk accepts.
///
/// ORC is an explicit ADR 0028 non-goal; a table referencing an ORC data file
/// fails closed with `unsupported.format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFileFormat {
    Avro,
    Parquet,
}

impl DataFileFormat {
    /// Parses the Iceberg `data_file.file_format` string.
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "AVRO" => Some(Self::Avro),
            "PARQUET" => Some(Self::Parquet),
            _ => None,
        }
    }

    /// The output object's extension: transforms are format-preserving.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Avro => "avro",
            Self::Parquet => "parquet",
        }
    }
}

/// One referenced data file handed to the seam.
#[derive(Debug, Clone, Copy)]
pub struct DataFileInput<'a> {
    /// The table-relative source object key (for error messages).
    pub key: &'a str,
    pub format: DataFileFormat,
    /// The manifest's declared record count for the source file.
    pub record_count: u64,
    /// The source file's bytes.
    pub bytes: &'a [u8],
    /// Upper bound for the produced output.
    pub max_output_bytes: usize,
}

/// The transformed data file plus the facts the manifest rewrite needs.
#[derive(Debug, Clone)]
pub struct TransformedDataFile {
    pub bytes: Vec<u8>,
    /// The output file's true record count after the transform.
    pub record_count: u64,
}

/// "Transform one data file" over a format codec (Parquet in production).
pub trait DataFileTransform {
    /// Transform one data file's stored bytes into its output representation.
    fn transform_data_file(
        &mut self,
        input: DataFileInput<'_>,
    ) -> Result<TransformedDataFile, MaskuraError>;

    /// Transform one logical value carried as data outside data files (the
    /// manifest `partition` tuple).
    ///
    /// Returning `None` (a record-filtering transform dropping the value) is a
    /// closed failure at this layer: a dropped partition value cannot be
    /// represented in a manifest entry, so the walk fails closed instead of
    /// writing a partition tuple that no longer describes the file.
    fn transform_value(
        &mut self,
        value: ValueIr,
        schema: &SchemaIr,
    ) -> Result<Option<ValueIr>, MaskuraError>;
}

/// The production fail-closed stub.
///
/// Every data file and every partition value is rejected with the named
/// `unsupported.format` error until the Parquet codec (ADR 0027) is wired
/// behind this seam. The table walk reaches this stub before it writes or
/// commits anything, so a table carrying data files cannot be processed
/// end-to-end while the stub stands — by design.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedDataFileTransform;

impl DataFileTransform for UnsupportedDataFileTransform {
    fn transform_data_file(
        &mut self,
        input: DataFileInput<'_>,
    ) -> Result<TransformedDataFile, MaskuraError> {
        Err(MaskuraError::new(
            codes::UNSUPPORTED_FORMAT,
            format!(
                "Iceberg data file {} cannot be transformed: the Parquet data-file codec (ADR 0027) is not wired yet",
                input.key
            ),
        ))
    }

    fn transform_value(
        &mut self,
        _value: ValueIr,
        _schema: &SchemaIr,
    ) -> Result<Option<ValueIr>, MaskuraError> {
        Err(MaskuraError::new(
            codes::UNSUPPORTED_FORMAT,
            "Iceberg partition values cannot be transformed: the Parquet data-file codec (ADR 0027) is not wired yet",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_file_format_parses_only_avro_and_parquet() {
        assert_eq!(
            DataFileFormat::parse("PARQUET"),
            Some(DataFileFormat::Parquet)
        );
        assert_eq!(DataFileFormat::parse("avro"), Some(DataFileFormat::Avro));
        assert_eq!(DataFileFormat::parse("ORC"), None);
        assert_eq!(DataFileFormat::parse(""), None);
    }

    #[test]
    fn the_stub_fails_closed_with_the_named_unsupported_format_error() {
        let mut stub = UnsupportedDataFileTransform;
        let error = stub
            .transform_data_file(DataFileInput {
                key: "t/data/x.parquet",
                format: DataFileFormat::Parquet,
                record_count: 1,
                bytes: b"PAR1",
                max_output_bytes: 1024,
            })
            .expect_err("the stub must fail closed");
        assert_eq!(error.code(), codes::UNSUPPORTED_FORMAT);
        assert!(
            error.message().contains("t/data/x.parquet"),
            "the error names the uncovered file: {}",
            error.message()
        );

        let error = stub
            .transform_value(
                ValueIr::new(crate::binary_ir::Value::String { value: "x".into() }),
                &SchemaIr::new(crate::binary_ir::SchemaNode::required(
                    crate::binary_ir::SchemaKind::String,
                )),
            )
            .expect_err("the stub must fail closed for values too");
        assert_eq!(error.code(), codes::UNSUPPORTED_FORMAT);
    }
}
