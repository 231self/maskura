//! Apache Lance file conversion at the binary-codec boundary.
//!
//! This module mirrors [`crate::avro`]: it intentionally has no HTTP or storage
//! dependency. Callers stream decoded values through the typed binary pump and
//! only commit encoded output after the pump succeeds. No Lance-specific type
//! crosses this module's public surface; decode and encode target the
//! normalized [`crate::binary_ir`] schema/value contract.
//!
//! # Container
//!
//! The codec reads and writes the Lance v2 container: a body of page buffers,
//! column-metadata protobufs, a column-metadata offset table, a global-buffer
//! offset table (global buffer 0 is the schema), and a fixed 40-byte footer
//! carrying the layout offsets, the column and global-buffer counts, the file
//! version pair, and the trailing `LANC` magic. There is **no head magic**:
//! real Lance files begin directly with page data, so conservative detection
//! validates the magic/version footer and the footer structure instead (see
//! [`validate_magic_footer`]).
//!
//! # Page grammars
//!
//! Page encodings are self-describing (`google.protobuf.Any`). The codec
//! implements two documented, deterministic subsets and fails closed on
//! everything else:
//!
//! * the legacy `lance.encodings` array-encoding grammar of Lance v2.0 files
//!   (`Flat`, `Nullable`, `Binary`, `List`, `FixedSizeList`, `SimpleStruct`)
//!   — decoded, so uploads of v2.0 files can be processed;
//! * the `lance.encodings21` structural pages of Lance v2.1/v2.2 files
//!   (`MiniBlockLayout` with flat/variable value compression,
//!   `ConstantLayout`, and `FullZipLayout` pages without control words) —
//!   decoded and encoded. All output uses this grammar (the legacy grammar
//!   cannot represent nullable structs, which envelope encryption produces).
//!
//! Dictionary, FSST, RLE, bitpacked, general-compression, blob, and planar
//! (2.3) encodings are rejected with a named error rather than guessed at.
//!
//! # Dataset versions
//!
//! A Lance dataset revision is opaque bytes within one object version. This
//! codec treats every input as one self-contained file: it never maps dataset
//! versions onto object versions and never performs cross-file reads.

use std::io::Read;

use chrono::{DateTime, Duration, NaiveDate, NaiveTime, Timelike, Utc};
use maskura_error::{MaskuraError, codes};

use crate::binary_ir::{
    BinaryIrLimits, SchemaField, SchemaIr, SchemaKind, SchemaNode, Value, ValueField, ValueIr,
};
use crate::binary_pump::{BinaryPump, BinaryTransform};
use crate::binary_reductor::BinaryReductor;
use crate::lance_wire::{
    AnyMessage, BufferRef, ColumnMetadataMessage, EncodingMessage, FieldMessage, FileDescriptor,
    LegacyArrayEncoding, LegacyNullable, PageMessage, SchemaMessage, decode_packed_u32,
    write_bytes_field, write_packed_u64_field, write_varint_field,
};

pub const DEFAULT_MAX_LANCE_SOURCE_BYTES: usize = 64 * 1024 * 1024;

/// The `LANC` magic at the tail of every Lance file.
pub const LANCE_MAGIC: &[u8; 4] = b"LANC";

/// The length of the v2 container footer.
pub const LANCE_FOOTER_LEN: usize = 40;

const LEGACY_ARRAY_ENCODING: &str = "/lance.encodings.ArrayEncoding";
const COLUMN_ENCODING: &str = "/lance.encodings.ColumnEncoding";
const STRUCTURAL_PAGE_LAYOUT: &str = "/lance.encodings21.PageLayout";

#[derive(Clone, Copy, Debug)]
pub struct LanceLimits {
    pub max_source_bytes: usize,
    pub ir: BinaryIrLimits,
}

impl Default for LanceLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: DEFAULT_MAX_LANCE_SOURCE_BYTES,
            ir: BinaryIrLimits::default(),
        }
    }
}

fn unsupported(message: impl Into<String>) -> MaskuraError {
    MaskuraError::new(codes::UNSUPPORTED_FORMAT, message)
}

fn validate_limits(limits: LanceLimits) -> Result<(), MaskuraError> {
    if limits.max_source_bytes == 0 {
        return Err(MaskuraError::new(
            codes::CONFIG_INVALID,
            "Lance source byte limit must be greater than zero",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Container
// ---------------------------------------------------------------------------

/// Parsed v2 container footer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LanceFooter {
    pub column_meta_start: u64,
    pub column_meta_offsets_start: u64,
    pub global_buffer_offsets_start: u64,
    pub num_global_buffers: u32,
    pub num_columns: u32,
    pub major_version: u16,
    pub minor_version: u16,
}

/// Validates the magic/version footer every Lance file carries.
///
/// Detection is deliberately conservative: the tail magic must match exactly,
/// the file must be long enough to hold the footer and its tables, and the
/// version pair must be one the ecosystem recognizes. Unknown versions and
/// inconsistent footer offsets are rejected rather than guessed at.
pub fn validate_magic_footer(source: &[u8]) -> Result<LanceFooter, MaskuraError> {
    if source.len() < LANCE_FOOTER_LEN {
        return Err(unsupported(
            "Lance file is too small to contain a file footer",
        ));
    }
    let footer = parse_footer(&source[source.len() - LANCE_FOOTER_LEN..])?;
    if is_legacy_v1_footer(footer.major_version, footer.minor_version) {
        return Err(unsupported(
            "Lance v1 files use a legacy container this codec does not decode",
        ));
    }
    validate_footer(&footer, source.len())?;
    Ok(footer)
}

fn parse_footer(raw: &[u8]) -> Result<LanceFooter, MaskuraError> {
    if raw.len() != LANCE_FOOTER_LEN {
        return Err(unsupported("Lance file footer has the wrong size"));
    }
    if &raw[LANCE_FOOTER_LEN - 4..] != LANCE_MAGIC {
        return Err(unsupported("Lance file footer magic does not match"));
    }
    let read_u64 = |offset: usize| {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&raw[offset..offset + 8]);
        u64::from_le_bytes(bytes)
    };
    let read_u32 = |offset: usize| {
        let mut bytes = [0_u8; 4];
        bytes.copy_from_slice(&raw[offset..offset + 4]);
        u32::from_le_bytes(bytes)
    };
    let read_u16 = |offset: usize| {
        let mut bytes = [0_u8; 2];
        bytes.copy_from_slice(&raw[offset..offset + 2]);
        u16::from_le_bytes(bytes)
    };
    let footer = LanceFooter {
        column_meta_start: read_u64(0),
        column_meta_offsets_start: read_u64(8),
        global_buffer_offsets_start: read_u64(16),
        num_global_buffers: read_u32(24),
        num_columns: read_u32(28),
        major_version: read_u16(32),
        minor_version: read_u16(34),
    };
    if !supported_footer_version(footer.major_version, footer.minor_version) {
        return Err(unsupported(format!(
            "unsupported Lance file version {}.{}",
            footer.major_version, footer.minor_version
        )));
    }
    Ok(footer)
}

/// Footer versions whose container layout this codec recognizes.
///
/// `(0, 0..=2)` is the legacy v1 file (a different container with a 16-byte
/// trailer): recognized by [`parse_footer`] for diagnostics but rejected by
/// decoding and by [`validate_magic_footer`].
fn supported_footer_version(major: u16, minor: u16) -> bool {
    matches!((major, minor), (0, 0..=2) | (0, 3) | (2, 0..=3))
}

fn is_legacy_v1_footer(major: u16, minor: u16) -> bool {
    matches!((major, minor), (0, 0..=2))
}

fn validate_footer(footer: &LanceFooter, file_len: usize) -> Result<(), MaskuraError> {
    if footer.num_global_buffers == 0 {
        return Err(unsupported(
            "Lance file must declare at least the schema global buffer",
        ));
    }
    let footer_start = (file_len - LANCE_FOOTER_LEN) as u64;
    let table_len = |name: &str, start: u64, entries: u64| -> Result<u64, MaskuraError> {
        let len = entries
            .checked_mul(16)
            .ok_or_else(|| unsupported(format!("Lance {name} table overflows its entry count")))?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| unsupported(format!("Lance {name} table overflows its offset")))?;
        if end > footer_start {
            return Err(unsupported(format!(
                "Lance {name} table extends past the file footer"
            )));
        }
        Ok(end)
    };
    let columns_end = table_len(
        "column metadata offsets",
        footer.column_meta_offsets_start,
        u64::from(footer.num_columns),
    )?;
    let globals_end = table_len(
        "global buffer offsets",
        footer.global_buffer_offsets_start,
        u64::from(footer.num_global_buffers),
    )?;
    if footer.column_meta_start > footer.column_meta_offsets_start
        || footer.column_meta_offsets_start > footer.global_buffer_offsets_start
        || footer.global_buffer_offsets_start > footer_start
        || columns_end > footer.global_buffer_offsets_start
        || globals_end > footer_start
    {
        return Err(unsupported(
            "Lance footer offsets are inconsistent with the metadata layout",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Schema mapping
// ---------------------------------------------------------------------------

/// The physical column shape of one schema field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldShape {
    /// Fixed-width leaf values (little-endian).
    Fixed { width_bytes: usize },
    /// Variable-width leaf values.
    Var,
    /// Bit-packed boolean leaf values.
    Bool,
    /// A list field: structure lives in its child column's repetition levels
    /// (structural grammar) or in end offsets (legacy grammar).
    List,
    /// A fixed-size list: `dimension` children per row (legacy grammar only).
    FixedSizeList { dimension: u32 },
    /// A struct parent: no data of its own in the structural grammar.
    Struct,
}

#[derive(Debug, Clone)]
struct FieldPlan {
    message: FieldMessage,
    node: SchemaNode,
    shape: FieldShape,
    parent: Option<usize>,
    children: Vec<usize>,
    column: Option<usize>,
}

fn logical_shape(logical_type: &str) -> Result<(SchemaKind, FieldShape), MaskuraError> {
    if let Some(rest) = logical_type.strip_prefix("fixed_size_list:") {
        let (item, dimension) = rest
            .rsplit_once(':')
            .ok_or_else(|| unsupported("Lance fixed-size-list type is malformed"))?;
        let dimension: u32 = dimension
            .parse()
            .map_err(|_| unsupported("Lance fixed-size-list dimension is not a number"))?;
        if dimension == 0 {
            return Err(unsupported(
                "Lance fixed-size-list dimension must be positive",
            ));
        }
        let (kind, _) = leaf_shape(item)?;
        return Ok((
            SchemaKind::Array {
                items: Box::new(SchemaNode::required(kind)),
            },
            FieldShape::FixedSizeList { dimension },
        ));
    }
    if logical_type == "list" || logical_type == "large_list" {
        return Ok((
            SchemaKind::Array {
                items: Box::new(SchemaNode::required(SchemaKind::Null)),
            },
            FieldShape::List,
        ));
    }
    if logical_type == "list.struct" || logical_type == "large_list.struct" {
        return Ok((
            SchemaKind::Array {
                items: Box::new(SchemaNode::required(SchemaKind::Record { fields: vec![] })),
            },
            FieldShape::List,
        ));
    }
    if logical_type == "struct" {
        return Ok((SchemaKind::Record { fields: vec![] }, FieldShape::Struct));
    }
    leaf_shape(logical_type)
}

fn leaf_shape(logical_type: &str) -> Result<(SchemaKind, FieldShape), MaskuraError> {
    let fixed = |width_bytes: usize| FieldShape::Fixed { width_bytes };
    match logical_type {
        "bool" => Ok((SchemaKind::Boolean, FieldShape::Bool)),
        "int32" => Ok((SchemaKind::I32, fixed(4))),
        "int64" => Ok((SchemaKind::I64, fixed(8))),
        "float" => Ok((SchemaKind::F32, fixed(4))),
        "double" => Ok((SchemaKind::F64, fixed(8))),
        "string" | "large_string" => Ok((SchemaKind::String, FieldShape::Var)),
        "binary" | "large_binary" => Ok((SchemaKind::Bytes, FieldShape::Var)),
        "date32:day" => Ok((SchemaKind::Date, fixed(4))),
        other => {
            if other == "time:us" || other == "time:us:-" {
                return Ok((SchemaKind::Time, fixed(8)));
            }
            if other == "timestamp:us" || other == "timestamp:us:-" {
                return Ok((SchemaKind::Timestamp, fixed(8)));
            }
            if let Some(rest) = other.strip_prefix("decimal:") {
                return decimal_shape(rest);
            }
            Err(unsupported(format!(
                "unsupported Lance logical type {other:?}"
            )))
        }
    }
}

fn decimal_shape(rest: &str) -> Result<(SchemaKind, FieldShape), MaskuraError> {
    let mut parts = rest.split(':');
    let width = parts.next().unwrap_or_default();
    let precision: u32 = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| unsupported("Lance decimal precision is missing"))?;
    let scale: u32 = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| unsupported("Lance decimal scale is missing"))?;
    if parts.next().is_some() || precision == 0 || scale > precision {
        return Err(unsupported("Lance decimal type is malformed"));
    }
    let width_bytes = match width {
        "128" => 16_usize,
        "256" => 32_usize,
        other => {
            return Err(unsupported(format!(
                "unsupported Lance decimal width {other:?}"
            )));
        }
    };
    Ok((
        SchemaKind::Decimal { precision, scale },
        FieldShape::Fixed { width_bytes },
    ))
}

fn logical_type_for(node: &SchemaNode) -> Result<String, MaskuraError> {
    let base = match &node.kind {
        SchemaKind::Null => "null",
        SchemaKind::Boolean => "bool",
        SchemaKind::I32 => "int32",
        SchemaKind::I64 => "int64",
        SchemaKind::F32 => "float",
        SchemaKind::F64 => "double",
        SchemaKind::String => "string",
        SchemaKind::Bytes => "binary",
        SchemaKind::Date => "date32:day",
        SchemaKind::Time => "time:us:-",
        SchemaKind::Timestamp => "timestamp:us:-",
        SchemaKind::Decimal { precision, scale } => {
            return Ok(format!("decimal:128:{precision}:{scale}"));
        }
        SchemaKind::Array { items } => match &items.kind {
            SchemaKind::Record { .. } => "list.struct",
            _ => "list",
        },
        SchemaKind::Record { .. } => "struct",
        SchemaKind::Map { .. } => {
            return Err(unsupported(
                "Lance has no map column type; maps cannot be encoded to Lance",
            ));
        }
        SchemaKind::Uuid | SchemaKind::Custom { .. } => {
            return Err(unsupported(
                "custom IR types need a binary reductor before Lance encoding",
            ));
        }
    };
    Ok(base.to_string())
}

/// Flattens an IR schema into the Lance field list (parents precede children).
fn schema_to_fields(schema: &SchemaIr) -> Result<Vec<FieldMessage>, MaskuraError> {
    let mut fields = Vec::new();
    push_field(&mut fields, "root", &schema.root, -1, true)?;
    // Drop the synthetic root: Lance fields are the root record's children.
    let root_children = match &schema.root.kind {
        SchemaKind::Record { fields } => fields.len(),
        _ => 1,
    };
    let _ = root_children;
    Ok(fields)
}

fn push_field(
    fields: &mut Vec<FieldMessage>,
    name: &str,
    node: &SchemaNode,
    parent_id: i32,
    is_root: bool,
) -> Result<(), MaskuraError> {
    if is_root {
        // The root record itself is not a Lance field; emit its children at
        // the top level.
        match &node.kind {
            SchemaKind::Record { fields: children } => {
                for child in children {
                    push_field(fields, &child.name, &child.schema, -1, false)?;
                }
                return Ok(());
            }
            other => {
                return Err(unsupported(format!(
                    "Lance output needs a root record schema, found {other:?}"
                )));
            }
        }
    }
    let id =
        i32::try_from(fields.len()).map_err(|_| unsupported("Lance schema has too many fields"))?;
    let logical_type = logical_type_for(node)?;
    let empty: Vec<&SchemaNode> = Vec::new();
    let (children, child_names): (Vec<&SchemaNode>, Vec<String>) = match &node.kind {
        SchemaKind::Array { items } => (vec![&**items], vec!["item".to_string()]),
        SchemaKind::Record { fields: children } => (
            children.iter().map(|f| &f.schema).collect(),
            children.iter().map(|f| f.name.clone()).collect(),
        ),
        _ => (empty, Vec::new()),
    };
    let encoding = match &node.kind {
        SchemaKind::Record { .. } => None,
        SchemaKind::String | SchemaKind::Bytes => Some(2),
        _ => Some(1),
    };
    fields.push(FieldMessage {
        name: name.to_string(),
        id,
        parent_id,
        logical_type,
        nullable: node.nullable,
        encoding,
    });
    for (child, child_name) in children.iter().zip(child_names.iter()) {
        if let SchemaKind::Record {
            fields: grandchildren,
        } = &child.kind
        {
            // Arrays of records use `list.struct` with a real `item` struct
            // child, matching the reference writer.
            let item_id = i32::try_from(fields.len())
                .map_err(|_| unsupported("Lance schema has too many fields"))?;
            fields.push(FieldMessage {
                name: child_name.clone(),
                id: item_id,
                parent_id: id,
                logical_type: "struct".to_string(),
                nullable: child.nullable,
                encoding: None,
            });
            for grandchild in grandchildren {
                push_field(fields, &grandchild.name, &grandchild.schema, item_id, false)?;
            }
        } else {
            push_field(fields, child_name, child, id, false)?;
        }
    }
    Ok(())
}

fn build_field_plans(
    schema: &SchemaMessage,
    num_columns: usize,
    legacy_columns: bool,
) -> Result<Vec<FieldPlan>, MaskuraError> {
    if schema.fields.is_empty() {
        return Err(unsupported("Lance schema has no fields"));
    }
    let mut plans: Vec<FieldPlan> = Vec::with_capacity(schema.fields.len());
    for (index, message) in schema.fields.iter().enumerate() {
        let (kind, shape) = logical_shape(&message.logical_type)?;
        if message.id != index as i32 {
            return Err(unsupported(
                "Lance schema field ids must be dense and in field order",
            ));
        }
        plans.push(FieldPlan {
            message: message.clone(),
            node: SchemaNode {
                nullable: message.nullable,
                kind,
            },
            shape,
            parent: None,
            children: Vec::new(),
            column: None,
        });
    }
    let mut roots = Vec::new();
    for index in 0..plans.len() {
        let parent = plans[index].message.parent_id;
        if parent == -1 {
            roots.push(index);
        } else {
            let parent_index = usize::try_from(parent)
                .map_err(|_| unsupported("Lance schema parent id is invalid"))?;
            if parent_index >= index {
                return Err(unsupported(
                    "Lance schema parents must precede their children",
                ));
            }
            plans[parent_index].children.push(index);
            plans[index].parent = Some(parent_index);
        }
    }
    if roots.is_empty() {
        return Err(unsupported("Lance schema has no top-level fields"));
    }
    for index in (0..plans.len()).rev() {
        let children = plans[index].children.clone();
        let message_name = plans[index].message.name.clone();
        match plans[index].shape {
            FieldShape::List => {
                if children.len() != 1 {
                    return Err(unsupported(
                        "Lance list fields must have exactly one child field",
                    ));
                }
                let items = plans[children[0]].node.clone();
                plans[index].node.kind = SchemaKind::Array {
                    items: Box::new(items),
                };
            }
            FieldShape::Struct => {
                if children.is_empty() {
                    return Err(unsupported(format!(
                        "Lance struct field {message_name:?} must have children"
                    )));
                }
                plans[index].node.kind = SchemaKind::Record {
                    fields: children
                        .iter()
                        .map(|child| SchemaField {
                            name: plans[*child].message.name.clone(),
                            schema: plans[*child].node.clone(),
                        })
                        .collect(),
                };
            }
            FieldShape::FixedSizeList { .. } => {
                if !children.is_empty() {
                    return Err(unsupported(
                        "Lance fixed-size-list fields carry their item type inline",
                    ));
                }
            }
            _ => {
                if !children.is_empty() {
                    return Err(unsupported("Lance leaf fields must not have child fields"));
                }
            }
        }
    }
    let mut next_column = 0_usize;
    for plan in plans.iter_mut() {
        let owns_column = legacy_columns || plan.children.is_empty();
        if owns_column {
            plan.column = Some(next_column);
            next_column += 1;
        }
    }
    if next_column != num_columns {
        return Err(unsupported(format!(
            "Lance schema maps to {next_column} columns but the file declares {num_columns}"
        )));
    }
    Ok(plans)
}

// ---------------------------------------------------------------------------
// Column slots and row assembly
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum ColumnSlot {
    /// A scalar slot. `bytes` is the raw little-endian leaf payload; null
    /// fixed-width slots are zero-filled and null variable-width slots empty.
    Scalar { valid: bool, bytes: Vec<u8> },
    /// A list slot referencing `[start, end)` child slots.
    Range {
        valid: bool,
        start: usize,
        end: usize,
    },
    /// A fixed-size-list slot carrying its own item payloads.
    Items {
        valid: bool,
        items: Vec<(bool, Vec<u8>)>,
    },
}

fn fixed_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], MaskuraError> {
    bytes
        .try_into()
        .map_err(|_| unsupported("Lance fixed-width value has the wrong size"))
}

fn scalar_value(slot: &ColumnSlot, node: &SchemaNode) -> Result<Value, MaskuraError> {
    let ColumnSlot::Scalar { valid, bytes } = slot else {
        return Err(unsupported("Lance slot does not hold a scalar value"));
    };
    if !*valid {
        return Ok(Value::Null);
    }
    Ok(match &node.kind {
        SchemaKind::Null => Value::Null,
        SchemaKind::Boolean => Value::Boolean {
            value: !bytes.is_empty() && bytes[0] & 1 == 1,
        },
        SchemaKind::I32 => Value::I32 {
            value: i32::from_le_bytes(fixed_bytes(bytes)?),
        },
        SchemaKind::I64 => Value::I64 {
            value: i64::from_le_bytes(fixed_bytes(bytes)?),
        },
        SchemaKind::F32 => Value::F32 {
            value: f32::from_le_bytes(fixed_bytes(bytes)?),
        },
        SchemaKind::F64 => Value::F64 {
            value: f64::from_le_bytes(fixed_bytes(bytes)?),
        },
        SchemaKind::String => Value::String {
            value: String::from_utf8(bytes.clone())
                .map_err(|_| unsupported("Lance string value is not UTF-8"))?,
        },
        SchemaKind::Bytes => Value::Bytes {
            value: bytes.clone(),
        },
        SchemaKind::Date => Value::Date {
            value: date_from_epoch_days(i32::from_le_bytes(fixed_bytes(bytes)?))?,
        },
        SchemaKind::Time => Value::Time {
            value: time_from_micros(i64::from_le_bytes(fixed_bytes(bytes)?))?,
        },
        SchemaKind::Timestamp => Value::Timestamp {
            value: timestamp_from_micros(i64::from_le_bytes(fixed_bytes(bytes)?))?,
        },
        SchemaKind::Decimal { scale, .. } => Value::Decimal {
            value: decimal_from_unscaled(bytes, *scale),
        },
        other => {
            return Err(unsupported(format!(
                "Lance scalar slot cannot represent {other:?}"
            )));
        }
    })
}

/// The leaf payload of one scalar IR value.
fn scalar_bytes(value: &Value, node: &SchemaNode) -> Result<(bool, Vec<u8>), MaskuraError> {
    if matches!(value, Value::Null) {
        if !node.nullable && !matches!(node.kind, SchemaKind::Null) {
            return Err(unsupported(
                "Lance value is null but its schema is not nullable",
            ));
        }
        let width = match &node.kind {
            SchemaKind::Boolean => 1,
            SchemaKind::I32 | SchemaKind::F32 | SchemaKind::Date => 4,
            SchemaKind::I64 | SchemaKind::F64 | SchemaKind::Time | SchemaKind::Timestamp => 8,
            SchemaKind::Decimal { .. } => 16,
            SchemaKind::Null => 0,
            _ => 0,
        };
        return Ok((false, vec![0_u8; width]));
    }
    let bytes = match (&node.kind, value) {
        (SchemaKind::Null, Value::Null) => Vec::new(),
        (SchemaKind::Boolean, Value::Boolean { value }) => vec![u8::from(*value)],
        (SchemaKind::I32, Value::I32 { value }) => value.to_le_bytes().to_vec(),
        (SchemaKind::I64, Value::I64 { value }) => value.to_le_bytes().to_vec(),
        (SchemaKind::F32, Value::F32 { value }) => value.to_le_bytes().to_vec(),
        (SchemaKind::F64, Value::F64 { value }) => value.to_le_bytes().to_vec(),
        (SchemaKind::String, Value::String { value }) => value.as_bytes().to_vec(),
        (SchemaKind::Bytes, Value::Bytes { value }) => value.clone(),
        (SchemaKind::Date, Value::Date { value }) => {
            date_to_epoch_days(value)?.to_le_bytes().to_vec()
        }
        (SchemaKind::Time, Value::Time { value }) => time_to_micros(value)?.to_le_bytes().to_vec(),
        (SchemaKind::Timestamp, Value::Timestamp { value }) => {
            timestamp_to_micros(value)?.to_le_bytes().to_vec()
        }
        (SchemaKind::Decimal { scale, .. }, Value::Decimal { value }) => {
            decimal_to_unscaled(value, *scale)?.to_vec()
        }
        _ => {
            return Err(unsupported(
                "IR value does not match its supported Lance schema",
            ));
        }
    };
    Ok((true, bytes))
}

// ---------------------------------------------------------------------------
// Temporal and decimal conversions (normalized ISO / canonical string values)
// ---------------------------------------------------------------------------

fn date_from_epoch_days(days: i32) -> Result<String, MaskuraError> {
    NaiveDate::from_ymd_opt(1970, 1, 1)
        .and_then(|epoch| epoch.checked_add_signed(Duration::days(i64::from(days))))
        .map(|date| date.format("%F").to_string())
        .ok_or_else(|| unsupported("Lance date is outside the supported calendar range"))
}

fn date_to_epoch_days(value: &str) -> Result<i32, MaskuraError> {
    let date =
        NaiveDate::parse_from_str(value, "%F").map_err(|_| unsupported("invalid date IR value"))?;
    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).expect("1970-01-01 is valid");
    i32::try_from(date.signed_duration_since(epoch).num_days())
        .map_err(|_| unsupported("date is outside the Lance i32 day range"))
}

fn time_from_micros(micros: i64) -> Result<String, MaskuraError> {
    let micros_per_day = 86_400_000_000_i64;
    if !(0..micros_per_day).contains(&micros) {
        return Err(unsupported("Lance time is outside one UTC day"));
    }
    let seconds = u32::try_from(micros / 1_000_000).expect("bounded to one day");
    let nanoseconds = u32::try_from((micros % 1_000_000) * 1_000).expect("subsecond is bounded");
    NaiveTime::from_num_seconds_from_midnight_opt(seconds, nanoseconds)
        .map(|time| time.format("%H:%M:%S%.f").to_string())
        .ok_or_else(|| unsupported("invalid Lance time"))
}

fn time_to_micros(value: &str) -> Result<i64, MaskuraError> {
    let time = NaiveTime::parse_from_str(value, "%H:%M:%S%.f")
        .map_err(|_| unsupported("invalid time IR value"))?;
    Ok(i64::from(time.num_seconds_from_midnight()) * 1_000_000
        + i64::from(time.nanosecond() / 1_000))
}

fn timestamp_from_micros(micros: i64) -> Result<String, MaskuraError> {
    let timestamp = DateTime::from_timestamp_micros(micros)
        .ok_or_else(|| unsupported("Lance timestamp is outside the supported range"))?;
    let seconds = DateTime::<Utc>::from_timestamp(timestamp.timestamp(), 0)
        .ok_or_else(|| unsupported("Lance timestamp is outside the supported range"))?;
    let base = seconds.format("%Y-%m-%dT%H:%M:%S").to_string();
    let micros_part = timestamp.timestamp_subsec_micros();
    if micros_part == 0 {
        Ok(format!("{base}Z"))
    } else {
        let fraction = format!("{micros_part:06}");
        Ok(format!("{base}.{}Z", fraction.trim_end_matches('0')))
    }
}

fn timestamp_to_micros(value: &str) -> Result<i64, MaskuraError> {
    Ok(DateTime::parse_from_rfc3339(value)
        .map_err(|_| unsupported("invalid timestamp IR value"))?
        .with_timezone(&Utc)
        .timestamp_micros())
}

/// Canonical decimal string from little-endian two's-complement unscaled bytes.
fn decimal_from_unscaled(bytes: &[u8], scale: u32) -> String {
    let negative = bytes.last().is_some_and(|byte| byte & 0x80 != 0);
    let mut magnitude = bytes.to_vec();
    if negative {
        let mut carry = 1_u16;
        for byte in magnitude.iter_mut() {
            let sum = u16::from(!*byte) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
    }
    let digits = le_bytes_to_decimal(&magnitude);
    let digits = digits.trim_start_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let scale = scale as usize;
    if scale == 0 {
        return if negative && digits != "0" {
            format!("-{digits}")
        } else {
            digits.to_string()
        };
    }
    let padded = format!("{:0>width$}", digits, width = scale + 1);
    let split = padded.len() - scale;
    let (integer, fraction) = padded.split_at(split);
    if negative && digits != "0" {
        format!("-{integer}.{fraction}")
    } else {
        format!("{integer}.{fraction}")
    }
}

fn le_bytes_to_decimal(bytes: &[u8]) -> String {
    let mut limbs: Vec<u32> = vec![0];
    for byte in bytes.iter().rev() {
        let mut carry = u32::from(*byte);
        for limb in limbs.iter_mut() {
            let value = *limb * 256 + carry;
            *limb = value % 1_000_000_000;
            carry = value / 1_000_000_000;
        }
        while carry > 0 {
            limbs.push(carry % 1_000_000_000);
            carry /= 1_000_000_000;
        }
    }
    let mut out = String::new();
    for (index, limb) in limbs.iter().enumerate().rev() {
        if index == limbs.len() - 1 {
            out.push_str(&limb.to_string());
        } else {
            out.push_str(&format!("{limb:09}"));
        }
    }
    out
}

/// Little-endian two's-complement unscaled bytes of a given width.
fn decimal_to_unscaled(value: &str, scale: u32) -> Result<[u8; 16], MaskuraError> {
    let (negative, unsigned) = match value.strip_prefix('-') {
        Some(unsigned) => (true, unsigned),
        None => (false, value),
    };
    let (integer, fraction) = match unsigned.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (unsigned, ""),
    };
    if fraction.len() as u32 > scale {
        return Err(unsupported(
            "decimal fractional digits exceed the schema scale",
        ));
    }
    let mut digits = String::with_capacity(integer.len() + scale as usize + 1);
    digits.push_str(integer);
    digits.push_str(fraction);
    for _ in (fraction.len() as u32)..scale {
        digits.push('0');
    }
    let mut magnitude = decimal_to_le_bytes(&digits)?;
    if negative {
        let mut carry = 1_u16;
        for byte in magnitude.iter_mut() {
            let sum = u16::from(!*byte) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
    }
    Ok(magnitude)
}

fn decimal_to_le_bytes(digits: &str) -> Result<[u8; 16], MaskuraError> {
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(unsupported("invalid decimal IR value"));
    }
    let mut out = [0_u8; 16];
    for digit in digits.bytes() {
        let mut carry = u16::from(digit - b'0');
        for byte in out.iter_mut() {
            let value = u16::from(*byte) * 10 + carry;
            *byte = value as u8;
            carry = value >> 8;
        }
        if carry != 0 {
            return Err(unsupported(
                "decimal IR value exceeds the 128-bit Lance storage width",
            ));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Repetition/definition levels (structural grammar)
// ---------------------------------------------------------------------------

/// `lance.encodings21.RepDefLayer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepDefLayer {
    AllValidItem,
    AllValidList,
    NullableItem,
    NullableList,
    EmptyableList,
    NullAndEmptyList,
}

impl RepDefLayer {
    fn from_proto(value: u32) -> Result<Self, MaskuraError> {
        match value {
            1 => Ok(Self::AllValidItem),
            2 => Ok(Self::AllValidList),
            3 => Ok(Self::NullableItem),
            4 => Ok(Self::NullableList),
            5 => Ok(Self::EmptyableList),
            6 => Ok(Self::NullAndEmptyList),
            other => Err(unsupported(format!(
                "unsupported Lance repetition/definition layer {other}"
            ))),
        }
    }

    fn to_proto(self) -> u32 {
        match self {
            Self::AllValidItem => 1,
            Self::AllValidList => 2,
            Self::NullableItem => 3,
            Self::NullableList => 4,
            Self::EmptyableList => 5,
            Self::NullAndEmptyList => 6,
        }
    }

    fn is_list(self) -> bool {
        matches!(
            self,
            Self::AllValidList | Self::NullableList | Self::EmptyableList | Self::NullAndEmptyList
        )
    }

    /// The definition modes this layer contributes, in level order: a null is
    /// shallower than an empty list.
    fn def_modes(self) -> &'static [DefMode] {
        match self {
            Self::AllValidItem | Self::AllValidList => &[],
            Self::NullableItem | Self::NullableList => &[DefMode::Null],
            Self::EmptyableList => &[DefMode::Empty],
            Self::NullAndEmptyList => &[DefMode::Null, DefMode::Empty],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefMode {
    Null,
    Empty,
}

/// Where one repetition/definition event terminates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Termination {
    /// A valid item at the innermost level.
    Item,
    /// A null item at the innermost level.
    NullItem,
    /// A null struct at an ancestor level (1-based layer position from the
    /// inner-most layer, counting the item layer as 1).
    NullStruct { layer: usize },
    /// A null list at a list layer (1-based list index from the inner-most).
    NullList { list_layer: usize },
    /// An empty list at a list layer.
    EmptyList { list_layer: usize },
}

/// Interprets one definition level against the page's layers.
fn interpret_def(layers: &[RepDefLayer], def: u16) -> Result<Termination, MaskuraError> {
    if def == 0 {
        return Ok(Termination::Item);
    }
    let mut cumulative = 0_u32;
    for (index, layer) in layers.iter().enumerate() {
        let modes = layer.def_modes();
        let start = cumulative;
        cumulative += modes.len() as u32;
        if u32::from(def) <= cumulative {
            let mode = modes[(u32::from(def) - start - 1) as usize];
            let list_layer = layers
                .iter()
                .take(index + 1)
                .filter(|layer| layer.is_list())
                .count();
            return Ok(match (mode, layer.is_list()) {
                (DefMode::Null, true) => Termination::NullList { list_layer },
                (DefMode::Empty, true) => Termination::EmptyList { list_layer },
                (DefMode::Null, false) if index == 0 => Termination::NullItem,
                (DefMode::Null, false) => Termination::NullStruct { layer: index + 1 },
                (DefMode::Empty, false) => {
                    return Err(unsupported(
                        "Lance definition level uses an empty mode on a non-list layer",
                    ));
                }
            });
        }
    }
    Err(unsupported(
        "Lance definition level exceeds the page's repetition/definition layers",
    ))
}

/// Computes the definition level for one event.
fn compute_def(layers: &[RepDefLayer], termination: Termination) -> Result<u16, MaskuraError> {
    let target = match termination {
        Termination::Item => return Ok(0),
        Termination::NullItem => 0,
        Termination::NullStruct { layer } => layer - 1,
        Termination::NullList { list_layer } | Termination::EmptyList { list_layer } => layers
            .iter()
            .enumerate()
            .filter(|(_, layer)| layer.is_list())
            .nth(list_layer - 1)
            .map(|(index, _)| index)
            .ok_or_else(|| unsupported("Lance list layer index is out of range"))?,
    };
    let mode = match termination {
        Termination::NullItem | Termination::NullStruct { .. } | Termination::NullList { .. } => {
            DefMode::Null
        }
        Termination::EmptyList { .. } => DefMode::Empty,
        Termination::Item => unreachable!(),
    };
    let mut cumulative = 0_u32;
    for (index, layer) in layers.iter().enumerate() {
        let modes = layer.def_modes();
        if index == target {
            let position = modes
                .iter()
                .position(|candidate| *candidate == mode)
                .ok_or_else(|| {
                    unsupported("Lance layer does not declare the requested definition mode")
                })?;
            return u16::try_from(cumulative + position as u32 + 1)
                .map_err(|_| unsupported("Lance definition level does not fit u16"));
        }
        cumulative += modes.len() as u32;
    }
    Err(unsupported("Lance termination layer is out of range"))
}

/// True when the event materializes a leaf value slot. Empty and null list
/// terminations are invisible markers; every other event (including null
/// items and null structs) occupies a slot (zero-filled or empty).
fn materialized(termination: Termination) -> bool {
    !matches!(
        termination,
        Termination::EmptyList { .. } | Termination::NullList { .. }
    )
}

// ---------------------------------------------------------------------------
// Structural page model
// ---------------------------------------------------------------------------

/// One repetition/definition event of a structural page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LevelEvent {
    rep: u16,
    def: u16,
    /// The reconstructed termination, used by both directions.
    termination: Termination,
}

/// The value-compression description the codec supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueCompression {
    /// `Flat`: fixed-width little-endian values.
    Flat { bits_per_value: u64 },
    /// `Variable`: buffer-relative `u32` end offsets plus the value bytes.
    Variable,
}

/// Parses the structural page encodings the codec supports.
fn parse_structural_page(raw: &[u8]) -> Result<StructuralPage, MaskuraError> {
    let mut reader = crate::lance_wire::WireReader::new(raw);
    let mut page: Option<StructuralPage> = None;
    while let Some((field, value)) = reader.next()? {
        let decoded = match (field, value) {
            (1, crate::lance_wire::WireValue::Bytes(bytes)) => parse_mini_block(bytes)?,
            (2, crate::lance_wire::WireValue::Bytes(bytes)) => parse_constant(bytes)?,
            (3, crate::lance_wire::WireValue::Bytes(bytes)) => parse_full_zip(bytes)?,
            (4, _) => {
                return Err(unsupported(
                    "Lance blob pages are not supported by this codec",
                ));
            }
            _ => {
                return Err(unsupported(
                    "unknown Lance structural page layout (planar 2.3 pages are not supported)",
                ));
            }
        };
        if page.is_some() {
            return Err(unsupported(
                "Lance page declares more than one structural layout",
            ));
        }
        page = Some(decoded);
    }
    page.ok_or_else(|| unsupported("Lance structural page has no layout"))
}

enum StructuralPage {
    MiniBlock {
        rep: bool,
        def: bool,
        values: ValueCompression,
        layers: Vec<RepDefLayer>,
        num_items: u64,
        large_chunks: bool,
    },
    Constant {
        layers: Vec<RepDefLayer>,
        inline_value: Option<Vec<u8>>,
    },
    FullZip {
        values: ValueCompression,
        bits_per_offset: Option<u32>,
        num_items: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SerializedValueBlock {
    offsets: Vec<usize>,
    values: Vec<u8>,
}

fn parse_flat_compression(raw: &[u8]) -> Result<ValueCompression, MaskuraError> {
    let mut reader = crate::lance_wire::WireReader::new(raw);
    let mut bits = 0_u64;
    let mut extra = false;
    while let Some((field, value)) = reader.next()? {
        match (field, value) {
            (1, crate::lance_wire::WireValue::Varint(value)) => bits = value,
            (2, crate::lance_wire::WireValue::Bytes(_)) => extra = true,
            _ => {}
        }
    }
    if extra {
        return Err(unsupported(
            "Lance buffer compression is not supported by this codec",
        ));
    }
    if bits == 0 {
        return Err(unsupported("Lance flat encoding needs a positive width"));
    }
    Ok(ValueCompression::Flat {
        bits_per_value: bits,
    })
}

/// Parses a `CompressiveEncoding` in the supported subset (uncompressed
/// `Flat` and `Variable`).
fn parse_compressive(raw: &[u8]) -> Result<ValueCompression, MaskuraError> {
    let mut reader = crate::lance_wire::WireReader::new(raw);
    let mut result: Option<ValueCompression> = None;
    while let Some((field, value)) = reader.next()? {
        let decoded = match (field, value) {
            (1, crate::lance_wire::WireValue::Bytes(bytes)) => parse_flat_compression(bytes)?,
            (2, crate::lance_wire::WireValue::Bytes(bytes)) => {
                let mut inner = crate::lance_wire::WireReader::new(bytes);
                let mut offsets = None;
                let mut values_extra = false;
                while let Some((inner_field, inner_value)) = inner.next()? {
                    match (inner_field, inner_value) {
                        (1, crate::lance_wire::WireValue::Bytes(raw)) => {
                            offsets = Some(parse_compressive(raw)?);
                        }
                        (2, crate::lance_wire::WireValue::Bytes(_)) => values_extra = true,
                        _ => {}
                    }
                }
                match offsets {
                    Some(ValueCompression::Flat { bits_per_value: 32 }) if !values_extra => {
                        ValueCompression::Variable
                    }
                    Some(ValueCompression::Flat { bits_per_value: 64 }) if !values_extra => {
                        return Err(unsupported(
                            "Lance variable values with 64-bit offsets are not supported",
                        ));
                    }
                    _ => {
                        return Err(unsupported(
                            "Lance variable values must use flat 32-bit offsets",
                        ));
                    }
                }
            }
            _ => {
                return Err(unsupported(
                    "Lance dictionary, bitpacked, FSST, RLE, and general-compressed pages are not supported by this codec",
                ));
            }
        };
        if result.is_some() {
            return Err(unsupported(
                "Lance compression description declares more than one encoding",
            ));
        }
        result = Some(decoded);
    }
    result.ok_or_else(|| unsupported("Lance compression description is empty"))
}

fn parse_layers(raw: &[u8]) -> Result<Vec<RepDefLayer>, MaskuraError> {
    decode_packed_u32(raw)?
        .into_iter()
        .map(RepDefLayer::from_proto)
        .collect()
}

fn parse_mini_block(raw: &[u8]) -> Result<StructuralPage, MaskuraError> {
    let mut reader = crate::lance_wire::WireReader::new(raw);
    let mut rep = false;
    let mut def = false;
    let mut values = None;
    let mut dictionary = false;
    let mut layers = Vec::new();
    let mut num_items = 0_u64;
    let mut num_buffers = 0_u64;
    let mut large_chunks = false;
    while let Some((field, value)) = reader.next()? {
        match (field, value) {
            (1, crate::lance_wire::WireValue::Bytes(bytes)) => {
                parse_compressive(bytes)?;
                rep = true;
            }
            (2, crate::lance_wire::WireValue::Bytes(bytes)) => {
                parse_compressive(bytes)?;
                def = true;
            }
            (3, crate::lance_wire::WireValue::Bytes(bytes)) => {
                values = Some(parse_compressive(bytes)?);
            }
            (4, _) | (5, _) => dictionary = true,
            (6, crate::lance_wire::WireValue::Bytes(bytes)) => layers = parse_layers(bytes)?,
            (7, crate::lance_wire::WireValue::Varint(value)) => num_buffers = value,
            (8, crate::lance_wire::WireValue::Varint(_)) => {}
            (9, crate::lance_wire::WireValue::Varint(value)) => num_items = value,
            (10, crate::lance_wire::WireValue::Varint(value)) => large_chunks = value != 0,
            _ => {}
        }
    }
    if dictionary {
        return Err(unsupported(
            "Lance mini-block dictionaries are not supported by this codec",
        ));
    }
    let values =
        values.ok_or_else(|| unsupported("Lance mini-block page has no value encoding"))?;
    if layers.is_empty() {
        return Err(unsupported("Lance mini-block page has no repdef layers"));
    }
    if num_buffers != 1 {
        return Err(unsupported(
            "Lance mini-block pages with dictionaries or multiple value buffers are not supported",
        ));
    }
    Ok(StructuralPage::MiniBlock {
        rep,
        def,
        values,
        layers,
        num_items,
        large_chunks,
    })
}

fn parse_constant(raw: &[u8]) -> Result<StructuralPage, MaskuraError> {
    let mut reader = crate::lance_wire::WireReader::new(raw);
    let mut layers = Vec::new();
    let mut inline_value = None;
    while let Some((field, value)) = reader.next()? {
        match (field, value) {
            (5, crate::lance_wire::WireValue::Bytes(bytes)) => layers = parse_layers(bytes)?,
            (6, crate::lance_wire::WireValue::Bytes(bytes)) => {
                inline_value = Some(bytes.to_vec());
            }
            (7, crate::lance_wire::WireValue::Bytes(bytes)) => {
                parse_compressive(bytes)?;
            }
            (8, crate::lance_wire::WireValue::Bytes(bytes)) => {
                parse_compressive(bytes)?;
            }
            (9, crate::lance_wire::WireValue::Varint(_))
            | (10, crate::lance_wire::WireValue::Varint(_)) => {}
            (11, _) => {
                return Err(unsupported(
                    "Lance constant-page dictionaries are not supported by this codec",
                ));
            }
            _ => {}
        }
    }
    if layers.is_empty() {
        return Err(unsupported("Lance constant page has no repdef layers"));
    }
    Ok(StructuralPage::Constant {
        layers,
        inline_value,
    })
}

#[allow(clippy::too_many_lines)]
fn parse_full_zip(raw: &[u8]) -> Result<StructuralPage, MaskuraError> {
    let mut reader = crate::lance_wire::WireReader::new(raw);
    let mut bits_rep = 0_u32;
    let mut bits_def = 0_u32;
    let mut bits_per_value = None;
    let mut bits_per_offset = None;
    let mut values = None;
    let mut num_items = 0_u32;
    while let Some((field, value)) = reader.next()? {
        match (field, value) {
            (1, crate::lance_wire::WireValue::Varint(value)) => bits_rep = value as u32,
            (2, crate::lance_wire::WireValue::Varint(value)) => bits_def = value as u32,
            (3, crate::lance_wire::WireValue::Varint(value)) => bits_per_value = Some(value as u32),
            (4, crate::lance_wire::WireValue::Varint(value)) => {
                bits_per_offset = Some(value as u32)
            }
            (5, crate::lance_wire::WireValue::Varint(value)) => num_items = value as u32,
            #[allow(unused_assignments)]
            (7, crate::lance_wire::WireValue::Bytes(bytes)) => {
                values = Some(parse_compressive(bytes)?);
            }
            _ => {}
        }
    }
    if bits_rep != 0 || bits_def != 0 {
        return Err(unsupported(
            "Lance full-zip control words (validity or repetition) are not supported by this codec",
        ));
    }
    let values = values.ok_or_else(|| unsupported("Lance full-zip page has no value encoding"))?;
    if bits_per_value.is_none() && bits_per_offset.is_none() {
        return Err(unsupported(
            "Lance full-zip page does not describe its value addressing",
        ));
    }
    Ok(StructuralPage::FullZip {
        values,
        bits_per_offset,
        num_items,
    })
}

// ---------------------------------------------------------------------------
// Structural column assembly
// ---------------------------------------------------------------------------

/// One node of a decoded column's value tree before sibling merge.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    /// A leaf value slot at layer position 1.
    Value { valid: bool, bytes: Vec<u8> },
    /// A null struct slot; `depth` counts levels below the top-level field.
    NullStruct { depth: usize },
    /// A list slot (null lists carry `valid: false`).
    List { valid: bool, items: Vec<Node> },
}

/// The role of one layer of a column path, inner-most first (the item layer is
/// position 1 and ancestors follow from inner to outer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayerRole {
    Item,
    Struct,
    List { list_index: usize },
}

/// The layer plan of one leaf column: roles and repetition/definition layers.
struct ColumnPlan {
    roles: Vec<LayerRole>,
    layers: Vec<RepDefLayer>,
    list_count: usize,
}

fn column_plan(path: &[FieldPlan], leaf: usize) -> Result<ColumnPlan, MaskuraError> {
    let mut chain = Vec::new();
    let mut current = leaf;
    loop {
        chain.push(current);
        match path[current].parent {
            Some(parent) => current = parent,
            None => break,
        }
    }
    // `chain` is leaf-first; ancestors follow from inner to outer.
    let mut roles = vec![LayerRole::Item];
    for &field in chain.iter().skip(1) {
        roles.push(match path[field].shape {
            FieldShape::List => LayerRole::List { list_index: 0 },
            FieldShape::Struct => LayerRole::Struct,
            FieldShape::FixedSizeList { .. } => {
                return Err(unsupported(
                    "Lance fixed-size-list fields are only supported in legacy v2.0 files",
                ));
            }
            _ => {
                return Err(unsupported(
                    "Lance leaf fields cannot be ancestors of another field",
                ));
            }
        });
    }
    let list_count = roles
        .iter()
        .filter(|role| matches!(role, LayerRole::List { .. }))
        .count();
    let mut assigned = 0_usize;
    for role in roles.iter_mut() {
        if matches!(role, LayerRole::List { .. }) {
            assigned += 1;
            *role = LayerRole::List {
                list_index: assigned,
            };
        }
    }
    let mut layers = Vec::with_capacity(roles.len());
    for (index, role) in roles.iter().enumerate() {
        let node = &path[chain[index.min(chain.len() - 1)]].node;
        layers.push(match role {
            LayerRole::Item | LayerRole::Struct => {
                if node.nullable {
                    RepDefLayer::NullableItem
                } else {
                    RepDefLayer::AllValidItem
                }
            }
            LayerRole::List { .. } => {
                if node.nullable {
                    RepDefLayer::NullAndEmptyList
                } else {
                    RepDefLayer::EmptyableList
                }
            }
        });
    }
    Ok(ColumnPlan {
        roles,
        layers,
        list_count,
    })
}

struct OpenList {
    list_index: usize,
    items: Vec<Node>,
    valid: bool,
}

fn list_position(roles: &[LayerRole], list_index: usize) -> usize {
    roles
        .iter()
        .enumerate()
        .find(|(_, role)| matches!(role, LayerRole::List { list_index: candidate } if *candidate == list_index))
        .map(|(index, _)| index + 1)
        .unwrap_or(usize::MAX)
}

/// Appends `node` to the innermost open list strictly outside `position`,
/// or to the row list when no such container is open.
fn append_node(
    rows: &mut Vec<Node>,
    open: &mut [OpenList],
    roles: &[LayerRole],
    position: usize,
    node: Node,
) {
    let mut target = None;
    for (offset, list) in open.iter().enumerate() {
        if list_position(roles, list.list_index) > position {
            target = Some(offset);
        }
    }
    match target {
        Some(offset) => open[offset].items.push(node),
        None => rows.push(node),
    }
}

/// Drops open lists that live strictly inside a null or empty layer.
fn discard_phantom(open: &mut Vec<OpenList>, roles: &[LayerRole], position: usize) {
    open.retain(|list| list_position(roles, list.list_index) >= position);
}

/// Rebuilds one column's per-row value tree from its structural events.
fn assemble_column(
    plan: &ColumnPlan,
    events: &[LevelEvent],
    slots: &[(bool, Vec<u8>)],
    rows: usize,
) -> Result<Vec<Node>, MaskuraError> {
    let mut row_nodes: Vec<Node> = Vec::new();
    let mut open: Vec<OpenList> = Vec::new();
    let mut slot_cursor = 0_usize;

    for event in events {
        let k = usize::from(event.rep);
        if k > plan.list_count {
            return Err(unsupported(
                "Lance repetition level exceeds the page's list layers",
            ));
        }
        // Reopened lists close from inner to outer and reopen from outer to
        // inner, so the open set always stays sorted by list index.
        for index in 1..=k {
            if let Some(offset) = open.iter().position(|list| list.list_index == index) {
                let list = open.remove(offset);
                let node = Node::List {
                    valid: list.valid,
                    items: list.items,
                };
                append_node(
                    &mut row_nodes,
                    &mut open,
                    &plan.roles,
                    list_position(&plan.roles, index),
                    node,
                );
            }
        }
        for index in (1..=k).rev() {
            open.push(OpenList {
                list_index: index,
                items: Vec::new(),
                valid: true,
            });
            open.sort_by_key(|list| list.list_index);
        }

        match event.termination {
            Termination::Item | Termination::NullItem => {
                let (valid, bytes) = slots
                    .get(slot_cursor)
                    .ok_or_else(|| unsupported("Lance page is missing a leaf value slot"))?;
                slot_cursor += 1;
                let node = Node::Value {
                    valid: *valid,
                    bytes: bytes.clone(),
                };
                match open.first_mut() {
                    Some(list) => list.items.push(node),
                    None => row_nodes.push(node),
                }
            }
            Termination::NullStruct { layer } => {
                // Null struct events occupy (and discard) a value slot.
                if slot_cursor >= slots.len() {
                    return Err(unsupported("Lance page is missing a leaf value slot"));
                }
                slot_cursor += 1;
                discard_phantom(&mut open, &plan.roles, layer);
                let node = Node::NullStruct {
                    depth: plan.roles.len() - layer,
                };
                append_node(&mut row_nodes, &mut open, &plan.roles, layer, node);
            }
            Termination::NullList { list_layer } | Termination::EmptyList { list_layer } => {
                let position = list_position(&plan.roles, list_layer);
                if position == usize::MAX {
                    return Err(unsupported("Lance list layer index is out of range"));
                }
                if usize::from(event.rep) < list_layer {
                    return Err(unsupported(
                        "Lance empty/null list marker does not open its own list",
                    ));
                }
                discard_phantom(&mut open, &plan.roles, position);
                let null = matches!(event.termination, Termination::NullList { .. });
                let list = open
                    .iter()
                    .position(|list| list.list_index == list_layer)
                    .map(|offset| open.remove(offset))
                    .ok_or_else(|| unsupported("Lance list marker has no open list"))?;
                let node = Node::List {
                    valid: !null,
                    items: list.items,
                };
                append_node(&mut row_nodes, &mut open, &plan.roles, position, node);
            }
        }
    }
    // Close everything that remains, inner to outer.
    while !open.is_empty() {
        let list = open.remove(0);
        let node = Node::List {
            valid: list.valid,
            items: list.items,
        };
        let position = list_position(&plan.roles, list.list_index);
        append_node(&mut row_nodes, &mut open, &plan.roles, position, node);
    }
    if slot_cursor != slots.len() {
        return Err(unsupported(
            "Lance page leaf value slots do not match its events",
        ));
    }
    if row_nodes.len() != rows {
        return Err(unsupported(format!(
            "Lance column rebuilt {} rows but the file declares {rows}",
            row_nodes.len()
        )));
    }
    Ok(row_nodes)
}

// ---------------------------------------------------------------------------
// Structural page decoding
// ---------------------------------------------------------------------------

/// Decodes one structural page into events and materialized leaf slots.
#[allow(clippy::type_complexity)]
fn decode_structural_page(
    encoding: &StructuralPage,
    buffers: &[Vec<u8>],
    rows: usize,
    shape: FieldShape,
) -> Result<(Vec<LevelEvent>, Vec<(bool, Vec<u8>)>), MaskuraError> {
    match encoding {
        StructuralPage::MiniBlock {
            rep,
            def,
            values,
            layers,
            num_items,
            large_chunks,
        } => decode_mini_block(
            *rep,
            *def,
            *values,
            layers,
            *num_items,
            *large_chunks,
            buffers,
            rows,
            shape,
        ),
        StructuralPage::Constant {
            layers,
            inline_value,
        } => decode_constant(layers, inline_value.as_deref(), buffers, rows, shape),
        StructuralPage::FullZip {
            values,
            bits_per_offset,
            num_items,
        } => decode_full_zip(*values, *bits_per_offset, *num_items, buffers, rows),
    }
}

fn read_levels(bytes: &[u8], events: usize, name: &str) -> Result<Vec<u16>, MaskuraError> {
    if bytes.len() != events * 2 {
        return Err(unsupported(format!(
            "Lance {name} levels do not match the page's event count"
        )));
    }
    Ok((0..events)
        .map(|index| u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]))
        .collect())
}

fn events_from_levels(
    layers: &[RepDefLayer],
    reps: Option<&[u16]>,
    defs: Option<&[u16]>,
    count: usize,
) -> Result<Vec<LevelEvent>, MaskuraError> {
    let zero_levels = |kind: &str| -> Result<Vec<u16>, MaskuraError> {
        if count > u16::MAX as usize {
            return Err(unsupported(format!(
                "Lance {kind} level count exceeds the u16 level range"
            )));
        }
        Ok(vec![0; count])
    };
    let reps = match reps {
        Some(reps) => reps.to_vec(),
        None => zero_levels("repetition")?,
    };
    let defs = match defs {
        Some(defs) => defs.to_vec(),
        None => zero_levels("definition")?,
    };
    if reps.len() != count || defs.len() != count {
        return Err(unsupported(
            "Lance level arrays do not match the page's event count",
        ));
    }
    reps.iter()
        .zip(defs.iter())
        .map(|(rep, def)| {
            let termination = interpret_def(layers, *def)?;
            Ok(LevelEvent {
                rep: *rep,
                def: *def,
                termination,
            })
        })
        .collect()
}

#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
fn decode_mini_block(
    rep: bool,
    def: bool,
    values: ValueCompression,
    layers: &[RepDefLayer],
    num_items: u64,
    large_chunks: bool,
    buffers: &[Vec<u8>],
    _rows: usize,
    shape: FieldShape,
) -> Result<(Vec<LevelEvent>, Vec<(bool, Vec<u8>)>), MaskuraError> {
    let has_lists = layers.iter().any(|layer| layer.is_list());
    let expected_buffers = 2 + usize::from(has_lists);
    if buffers.len() != expected_buffers {
        return Err(unsupported(format!(
            "Lance mini-block page declares {} buffers but its layout needs {expected_buffers}",
            buffers.len()
        )));
    }
    let miniblock = &buffers[1];
    let size_width = if large_chunks { 4 } else { 2 };
    let mut events = Vec::new();
    let mut slots = Vec::new();
    let mut offset = 0_usize;
    while offset < miniblock.len() {
        // Chunk header: [u16 level entries][u16 rep size][u16 def size][value
        // sizes]. Sizes are u32 in large-chunk (2.2) pages and u16 otherwise.
        // The level count is zero for chunks without level data.
        let header_bytes = 2 + 2 * usize::from(rep) + 2 * usize::from(def) + size_width;
        if miniblock.len() - offset < header_bytes {
            return Err(unsupported("Lance mini-block chunk header is truncated"));
        }
        let read_u16 = |at: usize| u16::from_le_bytes([miniblock[at], miniblock[at + 1]]) as usize;
        let level_entries = read_u16(offset);
        let mut cursor = offset + 2;
        let mut sub_sizes = Vec::new();
        if rep {
            sub_sizes.push(read_u16(cursor));
            cursor += 2;
        }
        if def {
            sub_sizes.push(read_u16(cursor));
            cursor += 2;
        }
        let value_size = if large_chunks {
            u32::from_le_bytes([
                miniblock[cursor],
                miniblock[cursor + 1],
                miniblock[cursor + 2],
                miniblock[cursor + 3],
            ]) as usize
        } else {
            read_u16(cursor)
        };
        cursor += size_width;
        sub_sizes.push(value_size);

        let mut padded = cursor + (8 - cursor % 8) % 8;
        let mut sub_buffers = Vec::with_capacity(sub_sizes.len());
        for size in &sub_sizes {
            let end = padded + *size;
            if end > miniblock.len() {
                return Err(unsupported("Lance mini-block chunk buffer is truncated"));
            }
            sub_buffers.push(&miniblock[padded..end]);
            padded = end + (8 - end % 8) % 8;
            if padded > miniblock.len() {
                return Err(unsupported("Lance mini-block chunk padding is truncated"));
            }
        }
        offset = padded;

        let chunk_events = if rep || def {
            level_entries
        } else {
            // Without levels every event is one materialized value; the
            // single-chunk case can take the count from the layout.
            let buffer = sub_buffers.last().copied().unwrap_or(&[]);
            match value_count(&values, buffer, shape) {
                Ok(count) => count,
                Err(_) if miniblock.len() == padded && num_items > 0 => num_items as usize,
                Err(error) => return Err(error),
            }
        };
        let mut sub = sub_buffers.into_iter();
        let reps = if rep {
            Some(read_levels(
                sub.next().expect("rep buffer"),
                chunk_events,
                "repetition",
            )?)
        } else {
            None
        };
        let defs = if def {
            Some(read_levels(
                sub.next().expect("def buffer"),
                chunk_events,
                "definition",
            )?)
        } else {
            None
        };
        let chunk_events_decoded =
            events_from_levels(layers, reps.as_deref(), defs.as_deref(), chunk_events)?;
        let value_buffer = sub.next().expect("value buffer");
        let chunk_slots = decode_value_buffer(
            &values,
            value_buffer,
            &chunk_events_decoded
                .iter()
                .map(|event| event.termination)
                .collect::<Vec<_>>(),
            shape,
        )?;
        events.extend(chunk_events_decoded);
        slots.extend(chunk_slots);
    }
    if slots.len() as u64 != num_items {
        return Err(unsupported(format!(
            "Lance mini-block page declares {num_items} values but decoded {}",
            slots.len()
        )));
    }
    Ok((events, slots))
}

/// The number of values a level-less value buffer carries.
fn value_count(
    values: &ValueCompression,
    buffer: &[u8],
    shape: FieldShape,
) -> Result<usize, MaskuraError> {
    match values {
        ValueCompression::Flat { bits_per_value } => {
            let width = match shape {
                FieldShape::Bool => (*bits_per_value as usize).div_ceil(8).max(1),
                FieldShape::Fixed { width_bytes } => width_bytes,
                _ => {
                    return Err(unsupported(
                        "Lance flat values cannot decode a variable-width column",
                    ));
                }
            };
            if *bits_per_value == 1 {
                return Err(unsupported(
                    "Lance level-less bit-packed chunks need an explicit value count",
                ));
            }
            let stride = (*bits_per_value / 8) as usize;
            if stride == 0 || !buffer.len().is_multiple_of(stride) {
                return Err(unsupported("Lance flat value buffer size is inconsistent"));
            }
            let _ = width;
            Ok(buffer.len() / stride)
        }
        ValueCompression::Variable => {
            if buffer.is_empty() {
                return Ok(0);
            }
            if buffer.len() < 4 {
                return Err(unsupported("Lance variable value offsets are truncated"));
            }
            let first = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
            if first < 4 || !first.is_multiple_of(4) {
                return Err(unsupported("Lance variable value offsets are inconsistent"));
            }
            Ok(first / 4 - 1)
        }
    }
}

#[allow(clippy::type_complexity)]
fn decode_value_buffer(
    values: &ValueCompression,
    buffer: &[u8],
    terminations: &[Termination],
    shape: FieldShape,
) -> Result<Vec<(bool, Vec<u8>)>, MaskuraError> {
    let materialized_flags: Vec<bool> = terminations
        .iter()
        .map(|termination| materialized(*termination))
        .collect();
    let materialized = &materialized_flags[..];
    let count = materialized.iter().filter(|present| **present).count();
    match values {
        ValueCompression::Flat { bits_per_value } => {
            let width = match shape {
                FieldShape::Bool => 1_usize,
                FieldShape::Fixed { width_bytes } => width_bytes,
                _ => {
                    return Err(unsupported(
                        "Lance flat values cannot decode a variable-width column",
                    ));
                }
            };
            if *bits_per_value != width as u64 * 8
                && !(*bits_per_value == 1 && shape == FieldShape::Bool)
            {
                return Err(unsupported(
                    "Lance flat value width does not match the column type",
                ));
            }
            let raw = read_fixed_width(buffer, *bits_per_value, count)?;
            let mut slots = Vec::with_capacity(count);
            let mut cursor = 0_usize;
            for (index, present) in materialized.iter().enumerate() {
                if !*present {
                    continue;
                }
                let bytes = raw
                    .get(cursor)
                    .cloned()
                    .ok_or_else(|| unsupported("Lance flat values are truncated"))?;
                cursor += 1;
                let valid = matches!(terminations.get(index), Some(Termination::Item) | None);
                slots.push((valid, if valid { bytes } else { Vec::new() }));
            }
            Ok(slots)
        }
        ValueCompression::Variable => {
            if count == 0 {
                return Ok(Vec::new());
            }
            let offsets_len = (count + 1) * 4;
            if buffer.len() < offsets_len {
                return Err(unsupported("Lance variable value offsets are truncated"));
            }
            let mut offsets = Vec::with_capacity(count + 1);
            for index in 0..=count {
                offsets.push(u32::from_le_bytes([
                    buffer[index * 4],
                    buffer[index * 4 + 1],
                    buffer[index * 4 + 2],
                    buffer[index * 4 + 3],
                ]) as usize);
            }
            if offsets[0] != offsets_len || offsets.windows(2).any(|pair| pair[0] > pair[1]) {
                return Err(unsupported("Lance variable value offsets are inconsistent"));
            }
            if offsets[count] > buffer.len() {
                return Err(unsupported("Lance variable values are truncated"));
            }
            let mut slots = Vec::with_capacity(count);
            let mut cursor = 0_usize;
            for (index, present) in materialized.iter().enumerate() {
                if !*present {
                    continue;
                }
                let bytes = buffer[offsets[cursor]..offsets[cursor + 1]].to_vec();
                cursor += 1;
                let valid = matches!(terminations.get(index), Some(Termination::Item) | None);
                slots.push((valid, if valid { bytes } else { Vec::new() }));
            }
            Ok(slots)
        }
    }
}

#[allow(clippy::type_complexity)]
fn decode_constant(
    layers: &[RepDefLayer],
    inline_value: Option<&[u8]>,
    buffers: &[Vec<u8>],
    rows: usize,
    shape: FieldShape,
) -> Result<(Vec<LevelEvent>, Vec<(bool, Vec<u8>)>), MaskuraError> {
    let has_lists = layers.iter().any(|layer| layer.is_list());
    let has_modes = layers.iter().any(|layer| !layer.def_modes().is_empty());
    let has_levels = has_lists || has_modes;
    let values_buffer = if !has_levels {
        match buffers.len() {
            0 => None,
            1 => Some(&buffers[0]),
            _ => {
                return Err(unsupported(
                    "Lance constant page declares unexpected buffers",
                ));
            }
        }
    } else if buffers.len() == 3 {
        Some(&buffers[0])
    } else if buffers.len() == 2 {
        None
    } else {
        return Err(unsupported(
            "Lance constant page with levels must declare its level buffers",
        ));
    };
    let mut offset = if values_buffer.is_some() { 1 } else { 0 };
    let rep_bytes = if has_levels {
        let bytes = buffers.get(offset);
        offset += 1;
        bytes
    } else {
        None
    };
    let def_bytes = if has_levels {
        buffers.get(offset)
    } else {
        None
    };
    let event_count = rows.max(
        rep_bytes
            .map(|bytes| bytes.len() / 2)
            .unwrap_or(0)
            .max(def_bytes.map(|bytes| bytes.len() / 2).unwrap_or(0)),
    );
    if event_count != rows && (has_lists || has_modes) {
        // Without lists every event is one row; with lists the event count can
        // exceed the row count and is taken from the level buffers.
    }
    let events_count = rep_bytes
        .map(|bytes| bytes.len() / 2)
        .unwrap_or(0)
        .max(def_bytes.map(|bytes| bytes.len() / 2).unwrap_or(0));
    let events_count = if has_levels && events_count == 0 {
        rows
    } else if has_levels {
        events_count
    } else {
        rows
    };
    let _ = event_count;
    let reps = match rep_bytes {
        Some(bytes) if has_lists => Some(read_levels(bytes, events_count, "repetition")?),
        Some(bytes) if !bytes.is_empty() => {
            return Err(unsupported(
                "Lance constant page carries repetition levels without list layers",
            ));
        }
        _ => None,
    };
    let defs = match def_bytes {
        Some(bytes) if has_modes => Some(read_levels(bytes, events_count, "definition")?),
        Some(bytes) if !bytes.is_empty() => {
            return Err(unsupported(
                "Lance constant page carries definition levels without optional layers",
            ));
        }
        _ => None,
    };
    let events = events_from_levels(layers, reps.as_deref(), defs.as_deref(), events_count)?;

    // The constant value applies to every materialized, non-null slot.
    let constant: Option<(bool, Vec<u8>)> = if let Some(inline) = inline_value {
        Some((true, inline.to_vec()))
    } else if let Some(buffer) = values_buffer {
        let block = parse_serialized_value_block(buffer)?;
        let start = block.offsets.first().copied().unwrap_or(0);
        let end = block.offsets.last().copied().unwrap_or(start);
        let start = start.saturating_sub(12 + block.offsets.len() * 4);
        let end = end.saturating_sub(12 + block.offsets.len() * 4);
        let value = block
            .values
            .get(start..end)
            .ok_or_else(|| unsupported("Lance constant value block is truncated"))?
            .to_vec();
        Some((true, value))
    } else {
        None
    };
    let slots = events
        .iter()
        .map(|event| match (materialized(event.termination), &constant) {
            (false, _) => Ok((false, Vec::new())),
            (true, Some((valid, bytes))) => {
                if matches!(event.termination, Termination::NullItem) {
                    let width = match shape {
                        FieldShape::Bool => 1,
                        FieldShape::Fixed { width_bytes } => width_bytes,
                        _ => 0,
                    };
                    Ok((false, vec![0_u8; width]))
                } else {
                    Ok((*valid, bytes.clone()))
                }
            }
            (true, None) => {
                if matches!(event.termination, Termination::NullItem) {
                    Ok((false, Vec::new()))
                } else {
                    Err(unsupported(
                        "Lance constant page has valid values but no constant payload",
                    ))
                }
            }
        })
        .collect::<Result<Vec<_>, MaskuraError>>()?;
    Ok((events, slots))
}

fn parse_serialized_value_block(buffer: &[u8]) -> Result<SerializedValueBlock, MaskuraError> {
    if buffer.len() < 12 {
        return Err(unsupported(
            "Lance serialized value block is missing its header",
        ));
    }
    let read_u32 = |index: usize| {
        u32::from_le_bytes([
            buffer[index],
            buffer[index + 1],
            buffer[index + 2],
            buffer[index + 3],
        ]) as usize
    };
    let offsets_count = read_u32(0);
    let offsets_bytes = read_u32(4);
    let values_bytes = read_u32(8);
    if offsets_count == 0
        || offsets_count.checked_mul(4) != Some(offsets_bytes)
        || 12_usize
            .checked_add(offsets_bytes)
            .and_then(|end| end.checked_add(values_bytes))
            != Some(buffer.len())
    {
        return Err(unsupported(
            "Lance serialized value block sizes are inconsistent",
        ));
    }
    let offsets = (0..offsets_count)
        .map(|index| read_u32(12 + index * 4))
        .collect::<Vec<_>>();
    let values = buffer[12 + offsets_bytes..].to_vec();
    if offsets.first() != Some(&(12 + offsets_bytes)) {
        return Err(unsupported(
            "Lance serialized value block offsets are inconsistent",
        ));
    }
    Ok(SerializedValueBlock { offsets, values })
}

#[allow(clippy::type_complexity)]
fn decode_full_zip(
    values: ValueCompression,
    bits_per_offset: Option<u32>,
    num_items: u32,
    buffers: &[Vec<u8>],
    rows: usize,
) -> Result<(Vec<LevelEvent>, Vec<(bool, Vec<u8>)>), MaskuraError> {
    if buffers.is_empty() || buffers.len() > 2 {
        return Err(unsupported(
            "Lance full-zip page declares an unexpected buffer count",
        ));
    }
    if rows != num_items as usize {
        return Err(unsupported(
            "Lance full-zip page without control words cannot carry null or list levels",
        ));
    }
    let data = &buffers[0];
    let slots = match values {
        ValueCompression::Flat { bits_per_value } => {
            let raw = read_fixed_width(data, bits_per_value, rows)?;
            raw.into_iter().map(|bytes| (true, bytes)).collect()
        }
        ValueCompression::Variable => {
            let width = match bits_per_offset {
                Some(32) => 4_usize,
                Some(64) => 8_usize,
                other => {
                    return Err(unsupported(format!(
                        "unsupported Lance full-zip offset width {other:?}"
                    )));
                }
            };
            let mut slots = Vec::with_capacity(rows);
            let mut cursor = 0_usize;
            for _ in 0..rows {
                if data.len() - cursor < width {
                    return Err(unsupported("Lance full-zip values are truncated"));
                }
                let size = if width == 4 {
                    u32::from_le_bytes([
                        data[cursor],
                        data[cursor + 1],
                        data[cursor + 2],
                        data[cursor + 3],
                    ]) as usize
                } else {
                    usize::try_from(u64::from_le_bytes(
                        data[cursor..cursor + 8].try_into().expect("8-byte slice"),
                    ))
                    .map_err(|_| unsupported("Lance full-zip value size overflows this platform"))?
                };
                cursor += width;
                if data.len() - cursor < size {
                    return Err(unsupported("Lance full-zip values are truncated"));
                }
                slots.push((true, data[cursor..cursor + size].to_vec()));
                cursor += size;
            }
            slots
        }
    };
    let events = (0..rows)
        .map(|_| LevelEvent {
            rep: 0,
            def: 0,
            termination: Termination::Item,
        })
        .collect();
    Ok((events, slots))
}

fn read_fixed_width(
    bytes: &[u8],
    bits_per_value: u64,
    rows: usize,
) -> Result<Vec<Vec<u8>>, MaskuraError> {
    if bits_per_value == 0 {
        return Err(unsupported("Lance flat encoding needs a positive width"));
    }
    let total_bits = bits_per_value
        .checked_mul(rows as u64)
        .ok_or_else(|| unsupported("Lance flat encoding overflows its row count"))?;
    let needed = total_bits.div_ceil(8) as usize;
    if bytes.len() < needed {
        return Err(unsupported("Lance flat values are truncated"));
    }
    let mut values = Vec::with_capacity(rows);
    if bits_per_value.is_multiple_of(8) {
        let stride = (bits_per_value / 8) as usize;
        for row in 0..rows {
            values.push(bytes[row * stride..(row + 1) * stride].to_vec());
        }
        return Ok(values);
    }
    if bits_per_value != 1 {
        return Err(unsupported(
            "Lance bit-packed encodings other than 1-bit values are not supported",
        ));
    }
    for row in 0..rows {
        let byte = bytes[row / 8];
        values.push(vec![(byte >> (row % 8)) & 1]);
    }
    Ok(values)
}

// ---------------------------------------------------------------------------
// Legacy (v2.0) page decoding
// ---------------------------------------------------------------------------

fn page_buffer(buffers: &[Vec<u8>], buffer: BufferRef) -> Result<&[u8], MaskuraError> {
    if buffer.buffer_type != 0 {
        return Err(unsupported(
            "Lance column and file buffers are not supported by this codec",
        ));
    }
    buffers
        .get(buffer.index as usize)
        .map(Vec::as_slice)
        .ok_or_else(|| unsupported("Lance page references a buffer that does not exist"))
}

fn decode_flat_bytes(
    encoding: &LegacyArrayEncoding,
    buffers: &[Vec<u8>],
    rows: usize,
) -> Result<Vec<Vec<u8>>, MaskuraError> {
    let mut encoding = encoding;
    while let LegacyArrayEncoding::Nullable(nullable) = encoding {
        match nullable.as_ref() {
            LegacyNullable::NoNull { values } => encoding = values,
            _ => {
                return Err(unsupported("Lance offset arrays cannot carry nullability"));
            }
        }
    }
    let LegacyArrayEncoding::Flat {
        bits_per_value,
        buffer,
    } = encoding
    else {
        return Err(unsupported("Lance column values must use a flat encoding"));
    };
    let bytes = page_buffer(buffers, *buffer)?;
    read_fixed_width(bytes, *bits_per_value, rows)
}

#[allow(clippy::only_used_in_recursion)]
fn decode_legacy_column(
    encoding: &LegacyArrayEncoding,
    buffers: &[Vec<u8>],
    rows: usize,
    shape: FieldShape,
) -> Result<Vec<ColumnSlot>, MaskuraError> {
    match encoding {
        LegacyArrayEncoding::Flat { .. } => {
            let values = decode_flat_bytes(encoding, buffers, rows)?;
            Ok(values
                .into_iter()
                .map(|bytes| ColumnSlot::Scalar { valid: true, bytes })
                .collect())
        }
        LegacyArrayEncoding::Nullable(nullable) => match nullable.as_ref() {
            LegacyNullable::NoNull { values } => decode_legacy_column(values, buffers, rows, shape),
            LegacyNullable::AllNull => Ok((0..rows)
                .map(|_| ColumnSlot::Scalar {
                    valid: false,
                    bytes: Vec::new(),
                })
                .collect()),
            LegacyNullable::SomeNull { validity, values } => {
                let bits = decode_flat_bytes(validity, buffers, rows)?;
                let mut slots = decode_legacy_column(values, buffers, rows, shape)?;
                for (slot, bit) in slots.iter_mut().zip(bits.iter()) {
                    let valid = !bit.is_empty() && bit[0] & 1 == 1;
                    match slot {
                        ColumnSlot::Scalar {
                            valid: slot_valid,
                            bytes,
                        } => {
                            *slot_valid = valid;
                            if !valid {
                                bytes.clear();
                            }
                        }
                        ColumnSlot::Range {
                            valid: slot_valid, ..
                        }
                        | ColumnSlot::Items {
                            valid: slot_valid, ..
                        } => *slot_valid = valid,
                    }
                }
                Ok(slots)
            }
        },
        LegacyArrayEncoding::Binary {
            indices,
            bytes,
            null_adjustment,
        } => {
            let ends = decode_flat_bytes(indices, buffers, rows)?;
            let payload = binary_payload(bytes, buffers)?;
            binary_slots(&ends, &payload, *null_adjustment, rows)
        }
        LegacyArrayEncoding::List {
            offsets,
            null_offset_adjustment,
            ..
        } => {
            let ends = decode_flat_bytes(offsets, buffers, rows)?;
            list_slots(&ends, *null_offset_adjustment, rows)
        }
        LegacyArrayEncoding::FixedSizeList {
            dimension, items, ..
        } => {
            let dimension = *dimension as usize;
            let rows_total = rows
                .checked_mul(dimension)
                .ok_or_else(|| unsupported("Lance fixed-size-list rows overflow"))?;
            let flat = decode_flat_bytes(items, buffers, rows_total)?;
            Ok((0..rows)
                .map(|row| ColumnSlot::Items {
                    valid: true,
                    items: flat[row * dimension..(row + 1) * dimension]
                        .iter()
                        .map(|bytes| (true, bytes.clone()))
                        .collect(),
                })
                .collect())
        }
        LegacyArrayEncoding::SimpleStruct => Ok((0..rows)
            .map(|_| ColumnSlot::Scalar {
                valid: true,
                bytes: Vec::new(),
            })
            .collect()),
        LegacyArrayEncoding::Unsupported(reason) => Err(unsupported(*reason)),
    }
}

/// The raw value buffer of a `Binary` bytes encoding.
fn binary_payload(
    encoding: &LegacyArrayEncoding,
    buffers: &[Vec<u8>],
) -> Result<Vec<u8>, MaskuraError> {
    let mut encoding = encoding;
    while let LegacyArrayEncoding::Nullable(nullable) = encoding {
        match nullable.as_ref() {
            LegacyNullable::NoNull { values } => encoding = values,
            _ => {
                return Err(unsupported(
                    "Lance binary payloads cannot carry nullability",
                ));
            }
        }
    }
    let LegacyArrayEncoding::Flat {
        bits_per_value: 8,
        buffer,
    } = encoding
    else {
        return Err(unsupported(
            "Lance binary payloads must use a flat byte encoding",
        ));
    };
    Ok(page_buffer(buffers, *buffer)?.to_vec())
}

fn binary_slots(
    ends: &[Vec<u8>],
    payload: &[u8],
    null_adjustment: u64,
    rows: usize,
) -> Result<Vec<ColumnSlot>, MaskuraError> {
    if ends.len() != rows {
        return Err(unsupported(
            "Lance binary offsets do not match the row count",
        ));
    }
    let mut slots = Vec::with_capacity(rows);
    let mut base = 0_u64;
    for end in ends {
        let end_value = u64::from_le_bytes(fixed_bytes(end)?);
        let length = end_value
            .checked_sub(base)
            .ok_or_else(|| unsupported("Lance binary offsets are not increasing"))?;
        if length >= null_adjustment {
            slots.push(ColumnSlot::Scalar {
                valid: false,
                bytes: Vec::new(),
            });
            base = end_value % null_adjustment;
        } else {
            let start = base as usize;
            let end = end_value as usize;
            if end > payload.len() {
                return Err(unsupported("Lance binary offsets exceed the value buffer"));
            }
            slots.push(ColumnSlot::Scalar {
                valid: true,
                bytes: payload[start..end].to_vec(),
            });
            base = end_value;
        }
    }
    Ok(slots)
}

fn list_slots(
    ends: &[Vec<u8>],
    null_offset_adjustment: u64,
    rows: usize,
) -> Result<Vec<ColumnSlot>, MaskuraError> {
    if ends.len() != rows {
        return Err(unsupported("Lance list offsets do not match the row count"));
    }
    let mut slots = Vec::with_capacity(rows);
    let mut base = 0_u64;
    for end in ends {
        let end_value = u64::from_le_bytes(fixed_bytes(end)?);
        let length = end_value
            .checked_sub(base)
            .ok_or_else(|| unsupported("Lance list offsets are not increasing"))?;
        if length >= null_offset_adjustment {
            slots.push(ColumnSlot::Range {
                valid: false,
                start: 0,
                end: 0,
            });
            base = end_value % null_offset_adjustment;
        } else {
            let start = usize::try_from(base)
                .map_err(|_| unsupported("Lance list offsets overflow this platform"))?;
            let end = usize::try_from(end_value)
                .map_err(|_| unsupported("Lance list offsets overflow this platform"))?;
            slots.push(ColumnSlot::Range {
                valid: true,
                start,
                end,
            });
            base = end_value;
        }
    }
    Ok(slots)
}

// ---------------------------------------------------------------------------
// Row assembly across sibling columns
// ---------------------------------------------------------------------------

/// Leaf field indices of a field's subtree, in field order.
fn subtree_leaves(plans: &[FieldPlan], field: usize) -> Vec<usize> {
    if plans[field].children.is_empty() {
        return vec![field];
    }
    let mut leaves = Vec::new();
    for child in &plans[field].children {
        leaves.extend(subtree_leaves(plans, *child));
    }
    leaves
}

/// Merges one row's per-column nodes into one IR value.
///
/// `depth` counts levels below the top-level field: depth 0 is the top-level
/// field's value. `nodes` holds one node per leaf column of the subtree.
fn merge_level(
    plans: &[FieldPlan],
    field: usize,
    depth: usize,
    nodes: &[&Node],
) -> Result<Value, MaskuraError> {
    let plan = &plans[field];
    if plan.children.is_empty() {
        let node = nodes
            .first()
            .ok_or_else(|| unsupported("Lance leaf field is missing its column"))?;
        if nodes.len() != 1 {
            return Err(unsupported("Lance leaf field has more than one column"));
        }
        return match node {
            Node::Value { valid, bytes } => scalar_value(
                &ColumnSlot::Scalar {
                    valid: *valid,
                    bytes: bytes.clone(),
                },
                &plan.node,
            ),
            Node::NullStruct { depth: node_depth } => {
                if *node_depth == depth {
                    Ok(Value::Null)
                } else {
                    Err(unsupported(
                        "Lance null-struct marker landed at the wrong level",
                    ))
                }
            }
            Node::List { .. } => Err(unsupported("Lance leaf column rebuilt a list node")),
        };
    }
    match plan.shape {
        FieldShape::Struct => {
            let mut null_votes = 0_usize;
            for node in nodes {
                match node {
                    Node::NullStruct { depth: node_depth } if *node_depth == depth => {
                        null_votes += 1
                    }
                    Node::NullStruct { .. } => {
                        return Err(unsupported(
                            "Lance null-struct marker landed at the wrong level",
                        ));
                    }
                    _ => {}
                }
            }
            if null_votes > 0 {
                if null_votes != nodes.len() {
                    return Err(unsupported(
                        "Lance sibling columns disagree about struct validity",
                    ));
                }
                return Ok(Value::Null);
            }
            let leaves = subtree_leaves(plans, field);
            let mut fields = Vec::with_capacity(plan.children.len());
            let mut consumed = 0_usize;
            for child in &plan.children {
                let child_leaves = subtree_leaves(plans, *child);
                let child_nodes = nodes
                    .get(consumed..consumed + child_leaves.len())
                    .ok_or_else(|| unsupported("Lance struct columns are missing child values"))?;
                consumed += child_leaves.len();
                fields.push(ValueField {
                    name: plans[*child].message.name.clone(),
                    value: merge_level(plans, *child, depth + 1, child_nodes)?,
                });
            }
            let _ = leaves;
            if consumed != nodes.len() {
                return Err(unsupported(
                    "Lance struct columns do not match their schema",
                ));
            }
            Ok(Value::Record { fields })
        }
        FieldShape::List => {
            let child = plan
                .children
                .first()
                .ok_or_else(|| unsupported("Lance list field is missing its child"))?;
            let mut lengths: Vec<(bool, usize)> = Vec::new();
            for node in nodes {
                match node {
                    Node::List { valid, items } => {
                        let signature = (*valid, items.len());
                        if lengths.first().is_some_and(|first| *first != signature) {
                            return Err(unsupported(
                                "Lance sibling columns disagree about list structure",
                            ));
                        }
                        lengths.push(signature);
                    }
                    Node::NullStruct { depth: node_depth } if *node_depth == depth => {
                        return Ok(Value::Null);
                    }
                    _ => {
                        return Err(unsupported("Lance list column rebuilt a non-list node"));
                    }
                }
            }
            let (valid, len) = lengths.first().copied().unwrap_or((true, 0));
            if !valid {
                return Ok(Value::Null);
            }
            let mut items = Vec::with_capacity(len);
            for index in 0..len {
                let mut item_nodes = Vec::with_capacity(nodes.len());
                for node in nodes {
                    let Node::List { items, .. } = node else {
                        return Err(unsupported("Lance list column rebuilt a non-list node"));
                    };
                    item_nodes.push(
                        items
                            .get(index)
                            .ok_or_else(|| unsupported("Lance list lengths disagree"))?,
                    );
                }
                items.push(merge_level(plans, *child, depth + 1, &item_nodes)?);
            }
            Ok(Value::Array { items })
        }
        FieldShape::FixedSizeList { .. }
        | FieldShape::Var
        | FieldShape::Bool
        | FieldShape::Fixed { .. } => {
            Err(unsupported("Lance container field rebuilt a leaf shape"))
        }
    }
}

// ---------------------------------------------------------------------------
// Structural event emission (encode)
// ---------------------------------------------------------------------------

struct EmitEvent {
    rep: u16,
    termination: Termination,
    value: Option<(bool, Vec<u8>)>,
}

struct EmitSink {
    events: Vec<EmitEvent>,
    pending_rep: u16,
    layers: Vec<RepDefLayer>,
    roles: Vec<LayerRole>,
    list_count: usize,
    chain: Vec<usize>,
}

impl EmitSink {
    fn emit(&mut self, termination: Termination, value: Option<(bool, Vec<u8>)>) {
        self.events.push(EmitEvent {
            rep: self.pending_rep,
            termination,
            value,
        });
        self.pending_rep = 0;
    }
}

fn emit_column(
    sink: &mut EmitSink,
    plans: &[FieldPlan],
    values: &[Value],
) -> Result<(), MaskuraError> {
    let top_position = sink.roles.len();
    for value in values {
        sink.pending_rep = sink.pending_rep.max(sink.list_count as u16);
        emit_at(sink, plans, value, top_position)?;
    }
    Ok(())
}

fn emit_at(
    sink: &mut EmitSink,
    plans: &[FieldPlan],
    value: &Value,
    position: usize,
) -> Result<(), MaskuraError> {
    let role = sink.roles[position - 1];
    match role {
        LayerRole::Item => {
            let leaf = *sink
                .chain
                .first()
                .ok_or_else(|| unsupported("Lance emit path is empty"))?;
            let (valid, bytes) = scalar_bytes(value, &plans[leaf].node)?;
            let termination = if valid {
                Termination::Item
            } else {
                Termination::NullItem
            };
            sink.emit(termination, Some((valid, bytes)));
            Ok(())
        }
        LayerRole::Struct => {
            let field = sink.chain[position - 1];
            let child = *sink
                .chain
                .get(position - 2)
                .ok_or_else(|| unsupported("Lance emit path is truncated"))?;
            let child_name = &plans[child].message.name;
            match value {
                Value::Null => {
                    sink.emit(
                        Termination::NullStruct { layer: position },
                        Some((false, Vec::new())),
                    );
                    Ok(())
                }
                Value::Record { fields } => {
                    let child_value = fields
                        .iter()
                        .find(|candidate| candidate.name == *child_name)
                        .map(|candidate| &candidate.value)
                        .ok_or_else(|| {
                            unsupported(format!(
                                "Lance record value is missing field {child_name:?}"
                            ))
                        })?;
                    let _ = field;
                    emit_at(sink, plans, child_value, position - 1)
                }
                _ => Err(unsupported(
                    "Lance struct column received a non-record value",
                )),
            }
        }
        LayerRole::List { list_index } => {
            let child = *sink
                .chain
                .get(position - 2)
                .ok_or_else(|| unsupported("Lance emit path is truncated"))?;
            let _ = child;
            match value {
                Value::Null => {
                    sink.pending_rep = sink.pending_rep.max(list_index as u16);
                    sink.emit(
                        Termination::NullList {
                            list_layer: list_index,
                        },
                        None,
                    );
                    Ok(())
                }
                Value::Array { items } if items.is_empty() => {
                    sink.pending_rep = sink.pending_rep.max(list_index as u16);
                    sink.emit(
                        Termination::EmptyList {
                            list_layer: list_index,
                        },
                        None,
                    );
                    Ok(())
                }
                Value::Array { items } => {
                    sink.pending_rep = sink.pending_rep.max(list_index as u16);
                    for item in items {
                        emit_at(sink, plans, item, position - 1)?;
                    }
                    Ok(())
                }
                _ => Err(unsupported("Lance list column received a non-array value")),
            }
        }
    }
}

/// Chooses the repetition/definition layer kinds from the events a column
/// actually emits: kinds describe observed data, not the schema.
fn observed_layers(roles: &[LayerRole], events: &[EmitEvent]) -> Vec<RepDefLayer> {
    let mut item_nullable = false;
    let mut struct_nulls = vec![false; roles.len()];
    let mut list_nulls = vec![false; roles.len()];
    let mut list_empty = vec![false; roles.len()];
    for event in events {
        match event.termination {
            Termination::Item => {}
            Termination::NullItem => item_nullable = true,
            Termination::NullStruct { layer } => {
                item_nullable = true;
                if let Some(flag) = struct_nulls.get_mut(layer - 1) {
                    *flag = true;
                }
            }
            Termination::NullList { list_layer } | Termination::EmptyList { list_layer } => {
                let position = roles
                    .iter()
                    .enumerate()
                    .filter(|(_, role)| matches!(role, LayerRole::List { .. }))
                    .nth(list_layer - 1)
                    .map(|(index, _)| index);
                if let Some(index) = position {
                    match event.termination {
                        Termination::NullList { .. } => list_nulls[index] = true,
                        _ => list_empty[index] = true,
                    }
                }
            }
        }
    }
    roles
        .iter()
        .enumerate()
        .map(|(index, role)| match role {
            LayerRole::Item => {
                if item_nullable {
                    RepDefLayer::NullableItem
                } else {
                    RepDefLayer::AllValidItem
                }
            }
            LayerRole::Struct => {
                if struct_nulls[index] {
                    RepDefLayer::NullableItem
                } else {
                    RepDefLayer::AllValidItem
                }
            }
            LayerRole::List { .. } => match (list_nulls[index], list_empty[index]) {
                (false, false) => RepDefLayer::AllValidList,
                (false, true) => RepDefLayer::EmptyableList,
                (true, false) => RepDefLayer::NullableList,
                (true, true) => RepDefLayer::NullAndEmptyList,
            },
        })
        .collect()
}

/// Builds the event stream and materialized slots of one structural column.
#[allow(clippy::type_complexity)]
fn encode_column_events(
    sink: &mut EmitSink,
    plans: &[FieldPlan],
    values: &[Value],
) -> Result<(Vec<LevelEvent>, Vec<(bool, Vec<u8>)>), MaskuraError> {
    emit_column(sink, plans, values)?;
    sink.layers = observed_layers(&sink.roles, &sink.events);
    let mut events = Vec::with_capacity(sink.events.len());
    let mut slots = Vec::new();
    for event in &sink.events {
        let def = compute_def(&sink.layers, event.termination)?;
        events.push(LevelEvent {
            rep: event.rep,
            def,
            termination: event.termination,
        });
        if materialized(event.termination) {
            slots.push(
                event
                    .value
                    .clone()
                    .ok_or_else(|| unsupported("Lance emitted an event without its value"))?,
            );
        }
    }
    Ok((events, slots))
}

// ---------------------------------------------------------------------------
// Structural page encoding
// ---------------------------------------------------------------------------

fn encode_levels(events: &[LevelEvent], get: fn(&LevelEvent) -> u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(events.len() * 2);
    for event in events {
        out.extend_from_slice(&get(event).to_le_bytes());
    }
    out
}

fn encode_value_buffer(
    values: &ValueCompression,
    slots: &[(bool, Vec<u8>)],
    shape: FieldShape,
) -> Result<Vec<u8>, MaskuraError> {
    match values {
        ValueCompression::Flat { bits_per_value } => {
            if *bits_per_value == 1 {
                return Ok(encode_flat_bits(slots));
            }
            let width = match shape {
                FieldShape::Fixed { width_bytes } => width_bytes,
                _ => {
                    return Err(unsupported(
                        "Lance flat values cannot encode a variable-width column",
                    ));
                }
            };
            let mut out = Vec::with_capacity(slots.len() * width);
            for (valid, bytes) in slots {
                if *valid {
                    if bytes.len() != width {
                        return Err(unsupported(
                            "Lance flat value has the wrong size for its column",
                        ));
                    }
                    out.extend_from_slice(bytes);
                } else {
                    out.extend(std::iter::repeat_n(0_u8, width));
                }
            }
            Ok(out)
        }
        ValueCompression::Variable => {
            let mut offsets = Vec::with_capacity(slots.len() + 1);
            let mut data = Vec::new();
            let mut position = (slots.len() + 1) * 4;
            offsets.push(position as u32);
            for (valid, bytes) in slots {
                if *valid {
                    data.extend_from_slice(bytes);
                    position += bytes.len();
                }
                offsets.push(position as u32);
            }
            // The reference writer pads the value bytes to the offset width.
            while data.len() % 4 != 0 {
                data.push(0);
            }
            let mut out = Vec::with_capacity(position + 4);
            for offset in offsets {
                out.extend_from_slice(&offset.to_le_bytes());
            }
            out.extend_from_slice(&data);
            Ok(out)
        }
    }
}

fn encode_flat_bits(slots: &[(bool, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![0_u8; slots.len().div_ceil(8)];
    for (index, (valid, bytes)) in slots.iter().enumerate() {
        if *valid && !bytes.is_empty() && bytes[0] & 1 == 1 {
            out[index / 8] |= 1 << (index % 8);
        }
    }
    out
}

/// Encodes one structural column into its page buffers and page metadata.
#[allow(clippy::type_complexity)]
fn encode_structural_column(
    plan: &ColumnPlan,
    events: &[LevelEvent],
    slots: &[(bool, Vec<u8>)],
    rows: usize,
    shape: FieldShape,
) -> Result<(PageMessage, Vec<Vec<u8>>), MaskuraError> {
    let has_lists = plan.layers.iter().any(|layer| layer.is_list());
    let has_modes = plan
        .layers
        .iter()
        .any(|layer| !layer.def_modes().is_empty());
    let values = match shape {
        FieldShape::Var => ValueCompression::Variable,
        FieldShape::Bool => ValueCompression::Flat { bits_per_value: 1 },
        FieldShape::Fixed { width_bytes } => ValueCompression::Flat {
            bits_per_value: width_bytes as u64 * 8,
        },
        _ => {
            return Err(unsupported(
                "Lance structural columns must hold leaf values",
            ));
        }
    };
    let rep_bytes = if has_lists {
        Some(encode_levels(events, |event| event.rep))
    } else {
        None
    };
    let def_bytes = if has_modes {
        Some(encode_levels(events, |event| event.def))
    } else {
        None
    };
    let value_bytes = encode_value_buffer(&values, slots, shape)?;

    // Chunk header: [u16 level entries][u16 rep size][u16 def size][u32 value
    // size]. Sizes are u32 because this codec writes large-chunk (2.2) pages.
    let mut chunk = Vec::new();
    let level_entries = if rep_bytes.is_some() || def_bytes.is_some() {
        u16::try_from(events.len())
            .map_err(|_| unsupported("Lance page has too many events for one chunk"))?
    } else {
        0
    };
    chunk.extend_from_slice(&level_entries.to_le_bytes());
    for bytes in [&rep_bytes, &def_bytes].into_iter().flatten() {
        let size = u16::try_from(bytes.len())
            .map_err(|_| unsupported("Lance level buffer exceeds the u16 size range"))?;
        chunk.extend_from_slice(&size.to_le_bytes());
    }
    let value_size = u32::try_from(value_bytes.len())
        .map_err(|_| unsupported("Lance value buffer exceeds the u32 size range"))?;
    chunk.extend_from_slice(&value_size.to_le_bytes());
    chunk.resize(chunk.len().div_ceil(8) * 8, 0xFE);
    for bytes in [&rep_bytes, &def_bytes, &Some(value_bytes.clone())]
        .into_iter()
        .flatten()
    {
        chunk.extend_from_slice(bytes);
        chunk.resize(chunk.len().div_ceil(8) * 8, 0xFE);
    }
    if !chunk.len().is_multiple_of(8) {
        return Err(unsupported("Lance chunk is not 8-byte aligned"));
    }
    let words = (chunk.len() / 8)
        .checked_sub(1)
        .ok_or_else(|| unsupported("Lance chunk is too small"))?;
    let mut chunk_metadata = Vec::new();
    chunk_metadata.extend_from_slice(
        &u32::try_from((words << 4) | usize::from(false))
            .map_err(|_| unsupported("Lance chunk is too large for its metadata word"))?
            .to_le_bytes(),
    );

    let mut buffers = vec![chunk_metadata, chunk];
    if has_lists {
        let mut index = Vec::new();
        index.extend_from_slice(&(rows as u64).to_le_bytes());
        index.extend_from_slice(&0_u64.to_le_bytes());
        buffers.push(index);
    }

    // The structural page layout description: PageLayout{mini_block_layout}.
    let mut miniblock = Vec::new();
    if has_lists {
        let mut flat = Vec::new();
        write_varint_field(&mut flat, 1, 16);
        let mut compression = Vec::new();
        write_bytes_field(&mut compression, 1, &flat);
        write_bytes_field(&mut miniblock, 1, &compression);
    }
    if has_modes {
        let mut flat = Vec::new();
        write_varint_field(&mut flat, 1, 16);
        let mut compression = Vec::new();
        write_bytes_field(&mut compression, 1, &flat);
        write_bytes_field(&mut miniblock, 2, &compression);
    }
    write_bytes_field(&mut miniblock, 3, &encode_compressive(&values));
    write_packed_u64_field(
        &mut miniblock,
        6,
        &plan
            .layers
            .iter()
            .map(|layer| u64::from(layer.to_proto()))
            .collect::<Vec<_>>(),
    );
    write_varint_field(&mut miniblock, 7, 1);
    if has_lists {
        write_varint_field(&mut miniblock, 8, 1);
    }
    write_varint_field(&mut miniblock, 9, slots.len() as u64);
    write_varint_field(&mut miniblock, 10, 1);
    let mut layout = Vec::new();
    write_bytes_field(&mut layout, 1, &miniblock);

    let any = AnyMessage {
        type_url: STRUCTURAL_PAGE_LAYOUT.to_string(),
        value: layout,
    };
    let page = PageMessage {
        buffer_offsets: Vec::new(),
        buffer_sizes: Vec::new(),
        length: rows as u64,
        encoding: Some(EncodingMessage {
            direct: Some(any.encode()),
        }),
        priority: 0,
    };
    Ok((page, buffers))
}

fn encode_compressive(values: &ValueCompression) -> Vec<u8> {
    let mut out = Vec::new();
    match values {
        ValueCompression::Flat { bits_per_value } => {
            let mut flat = Vec::new();
            write_varint_field(&mut flat, 1, *bits_per_value);
            write_bytes_field(&mut out, 1, &flat);
        }
        ValueCompression::Variable => {
            let mut flat = Vec::new();
            write_varint_field(&mut flat, 1, 32);
            let mut offsets = Vec::new();
            write_bytes_field(&mut offsets, 1, &flat);
            let mut variable = Vec::new();
            write_bytes_field(&mut variable, 1, &offsets);
            write_bytes_field(&mut out, 2, &variable);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Container input/output
// ---------------------------------------------------------------------------

struct LanceFile {
    descriptor: FileDescriptor,
    columns: Vec<ColumnMetadataMessage>,
}

fn parse_container(source: &[u8]) -> Result<LanceFile, MaskuraError> {
    let footer = validate_magic_footer(source)?;
    let read_table_entry = |start: u64, index: usize| -> Result<(u64, u64), MaskuraError> {
        let offset = start as usize + index * 16;
        let entry = source
            .get(offset..offset + 16)
            .ok_or_else(|| unsupported("Lance metadata table entry is truncated"))?;
        let read = |at: usize| {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(&entry[at..at + 8]);
            u64::from_le_bytes(bytes)
        };
        Ok((read(0), read(8)))
    };
    let mut columns = Vec::with_capacity(footer.num_columns as usize);
    for index in 0..footer.num_columns as usize {
        let (position, size) = read_table_entry(footer.column_meta_offsets_start, index)?;
        let raw = source
            .get(position as usize..position as usize + size as usize)
            .ok_or_else(|| unsupported("Lance column metadata is truncated"))?;
        columns.push(ColumnMetadataMessage::decode(raw)?);
    }
    let (position, size) = read_table_entry(footer.global_buffer_offsets_start, 0)?;
    let raw = source
        .get(position as usize..position as usize + size as usize)
        .ok_or_else(|| unsupported("Lance schema buffer is truncated"))?;
    let descriptor = FileDescriptor::decode(raw)?;
    Ok(LanceFile {
        descriptor,
        columns,
    })
}

fn page_buffers(source: &[u8], page: &PageMessage) -> Result<Vec<Vec<u8>>, MaskuraError> {
    page.buffer_offsets
        .iter()
        .zip(page.buffer_sizes.iter())
        .map(|(position, size)| {
            let end = position
                .checked_add(*size)
                .ok_or_else(|| unsupported("Lance page buffer range overflows"))?;
            source
                .get(*position as usize..end as usize)
                .map(|bytes| bytes.to_vec())
                .ok_or_else(|| unsupported("Lance page buffer is truncated"))
        })
        .collect()
}

/// The grammar family of one page encoding.
enum PageGrammar {
    Legacy(LegacyArrayEncoding),
    Structural(StructuralPage),
}

fn page_grammar(page: &PageMessage) -> Result<PageGrammar, MaskuraError> {
    let encoding = page
        .encoding
        .as_ref()
        .and_then(|encoding| encoding.direct.as_ref())
        .ok_or_else(|| unsupported("Lance page has no encoding description"))?;
    let any = AnyMessage::decode(encoding)?;
    match any.type_url.as_str() {
        LEGACY_ARRAY_ENCODING => Ok(PageGrammar::Legacy(LegacyArrayEncoding::decode(
            &any.value,
        )?)),
        STRUCTURAL_PAGE_LAYOUT => Ok(PageGrammar::Structural(parse_structural_page(&any.value)?)),
        other => Err(unsupported(format!(
            "unsupported Lance page encoding {other:?}"
        ))),
    }
}

fn column_grammar_ok(page: &PageMessage) -> Result<(), MaskuraError> {
    let encoding = page
        .encoding
        .as_ref()
        .and_then(|encoding| encoding.direct.as_ref())
        .ok_or_else(|| unsupported("Lance page has no encoding description"))?;
    let any = AnyMessage::decode(encoding)?;
    match any.type_url.as_str() {
        LEGACY_ARRAY_ENCODING | STRUCTURAL_PAGE_LAYOUT => Ok(()),
        other => Err(unsupported(format!(
            "unsupported Lance page encoding {other:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Public codec API
// ---------------------------------------------------------------------------

/// Decodes one Lance source and invokes `emit` once per logical record.
pub fn decode_lance<R, F>(
    source: R,
    limits: LanceLimits,
    mut emit: F,
) -> Result<SchemaIr, MaskuraError>
where
    R: Read,
    F: FnMut(ValueIr) -> Result<(), MaskuraError>,
{
    validate_limits(limits)?;
    let mut bytes = Vec::new();
    let mut source = source.take(limits.max_source_bytes as u64 + 1);
    source
        .read_to_end(&mut bytes)
        .map_err(|error| unsupported(format!("Lance source read failed: {error}")))?;
    if bytes.len() > limits.max_source_bytes {
        return Err(unsupported(
            "Lance source exceeds the configured byte limit",
        ));
    }
    let file = parse_container(&bytes)?;
    let rows = usize::try_from(file.descriptor.length)
        .map_err(|_| unsupported("Lance row count overflows this platform"))?;

    // The grammar family must be uniform across the file.
    let mut legacy: Option<bool> = None;
    for column in &file.columns {
        for page in &column.pages {
            column_grammar_ok(page)?;
            let is_legacy = matches!(page_grammar(page)?, PageGrammar::Legacy(_));
            match legacy {
                None => legacy = Some(is_legacy),
                Some(expected) if expected != is_legacy => {
                    return Err(unsupported(
                        "Lance file mixes legacy and structural page encodings",
                    ));
                }
                _ => {}
            }
        }
    }
    let legacy = legacy.unwrap_or(false);
    let plans = build_field_plans(&file.descriptor.schema, file.columns.len(), legacy)?;
    let roots: Vec<usize> = plans
        .iter()
        .enumerate()
        .filter(|(_, plan)| plan.message.parent_id == -1)
        .map(|(index, _)| index)
        .collect();

    let row_values = if legacy {
        decode_legacy_rows(&bytes, &file, &plans, &roots, rows)?
    } else {
        decode_structural_rows(&bytes, &file, &plans, &roots, rows)?
    };

    let schema = SchemaIr::new(SchemaNode::required(SchemaKind::Record {
        fields: roots
            .iter()
            .map(|root| SchemaField {
                name: plans[*root].message.name.clone(),
                schema: plans[*root].node.clone(),
            })
            .collect(),
    }));
    schema.validate(limits.ir)?;
    for row in row_values {
        let value = ValueIr::new(row);
        value.validate(&schema, limits.ir)?;
        emit(value)?;
    }
    Ok(schema)
}

fn decode_legacy_rows(
    source: &[u8],
    file: &LanceFile,
    plans: &[FieldPlan],
    roots: &[usize],
    rows: usize,
) -> Result<Vec<Value>, MaskuraError> {
    // Decode every column to slots keyed by field index.
    let mut slots: std::collections::BTreeMap<usize, Vec<ColumnSlot>> =
        std::collections::BTreeMap::new();
    for plan in plans {
        let Some(column) = plan.column else {
            continue;
        };
        let metadata = file
            .columns
            .get(column)
            .ok_or_else(|| unsupported("Lance column metadata is missing"))?;
        let mut column_slots = Vec::new();
        for page in &metadata.pages {
            let buffers = page_buffers(source, page)?;
            let PageGrammar::Legacy(encoding) = page_grammar(page)? else {
                return Err(unsupported(
                    "Lance file mixes legacy and structural page encodings",
                ));
            };
            let shape = plan.shape;
            column_slots.extend(decode_legacy_column(
                &encoding,
                &buffers,
                page.length as usize,
                shape,
            )?);
        }
        slots.insert(plan.message.id as usize, column_slots);
    }
    let mut per_field: BTreeMapWrapper = BTreeMapWrapper::default();
    for plan in plans.iter().rev() {
        let values = legacy_field_values(plans, plan, &slots, &mut per_field)?;
        per_field.0.insert(plan.message.id as usize, values);
    }
    let mut rows_out = Vec::with_capacity(rows);
    for row in 0..rows {
        let mut fields = Vec::with_capacity(roots.len());
        for root in roots {
            let values = per_field.0.get(root).ok_or_else(|| {
                unsupported("Lance top-level field is missing its decoded values")
            })?;
            let value = values
                .get(row)
                .ok_or_else(|| unsupported("Lance field values are shorter than the row count"))?
                .clone();
            fields.push(ValueField {
                name: plans[*root].message.name.clone(),
                value,
            });
        }
        rows_out.push(Value::Record { fields });
    }
    Ok(rows_out)
}

#[derive(Default)]
struct BTreeMapWrapper(std::collections::BTreeMap<usize, Vec<Value>>);

fn legacy_field_values(
    plans: &[FieldPlan],
    plan: &FieldPlan,
    slots: &std::collections::BTreeMap<usize, Vec<ColumnSlot>>,
    per_field: &mut BTreeMapWrapper,
) -> Result<Vec<Value>, MaskuraError> {
    let id = plan.message.id as usize;
    if plan.children.is_empty() || matches!(plan.shape, FieldShape::FixedSizeList { .. }) {
        let column_slots = slots
            .get(&id)
            .ok_or_else(|| unsupported("Lance leaf column is missing"))?;
        if matches!(plan.shape, FieldShape::FixedSizeList { .. }) {
            let SchemaKind::Array { items } = &plan.node.kind else {
                return Err(unsupported("Lance fixed-size-list field is malformed"));
            };
            return column_slots
                .iter()
                .map(|slot| match slot {
                    ColumnSlot::Items {
                        valid: true,
                        items: payloads,
                    } => Ok(Value::Array {
                        items: payloads
                            .iter()
                            .map(|(valid, bytes)| {
                                scalar_value(
                                    &ColumnSlot::Scalar {
                                        valid: *valid,
                                        bytes: bytes.clone(),
                                    },
                                    items,
                                )
                            })
                            .collect::<Result<Vec<_>, MaskuraError>>()?,
                    }),
                    _ => Ok(Value::Null),
                })
                .collect();
        }
        return column_slots
            .iter()
            .map(|slot| scalar_value(slot, &plan.node))
            .collect();
    }
    match plan.shape {
        FieldShape::Struct => {
            let child_values: Vec<&Vec<Value>> = plan
                .children
                .iter()
                .map(|child| {
                    per_field
                        .0
                        .get(child)
                        .ok_or_else(|| unsupported("Lance struct child values are missing"))
                })
                .collect::<Result<_, MaskuraError>>()?;
            let rows = child_values.first().map(|values| values.len()).unwrap_or(0);
            for values in &child_values {
                if values.len() != rows {
                    return Err(unsupported(
                        "Lance struct children disagree about their row counts",
                    ));
                }
            }
            let column_slots = slots.get(&id);
            (0..rows)
                .map(|row| {
                    if let Some(column_slots) = column_slots
                        && let Some(ColumnSlot::Scalar { valid: false, .. }) = column_slots.get(row)
                    {
                        return Ok(Value::Null);
                    }
                    let fields = plan
                        .children
                        .iter()
                        .zip(child_values.iter())
                        .map(|(child, values)| ValueField {
                            name: plans[*child].message.name.clone(),
                            value: values[row].clone(),
                        })
                        .collect();
                    Ok(Value::Record { fields })
                })
                .collect::<Result<Vec<_>, MaskuraError>>()
        }
        FieldShape::List | FieldShape::FixedSizeList { .. } => {
            let child = plan
                .children
                .first()
                .ok_or_else(|| unsupported("Lance list field is missing its child"))?;
            let child_values = per_field
                .0
                .get(child)
                .ok_or_else(|| unsupported("Lance list child values are missing"))?;
            let column_slots = slots
                .get(&id)
                .ok_or_else(|| unsupported("Lance list column is missing"))?;
            column_slots
                .iter()
                .map(|slot| match slot {
                    ColumnSlot::Range {
                        valid: true,
                        start,
                        end,
                    } => {
                        if *end > child_values.len() || start > end {
                            return Err(unsupported("Lance list offsets exceed the item column"));
                        }
                        Ok(Value::Array {
                            items: child_values[*start..*end].to_vec(),
                        })
                    }
                    _ => Ok(Value::Null),
                })
                .collect()
        }
        _ => Err(unsupported("Lance leaf field cannot have children")),
    }
}

fn decode_structural_rows(
    source: &[u8],
    file: &LanceFile,
    plans: &[FieldPlan],
    roots: &[usize],
    rows: usize,
) -> Result<Vec<Value>, MaskuraError> {
    let mut leaf_nodes: BTreeMapWrapper2 = BTreeMapWrapper2::default();
    for plan in plans {
        if !plan.children.is_empty() {
            continue;
        }
        let id = plan.message.id as usize;
        let column = plan
            .column
            .ok_or_else(|| unsupported("Lance leaf column is missing"))?;
        let metadata = file
            .columns
            .get(column)
            .ok_or_else(|| unsupported("Lance column metadata is missing"))?;
        let plan_roles = column_plan(plans, id)?;
        let mut events = Vec::new();
        let mut slots = Vec::new();
        for page in &metadata.pages {
            let buffers = page_buffers(source, page)?;
            let PageGrammar::Structural(page_encoding) = page_grammar(page)? else {
                return Err(unsupported(
                    "Lance file mixes legacy and structural page encodings",
                ));
            };
            let (page_events, page_slots) =
                decode_structural_page(&page_encoding, &buffers, page.length as usize, plan.shape)?;
            // Definition levels are interpreted against the page's own
            // layers, which the writer derives from the same schema.
            events.extend(page_events);
            slots.extend(page_slots);
        }
        let nodes = assemble_column(&plan_roles, &events, &slots, rows)?;
        leaf_nodes.0.insert(id, nodes);
    }
    let mut rows_out = Vec::with_capacity(rows);
    for row in 0..rows {
        let mut fields = Vec::with_capacity(roots.len());
        for root in roots {
            let leaves = subtree_leaves(plans, *root);
            let mut nodes = Vec::with_capacity(leaves.len());
            for leaf in &leaves {
                let column = leaf_nodes.0.get(leaf).ok_or_else(|| {
                    unsupported("Lance leaf column is missing its rebuilt values")
                })?;
                nodes.push(
                    column
                        .get(row)
                        .ok_or_else(|| unsupported("Lance column is shorter than the row count"))?,
                );
            }
            fields.push(ValueField {
                name: plans[*root].message.name.clone(),
                value: merge_level(plans, *root, 0, &nodes)?,
            });
        }
        rows_out.push(Value::Record { fields });
    }
    Ok(rows_out)
}

#[derive(Default)]
struct BTreeMapWrapper2(std::collections::BTreeMap<usize, Vec<Node>>);

/// Encodes validated IR records into one Lance file using the structural
/// page grammar (the legacy grammar cannot represent nullable structs).
pub fn encode_lance(
    schema: &SchemaIr,
    values: &[ValueIr],
    limits: LanceLimits,
) -> Result<Vec<u8>, MaskuraError> {
    validate_limits(limits)?;
    schema.validate(limits.ir)?;
    for value in values {
        value.validate(schema, limits.ir)?;
    }
    let fields = schema_to_fields(schema)?;
    let rows = values.len();
    // Build the field plans against our own generated schema (structural
    // columns: one per leaf field).
    let message = SchemaMessage {
        fields: fields.clone(),
    };
    let leaf_count = fields
        .iter()
        .filter(|field| {
            field.logical_type != "struct"
                && field.logical_type != "list"
                && field.logical_type != "list.struct"
        })
        .count();
    let plans = build_field_plans(&message, leaf_count, false)?;
    let roots: Vec<usize> = plans
        .iter()
        .enumerate()
        .filter(|(_, plan)| plan.message.parent_id == -1)
        .map(|(index, _)| index)
        .collect();

    // Collect the per-row values of every top-level field.
    let mut top_values: Vec<Vec<Value>> = Vec::with_capacity(roots.len());
    for value in values {
        let Value::Record { fields } = &value.root else {
            return Err(unsupported("Lance output needs record values"));
        };
        for (index, root) in roots.iter().enumerate() {
            let field = fields
                .iter()
                .find(|candidate| candidate.name == plans[*root].message.name)
                .ok_or_else(|| unsupported("Lance record value is missing a top-level field"))?;
            if top_values.len() <= index {
                top_values.push(Vec::new());
            }
            top_values[index].push(field.value.clone());
        }
    }

    let descriptor = FileDescriptor {
        schema: message,
        length: rows as u64,
    };
    let mut column_pages = Vec::new();
    for plan in plans.iter() {
        if !plan.children.is_empty() {
            continue;
        }
        let id = plan.message.id as usize;
        let plan_layers = column_plan(&plans, id)?;
        // The values of this column's top-level field.
        let root_index = roots
            .iter()
            .position(|root| {
                let mut current = id;
                while let Some(parent) = plans[current].parent {
                    current = parent;
                }
                current == *root
            })
            .ok_or_else(|| unsupported("Lance leaf column has no top-level field"))?;
        let mut sink = EmitSink {
            events: Vec::new(),
            pending_rep: 0,
            layers: plan_layers.layers.clone(),
            roles: plan_layers.roles.clone(),
            list_count: plan_layers.list_count,
            chain: {
                let mut chain = Vec::new();
                let mut current = id;
                loop {
                    chain.push(current);
                    let Some(parent) = plans[current].parent else {
                        break;
                    };
                    current = parent;
                }
                chain
            },
        };
        let (events, slots) = encode_column_events(&mut sink, &plans, &top_values[root_index])?;
        let observed = ColumnPlan {
            roles: plan_layers.roles.clone(),
            layers: sink.layers.clone(),
            list_count: plan_layers.list_count,
        };
        let (page, buffers) =
            encode_structural_column(&observed, &events, &slots, rows, plan.shape)?;
        column_pages.push((page, buffers));
    }

    build_container(&descriptor, &column_pages, rows)
}

/// Assembles the container: page buffers, column metadata, offset tables, and
/// the footer.
fn build_container(
    descriptor: &FileDescriptor,
    column_pages: &[(PageMessage, Vec<Vec<u8>>)],
    rows: usize,
) -> Result<Vec<u8>, MaskuraError> {
    let mut out: Vec<u8> = Vec::new();
    // Page buffers reference absolute offsets; lay every buffer out first.
    let mut pages: Vec<(PageMessage, Vec<(u64, u64)>)> = Vec::with_capacity(column_pages.len());
    for (page, buffers) in column_pages {
        let mut positions = Vec::with_capacity(buffers.len());
        for buffer in buffers {
            align64(&mut out);
            let position = out.len() as u64;
            out.extend_from_slice(buffer);
            positions.push((position, buffer.len() as u64));
        }
        pages.push((page.clone(), positions));
    }
    align64(&mut out);
    let schema_position = out.len() as u64;
    let schema_bytes = descriptor.encode();
    out.extend_from_slice(&schema_bytes);

    let pages: Vec<PageMessage> = pages
        .into_iter()
        .map(|(mut page, positions)| {
            page.buffer_offsets = positions.iter().map(|(position, _)| *position).collect();
            page.buffer_sizes = positions.iter().map(|(_, size)| *size).collect();
            page
        })
        .collect();

    align64(&mut out);
    let column_meta_start = out.len() as u64;
    let mut column_positions = Vec::new();
    for page in &pages {
        let metadata = ColumnMetadataMessage {
            encoding: Some(EncodingMessage {
                direct: Some(
                    AnyMessage {
                        type_url: COLUMN_ENCODING.to_string(),
                        value: vec![0x0a, 0x00],
                    }
                    .encode(),
                ),
            }),
            pages: vec![page.clone()],
        };
        align64(&mut out);
        column_positions.push((out.len() as u64, metadata.encode().len() as u64));
        out.extend_from_slice(&metadata.encode());
    }
    // The offset tables sit flush against each other and the footer: readers
    // treat the column-metadata region as ending exactly at the global-buffer
    // offset table.
    let cmo_start = out.len() as u64;
    for (position, size) in &column_positions {
        out.extend_from_slice(&position.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
    }
    let gbo_start = out.len() as u64;
    out.extend_from_slice(&schema_position.to_le_bytes());
    out.extend_from_slice(&(schema_bytes.len() as u64).to_le_bytes());

    out.extend_from_slice(&column_meta_start.to_le_bytes());
    out.extend_from_slice(&cmo_start.to_le_bytes());
    out.extend_from_slice(&gbo_start.to_le_bytes());
    out.extend_from_slice(&(1_u32.to_le_bytes()));
    out.extend_from_slice(&(u32::try_from(pages.len()).unwrap_or(0).to_le_bytes()));
    out.extend_from_slice(&2_u16.to_le_bytes()); // major: v2.2 structural grammar
    out.extend_from_slice(&2_u16.to_le_bytes());
    out.extend_from_slice(LANCE_MAGIC);
    let _ = rows;
    Ok(out)
}

fn align64(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(64) {
        out.push(0);
    }
}

/// Runs one Lance source through a planned typed binary transform and emits a
/// new Lance file only after every accepted value has passed schema validation.
pub fn process_lance<R, Reductor, Transform>(
    source: R,
    limits: LanceLimits,
    pump: &mut BinaryPump<Reductor, Transform>,
) -> Result<Vec<u8>, MaskuraError>
where
    R: Read,
    Reductor: BinaryReductor,
    Transform: BinaryTransform,
{
    let mut values = Vec::new();
    let input_schema = decode_lance(source, limits, |value| {
        values.push(value);
        Ok(())
    })?;
    let output_schema = pump.plan(&input_schema)?.clone();
    let mut accepted = Vec::with_capacity(values.len());
    for value in values {
        if let Some(value) = pump.process(value)? {
            value.validate(&output_schema, limits.ir)?;
            accepted.push(value);
        }
    }
    encode_lance(&output_schema, &accepted, limits)
}
#[cfg(test)]
mod tests;
