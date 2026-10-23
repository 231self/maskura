//! Protobuf wire primitives and the Lance file-format messages.
//!
//! This module is a deliberately small, hand-rolled protobuf codec for the
//! exact message shapes the Lance container uses (`lance.file`, `lance.file.v2`,
//! `lance.encodings`, and `lance.encodings21`). It has no external protobuf
//! dependency and fails closed on malformed wire data: unknown *fields* on
//! known messages are skipped for forward compatibility, but unknown wire
//! types, length overflows, truncated buffers, and trailing garbage inside a
//! length-delimited field are rejected.
//!
//! Nothing outside the Lance codec edge depends on these types.

use maskura_error::{MaskuraError, codes};

const WIRE_VARINT: u32 = 0;
const WIRE_FIXED64: u32 = 1;
const WIRE_LEN: u32 = 2;
const WIRE_FIXED32: u32 = 5;

fn wire_error(message: impl Into<String>) -> MaskuraError {
    MaskuraError::new(codes::UNSUPPORTED_FORMAT, message)
}

/// A parsed protobuf field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireValue<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed32([u8; 4]),
    Fixed64([u8; 8]),
}

/// Iterates the fields of one protobuf message.
pub(crate) struct WireReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub(crate) fn next(&mut self) -> Result<Option<(u32, WireValue<'a>)>, MaskuraError> {
        if self.is_empty() {
            return Ok(None);
        }
        let key = self.read_varint()?;
        let (field, wire) = ((key >> 3) as u32, (key & 0x7) as u32);
        if field == 0 {
            return Err(wire_error("protobuf field number 0 is invalid"));
        }
        let value = match wire {
            WIRE_VARINT => WireValue::Varint(self.read_varint()?),
            WIRE_LEN => {
                let len = usize::try_from(self.read_varint()?)
                    .map_err(|_| wire_error("protobuf length overflows this platform"))?;
                let end = self
                    .pos
                    .checked_add(len)
                    .ok_or_else(|| wire_error("protobuf length overflows the buffer"))?;
                if end > self.buf.len() {
                    return Err(wire_error("protobuf field is truncated"));
                }
                let bytes = &self.buf[self.pos..end];
                self.pos = end;
                WireValue::Bytes(bytes)
            }
            WIRE_FIXED32 => {
                if self.buf.len() - self.pos < 4 {
                    return Err(wire_error("protobuf fixed32 field is truncated"));
                }
                let mut bytes = [0_u8; 4];
                bytes.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
                self.pos += 4;
                WireValue::Fixed32(bytes)
            }
            WIRE_FIXED64 => {
                if self.buf.len() - self.pos < 8 {
                    return Err(wire_error("protobuf fixed64 field is truncated"));
                }
                let mut bytes = [0_u8; 8];
                bytes.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
                self.pos += 8;
                WireValue::Fixed64(bytes)
            }
            other => {
                return Err(wire_error(format!(
                    "unsupported protobuf wire type {other} (groups are not valid Lance wire data)"
                )));
            }
        };
        Ok(Some((field, value)))
    }

    fn read_varint(&mut self) -> Result<u64, MaskuraError> {
        let mut value = 0_u64;
        let mut shift = 0_u32;
        loop {
            let byte = *self
                .buf
                .get(self.pos)
                .ok_or_else(|| wire_error("protobuf varint is truncated"))?;
            self.pos += 1;
            if shift >= 64 {
                return Err(wire_error("protobuf varint is too long"));
            }
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }
}

pub(crate) fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

pub(crate) fn write_key(out: &mut Vec<u8>, field: u32, wire: u32) {
    write_varint(out, (u64::from(field) << 3) | u64::from(wire));
}

pub(crate) fn write_varint_field(out: &mut Vec<u8>, field: u32, value: u64) {
    write_key(out, field, WIRE_VARINT);
    write_varint(out, value);
}

pub(crate) fn write_bytes_field(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    write_key(out, field, WIRE_LEN);
    write_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

pub(crate) fn write_string_field(out: &mut Vec<u8>, field: u32, value: &str) {
    write_bytes_field(out, field, value.as_bytes());
}

pub(crate) fn write_packed_u64_field(out: &mut Vec<u8>, field: u32, values: &[u64]) {
    let mut packed = Vec::with_capacity(values.len() * 2);
    for value in values {
        write_varint(&mut packed, *value);
    }
    write_bytes_field(out, field, &packed);
}

pub(crate) fn decode_packed_u64(raw: &[u8]) -> Result<Vec<u64>, MaskuraError> {
    let mut reader = WireReader::new(raw);
    let mut values = Vec::new();
    while !reader.is_empty() {
        values.push(reader.read_varint()?);
    }
    Ok(values)
}

pub(crate) fn decode_packed_u32(raw: &[u8]) -> Result<Vec<u32>, MaskuraError> {
    decode_packed_u64(raw)?
        .into_iter()
        .map(|value| {
            u32::try_from(value).map_err(|_| wire_error("protobuf enum value does not fit u32"))
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn decode_varint_field(raw: &[u8]) -> Result<u64, MaskuraError> {
    let mut reader = WireReader::new(raw);
    let value = reader.read_varint()?;
    if !reader.is_empty() {
        return Err(wire_error("protobuf varint field has trailing bytes"));
    }
    Ok(value)
}

/// `google.protobuf.Any` framing: the type URL and the serialized value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnyMessage {
    pub(crate) type_url: String,
    pub(crate) value: Vec<u8>,
}

impl AnyMessage {
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, MaskuraError> {
        let mut reader = WireReader::new(raw);
        let mut type_url = String::new();
        let mut value = Vec::new();
        while let Some((field, value_wire)) = reader.next()? {
            match (field, value_wire) {
                (1, WireValue::Bytes(bytes)) => {
                    type_url = String::from_utf8(bytes.to_vec())
                        .map_err(|_| wire_error("protobuf Any type URL is not UTF-8"))?;
                }
                (2, WireValue::Bytes(bytes)) => value = bytes.to_vec(),
                _ => {}
            }
        }
        if type_url.is_empty() {
            return Err(wire_error("protobuf Any is missing its type URL"));
        }
        Ok(Self { type_url, value })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_string_field(&mut out, 1, &self.type_url);
        write_bytes_field(&mut out, 2, &self.value);
        out
    }
}

/// `lance.file.FileDescriptor`: the schema global buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileDescriptor {
    pub(crate) schema: SchemaMessage,
    pub(crate) length: u64,
}

impl FileDescriptor {
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, MaskuraError> {
        let mut reader = WireReader::new(raw);
        let mut schema = None;
        let mut length = 0_u64;
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (1, WireValue::Bytes(bytes)) => {
                    if schema.is_some() {
                        return Err(wire_error("Lance FileDescriptor has two schemas"));
                    }
                    schema = Some(SchemaMessage::decode(bytes)?);
                }
                (2, WireValue::Varint(value)) => length = value,
                _ => {}
            }
        }
        let schema =
            schema.ok_or_else(|| wire_error("Lance FileDescriptor is missing its schema"))?;
        Ok(Self { schema, length })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_bytes_field(&mut out, 1, &self.schema.encode());
        write_varint_field(&mut out, 2, self.length);
        out
    }
}

/// `lance.file.Schema`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SchemaMessage {
    pub(crate) fields: Vec<FieldMessage>,
}

impl SchemaMessage {
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, MaskuraError> {
        let mut reader = WireReader::new(raw);
        let mut fields = Vec::new();
        while let Some((field, value)) = reader.next()? {
            if let (1, WireValue::Bytes(bytes)) = (field, value) {
                fields.push(FieldMessage::decode(bytes)?);
            }
        }
        Ok(Self { fields })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for field in &self.fields {
            write_bytes_field(&mut out, 1, &field.encode());
        }
        out
    }
}

/// `lance.file.Field` in the subset the codec understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldMessage {
    pub(crate) name: String,
    pub(crate) id: i32,
    /// `-1` marks a top-level field (the reference writer always emits it).
    pub(crate) parent_id: i32,
    pub(crate) logical_type: String,
    pub(crate) nullable: bool,
    /// The deprecated `Encoding` hint: 1 = plain, 2 = var-binary, absent for
    /// fields that hold no leaf data.
    pub(crate) encoding: Option<u32>,
}

impl FieldMessage {
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, MaskuraError> {
        let mut reader = WireReader::new(raw);
        let mut name = String::new();
        let mut id = 0_i32;
        let mut parent_id = 0_i32;
        let mut logical_type = String::new();
        let mut nullable = false;
        let mut encoding = None;
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (2, WireValue::Bytes(bytes)) => {
                    name = String::from_utf8(bytes.to_vec())
                        .map_err(|_| wire_error("Lance field name is not UTF-8"))?;
                }
                (3, WireValue::Varint(value)) => id = value as i32,
                (4, WireValue::Varint(value)) => parent_id = value as i32,
                (5, WireValue::Bytes(bytes)) => {
                    logical_type = String::from_utf8(bytes.to_vec())
                        .map_err(|_| wire_error("Lance logical type is not UTF-8"))?;
                }
                (6, WireValue::Varint(value)) => nullable = value != 0,
                (7, WireValue::Varint(value)) => {
                    encoding =
                        Some(u32::try_from(value).map_err(|_| {
                            wire_error("Lance field encoding hint does not fit u32")
                        })?);
                }
                _ => {}
            }
        }
        if name.is_empty() {
            return Err(wire_error("Lance field is missing its name"));
        }
        if logical_type.is_empty() {
            return Err(wire_error(format!(
                "Lance field {name:?} is missing its type"
            )));
        }
        Ok(Self {
            name,
            id,
            parent_id,
            logical_type,
            nullable,
            encoding,
        })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_string_field(&mut out, 2, &self.name);
        if self.id != 0 {
            write_varint_field(&mut out, 3, self.id as u64);
        }
        write_varint_field(&mut out, 4, self.parent_id as u64);
        write_string_field(&mut out, 5, &self.logical_type);
        if self.nullable {
            write_varint_field(&mut out, 6, 1);
        }
        if let Some(encoding) = self.encoding {
            write_varint_field(&mut out, 7, u64::from(encoding));
        }
        out
    }
}

/// `lance.file.v2.ColumnMetadata`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ColumnMetadataMessage {
    pub(crate) encoding: Option<EncodingMessage>,
    pub(crate) pages: Vec<PageMessage>,
}

impl ColumnMetadataMessage {
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, MaskuraError> {
        let mut reader = WireReader::new(raw);
        let mut encoding = None;
        let mut pages = Vec::new();
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (1, WireValue::Bytes(bytes)) => encoding = Some(EncodingMessage::decode(bytes)?),
                (2, WireValue::Bytes(bytes)) => pages.push(PageMessage::decode(bytes)?),
                _ => {}
            }
        }
        Ok(Self { encoding, pages })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(encoding) = &self.encoding {
            write_bytes_field(&mut out, 1, &encoding.encode());
        }
        for page in &self.pages {
            write_bytes_field(&mut out, 2, &page.encode());
        }
        out
    }
}

/// `lance.file.v2.ColumnMetadata.Page`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PageMessage {
    pub(crate) buffer_offsets: Vec<u64>,
    pub(crate) buffer_sizes: Vec<u64>,
    pub(crate) length: u64,
    pub(crate) encoding: Option<EncodingMessage>,
    pub(crate) priority: u64,
}

impl PageMessage {
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, MaskuraError> {
        let mut reader = WireReader::new(raw);
        let mut page = Self::default();
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (1, WireValue::Bytes(bytes)) => {
                    page.buffer_offsets = decode_packed_u64(bytes)?;
                }
                (2, WireValue::Bytes(bytes)) => {
                    page.buffer_sizes = decode_packed_u64(bytes)?;
                }
                (3, WireValue::Varint(value)) => page.length = value,
                (4, WireValue::Bytes(bytes)) => {
                    page.encoding = Some(EncodingMessage::decode(bytes)?);
                }
                (5, WireValue::Varint(value)) => page.priority = value,
                _ => {}
            }
        }
        if page.buffer_offsets.len() != page.buffer_sizes.len() {
            return Err(wire_error(
                "Lance page declares mismatched buffer offsets and sizes",
            ));
        }
        Ok(page)
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.buffer_offsets.is_empty() {
            write_packed_u64_field(&mut out, 1, &self.buffer_offsets);
            write_packed_u64_field(&mut out, 2, &self.buffer_sizes);
        }
        write_varint_field(&mut out, 3, self.length);
        if let Some(encoding) = &self.encoding {
            write_bytes_field(&mut out, 4, &encoding.encode());
        }
        if self.priority != 0 {
            write_varint_field(&mut out, 5, self.priority);
        }
        out
    }
}

/// `lance.file.v2.Encoding`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EncodingMessage {
    /// `DirectEncoding.encoding`: the `google.protobuf.Any` bytes.
    pub(crate) direct: Option<Vec<u8>>,
}

impl EncodingMessage {
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, MaskuraError> {
        let mut reader = WireReader::new(raw);
        let mut direct = None;
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (2, WireValue::Bytes(bytes)) => {
                    let mut inner = WireReader::new(bytes);
                    while let Some((inner_field, inner_value)) = inner.next()? {
                        if inner_field == 1
                            && let WireValue::Bytes(inner_bytes) = inner_value
                        {
                            if direct.is_some() {
                                return Err(wire_error(
                                    "Lance page encoding has two direct payloads",
                                ));
                            }
                            direct = Some(inner_bytes.to_vec());
                        }
                    }
                }
                (3, _) => {
                    return Err(wire_error("Lance page has no encoding description"));
                }
                _ => {}
            }
        }
        Ok(Self { direct })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(direct) = &self.direct {
            let mut inner = Vec::new();
            write_bytes_field(&mut inner, 1, direct);
            write_bytes_field(&mut out, 2, &inner);
        }
        out
    }
}

/// `lance.encodings.Buffer`: a reference to a page/column/file buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BufferRef {
    pub(crate) index: u32,
    pub(crate) buffer_type: u32,
}

impl BufferRef {
    #[cfg(test)]
    pub(crate) fn page(index: u32) -> Self {
        Self {
            index,
            buffer_type: 0,
        }
    }

    pub(crate) fn decode(raw: &[u8]) -> Result<Self, MaskuraError> {
        let mut reader = WireReader::new(raw);
        let mut buffer = Self {
            index: 0,
            buffer_type: 0,
        };
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (1, WireValue::Varint(value)) => {
                    buffer.index = u32::try_from(value)
                        .map_err(|_| wire_error("Lance buffer index does not fit u32"))?;
                }
                (2, WireValue::Varint(value)) => {
                    buffer.buffer_type = u32::try_from(value)
                        .map_err(|_| wire_error("Lance buffer type does not fit u32"))?;
                }
                _ => {}
            }
        }
        Ok(buffer)
    }

    #[cfg(test)]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_varint_field(&mut out, 1, u64::from(self.index));
        if self.buffer_type != 0 {
            write_varint_field(&mut out, 2, u64::from(self.buffer_type));
        }
        out
    }
}

/// The `lance.encodings.ArrayEncoding` tree in the supported 2.0 subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LegacyArrayEncoding {
    /// `Flat`: fixed-width little-endian values (possibly bit-packed).
    Flat {
        bits_per_value: u64,
        buffer: BufferRef,
    },
    /// `Nullable`.
    Nullable(Box<LegacyNullable>),
    /// `Binary`: end offsets + raw bytes with a null adjustment.
    Binary {
        indices: Box<LegacyArrayEncoding>,
        bytes: Box<LegacyArrayEncoding>,
        null_adjustment: u64,
    },
    /// `List`: end offsets into an items column.
    List {
        offsets: Box<LegacyArrayEncoding>,
        null_offset_adjustment: u64,
        num_items: u64,
    },
    /// `FixedSizeList`.
    FixedSizeList {
        dimension: u32,
        items: Box<LegacyArrayEncoding>,
        has_validity: bool,
    },
    /// `SimpleStruct`: a parent column with no data of its own.
    SimpleStruct,
    /// An encoding outside the supported subset; decoded for diagnostics only
    /// and always rejected by the codec.
    Unsupported(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum LegacyNullable {
    NoNull {
        values: LegacyArrayEncoding,
    },
    SomeNull {
        validity: LegacyArrayEncoding,
        values: LegacyArrayEncoding,
    },
    AllNull,
}

impl LegacyArrayEncoding {
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, MaskuraError> {
        let mut reader = WireReader::new(raw);
        let mut result: Option<Self> = None;
        while let Some((field, value)) = reader.next()? {
            let decoded = match (field, value) {
                (1, WireValue::Bytes(bytes)) => Self::Flat {
                    bits_per_value: read_flat_bits(bytes)?,
                    buffer: read_flat_buffer(bytes)?,
                },
                (2, WireValue::Bytes(bytes)) => {
                    Self::Nullable(Box::new(LegacyNullable::decode(bytes)?))
                }
                (3, WireValue::Bytes(bytes)) => Self::FixedSizeList {
                    dimension: 0,
                    items: Box::new(Self::Unsupported(
                        "Lance fixed-size-list encoding is not supported here",
                    )),
                    has_validity: false,
                }
                .rebuild_fixed_size_list(bytes)?,
                (4, WireValue::Bytes(bytes)) => Self::decode_list(bytes)?,
                (5, WireValue::Bytes(_)) => Self::SimpleStruct,
                (6, WireValue::Bytes(bytes)) => Self::decode_binary(bytes)?,
                (13, WireValue::Bytes(_)) => Self::Unsupported(
                    "Lance constant array encodings are not supported by this codec",
                ),
                (11, _) => Self::Unsupported(
                    "Lance fixed-size-binary encodings are not supported by this codec",
                ),
                (7, _)
                | (8, _)
                | (9, _)
                | (10, _)
                | (12, _)
                | (14, _)
                | (15, _)
                | (16, _)
                | (17, _)
                | (18, _)
                | (19, _)
                | (20, _)
                | (21, _) => Self::Unsupported(
                    "Lance dictionary, packed, bitpacked, and compressed array encodings are not supported by this codec",
                ),
                _ => Self::Unsupported("unknown Lance array encoding"),
            };
            if result.is_some() {
                return Err(wire_error(
                    "Lance array encoding declares more than one encoding kind",
                ));
            }
            result = Some(decoded);
        }
        result.ok_or_else(|| wire_error("Lance array encoding is empty"))
    }

    fn rebuild_fixed_size_list(self, raw: &[u8]) -> Result<Self, MaskuraError> {
        let mut reader = WireReader::new(raw);
        let mut dimension = 0_u32;
        let mut items = None;
        let mut has_validity = false;
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (1, WireValue::Varint(value)) => {
                    dimension = u32::try_from(value).map_err(|_| {
                        wire_error("Lance fixed-size-list dimension does not fit u32")
                    })?;
                }
                (2, WireValue::Bytes(bytes)) => {
                    items = Some(LegacyArrayEncoding::decode(bytes)?);
                }
                (3, WireValue::Varint(value)) => has_validity = value != 0,
                _ => {}
            }
        }
        let items = items.ok_or_else(|| {
            wire_error("Lance fixed-size-list encoding is missing its items encoding")
        })?;
        if dimension == 0 {
            return Err(wire_error(
                "Lance fixed-size-list dimension must be positive",
            ));
        }
        Ok(Self::FixedSizeList {
            dimension,
            items: Box::new(items),
            has_validity,
        })
    }

    fn decode_list(raw: &[u8]) -> Result<Self, MaskuraError> {
        let mut reader = WireReader::new(raw);
        let mut offsets = None;
        let mut null_offset_adjustment = 0_u64;
        let mut num_items = 0_u64;
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (1, WireValue::Bytes(bytes)) => {
                    offsets = Some(LegacyArrayEncoding::decode(bytes)?);
                }
                (2, WireValue::Varint(value)) => null_offset_adjustment = value,
                (3, WireValue::Varint(value)) => num_items = value,
                _ => {}
            }
        }
        let offsets = offsets
            .ok_or_else(|| wire_error("Lance list encoding is missing its offsets encoding"))?;
        if null_offset_adjustment == 0 {
            return Err(wire_error(
                "Lance list encoding is missing its null offset adjustment",
            ));
        }
        Ok(Self::List {
            offsets: Box::new(offsets),
            null_offset_adjustment,
            num_items,
        })
    }

    fn decode_binary(raw: &[u8]) -> Result<Self, MaskuraError> {
        let mut reader = WireReader::new(raw);
        let mut indices = None;
        let mut bytes = None;
        let mut null_adjustment = 0_u64;
        while let Some((field, value)) = reader.next()? {
            match (field, value) {
                (1, WireValue::Bytes(raw)) => indices = Some(LegacyArrayEncoding::decode(raw)?),
                (2, WireValue::Bytes(raw)) => bytes = Some(LegacyArrayEncoding::decode(raw)?),
                (3, WireValue::Varint(value)) => null_adjustment = value,
                _ => {}
            }
        }
        let indices = indices
            .ok_or_else(|| wire_error("Lance binary encoding is missing its indices encoding"))?;
        let bytes = bytes
            .ok_or_else(|| wire_error("Lance binary encoding is missing its bytes encoding"))?;
        if null_adjustment == 0 {
            return Err(wire_error(
                "Lance binary encoding is missing its null adjustment",
            ));
        }
        Ok(Self::Binary {
            indices: Box::new(indices),
            bytes: Box::new(bytes),
            null_adjustment,
        })
    }

    #[cfg(test)]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Flat {
                bits_per_value,
                buffer,
            } => {
                let mut flat = Vec::new();
                write_varint_field(&mut flat, 1, *bits_per_value);
                write_bytes_field(&mut flat, 2, &buffer.encode());
                write_bytes_field(&mut out, 1, &flat);
            }
            Self::Nullable(nullable) => {
                write_bytes_field(&mut out, 2, &nullable.encode());
            }
            Self::FixedSizeList {
                dimension,
                items,
                has_validity,
            } => {
                let mut list = Vec::new();
                write_varint_field(&mut list, 1, u64::from(*dimension));
                write_bytes_field(&mut list, 2, &items.encode());
                if *has_validity {
                    write_varint_field(&mut list, 3, 1);
                }
                write_bytes_field(&mut out, 3, &list);
            }
            Self::List {
                offsets,
                null_offset_adjustment,
                num_items,
            } => {
                let mut list = Vec::new();
                write_bytes_field(&mut list, 1, &offsets.encode());
                write_varint_field(&mut list, 2, *null_offset_adjustment);
                write_varint_field(&mut list, 3, *num_items);
                write_bytes_field(&mut out, 4, &list);
            }
            Self::SimpleStruct => {
                write_bytes_field(&mut out, 5, &[]);
            }
            Self::Binary {
                indices,
                bytes,
                null_adjustment,
            } => {
                let mut binary = Vec::new();
                write_bytes_field(&mut binary, 1, &indices.encode());
                write_bytes_field(&mut binary, 2, &bytes.encode());
                write_varint_field(&mut binary, 3, *null_adjustment);
                write_bytes_field(&mut out, 6, &binary);
            }
            Self::Unsupported(_) => {
                // Unsupported encodings are never re-encoded; the codec rejects
                // them before any output is produced.
            }
        }
        out
    }
}

impl LegacyNullable {
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, MaskuraError> {
        let mut reader = WireReader::new(raw);
        let mut result: Option<Self> = None;
        while let Some((field, value)) = reader.next()? {
            let decoded = match (field, value) {
                (1, WireValue::Bytes(bytes)) => {
                    let mut inner = WireReader::new(bytes);
                    let mut values = None;
                    while let Some((inner_field, inner_value)) = inner.next()? {
                        if inner_field == 1
                            && let WireValue::Bytes(raw) = inner_value
                        {
                            values = Some(decode_single_array_encoding(raw)?);
                        }
                    }
                    Self::NoNull {
                        values: values.ok_or_else(|| {
                            wire_error("Lance no-null encoding is missing its values")
                        })?,
                    }
                }
                (2, WireValue::Bytes(bytes)) => {
                    let mut inner = WireReader::new(bytes);
                    let mut validity = None;
                    let mut values = None;
                    while let Some((inner_field, inner_value)) = inner.next()? {
                        match (inner_field, inner_value) {
                            (1, WireValue::Bytes(raw)) => {
                                validity = Some(decode_single_array_encoding(raw)?);
                            }
                            (2, WireValue::Bytes(raw)) => {
                                values = Some(decode_single_array_encoding(raw)?);
                            }
                            _ => {}
                        }
                    }
                    Self::SomeNull {
                        validity: validity.ok_or_else(|| {
                            wire_error("Lance nullable encoding is missing its validity")
                        })?,
                        values: values.ok_or_else(|| {
                            wire_error("Lance nullable encoding is missing its values")
                        })?,
                    }
                }
                (3, WireValue::Bytes(_)) => Self::AllNull,
                _ => Self::NoNull {
                    values: LegacyArrayEncoding::Unsupported("unknown Lance nullability encoding"),
                },
            };
            if result.is_some() {
                return Err(wire_error(
                    "Lance nullable encoding declares more than one nullability kind",
                ));
            }
            result = Some(decoded);
        }
        result.ok_or_else(|| wire_error("Lance nullable encoding is empty"))
    }

    #[cfg(test)]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::NoNull { values } => {
                write_bytes_field(&mut out, 1, &values.encode());
            }
            Self::SomeNull { validity, values } => {
                let mut inner = Vec::new();
                write_bytes_field(&mut inner, 1, &validity.encode());
                write_bytes_field(&mut inner, 2, &values.encode());
                write_bytes_field(&mut out, 2, &inner);
            }
            Self::AllNull => {
                write_bytes_field(&mut out, 3, &[]);
            }
        }
        out
    }
}

fn decode_single_array_encoding(raw: &[u8]) -> Result<LegacyArrayEncoding, MaskuraError> {
    LegacyArrayEncoding::decode(raw)
}

fn read_flat_bits(raw: &[u8]) -> Result<u64, MaskuraError> {
    let mut reader = WireReader::new(raw);
    let mut bits = 0_u64;
    while let Some((field, value)) = reader.next()? {
        if field == 1
            && let WireValue::Varint(value) = value
        {
            bits = value;
        }
    }
    if bits == 0 {
        return Err(wire_error(format!(
            "Lance flat encoding needs a positive bits-per-value (wire {raw:02x?})"
        )));
    }
    Ok(bits)
}

fn read_flat_buffer(raw: &[u8]) -> Result<BufferRef, MaskuraError> {
    let mut reader = WireReader::new(raw);
    while let Some((field, value)) = reader.next()? {
        if field == 2
            && let WireValue::Bytes(bytes) = value
        {
            return BufferRef::decode(bytes);
        }
    }
    Err(wire_error("Lance flat encoding is missing its buffer"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trips_and_rejects_truncation() {
        for value in [0_u64, 1, 127, 128, 300, u64::MAX] {
            let mut out = Vec::new();
            write_varint(&mut out, value);
            assert_eq!(decode_varint_field(&out).unwrap(), value);
        }
        assert!(decode_varint_field(&[0x80]).is_err());
        assert!(decode_varint_field(&[0x80; 11]).is_err());
    }

    #[test]
    fn wire_reader_skips_unknown_fields_and_rejects_groups() {
        let mut raw = Vec::new();
        write_varint_field(&mut raw, 9, 42);
        write_string_field(&mut raw, 2, "name");
        let mut reader = WireReader::new(&raw);
        assert_eq!(reader.next().unwrap(), Some((9, WireValue::Varint(42))));
        assert!(matches!(
            reader.next().unwrap(),
            Some((2, WireValue::Bytes(b"name")))
        ));
        assert_eq!(reader.next().unwrap(), None);

        let group = [(1_u8 << 3) | 3];
        let mut reader = WireReader::new(&group);
        assert!(reader.next().is_err());
    }

    #[test]
    fn field_message_round_trips_the_reference_shape() {
        let field = FieldMessage {
            name: "email".to_string(),
            id: 1,
            parent_id: -1,
            logical_type: "string".to_string(),
            nullable: true,
            encoding: Some(2),
        };
        let decoded = FieldMessage::decode(&field.encode()).unwrap();
        assert_eq!(decoded, field);
    }

    #[test]
    fn legacy_nullable_some_null_round_trips() {
        let encoding = LegacyArrayEncoding::Nullable(Box::new(LegacyNullable::SomeNull {
            validity: LegacyArrayEncoding::Flat {
                bits_per_value: 1,
                buffer: BufferRef::page(0),
            },
            values: LegacyArrayEncoding::Flat {
                bits_per_value: 64,
                buffer: BufferRef::page(1),
            },
        }));
        assert_eq!(
            LegacyArrayEncoding::decode(&encoding.encode()).unwrap(),
            encoding
        );
    }

    #[test]
    fn legacy_list_and_binary_round_trip() {
        let list = LegacyArrayEncoding::List {
            offsets: Box::new(LegacyArrayEncoding::Flat {
                bits_per_value: 64,
                buffer: BufferRef::page(0),
            }),
            null_offset_adjustment: 3,
            num_items: 2,
        };
        assert_eq!(LegacyArrayEncoding::decode(&list.encode()).unwrap(), list);

        let binary = LegacyArrayEncoding::Binary {
            indices: Box::new(LegacyArrayEncoding::Flat {
                bits_per_value: 64,
                buffer: BufferRef::page(0),
            }),
            bytes: Box::new(LegacyArrayEncoding::Flat {
                bits_per_value: 8,
                buffer: BufferRef::page(1),
            }),
            null_adjustment: 16,
        };
        assert_eq!(
            LegacyArrayEncoding::decode(&binary.encode()).unwrap(),
            binary
        );
    }

    #[test]
    fn unsupported_encodings_fail_closed() {
        let mut raw = Vec::new();
        // ArrayEncoding.dictionary = 7 with empty content.
        write_bytes_field(&mut raw, 7, &[]);
        match LegacyArrayEncoding::decode(&raw).unwrap() {
            LegacyArrayEncoding::Unsupported(_) => {}
            other => panic!("expected unsupported, got {other:?}"),
        }

        let mut raw = Vec::new();
        write_bytes_field(&mut raw, 1, &[]);
        assert!(LegacyArrayEncoding::decode(&raw).is_err());
    }

    #[test]
    fn page_and_column_metadata_round_trip() {
        let page = PageMessage {
            buffer_offsets: vec![0, 64],
            buffer_sizes: vec![16, 15],
            length: 2,
            encoding: Some(EncodingMessage {
                direct: Some(
                    AnyMessage {
                        type_url: "/lance.encodings.ArrayEncoding".to_string(),
                        value: vec![0x12, 0x00],
                    }
                    .encode(),
                ),
            }),
            priority: 0,
        };
        let meta = ColumnMetadataMessage {
            encoding: Some(EncodingMessage {
                direct: Some(
                    AnyMessage {
                        type_url: "/lance.encodings.ColumnEncoding".to_string(),
                        value: vec![0x0a, 0x00],
                    }
                    .encode(),
                ),
            }),
            pages: vec![page.clone()],
        };
        let decoded = ColumnMetadataMessage::decode(&meta.encode()).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn truncated_messages_are_rejected() {
        assert!(ColumnMetadataMessage::decode(&[0x12, 0x10, 0x01]).is_err());
        assert!(FileDescriptor::decode(&[0x0a, 0x02, 0x0a]).is_err());
    }
}
