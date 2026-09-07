//! Transport-independent MCP tool contracts shared by stdio and hosted adapters.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const MAX_TEXT_BODY_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_BUCKET_BYTES: usize = 255;
pub const MAX_KEY_BYTES: usize = 1024;
pub const MAX_LIST_FIELD_BYTES: usize = 4096;
pub const MAX_CONTENT_TYPE_BYTES: usize = 256;
pub const MAX_LIST_KEYS: u32 = 1000;

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
pub struct PutObjectRequest {
    /// Destination bucket name.
    pub bucket: String,
    /// Destination object key.
    pub key: String,
    /// UTF-8 object body to process and store.
    pub body: String,
    /// Media type supplied to the Maskura processing pipeline.
    #[serde(default = "default_content_type")]
    pub content_type: String,
}

pub fn default_content_type() -> String {
    "text/plain; charset=utf-8".to_string()
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
pub struct GetObjectRequest {
    /// Source bucket name.
    pub bucket: String,
    /// Source object key.
    pub key: String,
    /// Process the object through the configured read pipeline before returning it.
    #[serde(default)]
    pub process: bool,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
pub struct ListObjectsRequest {
    /// Bucket to list.
    pub bucket: String,
    /// Return only keys beginning with this prefix.
    #[serde(default)]
    pub prefix: String,
    /// Opaque continuation token from a previous response.
    pub continuation_token: Option<String>,
    /// Maximum number of keys to return, from 1 through 1000.
    pub max_keys: Option<u32>,
    /// Optional hierarchy delimiter, commonly `/`.
    pub delimiter: Option<String>,
    /// Begin listing after this key.
    pub start_after: Option<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
pub struct DeleteObjectRequest {
    /// Bucket containing the object.
    pub bucket: String,
    /// Object key to delete.
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "tool", content = "arguments")]
pub enum ToolRequest {
    PutObject(PutObjectRequest),
    GetObject(GetObjectRequest),
    ListObjects(ListObjectsRequest),
    DeleteObject(DeleteObjectRequest),
}

impl ToolRequest {
    pub fn validate(&self, max_body_bytes: usize) -> Result<(), ValidationError> {
        match self {
            Self::PutObject(value) => {
                validate_bucket(&value.bucket)?;
                validate_key(&value.key)?;
                validate_field(
                    "content_type",
                    &value.content_type,
                    MAX_CONTENT_TYPE_BYTES,
                    false,
                )?;
                if value.body.len() > max_body_bytes {
                    return Err(ValidationError::TooLarge("body", max_body_bytes));
                }
            }
            Self::GetObject(value) => {
                validate_bucket(&value.bucket)?;
                validate_key(&value.key)?;
            }
            Self::ListObjects(value) => {
                validate_bucket(&value.bucket)?;
                validate_field("prefix", &value.prefix, MAX_KEY_BYTES, true)?;
                validate_optional("continuation_token", value.continuation_token.as_deref())?;
                validate_optional("delimiter", value.delimiter.as_deref())?;
                validate_optional("start_after", value.start_after.as_deref())?;
                if value
                    .max_keys
                    .is_some_and(|count| count == 0 || count > MAX_LIST_KEYS)
                {
                    return Err(ValidationError::InvalidMaxKeys);
                }
            }
            Self::DeleteObject(value) => {
                validate_bucket(&value.bucket)?;
                validate_key(&value.key)?;
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("MCP tool requests are serializable")
    }
}

fn validate_bucket(value: &str) -> Result<(), ValidationError> {
    validate_field("bucket", value, MAX_BUCKET_BYTES, false)
}

fn validate_key(value: &str) -> Result<(), ValidationError> {
    validate_field("key", value, MAX_KEY_BYTES, false)
}

fn validate_optional(name: &'static str, value: Option<&str>) -> Result<(), ValidationError> {
    if let Some(value) = value {
        validate_field(name, value, MAX_LIST_FIELD_BYTES, false)?;
    }
    Ok(())
}

fn validate_field(
    name: &'static str,
    value: &str,
    maximum: usize,
    empty_allowed: bool,
) -> Result<(), ValidationError> {
    if !empty_allowed && value.is_empty() {
        return Err(ValidationError::Empty(name));
    }
    if value.len() > maximum {
        return Err(ValidationError::TooLarge(name, maximum));
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::ControlCharacter(name));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MutationResult {
    pub bucket: String,
    pub key: String,
    pub status: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GetObjectResult {
    pub body: String,
    pub content_type: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ListObjectsResult {
    pub keys: Vec<String>,
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
    pub next_continuation_token: Option<String>,
    pub key_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "result")]
pub enum ToolResult {
    PutObject(MutationResult),
    GetObject(GetObjectResult),
    ListObjects(ListObjectsResult),
    DeleteObject(MutationResult),
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ToolDefinition {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: serde_json::Value,
}

pub fn tool_definitions() -> Vec<ToolDefinition> {
    let definitions = [
        (
            "maskura_put_object",
            "Store a UTF-8 object through the configured Maskura pipeline",
            serde_json::to_value(schemars::schema_for!(PutObjectRequest)).unwrap(),
        ),
        (
            "maskura_get_object",
            "Read an object through the Maskura Gateway",
            serde_json::to_value(schemars::schema_for!(GetObjectRequest)).unwrap(),
        ),
        (
            "maskura_list_objects",
            "List object keys in a bucket using ListObjectsV2",
            serde_json::to_value(schemars::schema_for!(ListObjectsRequest)).unwrap(),
        ),
        (
            "maskura_delete_object",
            "Delete an object through the Maskura Gateway",
            serde_json::to_value(schemars::schema_for!(DeleteObjectRequest)).unwrap(),
        ),
    ];
    definitions
        .into_iter()
        .flat_map(|(name, description, input_schema)| {
            let legacy = match name {
                "maskura_put_object" => "s4_put_object",
                "maskura_get_object" => "s4_get_object",
                "maskura_list_objects" => "s4_list_objects",
                "maskura_delete_object" => "s4_delete_object",
                _ => unreachable!("tool definitions are static"),
            };
            [
                ToolDefinition {
                    name,
                    description,
                    input_schema: input_schema.clone(),
                },
                ToolDefinition {
                    name: legacy,
                    description,
                    input_schema,
                },
            ]
        })
        .collect()
}

pub fn dispatch(name: &str, arguments: serde_json::Value) -> Result<ToolRequest, DispatchError> {
    let canonical = name
        .strip_prefix("s4_")
        .map_or(name, |suffix| match suffix {
            "put_object" => "maskura_put_object",
            "get_object" => "maskura_get_object",
            "list_objects" => "maskura_list_objects",
            "delete_object" => "maskura_delete_object",
            _ => name,
        });
    match canonical {
        "maskura_put_object" => serde_json::from_value(arguments)
            .map(ToolRequest::PutObject)
            .map_err(DispatchError::InvalidArguments),
        "maskura_get_object" => serde_json::from_value(arguments)
            .map(ToolRequest::GetObject)
            .map_err(DispatchError::InvalidArguments),
        "maskura_list_objects" => serde_json::from_value(arguments)
            .map(ToolRequest::ListObjects)
            .map_err(DispatchError::InvalidArguments),
        "maskura_delete_object" => serde_json::from_value(arguments)
            .map(ToolRequest::DeleteObject)
            .map_err(DispatchError::InvalidArguments),
        _ => Err(DispatchError::UnknownTool(name.to_string())),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("{0} exceeds {1} bytes")]
    TooLarge(&'static str, usize),
    #[error("{0} must not contain control characters")]
    ControlCharacter(&'static str),
    #[error("max_keys must be between 1 and 1000")]
    InvalidMaxKeys,
}

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("unknown MCP tool: {0}")]
    UnknownTool(String),
    #[error("invalid MCP tool arguments: {0}")]
    InvalidArguments(serde_json::Error),
    #[error("invalid gateway MCP result: {0}")]
    InvalidGatewayResult(String),
}

#[derive(Debug, Deserialize)]
#[serde(rename = "ListBucketResult")]
struct ListBucketResult {
    #[serde(rename = "Contents", default)]
    contents: Vec<ListObject>,
    #[serde(rename = "CommonPrefixes", default)]
    common_prefixes: Vec<CommonPrefix>,
    #[serde(rename = "IsTruncated", default)]
    is_truncated: bool,
    #[serde(rename = "NextContinuationToken")]
    next_continuation_token: Option<String>,
    #[serde(rename = "KeyCount")]
    key_count: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ListObject {
    #[serde(rename = "Key")]
    key: String,
}

#[derive(Debug, Deserialize)]
struct CommonPrefix {
    #[serde(rename = "Prefix")]
    prefix: String,
}

pub fn parse_list_objects_result(xml: &str) -> Result<ListObjectsResult, DispatchError> {
    let result: ListBucketResult = quick_xml::de::from_str(xml)
        .map_err(|error| DispatchError::InvalidGatewayResult(error.to_string()))?;
    if result.is_truncated
        && result
            .next_continuation_token
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return Err(DispatchError::InvalidGatewayResult(
            "truncated response has no next continuation token".to_string(),
        ));
    }
    let keys = result
        .contents
        .into_iter()
        .map(|value| value.key)
        .collect::<Vec<_>>();
    let common_prefixes = result
        .common_prefixes
        .into_iter()
        .map(|value| value.prefix)
        .collect::<Vec<_>>();
    Ok(ListObjectsResult {
        key_count: result
            .key_count
            .unwrap_or(keys.len() + common_prefixes.len()),
        keys,
        common_prefixes,
        is_truncated: result.is_truncated,
        next_continuation_token: result.next_continuation_token,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_arguments_remain_compatible_and_schema_is_described() {
        let request = dispatch(
            "maskura_get_object",
            serde_json::json!({"bucket":"b","key":"k","process":true,"future":42}),
        )
        .unwrap();
        assert!(matches!(request, ToolRequest::GetObject(_)));
        let schema = &tool_definitions()[0].input_schema;
        assert!(schema["properties"]["bucket"]["description"].is_string());
        assert_ne!(
            schema.get("additionalProperties"),
            Some(&serde_json::Value::Bool(false))
        );
    }

    #[test]
    fn tool_schema_golden_hash_is_stable() {
        let document = serde_json::to_vec(&tool_definitions()).unwrap();
        let hash = document.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        });
        assert_eq!(hash, 1_844_581_680_589_375_509);
    }

    #[test]
    fn validation_rejects_empty_and_oversized_fields() {
        let empty = ToolRequest::GetObject(GetObjectRequest {
            bucket: String::new(),
            key: "k".into(),
            process: false,
        });
        assert!(matches!(
            empty.validate(MAX_TEXT_BODY_BYTES),
            Err(ValidationError::Empty("bucket"))
        ));
        let oversized = ToolRequest::DeleteObject(DeleteObjectRequest {
            bucket: "b".into(),
            key: "x".repeat(MAX_KEY_BYTES + 1),
        });
        assert!(matches!(
            oversized.validate(MAX_TEXT_BODY_BYTES),
            Err(ValidationError::TooLarge("key", MAX_KEY_BYTES))
        ));
        let body = ToolRequest::PutObject(PutObjectRequest {
            bucket: "b".into(),
            key: "k".into(),
            body: "xx".into(),
            content_type: default_content_type(),
        });
        assert!(matches!(
            body.validate(1),
            Err(ValidationError::TooLarge("body", 1))
        ));
        let empty_optional = ToolRequest::ListObjects(ListObjectsRequest {
            bucket: "b".into(),
            prefix: String::new(),
            continuation_token: Some(String::new()),
            max_keys: Some(1),
            delimiter: None,
            start_after: None,
        });
        assert!(matches!(
            empty_optional.validate(MAX_TEXT_BODY_BYTES),
            Err(ValidationError::Empty("continuation_token"))
        ));
    }

    #[test]
    fn canonical_identity_covers_every_argument() {
        let base = ToolRequest::ListObjects(ListObjectsRequest {
            bucket: "b".into(),
            prefix: "p".into(),
            continuation_token: None,
            max_keys: Some(10),
            delimiter: None,
            start_after: None,
        });
        let mut changed = base.clone();
        let ToolRequest::ListObjects(value) = &mut changed else {
            unreachable!()
        };
        value.delimiter = Some("/".into());
        assert_ne!(base.canonical_bytes(), changed.canonical_bytes());
    }

    #[test]
    fn parses_list_contract() {
        let page = parse_list_objects_result("<ListBucketResult><KeyCount>2</KeyCount><Contents><Key>a&amp;b</Key></Contents><CommonPrefixes><Prefix>dir/</Prefix></CommonPrefixes></ListBucketResult>").unwrap();
        assert_eq!(page.keys, ["a&b"]);
        assert_eq!(page.common_prefixes, ["dir/"]);
        assert_eq!(page.key_count, 2);
    }
}
