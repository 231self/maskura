//! Multipart upload staging, completion, and recovery.
//!
//! Extracted from `server.rs`. Items are re-exported from [`crate::server`].

use super::*;

pub(crate) struct MultipartStaging {
    pub(crate) repository: Arc<dyn MultipartRepository>,
    pub(crate) artifacts: Arc<dyn StagingArtifactStore>,
    pub(crate) directory: PathBuf,
    pub(crate) wrapping: Arc<dyn KeyWrapping>,
}

pub(crate) struct MultipartPersistenceBundle {
    pub(crate) mode: MultipartPersistenceMode,
    pub(crate) staging: Option<Arc<MultipartStaging>>,
    pub(crate) coordinator: Option<Arc<MultipartCompletionCoordinator>>,
    pub(crate) recovery: Option<Arc<MultipartRecoveryRuntime>>,
    pub(crate) worker: Mutex<Option<MultipartRecoveryWorker>>,
}

pub(crate) struct MultipartRecoveryRuntime {
    pub(crate) staging: Arc<MultipartStaging>,
    pub(crate) coordinator: Arc<MultipartCompletionCoordinator>,
    pub(crate) file_store: Option<Arc<FileStore>>,
    pub(crate) service_storage: Arc<ServiceStorage>,
}

pub(crate) struct MultipartRecoveryWorker {
    pub(crate) cancellation: tokio_util::sync::CancellationToken,
    pub(crate) task: tokio::task::JoinHandle<()>,
}

impl Drop for MultipartRecoveryWorker {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.task.abort();
    }
}

pub(crate) fn multipart_identity(
    auth: &Auth,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> MultipartIdentity {
    MultipartIdentity {
        tenant_id: auth.workspace_id().as_str().to_string(),
        credential_policy_id: auth.credential_policy_id.clone(),
        bucket: bucket.to_string(),
        key: key.to_string(),
        upload_id: upload_id.to_string(),
    }
}

pub(crate) fn managed_logical_key(auth: &Auth, bucket: &str, key: &str) -> LogicalObjectKey {
    LogicalObjectKey::new(auth.workspace_id().as_str(), bucket, key)
}

pub(crate) fn staged_multipart(state: &AppState) -> Option<&Arc<MultipartStaging>> {
    (state.multipart.mode != MultipartPersistenceMode::Reject)
        .then_some(state.multipart.staging.as_ref())
        .flatten()
}

pub(crate) fn multipart_snapshot(
    headers: &HeaderMap,
    backend: &ResolvedBackend,
    plugin_snapshot: serde_json::Value,
    max_bytes: u64,
) -> MultipartSnapshot {
    let mut metadata: std::collections::BTreeMap<String, String> = headers
        .iter()
        .filter_map(|(name, value)| {
            name.as_str()
                .strip_prefix("x-amz-meta-")
                .zip(value.to_str().ok())
                .map(|(name, value)| (name.to_string(), value.to_string()))
        })
        .collect();
    for name in [header::CONTENT_TYPE, header::CONTENT_ENCODING] {
        if let Some(value) = headers.get(&name).and_then(|value| value.to_str().ok()) {
            metadata.insert(name.to_string(), value.to_string());
        }
    }
    let tags = headers
        .get("x-amz-tagging")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split('&')
                .filter_map(|pair| {
                    pair.split_once('=')
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    let destination = match backend {
        ResolvedBackend::S3 { .. } => serde_json::json!({"kind":"s3"}),
        ResolvedBackend::Managed(_) => serde_json::json!({"kind":"managed"}),
        ResolvedBackend::File(_) => serde_json::json!({"kind":"file"}),
        ResolvedBackend::Memory(_) => serde_json::json!({"kind":"memory"}),
        ResolvedBackend::PresignedHttp(_) => serde_json::json!({"kind":"presigned-http"}),
    };
    MultipartSnapshot {
        metadata,
        tags,
        checksum_mode: headers
            .get("x-amz-checksum-algorithm")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned),
        destination,
        plugin_snapshot,
        max_staged_bytes: max_bytes,
    }
}

#[derive(Debug)]
pub(crate) enum MultipartPipelineRestoreError {
    LegacyRawSnapshot,
    Invalid(maskura_error::MaskuraError),
}

pub(crate) fn restore_multipart_pipeline(
    snapshot: &serde_json::Value,
) -> Result<crate::pipeline::PipelineResolution, MultipartPipelineRestoreError> {
    let resolution =
        serde_json::from_value::<crate::pipeline::PipelineResolution>(snapshot.clone())
            .map_err(|_| MultipartPipelineRestoreError::LegacyRawSnapshot)?;
    resolution
        .verify_fingerprint(crate::pipeline::PipelineDirection::Write)
        .map_err(MultipartPipelineRestoreError::Invalid)?;
    Ok(resolution)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PartReservationError {
    Missing,
    TooLarge(u64),
}

pub(crate) fn staged_part_reservation(headers: &HeaderMap) -> Result<u64, PartReservationError> {
    // SigV4 streaming carries the decoded length separately; reserving the
    // HTTP framing length would under/over-account the persisted plaintext.
    // A zero-byte decoded length is valid for the final part of an upload.
    let bytes = headers
        .get("x-amz-decoded-content-length")
        .or_else(|| headers.get(header::CONTENT_LENGTH))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(PartReservationError::Missing)?;
    if bytes > MAX_MULTIPART_PART_BYTES {
        return Err(PartReservationError::TooLarge(bytes));
    }
    Ok(bytes)
}

pub(crate) fn multipart_stored_metadata(snapshot: &MultipartSnapshot) -> MultipartStoredMetadata {
    let mut representation_headers = std::collections::BTreeMap::new();
    let mut user_metadata = std::collections::BTreeMap::new();
    for (name, value) in &snapshot.metadata {
        match name.as_str() {
            "content-type" => {}
            "content-encoding" => {
                representation_headers.insert(name.clone(), value.clone());
            }
            _ => {
                user_metadata.insert(name.clone(), value.clone());
            }
        }
    }
    MultipartStoredMetadata {
        representation_headers,
        user_metadata,
        tags: snapshot.tags.clone(),
        checksum_algorithm: snapshot.checksum_mode.clone(),
    }
}

/// Capture single-PUT representation/user metadata and tags from headers so a
/// plain PutObject persists the same metadata as a multipart completion.
pub(crate) fn single_put_stored_metadata(headers: &HeaderMap) -> MultipartStoredMetadata {
    let mut representation_headers = std::collections::BTreeMap::new();
    let mut user_metadata = std::collections::BTreeMap::new();
    for (name, value) in headers {
        let Some(value) = value.to_str().ok() else {
            continue;
        };
        if let Some(meta) = name.as_str().strip_prefix("x-amz-meta-") {
            user_metadata.insert(meta.to_string(), value.to_string());
        } else if name.as_str() == "content-encoding" {
            representation_headers.insert("content-encoding".to_string(), value.to_string());
        }
    }
    let tags = headers
        .get("x-amz-tagging")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split('&')
                .filter_map(|pair| {
                    pair.split_once('=')
                        .map(|(key, value)| (key.to_string(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    MultipartStoredMetadata {
        representation_headers,
        user_metadata,
        tags,
        checksum_algorithm: headers
            .get("x-amz-checksum-algorithm")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned),
    }
}

pub(crate) fn validate_multipart_checksum_mode(
    snapshot: &MultipartSnapshot,
) -> Result<(), &'static str> {
    match snapshot.checksum_mode.as_deref() {
        None | Some("SHA256") => Ok(()),
        Some(_) => Err("unsupported checksum algorithm; supported values are SHA256"),
    }
}

pub(crate) fn create_multipart_xml(bucket: &str, key: &str, upload_id: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>",
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(upload_id)
    )
}

pub(crate) fn list_parts_xml(
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number_marker: u32,
    max_parts: usize,
    parts: &[MultipartPart],
    truncated: bool,
) -> String {
    let part_xml: String = parts
        .iter()
        .map(|part| {
            format!(
                "<Part><PartNumber>{}</PartNumber><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size><ChecksumSHA256>{}</ChecksumSHA256></Part>",
                part.part_number,
                s3_timestamp(part.created_at_ms),
                xml_escape(&part.etag),
                part.size_bytes,
                part.checksum_sha256
            )
        })
        .collect();
    let next_part_number_marker = if truncated {
        parts
            .last()
            .map(|part| part.part_number.to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId><PartNumberMarker>{}</PartNumberMarker><NextPartNumberMarker>{}</NextPartNumberMarker><MaxParts>{}</MaxParts><IsTruncated>{}</IsTruncated>{part_xml}</ListPartsResult>",
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(upload_id),
        part_number_marker,
        next_part_number_marker,
        max_parts,
        truncated
    )
}

pub(crate) fn s3_timestamp(millis: i64) -> String {
    chrono::DateTime::from_timestamp_millis(millis)
        .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn list_multipart_uploads_xml(
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    key_marker: Option<&str>,
    upload_id_marker: Option<&str>,
    max_uploads: usize,
    page: &ListMultipartUploadsPage,
    url_encode_keys: bool,
) -> String {
    let encoded = |value: &str| -> String {
        let value = if url_encode_keys {
            url_encode(value)
        } else {
            value.to_string()
        };
        xml_escape(&value)
    };
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    xml.push_str(&format!("<Bucket>{}</Bucket>", xml_escape(bucket)));
    xml.push_str(&format!(
        "<KeyMarker>{}</KeyMarker>",
        encoded(key_marker.unwrap_or(""))
    ));
    xml.push_str(&format!(
        "<UploadIdMarker>{}</UploadIdMarker>",
        xml_escape(upload_id_marker.unwrap_or(""))
    ));
    if let Some(next) = &page.next_key_marker {
        xml.push_str(&format!("<NextKeyMarker>{}</NextKeyMarker>", encoded(next)));
    }
    if let Some(next) = &page.next_upload_id_marker {
        xml.push_str(&format!(
            "<NextUploadIdMarker>{}</NextUploadIdMarker>",
            xml_escape(next)
        ));
    }
    xml.push_str(&format!("<MaxUploads>{max_uploads}</MaxUploads>"));
    xml.push_str(&format!("<IsTruncated>{}</IsTruncated>", page.is_truncated));
    xml.push_str(&format!("<Prefix>{}</Prefix>", encoded(prefix)));
    if let Some(delimiter) = delimiter {
        xml.push_str(&format!("<Delimiter>{}</Delimiter>", encoded(delimiter)));
    }
    if url_encode_keys {
        xml.push_str("<EncodingType>url</EncodingType>");
    }
    for upload in &page.uploads {
        let identity = &upload.identity;
        xml.push_str(&format!(
            "<Upload><Key>{}</Key><UploadId>{}</UploadId><Initiator><ID>{}</ID><DisplayName>{}</DisplayName></Initiator><Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner><StorageClass>STANDARD</StorageClass><Initiated>{}</Initiated></Upload>",
            encoded(&identity.key),
            xml_escape(&identity.upload_id),
            xml_escape(&identity.tenant_id),
            xml_escape(&identity.credential_policy_id),
            xml_escape(&identity.tenant_id),
            xml_escape(&identity.credential_policy_id),
            s3_timestamp(upload.created_at_ms),
        ));
    }
    for common_prefix in &page.common_prefixes {
        xml.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            encoded(common_prefix)
        ));
    }
    xml.push_str("</ListMultipartUploadsResult>");
    xml
}

pub(crate) async fn list_multipart_uploads_response(
    state: &AppState,
    auth: &Auth,
    bucket: &str,
    params: &S3Query,
) -> axum::response::Response {
    let Some(staging) = staged_multipart(state).cloned() else {
        return s3_error::multipart_not_supported(bucket);
    };
    let max_uploads = match params.max_uploads {
        Some(value) if !(1..=1000).contains(&value) => {
            return s3_error::invalid_argument(bucket, "max-uploads must be between 1 and 1000");
        }
        Some(value) => value as usize,
        None => 1000,
    };
    match params.encoding_type.as_deref() {
        None | Some("url") => {}
        Some(other) => {
            return s3_error::invalid_argument(
                bucket,
                &format!("unsupported encoding-type \"{other}\""),
            );
        }
    }
    let request = ListMultipartUploadsRequest {
        tenant_id: auth.workspace_id().as_str().to_string(),
        credential_policy_id: auth.credential_policy_id.clone(),
        bucket: bucket.to_string(),
        prefix: params.prefix.clone().unwrap_or_default(),
        delimiter: params.delimiter.clone(),
        key_marker: params.key_marker.clone(),
        upload_id_marker: params.upload_id_marker.clone(),
        max_uploads,
    };
    let page = match staging.repository.list_authorized_uploads(&request).await {
        Ok(page) => page,
        Err(StagingError::InvalidListing | StagingError::NotFound) => {
            return s3_error::invalid_argument(bucket, "invalid multipart upload listing request");
        }
        Err(error) => return s3_error::internal_error(bucket, &error.to_string()),
    };
    s3_xml_ok(list_multipart_uploads_xml(
        bucket,
        &request.prefix,
        request.delimiter.as_deref(),
        request.key_marker.as_deref(),
        request.upload_id_marker.as_deref(),
        max_uploads,
        &page,
        params.encoding_type.as_deref() == Some("url"),
    ))
}

pub(crate) const MAX_COMPLETE_XML_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_MULTIPART_COMPLETION_SECS: u64 = 240;

pub(crate) const MIN_MULTIPART_NONFINAL_PART_BYTES: u64 = 5 * 1024 * 1024;
pub(crate) const MAX_MULTIPART_PART_BYTES: u64 = 5 * 1024 * 1024 * 1024;
pub(crate) const MAX_MULTIPART_ASSEMBLED_SOURCE_BYTES: u64 = 5 * 1024 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompletionPartSizeError {
    NonFinalTooSmall { part_number: u32, size_bytes: u64 },
    AssembledTooLarge(u64),
}

/// Validates S3's part-size contract against the repository-selected parts.
/// Every part except the numerically final selected part must be at least five
/// MiB, and the assembled source must stay within the five TiB ceiling. Sizes
/// and ETags come from the same durable part records, so a replacement that
/// changes a selected size also changes its ETag and fails completion instead.
pub(crate) fn validate_completion_part_sizes(
    parts: &[MultipartPart],
) -> Result<(), CompletionPartSizeError> {
    let final_index = parts.len().saturating_sub(1);
    for (index, part) in parts.iter().enumerate() {
        if index < final_index && part.size_bytes < MIN_MULTIPART_NONFINAL_PART_BYTES {
            return Err(CompletionPartSizeError::NonFinalTooSmall {
                part_number: part.part_number,
                size_bytes: part.size_bytes,
            });
        }
    }
    let assembled = parts.iter().try_fold(0u64, |total, part| {
        total
            .checked_add(part.size_bytes)
            .ok_or(CompletionPartSizeError::AssembledTooLarge(u64::MAX))
    })?;
    if assembled > MAX_MULTIPART_ASSEMBLED_SOURCE_BYTES {
        return Err(CompletionPartSizeError::AssembledTooLarge(assembled));
    }
    Ok(())
}

/// Fetches the durable part records that exactly match the client's completion
/// selection. Returns `None` when any requested part is missing or has a
/// mismatched ETag/checksum; the repository's atomic acquisition then rejects
/// that request as `InvalidPart`. A full match returns the matched records so
/// the caller can enforce the five MiB non-final minimum and the five TiB
/// assembly ceiling against the same content the completion would publish.
pub(crate) async fn staged_completion_sizes(
    repository: &dyn MultipartRepository,
    identity: &MultipartIdentity,
    requested: &[CompletePart],
) -> Result<Option<Vec<MultipartPart>>, StagingError> {
    let (current, _) = repository
        .list_parts(identity, 0, crate::multipart_staging::MAX_PARTS as usize)
        .await?;
    let mut matched = Vec::with_capacity(requested.len());
    for request in requested {
        let Some(part) = current
            .iter()
            .find(|part| part.part_number == request.part_number)
        else {
            return Ok(None);
        };
        if part.etag != request.etag
            || request
                .checksum_sha256
                .as_deref()
                .is_some_and(|checksum| checksum != part.checksum_sha256)
        {
            return Ok(None);
        }
        matched.push(part.clone());
    }
    Ok(Some(matched))
}

pub(crate) fn complete_multipart_xml(
    bucket: &str,
    key: &str,
    result: &MultipartCompletionResult,
) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Location>/{}/{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></CompleteMultipartUploadResult>",
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(bucket),
        xml_escape(key),
        xml_escape(result.etag.as_deref().unwrap_or_default()),
    )
}

/// Strictly parses the small CompleteMultipartUpload grammar instead of using a
/// general XML resolver. DTDs and unknown entities are rejected; only XML's
/// predefined and numeric character references are decoded in element text.
pub(crate) fn parse_complete_multipart_xml(body: &[u8]) -> Result<Vec<CompletePart>, String> {
    if body.len() > MAX_COMPLETE_XML_BYTES {
        return Err("CompleteMultipartUpload XML exceeds 1 MiB".to_string());
    }
    let input = std::str::from_utf8(body)
        .map_err(|_| "CompleteMultipartUpload XML must be UTF-8".to_string())?;
    if input.contains("<!") {
        return Err("CompleteMultipartUpload XML entities and DTDs are prohibited".to_string());
    }
    let mut stack = Vec::<String>::new();
    let mut parts = Vec::new();
    let mut current_number = None;
    let mut current_etag = None;
    let mut current_checksum = None;
    let mut cursor = 0;
    let mut root_started = false;
    let mut root_closed = false;
    while cursor < input.len() {
        let open = input[cursor..]
            .find('<')
            .map(|index| cursor + index)
            .ok_or_else(|| "malformed CompleteMultipartUpload XML".to_string())?;
        let text = input[cursor..open].trim();
        if !text.is_empty() {
            let text = decode_complete_xml_text(text)?;
            match stack.last().map(String::as_str) {
                Some("PartNumber") => {
                    if current_number.is_some() {
                        return Err("duplicate PartNumber value".to_string());
                    }
                    current_number = Some(
                        text.parse::<u32>()
                            .ok()
                            .filter(|number| *number > 0)
                            .ok_or_else(|| "invalid PartNumber".to_string())?,
                    );
                }
                Some("ETag") => {
                    if current_etag.replace(text).is_some() {
                        return Err("duplicate ETag value".to_string());
                    }
                }
                Some("ChecksumSHA256") => {
                    if current_checksum.replace(text).is_some() {
                        return Err("duplicate ChecksumSHA256 value".to_string());
                    }
                }
                _ => return Err("unexpected XML character data".to_string()),
            }
        }
        let close = input[open..]
            .find('>')
            .map(|index| open + index)
            .ok_or_else(|| "malformed CompleteMultipartUpload XML".to_string())?;
        let raw = input[open + 1..close].trim();
        cursor = close + 1;
        if root_closed {
            return Err("multiple CompleteMultipartUpload XML roots".to_string());
        }
        if raw.starts_with('?') && raw.ends_with('?') {
            if !stack.is_empty() || !parts.is_empty() {
                return Err("XML declaration is not at the beginning".to_string());
            }
            continue;
        }
        if let Some(raw) = raw.strip_prefix('/') {
            let name = raw.trim().rsplit(':').next().unwrap_or_default();
            if stack.last().map(String::as_str) != Some(name) {
                return Err("mismatched CompleteMultipartUpload XML element".to_string());
            }
            stack.pop();
            if name == "CompleteMultipartUpload" {
                root_closed = true;
            }
            if name == "Part" {
                let part_number = current_number
                    .take()
                    .ok_or_else(|| "Part is missing PartNumber".to_string())?;
                let etag = current_etag
                    .take()
                    .filter(|etag| !etag.is_empty())
                    .ok_or_else(|| "Part is missing ETag".to_string())?;
                parts.push(CompletePart {
                    part_number,
                    etag,
                    checksum_sha256: current_checksum.take(),
                });
            }
            continue;
        }
        if raw.ends_with('/') {
            return Err(
                "self-closing CompleteMultipartUpload XML elements are not allowed".to_string(),
            );
        }
        let name = raw
            .split_ascii_whitespace()
            .next()
            .unwrap_or_default()
            .rsplit(':')
            .next()
            .unwrap_or_default();
        let allowed = match (stack.len(), name) {
            (0, "CompleteMultipartUpload") if !root_started => true,
            (1, "Part") if stack.last().map(String::as_str) == Some("CompleteMultipartUpload") => {
                current_number = None;
                current_etag = None;
                current_checksum = None;
                true
            }
            (2, "PartNumber" | "ETag" | "ChecksumSHA256")
                if stack.last().map(String::as_str) == Some("Part") =>
            {
                true
            }
            _ => false,
        };
        if !allowed {
            return Err("unexpected CompleteMultipartUpload XML element".to_string());
        }
        if name == "CompleteMultipartUpload" {
            root_started = true;
        }
        stack.push(name.to_string());
    }
    if !root_started || !root_closed || !stack.is_empty() || parts.is_empty() {
        return Err("malformed CompleteMultipartUpload XML".to_string());
    }
    if parts
        .windows(2)
        .any(|pair| pair[0].part_number >= pair[1].part_number)
    {
        return Err("parts must be sorted and nonduplicate".to_string());
    }
    Ok(parts)
}

pub(crate) fn decode_complete_xml_text(text: &str) -> Result<String, String> {
    if !text.contains('&') {
        return Ok(text.to_string());
    }
    let mut decoded = String::with_capacity(text.len());
    let mut remaining = text;
    while let Some(start) = remaining.find('&') {
        decoded.push_str(&remaining[..start]);
        let entity_end = remaining[start + 1..]
            .find(';')
            .map(|index| start + 1 + index)
            .ok_or_else(|| "unterminated XML character reference".to_string())?;
        let entity = &remaining[start + 1..entity_end];
        match entity {
            "quot" => decoded.push('"'),
            "apos" => decoded.push('\''),
            "amp" => decoded.push('&'),
            "lt" => decoded.push('<'),
            "gt" => decoded.push('>'),
            value if let Some(hex) = value.strip_prefix("#x") => {
                let code = u32::from_str_radix(hex, 16)
                    .map_err(|_| "invalid hexadecimal XML character reference".to_string())?;
                decoded.push(
                    char::from_u32(code)
                        .ok_or_else(|| "invalid XML character reference".to_string())?,
                );
            }
            value if let Some(decimal) = value.strip_prefix('#') => {
                let code = decimal
                    .parse::<u32>()
                    .map_err(|_| "invalid decimal XML character reference".to_string())?;
                decoded.push(
                    char::from_u32(code)
                        .ok_or_else(|| "invalid XML character reference".to_string())?,
                );
            }
            _ => return Err("unknown XML entity is prohibited".to_string()),
        }
        remaining = &remaining[entity_end + 1..];
    }
    decoded.push_str(remaining);
    Ok(decoded)
}

pub(crate) async fn cleanup_staged_parts(
    staging: &MultipartStaging,
    upload_id: &str,
    parts: Vec<MultipartPart>,
    kind: &str,
) -> bool {
    let mut complete = true;
    for part in parts {
        let result = staging.artifacts.delete(&part.artifact_key).await;
        let detail = match result {
            Ok(()) => match staging
                .repository
                .confirm_artifact_deleted(&part.artifact_key)
                .await
            {
                Ok(()) => {
                    serde_json::json!({"part_number":part.part_number,"attempt":part.attempt})
                }
                Err(error) => {
                    complete = false;
                    serde_json::json!({"part_number":part.part_number,"attempt":part.attempt,"error":error.to_string()})
                }
            },
            Err(error) => {
                complete = false;
                serde_json::json!({"part_number":part.part_number,"attempt":part.attempt,"error":error.to_string()})
            }
        };
        if staging
            .repository
            .audit(CleanupAudit {
                id: Uuid::now_v7(),
                upload_id: upload_id.to_string(),
                kind: kind.to_string(),
                detail,
                created_at_ms: now_ms(),
            })
            .await
            .is_err()
        {
            warn!(
                error_category = "persistence",
                "multipart cleanup audit failed"
            );
        }
    }
    complete
}

#[derive(Debug)]
pub(crate) enum MultipartCompletionError {
    Staging(StagingError),
    Streaming(StreamingPutError),
    Invalid(String),
    PreserveReservation(Box<MultipartCompletionError>),
}

impl MultipartCompletionError {
    pub(crate) fn preserves_reservation(&self) -> bool {
        matches!(self, Self::PreserveReservation(_))
    }

    pub(crate) fn into_cause(self) -> Self {
        match self {
            Self::PreserveReservation(error) => *error,
            error => error,
        }
    }
}

impl From<StagingError> for MultipartCompletionError {
    fn from(error: StagingError) -> Self {
        Self::Staging(error)
    }
}

impl From<StreamingPutError> for MultipartCompletionError {
    fn from(error: StreamingPutError) -> Self {
        Self::Streaming(error)
    }
}

impl From<maskura_error::MaskuraError> for MultipartCompletionError {
    fn from(error: maskura_error::MaskuraError) -> Self {
        Self::Streaming(error.into())
    }
}

impl From<TransactionError> for MultipartCompletionError {
    fn from(error: TransactionError) -> Self {
        Self::Streaming(error.into())
    }
}

impl From<MultipartCoordinatorError> for MultipartCompletionError {
    fn from(error: MultipartCoordinatorError) -> Self {
        match error {
            MultipartCoordinatorError::Staging(error) => Self::Staging(error),
            MultipartCoordinatorError::Journal(error) => {
                Self::Streaming(TransactionError::Journal(error).into())
            }
            MultipartCoordinatorError::Transaction(error) => Self::Streaming(error.into()),
            MultipartCoordinatorError::Invalid(error) => Self::Invalid(error),
        }
    }
}

pub(crate) fn multipart_completion_coordinator(
    state: &AppState,
    _staging: &MultipartStaging,
) -> Result<MultipartCompletionCoordinator, MultipartCompletionError> {
    state
        .multipart
        .coordinator
        .as_deref()
        .cloned()
        .ok_or_else(|| {
            MultipartCompletionError::Invalid(
                "multipart completion requires a durable operation journal".to_string(),
            )
        })
}

pub(crate) async fn renew_and_fence_completion(
    staging: &MultipartStaging,
    identity: &MultipartIdentity,
    lease: &CompletionLease,
) -> Result<(), StagingError> {
    let now = now_ms();
    staging
        .repository
        .renew_completion(
            identity,
            lease.fencing_token,
            now + COMPLETION_LEASE.as_millis() as i64,
        )
        .await?;
    staging
        .repository
        .check_completion_lease(identity, lease.fencing_token, now_ms())
        .await
}

pub(crate) async fn renew_completion_if_due(
    staging: &MultipartStaging,
    identity: &MultipartIdentity,
    lease: &CompletionLease,
    last_renewal: &mut std::time::Instant,
) -> Result<(), StagingError> {
    if last_renewal.elapsed() < COMPLETION_LEASE / 3 {
        return Ok(());
    }
    renew_and_fence_completion(staging, identity, lease).await?;
    *last_renewal = std::time::Instant::now();
    Ok(())
}

pub(crate) async fn write_completed_record(
    sink: &mut Box<dyn ObjectSinkTransaction>,
    record: crate::record::Record,
    output_hasher: &mut sha2::Sha256,
    output_bytes: &mut u64,
) -> Result<(), MultipartCompletionError> {
    use sha2::Digest as _;

    // The caller checks the completion lease at each part/chunk boundary and
    // renews it at a bounded heartbeat interval. Destination bytes only leave
    // the transaction via the atomic publish below, which revalidates the
    // fencing token, so a per-record renewal would make many-record
    // completions quadratically slow for no extra safety.
    for chunk in [record.payload, record.separator] {
        if chunk.is_empty() {
            continue;
        }
        *output_bytes = output_bytes
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| MultipartCompletionError::Invalid("output is too large".to_string()))?;
        output_hasher.update(&chunk);
        sink.write(chunk).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn complete_staged_multipart(
    state: &AppState,
    staging: &MultipartStaging,
    identity: &MultipartIdentity,
    upload: &MultipartUpload,
    lease: &CompletionLease,
    operation: AuthorizedOperation<'_>,
    backend: ResolvedBackend,
    resolution: &crate::pipeline::PipelineResolution,
) -> Result<MultipartCompletionResult, MultipartCompletionError> {
    use sha2::Digest as _;

    let destination_kind = match &backend {
        ResolvedBackend::S3 { .. } => "s3",
        ResolvedBackend::Managed(_) => "managed",
        ResolvedBackend::File(_) => "file",
        ResolvedBackend::Memory(_) => "memory",
        ResolvedBackend::PresignedHttp(_) => "presigned-http",
    };
    if upload
        .snapshot
        .destination
        .get("kind")
        .and_then(serde_json::Value::as_str)
        != Some(destination_kind)
    {
        return Err(MultipartCompletionError::Invalid(
            "multipart destination changed since initiation".to_string(),
        ));
    }
    // Completion executes the exact persisted resolution, never the current
    // assignment. Legacy raw PluginInfo snapshots are rejected explicitly:
    // their process-local UUID identities cannot be proven restart-safe.
    let snapshot = state.gateway.snapshot_for(resolution).await?;
    let pipeline_started = std::time::Instant::now();
    let content_type = upload
        .snapshot
        .metadata
        .get("content-type")
        .ok_or_else(|| {
            MultipartCompletionError::Invalid("multipart Content-Type is missing".to_string())
        })?;
    if let Some(avro_media) = avro_media_type(content_type) {
        if !state.binary_avro_enabled {
            return Err(MultipartCompletionError::Streaming(
                StreamingPutError::Unsupported(
                    "Avro processing is disabled; set MASKURA_ENABLE_AVRO=true".to_string(),
                ),
            ));
        }
        return complete_staged_avro_multipart(
            state,
            staging,
            identity,
            upload,
            lease,
            operation,
            backend,
            &avro_media,
        )
        .await;
    }
    let (format, content_type) = streaming_format_content_type(content_type)?;
    let stored_metadata = multipart_stored_metadata(&upload.snapshot);
    validate_multipart_checksum_mode(&upload.snapshot)
        .map_err(|detail| MultipartCompletionError::Invalid(detail.to_string()))?;
    let fingerprint = upload
        .complete_request_fingerprint
        .as_deref()
        .ok_or_else(|| {
            MultipartCompletionError::Invalid(
                "multipart completion fingerprint is missing".to_string(),
            )
        })?;
    let destination_operation_id =
        crate::multipart_staging::DestinationCommitPermit::deterministic_operation_id(
            identity,
            fingerprint,
        );
    let coordinator = multipart_completion_coordinator(state, staging)?;
    renew_and_fence_completion(staging, identity, lease).await?;
    let mut sink = begin_streaming_sink(
        state,
        backend,
        operation,
        destination_operation_id,
        &identity.bucket,
        &identity.key,
        &content_type,
        Some((&coordinator, identity, fingerprint)),
        Some(stored_metadata),
    )
    .await?;
    coordinator
        .bind_existing_operation(destination_operation_id, identity)
        .await?;
    let cancellation = trusted_wasm_cancellation();
    let session = maskura_wasm_runtime::Session {
        format: format.as_str().to_string(),
        content_type,
        policy_version: 0,
        operation: maskura_wasm_runtime::Operation::Write,
        config_json: None,
        public_key_pem: operation.auth.public_key_pem.clone(),
        stable_key: operation.auth.stable_key.clone(),
        stable_fields: None,
    };
    let mut pipeline = Some(
        snapshot
            .clone()
            .start_streaming_session(session, cancellation.clone())
            .await?,
    );
    let limits = crate::record::DecoderLimits {
        max_source_frame_bytes: state.source_body_limits.max_frame_bytes,
        ..crate::record::DecoderLimits::default()
    };
    let mut decoder = crate::record::RecordDecoder::new(format, limits)?;
    let mut input_bytes = 0_u64;
    let mut output_bytes = 0_u64;
    let mut output_hasher = sha2::Sha256::new();

    let processing = async {
        for part in &lease.selected_parts {
            renew_and_fence_completion(staging, identity, lease).await?;
            let body = staging.artifacts.get(&part.artifact_key).await?;
            renew_and_fence_completion(staging, identity, lease).await?;
            let mut last_renewal = std::time::Instant::now();
            let mut reader = EncryptedPartReader::open(
                body,
                identity,
                part,
                &upload.snapshot,
                staging.wrapping.clone(),
            )
            .await?;
            let mut part_bytes = 0_u64;
            let mut part_sha256 = sha2::Sha256::new();
            let mut part_md5 = Md5::new();
            loop {
                renew_completion_if_due(staging, identity, lease, &mut last_renewal).await?;
                let Some(chunk) = reader.next_chunk().await? else {
                    break;
                };
                part_bytes = part_bytes.checked_add(chunk.len() as u64).ok_or_else(|| {
                    MultipartCompletionError::Invalid("multipart part is too large".to_string())
                })?;
                input_bytes = input_bytes.checked_add(chunk.len() as u64).ok_or_else(|| {
                    MultipartCompletionError::Invalid("multipart input is too large".to_string())
                })?;
                if part_bytes > part.size_bytes || input_bytes > state.source_body_limits.max_bytes
                {
                    return Err(MultipartCompletionError::Invalid(
                        "multipart input exceeds its limit".to_string(),
                    ));
                }
                part_sha256.update(&chunk);
                part_md5.update(&chunk);
                decoder.push(&chunk)?;
                while let Some(record) = decoder.next_record()? {
                    renew_completion_if_due(staging, identity, lease, &mut last_renewal).await?;
                    if let Some(record) = pipeline
                        .as_mut()
                        .expect("pipeline is present until finish")
                        .process(record)
                        .await?
                    {
                        write_completed_record(
                            &mut sink,
                            record,
                            &mut output_hasher,
                            &mut output_bytes,
                        )
                        .await?;
                    }
                }
            }
            if part_bytes != part.size_bytes
                || hex::encode(part_sha256.finalize()) != part.checksum_sha256
                || format!("\"{}\"", hex::encode(part_md5.finalize())) != part.etag
            {
                return Err(MultipartCompletionError::Invalid(
                    "staged multipart artifact does not match its committed part".to_string(),
                ));
            }
            // JSON is a whole-document format: parts carry independent
            // documents, so flush a completed document at each part boundary
            // instead of concatenating every part into one JSON value.
            decoder.end_of_segment()?;
            while let Some(record) = decoder.next_record()? {
                if let Some(record) = pipeline
                    .as_mut()
                    .expect("pipeline is present until finish")
                    .process(record)
                    .await?
                {
                    write_completed_record(
                        &mut sink,
                        record,
                        &mut output_hasher,
                        &mut output_bytes,
                    )
                    .await?;
                }
            }
        }
        decoder.finish()?;
        while let Some(record) = decoder.next_record()? {
            if let Some(record) = pipeline
                .as_mut()
                .expect("pipeline is present until finish")
                .process(record)
                .await?
            {
                write_completed_record(&mut sink, record, &mut output_hasher, &mut output_bytes)
                    .await?;
            }
        }
        let finishing = pipeline.take().expect("pipeline is present until finish");
        let (records, pipeline_fuel) = finishing.finish().await?;
        for record in records {
            write_completed_record(&mut sink, record, &mut output_hasher, &mut output_bytes)
                .await?;
        }
        let pipeline_evidence = snapshot.pipeline_evidence(
            pipeline_fuel,
            pipeline_started.elapsed().as_millis() as u64,
            "none",
        );
        let checksum_sha256 = hex::encode(output_hasher.finalize());
        renew_and_fence_completion(staging, identity, lease).await?;
        sink.verify_output(output_bytes, &checksum_sha256).await?;
        renew_and_fence_completion(staging, identity, lease).await?;
        let precommit_result = MultipartCompletionResult {
            etag: None,
            checksum_sha256: checksum_sha256.clone(),
            version_id: None,
            source_bytes: input_bytes,
            size_bytes: output_bytes,
            pipeline_evidence: pipeline_evidence.clone(),
        };
        let mut usage_event = multipart_completion_event(operation.grant, &precommit_result);
        usage_event = usage_event.with_operation_id(destination_operation_id);
        renew_and_fence_completion(staging, identity, lease).await?;
        coordinator
            .publish(
                identity,
                fingerprint,
                lease.fencing_token,
                precommit_result,
                &usage_event,
                &mut sink,
            )
            .await
            .map_err(MultipartCompletionError::from)
    }
    .await;
    if let Err(error) = &processing {
        cancellation.cancel();
        if let Some(pipeline) = pipeline.take() {
            let _ = pipeline.cancel_and_wait().await;
        }
        // Never allow a stale worker to issue an abort. The durable Phase 5
        // journal reconciles ambiguous destination outcomes after a crash.
        if !sink.commit_state().preserves_reservation()
            && renew_and_fence_completion(staging, identity, lease)
                .await
                .is_ok()
        {
            let _ = sink.abort().await;
        }
        let _ = error;
    }
    processing.map_err(|error| {
        if sink.commit_state().preserves_reservation() {
            MultipartCompletionError::PreserveReservation(Box::new(error))
        } else {
            error
        }
    })
}

pub(crate) fn multipart_completion_error_response(
    key: &str,
    error: MultipartCompletionError,
) -> axum::response::Response {
    match error.into_cause() {
        MultipartCompletionError::Staging(StagingError::Fenced) => {
            s3_error::service_unavailable(key, "multipart completion lease was lost")
        }
        MultipartCompletionError::Staging(StagingError::InvalidPart) => {
            s3_error::invalid_part(key, "staged part validation failed")
        }
        MultipartCompletionError::Staging(error) => {
            s3_error::internal_error(key, &error.to_string())
        }
        MultipartCompletionError::Streaming(error) => streaming_put_error_response(key, error),
        MultipartCompletionError::Invalid(error) => s3_error::invalid_request(key, &error),
        MultipartCompletionError::PreserveReservation(_) => unreachable!("cause is unwrapped"),
    }
}

pub(crate) async fn multipart_completion_failure_response(
    control: &dyn ControlPlane,
    context: &AuthenticatedRequestContext,
    grant: &AuthorizationGrant,
    key: &str,
    error: MultipartCompletionError,
) -> axum::response::Response {
    let preserve_reservation = error.preserves_reservation();
    let response = multipart_completion_error_response(key, error);
    if preserve_reservation {
        response
    } else {
        release_failure(control, context, grant, key, response).await
    }
}

pub(crate) enum ExistingDirectCompletion {
    New,
    Committed(Box<OperationRecord>),
    ProvenAborted,
    Pending,
    Conflict,
}

pub(crate) fn persisted_workspace_lease(
    operation: &OperationRecord,
) -> Result<(WorkspaceId, WorkspaceOperationLease), TransactionError> {
    let workspace = WorkspaceId::new(operation.tenant_id.clone().ok_or_else(|| {
        TransactionError::Publication("workspace operation has no tenant identity".to_string())
    })?)
    .map_err(|_| {
        TransactionError::Publication("workspace recovery identity is invalid".to_string())
    })?;
    let binding = operation
        .destination
        .workspace_binding
        .as_ref()
        .ok_or_else(|| {
            TransactionError::Publication(
                "workspace operation has no versioned destination binding".to_string(),
            )
        })?;
    let lease = WorkspaceOperationLease {
        operation_id: operation.id,
        lease_id: binding.routing_lease_id,
        config_version: crate::workspace_storage::BackendConfigVersionId::new(
            binding.backend_config_version.clone(),
        )
        .map_err(|_| {
            TransactionError::Publication("workspace recovery identity is invalid".to_string())
        })?,
        attestation_id: crate::workspace_storage::CapabilityAttestationId::new(
            binding.capability_attestation_id.clone(),
        )
        .map_err(|_| {
            TransactionError::Publication("workspace recovery identity is invalid".to_string())
        })?,
        routing_epoch: binding.routing_epoch,
        fencing_token: binding.routing_fencing_token,
        expires_at_ms: 0,
    };
    Ok((workspace, lease))
}

pub(crate) async fn settle_terminal_workspace_lease(
    repository: &Arc<dyn WorkspaceStorageRepository>,
    operation: &OperationRecord,
) -> Result<(), TransactionError> {
    let outcome = match operation.state {
        OperationState::Committed => WorkspaceOperationOutcome::Committed,
        OperationState::ProvenAborted => WorkspaceOperationOutcome::ProvenAborted,
        _ => {
            return Err(TransactionError::Publication(
                "workspace route settlement requires a terminal journal row".to_string(),
            ));
        }
    };
    let (workspace, lease) = persisted_workspace_lease(operation)?;
    repository
        .release_streaming_operation_lease(&workspace, &lease, outcome)
        .await
        .map_err(|_| {
            TransactionError::Publication(
                "workspace recovery lease terminal update failed".to_string(),
            )
        })
}

pub(crate) async fn reconcile_existing_direct_completion(
    state: &AppState,
    backend: &ResolvedBackend,
    operation_id: Uuid,
    workspace_id: &str,
    bucket: &str,
    key: &str,
) -> Result<ExistingDirectCompletion, TransactionError> {
    let Some(journal) = state.operation_journal.clone() else {
        return Ok(ExistingDirectCompletion::New);
    };
    let Some(mut operation) = journal.get(operation_id).await? else {
        return Ok(ExistingDirectCompletion::New);
    };
    let backend_id = match backend {
        ResolvedBackend::S3 {
            kind: BackendKind::PerUserS3,
            ..
        } => "PerUserS3",
        ResolvedBackend::S3 {
            kind: BackendKind::GlobalS3,
            ..
        } => "GlobalS3",
        _ => return Ok(ExistingDirectCompletion::Conflict),
    };
    if operation.tenant_id.as_deref() != Some(workspace_id)
        || operation.destination.backend_id != backend_id
        || operation.destination.bucket != bucket
        || operation.destination.logical_key != key
        || operation.destination.physical_key != key
    {
        return Ok(ExistingDirectCompletion::Conflict);
    }

    if operation.state.is_terminal() {
        if backend_id == "PerUserS3" {
            settle_terminal_workspace_lease(&state.workspace_storage, &operation).await?;
        }
    } else {
        let owner = format!("workspace-retry-{}", Uuid::now_v7());
        let now = crate::transaction::unix_time_ms();
        let Some(claimed) = journal
            .claim_reconcilable_operation(
                operation_id,
                &owner,
                now,
                now.saturating_add(WORKSPACE_OPERATION_LEASE_TTL.as_millis() as i64),
            )
            .await?
        else {
            return Ok(ExistingDirectCompletion::Pending);
        };

        let (transaction_backend, recovered_fence) = match backend {
            ResolvedBackend::S3 {
                kind: BackendKind::PerUserS3,
                ..
            } => {
                let binding = claimed
                    .destination
                    .workspace_binding
                    .as_ref()
                    .ok_or_else(|| {
                        TransactionError::Publication(
                            "workspace operation has no versioned destination binding".to_string(),
                        )
                    })?;
                let workspace = WorkspaceId::new(workspace_id.to_string()).map_err(|_| {
                    TransactionError::Publication(
                        "workspace recovery identity is invalid".to_string(),
                    )
                })?;
                let (historical, lease) = backend_resolver(state)
                    .recover_workspace_operation(
                        &workspace,
                        operation_id,
                        binding,
                        &owner,
                        WORKSPACE_OPERATION_LEASE_TTL,
                    )
                    .await
                    .map_err(TransactionError::Publication)?;
                let ResolvedBackend::S3 {
                    client,
                    workspace_streaming: Some(streaming),
                    ..
                } = historical
                else {
                    return Ok(ExistingDirectCompletion::Conflict);
                };
                let fence = WorkspaceMutationFence::new(
                    state.workspace_storage.clone(),
                    workspace,
                    lease,
                    WORKSPACE_OPERATION_LEASE_TTL,
                );
                let transaction_backend = if streaming.provider
                    == crate::backend::WorkspaceS3Provider::B2
                    && streaming.identity.attestation.exact_version_recovery
                {
                    AwsS3TransactionBackend::new_b2(
                        client,
                        streaming.identity.attestation.capabilities,
                    )
                } else {
                    AwsS3TransactionBackend::new(
                        client,
                        streaming.identity.attestation.capabilities,
                    )
                }
                .with_mutation_fence(fence.clone() as Arc<dyn ProviderMutationFence>);
                (transaction_backend, Some(fence))
            }
            ResolvedBackend::S3 {
                kind: BackendKind::GlobalS3,
                client,
                ..
            } => {
                let Some(capabilities) = state.s3_streaming_capabilities else {
                    return Ok(ExistingDirectCompletion::Conflict);
                };
                (
                    AwsS3TransactionBackend::new(client.clone(), capabilities),
                    None,
                )
            }
            _ => return Ok(ExistingDirectCompletion::Conflict),
        };
        let reconciler =
            OperationReconciler::new(journal.clone(), Arc::new(transaction_backend), owner)?;
        reconciler.reconcile_claimed(claimed).await?;
        operation = journal.get(operation_id).await?.ok_or_else(|| {
            TransactionError::Publication(
                "direct completion journal row disappeared during reconciliation".to_string(),
            )
        })?;
        if operation.state.is_terminal()
            && let Some(fence) = recovered_fence
        {
            let outcome = if operation.state == OperationState::Committed {
                WorkspaceOperationOutcome::Committed
            } else {
                WorkspaceOperationOutcome::ProvenAborted
            };
            let leased = WorkspaceLeasedSinkRelease { fence };
            leased.release(outcome).await?;
        }
    }
    Ok(match operation.state {
        OperationState::Committed => ExistingDirectCompletion::Committed(Box::new(operation)),
        OperationState::ProvenAborted => ExistingDirectCompletion::ProvenAborted,
        OperationState::Intent
        | OperationState::Open
        | OperationState::Completing
        | OperationState::CommitUnknown
        | OperationState::Aborting => ExistingDirectCompletion::Pending,
    })
}

pub(crate) struct WorkspaceLeasedSinkRelease {
    pub(crate) fence: Arc<WorkspaceMutationFence>,
}

impl WorkspaceLeasedSinkRelease {
    pub(crate) async fn release(
        &self,
        outcome: WorkspaceOperationOutcome,
    ) -> Result<(), TransactionError> {
        self.fence.stop();
        let lease = self.fence.terminal_lease().await;
        self.fence
            .repository
            .release_streaming_operation_lease(&self.fence.workspace_id, &lease, outcome)
            .await
            .map_err(|_| {
                TransactionError::Publication(
                    "workspace recovery lease terminal update failed".to_string(),
                )
            })
    }
}

/// Startup/periodic hook for private adapters to reconcile one durable BYO
/// operation after process loss. The operation's historical config version is
/// loaded before any provider request; current credentials are never used as a
/// fallback.
pub async fn reconcile_workspace_streaming_operation(
    state: &AppState,
    operation_id: Uuid,
) -> Result<bool, String> {
    let journal = state
        .operation_journal
        .as_ref()
        .ok_or_else(|| "durable operation journal is unavailable".to_string())?;
    let operation = journal
        .get(operation_id)
        .await
        .map_err(|_| "durable operation lookup failed".to_string())?
        .ok_or_else(|| "durable operation was not found".to_string())?;
    if operation.state.is_terminal() {
        settle_terminal_workspace_lease(&state.workspace_storage, &operation)
            .await
            .map_err(|_| "workspace terminal route settlement failed".to_string())?;
        return Ok(true);
    }
    let workspace_id = operation
        .tenant_id
        .as_deref()
        .ok_or_else(|| "workspace operation has no tenant identity".to_string())?;
    let workspace = WorkspaceId::new(workspace_id.to_string())
        .map_err(|_| "workspace operation identity is invalid".to_string())?;
    let owner = format!("workspace-periodic-{}", Uuid::now_v7());
    let now = crate::transaction::unix_time_ms();
    let Some(claimed) = journal
        .claim_reconcilable_operation(
            operation_id,
            &owner,
            now,
            now.saturating_add(WORKSPACE_OPERATION_LEASE_TTL.as_millis() as i64),
        )
        .await
        .map_err(|_| "workspace operation journal claim failed".to_string())?
    else {
        return Ok(false);
    };
    let binding = claimed
        .destination
        .workspace_binding
        .as_ref()
        .ok_or_else(|| "workspace operation has no versioned destination binding".to_string())?;
    let (historical, lease) = backend_resolver(state)
        .recover_workspace_operation(
            &workspace,
            operation_id,
            binding,
            &owner,
            WORKSPACE_OPERATION_LEASE_TTL,
        )
        .await?;
    let ResolvedBackend::S3 {
        client,
        workspace_streaming: Some(streaming),
        ..
    } = historical
    else {
        return Err("historical workspace storage kind changed".to_string());
    };
    let fence = WorkspaceMutationFence::new(
        state.workspace_storage.clone(),
        workspace,
        lease,
        WORKSPACE_OPERATION_LEASE_TTL,
    );
    let transaction_backend = if streaming.provider == crate::backend::WorkspaceS3Provider::B2
        && streaming.identity.attestation.exact_version_recovery
    {
        AwsS3TransactionBackend::new_b2(client, streaming.identity.attestation.capabilities)
    } else {
        AwsS3TransactionBackend::new(client, streaming.identity.attestation.capabilities)
    }
    .with_mutation_fence(fence.clone() as Arc<dyn ProviderMutationFence>);
    let reconciler =
        OperationReconciler::new(journal.clone(), Arc::new(transaction_backend), owner)
            .map_err(|_| "workspace operation provider capabilities changed".to_string())?;
    reconciler
        .reconcile_claimed(claimed)
        .await
        .map_err(|_| "workspace operation reconciliation failed".to_string())?;
    let operation = journal
        .get(operation_id)
        .await
        .map_err(|_| "workspace operation reload failed".to_string())?
        .ok_or_else(|| "workspace operation disappeared during reconciliation".to_string())?;
    if operation.state.is_terminal() {
        let outcome = if operation.state == OperationState::Committed {
            WorkspaceOperationOutcome::Committed
        } else {
            WorkspaceOperationOutcome::ProvenAborted
        };
        WorkspaceLeasedSinkRelease { fence }
            .release(outcome)
            .await
            .map_err(|_| "workspace terminal route settlement failed".to_string())?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub(crate) async fn recovered_multipart_result(
    journal: Option<&Arc<dyn OperationJournal>>,
    operation: OperationRecord,
    lease: &CompletionLease,
    receipt_id: Uuid,
) -> Result<MultipartCompletionResult, MultipartCompletionError> {
    let journal = journal.ok_or_else(|| {
        MultipartCompletionError::Invalid(
            "committed direct operation has no durable journal".to_string(),
        )
    })?;
    let durable = load_usage_evidence(journal, operation.id, receipt_id)
        .await
        .map_err(TransactionError::from)
        .map_err(StreamingPutError::from)?;
    let stored = operation.committed.ok_or_else(|| {
        MultipartCompletionError::Invalid(
            "committed direct operation is missing destination metadata".to_string(),
        )
    })?;
    let size_bytes = operation.expected.size.ok_or_else(|| {
        MultipartCompletionError::Invalid(
            "committed direct operation is missing expected output size".to_string(),
        )
    })?;
    let checksum_sha256 = operation.expected.digest.ok_or_else(|| {
        MultipartCompletionError::Invalid(
            "committed direct operation is missing expected output checksum".to_string(),
        )
    })?;
    let source_bytes = lease
        .selected_parts
        .iter()
        .try_fold(0_u64, |total, part| total.checked_add(part.size_bytes))
        .ok_or_else(|| {
            MultipartCompletionError::Invalid("multipart source size overflow".to_string())
        })?;
    if durable.source_bytes != source_bytes
        || durable.output_bytes != size_bytes
        || durable.processed_bytes != source_bytes.max(size_bytes)
        || durable.bucket != operation.destination.bucket
        || durable.route != UsageRoute::CompleteMultipartUpload.as_str()
        || durable.kind != RequestKind::Write.as_str()
    {
        return Err(MultipartCompletionError::Invalid(
            "committed direct operation usage evidence does not match recovery state".to_string(),
        ));
    }
    Ok(MultipartCompletionResult {
        etag: stored.etag,
        checksum_sha256,
        version_id: stored.version_id,
        source_bytes,
        size_bytes,
        pipeline_evidence: durable.pipeline_evidence,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn complete_staged_avro_multipart(
    state: &AppState,
    staging: &MultipartStaging,
    identity: &MultipartIdentity,
    upload: &MultipartUpload,
    lease: &CompletionLease,
    operation: AuthorizedOperation<'_>,
    backend: ResolvedBackend,
    content_type: &str,
) -> Result<MultipartCompletionResult, MultipartCompletionError> {
    use sha2::Digest as _;

    let fingerprint = upload
        .complete_request_fingerprint
        .as_deref()
        .ok_or_else(|| {
            MultipartCompletionError::Invalid(
                "multipart completion fingerprint is missing".to_string(),
            )
        })?;
    let destination_operation_id =
        crate::multipart_staging::DestinationCommitPermit::deterministic_operation_id(
            identity,
            fingerprint,
        );
    let coordinator = multipart_completion_coordinator(state, staging)?;
    renew_and_fence_completion(staging, identity, lease).await?;
    let stored_metadata = multipart_stored_metadata(&upload.snapshot);
    validate_multipart_checksum_mode(&upload.snapshot)
        .map_err(|detail| MultipartCompletionError::Invalid(detail.to_string()))?;
    let mut sink = begin_streaming_sink(
        state,
        backend,
        operation,
        destination_operation_id,
        &identity.bucket,
        &identity.key,
        content_type,
        Some((&coordinator, identity, fingerprint)),
        Some(stored_metadata),
    )
    .await?;
    coordinator
        .bind_existing_operation(destination_operation_id, identity)
        .await?;
    // Route admission can block; a stale completion worker must stop before it
    // polls any selected artifact.
    renew_and_fence_completion(staging, identity, lease).await?;

    let max_source_bytes = state.source_body_limits.max_bytes.min(64 * 1024 * 1024) as usize;
    let mut input = Vec::new();
    let mut input_bytes = 0_u64;
    for part in &lease.selected_parts {
        renew_and_fence_completion(staging, identity, lease).await?;
        let body = staging.artifacts.get(&part.artifact_key).await?;
        renew_and_fence_completion(staging, identity, lease).await?;
        let mut reader = EncryptedPartReader::open(
            body,
            identity,
            part,
            &upload.snapshot,
            staging.wrapping.clone(),
        )
        .await?;
        let mut part_bytes = 0_u64;
        let mut part_sha256 = sha2::Sha256::new();
        let mut part_md5 = Md5::new();
        loop {
            renew_and_fence_completion(staging, identity, lease).await?;
            let Some(chunk) = reader.next_chunk().await? else {
                break;
            };
            part_bytes = part_bytes.checked_add(chunk.len() as u64).ok_or_else(|| {
                MultipartCompletionError::Invalid("multipart part is too large".to_string())
            })?;
            input_bytes = input_bytes.checked_add(chunk.len() as u64).ok_or_else(|| {
                MultipartCompletionError::Invalid("multipart input is too large".to_string())
            })?;
            if part_bytes > part.size_bytes || input_bytes as usize > max_source_bytes {
                return Err(MultipartCompletionError::Invalid(
                    "multipart input exceeds its limit".to_string(),
                ));
            }
            part_sha256.update(&chunk);
            part_md5.update(&chunk);
            input.extend_from_slice(&chunk);
        }
        if part_bytes != part.size_bytes
            || hex::encode(part_sha256.finalize()) != part.checksum_sha256
            || format!("\"{}\"", hex::encode(part_md5.finalize())) != part.etag
        {
            return Err(MultipartCompletionError::Invalid(
                "staged multipart artifact does not match its committed part".to_string(),
            ));
        }
    }
    let limits = crate::avro::AvroLimits {
        max_source_bytes,
        ..crate::avro::AvroLimits::default()
    };
    let headers = HeaderMap::new();
    let mut pump = avro_pump(operation.auth, &headers, limits)?;
    let mut decoding = tokio::task::spawn_blocking(move || {
        crate::avro::process_ocf(input.as_slice(), limits, &mut pump)
    });
    let output = loop {
        tokio::select! {
            result = &mut decoding => {
                break result
                    .map_err(|_| MultipartCompletionError::Invalid(
                        "Avro decoding worker failed".to_string(),
                    ))??;
            }
            () = tokio::time::sleep((COMPLETION_LEASE / 3).max(Duration::from_millis(1))) => {
                if let Err(error) = renew_and_fence_completion(staging, identity, lease).await {
                    decoding.abort();
                    return Err(error.into());
                }
            }
        }
    };
    let output_bytes = u64::try_from(output.len())
        .map_err(|_| MultipartCompletionError::Invalid("Avro output is too large".to_string()))?;
    let output_digest = hex::encode(sha2::Sha256::digest(&output));
    let result = async {
        renew_and_fence_completion(staging, identity, lease).await?;
        sink.write(bytes::Bytes::from(output)).await?;
        sink.verify_output(output_bytes, &output_digest).await?;
        renew_and_fence_completion(staging, identity, lease).await?;
        let precommit_result = MultipartCompletionResult {
            etag: None,
            checksum_sha256: output_digest.clone(),
            version_id: None,
            source_bytes: input_bytes,
            size_bytes: output_bytes,
            pipeline_evidence: None,
        };
        let mut usage_event = multipart_completion_event(operation.grant, &precommit_result);
        usage_event = usage_event.with_operation_id(destination_operation_id);
        renew_and_fence_completion(staging, identity, lease).await?;
        coordinator
            .publish(
                identity,
                fingerprint,
                lease.fencing_token,
                precommit_result,
                &usage_event,
                &mut sink,
            )
            .await
            .map_err(MultipartCompletionError::from)
    }
    .await;

    if result.is_err()
        && renew_and_fence_completion(staging, identity, lease)
            .await
            .is_ok()
    {
        let _ = sink.abort().await;
    }
    result
}

pub(crate) async fn reconcile_staged_artifacts(
    staging: &MultipartStaging,
    now: i64,
    limit: usize,
) -> Result<(), StagingError> {
    for candidate in staging.repository.cleanup_candidates(now, limit).await? {
        if staging
            .artifacts
            .delete(&candidate.artifact_key)
            .await
            .is_ok()
        {
            staging
                .repository
                .confirm_artifact_deleted(&candidate.artifact_key)
                .await?;
            staging
                .repository
                .audit(CleanupAudit {
                    id: Uuid::now_v7(),
                    upload_id: candidate.upload_id,
                    kind: "reconcile_attempt".to_string(),
                    detail: serde_json::json!({"artifact_key": candidate.artifact_key}),
                    created_at_ms: now_ms(),
                })
                .await?;
        }
    }
    let known = staging.repository.known_artifact_keys().await?;
    let cutoff = now - crate::multipart_staging::RECONCILIATION_GRACE.as_millis() as i64;
    for StagedArtifact {
        key,
        modified_at_ms,
    } in staging.artifacts.list(ARTIFACT_PREFIX).await?
    {
        // An object is never written before its PENDING record commits. The
        // grace period avoids deleting an in-flight S3 PUT during a scan.
        if !known.contains_key(&key) && modified_at_ms <= cutoff {
            let _ = staging.artifacts.delete(&key).await;
        }
    }
    Ok(())
}

impl MultipartRecoveryRuntime {
    pub(crate) async fn run_once(&self, now: i64, limit: usize) -> anyhow::Result<()> {
        let limit = limit.max(1);
        if let Some(store) = &self.file_store {
            store.validate_commit_proofs().await?;
            store.backfill_current_commit_proofs().await?;
        }

        reconcile_staged_artifacts(&self.staging, now, limit).await?;
        for publishing in self.staging.repository.publishing_uploads(limit).await? {
            let _ = self.coordinator.recover_publishing(&publishing).await?;
        }

        let expired = self.staging.repository.reap_expired(now, limit).await?;
        let upload_ids: HashSet<_> = expired.iter().map(|part| part.upload_id.clone()).collect();
        for upload_id in upload_ids {
            let selected = expired
                .iter()
                .filter(|part| part.upload_id == upload_id)
                .cloned()
                .collect();
            cleanup_staged_parts(&self.staging, &upload_id, selected, "expiry_reap").await;
        }
        reconcile_staged_artifacts(&self.staging, now, limit).await?;

        for identity in self
            .staging
            .repository
            .terminal_upload_candidates(now, 1)
            .await?
        {
            for retired in self
                .coordinator
                .retire_terminal_upload(&identity, now, limit)
                .await?
            {
                if let Some(epoch) = retired.namespace_epoch {
                    self.service_storage
                        .finish_managed_multipart(&retired.upload_id, &retired.tenant_id, epoch)
                        .await
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                }
            }
        }

        EncryptedPartWriter::cleanup_stale(
            &self.staging.directory,
            Duration::from_secs(24 * 60 * 60),
        )
        .await?;
        if self.service_storage.managed_mode() != ManagedStreamingMode::Off {
            self.service_storage
                .reconcile_managed_multipart_activities(limit as u64)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        }
        Ok(())
    }
}

impl MultipartPersistenceBundle {
    pub(crate) fn start_worker(&self) {
        let Some(recovery) = self.recovery.clone() else {
            return;
        };
        let cancellation = tokio_util::sync::CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = worker_cancellation.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_secs(60)) => {
                        if recovery.run_once(now_ms(), 64).await.is_err() {
                            warn!(error_category = "recovery", "multipart recovery worker failed");
                        }
                    }
                }
            }
        });
        let mut worker = self.worker.lock().expect("multipart worker lock poisoned");
        debug_assert!(worker.is_none());
        *worker = Some(MultipartRecoveryWorker { cancellation, task });
    }
}

pub(crate) async fn s3_upload_part(
    state: Arc<AppState>,
    bucket: String,
    key: String,
    params: S3Query,
    request: Request,
) -> axum::response::Response {
    let (parts, mut body) = request.into_parts();
    if parts.headers.contains_key("x-amz-copy-source") {
        return s3_error::not_implemented(&key);
    }
    let (Some(part_number), Some(upload_id)) = (params.part_number, params.upload_id) else {
        return s3_error::invalid_request(&key, "partNumber and uploadId are required");
    };
    let mut authentication = match authenticate_headers(
        parts.method.as_str(),
        &parts.uri,
        &parts.headers,
        &state.keys,
        &state,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => return authentication_error_response(&key, error),
    };
    if let Some(response) = client_metering_id_rejection(&parts.headers, &key) {
        return response;
    }
    let Some(staging) = staged_multipart(&state).cloned() else {
        return s3_error::multipart_not_supported(&key);
    };
    let multipart_backend = match resolve_backend(
        &state,
        &authentication.auth,
        &parts.headers,
        StorageOperation::Multipart,
    )
    .await
    {
        Ok(backend) => backend,
        Err(_) => return backend_resolution_error_response(&key),
    };
    if let Err(error) = validate_streaming_backend(&state, &multipart_backend) {
        return streaming_put_error_response(&key, error);
    }
    let identity = multipart_identity(&authentication.auth, &bucket, &key, &upload_id);
    let upload = match staging.repository.get_authorized(&identity).await {
        Ok(upload) => upload,
        Err(StagingError::NotFound) => return s3_error::no_such_upload(&key),
        Err(error) => return s3_error::internal_error(&key, &error.to_string()),
    };
    if let ResolvedBackend::Managed(storage) = &multipart_backend {
        let Some(epoch) = upload.namespace_epoch else {
            return s3_error::service_unavailable(&key, "managed multipart upload has no epoch");
        };
        if storage
            .assert_managed_multipart(
                &upload_id,
                authentication.auth.workspace_id().as_str(),
                epoch,
                false,
            )
            .await
            .is_err()
        {
            return s3_error::service_unavailable(
                &key,
                "managed multipart storage is temporarily unavailable",
            );
        }
    }
    if upload.lifecycle != MultipartLifecycle::Open || upload.expires_at_ms <= now_ms() {
        return s3_error::no_such_upload(&key);
    }
    let reserved_bytes = match staged_part_reservation(&parts.headers) {
        Ok(bytes) => bytes,
        Err(PartReservationError::Missing) => {
            return s3_error::invalid_argument(
                &key,
                "multipart parts require a decoded Content-Length",
            );
        }
        Err(PartReservationError::TooLarge(_)) => return s3_error::entity_too_large(&key),
    };
    // This is the durable quota/CAS point. It must occur before consuming a
    // body frame, opening a temp file, or creating an object-store artifact.
    let pending = match staging
        .repository
        .begin_part(&identity, part_number, reserved_bytes, now_ms())
        .await
    {
        Ok(pending) => pending,
        Err(StagingError::QuotaExceeded) => return s3_error::slow_down(&key),
        Err(StagingError::NotFound | StagingError::NotOpen) => {
            return s3_error::no_such_upload(&key);
        }
        Err(StagingError::InvalidPart) => {
            return s3_error::invalid_request(&key, "invalid multipart part");
        }
        Err(error) => return s3_error::internal_error(&key, &error.to_string()),
    };
    let mut writer = match EncryptedPartWriter::begin(
        &staging.directory,
        &identity,
        part_number,
        pending.attempt,
        &upload.snapshot,
        pending.reserved_bytes,
        staging.wrapping.clone(),
    )
    .await
    {
        Ok(writer) => writer,
        Err(error) => {
            let _ = staging
                .repository
                .discard_pending(&identity, &pending)
                .await;
            return s3_error::internal_error(&key, &error.to_string());
        }
    };
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(_) => {
                let _ = staging
                    .repository
                    .discard_pending(&identity, &pending)
                    .await;
                return s3_error::invalid_request(&key, "request body transport failed");
            }
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if data.len() > state.source_body_limits.max_frame_bytes {
            let _ = staging
                .repository
                .discard_pending(&identity, &pending)
                .await;
            return s3_error::invalid_request(
                &key,
                "multipart body frame exceeds configured limit",
            );
        }
        let decoded = match &mut authentication.body_verifier {
            Some(verifier) => match verifier.push(&data) {
                Ok(decoded) => decoded,
                Err(error) => {
                    let _ = staging
                        .repository
                        .discard_pending(&identity, &pending)
                        .await;
                    return s3_error::bad_digest(&key, &error.to_string());
                }
            },
            None => vec![data],
        };
        for chunk in decoded {
            if let Err(error) = writer.write(chunk).await {
                let _ = staging
                    .repository
                    .discard_pending(&identity, &pending)
                    .await;
                return s3_error::internal_error(&key, &error.to_string());
            }
        }
    }
    if let Some(verifier) = authentication.body_verifier.take()
        && let Err(error) = verifier.finish()
    {
        let _ = staging
            .repository
            .discard_pending(&identity, &pending)
            .await;
        return s3_error::bad_digest(&key, &error.to_string());
    }
    let finished = match writer.finish().await {
        Ok(value) => value,
        Err(error) => {
            let _ = staging
                .repository
                .discard_pending(&identity, &pending)
                .await;
            return s3_error::internal_error(&key, &error.to_string());
        }
    };
    if let Some(expected) = parts
        .headers
        .get("content-md5")
        .and_then(|value| value.to_str().ok())
    {
        let actual = hex::decode(finished.etag.trim_matches('"')).unwrap_or_default();
        if B64.decode(expected).ok().as_deref() != Some(actual.as_slice()) {
            finished.remove().await;
            let _ = staging
                .repository
                .discard_pending(&identity, &pending)
                .await;
            return s3_error::bad_digest(&key, "Content-MD5 does not match the uploaded part");
        }
    }
    if let Err(error) = staging
        .artifacts
        .put_file(&pending.artifact_key, &finished.path)
        .await
    {
        finished.remove().await;
        return s3_error::internal_error(&key, &error.to_string());
    }
    finished.remove().await;
    let part = MultipartPart {
        upload_id: upload_id.clone(),
        part_number,
        attempt: pending.attempt,
        artifact_key: pending.artifact_key.clone(),
        etag: finished.etag,
        checksum_sha256: finished.checksum_sha256,
        size_bytes: finished.size_bytes,
        created_at_ms: now_ms(),
    };
    match staging
        .repository
        .commit_part(&identity, &pending, part)
        .await
    {
        Ok(previous) => {
            if !previous.is_empty() {
                cleanup_staged_parts(&staging, &upload_id, previous, "part_replaced").await;
            }
            let mut response = axum::response::Response::builder().status(StatusCode::OK);
            response = response.header(
                header::ETAG,
                staging
                    .repository
                    .list_parts(&identity, part_number.saturating_sub(1), 1)
                    .await
                    .ok()
                    .and_then(|parts| parts.0.first().map(|part| part.etag.clone()))
                    .unwrap_or_default(),
            );
            response.body(axum::body::Body::empty()).unwrap()
        }
        Err(error) => {
            // The DB outcome can be unknown after a connection failure. Leave
            // the PENDING outbox record and ciphertext for reconciliation.
            s3_error::internal_error(&key, &error.to_string())
        }
    }
}
