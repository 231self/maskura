//! S3 object open/metadata helpers, reads, writes, and listings.
//!
//! Extracted from `server.rs`. Items are re-exported from [`crate::server`].

use super::*;

/// Escape a value for inclusion in an S3 XML document.
pub(crate) fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// URL-encode a key for `encoding-type=url` list responses (S3 url-encoding:
/// everything except unreserved `A-Za-z0-9-_.~`).
pub(crate) fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub(crate) fn backend_resolver(state: &AppState) -> BackendResolver {
    BackendResolver::new(
        state.workspace_storage.clone(),
        state.service_storage.clone(),
        state.s3_client.clone(),
        state.store.clone(),
        state.explicit_single_tenant,
        state.workspace_endpoint_policy.clone(),
    )
    .with_file_store(state.file_store.clone())
}

pub(crate) async fn resolve_backend(
    state: &AppState,
    auth: &Auth,
    headers: &HeaderMap,
    operation: StorageOperation,
) -> Result<ResolvedBackend, String> {
    backend_resolver(state)
        .resolve(auth.workspace_id(), headers, operation)
        .await
}

pub(crate) fn backend_resolution_error_response(key: &str) -> axum::response::Response {
    warn!("workspace backend resolution failed");
    s3_error::service_unavailable(key, "workspace storage is unavailable")
}

#[derive(Debug)]
pub(crate) enum OpenObjectError {
    NotFound,
    InvalidRange { object_length: u64 },
    Rejected(String),
    Backend(String),
    S3(S3Failure),
    PresignedTransport(PresignedTransportFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PresignedTransportFailure {
    Timeout,
    Connect,
    Request,
}

impl PresignedTransportFailure {
    pub(crate) fn from_reqwest(error: &reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else if error.is_connect() {
            Self::Connect
        } else {
            Self::Request
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Connect => "connect",
            Self::Request => "request",
        }
    }
}

pub(crate) fn open_error_response(key: &str, error: OpenObjectError) -> axum::response::Response {
    match error {
        OpenObjectError::NotFound => s3_error::no_such_key(key),
        OpenObjectError::InvalidRange { object_length } => {
            s3_error::invalid_range(key, object_length)
        }
        OpenObjectError::Rejected(detail) => {
            drop(detail);
            warn!(error_category = "policy", "presigned source rejected");
            s3_error::access_denied(key)
        }
        OpenObjectError::Backend(detail) => {
            drop(detail);
            warn!(error_category = "backend", "backend read failed");
            s3_error::internal_error(key, "backend read failed")
        }
        OpenObjectError::S3(failure) => s3_error::internal_error(key, failure.client_message()),
        OpenObjectError::PresignedTransport(failure) => {
            warn!(
                category = failure.as_str(),
                "presigned source transport failed"
            );
            s3_error::internal_error(key, "presigned backend request failed")
        }
    }
}

pub(crate) fn insert_header(
    metadata: &mut ObjectMetadata,
    name: &'static str,
    value: Option<&str>,
) {
    if let Some(value) = value {
        metadata.insert(HeaderName::from_static(name), value);
    }
}

pub(crate) fn insert_number<T: ToString>(
    metadata: &mut ObjectMetadata,
    name: &'static str,
    value: Option<T>,
) {
    if let Some(value) = value {
        metadata.insert(HeaderName::from_static(name), value.to_string());
    }
}

pub(crate) fn http_date(millis: i64) -> Option<String> {
    aws_smithy_types::DateTime::from_millis(millis)
        .fmt(DateTimeFormat::HttpDate)
        .ok()
}

pub(crate) fn s3_response_body(
    body: aws_sdk_s3::primitives::ByteStream,
    operation: &'static str,
) -> axum::body::Body {
    axum::body::Body::new(body.into_inner().map_err(move |_| {
        std::io::Error::other(crate::s3_safety::record_s3_body_failure(operation))
    }))
}

pub(crate) fn s3_get_metadata(
    output: &aws_sdk_s3::operation::get_object::GetObjectOutput,
) -> ObjectMetadata {
    let mut metadata = ObjectMetadata {
        version_id: output.version_id.clone(),
        ..ObjectMetadata::default()
    };
    insert_number(&mut metadata, "content-length", output.content_length);
    insert_header(&mut metadata, "accept-ranges", output.accept_ranges());
    insert_header(&mut metadata, "content-range", output.content_range());
    insert_header(&mut metadata, "content-type", output.content_type());
    insert_header(&mut metadata, "content-encoding", output.content_encoding());
    insert_header(
        &mut metadata,
        "content-disposition",
        output.content_disposition(),
    );
    insert_header(&mut metadata, "content-language", output.content_language());
    insert_header(&mut metadata, "cache-control", output.cache_control());
    insert_header(&mut metadata, "etag", output.e_tag());
    insert_header(
        &mut metadata,
        "x-amz-checksum-crc32",
        output.checksum_crc32(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-crc32c",
        output.checksum_crc32_c(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-crc64nvme",
        output.checksum_crc64_nvme(),
    );
    insert_header(&mut metadata, "x-amz-checksum-sha1", output.checksum_sha1());
    insert_header(
        &mut metadata,
        "x-amz-checksum-sha256",
        output.checksum_sha256(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-sha512",
        output.checksum_sha512(),
    );
    insert_header(&mut metadata, "x-amz-checksum-md5", output.checksum_md5());
    insert_header(
        &mut metadata,
        "x-amz-checksum-xxhash64",
        output.checksum_xxhash64(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-xxhash3",
        output.checksum_xxhash3(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-xxhash128",
        output.checksum_xxhash128(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-type",
        output.checksum_type().map(|value| value.as_str()),
    );
    insert_header(&mut metadata, "x-amz-version-id", output.version_id());
    insert_number(&mut metadata, "x-amz-mp-parts-count", output.parts_count);
    insert_number(&mut metadata, "x-amz-missing-meta", output.missing_meta);
    insert_header(&mut metadata, "x-amz-expiration", output.expiration());
    insert_header(&mut metadata, "x-amz-restore", output.restore());
    insert_header(
        &mut metadata,
        "x-amz-website-redirect-location",
        output.website_redirect_location(),
    );
    if let Some(last_modified) = output.last_modified()
        && let Ok(value) = last_modified.fmt(DateTimeFormat::HttpDate)
    {
        metadata.insert(header::LAST_MODIFIED, value);
    }
    if let Some(user_metadata) = output.metadata() {
        for (name, value) in user_metadata {
            if let Ok(name) = HeaderName::from_bytes(format!("x-amz-meta-{name}").as_bytes()) {
                metadata.append(name, value);
            }
        }
    }
    metadata
}

pub(crate) fn s3_head_metadata(
    output: &aws_sdk_s3::operation::head_object::HeadObjectOutput,
) -> ObjectMetadata {
    let mut metadata = ObjectMetadata {
        version_id: output.version_id.clone(),
        ..ObjectMetadata::default()
    };
    insert_number(&mut metadata, "content-length", output.content_length);
    insert_header(&mut metadata, "accept-ranges", output.accept_ranges());
    insert_header(&mut metadata, "content-range", output.content_range());
    insert_header(&mut metadata, "content-type", output.content_type());
    insert_header(&mut metadata, "content-encoding", output.content_encoding());
    insert_header(
        &mut metadata,
        "content-disposition",
        output.content_disposition(),
    );
    insert_header(&mut metadata, "content-language", output.content_language());
    insert_header(&mut metadata, "cache-control", output.cache_control());
    insert_header(&mut metadata, "etag", output.e_tag());
    insert_header(
        &mut metadata,
        "x-amz-checksum-crc32",
        output.checksum_crc32(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-crc32c",
        output.checksum_crc32_c(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-crc64nvme",
        output.checksum_crc64_nvme(),
    );
    insert_header(&mut metadata, "x-amz-checksum-sha1", output.checksum_sha1());
    insert_header(
        &mut metadata,
        "x-amz-checksum-sha256",
        output.checksum_sha256(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-sha512",
        output.checksum_sha512(),
    );
    insert_header(&mut metadata, "x-amz-checksum-md5", output.checksum_md5());
    insert_header(
        &mut metadata,
        "x-amz-checksum-xxhash64",
        output.checksum_xxhash64(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-xxhash3",
        output.checksum_xxhash3(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-xxhash128",
        output.checksum_xxhash128(),
    );
    insert_header(
        &mut metadata,
        "x-amz-checksum-type",
        output.checksum_type().map(|value| value.as_str()),
    );
    insert_header(&mut metadata, "x-amz-version-id", output.version_id());
    insert_number(&mut metadata, "x-amz-mp-parts-count", output.parts_count);
    insert_number(&mut metadata, "x-amz-missing-meta", output.missing_meta);
    insert_header(&mut metadata, "x-amz-expiration", output.expiration());
    insert_header(&mut metadata, "x-amz-restore", output.restore());
    insert_header(
        &mut metadata,
        "x-amz-website-redirect-location",
        output.website_redirect_location(),
    );
    if let Some(last_modified) = output.last_modified()
        && let Ok(value) = last_modified.fmt(DateTimeFormat::HttpDate)
    {
        metadata.insert(header::LAST_MODIFIED, value);
    }
    if let Some(user_metadata) = output.metadata() {
        for (name, value) in user_metadata {
            if let Ok(name) = HeaderName::from_bytes(format!("x-amz-meta-{name}").as_bytes()) {
                metadata.append(name, value);
            }
        }
    }
    metadata
}

pub(crate) fn forwarded_read_headers(headers: &HeaderMap) -> HeaderMap {
    let mut forwarded = HeaderMap::new();
    for name in [
        header::RANGE,
        header::IF_MATCH,
        header::IF_NONE_MATCH,
        header::IF_MODIFIED_SINCE,
        header::IF_UNMODIFIED_SINCE,
        HeaderName::from_static("x-amz-checksum-mode"),
    ] {
        for value in headers.get_all(&name) {
            forwarded.append(name.clone(), value.clone());
        }
    }
    forwarded
}

pub(crate) async fn open_http_object(
    state: &AppState,
    url: reqwest::Url,
    headers: &HeaderMap,
    head_only: bool,
) -> Result<OpenedObject, OpenObjectError> {
    let client = state
        .presigned_http_policy
        .client_for(&url)
        .await
        .map_err(OpenObjectError::Rejected)?;
    let method = if head_only {
        reqwest::Method::HEAD
    } else {
        reqwest::Method::GET
    };
    let response = client
        .request(method, url)
        .headers(forwarded_read_headers(headers))
        .send()
        .await
        .map_err(|error| {
            OpenObjectError::PresignedTransport(PresignedTransportFailure::from_reqwest(&error))
        })?;
    if response.status().is_redirection() {
        return Err(OpenObjectError::Rejected(
            "presigned HTTP source redirects are forbidden".to_string(),
        ));
    }
    let response: axum::http::Response<reqwest::Body> = response.into();
    let (parts, body) = response.into_parts();
    let mut response_headers = parts.headers;
    filter_presigned_response_headers(&mut response_headers);
    let version_id = response_headers
        .get("x-amz-version-id")
        .or_else(|| response_headers.get("x-goog-generation"))
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let metadata = ObjectMetadata {
        headers: response_headers,
        version_id,
    };
    let body = if head_only {
        axum::body::Body::empty()
    } else {
        axum::body::Body::new(body)
    };
    Ok(OpenedObject::new(
        parts.status,
        metadata,
        body,
        state.source_body_limits,
    ))
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ByteRange {
    pub(crate) start: u64,
    pub(crate) length: u64,
    pub(crate) content_range: Option<String>,
}

pub(crate) fn parse_byte_range(
    object_length: u64,
    range: Option<&str>,
) -> Result<ByteRange, OpenObjectError> {
    let invalid_range = || OpenObjectError::InvalidRange { object_length };
    let Some(range) = range else {
        return Ok(ByteRange {
            start: 0,
            length: object_length,
            content_range: None,
        });
    };
    let spec = range
        .strip_prefix("bytes=")
        .filter(|spec| !spec.contains(','))
        .ok_or_else(invalid_range)?;
    let (start, end) = spec.split_once('-').ok_or_else(invalid_range)?;
    if object_length == 0 {
        return Err(invalid_range());
    }
    let (start, end) = if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| invalid_range())?;
        if suffix == 0 {
            return Err(invalid_range());
        }
        (object_length.saturating_sub(suffix), object_length - 1)
    } else {
        let start = start.parse::<u64>().map_err(|_| invalid_range())?;
        let end = if end.is_empty() {
            object_length - 1
        } else {
            end.parse::<u64>().map_err(|_| invalid_range())?
        };
        if start >= object_length || start > end {
            return Err(invalid_range());
        }
        (start, end.min(object_length - 1))
    };
    Ok(ByteRange {
        start,
        length: end - start + 1,
        content_range: Some(format!("bytes {start}-{end}/{object_length}")),
    })
}

pub(crate) fn memory_range(
    data: &bytes::Bytes,
    range: Option<&str>,
) -> Result<(bytes::Bytes, Option<String>), OpenObjectError> {
    let selected = parse_byte_range(data.len() as u64, range)?;
    let start = usize::try_from(selected.start).expect("byte range start fits memory object");
    let length = usize::try_from(selected.length).expect("byte range length fits memory object");
    Ok((data.slice(start..start + length), selected.content_range))
}

/// Reproduces the initiation metadata FileStore persisted at multipart
/// completion: representation headers, `x-amz-meta-*` user metadata, the
/// tagging header, and the stored SHA-256 checksum.
pub(crate) fn apply_file_stored_headers(
    metadata: &mut ObjectMetadata,
    representation_headers: &std::collections::BTreeMap<String, String>,
    user_metadata: &std::collections::BTreeMap<String, String>,
    tags: &std::collections::BTreeMap<String, String>,
    checksum: Option<&LocalChecksumState>,
) {
    for (name, value) in representation_headers {
        if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
            metadata.insert(name, value);
        }
    }
    for (name, value) in user_metadata {
        if let Ok(name) = HeaderName::from_bytes(format!("x-amz-meta-{name}").as_bytes()) {
            metadata.insert(name, value);
        }
    }
    if !tags.is_empty() {
        let joined = tags
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("&");
        metadata.insert(HeaderName::from_static("x-amz-tagging"), joined);
    }
    if let Some(state) = checksum.filter(|state| state.algorithm.eq_ignore_ascii_case("sha256")) {
        metadata.insert(
            HeaderName::from_static("x-amz-checksum-sha256"),
            &state.value,
        );
    }
}

pub(crate) async fn open_backend_object(
    state: &AppState,
    backend: ResolvedBackend,
    auth: &Auth,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
    head_only: bool,
) -> Result<OpenedObject, OpenObjectError> {
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    match backend {
        ResolvedBackend::PresignedHttp(url) => {
            open_http_object(state, url, headers, head_only).await
        }
        ResolvedBackend::S3 { client, .. } => {
            let checksum_mode = headers
                .get("x-amz-checksum-mode")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.eq_ignore_ascii_case("enabled"));
            if head_only {
                let mut request = client.head_object().bucket(bucket).key(key);
                if checksum_mode {
                    request = request.checksum_mode(ChecksumMode::Enabled);
                }
                let output = request.send().await.map_err(|error| {
                    if error
                        .as_service_error()
                        .is_some_and(|service| service.is_not_found())
                    {
                        OpenObjectError::NotFound
                    } else {
                        OpenObjectError::S3(record_s3_failure("head_object", &error))
                    }
                })?;
                return Ok(OpenedObject::new(
                    StatusCode::OK,
                    s3_head_metadata(&output),
                    axum::body::Body::empty(),
                    state.source_body_limits,
                ));
            }
            let mut request = client.get_object().bucket(bucket).key(key);
            if let Some(range) = range {
                request = request.range(range);
            }
            if checksum_mode {
                request = request.checksum_mode(ChecksumMode::Enabled);
            }
            let output = request.send().await.map_err(|error| {
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_no_such_key())
                {
                    OpenObjectError::NotFound
                } else {
                    OpenObjectError::S3(record_s3_failure("get_object", &error))
                }
            })?;
            let status = if output.content_range.is_some() {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            };
            let metadata = s3_get_metadata(&output);
            let body = s3_response_body(output.body, "get_object_body");
            Ok(OpenedObject::new(
                status,
                metadata,
                body,
                state.source_body_limits,
            ))
        }
        ResolvedBackend::Managed(storage) => {
            let logical = managed_logical_key(auth, bucket, key);
            let workspace_id = auth.workspace_id().as_str();
            if head_only {
                let output = if storage.managed_mode() == ManagedStreamingMode::Off
                    || (storage.managed_mode() == ManagedStreamingMode::Observe
                        && !storage
                            .has_authority(&logical)
                            .await
                            .map_err(|error| OpenObjectError::Backend(error.to_string()))?)
                {
                    storage
                        .head_output(&format!("{workspace_id}/{bucket}/{key}"))
                        .await
                } else {
                    storage
                        .head_authoritative(&logical)
                        .await
                        .map_err(|error| OpenObjectError::Backend(error.to_string()))?
                }
                .ok_or(OpenObjectError::NotFound)?;
                return Ok(OpenedObject::new(
                    StatusCode::OK,
                    s3_head_metadata(&output),
                    axum::body::Body::empty(),
                    state.source_body_limits,
                ));
            }
            let output = if storage.managed_mode() == ManagedStreamingMode::Off
                || (storage.managed_mode() == ManagedStreamingMode::Observe
                    && !storage
                        .has_authority(&logical)
                        .await
                        .map_err(|error| OpenObjectError::Backend(error.to_string()))?)
            {
                storage
                    .open(&format!("{workspace_id}/{bucket}/{key}"), range)
                    .await
            } else {
                storage
                    .open_authoritative(&logical, range)
                    .await
                    .map_err(|error| OpenObjectError::Backend(error.to_string()))?
            }
            .ok_or(OpenObjectError::NotFound)?;
            let status = if output.content_range.is_some() {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            };
            let metadata = s3_get_metadata(&output);
            let body = s3_response_body(output.body, "managed_get_object_body");
            Ok(OpenedObject::new(
                status,
                metadata,
                body,
                state.source_body_limits,
            ))
        }
        ResolvedBackend::File(store) => {
            if head_only {
                let stored = store
                    .stored_meta(bucket, key)
                    .await
                    .map_err(|error| OpenObjectError::Backend(error.to_string()))?
                    .ok_or(OpenObjectError::NotFound)?;
                let mut metadata = ObjectMetadata::default();
                metadata.insert(header::CONTENT_LENGTH, stored.size.to_string());
                metadata.insert(header::CONTENT_TYPE, &stored.content_type);
                metadata.insert(header::ETAG, &stored.etag);
                metadata.insert(header::ACCEPT_RANGES, "bytes");
                if let Some(modified) = stored.last_modified_ms.and_then(http_date) {
                    metadata.insert(header::LAST_MODIFIED, modified);
                }
                apply_file_stored_headers(
                    &mut metadata,
                    &stored.representation_headers,
                    &stored.user_metadata,
                    &stored.tags,
                    stored.checksum.as_ref(),
                );
                return Ok(OpenedObject::new(
                    StatusCode::OK,
                    metadata,
                    axum::body::Body::empty(),
                    state.source_body_limits,
                ));
            }
            let object = store
                .open(bucket, key)
                .await
                .map_err(|error| OpenObjectError::Backend(error.to_string()))?
                .ok_or(OpenObjectError::NotFound)?;
            let selected = parse_byte_range(object.object_length, range)?;
            let mut metadata = ObjectMetadata::default();
            metadata.insert(header::CONTENT_LENGTH, selected.length.to_string());
            metadata.insert(header::CONTENT_TYPE, &object.content_type);
            metadata.insert(header::ETAG, &object.etag);
            metadata.insert(header::ACCEPT_RANGES, "bytes");
            if let Some(modified) = object.last_modified_ms.and_then(http_date) {
                metadata.insert(header::LAST_MODIFIED, modified);
            }
            apply_file_stored_headers(
                &mut metadata,
                &object.representation_headers,
                &object.user_metadata,
                &object.tags,
                object.checksum.as_ref(),
            );
            let object = object
                .into_range(selected.start, selected.length)
                .await
                .map_err(|error| OpenObjectError::Backend(error.to_string()))?;
            if let Some(content_range) = selected.content_range {
                metadata.insert(header::CONTENT_RANGE, content_range);
            }
            let status = if range.is_some() {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            };
            let body = axum::body::Body::from_stream(ReaderStream::with_capacity(
                object.reader,
                state.source_body_limits.max_frame_bytes.max(1),
            ));
            Ok(OpenedObject::new(
                status,
                metadata,
                body,
                state.source_body_limits,
            ))
        }
        ResolvedBackend::Memory(store) => {
            if head_only {
                let (size, content_type, etag) = store
                    .metadata(bucket, key)
                    .ok_or(OpenObjectError::NotFound)?;
                let mut metadata = ObjectMetadata::default();
                metadata.insert(header::CONTENT_LENGTH, size.to_string());
                metadata.insert(header::CONTENT_TYPE, content_type);
                metadata.insert(header::ETAG, etag);
                metadata.insert(header::ACCEPT_RANGES, "bytes");
                return Ok(OpenedObject::new(
                    StatusCode::OK,
                    metadata,
                    axum::body::Body::empty(),
                    state.source_body_limits,
                ));
            }
            let object = store.get(bucket, key).ok_or(OpenObjectError::NotFound)?;
            let (data, content_range) = memory_range(&object.data, range)?;
            let mut metadata = ObjectMetadata::default();
            metadata.insert(header::CONTENT_LENGTH, data.len().to_string());
            metadata.insert(header::CONTENT_TYPE, object.content_type);
            metadata.insert(header::ETAG, object.etag);
            metadata.insert(header::ACCEPT_RANGES, "bytes");
            if let Some(content_range) = content_range {
                metadata.insert(header::CONTENT_RANGE, content_range);
            }
            let status = if range.is_some() {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            };
            let body = axum::body::Body::new(ChunkedBytesBody::new(
                data,
                state.source_body_limits.max_frame_bytes,
            ));
            Ok(OpenedObject::new(
                status,
                metadata,
                body,
                state.source_body_limits,
            ))
        }
    }
}

pub(crate) fn s3_xml_ok(xml: String) -> axum::response::Response {
    let mut response = axum::response::Response::new(axum::body::Body::from(xml));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/xml".parse().expect("static content type"),
    );
    harden_object_response_headers(response.headers_mut());
    response
}

pub(crate) fn wants_transformed_read(headers: &HeaderMap) -> bool {
    customer_headers::validated(headers, customer_headers::PROCESS)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("read") || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[derive(Debug)]
pub(crate) enum TransformedReadError {
    InvalidRequest(String),
    Capacity(String),
    Source(String),
    Pipeline(maskura_error::MaskuraError),
    Spool(TransactionError),
}

impl From<maskura_error::MaskuraError> for TransformedReadError {
    fn from(error: maskura_error::MaskuraError) -> Self {
        Self::Pipeline(error)
    }
}

impl From<TransactionError> for TransformedReadError {
    fn from(error: TransactionError) -> Self {
        Self::Spool(error)
    }
}

pub(crate) fn transformed_read_error_response(
    key: &str,
    error: TransformedReadError,
) -> axum::response::Response {
    match error {
        TransformedReadError::InvalidRequest(detail) => s3_error::invalid_request(key, &detail),
        TransformedReadError::Capacity(detail) => {
            drop(detail);
            s3_error::service_unavailable(
                key,
                "transformed-read capacity is temporarily unavailable",
            )
        }
        TransformedReadError::Source(detail) => s3_error::internal_error(key, &detail),
        TransformedReadError::Spool(TransactionError::CapacityExceeded) => {
            s3_error::service_unavailable(
                key,
                "encrypted transformed-read staging capacity is unavailable",
            )
        }
        TransformedReadError::Spool(error) => s3_error::internal_error(key, &error.to_string()),
        TransformedReadError::Pipeline(error) => pipeline_error_response(key, &error),
    }
}

/// A transformed representation has different validators and range semantics
/// from its source. Keep only descriptive representation metadata.
pub(crate) fn transformed_response_headers(
    metadata: &ObjectMetadata,
    content_length: Option<u64>,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for name in [
        header::CONTENT_TYPE,
        header::CONTENT_DISPOSITION,
        header::CONTENT_LANGUAGE,
    ] {
        for value in metadata.headers.get_all(&name) {
            headers.append(name.clone(), value.clone());
        }
    }
    if let Some(content_length) = content_length
        && let Ok(value) = content_length.to_string().parse()
    {
        headers.insert(header::CONTENT_LENGTH, value);
    }
    harden_object_response_headers(&mut headers);
    headers
}

pub(crate) fn avro_read_preflight(
    headers: &HeaderMap,
    params: &S3Query,
    metadata: &ObjectMetadata,
) -> Option<TransformedReadError> {
    if headers.contains_key(header::RANGE) {
        return Some(TransformedReadError::InvalidRequest(
            "Range is not supported for transformed reads".to_string(),
        ));
    }
    if params.part_number.is_some() {
        return Some(TransformedReadError::InvalidRequest(
            "part-number reads are not supported for transformed reads".to_string(),
        ));
    }
    if let Some(encoding) = metadata.headers.get(header::CONTENT_ENCODING)
        && !encoding
            .to_str()
            .map(|value| value.eq_ignore_ascii_case("identity"))
            .unwrap_or(false)
    {
        return Some(TransformedReadError::InvalidRequest(
            "Content-Encoding is unsupported for transformed reads".to_string(),
        ));
    }
    None
}

pub(crate) fn transformed_read_preflight(
    headers: &HeaderMap,
    params: &S3Query,
    metadata: &ObjectMetadata,
) -> Result<(Format, String), TransformedReadError> {
    if headers.contains_key(header::RANGE) {
        return Err(TransformedReadError::InvalidRequest(
            "Range is not supported for transformed reads".to_string(),
        ));
    }
    if params.part_number.is_some() {
        return Err(TransformedReadError::InvalidRequest(
            "part-number reads are not supported for transformed reads".to_string(),
        ));
    }
    if let Some(encoding) = metadata.headers.get(header::CONTENT_ENCODING) {
        let encoding = encoding.to_str().map_err(|_| {
            TransformedReadError::InvalidRequest("invalid source Content-Encoding".to_string())
        })?;
        if !encoding.eq_ignore_ascii_case("identity") {
            return Err(TransformedReadError::InvalidRequest(
                "Content-Encoding is unsupported for transformed reads".to_string(),
            ));
        }
    }
    let content_type = metadata
        .headers
        .get(header::CONTENT_TYPE)
        .ok_or_else(|| {
            TransformedReadError::InvalidRequest(
                "Content-Type is required for transformed reads".to_string(),
            )
        })?
        .to_str()
        .map_err(|_| {
            TransformedReadError::InvalidRequest("invalid source Content-Type".to_string())
        })?;
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let format = match media_type.as_str() {
        "text/plain" => Format::Text,
        "application/x-ndjson" | "application/jsonlines" => Format::Jsonl,
        "application/json" => Format::Json,
        "text/csv" => Format::Csv,
        "text/tab-separated-values" => Format::Tsv,
        _ => {
            return Err(TransformedReadError::InvalidRequest(format!(
                "unsupported transformed-read Content-Type {media_type:?}"
            )));
        }
    };
    Ok((format, media_type))
}

/// An unversioned source is safe to transform only if both metadata responses
/// carry the same strong validator. Weak ETags are cache validators, not an
/// assertion that the bytes consumed by GET match the bytes inspected by HEAD.
pub(crate) fn transformed_source_matches_preflight(
    preflight: &ObjectMetadata,
    source: &ObjectMetadata,
) -> bool {
    (is_immutable_version_id(preflight.version_id.as_deref())
        && preflight.version_id == source.version_id)
        || strong_etag(preflight)
            .zip(strong_etag(source))
            .is_some_and(|(left, right)| left == right)
}

pub(crate) fn conditional_read_status(
    headers: &HeaderMap,
    metadata: &ObjectMetadata,
) -> Option<StatusCode> {
    let etag = metadata.headers.get(header::ETAG)?.to_str().ok()?;
    let matches = |condition: &str| {
        condition
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == "*" || candidate == etag)
    };
    if let Some(condition) = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
    {
        (!matches(condition)).then_some(StatusCode::PRECONDITION_FAILED)
    } else if let Some(condition) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
    {
        matches(condition).then_some(StatusCode::NOT_MODIFIED)
    } else {
        None
    }
}

pub(crate) fn conditional_read_response(
    mut object: OpenedObject,
    status: StatusCode,
) -> axum::response::Response {
    let etag = object.metadata.headers[header::ETAG].clone();
    let version_id = object.metadata.version_id.clone();
    object.status = status;
    object.metadata.headers.clear();
    object.metadata.headers.insert(header::ETAG, etag);
    if let Some(version_id) = version_id
        && let Ok(value) = version_id.parse()
    {
        object.metadata.headers.insert("x-amz-version-id", value);
    }
    object.cancellation.cancel();
    object.body = axum::body::Body::empty();
    object.into_response()
}

pub(crate) fn is_immutable_version_id(version_id: Option<&str>) -> bool {
    matches!(version_id, Some(version_id) if !version_id.is_empty() && version_id != "null")
}

pub(crate) fn strong_etag(metadata: &ObjectMetadata) -> Option<&str> {
    let etag = metadata.headers.get(header::ETAG)?.to_str().ok()?;
    let etag = etag.trim();
    (etag.len() > 2 && etag.starts_with('"') && etag.ends_with('"') && !etag.starts_with("W/"))
        .then_some(etag)
}

pub(crate) fn schedule_spool_cleanup(config: CompatibilitySpoolConfig) {
    // A zero duration is useful for direct cleanup tests but must not create a
    // busy loop if a future caller reuses it for the service configuration.
    let interval = config.stale_after.max(Duration::from_secs(60));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            match CompatibilitySpoolTransaction::cleanup_stale(&config).await {
                Ok(removed) if removed > 0 => {
                    info!(removed, "removed stale spool files");
                }
                Ok(_) => {}
                Err(_) => warn!(
                    error_category = "spool",
                    "failed to remove stale spool files"
                ),
            }
        }
    });
}

pub(crate) fn transformed_session(
    auth: &Auth,
    headers: &HeaderMap,
    format: Format,
    content_type: String,
) -> maskura_wasm_runtime::Session {
    maskura_wasm_runtime::Session {
        format: format.as_str().to_string(),
        content_type,
        policy_version: 0,
        operation: maskura_wasm_runtime::Operation::Read,
        config_json: None,
        public_key_pem: auth.public_key_pem.clone(),
        stable_key: auth.stable_key.clone(),
        stable_fields: customer_headers::validated(headers, customer_headers::STABLE_FIELDS)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned),
    }
}

pub(crate) async fn collect_opened_object(
    object: &mut OpenedObject,
    max_bytes: usize,
) -> Result<Vec<u8>, TransformedReadError> {
    let mut output = Vec::new();
    while let Some(frame) = object.body.frame().await {
        let frame = frame.map_err(|error| TransformedReadError::Source(error.to_string()))?;
        let data = frame.into_data().map_err(|frame| {
            if frame.into_trailers().is_ok() {
                TransformedReadError::Source(
                    "source trailers are not valid for transformed reads".to_string(),
                )
            } else {
                TransformedReadError::Source("source returned a non-data frame".to_string())
            }
        })?;
        if output.len().saturating_add(data.len()) > max_bytes {
            object.cancellation.cancel();
            return Err(TransformedReadError::Source(
                "Avro source exceeds the configured byte limit".to_string(),
            ));
        }
        output.extend_from_slice(&data);
    }
    Ok(output)
}

pub(crate) async fn serve_spooled_bytes(
    state: &AppState,
    bytes: Vec<u8>,
    source_cancellation: maskura_wasm_runtime::CancellationToken,
) -> Result<(axum::body::Body, u64), TransformedReadError> {
    let mut spool = EncryptedReadSpool::begin(
        state.spool_config.directory.clone(),
        state.spool_config.max_object_bytes,
        Arc::clone(&state.spool_quota),
    )
    .await?;
    if let Err(error) = spool.write(bytes::Bytes::from(bytes)).await {
        spool.abort().await;
        return Err(TransformedReadError::from(error));
    }
    spool
        .into_body(source_cancellation)
        .await
        .map_err(TransformedReadError::from)
}

pub(crate) async fn avro_transformed_read_response(
    state: &AppState,
    auth: &Auth,
    headers: &HeaderMap,
    response_metadata: ObjectMetadata,
    mut object: OpenedObject,
    key: &str,
) -> (axum::response::Response, Option<u64>) {
    if !state.transformed_read_spool_enabled {
        object.cancellation.cancel();
        return (
            transformed_read_error_response(
                key,
                TransformedReadError::Capacity(
                    "unsafe transformed reads require MASKURA_TRANSFORMED_READ_SPOOL=encrypted"
                        .to_string(),
                ),
            ),
            None,
        );
    }
    let max_source_bytes = state.source_body_limits.max_bytes.min(64 * 1024 * 1024) as usize;
    let source = match collect_opened_object(&mut object, max_source_bytes).await {
        Ok(source) => source,
        Err(error) => return (transformed_read_error_response(key, error), None),
    };
    let limits = crate::avro::AvroLimits {
        max_source_bytes,
        ..crate::avro::AvroLimits::default()
    };
    let mut pump = match avro_pump(auth, headers, limits) {
        Ok(pump) => pump,
        Err(error) => {
            return (
                transformed_read_error_response(key, TransformedReadError::Pipeline(error)),
                None,
            );
        }
    };
    let output = match crate::avro::process_ocf(source.as_slice(), limits, &mut pump) {
        Ok(output) => output,
        Err(error) => {
            return (
                transformed_read_error_response(key, TransformedReadError::Pipeline(error)),
                None,
            );
        }
    };
    let (body, content_length) =
        match serve_spooled_bytes(state, output, object.cancellation.clone()).await {
            Ok(result) => result,
            Err(error) => return (transformed_read_error_response(key, error), None),
        };
    let mut response = axum::response::Response::builder().status(StatusCode::OK);
    response
        .headers_mut()
        .unwrap()
        .extend(transformed_response_headers(
            &response_metadata,
            Some(content_length),
        ));
    (response.body(body).unwrap(), Some(object.counters.bytes()))
}

pub(crate) async fn process_transformed_source<F, Fut>(
    mut object: OpenedObject,
    mut pipeline: StreamingPipelineSession,
    format: Format,
    max_source_frame_bytes: usize,
    mut emit: F,
) -> Result<u64, TransformedReadError>
where
    F: FnMut(bytes::Bytes) -> Fut,
    Fut: std::future::Future<Output = Result<(), TransformedReadError>>,
{
    let cancellation = object.cancellation.clone();
    let decoder_limits = crate::record::DecoderLimits {
        max_source_frame_bytes,
        ..crate::record::DecoderLimits::default()
    };
    // CountedBody enforces the configured source-frame bound before this point;
    // the decoder sees the same frame without copying it as a whole object.
    let mut decoder = crate::record::RecordDecoder::new(format, decoder_limits)?;
    let result = async {
        while let Some(frame) = object.body.frame().await {
            let frame = frame.map_err(|error| TransformedReadError::Source(error.to_string()))?;
            let data = frame.into_data().map_err(|frame| {
                if frame.into_trailers().is_ok() {
                    TransformedReadError::Source(
                        "source trailers are not valid for transformed reads".to_string(),
                    )
                } else {
                    TransformedReadError::Source("source returned a non-data frame".to_string())
                }
            })?;
            decoder.push(&data)?;
            while let Some(record) = decoder.next_record()? {
                if let Some(record) = pipeline.process(record).await? {
                    if !record.payload.is_empty() {
                        emit(record.payload).await?;
                    }
                    if !record.separator.is_empty() {
                        emit(record.separator).await?;
                    }
                }
            }
        }
        decoder.finish()?;
        while let Some(record) = decoder.next_record()? {
            if let Some(record) = pipeline.process(record).await? {
                if !record.payload.is_empty() {
                    emit(record.payload).await?;
                }
                if !record.separator.is_empty() {
                    emit(record.separator).await?;
                }
            }
        }
        let (records, fuel_consumed) = pipeline.finish().await?;
        for record in records {
            if !record.payload.is_empty() {
                emit(record.payload).await?;
            }
            if !record.separator.is_empty() {
                emit(record.separator).await?;
            }
        }
        Ok(fuel_consumed)
    }
    .await;
    if result.is_err() {
        cancellation.cancel();
        // Dropping an un-finished session interrupts a current guest call. The
        // worker owns it here, so no retry or raw fallback is possible.
    }
    result
}

pub(crate) enum DirectReadEvent {
    Data(bytes::Bytes),
    Failed(TransformedReadError),
    Done {
        source_bytes: u64,
        output_bytes: u64,
        evidence: Option<crate::control::PipelineEvidence>,
    },
}

pub(crate) const DIRECT_READ_SETTLEMENT_ATTEMPTS: usize = 3;

pub(crate) type DirectSettlementFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), MeteringError>> + Send + 'static>,
>;

pub(crate) fn direct_settlement_future(
    control: Arc<dyn ControlPlane>,
    context: AuthenticatedRequestContext,
    event: UsageEvent,
) -> DirectSettlementFuture {
    Box::pin(async move {
        let mut last_error = MeteringError::Unavailable;
        for attempt in 1..=DIRECT_READ_SETTLEMENT_ATTEMPTS {
            match control.record(&context, &event).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    last_error = error;
                    warn!(
                        operation_id = %event.operation_id(),
                        receipt_id = %event.receipt_id(),
                        attempt,
                        "direct transformed-read settlement retry failed"
                    );
                }
            }
        }
        Err(last_error)
    })
}

pub(crate) struct DirectReadBody {
    pub(crate) first: Option<bytes::Bytes>,
    pub(crate) receiver: tokio::sync::mpsc::Receiver<DirectReadEvent>,
    pub(crate) source_cancellation: maskura_wasm_runtime::CancellationToken,
    pub(crate) pipeline_cancellation: maskura_wasm_runtime::CancellationToken,
    pub(crate) control: Arc<dyn ControlPlane>,
    pub(crate) context: AuthenticatedRequestContext,
    pub(crate) grant: AuthorizationGrant,
    pub(crate) failure_operation: OperationIdentity,
    pub(crate) failure_bucket: String,
    pub(crate) failure_resolution: crate::pipeline::PipelineResolution,
    pub(crate) settlement: Option<DirectSettlementFuture>,
    pub(crate) disclosed: bool,
    pub(crate) reservation_owned: bool,
    pub(crate) done: bool,
}

impl http_body::Body for DirectReadBody {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if let Some(settlement) = &mut self.settlement {
            return match settlement.as_mut().poll(cx) {
                std::task::Poll::Ready(Ok(())) => {
                    self.settlement = None;
                    self.reservation_owned = false;
                    self.done = true;
                    std::task::Poll::Ready(None)
                }
                std::task::Poll::Ready(Err(_)) => {
                    self.settlement = None;
                    self.done = true;
                    std::task::Poll::Ready(Some(Err(std::io::Error::other(
                        "direct transformed-read usage settlement failed",
                    ))))
                }
                std::task::Poll::Pending => std::task::Poll::Pending,
            };
        }
        if let Some(bytes) = self.first.take() {
            self.disclosed = true;
            return std::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes))));
        }
        match self.receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(DirectReadEvent::Data(bytes))) => {
                self.disclosed = true;
                std::task::Poll::Ready(Some(Ok(http_body::Frame::data(bytes))))
            }
            std::task::Poll::Ready(Some(DirectReadEvent::Failed(error))) => {
                self.done = true;
                let control = self.control.clone();
                let context = self.context.clone();
                let operation = self.failure_operation;
                let bucket = self.failure_bucket.clone();
                let resolution = self.failure_resolution.clone();
                let error_code = match &error {
                    TransformedReadError::Pipeline(error) => error.code(),
                    _ => maskura_error::codes::INTERNAL,
                };
                tokio::spawn(async move {
                    record_failed_pipeline_attempt(
                        control.as_ref(),
                        &context,
                        operation.operation_id,
                        &bucket,
                        crate::pipeline::PipelineDirection::Read,
                        Some(&resolution),
                        error_code,
                        0,
                    )
                    .await;
                });
                if !self.disclosed {
                    let control = self.control.clone();
                    let context = self.context.clone();
                    let operation_id = self.grant.operation_id();
                    tokio::spawn(async move {
                        let _ = control.release(&context, operation_id).await;
                    });
                    self.reservation_owned = false;
                }
                std::task::Poll::Ready(Some(Err(std::io::Error::other(
                    "direct transformed-read pipeline failed",
                ))))
            }
            std::task::Poll::Ready(Some(DirectReadEvent::Done {
                source_bytes,
                output_bytes,
                evidence,
            })) => {
                if source_bytes.max(output_bytes) > self.grant.max_processed_bytes() {
                    self.done = true;
                    return std::task::Poll::Ready(Some(Err(std::io::Error::other(
                        "direct transformed-read exceeded its authorized size",
                    ))));
                }
                let event = UsageEvent::from_grant(&self.grant, source_bytes, output_bytes);
                let event = match evidence {
                    Some(evidence) => event.with_pipeline_evidence(evidence),
                    None => event,
                };
                self.settlement = Some(direct_settlement_future(
                    self.control.clone(),
                    self.context.clone(),
                    event,
                ));
                self.poll_frame(cx)
            }
            std::task::Poll::Ready(None) => {
                self.done = true;
                self.source_cancellation.cancel();
                self.pipeline_cancellation.cancel();
                std::task::Poll::Ready(Some(Err(std::io::Error::other(
                    "transformed read worker terminated unexpectedly",
                ))))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl Drop for DirectReadBody {
    fn drop(&mut self) {
        if !self.done {
            self.source_cancellation.cancel();
            self.pipeline_cancellation.cancel();
            if self.reservation_owned && !self.disclosed {
                let control = self.control.clone();
                let context = self.context.clone();
                let operation_id = self.grant.operation_id();
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn(async move {
                        let _ = control.release(&context, operation_id).await;
                    });
                }
                self.reservation_owned = false;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn transformed_read_response(
    state: &AppState,
    auth: &Auth,
    operation: OperationIdentity,
    grant: &AuthorizationGrant,
    resolution: &crate::pipeline::PipelineResolution,
    headers: &HeaderMap,
    snapshot: PipelineSnapshot,
    preflight: (Format, String),
    response_metadata: ObjectMetadata,
    object: OpenedObject,
    key: &str,
    pipeline_evidence: &mut Option<crate::control::PipelineEvidence>,
) -> (axum::response::Response, Option<u64>, bool) {
    let (format, content_type) = preflight;
    *pipeline_evidence = None;
    let pipeline_started = std::time::Instant::now();
    let source_cancellation = object.cancellation.clone();
    let source_counters = object.counters.clone();
    let pipeline_cancellation = trusted_wasm_cancellation();
    let pipeline = match snapshot
        .clone()
        .start_streaming_session(
            transformed_session(auth, headers, format, content_type),
            pipeline_cancellation.clone(),
        )
        .await
    {
        Ok(pipeline) => pipeline,
        Err(error) => {
            return (
                transformed_read_error_response(key, error.into()),
                None,
                false,
            );
        }
    };
    let direct = snapshot
        .capabilities()
        .iter()
        .all(|capabilities| capabilities.prefix_safe_for_read);
    if direct {
        let max_source_frame_bytes = state.source_body_limits.max_frame_bytes;
        let output_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let worker_output_bytes = output_bytes.clone();
        let worker_source_counters = source_counters.clone();
        let worker_snapshot = snapshot.clone();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            let result = process_transformed_source(
                object,
                pipeline,
                format,
                max_source_frame_bytes,
                |bytes| {
                    let sender = sender.clone();
                    let output_bytes = worker_output_bytes.clone();
                    async move {
                        output_bytes
                            .fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
                        sender
                            .send(DirectReadEvent::Data(bytes))
                            .await
                            .map_err(|_| {
                                TransformedReadError::Source(
                                    "client cancelled transformed read".to_string(),
                                )
                            })
                    }
                },
            )
            .await;
            let event = match result {
                Ok(fuel_consumed) => DirectReadEvent::Done {
                    source_bytes: worker_source_counters.bytes(),
                    output_bytes: worker_output_bytes.load(std::sync::atomic::Ordering::Relaxed),
                    evidence: worker_snapshot.pipeline_evidence(
                        fuel_consumed,
                        pipeline_started.elapsed().as_millis() as u64,
                        "none",
                    ),
                },
                Err(error) => DirectReadEvent::Failed(error),
            };
            let _ = sender.send(event).await;
        });
        let first_event = receiver.recv().await;
        if let Some(DirectReadEvent::Failed(error)) = first_event {
            return (transformed_read_error_response(key, error), None, false);
        }
        if first_event.is_none() {
            source_cancellation.cancel();
            pipeline_cancellation.cancel();
            return (
                transformed_read_error_response(
                    key,
                    TransformedReadError::Pipeline(maskura_error::MaskuraError::new(
                        maskura_error::codes::INTERNAL,
                        "transformed read worker terminated unexpectedly",
                    )),
                ),
                None,
                false,
            );
        }
        let (first, content_length, settlement) = match first_event {
            Some(DirectReadEvent::Data(bytes)) => (Some(bytes), None, None),
            Some(DirectReadEvent::Done {
                source_bytes,
                output_bytes,
                evidence,
            }) => {
                let event = UsageEvent::from_grant(grant, source_bytes, output_bytes);
                let event = match evidence {
                    Some(evidence) => event.with_pipeline_evidence(evidence),
                    None => event,
                };
                (
                    None,
                    Some(output_bytes),
                    Some(direct_settlement_future(
                        state.control.clone(),
                        auth.context.clone(),
                        event,
                    )),
                )
            }
            Some(DirectReadEvent::Failed(_)) | None => unreachable!("handled above"),
        };
        let mut response = axum::response::Response::builder().status(StatusCode::OK);
        response
            .headers_mut()
            .unwrap()
            .extend(transformed_response_headers(
                &response_metadata,
                content_length,
            ));
        return (
            response
                .body(axum::body::Body::new(DirectReadBody {
                    first,
                    receiver,
                    source_cancellation,
                    pipeline_cancellation,
                    control: state.control.clone(),
                    context: auth.context.clone(),
                    grant: grant.clone(),
                    failure_operation: operation,
                    failure_bucket: grant.bucket().to_string(),
                    failure_resolution: resolution.clone(),
                    settlement,
                    disclosed: false,
                    reservation_owned: true,
                    done: false,
                }))
                .unwrap(),
            None,
            true,
        );
    }
    if !state.transformed_read_spool_enabled {
        source_cancellation.cancel();
        return (
            transformed_read_error_response(
                key,
                TransformedReadError::Capacity(
                    "unsafe transformed reads require MASKURA_TRANSFORMED_READ_SPOOL=encrypted"
                        .to_string(),
                ),
            ),
            None,
            false,
        );
    }
    let spool = match EncryptedReadSpool::begin(
        state.spool_config.directory.clone(),
        state.spool_config.max_object_bytes,
        Arc::clone(&state.spool_quota),
    )
    .await
    {
        Ok(spool) => spool,
        Err(error) => {
            return (
                transformed_read_error_response(key, error.into()),
                None,
                false,
            );
        }
    };
    let (spool_sender, mut spool_receiver) = tokio::sync::mpsc::channel(2);
    let spool_writer = tokio::spawn(async move {
        let mut spool = spool;
        while let Some(bytes) = spool_receiver.recv().await {
            if let Err(error) = spool.write(bytes).await {
                spool.abort().await;
                return Err(TransformedReadError::from(error));
            }
        }
        Ok(spool)
    });
    let output_sender = spool_sender.clone();
    let result = process_transformed_source(
        object,
        pipeline,
        format,
        state.source_body_limits.max_frame_bytes,
        move |bytes| {
            let sender = output_sender.clone();
            async move {
                sender.send(bytes).await.map_err(|_| {
                    TransformedReadError::Capacity(
                        "encrypted transformed-read staging failed".to_string(),
                    )
                })
            }
        },
    )
    .await;
    drop(spool_sender);
    let pipeline_fuel = match result {
        Ok(fuel) => fuel,
        Err(error) => {
            let _ = spool_writer.await;
            return (transformed_read_error_response(key, error), None, false);
        }
    };
    let spool = match spool_writer.await {
        Ok(Ok(spool)) => spool,
        Ok(Err(error)) => return (transformed_read_error_response(key, error), None, false),
        Err(error) => {
            return (
                transformed_read_error_response(
                    key,
                    TransformedReadError::Capacity(format!(
                        "encrypted transformed-read staging task failed: {error}"
                    )),
                ),
                None,
                false,
            );
        }
    };
    *pipeline_evidence = snapshot.pipeline_evidence(
        pipeline_fuel,
        pipeline_started.elapsed().as_millis() as u64,
        "encrypted",
    );
    let (body, content_length) = match spool.into_body(source_cancellation).await {
        Ok(result) => result,
        Err(error) => {
            return (
                transformed_read_error_response(key, error.into()),
                None,
                false,
            );
        }
    };
    let mut response = axum::response::Response::builder().status(StatusCode::OK);
    response
        .headers_mut()
        .unwrap()
        .extend(transformed_response_headers(
            &response_metadata,
            Some(content_length),
        ));
    (
        response.body(body).unwrap(),
        Some(source_counters.bytes()),
        false,
    )
}

pub(crate) async fn s3_get(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<S3Query>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response(&key, error),
    };
    if let Some(response) = client_metering_id_rejection(&headers, &key) {
        return response;
    }
    let transformed_read = wants_transformed_read(&headers);
    if params.upload_id.is_some() {
        let backend =
            match resolve_backend(&state, &auth, &headers, StorageOperation::Multipart).await {
                Ok(backend) => backend,
                Err(_) => return backend_resolution_error_response(&key),
            };
        let Some(staging) = staged_multipart(&state).cloned() else {
            return s3_error::multipart_not_supported(&key);
        };
        let identity = multipart_identity(
            &auth,
            &bucket,
            &key,
            params.upload_id.as_deref().unwrap_or_default(),
        );
        if let ResolvedBackend::Managed(storage) = &backend {
            let upload = match staging.repository.get_authorized(&identity).await {
                Ok(upload) => upload,
                Err(StagingError::NotFound) => return s3_error::no_such_upload(&key),
                Err(error) => return s3_error::internal_error(&key, &error.to_string()),
            };
            let Some(epoch) = upload.namespace_epoch else {
                return s3_error::service_unavailable(
                    &key,
                    "managed multipart upload has no namespace epoch",
                );
            };
            if storage
                .assert_managed_multipart(
                    &identity.upload_id,
                    auth.workspace_id().as_str(),
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
        let max_parts = match params.max_parts {
            Some(value) if !(1..=1000).contains(&value) => {
                return s3_error::invalid_argument(&key, "max-parts must be between 1 and 1000");
            }
            Some(value) => value as usize,
            None => 1000,
        };
        let part_number_marker = params.part_number_marker.unwrap_or(0);
        return match staging
            .repository
            .list_parts(&identity, part_number_marker, max_parts)
            .await
        {
            Ok((parts, truncated)) => s3_xml_ok(list_parts_xml(
                &bucket,
                &key,
                &identity.upload_id,
                part_number_marker,
                max_parts,
                &parts,
                truncated,
            )),
            Err(StagingError::NotFound) => s3_error::no_such_upload(&key),
            Err(error) => s3_error::internal_error(&key, &error.to_string()),
        };
    }
    let operation = request_operation_identity();
    let resolution_started = Instant::now();
    let resolution = if transformed_read {
        match state
            .gateway
            .resolve(
                auth.workspace_id().as_str(),
                &bucket,
                crate::pipeline::PipelineDirection::Read,
            )
            .await
        {
            Ok(resolution) => Some(resolution),
            Err(error) => {
                record_failed_pipeline_attempt(
                    state.control.as_ref(),
                    &auth.context,
                    operation.operation_id,
                    &bucket,
                    crate::pipeline::PipelineDirection::Read,
                    None,
                    error.code(),
                    resolution_started.elapsed().as_millis() as u64,
                )
                .await;
                return pipeline_error_response(&key, &error);
            }
        }
    } else {
        None
    };
    let authorization = match &resolution {
        Some(resolution) => operation.pipeline_authorization(
            &bucket,
            UsageRoute::GetObject,
            RequestKind::Read,
            object_max_processed_bytes(&state),
            resolution,
        ),
        None => operation.authorization(
            &bucket,
            UsageRoute::GetObject,
            RequestKind::Read,
            object_max_processed_bytes(&state),
        ),
    };
    let grant = match authorize_request(state.control.as_ref(), &auth.context, &authorization, &key)
        .await
    {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    let pipeline_snapshot = if let Some(resolution) = &resolution {
        match state.gateway.snapshot_for(resolution).await {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                record_failed_pipeline_attempt(
                    state.control.as_ref(),
                    &auth.context,
                    operation.operation_id,
                    &bucket,
                    crate::pipeline::PipelineDirection::Read,
                    Some(resolution),
                    error.code(),
                    resolution_started.elapsed().as_millis() as u64,
                )
                .await;
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    pipeline_error_response(&key, &error),
                )
                .await;
            }
        }
    } else {
        None
    };
    if transformed_read && state.streaming_read_mode != StreamingReadMode::Transformed {
        return release_failure(
            state.control.as_ref(),
            &auth.context,
            &grant,
            &key,
            s3_error::transformed_read_not_supported(&key),
        )
        .await;
    }
    let backend = match resolve_backend(&state, &auth, &headers, StorageOperation::Get).await {
        Ok(backend) => backend,
        Err(_) => {
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                backend_resolution_error_response(&key),
            )
            .await;
        }
    };
    // A transformed representation must be admitted from authoritative object
    // metadata before a source GET can start delivering bytes. Passthrough keeps
    // its existing one-request behavior below.
    if transformed_read {
        if matches!(&backend, ResolvedBackend::PresignedHttp(_)) {
            let response = transformed_read_error_response(
                &key,
                TransformedReadError::InvalidRequest(
                    "transformed reads require stored object metadata".to_string(),
                ),
            );
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                response,
            )
            .await;
        }
        let metadata = match open_backend_object(
            &state,
            backend.clone(),
            &auth,
            &bucket,
            &key,
            &headers,
            true,
        )
        .await
        {
            Ok(object) => object.metadata,
            Err(error) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    open_error_response(&key, error),
                )
                .await;
            }
        };
        if is_avro_content_type(&metadata.headers) {
            if let Some(error) = avro_read_preflight(&headers, &params, &metadata) {
                return transformed_read_error_response(&key, error);
            }
            if !state.binary_avro_enabled {
                return transformed_read_error_response(
                    &key,
                    TransformedReadError::InvalidRequest(
                        "Avro processing is disabled; set MASKURA_ENABLE_AVRO=true".to_string(),
                    ),
                );
            }
            let object =
                match open_backend_object(&state, backend, &auth, &bucket, &key, &headers, false)
                    .await
                {
                    Ok(object) => object,
                    Err(error) => return open_error_response(&key, error),
                };
            let source_bytes = content_length(&object.metadata.headers);
            let response_metadata = object.metadata.clone();
            let (response, completed_source_bytes) = avro_transformed_read_response(
                &state,
                &auth,
                &headers,
                response_metadata,
                object,
                &key,
            )
            .await;
            return metered_read_response(
                state.control.clone(),
                &auth,
                &grant,
                &key,
                source_bytes.or(completed_source_bytes),
                response,
                None,
            )
            .await;
        }
        let preflight = match transformed_read_preflight(&headers, &params, &metadata) {
            Ok(preflight) => preflight,
            Err(error) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    transformed_read_error_response(&key, error),
                )
                .await;
            }
        };
        let object =
            match open_backend_object(&state, backend, &auth, &bucket, &key, &headers, false).await
            {
                Ok(object) => object,
                Err(error) => {
                    return release_failure(
                        state.control.as_ref(),
                        &auth.context,
                        &grant,
                        &key,
                        open_error_response(&key, error),
                    )
                    .await;
                }
            };
        let source_preflight = match transformed_read_preflight(&headers, &params, &object.metadata)
        {
            Ok(preflight) => preflight,
            Err(error) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    transformed_read_error_response(&key, error),
                )
                .await;
            }
        };
        if source_preflight.0 != preflight.0
            || source_preflight.1 != preflight.1
            || !transformed_source_matches_preflight(&metadata, &object.metadata)
        {
            object.cancellation.cancel();
            let response = transformed_read_error_response(
                &key,
                TransformedReadError::Source(
                    "source metadata changed after transformed-read preflight".to_string(),
                ),
            );
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                response,
            )
            .await;
        }
        if let Some(status) = conditional_read_status(&headers, &object.metadata) {
            let response = conditional_read_response(object, status);
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                response,
            )
            .await;
        }
        let source_bytes = content_length(&object.metadata.headers);
        let response_metadata = object.metadata.clone();
        let mut pipeline_evidence = None;
        let (response, completed_source_bytes, direct) = transformed_read_response(
            &state,
            &auth,
            operation,
            &grant,
            resolution
                .as_ref()
                .expect("transformed reads resolve an immutable pipeline"),
            &headers,
            pipeline_snapshot.expect("transformed reads resolve a pipeline snapshot"),
            preflight,
            response_metadata,
            object,
            &key,
            &mut pipeline_evidence,
        )
        .await;
        if direct {
            return response;
        }
        if !response.status().is_success() {
            record_failed_pipeline_attempt(
                state.control.as_ref(),
                &auth.context,
                operation.operation_id,
                &bucket,
                crate::pipeline::PipelineDirection::Read,
                resolution.as_ref(),
                maskura_error::codes::INTERNAL,
                resolution_started.elapsed().as_millis() as u64,
            )
            .await;
        }
        return metered_read_response(
            state.control.clone(),
            &auth,
            &grant,
            &key,
            source_bytes.or(completed_source_bytes),
            response,
            pipeline_evidence,
        )
        .await;
    }
    let object =
        match open_backend_object(&state, backend, &auth, &bucket, &key, &headers, false).await {
            Ok(object) => object,
            Err(error) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    open_error_response(&key, error),
                )
                .await;
            }
        };
    if let Some(status) = conditional_read_status(&headers, &object.metadata) {
        let response = conditional_read_response(object, status);
        return release_failure(
            state.control.as_ref(),
            &auth.context,
            &grant,
            &key,
            response,
        )
        .await;
    }

    if state.streaming_read_mode.streams_passthrough() {
        return metered_read_response(
            state.control.clone(),
            &auth,
            &grant,
            &key,
            None,
            object.into_response(),
            None,
        )
        .await;
    }

    // Legacy whole-object GET buffering was removed in Phase 12. With reads
    // administratively disabled, reject without collecting the object body;
    // dropping `object` cancels the source before any byte is buffered.
    release_failure(
        state.control.as_ref(),
        &auth.context,
        &grant,
        &key,
        s3_error::not_implemented(&key),
    )
    .await
}

pub(crate) async fn s3_head(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response(&key, error),
    };
    if let Some(response) = client_metering_id_rejection(&headers, &key) {
        return response;
    }
    let operation = request_operation_identity();
    let authorization =
        operation.authorization(&bucket, UsageRoute::HeadObject, RequestKind::Read, 0);
    let grant = match authorize_request(state.control.as_ref(), &auth.context, &authorization, &key)
        .await
    {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    if wants_transformed_read(&headers) {
        let response = s3_error::invalid_request(
            &key,
            "HEAD is not supported for transformed reads until transformed metadata is available",
        );
        return release_failure(
            state.control.as_ref(),
            &auth.context,
            &grant,
            &key,
            response,
        )
        .await;
    }

    let backend = match resolve_backend(&state, &auth, &headers, StorageOperation::Head).await {
        Ok(backend) => backend,
        Err(_) => {
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                backend_resolution_error_response(&key),
            )
            .await;
        }
    };
    match open_backend_object(&state, backend, &auth, &bucket, &key, &headers, true).await {
        Ok(object) => {
            if let Some(status) = conditional_read_status(&headers, &object.metadata) {
                let response = conditional_read_response(object, status);
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    response,
                )
                .await;
            }
            let Some(object_bytes) = content_length(&object.metadata.headers) else {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::service_unavailable(
                        &key,
                        "The object size is unavailable for HEAD accounting.",
                    ),
                )
                .await;
            };
            if object_bytes > state.source_body_limits.max_bytes {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::entity_too_large(&key),
                )
                .await;
            }
            let response = object.into_response();
            if !response.status().is_success() {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    response,
                )
                .await;
            }
            if let Err(response) = record_operation(
                state.control.clone(),
                &auth.context,
                OperationUsage {
                    grant: &grant,
                    source_bytes: 0,
                    output_bytes: 0,
                },
                &key,
            )
            .await
            {
                return response;
            }
            response
        }
        Err(error) => {
            release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                open_error_response(&key, error),
            )
            .await
        }
    }
}

pub(crate) async fn s3_delete(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<S3Query>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response(&key, error),
    };
    if let Some(response) = client_metering_id_rejection(&headers, &key) {
        return response;
    }
    let operation = request_operation_identity();
    let authorization = operation.authorization(
        &bucket,
        if params.upload_id.is_some() {
            UsageRoute::AbortMultipartUpload
        } else {
            UsageRoute::DeleteObject
        },
        RequestKind::Write,
        0,
    );
    let grant = match authorize_request(state.control.as_ref(), &auth.context, &authorization, &key)
        .await
    {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    info!(
        operation_id = %grant.operation_id(),
        receipt_id = %grant.receipt_id(),
        "DELETE authorized"
    );

    if params.upload_id.is_some() {
        let backend =
            match resolve_backend(&state, &auth, &headers, StorageOperation::Multipart).await {
                Ok(backend) => backend,
                Err(_) => {
                    return release_failure(
                        state.control.as_ref(),
                        &auth.context,
                        &grant,
                        &key,
                        backend_resolution_error_response(&key),
                    )
                    .await;
                }
            };
        let Some(staging) = staged_multipart(&state).cloned() else {
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                s3_error::multipart_not_supported(&key),
            )
            .await;
        };
        let upload_id = params.upload_id.as_deref().unwrap_or_default();
        let identity = multipart_identity(&auth, &bucket, &key, upload_id);
        let upload = match staging.repository.get_authorized(&identity).await {
            Ok(upload) => upload,
            Err(StagingError::NotFound) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::no_such_upload(&key),
                )
                .await;
            }
            Err(error) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::internal_error(&key, &error.to_string()),
                )
                .await;
            }
        };
        if let ResolvedBackend::Managed(storage) = &backend {
            let Some(epoch) = upload.namespace_epoch else {
                let response = s3_error::service_unavailable(
                    &key,
                    "managed multipart upload has no namespace epoch",
                );
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    response,
                )
                .await;
            };
            if storage
                .assert_managed_multipart(upload_id, auth.workspace_id().as_str(), epoch, true)
                .await
                .is_err()
            {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::service_unavailable(
                        &key,
                        "managed multipart storage is temporarily unavailable",
                    ),
                )
                .await;
            }
        }
        return match staging.repository.abort(&identity, now_ms()).await {
            Ok(parts) => {
                cleanup_staged_parts(&staging, upload_id, parts, "abort").await;
                if let Err(response) = record_operation(
                    state.control.clone(),
                    &auth.context,
                    OperationUsage {
                        grant: &grant,
                        source_bytes: 0,
                        output_bytes: 0,
                    },
                    &key,
                )
                .await
                {
                    return response;
                }
                StatusCode::NO_CONTENT.into_response()
            }
            Err(AbortMutationError::PreMutation(StagingError::NotFound)) => {
                release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::no_such_upload(&key),
                )
                .await
            }
            Err(AbortMutationError::PreMutation(StagingError::NotOpen)) => {
                if let Err(response) = record_operation(
                    state.control.clone(),
                    &auth.context,
                    OperationUsage {
                        grant: &grant,
                        source_bytes: 0,
                        output_bytes: 0,
                    },
                    &key,
                )
                .await
                {
                    return response;
                }
                StatusCode::NO_CONTENT.into_response()
            }
            Err(AbortMutationError::PreMutation(error)) => {
                release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::internal_error(&key, &error.to_string()),
                )
                .await
            }
            Err(AbortMutationError::MutationUnknown(error)) => {
                s3_error::internal_error(&key, &error.to_string())
            }
        };
    }

    let backend = match resolve_backend(&state, &auth, &headers, StorageOperation::Delete).await {
        Ok(backend) => backend,
        Err(_) => {
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &key,
                backend_resolution_error_response(&key),
            )
            .await;
        }
    };
    match backend {
        ResolvedBackend::PresignedHttp(url) => {
            let client = match state
                .presigned_http_policy
                .client_for_destination(&url, Duration::from_secs(30))
                .await
            {
                Ok(client) => client,
                Err(error) => {
                    return release_failure(
                        state.control.as_ref(),
                        &auth.context,
                        &grant,
                        &key,
                        open_error_response(&key, OpenObjectError::Rejected(error)),
                    )
                    .await;
                }
            };
            match client.delete(url).send().await {
                Ok(response) if response.status().is_success() => {
                    if let Err(response) = record_operation(
                        state.control.clone(),
                        &auth.context,
                        OperationUsage {
                            grant: &grant,
                            source_bytes: 0,
                            output_bytes: 0,
                        },
                        &key,
                    )
                    .await
                    {
                        return response;
                    }
                    StatusCode::NO_CONTENT.into_response()
                }
                Ok(response) => s3_error::internal_error(
                    &key,
                    &format!("presigned DELETE returned {}", response.status()),
                ),
                Err(error) => {
                    let failure = PresignedTransportFailure::from_reqwest(&error);
                    warn!(
                        category = failure.as_str(),
                        "presigned DELETE transport failed"
                    );
                    s3_error::internal_error(&key, "presigned backend request failed")
                }
            }
        }
        ResolvedBackend::S3 { client, .. } => match client
            .delete_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(_) => {
                if let Err(response) = record_operation(
                    state.control.clone(),
                    &auth.context,
                    OperationUsage {
                        grant: &grant,
                        source_bytes: 0,
                        output_bytes: 0,
                    },
                    &key,
                )
                .await
                {
                    return response;
                }
                StatusCode::NO_CONTENT.into_response()
            }
            Err(error) => {
                let failure = record_s3_failure("delete_object", &error);
                s3_error::internal_error(&key, failure.client_message())
            }
        },
        ResolvedBackend::Managed(storage) => {
            if storage.managed_mode() == ManagedStreamingMode::Observe {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::service_unavailable(
                        &key,
                        "managed mutations are disabled in observe mode",
                    ),
                )
                .await;
            }
            let result = match storage.managed_mode() {
                ManagedStreamingMode::Off => storage
                    .delete(&format!("{}/{bucket}/{key}", auth.workspace_id().as_str()))
                    .await
                    .map_err(|error| {
                        crate::managed::ManagedDeleteError::PreCommit(
                            crate::managed::ManagedError::Persistence(error.to_string()),
                        )
                    }),
                ManagedStreamingMode::Observe => unreachable!("handled above"),
                ManagedStreamingMode::Enforce => {
                    storage
                        .delete_authoritative(
                            &managed_logical_key(&auth, &bucket, &key),
                            grant.operation_id(),
                            grant.receipt_id(),
                            grant.occurred_at().timestamp_micros(),
                            grant.rate_version(),
                            grant.max_processed_bytes(),
                        )
                        .await
                }
            };
            if let Err(error) = result {
                return managed_delete_failure_response(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    error,
                )
                .await;
            }
            if let Err(response) = record_operation(
                state.control.clone(),
                &auth.context,
                OperationUsage {
                    grant: &grant,
                    source_bytes: 0,
                    output_bytes: 0,
                },
                &key,
            )
            .await
            {
                return response;
            }
            if storage.managed_mode() == ManagedStreamingMode::Enforce
                && let Err(_) = storage
                    .mark_authoritative_delete_settled(grant.operation_id(), grant.receipt_id())
                    .await
            {
                warn!(
                    operation_id = %grant.operation_id(),
                    error_category = "persistence",
                    "durable managed DELETE settlement remains pending"
                );
            }
            StatusCode::NO_CONTENT.into_response()
        }
        ResolvedBackend::File(store) => {
            if let Err(error) = store.delete(&bucket, &key).await {
                return s3_error::internal_error(&key, &error.to_string());
            }
            if let Err(response) = record_operation(
                state.control.clone(),
                &auth.context,
                OperationUsage {
                    grant: &grant,
                    source_bytes: 0,
                    output_bytes: 0,
                },
                &key,
            )
            .await
            {
                return response;
            }
            StatusCode::NO_CONTENT.into_response()
        }
        ResolvedBackend::Memory(store) => {
            store.delete(&bucket, &key);
            if let Err(response) = record_operation(
                state.control.clone(),
                &auth.context,
                OperationUsage {
                    grant: &grant,
                    source_bytes: 0,
                    output_bytes: 0,
                },
                &key,
            )
            .await
            {
                return response;
            }
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

pub(crate) async fn s3_post(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<S3Query>,
    request: Request,
) -> impl IntoResponse {
    let (parts, body) = request.into_parts();
    if let Some(upload_id) = params.upload_id.as_deref() {
        let authentication = match authenticate_headers(
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
        let identity = multipart_identity(&authentication.auth, &bucket, &key, upload_id);
        let mut upload = match staging.repository.get_authorized(&identity).await {
            Ok(upload) => upload,
            Err(StagingError::NotFound) => return s3_error::no_such_upload(&key),
            Err(error) => return s3_error::internal_error(&key, &error.to_string()),
        };
        let persisted_resolution = match restore_multipart_pipeline(
            &upload.snapshot.plugin_snapshot,
        ) {
            Ok(resolution) => resolution,
            Err(MultipartPipelineRestoreError::LegacyRawSnapshot) => {
                return s3_error::invalid_request(
                    &key,
                    "Legacy multipart pipeline snapshots cannot be resumed safely; abort and restart the upload.",
                );
            }
            Err(MultipartPipelineRestoreError::Invalid(error)) => {
                return pipeline_error_response(&key, &error);
            }
        };
        let backend = match resolve_backend(
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
        if let Err(error) = validate_streaming_backend(&state, &backend) {
            return streaming_put_error_response(&key, error);
        }
        let (auth, body) =
            match read_verified_body(authentication, body, MAX_COMPLETE_XML_BYTES).await {
                Ok(value) => value,
                Err(VerifiedBodyError::TooLarge) => {
                    return s3_error::invalid_request(
                        &key,
                        "CompleteMultipartUpload XML exceeds 1 MiB",
                    );
                }
                Err(VerifiedBodyError::Integrity(error)) => {
                    return s3_error::bad_digest(&key, &error.to_string());
                }
                Err(VerifiedBodyError::Transport) => {
                    return s3_error::invalid_request(
                        &key,
                        "CompleteMultipartUpload request body failed",
                    );
                }
            };
        let selected = match parse_complete_multipart_xml(&body) {
            Ok(parts) => parts,
            Err(error) if error.contains("sorted") => {
                return s3_error::invalid_part_order(&key);
            }
            Err(error) if error.contains("exceeds") => {
                return s3_error::invalid_request(&key, &error);
            }
            Err(error) => return s3_error::malformed_xml(&key, &error),
        };
        match staged_completion_sizes(staging.repository.as_ref(), &identity, &selected).await {
            Ok(Some(matched)) => {
                if let Err(error) = validate_completion_part_sizes(&matched) {
                    return match error {
                        CompletionPartSizeError::NonFinalTooSmall {
                            part_number,
                            size_bytes,
                        } => s3_error::entity_too_small(
                            &key,
                            &format!(
                                "part {part_number} is {size_bytes} bytes; every non-final part must be at least 5 MiB"
                            ),
                        ),
                        CompletionPartSizeError::AssembledTooLarge(_) => {
                            s3_error::entity_too_large(&key)
                        }
                    };
                }
            }
            Ok(None) => {}
            Err(StagingError::NotFound) => return s3_error::no_such_upload(&key),
            Err(error) => return s3_error::internal_error(&key, &error.to_string()),
        }
        if let ResolvedBackend::Managed(storage) = &backend {
            let Some(epoch) = upload.namespace_epoch else {
                let response = s3_error::service_unavailable(
                    &key,
                    "managed multipart upload has no namespace epoch",
                );
                return response;
            };
            if storage
                .assert_managed_multipart(upload_id, auth.workspace_id().as_str(), epoch, false)
                .await
                .is_err()
            {
                return s3_error::service_unavailable(
                    &key,
                    "managed multipart storage is temporarily unavailable",
                );
            }
        }
        let fingerprint = match completion_fingerprint(&upload, &selected) {
            Ok(fingerprint) => fingerprint,
            Err(error) => {
                return s3_error::internal_error(&key, &error.to_string());
            }
        };
        // Exact retries share an operation; conflicting canonical requests do not.
        let operation = multipart_completion_operation_identity(upload_id, &fingerprint);
        let authorization = operation.pipeline_authorization(
            &bucket,
            UsageRoute::CompleteMultipartUpload,
            RequestKind::Write,
            object_max_processed_bytes(&state),
            &persisted_resolution,
        );
        let grant =
            match authorize_request(state.control.as_ref(), &auth.context, &authorization, &key)
                .await
            {
                Ok(grant) => grant,
                Err(response) => return response,
            };
        let lease = match staging
            .repository
            .acquire_completion(
                &identity,
                &fingerprint,
                &selected,
                &format!("complete-{}", Uuid::now_v7()),
                now_ms() + COMPLETION_LEASE.as_millis() as i64,
                now_ms(),
            )
            .await
        {
            Ok(CompletionAcquire::Replayed(result)) => {
                if let Err(response) = record_durable_operation_with_event(
                    state.operation_journal.as_ref(),
                    state.control.clone(),
                    &auth.context,
                    multipart_completion_event(&grant, &result),
                    &key,
                )
                .await
                {
                    return response;
                }
                let mut response = s3_xml_ok(complete_multipart_xml(&bucket, &key, &result));
                if let Some(version) = result.version_id
                    && let Ok(version) = version.parse()
                {
                    response.headers_mut().insert("x-amz-version-id", version);
                }
                return response;
            }
            Ok(CompletionAcquire::Busy) => {
                // This exact operation may still be committing in another worker.
                return s3_error::slow_down(&key);
            }
            Ok(CompletionAcquire::Acquired(lease)) => {
                // Acquisition persisted the completion fingerprint, fencing
                // token, and lease into the durable upload; refresh the local
                // snapshot so completion uses the exact acquired state.
                upload = match staging.repository.get_authorized(&identity).await {
                    Ok(upload) => upload,
                    Err(StagingError::NotFound) => return s3_error::no_such_upload(&key),
                    Err(error) => return s3_error::internal_error(&key, &error.to_string()),
                };
                lease
            }
            Err(StagingError::InvalidPart) => {
                let response = s3_error::invalid_part(
                    &key,
                    "submitted part is missing or does not match its staged ETag/checksum",
                );
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    response,
                )
                .await;
            }
            Err(StagingError::CompletionConflict) => {
                let response =
                    s3_error::invalid_request(&key, "conflicting CompleteMultipartUpload request");
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    response,
                )
                .await;
            }
            Err(StagingError::NotFound | StagingError::NotOpen) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::no_such_upload(&key),
                )
                .await;
            }
            Err(error) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::internal_error(&key, &error.to_string()),
                )
                .await;
            }
        };
        let destination_operation_id =
            crate::multipart_staging::DestinationCommitPermit::deterministic_operation_id(
                &identity,
                &fingerprint,
            );
        let recovered = match reconcile_existing_direct_completion(
            &state,
            &backend,
            destination_operation_id,
            auth.workspace_id().as_str(),
            &bucket,
            &key,
        )
        .await
        {
            Ok(ExistingDirectCompletion::New) => None,
            Ok(ExistingDirectCompletion::Committed(operation)) => Some(*operation),
            Ok(ExistingDirectCompletion::ProvenAborted) => {
                return release_failure(
                    state.control.as_ref(),
                    &auth.context,
                    &grant,
                    &key,
                    s3_error::service_unavailable(
                        &key,
                        "The previous multipart completion attempt was proven aborted.",
                    ),
                )
                .await;
            }
            Ok(ExistingDirectCompletion::Pending) | Err(_) => {
                return s3_error::service_unavailable(
                    &key,
                    "The previous multipart completion outcome is still being reconciled.",
                );
            }
            Ok(ExistingDirectCompletion::Conflict) => {
                return s3_error::invalid_request(
                    &key,
                    "The multipart completion backend or routing identity changed.",
                );
            }
        };
        let result = if let Some(recovered_operation) = recovered {
            let result = match recovered_multipart_result(
                state.operation_journal.as_ref(),
                recovered_operation,
                &lease,
                operation.receipt_id,
            )
            .await
            {
                Ok(result) => result,
                Err(error) => return multipart_completion_error_response(&key, error),
            };
            let fingerprint = upload
                .complete_request_fingerprint
                .as_deref()
                .unwrap_or(&fingerprint);
            let coordinator = match multipart_completion_coordinator(&state, &staging) {
                Ok(coordinator) => coordinator,
                Err(error) => return multipart_completion_error_response(&key, error),
            };
            if let Err(error) = coordinator
                .complete_recovered_journal_result(
                    &identity,
                    fingerprint,
                    lease.fencing_token,
                    result.clone(),
                )
                .await
            {
                return multipart_completion_error_response(
                    &key,
                    MultipartCompletionError::from(error),
                );
            }
            result
        } else {
            let complete = tokio::time::timeout(
                Duration::from_secs(MAX_MULTIPART_COMPLETION_SECS),
                complete_staged_multipart(
                    &state,
                    &staging,
                    &identity,
                    &upload,
                    &lease,
                    AuthorizedOperation {
                        auth: &auth,
                        grant: &grant,
                    },
                    backend,
                    &persisted_resolution,
                ),
            )
            .await;
            match complete {
                Ok(Ok(result)) => result,
                Ok(Err(error)) => {
                    return multipart_completion_failure_response(
                        state.control.as_ref(),
                        &auth.context,
                        &grant,
                        &key,
                        error,
                    )
                    .await;
                }
                Err(_) => {
                    return s3_error::service_unavailable(
                        &key,
                        "multipart completion exceeded the configured hosted time limit",
                    );
                }
            }
        };
        cleanup_staged_parts(&staging, upload_id, lease.cleanup_parts, "complete").await;
        if let Err(response) = record_durable_operation_with_event(
            state.operation_journal.as_ref(),
            state.control.clone(),
            &auth.context,
            multipart_completion_event(&grant, &result),
            &key,
        )
        .await
        {
            return response;
        }
        let mut response = s3_xml_ok(complete_multipart_xml(&bucket, &key, &result));
        if let Some(version) = result.version_id
            && let Ok(version) = version.parse()
        {
            response.headers_mut().insert("x-amz-version-id", version);
        }
        return response;
    }
    let auth = match authenticate(
        parts.method.as_str(),
        &parts.uri,
        &parts.headers,
        &[],
        &state.keys,
        &state,
    )
    .await
    {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response(&key, error),
    };
    if let Some(response) = client_metering_id_rejection(&parts.headers, &key) {
        return response;
    }
    if params.uploads.is_some() {
        let resolution_started = Instant::now();
        let resolution = match state
            .gateway
            .resolve(
                auth.workspace_id().as_str(),
                &bucket,
                crate::pipeline::PipelineDirection::Write,
            )
            .await
        {
            Ok(resolution) => resolution,
            Err(error) => {
                let operation = request_operation_identity();
                record_failed_pipeline_attempt(
                    state.control.as_ref(),
                    &auth.context,
                    operation.operation_id,
                    &bucket,
                    crate::pipeline::PipelineDirection::Write,
                    None,
                    error.code(),
                    resolution_started.elapsed().as_millis() as u64,
                )
                .await;
                return pipeline_error_response(&key, &error);
            }
        };
        let backend =
            match resolve_backend(&state, &auth, &parts.headers, StorageOperation::Multipart).await
            {
                Ok(backend) => backend,
                Err(_) => return backend_resolution_error_response(&key),
            };
        if let Err(error) = validate_streaming_backend(&state, &backend) {
            return streaming_put_error_response(&key, error);
        }
        if let Some(response) = require_file_bucket(&backend, &bucket).await {
            return response;
        }
        if let ResolvedBackend::Managed(storage) = &backend
            && storage
                .assert_namespace_active(auth.workspace_id().as_str())
                .await
                .is_err()
        {
            return s3_error::service_unavailable(
                &key,
                "managed namespace is temporarily unavailable",
            );
        }
        let Some(staging) = staged_multipart(&state).cloned() else {
            return s3_error::multipart_not_supported(&key);
        };
        // Freeze and serialize policy before creating managed multipart state.
        // Resolver or serialization failures therefore cannot orphan a managed
        // registration without a corresponding staging upload.
        let plugin_snapshot = match serde_json::to_value(&resolution) {
            Ok(snapshot) => snapshot,
            Err(error) => return s3_error::internal_error(&key, &error.to_string()),
        };
        let upload_id = Uuid::now_v7().to_string();
        let managed_registration = if let ResolvedBackend::Managed(storage) = &backend {
            match storage
                .begin_managed_multipart(&upload_id, auth.workspace_id().as_str())
                .await
            {
                Ok(epoch) => Some((storage.clone(), epoch)),
                Err(_) => {
                    return s3_error::service_unavailable(
                        &key,
                        "managed multipart storage is temporarily unavailable",
                    );
                }
            }
        } else {
            None
        };
        let now = now_ms();
        let upload = MultipartUpload {
            identity: multipart_identity(&auth, &bucket, &key, &upload_id),
            namespace_epoch: managed_registration.as_ref().map(|(_, epoch)| *epoch),
            snapshot: multipart_snapshot(
                &parts.headers,
                &backend,
                plugin_snapshot,
                state.source_body_limits.max_bytes,
            ),
            lifecycle: MultipartLifecycle::Open,
            staged_bytes: 0,
            reserved_bytes: 0,
            created_at_ms: now,
            expires_at_ms: now + 24 * 60 * 60 * 1000,
            updated_at_ms: now,
            tombstone_until_ms: None,
            complete_request_fingerprint: None,
            completion_lease_owner: None,
            completion_lease_expires_at_ms: None,
            completion_fencing_token: 0,
            destination_operation_id: None,
            publishing_started_at_ms: None,
            destination_commit: None,
            completion_result: None,
        };
        if let Err(detail) = validate_multipart_checksum_mode(&upload.snapshot) {
            return s3_error::invalid_argument(&key, detail);
        }
        return match staging.repository.create(upload).await {
            Ok(()) => {
                if let Some((storage, epoch)) = &managed_registration
                    && let Err(_) = storage
                        .confirm_managed_multipart(&upload_id, auth.workspace_id().as_str(), *epoch)
                        .await
                {
                    let identity = multipart_identity(&auth, &bucket, &key, &upload_id);
                    let _ = staging.repository.abort(&identity, now_ms()).await;
                    let _ = staging.repository.delete_terminal_upload(&identity).await;
                    let _ = storage
                        .finish_managed_multipart(&upload_id, auth.workspace_id().as_str(), *epoch)
                        .await;
                    return s3_error::service_unavailable(
                        &key,
                        "managed multipart storage is temporarily unavailable",
                    );
                }
                s3_xml_ok(create_multipart_xml(&bucket, &key, &upload_id))
            }
            Err(error) => {
                if let Some((storage, epoch)) = managed_registration {
                    let _ = storage
                        .finish_managed_multipart(&upload_id, auth.workspace_id().as_str(), epoch)
                        .await;
                }
                match error {
                    StagingError::QuotaExceeded => s3_error::slow_down(&key),
                    error => s3_error::internal_error(&key, &error.to_string()),
                }
            }
        };
    }
    s3_error::not_implemented(&key)
}

/// ListObjectsV2/ListObjectsV1 — `GET /{bucket}`.
pub(crate) async fn s3_list_objects(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(params): Query<S3Query>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response(&bucket, error),
    };
    if let Some(response) = client_metering_id_rejection(&headers, &bucket) {
        return response;
    }
    let operation = request_operation_identity();
    let authorization =
        operation.authorization(&bucket, UsageRoute::ListObjects, RequestKind::Read, 0);
    let grant = match authorize_request(
        state.control.as_ref(),
        &auth.context,
        &authorization,
        &bucket,
    )
    .await
    {
        Ok(grant) => grant,
        Err(response) => return response,
    };
    if params.uploads.is_some() {
        let response = list_multipart_uploads_response(&state, &auth, &bucket, &params).await;
        if !response.status().is_success() {
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &bucket,
                response,
            )
            .await;
        }
        if let Err(response) = record_operation(
            state.control.clone(),
            &auth.context,
            OperationUsage {
                grant: &grant,
                source_bytes: 0,
                output_bytes: 0,
            },
            &bucket,
        )
        .await
        {
            return response;
        }
        return response;
    }
    let backend = match resolve_backend(&state, &auth, &headers, StorageOperation::List).await {
        Ok(backend) => backend,
        Err(_) => {
            return release_failure(
                state.control.as_ref(),
                &auth.context,
                &grant,
                &bucket,
                backend_resolution_error_response(&bucket),
            )
            .await;
        }
    };
    // A File-backed bucket is explicit: listing (and HEAD, which is served by
    // this same handler) a bucket that was never created must return
    // NoSuchBucket, not an empty 200.
    if let Some(response) = require_file_bucket(&backend, &bucket).await {
        return release_failure(
            state.control.as_ref(),
            &auth.context,
            &grant,
            &bucket,
            response,
        )
        .await;
    }
    let response = match backend {
        ResolvedBackend::S3 { client, .. } => match list_from_s3(&client, &bucket, &params).await {
            Ok(xml) => s3_xml_ok(xml),
            Err(failure) => s3_error::internal_error(&bucket, failure.client_message()),
        },
        ResolvedBackend::Memory(store) => {
            match list_from_memory(&store, &bucket, &params, &state.continuation_token_key) {
                Ok(xml) => s3_xml_ok(xml),
                Err(error) => s3_error::invalid_request(&bucket, &error),
            }
        }
        ResolvedBackend::File(store) => {
            match list_from_file(&store, &bucket, &params, &state.continuation_token_key).await {
                Ok(xml) => s3_xml_ok(xml),
                Err(error) => s3_error::invalid_request(&bucket, &error),
            }
        }
        ResolvedBackend::Managed(storage) => match list_from_managed(
            &storage,
            auth.workspace_id().as_str(),
            &bucket,
            &params,
            &state.continuation_token_key,
        )
        .await
        {
            Ok(xml) => s3_xml_ok(xml),
            Err(ManagedListError::InvalidRequest(error)) => {
                s3_error::invalid_request(&bucket, &error)
            }
            Err(ManagedListError::Unavailable) => {
                s3_error::service_unavailable(&bucket, "managed listing is temporarily unavailable")
            }
        },
        ResolvedBackend::PresignedHttp(url) => {
            match open_http_object(&state, url, &headers, false).await {
                Ok(object) => object.into_response(),
                Err(error) => open_error_response(&bucket, error),
            }
        }
    };
    if !response.status().is_success() {
        return release_failure(
            state.control.as_ref(),
            &auth.context,
            &grant,
            &bucket,
            response,
        )
        .await;
    }
    if let Err(response) = record_operation(
        state.control.clone(),
        &auth.context,
        OperationUsage {
            grant: &grant,
            source_bytes: 0,
            output_bytes: 0,
        },
        &bucket,
    )
    .await
    {
        return response;
    }
    response
}

/// Forward a ListObjectsV2 request to an S3 backend.
pub(crate) async fn list_from_s3(
    s3: &Client,
    bucket: &str,
    params: &S3Query,
) -> Result<String, S3Failure> {
    if params.list_type.as_deref() != Some("2") {
        return list_from_s3_v1(s3, bucket, params).await;
    }
    let mut req = s3.list_objects_v2().bucket(bucket);
    if let Some(p) = params.prefix.as_deref() {
        req = req.prefix(p);
    }
    if let Some(d) = params.delimiter.as_deref() {
        req = req.delimiter(d);
    }
    if let Some(t) = params.continuation_token.as_deref() {
        req = req.continuation_token(t);
    }
    if let Some(s) = params.start_after.as_deref() {
        req = req.start_after(s);
    }
    if let Some(m) = params.max_keys {
        req = req.max_keys(m.min(1000) as i32);
    }
    let out = req
        .send()
        .await
        .map_err(|error| record_s3_failure("list_objects_v2", &error))?;

    let encoding = params.encoding_type.as_deref() == Some("url");
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    xml.push_str(&format!(
        "<Prefix>{}</Prefix>",
        xml_escape(params.prefix.as_deref().unwrap_or(""))
    ));
    if let Some(d) = params.delimiter.as_deref() {
        xml.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(d)));
    }
    xml.push_str(&format!(
        "<KeyCount>{}</KeyCount>",
        out.key_count().unwrap_or(0)
    ));
    xml.push_str(&format!(
        "<MaxKeys>{}</MaxKeys>",
        out.max_keys().unwrap_or(1000)
    ));
    xml.push_str(&format!(
        "<IsTruncated>{}</IsTruncated>",
        out.is_truncated().unwrap_or(false)
    ));
    if let Some(token) = out.continuation_token() {
        xml.push_str(&format!(
            "<ContinuationToken>{}</ContinuationToken>",
            xml_escape(token)
        ));
    }
    if let Some(token) = out.next_continuation_token() {
        xml.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            xml_escape(token)
        ));
    }
    if let Some(start) = params.start_after.as_deref() {
        xml.push_str(&format!("<StartAfter>{}</StartAfter>", xml_escape(start)));
    }
    for c in out.contents().iter() {
        let k = c.key().unwrap_or_default();
        let display = if encoding {
            url_encode(k)
        } else {
            k.to_string()
        };
        let etag = c.e_tag().unwrap_or_default();
        let size = c.size().unwrap_or(0);
        let lm = c.last_modified().map(|d| d.to_string()).unwrap_or_default();
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>{lm}</LastModified><ETag>{}</ETag><Size>{size}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(&display),
            xml_escape(etag)
        ));
    }
    for cp in out.common_prefixes() {
        if let Some(p) = cp.prefix() {
            let display = if encoding {
                url_encode(p)
            } else {
                p.to_string()
            };
            xml.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                xml_escape(&display)
            ));
        }
    }
    xml.push_str("</ListBucketResult>");
    Ok(xml)
}

pub(crate) async fn list_from_s3_v1(
    s3: &Client,
    bucket: &str,
    params: &S3Query,
) -> Result<String, S3Failure> {
    let mut request = s3.list_objects().bucket(bucket);
    if let Some(prefix) = params.prefix.as_deref() {
        request = request.prefix(prefix);
    }
    if let Some(delimiter) = params.delimiter.as_deref() {
        request = request.delimiter(delimiter);
    }
    if let Some(marker) = params.marker.as_deref() {
        request = request.marker(marker);
    }
    if let Some(max_keys) = params.max_keys {
        request = request.max_keys(max_keys.min(1000) as i32);
    }
    let output = request
        .send()
        .await
        .map_err(|error| record_s3_failure("list_objects_v1", &error))?;
    let encoding = params.encoding_type.as_deref() == Some("url");
    let display = |value: &str| {
        if encoding {
            url_encode(value)
        } else {
            value.to_string()
        }
    };
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    xml.push_str(&format!(
        "<Prefix>{}</Prefix>",
        xml_escape(params.prefix.as_deref().unwrap_or(""))
    ));
    if let Some(delimiter) = params.delimiter.as_deref() {
        xml.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(delimiter)));
    }
    if let Some(marker) = params.marker.as_deref() {
        xml.push_str(&format!("<Marker>{}</Marker>", xml_escape(marker)));
    }
    xml.push_str(&format!(
        "<MaxKeys>{}</MaxKeys>",
        output.max_keys().unwrap_or(1000)
    ));
    xml.push_str(&format!(
        "<IsTruncated>{}</IsTruncated>",
        output.is_truncated().unwrap_or(false)
    ));
    if let Some(marker) = output.next_marker() {
        xml.push_str(&format!("<NextMarker>{}</NextMarker>", xml_escape(marker)));
    }
    for content in output.contents() {
        let key = content.key().unwrap_or_default();
        let last_modified = content
            .last_modified()
            .map(|value| value.to_string())
            .unwrap_or_default();
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>{last_modified}</LastModified><ETag>{}</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(&display(key)),
            xml_escape(content.e_tag().unwrap_or_default()),
            content.size().unwrap_or(0),
        ));
    }
    for common_prefix in output.common_prefixes() {
        if let Some(prefix) = common_prefix.prefix() {
            xml.push_str(&format!(
                "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                xml_escape(&display(prefix))
            ));
        }
    }
    xml.push_str("</ListBucketResult>");
    Ok(xml)
}

pub(crate) fn encode_memory_continuation(
    key: &[u8; 32],
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    last: &str,
) -> String {
    let payload = serde_json::to_vec(&(bucket, prefix, delimiter, last))
        .expect("continuation tuple is serializable");
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts fixed key");
    mac.update(&payload);
    let mut encoded = mac.finalize().into_bytes().to_vec();
    encoded.extend(payload);
    URL_SAFE_NO_PAD.encode(encoded)
}

pub(crate) fn decode_memory_continuation(
    key: &[u8; 32],
    token: &str,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
) -> Result<String, String> {
    let encoded = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| "invalid continuation token".to_string())?;
    if encoded.len() < 32 {
        return Err("invalid continuation token".to_string());
    }
    let (tag, payload) = encoded.split_at(32);
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts fixed key");
    mac.update(payload);
    mac.verify_slice(tag)
        .map_err(|_| "invalid continuation token".to_string())?;
    let (token_bucket, token_prefix, token_delimiter, last): (
        String,
        String,
        Option<String>,
        String,
    ) = serde_json::from_slice(payload).map_err(|_| "invalid continuation token".to_string())?;
    (token_bucket == bucket && token_prefix == prefix && token_delimiter.as_deref() == delimiter)
        .then_some(last)
        .ok_or_else(|| "continuation token does not match this listing".to_string())
}

#[derive(Debug)]
pub(crate) enum ManagedListError {
    InvalidRequest(String),
    Unavailable,
}

pub(crate) fn encode_managed_continuation(
    key: &[u8; 32],
    tenant_id: &str,
    bucket: &str,
    prefix: &str,
    last: &str,
) -> String {
    let payload = serde_json::to_vec(&(tenant_id, bucket, prefix, last))
        .expect("managed continuation tuple is serializable");
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts fixed key");
    mac.update(&payload);
    let mut encoded = mac.finalize().into_bytes().to_vec();
    encoded.extend(payload);
    URL_SAFE_NO_PAD.encode(encoded)
}

pub(crate) fn decode_managed_continuation(
    key: &[u8; 32],
    token: &str,
    tenant_id: &str,
    bucket: &str,
    prefix: &str,
) -> Result<String, ManagedListError> {
    let encoded = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ManagedListError::InvalidRequest("invalid continuation token".to_string()))?;
    if encoded.len() < 32 {
        return Err(ManagedListError::InvalidRequest(
            "invalid continuation token".to_string(),
        ));
    }
    let (tag, payload) = encoded.split_at(32);
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts fixed key");
    mac.update(payload);
    mac.verify_slice(tag)
        .map_err(|_| ManagedListError::InvalidRequest("invalid continuation token".to_string()))?;
    let (token_tenant, token_bucket, token_prefix, last): (String, String, String, String) =
        serde_json::from_slice(payload).map_err(|_| {
            ManagedListError::InvalidRequest("invalid continuation token".to_string())
        })?;
    (token_tenant == tenant_id && token_bucket == bucket && token_prefix == prefix)
        .then_some(last)
        .ok_or_else(|| {
            ManagedListError::InvalidRequest(
                "continuation token does not match this listing".to_string(),
            )
        })
}

#[cfg(test)]
#[test]
pub(crate) fn managed_list_continuation_is_bound_to_tenant_and_query() {
    let key = [7_u8; 32];
    let token = encode_managed_continuation(&key, "tenant-a", "bucket", "logs/", "logs/a");
    assert_eq!(
        decode_managed_continuation(&key, &token, "tenant-a", "bucket", "logs/").unwrap(),
        "logs/a"
    );
    assert!(matches!(
        decode_managed_continuation(&key, &token, "tenant-b", "bucket", "logs/"),
        Err(ManagedListError::InvalidRequest(_))
    ));
    assert!(matches!(
        decode_managed_continuation(&key, &token, "tenant-a", "bucket", "other/"),
        Err(ManagedListError::InvalidRequest(_))
    ));
}

/// ListObjects against the managed authority ledger. The ledger is the sole
/// logical namespace: service-provider generation keys are never listed.
pub(crate) async fn list_from_managed(
    storage: &ServiceStorage,
    tenant_id: &str,
    bucket: &str,
    params: &S3Query,
    continuation_key: &[u8; 32],
) -> Result<String, ManagedListError> {
    if params
        .delimiter
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        return Err(ManagedListError::InvalidRequest(
            "managed listing does not support delimiter".to_string(),
        ));
    }
    let prefix = params.prefix.as_deref().unwrap_or("");
    let is_v2 = params.list_type.as_deref() == Some("2");
    let max_keys = params.max_keys.unwrap_or(1000).clamp(0, 1000) as u64;
    let after = match params.continuation_token.as_deref() {
        Some(token) if is_v2 => Some(decode_managed_continuation(
            continuation_key,
            token,
            tenant_id,
            bucket,
            prefix,
        )?),
        Some(_) => {
            return Err(ManagedListError::InvalidRequest(
                "continuation-token requires list-type=2".to_string(),
            ));
        }
        None => params
            .start_after
            .as_deref()
            .or(params.marker.as_deref())
            .map(ToOwned::to_owned),
    };
    let page = storage
        .list_authority(AuthorityListQuery {
            tenant_id: tenant_id.to_string(),
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
            after: after.clone(),
            max_keys,
        })
        .await
        .map_err(|_| ManagedListError::Unavailable)?;
    let truncated = page.next_after.is_some();
    let encoding = params.encoding_type.as_deref() == Some("url");
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(prefix)));
    xml.push_str(&format!("<KeyCount>{}</KeyCount>", page.objects.len()));
    xml.push_str(&format!("<MaxKeys>{max_keys}</MaxKeys>"));
    xml.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
    if encoding {
        xml.push_str("<EncodingType>url</EncodingType>");
    }
    if let Some(token) = params.continuation_token.as_deref() {
        xml.push_str(&format!(
            "<ContinuationToken>{}</ContinuationToken>",
            xml_escape(token)
        ));
    } else if let Some(position) = &after {
        let element = if is_v2 { "StartAfter" } else { "Marker" };
        xml.push_str(&format!("<{element}>{}</{element}>", xml_escape(position)));
    }
    if let Some(next_after) = &page.next_after {
        let next = if is_v2 {
            encode_managed_continuation(continuation_key, tenant_id, bucket, prefix, next_after)
        } else {
            next_after.clone()
        };
        let element = if is_v2 {
            "NextContinuationToken"
        } else {
            "NextMarker"
        };
        xml.push_str(&format!("<{element}>{}</{element}>", xml_escape(&next)));
    }
    for authority in page.objects {
        let key = if encoding {
            url_encode(&authority.logical.key)
        } else {
            authority.logical.key
        };
        let last_modified = chrono::DateTime::from_timestamp_millis(authority.updated_at_ms)
            .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string());
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>{last_modified}</LastModified><ETag>\"{}\"</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(&key),
            xml_escape(&authority.digest),
            authority.size,
        ));
    }
    xml.push_str("</ListBucketResult>");
    Ok(xml)
}

/// ListObjectsV2 against the in-memory store.
pub(crate) fn list_from_memory(
    store: &MemoryStore,
    bucket: &str,
    params: &S3Query,
    continuation_key: &[u8; 32],
) -> Result<String, String> {
    let bucket_prefix = format!("{bucket}/");
    let objects = store
        .list_keys()
        .into_iter()
        .filter_map(|full| full.strip_prefix(&bucket_prefix).map(|key| key.to_string()))
        .map(|key| {
            let (size, _, etag) = store.metadata(bucket, &key).unwrap_or_default();
            (key, etag, size as u64, None)
        })
        .collect();
    list_from_local_objects(objects, bucket, params, continuation_key)
}

pub(crate) async fn list_from_file(
    store: &FileStore,
    bucket: &str,
    params: &S3Query,
    continuation_key: &[u8; 32],
) -> Result<String, String> {
    let objects = store
        .list_objects(bucket)
        .await
        .map_err(|error| error.to_string())?;
    list_from_local_objects(objects, bucket, params, continuation_key)
}

pub(crate) fn list_from_local_objects(
    objects: Vec<(String, String, u64, Option<i64>)>,
    bucket: &str,
    params: &S3Query,
    continuation_key: &[u8; 32],
) -> Result<String, String> {
    let is_v2 = params.list_type.as_deref() == Some("2");
    if params.continuation_token.is_some() && !is_v2 {
        return Err("continuation-token requires list-type=2".to_string());
    }
    if params
        .encoding_type
        .as_deref()
        .is_some_and(|encoding| encoding != "url")
    {
        return Err("encoding-type must be url".to_string());
    }
    let prefix = params.prefix.as_deref().unwrap_or("");
    let delimiter = params.delimiter.as_deref();
    let max_keys = params.max_keys.unwrap_or(1000).min(1000) as usize;
    let encoding = params.encoding_type.as_deref() == Some("url");
    let resume_after = match params.continuation_token.as_deref() {
        Some(token) => Some(decode_memory_continuation(
            continuation_key,
            token,
            bucket,
            prefix,
            delimiter,
        )?),
        None => params
            .start_after
            .as_deref()
            .or(params.marker.as_deref())
            .map(ToOwned::to_owned),
    };

    let mut objects: Vec<(String, String, u64, Option<i64>)> = objects
        .into_iter()
        .filter(|(key, _, _, _)| key.starts_with(prefix))
        .collect();
    objects.sort_by(|left, right| left.0.cmp(&right.0));
    enum Output {
        Content((String, String, u64, Option<i64>)),
        Common(String),
    }
    let mut outputs: Vec<Output> = Vec::new();
    let mut prev_common: Option<String> = None;
    for (k, etag, size, modified) in objects {
        if let Some(delim) = delimiter.filter(|d| !d.is_empty())
            && let Some(rel) = k.strip_prefix(prefix)
            && let Some(idx) = rel.find(delim)
        {
            let cp = format!("{prefix}{}", &rel[..=idx]);
            if prev_common.as_deref() != Some(cp.as_str()) {
                prev_common = Some(cp.clone());
                outputs.push(Output::Common(cp));
            }
            continue;
        }
        prev_common = None;
        outputs.push(Output::Content((k, etag, size, modified)));
    }

    // Continue from the previous *listed output*, not the raw object key. A
    // delimiter page can end at `logs/` while raw keys `logs/a` still sort
    // after it; filtering only raw keys would repeat that CommonPrefix forever.
    if let Some(resume_after) = &resume_after {
        outputs.retain(|output| match output {
            Output::Content((key, _, _, _)) => key > resume_after,
            Output::Common(prefix) => prefix > resume_after,
        });
    }

    let mut contents: Vec<(String, String, u64, Option<i64>)> = Vec::new();
    let mut commons: Vec<String> = Vec::new();
    let mut seen = 0usize;
    for out in outputs.iter().take(max_keys) {
        match out {
            Output::Content(entry) => contents.push(entry.clone()),
            Output::Common(cp) => commons.push(cp.clone()),
        }
        seen += 1;
    }
    // S3 permits max-keys=0. It returns an empty non-resumable page rather
    // than manufacturing a cursor that cannot advance.
    let truncated = max_keys > 0 && outputs.len() > seen;
    let next_token = if truncated && seen > 0 {
        outputs.get(seen - 1).map(|out| match out {
            Output::Content((k, _, _, _)) => k.clone(),
            Output::Common(cp) => cp.clone(),
        })
    } else {
        None
    };

    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml.push_str(&format!("<Name>{}</Name>", xml_escape(bucket)));
    xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(prefix)));
    if let Some(d) = delimiter {
        xml.push_str(&format!("<Delimiter>{}</Delimiter>", xml_escape(d)));
    }
    xml.push_str(&format!(
        "<KeyCount>{}</KeyCount>",
        contents.len() + commons.len()
    ));
    xml.push_str(&format!("<MaxKeys>{max_keys}</MaxKeys>"));
    xml.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
    if encoding {
        xml.push_str("<EncodingType>url</EncodingType>");
    }
    if let Some(t) = params.continuation_token.as_deref() {
        let elem = if is_v2 {
            format!("<ContinuationToken>{}</ContinuationToken>", xml_escape(t))
        } else {
            format!("<Marker>{}</Marker>", xml_escape(t))
        };
        xml.push_str(&elem);
    } else if let Some(t) = &resume_after {
        let elem = if is_v2 {
            format!("<StartAfter>{}</StartAfter>", xml_escape(t))
        } else {
            format!("<Marker>{}</Marker>", xml_escape(t))
        };
        xml.push_str(&elem);
    }
    if let Some(t) = next_token {
        let elem = if is_v2 {
            format!(
                "<NextContinuationToken>{}</NextContinuationToken>",
                xml_escape(&encode_memory_continuation(
                    continuation_key,
                    bucket,
                    prefix,
                    delimiter,
                    &t,
                ))
            )
        } else {
            format!("<NextMarker>{}</NextMarker>", xml_escape(&t))
        };
        xml.push_str(&elem);
    }
    for (k, etag, size, modified) in &contents {
        let display = if encoding { url_encode(k) } else { k.clone() };
        let last_modified = modified
            .and_then(chrono::DateTime::from_timestamp_millis)
            .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string());
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>{last_modified}</LastModified><ETag>{}</ETag><Size>{size}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(&display),
            xml_escape(etag)
        ));
    }
    for cp in &commons {
        let display = if encoding { url_encode(cp) } else { cp.clone() };
        xml.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            xml_escape(&display)
        ));
    }
    xml.push_str("</ListBucketResult>");
    Ok(xml)
}
