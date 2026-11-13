//! Local-only versioning protocol. Existing object handlers retain read/write
//! authority; a query selector never grants a different storage destination.
use super::*;
use crate::file_store::{FileStoreError, FileVersion, FileVersioning};
use axum::extract::FromRequestParts;
use quick_xml::{Reader, events::Event};

const VERSIONING_XML_LIMIT: usize = 16 * 1024;

pub(super) fn query_pairs(query: Option<&str>) -> Result<Vec<(String, String)>, ()> {
    let raw = query.unwrap_or("");
    for (index, byte) in raw.bytes().enumerate() {
        if byte == b'%'
            && !raw
                .as_bytes()
                .get(index + 1..index + 3)
                .is_some_and(|bytes| bytes.iter().all(u8::is_ascii_hexdigit))
        {
            return Err(());
        }
    }
    let mut url = reqwest::Url::parse("http://local.invalid/").map_err(|_| ())?;
    url.set_query(Some(raw));
    let pairs: Vec<_> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if pairs
        .iter()
        .any(|(k, v)| k.contains('\u{fffd}') || v.contains('\u{fffd}'))
    {
        return Err(());
    }
    Ok(pairs)
}

/// Returns true for bucket configuration, which has its own bounded body path.
pub(super) fn validate_query(request: &Request, pairs: &[(String, String)]) -> Result<bool, ()> {
    let get = |name: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    let configuration = get("versioning");
    let listing = get("versions");
    let version = get("versionId");
    for field in ["versioning", "versions", "versionId", "version-id-marker"] {
        if pairs.iter().filter(|(k, _)| k == field).count() > 1 {
            return Err(());
        }
    }
    let count = [configuration, listing, version]
        .iter()
        .filter(|v| v.is_some())
        .count();
    if count > 1 {
        return Err(());
    }
    if get("version-id-marker").is_some() && listing.is_none() {
        return Err(());
    }
    if count == 0 {
        if get("version-id-marker").is_some() {
            return Err(());
        }
        return Ok(false);
    }
    if ["uploadId", "uploads", "partNumber", "delete"]
        .iter()
        .any(|name| get(name).is_some())
    {
        return Err(());
    }
    let bucket = request
        .uri()
        .path()
        .split('/')
        .filter(|s| !s.is_empty())
        .count()
        == 1;
    if let Some(value) = configuration {
        if !bucket || !value.is_empty() || !matches!(*request.method(), Method::GET | Method::PUT) {
            return Err(());
        }
        return Ok(true);
    }
    if let Some(value) = listing
        && (!bucket
            || !value.is_empty()
            || *request.method() != Method::GET
            || get("list-type").is_some()
            || get("continuation-token").is_some()
            || get("version-id-marker").is_some() && get("key-marker").is_none())
    {
        return Err(());
    }
    if let Some(version) = version
        && (bucket
            || !matches!(
                *request.method(),
                Method::GET | Method::HEAD | Method::DELETE
            )
            || crate::file_store::validate_version_id(version).is_err())
    {
        return Err(());
    }
    Ok(false)
}

pub(super) fn file_error_response(key: &str, error: FileStoreError) -> axum::response::Response {
    match error {
        FileStoreError::NoSuchBucket => s3_error::no_such_bucket(key),
        FileStoreError::InvalidVersion => {
            s3_error::invalid_argument(key, "Invalid version selector.")
        }
        FileStoreError::NoSuchVersion => s3_error::no_such_version(key),
        FileStoreError::DeleteMarker {
            version_id,
            explicit,
            last_modified_ms,
        } => {
            let mut response = s3_error::delete_marker(key, explicit);
            response
                .headers_mut()
                .insert("x-amz-delete-marker", "true".parse().unwrap());
            if let Ok(value) = version_id.parse() {
                response.headers_mut().insert("x-amz-version-id", value);
            }
            if explicit
                && let Some(value) = http_date(last_modified_ms).and_then(|v| v.parse().ok())
            {
                response.headers_mut().insert(header::LAST_MODIFIED, value);
            }
            response
        }
        FileStoreError::HistoryFull => {
            s3_error::service_unavailable(key, "Object version metadata capacity exceeded.")
        }
        _ => s3_error::internal_error(key, "Local version storage is unavailable."),
    }
}

pub(super) fn delete_response(
    result: crate::file_store::FileDeleteResult,
) -> axum::response::Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Some(id) = result.version_id
        && let Ok(value) = id.parse()
    {
        response.headers_mut().insert("x-amz-version-id", value);
    }
    if result.delete_marker {
        response
            .headers_mut()
            .insert("x-amz-delete-marker", "true".parse().unwrap());
    }
    harden_object_response_headers(response.headers_mut());
    response
}

/// Preserve the selected local source identity on transformed output without
/// forwarding stored validators, checksums or unprotected customer metadata.
pub(super) fn apply_read_version(
    response: &mut axum::response::Response,
    backend: &ResolvedBackend,
    version: Option<&str>,
) {
    if response.status().is_success()
        && matches!(backend, ResolvedBackend::File(_))
        && let Some(value) = version.and_then(|id| id.parse().ok())
    {
        response.headers_mut().insert("x-amz-version-id", value);
    }
}

fn parse_configuration(body: &[u8]) -> Result<FileVersioning, ()> {
    if body.len() > VERSIONING_XML_LIMIT {
        return Err(());
    }
    std::str::from_utf8(body).map_err(|_| ())?;
    let mut reader = Reader::from_reader(body);
    let mut stack = Vec::new();
    let mut status = String::new();
    let (mut root_seen, mut root_closed, mut status_seen, mut declaration) =
        (false, false, false, false);
    loop {
        match reader.read_event().map_err(|_| ())? {
            Event::Decl(_) if !root_seen && !declaration => declaration = true,
            Event::Start(start) => {
                let name = start.name().as_ref().to_vec();
                for attr in start.attributes() {
                    let attr = attr.map_err(|_| ())?;
                    if !stack.is_empty()
                        || attr.key.as_ref() != b"xmlns"
                        || attr.value.as_ref() != b"http://s3.amazonaws.com/doc/2006-03-01/"
                    {
                        return Err(());
                    }
                }
                match (stack.len(), name.as_slice()) {
                    (0, b"VersioningConfiguration") if !root_seen && !root_closed => {
                        root_seen = true
                    }
                    (1, b"Status") if !status_seen => status_seen = true,
                    _ => return Err(()),
                }
                stack.push(name);
            }
            Event::End(end) => {
                if stack.pop().as_deref() != Some(end.name().as_ref()) {
                    return Err(());
                }
                if stack.is_empty() {
                    root_closed = true;
                }
            }
            Event::Text(text) => {
                let text = text.decode().map_err(|_| ())?;
                if stack.last().is_some_and(|v| v == b"Status") {
                    status.push_str(&text);
                } else if !text.trim().is_empty() {
                    return Err(());
                }
            }
            Event::Eof if root_seen && root_closed && status_seen && stack.is_empty() => break,
            _ => return Err(()),
        }
    }
    match status.trim() {
        "Enabled" => Ok(FileVersioning::Enabled),
        "Suspended" => Ok(FileVersioning::Suspended),
        _ => Err(()),
    }
}

pub(super) async fn bucket_configuration(
    state: Arc<AppState>,
    request: Request,
) -> axum::response::Response {
    let (mut parts, body) = request.into_parts();
    let bucket = match Path::<String>::from_request_parts(&mut parts, &()).await {
        Ok(Path(bucket)) => bucket,
        Err(_) => return s3_error::invalid_argument("", "Invalid bucket path."),
    };
    let authentication = match authenticate_headers(
        parts.method.as_str(),
        &parts.uri,
        &parts.headers,
        &state.keys,
        &state,
    )
    .await
    {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response(&bucket, error),
    };
    let auth = authentication.auth.clone();
    if let Some(response) = client_metering_id_rejection(&parts.headers, &bucket) {
        return response;
    }
    let write = parts.method == Method::PUT;
    let backend = match resolve_backend(
        &state,
        &auth,
        &parts.headers,
        if write {
            StorageOperation::Put
        } else {
            StorageOperation::List
        },
    )
    .await
    {
        Ok(selection) => selection.backend,
        Err(_) => return backend_resolution_error_response(&bucket),
    };
    let ResolvedBackend::File(store) = backend else {
        return s3_error::not_implemented(&bucket);
    };
    match store.bucket_exists(&bucket).await {
        Ok(true) => {}
        Ok(false) => return s3_error::no_such_bucket(&bucket),
        Err(error) => return file_error_response(&bucket, error),
    }
    let operation = request_operation_identity();
    let authorization = operation.authorization(
        &bucket,
        if write {
            UsageRoute::PutObject
        } else {
            UsageRoute::ListObjects
        },
        if write {
            RequestKind::Write
        } else {
            RequestKind::Read
        },
        0,
    );
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
    let response = if write {
        match read_verified_body(authentication, body, VERSIONING_XML_LIMIT).await {
            Ok((_, bytes)) => match parse_configuration(&bytes) {
                Ok(configuration) => match store.set_versioning(&bucket, configuration).await {
                    Ok(()) => StatusCode::OK.into_response(),
                    Err(error) => file_error_response(&bucket, error),
                },
                Err(()) => s3_error::malformed_xml(
                    &bucket,
                    "Expected one Enabled or Suspended Status; unsupported fields are rejected.",
                ),
            },
            Err(VerifiedBodyError::TooLarge) => s3_error::entity_too_large(&bucket),
            Err(VerifiedBodyError::Integrity(_)) => {
                s3_error::bad_digest(&bucket, "Request integrity verification failed.")
            }
            Err(VerifiedBodyError::Transport) => {
                s3_error::invalid_request(&bucket, "Request body failed.")
            }
        }
    } else {
        match store.versioning(&bucket).await {
            Ok(state) => {
                let status = match state {
                    FileVersioning::Unversioned => "",
                    FileVersioning::Enabled => "<Status>Enabled</Status>",
                    FileVersioning::Suspended => "<Status>Suspended</Status>",
                };
                s3_xml_ok(format!(
                    "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{status}</VersioningConfiguration>"
                ))
            }
            Err(error) => file_error_response(&bucket, error),
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

fn versions_xml(bucket: &str, params: &S3Query, versions: Vec<FileVersion>) -> Result<String, ()> {
    let limit = params.max_keys.unwrap_or(1000).min(1000) as usize;
    if params.encoding_type.as_deref().is_some_and(|v| v != "url") {
        return Err(());
    }
    let marker = params.key_marker.as_deref();
    let version_marker = params.version_id_marker.as_deref();
    if let Some(id) = version_marker
        && !versions
            .iter()
            .any(|v| Some(v.key.as_str()) == marker && v.version_id == id)
    {
        return Err(());
    }
    let enc = |value: &str| {
        xml_escape(&if params.encoding_type.as_deref() == Some("url") {
            url_encode(value)
        } else {
            value.to_owned()
        })
    };
    let prefix = params.prefix.as_deref().unwrap_or("");
    let delimiter = params.delimiter.as_deref().filter(|d| !d.is_empty());
    let mut xml_entries = Vec::new();
    let mut prefixes = std::collections::BTreeSet::new();
    let mut after_pair = version_marker.is_none();
    for version in versions {
        if Some(version.key.as_str()) == marker && !after_pair {
            if Some(version.version_id.as_str()) == version_marker {
                after_pair = true;
            }
            continue;
        }
        if marker.is_some_and(|m| {
            version.key.as_str() < m || version.key == m && version_marker.is_none()
        }) {
            continue;
        }
        if !version.key.starts_with(prefix) {
            continue;
        }
        if let Some(delimiter) = delimiter
            && let Some(index) = version.key[prefix.len()..].find(delimiter)
        {
            let common = &version.key[..prefix.len() + index + delimiter.len()];
            if marker.is_some_and(|m| common <= m) || !prefixes.insert(common.to_owned()) {
                continue;
            }
            xml_entries.push((
                common.to_owned(),
                None,
                format!(
                    "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                    enc(common)
                ),
            ));
            continue;
        }
        let kind = if version.delete_marker {
            "DeleteMarker"
        } else {
            "Version"
        };
        let date = chrono::DateTime::from_timestamp_millis(version.last_modified_ms)
            .ok_or(())?
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let detail = if version.delete_marker {
            String::new()
        } else {
            format!(
                "<ETag>{}</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass>",
                xml_escape(&version.etag),
                version.size
            )
        };
        let entry = format!(
            "<{kind}><Key>{}</Key><VersionId>{}</VersionId><IsLatest>{}</IsLatest><LastModified>{date}</LastModified>{detail}</{kind}>",
            enc(&version.key),
            xml_escape(&version.version_id),
            version.is_latest
        );
        xml_entries.push((version.key, Some(version.version_id), entry));
    }
    let truncated = limit > 0 && xml_entries.len() > limit;
    let mut xml = format!(
        "<ListVersionsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{}</Name><Prefix>{}</Prefix><KeyMarker>{}</KeyMarker><VersionIdMarker>{}</VersionIdMarker><MaxKeys>{limit}</MaxKeys><IsTruncated>{truncated}</IsTruncated>",
        xml_escape(bucket),
        enc(prefix),
        enc(marker.unwrap_or("")),
        xml_escape(version_marker.unwrap_or(""))
    );
    if let Some(delimiter) = delimiter {
        xml.push_str(&format!("<Delimiter>{}</Delimiter>", enc(delimiter)));
    }
    if params.encoding_type.is_some() {
        xml.push_str("<EncodingType>url</EncodingType>");
    }
    if truncated && let Some((key, version, _)) = xml_entries.get(limit - 1) {
        xml.push_str(&format!("<NextKeyMarker>{}</NextKeyMarker>", enc(key)));
        if let Some(version) = version {
            xml.push_str(&format!(
                "<NextVersionIdMarker>{}</NextVersionIdMarker>",
                xml_escape(version)
            ));
        }
    }
    for (_, _, entry) in xml_entries.into_iter().take(limit) {
        xml.push_str(&entry);
    }
    xml.push_str("</ListVersionsResult>");
    Ok(xml)
}

pub(super) async fn list_versions_response(
    backend: &ResolvedBackend,
    bucket: &str,
    params: &S3Query,
) -> axum::response::Response {
    let ResolvedBackend::File(store) = backend else {
        return s3_error::not_implemented(bucket);
    };
    if let Some(response) = require_file_bucket(backend, bucket).await {
        return response;
    }
    match store.list_versions(bucket).await {
        Ok(versions) => match versions_xml(bucket, params, versions) {
            Ok(xml) => s3_xml_ok(xml),
            Err(()) => s3_error::invalid_argument(bucket, "Invalid version listing parameters."),
        },
        Err(error) => file_error_response(bucket, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_is_strict_and_bounded() {
        for (text, state) in [
            ("Enabled", FileVersioning::Enabled),
            ("Suspended", FileVersioning::Suspended),
        ] {
            assert_eq!(parse_configuration(format!("<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>{text}</Status></VersioningConfiguration>").as_bytes()), Ok(state));
        }
        for body in [
            "<VersioningConfiguration/>",
            "<VersioningConfiguration><Status>Enabled</Status><MfaDelete>Disabled</MfaDelete></VersioningConfiguration>",
            "<VersioningConfiguration><Status>Enabled</Status><Status>Suspended</Status></VersioningConfiguration>",
            "<!DOCTYPE x><VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
            "<VersioningConfiguration><Status>Disabled</Status></VersioningConfiguration>",
            "<VersioningConfiguration xmlns=\"wrong\"><Status>Enabled</Status></VersioningConfiguration>",
        ] {
            assert!(parse_configuration(body.as_bytes()).is_err(), "{body}");
        }
        assert!(parse_configuration(&vec![b' '; VERSIONING_XML_LIMIT + 1]).is_err());
    }

    #[test]
    fn selector_guard_rejects_duplicates_and_misrouted_mutations() {
        for (method, uri) in [
            ("PUT", "/bucket/key?versionId=null"),
            ("DELETE", "/bucket?versioning"),
            ("GET", "/bucket/key?versionId=null&version%49d=null"),
            ("GET", "/bucket/key?versionId=null&uploadId=upload"),
            ("GET", "/bucket?versions&versioning"),
            ("GET", "/bucket?versions&version-id-marker=null"),
            ("GET", "/bucket?versioning&version-id-marker=null"),
            ("GET", "/bucket/key?versionId=null&version-id-marker=null"),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap();
            assert!(
                validate_query(&request, &query_pairs(request.uri().query()).unwrap()).is_err(),
                "{uri}"
            );
        }
        assert!(query_pairs(Some("versionId=%QQ")).is_err());
    }

    #[test]
    fn version_listing_encodes_prefixes_and_resumes_after_a_common_prefix() {
        let versions = ["a b/first", "a b/first", "a b/second", "z &é"]
            .into_iter()
            .enumerate()
            .map(|(index, key)| FileVersion {
                key: key.into(),
                version_id: Uuid::from_u128(index as u128 + 1).to_string(),
                is_latest: index != 1,
                delete_marker: index == 1,
                last_modified_ms: 1_000,
                size: 1,
                etag: "\"&\"".into(),
            })
            .collect::<Vec<_>>();
        let params = S3Query {
            max_keys: Some(1),
            delimiter: Some("/".into()),
            encoding_type: Some("url".into()),
            ..Default::default()
        };
        let first = versions_xml("bucket", &params, versions.clone()).unwrap();
        assert_eq!(first.matches("<CommonPrefixes>").count(), 1);
        assert!(first.contains("<Prefix>a%20b%2F</Prefix>"), "{first}");
        assert!(first.contains("<NextKeyMarker>a%20b%2F</NextKeyMarker>"));
        assert!(!first.contains("<NextVersionIdMarker>"));
        assert!(!first.contains("<Version>") && !first.contains("<DeleteMarker>"));
        let next = versions_xml(
            "bucket",
            &S3Query {
                key_marker: Some("a b/".into()),
                ..params
            },
            versions.clone(),
        )
        .unwrap();
        assert!(next.contains("<Key>z%20%26%C3%A9</Key>"), "{next}");
        assert!(next.contains("<IsTruncated>false</IsTruncated>"));
        assert!(!next.contains("<CommonPrefixes>"));
        let pair = versions_xml(
            "bucket",
            &S3Query {
                max_keys: Some(1),
                prefix: Some("a b/".into()),
                key_marker: Some("a b/first".into()),
                version_id_marker: Some(versions[0].version_id.clone()),
                ..Default::default()
            },
            versions.clone(),
        )
        .unwrap();
        assert!(pair.contains("<DeleteMarker>") && pair.contains("<IsLatest>false</IsLatest>"));
        assert!(pair.contains(&format!(
            "<NextVersionIdMarker>{}</NextVersionIdMarker>",
            versions[1].version_id
        )));
        assert!(
            versions_xml(
                "bucket",
                &S3Query {
                    key_marker: Some("a b/first".into()),
                    version_id_marker: Some("null".into()),
                    ..Default::default()
                },
                versions
            )
            .is_err()
        );
    }
}
