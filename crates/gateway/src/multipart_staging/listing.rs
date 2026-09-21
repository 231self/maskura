//! Extracted from `multipart_staging.rs`; re-exported from `crate::multipart_staging`.

use super::*;

pub(crate) fn same_identity(upload: &MultipartUpload, identity: &MultipartIdentity) -> bool {
    upload.identity.tenant_id == identity.tenant_id
        && upload.identity.credential_policy_id == identity.credential_policy_id
        && upload.identity.bucket == identity.bucket
        && upload.identity.key == identity.key
        && upload.identity.upload_id == identity.upload_id
}

#[derive(Clone)]
pub(crate) enum MultipartListingEntry {
    Upload(Box<MultipartUpload>),
    CommonPrefix(String),
}

pub(crate) fn paginate_multipart_uploads(
    mut uploads: Vec<MultipartUpload>,
    request: &ListMultipartUploadsRequest,
) -> Result<ListMultipartUploadsPage, StagingError> {
    if request.max_uploads > MAX_MULTIPART_UPLOADS_PAGE
        || request.upload_id_marker.is_some() && request.key_marker.is_none()
        || request.delimiter.as_deref() == Some("")
    {
        return Err(StagingError::InvalidListing);
    }
    uploads.sort_by(|left, right| {
        (&left.identity.key, &left.identity.upload_id)
            .cmp(&(&right.identity.key, &right.identity.upload_id))
    });
    let after_marker = |key: &str, upload_id: Option<&str>| match &request.key_marker {
        None => true,
        Some(marker) if key > marker.as_str() => true,
        Some(marker) if key == marker => match &request.upload_id_marker {
            Some(upload_marker) => upload_id.is_some_and(|id| id > upload_marker.as_str()),
            None => false,
        },
        Some(_) => false,
    };

    let mut entries = BTreeMap::<(String, Option<String>), MultipartListingEntry>::new();
    for upload in uploads {
        if !upload.identity.key.starts_with(&request.prefix) {
            continue;
        }
        if let Some(delimiter) = &request.delimiter {
            let suffix = &upload.identity.key[request.prefix.len()..];
            if let Some(index) = suffix.find(delimiter) {
                let prefix = upload.identity.key[..request.prefix.len() + index + delimiter.len()]
                    .to_string();
                if after_marker(&prefix, None) {
                    entries
                        .entry((prefix.clone(), None))
                        .or_insert(MultipartListingEntry::CommonPrefix(prefix));
                }
                continue;
            }
        }
        if after_marker(&upload.identity.key, Some(&upload.identity.upload_id)) {
            entries.insert(
                (
                    upload.identity.key.clone(),
                    Some(upload.identity.upload_id.clone()),
                ),
                MultipartListingEntry::Upload(Box::new(upload)),
            );
        }
    }

    let is_truncated = entries.len() > request.max_uploads;
    let selected: Vec<_> = entries.into_iter().take(request.max_uploads).collect();
    let (next_key_marker, next_upload_id_marker) = if is_truncated {
        selected
            .last()
            .map(|((key, upload_id), _)| (Some(key.clone()), upload_id.clone()))
            .unwrap_or((request.key_marker.clone(), request.upload_id_marker.clone()))
    } else {
        (None, None)
    };
    let mut page = ListMultipartUploadsPage {
        uploads: Vec::new(),
        common_prefixes: Vec::new(),
        is_truncated,
        next_key_marker,
        next_upload_id_marker,
    };
    for (_, entry) in selected {
        match entry {
            MultipartListingEntry::Upload(upload) => page.uploads.push(*upload),
            MultipartListingEntry::CommonPrefix(prefix) => page.common_prefixes.push(prefix),
        }
    }
    Ok(page)
}

pub(crate) fn permit_matches(upload: &MultipartUpload, permit: &DestinationCommitPermit) -> bool {
    upload.lifecycle == MultipartLifecycle::Publishing
        && upload.identity.upload_id == permit.upload_id
        && upload.complete_request_fingerprint.as_deref()
            == Some(permit.completion_fingerprint.as_str())
        && upload.completion_fencing_token == permit.fencing_token
        && upload.destination_operation_id == Some(permit.operation_id)
}

pub(crate) fn publishing_upload(
    upload: MultipartUpload,
) -> Result<PublishingMultipartUpload, StagingError> {
    let fingerprint = upload.complete_request_fingerprint.clone().ok_or_else(|| {
        StagingError::Persistence("publishing upload is missing its fingerprint".to_string())
    })?;
    let operation_id = upload.destination_operation_id.ok_or_else(|| {
        StagingError::Persistence("publishing upload is missing its operation id".to_string())
    })?;
    let publishing_started_at_ms = upload.publishing_started_at_ms.ok_or_else(|| {
        StagingError::Persistence("publishing upload is missing its start time".to_string())
    })?;
    Ok(PublishingMultipartUpload {
        identity: upload.identity.clone(),
        permit: DestinationCommitPermit {
            upload_id: upload.identity.upload_id,
            completion_fingerprint: fingerprint,
            fencing_token: upload.completion_fencing_token,
            operation_id,
        },
        publishing_started_at_ms,
        destination_commit: upload.destination_commit,
    })
}
