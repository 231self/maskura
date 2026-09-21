//! Extracted from `file_multipart_repository.rs`; re-exported from `crate::file_multipart_repository`.

use super::*;

pub(crate) fn reduce_transition(
    snapshot: &mut FileMultipartSnapshotV1,
    event: &FileMultipartEventV1,
) -> Result<(), FileMultipartReducerError> {
    if let Some(identity) = &snapshot.identity {
        if identity != &event.identity {
            return Err(FileMultipartReducerError::IdentityConflict);
        }
    } else if !matches!(
        event.transition,
        FileMultipartTransitionV1::UploadCreated { .. }
    ) {
        return Err(FileMultipartReducerError::UnknownReference);
    }

    match &event.transition {
        FileMultipartTransitionV1::UploadCreated { upload } => {
            if snapshot.identity.is_some() || snapshot.upload.is_some() {
                return Err(FileMultipartReducerError::ConflictingDuplicate);
            }
            if upload.identity != event.identity {
                return Err(FileMultipartReducerError::IdentityConflict);
            }
            snapshot.identity = Some(event.identity.clone());
            snapshot.upload = Some(upload.as_ref().clone());
        }
        FileMultipartTransitionV1::PartReplaced {
            part,
            updated_at_ms,
        } => {
            require_open(snapshot)?;
            validate_part_reference(part, &event.identity)?;
            if part.part_number == 0 || part.part_number > MAX_PARTS {
                return Err(FileMultipartReducerError::InvalidPart);
            }
            let max_attempt = max_attempt(snapshot, part.part_number);
            if part.attempt <= max_attempt || snapshot.attempts.len() >= MAX_PARTS as usize {
                return Err(FileMultipartReducerError::InvalidPart);
            }
            snapshot.attempts.retain(|attempt| {
                !(attempt.part.part_number == part.part_number
                    && attempt.lifecycle == FilePartAttemptLifecycleV1::Current)
            });
            snapshot.attempts.push(FilePartAttemptV1 {
                lifecycle: FilePartAttemptLifecycleV1::Current,
                part: part.clone(),
                reserved_bytes: 0,
            });
            set_updated_at(snapshot, *updated_at_ms)?;
        }
        FileMultipartTransitionV1::PartReserved {
            pending,
            created_at_ms,
        } => {
            let upload = require_open(snapshot)?;
            if upload.expires_at_ms <= *created_at_ms
                || pending.upload_id != event.identity.upload_id
                || pending.part_number == 0
                || pending.part_number > MAX_PARTS
                || snapshot.attempts.len() >= MAX_PARTS as usize
            {
                return Err(FileMultipartReducerError::InvalidPart);
            }
            let expected_attempt = max_attempt(snapshot, pending.part_number)
                .checked_add(1)
                .ok_or(FileMultipartReducerError::InvalidPart)?;
            if pending.attempt != expected_attempt {
                return Err(FileMultipartReducerError::InvalidPart);
            }
            let part = MultipartPart {
                upload_id: pending.upload_id.clone(),
                part_number: pending.part_number,
                attempt: pending.attempt,
                artifact_key: pending.artifact_key.clone(),
                etag: String::new(),
                checksum_sha256: String::new(),
                size_bytes: 0,
                created_at_ms: *created_at_ms,
            };
            snapshot.attempts.push(FilePartAttemptV1 {
                lifecycle: FilePartAttemptLifecycleV1::Pending,
                part,
                reserved_bytes: pending.reserved_bytes,
            });
            set_updated_at(snapshot, *created_at_ms)?;
        }
        FileMultipartTransitionV1::PartCommitted {
            pending,
            part,
            updated_at_ms,
        } => {
            require_open(snapshot)?;
            validate_part_reference(part, &event.identity)?;
            let index = attempt_index(snapshot, &pending.artifact_key)?;
            if pending.upload_id != event.identity.upload_id
                || part.upload_id != pending.upload_id
                || part.part_number != pending.part_number
                || part.attempt != pending.attempt
                || part.artifact_key != pending.artifact_key
                || part.size_bytes > pending.reserved_bytes
            {
                return Err(FileMultipartReducerError::InvalidPart);
            }
            let attempt = &snapshot.attempts[index];
            if attempt.lifecycle != FilePartAttemptLifecycleV1::Pending
                || attempt.reserved_bytes != pending.reserved_bytes
                || attempt.part.part_number != pending.part_number
                || attempt.part.attempt != pending.attempt
            {
                return Err(FileMultipartReducerError::UnknownReference);
            }
            for old in &mut snapshot.attempts {
                if old.part.part_number == part.part_number
                    && old.lifecycle == FilePartAttemptLifecycleV1::Current
                {
                    old.lifecycle = FilePartAttemptLifecycleV1::Retired;
                }
            }
            snapshot.attempts[index] = FilePartAttemptV1 {
                lifecycle: FilePartAttemptLifecycleV1::Current,
                part: part.clone(),
                reserved_bytes: 0,
            };
            set_updated_at(snapshot, *updated_at_ms)?;
        }
        FileMultipartTransitionV1::ArtifactDeleted {
            artifact_key,
            updated_at_ms,
        } => {
            let index = attempt_index(snapshot, artifact_key)?;
            let lifecycle = snapshot.attempts[index].lifecycle;
            if lifecycle == FilePartAttemptLifecycleV1::Current
                && snapshot.upload.as_ref().is_some_and(|upload| {
                    matches!(
                        upload.lifecycle,
                        MultipartLifecycle::Open
                            | MultipartLifecycle::Completing
                            | MultipartLifecycle::Publishing
                    )
                })
            {
                return Err(FileMultipartReducerError::IllegalLifecycle);
            }
            snapshot.attempts.remove(index);
            set_updated_at(snapshot, *updated_at_ms)?;
        }
        FileMultipartTransitionV1::CompletionAcquired {
            fingerprint,
            selected_parts,
            owner,
            lease_expires_at_ms,
            fencing_token,
            updated_at_ms,
        } => acquire_completion(
            snapshot,
            fingerprint,
            selected_parts,
            owner,
            *lease_expires_at_ms,
            *fencing_token,
            *updated_at_ms,
        )?,
        FileMultipartTransitionV1::CompletionRenewed {
            fencing_token,
            lease_expires_at_ms,
            updated_at_ms,
        } => {
            let upload = require_upload_mut(snapshot)?;
            if upload.lifecycle != MultipartLifecycle::Completing
                || upload.completion_fencing_token != *fencing_token
            {
                return Err(FileMultipartReducerError::InvalidFence);
            }
            if *lease_expires_at_ms <= *updated_at_ms {
                return Err(FileMultipartReducerError::InvalidExpiry);
            }
            upload.completion_lease_expires_at_ms = Some(*lease_expires_at_ms);
            set_updated_at(snapshot, *updated_at_ms)?;
        }
        FileMultipartTransitionV1::DestinationCommitBegun {
            permit,
            publishing_started_at_ms,
        } => {
            begin_destination_commit(snapshot, &event.identity, permit, *publishing_started_at_ms)?
        }
        FileMultipartTransitionV1::DestinationCommitRecorded {
            permit,
            record,
            updated_at_ms,
        } => {
            validate_permit(snapshot, permit)?;
            if record.operation_id != permit.operation_id {
                return Err(FileMultipartReducerError::InvalidPermit);
            }
            let upload = require_upload_mut(snapshot)?;
            if upload.destination_commit.is_some() {
                return Err(FileMultipartReducerError::CompletionConflict);
            }
            upload.destination_commit = Some(record.clone());
            set_updated_at(snapshot, *updated_at_ms)?;
        }
        FileMultipartTransitionV1::DestinationCommitReleased {
            permit,
            updated_at_ms,
        } => {
            validate_permit(snapshot, permit)?;
            let upload = require_upload_mut(snapshot)?;
            if upload.destination_commit.is_some() {
                return Err(FileMultipartReducerError::InvalidPermit);
            }
            upload.lifecycle = MultipartLifecycle::Completing;
            upload.destination_operation_id = None;
            upload.publishing_started_at_ms = None;
            upload.completion_lease_owner = None;
            upload.completion_lease_expires_at_ms = Some(*updated_at_ms);
            set_updated_at(snapshot, *updated_at_ms)?;
        }
        FileMultipartTransitionV1::CompletionCompleted {
            permit,
            result,
            completed_at_ms,
            tombstone_until_ms,
        } => {
            validate_permit(snapshot, permit)?;
            validate_tombstone(*completed_at_ms, *tombstone_until_ms)?;
            let upload = require_upload_mut(snapshot)?;
            if upload
                .destination_commit
                .as_ref()
                .map(|record| &record.result)
                != Some(result)
            {
                return Err(FileMultipartReducerError::CompletionConflict);
            }
            upload.lifecycle = MultipartLifecycle::Completed;
            upload.completion_result = Some(result.clone());
            upload.completion_lease_owner = None;
            upload.completion_lease_expires_at_ms = None;
            upload.tombstone_until_ms = Some(*tombstone_until_ms);
            retire_current_attempts(snapshot);
            set_updated_at(snapshot, *completed_at_ms)?;
        }
        FileMultipartTransitionV1::DestinationCommitReferenceCleared {
            expected_operation_id,
            updated_at_ms,
        } => {
            let upload = require_upload_mut(snapshot)?;
            if !is_terminal(upload.lifecycle)
                || upload.destination_operation_id != Some(*expected_operation_id)
            {
                return Err(FileMultipartReducerError::InvalidPermit);
            }
            upload.destination_operation_id = None;
            upload.destination_commit = None;
            upload.publishing_started_at_ms = None;
            set_updated_at(snapshot, *updated_at_ms)?;
        }
        FileMultipartTransitionV1::UploadAborted {
            aborted_at_ms,
            tombstone_until_ms,
        } => terminal_without_commit(
            snapshot,
            MultipartLifecycle::Aborted,
            *aborted_at_ms,
            *tombstone_until_ms,
        )?,
        FileMultipartTransitionV1::UploadExpired {
            expired_at_ms,
            tombstone_until_ms,
        } => {
            if require_open(snapshot)?.expires_at_ms > *expired_at_ms {
                return Err(FileMultipartReducerError::InvalidExpiry);
            }
            terminal_without_commit(
                snapshot,
                MultipartLifecycle::Expired,
                *expired_at_ms,
                *tombstone_until_ms,
            )?;
        }
        FileMultipartTransitionV1::CleanupAudited { audit } => {
            let upload = require_upload(snapshot)?;
            if audit.upload_id != event.identity.upload_id {
                return Err(FileMultipartReducerError::IdentityConflict);
            }
            if snapshot.cleanup_audits.len() >= MAX_FILE_MULTIPART_AUDITS
                || snapshot.cleanup_audits.iter().any(|old| old.id == audit.id)
                || json_record_count(&audit.detail)? > MAX_FILE_MULTIPART_EVIDENCE_RECORDS
                || audit.created_at_ms < upload.created_at_ms
            {
                return Err(FileMultipartReducerError::BoundExceeded);
            }
            snapshot.cleanup_audits.push(audit.clone());
        }
        FileMultipartTransitionV1::TerminalUploadDeleted => {
            let upload = require_upload(snapshot)?;
            if !matches!(
                upload.lifecycle,
                MultipartLifecycle::Aborted | MultipartLifecycle::Expired
            ) || !snapshot.attempts.is_empty()
                || upload.destination_operation_id.is_some()
                || upload.destination_commit.is_some()
            {
                return Err(FileMultipartReducerError::IllegalLifecycle);
            }
            snapshot.upload = None;
            snapshot.cleanup_audits.clear();
        }
        FileMultipartTransitionV1::TerminalUploadRetired { retired_at_ms } => {
            let upload = require_upload(snapshot)?;
            if !is_terminal(upload.lifecycle)
                || !snapshot.attempts.is_empty()
                || upload.destination_operation_id.is_some()
                || upload.destination_commit.is_some()
                || upload
                    .tombstone_until_ms
                    .is_none_or(|until| until > *retired_at_ms)
            {
                return Err(FileMultipartReducerError::IllegalLifecycle);
            }
            snapshot.upload = None;
            snapshot.cleanup_audits.clear();
        }
    }
    Ok(())
}

pub(crate) fn acquire_completion(
    snapshot: &mut FileMultipartSnapshotV1,
    fingerprint: &str,
    selected_parts: &[CompletePart],
    owner: &str,
    lease_expires_at_ms: i64,
    fencing_token: u64,
    updated_at_ms: i64,
) -> Result<(), FileMultipartReducerError> {
    let upload = require_upload(snapshot)?;
    if !matches!(
        upload.lifecycle,
        MultipartLifecycle::Open | MultipartLifecycle::Completing
    ) {
        return Err(FileMultipartReducerError::IllegalLifecycle);
    }
    if upload.lifecycle == MultipartLifecycle::Open && upload.expires_at_ms <= updated_at_ms {
        return Err(FileMultipartReducerError::InvalidExpiry);
    }
    if upload
        .complete_request_fingerprint
        .as_deref()
        .is_some_and(|old| old != fingerprint)
    {
        return Err(FileMultipartReducerError::CompletionConflict);
    }
    if upload.lifecycle == MultipartLifecycle::Completing
        && upload
            .completion_lease_expires_at_ms
            .is_some_and(|expires| expires > updated_at_ms)
    {
        return Err(FileMultipartReducerError::InvalidFence);
    }
    if fencing_token
        != upload
            .completion_fencing_token
            .checked_add(1)
            .ok_or(FileMultipartReducerError::InvalidFence)?
        || lease_expires_at_ms <= updated_at_ms
        || fingerprint.is_empty()
        || owner.is_empty()
    {
        return Err(FileMultipartReducerError::InvalidFence);
    }
    validate_selected_parts(snapshot, selected_parts)?;
    let upload = require_upload_mut(snapshot)?;
    upload.lifecycle = MultipartLifecycle::Completing;
    upload.complete_request_fingerprint = Some(fingerprint.to_string());
    upload.completion_lease_owner = Some(owner.to_string());
    upload.completion_lease_expires_at_ms = Some(lease_expires_at_ms);
    upload.completion_fencing_token = fencing_token;
    set_updated_at(snapshot, updated_at_ms)
}

pub(crate) fn begin_destination_commit(
    snapshot: &mut FileMultipartSnapshotV1,
    identity: &MultipartIdentity,
    permit: &DestinationCommitPermit,
    now_ms: i64,
) -> Result<(), FileMultipartReducerError> {
    let upload = require_upload(snapshot)?;
    if upload.lifecycle != MultipartLifecycle::Completing
        || upload.complete_request_fingerprint.as_deref()
            != Some(permit.completion_fingerprint.as_str())
        || upload.completion_fencing_token != permit.fencing_token
        || upload
            .completion_lease_expires_at_ms
            .is_none_or(|expires| expires <= now_ms)
        || permit.upload_id != identity.upload_id
        || permit.operation_id
            != DestinationCommitPermit::deterministic_operation_id(
                identity,
                &permit.completion_fingerprint,
            )
    {
        return Err(FileMultipartReducerError::InvalidPermit);
    }
    let upload = require_upload_mut(snapshot)?;
    upload.lifecycle = MultipartLifecycle::Publishing;
    upload.destination_operation_id = Some(permit.operation_id);
    upload.publishing_started_at_ms = Some(now_ms);
    upload.destination_commit = None;
    upload.completion_lease_owner = None;
    upload.completion_lease_expires_at_ms = None;
    set_updated_at(snapshot, now_ms)
}

pub(crate) fn terminal_without_commit(
    snapshot: &mut FileMultipartSnapshotV1,
    lifecycle: MultipartLifecycle,
    at_ms: i64,
    tombstone_until_ms: i64,
) -> Result<(), FileMultipartReducerError> {
    validate_tombstone(at_ms, tombstone_until_ms)?;
    if require_upload(snapshot)?.lifecycle != MultipartLifecycle::Open {
        return Err(FileMultipartReducerError::IllegalLifecycle);
    }
    let upload = require_upload_mut(snapshot)?;
    upload.lifecycle = lifecycle;
    upload.tombstone_until_ms = Some(tombstone_until_ms);
    retire_current_attempts(snapshot);
    set_updated_at(snapshot, at_ms)
}

pub(crate) fn validate_snapshot(
    snapshot: &FileMultipartSnapshotV1,
) -> Result<(), FileMultipartReducerError> {
    if snapshot.schema_version != FILE_MULTIPART_SCHEMA_VERSION {
        return Err(FileMultipartReducerError::UnsupportedVersion(
            snapshot.schema_version,
        ));
    }
    if snapshot.cleanup_audits.len() > MAX_FILE_MULTIPART_AUDITS
        || snapshot.attempts.len() > MAX_PARTS as usize
    {
        return Err(FileMultipartReducerError::BoundExceeded);
    }
    let Some(identity) = &snapshot.identity else {
        return if snapshot.upload.is_none()
            && snapshot.attempts.is_empty()
            && snapshot.cleanup_audits.is_empty()
            && snapshot.final_event_sequence == 0
        {
            Ok(())
        } else {
            Err(FileMultipartReducerError::CorruptSnapshot)
        };
    };
    validate_identity(identity)?;
    if let Some(upload) = &snapshot.upload {
        if &upload.identity != identity {
            return Err(FileMultipartReducerError::IdentityConflict);
        }
        validate_upload(upload)?;
    } else if !snapshot.attempts.is_empty() || !snapshot.cleanup_audits.is_empty() {
        return Err(FileMultipartReducerError::CorruptSnapshot);
    }

    let mut artifacts = BTreeSet::new();
    let mut coordinates = BTreeSet::new();
    let mut current_parts = BTreeSet::new();
    let mut staged_bytes = 0u64;
    let mut reserved_bytes = 0u64;
    for attempt in &snapshot.attempts {
        validate_part_reference(&attempt.part, identity)?;
        if !artifacts.insert(attempt.part.artifact_key.as_str())
            || !coordinates.insert((attempt.part.part_number, attempt.part.attempt))
        {
            return Err(FileMultipartReducerError::InvalidPart);
        }
        match attempt.lifecycle {
            FilePartAttemptLifecycleV1::Pending => {
                if attempt.part.size_bytes != 0
                    || !attempt.part.etag.is_empty()
                    || !attempt.part.checksum_sha256.is_empty()
                {
                    return Err(FileMultipartReducerError::InvalidPart);
                }
                reserved_bytes = checked_add(reserved_bytes, attempt.reserved_bytes)?;
            }
            FilePartAttemptLifecycleV1::Current => {
                if attempt.reserved_bytes != 0
                    || !current_parts.insert(attempt.part.part_number)
                    || attempt.part.etag.is_empty()
                    || attempt.part.checksum_sha256.is_empty()
                {
                    return Err(FileMultipartReducerError::InvalidPart);
                }
                staged_bytes = checked_add(staged_bytes, attempt.part.size_bytes)?;
            }
            FilePartAttemptLifecycleV1::Retired => {
                if attempt.reserved_bytes != 0
                    || attempt.part.etag.is_empty()
                    || attempt.part.checksum_sha256.is_empty()
                {
                    return Err(FileMultipartReducerError::InvalidPart);
                }
                staged_bytes = checked_add(staged_bytes, attempt.part.size_bytes)?;
            }
        }
    }
    if let Some(upload) = &snapshot.upload {
        if upload.staged_bytes != staged_bytes
            || upload.reserved_bytes != reserved_bytes
            || checked_add(staged_bytes, reserved_bytes)? > upload.snapshot.max_staged_bytes
        {
            return Err(FileMultipartReducerError::InvalidAccounting);
        }
        if is_terminal(upload.lifecycle) && !current_parts.is_empty() {
            return Err(FileMultipartReducerError::InvalidPart);
        }
    }

    let mut audit_ids = BTreeSet::new();
    for audit in &snapshot.cleanup_audits {
        if audit.upload_id != identity.upload_id
            || !audit_ids.insert(audit.id)
            || json_record_count(&audit.detail)? > MAX_FILE_MULTIPART_EVIDENCE_RECORDS
        {
            return Err(FileMultipartReducerError::BoundExceeded);
        }
    }
    Ok(())
}

pub(crate) fn validate_upload(upload: &MultipartUpload) -> Result<(), FileMultipartReducerError> {
    validate_identity(&upload.identity)?;
    if upload.created_at_ms > upload.updated_at_ms
        || upload.created_at_ms >= upload.expires_at_ms
        || upload.snapshot.max_staged_bytes == 0
    {
        return Err(FileMultipartReducerError::InvalidExpiry);
    }
    match upload.lifecycle {
        MultipartLifecycle::Open => {
            if upload.complete_request_fingerprint.is_some()
                || upload.completion_lease_owner.is_some()
                || upload.completion_lease_expires_at_ms.is_some()
                || upload.completion_fencing_token != 0
                || upload.destination_operation_id.is_some()
                || upload.publishing_started_at_ms.is_some()
                || upload.destination_commit.is_some()
                || upload.completion_result.is_some()
                || upload.tombstone_until_ms.is_some()
            {
                return Err(FileMultipartReducerError::CorruptSnapshot);
            }
        }
        MultipartLifecycle::Completing => {
            if upload
                .complete_request_fingerprint
                .as_deref()
                .is_none_or(str::is_empty)
                || upload.completion_fencing_token == 0
                || upload.completion_lease_expires_at_ms.is_none()
                || upload.destination_operation_id.is_some()
                || upload.publishing_started_at_ms.is_some()
                || upload.destination_commit.is_some()
                || upload.completion_result.is_some()
                || upload.tombstone_until_ms.is_some()
            {
                return Err(FileMultipartReducerError::CorruptSnapshot);
            }
        }
        MultipartLifecycle::Publishing => {
            if upload
                .complete_request_fingerprint
                .as_deref()
                .is_none_or(str::is_empty)
                || upload.completion_fencing_token == 0
                || upload.completion_lease_owner.is_some()
                || upload.completion_lease_expires_at_ms.is_some()
                || upload.destination_operation_id.is_none()
                || upload.publishing_started_at_ms.is_none()
                || upload.completion_result.is_some()
                || upload.tombstone_until_ms.is_some()
            {
                return Err(FileMultipartReducerError::CorruptSnapshot);
            }
        }
        MultipartLifecycle::Completed => {
            if upload
                .complete_request_fingerprint
                .as_deref()
                .is_none_or(str::is_empty)
                || upload.completion_result.is_none()
                || upload.tombstone_until_ms.is_none()
                || upload.destination_operation_id.is_some() != upload.destination_commit.is_some()
                || upload.destination_operation_id.is_some()
                    != upload.publishing_started_at_ms.is_some()
                || upload.completion_lease_owner.is_some()
                || upload.completion_lease_expires_at_ms.is_some()
            {
                return Err(FileMultipartReducerError::CorruptSnapshot);
            }
        }
        MultipartLifecycle::Aborted | MultipartLifecycle::Expired => {
            if upload.tombstone_until_ms.is_none()
                || upload.complete_request_fingerprint.is_some()
                || upload.completion_lease_owner.is_some()
                || upload.completion_lease_expires_at_ms.is_some()
                || upload.completion_fencing_token != 0
                || upload.destination_operation_id.is_some()
                || upload.publishing_started_at_ms.is_some()
                || upload.destination_commit.is_some()
                || upload.completion_result.is_some()
            {
                return Err(FileMultipartReducerError::CorruptSnapshot);
            }
        }
    }
    if let Some(commit) = &upload.destination_commit {
        if upload.destination_operation_id != Some(commit.operation_id) {
            return Err(FileMultipartReducerError::CompletionConflict);
        }
        if upload
            .publishing_started_at_ms
            .is_some_and(|started| commit.committed_at_ms < started)
            || commit.committed_at_ms > upload.updated_at_ms
        {
            return Err(FileMultipartReducerError::InvalidExpiry);
        }
        if let Some(result) = &upload.completion_result
            && result != &commit.result
        {
            return Err(FileMultipartReducerError::CompletionConflict);
        }
    }
    Ok(())
}

pub(crate) fn validate_identity(
    identity: &MultipartIdentity,
) -> Result<(), FileMultipartReducerError> {
    if identity.tenant_id.is_empty()
        || identity.credential_policy_id.is_empty()
        || identity.bucket.is_empty()
        || identity.key.is_empty()
        || identity.upload_id.is_empty()
    {
        return Err(FileMultipartReducerError::IdentityConflict);
    }
    Ok(())
}

pub(crate) fn validate_part_reference(
    part: &MultipartPart,
    identity: &MultipartIdentity,
) -> Result<(), FileMultipartReducerError> {
    if part.upload_id != identity.upload_id
        || part.part_number == 0
        || part.part_number > MAX_PARTS
        || part.attempt == 0
        || part.artifact_key.is_empty()
    {
        return Err(FileMultipartReducerError::InvalidPart);
    }
    Ok(())
}

pub(crate) fn validate_selected_parts(
    snapshot: &FileMultipartSnapshotV1,
    selected: &[CompletePart],
) -> Result<(), FileMultipartReducerError> {
    if selected.is_empty() || selected.len() > MAX_PARTS as usize {
        return Err(FileMultipartReducerError::InvalidPart);
    }
    let mut previous = 0;
    for requested in selected {
        if requested.part_number <= previous {
            return Err(FileMultipartReducerError::InvalidPart);
        }
        let current = snapshot
            .attempts
            .iter()
            .find(|attempt| {
                attempt.lifecycle == FilePartAttemptLifecycleV1::Current
                    && attempt.part.part_number == requested.part_number
            })
            .ok_or(FileMultipartReducerError::UnknownReference)?;
        if current.part.etag != requested.etag
            || requested
                .checksum_sha256
                .as_ref()
                .is_some_and(|checksum| checksum != &current.part.checksum_sha256)
        {
            return Err(FileMultipartReducerError::InvalidPart);
        }
        previous = requested.part_number;
    }
    Ok(())
}

pub(crate) fn validate_permit(
    snapshot: &FileMultipartSnapshotV1,
    permit: &DestinationCommitPermit,
) -> Result<(), FileMultipartReducerError> {
    let upload = require_upload(snapshot)?;
    if upload.lifecycle != MultipartLifecycle::Publishing
        || upload.identity.upload_id != permit.upload_id
        || upload.complete_request_fingerprint.as_deref()
            != Some(permit.completion_fingerprint.as_str())
        || upload.completion_fencing_token != permit.fencing_token
        || upload.destination_operation_id != Some(permit.operation_id)
        || permit.operation_id
            != DestinationCommitPermit::deterministic_operation_id(
                &upload.identity,
                &permit.completion_fingerprint,
            )
    {
        return Err(FileMultipartReducerError::InvalidPermit);
    }
    Ok(())
}

pub(crate) fn require_upload(
    snapshot: &FileMultipartSnapshotV1,
) -> Result<&MultipartUpload, FileMultipartReducerError> {
    snapshot
        .upload
        .as_ref()
        .ok_or(FileMultipartReducerError::UnknownReference)
}

pub(crate) fn require_upload_mut(
    snapshot: &mut FileMultipartSnapshotV1,
) -> Result<&mut MultipartUpload, FileMultipartReducerError> {
    snapshot
        .upload
        .as_mut()
        .ok_or(FileMultipartReducerError::UnknownReference)
}

pub(crate) fn require_open(
    snapshot: &FileMultipartSnapshotV1,
) -> Result<&MultipartUpload, FileMultipartReducerError> {
    let upload = require_upload(snapshot)?;
    if upload.lifecycle != MultipartLifecycle::Open {
        return Err(FileMultipartReducerError::IllegalLifecycle);
    }
    Ok(upload)
}

pub(crate) fn attempt_index(
    snapshot: &FileMultipartSnapshotV1,
    artifact_key: &str,
) -> Result<usize, FileMultipartReducerError> {
    snapshot
        .attempts
        .iter()
        .position(|attempt| attempt.part.artifact_key == artifact_key)
        .ok_or(FileMultipartReducerError::UnknownReference)
}

pub(crate) fn max_attempt(snapshot: &FileMultipartSnapshotV1, part_number: u32) -> u32 {
    snapshot
        .attempts
        .iter()
        .filter(|attempt| attempt.part.part_number == part_number)
        .map(|attempt| attempt.part.attempt)
        .max()
        .unwrap_or(0)
}

pub(crate) fn retire_current_attempts(snapshot: &mut FileMultipartSnapshotV1) {
    for attempt in &mut snapshot.attempts {
        if attempt.lifecycle == FilePartAttemptLifecycleV1::Current {
            attempt.lifecycle = FilePartAttemptLifecycleV1::Retired;
        }
    }
}

pub(crate) fn set_updated_at(
    snapshot: &mut FileMultipartSnapshotV1,
    updated_at_ms: i64,
) -> Result<(), FileMultipartReducerError> {
    if updated_at_ms < require_upload(snapshot)?.updated_at_ms {
        return Err(FileMultipartReducerError::InvalidExpiry);
    }
    let (staged, reserved) = calculate_accounting(&snapshot.attempts)?;
    let upload = require_upload_mut(snapshot)?;
    upload.staged_bytes = staged;
    upload.reserved_bytes = reserved;
    upload.updated_at_ms = updated_at_ms;
    Ok(())
}

pub(crate) fn calculate_accounting(
    attempts: &[FilePartAttemptV1],
) -> Result<(u64, u64), FileMultipartReducerError> {
    attempts
        .iter()
        .try_fold((0u64, 0u64), |(staged, reserved), attempt| {
            match attempt.lifecycle {
                FilePartAttemptLifecycleV1::Pending => {
                    Ok((staged, checked_add(reserved, attempt.reserved_bytes)?))
                }
                FilePartAttemptLifecycleV1::Current | FilePartAttemptLifecycleV1::Retired => {
                    Ok((checked_add(staged, attempt.part.size_bytes)?, reserved))
                }
            }
        })
}

pub(crate) fn checked_add(left: u64, right: u64) -> Result<u64, FileMultipartReducerError> {
    left.checked_add(right)
        .ok_or(FileMultipartReducerError::InvalidAccounting)
}

pub(crate) fn validate_usage(
    usage: FileMultipartQuotaUsage,
    limit: u64,
) -> Result<(), FileMultipartReducerError> {
    if checked_add(usage.staged_bytes, usage.reserved_bytes)? > limit {
        return Err(FileMultipartReducerError::InvalidAccounting);
    }
    Ok(())
}

pub(crate) fn validate_tombstone(
    at_ms: i64,
    tombstone_until_ms: i64,
) -> Result<(), FileMultipartReducerError> {
    let expected = at_ms
        .checked_add(DEFAULT_EXPIRY.as_millis() as i64)
        .ok_or(FileMultipartReducerError::InvalidExpiry)?;
    if tombstone_until_ms != expected {
        return Err(FileMultipartReducerError::InvalidExpiry);
    }
    Ok(())
}

pub(crate) fn is_terminal(lifecycle: MultipartLifecycle) -> bool {
    matches!(
        lifecycle,
        MultipartLifecycle::Completed | MultipartLifecycle::Aborted | MultipartLifecycle::Expired
    )
}

pub(crate) fn json_record_count(
    value: &serde_json::Value,
) -> Result<usize, FileMultipartReducerError> {
    match value {
        serde_json::Value::Array(values) => values.iter().try_fold(values.len(), |count, value| {
            count
                .checked_add(json_record_count(value)?)
                .ok_or(FileMultipartReducerError::BoundExceeded)
        }),
        serde_json::Value::Object(values) => values.values().try_fold(1usize, |count, value| {
            count
                .checked_add(json_record_count(value)?)
                .ok_or(FileMultipartReducerError::BoundExceeded)
        }),
        _ => Ok(0),
    }
}
