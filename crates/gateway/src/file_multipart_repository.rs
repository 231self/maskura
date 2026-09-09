//! Pure state reduction for the durable local multipart repository.
//!
//! File framing, checksums, locking, and durable append are intentionally left
//! to the Task 8 adapter. This module owns the versioned persistence vocabulary
//! and rejects state that the adapter must never publish.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::multipart_staging::{
    CleanupAudit, CompletePart, DEFAULT_EXPIRY, DestinationCommitPermit, DestinationCommitRecord,
    MAX_ACTIVE_UPLOADS, MAX_PARTS, MultipartCompletionResult, MultipartIdentity,
    MultipartLifecycle, MultipartPart, MultipartUpload, PendingPart, StagingQuotaLimits,
};

pub(crate) const FILE_MULTIPART_SCHEMA_VERSION: u32 = 1;
pub(crate) const MAX_FILE_MULTIPART_AUDITS: usize = 256;
pub(crate) const MAX_FILE_MULTIPART_EVIDENCE_RECORDS: usize = 4_096;
const MAX_REPLAY_EVENTS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum FilePartAttemptLifecycleV1 {
    Pending,
    Current,
    Retired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FilePartAttemptV1 {
    pub lifecycle: FilePartAttemptLifecycleV1,
    pub part: MultipartPart,
    pub reserved_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FileMultipartSnapshotV1 {
    pub schema_version: u32,
    pub final_event_sequence: u64,
    pub identity: Option<MultipartIdentity>,
    pub upload: Option<MultipartUpload>,
    pub attempts: Vec<FilePartAttemptV1>,
    pub cleanup_audits: Vec<CleanupAudit>,
}

impl Default for FileMultipartSnapshotV1 {
    fn default() -> Self {
        Self {
            schema_version: FILE_MULTIPART_SCHEMA_VERSION,
            final_event_sequence: 0,
            identity: None,
            upload: None,
            attempts: Vec::new(),
            cleanup_audits: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FileMultipartEventV1 {
    pub schema_version: u32,
    pub sequence: u64,
    pub event_id: Uuid,
    pub identity: MultipartIdentity,
    pub transition: FileMultipartTransitionV1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum FileMultipartTransitionV1 {
    UploadCreated {
        upload: Box<MultipartUpload>,
    },
    /// Compatibility transition for the pre-outbox `replace_part` API.
    PartReplaced {
        part: MultipartPart,
        updated_at_ms: i64,
    },
    PartReserved {
        pending: PendingPart,
        created_at_ms: i64,
    },
    PartCommitted {
        pending: PendingPart,
        part: MultipartPart,
        updated_at_ms: i64,
    },
    ArtifactDeleted {
        artifact_key: String,
        updated_at_ms: i64,
    },
    CompletionAcquired {
        fingerprint: String,
        selected_parts: Vec<CompletePart>,
        owner: String,
        lease_expires_at_ms: i64,
        fencing_token: u64,
        updated_at_ms: i64,
    },
    CompletionRenewed {
        fencing_token: u64,
        lease_expires_at_ms: i64,
        updated_at_ms: i64,
    },
    DestinationCommitBegun {
        permit: DestinationCommitPermit,
        publishing_started_at_ms: i64,
    },
    DestinationCommitRecorded {
        permit: DestinationCommitPermit,
        record: DestinationCommitRecord,
        updated_at_ms: i64,
    },
    DestinationCommitReleased {
        permit: DestinationCommitPermit,
        updated_at_ms: i64,
    },
    CompletionCompleted {
        permit: DestinationCommitPermit,
        result: MultipartCompletionResult,
        completed_at_ms: i64,
        tombstone_until_ms: i64,
    },
    DestinationCommitReferenceCleared {
        expected_operation_id: Uuid,
        updated_at_ms: i64,
    },
    UploadAborted {
        aborted_at_ms: i64,
        tombstone_until_ms: i64,
    },
    UploadExpired {
        expired_at_ms: i64,
        tombstone_until_ms: i64,
    },
    CleanupAudited {
        audit: CleanupAudit,
    },
    TerminalUploadDeleted,
    TerminalUploadRetired {
        retired_at_ms: i64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReducerApply {
    Applied,
    ExactDuplicate,
    CompactedDuplicate,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub(crate) enum FileMultipartReducerError {
    #[error("unsupported file multipart schema version {0}")]
    UnsupportedVersion(u32),
    #[error("file multipart event sequence is invalid")]
    InvalidSequence,
    #[error("file multipart event duplicate conflicts with persisted history")]
    ConflictingDuplicate,
    #[error("file multipart upload identity conflicts with persisted identity")]
    IdentityConflict,
    #[error("file multipart event references unknown state")]
    UnknownReference,
    #[error("file multipart lifecycle transition is invalid")]
    IllegalLifecycle,
    #[error("file multipart completion fence is invalid")]
    InvalidFence,
    #[error("file multipart destination permit is invalid")]
    InvalidPermit,
    #[error("file multipart part state is invalid")]
    InvalidPart,
    #[error("file multipart accounting overflow, underflow, or limit violation")]
    InvalidAccounting,
    #[error("file multipart immutable completion data conflicts")]
    CompletionConflict,
    #[error("file multipart expiry or timestamp is invalid")]
    InvalidExpiry,
    #[error("file multipart audit or evidence bound exceeded")]
    BoundExceeded,
    #[error("file multipart snapshot is corrupt")]
    CorruptSnapshot,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FileMultipartQuotaUsage {
    pub staged_bytes: u64,
    pub reserved_bytes: u64,
    pub active_uploads: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FileMultipartAggregateQuotas {
    pub tenants: BTreeMap<String, FileMultipartQuotaUsage>,
    pub global: FileMultipartQuotaUsage,
}

pub(crate) struct FileMultipartReducer {
    snapshot: FileMultipartSnapshotV1,
    replay_floor: u64,
    replayed: BTreeMap<u64, Vec<u8>>,
    event_ids: BTreeMap<Uuid, u64>,
}

impl FileMultipartReducer {
    pub(crate) fn empty() -> Self {
        Self {
            snapshot: FileMultipartSnapshotV1::default(),
            replay_floor: 0,
            replayed: BTreeMap::new(),
            event_ids: BTreeMap::new(),
        }
    }

    pub(crate) fn from_snapshot(
        snapshot: FileMultipartSnapshotV1,
    ) -> Result<Self, FileMultipartReducerError> {
        validate_snapshot(&snapshot)?;
        Ok(Self {
            replay_floor: snapshot.final_event_sequence,
            snapshot,
            replayed: BTreeMap::new(),
            event_ids: BTreeMap::new(),
        })
    }

    pub(crate) fn snapshot(&self) -> &FileMultipartSnapshotV1 {
        &self.snapshot
    }

    pub(crate) fn compacted_snapshot(&self) -> FileMultipartSnapshotV1 {
        self.snapshot.clone()
    }

    pub(crate) fn apply(
        &mut self,
        event: &FileMultipartEventV1,
    ) -> Result<ReducerApply, FileMultipartReducerError> {
        if event.schema_version != FILE_MULTIPART_SCHEMA_VERSION {
            return Err(FileMultipartReducerError::UnsupportedVersion(
                event.schema_version,
            ));
        }
        if event.sequence <= self.replay_floor {
            return Ok(ReducerApply::CompactedDuplicate);
        }

        let canonical =
            serde_json::to_vec(event).map_err(|_| FileMultipartReducerError::CorruptSnapshot)?;
        if let Some(previous) = self.replayed.get(&event.sequence) {
            return if previous == &canonical {
                Ok(ReducerApply::ExactDuplicate)
            } else {
                Err(FileMultipartReducerError::ConflictingDuplicate)
            };
        }
        if self.event_ids.contains_key(&event.event_id) {
            return Err(FileMultipartReducerError::ConflictingDuplicate);
        }
        if self.replayed.len() >= MAX_REPLAY_EVENTS {
            return Err(FileMultipartReducerError::BoundExceeded);
        }
        if event.sequence
            != self
                .snapshot
                .final_event_sequence
                .checked_add(1)
                .ok_or(FileMultipartReducerError::InvalidSequence)?
        {
            return Err(FileMultipartReducerError::InvalidSequence);
        }

        let mut candidate = self.snapshot.clone();
        reduce_transition(&mut candidate, event)?;
        candidate.final_event_sequence = event.sequence;
        validate_snapshot(&candidate)?;
        self.snapshot = candidate;
        self.replayed.insert(event.sequence, canonical);
        self.event_ids.insert(event.event_id, event.sequence);
        Ok(ReducerApply::Applied)
    }
}

pub(crate) fn reconstruct_file_multipart_quotas<'a>(
    snapshots: impl IntoIterator<Item = &'a FileMultipartSnapshotV1>,
    limits: StagingQuotaLimits,
) -> Result<FileMultipartAggregateQuotas, FileMultipartReducerError> {
    let mut result = FileMultipartAggregateQuotas::default();
    let mut upload_ids = BTreeSet::new();
    for snapshot in snapshots {
        validate_snapshot(snapshot)?;
        let Some(upload) = &snapshot.upload else {
            continue;
        };
        if !upload_ids.insert(upload.identity.upload_id.clone()) {
            return Err(FileMultipartReducerError::IdentityConflict);
        }
        let active = usize::from(upload.lifecycle == MultipartLifecycle::Open);
        let tenant = result
            .tenants
            .entry(upload.identity.tenant_id.clone())
            .or_default();
        tenant.staged_bytes = checked_add(tenant.staged_bytes, upload.staged_bytes)?;
        tenant.reserved_bytes = checked_add(tenant.reserved_bytes, upload.reserved_bytes)?;
        tenant.active_uploads = tenant
            .active_uploads
            .checked_add(active)
            .ok_or(FileMultipartReducerError::InvalidAccounting)?;
        result.global.staged_bytes = checked_add(result.global.staged_bytes, upload.staged_bytes)?;
        result.global.reserved_bytes =
            checked_add(result.global.reserved_bytes, upload.reserved_bytes)?;
        result.global.active_uploads = result
            .global
            .active_uploads
            .checked_add(active)
            .ok_or(FileMultipartReducerError::InvalidAccounting)?;
    }
    for usage in result.tenants.values() {
        validate_usage(*usage, limits.tenant_bytes)?;
        if usage.active_uploads > MAX_ACTIVE_UPLOADS {
            return Err(FileMultipartReducerError::InvalidAccounting);
        }
    }
    validate_usage(result.global, limits.global_bytes)?;
    Ok(result)
}

fn reduce_transition(
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
                || pending.reserved_bytes == 0
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

fn acquire_completion(
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

fn begin_destination_commit(
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

fn terminal_without_commit(
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

fn validate_snapshot(snapshot: &FileMultipartSnapshotV1) -> Result<(), FileMultipartReducerError> {
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
                if attempt.reserved_bytes == 0
                    || attempt.part.size_bytes != 0
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

fn validate_upload(upload: &MultipartUpload) -> Result<(), FileMultipartReducerError> {
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

fn validate_identity(identity: &MultipartIdentity) -> Result<(), FileMultipartReducerError> {
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

fn validate_part_reference(
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

fn validate_selected_parts(
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

fn validate_permit(
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

fn require_upload(
    snapshot: &FileMultipartSnapshotV1,
) -> Result<&MultipartUpload, FileMultipartReducerError> {
    snapshot
        .upload
        .as_ref()
        .ok_or(FileMultipartReducerError::UnknownReference)
}

fn require_upload_mut(
    snapshot: &mut FileMultipartSnapshotV1,
) -> Result<&mut MultipartUpload, FileMultipartReducerError> {
    snapshot
        .upload
        .as_mut()
        .ok_or(FileMultipartReducerError::UnknownReference)
}

fn require_open(
    snapshot: &FileMultipartSnapshotV1,
) -> Result<&MultipartUpload, FileMultipartReducerError> {
    let upload = require_upload(snapshot)?;
    if upload.lifecycle != MultipartLifecycle::Open {
        return Err(FileMultipartReducerError::IllegalLifecycle);
    }
    Ok(upload)
}

fn attempt_index(
    snapshot: &FileMultipartSnapshotV1,
    artifact_key: &str,
) -> Result<usize, FileMultipartReducerError> {
    snapshot
        .attempts
        .iter()
        .position(|attempt| attempt.part.artifact_key == artifact_key)
        .ok_or(FileMultipartReducerError::UnknownReference)
}

fn max_attempt(snapshot: &FileMultipartSnapshotV1, part_number: u32) -> u32 {
    snapshot
        .attempts
        .iter()
        .filter(|attempt| attempt.part.part_number == part_number)
        .map(|attempt| attempt.part.attempt)
        .max()
        .unwrap_or(0)
}

fn retire_current_attempts(snapshot: &mut FileMultipartSnapshotV1) {
    for attempt in &mut snapshot.attempts {
        if attempt.lifecycle == FilePartAttemptLifecycleV1::Current {
            attempt.lifecycle = FilePartAttemptLifecycleV1::Retired;
        }
    }
}

fn set_updated_at(
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

fn calculate_accounting(
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

fn checked_add(left: u64, right: u64) -> Result<u64, FileMultipartReducerError> {
    left.checked_add(right)
        .ok_or(FileMultipartReducerError::InvalidAccounting)
}

fn validate_usage(
    usage: FileMultipartQuotaUsage,
    limit: u64,
) -> Result<(), FileMultipartReducerError> {
    if checked_add(usage.staged_bytes, usage.reserved_bytes)? > limit {
        return Err(FileMultipartReducerError::InvalidAccounting);
    }
    Ok(())
}

fn validate_tombstone(
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

fn is_terminal(lifecycle: MultipartLifecycle) -> bool {
    matches!(
        lifecycle,
        MultipartLifecycle::Completed | MultipartLifecycle::Aborted | MultipartLifecycle::Expired
    )
}

fn json_record_count(value: &serde_json::Value) -> Result<usize, FileMultipartReducerError> {
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;
    use crate::multipart_staging::MultipartSnapshot;

    const DAY_MS: i64 = 24 * 60 * 60 * 1_000;

    fn identity(upload_id: &str, tenant: &str) -> MultipartIdentity {
        MultipartIdentity {
            tenant_id: tenant.to_string(),
            credential_policy_id: "policy".to_string(),
            bucket: "bucket".to_string(),
            key: "key".to_string(),
            upload_id: upload_id.to_string(),
        }
    }

    fn upload(identity: MultipartIdentity, max_staged_bytes: u64) -> MultipartUpload {
        MultipartUpload {
            identity,
            namespace_epoch: Some(7),
            snapshot: MultipartSnapshot {
                metadata: BTreeMap::new(),
                tags: BTreeMap::new(),
                checksum_mode: Some("SHA256".to_string()),
                destination: json!({"mode": "local"}),
                plugin_snapshot: json!({"revision": "one"}),
                max_staged_bytes,
            },
            lifecycle: MultipartLifecycle::Open,
            staged_bytes: 0,
            reserved_bytes: 0,
            created_at_ms: 100,
            expires_at_ms: 10_000,
            updated_at_ms: 100,
            tombstone_until_ms: None,
            complete_request_fingerprint: None,
            completion_lease_owner: None,
            completion_lease_expires_at_ms: None,
            completion_fencing_token: 0,
            destination_operation_id: None,
            publishing_started_at_ms: None,
            destination_commit: None,
            completion_result: None,
        }
    }

    fn event(
        identity: &MultipartIdentity,
        sequence: u64,
        transition: FileMultipartTransitionV1,
    ) -> FileMultipartEventV1 {
        FileMultipartEventV1 {
            schema_version: FILE_MULTIPART_SCHEMA_VERSION,
            sequence,
            event_id: Uuid::from_u128(sequence as u128),
            identity: identity.clone(),
            transition,
        }
    }

    fn create_event(identity: &MultipartIdentity, max: u64) -> FileMultipartEventV1 {
        event(
            identity,
            1,
            FileMultipartTransitionV1::UploadCreated {
                upload: Box::new(upload(identity.clone(), max)),
            },
        )
    }

    fn pending(identity: &MultipartIdentity, number: u32, attempt: u32, bytes: u64) -> PendingPart {
        PendingPart {
            upload_id: identity.upload_id.clone(),
            part_number: number,
            attempt,
            artifact_key: format!("multipart/{}/{number}/{attempt}", identity.upload_id),
            reserved_bytes: bytes,
        }
    }

    fn part(pending: &PendingPart, bytes: u64) -> MultipartPart {
        MultipartPart {
            upload_id: pending.upload_id.clone(),
            part_number: pending.part_number,
            attempt: pending.attempt,
            artifact_key: pending.artifact_key.clone(),
            etag: format!("etag-{}", pending.attempt),
            checksum_sha256: format!("sha-{}", pending.attempt),
            size_bytes: bytes,
            created_at_ms: 200 + i64::from(pending.attempt),
        }
    }

    fn completion_result() -> MultipartCompletionResult {
        MultipartCompletionResult {
            etag: Some("final-etag".to_string()),
            checksum_sha256: "final-sha".to_string(),
            version_id: Some("version".to_string()),
            source_bytes: 200,
            size_bytes: 180,
            pipeline_evidence: None,
        }
    }

    fn apply_ok(reducer: &mut FileMultipartReducer, event: FileMultipartEventV1) {
        assert_eq!(reducer.apply(&event), Ok(ReducerApply::Applied));
    }

    fn reducer_with_current_part() -> (FileMultipartReducer, MultipartIdentity, PendingPart) {
        let identity = identity("upload", "tenant");
        let mut reducer = FileMultipartReducer::empty();
        apply_ok(&mut reducer, create_event(&identity, 1_000));
        let pending = pending(&identity, 1, 1, 400);
        apply_ok(
            &mut reducer,
            event(
                &identity,
                2,
                FileMultipartTransitionV1::PartReserved {
                    pending: pending.clone(),
                    created_at_ms: 200,
                },
            ),
        );
        apply_ok(
            &mut reducer,
            event(
                &identity,
                3,
                FileMultipartTransitionV1::PartCommitted {
                    pending: pending.clone(),
                    part: part(&pending, 300),
                    updated_at_ms: 210,
                },
            ),
        );
        (reducer, identity, pending)
    }

    #[test]
    fn full_lifecycle_replay_enforces_replacement_outbox_and_publication() {
        let (mut reducer, identity, first) = reducer_with_current_part();
        let second = pending(&identity, 1, 2, 400);
        apply_ok(
            &mut reducer,
            event(
                &identity,
                4,
                FileMultipartTransitionV1::PartReserved {
                    pending: second.clone(),
                    created_at_ms: 220,
                },
            ),
        );
        assert_eq!(
            reducer.snapshot().upload.as_ref().unwrap().staged_bytes,
            300
        );
        assert_eq!(
            reducer.snapshot().upload.as_ref().unwrap().reserved_bytes,
            400
        );
        apply_ok(
            &mut reducer,
            event(
                &identity,
                5,
                FileMultipartTransitionV1::PartCommitted {
                    pending: second.clone(),
                    part: part(&second, 200),
                    updated_at_ms: 230,
                },
            ),
        );
        assert_eq!(
            reducer.snapshot().upload.as_ref().unwrap().staged_bytes,
            500
        );
        assert_eq!(
            reducer
                .snapshot()
                .attempts
                .iter()
                .filter(|attempt| attempt.lifecycle == FilePartAttemptLifecycleV1::Current)
                .count(),
            1
        );
        apply_ok(
            &mut reducer,
            event(
                &identity,
                6,
                FileMultipartTransitionV1::ArtifactDeleted {
                    artifact_key: first.artifact_key,
                    updated_at_ms: 240,
                },
            ),
        );

        let selected = vec![CompletePart {
            part_number: 1,
            etag: "etag-2".to_string(),
            checksum_sha256: Some("sha-2".to_string()),
        }];
        apply_ok(
            &mut reducer,
            event(
                &identity,
                7,
                FileMultipartTransitionV1::CompletionAcquired {
                    fingerprint: "fingerprint".to_string(),
                    selected_parts: selected,
                    owner: "worker-a".to_string(),
                    lease_expires_at_ms: 400,
                    fencing_token: 1,
                    updated_at_ms: 300,
                },
            ),
        );
        apply_ok(
            &mut reducer,
            event(
                &identity,
                8,
                FileMultipartTransitionV1::CompletionRenewed {
                    fencing_token: 1,
                    lease_expires_at_ms: 450,
                    updated_at_ms: 310,
                },
            ),
        );
        let operation_id =
            DestinationCommitPermit::deterministic_operation_id(&identity, "fingerprint");
        let permit = DestinationCommitPermit {
            upload_id: identity.upload_id.clone(),
            completion_fingerprint: "fingerprint".to_string(),
            fencing_token: 1,
            operation_id,
        };
        apply_ok(
            &mut reducer,
            event(
                &identity,
                9,
                FileMultipartTransitionV1::DestinationCommitBegun {
                    permit: permit.clone(),
                    publishing_started_at_ms: 320,
                },
            ),
        );
        let result = completion_result();
        apply_ok(
            &mut reducer,
            event(
                &identity,
                10,
                FileMultipartTransitionV1::DestinationCommitRecorded {
                    permit: permit.clone(),
                    record: DestinationCommitRecord {
                        operation_id,
                        result: result.clone(),
                        committed_at_ms: 330,
                    },
                    updated_at_ms: 330,
                },
            ),
        );
        apply_ok(
            &mut reducer,
            event(
                &identity,
                11,
                FileMultipartTransitionV1::CompletionCompleted {
                    permit,
                    result,
                    completed_at_ms: 340,
                    tombstone_until_ms: 340 + DAY_MS,
                },
            ),
        );
        assert_eq!(
            reducer.snapshot().upload.as_ref().unwrap().lifecycle,
            MultipartLifecycle::Completed
        );
        assert!(
            reducer
                .snapshot()
                .attempts
                .iter()
                .all(|attempt| { attempt.lifecycle == FilePartAttemptLifecycleV1::Retired })
        );
        apply_ok(
            &mut reducer,
            event(
                &identity,
                12,
                FileMultipartTransitionV1::ArtifactDeleted {
                    artifact_key: second.artifact_key,
                    updated_at_ms: 350,
                },
            ),
        );
        apply_ok(
            &mut reducer,
            event(
                &identity,
                13,
                FileMultipartTransitionV1::DestinationCommitReferenceCleared {
                    expected_operation_id: operation_id,
                    updated_at_ms: 360,
                },
            ),
        );
        apply_ok(
            &mut reducer,
            event(
                &identity,
                14,
                FileMultipartTransitionV1::CleanupAudited {
                    audit: CleanupAudit {
                        id: Uuid::from_u128(999),
                        upload_id: identity.upload_id.clone(),
                        kind: "retired".to_string(),
                        detail: json!({"evidence": [{"artifact": "gone"}]}),
                        created_at_ms: 370,
                    },
                },
            ),
        );
        apply_ok(
            &mut reducer,
            event(
                &identity,
                15,
                FileMultipartTransitionV1::TerminalUploadRetired {
                    retired_at_ms: 340 + DAY_MS,
                },
            ),
        );
        assert!(reducer.snapshot().upload.is_none());
    }

    #[test]
    fn exact_duplicate_is_idempotent_and_conflicting_duplicates_fail() {
        let identity = identity("duplicate", "tenant");
        let mut reducer = FileMultipartReducer::empty();
        let create = create_event(&identity, 100);
        assert_eq!(reducer.apply(&create), Ok(ReducerApply::Applied));
        let before = serde_json::to_value(reducer.snapshot()).unwrap();
        assert_eq!(reducer.apply(&create), Ok(ReducerApply::ExactDuplicate));
        assert_eq!(serde_json::to_value(reducer.snapshot()).unwrap(), before);

        let mut conflict = create;
        conflict.transition = FileMultipartTransitionV1::UploadCreated {
            upload: Box::new(upload(identity.clone(), 101)),
        };
        assert_eq!(
            reducer.apply(&conflict),
            Err(FileMultipartReducerError::ConflictingDuplicate)
        );
        let reused_id = FileMultipartEventV1 {
            sequence: 2,
            event_id: Uuid::from_u128(1),
            transition: FileMultipartTransitionV1::UploadAborted {
                aborted_at_ms: 200,
                tombstone_until_ms: 200 + DAY_MS,
            },
            schema_version: FILE_MULTIPART_SCHEMA_VERSION,
            identity,
        };
        assert_eq!(
            reducer.apply(&reused_id),
            Err(FileMultipartReducerError::ConflictingDuplicate)
        );
    }

    #[test]
    fn snapshot_plus_event_replay_equals_full_replay_and_skips_compacted_log() {
        let (full, identity, pending) = reducer_with_current_part();
        let events = [
            create_event(&identity, 1_000),
            event(
                &identity,
                2,
                FileMultipartTransitionV1::PartReserved {
                    pending: pending.clone(),
                    created_at_ms: 200,
                },
            ),
            event(
                &identity,
                3,
                FileMultipartTransitionV1::PartCommitted {
                    pending,
                    part: full.snapshot().attempts[0].part.clone(),
                    updated_at_ms: 210,
                },
            ),
        ];
        let mut compacted = FileMultipartReducer::from_snapshot(full.compacted_snapshot()).unwrap();
        for old in &events {
            assert_eq!(compacted.apply(old), Ok(ReducerApply::CompactedDuplicate));
        }
        assert_eq!(
            serde_json::to_value(compacted.snapshot()).unwrap(),
            serde_json::to_value(full.snapshot()).unwrap()
        );

        let abort = event(
            &identity,
            4,
            FileMultipartTransitionV1::UploadAborted {
                aborted_at_ms: 300,
                tombstone_until_ms: 300 + DAY_MS,
            },
        );
        let mut complete_replay = FileMultipartReducer::empty();
        for old in &events {
            apply_ok(&mut complete_replay, old.clone());
        }
        apply_ok(&mut complete_replay, abort.clone());
        apply_ok(&mut compacted, abort);
        assert_eq!(
            serde_json::to_value(compacted.snapshot()).unwrap(),
            serde_json::to_value(complete_replay.snapshot()).unwrap()
        );
    }

    #[test]
    fn illegal_lifecycle_fence_permit_and_reference_transitions_fail_atomically() {
        let (base, identity, current_pending) = reducer_with_current_part();
        let selected = vec![CompletePart {
            part_number: 1,
            etag: "etag-1".to_string(),
            checksum_sha256: None,
        }];
        let invalid = vec![
            FileMultipartTransitionV1::CompletionRenewed {
                fencing_token: 1,
                lease_expires_at_ms: 500,
                updated_at_ms: 300,
            },
            FileMultipartTransitionV1::ArtifactDeleted {
                artifact_key: current_pending.artifact_key,
                updated_at_ms: 300,
            },
            FileMultipartTransitionV1::CompletionAcquired {
                fingerprint: "fingerprint".to_string(),
                selected_parts: selected.clone(),
                owner: "worker".to_string(),
                lease_expires_at_ms: 400,
                fencing_token: 2,
                updated_at_ms: 300,
            },
            FileMultipartTransitionV1::DestinationCommitReferenceCleared {
                expected_operation_id: Uuid::from_u128(8),
                updated_at_ms: 300,
            },
            FileMultipartTransitionV1::PartReserved {
                pending: pending(&identity, 10_001, 1, 1),
                created_at_ms: 300,
            },
        ];
        for transition in invalid {
            let mut reducer =
                FileMultipartReducer::from_snapshot(base.compacted_snapshot()).unwrap();
            let before = serde_json::to_value(reducer.snapshot()).unwrap();
            assert!(reducer.apply(&event(&identity, 4, transition)).is_err());
            assert_eq!(serde_json::to_value(reducer.snapshot()).unwrap(), before);
        }

        let mut reducer = FileMultipartReducer::from_snapshot(base.compacted_snapshot()).unwrap();
        apply_ok(
            &mut reducer,
            event(
                &identity,
                4,
                FileMultipartTransitionV1::CompletionAcquired {
                    fingerprint: "fingerprint".to_string(),
                    selected_parts: selected,
                    owner: "worker".to_string(),
                    lease_expires_at_ms: 400,
                    fencing_token: 1,
                    updated_at_ms: 300,
                },
            ),
        );
        let stale_takeover = event(
            &identity,
            5,
            FileMultipartTransitionV1::CompletionAcquired {
                fingerprint: "fingerprint".to_string(),
                selected_parts: vec![CompletePart {
                    part_number: 1,
                    etag: "etag-1".to_string(),
                    checksum_sha256: None,
                }],
                owner: "other".to_string(),
                lease_expires_at_ms: 450,
                fencing_token: 2,
                updated_at_ms: 350,
            },
        );
        assert_eq!(
            reducer.apply(&stale_takeover),
            Err(FileMultipartReducerError::InvalidFence)
        );
    }

    #[test]
    fn unknown_and_cross_tenant_references_fail_closed() {
        let upload_identity = identity("unknown", "tenant");
        let mut reducer = FileMultipartReducer::empty();
        let reserve = event(
            &upload_identity,
            1,
            FileMultipartTransitionV1::PartReserved {
                pending: pending(&upload_identity, 1, 1, 10),
                created_at_ms: 200,
            },
        );
        assert_eq!(
            reducer.apply(&reserve),
            Err(FileMultipartReducerError::UnknownReference)
        );

        apply_ok(&mut reducer, create_event(&upload_identity, 100));
        let thief = identity("unknown", "other-tenant");
        assert_eq!(
            reducer.apply(&event(
                &thief,
                2,
                FileMultipartTransitionV1::UploadAborted {
                    aborted_at_ms: 200,
                    tombstone_until_ms: 200 + DAY_MS,
                },
            )),
            Err(FileMultipartReducerError::IdentityConflict)
        );
        assert_eq!(
            reducer.apply(&event(
                &upload_identity,
                2,
                FileMultipartTransitionV1::ArtifactDeleted {
                    artifact_key: "missing".to_string(),
                    updated_at_ms: 200,
                },
            )),
            Err(FileMultipartReducerError::UnknownReference)
        );
    }

    #[test]
    fn quota_overflow_and_aggregate_limits_are_rejected() {
        let identity = identity("quota", "tenant");
        let mut reducer = FileMultipartReducer::empty();
        apply_ok(&mut reducer, create_event(&identity, u64::MAX));
        apply_ok(
            &mut reducer,
            event(
                &identity,
                2,
                FileMultipartTransitionV1::PartReserved {
                    pending: pending(&identity, 1, 1, u64::MAX),
                    created_at_ms: 200,
                },
            ),
        );
        assert_eq!(
            reducer.apply(&event(
                &identity,
                3,
                FileMultipartTransitionV1::PartReserved {
                    pending: pending(&identity, 2, 1, 1),
                    created_at_ms: 201,
                },
            )),
            Err(FileMultipartReducerError::InvalidAccounting)
        );
        assert_eq!(reducer.snapshot().final_event_sequence, 2);

        assert_eq!(
            reconstruct_file_multipart_quotas(
                [reducer.snapshot()],
                StagingQuotaLimits::new(100, 100).unwrap(),
            ),
            Err(FileMultipartReducerError::InvalidAccounting)
        );
    }

    #[test]
    fn corrupted_snapshots_and_history_bounds_are_rejected() {
        let (reducer, identity, _) = reducer_with_current_part();
        let mut wrong_counter = reducer.compacted_snapshot();
        wrong_counter.upload.as_mut().unwrap().staged_bytes += 1;
        assert!(matches!(
            FileMultipartReducer::from_snapshot(wrong_counter),
            Err(FileMultipartReducerError::InvalidAccounting)
        ));

        let mut two_current = reducer.compacted_snapshot();
        let mut duplicate = two_current.attempts[0].clone();
        duplicate.part.attempt = 2;
        duplicate.part.artifact_key = "another-artifact".to_string();
        two_current.attempts.push(duplicate);
        two_current.upload.as_mut().unwrap().staged_bytes *= 2;
        assert!(matches!(
            FileMultipartReducer::from_snapshot(two_current),
            Err(FileMultipartReducerError::InvalidPart)
        ));

        let mut too_many_audits = reducer.compacted_snapshot();
        too_many_audits.cleanup_audits = (0..=MAX_FILE_MULTIPART_AUDITS)
            .map(|index| CleanupAudit {
                id: Uuid::from_u128(10_000 + index as u128),
                upload_id: identity.upload_id.clone(),
                kind: "cleanup".to_string(),
                detail: json!({}),
                created_at_ms: 300,
            })
            .collect();
        assert!(matches!(
            FileMultipartReducer::from_snapshot(too_many_audits),
            Err(FileMultipartReducerError::BoundExceeded)
        ));

        let mut audit_reducer =
            FileMultipartReducer::from_snapshot(reducer.compacted_snapshot()).unwrap();
        let evidence = vec![json!({}); MAX_FILE_MULTIPART_EVIDENCE_RECORDS + 1];
        assert_eq!(
            audit_reducer.apply(&event(
                &identity,
                4,
                FileMultipartTransitionV1::CleanupAudited {
                    audit: CleanupAudit {
                        id: Uuid::from_u128(5_000),
                        upload_id: identity.upload_id.clone(),
                        kind: "oversized".to_string(),
                        detail: serde_json::Value::Array(evidence),
                        created_at_ms: 300,
                    },
                },
            )),
            Err(FileMultipartReducerError::BoundExceeded)
        );
    }

    #[test]
    fn release_requires_exact_uncommitted_publishing_permit() {
        let (mut reducer, identity, _) = reducer_with_current_part();
        apply_ok(
            &mut reducer,
            event(
                &identity,
                4,
                FileMultipartTransitionV1::CompletionAcquired {
                    fingerprint: "fingerprint".to_string(),
                    selected_parts: vec![CompletePart {
                        part_number: 1,
                        etag: "etag-1".to_string(),
                        checksum_sha256: None,
                    }],
                    owner: "worker".to_string(),
                    lease_expires_at_ms: 400,
                    fencing_token: 1,
                    updated_at_ms: 300,
                },
            ),
        );
        let permit = DestinationCommitPermit {
            upload_id: identity.upload_id.clone(),
            completion_fingerprint: "fingerprint".to_string(),
            fencing_token: 1,
            operation_id: DestinationCommitPermit::deterministic_operation_id(
                &identity,
                "fingerprint",
            ),
        };
        apply_ok(
            &mut reducer,
            event(
                &identity,
                5,
                FileMultipartTransitionV1::DestinationCommitBegun {
                    permit: permit.clone(),
                    publishing_started_at_ms: 320,
                },
            ),
        );
        let mut stale = permit.clone();
        stale.fencing_token = 0;
        assert_eq!(
            reducer.apply(&event(
                &identity,
                6,
                FileMultipartTransitionV1::DestinationCommitReleased {
                    permit: stale,
                    updated_at_ms: 330,
                },
            )),
            Err(FileMultipartReducerError::InvalidPermit)
        );
        apply_ok(
            &mut reducer,
            event(
                &identity,
                6,
                FileMultipartTransitionV1::DestinationCommitReleased {
                    permit,
                    updated_at_ms: 330,
                },
            ),
        );
        assert_eq!(
            reducer.snapshot().upload.as_ref().unwrap().lifecycle,
            MultipartLifecycle::Completing
        );
    }

    #[test]
    fn expiry_requires_deadline_and_terminal_cleanup_before_deletion() {
        let (mut reducer, identity, pending) = reducer_with_current_part();
        assert_eq!(
            reducer.apply(&event(
                &identity,
                4,
                FileMultipartTransitionV1::UploadExpired {
                    expired_at_ms: 9_999,
                    tombstone_until_ms: 9_999 + DAY_MS,
                },
            )),
            Err(FileMultipartReducerError::InvalidExpiry)
        );
        apply_ok(
            &mut reducer,
            event(
                &identity,
                4,
                FileMultipartTransitionV1::UploadExpired {
                    expired_at_ms: 10_000,
                    tombstone_until_ms: 10_000 + DAY_MS,
                },
            ),
        );
        assert_eq!(
            reducer.apply(&event(
                &identity,
                5,
                FileMultipartTransitionV1::TerminalUploadDeleted,
            )),
            Err(FileMultipartReducerError::IllegalLifecycle)
        );
        apply_ok(
            &mut reducer,
            event(
                &identity,
                5,
                FileMultipartTransitionV1::ArtifactDeleted {
                    artifact_key: pending.artifact_key,
                    updated_at_ms: 10_001,
                },
            ),
        );
        apply_ok(
            &mut reducer,
            event(
                &identity,
                6,
                FileMultipartTransitionV1::TerminalUploadDeleted,
            ),
        );
        assert!(reducer.snapshot().upload.is_none());
    }

    #[test]
    fn completion_fingerprint_commit_and_result_are_immutable() {
        let (mut reducer, identity, _) = reducer_with_current_part();
        let selected = vec![CompletePart {
            part_number: 1,
            etag: "etag-1".to_string(),
            checksum_sha256: None,
        }];
        apply_ok(
            &mut reducer,
            event(
                &identity,
                4,
                FileMultipartTransitionV1::CompletionAcquired {
                    fingerprint: "fingerprint".to_string(),
                    selected_parts: selected.clone(),
                    owner: "worker".to_string(),
                    lease_expires_at_ms: 400,
                    fencing_token: 1,
                    updated_at_ms: 300,
                },
            ),
        );
        assert_eq!(
            reducer.apply(&event(
                &identity,
                5,
                FileMultipartTransitionV1::CompletionAcquired {
                    fingerprint: "different".to_string(),
                    selected_parts: selected,
                    owner: "other".to_string(),
                    lease_expires_at_ms: 500,
                    fencing_token: 2,
                    updated_at_ms: 401,
                },
            )),
            Err(FileMultipartReducerError::CompletionConflict)
        );
        let permit = DestinationCommitPermit {
            upload_id: identity.upload_id.clone(),
            completion_fingerprint: "fingerprint".to_string(),
            fencing_token: 1,
            operation_id: DestinationCommitPermit::deterministic_operation_id(
                &identity,
                "fingerprint",
            ),
        };
        apply_ok(
            &mut reducer,
            event(
                &identity,
                5,
                FileMultipartTransitionV1::DestinationCommitBegun {
                    permit: permit.clone(),
                    publishing_started_at_ms: 320,
                },
            ),
        );
        let result = completion_result();
        apply_ok(
            &mut reducer,
            event(
                &identity,
                6,
                FileMultipartTransitionV1::DestinationCommitRecorded {
                    permit: permit.clone(),
                    record: DestinationCommitRecord {
                        operation_id: permit.operation_id,
                        result: result.clone(),
                        committed_at_ms: 330,
                    },
                    updated_at_ms: 330,
                },
            ),
        );
        let mut conflicting = result.clone();
        conflicting.checksum_sha256 = "different".to_string();
        assert_eq!(
            reducer.apply(&event(
                &identity,
                7,
                FileMultipartTransitionV1::DestinationCommitRecorded {
                    permit: permit.clone(),
                    record: DestinationCommitRecord {
                        operation_id: permit.operation_id,
                        result: conflicting.clone(),
                        committed_at_ms: 331,
                    },
                    updated_at_ms: 331,
                },
            )),
            Err(FileMultipartReducerError::CompletionConflict)
        );
        assert_eq!(
            reducer.apply(&event(
                &identity,
                7,
                FileMultipartTransitionV1::CompletionCompleted {
                    permit,
                    result: conflicting,
                    completed_at_ms: 340,
                    tombstone_until_ms: 340 + DAY_MS,
                },
            )),
            Err(FileMultipartReducerError::CompletionConflict)
        );
    }

    proptest! {
        #[test]
        fn aggregate_quota_reconstruction_is_deterministic(sizes in prop::collection::vec(1u64..10_000, 1..64)) {
            let identity = identity("property", "tenant");
            let max = sizes.iter().copied().sum::<u64>();
            let mut reducer = FileMultipartReducer::empty();
            apply_ok(&mut reducer, create_event(&identity, max));
            for (index, size) in sizes.iter().copied().enumerate() {
                let number = u32::try_from(index + 1).unwrap();
                let pending = pending(&identity, number, 1, size);
                apply_ok(
                    &mut reducer,
                    event(
                        &identity,
                        u64::try_from(index + 2).unwrap(),
                        FileMultipartTransitionV1::PartReplaced {
                            part: part(&pending, size),
                            updated_at_ms: 200 + i64::try_from(index).unwrap(),
                        },
                    ),
                );
            }
            let limits = StagingQuotaLimits::new(max, max).unwrap();
            let first = reconstruct_file_multipart_quotas([reducer.snapshot()], limits).unwrap();
            let serialized = serde_json::to_vec(reducer.snapshot()).unwrap();
            let restored: FileMultipartSnapshotV1 = serde_json::from_slice(&serialized).unwrap();
            let second = reconstruct_file_multipart_quotas([&restored], limits).unwrap();
            prop_assert_eq!(&first, &second);
            prop_assert_eq!(first.global.staged_bytes, max);
            prop_assert_eq!(first.global.reserved_bytes, 0);
        }
    }
}
