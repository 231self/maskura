//! Pure state reduction for the durable local multipart repository.
//!
//! File framing, checksums, locking, and durable append are intentionally left
//! to the Task 8 adapter. This module owns the versioned persistence vocabulary
//! and rejects state that the adapter must never publish.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::filesystem_persistence::{
    EventLog, FilesystemPersistence, PersistenceError, create_private_dir_all, sync_parent,
};
use crate::multipart_staging::{
    AbortMutationError, CleanupAudit, CleanupCandidate, CompletePart, CompletionAcquire,
    CompletionLease, DEFAULT_EXPIRY, DestinationCommitPermit, DestinationCommitRecord,
    ListMultipartUploadsPage, ListMultipartUploadsRequest, MAX_ACTIVE_UPLOADS, MAX_PARTS,
    MultipartCompletionResult, MultipartIdentity, MultipartLifecycle, MultipartPart,
    MultipartRepository, MultipartUpload, PendingPart, PublishingMultipartUpload,
    RECONCILIATION_GRACE, RetiredMultipartUpload, StagingError, StagingQuotaLimits, now_ms,
    paginate_multipart_uploads, permit_matches, publishing_upload, same_identity,
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

const SNAPSHOT_FILE: &str = "snapshot.json";
const EVENT_LOG_FILE: &str = "events.log";

struct FileMultipartEntry {
    directory: PathBuf,
    reducer: FileMultipartReducer,
    log: EventLog,
}

struct FileMultipartState {
    uploads_root: PathBuf,
    persistence: FilesystemPersistence,
    quotas: StagingQuotaLimits,
    entries: BTreeMap<String, FileMultipartEntry>,
    poisoned: Option<String>,
}

#[derive(Debug)]
struct MutationFailure {
    error: StagingError,
    unknown: bool,
}

/// Durable, single-process multipart repository for a locked local storage root.
pub(crate) struct FileMultipartRepository {
    state: Mutex<FileMultipartState>,
}

impl std::fmt::Debug for FileMultipartRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileMultipartRepository")
            .finish_non_exhaustive()
    }
}

impl FileMultipartRepository {
    pub(crate) fn open(
        multipart_root: PathBuf,
        quotas: StagingQuotaLimits,
    ) -> Result<Self, StagingError> {
        Self::open_with_persistence(multipart_root, quotas, FilesystemPersistence::default())
    }

    fn open_with_persistence(
        multipart_root: PathBuf,
        quotas: StagingQuotaLimits,
        persistence: FilesystemPersistence,
    ) -> Result<Self, StagingError> {
        let uploads_root = multipart_root.join("uploads");
        prepare_uploads_root(&uploads_root)?;
        let entries = load_entries(&uploads_root, &persistence, quotas)?;
        Ok(Self {
            state: Mutex::new(FileMultipartState {
                uploads_root,
                persistence,
                quotas,
                entries,
                poisoned: None,
            }),
        })
    }

    #[cfg(test)]
    fn open_for_test(
        multipart_root: PathBuf,
        quotas: StagingQuotaLimits,
        persistence: FilesystemPersistence,
    ) -> Result<Self, StagingError> {
        Self::open_with_persistence(multipart_root, quotas, persistence)
    }
}

impl FileMultipartState {
    fn ensure_healthy(&self) -> Result<(), StagingError> {
        match &self.poisoned {
            Some(error) => Err(StagingError::Persistence(error.clone())),
            None => Ok(()),
        }
    }

    fn upload(&self, upload_id: &str) -> Result<&MultipartUpload, StagingError> {
        self.entries
            .get(upload_id)
            .and_then(|entry| entry.reducer.snapshot().upload.as_ref())
            .ok_or(StagingError::NotFound)
    }

    fn authorized(&self, identity: &MultipartIdentity) -> Result<&MultipartUpload, StagingError> {
        let upload = self.upload(&identity.upload_id)?;
        same_identity(upload, identity)
            .then_some(upload)
            .ok_or(StagingError::NotFound)
    }

    fn snapshots_with_candidate<'a>(
        &'a self,
        upload_id: &str,
        candidate: &'a FileMultipartSnapshotV1,
    ) -> impl Iterator<Item = &'a FileMultipartSnapshotV1> {
        self.entries
            .iter()
            .filter(move |(id, _)| id.as_str() != upload_id)
            .map(|(_, entry)| entry.reducer.snapshot())
            .chain(std::iter::once(candidate))
    }

    fn validate_candidate(
        &self,
        upload_id: &str,
        candidate: &FileMultipartSnapshotV1,
    ) -> Result<(), StagingError> {
        reconstruct_file_multipart_quotas(
            self.snapshots_with_candidate(upload_id, candidate),
            self.quotas,
        )
        .map(|_| ())
        .map_err(reducer_persistence_error)
    }

    fn reload_after_unknown(&mut self) {
        match load_entries(&self.uploads_root, &self.persistence, self.quotas) {
            Ok(entries) => {
                self.entries = entries;
                self.poisoned = None;
            }
            Err(error) => self.poisoned = Some(error.to_string()),
        }
    }

    fn apply_transition(
        &mut self,
        upload_id: &str,
        transition: FileMultipartTransitionV1,
    ) -> Result<(), MutationFailure> {
        self.ensure_healthy().map_err(pre_mutation)?;
        let entry = self.entries.get(upload_id).ok_or_else(|| {
            pre_mutation(StagingError::Persistence(
                "multipart upload state disappeared".to_string(),
            ))
        })?;
        let identity = entry
            .reducer
            .snapshot()
            .identity
            .clone()
            .ok_or_else(|| pre_mutation(corrupt_state("multipart identity is missing")))?;
        let sequence = entry
            .reducer
            .snapshot()
            .final_event_sequence
            .checked_add(1)
            .ok_or_else(|| pre_mutation(corrupt_state("multipart event sequence exhausted")))?;
        let event = FileMultipartEventV1 {
            schema_version: FILE_MULTIPART_SCHEMA_VERSION,
            sequence,
            event_id: Uuid::now_v7(),
            identity,
            transition,
        };
        let mut candidate = FileMultipartReducer::from_snapshot(entry.reducer.compacted_snapshot())
            .map_err(|error| pre_mutation(reducer_persistence_error(error)))?;
        candidate
            .apply(&event)
            .map_err(|error| pre_mutation(reducer_persistence_error(error)))?;
        self.validate_candidate(upload_id, candidate.snapshot())
            .map_err(pre_mutation)?;

        let append = self
            .entries
            .get_mut(upload_id)
            .expect("entry checked above")
            .log
            .append(&event);
        if let Err(error) = append {
            let unknown = error.mutation_unknown();
            if unknown {
                self.reload_after_unknown();
            }
            return Err(MutationFailure {
                error: persistence_error(error),
                unknown,
            });
        }

        let entry = self
            .entries
            .get_mut(upload_id)
            .expect("entry checked above");
        entry.reducer = candidate;
        if entry.log.should_compact() {
            let snapshot = entry.reducer.compacted_snapshot();
            match entry
                .log
                .compact(&entry.directory.join(SNAPSHOT_FILE), &snapshot)
            {
                Ok(()) => {
                    entry.reducer = FileMultipartReducer::from_snapshot(snapshot)
                        .expect("validated compacted multipart snapshot");
                }
                Err(error) if error.mutation_unknown() => self.reload_after_unknown(),
                Err(_) => {}
            }
        }
        self.ensure_healthy().map_err(|error| MutationFailure {
            error,
            unknown: true,
        })
    }

    fn create_upload(&mut self, upload: MultipartUpload) -> Result<(), MutationFailure> {
        self.ensure_healthy().map_err(pre_mutation)?;
        let upload_id = upload.identity.upload_id.clone();
        validate_upload_directory_name(&upload_id).map_err(pre_mutation)?;
        if self.entries.contains_key(&upload_id) {
            return Err(pre_mutation(StagingError::Persistence(
                "duplicate upload id".to_string(),
            )));
        }
        let event = FileMultipartEventV1 {
            schema_version: FILE_MULTIPART_SCHEMA_VERSION,
            sequence: 1,
            event_id: Uuid::now_v7(),
            identity: upload.identity.clone(),
            transition: FileMultipartTransitionV1::UploadCreated {
                upload: Box::new(upload),
            },
        };
        let mut candidate = FileMultipartReducer::empty();
        candidate
            .apply(&event)
            .map_err(|error| pre_mutation(reducer_persistence_error(error)))?;
        self.validate_candidate(&upload_id, candidate.snapshot())
            .map_err(pre_mutation)?;

        let directory = self.uploads_root.join(&upload_id);
        create_private_dir_all(&directory)
            .map_err(|error| pre_mutation(persistence_error(error)))?;
        sync_parent(&directory).map_err(|error| {
            pre_mutation(StagingError::Persistence(format!(
                "multipart upload directory sync failed: {error}"
            )))
        })?;
        let opened = self
            .persistence
            .open_event_log::<FileMultipartEventV1>(directory.join(EVENT_LOG_FILE), 0);
        let (mut log, existing) = match opened {
            Ok(value) => value,
            Err(error) => return Err(pre_mutation(persistence_error(error))),
        };
        if !existing.is_empty() {
            return Err(pre_mutation(corrupt_state(
                "new multipart event log was not empty",
            )));
        }
        match log.append(&event) {
            Ok(1) => {
                self.entries.insert(
                    upload_id,
                    FileMultipartEntry {
                        directory,
                        reducer: candidate,
                        log,
                    },
                );
                Ok(())
            }
            Ok(_) => Err(pre_mutation(corrupt_state(
                "new multipart event sequence is invalid",
            ))),
            Err(error) => {
                let unknown = error.mutation_unknown();
                if unknown {
                    self.reload_after_unknown();
                } else {
                    let _ = std::fs::remove_file(directory.join(EVENT_LOG_FILE));
                    let _ = std::fs::remove_dir(&directory);
                }
                Err(MutationFailure {
                    error: persistence_error(error),
                    unknown,
                })
            }
        }
    }
}

#[async_trait]
impl MultipartRepository for FileMultipartRepository {
    fn is_durable(&self) -> bool {
        true
    }

    async fn create(&self, upload: MultipartUpload) -> Result<(), StagingError> {
        self.state
            .lock()
            .await
            .create_upload(upload)
            .map_err(|failure| failure.error)
    }

    async fn get_authorized(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<MultipartUpload, StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        state.authorized(identity).cloned()
    }

    async fn list_authorized_uploads(
        &self,
        request: &ListMultipartUploadsRequest,
    ) -> Result<ListMultipartUploadsPage, StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        let uploads = state
            .entries
            .values()
            .filter_map(|entry| entry.reducer.snapshot().upload.as_ref())
            .filter(|upload| {
                upload.identity.tenant_id == request.tenant_id
                    && upload.identity.credential_policy_id == request.credential_policy_id
                    && upload.identity.bucket == request.bucket
                    && matches!(
                        upload.lifecycle,
                        MultipartLifecycle::Open
                            | MultipartLifecycle::Completing
                            | MultipartLifecycle::Publishing
                    )
            })
            .cloned()
            .collect();
        paginate_multipart_uploads(uploads, request)
    }

    async fn replace_part(
        &self,
        identity: &MultipartIdentity,
        part: MultipartPart,
    ) -> Result<Option<MultipartPart>, StagingError> {
        if part.upload_id != identity.upload_id
            || part.part_number == 0
            || part.part_number > MAX_PARTS
        {
            return Err(StagingError::InvalidPart);
        }
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?;
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(StagingError::NotOpen);
        }
        let previous = current_part(
            state.entries.get(&identity.upload_id).unwrap(),
            part.part_number,
        );
        if previous
            .as_ref()
            .is_some_and(|old| part.attempt <= old.attempt)
        {
            return Err(StagingError::Persistence(
                "stale part replacement".to_string(),
            ));
        }
        let updated_at_ms = now_ms().max(upload.updated_at_ms);
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::PartReplaced {
                    part,
                    updated_at_ms,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::QuotaExceeded))?;
        Ok(previous)
    }

    async fn begin_part(
        &self,
        identity: &MultipartIdentity,
        part_number: u32,
        reserved_bytes: u64,
        now: i64,
    ) -> Result<PendingPart, StagingError> {
        if part_number == 0 || part_number > MAX_PARTS {
            return Err(StagingError::InvalidPart);
        }
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?;
        if upload.lifecycle != MultipartLifecycle::Open || upload.expires_at_ms <= now {
            return Err(StagingError::NotOpen);
        }
        let entry = state.entries.get(&identity.upload_id).unwrap();
        let attempt = entry
            .reducer
            .snapshot()
            .attempts
            .iter()
            .filter(|attempt| attempt.part.part_number == part_number)
            .map(|attempt| attempt.part.attempt)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StagingError::InvalidPart)?;
        let pending = PendingPart {
            upload_id: identity.upload_id.clone(),
            part_number,
            attempt,
            artifact_key: format!(
                "multipart/{}/{}/{part_number}/{attempt}",
                identity.tenant_id, identity.upload_id
            ),
            reserved_bytes,
        };
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::PartReserved {
                    pending: pending.clone(),
                    created_at_ms: now,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::QuotaExceeded))?;
        Ok(pending)
    }

    async fn commit_part(
        &self,
        identity: &MultipartIdentity,
        pending: &PendingPart,
        part: MultipartPart,
    ) -> Result<Vec<MultipartPart>, StagingError> {
        if part.upload_id != pending.upload_id
            || pending.upload_id != identity.upload_id
            || part.part_number != pending.part_number
            || part.attempt != pending.attempt
            || part.artifact_key != pending.artifact_key
            || part.size_bytes > pending.reserved_bytes
        {
            return Err(StagingError::InvalidPart);
        }
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?;
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(StagingError::NotOpen);
        }
        let previous = current_part(
            state.entries.get(&identity.upload_id).unwrap(),
            part.part_number,
        )
        .into_iter()
        .collect();
        let updated_at_ms = now_ms().max(upload.updated_at_ms);
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::PartCommitted {
                    pending: pending.clone(),
                    part,
                    updated_at_ms,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::NotFound))?;
        Ok(previous)
    }

    async fn discard_pending(
        &self,
        identity: &MultipartIdentity,
        pending: &PendingPart,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        state.authorized(identity)?;
        if pending.upload_id != identity.upload_id {
            return Err(StagingError::NotFound);
        }
        let Some((upload_id, updated_at_ms)) = artifact_owner(&state, &pending.artifact_key) else {
            return Ok(());
        };
        if upload_id != identity.upload_id {
            return Err(StagingError::NotFound);
        }
        state
            .apply_transition(
                &upload_id,
                FileMultipartTransitionV1::ArtifactDeleted {
                    artifact_key: pending.artifact_key.clone(),
                    updated_at_ms,
                },
            )
            .map_err(|failure| failure.error)
    }

    async fn cleanup_candidates(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<CleanupCandidate>, StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        let cutoff = now.saturating_sub(RECONCILIATION_GRACE.as_millis() as i64);
        let mut candidates = Vec::new();
        for entry in state.entries.values() {
            let Some(upload) = &entry.reducer.snapshot().upload else {
                continue;
            };
            for attempt in &entry.reducer.snapshot().attempts {
                let eligible = matches!(
                    upload.lifecycle,
                    MultipartLifecycle::Completed
                        | MultipartLifecycle::Aborted
                        | MultipartLifecycle::Expired
                ) || attempt.lifecycle == FilePartAttemptLifecycleV1::Retired
                    || attempt.lifecycle == FilePartAttemptLifecycleV1::Pending
                        && attempt.part.created_at_ms <= cutoff;
                if eligible {
                    candidates.push((
                        attempt.part.created_at_ms,
                        CleanupCandidate {
                            upload_id: upload.identity.upload_id.clone(),
                            artifact_key: attempt.part.artifact_key.clone(),
                        },
                    ));
                }
            }
        }
        candidates.sort_by(|left, right| {
            (left.0, &left.1.artifact_key).cmp(&(right.0, &right.1.artifact_key))
        });
        Ok(candidates
            .into_iter()
            .take(limit)
            .map(|(_, candidate)| candidate)
            .collect())
    }

    async fn confirm_artifact_deleted(&self, artifact_key: &str) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        state.ensure_healthy()?;
        let Some((upload_id, updated_at_ms)) = artifact_owner(&state, artifact_key) else {
            return Ok(());
        };
        state
            .apply_transition(
                &upload_id,
                FileMultipartTransitionV1::ArtifactDeleted {
                    artifact_key: artifact_key.to_string(),
                    updated_at_ms,
                },
            )
            .map_err(|failure| failure.error)
    }

    async fn known_artifact_keys(&self) -> Result<HashMap<String, i64>, StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        Ok(state
            .entries
            .values()
            .flat_map(|entry| &entry.reducer.snapshot().attempts)
            .map(|attempt| {
                (
                    attempt.part.artifact_key.clone(),
                    attempt.part.created_at_ms,
                )
            })
            .collect())
    }

    async fn list_parts(
        &self,
        identity: &MultipartIdentity,
        marker: u32,
        limit: usize,
    ) -> Result<(Vec<MultipartPart>, bool), StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        state.authorized(identity)?;
        let mut parts = current_parts(state.entries.get(&identity.upload_id).unwrap());
        parts.retain(|part| part.part_number > marker);
        let truncated = parts.len() > limit;
        parts.truncate(limit);
        Ok((parts, truncated))
    }

    async fn acquire_completion(
        &self,
        identity: &MultipartIdentity,
        fingerprint: &str,
        parts: &[CompletePart],
        owner: &str,
        lease_expires_at_ms: i64,
        now: i64,
    ) -> Result<CompletionAcquire, StagingError> {
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?.clone();
        match upload.lifecycle {
            MultipartLifecycle::Completed => {
                let result = upload
                    .completion_result
                    .ok_or_else(|| corrupt_state("completed multipart upload has no result"))?;
                return if upload.complete_request_fingerprint.as_deref() == Some(fingerprint) {
                    Ok(CompletionAcquire::Replayed(result))
                } else {
                    Err(StagingError::CompletionConflict)
                };
            }
            MultipartLifecycle::Publishing => {
                return if upload.complete_request_fingerprint.as_deref() == Some(fingerprint) {
                    Ok(CompletionAcquire::Busy)
                } else {
                    Err(StagingError::CompletionConflict)
                };
            }
            MultipartLifecycle::Aborted | MultipartLifecycle::Expired => {
                return Err(StagingError::NotOpen);
            }
            MultipartLifecycle::Completing
                if upload.complete_request_fingerprint.as_deref() != Some(fingerprint) =>
            {
                return Err(StagingError::CompletionConflict);
            }
            MultipartLifecycle::Completing
                if upload
                    .completion_lease_expires_at_ms
                    .is_some_and(|expiry| expiry > now) =>
            {
                return Ok(CompletionAcquire::Busy);
            }
            MultipartLifecycle::Open if upload.expires_at_ms <= now => {
                return Err(StagingError::NotOpen);
            }
            _ => {}
        }
        let cleanup_parts = current_parts(state.entries.get(&identity.upload_id).unwrap());
        let selected_parts = select_parts(&cleanup_parts, parts)?;
        let fencing_token = upload
            .completion_fencing_token
            .checked_add(1)
            .ok_or_else(|| corrupt_state("completion fencing token exhausted"))?;
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::CompletionAcquired {
                    fingerprint: fingerprint.to_string(),
                    selected_parts: parts.to_vec(),
                    owner: owner.to_string(),
                    lease_expires_at_ms,
                    fencing_token,
                    updated_at_ms: now,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))?;
        Ok(CompletionAcquire::Acquired(CompletionLease {
            fencing_token,
            selected_parts,
            cleanup_parts,
        }))
    }

    async fn renew_completion(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        lease_expires_at_ms: i64,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?;
        if upload.lifecycle != MultipartLifecycle::Completing
            || upload.completion_fencing_token != fencing_token
        {
            return Err(StagingError::Fenced);
        }
        let updated_at_ms = now_ms().max(upload.updated_at_ms);
        if lease_expires_at_ms <= updated_at_ms {
            return Err(StagingError::Fenced);
        }
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::CompletionRenewed {
                    fencing_token,
                    lease_expires_at_ms,
                    updated_at_ms,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))
    }

    async fn check_completion_lease(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        now: i64,
    ) -> Result<(), StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        let upload = state.authorized(identity)?;
        (upload.lifecycle == MultipartLifecycle::Completing
            && upload.completion_fencing_token == fencing_token
            && upload
                .completion_lease_expires_at_ms
                .is_some_and(|expiry| expiry > now))
        .then_some(())
        .ok_or(StagingError::Fenced)
    }

    async fn begin_destination_commit(
        &self,
        identity: &MultipartIdentity,
        fingerprint: &str,
        fencing_token: u64,
        operation_id: Uuid,
        now: i64,
    ) -> Result<DestinationCommitPermit, StagingError> {
        let permit = DestinationCommitPermit {
            upload_id: identity.upload_id.clone(),
            completion_fingerprint: fingerprint.to_string(),
            fencing_token,
            operation_id,
        };
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?;
        if operation_id
            != DestinationCommitPermit::deterministic_operation_id(identity, fingerprint)
            || upload.lifecycle != MultipartLifecycle::Completing
            || upload.complete_request_fingerprint.as_deref() != Some(fingerprint)
            || upload.completion_fencing_token != fencing_token
            || upload
                .completion_lease_expires_at_ms
                .is_none_or(|expiry| expiry <= now)
        {
            return Err(StagingError::Fenced);
        }
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::DestinationCommitBegun {
                    permit: permit.clone(),
                    publishing_started_at_ms: now,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))?;
        Ok(permit)
    }

    async fn validate_destination_commit_permit(
        &self,
        permit: &DestinationCommitPermit,
    ) -> Result<(), StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        state
            .upload(&permit.upload_id)
            .is_ok_and(|upload| permit_matches(upload, permit))
            .then_some(())
            .ok_or(StagingError::Fenced)
    }

    async fn record_destination_commit(
        &self,
        permit: &DestinationCommitPermit,
        result: MultipartCompletionResult,
        now: i64,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state
            .upload(&permit.upload_id)
            .map_err(|_| StagingError::Fenced)?;
        if !permit_matches(upload, permit) {
            return Err(StagingError::Fenced);
        }
        let record = DestinationCommitRecord {
            operation_id: permit.operation_id,
            result,
            committed_at_ms: now,
        };
        if let Some(existing) = &upload.destination_commit {
            return if existing.operation_id == record.operation_id
                && existing.result == record.result
            {
                Ok(())
            } else {
                Err(StagingError::CompletionConflict)
            };
        }
        state
            .apply_transition(
                &permit.upload_id,
                FileMultipartTransitionV1::DestinationCommitRecorded {
                    permit: permit.clone(),
                    record,
                    updated_at_ms: now,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))
    }

    async fn release_destination_commit_after_proven_absence(
        &self,
        permit: &DestinationCommitPermit,
        now: i64,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state
            .upload(&permit.upload_id)
            .map_err(|_| StagingError::Fenced)?;
        if !permit_matches(upload, permit) || upload.destination_commit.is_some() {
            return Err(StagingError::Fenced);
        }
        state
            .apply_transition(
                &permit.upload_id,
                FileMultipartTransitionV1::DestinationCommitReleased {
                    permit: permit.clone(),
                    updated_at_ms: now,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))
    }

    async fn publishing_uploads(
        &self,
        limit: usize,
    ) -> Result<Vec<PublishingMultipartUpload>, StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        let mut uploads = state
            .entries
            .values()
            .filter_map(|entry| entry.reducer.snapshot().upload.as_ref())
            .filter(|upload| upload.lifecycle == MultipartLifecycle::Publishing)
            .cloned()
            .collect::<Vec<_>>();
        uploads.sort_by_key(|upload| {
            (
                upload.publishing_started_at_ms.unwrap_or(i64::MIN),
                upload.identity.upload_id.clone(),
            )
        });
        uploads
            .into_iter()
            .take(limit)
            .map(publishing_upload)
            .collect()
    }

    async fn complete_completion(
        &self,
        identity: &MultipartIdentity,
        permit: &DestinationCommitPermit,
        result: MultipartCompletionResult,
        now: i64,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?;
        if !permit_matches(upload, permit)
            || upload
                .destination_commit
                .as_ref()
                .map(|record| &record.result)
                != Some(&result)
        {
            return Err(StagingError::Fenced);
        }
        let tombstone_until_ms = now
            .checked_add(DEFAULT_EXPIRY.as_millis() as i64)
            .ok_or_else(|| corrupt_state("multipart tombstone timestamp overflow"))?;
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::CompletionCompleted {
                    permit: permit.clone(),
                    result,
                    completed_at_ms: now,
                    tombstone_until_ms,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))
    }

    async fn clear_destination_commit_reference(
        &self,
        identity: &MultipartIdentity,
        expected_operation_id: Uuid,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?;
        if !matches!(
            upload.lifecycle,
            MultipartLifecycle::Completed
                | MultipartLifecycle::Aborted
                | MultipartLifecycle::Expired
        ) || upload.destination_operation_id != Some(expected_operation_id)
        {
            return Err(StagingError::Fenced);
        }
        let updated_at_ms = now_ms().max(upload.updated_at_ms);
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::DestinationCommitReferenceCleared {
                    expected_operation_id,
                    updated_at_ms,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))
    }

    async fn abort(
        &self,
        identity: &MultipartIdentity,
        now: i64,
    ) -> Result<Vec<MultipartPart>, AbortMutationError> {
        let mut state = self.state.lock().await;
        let upload = state
            .authorized(identity)
            .map_err(AbortMutationError::PreMutation)?;
        if upload.lifecycle != MultipartLifecycle::Open {
            if upload.lifecycle == MultipartLifecycle::Aborted {
                return Ok(Vec::new());
            }
            return Err(AbortMutationError::PreMutation(StagingError::NotOpen));
        }
        let parts = current_parts(state.entries.get(&identity.upload_id).unwrap());
        let tombstone_until_ms = now
            .checked_add(DEFAULT_EXPIRY.as_millis() as i64)
            .ok_or(AbortMutationError::PreMutation(StagingError::Unavailable))?;
        match state.apply_transition(
            &identity.upload_id,
            FileMultipartTransitionV1::UploadAborted {
                aborted_at_ms: now,
                tombstone_until_ms,
            },
        ) {
            Ok(()) => Ok(parts),
            Err(failure) if failure.unknown => {
                Err(AbortMutationError::MutationUnknown(failure.error))
            }
            Err(failure) => Err(AbortMutationError::PreMutation(failure.error)),
        }
    }

    async fn delete_terminal_upload(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?;
        if !matches!(
            upload.lifecycle,
            MultipartLifecycle::Aborted | MultipartLifecycle::Expired
        ) || upload.destination_operation_id.is_some()
            || !state
                .entries
                .get(&identity.upload_id)
                .unwrap()
                .reducer
                .snapshot()
                .attempts
                .is_empty()
        {
            return Err(StagingError::Persistence(
                "multipart artifacts remain after cleanup".to_string(),
            ));
        }
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::TerminalUploadDeleted,
            )
            .map_err(|failure| failure.error)
    }

    async fn terminal_upload_candidates(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<MultipartIdentity>, StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        let mut uploads = state
            .entries
            .values()
            .filter_map(|entry| entry.reducer.snapshot().upload.as_ref())
            .filter(|upload| {
                matches!(
                    upload.lifecycle,
                    MultipartLifecycle::Completed
                        | MultipartLifecycle::Aborted
                        | MultipartLifecycle::Expired
                ) && upload.tombstone_until_ms.is_some_and(|until| until <= now)
            })
            .collect::<Vec<_>>();
        uploads.sort_by_key(|upload| (upload.updated_at_ms, upload.identity.upload_id.clone()));
        Ok(uploads
            .into_iter()
            .take(limit)
            .map(|upload| upload.identity.clone())
            .collect())
    }

    async fn retire_terminal_uploads(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<RetiredMultipartUpload>, StagingError> {
        let mut state = self.state.lock().await;
        state.ensure_healthy()?;
        let ids = state
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                let upload = entry.reducer.snapshot().upload.as_ref()?;
                (matches!(
                    upload.lifecycle,
                    MultipartLifecycle::Completed
                        | MultipartLifecycle::Aborted
                        | MultipartLifecycle::Expired
                ) && upload.tombstone_until_ms.is_some_and(|until| until <= now)
                    && entry.reducer.snapshot().attempts.is_empty()
                    && upload.destination_operation_id.is_none())
                .then(|| id.clone())
            })
            .take(limit)
            .collect::<Vec<_>>();
        let mut retired = Vec::with_capacity(ids.len());
        for id in ids {
            let upload = state.upload(&id)?.clone();
            state
                .apply_transition(
                    &id,
                    FileMultipartTransitionV1::TerminalUploadRetired { retired_at_ms: now },
                )
                .map_err(|failure| failure.error)?;
            retired.push(RetiredMultipartUpload {
                upload_id: upload.identity.upload_id,
                tenant_id: upload.identity.tenant_id,
                namespace_epoch: upload.namespace_epoch,
            });
        }
        Ok(retired)
    }

    async fn reap_expired(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<MultipartPart>, StagingError> {
        let mut state = self.state.lock().await;
        state.ensure_healthy()?;
        let ids = state
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry
                    .reducer
                    .snapshot()
                    .upload
                    .as_ref()
                    .is_some_and(|upload| {
                        upload.lifecycle == MultipartLifecycle::Open && upload.expires_at_ms <= now
                    })
            })
            .map(|(id, _)| id.clone())
            .take(limit)
            .collect::<Vec<_>>();
        let mut parts = Vec::new();
        for id in ids {
            parts.extend(current_parts(state.entries.get(&id).unwrap()));
            let tombstone_until_ms = now
                .checked_add(DEFAULT_EXPIRY.as_millis() as i64)
                .ok_or_else(|| corrupt_state("multipart tombstone timestamp overflow"))?;
            state
                .apply_transition(
                    &id,
                    FileMultipartTransitionV1::UploadExpired {
                        expired_at_ms: now,
                        tombstone_until_ms,
                    },
                )
                .map_err(|failure| failure.error)?;
        }
        Ok(parts)
    }

    async fn audit(&self, audit: CleanupAudit) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        state.ensure_healthy()?;
        let upload_id = audit.upload_id.clone();
        state.upload(&upload_id)?;
        state
            .apply_transition(
                &upload_id,
                FileMultipartTransitionV1::CleanupAudited { audit },
            )
            .map_err(|failure| failure.error)
    }
}

fn prepare_uploads_root(path: &Path) -> Result<(), StagingError> {
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && !metadata.file_type().is_dir()
    {
        return Err(corrupt_state("multipart uploads root is not a directory"));
    }
    create_private_dir_all(path).map_err(persistence_error)
}

fn load_entries(
    uploads_root: &Path,
    persistence: &FilesystemPersistence,
    quotas: StagingQuotaLimits,
) -> Result<BTreeMap<String, FileMultipartEntry>, StagingError> {
    prepare_uploads_root(uploads_root)?;
    let mut entries = BTreeMap::new();
    for item in std::fs::read_dir(uploads_root)
        .map_err(|error| corrupt_state(format!("cannot read multipart uploads root: {error}")))?
    {
        let item = item
            .map_err(|error| corrupt_state(format!("cannot inspect multipart upload: {error}")))?;
        let metadata = std::fs::symlink_metadata(item.path()).map_err(|error| {
            corrupt_state(format!("cannot inspect multipart upload state: {error}"))
        })?;
        if !metadata.file_type().is_dir() {
            return Err(corrupt_state("unknown file in multipart uploads root"));
        }
        let upload_id = item
            .file_name()
            .into_string()
            .map_err(|_| corrupt_state("multipart upload directory is not UTF-8"))?;
        validate_upload_directory_name(&upload_id)?;
        let directory = item.path();
        validate_upload_files(&directory)?;
        let snapshot_path = directory.join(SNAPSHOT_FILE);
        let snapshot = persistence
            .load_snapshot::<FileMultipartSnapshotV1>(&snapshot_path)
            .map_err(persistence_error)?;
        let (snapshot_sequence, snapshot) = match snapshot {
            Some(snapshot) => {
                if snapshot.final_sequence != snapshot.payload.final_event_sequence {
                    return Err(corrupt_state("multipart snapshot sequence mismatch"));
                }
                (snapshot.final_sequence, snapshot.payload)
            }
            None => (0, FileMultipartSnapshotV1::default()),
        };
        let mut reducer =
            FileMultipartReducer::from_snapshot(snapshot).map_err(reducer_persistence_error)?;
        let (log, events) = persistence
            .open_event_log::<FileMultipartEventV1>(
                directory.join(EVENT_LOG_FILE),
                snapshot_sequence,
            )
            .map_err(persistence_error)?;
        for logged in events {
            if logged.sequence != logged.payload.sequence {
                return Err(corrupt_state("multipart event sequence mismatch"));
            }
            reducer
                .apply(&logged.payload)
                .map_err(reducer_persistence_error)?;
        }
        let identity = reducer
            .snapshot()
            .identity
            .as_ref()
            .ok_or_else(|| corrupt_state("multipart upload directory has no identity"))?;
        if identity.upload_id != upload_id {
            return Err(corrupt_state(
                "multipart upload directory identity mismatch",
            ));
        }
        if entries
            .insert(
                upload_id,
                FileMultipartEntry {
                    directory,
                    reducer,
                    log,
                },
            )
            .is_some()
        {
            return Err(corrupt_state("duplicate multipart upload identity"));
        }
    }
    reconstruct_file_multipart_quotas(
        entries.values().map(|entry| entry.reducer.snapshot()),
        quotas,
    )
    .map_err(reducer_persistence_error)?;
    Ok(entries)
}

fn validate_upload_files(directory: &Path) -> Result<(), StagingError> {
    let mut has_log = false;
    for item in std::fs::read_dir(directory)
        .map_err(|error| corrupt_state(format!("cannot read multipart upload state: {error}")))?
    {
        let item = item
            .map_err(|error| corrupt_state(format!("cannot inspect multipart state: {error}")))?;
        let name = item.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| corrupt_state("multipart state filename is not UTF-8"))?;
        if name != SNAPSHOT_FILE && name != EVENT_LOG_FILE {
            return Err(corrupt_state("unknown file in multipart upload directory"));
        }
        let metadata = std::fs::symlink_metadata(item.path())
            .map_err(|error| corrupt_state(format!("cannot inspect multipart state: {error}")))?;
        if !metadata.file_type().is_file() {
            return Err(corrupt_state("multipart state path is not a regular file"));
        }
        has_log |= name == EVENT_LOG_FILE;
    }
    if !has_log {
        return Err(corrupt_state("multipart upload event log is missing"));
    }
    Ok(())
}

fn validate_upload_directory_name(upload_id: &str) -> Result<(), StagingError> {
    let parsed = Uuid::parse_str(upload_id)
        .map_err(|_| corrupt_state("local multipart upload id is not a UUID"))?;
    if parsed.to_string() != upload_id {
        return Err(corrupt_state("local multipart upload id is not canonical"));
    }
    Ok(())
}

fn current_part(entry: &FileMultipartEntry, part_number: u32) -> Option<MultipartPart> {
    entry
        .reducer
        .snapshot()
        .attempts
        .iter()
        .find(|attempt| {
            attempt.lifecycle == FilePartAttemptLifecycleV1::Current
                && attempt.part.part_number == part_number
        })
        .map(|attempt| attempt.part.clone())
}

fn current_parts(entry: &FileMultipartEntry) -> Vec<MultipartPart> {
    let mut parts = entry
        .reducer
        .snapshot()
        .attempts
        .iter()
        .filter(|attempt| attempt.lifecycle == FilePartAttemptLifecycleV1::Current)
        .map(|attempt| attempt.part.clone())
        .collect::<Vec<_>>();
    parts.sort_by_key(|part| part.part_number);
    parts
}

fn select_parts(
    current: &[MultipartPart],
    selected: &[CompletePart],
) -> Result<Vec<MultipartPart>, StagingError> {
    if selected.is_empty() || selected.len() > MAX_PARTS as usize {
        return Err(StagingError::InvalidPart);
    }
    let mut previous = 0;
    let mut result = Vec::with_capacity(selected.len());
    for requested in selected {
        if requested.part_number <= previous {
            return Err(StagingError::InvalidPart);
        }
        let part = current
            .iter()
            .find(|part| part.part_number == requested.part_number)
            .filter(|part| {
                part.etag == requested.etag
                    && requested
                        .checksum_sha256
                        .as_ref()
                        .is_none_or(|checksum| checksum == &part.checksum_sha256)
            })
            .ok_or(StagingError::InvalidPart)?;
        result.push(part.clone());
        previous = requested.part_number;
    }
    Ok(result)
}

fn artifact_owner(state: &FileMultipartState, artifact_key: &str) -> Option<(String, i64)> {
    state.entries.iter().find_map(|(upload_id, entry)| {
        entry
            .reducer
            .snapshot()
            .attempts
            .iter()
            .any(|attempt| attempt.part.artifact_key == artifact_key)
            .then(|| {
                let updated = entry
                    .reducer
                    .snapshot()
                    .upload
                    .as_ref()
                    .map_or_else(now_ms, |upload| now_ms().max(upload.updated_at_ms));
                (upload_id.clone(), updated)
            })
    })
}

fn persistence_error(error: PersistenceError) -> StagingError {
    StagingError::Persistence(error.to_string())
}

fn reducer_persistence_error(error: FileMultipartReducerError) -> StagingError {
    StagingError::Persistence(error.to_string())
}

fn corrupt_state(message: impl Into<String>) -> StagingError {
    StagingError::Persistence(message.into())
}

fn pre_mutation(error: StagingError) -> MutationFailure {
    MutationFailure {
        error,
        unknown: false,
    }
}

fn map_reducer_failure(failure: MutationFailure, semantic: StagingError) -> StagingError {
    if failure.unknown {
        failure.error
    } else if failure.error.to_string().contains("accounting") {
        semantic
    } else {
        failure.error
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;
    use std::sync::Arc;

    use super::*;
    use crate::filesystem_persistence::FaultPoint;
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

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("maskura-file-multipart-{}", Uuid::now_v7()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn adapter_identity(tenant: &str, key: &str) -> MultipartIdentity {
        MultipartIdentity {
            tenant_id: tenant.to_string(),
            credential_policy_id: "policy".to_string(),
            bucket: "bucket".to_string(),
            key: key.to_string(),
            upload_id: Uuid::now_v7().to_string(),
        }
    }

    fn adapter_upload(identity: MultipartIdentity, max_staged_bytes: u64) -> MultipartUpload {
        let mut upload = upload(identity, max_staged_bytes);
        upload.created_at_ms = 0;
        upload.updated_at_ms = 0;
        upload.expires_at_ms = i64::MAX / 2;
        upload
    }

    fn limits(bytes: u64) -> StagingQuotaLimits {
        StagingQuotaLimits::new(bytes, bytes).unwrap()
    }

    fn open_adapter(root: &Path, bytes: u64) -> FileMultipartRepository {
        FileMultipartRepository::open_for_test(
            root.to_path_buf(),
            limits(bytes),
            FilesystemPersistence::default(),
        )
        .unwrap()
    }

    fn selected(part: &MultipartPart) -> CompletePart {
        CompletePart {
            part_number: part.part_number,
            etag: part.etag.clone(),
            checksum_sha256: Some(part.checksum_sha256.clone()),
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

    #[tokio::test]
    async fn adapter_completion_lifecycle_survives_every_restart_boundary() {
        let directory = TempDir::new();
        let identity = adapter_identity("tenant", "complete/key");
        let repo = open_adapter(directory.path(), 2_000);
        assert!(repo.is_durable());
        repo.create(adapter_upload(identity.clone(), 1_000))
            .await
            .unwrap();
        let pending = repo.begin_part(&identity, 1, 400, 10).await.unwrap();
        let committed = part(&pending, 300);
        assert!(
            repo.commit_part(&identity, &pending, committed.clone())
                .await
                .unwrap()
                .is_empty()
        );
        drop(repo);

        let repo = open_adapter(directory.path(), 2_000);
        assert_eq!(
            repo.get_authorized(&identity).await.unwrap().staged_bytes,
            300
        );
        assert_eq!(repo.list_parts(&identity, 0, 10).await.unwrap().0.len(), 1);
        let selection = [selected(&committed)];
        let now = now_ms();
        let first_lease = match repo
            .acquire_completion(
                &identity,
                "fingerprint",
                &selection,
                "worker-a",
                i64::MAX / 4,
                now,
            )
            .await
            .unwrap()
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("expected completion lease"),
        };
        drop(repo);

        let repo = open_adapter(directory.path(), 2_000);
        repo.check_completion_lease(&identity, first_lease.fencing_token, now + 1)
            .await
            .unwrap();
        repo.renew_completion(&identity, first_lease.fencing_token, i64::MAX / 3)
            .await
            .unwrap();
        let operation_id =
            DestinationCommitPermit::deterministic_operation_id(&identity, "fingerprint");
        let first_permit = repo
            .begin_destination_commit(
                &identity,
                "fingerprint",
                first_lease.fencing_token,
                operation_id,
                now_ms(),
            )
            .await
            .unwrap();
        drop(repo);

        let repo = open_adapter(directory.path(), 2_000);
        repo.validate_destination_commit_permit(&first_permit)
            .await
            .unwrap();
        assert_eq!(
            repo.publishing_uploads(10).await.unwrap()[0].permit,
            first_permit
        );
        repo.release_destination_commit_after_proven_absence(&first_permit, now_ms())
            .await
            .unwrap();
        let second_lease = match repo
            .acquire_completion(
                &identity,
                "fingerprint",
                &selection,
                "worker-b",
                i64::MAX / 2,
                now_ms(),
            )
            .await
            .unwrap()
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("expected completion takeover"),
        };
        let permit = repo
            .begin_destination_commit(
                &identity,
                "fingerprint",
                second_lease.fencing_token,
                operation_id,
                now_ms(),
            )
            .await
            .unwrap();
        drop(repo);

        let repo = open_adapter(directory.path(), 2_000);
        let result = completion_result();
        repo.record_destination_commit(&permit, result.clone(), now_ms())
            .await
            .unwrap();
        drop(repo);

        let repo = open_adapter(directory.path(), 2_000);
        let publishing = repo.publishing_uploads(10).await.unwrap();
        assert_eq!(
            publishing[0].destination_commit.as_ref().unwrap().result,
            result
        );
        let completed_at = now_ms();
        repo.complete_completion(&identity, &permit, result.clone(), completed_at)
            .await
            .unwrap();
        drop(repo);

        let repo = open_adapter(directory.path(), 2_000);
        assert!(matches!(
            repo.acquire_completion(
                &identity,
                "fingerprint",
                &selection,
                "worker-c",
                i64::MAX / 2,
                now_ms(),
            )
                .await,
            Ok(CompletionAcquire::Replayed(ref replayed)) if replayed == &result
        ));
        repo.audit(CleanupAudit {
            id: Uuid::now_v7(),
            upload_id: identity.upload_id.clone(),
            kind: "completion-cleanup".to_string(),
            detail: json!({"artifact": committed.artifact_key}),
            created_at_ms: now_ms(),
        })
        .await
        .unwrap();
        repo.confirm_artifact_deleted(&committed.artifact_key)
            .await
            .unwrap();
        repo.clear_destination_commit_reference(&identity, operation_id)
            .await
            .unwrap();
        let retired = repo
            .retire_terminal_uploads(completed_at + DAY_MS, 10)
            .await
            .unwrap();
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].upload_id, identity.upload_id);
        assert!(repo.known_artifact_keys().await.unwrap().is_empty());
        assert!(matches!(
            repo.get_authorized(&identity).await,
            Err(StagingError::NotFound)
        ));
        drop(repo);
        assert!(matches!(
            open_adapter(directory.path(), 2_000)
                .get_authorized(&identity)
                .await,
            Err(StagingError::NotFound)
        ));
    }

    #[tokio::test]
    async fn adapter_abort_expiry_discard_replace_and_cleanup_lifecycle() {
        let directory = TempDir::new();
        let repo = open_adapter(directory.path(), 5_000);

        let aborted = adapter_identity("tenant", "abort");
        repo.create(adapter_upload(aborted.clone(), 1_000))
            .await
            .unwrap();
        let discarded = repo.begin_part(&aborted, 2, 100, 1).await.unwrap();
        repo.discard_pending(&aborted, &discarded).await.unwrap();
        let pending = repo.begin_part(&aborted, 1, 300, now_ms()).await.unwrap();
        let first = part(&pending, 250);
        repo.commit_part(&aborted, &pending, first.clone())
            .await
            .unwrap();
        let mut replacement = first.clone();
        replacement.attempt += 1;
        replacement.artifact_key.push_str("-replacement");
        replacement.etag.push_str("-replacement");
        assert_eq!(
            repo.replace_part(&aborted, replacement.clone())
                .await
                .unwrap()
                .unwrap()
                .artifact_key,
            first.artifact_key
        );
        let aborted_at = now_ms();
        let aborted_parts = repo.abort(&aborted, aborted_at).await.unwrap();
        assert_eq!(aborted_parts.len(), 1);
        assert_eq!(aborted_parts[0].artifact_key, replacement.artifact_key);
        assert_eq!(
            repo.cleanup_candidates(aborted_at + 1, 10)
                .await
                .unwrap()
                .len(),
            1
        );
        repo.confirm_artifact_deleted(&replacement.artifact_key)
            .await
            .unwrap();
        repo.delete_terminal_upload(&aborted).await.unwrap();

        let expired = adapter_identity("tenant", "expired");
        let mut expiring_upload = adapter_upload(expired.clone(), 1_000);
        expiring_upload.expires_at_ms = 10_000;
        repo.create(expiring_upload).await.unwrap();
        assert_eq!(repo.reap_expired(9_999, 10).await.unwrap().len(), 0);
        assert!(repo.reap_expired(10_000, 10).await.unwrap().is_empty());
        repo.delete_terminal_upload(&expired).await.unwrap();
        assert!(
            repo.cleanup_candidates(i64::MAX, 10)
                .await
                .unwrap()
                .is_empty()
        );
        drop(repo);
        let repo = open_adapter(directory.path(), 5_000);
        assert!(matches!(
            repo.get_authorized(&aborted).await,
            Err(StagingError::NotFound)
        ));
        assert!(matches!(
            repo.get_authorized(&expired).await,
            Err(StagingError::NotFound)
        ));
    }

    #[tokio::test]
    async fn adapter_reconstructs_quota_and_serializes_concurrent_reservations() {
        let directory = TempDir::new();
        let first = adapter_identity("tenant", "first");
        let second = adapter_identity("tenant", "second");
        let repo = open_adapter(directory.path(), 100);
        repo.create(adapter_upload(first.clone(), 100))
            .await
            .unwrap();
        repo.create(adapter_upload(second.clone(), 100))
            .await
            .unwrap();
        repo.begin_part(&first, 1, 60, 1).await.unwrap();
        drop(repo);

        assert!(matches!(
            FileMultipartRepository::open(directory.path().to_path_buf(), limits(50)),
            Err(StagingError::Persistence(_))
        ));
        let repo = Arc::new(open_adapter(directory.path(), 100));
        let left = {
            let repo = Arc::clone(&repo);
            let first = first.clone();
            tokio::spawn(async move { repo.begin_part(&first, 2, 40, 2).await })
        };
        let right = {
            let repo = Arc::clone(&repo);
            let second = second.clone();
            tokio::spawn(async move { repo.begin_part(&second, 1, 40, 2).await })
        };
        let outcomes = [left.await.unwrap(), right.await.unwrap()];
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(result, Err(StagingError::QuotaExceeded)))
                .count(),
            1
        );
        drop(repo);
        open_adapter(directory.path(), 100);
    }

    #[tokio::test]
    async fn adapter_authorized_listing_is_paginated_and_persisted() {
        let directory = TempDir::new();
        let repo = open_adapter(directory.path(), 10_000);
        let mut identities = Vec::new();
        for (key, tenant) in [
            ("b", "tenant"),
            ("a", "tenant"),
            ("dir/x", "tenant"),
            ("a", "tenant"),
            ("secret", "other"),
        ] {
            let identity = adapter_identity(tenant, key);
            repo.create(adapter_upload(identity.clone(), 100))
                .await
                .unwrap();
            identities.push(identity);
        }
        drop(repo);

        let repo = open_adapter(directory.path(), 10_000);
        let request = ListMultipartUploadsRequest {
            tenant_id: "tenant".to_string(),
            credential_policy_id: "policy".to_string(),
            bucket: "bucket".to_string(),
            prefix: String::new(),
            delimiter: None,
            key_marker: None,
            upload_id_marker: None,
            max_uploads: 2,
        };
        let first = repo.list_authorized_uploads(&request).await.unwrap();
        assert_eq!(
            first
                .uploads
                .iter()
                .map(|upload| upload.identity.key.as_str())
                .collect::<Vec<_>>(),
            ["a", "a"]
        );
        assert!(first.is_truncated);
        let second = repo
            .list_authorized_uploads(&ListMultipartUploadsRequest {
                key_marker: first.next_key_marker,
                upload_id_marker: first.next_upload_id_marker,
                ..request.clone()
            })
            .await
            .unwrap();
        assert_eq!(
            second
                .uploads
                .iter()
                .map(|upload| upload.identity.key.as_str())
                .collect::<Vec<_>>(),
            ["b", "dir/x"]
        );
        let delimited = repo
            .list_authorized_uploads(&ListMultipartUploadsRequest {
                delimiter: Some("/".to_string()),
                max_uploads: 10,
                ..request.clone()
            })
            .await
            .unwrap();
        assert_eq!(delimited.common_prefixes, ["dir/"]);
        let unauthorized = repo
            .list_authorized_uploads(&ListMultipartUploadsRequest {
                tenant_id: "other-missing".to_string(),
                max_uploads: 10,
                ..request
            })
            .await
            .unwrap();
        assert!(unauthorized.uploads.is_empty());
        assert!(matches!(
            repo.get_authorized(&MultipartIdentity {
                tenant_id: "other".to_string(),
                ..identities[0].clone()
            })
            .await,
            Err(StagingError::NotFound)
        ));
    }

    #[tokio::test]
    async fn adapter_zero_byte_final_part_survives_replay() {
        let directory = TempDir::new();
        let repo = open_adapter(directory.path(), 10_000);
        let identity = adapter_identity("tenant", "key");
        repo.create(adapter_upload(identity.clone(), 100))
            .await
            .unwrap();
        let started = now_ms();
        let pending = repo
            .begin_part(&identity, 1, 0, started)
            .await
            .expect("a zero-byte reservation is a valid final part");
        let zero = MultipartPart {
            upload_id: identity.upload_id.clone(),
            part_number: 1,
            attempt: pending.attempt,
            artifact_key: pending.artifact_key.clone(),
            etag: "\"empty\"".to_string(),
            checksum_sha256: "empty-sha".to_string(),
            size_bytes: 0,
            created_at_ms: started,
        };
        repo.commit_part(&identity, &pending, zero.clone())
            .await
            .unwrap();
        let acquired_at = now_ms();
        let lease = match repo
            .acquire_completion(
                &identity,
                "zero-final",
                &[selected(&zero)],
                "worker",
                acquired_at + 10_000,
                acquired_at,
            )
            .await
            .unwrap()
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("expected a completion lease for a zero-byte final part"),
        };
        assert_eq!(lease.selected_parts.len(), 1);
        assert_eq!(lease.selected_parts[0].size_bytes, 0);
        drop(repo);

        let reopened = open_adapter(directory.path(), 10_000);
        let (parts, truncated) = reopened.list_parts(&identity, 0, 10).await.unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].size_bytes, 0);
        assert_eq!(parts[0].etag, "\"empty\"");
        assert!(!truncated);
    }

    #[tokio::test]
    async fn adapter_compacts_and_reopens_without_losing_completion_lease() {
        let directory = TempDir::new();
        let identity = adapter_identity("tenant", "compaction");
        let repo = open_adapter(directory.path(), 1_000);
        repo.create(adapter_upload(identity.clone(), 1_000))
            .await
            .unwrap();
        let pending = repo.begin_part(&identity, 1, 100, 1).await.unwrap();
        let committed = part(&pending, 90);
        repo.commit_part(&identity, &pending, committed.clone())
            .await
            .unwrap();
        let now = now_ms();
        let lease = match repo
            .acquire_completion(
                &identity,
                "compact",
                &[selected(&committed)],
                "worker",
                now + 10_000,
                now,
            )
            .await
            .unwrap()
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("expected completion lease"),
        };
        for offset in 10_001..10_260 {
            repo.renew_completion(&identity, lease.fencing_token, now + offset)
                .await
                .unwrap();
        }
        let upload_directory = directory.path().join("uploads").join(&identity.upload_id);
        assert!(upload_directory.join(SNAPSHOT_FILE).is_file());
        drop(repo);

        let repo = open_adapter(directory.path(), 1_000);
        repo.check_completion_lease(&identity, lease.fencing_token, now + 100)
            .await
            .unwrap();
        assert_eq!(repo.list_parts(&identity, 0, 10).await.unwrap().0.len(), 1);
    }

    #[tokio::test]
    async fn adapter_reloads_after_mutation_unknown_and_recovers_committed_frame() {
        let directory = TempDir::new();
        let persistence = FilesystemPersistence::default();
        let repo = FileMultipartRepository::open_for_test(
            directory.path().to_path_buf(),
            limits(1_000),
            persistence.clone(),
        )
        .unwrap();
        let identity = adapter_identity("tenant", "unknown");
        repo.create(adapter_upload(identity.clone(), 1_000))
            .await
            .unwrap();
        persistence.fail_once(FaultPoint::AppendSync);
        assert!(matches!(
            repo.begin_part(&identity, 1, 100, 1).await,
            Err(StagingError::Persistence(_))
        ));
        let recovered = repo.get_authorized(&identity).await.unwrap();
        assert_eq!(recovered.reserved_bytes, 100);
        repo.begin_part(&identity, 2, 100, 2).await.unwrap();
    }

    #[tokio::test]
    async fn adapter_rejects_corruption_symlinks_and_unknown_entries() {
        let unknown = TempDir::new();
        std::fs::create_dir(unknown.path().join("uploads")).unwrap();
        std::fs::write(unknown.path().join("uploads/unknown"), b"unknown").unwrap();
        assert!(matches!(
            FileMultipartRepository::open(unknown.path().to_path_buf(), limits(1_000)),
            Err(StagingError::Persistence(_))
        ));

        let corrupt = TempDir::new();
        let identity = adapter_identity("tenant", "corrupt");
        let repo = open_adapter(corrupt.path(), 1_000);
        repo.create(adapter_upload(identity.clone(), 1_000))
            .await
            .unwrap();
        drop(repo);
        std::fs::write(
            corrupt
                .path()
                .join("uploads")
                .join(identity.upload_id)
                .join(EVENT_LOG_FILE),
            b"not-an-event-log",
        )
        .unwrap();
        assert!(matches!(
            FileMultipartRepository::open(corrupt.path().to_path_buf(), limits(1_000)),
            Err(StagingError::Persistence(_))
        ));

        #[cfg(unix)]
        {
            let symlink = TempDir::new();
            std::fs::create_dir(symlink.path().join("uploads")).unwrap();
            std::os::unix::fs::symlink(
                symlink.path(),
                symlink
                    .path()
                    .join("uploads")
                    .join(Uuid::now_v7().to_string()),
            )
            .unwrap();
            assert!(matches!(
                FileMultipartRepository::open(symlink.path().to_path_buf(), limits(1_000)),
                Err(StagingError::Persistence(_))
            ));
        }
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
