//! Extracted from `file_multipart_repository.rs`; re-exported from `crate::file_multipart_repository`.

use super::*;

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
    pub(crate) snapshot: FileMultipartSnapshotV1,
    pub(crate) replay_floor: u64,
    pub(crate) replayed: BTreeMap<u64, Vec<u8>>,
    pub(crate) event_ids: BTreeMap<Uuid, u64>,
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
