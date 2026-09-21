//! Extracted from `multipart_staging.rs`; re-exported from `crate::multipart_staging`.

use super::*;

#[derive(Clone, Copy, Debug)]
pub struct StagingQuotaLimits {
    pub tenant_bytes: u64,
    pub global_bytes: u64,
}

impl StagingQuotaLimits {
    pub fn new(tenant_bytes: u64, global_bytes: u64) -> Result<Self, StagingError> {
        if tenant_bytes == 0 || global_bytes == 0 || tenant_bytes > global_bytes {
            return Err(StagingError::QuotaExceeded);
        }
        Ok(Self {
            tenant_bytes,
            global_bytes,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingPart {
    pub upload_id: String,
    pub part_number: u32,
    pub attempt: u32,
    pub artifact_key: String,
    pub reserved_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct CleanupCandidate {
    pub upload_id: String,
    pub artifact_key: String,
}

#[derive(Clone, Debug)]
pub struct StagedArtifact {
    pub key: String,
    pub modified_at_ms: i64,
}

pub type StagingArtifactReader = Pin<Box<dyn AsyncRead + Send>>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MultipartIdentity {
    pub tenant_id: String,
    pub credential_policy_id: String,
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MultipartSnapshot {
    pub metadata: BTreeMap<String, String>,
    pub tags: BTreeMap<String, String>,
    pub checksum_mode: Option<String>,
    pub destination: serde_json::Value,
    pub plugin_snapshot: serde_json::Value,
    pub max_staged_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MultipartLifecycle {
    Open,
    Completing,
    Publishing,
    Completed,
    Aborted,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultipartUpload {
    pub identity: MultipartIdentity,
    #[serde(default)]
    pub namespace_epoch: Option<u64>,
    pub snapshot: MultipartSnapshot,
    pub lifecycle: MultipartLifecycle,
    pub staged_bytes: u64,
    pub reserved_bytes: u64,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub updated_at_ms: i64,
    pub tombstone_until_ms: Option<i64>,
    pub complete_request_fingerprint: Option<String>,
    pub completion_lease_owner: Option<String>,
    pub completion_lease_expires_at_ms: Option<i64>,
    pub completion_fencing_token: u64,
    #[serde(default)]
    pub destination_operation_id: Option<Uuid>,
    #[serde(default)]
    pub publishing_started_at_ms: Option<i64>,
    #[serde(default)]
    pub destination_commit: Option<DestinationCommitRecord>,
    pub completion_result: Option<MultipartCompletionResult>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultipartPart {
    pub upload_id: String,
    pub part_number: u32,
    pub attempt: u32,
    pub artifact_key: String,
    pub etag: String,
    pub checksum_sha256: String,
    pub size_bytes: u64,
    pub created_at_ms: i64,
}

/// A client-selected part from a CompleteMultipartUpload document. Checksum is
/// optional because S3 clients commonly submit only the ETag; when supplied it
/// is matched exactly against the staged part.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompletePart {
    pub part_number: u32,
    pub etag: String,
    pub checksum_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MultipartCompletionResult {
    pub etag: Option<String>,
    pub checksum_sha256: String,
    pub version_id: Option<String>,
    #[serde(default)]
    pub source_bytes: u64,
    #[serde(default)]
    pub size_bytes: u64,
    /// Immutable pipeline COGS evidence for the exact completed revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipeline_evidence: Option<crate::control::PipelineEvidence>,
}

#[derive(Clone, Debug)]
pub struct CompletionLease {
    pub fencing_token: u64,
    pub selected_parts: Vec<MultipartPart>,
    /// Includes selected and unselected current parts. Cleanup is retried by
    /// reconciliation after a process crash, so success never depends on it.
    pub cleanup_parts: Vec<MultipartPart>,
}

#[derive(Clone, Debug)]
pub enum CompletionAcquire {
    Acquired(CompletionLease),
    Replayed(MultipartCompletionResult),
    Busy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ListMultipartUploadsRequest {
    pub tenant_id: String,
    pub credential_policy_id: String,
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
    pub delimiter: Option<String>,
    pub key_marker: Option<String>,
    pub upload_id_marker: Option<String>,
    pub max_uploads: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ListMultipartUploadsPage {
    pub uploads: Vec<MultipartUpload>,
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
    pub next_key_marker: Option<String>,
    pub next_upload_id_marker: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DestinationCommitPermit {
    pub upload_id: String,
    pub completion_fingerprint: String,
    pub fencing_token: u64,
    pub operation_id: Uuid,
}

impl DestinationCommitPermit {
    pub fn deterministic_operation_id(identity: &MultipartIdentity, fingerprint: &str) -> Uuid {
        const NAMESPACE: Uuid = Uuid::from_bytes([
            0x96, 0xa0, 0x29, 0xa7, 0x7f, 0x85, 0x4d, 0xef, 0xa5, 0x3d, 0x34, 0xca, 0x58, 0xe9,
            0x31, 0xad,
        ]);
        let encoded = serde_json::to_vec(&(identity, fingerprint))
            .expect("multipart permit identity serialization cannot fail");
        Uuid::new_v5(&NAMESPACE, &encoded)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DestinationCommitRecord {
    pub operation_id: Uuid,
    pub result: MultipartCompletionResult,
    pub committed_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublishingMultipartUpload {
    pub identity: MultipartIdentity,
    pub permit: DestinationCommitPermit,
    pub publishing_started_at_ms: i64,
    pub destination_commit: Option<DestinationCommitRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleanupAudit {
    pub id: Uuid,
    pub upload_id: String,
    pub kind: String,
    pub detail: serde_json::Value,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetiredMultipartUpload {
    pub upload_id: String,
    pub tenant_id: String,
    pub namespace_epoch: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum StagingError {
    #[error("multipart staging is unavailable")]
    Unavailable,
    #[error("multipart upload was not found or is not authorized")]
    NotFound,
    #[error("multipart upload is no longer open")]
    NotOpen,
    #[error("multipart staging quota exceeded")]
    QuotaExceeded,
    #[error("invalid multipart part")]
    InvalidPart,
    #[error("invalid multipart upload listing request")]
    InvalidListing,
    #[error("multipart completion request conflicts with the existing request")]
    CompletionConflict,
    #[error("multipart completion lease is fenced")]
    Fenced,
    #[error("multipart staging persistence failure: {0}")]
    Persistence(String),
    #[error("multipart staging encryption failure: {0}")]
    Crypto(String),
}

#[derive(Debug, thiserror::Error)]
pub enum AbortMutationError {
    #[error(transparent)]
    PreMutation(StagingError),
    #[error(transparent)]
    MutationUnknown(StagingError),
}

pub fn completion_fingerprint(
    upload: &MultipartUpload,
    parts: &[CompletePart],
) -> Result<String, StagingError> {
    // Serialize only immutable upload inputs and canonical client selection.
    // BTreeMap-backed metadata/tags keep the fingerprint stable across retries.
    let encoded = serde_json::to_vec(&serde_json::json!({
        "identity": upload.identity,
        "parts": parts,
        "metadata": upload.snapshot.metadata,
        "tags": upload.snapshot.tags,
        "checksum_mode": upload.snapshot.checksum_mode,
        "destination": upload.snapshot.destination,
        "plugin_snapshot": upload.snapshot.plugin_snapshot,
        "limits": upload.snapshot.max_staged_bytes,
    }))
    .map_err(json_error)?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

pub(crate) fn validate_selected_parts(
    current: &[MultipartPart],
    requested: &[CompletePart],
) -> Result<Vec<MultipartPart>, StagingError> {
    if requested.is_empty() {
        return Err(StagingError::InvalidPart);
    }
    let mut previous = 0;
    let mut selected = Vec::with_capacity(requested.len());
    for request in requested {
        if request.part_number == 0 || request.part_number <= previous {
            return Err(StagingError::InvalidPart);
        }
        previous = request.part_number;
        let part = current
            .iter()
            .find(|part| part.part_number == request.part_number)
            .ok_or(StagingError::InvalidPart)?;
        if part.etag != request.etag
            || request
                .checksum_sha256
                .as_deref()
                .is_some_and(|checksum| checksum != part.checksum_sha256)
        {
            return Err(StagingError::InvalidPart);
        }
        selected.push(part.clone());
    }
    Ok(selected)
}
