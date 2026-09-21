//! Extracted from `multipart_staging.rs`; re-exported from `crate::multipart_staging`.

use super::*;

#[async_trait]
pub trait MultipartRepository: Send + Sync {
    fn is_durable(&self) -> bool;
    async fn create(&self, upload: MultipartUpload) -> Result<(), StagingError>;
    async fn get_authorized(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<MultipartUpload, StagingError>;
    async fn list_authorized_uploads(
        &self,
        request: &ListMultipartUploadsRequest,
    ) -> Result<ListMultipartUploadsPage, StagingError>;
    async fn replace_part(
        &self,
        identity: &MultipartIdentity,
        part: MultipartPart,
    ) -> Result<Option<MultipartPart>, StagingError>;
    /// Create the durable outbox record and reserve both quota scopes before
    /// the request body is read or a ciphertext file is allocated.
    async fn begin_part(
        &self,
        identity: &MultipartIdentity,
        part_number: u32,
        reserved_bytes: u64,
        now_ms: i64,
    ) -> Result<PendingPart, StagingError>;
    /// Atomically publishes an already-uploaded artifact as the current part.
    /// The returned artifacts remain quota-accounted until cleanup confirms
    /// their delete, so replacement cannot overcommit backing storage.
    async fn commit_part(
        &self,
        identity: &MultipartIdentity,
        pending: &PendingPart,
        part: MultipartPart,
    ) -> Result<Vec<MultipartPart>, StagingError>;
    /// Used only before `put_file` has been attempted.
    async fn discard_pending(
        &self,
        identity: &MultipartIdentity,
        pending: &PendingPart,
    ) -> Result<(), StagingError>;
    async fn cleanup_candidates(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<CleanupCandidate>, StagingError>;
    /// Idempotently removes accounting only after object deletion succeeds.
    async fn confirm_artifact_deleted(&self, artifact_key: &str) -> Result<(), StagingError>;
    async fn known_artifact_keys(&self) -> Result<HashMap<String, i64>, StagingError>;
    async fn list_parts(
        &self,
        identity: &MultipartIdentity,
        marker: u32,
        limit: usize,
    ) -> Result<(Vec<MultipartPart>, bool), StagingError>;
    /// Validates client-selected parts and acquires (or takes over) the only
    /// completion lease. The request fingerprint is durable before any staged
    /// bytes are read.
    async fn acquire_completion(
        &self,
        identity: &MultipartIdentity,
        fingerprint: &str,
        parts: &[CompletePart],
        owner: &str,
        lease_expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<CompletionAcquire, StagingError>;
    async fn renew_completion(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        lease_expires_at_ms: i64,
    ) -> Result<(), StagingError>;
    async fn check_completion_lease(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        now_ms: i64,
    ) -> Result<(), StagingError>;
    async fn begin_destination_commit(
        &self,
        identity: &MultipartIdentity,
        fingerprint: &str,
        fencing_token: u64,
        operation_id: Uuid,
        now_ms: i64,
    ) -> Result<DestinationCommitPermit, StagingError>;
    async fn validate_destination_commit_permit(
        &self,
        permit: &DestinationCommitPermit,
    ) -> Result<(), StagingError>;
    async fn record_destination_commit(
        &self,
        permit: &DestinationCommitPermit,
        result: MultipartCompletionResult,
        now_ms: i64,
    ) -> Result<(), StagingError>;
    async fn release_destination_commit_after_proven_absence(
        &self,
        permit: &DestinationCommitPermit,
        now_ms: i64,
    ) -> Result<(), StagingError>;
    async fn publishing_uploads(
        &self,
        limit: usize,
    ) -> Result<Vec<PublishingMultipartUpload>, StagingError>;
    async fn complete_completion(
        &self,
        identity: &MultipartIdentity,
        permit: &DestinationCommitPermit,
        result: MultipartCompletionResult,
        now_ms: i64,
    ) -> Result<(), StagingError>;
    async fn clear_destination_commit_reference(
        &self,
        identity: &MultipartIdentity,
        expected_operation_id: Uuid,
    ) -> Result<(), StagingError>;
    async fn abort(
        &self,
        identity: &MultipartIdentity,
        now_ms: i64,
    ) -> Result<Vec<MultipartPart>, AbortMutationError>;
    async fn delete_terminal_upload(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<(), StagingError>;
    async fn terminal_upload_candidates(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<MultipartIdentity>, StagingError>;
    async fn retire_terminal_uploads(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<RetiredMultipartUpload>, StagingError>;
    async fn reap_expired(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<MultipartPart>, StagingError>;
    async fn audit(&self, audit: CleanupAudit) -> Result<(), StagingError>;
}

#[async_trait]
pub trait StagingArtifactStore: Send + Sync {
    async fn put_file(&self, key: &str, path: &Path) -> Result<(), StagingError>;
    /// Returns an incremental encrypted artifact body. Callers decrypt frame by
    /// frame and must hold a valid completion fence for every read.
    async fn get(&self, key: &str) -> Result<StagingArtifactReader, StagingError>;
    async fn delete(&self, key: &str) -> Result<(), StagingError>;
    /// Discovery is required for startup reconciliation. Implementations must
    /// return every object below the supplied prefix, not an arbitrary page.
    async fn list(&self, prefix: &str) -> Result<Vec<StagedArtifact>, StagingError>;
}
