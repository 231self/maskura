#![allow(
    dead_code,
    reason = "local recovery and retirement APIs are wired by multipart Task 12"
)]

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::control::UsageEvent;
use crate::file_store::{CommittedLocalCommitProof, FileStore, LocalCommitProbe};
use crate::multipart_staging::{
    DestinationCommitPermit, MultipartCompletionResult, MultipartIdentity, MultipartLifecycle,
    MultipartRepository, MultipartUpload, PublishingMultipartUpload, RetiredMultipartUpload,
    StagingError, now_ms,
};
use crate::transaction::{
    DestinationCommitAuthority, EvidenceRecord, ExpectedObject, JournalError,
    ObjectSinkTransaction, OperationJournal, OperationRecord, OperationState, StoredObjectMeta,
    TransactionError,
};

const COMPLETION_EVIDENCE_KIND: &str = "multipart_completion";
const USAGE_EVIDENCE_KIND: &str = "usage";

#[derive(Debug, thiserror::Error)]
pub(crate) enum MultipartCoordinatorError {
    #[error(transparent)]
    Staging(#[from] StagingError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error("multipart completion coordination failed: {0}")]
    Invalid(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct DurableUsageEvidence {
    pub receipt_id: Uuid,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub rate_version: i32,
    pub source_bytes: u64,
    pub output_bytes: u64,
    pub processed_bytes: u64,
    pub route: String,
    pub kind: String,
    pub bucket: String,
    #[serde(default)]
    pub pipeline_evidence: Option<crate::control::PipelineEvidence>,
}

impl From<&UsageEvent> for DurableUsageEvidence {
    fn from(event: &UsageEvent) -> Self {
        Self {
            receipt_id: event.receipt_id(),
            occurred_at: event.occurred_at(),
            rate_version: event.rate_version(),
            source_bytes: event.source_bytes(),
            output_bytes: event.output_bytes(),
            processed_bytes: event.processed_bytes(),
            route: event.route().as_str().to_string(),
            kind: event.kind().as_str().to_string(),
            bucket: event.bucket().to_string(),
            pipeline_evidence: event.pipeline_evidence().cloned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublishingRecovery {
    Completed,
    Released,
    Pending,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CommitProofProbe {
    Committed(Box<CommittedLocalCommitProof>),
    ExactAbsent,
    Mismatch,
    Inconclusive,
}

#[async_trait::async_trait]
pub(crate) trait MultipartCommitProof: Send + Sync {
    async fn probe(
        &self,
        operation_id: Uuid,
        generation_id: Uuid,
    ) -> Result<CommitProofProbe, MultipartCoordinatorError>;

    async fn retire(
        &self,
        operation_id: Uuid,
        generation_id: Uuid,
    ) -> Result<(), MultipartCoordinatorError>;
}

pub(crate) struct FileMultipartCommitProof {
    store: Arc<FileStore>,
}

impl FileMultipartCommitProof {
    pub(crate) fn new(store: Arc<FileStore>) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl MultipartCommitProof for FileMultipartCommitProof {
    async fn probe(
        &self,
        operation_id: Uuid,
        generation_id: Uuid,
    ) -> Result<CommitProofProbe, MultipartCoordinatorError> {
        let probe = self
            .store
            .probe_commit(operation_id, generation_id)
            .await
            .map_err(|error| MultipartCoordinatorError::Invalid(error.to_string()))?;
        Ok(match probe {
            LocalCommitProbe::Committed(proof) => CommitProofProbe::Committed(Box::new(proof)),
            LocalCommitProbe::Published(proof) => {
                let proof = self
                    .store
                    .backfill_commit_proof(&proof.prepared.bucket, &proof.prepared.key)
                    .await
                    .map_err(|error| MultipartCoordinatorError::Invalid(error.to_string()))?
                    .ok_or_else(|| {
                        MultipartCoordinatorError::Invalid(
                            "published local object disappeared during proof backfill".to_string(),
                        )
                    })?;
                CommitProofProbe::Committed(Box::new(proof))
            }
            LocalCommitProbe::Absent | LocalCommitProbe::Prepared(_) => {
                CommitProofProbe::ExactAbsent
            }
            LocalCommitProbe::Mismatch => CommitProofProbe::Mismatch,
        })
    }

    async fn retire(
        &self,
        operation_id: Uuid,
        generation_id: Uuid,
    ) -> Result<(), MultipartCoordinatorError> {
        self.store
            .retire_commit_proof(operation_id, generation_id)
            .await
            .map_err(|error| MultipartCoordinatorError::Invalid(error.to_string()))?;
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct MultipartCompletionCoordinator {
    repository: Arc<dyn MultipartRepository>,
    journal: Arc<dyn OperationJournal>,
    proof: Option<Arc<dyn MultipartCommitProof>>,
    exact_absence_confirmation_delay: Duration,
    #[cfg(test)]
    stop_after: Option<PublicationBoundary>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationBoundary {
    SinkCompleted,
    DestinationRecorded,
    JournalCommitted,
}

impl MultipartCompletionCoordinator {
    pub(crate) fn new(
        repository: Arc<dyn MultipartRepository>,
        journal: Arc<dyn OperationJournal>,
    ) -> Result<Self, MultipartCoordinatorError> {
        if !repository.is_durable() || !journal.is_durable() {
            return Err(MultipartCoordinatorError::Invalid(
                "multipart publication requires durable repository and journal".to_string(),
            ));
        }
        Ok(Self {
            repository,
            journal,
            proof: None,
            exact_absence_confirmation_delay: Duration::from_millis(1),
            #[cfg(test)]
            stop_after: None,
        })
    }

    pub(crate) fn with_file_proof(mut self, store: Arc<FileStore>) -> Self {
        self.proof = Some(Arc::new(FileMultipartCommitProof::new(store)));
        self
    }

    #[cfg(test)]
    fn with_proof(mut self, proof: Arc<dyn MultipartCommitProof>) -> Self {
        self.proof = Some(proof);
        self
    }

    #[cfg(test)]
    fn with_exact_absence_confirmation_delay(mut self, delay: Duration) -> Self {
        self.exact_absence_confirmation_delay = delay;
        self
    }

    #[cfg(test)]
    fn stopping_after(mut self, boundary: PublicationBoundary) -> Self {
        self.stop_after = Some(boundary);
        self
    }

    pub(crate) async fn open_operation(
        &self,
        mut operation: OperationRecord,
        identity: &MultipartIdentity,
        fingerprint: &str,
    ) -> Result<(), MultipartCoordinatorError> {
        if operation.id
            != DestinationCommitPermit::deterministic_operation_id(identity, fingerprint)
        {
            return Err(MultipartCoordinatorError::Invalid(
                "multipart journal operation identity is not deterministic".to_string(),
            ));
        }
        operation.client_multipart_upload_id = Some(identity.upload_id.clone());
        self.journal.insert_intent(operation.clone()).await?;
        self.journal.set_open(operation.id, None).await?;
        Ok(())
    }

    pub(crate) async fn bind_existing_operation(
        &self,
        operation_id: Uuid,
        identity: &MultipartIdentity,
    ) -> Result<(), MultipartCoordinatorError> {
        let operation = self.operation(operation_id).await?;
        if operation.tenant_id.as_deref() != Some(&identity.tenant_id)
            || operation.destination.bucket != identity.bucket
            || operation.destination.logical_key != identity.key
        {
            return Err(MultipartCoordinatorError::Invalid(
                "multipart operation destination changed before publication".to_string(),
            ));
        }
        if operation.client_multipart_upload_id.as_deref() == Some(&identity.upload_id) {
            return Ok(());
        }
        if operation.client_multipart_upload_id.is_some() {
            return Err(MultipartCoordinatorError::Invalid(
                "destination operation references another client multipart upload".to_string(),
            ));
        }
        self.journal
            .compare_and_set_client_multipart_upload_reference(
                operation_id,
                None,
                Some(&identity.upload_id),
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn publish(
        &self,
        identity: &MultipartIdentity,
        fingerprint: &str,
        fencing_token: u64,
        precommit: MultipartCompletionResult,
        usage: &UsageEvent,
        sink: &mut Box<dyn ObjectSinkTransaction>,
    ) -> Result<MultipartCompletionResult, MultipartCoordinatorError> {
        let operation_id =
            DestinationCommitPermit::deterministic_operation_id(identity, fingerprint);
        if sink.durable_operation_id() != Some(operation_id) || usage.operation_id() != operation_id
        {
            return Err(MultipartCoordinatorError::Invalid(
                "sink, usage, and multipart operation identities differ".to_string(),
            ));
        }
        self.bind_existing_operation(operation_id, identity).await?;
        let mut operation = self.operation(operation_id).await?;
        let expected = ExpectedObject {
            digest: Some(precommit.checksum_sha256.clone()),
            size: Some(precommit.size_bytes),
            metadata: operation.expected.metadata.clone(),
        };
        if operation.expected != expected {
            self.journal.set_expected(operation_id, &expected).await?;
            operation.expected = expected;
        }
        self.append_usage_evidence(usage).await?;
        self.append_completion_evidence(operation_id, &precommit)
            .await?;
        self.repository
            .check_completion_lease(identity, fencing_token, now_ms())
            .await?;
        let permit = self
            .repository
            .begin_destination_commit(identity, fingerprint, fencing_token, operation_id, now_ms())
            .await?;
        sink.record_usage_evidence(usage).await?;
        let stored = sink
            .complete(DestinationCommitAuthority::client_multipart(
                self.repository.clone(),
                identity.clone(),
                permit.clone(),
            ))
            .await?;
        #[cfg(test)]
        self.stop_at(PublicationBoundary::SinkCompleted)?;
        let result = committed_result(precommit, &stored);
        self.finish_committed(identity, &permit, result.clone(), stored)
            .await?;
        Ok(result)
    }

    pub(crate) async fn recover_publishing(
        &self,
        publishing: &PublishingMultipartUpload,
    ) -> Result<PublishingRecovery, MultipartCoordinatorError> {
        if let Some(record) = &publishing.destination_commit {
            let stored = match self.journal.get(publishing.permit.operation_id).await? {
                Some(operation) if operation.state == OperationState::Committed => {
                    operation.committed.ok_or_else(|| {
                        MultipartCoordinatorError::Invalid(
                            "committed journal operation has no destination metadata".to_string(),
                        )
                    })?
                }
                _ => stored_from_result(&record.result),
            };
            self.finish_committed(
                &publishing.identity,
                &publishing.permit,
                record.result.clone(),
                stored,
            )
            .await?;
            return Ok(PublishingRecovery::Completed);
        }
        let operation = self.operation(publishing.permit.operation_id).await?;
        self.validate_operation_reference(&operation, &publishing.identity)?;
        if operation.state == OperationState::Committed {
            let result = self.result_from_journal(&operation).await?;
            let stored = operation.committed.clone().ok_or_else(|| {
                MultipartCoordinatorError::Invalid(
                    "committed journal operation has no destination metadata".to_string(),
                )
            })?;
            self.finish_committed(&publishing.identity, &publishing.permit, result, stored)
                .await?;
            return Ok(PublishingRecovery::Completed);
        }
        let Some(proof) = &self.proof else {
            return Ok(PublishingRecovery::Pending);
        };
        match proof
            .probe(
                publishing.permit.operation_id,
                publishing.permit.operation_id,
            )
            .await?
        {
            CommitProofProbe::Committed(proof) => {
                let precommit = self.completion_evidence(operation.id).await?;
                let stored = StoredObjectMeta {
                    etag: Some(proof.etag),
                    version_id: None,
                    superseded_version_ids: Vec::new(),
                    version_history_complete: true,
                };
                let result = committed_result(precommit, &stored);
                self.finish_committed(&publishing.identity, &publishing.permit, result, stored)
                    .await?;
                Ok(PublishingRecovery::Completed)
            }
            CommitProofProbe::ExactAbsent => {
                let confirmed = self
                    .journal
                    .confirm_exact_absence(
                        operation.id,
                        now_ms(),
                        self.exact_absence_confirmation_delay
                            .as_millis()
                            .min(i64::MAX as u128) as i64,
                    )
                    .await?;
                if !confirmed {
                    return Ok(PublishingRecovery::Pending);
                }
                self.repository
                    .release_destination_commit_after_proven_absence(&publishing.permit, now_ms())
                    .await?;
                Ok(PublishingRecovery::Released)
            }
            CommitProofProbe::Mismatch | CommitProofProbe::Inconclusive => {
                Ok(PublishingRecovery::Pending)
            }
        }
    }

    pub(crate) async fn complete_recovered_journal_result(
        &self,
        identity: &MultipartIdentity,
        fingerprint: &str,
        fencing_token: u64,
        result: MultipartCompletionResult,
    ) -> Result<(), MultipartCoordinatorError> {
        let operation_id =
            DestinationCommitPermit::deterministic_operation_id(identity, fingerprint);
        self.bind_existing_operation(operation_id, identity).await?;
        self.ensure_completion_evidence(operation_id, &result)
            .await?;
        let permit = self
            .repository
            .begin_destination_commit(identity, fingerprint, fencing_token, operation_id, now_ms())
            .await?;
        let operation = self.operation(operation_id).await?;
        let stored = operation.committed.ok_or_else(|| {
            MultipartCoordinatorError::Invalid(
                "recovered terminal journal operation has no destination metadata".to_string(),
            )
        })?;
        self.finish_committed(identity, &permit, result, stored)
            .await
    }

    pub(crate) async fn retire_terminal_upload(
        &self,
        identity: &MultipartIdentity,
        now: i64,
        limit: usize,
    ) -> Result<Vec<RetiredMultipartUpload>, MultipartCoordinatorError> {
        let upload = self.repository.get_authorized(identity).await?;
        if !is_retirable_tombstone(&upload, now) {
            return Ok(Vec::new());
        }
        let artifact_prefix = format!(
            "{}{}/{}/",
            crate::multipart_staging::ARTIFACT_PREFIX,
            identity.tenant_id,
            identity.upload_id
        );
        if self
            .repository
            .known_artifact_keys()
            .await?
            .keys()
            .any(|key| key.starts_with(&artifact_prefix))
        {
            return Ok(Vec::new());
        }
        if let Some(operation_id) = upload.destination_operation_id {
            let terminal_operation = self.journal.get(operation_id).await?;
            if terminal_operation
                .as_ref()
                .is_some_and(|operation| !operation.state.is_terminal())
            {
                return Ok(Vec::new());
            }
            if let Some(proof) = &self.proof {
                proof.retire(operation_id, operation_id).await?;
            }
            if let Some(operation) = terminal_operation {
                self.journal
                    .retire_terminal(operation_id, operation.state, Some(&identity.upload_id))
                    .await?;
            }
            self.repository
                .clear_destination_commit_reference(identity, operation_id)
                .await?;
        }
        Ok(self.repository.retire_terminal_uploads(now, limit).await?)
    }

    async fn finish_committed(
        &self,
        identity: &MultipartIdentity,
        permit: &DestinationCommitPermit,
        result: MultipartCompletionResult,
        stored: StoredObjectMeta,
    ) -> Result<(), MultipartCoordinatorError> {
        self.repository
            .record_destination_commit(permit, result.clone(), now_ms())
            .await?;
        #[cfg(test)]
        self.stop_at(PublicationBoundary::DestinationRecorded)?;
        self.commit_journal(permit.operation_id, &stored).await?;
        #[cfg(test)]
        self.stop_at(PublicationBoundary::JournalCommitted)?;
        self.repository
            .complete_completion(identity, permit, result, now_ms())
            .await?;
        Ok(())
    }

    async fn commit_journal(
        &self,
        operation_id: Uuid,
        stored: &StoredObjectMeta,
    ) -> Result<(), MultipartCoordinatorError> {
        let mut operation = self.operation(operation_id).await?;
        if operation.state == OperationState::Committed {
            if operation.committed.as_ref() == Some(stored) {
                return Ok(());
            }
            return Err(MultipartCoordinatorError::Invalid(
                "journal destination commit differs from recovered proof".to_string(),
            ));
        }
        if operation.state == OperationState::Intent {
            self.journal.set_open(operation_id, None).await?;
            operation.state = OperationState::Open;
        }
        if operation.state == OperationState::Open {
            self.journal
                .transition(
                    operation_id,
                    OperationState::Open,
                    OperationState::Completing,
                    None,
                )
                .await?;
            operation.state = OperationState::Completing;
        }
        let from = match operation.state {
            OperationState::Completing | OperationState::CommitUnknown => operation.state,
            _ => {
                return Err(MultipartCoordinatorError::Invalid(format!(
                    "journal operation cannot commit from {}",
                    operation.state
                )));
            }
        };
        self.journal
            .transition(operation_id, from, OperationState::Committed, Some(stored))
            .await?;
        Ok(())
    }

    async fn append_usage_evidence(
        &self,
        event: &UsageEvent,
    ) -> Result<(), MultipartCoordinatorError> {
        let mut evidence = EvidenceRecord::new(
            event.operation_id(),
            USAGE_EVIDENCE_KIND,
            serde_json::to_value(DurableUsageEvidence::from(event))
                .map_err(|error| MultipartCoordinatorError::Invalid(error.to_string()))?,
        );
        evidence.id = usage_evidence_id(event.receipt_id());
        self.journal.append_evidence(evidence).await?;
        Ok(())
    }

    async fn append_completion_evidence(
        &self,
        operation_id: Uuid,
        result: &MultipartCompletionResult,
    ) -> Result<(), MultipartCoordinatorError> {
        let mut evidence = EvidenceRecord::new(
            operation_id,
            COMPLETION_EVIDENCE_KIND,
            serde_json::to_value(result)
                .map_err(|error| MultipartCoordinatorError::Invalid(error.to_string()))?,
        );
        evidence.id = completion_evidence_id(operation_id);
        self.journal.append_evidence(evidence).await?;
        Ok(())
    }

    async fn completion_evidence(
        &self,
        operation_id: Uuid,
    ) -> Result<MultipartCompletionResult, MultipartCoordinatorError> {
        let expected_id = completion_evidence_id(operation_id);
        let evidence = self
            .journal
            .evidence(operation_id)
            .await?
            .into_iter()
            .find(|record| record.id == expected_id && record.kind == COMPLETION_EVIDENCE_KIND)
            .ok_or_else(|| {
                MultipartCoordinatorError::Invalid(
                    "multipart operation is missing completion evidence".to_string(),
                )
            })?;
        serde_json::from_value(evidence.detail)
            .map_err(|error| MultipartCoordinatorError::Invalid(error.to_string()))
    }

    async fn ensure_completion_evidence(
        &self,
        operation_id: Uuid,
        result: &MultipartCompletionResult,
    ) -> Result<(), MultipartCoordinatorError> {
        let existing = self
            .journal
            .evidence(operation_id)
            .await?
            .into_iter()
            .find(|record| {
                record.id == completion_evidence_id(operation_id)
                    && record.kind == COMPLETION_EVIDENCE_KIND
            });
        if let Some(existing) = existing {
            let mut persisted: MultipartCompletionResult = serde_json::from_value(existing.detail)
                .map_err(|error| MultipartCoordinatorError::Invalid(error.to_string()))?;
            persisted.etag = result.etag.clone();
            persisted.version_id = result.version_id.clone();
            if persisted != *result {
                return Err(MultipartCoordinatorError::Invalid(
                    "recovered multipart result differs from precommit evidence".to_string(),
                ));
            }
            return Ok(());
        }
        let mut precommit = result.clone();
        precommit.etag = None;
        precommit.version_id = None;
        self.append_completion_evidence(operation_id, &precommit)
            .await
    }

    async fn result_from_journal(
        &self,
        operation: &OperationRecord,
    ) -> Result<MultipartCompletionResult, MultipartCoordinatorError> {
        let precommit = self.completion_evidence(operation.id).await?;
        let stored = operation.committed.as_ref().ok_or_else(|| {
            MultipartCoordinatorError::Invalid(
                "committed operation is missing destination metadata".to_string(),
            )
        })?;
        Ok(committed_result(precommit, stored))
    }

    async fn operation(
        &self,
        operation_id: Uuid,
    ) -> Result<OperationRecord, MultipartCoordinatorError> {
        self.journal.get(operation_id).await?.ok_or_else(|| {
            MultipartCoordinatorError::Invalid(format!(
                "multipart destination operation {operation_id} has no journal intent"
            ))
        })
    }

    fn validate_operation_reference(
        &self,
        operation: &OperationRecord,
        identity: &MultipartIdentity,
    ) -> Result<(), MultipartCoordinatorError> {
        if operation.client_multipart_upload_id.as_deref() != Some(&identity.upload_id)
            || operation.tenant_id.as_deref() != Some(&identity.tenant_id)
            || operation.destination.bucket != identity.bucket
            || operation.destination.logical_key != identity.key
        {
            return Err(MultipartCoordinatorError::Invalid(
                "multipart journal reference or destination changed".to_string(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn stop_at(&self, boundary: PublicationBoundary) -> Result<(), MultipartCoordinatorError> {
        if self.stop_after == Some(boundary) {
            return Err(MultipartCoordinatorError::Invalid(format!(
                "simulated crash after {boundary:?}"
            )));
        }
        Ok(())
    }
}

pub(crate) fn usage_evidence_id(receipt_id: Uuid) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, receipt_id.as_bytes().as_slice())
}

pub(crate) async fn append_usage_evidence(
    journal: &Arc<dyn OperationJournal>,
    event: &UsageEvent,
) -> Result<(), JournalError> {
    let mut evidence = EvidenceRecord::new(
        event.operation_id(),
        USAGE_EVIDENCE_KIND,
        serde_json::to_value(DurableUsageEvidence::from(event))
            .map_err(|error| JournalError::Persistence(error.to_string()))?,
    );
    evidence.id = usage_evidence_id(event.receipt_id());
    journal.append_evidence(evidence).await
}

pub(crate) async fn load_usage_evidence(
    journal: &Arc<dyn OperationJournal>,
    operation_id: Uuid,
    receipt_id: Uuid,
) -> Result<DurableUsageEvidence, JournalError> {
    let expected_id = usage_evidence_id(receipt_id);
    let record = journal
        .evidence(operation_id)
        .await?
        .into_iter()
        .find(|record| record.id == expected_id && record.kind == USAGE_EVIDENCE_KIND)
        .ok_or_else(|| {
            JournalError::Corrupt(format!(
                "operation {operation_id} is missing deterministic usage evidence"
            ))
        })?;
    let evidence: DurableUsageEvidence = serde_json::from_value(record.detail)
        .map_err(|error| JournalError::Corrupt(error.to_string()))?;
    if evidence.receipt_id != receipt_id {
        return Err(JournalError::Corrupt(format!(
            "operation {operation_id} usage evidence has the wrong receipt"
        )));
    }
    Ok(evidence)
}

fn completion_evidence_id(operation_id: Uuid) -> Uuid {
    const NAMESPACE: Uuid = Uuid::from_bytes([
        0x51, 0x8c, 0xaf, 0x4e, 0x7f, 0x33, 0x43, 0xcb, 0x90, 0x60, 0x84, 0x89, 0x43, 0xe5, 0x0e,
        0x02,
    ]);
    Uuid::new_v5(&NAMESPACE, operation_id.as_bytes().as_slice())
}

fn committed_result(
    mut precommit: MultipartCompletionResult,
    stored: &StoredObjectMeta,
) -> MultipartCompletionResult {
    precommit.etag = stored.etag.clone();
    precommit.version_id = stored.version_id.clone();
    precommit
}

fn stored_from_result(result: &MultipartCompletionResult) -> StoredObjectMeta {
    StoredObjectMeta {
        etag: result.etag.clone(),
        version_id: result.version_id.clone(),
        superseded_version_ids: Vec::new(),
        version_history_complete: true,
    }
}

fn is_retirable_tombstone(upload: &MultipartUpload, now: i64) -> bool {
    matches!(
        upload.lifecycle,
        MultipartLifecycle::Completed | MultipartLifecycle::Aborted | MultipartLifecycle::Expired
    ) && upload.tombstone_until_ms.is_some_and(|until| until <= now)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::control::{AuthorizationGrant, RequestKind, UsageAuthorization, UsageRoute};
    use crate::file_multipart_repository::FileMultipartRepository;
    use crate::multipart_staging::{
        CompletePart, CompletionAcquire, CompletionLease, MultipartPart, MultipartSnapshot,
        StagingQuotaLimits,
    };
    use crate::transaction::{DirectOperationScope, FileOperationJournal, FileSinkTransaction};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("maskura-multipart-coordinator-{}", Uuid::now_v7()));
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

    struct CountingSink {
        inner: FileSinkTransaction,
        completions: Arc<AtomicUsize>,
        journal: Arc<FileOperationJournal>,
        repository: Arc<FileMultipartRepository>,
        identity: MultipartIdentity,
    }

    #[async_trait::async_trait]
    impl ObjectSinkTransaction for CountingSink {
        fn commit_state(&self) -> crate::transaction::SinkCommitState {
            self.inner.commit_state()
        }

        fn durable_operation_id(&self) -> Option<Uuid> {
            self.inner.durable_operation_id()
        }

        async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError> {
            self.inner.write(chunk).await
        }

        async fn verify_output(
            &mut self,
            expected_size: u64,
            expected_sha256: &str,
        ) -> Result<(), TransactionError> {
            self.inner
                .verify_output(expected_size, expected_sha256)
                .await
        }

        async fn complete(
            &mut self,
            authority: DestinationCommitAuthority,
        ) -> Result<StoredObjectMeta, TransactionError> {
            let operation = self
                .journal
                .get(self.inner.durable_operation_id().unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(operation.state, OperationState::Open);
            assert_eq!(
                operation.client_multipart_upload_id.as_deref(),
                Some(self.identity.upload_id.as_str())
            );
            assert!(operation.expected.digest.is_some());
            assert!(operation.expected.size.is_some());
            let evidence = self.journal.evidence(operation.id).await.unwrap();
            assert!(evidence.iter().any(|item| item.kind == USAGE_EVIDENCE_KIND));
            assert!(
                evidence
                    .iter()
                    .any(|item| item.kind == COMPLETION_EVIDENCE_KIND)
            );
            assert_eq!(
                self.repository
                    .get_authorized(&self.identity)
                    .await
                    .unwrap()
                    .lifecycle,
                MultipartLifecycle::Publishing
            );
            self.completions.fetch_add(1, Ordering::SeqCst);
            self.inner.complete(authority).await
        }

        async fn abort(&mut self) -> Result<(), TransactionError> {
            self.inner.abort().await
        }
    }

    struct FixedProof(CommitProofProbe);

    #[async_trait::async_trait]
    impl MultipartCommitProof for FixedProof {
        async fn probe(
            &self,
            _operation_id: Uuid,
            _generation_id: Uuid,
        ) -> Result<CommitProofProbe, MultipartCoordinatorError> {
            Ok(self.0.clone())
        }

        async fn retire(
            &self,
            _operation_id: Uuid,
            _generation_id: Uuid,
        ) -> Result<(), MultipartCoordinatorError> {
            Ok(())
        }
    }

    struct Fixture {
        _directory: TempDir,
        identity: MultipartIdentity,
        repository: Arc<FileMultipartRepository>,
        journal: Arc<FileOperationJournal>,
        store: Arc<FileStore>,
        lease: CompletionLease,
        operation_id: Uuid,
        receipt_id: Uuid,
        artifact_key: String,
    }

    impl Fixture {
        async fn new() -> Self {
            let directory = TempDir::new();
            let repository = Arc::new(
                FileMultipartRepository::open(
                    directory.path().join("multipart"),
                    StagingQuotaLimits::new(1024 * 1024, 1024 * 1024).unwrap(),
                )
                .unwrap(),
            );
            let journal =
                Arc::new(FileOperationJournal::open(directory.path().join("journal")).unwrap());
            let store = Arc::new(
                FileStore::new(directory.path().join("objects"))
                    .await
                    .unwrap(),
            );
            let identity = MultipartIdentity {
                tenant_id: "tenant-a".to_string(),
                credential_policy_id: "policy-a".to_string(),
                bucket: "bucket-a".to_string(),
                key: "key-a".to_string(),
                upload_id: Uuid::now_v7().to_string(),
            };
            let now = now_ms();
            repository
                .create(MultipartUpload {
                    identity: identity.clone(),
                    namespace_epoch: None,
                    snapshot: MultipartSnapshot {
                        metadata: BTreeMap::from([(
                            "content-type".to_string(),
                            "application/jsonl".to_string(),
                        )]),
                        tags: BTreeMap::new(),
                        checksum_mode: None,
                        destination: serde_json::json!({"kind": "file"}),
                        plugin_snapshot: serde_json::json!({}),
                        max_staged_bytes: 1024 * 1024,
                    },
                    lifecycle: MultipartLifecycle::Open,
                    staged_bytes: 0,
                    reserved_bytes: 0,
                    created_at_ms: now,
                    expires_at_ms: now + 60_000,
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
                })
                .await
                .unwrap();
            let pending = repository.begin_part(&identity, 1, 8, now).await.unwrap();
            let artifact_key = pending.artifact_key.clone();
            repository
                .commit_part(
                    &identity,
                    &pending,
                    MultipartPart {
                        upload_id: identity.upload_id.clone(),
                        part_number: 1,
                        attempt: pending.attempt,
                        artifact_key: artifact_key.clone(),
                        etag: "\"part\"".to_string(),
                        checksum_sha256: "part-sha".to_string(),
                        size_bytes: 8,
                        created_at_ms: now,
                    },
                )
                .await
                .unwrap();
            let lease = match repository
                .acquire_completion(
                    &identity,
                    "fingerprint-a",
                    &[CompletePart {
                        part_number: 1,
                        etag: "\"part\"".to_string(),
                        checksum_sha256: Some("part-sha".to_string()),
                    }],
                    "worker-a",
                    now_ms() + 60_000,
                    now_ms(),
                )
                .await
                .unwrap()
            {
                CompletionAcquire::Acquired(lease) => lease,
                _ => panic!("completion lease was not acquired"),
            };
            let operation_id =
                DestinationCommitPermit::deterministic_operation_id(&identity, "fingerprint-a");
            let receipt_id = Uuid::new_v5(&Uuid::NAMESPACE_X500, operation_id.as_bytes());
            let coordinator =
                MultipartCompletionCoordinator::new(repository.clone(), journal.clone()).unwrap();
            coordinator
                .open_operation(
                    OperationRecord::direct_intent(
                        DirectOperationScope {
                            operation_id,
                            tenant_id: identity.tenant_id.clone(),
                        },
                        crate::transaction::ObjectDestination {
                            backend_id: "File".to_string(),
                            bucket: identity.bucket.clone(),
                            logical_key: identity.key.clone(),
                            physical_key: identity.key.clone(),
                            workspace_binding: None,
                        },
                        ExpectedObject {
                            metadata: BTreeMap::from([(
                                "content-type".to_string(),
                                "application/jsonl".to_string(),
                            )]),
                            ..ExpectedObject::default()
                        },
                    ),
                    &identity,
                    "fingerprint-a",
                )
                .await
                .unwrap();
            Self {
                _directory: directory,
                identity,
                repository,
                journal,
                store,
                lease,
                operation_id,
                receipt_id,
                artifact_key,
            }
        }

        fn coordinator(&self) -> MultipartCompletionCoordinator {
            MultipartCompletionCoordinator::new(self.repository.clone(), self.journal.clone())
                .unwrap()
                .with_file_proof(self.store.clone())
        }

        fn usage(&self, source_bytes: u64, output_bytes: u64) -> UsageEvent {
            let authorization = UsageAuthorization::new(
                self.operation_id,
                self.receipt_id,
                self.identity.bucket.clone(),
                UsageRoute::CompleteMultipartUpload,
                RequestKind::Write,
                1024 * 1024,
            );
            UsageEvent::from_grant(
                &AuthorizationGrant::new(&authorization, chrono::Utc::now(), 1),
                source_bytes,
                output_bytes,
            )
        }

        async fn sink(
            &self,
            bytes: &[u8],
            completions: Arc<AtomicUsize>,
        ) -> Box<dyn ObjectSinkTransaction> {
            let mut sink = FileSinkTransaction::new_for_operation(
                self.store.clone(),
                self.identity.bucket.clone(),
                self.identity.key.clone(),
                "application/jsonl",
                1024 * 1024,
                self.operation_id,
            )
            .await
            .unwrap();
            sink.write(Bytes::copy_from_slice(bytes)).await.unwrap();
            sink.verify_output(bytes.len() as u64, &hex::encode(Sha256::digest(bytes)))
                .await
                .unwrap();
            Box::new(CountingSink {
                inner: sink,
                completions,
                journal: self.journal.clone(),
                repository: self.repository.clone(),
                identity: self.identity.clone(),
            })
        }

        fn precommit(&self, bytes: &[u8]) -> MultipartCompletionResult {
            MultipartCompletionResult {
                etag: None,
                checksum_sha256: hex::encode(Sha256::digest(bytes)),
                version_id: None,
                source_bytes: 8,
                size_bytes: bytes.len() as u64,
                pipeline_evidence: Some(crate::control::PipelineEvidence {
                    revision: "revision-a".to_string(),
                    fingerprint: "pipeline-a".to_string(),
                    components: "randomized-transform".to_string(),
                    fuel_consumed: 17,
                    duration_ms: 3,
                    spool_mode: "none".to_string(),
                }),
            }
        }
    }

    #[tokio::test]
    async fn crashes_after_each_publication_boundary_recover_without_rerunning_transform() {
        for boundary in [
            PublicationBoundary::SinkCompleted,
            PublicationBoundary::DestinationRecorded,
            PublicationBoundary::JournalCommitted,
        ] {
            let fixture = Fixture::new().await;
            let transformed = format!("randomized:{}", Uuid::now_v7()).into_bytes();
            let completions = Arc::new(AtomicUsize::new(0));
            let mut sink = fixture.sink(&transformed, completions.clone()).await;
            let coordinator = fixture.coordinator().stopping_after(boundary);
            assert!(
                coordinator
                    .publish(
                        &fixture.identity,
                        "fingerprint-a",
                        fixture.lease.fencing_token,
                        fixture.precommit(&transformed),
                        &fixture.usage(8, transformed.len() as u64),
                        &mut sink,
                    )
                    .await
                    .is_err()
            );
            assert_eq!(completions.load(Ordering::SeqCst), 1);

            let interrupted_upload = fixture
                .repository
                .get_authorized(&fixture.identity)
                .await
                .unwrap();
            let interrupted_operation = fixture
                .journal
                .get(fixture.operation_id)
                .await
                .unwrap()
                .unwrap();
            match boundary {
                PublicationBoundary::SinkCompleted => {
                    assert!(interrupted_upload.destination_commit.is_none());
                    assert_eq!(interrupted_operation.state, OperationState::Open);
                }
                PublicationBoundary::DestinationRecorded => {
                    assert!(interrupted_upload.destination_commit.is_some());
                    assert_eq!(interrupted_operation.state, OperationState::Open);
                }
                PublicationBoundary::JournalCommitted => {
                    assert!(interrupted_upload.destination_commit.is_some());
                    assert_eq!(interrupted_operation.state, OperationState::Committed);
                }
            }

            let publishing = fixture.repository.publishing_uploads(1).await.unwrap();
            assert_eq!(publishing.len(), 1);
            assert_eq!(
                fixture
                    .coordinator()
                    .recover_publishing(&publishing[0])
                    .await
                    .unwrap(),
                PublishingRecovery::Completed
            );
            assert_eq!(completions.load(Ordering::SeqCst), 1);
            assert_eq!(
                fixture
                    .store
                    .get(&fixture.identity.bucket, &fixture.identity.key)
                    .await
                    .unwrap()
                    .unwrap()
                    .data,
                Bytes::copy_from_slice(&transformed)
            );
            let upload = fixture
                .repository
                .get_authorized(&fixture.identity)
                .await
                .unwrap();
            assert_eq!(upload.lifecycle, MultipartLifecycle::Completed);
            assert_eq!(
                fixture
                    .journal
                    .get(fixture.operation_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .state,
                OperationState::Committed
            );
            assert!(matches!(
                fixture
                    .repository
                    .acquire_completion(
                        &fixture.identity,
                        "fingerprint-a",
                        &[CompletePart {
                            part_number: 1,
                            etag: "\"part\"".to_string(),
                            checksum_sha256: Some("part-sha".to_string()),
                        }],
                        "replay-worker",
                        now_ms() + 60_000,
                        now_ms(),
                    )
                    .await,
                Ok(CompletionAcquire::Replayed(result))
                    if result.checksum_sha256 == hex::encode(Sha256::digest(&transformed))
                        && result.size_bytes == transformed.len() as u64
            ));
        }
    }

    #[tokio::test]
    async fn stale_completion_fence_is_rejected_before_file_publication() {
        let fixture = Fixture::new().await;
        let transformed = b"stale-output";
        let completions = Arc::new(AtomicUsize::new(0));
        let mut sink = fixture.sink(transformed, completions.clone()).await;
        let error = fixture
            .coordinator()
            .publish(
                &fixture.identity,
                "fingerprint-a",
                fixture.lease.fencing_token + 1,
                fixture.precommit(transformed),
                &fixture.usage(8, transformed.len() as u64),
                &mut sink,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            MultipartCoordinatorError::Staging(StagingError::Fenced)
        ));
        assert_eq!(completions.load(Ordering::SeqCst), 0);
        assert!(
            fixture
                .store
                .get(&fixture.identity.bucket, &fixture.identity.key)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn exact_absence_requires_confirmation_but_inconclusive_probe_stays_pending() {
        let fixture = Fixture::new().await;
        let coordinator = fixture
            .coordinator()
            .with_proof(Arc::new(FixedProof(CommitProofProbe::ExactAbsent)))
            .with_exact_absence_confirmation_delay(Duration::ZERO);
        let permit = fixture
            .repository
            .begin_destination_commit(
                &fixture.identity,
                "fingerprint-a",
                fixture.lease.fencing_token,
                fixture.operation_id,
                now_ms(),
            )
            .await
            .unwrap();
        let publishing = fixture
            .repository
            .publishing_uploads(1)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(
            coordinator.recover_publishing(&publishing).await.unwrap(),
            PublishingRecovery::Pending
        );
        assert_eq!(
            coordinator.recover_publishing(&publishing).await.unwrap(),
            PublishingRecovery::Released
        );
        assert_eq!(
            fixture
                .repository
                .get_authorized(&fixture.identity)
                .await
                .unwrap()
                .lifecycle,
            MultipartLifecycle::Completing
        );

        let second_lease = match fixture
            .repository
            .acquire_completion(
                &fixture.identity,
                "fingerprint-a",
                &[CompletePart {
                    part_number: 1,
                    etag: "\"part\"".to_string(),
                    checksum_sha256: Some("part-sha".to_string()),
                }],
                "worker-b",
                now_ms() + 60_000,
                now_ms(),
            )
            .await
            .unwrap()
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("released publication was not reacquired"),
        };
        fixture
            .repository
            .begin_destination_commit(
                &fixture.identity,
                "fingerprint-a",
                second_lease.fencing_token,
                permit.operation_id,
                now_ms(),
            )
            .await
            .unwrap();
        let publishing = fixture
            .repository
            .publishing_uploads(1)
            .await
            .unwrap()
            .remove(0);
        let inconclusive = fixture
            .coordinator()
            .with_proof(Arc::new(FixedProof(CommitProofProbe::Inconclusive)));
        assert_eq!(
            inconclusive.recover_publishing(&publishing).await.unwrap(),
            PublishingRecovery::Pending
        );
        assert_eq!(
            fixture
                .repository
                .get_authorized(&fixture.identity)
                .await
                .unwrap()
                .lifecycle,
            MultipartLifecycle::Publishing
        );
        let mismatch = fixture
            .coordinator()
            .with_proof(Arc::new(FixedProof(CommitProofProbe::Mismatch)));
        assert_eq!(
            mismatch.recover_publishing(&publishing).await.unwrap(),
            PublishingRecovery::Pending
        );
        assert_eq!(
            fixture
                .repository
                .get_authorized(&fixture.identity)
                .await
                .unwrap()
                .lifecycle,
            MultipartLifecycle::Publishing
        );
    }

    #[tokio::test]
    async fn retirement_waits_for_artifacts_then_retires_proof_journal_reference_and_upload() {
        let fixture = Fixture::new().await;
        let transformed = b"terminal-output";
        let completions = Arc::new(AtomicUsize::new(0));
        let mut sink = fixture.sink(transformed, completions).await;
        fixture
            .coordinator()
            .publish(
                &fixture.identity,
                "fingerprint-a",
                fixture.lease.fencing_token,
                fixture.precommit(transformed),
                &fixture.usage(8, transformed.len() as u64),
                &mut sink,
            )
            .await
            .unwrap();

        assert!(
            fixture
                .coordinator()
                .retire_terminal_upload(&fixture.identity, i64::MAX, 16)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            fixture
                .journal
                .get(fixture.operation_id)
                .await
                .unwrap()
                .is_some()
        );
        fixture
            .repository
            .confirm_artifact_deleted(&fixture.artifact_key)
            .await
            .unwrap();
        assert!(
            fixture
                .coordinator()
                .retire_terminal_upload(&fixture.identity, now_ms(), 16)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            fixture
                .journal
                .get(fixture.operation_id)
                .await
                .unwrap()
                .is_some()
        );
        let retired = fixture
            .coordinator()
            .retire_terminal_upload(&fixture.identity, i64::MAX, 16)
            .await
            .unwrap();
        assert!(
            retired
                .iter()
                .any(|upload| upload.upload_id == fixture.identity.upload_id)
        );
        assert!(
            fixture
                .journal
                .get(fixture.operation_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            fixture
                .store
                .probe_commit(fixture.operation_id, fixture.operation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Absent
        ));
        assert!(matches!(
            fixture.repository.get_authorized(&fixture.identity).await,
            Err(StagingError::NotFound)
        ));
    }
}
