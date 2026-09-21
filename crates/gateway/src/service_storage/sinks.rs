//! Extracted from `service_storage.rs`; re-exported from `crate::service_storage`.

use super::*;

#[derive(Clone, Debug)]
pub(crate) enum ManagedChildIdentity {
    Supplied {
        scope: ManagedOperationScope,
        parent_operation_id: uuid::Uuid,
    },
    Deterministic {
        parent: uuid::Uuid,
        role: ManagedChildRole,
    },
}

pub(crate) struct ManagedDirectSink {
    pub(crate) sink: DirectS3Sink,
    pub(crate) journal: Arc<dyn OperationJournal>,
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) repository: Arc<dyn ManagedRepository>,
    pub(crate) lease: crate::managed::PhysicalWriteLease,
    pub(crate) logical_parent_operation_id: Option<uuid::Uuid>,
    pub(crate) lease_stop: Option<watch::Sender<()>>,
}

impl Drop for ManagedDirectSink {
    fn drop(&mut self) {
        if let Some(stop) = self.lease_stop.take() {
            let _ = stop.send(());
        }
    }
}

pub(crate) async fn settle_managed_intent_from_journal(
    repository: &Arc<dyn ManagedRepository>,
    lease: &crate::managed::PhysicalWriteLease,
    operation: &crate::transaction::OperationRecord,
) -> Result<(), TransactionError> {
    match operation.state {
        OperationState::ProvenAborted => repository
            .abort_physical_write(lease)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string())),
        OperationState::Committed => {
            let Some(stored) = &operation.committed else {
                let reason = "committed managed operation has no provider result metadata";
                repository
                    .block_physical_write(lease, reason)
                    .await
                    .map_err(|error| TransactionError::Publication(error.to_string()))?;
                return Err(TransactionError::Publication(reason.to_string()));
            };
            if !stored.version_history_complete {
                let reason = "committed managed operation has ambiguous provider version history";
                repository
                    .block_physical_write(lease, reason)
                    .await
                    .map_err(|error| TransactionError::Publication(error.to_string()))?;
                return Err(TransactionError::CompletionAmbiguous);
            }
            repository
                .commit_physical_write(
                    lease,
                    &stored.superseded_version_ids,
                    stored.version_id.as_deref(),
                )
                .await
                .map_err(|error| TransactionError::Publication(error.to_string()))
        }
        state => {
            let reason = format!(
                "managed operation remains unresolved in journal state {}",
                state.as_str()
            );
            repository
                .block_physical_write(lease, &reason)
                .await
                .map_err(|error| TransactionError::Publication(error.to_string()))?;
            Err(TransactionError::CompletionAmbiguous)
        }
    }
}

#[async_trait::async_trait]
pub(crate) trait ManagedDestination: Send {
    async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError>;
    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError>;
    async fn complete(
        &mut self,
        authority: &DestinationCommitAuthority,
    ) -> Result<StoredObjectMeta, TransactionError>;
    async fn abort(&mut self) -> Result<(), TransactionError>;
    fn physical_lease(&self) -> crate::managed::PhysicalWriteLease;
}

#[async_trait::async_trait]
impl ManagedDestination for ManagedDirectSink {
    fn physical_lease(&self) -> crate::managed::PhysicalWriteLease {
        self.lease.clone()
    }

    async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError> {
        self.repository
            .renew_physical_write_intent(
                &self.lease,
                crate::transaction::unix_time_ms()
                    .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
            )
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        self.sink.write(chunk).await
    }

    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError> {
        self.repository
            .renew_physical_write_intent(
                &self.lease,
                crate::transaction::unix_time_ms()
                    .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
            )
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        self.sink
            .verify_output(expected_size, expected_sha256)
            .await
    }

    async fn complete(
        &mut self,
        _authority: &DestinationCommitAuthority,
    ) -> Result<StoredObjectMeta, TransactionError> {
        self.repository
            .renew_physical_write_intent(
                &self.lease,
                crate::transaction::unix_time_ms()
                    .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
            )
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        let journal = self.journal.clone();
        let stored = match complete_reconciled(self, &journal).await {
            Ok(stored) => stored,
            Err(error) => {
                let reason =
                    format!("provider completion did not prove exact version history: {error}");
                self.repository
                    .block_physical_write(&self.lease, &reason)
                    .await
                    .map_err(|ledger_error| {
                        TransactionError::Publication(format!(
                            "{reason}; additionally failed to block its physical write intent: {ledger_error}"
                        ))
                    })?;
                return Err(error);
            }
        };
        if !stored.version_history_complete {
            let reason = "provider version history is ambiguous; exact namespace purge is blocked";
            self.repository
                .block_physical_write(&self.lease, reason)
                .await
                .map_err(|error| TransactionError::Publication(error.to_string()))?;
            return Err(TransactionError::Publication(reason.to_string()));
        }
        if self.logical_parent_operation_id.is_some() {
            return Ok(stored);
        }
        if let Err(error) = self
            .repository
            .commit_physical_write(
                &self.lease,
                &stored.superseded_version_ids,
                stored.version_id.as_deref(),
            )
            .await
        {
            let reason = format!("physical version ledger commit failed: {error}");
            let _ = self
                .repository
                .block_physical_write(&self.lease, &reason)
                .await;
            return Err(TransactionError::Publication(reason));
        }
        Ok(stored)
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        self.repository
            .renew_physical_write_intent(
                &self.lease,
                crate::transaction::unix_time_ms()
                    .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
            )
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        if let Some(operation) = self.journal.get(self.operation_id).await?
            && matches!(
                operation.state,
                OperationState::Committed
                    | OperationState::CommitUnknown
                    | OperationState::Completing
            )
        {
            if self.logical_parent_operation_id.is_none() {
                settle_managed_intent_from_journal(&self.repository, &self.lease, &operation)
                    .await?;
            }
            return Err(TransactionError::CompletionAmbiguous);
        }
        self.sink.abort().await?;
        let operation = self.journal.get(self.operation_id).await?.ok_or_else(|| {
            TransactionError::Publication("managed operation journal row disappeared".to_string())
        })?;
        if self.logical_parent_operation_id.is_some() {
            if operation.state == OperationState::ProvenAborted
                && operation.exact_absence_observed_at_ms.is_some()
            {
                Ok(())
            } else {
                Err(TransactionError::CompletionAmbiguous)
            }
        } else {
            settle_managed_intent_from_journal(&self.repository, &self.lease, &operation).await
        }
    }
}

pub(crate) async fn complete_reconciled(
    destination: &mut ManagedDirectSink,
    journal: &Arc<dyn OperationJournal>,
) -> Result<StoredObjectMeta, TransactionError> {
    match destination
        .sink
        .complete(DestinationCommitAuthority::SinglePut)
        .await
    {
        Ok(stored) => Ok(stored),
        Err(original) => {
            let operation = journal
                .get(destination.operation_id)
                .await?
                .ok_or_else(|| {
                    TransactionError::Publication("managed operation disappeared".to_string())
                })?;
            if operation.state == OperationState::Committed {
                operation.committed.ok_or_else(|| {
                    TransactionError::Publication(
                        "committed managed operation has no result metadata".to_string(),
                    )
                })
            } else {
                Err(original)
            }
        }
    }
}

pub(crate) struct ManagedReplicatedSink {
    pub(crate) repository: Arc<dyn ManagedRepository>,
    pub(crate) logical: LogicalObjectKey,
    pub(crate) generation: uuid::Uuid,
    pub(crate) placement: Placement,
    pub(crate) logical_operation_id: Option<uuid::Uuid>,
    pub(crate) expected_cas: Option<u64>,
    pub(crate) metadata: BTreeMap<String, String>,
    pub(crate) primary: Box<dyn ManagedDestination>,
    pub(crate) replica: Option<Box<dyn ManagedDestination>>,
    pub(crate) output: Option<(u64, String)>,
    pub(crate) finished: bool,
}

impl ManagedReplicatedSink {
    pub(crate) async fn abandon_replica(&mut self) {
        if let Some(mut replica) = self.replica.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), replica.abort()).await;
        }
    }
}

#[async_trait::async_trait]
impl ObjectSinkTransaction for ManagedReplicatedSink {
    fn commit_state(&self) -> crate::transaction::SinkCommitState {
        if self.finished {
            crate::transaction::SinkCommitState::Committed
        } else if self.output.is_some() {
            crate::transaction::SinkCommitState::CommitUnknown
        } else {
            crate::transaction::SinkCommitState::PreCommit
        }
    }

    async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError> {
        if self.finished {
            return Err(TransactionError::Finished);
        }
        self.primary.write(chunk.clone()).await?;
        if let Some(replica) = &mut self.replica {
            let result = tokio::time::timeout(Duration::from_secs(30), replica.write(chunk)).await;
            if !matches!(result, Ok(Ok(()))) {
                self.abandon_replica().await;
            }
        }
        Ok(())
    }

    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError> {
        self.primary
            .verify_output(expected_size, expected_sha256)
            .await?;
        if let Some(replica) = &mut self.replica
            && replica
                .verify_output(expected_size, expected_sha256)
                .await
                .is_err()
        {
            self.abandon_replica().await;
        }
        self.output = Some((expected_size, expected_sha256.to_string()));
        Ok(())
    }

    async fn complete(
        &mut self,
        authority: DestinationCommitAuthority,
    ) -> Result<StoredObjectMeta, TransactionError> {
        if self.finished {
            return Err(TransactionError::Finished);
        }
        let (size, digest) = self
            .output
            .clone()
            .ok_or(TransactionError::OutputMismatch)?;
        authority
            .validate(
                self.logical_operation_id,
                &self.logical.bucket,
                &self.logical.key,
            )
            .await?;
        let primary = self.primary.complete(&authority).await?;
        let primary_lease = self.primary.physical_lease();
        let replica_status = if let Some(replica) = &mut self.replica {
            authority
                .validate(
                    self.logical_operation_id,
                    &self.logical.bucket,
                    &self.logical.key,
                )
                .await?;
            match tokio::time::timeout(Duration::from_secs(30), replica.complete(&authority)).await
            {
                Ok(Ok(_)) => CopyStatus::Ready,
                _ => CopyStatus::RepairPending,
            }
        } else if self.placement.replica_backend_id.is_some() {
            CopyStatus::RepairPending
        } else {
            CopyStatus::Absent
        };
        let now = crate::transaction::unix_time_ms();
        let authority = ObjectAuthority {
            logical: self.logical.clone(),
            generation: self.generation,
            digest,
            size,
            metadata: self.metadata.clone(),
            placement_version: self.placement.version,
            primary_backend_id: self.placement.primary_backend_id.clone(),
            primary_version_id: primary.version_id.clone(),
            replica_backend_id: self.placement.replica_backend_id.clone(),
            primary_status: CopyStatus::Ready,
            replica_status,
            tombstone: false,
            cas_version: 0,
            created_at_ms: now,
            updated_at_ms: now,
        };
        if let Some(logical_operation_id) = self.logical_operation_id {
            self.repository
                .finalize_logical_put(
                    logical_operation_id,
                    &primary_lease,
                    ExactPhysicalCommit {
                        selected_version_id: primary.version_id.clone(),
                        superseded_version_ids: primary.superseded_version_ids.clone(),
                        version_history_complete: primary.version_history_complete,
                    },
                    None,
                )
                .await
                .map_err(|error| TransactionError::Publication(error.to_string()))?;
        } else if let Err(error) = self
            .repository
            .publish(authority.clone(), self.expected_cas)
            .await
        {
            for backend_id in std::iter::once(authority.primary_backend_id.clone())
                .chain(authority.replica_backend_id.clone())
            {
                let _ = self
                    .repository
                    .enqueue(RepairRecord::copy(
                        RepairKind::DeleteGeneration,
                        &authority,
                        None,
                        backend_id,
                        RepairTargetRole::Cleanup,
                        authority.placement_version,
                    ))
                    .await;
            }
            return Err(TransactionError::Publication(error.to_string()));
        }
        self.finished = true;
        Ok(primary)
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        if self.finished {
            return Ok(());
        }
        let primary_lease = self.primary.physical_lease();
        let primary = self.primary.abort().await;
        self.abandon_replica().await;
        primary?;
        if let Some(operation_id) = self.logical_operation_id {
            self.repository
                .abort_logical_put(
                    operation_id,
                    Some(&primary_lease),
                    crate::managed::LogicalAbortProof::ChildProvenAborted,
                    "client_abort",
                    None,
                )
                .await
                .map_err(|error| TransactionError::Publication(error.to_string()))?;
        }
        self.finished = true;
        Ok(())
    }
}

/// Logical-operation wrapper around a managed authoritative sink. The inner
/// replicated sink writes the generation to the provider and publishes object
/// authority; this wrapper records the canonical usage evidence into the
/// managed authority ledger before commit and proves the logical abort on a
/// clean failure so the workspace's mutation slot and reservation are released.
pub(crate) struct ManagedLogicalSink {
    pub(crate) inner: Box<dyn ObjectSinkTransaction>,
    pub(crate) repository: Arc<dyn ManagedRepository>,
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) expected_output_size: Option<u64>,
    pub(crate) expected_output_digest: Option<String>,
    pub(crate) usage_recorded: bool,
    pub(crate) committed: bool,
}

#[async_trait::async_trait]
impl ObjectSinkTransaction for ManagedLogicalSink {
    fn commit_state(&self) -> SinkCommitState {
        if self.committed {
            SinkCommitState::Committed
        } else if self.usage_recorded {
            SinkCommitState::CommitUnknown
        } else {
            SinkCommitState::PreCommit
        }
    }

    fn durable_operation_id(&self) -> Option<uuid::Uuid> {
        Some(self.operation_id)
    }

    fn usage_journal_operation_id(&self) -> Option<uuid::Uuid> {
        // The canonical managed operation lives in the authority ledger, not
        // the child object-operation journal. Claiming its ID for usage makes
        // the server look for a journal row that deliberately does not exist.
        None
    }

    async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError> {
        if self.committed {
            return Err(TransactionError::Finished);
        }
        self.inner.write(chunk).await
    }

    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError> {
        if self.committed {
            return Err(TransactionError::Finished);
        }
        self.inner
            .verify_output(expected_size, expected_sha256)
            .await?;
        self.expected_output_size = Some(expected_size);
        self.expected_output_digest = Some(expected_sha256.to_string());
        Ok(())
    }

    async fn record_usage_evidence(&mut self, event: &UsageEvent) -> Result<(), TransactionError> {
        if self.usage_recorded {
            return Ok(());
        }
        let expected_output_size = self.expected_output_size.ok_or_else(|| {
            TransactionError::Publication(
                "managed logical usage evidence requires a verified output size".to_string(),
            )
        })?;
        let expected_output_digest = self.expected_output_digest.clone().ok_or_else(|| {
            TransactionError::Publication(
                "managed logical usage evidence requires a verified output digest".to_string(),
            )
        })?;
        let logical = self
            .repository
            .logical_operation(self.operation_id)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?
            .ok_or_else(|| {
                TransactionError::Publication("managed logical operation disappeared".to_string())
            })?;
        if logical.intent.kind != ManagedMutationKind::Put {
            return Err(TransactionError::Publication(
                "managed logical operation is not a put".to_string(),
            ));
        }
        if event.processed_bytes() != event.source_bytes().max(expected_output_size) {
            return Err(TransactionError::Publication(
                "managed usage evidence is inconsistent with the request".to_string(),
            ));
        }
        let evidence = ManagedUsageEvidence {
            expected_output_digest: Some(expected_output_digest),
            expected_output_size,
            source_bytes: event.source_bytes(),
            processed_bytes: event.processed_bytes(),
            payload: serde_json::json!({
                "route": event.route().as_str(),
                "kind": event.kind().as_str(),
                "bucket": event.bucket(),
                "pipeline_evidence": event.pipeline_evidence(),
            }),
        };
        self.repository
            .record_logical_usage_and_begin_completion(self.operation_id, evidence)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        self.usage_recorded = true;
        Ok(())
    }

    async fn complete(
        &mut self,
        authority: DestinationCommitAuthority,
    ) -> Result<StoredObjectMeta, TransactionError> {
        if self.committed {
            return Err(TransactionError::Finished);
        }
        if !self.usage_recorded {
            return Err(TransactionError::Publication(
                "managed logical usage evidence was not recorded before commit".to_string(),
            ));
        }
        let stored = self.inner.complete(authority).await?;
        self.committed = true;
        Ok(stored)
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        if self.committed {
            return Ok(());
        }
        self.inner.abort().await?;
        Ok(())
    }
}
