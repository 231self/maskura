//! Workspace streaming-operation routing leases and mutation fencing.
//!
//! Extracted from `server.rs`. Items are re-exported from [`crate::server`].

use super::*;

pub(crate) struct WorkspaceMutationFence {
    pub(crate) repository: Arc<dyn WorkspaceStorageRepository>,
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) lease: tokio::sync::Mutex<WorkspaceOperationLease>,
    pub(crate) ttl: Duration,
    pub(crate) stopped: std::sync::atomic::AtomicBool,
    pub(crate) cancelled: tokio::sync::Notify,
}

impl WorkspaceMutationFence {
    pub(crate) fn new(
        repository: Arc<dyn WorkspaceStorageRepository>,
        workspace_id: WorkspaceId,
        lease: WorkspaceOperationLease,
        ttl: Duration,
    ) -> Arc<Self> {
        let fence = Arc::new(Self {
            repository,
            workspace_id,
            lease: tokio::sync::Mutex::new(lease),
            ttl,
            stopped: std::sync::atomic::AtomicBool::new(false),
            cancelled: tokio::sync::Notify::new(),
        });
        let weak = Arc::downgrade(&fence);
        tokio::spawn(async move {
            loop {
                let Some(interval) = weak.upgrade().map(|fence| fence.heartbeat_interval()) else {
                    return;
                };
                tokio::time::sleep(interval).await;
                let Some(fence) = weak.upgrade() else {
                    return;
                };
                if fence.stopped.load(std::sync::atomic::Ordering::Acquire)
                    || fence.heartbeat().await.is_err()
                {
                    return;
                }
            }
        });
        fence
    }

    pub(crate) fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::Release);
        self.cancelled.notify_waiters();
    }

    pub(crate) async fn terminal_lease(&self) -> WorkspaceOperationLease {
        self.lease.lock().await.clone()
    }

    pub(crate) fn lost(&self) -> BackendError {
        BackendError::ambiguous("workspace routing lease was lost")
    }
}

#[async_trait::async_trait]
impl ProviderMutationFence for WorkspaceMutationFence {
    fn heartbeat_interval(&self) -> Duration {
        (self.ttl / 4).max(Duration::from_millis(1))
    }

    async fn assert_current(&self) -> Result<(), BackendError> {
        if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            return Err(self.lost());
        }
        let lease = self.lease.lock().await;
        self.repository
            .assert_streaming_operation_lease(&self.workspace_id, &lease)
            .await
            .map_err(|_| self.lost())
    }

    async fn heartbeat(&self) -> Result<(), BackendError> {
        if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            return Err(self.lost());
        }
        let mut lease = self.lease.lock().await;
        *lease = self
            .repository
            .renew_streaming_operation_lease(&self.workspace_id, &lease, self.ttl)
            .await
            .map_err(|_| {
                self.stopped
                    .store(true, std::sync::atomic::Ordering::Release);
                self.cancelled.notify_waiters();
                self.lost()
            })?;
        drop(lease);
        Ok(())
    }

    async fn cancelled(&self) {
        loop {
            let cancelled = self.cancelled.notified();
            if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            cancelled.await;
        }
    }
}

pub(crate) struct WorkspaceLeasedSink {
    pub(crate) inner: DirectS3Sink,
    pub(crate) fence: Arc<WorkspaceMutationFence>,
}

impl WorkspaceLeasedSink {
    pub(crate) async fn release(
        &self,
        outcome: WorkspaceOperationOutcome,
    ) -> Result<(), TransactionError> {
        self.fence.stop();
        let lease = self.fence.terminal_lease().await;
        self.fence
            .repository
            .release_streaming_operation_lease(&self.fence.workspace_id, &lease, outcome)
            .await
            .map_err(|_| {
                TransactionError::Publication(
                    "workspace routing lease terminal update failed".to_string(),
                )
            })
    }
}

#[async_trait::async_trait]
impl ObjectSinkTransaction for WorkspaceLeasedSink {
    fn commit_state(&self) -> crate::transaction::SinkCommitState {
        self.inner.commit_state()
    }

    fn durable_operation_id(&self) -> Option<Uuid> {
        self.inner.durable_operation_id()
    }

    async fn write(&mut self, chunk: bytes::Bytes) -> Result<(), TransactionError> {
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
        self.fence.assert_current().await.map_err(|_| {
            TransactionError::Publication("workspace routing fence changed".to_string())
        })?;
        let stored = self.inner.complete(authority).await?;
        self.release(WorkspaceOperationOutcome::Committed).await?;
        Ok(stored)
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        self.fence
            .assert_current()
            .await
            .map_err(TransactionError::Backend)?;
        self.inner.abort().await?;
        self.release(WorkspaceOperationOutcome::ProvenAborted).await
    }
}

pub(crate) fn direct_journal_allowed(
    kind: BackendKind,
    journal: Option<&Arc<dyn OperationJournal>>,
    auth_disabled: bool,
    explicit_single_tenant: bool,
) -> bool {
    journal.is_some_and(|journal| {
        journal.is_durable()
            || (kind == BackendKind::GlobalS3
                && cfg!(debug_assertions)
                && auth_disabled
                && explicit_single_tenant)
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn begin_streaming_sink(
    state: &AppState,
    backend: ResolvedBackend,
    operation: AuthorizedOperation<'_>,
    destination_operation_id: Uuid,
    bucket: &str,
    key: &str,
    content_type: &str,
    multipart_publication: Option<(&MultipartCompletionCoordinator, &MultipartIdentity, &str)>,
    metadata: Option<MultipartStoredMetadata>,
) -> Result<Box<dyn ObjectSinkTransaction>, StreamingPutError> {
    validate_streaming_backend(state, &backend)?;
    match backend {
        ResolvedBackend::S3 {
            kind,
            client,
            workspace_streaming,
        } => {
            let journal = state.operation_journal.clone().ok_or_else(|| {
                StreamingPutError::Unsupported(
                    "direct S3 streaming needs a durable operation journal".to_string(),
                )
            })?;
            if !direct_journal_allowed(
                kind,
                Some(&journal),
                state.auth_disabled,
                state.explicit_single_tenant,
            ) {
                return Err(StreamingPutError::Unsupported(
                    "direct S3 streaming needs a durable operation journal".to_string(),
                ));
            }
            let expected = ExpectedObject {
                metadata: std::collections::BTreeMap::from([(
                    "content-type".to_string(),
                    content_type.to_string(),
                )]),
                ..ExpectedObject::default()
            };
            let scope = direct_operation_scope(operation, destination_operation_id);
            let (capabilities, backend_id, workspace_lease) = match kind {
                BackendKind::PerUserS3 => {
                    let binding = workspace_streaming.ok_or_else(|| {
                        StreamingPutError::Unsupported(
                            "workspace S3 streaming needs an immutable operator attestation and durable routing lease contract"
                                .to_string(),
                        )
                    })?;
                    let workspace_id = operation.auth.workspace_id().clone();
                    let provisional = OperationRecord::direct_intent(
                        scope.clone(),
                        ObjectDestination {
                            backend_id: "PerUserS3".to_string(),
                            bucket: bucket.to_string(),
                            logical_key: key.to_string(),
                            physical_key: key.to_string(),
                            workspace_binding: None,
                        },
                        expected.clone(),
                    );
                    let lease = state
                        .workspace_storage
                        .admit_streaming_operation(
                            &workspace_id,
                            &provisional,
                            &binding.identity.config_version,
                            &binding.identity.attestation.id,
                            binding.routing_epoch,
                            WORKSPACE_OPERATION_LEASE_TTL,
                        )
                        .await
                        .map_err(|error| match error {
                            WorkspaceStorageError::AmbiguousAdmission(_) => {
                                StreamingPutError::PreserveReservation(Box::new(
                                    StreamingPutError::Unsupported(
                                        "workspace S3 streaming admission outcome is pending recovery"
                                            .to_string(),
                                    ),
                                ))
                            }
                            _ => StreamingPutError::Unsupported(
                                "workspace S3 streaming atomic admission is unavailable".to_string(),
                            ),
                        })?;
                    (
                        binding.identity.attestation.capabilities,
                        "PerUserS3".to_string(),
                        Some((binding, workspace_id, lease)),
                    )
                }
                BackendKind::GlobalS3 => (
                    state.s3_streaming_capabilities.ok_or_else(|| {
                        StreamingPutError::Unsupported(
                            "direct global S3 streaming needs MASKURA_STREAMING_S3_PROVIDER"
                                .to_string(),
                        )
                    })?,
                    format!("{kind:?}"),
                    None,
                ),
                _ => {
                    return Err(StreamingPutError::Unsupported(
                        "direct S3 streaming backend kind is unsupported".to_string(),
                    ));
                }
            };
            let destination = ObjectDestination {
                backend_id,
                bucket: bucket.to_string(),
                logical_key: key.to_string(),
                physical_key: key.to_string(),
                workspace_binding: workspace_lease.as_ref().map(|(binding, _, lease)| {
                    WorkspaceDestinationBinding {
                        backend_config_version: binding
                            .identity
                            .config_version
                            .as_str()
                            .to_string(),
                        capability_attestation_id: binding
                            .identity
                            .attestation
                            .id
                            .as_str()
                            .to_string(),
                        routing_epoch: lease.routing_epoch,
                        routing_lease_id: lease.lease_id,
                        routing_fencing_token: lease.fencing_token,
                    }
                }),
            };
            let exact_b2 = workspace_lease.as_ref().is_some_and(|(binding, _, _)| {
                binding.provider == crate::backend::WorkspaceS3Provider::B2
                    && binding.identity.attestation.exact_version_recovery
            });
            let mutation_fence = workspace_lease.as_ref().map(|(_, workspace_id, lease)| {
                WorkspaceMutationFence::new(
                    state.workspace_storage.clone(),
                    workspace_id.clone(),
                    lease.clone(),
                    WORKSPACE_OPERATION_LEASE_TTL,
                )
            });
            let mut transaction_backend = if exact_b2 {
                AwsS3TransactionBackend::new_b2(client, capabilities)
            } else {
                AwsS3TransactionBackend::new(client, capabilities)
            };
            if let Some(fence) = &mutation_fence {
                transaction_backend = transaction_backend
                    .with_mutation_fence(fence.clone() as Arc<dyn ProviderMutationFence>);
            }
            let backend = Arc::new(transaction_backend);
            let (abort_signal, mut abort_receiver) = AbortSignal::channel(1);
            let reconciler = OperationReconciler::new(
                journal.clone(),
                backend.clone(),
                format!("request-{}", uuid::Uuid::now_v7()),
            )
            .map_err(TransactionError::from)?;
            tokio::spawn(async move {
                while let Some(operation_id) = abort_receiver.recv().await {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if reconciler
                        .reconcile_operation(operation_id, Duration::from_secs(1))
                        .await
                        .is_err()
                    {
                        warn!(
                            operation_id = %operation_id,
                            error_category = "reconciliation",
                            "streaming transaction cleanup failed"
                        );
                    }
                }
            });
            let sink = if workspace_lease.is_some() {
                DirectS3Sink::new_direct_admitted(
                    journal,
                    backend,
                    scope,
                    destination,
                    expected,
                    3,
                    abort_signal,
                )
                .await
            } else {
                DirectS3Sink::new_direct(
                    journal,
                    backend,
                    scope,
                    destination,
                    expected,
                    3,
                    abort_signal,
                )
                .await
            };
            match (sink, workspace_lease) {
                (Ok(inner), Some(_)) => Ok(Box::new(WorkspaceLeasedSink {
                    inner,
                    fence: mutation_fence.expect("workspace lease created a mutation fence"),
                })),
                (Ok(inner), None) => Ok(Box::new(inner)),
                (Err(error), Some(_)) => {
                    if let Some(fence) = mutation_fence {
                        fence.stop();
                    }
                    Err(StreamingPutError::PreserveReservation(Box::new(
                        StreamingPutError::Transaction(error),
                    )))
                }
                (Err(error), None) => Err(error.into()),
            }
        }
        ResolvedBackend::PresignedHttp(_) => Err(StreamingPutError::Unsupported(
            "presigned streaming cannot durably align the authorization and transaction journals"
                .to_string(),
        )),
        ResolvedBackend::File(store) => {
            if let Some((coordinator, identity, fingerprint)) = multipart_publication {
                let operation = OperationRecord::direct_intent(
                    direct_operation_scope(operation, destination_operation_id),
                    ObjectDestination {
                        backend_id: "File".to_string(),
                        bucket: bucket.to_string(),
                        logical_key: key.to_string(),
                        physical_key: key.to_string(),
                        workspace_binding: None,
                    },
                    ExpectedObject {
                        metadata: std::collections::BTreeMap::from([(
                            "content-type".to_string(),
                            content_type.to_string(),
                        )]),
                        ..ExpectedObject::default()
                    },
                );
                coordinator
                    .open_operation(operation, identity, fingerprint)
                    .await
                    .map_err(|error| {
                        StreamingPutError::Transaction(TransactionError::Publication(
                            error.to_string(),
                        ))
                    })?;
                Ok(Box::new(
                    FileSinkTransaction::new_for_multipart_operation(
                        store,
                        bucket,
                        key,
                        content_type,
                        state.max_pipeline_output_bytes,
                        destination_operation_id,
                        metadata.clone().unwrap_or_default(),
                    )
                    .await?,
                ))
            } else {
                Ok(Box::new(
                    FileSinkTransaction::new_with_metadata(
                        store,
                        bucket,
                        key,
                        content_type,
                        state.max_pipeline_output_bytes,
                        metadata.clone().unwrap_or_default(),
                    )
                    .await?,
                ))
            }
        }
        ResolvedBackend::Memory(store) if state.dev_memory_streaming_enabled => {
            Ok(Box::new(MemorySinkTransaction::new(
                store,
                bucket,
                key,
                content_type,
                state.dev_memory_max_object_bytes,
            )?))
        }
        ResolvedBackend::Memory(_) => Err(StreamingPutError::Unsupported(
            "development memory streaming is not enabled".to_string(),
        )),
        ResolvedBackend::Managed(storage) => {
            let journal = state.operation_journal.clone().ok_or_else(|| {
                StreamingPutError::Unsupported(
                    "managed streaming needs a durable operation journal".to_string(),
                )
            })?;
            if !journal.is_durable() {
                return Err(StreamingPutError::Unsupported(
                    "managed streaming needs a durable operation journal".to_string(),
                ));
            }
            if storage.managed_mode() != ManagedStreamingMode::Enforce {
                return Err(StreamingPutError::Unsupported(
                    "managed streaming requires enforce mode".to_string(),
                ));
            }
            storage
                .validate_managed_launch_configuration()
                .map_err(|detail| {
                    StreamingPutError::Unsupported(format!(
                        "managed streaming configuration is invalid: {detail}"
                    ))
                })?;
            let capabilities = state.managed_streaming_capabilities.ok_or_else(|| {
                StreamingPutError::Unsupported(
                    "managed streaming capabilities are not configured".to_string(),
                )
            })?;
            let repository = storage.authority_repository().cloned().ok_or_else(|| {
                StreamingPutError::Unsupported(
                    "managed streaming has no authority repository".to_string(),
                )
            })?;
            let tenant_id = operation.auth.workspace_id().as_str().to_string();
            let logical = LogicalObjectKey::new(&tenant_id, bucket, key);
            let existing = repository.get(&logical).await.map_err(|error| {
                StreamingPutError::Transaction(TransactionError::Publication(error.to_string()))
            })?;
            let (expected_authority_cas, prior_logical_size) = match existing.as_ref() {
                Some(authority) => (
                    Some(authority.cas_version),
                    if authority.tombstone {
                        0
                    } else {
                        authority.size
                    },
                ),
                None => (None, 0),
            };
            let grant = operation.grant;
            // The coordinator requires the deterministic destination operation
            // in the durable journal before it can bind and commit a client
            // multipart upload. Managed storage tracks that same parent
            // operation in its authority ledger; insert the journal INTENT here
            // so completion can resolve it.
            if let Some((coordinator, identity, fingerprint)) = multipart_publication {
                let operation = OperationRecord::direct_intent(
                    direct_operation_scope(operation, destination_operation_id),
                    ObjectDestination {
                        backend_id: "Managed".to_string(),
                        bucket: bucket.to_string(),
                        logical_key: key.to_string(),
                        physical_key: key.to_string(),
                        workspace_binding: None,
                    },
                    ExpectedObject {
                        metadata: std::collections::BTreeMap::from([(
                            "content-type".to_string(),
                            content_type.to_string(),
                        )]),
                        ..ExpectedObject::default()
                    },
                );
                coordinator
                    .open_operation(operation, identity, fingerprint)
                    .await
                    .map_err(|error| {
                        StreamingPutError::Transaction(TransactionError::Publication(
                            error.to_string(),
                        ))
                    })?;
            }
            let sink = storage
                .begin_managed_put_sink(
                    journal,
                    capabilities,
                    logical,
                    content_type,
                    destination_operation_id,
                    grant.receipt_id(),
                    crate::transaction::unix_time_ms(),
                    grant.rate_version(),
                    grant.max_processed_bytes(),
                    expected_authority_cas,
                    prior_logical_size,
                )
                .await?;
            Ok(sink)
        }
    }
}

pub(crate) fn direct_operation_scope(
    operation: AuthorizedOperation<'_>,
    operation_id: Uuid,
) -> DirectOperationScope {
    DirectOperationScope {
        operation_id,
        tenant_id: operation.auth.workspace_id().as_str().to_string(),
    }
}

/// For File-backed storage, reject writes to a bucket that does not exist yet.
/// S3 buckets are explicit: a PutObject must not silently create one. Non-File
/// backends are unaffected.
pub(crate) async fn require_file_bucket(
    backend: &ResolvedBackend,
    bucket: &str,
) -> Option<axum::response::Response> {
    let ResolvedBackend::File(store) = backend else {
        return None;
    };
    match store.bucket_exists(bucket).await {
        Ok(true) => None,
        Ok(false) => Some(s3_error::no_such_bucket(bucket)),
        Err(error) => Some(s3_error::invalid_request(bucket, &error.to_string())),
    }
}

pub(crate) fn validate_streaming_backend(
    state: &AppState,
    backend: &ResolvedBackend,
) -> Result<(), StreamingPutError> {
    match backend {
        ResolvedBackend::S3 {
            kind: BackendKind::PerUserS3,
            workspace_streaming: Some(_),
            ..
        } if direct_journal_allowed(
            BackendKind::PerUserS3,
            state.operation_journal.as_ref(),
            state.auth_disabled,
            state.explicit_single_tenant,
        ) => Ok(()),
        ResolvedBackend::S3 {
            kind: BackendKind::GlobalS3,
            ..
        } if state.s3_streaming_capabilities.is_some()
            && direct_journal_allowed(
                BackendKind::GlobalS3,
                state.operation_journal.as_ref(),
                state.auth_disabled,
                state.explicit_single_tenant,
            ) => Ok(()),
        ResolvedBackend::S3 {
            kind: BackendKind::PerUserS3,
            ..
        } => Err(StreamingPutError::Unsupported(
            "workspace S3 streaming needs a trusted provider capability profile, stable routing fence, and durable operation journal"
                .to_string(),
        )),
        ResolvedBackend::S3 { .. } => Err(StreamingPutError::Unsupported(
            "direct global S3 streaming needs configured capabilities and a durable operation journal"
                .to_string(),
        )),
        ResolvedBackend::File(_) => Ok(()),
        ResolvedBackend::Memory(_) if state.dev_memory_streaming_enabled => Ok(()),
        ResolvedBackend::Memory(_) => Err(StreamingPutError::Unsupported(
            "development memory streaming is not enabled".to_string(),
        )),
        ResolvedBackend::PresignedHttp(_) => Err(StreamingPutError::Unsupported(
            "presigned streaming cannot durably align authorization and destination commit"
                .to_string(),
        )),
        ResolvedBackend::Managed(storage)
            if state.operation_journal.as_ref().is_some_and(|journal| journal.is_durable())
                && state.managed_streaming_capabilities.is_some()
                && storage.managed_mode() == ManagedStreamingMode::Enforce
                && storage
                    .authority_repository()
                    .is_some_and(|repository| repository.is_durable())
                && storage.validate_managed_launch_configuration().is_ok() =>
        {
            Ok(())
        }
        ResolvedBackend::Managed(_) => Err(StreamingPutError::Unsupported(
            "managed streaming needs a durable operation journal and authority ledger in enforce mode"
                .to_string(),
        )),
    }
}

pub(crate) async fn write_stream_record(
    sink: &Arc<tokio::sync::Mutex<Box<dyn ObjectSinkTransaction>>>,
    record: crate::record::Record,
    output_hasher: &mut sha2::Sha256,
    output_bytes: &mut u64,
) -> Result<(), StreamingPutError> {
    use sha2::Digest as _;
    for chunk in [record.payload, record.separator] {
        if chunk.is_empty() {
            continue;
        }
        *output_bytes = output_bytes
            .checked_add(chunk.len() as u64)
            .ok_or(StreamingPutError::InputTooLarge)?;
        output_hasher.update(&chunk);
        sink.lock().await.write(chunk).await?;
    }
    Ok(())
}

pub(crate) struct SinkAbortGuard {
    pub(crate) sink: Arc<tokio::sync::Mutex<Box<dyn ObjectSinkTransaction>>>,
    pub(crate) armed: bool,
}

impl SinkAbortGuard {
    pub(crate) fn new(sink: Box<dyn ObjectSinkTransaction>) -> Self {
        Self {
            sink: Arc::new(tokio::sync::Mutex::new(sink)),
            armed: true,
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SinkAbortGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let sink = Arc::clone(&self.sink);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = sink.lock().await.abort().await;
            });
        }
    }
}
