//! Extracted from `service_storage.rs`; re-exported from `crate::service_storage`.

use super::*;

#[derive(Debug)]
pub struct ServiceStorage {
    pub backends: Vec<ServiceBackend>,
    pub(crate) clients: RwLock<Vec<Option<Client>>>,
    pub(crate) authority: Option<Arc<dyn ManagedRepository>>,
    pub(crate) managed_mode: ManagedStreamingMode,
    pub(crate) placement_version: u32,
    pub(crate) managed_versioning_capability: Option<BackendVersioningCapability>,
}

pub(crate) enum DurableBackendValidationError {
    Transient,
    Blocked(String),
}

pub(crate) fn legacy_hash(value: impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

impl ServiceStorage {
    pub fn new(backends: Vec<ServiceBackend>) -> Self {
        let n = backends.len();
        let clients = RwLock::new(vec![None; n]);
        Self {
            backends,
            clients,
            authority: None,
            managed_mode: ManagedStreamingMode::Off,
            placement_version: PLACEMENT_VERSION_V1,
            managed_versioning_capability: None,
        }
    }

    pub fn with_management(
        backends: Vec<ServiceBackend>,
        authority: Arc<dyn ManagedRepository>,
        managed_mode: ManagedStreamingMode,
        placement_version: u32,
    ) -> Self {
        let mut storage = Self::new(backends);
        storage.authority = Some(authority);
        storage.managed_mode = managed_mode;
        storage.placement_version = placement_version.max(1);
        storage
    }

    pub fn with_managed_capabilities(mut self, capabilities: Option<BackendCapabilities>) -> Self {
        self.managed_versioning_capability =
            capabilities.map(|capabilities| match capabilities.versioning {
                VersioningCapability::Unsupported => BackendVersioningCapability::Unsupported,
                VersioningCapability::Optional => BackendVersioningCapability::Optional,
                VersioningCapability::Required => BackendVersioningCapability::Required,
            });
        self
    }

    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    pub fn managed_mode(&self) -> ManagedStreamingMode {
        self.managed_mode
    }

    pub fn placement_version(&self) -> u32 {
        self.placement_version
    }

    pub fn authority_repository(&self) -> Option<&Arc<dyn ManagedRepository>> {
        self.authority.as_ref()
    }

    /// Lists only authoritative logical objects. Provider buckets hold opaque
    /// generation keys and must never be exposed through the S3 front door.
    pub async fn list_authority(
        &self,
        query: AuthorityListQuery,
    ) -> Result<AuthorityListPage, ManagedError> {
        self.authority_repository_required()?
            .list_authority(query)
            .await
    }

    /// Reconciles one stale authority to a desired placement. A ready authority
    /// that already occupies every desired location advances by CAS without a
    /// provider copy; otherwise only the missing placement repair legs are
    /// enqueued from an already verified ready authority location.
    pub async fn reconcile_authority_placement(
        &self,
        authority: &ObjectAuthority,
        desired: &Placement,
    ) -> Result<(), ManagedError> {
        if authority.tombstone || authority.placement_version >= desired.version {
            return Ok(());
        }
        let repository = self.authority_repository_required()?;
        let locations_match = authority.primary_backend_id == desired.primary_backend_id
            && authority.primary_status == CopyStatus::Ready
            && match desired.replica_backend_id.as_deref() {
                Some(replica) => {
                    authority.replica_backend_id.as_deref() == Some(replica)
                        && authority.replica_status == CopyStatus::Ready
                }
                None => {
                    authority.replica_backend_id.is_none()
                        && authority.replica_status == CopyStatus::Absent
                }
            };
        if locations_match {
            repository
                .advance_placement_version(&authority.logical, authority.cas_version, desired)
                .await?;
            return Ok(());
        }

        let source = if authority.primary_status == CopyStatus::Ready {
            Some(authority.primary_backend_id.clone())
        } else if authority.replica_status == CopyStatus::Ready {
            authority.replica_backend_id.clone()
        } else {
            None
        }
        .ok_or_else(|| {
            ManagedError::Persistence(
                "stale authority has no verified ready source for placement repair".to_string(),
            )
        })?;

        let primary_matches = authority.primary_backend_id == desired.primary_backend_id
            && authority.primary_status == CopyStatus::Ready;
        // A primary leg is also the durable way to remove an obsolete replica.
        if !primary_matches
            || (desired.replica_backend_id.is_none() && authority.replica_backend_id.is_some())
        {
            repository
                .enqueue(RepairRecord::placement(
                    authority,
                    Some(source.clone()),
                    desired.primary_backend_id.clone(),
                    RepairTargetRole::Primary,
                    desired,
                ))
                .await?;
        }
        if let Some(replica) = &desired.replica_backend_id
            && (authority.replica_backend_id.as_deref() != Some(replica)
                || authority.replica_status != CopyStatus::Ready)
        {
            repository
                .enqueue(RepairRecord::placement(
                    authority,
                    Some(source),
                    replica.clone(),
                    RepairTargetRole::Replica,
                    desired,
                ))
                .await?;
        }
        Ok(())
    }

    /// Processes one bounded global page of authorities behind this storage's
    /// placement version. The returned cursor can resume the same keyset scan.
    pub async fn reconcile_authority_placement_page(
        &self,
        after: Option<AuthorityPlacementCursor>,
        limit: u64,
    ) -> Result<AuthorityPlacementPage, ManagedError> {
        let repository = self.authority_repository_required()?;
        let page = repository
            .list_authority_below_placement_version(AuthorityPlacementPageQuery {
                target_placement_version: self.placement_version,
                after,
                limit,
            })
            .await?;
        for authority in &page.objects {
            let desired = self.placement(&authority.logical).ok_or_else(|| {
                ManagedError::Persistence("managed storage has no backends".to_string())
            })?;
            self.reconcile_authority_placement(authority, &desired)
                .await?;
        }
        Ok(page)
    }

    /// Aggregate of authorities still below the target placement version.
    pub async fn authority_placement_stats(&self) -> Result<AuthorityPlacementStats, ManagedError> {
        self.authority_repository_required()?
            .authority_placement_stats(self.placement_version)
            .await
    }

    /// Counts of repair records grouped by lifecycle state.
    pub async fn repair_state_counts(&self) -> Result<RepairStateCounts, ManagedError> {
        self.authority_repository_required()?
            .repair_state_counts()
            .await
    }

    /// Validate the launch topology before enabling transactional managed
    /// mutations. Observe/off modes retain the legacy multi-provider topology.
    pub fn validate_managed_launch_configuration(&self) -> Result<(), String> {
        if self.managed_mode != ManagedStreamingMode::Enforce {
            return Ok(());
        }
        if self.backends.is_empty() {
            return Err(
                "transactional managed mode requires one or more managed B2 or AWS backends at launch"
                    .to_string(),
            );
        }
        let mut backend_ids = HashSet::with_capacity(self.backends.len());
        for backend in &self.backends {
            if !matches!(backend.provider_kind(), "b2" | "aws") {
                return Err(
                    "transactional managed mode supports only B2 and AWS backend pools at launch"
                        .to_string(),
                );
            }
            if reqwest::Url::parse(&backend.endpoint)
                .ok()
                .is_none_or(|endpoint| endpoint.scheme() != "https")
            {
                return Err(
                    "transactional managed storage requires HTTPS provider endpoints".to_string(),
                );
            }
            if backend.storage_identity().is_none()
                || backend.provider_account_id().is_none()
                || !backend.credential_epoch().is_some_and(|epoch| epoch > 0)
            {
                return Err(
                    "transactional managed storage requires explicit provider instance/account identity and a positive credential epoch"
                        .to_string(),
                );
            }
            if backend.placement_weight().is_none_or(|weight| weight == 0) {
                return Err(
                    "transactional managed storage requires positive static placement weight and capacity units"
                        .to_string(),
                );
            }
            if !backend_ids.insert(backend.id()) {
                return Err(
                    "transactional managed storage requires unique stable backend IDs".to_string(),
                );
            }
        }
        Ok(())
    }

    pub async fn assert_namespace_active(&self, tenant_id: &str) -> Result<(), ManagedError> {
        self.authority_repository_required()?
            .assert_namespace_active(tenant_id)
            .await
    }

    pub async fn begin_managed_multipart(
        &self,
        upload_id: &str,
        tenant_id: &str,
    ) -> Result<u64, ManagedError> {
        self.authority_repository_required()?
            .begin_multipart_activity(upload_id, tenant_id)
            .await
    }

    pub async fn assert_managed_multipart(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
        allow_purging: bool,
    ) -> Result<(), ManagedError> {
        self.authority_repository_required()?
            .assert_multipart_activity(upload_id, tenant_id, namespace_epoch, allow_purging)
            .await
    }

    pub async fn confirm_managed_multipart(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        self.authority_repository_required()?
            .confirm_multipart_activity(upload_id, tenant_id, namespace_epoch)
            .await
    }

    pub async fn reconcile_managed_multipart_activities(
        &self,
        limit: u64,
    ) -> Result<u64, ManagedError> {
        self.authority_repository_required()?
            .reconcile_multipart_activities(limit)
            .await
    }

    pub async fn finish_managed_multipart(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        self.authority_repository_required()?
            .finish_multipart_activity(upload_id, tenant_id, namespace_epoch)
            .await
    }

    /// Start an idempotent authority-backed namespace purge. Physical deletion
    /// policy belongs to the authority implementation; this method never lists
    /// or deletes backend objects itself.
    pub async fn purge_namespace(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        let Some(authority) = &self.authority else {
            return Ok(NamespacePurgeStatus::Unsupported {
                reason: "managed namespace purge requires an authority repository".to_string(),
            });
        };
        if self.managed_mode != ManagedStreamingMode::Enforce {
            return Ok(NamespacePurgeStatus::Unsupported {
                reason: "complete managed namespace purge requires enforce mode and its exact physical-version ledger"
                    .to_string(),
            });
        }
        let status = authority.purge_namespace(request).await?;
        if matches!(
            status,
            NamespacePurgeStatus::Running | NamespacePurgeStatus::Blocked { .. }
        ) {
            self.drive_namespace_purge(authority, request).await
        } else {
            Ok(status)
        }
    }

    /// Query an authority-backed namespace purge without starting or advancing
    /// it. An unconfigured authority is explicitly unsupported, not complete.
    pub async fn namespace_purge_status(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        let Some(authority) = &self.authority else {
            return Ok(NamespacePurgeStatus::Unsupported {
                reason: "managed namespace purge status requires an authority repository"
                    .to_string(),
            });
        };
        if self.managed_mode != ManagedStreamingMode::Enforce {
            return Ok(NamespacePurgeStatus::Unsupported {
                reason: "complete managed namespace purge requires enforce mode and its exact physical-version ledger"
                    .to_string(),
            });
        }
        let status = authority.namespace_purge_status(request).await?;
        if matches!(
            status,
            NamespacePurgeStatus::Running | NamespacePurgeStatus::Blocked { .. }
        ) {
            self.drive_namespace_purge(authority, request).await
        } else {
            Ok(status)
        }
    }

    pub(crate) async fn drive_namespace_purge(
        &self,
        authority: &Arc<dyn ManagedRepository>,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        for target in authority.purge_targets(request, 64).await? {
            if let Err(reason) = self.delete_and_verify_purge_target(&target).await {
                authority
                    .mark_purge_target_blocked(request, &target, &reason)
                    .await?;
                continue;
            }
            authority
                .mark_purge_target_deleted(request, &target)
                .await?;
        }
        authority.namespace_purge_status(request).await
    }

    pub(crate) async fn delete_and_verify_purge_target(
        &self,
        target: &PhysicalVersionTarget,
    ) -> Result<(), String> {
        let index = self
            .index_for_id(&target.backend_id)
            .ok_or_else(|| format!("unknown managed backend {}", target.backend_id))?;
        if !self.backends[index]
            .matches_persisted_identity(&target.storage_identity, target.credential_epoch)
        {
            return Err(format!(
                "managed backend {} storage identity changed or its credential epoch moved backwards since the physical version was written",
                target.backend_id
            ));
        }
        if self.backends[index].bucket != target.provider_bucket {
            return Err(format!(
                "managed backend {} bucket changed from {} to {}",
                target.backend_id, target.provider_bucket, self.backends[index].bucket
            ));
        }
        let current_versioning = self.versioning_mode(index).await;
        if target.versioning_mode == BackendVersioningMode::Unknown
            || current_versioning == BackendVersioningMode::Unknown
        {
            return Err(format!(
                "managed backend {} bucket versioning mode is unknown",
                target.backend_id
            ));
        }
        if current_versioning != target.versioning_mode {
            return Err(format!(
                "managed backend {} bucket versioning mode changed from {} to {}",
                target.backend_id,
                target.versioning_mode.as_str(),
                current_versioning.as_str()
            ));
        }
        if self.managed_versioning_capability != Some(target.versioning_capability) {
            return Err(format!(
                "managed backend {} versioning capability is unknown or changed",
                target.backend_id
            ));
        }
        if target.version_id.is_none()
            && (target.versioning_mode != BackendVersioningMode::Unversioned
                || target.versioning_capability != BackendVersioningCapability::Unsupported)
        {
            return Err(format!(
                "managed backend {} cannot prove an unversioned ledger target has no historical versions",
                target.backend_id
            ));
        }
        let client = self
            .client_for(index)
            .await
            .ok_or_else(|| format!("managed backend {} is unavailable", target.backend_id))?;
        let mut delete = client
            .delete_object()
            .bucket(&target.provider_bucket)
            .key(&target.physical_key);
        if let Some(version_id) = &target.version_id {
            delete = delete.version_id(version_id);
        }
        if let Err(error) = delete.send().await
            && !error
                .raw_response()
                .is_some_and(|response| response.status().as_u16() == 404)
        {
            return Err(record_s3_failure("managed_delete_version", &error).to_string());
        }

        let mut head = client
            .head_object()
            .bucket(&target.provider_bucket)
            .key(&target.physical_key);
        if let Some(version_id) = &target.version_id {
            head = head.version_id(version_id);
        }
        match head.send().await {
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_not_found()) =>
            {
                Ok(())
            }
            Err(error) => Err(record_s3_failure("managed_verify_delete", &error).to_string()),
            Ok(_) => Err(format!(
                "managed physical version on {} is still present after deletion",
                target.backend_id
            )),
        }
    }

    pub fn placement(&self, logical: &LogicalObjectKey) -> Option<Placement> {
        weighted_rendezvous_placement(
            self.placement_version,
            &logical.tenant_id,
            &logical.object_key(),
            self.backends.iter().filter_map(|backend| {
                backend
                    .placement_weight()
                    .map(|weight| (backend.id(), weight))
            }),
        )
    }

    pub(crate) fn get_backend_ids(&self, key: &str) -> (usize, Option<usize>) {
        // Keep direct and pre-authority managed objects on the exact legacy
        // ring. New rendezvous placement applies only to authority-backed
        // immutable generations.
        let hash = legacy_hash(key);
        let mut ring = BTreeMap::new();
        for (backend_index, backend) in self.backends.iter().enumerate() {
            for vnode in 0..LEGACY_VIRTUAL_NODES {
                ring.insert(
                    legacy_hash(format!("{}:{vnode}", backend.id())),
                    backend_index,
                );
            }
        }
        let primary = ring
            .range(hash..)
            .next()
            .or_else(|| ring.iter().next())
            .map(|(_, &backend_index)| backend_index)
            .unwrap_or(0);
        let replica = (self.backends.len() > 1)
            .then(|| {
                ring.range(hash..)
                    .chain(ring.iter())
                    .find(|&(_, backend_index)| *backend_index != primary)
                    .map(|(_, &backend_index)| backend_index)
            })
            .flatten();
        (primary, replica)
    }

    pub(crate) fn index_for_id(&self, backend_id: &str) -> Option<usize> {
        self.backends
            .iter()
            .position(|backend| backend.id() == backend_id)
    }

    pub(crate) async fn client_for(&self, index: usize) -> Option<Client> {
        {
            let clients = self.clients.read().await;
            if let Some(Some(c)) = clients.get(index) {
                return Some(c.clone());
            }
        }
        let client = self.backends[index].build_client().await;
        if let Some(ref c) = client {
            let mut clients = self.clients.write().await;
            clients[index] = Some(c.clone());
        }
        client
    }

    pub(crate) async fn versioning_mode(&self, index: usize) -> BackendVersioningMode {
        let Some(client) = self.client_for(index).await else {
            return BackendVersioningMode::Unknown;
        };
        match client
            .get_bucket_versioning()
            .bucket(&self.backends[index].bucket)
            .send()
            .await
        {
            Ok(output) => match output.status().map(|status| status.as_str()) {
                Some("Enabled") => BackendVersioningMode::Enabled,
                Some("Suspended") => BackendVersioningMode::Suspended,
                None => BackendVersioningMode::Unversioned,
                Some(_) => BackendVersioningMode::Unknown,
            },
            Err(error) => {
                record_s3_failure("managed_get_bucket_versioning", &error);
                BackendVersioningMode::Unknown
            }
        }
    }

    pub(crate) async fn validate_durable_intent_backend(
        &self,
        durable: &DurablePhysicalWriteIntent,
    ) -> Result<usize, DurableBackendValidationError> {
        let intent = &durable.intent;
        let index = self.index_for_id(&intent.backend_id).ok_or_else(|| {
            DurableBackendValidationError::Blocked(format!(
                "unknown managed backend {}",
                intent.backend_id
            ))
        })?;
        if !self.backends[index]
            .matches_persisted_identity(&intent.storage_identity, intent.credential_epoch)
        {
            return Err(DurableBackendValidationError::Blocked(format!(
                "managed backend {} storage identity changed or its credential epoch moved backwards while a write intent was unresolved",
                intent.backend_id
            )));
        }
        if self.backends[index].bucket != intent.provider_bucket {
            return Err(DurableBackendValidationError::Blocked(format!(
                "managed backend {} bucket changed while a write intent was unresolved",
                intent.backend_id
            )));
        }
        let current_versioning = self.versioning_mode(index).await;
        if intent.versioning_mode == BackendVersioningMode::Unknown {
            return Err(DurableBackendValidationError::Blocked(format!(
                "managed backend {} persisted an unknown versioning mode while a write intent was unresolved",
                intent.backend_id
            )));
        }
        if current_versioning == BackendVersioningMode::Unknown {
            return Err(DurableBackendValidationError::Transient);
        }
        if current_versioning != intent.versioning_mode {
            return Err(DurableBackendValidationError::Blocked(format!(
                "managed backend {} versioning mode is unknown or changed while a write intent was unresolved",
                intent.backend_id
            )));
        }
        if self.managed_versioning_capability != Some(intent.versioning_capability) {
            return Err(DurableBackendValidationError::Blocked(format!(
                "managed backend {} versioning capability changed while a write intent was unresolved",
                intent.backend_id
            )));
        }
        Ok(index)
    }

    pub async fn reconcile_managed_write_intents(
        &self,
        journal: Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        stale_after: Duration,
        limit: u64,
    ) -> Result<usize, ManagedError> {
        let repository = self.authority_repository_required()?;
        let intents = repository.pending_physical_write_intents(limit).await?;
        let count = intents.len();
        for durable in intents {
            if durable.lease_expires_at_ms > crate::transaction::unix_time_ms() {
                continue;
            }
            let intent = &durable.intent;
            let owner = format!("managed-reconciler-{}", uuid::Uuid::now_v7());
            let Some(lease) = repository
                .claim_expired_physical_write_intent(
                    intent.intent_id,
                    &owner,
                    crate::transaction::unix_time_ms()
                        .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
                )
                .await?
            else {
                continue;
            };
            let index = match self.validate_durable_intent_backend(&durable).await {
                Ok(index) => index,
                Err(DurableBackendValidationError::Transient) => continue,
                Err(DurableBackendValidationError::Blocked(reason)) => {
                    repository.block_physical_write(&lease, &reason).await?;
                    continue;
                }
            };
            let Some(mut operation) = journal
                .get(intent.intent_id)
                .await
                .map_err(|error| ManagedError::Persistence(error.to_string()))?
            else {
                repository
                    .block_physical_write(
                        &lease,
                        "managed write intent has no operation journal row",
                    )
                    .await?;
                continue;
            };
            if operation.tenant_id.as_deref() != Some(intent.tenant_id.as_str())
                || operation.namespace_epoch != Some(durable.namespace_epoch)
                || operation.destination.backend_id != intent.backend_id
                || operation.destination.bucket != intent.provider_bucket
                || operation.destination.physical_key != intent.physical_key
            {
                repository
                    .block_physical_write(
                        &lease,
                        "managed write intent does not match its operation journal identity",
                    )
                    .await?;
                continue;
            }
            if !operation.state.is_terminal() {
                let client = self.client_for(index).await.ok_or_else(|| {
                    ManagedError::Persistence(format!(
                        "managed backend {} is unavailable",
                        intent.backend_id
                    ))
                })?;
                let backend: Arc<dyn TransactionBackend> = if self.backends[index].is_b2() {
                    Arc::new(AwsS3TransactionBackend::new_managed_b2(
                        client,
                        capabilities,
                    ))
                } else {
                    Arc::new(AwsS3TransactionBackend::new(client, capabilities))
                };
                let reconciler = OperationReconciler::new(
                    journal.clone(),
                    backend,
                    format!("managed-intent-{}", uuid::Uuid::now_v7()),
                )
                .map_err(|error| ManagedError::Persistence(error.to_string()))?;
                if let Err(error) = reconciler
                    .reconcile_operation(intent.intent_id, stale_after)
                    .await
                {
                    repository
                        .block_physical_write(
                            &lease,
                            &format!("managed operation reconciliation failed: {error}"),
                        )
                        .await?;
                    continue;
                }
                operation = journal
                    .get(intent.intent_id)
                    .await
                    .map_err(|error| ManagedError::Persistence(error.to_string()))?
                    .ok_or_else(|| {
                        ManagedError::Persistence(
                            "managed operation disappeared after reconciliation".to_string(),
                        )
                    })?;
            }
            match (operation.state, operation.committed) {
                (OperationState::ProvenAborted, _)
                    if operation.exact_absence_observed_at_ms.is_some() =>
                {
                    repository.abort_physical_write(&lease).await?;
                }
                (OperationState::ProvenAborted, _) => {
                    repository
                        .block_physical_write(
                            &lease,
                            "managed operation is aborted without exact absence evidence",
                        )
                        .await?;
                }
                (OperationState::Committed, Some(stored)) if stored.version_history_complete => {
                    repository
                        .commit_physical_write(
                            &lease,
                            &stored.superseded_version_ids,
                            stored.version_id.as_deref(),
                        )
                        .await?;
                }
                (OperationState::Committed, _) => {
                    repository
                        .block_physical_write(
                            &lease,
                            "managed operation committed with ambiguous or missing version history",
                        )
                        .await?;
                }
                (state, _) => {
                    // A fresh operation not claimed by the stale lease remains
                    // pending. Purge cannot complete while its intent exists.
                    if operation.updated_at_ms
                        <= crate::transaction::unix_time_ms()
                            .saturating_sub(stale_after.as_millis() as i64)
                    {
                        repository
                            .block_physical_write(
                                &lease,
                                &format!(
                                    "managed operation remains unresolved in journal state {}",
                                    state.as_str()
                                ),
                            )
                            .await?;
                    }
                }
            }
        }
        Ok(count)
    }

    /// Recover stale logical managed writes from their immutable publication
    /// recipe and terminal child journal. Ambiguous evidence is retained for
    /// operator action instead of releasing quota or deriving current routing.
    pub async fn reconcile_managed_logical_operations(
        &self,
        journal: Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        stale_after: Duration,
        limit: u64,
    ) -> Result<usize, ManagedError> {
        let repository = self.authority_repository_required()?;
        let now = crate::transaction::unix_time_ms();
        let owner = format!("managed-logical-reconciler-{}", uuid::Uuid::now_v7());
        let claims = repository
            .claim_stale_logical_operations(
                &owner,
                now.saturating_sub(stale_after.as_millis() as i64),
                now.saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
                limit,
            )
            .await?;
        let count = claims.len();
        for mut claim in claims {
            let operation = claim.operation.clone();
            let durable = repository
                .physical_write_intent(operation.intent.primary_child_operation_id)
                .await?;
            let child = match journal
                .get(operation.intent.primary_child_operation_id)
                .await
            {
                Ok(child) => child,
                Err(_) => continue,
            };
            if matches!(
                operation.state,
                ManagedLogicalOperationState::Intent | ManagedLogicalOperationState::Open
            ) && durable.is_none()
                && child.is_none()
            {
                match repository
                    .abort_logical_put(
                        operation.intent.operation_id,
                        None,
                        crate::managed::LogicalAbortProof::NoChildStarted,
                        "proven_no_child",
                        Some(&claim),
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(ManagedError::RecoveryBlocked(reason)) => {
                        warn!(
                            operation_id = %operation.intent.operation_id,
                            reason,
                            "managed logical recovery blocked"
                        );
                        repository
                            .mark_logical_recovery_blocked(&claim, reason)
                            .await?;
                    }
                    Err(_) => {}
                }
                continue;
            }
            if operation.intent.publication_recipe.is_none() {
                if operation.state != ManagedLogicalOperationState::RecoveryBlocked {
                    warn!(
                        operation_id = %operation.intent.operation_id,
                        reason = "missing_publication_recipe",
                        "managed logical recovery blocked"
                    );
                }
                repository
                    .mark_logical_recovery_blocked(&claim, "missing_publication_recipe")
                    .await?;
                continue;
            }
            let Some(durable) = durable else {
                if operation.state != ManagedLogicalOperationState::RecoveryBlocked {
                    warn!(
                        operation_id = %operation.intent.operation_id,
                        reason = "missing_physical_intent",
                        "managed logical recovery blocked"
                    );
                }
                repository
                    .mark_logical_recovery_blocked(&claim, "missing_physical_intent")
                    .await?;
                continue;
            };
            let Some(mut child) = child else {
                if operation.state != ManagedLogicalOperationState::RecoveryBlocked {
                    warn!(
                        operation_id = %operation.intent.operation_id,
                        reason = "missing_child_journal",
                        "managed logical recovery blocked"
                    );
                }
                repository
                    .mark_logical_recovery_blocked(&claim, "missing_child_journal")
                    .await?;
                continue;
            };
            if child.tenant_id.as_deref() != Some(operation.intent.logical.tenant_id.as_str())
                || child.namespace_epoch != Some(operation.intent.fence.namespace_epoch)
                || child.destination.backend_id != operation.intent.backend_id
                || child.destination.bucket != operation.intent.provider_bucket
                || child.destination.physical_key != operation.intent.physical_key
                || child.expected.digest
                    != operation
                        .evidence
                        .as_ref()
                        .and_then(|evidence| evidence.expected_output_digest.clone())
                || child.expected.size
                    != operation
                        .evidence
                        .as_ref()
                        .map(|evidence| evidence.expected_output_size)
            {
                if operation.state != ManagedLogicalOperationState::RecoveryBlocked {
                    warn!(
                        operation_id = %operation.intent.operation_id,
                        reason = "child_evidence_mismatch",
                        "managed logical recovery blocked"
                    );
                }
                repository
                    .mark_logical_recovery_blocked(&claim, "child_evidence_mismatch")
                    .await?;
                continue;
            }
            let index = match self.validate_durable_intent_backend(&durable).await {
                Ok(index) => index,
                Err(DurableBackendValidationError::Transient) => continue,
                Err(DurableBackendValidationError::Blocked(_)) => {
                    if operation.state != ManagedLogicalOperationState::RecoveryBlocked {
                        warn!(
                            operation_id = %operation.intent.operation_id,
                            reason = "provider_binding_mismatch",
                            "managed logical recovery blocked"
                        );
                    }
                    repository
                        .mark_logical_recovery_blocked(&claim, "provider_binding_mismatch")
                        .await?;
                    continue;
                }
            };
            claim = match repository
                .renew_logical_recovery_claim(
                    &claim,
                    crate::transaction::unix_time_ms()
                        .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
                )
                .await
            {
                Ok(claim) => claim,
                Err(_) => continue,
            };
            let Some(lease) = repository
                .claim_logical_physical_write_intent(
                    &claim,
                    crate::transaction::unix_time_ms()
                        .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
                )
                .await?
            else {
                continue;
            };
            if !child.state.is_terminal() {
                let Some(client) = self.client_for(index).await else {
                    continue;
                };
                let backend: Arc<dyn TransactionBackend> = if self.backends[index].is_b2() {
                    Arc::new(AwsS3TransactionBackend::new_managed_b2(
                        client,
                        capabilities,
                    ))
                } else {
                    Arc::new(AwsS3TransactionBackend::new(client, capabilities))
                };
                let reconciler = OperationReconciler::new(journal.clone(), backend, owner.clone())
                    .map_err(|error| ManagedError::Persistence(error.to_string()))?;
                if reconciler
                    .reconcile_operation(child.id, stale_after)
                    .await
                    .is_err()
                {
                    continue;
                }
                claim = match repository
                    .renew_logical_recovery_claim(
                        &claim,
                        crate::transaction::unix_time_ms()
                            .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
                    )
                    .await
                {
                    Ok(claim) => claim,
                    Err(_) => continue,
                };
                child = journal
                    .get(child.id)
                    .await
                    .map_err(|error| ManagedError::Persistence(error.to_string()))?
                    .ok_or_else(|| {
                        ManagedError::Persistence("child journal disappeared".to_string())
                    })?;
            }
            match (child.state, child.committed) {
                (OperationState::Committed, Some(stored)) if stored.version_history_complete => {
                    match repository
                        .finalize_logical_put(
                            operation.intent.operation_id,
                            &lease,
                            ExactPhysicalCommit {
                                selected_version_id: stored.version_id,
                                superseded_version_ids: stored.superseded_version_ids,
                                version_history_complete: true,
                            },
                            Some(&claim),
                        )
                        .await
                    {
                        Ok(_) => {}
                        Err(
                            ManagedError::Persistence(_)
                            | ManagedError::MutationInProgress
                            | ManagedError::Conflict,
                        ) => continue,
                        Err(ManagedError::RecoveryBlocked(reason)) => {
                            if operation.state != ManagedLogicalOperationState::RecoveryBlocked {
                                warn!(
                                    operation_id = %operation.intent.operation_id,
                                    reason,
                                    "managed logical recovery blocked"
                                );
                            }
                            repository
                                .mark_logical_recovery_blocked(&claim, reason)
                                .await?;
                        }
                        Err(_) => continue,
                    }
                }
                (OperationState::ProvenAborted, _)
                    if child.exact_absence_observed_at_ms.is_some() =>
                {
                    match repository
                        .abort_logical_put(
                            operation.intent.operation_id,
                            Some(&lease),
                            crate::managed::LogicalAbortProof::ChildProvenAborted,
                            "child_proven_aborted",
                            Some(&claim),
                        )
                        .await
                    {
                        Ok(_) => {}
                        Err(ManagedError::RecoveryBlocked(reason)) => {
                            warn!(
                                operation_id = %operation.intent.operation_id,
                                reason,
                                "managed logical recovery blocked"
                            );
                            repository
                                .mark_logical_recovery_blocked(&claim, reason)
                                .await?;
                        }
                        Err(_) => continue,
                    }
                }
                (OperationState::Committed, _) => {
                    if operation.state != ManagedLogicalOperationState::RecoveryBlocked {
                        warn!(
                            operation_id = %operation.intent.operation_id,
                            reason = "incomplete_version_history",
                            "managed logical recovery blocked"
                        );
                    }
                    repository
                        .mark_logical_recovery_blocked(&claim, "incomplete_version_history")
                        .await?;
                }
                (OperationState::ProvenAborted, _) => {
                    if operation.state != ManagedLogicalOperationState::RecoveryBlocked {
                        warn!(
                            operation_id = %operation.intent.operation_id,
                            reason = "absence_not_proven",
                            "managed logical recovery blocked"
                        );
                    }
                    repository
                        .mark_logical_recovery_blocked(&claim, "absence_not_proven")
                        .await?;
                }
                _ => {}
            }
        }
        Ok(count)
    }

    pub async fn open(
        &self,
        key: &str,
        range: Option<&str>,
    ) -> Option<aws_sdk_s3::operation::get_object::GetObjectOutput> {
        let (primary, replica_opt) = self.get_backend_ids(key);

        let try_get = |index: usize| async move {
            let client = self.client_for(index).await?;
            let mut request = client
                .get_object()
                .bucket(&self.backends[index].bucket)
                .key(key);
            if let Some(range) = range {
                request = request.range(range);
            }
            match request.send().await {
                Ok(output) => Some(output),
                Err(error) => {
                    if !error
                        .as_service_error()
                        .is_some_and(|service| service.is_no_such_key())
                    {
                        record_s3_failure("managed_get_object", &error);
                    }
                    None
                }
            }
        };

        if let Some(output) = try_get(primary).await {
            return Some(output);
        }
        info!("managed primary miss; trying replica");
        if let Some(replica) = replica_opt {
            return try_get(replica).await;
        }
        None
    }

    pub async fn delete(&self, key: &str) -> anyhow::Result<()> {
        let (primary, replica_opt) = self.get_backend_ids(key);
        let primary_client = self
            .client_for(primary)
            .await
            .ok_or_else(|| anyhow::anyhow!("No client for primary"))?;
        if let Err(error) = primary_client
            .delete_object()
            .bucket(&self.backends[primary].bucket)
            .key(key)
            .send()
            .await
        {
            record_s3_failure("managed_delete_object", &error);
        }

        if let Some(ri) = replica_opt
            && let Some(rc) = self.client_for(ri).await
            && let Err(error) = rc
                .delete_object()
                .bucket(&self.backends[ri].bucket)
                .key(key)
                .send()
                .await
        {
            record_s3_failure("managed_delete_replica", &error);
        }
        Ok(())
    }

    pub async fn head(&self, key: &str) -> Option<(u64, String)> {
        let (primary, replica_opt) = self.get_backend_ids(key);
        let try_head = |index: usize| async move {
            let client = self.client_for(index).await?;
            let resp = match client
                .head_object()
                .bucket(&self.backends[index].bucket)
                .key(key)
                .send()
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    if !error
                        .as_service_error()
                        .is_some_and(|service| service.is_not_found())
                    {
                        record_s3_failure("managed_head_object", &error);
                    }
                    return None;
                }
            };
            let size = resp.content_length.map(|s| s as u64).unwrap_or(0);
            let etag = resp.e_tag.unwrap_or_default();
            Some((size, etag))
        };

        if let Some(result) = try_head(primary).await {
            return Some(result);
        }
        if let Some(ri) = replica_opt {
            return try_head(ri).await;
        }
        None
    }

    pub async fn head_output(
        &self,
        key: &str,
    ) -> Option<aws_sdk_s3::operation::head_object::HeadObjectOutput> {
        let (primary, replica_opt) = self.get_backend_ids(key);
        let try_head = |index: usize| async move {
            let client = self.client_for(index).await?;
            match client
                .head_object()
                .bucket(&self.backends[index].bucket)
                .key(key)
                .send()
                .await
            {
                Ok(output) => Some(output),
                Err(error) => {
                    if !error
                        .as_service_error()
                        .is_some_and(|service| service.is_not_found())
                    {
                        record_s3_failure("managed_head_output", &error);
                    }
                    None
                }
            }
        };
        if let Some(output) = try_head(primary).await {
            return Some(output);
        }
        if let Some(replica) = replica_opt {
            return try_head(replica).await;
        }
        None
    }

    pub(crate) fn authority_repository_required(
        &self,
    ) -> Result<Arc<dyn ManagedRepository>, ManagedError> {
        self.authority.clone().ok_or_else(|| {
            ManagedError::Persistence("managed authority repository is not configured".to_string())
        })
    }

    pub async fn has_authority(&self, logical: &LogicalObjectKey) -> Result<bool, ManagedError> {
        Ok(self
            .authority_repository_required()?
            .get(logical)
            .await?
            .is_some())
    }

    pub(crate) fn metadata_matches(
        metadata: Option<&std::collections::HashMap<String, String>>,
        content_length: Option<i64>,
        authority: &ObjectAuthority,
        ranged: bool,
    ) -> bool {
        let Some(metadata) = metadata else {
            return false;
        };
        let generation_matches = metadata
            .get("maskura-generation")
            .is_some_and(|value| value == &authority.generation.to_string());
        let digest_matches = metadata
            .get("maskura-sha256")
            .is_some_and(|value| value == &authority.digest);
        let size_metadata_matches = metadata
            .get("maskura-size")
            .and_then(|value| value.parse::<u64>().ok())
            == Some(authority.size);
        let response_size_matches = ranged
            || content_length
                .and_then(|value| u64::try_from(value).ok())
                .is_some_and(|value| value == authority.size);
        generation_matches && digest_matches && size_metadata_matches && response_size_matches
    }

    pub(crate) async fn enqueue_read_repairs(
        &self,
        authority: &ObjectAuthority,
        valid_source: &str,
        primary_failed: bool,
    ) -> Result<(), ManagedError> {
        let repository = self.authority_repository_required()?;
        if primary_failed && valid_source != authority.primary_backend_id {
            repository
                .enqueue(RepairRecord::copy(
                    RepairKind::Replica,
                    authority,
                    Some(valid_source.to_string()),
                    authority.primary_backend_id.clone(),
                    RepairTargetRole::Primary,
                    authority.placement_version,
                ))
                .await?;
        }
        let Some(current) = self.placement(&authority.logical) else {
            return Ok(());
        };
        if current.version == authority.placement_version {
            return Ok(());
        }
        if current.primary_backend_id != authority.primary_backend_id {
            repository
                .enqueue(RepairRecord::placement(
                    authority,
                    Some(valid_source.to_string()),
                    current.primary_backend_id.clone(),
                    RepairTargetRole::Primary,
                    &current,
                ))
                .await?;
        }
        if let Some(replica) = current.replica_backend_id.clone()
            && authority.replica_backend_id.as_deref() != Some(replica.as_str())
        {
            repository
                .enqueue(RepairRecord::placement(
                    authority,
                    Some(valid_source.to_string()),
                    replica,
                    RepairTargetRole::Replica,
                    &current,
                ))
                .await?;
        }
        Ok(())
    }

    pub(crate) async fn authoritative_get_from(
        &self,
        backend_id: &str,
        physical_key: &str,
        range: Option<&str>,
        authority: &ObjectAuthority,
    ) -> Option<aws_sdk_s3::operation::get_object::GetObjectOutput> {
        let index = self.index_for_id(backend_id)?;
        let client = self.client_for(index).await?;
        let version_id = (backend_id == authority.primary_backend_id)
            .then(|| authority.primary_version_id.clone())
            .flatten();
        let mut request = client
            .get_object()
            .bucket(&self.backends[index].bucket)
            .key(physical_key)
            .set_version_id(version_id);
        if let Some(range) = range {
            request = request.range(range);
        }
        let output = match request.send().await {
            Ok(output) => output,
            Err(error) => {
                if !error
                    .as_service_error()
                    .is_some_and(|service| service.is_no_such_key())
                {
                    record_s3_failure("managed_authoritative_get", &error);
                }
                return None;
            }
        };
        Self::metadata_matches(
            output.metadata(),
            output.content_length(),
            authority,
            range.is_some(),
        )
        .then_some(output)
    }

    pub async fn open_authoritative(
        &self,
        logical: &LogicalObjectKey,
        range: Option<&str>,
    ) -> Result<Option<aws_sdk_s3::operation::get_object::GetObjectOutput>, ManagedError> {
        let repository = self.authority_repository_required()?;
        let Some(authority) = repository.get(logical).await? else {
            return Ok(None);
        };
        if authority.tombstone {
            return Ok(None);
        }
        let physical_key = generation_physical_key(logical, authority.generation);
        if let Some(output) = self
            .authoritative_get_from(
                &authority.primary_backend_id,
                &physical_key,
                range,
                &authority,
            )
            .await
        {
            self.enqueue_read_repairs(&authority, &authority.primary_backend_id, false)
                .await?;
            return Ok(Some(output));
        }

        if authority.replica_status == CopyStatus::Ready
            && let Some(replica) = &authority.replica_backend_id
            && let Some(output) = self
                .authoritative_get_from(replica, &physical_key, range, &authority)
                .await
        {
            self.enqueue_read_repairs(&authority, replica, true).await?;
            return Ok(Some(output));
        }

        // During a placement-version migration, a previously repaired new
        // destination may be read only after validating the exact generation.
        if let Some(current) = self.placement(logical)
            && current.version != authority.placement_version
        {
            for backend_id in
                std::iter::once(current.primary_backend_id).chain(current.replica_backend_id)
            {
                if let Some(output) = self
                    .authoritative_get_from(&backend_id, &physical_key, range, &authority)
                    .await
                {
                    self.enqueue_read_repairs(&authority, &backend_id, true)
                        .await?;
                    return Ok(Some(output));
                }
            }
        }
        Ok(None)
    }

    pub(crate) async fn authoritative_head_from(
        &self,
        backend_id: &str,
        physical_key: &str,
        authority: &ObjectAuthority,
    ) -> Option<aws_sdk_s3::operation::head_object::HeadObjectOutput> {
        let index = self.index_for_id(backend_id)?;
        let client = self.client_for(index).await?;
        let version_id = (backend_id == authority.primary_backend_id)
            .then(|| authority.primary_version_id.clone())
            .flatten();
        let output = match client
            .head_object()
            .bucket(&self.backends[index].bucket)
            .key(physical_key)
            .set_version_id(version_id)
            .send()
            .await
        {
            Ok(output) => output,
            Err(error) => {
                if !error
                    .as_service_error()
                    .is_some_and(|service| service.is_not_found())
                {
                    record_s3_failure("managed_authoritative_head", &error);
                }
                return None;
            }
        };
        Self::metadata_matches(output.metadata(), output.content_length(), authority, false)
            .then_some(output)
    }

    pub async fn head_authoritative(
        &self,
        logical: &LogicalObjectKey,
    ) -> Result<Option<aws_sdk_s3::operation::head_object::HeadObjectOutput>, ManagedError> {
        let repository = self.authority_repository_required()?;
        let Some(authority) = repository.get(logical).await? else {
            return Ok(None);
        };
        if authority.tombstone {
            return Ok(None);
        }
        let physical_key = generation_physical_key(logical, authority.generation);
        if let Some(output) = self
            .authoritative_head_from(&authority.primary_backend_id, &physical_key, &authority)
            .await
        {
            self.enqueue_read_repairs(&authority, &authority.primary_backend_id, false)
                .await?;
            return Ok(Some(output));
        }
        if authority.replica_status == CopyStatus::Ready
            && let Some(replica) = &authority.replica_backend_id
            && let Some(output) = self
                .authoritative_head_from(replica, &physical_key, &authority)
                .await
        {
            self.enqueue_read_repairs(&authority, replica, true).await?;
            return Ok(Some(output));
        }
        if let Some(current) = self.placement(logical)
            && current.version != authority.placement_version
        {
            for backend_id in
                std::iter::once(current.primary_backend_id).chain(current.replica_backend_id)
            {
                if let Some(output) = self
                    .authoritative_head_from(&backend_id, &physical_key, &authority)
                    .await
                {
                    self.enqueue_read_repairs(&authority, &backend_id, true)
                        .await?;
                    return Ok(Some(output));
                }
            }
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn delete_authoritative(
        &self,
        logical: &LogicalObjectKey,
        operation_id: uuid::Uuid,
        receipt_id: uuid::Uuid,
        occurred_at_micros: i64,
        rate_version: i32,
        max_processed_bytes: u64,
    ) -> Result<(), ManagedDeleteError> {
        if !self.managed_mode.allows_mutations() {
            return Err(ManagedError::MutationDisabled(self.managed_mode).into());
        }
        let repository = self.authority_repository_required()?;
        let placement = self.placement(logical).ok_or_else(|| {
            ManagedError::Persistence("managed storage has no backends".to_string())
        })?;
        let backend_index = self
            .index_for_id(&placement.primary_backend_id)
            .ok_or_else(|| {
                ManagedError::Persistence(format!(
                    "unknown managed backend {}",
                    placement.primary_backend_id
                ))
            })?;
        let request = ManagedDeleteRequest {
            operation_id,
            receipt_id,
            logical: logical.clone(),
            placement,
            provider_bucket: self.backends[backend_index].bucket.clone(),
            occurred_at_micros,
            rate_version,
            max_processed_bytes,
        };
        if let Err(error) = repository
            .commit_atomic_logical_delete(request.clone())
            .await
        {
            if !matches!(&error, ManagedDeleteError::CommitUnknown(_)) {
                return Err(error);
            }
            // Re-enter with the same durable identity. This either observes the
            // committed DELETE or executes it after a definitely failed commit;
            // a second ambiguous result must retain the external reservation.
            return repository
                .commit_atomic_logical_delete(request)
                .await
                .map(|_| ())
                .map_err(|_| error);
        }
        Ok(())
    }

    pub async fn mark_authoritative_delete_settled(
        &self,
        operation_id: uuid::Uuid,
        receipt_id: uuid::Uuid,
    ) -> Result<(), ManagedError> {
        self.authority_repository_required()?
            .mark_logical_operation_settled(operation_id, receipt_id)
            .await
    }

    pub async fn reconcile_managed_delete_settlements(
        &self,
        control: &dyn ControlPlane,
        limit: u64,
    ) -> Result<usize, ManagedError> {
        let repository = self.authority_repository_required()?;
        let operations = repository.pending_delete_settlements(limit).await?;
        let mut settled = 0;
        for operation in operations {
            let intent = &operation.intent;
            let Ok(workspace_id) = WorkspaceId::new(intent.logical.tenant_id.clone()) else {
                warn!(
                    operation_id = %intent.operation_id,
                    "managed DELETE settlement has an invalid workspace identity"
                );
                defer_delete_settlement(&repository, intent.operation_id, intent.receipt_id).await;
                continue;
            };
            let Some(occurred_at_micros) = operation
                .evidence
                .as_ref()
                .and_then(|evidence| evidence.payload.get("occurred_at_micros"))
                .and_then(serde_json::Value::as_i64)
            else {
                warn!(
                    operation_id = %intent.operation_id,
                    "managed DELETE settlement has no exact authorization timestamp"
                );
                defer_delete_settlement(&repository, intent.operation_id, intent.receipt_id).await;
                continue;
            };
            let Some(event) = UsageEvent::from_durable_settlement(
                intent.receipt_id,
                intent.operation_id,
                occurred_at_micros,
                intent.rate_version,
                intent.logical.bucket.clone(),
                intent.request_kind,
                intent.route,
                0,
                0,
            ) else {
                warn!(
                    operation_id = %intent.operation_id,
                    "managed DELETE settlement timestamp is out of range"
                );
                defer_delete_settlement(&repository, intent.operation_id, intent.receipt_id).await;
                continue;
            };
            if control
                .record_reconciled(&workspace_id, &event)
                .await
                .is_err()
            {
                warn!(
                    operation_id = %intent.operation_id,
                    "managed DELETE settlement recording failed"
                );
                defer_delete_settlement(&repository, intent.operation_id, intent.receipt_id).await;
                continue;
            }
            if repository
                .mark_logical_operation_settled(intent.operation_id, intent.receipt_id)
                .await
                .is_err()
            {
                warn!(
                    operation_id = %intent.operation_id,
                    "managed DELETE settlement acknowledgement failed"
                );
                defer_delete_settlement(&repository, intent.operation_id, intent.receipt_id).await;
                continue;
            }
            settled += 1;
        }
        Ok(settled)
    }

    /// Start a managed generation with the exact physical child identity
    /// persisted by its logical parent.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_authoritative_sink_for_operation(
        self: &Arc<Self>,
        journal: Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        logical: LogicalObjectKey,
        content_type: &str,
        logical_operation_id: uuid::Uuid,
        child_scope: ManagedOperationScope,
        generation: uuid::Uuid,
    ) -> Result<Box<dyn ObjectSinkTransaction>, TransactionError> {
        if child_scope.tenant_id != logical.tenant_id {
            return Err(TransactionError::Publication(
                "managed child scope belongs to a different tenant".to_string(),
            ));
        }
        if self.managed_mode != ManagedStreamingMode::Enforce {
            return Err(TransactionError::Publication(
                ManagedError::MutationDisabled(self.managed_mode).to_string(),
            ));
        }
        self.validate_managed_launch_configuration()
            .map_err(TransactionError::Publication)?;
        let repository = self
            .authority_repository_required()
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        let placement = self.placement(&logical).ok_or_else(|| {
            TransactionError::Publication("managed storage has no backends".to_string())
        })?;
        let physical_key = generation_physical_key(&logical, generation);
        let parent = repository
            .logical_operation(logical_operation_id)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?
            .ok_or_else(|| {
                TransactionError::Publication(
                    "managed logical parent operation was not found".to_string(),
                )
            })?;
        let parent_bucket = self
            .index_for_id(&parent.intent.backend_id)
            .map(|index| self.backends[index].bucket.as_str())
            .unwrap_or_default();
        let usage = repository
            .workspace_usage(&logical.tenant_id)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        if parent.intent.kind != ManagedMutationKind::Put
            || parent.state != ManagedLogicalOperationState::Open
            || usage
                .as_ref()
                .is_none_or(|usage| usage.active_operation_id != Some(logical_operation_id))
            || parent.intent.logical != logical
            || parent.intent.generation != generation
            || parent.intent.primary_child_operation_id != child_scope.operation_id
            || parent.intent.fence.namespace_epoch != child_scope.namespace_epoch
            || parent.intent.backend_id != placement.primary_backend_id
            || parent.intent.provider_bucket != parent_bucket
            || parent.intent.physical_key != physical_key
        {
            return Err(TransactionError::Publication(
                "managed logical parent does not match its reserved physical child".to_string(),
            ));
        }
        let mut metadata = BTreeMap::from([
            ("content-type".to_string(), content_type.to_string()),
            ("maskura-generation".to_string(), generation.to_string()),
        ]);
        let primary = self
            .direct_sink_for(
                &journal,
                capabilities,
                &placement.primary_backend_id,
                &logical,
                &physical_key,
                metadata.clone(),
                ManagedChildIdentity::Supplied {
                    scope: child_scope,
                    parent_operation_id: logical_operation_id,
                },
            )
            .await?;
        metadata.remove("maskura-generation");
        Ok(Box::new(ManagedReplicatedSink {
            repository,
            logical,
            generation,
            placement,
            logical_operation_id: Some(logical_operation_id),
            expected_cas: None,
            metadata,
            primary,
            replica: None,
            output: None,
            finished: false,
        }))
    }

    /// Admit a single-object streaming PUT against managed storage and begin
    /// its authoritative sink. The logical operation is journaled in the
    /// managed repository under the operator routing fence captured from the
    /// persisted namespace, while the request authorization grant remains the
    /// tenant-side identity; the returned sink records the canonical usage
    /// evidence into the same authority ledger before publishing object
    /// authority at commit. This separation is what makes managed commit an
    /// operator-fenced act rather than one the tenant grant could forge.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_managed_put_sink(
        self: &Arc<Self>,
        journal: Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        logical: LogicalObjectKey,
        content_type: &str,
        operation_id: uuid::Uuid,
        receipt_id: uuid::Uuid,
        occurred_at_ms: i64,
        rate_version: i32,
        max_processed_bytes: u64,
        expected_authority_cas: Option<u64>,
        prior_logical_size: u64,
    ) -> Result<Box<dyn ObjectSinkTransaction>, TransactionError> {
        if self.managed_mode != ManagedStreamingMode::Enforce {
            return Err(TransactionError::Publication(
                ManagedError::MutationDisabled(self.managed_mode).to_string(),
            ));
        }
        self.validate_managed_launch_configuration()
            .map_err(TransactionError::Publication)?;
        if !journal.is_durable() {
            return Err(TransactionError::Publication(
                "managed streaming requires a durable operation journal".to_string(),
            ));
        }
        let repository = self
            .authority_repository_required()
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        let fence = repository
            .route_fence(&logical.tenant_id)
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        let placement = self.placement(&logical).ok_or_else(|| {
            TransactionError::Publication("managed storage has no backends".to_string())
        })?;
        let backend_index = self
            .index_for_id(&placement.primary_backend_id)
            .ok_or_else(|| {
                TransactionError::Publication(format!(
                    "unknown managed backend {}",
                    placement.primary_backend_id
                ))
            })?;
        let provider_bucket = self.backends[backend_index].bucket.clone();
        let generation = uuid::Uuid::now_v7();
        let physical_key = generation_physical_key(&logical, generation);
        let child_scope = ManagedOperationScope::deterministic_child(
            operation_id,
            logical.tenant_id.clone(),
            fence.namespace_epoch,
            &ObjectDestination {
                backend_id: placement.primary_backend_id.clone(),
                bucket: provider_bucket.clone(),
                logical_key: logical.object_key(),
                physical_key: physical_key.clone(),
                workspace_binding: None,
            },
            ManagedChildRole::Primary,
        );
        let intent = ManagedLogicalOperationIntent {
            operation_id,
            receipt_id,
            logical: logical.clone(),
            kind: ManagedMutationKind::Put,
            generation,
            fence,
            expected_authority_cas,
            prior_logical_size,
            primary_child_operation_id: child_scope.operation_id,
            backend_id: placement.primary_backend_id.clone(),
            provider_bucket: provider_bucket.clone(),
            physical_key: physical_key.clone(),
            occurred_at_ms,
            rate_version,
            route: UsageRoute::PutObject,
            request_kind: RequestKind::Write,
            max_processed_bytes,
            publication_recipe: Some(ManagedPublicationRecipe {
                version: MANAGED_PUBLICATION_RECIPE_VERSION,
                placement_version: placement.version,
                primary_backend_id: placement.primary_backend_id.clone(),
                replica_backend_id: placement.replica_backend_id.clone(),
                metadata: BTreeMap::from([("content-type".to_string(), content_type.to_string())]),
                primary_status: CopyStatus::Ready,
                replica_status: if placement.replica_backend_id.is_some() {
                    CopyStatus::RepairPending
                } else {
                    CopyStatus::Absent
                },
            }),
        };
        // Admit the logical operation and reserve the maximum exposure this
        // request could publish in one transaction. The reservation is bounded
        // by the workspace's physical headroom so an arbitrary per-object limit
        // can never overflow the launch usage budget, and the workspace admits
        // one managed mutation at a time. Admission is atomic, so a failed
        // reservation leaves no logical operation for reconciliation to abort.
        if let Err(error) = repository
            .admit_logical_operation(
                intent,
                max_processed_bytes.saturating_mul(MANAGED_STREAMING_PUT_HEADROOM),
            )
            .await
        {
            return Err(TransactionError::Publication(format!(
                "managed logical admission failed: {error}"
            )));
        }
        let sink = match self
            .begin_authoritative_sink_for_operation(
                journal,
                capabilities,
                logical.clone(),
                content_type,
                operation_id,
                child_scope,
                generation,
            )
            .await
        {
            Ok(sink) => sink,
            Err(error) => {
                let _ = repository
                    .abort_logical_put(
                        operation_id,
                        None,
                        crate::managed::LogicalAbortProof::NoChildStarted,
                        "sink_begin_failed",
                        None,
                    )
                    .await;
                return Err(error);
            }
        };
        Ok(Box::new(ManagedLogicalSink {
            inner: sink,
            repository,
            operation_id,
            expected_output_size: None,
            expected_output_digest: None,
            usage_recorded: false,
            committed: false,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn direct_sink_for(
        &self,
        journal: &Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        backend_id: &str,
        logical: &LogicalObjectKey,
        physical_key: &str,
        mut metadata: BTreeMap<String, String>,
        child_identity: ManagedChildIdentity,
    ) -> Result<Box<dyn ManagedDestination>, TransactionError> {
        let index = self.index_for_id(backend_id).ok_or_else(|| {
            TransactionError::Publication(format!("unknown managed backend {backend_id}"))
        })?;
        let client = self.client_for(index).await.ok_or_else(|| {
            TransactionError::Publication(format!("managed backend {backend_id} is unavailable"))
        })?;
        let backend: Arc<dyn TransactionBackend> = if self.backends[index].is_b2() {
            Arc::new(AwsS3TransactionBackend::new_managed_b2(
                client,
                capabilities,
            ))
        } else {
            Arc::new(AwsS3TransactionBackend::new(client, capabilities))
        };
        if let Some(instance_id) = self.backends[index].provider_instance_id() {
            metadata.insert(
                "maskura-provider-instance".to_string(),
                instance_id.to_string(),
            );
        }
        if let Some(account_id) = self.backends[index].provider_account_id() {
            metadata.insert(
                "maskura-provider-account".to_string(),
                account_id.to_string(),
            );
        }
        if let Some(credential_epoch) = self.backends[index].credential_epoch() {
            metadata.insert(
                "maskura-credential-epoch".to_string(),
                credential_epoch.to_string(),
            );
        }
        let destination = ObjectDestination {
            backend_id: backend_id.to_string(),
            bucket: self.backends[index].bucket.clone(),
            logical_key: logical.object_key(),
            physical_key: physical_key.to_string(),
            workspace_binding: None,
        };
        let logical_parent_operation_id = match &child_identity {
            ManagedChildIdentity::Supplied {
                parent_operation_id,
                ..
            } => Some(*parent_operation_id),
            ManagedChildIdentity::Deterministic { .. } => None,
        };
        let (operation_id, expected_namespace_epoch) = match child_identity {
            ManagedChildIdentity::Supplied { scope, .. } => {
                (scope.operation_id, Some(scope.namespace_epoch))
            }
            ManagedChildIdentity::Deterministic { parent, role } => (
                ManagedOperationScope::deterministic_child(
                    parent,
                    logical.tenant_id.clone(),
                    0,
                    &destination,
                    role,
                )
                .operation_id,
                None,
            ),
        };
        let repository = self
            .authority_repository_required()
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        let versioning_mode = self.versioning_mode(index).await;
        let storage_identity = self.backends[index].storage_identity().ok_or_else(|| {
            TransactionError::Publication(format!(
                "managed backend {backend_id} has no immutable storage identity"
            ))
        })?;
        let credential_epoch = self.backends[index].credential_epoch().ok_or_else(|| {
            TransactionError::Publication(format!(
                "managed backend {backend_id} has no credential epoch"
            ))
        })?;
        let writer_owner = format!("managed-writer-{}", uuid::Uuid::now_v7());
        let lease = repository
            .begin_physical_write(PhysicalWriteIntent {
                intent_id: operation_id,
                tenant_id: logical.tenant_id.clone(),
                backend_id: backend_id.to_string(),
                storage_identity,
                credential_epoch,
                provider_bucket: self.backends[index].bucket.clone(),
                physical_key: physical_key.to_string(),
                versioning_mode,
                versioning_capability: match capabilities.versioning {
                    VersioningCapability::Unsupported => BackendVersioningCapability::Unsupported,
                    VersioningCapability::Optional => BackendVersioningCapability::Optional,
                    VersioningCapability::Required => BackendVersioningCapability::Required,
                },
                lease_owner: writer_owner,
            })
            .await
            .map_err(|error| TransactionError::Publication(error.to_string()))?;
        if expected_namespace_epoch.is_some_and(|expected| expected != lease.namespace_epoch) {
            if let Some(parent) = logical_parent_operation_id {
                repository
                    .abort_logical_put(
                        parent,
                        Some(&lease),
                        crate::managed::LogicalAbortProof::NoChildStarted,
                        "stale_child_scope",
                        None,
                    )
                    .await
                    .map_err(|error| TransactionError::Publication(error.to_string()))?;
            } else {
                repository
                    .abort_physical_write(&lease)
                    .await
                    .map_err(|error| TransactionError::Publication(error.to_string()))?;
            }
            return Err(TransactionError::Publication(
                "managed child scope namespace epoch is stale".to_string(),
            ));
        }
        let (abort_signal, mut abort_receiver) = AbortSignal::channel(1);
        let reconciler = OperationReconciler::new(
            journal.clone(),
            backend.clone(),
            format!("managed-request-{}", uuid::Uuid::now_v7()),
        )?;
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
                        "managed transaction cleanup failed"
                    );
                }
            }
        });
        let sink = match DirectS3Sink::new_scoped(
            journal.clone(),
            backend.clone(),
            ManagedOperationScope {
                operation_id,
                tenant_id: logical.tenant_id.clone(),
                namespace_epoch: lease.namespace_epoch,
            },
            destination,
            ExpectedObject {
                metadata,
                ..ExpectedObject::default()
            },
            3,
            abort_signal,
        )
        .await
        {
            Ok(sink) => sink,
            Err(error) => {
                let cleanup = if let Some(parent) = logical_parent_operation_id {
                    repository
                        .abort_logical_put(
                            parent,
                            Some(&lease),
                            crate::managed::LogicalAbortProof::NoChildStarted,
                            "child_journal_init_failed",
                            None,
                        )
                        .await
                        .map(|_| ())
                } else {
                    repository.abort_physical_write(&lease).await
                };
                cleanup.map_err(|ledger_error| {
                        TransactionError::Publication(format!(
                            "managed journal initialization failed: {error}; intent cleanup failed: {ledger_error}"
                        ))
                    })?;
                return Err(error);
            }
        };
        let (lease_stop, mut lease_stopped) = watch::channel(());
        let lease_repository = repository.clone();
        let heartbeat_lease = lease.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = lease_stopped.changed() => break,
                    _ = interval.tick() => {
                        if lease_repository
                            .renew_physical_write_intent(
                                &heartbeat_lease,
                                crate::transaction::unix_time_ms()
                                    .saturating_add(crate::managed::PHYSICAL_WRITE_LEASE_MS),
                            )
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });
        Ok(Box::new(ManagedDirectSink {
            sink,
            journal: journal.clone(),
            operation_id,
            repository,
            lease,
            logical_parent_operation_id,
            lease_stop: Some(lease_stop),
        }))
    }

    pub async fn repair_due(
        self: &Arc<Self>,
        journal: Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        owner: &str,
        limit: u64,
    ) -> Result<usize, ManagedError> {
        let repository = self.authority_repository_required()?;
        let lease_until = crate::transaction::unix_time_ms() + 30_000;
        let repairs = repository.claim_repairs(owner, lease_until, limit).await?;
        let count = repairs.len();
        for repair in repairs {
            let (stop_heartbeat, mut heartbeat_stopped) = watch::channel(());
            let heartbeat_repository = repository.clone();
            let lease_token = repair.id;
            let heartbeat = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(10));
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = heartbeat_stopped.changed() => break,
                        _ = interval.tick() => {
                            let lease_until = crate::transaction::unix_time_ms() + 30_000;
                            match heartbeat_repository.renew_repair(lease_token, lease_until).await {
                                Ok(()) => {}
                                Err(ManagedError::Conflict) => break,
                                Err(_) => warn!(
                                    repair_id = %lease_token,
                                    error_category = "persistence",
                                    "managed repair lease heartbeat failed"
                                ),
                            }
                        }
                    }
                }
            });
            let result = self
                .execute_repair(journal.clone(), capabilities, &repair)
                .await;
            let _ = stop_heartbeat.send(());
            if heartbeat.await.is_err() {
                warn!(
                    repair_id = %lease_token,
                    error_category = "task",
                    "managed repair lease heartbeat task failed"
                );
            }
            match result {
                Ok(()) => match repository.complete_repair(&repair).await {
                    Ok(_) | Err(ManagedError::Conflict) => {}
                    Err(error) => return Err(error),
                },
                Err(error) => match repository.fail_repair(repair.id, &error).await {
                    Ok(()) | Err(ManagedError::Conflict) => {}
                    Err(error) => return Err(error),
                },
            }
        }
        Ok(count)
    }

    pub(crate) async fn execute_repair(
        &self,
        journal: Arc<dyn OperationJournal>,
        capabilities: BackendCapabilities,
        repair: &RepairRecord,
    ) -> Result<(), String> {
        if repair.kind == RepairKind::DeleteGeneration {
            return self.delete_generation(repair).await;
        }
        let source_id = repair
            .source_backend_id
            .as_deref()
            .ok_or_else(|| "repair has no source backend".to_string())?;
        let source_index = self
            .index_for_id(source_id)
            .ok_or_else(|| format!("unknown repair source backend {source_id}"))?;
        let source = self
            .client_for(source_index)
            .await
            .ok_or_else(|| format!("repair source backend {source_id} is unavailable"))?;
        let output = source
            .get_object()
            .bucket(&self.backends[source_index].bucket)
            .key(&repair.physical_key)
            .send()
            .await
            .map_err(|error| record_s3_failure("managed_repair_get", &error).to_string())?;
        let authority = ObjectAuthority {
            logical: repair.logical.clone(),
            generation: repair.generation,
            digest: repair.digest.clone(),
            size: repair.size,
            metadata: repair.metadata.clone(),
            placement_version: repair.placement_version,
            primary_backend_id: source_id.to_string(),
            primary_version_id: output.version_id().map(ToOwned::to_owned),
            replica_backend_id: None,
            primary_status: CopyStatus::Ready,
            replica_status: CopyStatus::Absent,
            tombstone: false,
            cas_version: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        if !Self::metadata_matches(
            output.metadata(),
            output.content_length(),
            &authority,
            false,
        ) {
            return Err("repair source generation metadata does not match authority".to_string());
        }
        let mut metadata = repair.metadata.clone();
        metadata.insert(
            "maskura-generation".to_string(),
            repair.generation.to_string(),
        );
        let mut target = self
            .direct_sink_for(
                &journal,
                capabilities,
                &repair.target_backend_id,
                &repair.logical,
                &repair.physical_key,
                metadata,
                ManagedChildIdentity::Deterministic {
                    parent: repair.id,
                    role: ManagedChildRole::Repair,
                },
            )
            .await
            .map_err(|error| error.to_string())?;
        let mut body = output.body;
        while let Some(chunk) = body
            .try_next()
            .await
            .map_err(|_| record_s3_body_failure("managed_repair_get_body").to_string())?
        {
            target
                .write(chunk)
                .await
                .map_err(|error| error.to_string())?;
        }
        target
            .verify_output(repair.size, &repair.digest)
            .await
            .map_err(|error| error.to_string())?;
        target
            .complete(&DestinationCommitAuthority::SinglePut)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub(crate) async fn delete_generation(&self, repair: &RepairRecord) -> Result<(), String> {
        let index = self
            .index_for_id(&repair.target_backend_id)
            .ok_or_else(|| format!("unknown cleanup backend {}", repair.target_backend_id))?;
        let repository = self
            .authority_repository_required()
            .map_err(|error| error.to_string())?;
        if let Some(authority) = repository
            .get(&repair.logical)
            .await
            .map_err(|error| error.to_string())?
            && !authority.tombstone
            && authority.generation == repair.generation
            && (authority.primary_backend_id == repair.target_backend_id
                || authority.replica_backend_id.as_deref() == Some(&repair.target_backend_id))
        {
            return Err(
                "cleanup target is currently authoritative for this generation".to_string(),
            );
        }
        let versions = repository
            .physical_versions(
                &repair.logical.tenant_id,
                &repair.target_backend_id,
                &self.backends[index].bucket,
                &repair.physical_key,
            )
            .await
            .map_err(|error| error.to_string())?;
        if versions.is_empty() {
            return Err("cleanup has no exact physical-version ledger targets".to_string());
        }
        for target in versions {
            self.delete_and_verify_purge_target(&target).await?;
            repository
                .forget_physical_version(&target)
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}
