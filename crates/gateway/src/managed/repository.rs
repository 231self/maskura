//! Extracted from `managed.rs`; re-exported from `crate::managed`.

use super::*;

#[async_trait]
pub trait ManagedRepository: Send + Sync {
    fn is_durable(&self) -> bool;
    async fn assert_namespace_active(&self, _tenant_id: &str) -> Result<(), ManagedError> {
        Ok(())
    }
    async fn route_fence(&self, tenant_id: &str) -> Result<ManagedRouteFence, ManagedError>;
    async fn advance_routing_epoch(
        &self,
        tenant_id: &str,
        expected_routing_epoch: u64,
    ) -> Result<ManagedRouteFence, ManagedError>;
    async fn insert_logical_operation(
        &self,
        intent: ManagedLogicalOperationIntent,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    async fn logical_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<ManagedLogicalOperation>, ManagedError>;
    async fn pending_logical_operations(
        &self,
        limit: u64,
    ) -> Result<Vec<ManagedLogicalOperation>, ManagedError>;
    async fn pending_delete_settlements(
        &self,
        limit: u64,
    ) -> Result<Vec<ManagedLogicalOperation>, ManagedError>;
    async fn mark_logical_operation_settled(
        &self,
        operation_id: Uuid,
        receipt_id: Uuid,
    ) -> Result<(), ManagedError>;
    async fn defer_delete_settlement(
        &self,
        operation_id: Uuid,
        receipt_id: Uuid,
    ) -> Result<(), ManagedError>;
    async fn claim_stale_logical_operations(
        &self,
        owner: &str,
        stale_before_ms: i64,
        claim_expires_at_ms: i64,
        limit: u64,
    ) -> Result<Vec<ManagedRecoveryClaim>, ManagedError>;
    async fn mark_logical_recovery_blocked(
        &self,
        claim: &ManagedRecoveryClaim,
        reason: &str,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    async fn renew_logical_recovery_claim(
        &self,
        claim: &ManagedRecoveryClaim,
        claim_expires_at_ms: i64,
    ) -> Result<ManagedRecoveryClaim, ManagedError>;
    /// Reserve maximum provider exposure and acquire the workspace's only
    /// managed-mutation slot before a physical child may be created.
    async fn reserve_logical_operation(
        &self,
        operation_id: Uuid,
        physical_bytes: u64,
    ) -> Result<ManagedWorkspaceUsage, ManagedError>;
    /// Admit a logical operation and reserve its provider exposure in one
    /// transaction, clamping the reservation to the workspace's available
    /// physical headroom. Admission is atomic: on failure no logical operation
    /// is committed, so nothing is left for reconciliation to abort.
    async fn admit_logical_operation(
        &self,
        intent: ManagedLogicalOperationIntent,
        reservation_cap: u64,
    ) -> Result<(ManagedLogicalOperation, ManagedWorkspaceUsage), ManagedError>;
    async fn record_logical_usage(
        &self,
        operation_id: Uuid,
        evidence: ManagedUsageEvidence,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    async fn transition_logical_operation(
        &self,
        operation_id: Uuid,
        from: ManagedLogicalOperationState,
        to: ManagedLogicalOperationState,
        error_class: Option<&str>,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    /// Record usage evidence and advance the operation from `Open` to
    /// `Completing` in one transaction (one database round trip instead of two).
    async fn record_logical_usage_and_begin_completion(
        &self,
        operation_id: Uuid,
        evidence: ManagedUsageEvidence,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    async fn finalize_logical_put(
        &self,
        operation_id: Uuid,
        physical_lease: &PhysicalWriteLease,
        result: ExactPhysicalCommit,
        recovery_claim: Option<&ManagedRecoveryClaim>,
    ) -> Result<ManagedOperationCommit, ManagedError>;
    async fn commit_logical_delete(
        &self,
        operation_id: Uuid,
        placement: &Placement,
    ) -> Result<ManagedOperationCommit, ManagedError>;
    /// Persist the DELETE intent, evidence, tombstone, cleanup work, and usage
    /// accounting as one transaction after locking current authority.
    async fn commit_atomic_logical_delete(
        &self,
        request: ManagedDeleteRequest,
    ) -> Result<ManagedOperationCommit, ManagedDeleteError>;
    /// Mark an operation non-billable only after absence is proven. If a
    /// provider mutation occurred, transfer its reservation to allocated bytes
    /// and enqueue exact cleanup instead of releasing physical capacity early.
    async fn prove_logical_abort(
        &self,
        operation_id: Uuid,
        error_class: &str,
        physical: Option<ManagedProvenPhysicalAllocation>,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    /// Atomically consume a logical PUT child intent after exact non-mutation
    /// evidence, release its reservation/active slot, and mark the parent
    /// `PROVEN_ABORTED`. Logical children must never use the standalone physical
    /// abort path.
    async fn abort_logical_put(
        &self,
        operation_id: Uuid,
        physical_lease: Option<&PhysicalWriteLease>,
        proof: LogicalAbortProof,
        error_class: &str,
        recovery_claim: Option<&ManagedRecoveryClaim>,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    async fn workspace_usage(
        &self,
        tenant_id: &str,
    ) -> Result<Option<ManagedWorkspaceUsage>, ManagedError>;
    async fn list_authority(
        &self,
        query: AuthorityListQuery,
    ) -> Result<AuthorityListPage, ManagedError>;
    async fn list_authority_below_placement_version(
        &self,
        query: AuthorityPlacementPageQuery,
    ) -> Result<AuthorityPlacementPage, ManagedError>;
    async fn authority_placement_stats(
        &self,
        target_placement_version: u32,
    ) -> Result<AuthorityPlacementStats, ManagedError>;

    async fn create_list_cursor(
        &self,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError>;
    /// Create the next cached page exactly once for a cursor replay. Concurrent
    /// uses converge on the same successor row and therefore the same token.
    async fn create_list_cursor_successor(
        &self,
        predecessor_cursor_id: Uuid,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError>;
    async fn use_list_cursor(
        &self,
        cursor_id: Uuid,
        binding: &ManagedListCursorBinding,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError>;
    async fn delete_list_cursor(&self, cursor_id: Uuid) -> Result<(), ManagedError>;
    async fn cleanup_expired_list_cursors(
        &self,
        now_ms: i64,
        limit: u64,
    ) -> Result<u64, ManagedError>;
    async fn begin_multipart_activity(
        &self,
        _upload_id: &str,
        _tenant_id: &str,
    ) -> Result<u64, ManagedError> {
        Err(ManagedError::Persistence(
            "managed multipart epoch fencing is unsupported".to_string(),
        ))
    }
    async fn assert_multipart_activity(
        &self,
        _upload_id: &str,
        _tenant_id: &str,
        _namespace_epoch: u64,
        _allow_purging: bool,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed multipart epoch fencing is unsupported".to_string(),
        ))
    }
    async fn confirm_multipart_activity(
        &self,
        _upload_id: &str,
        _tenant_id: &str,
        _namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed multipart epoch fencing is unsupported".to_string(),
        ))
    }
    async fn reconcile_multipart_activities(&self, _limit: u64) -> Result<u64, ManagedError> {
        Ok(0)
    }
    async fn finish_multipart_activity(
        &self,
        _upload_id: &str,
        _tenant_id: &str,
        _namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed multipart epoch fencing is unsupported".to_string(),
        ))
    }
    async fn any_authority(&self) -> Result<bool, ManagedError>;
    async fn get(
        &self,
        logical: &LogicalObjectKey,
    ) -> Result<Option<ObjectAuthority>, ManagedError>;
    async fn publish(
        &self,
        authority: ObjectAuthority,
        expected_cas: Option<u64>,
    ) -> Result<ObjectAuthority, ManagedError>;
    async fn advance_placement_version(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: u64,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError>;
    /// Record a durable placement policy. Returns `Ok(false)` when a different
    /// policy (a different fingerprint) is already durable at the same version —
    /// a same-version edit that the caller must reject.
    async fn record_placement_policy(
        &self,
        policy: &ManagedPlacementPolicy,
    ) -> Result<bool, ManagedError>;
    async fn tombstone(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: Option<u64>,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError>;
    async fn enqueue(&self, repair: RepairRecord) -> Result<(), ManagedError>;
    async fn claim_repairs(
        &self,
        owner: &str,
        lease_until_ms: i64,
        limit: u64,
    ) -> Result<Vec<RepairRecord>, ManagedError>;
    async fn renew_repair(
        &self,
        lease_token: Uuid,
        lease_until_ms: i64,
    ) -> Result<(), ManagedError>;
    async fn complete_repair(&self, repair: &RepairRecord) -> Result<bool, ManagedError>;
    async fn fail_repair(&self, lease_token: Uuid, error: &str) -> Result<(), ManagedError>;
    async fn repair_state_counts(&self) -> Result<RepairStateCounts, ManagedError>;

    /// Persist a write intent before any provider operation can create a
    /// physical version. Implementations must reject a fenced namespace.
    async fn begin_physical_write(
        &self,
        _intent: PhysicalWriteIntent,
    ) -> Result<PhysicalWriteLease, ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn pending_physical_write_intents(
        &self,
        _limit: u64,
    ) -> Result<Vec<DurablePhysicalWriteIntent>, ManagedError> {
        Ok(Vec::new())
    }
    async fn physical_write_intent(
        &self,
        _intent_id: Uuid,
    ) -> Result<Option<DurablePhysicalWriteIntent>, ManagedError> {
        Ok(None)
    }
    async fn renew_physical_write_intent(
        &self,
        _lease: &PhysicalWriteLease,
        _lease_expires_at_ms: i64,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical write lease is unsupported".to_string(),
        ))
    }
    async fn claim_expired_physical_write_intent(
        &self,
        _intent_id: Uuid,
        _owner: &str,
        _lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        Ok(None)
    }
    async fn claim_logical_physical_write_intent(
        &self,
        _claim: &ManagedRecoveryClaim,
        _lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        Ok(None)
    }

    /// Atomically replace a durable write intent with its exact provider
    /// version. `None` denotes an unversioned object.
    async fn commit_physical_write(
        &self,
        _lease: &PhysicalWriteLease,
        _superseded_version_ids: &[String],
        _version_id: Option<&str>,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn abort_physical_write(&self, _lease: &PhysicalWriteLease) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn block_physical_write(
        &self,
        _lease: &PhysicalWriteLease,
        _reason: &str,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn physical_versions(
        &self,
        _tenant_id: &str,
        _backend_id: &str,
        _provider_bucket: &str,
        _physical_key: &str,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn forget_physical_version(
        &self,
        _target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn purge_targets(
        &self,
        _request: &NamespacePurgeRequest,
        _limit: u64,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        Ok(Vec::new())
    }

    async fn mark_purge_target_deleted(
        &self,
        _request: &NamespacePurgeRequest,
        _target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed namespace purge target tracking is unsupported".to_string(),
        ))
    }

    async fn mark_purge_target_blocked(
        &self,
        _request: &NamespacePurgeRequest,
        _target: &PhysicalVersionTarget,
        _reason: &str,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed namespace purge target tracking is unsupported".to_string(),
        ))
    }

    /// Purge every physical generation owned by a managed tenant namespace.
    /// The default is deliberately unsupported: authority rows are not a full
    /// version ledger, so ListObjects-based deletion cannot prove completeness.
    async fn purge_namespace(
        &self,
        _request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        Ok(NamespacePurgeStatus::Unsupported {
            reason: "managed storage has no complete physical version ledger".to_string(),
        })
    }

    /// Query an idempotent purge operation without starting or advancing it.
    async fn namespace_purge_status(
        &self,
        _request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        Ok(NamespacePurgeStatus::Unsupported {
            reason: "managed storage has no complete physical version ledger".to_string(),
        })
    }
}
