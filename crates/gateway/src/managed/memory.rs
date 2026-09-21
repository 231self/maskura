//! Extracted from `managed.rs`; re-exported from `crate::managed`.

use super::*;

#[derive(Default)]
pub(crate) struct MemoryState {
    pub(crate) authorities: HashMap<LogicalObjectKey, ObjectAuthority>,
    pub(crate) logical_operations: HashMap<Uuid, ManagedLogicalOperation>,
    pub(crate) workspace_usage: HashMap<String, ManagedWorkspaceUsage>,
    pub(crate) list_cursors: HashMap<Uuid, ManagedListCursor>,
    pub(crate) list_cursor_successors: HashMap<Uuid, Uuid>,
    pub(crate) repairs: HashMap<Uuid, (RepairRecord, String)>,
    pub(crate) physical_write_intents: HashMap<Uuid, PhysicalWriteIntent>,
    pub(crate) blocked_write_intents: HashMap<Uuid, String>,
    pub(crate) physical_write_leases: HashMap<Uuid, i64>,
    pub(crate) physical_write_tokens: HashMap<Uuid, Uuid>,
    pub(crate) physical_write_epochs: HashMap<Uuid, u64>,
    pub(crate) physical_versions: Vec<PhysicalVersionTarget>,
    pub(crate) fenced_namespaces: HashMap<String, Uuid>,
    pub(crate) purges: HashMap<Uuid, MemoryPurge>,
    pub(crate) namespace_epochs: HashMap<String, u64>,
    pub(crate) routing_epochs: HashMap<String, u64>,
    pub(crate) multipart_activities: HashMap<String, (String, u64)>,
    pub(crate) confirmed_multipart_activities: HashSet<String>,
    pub(crate) multipart_registration_expiry: HashMap<String, i64>,
    pub(crate) placement_policy_fingerprints: HashMap<u32, String>,
}

#[derive(Clone)]
pub(crate) struct MemoryPurge {
    pub(crate) tenant_id: String,
    pub(crate) status: NamespacePurgeStatus,
    pub(crate) deleted_versions: u64,
}

#[derive(Clone, Default)]
pub struct InMemoryManagedRepository {
    pub(crate) state: Arc<Mutex<MemoryState>>,
}

impl InMemoryManagedRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn workspace_usage<'a>(
        state: &'a mut MemoryState,
        tenant_id: &str,
    ) -> &'a mut ManagedWorkspaceUsage {
        let now = crate::transaction::unix_time_ms();
        state
            .workspace_usage
            .entry(tenant_id.to_string())
            .or_insert_with(|| ManagedWorkspaceUsage {
                tenant_id: tenant_id.to_string(),
                visible_logical_bytes: 0,
                physical_allocated_bytes: 0,
                reserved_bytes: 0,
                visible_limit_bytes: MANAGED_VISIBLE_LIMIT_BYTES,
                replacement_headroom_bytes: MANAGED_REPLACEMENT_HEADROOM_BYTES,
                active_operation_id: None,
                version: 1,
                created_at_ms: now,
                updated_at_ms: now,
            })
    }

    pub(crate) fn create_list_cursor_in_state(
        state: &mut MemoryState,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let response_state_bytes =
            serialize_cursor_response_state(&request.response_state)?.len() as u64;
        if state
            .fenced_namespaces
            .contains_key(&request.binding.tenant_id)
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let workspace_count = state
            .list_cursors
            .values()
            .filter(|cursor| {
                cursor.binding.tenant_id == request.binding.tenant_id
                    && cursor.expires_at_ms > now_ms
            })
            .count() as u64;
        let global_count = state
            .list_cursors
            .values()
            .filter(|cursor| cursor.expires_at_ms > now_ms)
            .count() as u64;
        let workspace_bytes = state
            .list_cursors
            .values()
            .filter(|cursor| {
                cursor.binding.tenant_id == request.binding.tenant_id
                    && cursor.expires_at_ms > now_ms
            })
            .try_fold(0_u64, |total, cursor| {
                total
                    .checked_add(cursor.response_state_bytes)
                    .ok_or(ManagedError::CursorLimitExceeded)
            })?;
        let global_bytes = state
            .list_cursors
            .values()
            .filter(|cursor| cursor.expires_at_ms > now_ms)
            .try_fold(0_u64, |total, cursor| {
                total
                    .checked_add(cursor.response_state_bytes)
                    .ok_or(ManagedError::CursorLimitExceeded)
            })?;
        if workspace_count >= MANAGED_LIST_CURSOR_WORKSPACE_LIMIT
            || global_count >= MANAGED_LIST_CURSOR_GLOBAL_LIMIT
            || workspace_bytes
                .checked_add(response_state_bytes)
                .is_none_or(|bytes| bytes > MANAGED_LIST_CURSOR_WORKSPACE_MAX_BYTES)
            || global_bytes
                .checked_add(response_state_bytes)
                .is_none_or(|bytes| bytes > MANAGED_LIST_CURSOR_GLOBAL_MAX_BYTES)
        {
            return Err(ManagedError::CursorLimitExceeded);
        }
        let fence = ManagedRouteFence {
            namespace_epoch: *state
                .namespace_epochs
                .entry(request.binding.tenant_id.clone())
                .or_insert(1),
            routing_epoch: *state
                .routing_epochs
                .entry(request.binding.tenant_id.clone())
                .or_insert(1),
        };
        let cursor = ManagedListCursor {
            id: Uuid::new_v4(),
            binding: request.binding,
            fence,
            position: request.position,
            response_state: request.response_state,
            response_state_bytes,
            final_page: request.final_page,
            state: ManagedListCursorState::Active,
            created_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(MANAGED_LIST_CURSOR_TTL_MS),
            first_used_at_ms: None,
        };
        state.list_cursors.insert(cursor.id, cursor.clone());
        Ok(cursor)
    }

    pub(crate) fn remove_list_cursor(state: &mut MemoryState, cursor_id: Uuid) {
        if let Some(successor_id) = state.list_cursor_successors.remove(&cursor_id) {
            Self::remove_list_cursor(state, successor_id);
        }
        state
            .list_cursor_successors
            .retain(|_, successor_id| *successor_id != cursor_id);
        state.list_cursors.remove(&cursor_id);
    }

    pub(crate) fn finish_purge(
        state: &mut MemoryState,
        operation_id: Uuid,
    ) -> NamespacePurgeStatus {
        let Some(purge) = state.purges.get(&operation_id).cloned() else {
            return NamespacePurgeStatus::Blocked {
                reason: "managed namespace purge operation was not found".to_string(),
            };
        };
        if matches!(purge.status, NamespacePurgeStatus::Complete { .. }) {
            return purge.status;
        }
        if let Some(reason) = state
            .blocked_write_intents
            .iter()
            .find_map(|(intent_id, reason)| {
                state
                    .physical_write_intents
                    .get(intent_id)
                    .filter(|intent| intent.tenant_id == purge.tenant_id)
                    .map(|_| reason.clone())
            })
        {
            let blocked = NamespacePurgeStatus::Blocked { reason };
            if let Some(purge) = state.purges.get_mut(&operation_id) {
                purge.status = blocked.clone();
            }
            return blocked;
        }
        if state.logical_operations.values().any(|operation| {
            operation.intent.logical.tenant_id == purge.tenant_id && !operation.state.terminal()
        }) {
            let blocked = NamespacePurgeStatus::Blocked {
                reason: "managed namespace has unresolved logical operations".to_string(),
            };
            if let Some(purge) = state.purges.get_mut(&operation_id) {
                purge.status = blocked.clone();
            }
            return blocked;
        }
        if state
            .physical_write_intents
            .values()
            .any(|intent| intent.tenant_id == purge.tenant_id)
            || state
                .physical_versions
                .iter()
                .any(|target| target.tenant_id == purge.tenant_id)
            || state
                .multipart_activities
                .values()
                .any(|(tenant_id, _)| tenant_id == &purge.tenant_id)
        {
            return purge.status;
        }
        state
            .authorities
            .retain(|logical, _| logical.tenant_id != purge.tenant_id);
        state
            .repairs
            .retain(|_, (repair, _)| repair.logical.tenant_id != purge.tenant_id);
        let now = crate::transaction::unix_time_ms();
        for operation in state
            .logical_operations
            .values_mut()
            .filter(|operation| operation.intent.logical.tenant_id == purge.tenant_id)
        {
            operation.released_physical_bytes = operation.committed_physical_bytes;
            operation.updated_at_ms = now;
        }
        if let Some(usage) = state.workspace_usage.get_mut(&purge.tenant_id) {
            usage.visible_logical_bytes = 0;
            usage.physical_allocated_bytes = 0;
            usage.reserved_bytes = 0;
            usage.active_operation_id = None;
            usage.version = usage.version.saturating_add(1);
            usage.updated_at_ms = now;
        }
        state
            .list_cursors
            .retain(|_, cursor| cursor.binding.tenant_id != purge.tenant_id);
        let live_cursor_ids = state.list_cursors.keys().copied().collect::<HashSet<_>>();
        state
            .list_cursor_successors
            .retain(|predecessor, successor| {
                live_cursor_ids.contains(predecessor) && live_cursor_ids.contains(successor)
            });
        state.fenced_namespaces.remove(&purge.tenant_id);
        *state
            .namespace_epochs
            .entry(purge.tenant_id.clone())
            .or_insert(1) += 1;
        *state
            .routing_epochs
            .entry(purge.tenant_id.clone())
            .or_insert(1) += 1;
        let complete = NamespacePurgeStatus::Complete {
            deleted_versions: purge.deleted_versions,
        };
        if let Some(purge) = state.purges.get_mut(&operation_id) {
            purge.status = complete.clone();
        }
        complete
    }
}

pub(crate) fn insert_memory_repair(state: &mut MemoryState, repair: RepairRecord) {
    let duplicate = state.repairs.iter_mut().find(|(_, (existing, _))| {
        existing.kind == repair.kind
            && existing.generation == repair.generation
            && existing.target_backend_id == repair.target_backend_id
    });
    if let Some((_, (existing, status))) = duplicate {
        if status == "DONE" {
            let repair_id = existing.repair_id;
            *existing = repair;
            existing.id = repair_id;
            existing.repair_id = repair_id;
            existing.updated_at_ms = crate::transaction::unix_time_ms();
            existing.lease_owner = None;
            existing.lease_token = None;
            existing.lease_expires_at_ms = None;
            *status = "PENDING".to_string();
        }
    } else {
        state
            .repairs
            .insert(repair.repair_id, (repair, "PENDING".to_string()));
    }
}

pub(crate) fn insert_memory_waiting_placement_cleanup(
    state: &mut MemoryState,
    repair: RepairRecord,
) {
    let duplicate = state.repairs.values().any(|(existing, _)| {
        existing.kind == repair.kind
            && existing.generation == repair.generation
            && existing.target_backend_id == repair.target_backend_id
    });
    if !duplicate {
        state
            .repairs
            .insert(repair.repair_id, (repair, "WAITING_CUTOVER".to_string()));
    }
}

#[async_trait]
impl ManagedRepository for InMemoryManagedRepository {
    fn is_durable(&self) -> bool {
        false
    }

    async fn assert_namespace_active(&self, tenant_id: &str) -> Result<(), ManagedError> {
        if self
            .state
            .lock()
            .await
            .fenced_namespaces
            .contains_key(tenant_id)
        {
            Err(ManagedError::NamespaceFenced)
        } else {
            Ok(())
        }
    }

    async fn route_fence(&self, tenant_id: &str) -> Result<ManagedRouteFence, ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let namespace_epoch = *state
            .namespace_epochs
            .entry(tenant_id.to_string())
            .or_insert(1);
        let routing_epoch = *state
            .routing_epochs
            .entry(tenant_id.to_string())
            .or_insert(1);
        Ok(ManagedRouteFence {
            namespace_epoch,
            routing_epoch,
        })
    }

    async fn advance_routing_epoch(
        &self,
        tenant_id: &str,
        expected_routing_epoch: u64,
    ) -> Result<ManagedRouteFence, ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let namespace_epoch = *state
            .namespace_epochs
            .entry(tenant_id.to_string())
            .or_insert(1);
        let routing_epoch = state
            .routing_epochs
            .entry(tenant_id.to_string())
            .or_insert(1);
        if *routing_epoch != expected_routing_epoch {
            return Err(ManagedError::Conflict);
        }
        *routing_epoch = routing_epoch
            .checked_add(1)
            .ok_or_else(|| ManagedError::Corrupt("managed routing epoch overflow".to_string()))?;
        Ok(ManagedRouteFence {
            namespace_epoch,
            routing_epoch: *routing_epoch,
        })
    }

    async fn insert_logical_operation(
        &self,
        intent: ManagedLogicalOperationIntent,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        validate_logical_intent(&intent)?;
        let mut state = self.state.lock().await;
        if state
            .fenced_namespaces
            .contains_key(&intent.logical.tenant_id)
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let namespace_epoch = *state
            .namespace_epochs
            .entry(intent.logical.tenant_id.clone())
            .or_insert(1);
        let routing_epoch = *state
            .routing_epochs
            .entry(intent.logical.tenant_id.clone())
            .or_insert(1);
        if intent.fence
            != (ManagedRouteFence {
                namespace_epoch,
                routing_epoch,
            })
        {
            return Err(ManagedError::Conflict);
        }
        if let Some(existing) = state.logical_operations.get(&intent.operation_id) {
            return (existing.intent == intent)
                .then(|| existing.clone())
                .ok_or(ManagedError::Conflict);
        }
        if state.logical_operations.values().any(|operation| {
            operation.intent.receipt_id == intent.receipt_id
                || operation.intent.primary_child_operation_id == intent.primary_child_operation_id
        }) || state
            .physical_write_intents
            .contains_key(&intent.primary_child_operation_id)
            || state
                .physical_versions
                .iter()
                .any(|target| target.write_operation_id == intent.primary_child_operation_id)
        {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        let operation = ManagedLogicalOperation {
            intent,
            evidence: None,
            reserved_physical_bytes: 0,
            committed_physical_bytes: 0,
            released_physical_bytes: 0,
            state: ManagedLogicalOperationState::Intent,
            committed_authority_version: None,
            settlement_state: ManagedSettlementState::Pending,
            last_error_class: None,
            recovery_owner: None,
            recovery_token: None,
            recovery_expires_at_ms: None,
            created_at_ms: now,
            updated_at_ms: now,
            committed_at_ms: None,
            aborted_at_ms: None,
        };
        state
            .logical_operations
            .insert(operation.intent.operation_id, operation.clone());
        Ok(operation)
    }

    async fn logical_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<ManagedLogicalOperation>, ManagedError> {
        Ok(self
            .state
            .lock()
            .await
            .logical_operations
            .get(&operation_id)
            .cloned())
    }

    async fn pending_logical_operations(
        &self,
        limit: u64,
    ) -> Result<Vec<ManagedLogicalOperation>, ManagedError> {
        let mut operations: Vec<_> = self
            .state
            .lock()
            .await
            .logical_operations
            .values()
            .filter(|operation| !operation.state.terminal())
            .cloned()
            .collect();
        operations.sort_by_key(|operation| operation.updated_at_ms);
        operations.truncate(limit as usize);
        Ok(operations)
    }

    async fn pending_delete_settlements(
        &self,
        limit: u64,
    ) -> Result<Vec<ManagedLogicalOperation>, ManagedError> {
        let mut operations: Vec<_> = self
            .state
            .lock()
            .await
            .logical_operations
            .values()
            .filter(|operation| {
                operation.intent.kind == ManagedMutationKind::Delete
                    && operation.state == ManagedLogicalOperationState::Committed
                    && operation.settlement_state == ManagedSettlementState::Pending
            })
            .cloned()
            .collect();
        operations.sort_by_key(|operation| operation.updated_at_ms);
        operations.truncate(limit as usize);
        Ok(operations)
    }

    async fn mark_logical_operation_settled(
        &self,
        operation_id: Uuid,
        receipt_id: Uuid,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get_mut(&operation_id)
            .ok_or(ManagedError::Conflict)?;
        if operation.intent.receipt_id != receipt_id
            || operation.intent.kind != ManagedMutationKind::Delete
            || operation.state != ManagedLogicalOperationState::Committed
            || !matches!(
                operation.settlement_state,
                ManagedSettlementState::Pending | ManagedSettlementState::Settled
            )
        {
            return Err(ManagedError::Conflict);
        }
        operation.settlement_state = ManagedSettlementState::Settled;
        operation.updated_at_ms = crate::transaction::unix_time_ms();
        Ok(())
    }

    async fn defer_delete_settlement(
        &self,
        operation_id: Uuid,
        receipt_id: Uuid,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get_mut(&operation_id)
            .ok_or(ManagedError::Conflict)?;
        if operation.intent.receipt_id != receipt_id
            || operation.intent.kind != ManagedMutationKind::Delete
            || operation.state != ManagedLogicalOperationState::Committed
            || operation.settlement_state != ManagedSettlementState::Pending
        {
            return Err(ManagedError::Conflict);
        }
        operation.updated_at_ms = crate::transaction::unix_time_ms().saturating_add(60_000);
        Ok(())
    }

    async fn claim_stale_logical_operations(
        &self,
        owner: &str,
        stale_before_ms: i64,
        claim_expires_at_ms: i64,
        limit: u64,
    ) -> Result<Vec<ManagedRecoveryClaim>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        if owner.is_empty() || owner.len() > 256 || claim_expires_at_ms <= now {
            return Err(ManagedError::Conflict);
        }
        let mut state = self.state.lock().await;
        let mut ids = state
            .logical_operations
            .values()
            .filter(|operation| {
                !operation.state.terminal()
                    && operation.intent.kind == ManagedMutationKind::Put
                    && operation.updated_at_ms <= stale_before_ms
                    && operation
                        .recovery_expires_at_ms
                        .is_none_or(|expires| expires <= now)
            })
            .map(|operation| (operation.updated_at_ms, operation.intent.operation_id))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.truncate(limit as usize);
        Ok(ids
            .into_iter()
            .map(|(_, operation_id)| {
                let token = Uuid::now_v7();
                let operation = state.logical_operations.get_mut(&operation_id).unwrap();
                operation.recovery_owner = Some(owner.to_string());
                operation.recovery_token = Some(token);
                operation.recovery_expires_at_ms = Some(claim_expires_at_ms);
                ManagedRecoveryClaim {
                    operation: operation.clone(),
                    owner: owner.to_string(),
                    token,
                    expires_at_ms: claim_expires_at_ms,
                }
            })
            .collect())
    }

    async fn mark_logical_recovery_blocked(
        &self,
        claim: &ManagedRecoveryClaim,
        reason: &str,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get_mut(&claim.operation.intent.operation_id)
            .ok_or(ManagedError::Conflict)?;
        if operation.recovery_owner.as_deref() != Some(&claim.owner)
            || operation.recovery_token != Some(claim.token)
            || operation.recovery_expires_at_ms != Some(claim.expires_at_ms)
            || claim.expires_at_ms <= crate::transaction::unix_time_ms()
            || operation.state.terminal()
        {
            return Err(ManagedError::Conflict);
        }
        operation.state = ManagedLogicalOperationState::RecoveryBlocked;
        operation.last_error_class = Some(reason.chars().take(128).collect());
        operation.recovery_owner = None;
        operation.recovery_token = None;
        operation.recovery_expires_at_ms = None;
        operation.updated_at_ms = crate::transaction::unix_time_ms();
        Ok(operation.clone())
    }

    async fn renew_logical_recovery_claim(
        &self,
        claim: &ManagedRecoveryClaim,
        claim_expires_at_ms: i64,
    ) -> Result<ManagedRecoveryClaim, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        if claim_expires_at_ms <= now {
            return Err(ManagedError::Conflict);
        }
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get_mut(&claim.operation.intent.operation_id)
            .ok_or(ManagedError::Conflict)?;
        if operation.state.terminal()
            || operation.recovery_owner.as_deref() != Some(&claim.owner)
            || operation.recovery_token != Some(claim.token)
            || operation.recovery_expires_at_ms != Some(claim.expires_at_ms)
            || claim.expires_at_ms <= now
        {
            return Err(ManagedError::Conflict);
        }
        operation.recovery_expires_at_ms = Some(claim_expires_at_ms);
        Ok(ManagedRecoveryClaim {
            operation: operation.clone(),
            owner: claim.owner.clone(),
            token: claim.token,
            expires_at_ms: claim_expires_at_ms,
        })
    }

    async fn reserve_logical_operation(
        &self,
        operation_id: Uuid,
        physical_bytes: u64,
    ) -> Result<ManagedWorkspaceUsage, ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get(&operation_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        if state
            .fenced_namespaces
            .contains_key(&operation.intent.logical.tenant_id)
            || state
                .namespace_epochs
                .get(&operation.intent.logical.tenant_id)
                .copied()
                .unwrap_or(1)
                != operation.intent.fence.namespace_epoch
            || state
                .routing_epochs
                .get(&operation.intent.logical.tenant_id)
                .copied()
                .unwrap_or(1)
                != operation.intent.fence.routing_epoch
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        if operation.state == ManagedLogicalOperationState::Open
            && operation.reserved_physical_bytes == physical_bytes
            && usage.active_operation_id == Some(operation_id)
        {
            return Ok(usage.clone());
        }
        if operation.state != ManagedLogicalOperationState::Intent {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::Open,
            });
        }
        if usage.active_operation_id.is_some() {
            return Err(ManagedError::MutationInProgress);
        }
        let bound = usage
            .visible_limit_bytes
            .checked_add(usage.replacement_headroom_bytes)
            .ok_or(ManagedError::QuotaExceeded)?;
        let reserved = usage
            .reserved_bytes
            .checked_add(physical_bytes)
            .ok_or(ManagedError::QuotaExceeded)?;
        if usage
            .physical_allocated_bytes
            .checked_add(reserved)
            .is_none_or(|value| value > bound)
        {
            return Err(ManagedError::QuotaExceeded);
        }
        let now = crate::transaction::unix_time_ms();
        usage.reserved_bytes = reserved;
        usage.active_operation_id = Some(operation_id);
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        let result = usage.clone();
        let operation = state.logical_operations.get_mut(&operation_id).unwrap();
        operation.reserved_physical_bytes = physical_bytes;
        operation.state = ManagedLogicalOperationState::Open;
        operation.updated_at_ms = now;
        Ok(result)
    }

    async fn admit_logical_operation(
        &self,
        intent: ManagedLogicalOperationIntent,
        reservation_cap: u64,
    ) -> Result<(ManagedLogicalOperation, ManagedWorkspaceUsage), ManagedError> {
        self.insert_logical_operation(intent.clone()).await?;
        let reserved = {
            let mut state = self.state.lock().await;
            let usage = Self::workspace_usage(&mut state, &intent.logical.tenant_id);
            let available = usage
                .visible_limit_bytes
                .saturating_add(usage.replacement_headroom_bytes)
                .saturating_sub(usage.physical_allocated_bytes)
                .saturating_sub(usage.reserved_bytes)
                .max(1);
            reservation_cap.min(available)
        };
        let usage = self
            .reserve_logical_operation(intent.operation_id, reserved)
            .await?;
        let operation = self
            .logical_operation(intent.operation_id)
            .await?
            .ok_or(ManagedError::Conflict)?;
        Ok((operation, usage))
    }

    async fn record_logical_usage(
        &self,
        operation_id: Uuid,
        evidence: ManagedUsageEvidence,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        if evidence.processed_bytes != evidence.source_bytes.max(evidence.expected_output_size) {
            return Err(ManagedError::Conflict);
        }
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get_mut(&operation_id)
            .ok_or(ManagedError::Conflict)?;
        if operation.evidence.as_ref() == Some(&evidence) {
            return Ok(operation.clone());
        }
        if operation.evidence.is_some()
            || operation.state == ManagedLogicalOperationState::Intent
            || operation.state.terminal()
            || evidence.processed_bytes > operation.intent.max_processed_bytes
            || (operation.intent.kind == ManagedMutationKind::Put
                && evidence.expected_output_digest.is_none())
            || (operation.intent.kind == ManagedMutationKind::Delete
                && (evidence.expected_output_size != 0
                    || evidence.source_bytes != 0
                    || evidence.processed_bytes != 0))
        {
            return Err(ManagedError::Conflict);
        }
        operation.evidence = Some(evidence);
        operation.updated_at_ms = crate::transaction::unix_time_ms();
        Ok(operation.clone())
    }

    async fn finalize_logical_put(
        &self,
        operation_id: Uuid,
        physical_lease: &PhysicalWriteLease,
        result: ExactPhysicalCommit,
        recovery_claim: Option<&ManagedRecoveryClaim>,
    ) -> Result<ManagedOperationCommit, ManagedError> {
        validate_exact_physical_commit(&result)?;
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get(&operation_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        let now = crate::transaction::unix_time_ms();
        if operation.state == ManagedLogicalOperationState::Committed {
            let persisted = state
                .authorities
                .get(&operation.intent.logical)
                .cloned()
                .ok_or(ManagedError::Conflict)?;
            let persisted_ids = state
                .physical_versions
                .iter()
                .filter(|version| {
                    version.write_operation_id == operation.intent.primary_child_operation_id
                })
                .map(|version| version.version_id.clone().unwrap_or_default())
                .collect::<HashSet<_>>();
            let persisted_targets = state
                .physical_versions
                .iter()
                .filter(|version| {
                    version.write_operation_id == operation.intent.primary_child_operation_id
                })
                .cloned()
                .collect::<Vec<_>>();
            let canonical_target = persisted_targets.first().ok_or(ManagedError::Conflict)?;
            let evidence = operation.evidence.as_ref().ok_or(ManagedError::Conflict)?;
            let recipe = operation
                .intent
                .publication_recipe
                .as_ref()
                .ok_or(ManagedError::Conflict)?;
            let committed_authority_version = operation
                .committed_authority_version
                .ok_or(ManagedError::Conflict)?;
            let original_authority_matches = persisted.generation == operation.intent.generation
                && persisted.digest
                    == evidence
                        .expected_output_digest
                        .clone()
                        .ok_or(ManagedError::Conflict)?
                && persisted.size == evidence.expected_output_size
                && persisted.metadata == recipe.metadata
                && persisted.placement_version == recipe.placement_version
                && persisted.primary_backend_id == recipe.primary_backend_id
                && persisted.primary_version_id == result.selected_version_id
                && persisted.replica_backend_id == recipe.replica_backend_id
                && persisted.primary_status == recipe.primary_status
                && persisted.replica_status == recipe.replica_status
                && !persisted.tombstone;
            if persisted.logical != operation.intent.logical
                || committed_authority_version
                    != operation
                        .intent
                        .expected_authority_cas
                        .unwrap_or(0)
                        .saturating_add(1)
                || persisted.cas_version < committed_authority_version
                || (persisted.cas_version == committed_authority_version
                    && !original_authority_matches)
                || persisted_ids != exact_version_ids(&result).into_iter().collect()
                || persisted_targets.iter().any(|target| {
                    target.tenant_id != operation.intent.logical.tenant_id
                        || target.namespace_epoch != operation.intent.fence.namespace_epoch
                        || target.backend_id != operation.intent.backend_id
                        || target.provider_bucket != operation.intent.provider_bucket
                        || target.physical_key != operation.intent.physical_key
                        || target.storage_identity != canonical_target.storage_identity
                        || target.credential_epoch != canonical_target.credential_epoch
                        || target.versioning_mode != canonical_target.versioning_mode
                        || target.versioning_capability != canonical_target.versioning_capability
                })
                || operation.committed_physical_bytes
                    != physical_allocation(
                        evidence.expected_output_size,
                        persisted_ids.len() as u64,
                    )?
            {
                return Err(ManagedError::Conflict);
            }
            let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
            return Ok(ManagedOperationCommit {
                operation,
                authority: persisted,
                usage: usage.clone(),
            });
        }
        validate_recovery_authority(&operation, recovery_claim, now)?;
        let evidence = operation.evidence.clone().ok_or(ManagedError::Conflict)?;
        let recipe = operation
            .intent
            .publication_recipe
            .clone()
            .ok_or(ManagedError::Conflict)?;
        if operation.intent.kind != ManagedMutationKind::Put
            || !matches!(
                operation.state,
                ManagedLogicalOperationState::Completing
                    | ManagedLogicalOperationState::CommitUnknown
                    | ManagedLogicalOperationState::RecoveryBlocked
            )
            || (operation.state == ManagedLogicalOperationState::RecoveryBlocked
                && recovery_claim.is_none())
            || recipe.version != MANAGED_PUBLICATION_RECIPE_VERSION
            || recipe.primary_backend_id != operation.intent.backend_id
        {
            return Err(ManagedError::Conflict);
        }
        if state
            .fenced_namespaces
            .contains_key(&operation.intent.logical.tenant_id)
            || state
                .namespace_epochs
                .get(&operation.intent.logical.tenant_id)
                .copied()
                .unwrap_or(1)
                != operation.intent.fence.namespace_epoch
            || state
                .routing_epochs
                .get(&operation.intent.logical.tenant_id)
                .copied()
                .unwrap_or(1)
                != operation.intent.fence.routing_epoch
        {
            return Err(ManagedError::RecoveryBlocked("namespace_fence_changed"));
        }
        let physical_intent = state
            .physical_write_intents
            .get(&physical_lease.intent_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        validate_physical_commit_versioning(&physical_intent, &result)?;
        if physical_lease.intent_id != operation.intent.primary_child_operation_id
            || physical_intent.tenant_id != operation.intent.logical.tenant_id
            || physical_intent.backend_id != operation.intent.backend_id
            || physical_intent.provider_bucket != operation.intent.provider_bucket
            || physical_intent.physical_key != operation.intent.physical_key
            || physical_intent.lease_owner != physical_lease.owner
            || state.physical_write_tokens.get(&physical_lease.intent_id)
                != Some(&physical_lease.token)
            || state.physical_write_epochs.get(&physical_lease.intent_id)
                != Some(&physical_lease.namespace_epoch)
            || state
                .physical_write_leases
                .get(&physical_lease.intent_id)
                .is_none_or(|expiry| *expiry <= crate::transaction::unix_time_ms())
            || operation
                .recovery_owner
                .as_ref()
                .is_some_and(|owner| owner != &physical_lease.owner)
        {
            return Err(ManagedError::Conflict);
        }
        let expected_targets =
            expected_physical_targets(&physical_intent, physical_lease.namespace_epoch, &result);
        let preexisting_targets = state
            .physical_versions
            .iter()
            .filter(|target| {
                target.write_operation_id == operation.intent.primary_child_operation_id
            })
            .cloned()
            .collect::<Vec<_>>();
        if preexisting_targets
            .iter()
            .any(|existing| !expected_targets.contains(existing))
        {
            return Err(ManagedError::RecoveryBlocked("physical_version_mismatch"));
        }
        for target in &expected_targets {
            if !state.physical_versions.iter().any(|existing| {
                existing.tenant_id == target.tenant_id
                    && existing.backend_id == target.backend_id
                    && existing.provider_bucket == target.provider_bucket
                    && existing.physical_key == target.physical_key
                    && existing.version_id == target.version_id
            }) {
                state.physical_versions.push(target.clone());
            }
        }
        let child_versions = state
            .physical_versions
            .iter()
            .filter(|target| {
                target.write_operation_id == operation.intent.primary_child_operation_id
                    && target.tenant_id == operation.intent.logical.tenant_id
                    && target.backend_id == operation.intent.backend_id
                    && target.provider_bucket == operation.intent.provider_bucket
                    && target.physical_key == operation.intent.physical_key
            })
            .cloned()
            .collect::<Vec<_>>();
        let derived_physical_allocation =
            physical_allocation(evidence.expected_output_size, child_versions.len() as u64)?;
        if child_versions.len() != expected_targets.len()
            || expected_targets
                .iter()
                .any(|expected| !child_versions.contains(expected))
            || derived_physical_allocation > operation.reserved_physical_bytes
        {
            return Err(ManagedError::RecoveryBlocked("physical_version_mismatch"));
        }
        let existing = state.authorities.get(&operation.intent.logical).cloned();
        if existing.as_ref().map(|value| value.cas_version)
            != operation.intent.expected_authority_cas
            || existing
                .as_ref()
                .filter(|value| !value.tombstone)
                .map_or(0, |value| value.size)
                != operation.intent.prior_logical_size
        {
            return Err(ManagedError::RecoveryBlocked("authority_fence_changed"));
        }
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        if usage.active_operation_id != Some(operation_id)
            || usage.reserved_bytes < operation.reserved_physical_bytes
        {
            return Err(ManagedError::Conflict);
        }
        let visible = usage
            .visible_logical_bytes
            .checked_sub(operation.intent.prior_logical_size)
            .and_then(|value| value.checked_add(evidence.expected_output_size))
            .ok_or(ManagedError::QuotaExceeded)?;
        if visible > usage.visible_limit_bytes {
            return Err(ManagedError::QuotaExceeded);
        }
        let mut authority = ObjectAuthority {
            logical: operation.intent.logical.clone(),
            generation: operation.intent.generation,
            digest: evidence
                .expected_output_digest
                .clone()
                .ok_or(ManagedError::Conflict)?,
            size: evidence.expected_output_size,
            metadata: recipe.metadata,
            placement_version: recipe.placement_version,
            primary_backend_id: recipe.primary_backend_id,
            primary_version_id: result.selected_version_id,
            replica_backend_id: recipe.replica_backend_id,
            primary_status: recipe.primary_status,
            replica_status: recipe.replica_status,
            tombstone: false,
            cas_version: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        authority.cas_version = operation
            .intent
            .expected_authority_cas
            .unwrap_or(0)
            .saturating_add(1);
        authority.created_at_ms = existing.as_ref().map_or(now, |value| value.created_at_ms);
        authority.updated_at_ms = now;
        let namespace_epoch = operation.intent.fence.namespace_epoch;
        state
            .authorities
            .insert(authority.logical.clone(), authority.clone());
        for mut repair in publication_repairs(&authority) {
            repair.namespace_epoch = namespace_epoch;
            insert_memory_repair(&mut state, repair);
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                if state.physical_versions.iter().any(|target| {
                    target.tenant_id == repair.logical.tenant_id
                        && target.backend_id == repair.target_backend_id
                        && target.physical_key == repair.physical_key
                }) {
                    repair.namespace_epoch = namespace_epoch;
                    insert_memory_repair(&mut state, repair);
                }
            }
        }
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        usage.visible_logical_bytes = visible;
        usage.physical_allocated_bytes = usage
            .physical_allocated_bytes
            .checked_add(derived_physical_allocation)
            .ok_or(ManagedError::QuotaExceeded)?;
        usage.reserved_bytes = usage
            .reserved_bytes
            .checked_sub(operation.reserved_physical_bytes)
            .ok_or(ManagedError::Conflict)?;
        usage.active_operation_id = None;
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        let committed_usage = usage.clone();
        let operation = state.logical_operations.get_mut(&operation_id).unwrap();
        operation.state = ManagedLogicalOperationState::Committed;
        operation.committed_physical_bytes = derived_physical_allocation;
        operation.committed_authority_version = Some(authority.cas_version);
        operation.updated_at_ms = now;
        operation.committed_at_ms = Some(now);
        operation.recovery_owner = None;
        operation.recovery_token = None;
        operation.recovery_expires_at_ms = None;
        let committed_operation = operation.clone();
        state
            .physical_write_intents
            .remove(&physical_lease.intent_id);
        state
            .blocked_write_intents
            .remove(&physical_lease.intent_id);
        state
            .physical_write_leases
            .remove(&physical_lease.intent_id);
        state
            .physical_write_tokens
            .remove(&physical_lease.intent_id);
        state
            .physical_write_epochs
            .remove(&physical_lease.intent_id);
        Ok(ManagedOperationCommit {
            operation: committed_operation,
            authority,
            usage: committed_usage,
        })
    }

    async fn commit_logical_delete(
        &self,
        operation_id: Uuid,
        placement: &Placement,
    ) -> Result<ManagedOperationCommit, ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get(&operation_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        if operation.state == ManagedLogicalOperationState::Committed {
            let authority = state
                .authorities
                .get(&operation.intent.logical)
                .cloned()
                .filter(|authority| {
                    authority.tombstone && authority.generation == operation.intent.generation
                })
                .ok_or(ManagedError::Conflict)?;
            let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
            return Ok(ManagedOperationCommit {
                operation,
                authority,
                usage: usage.clone(),
            });
        }
        if operation.intent.kind != ManagedMutationKind::Delete
            || operation.reserved_physical_bytes != 0
            || operation.evidence.as_ref().is_none_or(|evidence| {
                evidence.expected_output_size != 0
                    || evidence.source_bytes != 0
                    || evidence.processed_bytes != 0
            })
            || !matches!(
                operation.state,
                ManagedLogicalOperationState::Completing
                    | ManagedLogicalOperationState::CommitUnknown
            )
        {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::Committed,
            });
        }
        if state
            .fenced_namespaces
            .contains_key(&operation.intent.logical.tenant_id)
            || state
                .namespace_epochs
                .get(&operation.intent.logical.tenant_id)
                .copied()
                .unwrap_or(1)
                != operation.intent.fence.namespace_epoch
            || state
                .routing_epochs
                .get(&operation.intent.logical.tenant_id)
                .copied()
                .unwrap_or(1)
                != operation.intent.fence.routing_epoch
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let existing = state.authorities.get(&operation.intent.logical).cloned();
        if existing.as_ref().map(|value| value.cas_version)
            != operation.intent.expected_authority_cas
            || existing
                .as_ref()
                .filter(|value| !value.tombstone)
                .map_or(0, |value| value.size)
                != operation.intent.prior_logical_size
        {
            return Err(ManagedError::Conflict);
        }
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        if usage.active_operation_id != Some(operation_id) {
            return Err(ManagedError::Conflict);
        }
        let visible = usage
            .visible_logical_bytes
            .checked_sub(operation.intent.prior_logical_size)
            .ok_or(ManagedError::Conflict)?;
        let now = crate::transaction::unix_time_ms();
        let authority = ObjectAuthority {
            logical: operation.intent.logical.clone(),
            generation: operation.intent.generation,
            digest: String::new(),
            size: 0,
            metadata: BTreeMap::new(),
            placement_version: placement.version,
            primary_backend_id: placement.primary_backend_id.clone(),
            primary_version_id: None,
            replica_backend_id: placement.replica_backend_id.clone(),
            primary_status: CopyStatus::Absent,
            replica_status: CopyStatus::Absent,
            tombstone: true,
            cas_version: operation
                .intent
                .expected_authority_cas
                .unwrap_or(0)
                .saturating_add(1),
            created_at_ms: existing.as_ref().map_or(now, |value| value.created_at_ms),
            updated_at_ms: now,
        };
        state
            .authorities
            .insert(authority.logical.clone(), authority.clone());
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                if state.physical_versions.iter().any(|target| {
                    target.tenant_id == repair.logical.tenant_id
                        && target.backend_id == repair.target_backend_id
                        && target.physical_key == repair.physical_key
                }) {
                    repair.namespace_epoch = operation.intent.fence.namespace_epoch;
                    insert_memory_repair(&mut state, repair);
                }
            }
        }
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        usage.visible_logical_bytes = visible;
        usage.active_operation_id = None;
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        let committed_usage = usage.clone();
        let operation = state.logical_operations.get_mut(&operation_id).unwrap();
        operation.state = ManagedLogicalOperationState::Committed;
        operation.committed_authority_version = Some(authority.cas_version);
        operation.updated_at_ms = now;
        operation.committed_at_ms = Some(now);
        Ok(ManagedOperationCommit {
            operation: operation.clone(),
            authority,
            usage: committed_usage,
        })
    }

    async fn commit_atomic_logical_delete(
        &self,
        request: ManagedDeleteRequest,
    ) -> Result<ManagedOperationCommit, ManagedDeleteError> {
        if request.logical.tenant_id.is_empty()
            || request.logical.bucket.is_empty()
            || request.placement.version == 0
            || request.placement.primary_backend_id.is_empty()
            || request.provider_bucket.is_empty()
            || request.rate_version <= 0
            || request.occurred_at_micros < 0
        {
            return Err(ManagedError::Conflict.into());
        }
        let mut state = self.state.lock().await;
        if state
            .fenced_namespaces
            .contains_key(&request.logical.tenant_id)
        {
            return Err(ManagedError::NamespaceFenced.into());
        }
        let fence = ManagedRouteFence {
            namespace_epoch: state
                .namespace_epochs
                .get(&request.logical.tenant_id)
                .copied()
                .unwrap_or(1),
            routing_epoch: state
                .routing_epochs
                .get(&request.logical.tenant_id)
                .copied()
                .unwrap_or(1),
        };
        let existing = state.authorities.get(&request.logical).cloned();
        let generation = existing
            .as_ref()
            .filter(|authority| authority.tombstone)
            .map_or_else(
                || Uuid::new_v5(&Uuid::NAMESPACE_URL, request.operation_id.as_bytes()),
                |authority| authority.generation,
            );
        let prior_logical_size = existing
            .as_ref()
            .filter(|authority| !authority.tombstone)
            .map_or(0, |authority| authority.size);
        let intent = ManagedLogicalOperationIntent {
            operation_id: request.operation_id,
            receipt_id: request.receipt_id,
            logical: request.logical.clone(),
            kind: ManagedMutationKind::Delete,
            generation,
            fence,
            expected_authority_cas: existing.as_ref().map(|authority| authority.cas_version),
            prior_logical_size,
            primary_child_operation_id: Uuid::new_v5(
                &Uuid::NAMESPACE_OID,
                request.operation_id.as_bytes(),
            ),
            backend_id: request.placement.primary_backend_id.clone(),
            provider_bucket: request.provider_bucket.clone(),
            physical_key: generation_physical_key(&request.logical, generation),
            occurred_at_ms: request.occurred_at_micros.div_euclid(1_000),
            rate_version: request.rate_version,
            route: UsageRoute::DeleteObject,
            request_kind: RequestKind::Write,
            max_processed_bytes: request.max_processed_bytes,
            publication_recipe: Some(ManagedPublicationRecipe {
                version: MANAGED_PUBLICATION_RECIPE_VERSION,
                placement_version: request.placement.version,
                primary_backend_id: request.placement.primary_backend_id.clone(),
                replica_backend_id: request.placement.replica_backend_id.clone(),
                metadata: BTreeMap::new(),
                primary_status: CopyStatus::Absent,
                replica_status: CopyStatus::Absent,
            }),
        };
        if let Some(operation) = state.logical_operations.get(&request.operation_id).cloned() {
            if !delete_request_matches_operation(&request, &operation)
                || operation.state != ManagedLogicalOperationState::Committed
            {
                return Err(ManagedError::Conflict.into());
            }
            let authority = committed_delete_replay_authority(&operation, existing)?;
            let usage = Self::workspace_usage(&mut state, &request.logical.tenant_id).clone();
            return Ok(ManagedOperationCommit {
                operation,
                authority,
                usage,
            });
        }
        let usage = Self::workspace_usage(&mut state, &request.logical.tenant_id);
        if usage.active_operation_id.is_some() {
            return Err(ManagedError::MutationInProgress.into());
        }
        let visible = usage
            .visible_logical_bytes
            .checked_sub(prior_logical_size)
            .ok_or(ManagedError::Conflict)?;
        let now = crate::transaction::unix_time_ms();
        let authority = existing
            .as_ref()
            .filter(|authority| authority.tombstone)
            .cloned()
            .unwrap_or_else(|| ObjectAuthority {
                logical: request.logical.clone(),
                generation,
                digest: String::new(),
                size: 0,
                metadata: BTreeMap::new(),
                placement_version: request.placement.version,
                primary_backend_id: request.placement.primary_backend_id,
                primary_version_id: None,
                replica_backend_id: request.placement.replica_backend_id,
                primary_status: CopyStatus::Absent,
                replica_status: CopyStatus::Absent,
                tombstone: true,
                cas_version: existing
                    .as_ref()
                    .map_or(1, |authority| authority.cas_version.saturating_add(1)),
                created_at_ms: existing
                    .as_ref()
                    .map_or(now, |authority| authority.created_at_ms),
                updated_at_ms: now,
            });
        let repairs = existing
            .as_ref()
            .filter(|authority| !authority.tombstone)
            .into_iter()
            .flat_map(cleanup_repairs)
            .filter(|repair| {
                state.physical_versions.iter().any(|target| {
                    target.tenant_id == repair.logical.tenant_id
                        && target.backend_id == repair.target_backend_id
                        && target.physical_key == repair.physical_key
                })
            })
            .map(|mut repair| {
                repair.namespace_epoch = fence.namespace_epoch;
                repair
            })
            .collect::<Vec<_>>();
        state
            .authorities
            .insert(request.logical.clone(), authority.clone());
        for repair in repairs {
            insert_memory_repair(&mut state, repair);
        }
        let usage = Self::workspace_usage(&mut state, &request.logical.tenant_id);
        usage.visible_logical_bytes = visible;
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        let committed_usage = usage.clone();
        let evidence = ManagedUsageEvidence {
            expected_output_digest: None,
            expected_output_size: 0,
            source_bytes: 0,
            processed_bytes: 0,
            payload: serde_json::json!({
                "occurred_at_micros": request.occurred_at_micros,
            }),
        };
        let operation = ManagedLogicalOperation {
            intent,
            evidence: Some(evidence),
            reserved_physical_bytes: 0,
            committed_physical_bytes: 0,
            released_physical_bytes: 0,
            state: ManagedLogicalOperationState::Committed,
            committed_authority_version: Some(authority.cas_version),
            settlement_state: ManagedSettlementState::Pending,
            last_error_class: None,
            recovery_owner: None,
            recovery_token: None,
            recovery_expires_at_ms: None,
            created_at_ms: now,
            updated_at_ms: now,
            committed_at_ms: Some(now),
            aborted_at_ms: None,
        };
        state
            .logical_operations
            .insert(request.operation_id, operation.clone());
        Ok(ManagedOperationCommit {
            operation,
            authority,
            usage: committed_usage,
        })
    }

    async fn transition_logical_operation(
        &self,
        operation_id: Uuid,
        from: ManagedLogicalOperationState,
        to: ManagedLogicalOperationState,
        error_class: Option<&str>,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        if !valid_logical_transition(from, to) {
            return Err(ManagedError::InvalidTransition { from, to });
        }
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get_mut(&operation_id)
            .ok_or(ManagedError::Conflict)?;
        if operation.state != from {
            return Err(ManagedError::Conflict);
        }
        operation.state = to;
        operation.last_error_class =
            error_class.map(|value| value.chars().take(128).collect::<String>());
        operation.updated_at_ms = crate::transaction::unix_time_ms();
        Ok(operation.clone())
    }

    async fn record_logical_usage_and_begin_completion(
        &self,
        operation_id: Uuid,
        evidence: ManagedUsageEvidence,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        self.record_logical_usage(operation_id, evidence).await?;
        self.transition_logical_operation(
            operation_id,
            ManagedLogicalOperationState::Open,
            ManagedLogicalOperationState::Completing,
            None,
        )
        .await
    }

    async fn prove_logical_abort(
        &self,
        operation_id: Uuid,
        error_class: &str,
        physical: Option<ManagedProvenPhysicalAllocation>,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get(&operation_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        if operation.state == ManagedLogicalOperationState::ProvenAborted {
            return Ok(operation);
        }
        if operation.state == ManagedLogicalOperationState::Committed {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::ProvenAborted,
            });
        }
        if state
            .namespace_epochs
            .get(&operation.intent.logical.tenant_id)
            .copied()
            .unwrap_or(1)
            != operation.intent.fence.namespace_epoch
        {
            return Err(ManagedError::Conflict);
        }
        let child_version_count = state
            .physical_versions
            .iter()
            .filter(|target| {
                target.write_operation_id == operation.intent.primary_child_operation_id
                    && target.tenant_id == operation.intent.logical.tenant_id
                    && target.backend_id == operation.intent.backend_id
                    && target.provider_bucket == operation.intent.provider_bucket
                    && target.physical_key == operation.intent.physical_key
            })
            .count() as u64;
        let allocated = match physical {
            None => {
                if child_version_count != 0 {
                    return Err(ManagedError::Conflict);
                }
                0
            }
            Some(physical) => {
                let evidence = operation.evidence.as_ref().ok_or(ManagedError::Conflict)?;
                let derived = physical_allocation(physical.authority.size, child_version_count)?;
                if child_version_count == 0
                    || physical.authority.logical != operation.intent.logical
                    || physical.authority.generation != operation.intent.generation
                    || physical.authority.primary_backend_id != operation.intent.backend_id
                    || physical.authority.tombstone
                    || evidence.expected_output_size != physical.authority.size
                    || evidence.expected_output_digest.as_deref()
                        != Some(physical.authority.digest.as_str())
                    || physical.allocated_bytes != derived
                    || derived > operation.reserved_physical_bytes
                {
                    return Err(ManagedError::Conflict);
                }
                for mut repair in cleanup_repairs(&physical.authority) {
                    if state.physical_versions.iter().any(|target| {
                        target.tenant_id == repair.logical.tenant_id
                            && target.backend_id == repair.target_backend_id
                            && target.physical_key == repair.physical_key
                    }) {
                        repair.namespace_epoch = operation.intent.fence.namespace_epoch;
                        insert_memory_repair(&mut state, repair);
                    }
                }
                derived
            }
        };
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        if operation.state != ManagedLogicalOperationState::Intent
            && usage.active_operation_id != Some(operation_id)
        {
            return Err(ManagedError::Conflict);
        }
        usage.reserved_bytes = usage
            .reserved_bytes
            .checked_sub(operation.reserved_physical_bytes)
            .ok_or(ManagedError::Conflict)?;
        usage.physical_allocated_bytes = usage
            .physical_allocated_bytes
            .checked_add(allocated)
            .ok_or(ManagedError::QuotaExceeded)?;
        if usage.active_operation_id == Some(operation_id) {
            usage.active_operation_id = None;
        }
        let now = crate::transaction::unix_time_ms();
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        let operation = state.logical_operations.get_mut(&operation_id).unwrap();
        operation.state = ManagedLogicalOperationState::ProvenAborted;
        operation.committed_physical_bytes = allocated;
        operation.settlement_state = ManagedSettlementState::Released;
        operation.last_error_class = Some(error_class.chars().take(128).collect());
        operation.updated_at_ms = now;
        operation.aborted_at_ms = Some(now);
        Ok(operation.clone())
    }

    async fn abort_logical_put(
        &self,
        operation_id: Uuid,
        physical_lease: Option<&PhysicalWriteLease>,
        proof: LogicalAbortProof,
        error_class: &str,
        recovery_claim: Option<&ManagedRecoveryClaim>,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get(&operation_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        if operation.state == ManagedLogicalOperationState::ProvenAborted {
            return Ok(operation);
        }
        let now = crate::transaction::unix_time_ms();
        validate_recovery_authority(&operation, recovery_claim, now)?;
        if operation.intent.kind != ManagedMutationKind::Put
            || operation.state == ManagedLogicalOperationState::Committed
        {
            return Err(ManagedError::Conflict);
        }
        if state
            .namespace_epochs
            .get(&operation.intent.logical.tenant_id)
            .copied()
            .unwrap_or(1)
            != operation.intent.fence.namespace_epoch
        {
            return Err(ManagedError::RecoveryBlocked("namespace_fence_changed"));
        }
        if state
            .physical_versions
            .iter()
            .any(|target| target.write_operation_id == operation.intent.primary_child_operation_id)
        {
            return Err(ManagedError::Conflict);
        }
        let intent = state
            .physical_write_intents
            .get(&operation.intent.primary_child_operation_id);
        match (proof, physical_lease, intent) {
            (LogicalAbortProof::NoChildStarted, None, None)
                if matches!(
                    operation.state,
                    ManagedLogicalOperationState::Intent | ManagedLogicalOperationState::Open
                ) => {}
            (
                LogicalAbortProof::NoChildStarted | LogicalAbortProof::ChildProvenAborted,
                Some(lease),
                Some(intent),
            ) if lease.intent_id == operation.intent.primary_child_operation_id
                && intent.lease_owner == lease.owner
                && state.physical_write_tokens.get(&lease.intent_id) == Some(&lease.token)
                && state.physical_write_epochs.get(&lease.intent_id)
                    == Some(&lease.namespace_epoch)
                && state
                    .physical_write_leases
                    .get(&lease.intent_id)
                    .is_some_and(|expiry| *expiry > now) => {}
            _ => return Err(ManagedError::Conflict),
        }
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        if operation.state != ManagedLogicalOperationState::Intent
            && usage.active_operation_id != Some(operation_id)
        {
            return Err(ManagedError::Conflict);
        }
        usage.reserved_bytes = usage
            .reserved_bytes
            .checked_sub(operation.reserved_physical_bytes)
            .ok_or(ManagedError::Conflict)?;
        if usage.active_operation_id == Some(operation_id) {
            usage.active_operation_id = None;
        }
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        let child_operation_id = operation.intent.primary_child_operation_id;
        let operation = state.logical_operations.get_mut(&operation_id).unwrap();
        operation.state = ManagedLogicalOperationState::ProvenAborted;
        operation.settlement_state = ManagedSettlementState::Released;
        operation.last_error_class = Some(error_class.chars().take(128).collect());
        operation.recovery_owner = None;
        operation.recovery_token = None;
        operation.recovery_expires_at_ms = None;
        operation.updated_at_ms = now;
        operation.aborted_at_ms = Some(now);
        let aborted = operation.clone();
        let _ = operation;
        state.physical_write_intents.remove(&child_operation_id);
        state.blocked_write_intents.remove(&child_operation_id);
        state.physical_write_leases.remove(&child_operation_id);
        state.physical_write_tokens.remove(&child_operation_id);
        state.physical_write_epochs.remove(&child_operation_id);
        Ok(aborted)
    }

    async fn workspace_usage(
        &self,
        tenant_id: &str,
    ) -> Result<Option<ManagedWorkspaceUsage>, ManagedError> {
        Ok(self
            .state
            .lock()
            .await
            .workspace_usage
            .get(tenant_id)
            .cloned())
    }

    async fn list_authority(
        &self,
        query: AuthorityListQuery,
    ) -> Result<AuthorityListPage, ManagedError> {
        if query.max_keys > MANAGED_AUTHORITY_LIST_MAX_KEYS {
            return Err(ManagedError::Conflict);
        }
        if query.max_keys == 0 {
            return Ok(AuthorityListPage {
                objects: Vec::new(),
                next_after: None,
            });
        }
        let state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(&query.tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let mut objects: Vec<_> = state
            .authorities
            .values()
            .filter(|authority| {
                authority.logical.tenant_id == query.tenant_id
                    && authority.logical.bucket == query.bucket
                    && !authority.tombstone
                    && authority.logical.key.starts_with(&query.prefix)
                    && query
                        .after
                        .as_ref()
                        .is_none_or(|after| authority.logical.key > *after)
            })
            .cloned()
            .collect();
        objects.sort_by(|left, right| left.logical.key.cmp(&right.logical.key));
        let next_after = (objects.len() as u64 > query.max_keys)
            .then(|| objects[query.max_keys as usize - 1].logical.key.clone());
        objects.truncate(query.max_keys as usize);
        Ok(AuthorityListPage {
            objects,
            next_after,
        })
    }

    async fn list_authority_below_placement_version(
        &self,
        query: AuthorityPlacementPageQuery,
    ) -> Result<AuthorityPlacementPage, ManagedError> {
        if query.limit > MANAGED_AUTHORITY_LIST_MAX_KEYS || query.target_placement_version == 0 {
            return Err(ManagedError::Conflict);
        }
        if query.limit == 0 {
            return Ok(AuthorityPlacementPage {
                objects: Vec::new(),
                next_after: None,
            });
        }
        let state = self.state.lock().await;
        let mut objects: Vec<_> = state
            .authorities
            .values()
            .filter(|authority| {
                !authority.tombstone
                    && authority.placement_version < query.target_placement_version
                    && query.after.as_ref().is_none_or(|after| {
                        (
                            authority.logical.tenant_id.as_str(),
                            authority.logical.bucket.as_str(),
                            authority.logical.key.as_str(),
                        ) > (
                            after.tenant_id.as_str(),
                            after.bucket.as_str(),
                            after.key.as_str(),
                        )
                    })
            })
            .cloned()
            .collect();
        objects.sort_by(|left, right| {
            (
                left.logical.tenant_id.as_str(),
                left.logical.bucket.as_str(),
                left.logical.key.as_str(),
            )
                .cmp(&(
                    right.logical.tenant_id.as_str(),
                    right.logical.bucket.as_str(),
                    right.logical.key.as_str(),
                ))
        });
        let next_after = (objects.len() as u64 > query.limit).then(|| {
            let authority = &objects[query.limit as usize - 1];
            AuthorityPlacementCursor {
                tenant_id: authority.logical.tenant_id.clone(),
                bucket: authority.logical.bucket.clone(),
                key: authority.logical.key.clone(),
            }
        });
        objects.truncate(query.limit as usize);
        Ok(AuthorityPlacementPage {
            objects,
            next_after,
        })
    }

    async fn authority_placement_stats(
        &self,
        target_placement_version: u32,
    ) -> Result<AuthorityPlacementStats, ManagedError> {
        if target_placement_version == 0 {
            return Err(ManagedError::Conflict);
        }
        let state = self.state.lock().await;
        let mut remaining = 0_u64;
        let mut oldest_updated_at_ms: Option<i64> = None;
        for authority in state.authorities.values() {
            if !authority.tombstone && authority.placement_version < target_placement_version {
                remaining = remaining.saturating_add(1);
                oldest_updated_at_ms = Some(
                    oldest_updated_at_ms.map_or(authority.updated_at_ms, |oldest| {
                        oldest.min(authority.updated_at_ms)
                    }),
                );
            }
        }
        Ok(AuthorityPlacementStats {
            remaining,
            oldest_updated_at_ms,
        })
    }

    async fn create_list_cursor(
        &self,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let mut state = self.state.lock().await;
        Self::create_list_cursor_in_state(&mut state, request, now_ms)
    }

    async fn create_list_cursor_successor(
        &self,
        predecessor_cursor_id: Uuid,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let mut state = self.state.lock().await;
        if let Some(successor_id) = state
            .list_cursor_successors
            .get(&predecessor_cursor_id)
            .copied()
        {
            let cursor = state
                .list_cursors
                .get(&successor_id)
                .cloned()
                .ok_or_else(|| {
                    ManagedError::Corrupt("managed cursor successor is missing".to_string())
                })?;
            let current_fence = ManagedRouteFence {
                namespace_epoch: state
                    .namespace_epochs
                    .get(&cursor.binding.tenant_id)
                    .copied()
                    .unwrap_or(1),
                routing_epoch: state
                    .routing_epochs
                    .get(&cursor.binding.tenant_id)
                    .copied()
                    .unwrap_or(1),
            };
            if cursor.expires_at_ms <= now_ms || cursor.fence != current_fence {
                return Err(ManagedError::CursorExpired);
            }
            return cursor_matches_request(&cursor, &request)
                .then_some(cursor)
                .ok_or(ManagedError::Conflict);
        }
        let cursor = Self::create_list_cursor_in_state(&mut state, request, now_ms)?;
        state
            .list_cursor_successors
            .insert(predecessor_cursor_id, cursor.id);
        Ok(cursor)
    }

    async fn use_list_cursor(
        &self,
        cursor_id: Uuid,
        binding: &ManagedListCursorBinding,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(&binding.tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let Some(cursor) = state.list_cursors.get(&cursor_id).cloned() else {
            return Err(ManagedError::CursorExpired);
        };
        if cursor.expires_at_ms <= now_ms {
            Self::remove_list_cursor(&mut state, cursor_id);
            return Err(ManagedError::CursorExpired);
        }
        if &cursor.binding != binding {
            return Err(ManagedError::CursorQueryMismatch);
        }
        let current_fence = ManagedRouteFence {
            namespace_epoch: state
                .namespace_epochs
                .get(&cursor.binding.tenant_id)
                .copied()
                .unwrap_or(1),
            routing_epoch: state
                .routing_epochs
                .get(&cursor.binding.tenant_id)
                .copied()
                .unwrap_or(1),
        };
        if cursor.fence != current_fence {
            Self::remove_list_cursor(&mut state, cursor_id);
            return Err(ManagedError::CursorExpired);
        }
        let cursor = state
            .list_cursors
            .get_mut(&cursor_id)
            .ok_or(ManagedError::CursorExpired)?;
        if cursor.state == ManagedListCursorState::Active {
            cursor.state = ManagedListCursorState::Used;
            cursor.first_used_at_ms = Some(now_ms);
        }
        Ok(cursor.clone())
    }

    async fn delete_list_cursor(&self, cursor_id: Uuid) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        Self::remove_list_cursor(&mut state, cursor_id);
        Ok(())
    }

    async fn cleanup_expired_list_cursors(
        &self,
        now_ms: i64,
        limit: u64,
    ) -> Result<u64, ManagedError> {
        let mut state = self.state.lock().await;
        let mut expired: Vec<_> = state
            .list_cursors
            .values()
            .filter(|cursor| cursor.expires_at_ms <= now_ms)
            .map(|cursor| (cursor.expires_at_ms, cursor.id))
            .collect();
        expired.sort_unstable();
        expired.truncate(limit as usize);
        for (_, cursor_id) in &expired {
            Self::remove_list_cursor(&mut state, *cursor_id);
        }
        Ok(expired.len() as u64)
    }

    async fn begin_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
    ) -> Result<u64, ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let epoch = *state
            .namespace_epochs
            .entry(tenant_id.to_string())
            .or_insert(1);
        state
            .multipart_activities
            .insert(upload_id.to_string(), (tenant_id.to_string(), epoch));
        state.multipart_registration_expiry.insert(
            upload_id.to_string(),
            crate::transaction::unix_time_ms().saturating_add(10 * 60 * 1000),
        );
        Ok(epoch)
    }

    async fn assert_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
        allow_purging: bool,
    ) -> Result<(), ManagedError> {
        let state = self.state.lock().await;
        if state.namespace_epochs.get(tenant_id).copied().unwrap_or(1) != namespace_epoch
            || (state.fenced_namespaces.contains_key(tenant_id) && !allow_purging)
            || state.multipart_activities.get(upload_id)
                != Some(&(tenant_id.to_string(), namespace_epoch))
            || !state.confirmed_multipart_activities.contains(upload_id)
        {
            return Err(ManagedError::NamespaceFenced);
        }
        Ok(())
    }

    async fn confirm_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(tenant_id)
            || state.multipart_activities.get(upload_id)
                != Some(&(tenant_id.to_string(), namespace_epoch))
        {
            return Err(ManagedError::NamespaceFenced);
        }
        state
            .confirmed_multipart_activities
            .insert(upload_id.to_string());
        state.multipart_registration_expiry.remove(upload_id);
        Ok(())
    }

    async fn reconcile_multipart_activities(&self, limit: u64) -> Result<u64, ManagedError> {
        let mut state = self.state.lock().await;
        let now = crate::transaction::unix_time_ms();
        let expired: Vec<_> = state
            .multipart_registration_expiry
            .iter()
            .filter(|(_, expires)| **expires <= now)
            .take(limit as usize)
            .map(|(upload_id, _)| upload_id.clone())
            .collect();
        for upload_id in &expired {
            state.multipart_registration_expiry.remove(upload_id);
            state.multipart_activities.remove(upload_id);
        }
        Ok(expired.len() as u64)
    }

    async fn finish_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state.multipart_activities.get(upload_id)
            == Some(&(tenant_id.to_string(), namespace_epoch))
        {
            state.multipart_activities.remove(upload_id);
            state.confirmed_multipart_activities.remove(upload_id);
            state.multipart_registration_expiry.remove(upload_id);
        }
        Ok(())
    }

    async fn any_authority(&self) -> Result<bool, ManagedError> {
        Ok(!self.state.lock().await.authorities.is_empty())
    }

    async fn get(
        &self,
        logical: &LogicalObjectKey,
    ) -> Result<Option<ObjectAuthority>, ManagedError> {
        let state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(&logical.tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        Ok(state.authorities.get(logical).cloned())
    }

    async fn publish(
        &self,
        mut authority: ObjectAuthority,
        expected_cas: Option<u64>,
    ) -> Result<ObjectAuthority, ManagedError> {
        let mut state = self.state.lock().await;
        if state
            .fenced_namespaces
            .contains_key(&authority.logical.tenant_id)
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let existing = state.authorities.get(&authority.logical).cloned();
        if existing.as_ref().map(|value| value.cas_version) != expected_cas {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        authority.cas_version = expected_cas.unwrap_or(0).saturating_add(1);
        authority.created_at_ms = existing.as_ref().map_or(now, |value| value.created_at_ms);
        authority.updated_at_ms = now;
        let namespace_epoch = *state
            .namespace_epochs
            .entry(authority.logical.tenant_id.clone())
            .or_insert(1);
        state
            .authorities
            .insert(authority.logical.clone(), authority.clone());
        for mut repair in publication_repairs(&authority) {
            repair.namespace_epoch = namespace_epoch;
            insert_memory_repair(&mut state, repair);
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                if !state.physical_versions.iter().any(|target| {
                    target.tenant_id == repair.logical.tenant_id
                        && target.backend_id == repair.target_backend_id
                        && target.physical_key == repair.physical_key
                }) {
                    continue;
                }
                repair.namespace_epoch = namespace_epoch;
                insert_memory_repair(&mut state, repair);
            }
        }
        Ok(authority)
    }

    async fn record_placement_policy(
        &self,
        policy: &ManagedPlacementPolicy,
    ) -> Result<bool, ManagedError> {
        let mut state = self.state.lock().await;
        if let Some(existing) = state.placement_policy_fingerprints.get(&policy.version) {
            return Ok(existing == &policy.fingerprint);
        }
        state
            .placement_policy_fingerprints
            .insert(policy.version, policy.fingerprint.clone());
        Ok(true)
    }

    async fn advance_placement_version(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: u64,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(&logical.tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let authority = state
            .authorities
            .get_mut(logical)
            .ok_or(ManagedError::Conflict)?;
        let locations_match = authority.primary_backend_id == placement.primary_backend_id
            && authority.primary_status == CopyStatus::Ready
            && match placement.replica_backend_id.as_deref() {
                Some(replica) => {
                    authority.replica_backend_id.as_deref() == Some(replica)
                        && authority.replica_status == CopyStatus::Ready
                }
                None => {
                    authority.replica_backend_id.is_none()
                        && authority.replica_status == CopyStatus::Absent
                }
            };
        if authority.tombstone
            || authority.cas_version != expected_cas
            || placement.version <= authority.placement_version
            || !locations_match
        {
            return Err(ManagedError::Conflict);
        }
        authority.placement_version = placement.version;
        authority.cas_version = authority.cas_version.saturating_add(1);
        authority.updated_at_ms = crate::transaction::unix_time_ms();
        Ok(authority.clone())
    }

    async fn tombstone(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: Option<u64>,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        self.publish(
            ObjectAuthority {
                logical: logical.clone(),
                generation: Uuid::now_v7(),
                digest: String::new(),
                size: 0,
                metadata: BTreeMap::new(),
                placement_version: placement.version,
                primary_backend_id: placement.primary_backend_id.clone(),
                primary_version_id: None,
                replica_backend_id: placement.replica_backend_id.clone(),
                primary_status: CopyStatus::Absent,
                replica_status: CopyStatus::Absent,
                tombstone: true,
                cas_version: 0,
                created_at_ms: now,
                updated_at_ms: now,
            },
            expected_cas,
        )
        .await
    }

    async fn enqueue(&self, mut repair: RepairRecord) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state
            .fenced_namespaces
            .contains_key(&repair.logical.tenant_id)
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let current_epoch = *state
            .namespace_epochs
            .entry(repair.logical.tenant_id.clone())
            .or_insert(1);
        if repair.kind == RepairKind::DeleteGeneration {
            let targets: Vec<_> = state
                .physical_versions
                .iter()
                .filter(|target| {
                    target.tenant_id == repair.logical.tenant_id
                        && target.backend_id == repair.target_backend_id
                        && target.physical_key == repair.physical_key
                })
                .collect();
            if targets.is_empty() {
                return Ok(());
            }
            if targets
                .iter()
                .any(|target| target.namespace_epoch != current_epoch)
            {
                return Err(ManagedError::Conflict);
            }
        } else if state
            .authorities
            .get(&repair.logical)
            .is_none_or(|authority| {
                authority.generation != repair.generation
                    || authority.cas_version != repair.authority_cas_version
            })
        {
            return Err(ManagedError::Conflict);
        }
        repair.namespace_epoch = current_epoch;
        insert_memory_repair(&mut state, repair);
        Ok(())
    }

    async fn claim_repairs(
        &self,
        owner: &str,
        lease_until_ms: i64,
        limit: u64,
    ) -> Result<Vec<RepairRecord>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let mut state = self.state.lock().await;
        let fenced_namespaces = state.fenced_namespaces.clone();
        let namespace_epochs = state.namespace_epochs.clone();
        let authorities = state.authorities.clone();
        let mut candidates: Vec<_> = state
            .repairs
            .values_mut()
            .filter(|(repair, status)| {
                !fenced_namespaces.contains_key(&repair.logical.tenant_id)
                    && namespace_epochs
                        .get(&repair.logical.tenant_id)
                        .copied()
                        .unwrap_or(1)
                        == repair.namespace_epoch
                    && (status.as_str() == "PENDING"
                        || (status.as_str() == "LEASED"
                            && repair
                                .lease_expires_at_ms
                                .is_some_and(|expiry| expiry <= now)))
                    && repair.not_before_ms <= now
                    && !(repair.kind == RepairKind::DeleteGeneration
                        && authorities.get(&repair.logical).is_some_and(|authority| {
                            repair_target_is_authoritative(authority, repair)
                        }))
            })
            .collect();
        candidates.sort_by_key(|(repair, _)| repair.updated_at_ms);
        let mut claimed = Vec::new();
        for (repair, status) in candidates.into_iter().take(limit as usize) {
            let lease_token = Uuid::now_v7();
            *status = "LEASED".to_string();
            repair.id = lease_token;
            repair.lease_owner = Some(owner.to_string());
            repair.lease_token = Some(lease_token);
            repair.lease_expires_at_ms = Some(lease_until_ms);
            repair.updated_at_ms = now;
            claimed.push(repair.clone());
        }
        Ok(claimed)
    }

    async fn renew_repair(
        &self,
        lease_token: Uuid,
        lease_until_ms: i64,
    ) -> Result<(), ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let mut state = self.state.lock().await;
        let Some((repair, status)) = state
            .repairs
            .values_mut()
            .find(|(repair, _)| repair.lease_token == Some(lease_token))
        else {
            return Err(ManagedError::Conflict);
        };
        if status != "LEASED"
            || repair
                .lease_expires_at_ms
                .is_none_or(|expiry| expiry <= now)
        {
            return Err(ManagedError::Conflict);
        }
        repair.lease_expires_at_ms = Some(lease_until_ms);
        repair.updated_at_ms = now;
        Ok(())
    }

    async fn complete_repair(&self, repair: &RepairRecord) -> Result<bool, ManagedError> {
        let mut state = self.state.lock().await;
        let now = crate::transaction::unix_time_ms();
        if repair.lease_token != Some(repair.id) {
            return Err(ManagedError::Conflict);
        }
        if state
            .namespace_epochs
            .get(&repair.logical.tenant_id)
            .copied()
            .unwrap_or(1)
            != repair.namespace_epoch
        {
            return Err(ManagedError::Conflict);
        }
        {
            let Some((stored, status)) = state.repairs.get_mut(&repair.repair_id) else {
                return Err(ManagedError::Conflict);
            };
            if status != "LEASED"
                || stored.lease_token != Some(repair.id)
                || stored
                    .lease_expires_at_ms
                    .is_none_or(|expiry| expiry <= now)
            {
                return Err(ManagedError::Conflict);
            }
            *status = "DONE".to_string();
            stored.lease_owner = None;
            stored.lease_token = None;
            stored.lease_expires_at_ms = None;
            stored.updated_at_ms = now;
        }
        if repair.kind == RepairKind::DeleteGeneration
            && state.physical_versions.iter().any(|target| {
                target.tenant_id == repair.logical.tenant_id
                    && target.backend_id == repair.target_backend_id
                    && target.physical_key == repair.physical_key
            })
        {
            let (_, status) = state.repairs.get_mut(&repair.repair_id).unwrap();
            *status = "PENDING".to_string();
            return Ok(false);
        }
        let mut updated = false;
        let mut cleanups = Vec::new();
        let mut activate_cleanup = false;
        let cleanup_in_progress = state.repairs.values().any(|(cleanup, status)| {
            cleanup.kind == RepairKind::DeleteGeneration
                && cleanup.logical == repair.logical
                && cleanup.generation == repair.generation
                && cleanup.target_backend_id == repair.target_backend_id
                && status == "LEASED"
        });
        if repair.kind != RepairKind::DeleteGeneration
            && !cleanup_in_progress
            && let Some(authority) = state.authorities.get_mut(&repair.logical)
            && authority.generation == repair.generation
            && authority.cas_version == repair.authority_cas_version
            && !authority.tombstone
        {
            let previous = authority.clone();
            if apply_repair_to_authority(authority, repair)? {
                authority.cas_version = authority.cas_version.saturating_add(1);
                authority.updated_at_ms = crate::transaction::unix_time_ms();
                updated = true;
                if repair.kind == RepairKind::Placement {
                    cleanups = placement_cleanup_repairs(&previous, authority);
                    activate_cleanup = authority.placement_version == repair.placement_version;
                }
            }
        }
        for mut cleanup in cleanups {
            cleanup.namespace_epoch = repair.namespace_epoch;
            cleanup.placement_version = repair.placement_version;
            insert_memory_waiting_placement_cleanup(&mut state, cleanup);
        }
        if activate_cleanup {
            for (cleanup, status) in state.repairs.values_mut() {
                if *status == "WAITING_CUTOVER"
                    && cleanup.logical == repair.logical
                    && cleanup.generation == repair.generation
                    && cleanup.placement_version == repair.placement_version
                {
                    *status = "PENDING".to_string();
                }
            }
        }
        if !updated
            && repair.kind != RepairKind::DeleteGeneration
            && state
                .authorities
                .get(&repair.logical)
                .is_none_or(|authority| !repair_target_is_authoritative(authority, repair))
            && state.physical_versions.iter().any(|target| {
                target.tenant_id == repair.logical.tenant_id
                    && target.backend_id == repair.target_backend_id
                    && target.physical_key == repair.physical_key
            })
        {
            insert_memory_repair(&mut state, stale_repair_cleanup(repair));
        }
        Ok(updated)
    }

    async fn fail_repair(&self, lease_token: Uuid, _error: &str) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        let now = crate::transaction::unix_time_ms();
        let Some((repair, status)) = state
            .repairs
            .values_mut()
            .find(|(repair, _)| repair.lease_token == Some(lease_token))
        else {
            return Err(ManagedError::Conflict);
        };
        if status != "LEASED"
            || repair
                .lease_expires_at_ms
                .is_none_or(|expiry| expiry <= now)
        {
            return Err(ManagedError::Conflict);
        }
        repair.attempts = repair.attempts.saturating_add(1);
        repair.lease_owner = None;
        repair.lease_token = None;
        repair.lease_expires_at_ms = None;
        repair.updated_at_ms = now;
        if repair.attempts >= MAX_REPAIR_ATTEMPTS {
            *status = "DEAD".to_string();
            repair.not_before_ms = 0;
        } else {
            *status = "PENDING".to_string();
            repair.not_before_ms = now.saturating_add(repair_backoff_ms(repair.attempts));
        }
        Ok(())
    }

    async fn repair_state_counts(&self) -> Result<RepairStateCounts, ManagedError> {
        let state = self.state.lock().await;
        let mut counts = RepairStateCounts::default();
        for (_, status) in state.repairs.values() {
            match status.as_str() {
                "LEASED" => counts.leased = counts.leased.saturating_add(1),
                "DEAD" => counts.dead = counts.dead.saturating_add(1),
                _ => counts.pending = counts.pending.saturating_add(1),
            }
        }
        Ok(counts)
    }

    async fn begin_physical_write(
        &self,
        intent: PhysicalWriteIntent,
    ) -> Result<PhysicalWriteLease, ManagedError> {
        validate_physical_intent(&intent)?;
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(&intent.tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let namespace_epoch = *state
            .namespace_epochs
            .entry(intent.tenant_id.clone())
            .or_insert(1);
        let routing_epoch = *state
            .routing_epochs
            .entry(intent.tenant_id.clone())
            .or_insert(1);
        if let Some(parent) = state
            .logical_operations
            .values()
            .find(|operation| operation.intent.primary_child_operation_id == intent.intent_id)
            && (parent.state != ManagedLogicalOperationState::Open
                || parent
                    .intent
                    .publication_recipe
                    .as_ref()
                    .is_none_or(|recipe| {
                        recipe.version != MANAGED_PUBLICATION_RECIPE_VERSION
                            || recipe.placement_version == 0
                            || recipe.primary_backend_id != parent.intent.backend_id
                            || recipe.primary_status != CopyStatus::Ready
                            || (recipe.replica_backend_id.is_none()
                                && recipe.replica_status != CopyStatus::Absent)
                            || (recipe.replica_backend_id.is_some()
                                && recipe.replica_status != CopyStatus::RepairPending)
                    })
                || state
                    .workspace_usage
                    .get(&intent.tenant_id)
                    .is_none_or(|usage| {
                        usage.active_operation_id != Some(parent.intent.operation_id)
                    })
                || parent.intent.logical.tenant_id != intent.tenant_id
                || parent.intent.backend_id != intent.backend_id
                || parent.intent.provider_bucket != intent.provider_bucket
                || parent.intent.physical_key != intent.physical_key
                || !physical_intent_supports_exact_history(&intent)
                || namespace_epoch != parent.intent.fence.namespace_epoch
                || routing_epoch != parent.intent.fence.routing_epoch)
        {
            return Err(ManagedError::Conflict);
        }
        if let Some(existing) = state.physical_write_intents.get(&intent.intent_id) {
            if existing != &intent
                || state.physical_write_epochs.get(&intent.intent_id) != Some(&namespace_epoch)
            {
                return Err(ManagedError::RecoveryBlocked("physical_intent_mismatch"));
            }
            return Ok(PhysicalWriteLease {
                intent_id: intent.intent_id,
                namespace_epoch,
                owner: existing.lease_owner.clone(),
                token: state
                    .physical_write_tokens
                    .get(&intent.intent_id)
                    .copied()
                    .ok_or(ManagedError::Conflict)?,
            });
        }
        let intent_id = intent.intent_id;
        let owner = intent.lease_owner.clone();
        let token = Uuid::now_v7();
        state.physical_write_intents.insert(intent_id, intent);
        state.physical_write_leases.insert(
            intent_id,
            crate::transaction::unix_time_ms().saturating_add(PHYSICAL_WRITE_LEASE_MS),
        );
        state.physical_write_tokens.insert(intent_id, token);
        state
            .physical_write_epochs
            .insert(intent_id, namespace_epoch);
        Ok(PhysicalWriteLease {
            intent_id,
            namespace_epoch,
            owner,
            token,
        })
    }

    async fn pending_physical_write_intents(
        &self,
        limit: u64,
    ) -> Result<Vec<DurablePhysicalWriteIntent>, ManagedError> {
        let state = self.state.lock().await;
        Ok(state
            .physical_write_intents
            .values()
            .filter(|intent| {
                !state.logical_operations.values().any(|operation| {
                    !operation.state.terminal()
                        && operation.intent.primary_child_operation_id == intent.intent_id
                })
            })
            .take(limit as usize)
            .map(|intent| DurablePhysicalWriteIntent {
                intent: intent.clone(),
                namespace_epoch: state
                    .physical_write_epochs
                    .get(&intent.intent_id)
                    .copied()
                    .unwrap_or(1),
                blocked_reason: state.blocked_write_intents.get(&intent.intent_id).cloned(),
                lease_expires_at_ms: state
                    .physical_write_leases
                    .get(&intent.intent_id)
                    .copied()
                    .unwrap_or(0),
                lease: PhysicalWriteLease {
                    intent_id: intent.intent_id,
                    namespace_epoch: state
                        .physical_write_epochs
                        .get(&intent.intent_id)
                        .copied()
                        .unwrap_or(1),
                    owner: intent.lease_owner.clone(),
                    token: state
                        .physical_write_tokens
                        .get(&intent.intent_id)
                        .copied()
                        .unwrap_or(Uuid::nil()),
                },
            })
            .collect())
    }

    async fn physical_write_intent(
        &self,
        intent_id: Uuid,
    ) -> Result<Option<DurablePhysicalWriteIntent>, ManagedError> {
        let state = self.state.lock().await;
        Ok(state.physical_write_intents.get(&intent_id).map(|intent| {
            let namespace_epoch = state
                .physical_write_epochs
                .get(&intent_id)
                .copied()
                .unwrap_or(1);
            DurablePhysicalWriteIntent {
                intent: intent.clone(),
                namespace_epoch,
                blocked_reason: state.blocked_write_intents.get(&intent_id).cloned(),
                lease_expires_at_ms: state
                    .physical_write_leases
                    .get(&intent_id)
                    .copied()
                    .unwrap_or(0),
                lease: PhysicalWriteLease {
                    intent_id,
                    namespace_epoch,
                    owner: intent.lease_owner.clone(),
                    token: state
                        .physical_write_tokens
                        .get(&intent_id)
                        .copied()
                        .unwrap_or(Uuid::nil()),
                },
            }
        }))
    }

    async fn renew_physical_write_intent(
        &self,
        lease: &PhysicalWriteLease,
        lease_expires_at_ms: i64,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state
            .physical_write_intents
            .get(&lease.intent_id)
            .is_none_or(|intent| intent.lease_owner != lease.owner)
            || state.physical_write_tokens.get(&lease.intent_id) != Some(&lease.token)
            || state.physical_write_epochs.get(&lease.intent_id) != Some(&lease.namespace_epoch)
            || state
                .physical_write_leases
                .get(&lease.intent_id)
                .is_none_or(|expires| *expires <= crate::transaction::unix_time_ms())
        {
            return Err(ManagedError::Conflict);
        }
        state
            .physical_write_leases
            .insert(lease.intent_id, lease_expires_at_ms);
        Ok(())
    }

    async fn claim_expired_physical_write_intent(
        &self,
        intent_id: Uuid,
        owner: &str,
        lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        let mut state = self.state.lock().await;
        if state.logical_operations.values().any(|operation| {
            !operation.state.terminal() && operation.intent.primary_child_operation_id == intent_id
        }) {
            return Ok(None);
        }
        if state
            .physical_write_leases
            .get(&intent_id)
            .is_none_or(|expires| *expires > crate::transaction::unix_time_ms())
        {
            return Ok(None);
        }
        let token = Uuid::now_v7();
        let namespace_epoch = state
            .physical_write_epochs
            .get(&intent_id)
            .copied()
            .ok_or(ManagedError::Conflict)?;
        let intent = state
            .physical_write_intents
            .get_mut(&intent_id)
            .ok_or(ManagedError::Conflict)?;
        intent.lease_owner = owner.to_string();
        state.physical_write_tokens.insert(intent_id, token);
        state
            .physical_write_leases
            .insert(intent_id, lease_expires_at_ms);
        Ok(Some(PhysicalWriteLease {
            intent_id,
            namespace_epoch,
            owner: owner.to_string(),
            token,
        }))
    }

    async fn claim_logical_physical_write_intent(
        &self,
        claim: &ManagedRecoveryClaim,
        lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        if lease_expires_at_ms <= now {
            return Err(ManagedError::Conflict);
        }
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get(&claim.operation.intent.operation_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        validate_recovery_authority(&operation, Some(claim), now)?;
        let intent_id = operation.intent.primary_child_operation_id;
        if state
            .physical_write_leases
            .get(&intent_id)
            .is_none_or(|expires| *expires > now)
        {
            return Ok(None);
        }
        let intent = state
            .physical_write_intents
            .get_mut(&intent_id)
            .ok_or(ManagedError::Conflict)?;
        intent.lease_owner = claim.owner.clone();
        let token = Uuid::now_v7();
        state.physical_write_tokens.insert(intent_id, token);
        state
            .physical_write_leases
            .insert(intent_id, lease_expires_at_ms);
        Ok(Some(PhysicalWriteLease {
            intent_id,
            namespace_epoch: operation.intent.fence.namespace_epoch,
            owner: claim.owner.clone(),
            token,
        }))
    }

    async fn commit_physical_write(
        &self,
        lease: &PhysicalWriteLease,
        superseded_version_ids: &[String],
        version_id: Option<&str>,
    ) -> Result<(), ManagedError> {
        if superseded_version_ids.iter().any(String::is_empty)
            || version_id.is_some_and(str::is_empty)
        {
            return Err(ManagedError::Conflict);
        }
        let mut state = self.state.lock().await;
        if state.logical_operations.values().any(|operation| {
            !operation.state.terminal()
                && operation.intent.primary_child_operation_id == lease.intent_id
        }) {
            return Err(ManagedError::Conflict);
        }
        if state
            .physical_write_intents
            .get(&lease.intent_id)
            .is_none_or(|intent| intent.lease_owner != lease.owner)
            || state.physical_write_tokens.get(&lease.intent_id) != Some(&lease.token)
            || state.physical_write_epochs.get(&lease.intent_id) != Some(&lease.namespace_epoch)
            || state
                .physical_write_leases
                .get(&lease.intent_id)
                .is_none_or(|expires| *expires <= crate::transaction::unix_time_ms())
        {
            return Err(ManagedError::Conflict);
        }
        let intent = state
            .physical_write_intents
            .remove(&lease.intent_id)
            .unwrap();
        state.blocked_write_intents.remove(&lease.intent_id);
        state.physical_write_leases.remove(&lease.intent_id);
        state.physical_write_tokens.remove(&lease.intent_id);
        state.physical_write_epochs.remove(&lease.intent_id);
        for version_id in superseded_version_ids
            .iter()
            .map(|value| Some(value.clone()))
            .chain(std::iter::once(version_id.map(ToOwned::to_owned)))
        {
            let target = PhysicalVersionTarget {
                tenant_id: intent.tenant_id.clone(),
                namespace_epoch: lease.namespace_epoch,
                backend_id: intent.backend_id.clone(),
                storage_identity: intent.storage_identity.clone(),
                credential_epoch: intent.credential_epoch,
                provider_bucket: intent.provider_bucket.clone(),
                physical_key: intent.physical_key.clone(),
                version_id,
                versioning_mode: intent.versioning_mode,
                versioning_capability: intent.versioning_capability,
                write_operation_id: lease.intent_id,
            };
            let duplicate = state.physical_versions.iter().any(|existing| {
                existing.tenant_id == target.tenant_id
                    && existing.backend_id == target.backend_id
                    && existing.provider_bucket == target.provider_bucket
                    && existing.physical_key == target.physical_key
                    && existing.version_id == target.version_id
            });
            if !duplicate {
                state.physical_versions.push(target);
            }
        }
        Ok(())
    }

    async fn abort_physical_write(&self, lease: &PhysicalWriteLease) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state.logical_operations.values().any(|operation| {
            !operation.state.terminal()
                && operation.intent.primary_child_operation_id == lease.intent_id
        }) {
            return Err(ManagedError::Conflict);
        }
        if state.physical_write_tokens.get(&lease.intent_id) != Some(&lease.token)
            || state.physical_write_epochs.get(&lease.intent_id) != Some(&lease.namespace_epoch)
            || state
                .physical_write_leases
                .get(&lease.intent_id)
                .is_none_or(|expires| *expires <= crate::transaction::unix_time_ms())
        {
            return Err(ManagedError::Conflict);
        }
        state.physical_write_intents.remove(&lease.intent_id);
        state.blocked_write_intents.remove(&lease.intent_id);
        state.physical_write_leases.remove(&lease.intent_id);
        state.physical_write_tokens.remove(&lease.intent_id);
        state.physical_write_epochs.remove(&lease.intent_id);
        Ok(())
    }

    async fn block_physical_write(
        &self,
        lease: &PhysicalWriteLease,
        reason: &str,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state.physical_write_tokens.get(&lease.intent_id) != Some(&lease.token)
            || state.physical_write_epochs.get(&lease.intent_id) != Some(&lease.namespace_epoch)
            || state
                .physical_write_leases
                .get(&lease.intent_id)
                .is_none_or(|expires| *expires <= crate::transaction::unix_time_ms())
        {
            return Err(ManagedError::Conflict);
        }
        state
            .blocked_write_intents
            .insert(lease.intent_id, reason.to_string());
        Ok(())
    }

    async fn physical_versions(
        &self,
        tenant_id: &str,
        backend_id: &str,
        provider_bucket: &str,
        physical_key: &str,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        Ok(self
            .state
            .lock()
            .await
            .physical_versions
            .iter()
            .filter(|target| {
                target.tenant_id == tenant_id
                    && target.backend_id == backend_id
                    && target.provider_bucket == provider_bucket
                    && target.physical_key == physical_key
            })
            .cloned()
            .collect())
    }

    async fn forget_physical_version(
        &self,
        target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        let previous_len = state.physical_versions.len();
        state
            .physical_versions
            .retain(|candidate| candidate != target);
        if state.physical_versions.len() == previous_len
            || state
                .physical_versions
                .iter()
                .any(|candidate| candidate.write_operation_id == target.write_operation_id)
        {
            return Ok(());
        }
        let operation_id = state
            .logical_operations
            .iter()
            .find_map(|(operation_id, operation)| {
                (operation.intent.primary_child_operation_id == target.write_operation_id)
                    .then_some(*operation_id)
            });
        if let Some(operation_id) = operation_id {
            let operation = state.logical_operations.get(&operation_id).unwrap();
            let tenant_id = operation.intent.logical.tenant_id.clone();
            let committed = operation.committed_physical_bytes;
            let released = committed
                .checked_sub(operation.released_physical_bytes)
                .ok_or_else(|| {
                    ManagedError::Corrupt(
                        "managed operation released bytes exceed committed bytes".to_string(),
                    )
                })?;
            if released > 0 {
                let usage = Self::workspace_usage(&mut state, &tenant_id);
                usage.physical_allocated_bytes = usage
                    .physical_allocated_bytes
                    .checked_sub(released)
                    .ok_or_else(|| {
                        ManagedError::Corrupt(
                            "managed physical usage is below the child allocation".to_string(),
                        )
                    })?;
                let now = crate::transaction::unix_time_ms();
                usage.version = usage.version.saturating_add(1);
                usage.updated_at_ms = now;
                let operation = state.logical_operations.get_mut(&operation_id).unwrap();
                operation.released_physical_bytes = committed;
                operation.updated_at_ms = now;
            }
        }
        Ok(())
    }

    async fn purge_namespace(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        let mut state = self.state.lock().await;
        if let Some(purge) = state.purges.get(&request.operation_id) {
            if purge.tenant_id != request.tenant_id {
                return Ok(NamespacePurgeStatus::Blocked {
                    reason: "purge operation belongs to another namespace".to_string(),
                });
            }
            return Ok(Self::finish_purge(&mut state, request.operation_id));
        }
        if state.fenced_namespaces.contains_key(&request.tenant_id) {
            return Ok(NamespacePurgeStatus::Blocked {
                reason: "another managed namespace purge is already running".to_string(),
            });
        }
        for authority in state
            .authorities
            .values()
            .filter(|authority| authority.logical.tenant_id == request.tenant_id)
            .filter(|authority| !authority.tombstone)
        {
            let physical_key = generation_physical_key(&authority.logical, authority.generation);
            let required_backends = std::iter::once(authority.primary_backend_id.as_str()).chain(
                authority
                    .replica_backend_id
                    .as_deref()
                    .filter(|_| authority.replica_status == CopyStatus::Ready),
            );
            for backend_id in required_backends {
                if !state.physical_versions.iter().any(|target| {
                    target.tenant_id == request.tenant_id
                        && target.backend_id == backend_id
                        && target.physical_key == physical_key
                }) {
                    return Ok(NamespacePurgeStatus::Blocked {
                        reason: format!(
                            "managed authority references unledgered physical versions on backend {backend_id}"
                        ),
                    });
                }
            }
        }
        state
            .fenced_namespaces
            .insert(request.tenant_id.clone(), request.operation_id);
        state.purges.insert(
            request.operation_id,
            MemoryPurge {
                tenant_id: request.tenant_id.clone(),
                status: NamespacePurgeStatus::Running,
                deleted_versions: 0,
            },
        );
        Ok(Self::finish_purge(&mut state, request.operation_id))
    }

    async fn namespace_purge_status(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        let mut state = self.state.lock().await;
        Ok(Self::finish_purge(&mut state, request.operation_id))
    }

    async fn purge_targets(
        &self,
        request: &NamespacePurgeRequest,
        limit: u64,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        let state = self.state.lock().await;
        if state
            .purges
            .get(&request.operation_id)
            .is_none_or(|purge| purge.tenant_id != request.tenant_id)
        {
            return Err(ManagedError::Conflict);
        }
        Ok(state
            .physical_versions
            .iter()
            .filter(|target| target.tenant_id == request.tenant_id)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn mark_purge_target_deleted(
        &self,
        request: &NamespacePurgeRequest,
        target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        let before = state.physical_versions.len();
        state
            .physical_versions
            .retain(|candidate| candidate != target);
        if state.physical_versions.len() != before
            && let Some(purge) = state.purges.get_mut(&request.operation_id)
        {
            purge.deleted_versions = purge.deleted_versions.saturating_add(1);
            purge.status = NamespacePurgeStatus::Running;
        }
        Ok(())
    }

    async fn mark_purge_target_blocked(
        &self,
        request: &NamespacePurgeRequest,
        _target: &PhysicalVersionTarget,
        reason: &str,
    ) -> Result<(), ManagedError> {
        if let Some(purge) = self
            .state
            .lock()
            .await
            .purges
            .get_mut(&request.operation_id)
        {
            purge.status = NamespacePurgeStatus::Blocked {
                reason: reason.to_string(),
            };
        }
        Ok(())
    }
}
