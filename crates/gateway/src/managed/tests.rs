use super::memory::insert_memory_repair;
use super::*;

fn authority(logical: LogicalObjectKey, generation: Uuid) -> ObjectAuthority {
    ObjectAuthority {
        logical,
        generation,
        digest: "abc".to_string(),
        size: 3,
        metadata: BTreeMap::new(),
        placement_version: 1,
        primary_backend_id: "a".to_string(),
        primary_version_id: None,
        replica_backend_id: Some("b".to_string()),
        primary_status: CopyStatus::Ready,
        replica_status: CopyStatus::RepairPending,
        tombstone: false,
        cas_version: 0,
        created_at_ms: 0,
        updated_at_ms: 0,
    }
}

fn logical_intent(
    tenant_id: &str,
    key: &str,
    kind: ManagedMutationKind,
    fence: ManagedRouteFence,
) -> ManagedLogicalOperationIntent {
    let logical = LogicalObjectKey::new(tenant_id, "bucket", key);
    let generation = Uuid::now_v7();
    ManagedLogicalOperationIntent {
        operation_id: Uuid::now_v7(),
        receipt_id: Uuid::now_v7(),
        logical: logical.clone(),
        kind,
        generation,
        fence,
        expected_authority_cas: None,
        prior_logical_size: 0,
        primary_child_operation_id: Uuid::now_v7(),
        backend_id: "a".to_string(),
        provider_bucket: "provider-bucket".to_string(),
        physical_key: generation_physical_key(&logical, generation),
        occurred_at_ms: crate::transaction::unix_time_ms(),
        rate_version: 1,
        route: match kind {
            ManagedMutationKind::Put => UsageRoute::PutObject,
            ManagedMutationKind::Delete => UsageRoute::DeleteObject,
        },
        request_kind: RequestKind::Write,
        max_processed_bytes: 64,
        publication_recipe: (kind == ManagedMutationKind::Put).then(|| ManagedPublicationRecipe {
            version: MANAGED_PUBLICATION_RECIPE_VERSION,
            placement_version: 1,
            primary_backend_id: "a".to_string(),
            replica_backend_id: None,
            metadata: BTreeMap::new(),
            primary_status: CopyStatus::Ready,
            replica_status: CopyStatus::Absent,
        }),
    }
}

fn child_intent(intent: &ManagedLogicalOperationIntent) -> PhysicalWriteIntent {
    PhysicalWriteIntent {
        intent_id: intent.primary_child_operation_id,
        tenant_id: intent.logical.tenant_id.clone(),
        backend_id: intent.backend_id.clone(),
        storage_identity: test_storage_identity(),
        credential_epoch: 1,
        provider_bucket: intent.provider_bucket.clone(),
        physical_key: intent.physical_key.clone(),
        versioning_mode: BackendVersioningMode::Enabled,
        versioning_capability: BackendVersioningCapability::Required,
        lease_owner: "writer".to_string(),
    }
}

fn test_storage_identity() -> ProviderStorageIdentity {
    ProviderStorageIdentity {
        provider_kind: "test".to_string(),
        provider_instance_id: "provider-instance".to_string(),
        provider_account_id: "provider-account".to_string(),
        canonical_endpoint: "https://provider.example/".to_string(),
        region: "test-region-1".to_string(),
    }
}

async fn record_put_evidence(
    repository: &InMemoryManagedRepository,
    intent: &ManagedLogicalOperationIntent,
    output_size: u64,
) {
    repository
        .record_logical_usage(
            intent.operation_id,
            ManagedUsageEvidence {
                expected_output_digest: Some("output-digest".to_string()),
                expected_output_size: output_size,
                source_bytes: output_size,
                processed_bytes: output_size,
                payload: serde_json::json!({"source": "repository-test"}),
            },
        )
        .await
        .unwrap();
    repository
        .transition_logical_operation(
            intent.operation_id,
            ManagedLogicalOperationState::Open,
            ManagedLogicalOperationState::Completing,
            None,
        )
        .await
        .unwrap();
}

#[test]
fn logical_transition_matrix_rejects_all_unlisted_and_terminal_edges() {
    use ManagedLogicalOperationState as State;

    let states = [
        State::Intent,
        State::Open,
        State::Completing,
        State::CommitUnknown,
        State::Committed,
        State::ProvenAborted,
    ];
    for from in states {
        for to in states {
            let expected = matches!(
                (from, to),
                (State::Open, State::Completing)
                    | (State::Open, State::CommitUnknown)
                    | (State::Completing, State::CommitUnknown)
                    | (State::CommitUnknown, State::Completing)
            );
            assert_eq!(
                valid_logical_transition(from, to),
                expected,
                "{from:?} -> {to:?}"
            );
        }
    }
}

#[tokio::test]
async fn logical_put_requires_reservation_and_releases_after_final_exact_version() {
    let repository = InMemoryManagedRepository::new();
    let intent = logical_intent(
        "tenant-logical-put",
        "key",
        ManagedMutationKind::Put,
        repository.route_fence("tenant-logical-put").await.unwrap(),
    );
    repository
        .insert_logical_operation(intent.clone())
        .await
        .unwrap();
    assert!(matches!(
        repository.begin_physical_write(child_intent(&intent)).await,
        Err(ManagedError::Conflict)
    ));

    let reserved = repository
        .reserve_logical_operation(intent.operation_id, 6)
        .await
        .unwrap();
    assert_eq!(reserved.reserved_bytes, 6);
    assert_eq!(reserved.active_operation_id, Some(intent.operation_id));
    let lease = repository
        .begin_physical_write(child_intent(&intent))
        .await
        .unwrap();
    record_put_evidence(&repository, &intent, 3).await;

    assert!(matches!(
        repository
            .finalize_logical_put(
                intent.operation_id,
                &lease,
                ExactPhysicalCommit {
                    selected_version_id: Some("final-version".to_string()),
                    superseded_version_ids: vec!["retry-version".to_string()],
                    version_history_complete: false,
                },
                None,
            )
            .await,
        Err(ManagedError::RecoveryBlocked(_))
    ));
    let committed = repository
        .finalize_logical_put(
            intent.operation_id,
            &lease,
            ExactPhysicalCommit {
                selected_version_id: Some("final-version".to_string()),
                superseded_version_ids: vec!["retry-version".to_string()],
                version_history_complete: true,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        committed.operation.state,
        ManagedLogicalOperationState::Committed
    );
    assert_eq!(committed.operation.intent.receipt_id, intent.receipt_id);
    assert_eq!(committed.operation.intent.rate_version, intent.rate_version);
    assert_eq!(committed.usage.visible_logical_bytes, 3);
    assert_eq!(committed.usage.physical_allocated_bytes, 6);
    assert_eq!(committed.usage.reserved_bytes, 0);
    assert_eq!(committed.usage.active_operation_id, None);
    repository
        .finalize_logical_put(
            intent.operation_id,
            &lease,
            ExactPhysicalCommit {
                selected_version_id: Some("final-version".to_string()),
                superseded_version_ids: vec!["retry-version".to_string()],
                version_history_complete: true,
            },
            None,
        )
        .await
        .unwrap();

    let versions = repository
        .physical_versions(
            &intent.logical.tenant_id,
            &intent.backend_id,
            &intent.provider_bucket,
            &intent.physical_key,
        )
        .await
        .unwrap();
    assert_eq!(versions.len(), 2);
    repository
        .forget_physical_version(&versions[0])
        .await
        .unwrap();
    assert_eq!(
        repository
            .workspace_usage(&intent.logical.tenant_id)
            .await
            .unwrap()
            .unwrap()
            .physical_allocated_bytes,
        6
    );
    repository
        .forget_physical_version(&versions[1])
        .await
        .unwrap();
    let usage = repository
        .workspace_usage(&intent.logical.tenant_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(usage.physical_allocated_bytes, 0);
    assert_eq!(
        repository
            .logical_operation(intent.operation_id)
            .await
            .unwrap()
            .unwrap()
            .released_physical_bytes,
        6
    );
}

#[tokio::test]
async fn workspace_quota_serializes_mutations_and_proven_abort_releases_reservation() {
    let repository = InMemoryManagedRepository::new();
    let tenant = "tenant-quota";
    let fence = repository.route_fence(tenant).await.unwrap();
    let first = logical_intent(tenant, "first", ManagedMutationKind::Put, fence);
    let second = logical_intent(tenant, "second", ManagedMutationKind::Put, fence);
    repository
        .insert_logical_operation(first.clone())
        .await
        .unwrap();
    repository
        .insert_logical_operation(second.clone())
        .await
        .unwrap();
    repository
        .reserve_logical_operation(first.operation_id, 64)
        .await
        .unwrap();
    assert!(matches!(
        repository
            .reserve_logical_operation(second.operation_id, 1)
            .await,
        Err(ManagedError::MutationInProgress)
    ));
    repository
        .prove_logical_abort(first.operation_id, "provider_not_called", None)
        .await
        .unwrap();
    let usage = repository.workspace_usage(tenant).await.unwrap().unwrap();
    assert_eq!(usage.reserved_bytes, 0);
    assert_eq!(usage.active_operation_id, None);
    assert!(matches!(
        repository
            .reserve_logical_operation(
                second.operation_id,
                MANAGED_VISIBLE_LIMIT_BYTES + MANAGED_REPLACEMENT_HEADROOM_BYTES + 1,
            )
            .await,
        Err(ManagedError::QuotaExceeded)
    ));
}

#[tokio::test]
async fn zero_byte_put_uses_active_operation_state_and_ledgers_one_version() {
    let repository = InMemoryManagedRepository::new();
    let tenant = "tenant-zero-byte";
    let intent = logical_intent(
        tenant,
        "empty",
        ManagedMutationKind::Put,
        repository.route_fence(tenant).await.unwrap(),
    );
    repository
        .insert_logical_operation(intent.clone())
        .await
        .unwrap();
    let usage = repository
        .reserve_logical_operation(intent.operation_id, 0)
        .await
        .unwrap();
    assert_eq!(usage.active_operation_id, Some(intent.operation_id));
    let lease = repository
        .begin_physical_write(child_intent(&intent))
        .await
        .unwrap();
    record_put_evidence(&repository, &intent, 0).await;
    let committed = repository
        .finalize_logical_put(
            intent.operation_id,
            &lease,
            ExactPhysicalCommit {
                selected_version_id: Some("empty-version".to_string()),
                superseded_version_ids: Vec::new(),
                version_history_complete: true,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(committed.usage.visible_logical_bytes, 0);
    assert_eq!(committed.usage.physical_allocated_bytes, 0);
    assert_eq!(
        repository
            .physical_versions(
                tenant,
                &intent.backend_id,
                &intent.provider_bucket,
                &intent.physical_key,
            )
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn logical_child_is_hidden_from_standalone_reconciliation_but_exactly_addressable() {
    let repository = InMemoryManagedRepository::new();
    let tenant = "tenant-child-selection";
    let intent = logical_intent(
        tenant,
        "key",
        ManagedMutationKind::Put,
        repository.route_fence(tenant).await.unwrap(),
    );
    repository
        .admit_logical_operation(intent.clone(), 3)
        .await
        .unwrap();
    let lease = repository
        .begin_physical_write(child_intent(&intent))
        .await
        .unwrap();
    assert!(
        repository
            .pending_physical_write_intents(10)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        repository
            .physical_write_intent(intent.primary_child_operation_id)
            .await
            .unwrap()
            .unwrap()
            .lease,
        lease
    );
    assert!(matches!(
        repository
            .commit_physical_write(&lease, &[], Some("forbidden"))
            .await,
        Err(ManagedError::Conflict)
    ));
}

#[tokio::test]
async fn recovery_claim_fences_request_and_competing_recovery_then_finalizes_exactly_once() {
    let repository = InMemoryManagedRepository::new();
    let tenant = "tenant-recovery-race";
    let mut intent = logical_intent(
        tenant,
        "key",
        ManagedMutationKind::Put,
        repository.route_fence(tenant).await.unwrap(),
    );
    intent
        .publication_recipe
        .as_mut()
        .unwrap()
        .placement_version = 9;
    repository
        .admit_logical_operation(intent.clone(), 6)
        .await
        .unwrap();
    let request_lease = repository
        .begin_physical_write(child_intent(&intent))
        .await
        .unwrap();
    record_put_evidence(&repository, &intent, 3).await;
    {
        let mut state = repository.state.lock().await;
        state
            .logical_operations
            .get_mut(&intent.operation_id)
            .unwrap()
            .updated_at_ms = 0;
        state
            .physical_write_leases
            .insert(request_lease.intent_id, 0);
    }
    let expiry = crate::transaction::unix_time_ms() + 60_000;
    let mut first = repository
        .claim_stale_logical_operations("recovery-a", 1, expiry, 10)
        .await
        .unwrap();
    assert_eq!(first.len(), 1);
    assert!(
        repository
            .claim_stale_logical_operations("recovery-b", 1, expiry, 10)
            .await
            .unwrap()
            .is_empty()
    );
    let initial_claim = first.pop().unwrap();
    repository
        .mark_logical_recovery_blocked(&initial_claim, "temporarily_unprovable")
        .await
        .unwrap();
    {
        repository
            .state
            .lock()
            .await
            .logical_operations
            .get_mut(&intent.operation_id)
            .unwrap()
            .updated_at_ms = 0;
    }
    let claim = repository
        .claim_stale_logical_operations("recovery-c", 1, expiry, 10)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        claim.operation.state,
        ManagedLogicalOperationState::RecoveryBlocked
    );
    assert!(matches!(
        repository
            .finalize_logical_put(
                intent.operation_id,
                &request_lease,
                ExactPhysicalCommit {
                    selected_version_id: Some("version-2".to_string()),
                    superseded_version_ids: vec!["version-1".to_string()],
                    version_history_complete: true,
                },
                None,
            )
            .await,
        Err(ManagedError::Conflict)
    ));
    let recovery_lease = repository
        .claim_logical_physical_write_intent(&claim, expiry)
        .await
        .unwrap()
        .unwrap();
    let result = ExactPhysicalCommit {
        selected_version_id: Some("version-2".to_string()),
        superseded_version_ids: vec!["version-1".to_string()],
        version_history_complete: true,
    };
    let committed = repository
        .finalize_logical_put(
            intent.operation_id,
            &recovery_lease,
            result.clone(),
            Some(&claim),
        )
        .await
        .unwrap();
    assert_eq!(committed.authority.placement_version, 9);
    assert_eq!(committed.operation.committed_physical_bytes, 6);
    assert_eq!(committed.usage.reserved_bytes, 0);
    assert_eq!(committed.usage.active_operation_id, None);
    repository
        .finalize_logical_put(intent.operation_id, &recovery_lease, result, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn exact_version_mismatch_rolls_back_in_memory_finalization() {
    let repository = InMemoryManagedRepository::new();
    let tenant = "tenant-exact-mismatch";
    let intent = logical_intent(
        tenant,
        "key",
        ManagedMutationKind::Put,
        repository.route_fence(tenant).await.unwrap(),
    );
    repository
        .admit_logical_operation(intent.clone(), 6)
        .await
        .unwrap();
    let lease = repository
        .begin_physical_write(child_intent(&intent))
        .await
        .unwrap();
    record_put_evidence(&repository, &intent, 3).await;
    let mismatched = ExactPhysicalCommit {
        selected_version_id: Some("same".to_string()),
        superseded_version_ids: vec!["same".to_string()],
        version_history_complete: true,
    };
    assert!(matches!(
        repository
            .finalize_logical_put(intent.operation_id, &lease, mismatched, None)
            .await,
        Err(ManagedError::RecoveryBlocked(_))
    ));
    assert!(repository.get(&intent.logical).await.unwrap().is_none());
    assert!(
        repository
            .physical_versions(
                tenant,
                &intent.backend_id,
                &intent.provider_bucket,
                &intent.physical_key,
            )
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repository
            .physical_write_intent(intent.primary_child_operation_id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn routing_epoch_fences_stale_intents_and_reserved_children() {
    let repository = InMemoryManagedRepository::new();
    let tenant = "tenant-routing-fence";
    let stale_fence = repository.route_fence(tenant).await.unwrap();
    let current_fence = repository
        .advance_routing_epoch(tenant, stale_fence.routing_epoch)
        .await
        .unwrap();
    let stale = logical_intent(tenant, "stale", ManagedMutationKind::Put, stale_fence);
    assert!(matches!(
        repository.insert_logical_operation(stale).await,
        Err(ManagedError::Conflict)
    ));

    let current = logical_intent(tenant, "current", ManagedMutationKind::Put, current_fence);
    repository
        .insert_logical_operation(current.clone())
        .await
        .unwrap();
    repository
        .reserve_logical_operation(current.operation_id, 3)
        .await
        .unwrap();
    repository
        .advance_routing_epoch(tenant, current_fence.routing_epoch)
        .await
        .unwrap();
    assert!(matches!(
        repository
            .begin_physical_write(child_intent(&current))
            .await,
        Err(ManagedError::Conflict)
    ));
    repository
        .prove_logical_abort(current.operation_id, "routing_changed", None)
        .await
        .unwrap();
}

#[tokio::test]
async fn logical_child_abort_is_atomic_and_releases_the_workspace_slot() {
    let repository = InMemoryManagedRepository::new();
    let tenant = "tenant-physical-abort";
    let intent = logical_intent(
        tenant,
        "key",
        ManagedMutationKind::Put,
        repository.route_fence(tenant).await.unwrap(),
    );
    repository
        .insert_logical_operation(intent.clone())
        .await
        .unwrap();
    repository
        .reserve_logical_operation(intent.operation_id, 6)
        .await
        .unwrap();
    let lease = repository
        .begin_physical_write(child_intent(&intent))
        .await
        .unwrap();
    assert!(matches!(
        repository.abort_physical_write(&lease).await,
        Err(ManagedError::Conflict)
    ));
    let aborted = repository
        .abort_logical_put(
            intent.operation_id,
            Some(&lease),
            LogicalAbortProof::ChildProvenAborted,
            "child_proven_aborted",
            None,
        )
        .await
        .unwrap();
    assert_eq!(aborted.state, ManagedLogicalOperationState::ProvenAborted);
    assert_eq!(aborted.settlement_state, ManagedSettlementState::Released);
    let usage = repository.workspace_usage(tenant).await.unwrap().unwrap();
    assert_eq!(usage.reserved_bytes, 0);
    assert_eq!(usage.active_operation_id, None);
    assert!(
        repository
            .physical_write_intent(intent.primary_child_operation_id)
            .await
            .unwrap()
            .is_none()
    );
    let next = logical_intent(
        tenant,
        "next",
        ManagedMutationKind::Put,
        repository.route_fence(tenant).await.unwrap(),
    );
    repository.admit_logical_operation(next, 1).await.unwrap();
}

#[tokio::test]
async fn atomic_logical_delete_commits_exact_cleanup_and_is_idempotent() {
    let repository = InMemoryManagedRepository::new();
    let tenant = "tenant-logical-delete";
    let fence = repository.route_fence(tenant).await.unwrap();
    let mut put = logical_intent(tenant, "key", ManagedMutationKind::Put, fence);
    let recipe = put.publication_recipe.as_mut().unwrap();
    recipe.replica_backend_id = Some("b".to_string());
    recipe.replica_status = CopyStatus::RepairPending;
    repository
        .insert_logical_operation(put.clone())
        .await
        .unwrap();
    repository
        .reserve_logical_operation(put.operation_id, 3)
        .await
        .unwrap();
    let lease = repository
        .begin_physical_write(child_intent(&put))
        .await
        .unwrap();
    record_put_evidence(&repository, &put, 3).await;
    let put_commit = repository
        .finalize_logical_put(
            put.operation_id,
            &lease,
            ExactPhysicalCommit {
                selected_version_id: Some("put-version".to_string()),
                superseded_version_ids: Vec::new(),
                version_history_complete: true,
            },
            None,
        )
        .await
        .unwrap();
    let replica_lease = repository
        .begin_physical_write(PhysicalWriteIntent {
            intent_id: Uuid::now_v7(),
            tenant_id: tenant.to_string(),
            backend_id: "b".to_string(),
            storage_identity: test_storage_identity(),
            credential_epoch: 1,
            provider_bucket: put.provider_bucket.clone(),
            physical_key: put.physical_key.clone(),
            versioning_mode: BackendVersioningMode::Enabled,
            versioning_capability: BackendVersioningCapability::Required,
            lease_owner: "replica-writer".to_string(),
        })
        .await
        .unwrap();
    let existing_replica_lease = repository
        .begin_physical_write(PhysicalWriteIntent {
            intent_id: Uuid::now_v7(),
            tenant_id: tenant.to_string(),
            backend_id: "b".to_string(),
            storage_identity: test_storage_identity(),
            credential_epoch: 1,
            provider_bucket: put.provider_bucket.clone(),
            physical_key: put.physical_key.clone(),
            versioning_mode: BackendVersioningMode::Enabled,
            versioning_capability: BackendVersioningCapability::Required,
            lease_owner: "existing-replica-writer".to_string(),
        })
        .await
        .unwrap();
    repository
        .commit_physical_write(
            &existing_replica_lease,
            &[],
            Some("existing-replica-version"),
        )
        .await
        .unwrap();
    repository
        .enqueue(RepairRecord::placement(
            &put_commit.authority,
            Some("a".to_string()),
            "c".to_string(),
            RepairTargetRole::Primary,
            &Placement {
                version: 2,
                primary_backend_id: "c".to_string(),
                replica_backend_id: Some("b".to_string()),
            },
        ))
        .await
        .unwrap();
    let placement_lease = repository
        .begin_physical_write(PhysicalWriteIntent {
            intent_id: Uuid::now_v7(),
            tenant_id: tenant.to_string(),
            backend_id: "c".to_string(),
            storage_identity: test_storage_identity(),
            credential_epoch: 1,
            provider_bucket: put.provider_bucket.clone(),
            physical_key: put.physical_key.clone(),
            versioning_mode: BackendVersioningMode::Enabled,
            versioning_capability: BackendVersioningCapability::Required,
            lease_owner: "placement-writer".to_string(),
        })
        .await
        .unwrap();
    let stale_repairs = repository
        .claim_repairs("replica", i64::MAX, 10)
        .await
        .unwrap();
    let stale_replica = stale_repairs
        .iter()
        .find(|repair| repair.kind == RepairKind::Replica)
        .unwrap();
    let stale_placement = stale_repairs
        .iter()
        .find(|repair| repair.kind == RepairKind::Placement)
        .unwrap();

    let delete_id = Uuid::now_v7();
    let delete = ManagedDeleteRequest {
        operation_id: delete_id,
        receipt_id: Uuid::now_v7(),
        logical: put.logical.clone(),
        placement: Placement {
            version: 1,
            primary_backend_id: "a".to_string(),
            replica_backend_id: Some("b".to_string()),
        },
        provider_bucket: "provider-bucket".to_string(),
        occurred_at_micros: crate::transaction::unix_time_ms() * 1_000,
        rate_version: 1,
        max_processed_bytes: 0,
    };
    let deleted = repository
        .commit_atomic_logical_delete(delete.clone())
        .await
        .unwrap();
    assert!(deleted.authority.tombstone);
    assert_eq!(
        deleted.authority.cas_version,
        put_commit.authority.cas_version + 1
    );
    assert_eq!(deleted.usage.visible_logical_bytes, 0);
    assert_eq!(deleted.usage.physical_allocated_bytes, 3);
    assert_eq!(deleted.usage.active_operation_id, None);
    assert_eq!(
        deleted.operation.state,
        ManagedLogicalOperationState::Committed
    );
    assert_eq!(
        deleted.operation.evidence.as_ref().unwrap().processed_bytes,
        0
    );
    assert!(deleted.operation.intent.publication_recipe.is_some());
    assert_eq!(
        repository
            .logical_operation(delete_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ManagedLogicalOperationState::Committed
    );
    let tombstone_cas = deleted.authority.cas_version;
    let leased_cleanup = repository
        .claim_repairs("cleanup-snapshot", i64::MAX, 10)
        .await
        .unwrap();
    let replica_cleanup = leased_cleanup
        .iter()
        .find(|repair| repair.target_backend_id == "b")
        .unwrap();
    let primary_cleanup = leased_cleanup
        .iter()
        .find(|repair| repair.target_backend_id == "a")
        .unwrap();
    let existing_replica = repository
        .physical_versions(tenant, "b", &put.provider_bucket, &put.physical_key)
        .await
        .unwrap()
        .pop()
        .unwrap();
    // Simulate a provider repair that started before DELETE but ledgered its
    // physical version only after the tombstone committed.
    repository
        .commit_physical_write(&replica_lease, &[], Some("replica-version"))
        .await
        .unwrap();
    repository
        .commit_physical_write(&placement_lease, &[], Some("placement-version"))
        .await
        .unwrap();
    assert!(!repository.complete_repair(stale_replica).await.unwrap());
    assert!(!repository.complete_repair(stale_placement).await.unwrap());
    repository
        .forget_physical_version(&existing_replica)
        .await
        .unwrap();
    assert!(!repository.complete_repair(replica_cleanup).await.unwrap());
    repository
        .fail_repair(primary_cleanup.id, "defer cleanup")
        .await
        .unwrap();
    assert_eq!(
        repository
            .get(&put.logical)
            .await
            .unwrap()
            .unwrap()
            .cas_version,
        tombstone_cas
    );

    let cleanup = repository
        .claim_repairs("cleanup", i64::MAX, 10)
        .await
        .unwrap();
    assert!(cleanup.iter().all(|repair| {
        repair.kind == RepairKind::DeleteGeneration && repair.generation == put.generation
    }));
    assert_eq!(
        cleanup
            .iter()
            .map(|repair| repair.target_backend_id.as_str())
            .collect::<HashSet<_>>(),
        HashSet::from(["b", "c"])
    );

    let again = repository
        .commit_atomic_logical_delete(ManagedDeleteRequest {
            operation_id: Uuid::now_v7(),
            receipt_id: Uuid::now_v7(),
            logical: put.logical,
            placement: Placement {
                version: 1,
                primary_backend_id: "a".to_string(),
                replica_backend_id: Some("b".to_string()),
            },
            provider_bucket: "provider-bucket".to_string(),
            occurred_at_micros: crate::transaction::unix_time_ms() * 1_000,
            rate_version: 1,
            max_processed_bytes: 0,
        })
        .await
        .unwrap();
    assert_eq!(again.authority.cas_version, tombstone_cas);
    assert_eq!(again.usage.physical_allocated_bytes, 3);

    let mut replacement = logical_intent(
        tenant,
        "key",
        ManagedMutationKind::Put,
        repository.route_fence(tenant).await.unwrap(),
    );
    replacement.expected_authority_cas = Some(tombstone_cas);
    repository
        .insert_logical_operation(replacement.clone())
        .await
        .unwrap();
    repository
        .reserve_logical_operation(replacement.operation_id, 4)
        .await
        .unwrap();
    let replacement_lease = repository
        .begin_physical_write(child_intent(&replacement))
        .await
        .unwrap();
    record_put_evidence(&repository, &replacement, 4).await;
    let replacement_commit = repository
        .finalize_logical_put(
            replacement.operation_id,
            &replacement_lease,
            ExactPhysicalCommit {
                selected_version_id: Some("replacement-version".to_string()),
                superseded_version_ids: Vec::new(),
                version_history_complete: true,
            },
            None,
        )
        .await
        .unwrap();
    let replay = repository
        .commit_atomic_logical_delete(delete)
        .await
        .unwrap();
    assert_eq!(replay.authority, replacement_commit.authority);
    assert!(!replay.authority.tombstone);
}

#[tokio::test]
async fn atomic_logical_delete_missing_and_failure_have_no_partial_state() {
    let repository = InMemoryManagedRepository::new();
    let tenant = "tenant-atomic-delete-failure";
    let missing = LogicalObjectKey::new(tenant, "bucket", "missing");
    let request = ManagedDeleteRequest {
        operation_id: Uuid::now_v7(),
        receipt_id: Uuid::now_v7(),
        logical: missing.clone(),
        placement: Placement {
            version: 1,
            primary_backend_id: "a".to_string(),
            replica_backend_id: None,
        },
        provider_bucket: "provider-bucket".to_string(),
        occurred_at_micros: crate::transaction::unix_time_ms() * 1_000,
        rate_version: 1,
        max_processed_bytes: 0,
    };
    let deleted = repository
        .commit_atomic_logical_delete(request)
        .await
        .unwrap();
    assert!(deleted.authority.tombstone);
    assert_eq!(deleted.usage.visible_logical_bytes, 0);
    assert_eq!(deleted.usage.physical_allocated_bytes, 0);

    let fence = repository.route_fence(tenant).await.unwrap();
    let blocker = logical_intent(tenant, "blocker", ManagedMutationKind::Put, fence);
    repository
        .admit_logical_operation(blocker.clone(), 1)
        .await
        .unwrap();
    let failed_id = Uuid::now_v7();
    let result = repository
        .commit_atomic_logical_delete(ManagedDeleteRequest {
            operation_id: failed_id,
            receipt_id: Uuid::now_v7(),
            logical: LogicalObjectKey::new(tenant, "bucket", "other"),
            placement: Placement {
                version: 1,
                primary_backend_id: "a".to_string(),
                replica_backend_id: None,
            },
            provider_bucket: "provider-bucket".to_string(),
            occurred_at_micros: crate::transaction::unix_time_ms() * 1_000,
            rate_version: 1,
            max_processed_bytes: 0,
        })
        .await;
    assert!(matches!(
        result,
        Err(ManagedDeleteError::PreCommit(
            ManagedError::MutationInProgress
        ))
    ));
    assert!(
        repository
            .logical_operation(failed_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repository
            .get(&LogicalObjectKey::new(tenant, "bucket", "other"))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repository
            .workspace_usage(tenant)
            .await
            .unwrap()
            .unwrap()
            .active_operation_id,
        Some(blocker.operation_id)
    );
}

#[tokio::test]
async fn authority_listing_uses_literal_prefix_c_order_and_stable_pages() {
    let repository = InMemoryManagedRepository::new();
    let tenant = "tenant-list";
    for key in ["p_a", "p/a", "p%a", "p💾", "q"] {
        repository
            .publish(
                authority(LogicalObjectKey::new(tenant, "bucket", key), Uuid::now_v7()),
                None,
            )
            .await
            .unwrap();
    }
    let literal = repository
        .list_authority(AuthorityListQuery {
            tenant_id: tenant.to_string(),
            bucket: "bucket".to_string(),
            prefix: "p%".to_string(),
            after: None,
            max_keys: 10,
        })
        .await
        .unwrap();
    assert_eq!(
        literal
            .objects
            .iter()
            .map(|object| object.logical.key.as_str())
            .collect::<Vec<_>>(),
        ["p%a"]
    );
    let first = repository
        .list_authority(AuthorityListQuery {
            tenant_id: tenant.to_string(),
            bucket: "bucket".to_string(),
            prefix: "p".to_string(),
            after: None,
            max_keys: 2,
        })
        .await
        .unwrap();
    assert_eq!(
        first
            .objects
            .iter()
            .map(|object| object.logical.key.as_str())
            .collect::<Vec<_>>(),
        ["p%a", "p/a"]
    );
    let second = repository
        .list_authority(AuthorityListQuery {
            tenant_id: tenant.to_string(),
            bucket: "bucket".to_string(),
            prefix: "p".to_string(),
            after: first.next_after,
            max_keys: 2,
        })
        .await
        .unwrap();
    assert_eq!(
        second
            .objects
            .iter()
            .map(|object| object.logical.key.as_str())
            .collect::<Vec<_>>(),
        ["p_a", "p💾"]
    );
    assert_eq!(second.next_after, None);
}

#[tokio::test]
async fn list_cursors_bind_exact_queries_replay_and_enforce_ttl_and_bounds() {
    let repository = InMemoryManagedRepository::new();
    let now = crate::transaction::unix_time_ms();
    let binding = ManagedListCursorBinding {
        tenant_id: "tenant-cursor".to_string(),
        bucket: "bucket".to_string(),
        prefix: "prefix".to_string(),
        delimiter: Some("/".to_string()),
        version: ManagedListVersion::V2,
    };
    let request = ManagedListCursorRequest {
        binding: binding.clone(),
        position: ManagedListCursorPosition {
            last_key: Some("prefix/key".to_string()),
            last_common_prefix: None,
        },
        response_state: serde_json::json!({"objects": ["prefix/key"]}),
        final_page: false,
    };
    let cursor = repository
        .create_list_cursor(request.clone(), now)
        .await
        .unwrap();
    assert_eq!(cursor.id.get_version(), Some(uuid::Version::Random));
    assert_eq!(
        cursor.fence,
        ManagedRouteFence {
            namespace_epoch: 1,
            routing_epoch: 1,
        }
    );
    assert_eq!(
        cursor.response_state_bytes,
        serde_json::to_vec(&request.response_state).unwrap().len() as u64
    );
    let mut wrong = binding.clone();
    wrong.prefix.push_str("-other");
    assert!(matches!(
        repository.use_list_cursor(cursor.id, &wrong, now + 1).await,
        Err(ManagedError::CursorQueryMismatch)
    ));
    let first = repository
        .use_list_cursor(cursor.id, &binding, now + 1)
        .await
        .unwrap();
    let replay = repository
        .use_list_cursor(cursor.id, &binding, now + 2)
        .await
        .unwrap();
    assert_eq!(first.state, ManagedListCursorState::Used);
    assert_eq!(replay.first_used_at_ms, first.first_used_at_ms);
    assert_eq!(replay.response_state, first.response_state);
    assert!(matches!(
        repository
            .use_list_cursor(cursor.id, &binding, now + MANAGED_LIST_CURSOR_TTL_MS)
            .await,
        Err(ManagedError::CursorExpired)
    ));

    for _ in 0..MANAGED_LIST_CURSOR_WORKSPACE_LIMIT {
        repository
            .create_list_cursor(request.clone(), now)
            .await
            .unwrap();
    }
    assert!(matches!(
        repository.create_list_cursor(request.clone(), now).await,
        Err(ManagedError::CursorLimitExceeded)
    ));
    assert_eq!(
        repository
            .cleanup_expired_list_cursors(now + MANAGED_LIST_CURSOR_TTL_MS, 10)
            .await
            .unwrap(),
        10
    );

    let oversized = ManagedListCursorRequest {
        response_state: serde_json::Value::String(
            "x".repeat(MANAGED_LIST_CURSOR_RESPONSE_MAX_BYTES as usize),
        ),
        ..request.clone()
    };
    assert!(matches!(
        repository.create_list_cursor(oversized, now).await,
        Err(ManagedError::CursorLimitExceeded)
    ));

    let mut state = repository.state.lock().await;
    state.list_cursors.clear();
    drop(state);
    let amplified = ManagedListCursorRequest {
        response_state: serde_json::Value::String("x".repeat(60 * 1024)),
        ..request.clone()
    };
    let serialized_bytes = serde_json::to_vec(&amplified.response_state).unwrap().len() as u64;
    let allowed = MANAGED_LIST_CURSOR_WORKSPACE_MAX_BYTES / serialized_bytes;
    for _ in 0..allowed {
        repository
            .create_list_cursor(amplified.clone(), now)
            .await
            .unwrap();
    }
    assert!(matches!(
        repository.create_list_cursor(amplified, now).await,
        Err(ManagedError::CursorLimitExceeded)
    ));

    let mut state = repository.state.lock().await;
    state.list_cursors.clear();
    for index in 0..MANAGED_LIST_CURSOR_GLOBAL_LIMIT {
        let id = Uuid::from_u128(u128::from(index) + 1);
        state.list_cursors.insert(
            id,
            ManagedListCursor {
                id,
                binding: ManagedListCursorBinding {
                    tenant_id: format!("global-tenant-{}", index / 100),
                    bucket: "bucket".to_string(),
                    prefix: String::new(),
                    delimiter: None,
                    version: ManagedListVersion::V1,
                },
                fence: ManagedRouteFence {
                    namespace_epoch: 1,
                    routing_epoch: 1,
                },
                position: ManagedListCursorPosition {
                    last_key: None,
                    last_common_prefix: None,
                },
                response_state: serde_json::json!({}),
                response_state_bytes: 2,
                final_page: false,
                state: ManagedListCursorState::Active,
                created_at_ms: now,
                expires_at_ms: now + MANAGED_LIST_CURSOR_TTL_MS,
                first_used_at_ms: None,
            },
        );
    }
    drop(state);
    assert!(matches!(
        repository
            .create_list_cursor(
                ManagedListCursorRequest {
                    binding: ManagedListCursorBinding {
                        tenant_id: "global-overflow".to_string(),
                        bucket: "bucket".to_string(),
                        prefix: String::new(),
                        delimiter: None,
                        version: ManagedListVersion::V1,
                    },
                    position: ManagedListCursorPosition {
                        last_key: None,
                        last_common_prefix: None,
                    },
                    response_state: serde_json::json!({}),
                    final_page: false,
                },
                now,
            )
            .await,
        Err(ManagedError::CursorLimitExceeded)
    ));

    let mut state = repository.state.lock().await;
    state.list_cursors.clear();
    drop(state);
    let routing_cursor = repository
        .create_list_cursor(request.clone(), now)
        .await
        .unwrap();
    repository
        .advance_routing_epoch(&binding.tenant_id, routing_cursor.fence.routing_epoch)
        .await
        .unwrap();
    assert!(matches!(
        repository
            .use_list_cursor(routing_cursor.id, &binding, now + 1)
            .await,
        Err(ManagedError::CursorExpired)
    ));

    let namespace_cursor = repository.create_list_cursor(request, now).await.unwrap();
    let purge = NamespacePurgeRequest {
        tenant_id: binding.tenant_id.clone(),
        operation_id: Uuid::now_v7(),
    };
    assert!(matches!(
        repository.purge_namespace(&purge).await.unwrap(),
        NamespacePurgeStatus::Complete {
            deleted_versions: 0
        }
    ));
    assert!(matches!(
        repository
            .use_list_cursor(namespace_cursor.id, &binding, now + 1)
            .await,
        Err(ManagedError::CursorExpired)
    ));
}

#[tokio::test]
async fn list_cursor_successors_are_singleton_exact_and_cascade_with_predecessors() {
    let repository = InMemoryManagedRepository::new();
    let now = crate::transaction::unix_time_ms();
    let binding = ManagedListCursorBinding {
        tenant_id: "tenant-successor".to_string(),
        bucket: "bucket".to_string(),
        prefix: "prefix".to_string(),
        delimiter: None,
        version: ManagedListVersion::V2,
    };
    let predecessor = repository
        .create_list_cursor(
            ManagedListCursorRequest {
                binding: binding.clone(),
                position: ManagedListCursorPosition {
                    last_key: Some("prefix/a".to_string()),
                    last_common_prefix: None,
                },
                response_state: serde_json::json!({"objects": ["prefix/a"]}),
                final_page: false,
            },
            now,
        )
        .await
        .unwrap();
    repository
        .use_list_cursor(predecessor.id, &binding, now + 1)
        .await
        .unwrap();
    let request = ManagedListCursorRequest {
        binding: binding.clone(),
        position: ManagedListCursorPosition {
            last_key: Some("prefix/b".to_string()),
            last_common_prefix: None,
        },
        response_state: serde_json::json!({"objects": ["prefix/b"]}),
        final_page: true,
    };
    let successor = repository
        .create_list_cursor_successor(predecessor.id, request.clone(), now + 1)
        .await
        .unwrap();
    let replay = repository
        .create_list_cursor_successor(predecessor.id, request.clone(), now + 2)
        .await
        .unwrap();
    assert_eq!(replay.id, successor.id);

    let mut different = request;
    different.final_page = false;
    assert!(matches!(
        repository
            .create_list_cursor_successor(predecessor.id, different, now + 2)
            .await,
        Err(ManagedError::Conflict)
    ));

    repository.delete_list_cursor(predecessor.id).await.unwrap();
    assert!(matches!(
        repository
            .use_list_cursor(successor.id, &binding, now + 3)
            .await,
        Err(ManagedError::CursorExpired)
    ));
}

#[tokio::test]
async fn namespace_purge_releases_logical_accounting_cursors_and_fences() {
    let repository = InMemoryManagedRepository::new();
    let tenant = "tenant-logical-purge";
    let intent = logical_intent(
        tenant,
        "key",
        ManagedMutationKind::Put,
        repository.route_fence(tenant).await.unwrap(),
    );
    repository
        .insert_logical_operation(intent.clone())
        .await
        .unwrap();
    repository
        .reserve_logical_operation(intent.operation_id, 3)
        .await
        .unwrap();
    let lease = repository
        .begin_physical_write(child_intent(&intent))
        .await
        .unwrap();
    record_put_evidence(&repository, &intent, 3).await;
    repository
        .finalize_logical_put(
            intent.operation_id,
            &lease,
            ExactPhysicalCommit {
                selected_version_id: Some("purge-version".to_string()),
                superseded_version_ids: Vec::new(),
                version_history_complete: true,
            },
            None,
        )
        .await
        .unwrap();

    let binding = ManagedListCursorBinding {
        tenant_id: tenant.to_string(),
        bucket: "bucket".to_string(),
        prefix: String::new(),
        delimiter: None,
        version: ManagedListVersion::V2,
    };
    let now = crate::transaction::unix_time_ms();
    let cursor = repository
        .create_list_cursor(
            ManagedListCursorRequest {
                binding: binding.clone(),
                position: ManagedListCursorPosition {
                    last_key: Some("key".to_string()),
                    last_common_prefix: None,
                },
                response_state: serde_json::json!({"objects": ["key"]}),
                final_page: false,
            },
            now,
        )
        .await
        .unwrap();
    let request = NamespacePurgeRequest {
        tenant_id: tenant.to_string(),
        operation_id: Uuid::now_v7(),
    };
    assert_eq!(
        repository.purge_namespace(&request).await.unwrap(),
        NamespacePurgeStatus::Running
    );
    let target = repository
        .purge_targets(&request, 10)
        .await
        .unwrap()
        .pop()
        .unwrap();
    repository
        .mark_purge_target_deleted(&request, &target)
        .await
        .unwrap();
    assert_eq!(
        repository.namespace_purge_status(&request).await.unwrap(),
        NamespacePurgeStatus::Complete {
            deleted_versions: 1
        }
    );

    let usage = repository.workspace_usage(tenant).await.unwrap().unwrap();
    assert_eq!(usage.visible_logical_bytes, 0);
    assert_eq!(usage.physical_allocated_bytes, 0);
    assert_eq!(usage.reserved_bytes, 0);
    assert_eq!(usage.active_operation_id, None);
    let operation = repository
        .logical_operation(intent.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        operation.released_physical_bytes,
        operation.committed_physical_bytes
    );
    assert!(matches!(
        repository
            .use_list_cursor(cursor.id, &binding, now + 1)
            .await,
        Err(ManagedError::CursorExpired)
    ));
    assert_eq!(
        repository.route_fence(tenant).await.unwrap(),
        ManagedRouteFence {
            namespace_epoch: 2,
            routing_epoch: 2,
        }
    );
    assert_eq!(repository.get(&intent.logical).await.unwrap(), None);

    let next_fence = repository.route_fence(tenant).await.unwrap();
    let next = logical_intent(tenant, "next", ManagedMutationKind::Put, next_fence);
    repository
        .insert_logical_operation(next.clone())
        .await
        .unwrap();
    repository
        .reserve_logical_operation(next.operation_id, 3)
        .await
        .unwrap();
    let next_lease = repository
        .begin_physical_write(child_intent(&next))
        .await
        .unwrap();
    assert_eq!(next_lease.namespace_epoch, next_fence.namespace_epoch);
    repository
        .abort_logical_put(
            next.operation_id,
            Some(&next_lease),
            LogicalAbortProof::ChildProvenAborted,
            "test_cleanup",
            None,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn empty_in_memory_namespace_purge_completes_idempotently() {
    let repository = InMemoryManagedRepository::new();
    let request = NamespacePurgeRequest {
        tenant_id: "tenant-a".to_string(),
        operation_id: Uuid::now_v7(),
    };
    let complete = NamespacePurgeStatus::Complete {
        deleted_versions: 0,
    };
    assert_eq!(
        repository.purge_namespace(&request).await.unwrap(),
        complete
    );
    assert_eq!(
        repository.namespace_purge_status(&request).await.unwrap(),
        complete
    );
}

#[tokio::test]
async fn in_memory_purge_fences_concurrent_writes_and_blocks_ambiguous_history() {
    let repository = InMemoryManagedRepository::new();
    let intent_id = Uuid::now_v7();
    let lease = repository
        .begin_physical_write(PhysicalWriteIntent {
            intent_id,
            tenant_id: "tenant-a".to_string(),
            backend_id: "provider:bucket".to_string(),
            storage_identity: test_storage_identity(),
            credential_epoch: 1,
            provider_bucket: "bucket".to_string(),
            physical_key: "managed/key".to_string(),
            versioning_mode: BackendVersioningMode::Unversioned,
            versioning_capability: BackendVersioningCapability::Unsupported,
            lease_owner: "writer-a".to_string(),
        })
        .await
        .unwrap();
    let request = NamespacePurgeRequest {
        tenant_id: "tenant-a".to_string(),
        operation_id: Uuid::now_v7(),
    };
    assert_eq!(
        repository.purge_namespace(&request).await.unwrap(),
        NamespacePurgeStatus::Running
    );
    assert!(matches!(
        repository
            .begin_physical_write(PhysicalWriteIntent {
                intent_id: Uuid::now_v7(),
                tenant_id: "tenant-a".to_string(),
                backend_id: "provider:bucket".to_string(),
                storage_identity: test_storage_identity(),
                credential_epoch: 1,
                provider_bucket: "bucket".to_string(),
                physical_key: "managed/new-key".to_string(),
                versioning_mode: BackendVersioningMode::Unversioned,
                versioning_capability: BackendVersioningCapability::Unsupported,
                lease_owner: "writer-b".to_string(),
            })
            .await,
        Err(ManagedError::NamespaceFenced)
    ));
    repository
        .block_physical_write(&lease, "provider response was ambiguous")
        .await
        .unwrap();
    assert_eq!(
        repository.namespace_purge_status(&request).await.unwrap(),
        NamespacePurgeStatus::Blocked {
            reason: "provider response was ambiguous".to_string(),
        }
    );
}

#[tokio::test]
async fn stale_authority_snapshot_cannot_enqueue_repair_after_cas_changes() {
    let repository = InMemoryManagedRepository::new();
    let first = repository
        .publish(
            authority(
                LogicalObjectKey::new("tenant-stale", "bucket", "key"),
                Uuid::now_v7(),
            ),
            None,
        )
        .await
        .unwrap();
    let stale_repair = RepairRecord::copy(
        RepairKind::Replica,
        &first,
        Some(first.primary_backend_id.clone()),
        first.replica_backend_id.clone().unwrap(),
        RepairTargetRole::Replica,
        first.placement_version,
    );
    let mut replacement = first.clone();
    replacement.generation = Uuid::now_v7();
    repository
        .publish(replacement, Some(first.cas_version))
        .await
        .unwrap();
    assert!(matches!(
        repository.enqueue(stale_repair).await,
        Err(ManagedError::Conflict)
    ));
}

#[test]
fn repair_backoff_grows_and_is_capped() {
    assert_eq!(repair_backoff_ms(0), 30_000);
    assert_eq!(repair_backoff_ms(1), 60_000);
    assert_eq!(repair_backoff_ms(10), REPAIR_BACKOFF_MAX_MS);
    assert_eq!(repair_backoff_ms(100), REPAIR_BACKOFF_MAX_MS);
}

#[tokio::test]
async fn repair_dead_letters_after_max_attempts_and_honors_backoff() {
    let repository = InMemoryManagedRepository::new();
    let published = repository
        .publish(
            authority(
                LogicalObjectKey::new("tenant-repair", "bucket", "key"),
                Uuid::now_v7(),
            ),
            None,
        )
        .await
        .unwrap();
    let repair = RepairRecord::copy(
        RepairKind::Replica,
        &published,
        Some(published.primary_backend_id.clone()),
        published.replica_backend_id.clone().unwrap(),
        RepairTargetRole::Replica,
        published.placement_version,
    );
    repository.enqueue(repair).await.unwrap();

    for attempt in 1..=MAX_REPAIR_ATTEMPTS {
        let claimed = repository
            .claim_repairs("worker", crate::transaction::unix_time_ms() + 60_000, 10)
            .await
            .unwrap();
        assert_eq!(
            claimed.len(),
            1,
            "attempt {attempt} should claim the repair"
        );
        repository
            .fail_repair(claimed[0].lease_token.unwrap(), "injected failure")
            .await
            .unwrap();
        if attempt < MAX_REPAIR_ATTEMPTS {
            let immediate = repository
                .claim_repairs("worker", crate::transaction::unix_time_ms() + 60_000, 10)
                .await
                .unwrap();
            assert!(
                immediate.is_empty(),
                "attempt {attempt} should be backed off, not immediately claimable"
            );
            // Advance past the backoff for the next attempt.
            let mut state = repository.state.lock().await;
            for (repair, _) in state.repairs.values_mut() {
                repair.not_before_ms = 0;
            }
        }
    }

    let final_claim = repository
        .claim_repairs("worker", crate::transaction::unix_time_ms() + 60_000, 10)
        .await
        .unwrap();
    assert!(
        final_claim.is_empty(),
        "dead-lettered repair must never be retried"
    );
}

#[tokio::test]
async fn cleanup_without_matching_physical_ledger_is_already_complete() {
    let repository = InMemoryManagedRepository::new();
    let mut source = authority(
        LogicalObjectKey::new("tenant-cleanup", "bucket", "key"),
        Uuid::now_v7(),
    );
    source.replica_backend_id = None;
    source.replica_status = CopyStatus::Absent;
    let published = repository.publish(source, None).await.unwrap();
    let cleanup = cleanup_repairs(&published).pop().unwrap();
    repository.enqueue(cleanup).await.unwrap();
    assert!(
        repository
            .claim_repairs("worker", crate::transaction::unix_time_ms() + 60_000, 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn multipart_activity_fences_parts_and_blocks_purge_until_abort_cleanup() {
    let repository = InMemoryManagedRepository::new();
    let epoch = repository
        .begin_multipart_activity("upload", "tenant-a")
        .await
        .unwrap();
    repository
        .confirm_multipart_activity("upload", "tenant-a", epoch)
        .await
        .unwrap();
    let request = NamespacePurgeRequest {
        tenant_id: "tenant-a".to_string(),
        operation_id: Uuid::now_v7(),
    };
    assert_eq!(
        repository.purge_namespace(&request).await.unwrap(),
        NamespacePurgeStatus::Running
    );
    assert!(matches!(
        repository
            .assert_multipart_activity("upload", "tenant-a", epoch, false)
            .await,
        Err(ManagedError::NamespaceFenced)
    ));
    repository
        .assert_multipart_activity("upload", "tenant-a", epoch, true)
        .await
        .unwrap();
    repository
        .finish_multipart_activity("upload", "tenant-a", epoch)
        .await
        .unwrap();
    assert_eq!(
        repository.namespace_purge_status(&request).await.unwrap(),
        NamespacePurgeStatus::Complete {
            deleted_versions: 0,
        }
    );
    assert!(matches!(
        repository
            .assert_multipart_activity("upload", "tenant-a", epoch, false)
            .await,
        Err(ManagedError::NamespaceFenced)
    ));
}

#[tokio::test]
async fn crashed_multipart_registration_expires_without_racing_confirmed_upload() {
    let repository = InMemoryManagedRepository::new();
    let orphan_epoch = repository
        .begin_multipart_activity("orphan", "tenant-a")
        .await
        .unwrap();
    repository
        .state
        .lock()
        .await
        .multipart_registration_expiry
        .insert("orphan".to_string(), crate::transaction::unix_time_ms() - 1);
    let valid_epoch = repository
        .begin_multipart_activity("valid", "tenant-a")
        .await
        .unwrap();
    repository
        .confirm_multipart_activity("valid", "tenant-a", valid_epoch)
        .await
        .unwrap();
    assert_eq!(
        repository.reconcile_multipart_activities(10).await.unwrap(),
        1
    );
    assert!(matches!(
        repository
            .assert_multipart_activity("orphan", "tenant-a", orphan_epoch, false)
            .await,
        Err(ManagedError::NamespaceFenced)
    ));
    repository
        .assert_multipart_activity("valid", "tenant-a", valid_epoch, false)
        .await
        .unwrap();
}

#[tokio::test]
async fn reclaimed_physical_write_lease_fences_stale_writer() {
    let repository = InMemoryManagedRepository::new();
    let intent_id = Uuid::now_v7();
    let stale = repository
        .begin_physical_write(PhysicalWriteIntent {
            intent_id,
            tenant_id: "tenant-lease".to_string(),
            backend_id: "provider:bucket".to_string(),
            storage_identity: test_storage_identity(),
            credential_epoch: 1,
            provider_bucket: "bucket".to_string(),
            physical_key: "managed/key".to_string(),
            versioning_mode: BackendVersioningMode::Enabled,
            versioning_capability: BackendVersioningCapability::Optional,
            lease_owner: "writer-a".to_string(),
        })
        .await
        .unwrap();
    repository
        .renew_physical_write_intent(&stale, crate::transaction::unix_time_ms().saturating_sub(1))
        .await
        .unwrap();
    let current = repository
        .claim_expired_physical_write_intent(
            intent_id,
            "writer-b",
            crate::transaction::unix_time_ms().saturating_add(60_000),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        repository
            .commit_physical_write(&stale, &[], Some("stale-version"))
            .await,
        Err(ManagedError::Conflict)
    ));
    assert!(matches!(
        repository.abort_physical_write(&stale).await,
        Err(ManagedError::Conflict)
    ));
    repository
        .commit_physical_write(&current, &[], Some("current-version"))
        .await
        .unwrap();
}

#[test]
fn rendezvous_has_stable_golden_vectors() {
    let score = rendezvous_score(1, "tenant-a", "bucket/path/to/object", "b2:bucket-a");
    assert_eq!(
        hex::encode(score),
        "bdaa1cebd6b1ff544ff1a5821c103391418bdecf94e17d934f8e56b0915c1657"
    );
    let placement = rendezvous_placement(
        1,
        "tenant-a",
        "bucket/path/to/object",
        ["r2:bucket-c", "b2:bucket-a", "s3:bucket-b"]
            .into_iter()
            .map(str::to_string),
    )
    .unwrap();
    assert_eq!(placement.primary_backend_id, "s3:bucket-b");
    assert_eq!(placement.replica_backend_id.as_deref(), Some("b2:bucket-a"));
}

#[test]
fn placement_is_independent_of_backend_input_order() {
    let first = rendezvous_placement(
        1,
        "tenant",
        "bucket/key",
        ["a", "b", "c"].into_iter().map(str::to_string),
    );
    let second = rendezvous_placement(
        1,
        "tenant",
        "bucket/key",
        ["c", "a", "b"].into_iter().map(str::to_string),
    );
    assert_eq!(first, second);
}

#[test]
fn placement_policy_fingerprint_is_order_independent_and_version_sensitive() {
    let ordered =
        placement_policy_fingerprint(1, [("a".to_string(), 1, 2), ("b".to_string(), 3, 4)]);
    let reordered =
        placement_policy_fingerprint(1, [("b".to_string(), 3, 4), ("a".to_string(), 1, 2)]);
    assert_eq!(ordered, reordered);
    assert_eq!(
        ordered,
        "1450298f70f46a4f639440b1721e9f516ee0093ab61de73508d67270b7617fe9"
    );
    let other_version =
        placement_policy_fingerprint(2, [("a".to_string(), 1, 2), ("b".to_string(), 3, 4)]);
    assert_ne!(ordered, other_version);
    let other_weight =
        placement_policy_fingerprint(1, [("a".to_string(), 1, 2), ("b".to_string(), 5, 4)]);
    assert_ne!(ordered, other_weight);
}

#[tokio::test]
async fn record_placement_policy_rejects_same_version_different_fingerprint() {
    let repository = InMemoryManagedRepository::new();
    let policy = ManagedPlacementPolicy {
        version: 1,
        fingerprint: "fingerprint-one".to_string(),
        backend_facts: vec![],
        activated_at_ms: 1,
    };
    assert!(repository.record_placement_policy(&policy).await.unwrap());
    assert!(repository.record_placement_policy(&policy).await.unwrap());
    let conflicting = ManagedPlacementPolicy {
        version: 1,
        fingerprint: "fingerprint-two".to_string(),
        backend_facts: vec![],
        activated_at_ms: 2,
    };
    assert!(
        !repository
            .record_placement_policy(&conflicting)
            .await
            .unwrap()
    );
}

#[test]
fn weighted_placement_favors_configured_capacity_over_fixed_corpus() {
    let mut primary_counts = HashMap::new();
    for object in 0..20_000 {
        let placement = weighted_rendezvous_placement(
            2,
            "tenant",
            &format!("bucket/object-{object}"),
            [("b2:small".to_string(), 1), ("b2:large".to_string(), 3)],
        )
        .unwrap();
        assert_ne!(
            placement.primary_backend_id,
            placement.replica_backend_id.unwrap()
        );
        *primary_counts
            .entry(placement.primary_backend_id)
            .or_insert(0usize) += 1;
    }
    let small = primary_counts["b2:small"];
    let large = primary_counts["b2:large"];
    assert!(
        (4_500..=5_500).contains(&small),
        "expected roughly 25% of the fixed corpus on small, got {small}"
    );
    assert!(
        (14_500..=15_500).contains(&large),
        "expected roughly 75% of the fixed corpus on large, got {large}"
    );
}

#[test]
fn placement_process_helper() {
    if std::env::var_os("MASKURA_PLACEMENT_PROCESS_HELPER").is_some() {
        let placement = rendezvous_placement(
            1,
            "tenant-a",
            "bucket/path/to/object",
            ["r2:bucket-c", "b2:bucket-a", "s3:bucket-b"]
                .into_iter()
                .map(str::to_string),
        )
        .unwrap();
        println!(
            "MASKURA_PLACEMENT={}:{}",
            placement.primary_backend_id,
            placement.replica_backend_id.unwrap()
        );
    }
}

#[test]
fn placement_is_stable_in_a_separate_process() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "managed::tests::placement_process_helper",
            "--nocapture",
        ])
        .env("MASKURA_PLACEMENT_PROCESS_HELPER", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("MASKURA_PLACEMENT=s3:bucket-b:b2:bucket-a")
    );
}

#[tokio::test]
async fn authority_cas_tombstone_and_repair_restart_are_safe() {
    let repository = InMemoryManagedRepository::new();
    let logical = LogicalObjectKey::new("tenant", "bucket", "key");
    let first = repository
        .publish(authority(logical.clone(), Uuid::now_v7()), None)
        .await
        .unwrap();
    assert!(
        repository
            .publish(authority(logical.clone(), Uuid::now_v7()), None)
            .await
            .is_err()
    );
    let claimed = repository
        .claim_repairs("process-a", crate::transaction::unix_time_ms() - 1, 10)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    let reclaimed = repository
        .claim_repairs("process-b", crate::transaction::unix_time_ms() + 30_000, 10)
        .await
        .unwrap();
    assert_eq!(reclaimed.len(), 1);
    assert!(repository.complete_repair(&claimed[0]).await.is_err());
    assert!(
        repository
            .fail_repair(claimed[0].id, "stale worker")
            .await
            .is_err()
    );
    repository.complete_repair(&reclaimed[0]).await.unwrap();
    let repaired = repository.get(&logical).await.unwrap().unwrap();
    assert_eq!(repaired.replica_status, CopyStatus::Ready);
    let placement = Placement {
        version: 1,
        primary_backend_id: "a".to_string(),
        replica_backend_id: Some("b".to_string()),
    };
    let tombstone = repository
        .tombstone(&logical, Some(repaired.cas_version), &placement)
        .await
        .unwrap();
    assert!(tombstone.tombstone);
    assert!(
        repository
            .publish(authority(logical, Uuid::now_v7()), Some(first.cas_version))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn mode_transition_floor_is_enforced() {
    let repository = InMemoryManagedRepository::new();
    validate_mode(ManagedStreamingMode::Off, &repository, true)
        .await
        .unwrap();
    validate_mode(ManagedStreamingMode::Observe, &repository, true)
        .await
        .unwrap();
    validate_mode(ManagedStreamingMode::Enforce, &repository, true)
        .await
        .unwrap();
    let logical = LogicalObjectKey::new("tenant", "bucket", "key");
    repository
        .publish(authority(logical, Uuid::now_v7()), None)
        .await
        .unwrap();
    assert!(
        validate_mode(ManagedStreamingMode::Off, &repository, true)
            .await
            .is_err()
    );
    validate_mode(ManagedStreamingMode::Observe, &repository, true)
        .await
        .unwrap();
}

#[tokio::test]
async fn replica_outcome_and_old_generation_cleanup_are_durable() {
    let repository = InMemoryManagedRepository::new();
    let logical = LogicalObjectKey::new("tenant", "bucket", "key");
    let pending = repository
        .publish(authority(logical.clone(), Uuid::now_v7()), None)
        .await
        .unwrap();
    let repairs = repository
        .claim_repairs("repair", crate::transaction::unix_time_ms() + 30_000, 10)
        .await
        .unwrap();
    assert_eq!(repairs.len(), 1);
    assert_eq!(repairs[0].kind, RepairKind::Replica);
    repository.complete_repair(&repairs[0]).await.unwrap();

    let mut replacement = authority(logical, Uuid::now_v7());
    replacement.replica_status = CopyStatus::Ready;
    repository
        .publish(replacement, Some(pending.cas_version + 1))
        .await
        .unwrap();
    let cleanup = repository
        .claim_repairs("gc", crate::transaction::unix_time_ms() + 30_000, 10)
        .await
        .unwrap();
    assert!(cleanup.is_empty());
    assert!(
        cleanup
            .iter()
            .all(|repair| repair.kind == RepairKind::DeleteGeneration)
    );
}

#[tokio::test]
async fn replica_only_placement_repair_advances_authority_placement_version() {
    let repository = InMemoryManagedRepository::new();
    let logical = LogicalObjectKey::new("tenant", "bucket", "key");
    let mut initial = authority(logical.clone(), Uuid::now_v7());
    initial.replica_status = CopyStatus::Ready;
    let published = repository.publish(initial, None).await.unwrap();
    let placement = Placement {
        version: published.placement_version + 1,
        primary_backend_id: "a".to_string(),
        replica_backend_id: Some("c".to_string()),
    };
    repository
        .enqueue(RepairRecord::placement(
            &published,
            Some("a".to_string()),
            "c".to_string(),
            RepairTargetRole::Replica,
            &placement,
        ))
        .await
        .unwrap();

    let repair = repository
        .claim_repairs("repair", crate::transaction::unix_time_ms() + 30_000, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(repository.complete_repair(&repair).await.unwrap());

    let repaired = repository.get(&logical).await.unwrap().unwrap();
    assert_eq!(repaired.primary_backend_id, "a");
    assert_eq!(repaired.replica_backend_id.as_deref(), Some("c"));
    assert_eq!(repaired.replica_status, CopyStatus::Ready);
    assert_eq!(
        repaired.placement_version,
        published.placement_version + 1,
        "a replica-only placement repair must advance the authority version"
    );
}

#[tokio::test]
async fn leased_generation_cleanup_fences_repair_publication() {
    let repository = InMemoryManagedRepository::new();
    let logical = LogicalObjectKey::new("tenant-cleanup-fence", "bucket", "key");
    let mut initial = authority(logical, Uuid::now_v7());
    initial.replica_status = CopyStatus::Ready;
    let published = repository.publish(initial, None).await.unwrap();
    let placement = Placement {
        version: published.placement_version + 1,
        primary_backend_id: "c".to_string(),
        replica_backend_id: Some("b".to_string()),
    };
    repository
        .enqueue(RepairRecord::placement(
            &published,
            Some("a".to_string()),
            "c".to_string(),
            RepairTargetRole::Primary,
            &placement,
        ))
        .await
        .unwrap();
    let repair = repository
        .claim_repairs("repair", crate::transaction::unix_time_ms() + 30_000, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let target_lease = repository
        .begin_physical_write(PhysicalWriteIntent {
            intent_id: Uuid::now_v7(),
            tenant_id: published.logical.tenant_id.clone(),
            backend_id: "c".to_string(),
            storage_identity: test_storage_identity(),
            credential_epoch: 1,
            provider_bucket: "provider-bucket".to_string(),
            physical_key: generation_physical_key(&published.logical, published.generation),
            versioning_mode: BackendVersioningMode::Enabled,
            versioning_capability: BackendVersioningCapability::Required,
            lease_owner: "repair-target".to_string(),
        })
        .await
        .unwrap();
    repository
        .commit_physical_write(&target_lease, &[], Some("repair-target-version"))
        .await
        .unwrap();
    repository
        .enqueue(RepairRecord::copy(
            RepairKind::DeleteGeneration,
            &published,
            None,
            "c".to_string(),
            RepairTargetRole::Cleanup,
            published.placement_version,
        ))
        .await
        .unwrap();
    let cleanup = repository
        .claim_repairs("cleanup", crate::transaction::unix_time_ms() + 30_000, 1)
        .await
        .unwrap();
    assert_eq!(cleanup.len(), 1);
    assert_eq!(cleanup[0].kind, RepairKind::DeleteGeneration);

    assert!(!repository.complete_repair(&repair).await.unwrap());
    assert_eq!(
        repository.get(&published.logical).await.unwrap(),
        Some(published)
    );
}

#[tokio::test]
async fn concurrent_authority_publish_has_one_cas_winner() {
    let repository = InMemoryManagedRepository::new();
    let logical = LogicalObjectKey::new("tenant", "bucket", "race");
    let initial = repository
        .publish(authority(logical.clone(), Uuid::now_v7()), None)
        .await
        .unwrap();
    let left = authority(logical.clone(), Uuid::now_v7());
    let right = authority(logical, Uuid::now_v7());
    let (left, right) = tokio::join!(
        repository.publish(left, Some(initial.cas_version)),
        repository.publish(right, Some(initial.cas_version)),
    );
    assert_ne!(left.is_ok(), right.is_ok());
}

#[tokio::test]
async fn placement_migration_never_advances_before_both_targets_are_ready() {
    let repository = InMemoryManagedRepository::new();
    let logical = LogicalObjectKey::new("tenant", "bucket", "placement-legs");
    let mut initial = authority(logical.clone(), Uuid::now_v7());
    initial.replica_status = CopyStatus::Ready;
    let initial = repository.publish(initial, None).await.unwrap();
    let placement = Placement {
        version: initial.placement_version + 1,
        primary_backend_id: "c".to_string(),
        replica_backend_id: Some("d".to_string()),
    };
    repository
        .enqueue(RepairRecord::placement(
            &initial,
            Some("a".to_string()),
            "c".to_string(),
            RepairTargetRole::Primary,
            &placement,
        ))
        .await
        .unwrap();
    repository
        .enqueue(RepairRecord::placement(
            &initial,
            Some("a".to_string()),
            "d".to_string(),
            RepairTargetRole::Replica,
            &placement,
        ))
        .await
        .unwrap();
    let mut repairs = repository
        .claim_repairs(
            "placement-worker",
            crate::transaction::unix_time_ms() + 30_000,
            2,
        )
        .await
        .unwrap();
    let primary = repairs
        .iter()
        .position(|repair| repair.target_role == RepairTargetRole::Primary)
        .map(|index| repairs.swap_remove(index))
        .unwrap();
    let replica = repairs.pop().unwrap();

    repository.complete_repair(&primary).await.unwrap();
    let partial = repository.get(&logical).await.unwrap().unwrap();
    assert_eq!(partial.primary_backend_id, "c");
    assert_eq!(partial.replica_backend_id.as_deref(), Some("b"));
    assert_eq!(partial.placement_version, initial.placement_version);

    assert!(
        !repository.complete_repair(&replica).await.unwrap(),
        "a leg leased before another leg's CAS update must not mutate authority"
    );
    repository
        .enqueue(RepairRecord::placement(
            &partial,
            Some("c".to_string()),
            "d".to_string(),
            RepairTargetRole::Replica,
            &placement,
        ))
        .await
        .unwrap();
    let retry = repository
        .claim_repairs(
            "placement-worker",
            crate::transaction::unix_time_ms() + 30_000,
            1,
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(repository.complete_repair(&retry).await.unwrap());
    let converged = repository.get(&logical).await.unwrap().unwrap();
    assert_eq!(converged.primary_backend_id, "c");
    assert_eq!(converged.replica_backend_id.as_deref(), Some("d"));
    assert_eq!(converged.placement_version, placement.version);
    let cleanup = repository
        .claim_repairs("cleanup", crate::transaction::unix_time_ms() + 30_000, 10)
        .await
        .unwrap();
    assert_eq!(cleanup.len(), 2);
    assert!(cleanup.iter().all(|repair| {
        repair.kind == RepairKind::DeleteGeneration
            && repair.target_role == RepairTargetRole::Cleanup
            && matches!(repair.target_backend_id.as_str(), "a" | "b")
    }));
}

#[tokio::test]
async fn concurrent_placement_repair_completions_fence_stale_legs() {
    let repository = InMemoryManagedRepository::new();
    let logical = LogicalObjectKey::new("tenant", "bucket", "placement-race");
    let mut initial = authority(logical.clone(), Uuid::now_v7());
    initial.replica_status = CopyStatus::Ready;
    let initial = repository.publish(initial, None).await.unwrap();
    let placement = Placement {
        version: initial.placement_version + 1,
        primary_backend_id: "c".to_string(),
        replica_backend_id: Some("d".to_string()),
    };
    for (target_backend_id, target_role) in [
        ("c".to_string(), RepairTargetRole::Primary),
        ("d".to_string(), RepairTargetRole::Replica),
    ] {
        repository
            .enqueue(RepairRecord::placement(
                &initial,
                Some("a".to_string()),
                target_backend_id,
                target_role,
                &placement,
            ))
            .await
            .unwrap();
    }
    let repairs = repository
        .claim_repairs(
            "placement-workers",
            crate::transaction::unix_time_ms() + 30_000,
            2,
        )
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        repository.complete_repair(&repairs[0]),
        repository.complete_repair(&repairs[1]),
    );
    assert_ne!(left.unwrap(), right.unwrap());
    let partial = repository.get(&logical).await.unwrap().unwrap();
    let (target_backend_id, target_role) = if partial.primary_backend_id == "c" {
        ("d".to_string(), RepairTargetRole::Replica)
    } else {
        ("c".to_string(), RepairTargetRole::Primary)
    };
    repository
        .enqueue(RepairRecord::placement(
            &partial,
            Some(partial.primary_backend_id.clone()),
            target_backend_id,
            target_role,
            &placement,
        ))
        .await
        .unwrap();
    let retry = repository
        .claim_repairs(
            "placement-retry",
            crate::transaction::unix_time_ms() + 30_000,
            1,
        )
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(repository.complete_repair(&retry).await.unwrap());
    let converged = repository.get(&logical).await.unwrap().unwrap();
    assert_eq!(converged.primary_backend_id, "c");
    assert_eq!(converged.replica_backend_id.as_deref(), Some("d"));
    assert_eq!(converged.placement_version, placement.version);
}

#[tokio::test]
async fn repair_lease_renewal_extends_only_the_current_fence() {
    let repository = InMemoryManagedRepository::new();
    let logical = LogicalObjectKey::new("tenant", "bucket", "lease-renewal");
    let pending = repository
        .publish(authority(logical, Uuid::now_v7()), None)
        .await
        .unwrap();
    let claim = repository
        .claim_repairs("worker-a", crate::transaction::unix_time_ms() + 1_000, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(
        repository
            .renew_repair(Uuid::now_v7(), crate::transaction::unix_time_ms() + 60_000)
            .await
            .is_err()
    );
    repository
        .renew_repair(claim.id, crate::transaction::unix_time_ms() + 60_000)
        .await
        .unwrap();
    assert!(
        repository
            .claim_repairs("worker-b", crate::transaction::unix_time_ms() + 60_000, 1)
            .await
            .unwrap()
            .is_empty()
    );
    repository.complete_repair(&claim).await.unwrap();

    let current = repository.get(&pending.logical).await.unwrap().unwrap();
    repository
        .enqueue(RepairRecord::copy(
            RepairKind::Replica,
            &current,
            Some("a".to_string()),
            "b".to_string(),
            RepairTargetRole::Replica,
            current.placement_version,
        ))
        .await
        .unwrap();
    let expired = repository
        .claim_repairs("worker-c", crate::transaction::unix_time_ms() - 1, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(
        repository
            .renew_repair(expired.id, crate::transaction::unix_time_ms() + 60_000)
            .await
            .is_err()
    );
    assert_eq!(
        repository
            .claim_repairs("worker-d", crate::transaction::unix_time_ms() + 60_000, 1)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn global_placement_pages_are_ordered_resumable_and_exclude_tombstones() {
    let repository = InMemoryManagedRepository::new();
    for (tenant, bucket, key, version, tombstone) in [
        ("a", "b", "one", 1, false),
        ("a", "b", "two", 1, false),
        ("b", "a", "one", 1, false),
        ("b", "a", "tombstone", 1, true),
        ("z", "z", "current", 2, false),
    ] {
        let mut object = authority(LogicalObjectKey::new(tenant, bucket, key), Uuid::now_v7());
        object.placement_version = version;
        object.tombstone = tombstone;
        repository.publish(object, None).await.unwrap();
    }
    let first = repository
        .list_authority_below_placement_version(AuthorityPlacementPageQuery {
            target_placement_version: 2,
            after: None,
            limit: 2,
        })
        .await
        .unwrap();
    assert_eq!(
        first
            .objects
            .iter()
            .map(|object| object.logical.key.as_str())
            .collect::<Vec<_>>(),
        ["one", "two"]
    );
    let second = repository
        .list_authority_below_placement_version(AuthorityPlacementPageQuery {
            target_placement_version: 2,
            after: first.next_after.clone(),
            limit: 2,
        })
        .await
        .unwrap();
    assert_eq!(
        second
            .objects
            .iter()
            .map(|object| object.logical.tenant_id.as_str())
            .collect::<Vec<_>>(),
        ["b"]
    );
    assert!(second.next_after.is_none());
}

#[tokio::test]
async fn placement_advance_requires_current_cas_and_ready_locations() {
    let repository = InMemoryManagedRepository::new();
    let logical = LogicalObjectKey::new("tenant", "bucket", "key");
    let mut object = authority(logical.clone(), Uuid::now_v7());
    object.replica_status = CopyStatus::Ready;
    let published = repository.publish(object, None).await.unwrap();
    let desired = Placement {
        version: 2,
        primary_backend_id: "a".to_string(),
        replica_backend_id: Some("b".to_string()),
    };
    let advanced = repository
        .advance_placement_version(&logical, published.cas_version, &desired)
        .await
        .unwrap();
    assert_eq!(advanced.placement_version, 2);
    assert!(matches!(
        repository
            .advance_placement_version(
                &logical,
                published.cas_version,
                &Placement {
                    version: 3,
                    primary_backend_id: "a".to_string(),
                    replica_backend_id: Some("b".to_string())
                }
            )
            .await,
        Err(ManagedError::Conflict)
    ));
}

#[tokio::test]
async fn authority_placement_stats_counts_stale_and_reports_oldest() {
    let repository = InMemoryManagedRepository::new();
    for (key, version, tombstone) in [
        ("stale", 1, false),
        ("oldest", 1, false),
        ("current", 2, false),
        ("tombstone", 1, true),
    ] {
        let mut object = authority(
            LogicalObjectKey::new("stats", "bucket", key),
            Uuid::now_v7(),
        );
        object.placement_version = version;
        object.tombstone = tombstone;
        object.replica_status = CopyStatus::Ready;
        repository.publish(object, None).await.unwrap();
    }
    {
        let mut state = repository.state.lock().await;
        state
            .authorities
            .get_mut(&LogicalObjectKey::new("stats", "bucket", "stale"))
            .unwrap()
            .updated_at_ms = 100;
        state
            .authorities
            .get_mut(&LogicalObjectKey::new("stats", "bucket", "oldest"))
            .unwrap()
            .updated_at_ms = 40;
        state
            .authorities
            .get_mut(&LogicalObjectKey::new("stats", "bucket", "current"))
            .unwrap()
            .updated_at_ms = 5;
        state
            .authorities
            .get_mut(&LogicalObjectKey::new("stats", "bucket", "tombstone"))
            .unwrap()
            .updated_at_ms = 1;
    }

    let stats = repository.authority_placement_stats(2).await.unwrap();
    assert_eq!(stats.remaining, 2);
    assert_eq!(stats.oldest_updated_at_ms, Some(40));
    assert!(matches!(
        repository.authority_placement_stats(0).await,
        Err(ManagedError::Conflict)
    ));
}

#[tokio::test]
async fn repair_state_counts_groups_pending_leased_and_dead() {
    let repository = InMemoryManagedRepository::new();
    let mut object = authority(
        LogicalObjectKey::new("repair-counts", "bucket", "key"),
        Uuid::now_v7(),
    );
    object.replica_status = CopyStatus::Ready;
    let published = repository.publish(object, None).await.unwrap();

    {
        let mut state = repository.state.lock().await;
        for target in ["a", "b", "c"] {
            let mut repair = RepairRecord::copy(
                RepairKind::Replica,
                &published,
                Some(published.primary_backend_id.clone()),
                target.to_string(),
                RepairTargetRole::Replica,
                published.placement_version,
            );
            repair.generation = Uuid::now_v7();
            insert_memory_repair(&mut state, repair);
        }
        let statuses = ["PENDING", "LEASED", "DEAD"];
        for ((_, status), wanted) in state.repairs.values_mut().zip(statuses) {
            *status = wanted.to_string();
        }
    }

    assert_eq!(
        repository.repair_state_counts().await.unwrap(),
        RepairStateCounts {
            pending: 1,
            leased: 1,
            dead: 1
        }
    );
}
