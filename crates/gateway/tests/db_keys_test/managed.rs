use super::*;

#[test]
fn physical_intent_duplicate_contract_matches_memory_and_postgres() {
    with_pool(|pool| async move {
        let tenant = format!("physical-contract-{}", uuid::Uuid::new_v4());
        assert_physical_intent_duplicate_contract(
            &InMemoryManagedRepository::new(),
            "physical-contract-memory",
        )
        .await;
        assert_physical_intent_duplicate_contract(
            &PostgresManagedRepository::new(pool.clone()),
            &tenant,
        )
        .await;

        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&sea_db(pool))
            .await
            .unwrap();
    });
}

#[test]
fn postgres_namespace_purge_fences_late_writes_and_completes_idempotently() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let journal = PostgresOperationJournal::new(pool.clone());
        let repository = PostgresManagedRepository::new(pool.clone());
        let tenant = format!("purge-unit-{}", uuid::Uuid::new_v4());
        let intent_id = uuid::Uuid::now_v7();
        let physical_intent = test_physical_intent(
            intent_id,
            &tenant,
            "provider:bucket",
            "bucket",
            "managed/physical-key",
            "db-test-writer",
        );
        let lease = repository
            .begin_physical_write(physical_intent.clone())
            .await
            .unwrap();
        let duplicate = repository
            .begin_physical_write(physical_intent.clone())
            .await
            .unwrap();
        assert_eq!(duplicate, lease);
        assert!(matches!(
            repository
                .begin_physical_write(PhysicalWriteIntent {
                    physical_key: "managed/different-key".to_string(),
                    ..physical_intent
                })
                .await,
            Err(maskura_gateway::managed::ManagedError::RecoveryBlocked(
                "physical_intent_mismatch"
            ))
        ));
        journal
            .insert_intent(OperationRecord::scoped_intent(
                intent_id,
                ObjectDestination {
                    backend_id: "provider:bucket".to_string(),
                    bucket: "bucket".to_string(),
                    logical_key: "bucket/key".to_string(),
                    physical_key: "managed/physical-key".to_string(),
                    workspace_binding: None,
                },
                ExpectedObject::default(),
                tenant.clone(),
                lease.namespace_epoch,
            ))
            .await
            .unwrap();
        journal.set_open(intent_id, None).await.unwrap();
        journal
            .transition(
                intent_id,
                OperationState::Open,
                OperationState::Completing,
                None,
            )
            .await
            .unwrap();
        let unresolved_operation_id = uuid::Uuid::now_v7();
        journal
            .insert_intent(OperationRecord::scoped_intent(
                unresolved_operation_id,
                ObjectDestination {
                    backend_id: "provider:bucket".to_string(),
                    bucket: "bucket".to_string(),
                    logical_key: "bucket/unresolved".to_string(),
                    physical_key: "managed/unresolved".to_string(),
                    workspace_binding: None,
                },
                ExpectedObject::default(),
                tenant.clone(),
                lease.namespace_epoch,
            ))
            .await
            .unwrap();
        journal
            .transition(
                intent_id,
                OperationState::Completing,
                OperationState::Committed,
                Some(&StoredObjectMeta {
                    etag: Some("etag".to_string()),
                    version_id: Some("version-2".to_string()),
                    superseded_version_ids: vec!["version-1".to_string()],
                    version_history_complete: true,
                }),
            )
            .await
            .unwrap();
        let request = NamespacePurgeRequest {
            tenant_id: tenant.clone(),
            operation_id: uuid::Uuid::now_v7(),
        };

        assert_eq!(
            repository.purge_namespace(&request).await.unwrap(),
            NamespacePurgeStatus::Running,
            "the pre-fence write intent prevents false completion"
        );
        assert!(matches!(
            repository.assert_namespace_active(&tenant).await,
            Err(maskura_gateway::managed::ManagedError::NamespaceFenced)
        ));
        assert!(matches!(
            repository
                .begin_physical_write(test_physical_intent(
                    uuid::Uuid::now_v7(),
                    &tenant,
                    "provider:bucket",
                    "bucket",
                    "must-not-start",
                    "stale-writer",
                ))
                .await,
            Err(maskura_gateway::managed::ManagedError::NamespaceFenced)
        ));

        repository
            .commit_physical_write(&lease, &["version-1".to_string()], Some("version-2"))
            .await
            .unwrap();
        let targets = repository.purge_targets(&request, 10).await.unwrap();
        assert_eq!(targets.len(), 2);
        for target in targets {
            repository
                .mark_purge_target_deleted(&request, &target)
                .await
                .unwrap();
        }
        assert!(matches!(
            repository.namespace_purge_status(&request).await.unwrap(),
            NamespacePurgeStatus::Blocked { reason }
                if reason.contains("unresolved operation journal")
        ));
        journal
            .transition(
                unresolved_operation_id,
                OperationState::Intent,
                OperationState::Aborting,
                None,
            )
            .await
            .unwrap();
        journal
            .transition(
                unresolved_operation_id,
                OperationState::Aborting,
                OperationState::ProvenAborted,
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            repository.namespace_purge_status(&request).await.unwrap(),
            NamespacePurgeStatus::Complete {
                deleted_versions: 2,
            }
        );
        assert_eq!(
            repository.purge_namespace(&request).await.unwrap(),
            NamespacePurgeStatus::Complete {
                deleted_versions: 2,
            },
            "restarting the same purge operation is idempotent"
        );
        repository
            .assert_namespace_active(&tenant)
            .await
            .expect("completion reactivates an empty next epoch");
        assert!(journal.get(intent_id).await.unwrap().is_none());
        assert!(
            journal
                .get(unresolved_operation_id)
                .await
                .unwrap()
                .is_none()
        );

        managed_namespace_purge::Entity::delete_many()
            .filter(managed_namespace_purge::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
    });
}

#[test]
fn postgres_global_authority_placement_page_has_stable_boundaries() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = PostgresManagedRepository::new(pool);
        let tenant = format!("managed-placement-page-{}", uuid::Uuid::new_v4());
        for key in ["a", "b", "c"] {
            let logical = LogicalObjectKey::new(&tenant, "bucket", key);
            let generation = uuid::Uuid::now_v7();
            let version = ledger_managed_test_version(
                &repository,
                &tenant,
                "primary",
                &generation_physical_key(&logical, generation),
            )
            .await;
            repository
                .publish(
                    ObjectAuthority {
                        logical,
                        generation,
                        digest: "digest".to_string(),
                        size: 3,
                        metadata: std::collections::BTreeMap::new(),
                        placement_version: 1,
                        primary_backend_id: "primary".to_string(),
                        primary_version_id: Some(version),
                        replica_backend_id: None,
                        primary_status: CopyStatus::Ready,
                        replica_status: CopyStatus::Absent,
                        tombstone: false,
                        cas_version: 0,
                        created_at_ms: 0,
                        updated_at_ms: 0,
                    },
                    None,
                )
                .await
                .unwrap();
        }
        let first = repository
            .list_authority_below_placement_version(AuthorityPlacementPageQuery {
                target_placement_version: 2,
                after: None,
                limit: 2,
            })
            .await
            .unwrap();
        assert_eq!(first.objects.len(), 2);
        let second = repository
            .list_authority_below_placement_version(AuthorityPlacementPageQuery {
                target_placement_version: 2,
                after: first.next_after,
                limit: 2,
            })
            .await
            .unwrap();
        assert_eq!(second.objects.len(), 1);

        // This global-page test must not leave stale placement candidates for
        // later router tests sharing the same Postgres database.
        managed_object_authority::Entity::delete_many()
            .filter(managed_object_authority::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_physical_object_version::Entity::delete_many()
            .filter(managed_physical_object_version::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
    });
}

#[test]
fn postgres_managed_authority_publish_repair_lease_and_tombstone_are_atomic() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = PostgresManagedRepository::new(pool);
        let tenant = format!("managed-unit-{}", uuid::Uuid::new_v4());
        let logical = LogicalObjectKey::new(&tenant, "bucket", "path/to/key");
        let generation = uuid::Uuid::now_v7();
        let primary_version_id = ledger_managed_test_version(
            &repository,
            &tenant,
            "primary",
            &maskura_gateway::managed::generation_physical_key(&logical, generation),
        )
        .await;
        let authority = ObjectAuthority {
            logical: logical.clone(),
            generation,
            digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string(),
            size: 3,
            metadata: std::collections::BTreeMap::from([(
                "content-type".to_string(),
                "text/plain".to_string(),
            )]),
            placement_version: 1,
            primary_backend_id: "primary".to_string(),
            primary_version_id: Some(primary_version_id),
            replica_backend_id: Some("replica".to_string()),
            primary_status: CopyStatus::Ready,
            replica_status: CopyStatus::RepairPending,
            tombstone: false,
            cas_version: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        };

        let published = repository.publish(authority.clone(), None).await.unwrap();
        assert_eq!(published.cas_version, 1);
        let persisted = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(persisted.generation, generation);
        assert_eq!(persisted.replica_status, CopyStatus::RepairPending);
        assert_eq!(
            managed_object_repair::Entity::find()
                .filter(managed_object_repair::Column::TenantId.eq(&tenant))
                .all(&db)
                .await
                .unwrap()
                .len(),
            1,
            "authority and replica repair publish in one transaction"
        );

        assert!(
            repository.publish(authority.clone(), None).await.is_err(),
            "create CAS cannot overwrite authority"
        );
        let expired_lease = unix_time_ms() - 1;
        let first_claim = repository
            .claim_repairs("process-before-restart", expired_lease, 10)
            .await
            .unwrap();
        assert_eq!(first_claim.len(), 1);
        let restarted_claim = repository
            .claim_repairs("process-after-restart", unix_time_ms() + 30_000, 10)
            .await
            .unwrap();
        assert_eq!(restarted_claim.len(), 1);
        assert!(
            repository
                .renew_repair(uuid::Uuid::now_v7(), unix_time_ms() + 60_000)
                .await
                .is_err()
        );
        repository
            .renew_repair(restarted_claim[0].id, unix_time_ms() + 60_000)
            .await
            .unwrap();
        assert!(
            repository
                .claim_repairs("process-during-heartbeat", unix_time_ms() + 30_000, 10)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(repository.complete_repair(&first_claim[0]).await.is_err());
        assert!(
            repository
                .fail_repair(first_claim[0].id, "stale process")
                .await
                .is_err()
        );
        let _ = ledger_managed_test_version(
            &repository,
            &tenant,
            &restarted_claim[0].target_backend_id,
            &restarted_claim[0].physical_key,
        )
        .await;
        assert!(
            repository
                .complete_repair(&restarted_claim[0])
                .await
                .unwrap()
        );
        let current_after_repair = repository.get(&logical).await.unwrap().unwrap();
        repository
            .enqueue(maskura_gateway::managed::RepairRecord::copy(
                maskura_gateway::managed::RepairKind::Replica,
                &current_after_repair,
                Some(current_after_repair.primary_backend_id.clone()),
                current_after_repair
                    .replica_backend_id
                    .clone()
                    .expect("replica backend"),
                maskura_gateway::managed::RepairTargetRole::Replica,
                current_after_repair.placement_version,
            ))
            .await
            .expect("completed repair can be re-enqueued without poisoning the transaction");
        let requeued = repository
            .claim_repairs("process-requeued", unix_time_ms() + 30_000, 10)
            .await
            .unwrap();
        assert_eq!(requeued.len(), 1);
        repository.complete_repair(&requeued[0]).await.unwrap();
        let repaired = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(repaired.replica_status, CopyStatus::Ready);

        let replica_placement = Placement {
            version: repaired.placement_version + 1,
            primary_backend_id: "primary".to_string(),
            replica_backend_id: Some("replica-v2".to_string()),
        };
        repository
            .enqueue(maskura_gateway::managed::RepairRecord::placement(
                &repaired,
                Some("primary".to_string()),
                "replica-v2".to_string(),
                maskura_gateway::managed::RepairTargetRole::Replica,
                &replica_placement,
            ))
            .await
            .unwrap();
        let replica_migration = repository
            .claim_repairs("process-replica-migration", unix_time_ms() + 30_000, 10)
            .await
            .unwrap();
        assert_eq!(replica_migration.len(), 1);
        let _ = ledger_managed_test_version(
            &repository,
            &tenant,
            &replica_migration[0].target_backend_id,
            &replica_migration[0].physical_key,
        )
        .await;
        assert!(
            repository
                .complete_repair(&replica_migration[0])
                .await
                .unwrap()
        );
        let migrated = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(migrated.primary_backend_id, "primary");
        assert_eq!(migrated.replica_backend_id.as_deref(), Some("replica-v2"));
        assert_eq!(migrated.placement_version, repaired.placement_version + 1);

        let full_placement = Placement {
            version: migrated.placement_version + 1,
            primary_backend_id: "primary-v3".to_string(),
            replica_backend_id: Some("replica-v3".to_string()),
        };
        for (target_backend_id, target_role) in [
            (
                full_placement.primary_backend_id.clone(),
                maskura_gateway::managed::RepairTargetRole::Primary,
            ),
            (
                full_placement.replica_backend_id.clone().unwrap(),
                maskura_gateway::managed::RepairTargetRole::Replica,
            ),
        ] {
            repository
                .enqueue(maskura_gateway::managed::RepairRecord::placement(
                    &migrated,
                    Some("primary".to_string()),
                    target_backend_id,
                    target_role,
                    &full_placement,
                ))
                .await
                .unwrap();
        }
        let migration_repairs = repository
            .claim_repairs("process-placement-race", unix_time_ms() + 30_000, 10)
            .await
            .unwrap();
        // A prior completed placement may have released cleanup work as well;
        // only its two placement legs participate in this cutover race.
        let (placement_repairs, cleanup_repairs): (Vec<_>, Vec<_>) = migration_repairs
            .into_iter()
            .partition(|repair| repair.kind == maskura_gateway::managed::RepairKind::Placement);
        assert_eq!(placement_repairs.len(), 2);
        for repair in cleanup_repairs {
            assert!(!repository.complete_repair(&repair).await.unwrap());
        }
        for repair in &placement_repairs {
            let _ = ledger_managed_test_version(
                &repository,
                &tenant,
                &repair.target_backend_id,
                &repair.physical_key,
            )
            .await;
        }
        let (left, right) = tokio::join!(
            repository.complete_repair(&placement_repairs[0]),
            repository.complete_repair(&placement_repairs[1]),
        );
        assert_ne!(left.unwrap(), right.unwrap());
        let partial = repository.get(&logical).await.unwrap().unwrap();
        let (target_backend_id, target_role) = if partial.primary_backend_id == "primary-v3" {
            (
                "replica-v3".to_string(),
                maskura_gateway::managed::RepairTargetRole::Replica,
            )
        } else {
            (
                "primary-v3".to_string(),
                maskura_gateway::managed::RepairTargetRole::Primary,
            )
        };
        repository
            .enqueue(maskura_gateway::managed::RepairRecord::placement(
                &partial,
                Some(partial.primary_backend_id.clone()),
                target_backend_id.clone(),
                target_role,
                &full_placement,
            ))
            .await
            .unwrap();
        let retry_claims = repository
            .claim_repairs("process-placement-retry", unix_time_ms() + 30_000, 10)
            .await
            .unwrap();
        let retry = retry_claims
            .iter()
            .find(|repair| {
                repair.kind == maskura_gateway::managed::RepairKind::Placement
                    && repair.target_backend_id == target_backend_id
            })
            .unwrap()
            .clone();
        for cleanup in retry_claims.iter().filter(|repair| repair.id != retry.id) {
            repository
                .fail_repair(cleanup.id, "defer cleanup during placement retry")
                .await
                .unwrap();
        }
        assert!(repository.complete_repair(&retry).await.unwrap());
        let converged = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(converged.primary_backend_id, "primary-v3");
        assert_eq!(converged.replica_backend_id.as_deref(), Some("replica-v3"));
        assert_eq!(converged.placement_version, full_placement.version);

        let tombstone = repository
            .tombstone(
                &logical,
                Some(converged.cas_version),
                &Placement {
                    version: 1,
                    primary_backend_id: "primary".to_string(),
                    replica_backend_id: Some("replica".to_string()),
                },
            )
            .await
            .unwrap();
        assert!(tombstone.tombstone);
        assert_ne!(tombstone.generation, generation);
        assert!(
            repository
                .publish(authority, Some(published.cas_version))
                .await
                .is_err(),
            "stale update cannot resurrect a tombstoned generation"
        );
        let cleanup_count = managed_object_repair::Entity::find()
            .filter(managed_object_repair::Column::TenantId.eq(&tenant))
            .filter(managed_object_repair::Column::Kind.eq("DELETE_GENERATION"))
            .all(&db)
            .await
            .unwrap()
            .len();
        managed_object_repair::Entity::delete_many()
            .filter(managed_object_repair::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_object_authority::Entity::delete_many()
            .filter(managed_object_authority::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_physical_object_version::Entity::delete_many()
            .filter(managed_physical_object_version::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();

        // Cleanup precedes the assertion so a future expectation mismatch
        // cannot contaminate later tests sharing this database.
        assert_eq!(cleanup_count, 5);
    });
}

#[test]
fn postgres_managed_logical_quota_listing_cursor_and_release_contract() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = PostgresManagedRepository::new(pool.clone());
        let tenant = format!("managed-logical-unit-{}", uuid::Uuid::new_v4());
        let logical = LogicalObjectKey::new(&tenant, "bucket", "prefix%/key");
        let generation = uuid::Uuid::now_v7();
        let fence = repository.route_fence(&tenant).await.unwrap();
        assert_eq!(
            fence,
            ManagedRouteFence {
                namespace_epoch: 1,
                routing_epoch: 1
            }
        );
        let intent = ManagedLogicalOperationIntent {
            operation_id: uuid::Uuid::now_v7(),
            receipt_id: uuid::Uuid::now_v7(),
            logical: logical.clone(),
            kind: ManagedMutationKind::Put,
            generation,
            fence,
            expected_authority_cas: None,
            prior_logical_size: 0,
            primary_child_operation_id: uuid::Uuid::now_v7(),
            backend_id: "primary".to_string(),
            provider_bucket: "provider-bucket".to_string(),
            physical_key: generation_physical_key(&logical, generation),
            occurred_at_ms: unix_time_ms(),
            rate_version: 7,
            route: UsageRoute::PutObject,
            request_kind: RequestKind::Write,
            max_processed_bytes: 64,
            publication_recipe: Some(publication_recipe("primary")),
        };
        let mut concurrent = intent.clone();
        concurrent.operation_id = uuid::Uuid::now_v7();
        concurrent.receipt_id = uuid::Uuid::now_v7();
        concurrent.logical = LogicalObjectKey::new(&tenant, "bucket", "other");
        concurrent.generation = uuid::Uuid::now_v7();
        concurrent.primary_child_operation_id = uuid::Uuid::now_v7();
        concurrent.physical_key =
            generation_physical_key(&concurrent.logical, concurrent.generation);

        let inserted = repository
            .insert_logical_operation(intent.clone())
            .await
            .unwrap();
        assert_eq!(inserted.intent, intent);
        assert_eq!(
            repository
                .insert_logical_operation(intent.clone())
                .await
                .unwrap()
                .intent,
            intent
        );
        assert!(
            managed_logical_operation::Entity::update_many()
                .col_expr(
                    managed_logical_operation::Column::RateVersion,
                    Expr::value(intent.rate_version + 1),
                )
                .filter(managed_logical_operation::Column::OperationId.eq(intent.operation_id),)
                .exec(&db)
                .await
                .is_err(),
            "canonical pricing identity must be database-immutable"
        );
        assert_eq!(
            repository
                .logical_operation(intent.operation_id)
                .await
                .unwrap()
                .unwrap()
                .intent
                .rate_version,
            intent.rate_version
        );
        repository
            .insert_logical_operation(concurrent.clone())
            .await
            .unwrap();
        let child = PhysicalWriteIntent {
            intent_id: intent.primary_child_operation_id,
            tenant_id: tenant.clone(),
            backend_id: intent.backend_id.clone(),
            storage_identity: test_storage_identity(),
            credential_epoch: 1,
            provider_bucket: intent.provider_bucket.clone(),
            physical_key: intent.physical_key.clone(),
            versioning_mode: BackendVersioningMode::Enabled,
            versioning_capability: BackendVersioningCapability::Required,
            lease_owner: "logical-db-test".to_string(),
        };
        assert!(
            repository
                .begin_physical_write(child.clone())
                .await
                .is_err()
        );
        repository
            .reserve_logical_operation(intent.operation_id, 6)
            .await
            .unwrap();
        assert!(matches!(
            repository
                .reserve_logical_operation(concurrent.operation_id, 1)
                .await,
            Err(maskura_gateway::managed::ManagedError::MutationInProgress)
        ));
        let lease = repository.begin_physical_write(child).await.unwrap();
        assert_eq!(
            repository
                .insert_logical_operation(intent.clone())
                .await
                .unwrap()
                .intent,
            intent,
            "parent insertion must remain idempotent after child creation"
        );
        repository
            .record_logical_usage(
                intent.operation_id,
                ManagedUsageEvidence {
                    expected_output_digest: Some("digest".to_string()),
                    expected_output_size: 3,
                    source_bytes: 3,
                    processed_bytes: 3,
                    payload: serde_json::json!({"immutable": true}),
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
        assert!(matches!(
            repository
                .finalize_logical_put(
                    intent.operation_id,
                    &lease,
                    ExactPhysicalCommit {
                        selected_version_id: Some("committed-version".to_string()),
                        superseded_version_ids: vec!["ambiguous-retry-version".to_string()],
                        version_history_complete: false,
                    },
                    None,
                )
                .await,
            Err(maskura_gateway::managed::ManagedError::RecoveryBlocked(
                "invalid_exact_version_history"
            ))
        ));
        let exact_commit = ExactPhysicalCommit {
            selected_version_id: Some("committed-version".to_string()),
            superseded_version_ids: vec!["ambiguous-retry-version".to_string()],
            version_history_complete: true,
        };
        assert!(matches!(
            repository
                .finalize_logical_put(
                    intent.operation_id,
                    &lease,
                    ExactPhysicalCommit {
                        selected_version_id: None,
                        superseded_version_ids: Vec::new(),
                        version_history_complete: true,
                    },
                    None,
                )
                .await,
            Err(maskura_gateway::managed::ManagedError::RecoveryBlocked(
                "physical_versioning_contract_mismatch"
            ))
        ));
        assert!(matches!(
            repository
                .finalize_logical_put(intent.operation_id, &lease, exact_commit.clone(), None,)
                .await,
            Err(maskura_gateway::managed::ManagedError::RecoveryBlocked(
                "missing_child_journal"
            ))
        ));
        insert_committed_child(&pool, &intent, "digest", 3, &exact_commit).await;
        let committed = repository
            .finalize_logical_put(intent.operation_id, &lease, exact_commit.clone(), None)
            .await
            .unwrap();
        assert_eq!(committed.operation.intent.receipt_id, intent.receipt_id);
        assert_eq!(committed.operation.intent.rate_version, 7);
        assert_eq!(committed.usage.visible_logical_bytes, 3);
        assert_eq!(committed.usage.physical_allocated_bytes, 6);
        assert_eq!(committed.usage.reserved_bytes, 0);
        assert_eq!(committed.usage.active_operation_id, None);
        repository
            .finalize_logical_put(intent.operation_id, &lease, exact_commit.clone(), None)
            .await
            .unwrap();
        managed_object_authority::Entity::insert(managed_object_authority::ActiveModel {
            tenant_id: Set(tenant.clone()),
            bucket: Set("bucket".to_string()),
            logical_key: Set("prefixX/key".to_string()),
            generation: Set(uuid::Uuid::now_v7()),
            digest: Set("other".to_string()),
            size_bytes: Set(1),
            metadata: Set(serde_json::json!({})),
            placement_version: Set(1),
            primary_backend_id: Set("primary".to_string()),
            primary_version_id: Set(Some("other-version".to_string())),
            replica_backend_id: Set(None),
            primary_status: Set("READY".to_string()),
            replica_status: Set("ABSENT".to_string()),
            tombstone: Set(false),
            cas_version: Set(1),
            created_at_ms: Set(0),
            updated_at_ms: Set(0),
        })
        .exec(&db)
        .await
        .unwrap();
        let listed = repository
            .list_authority(AuthorityListQuery {
                tenant_id: tenant.clone(),
                bucket: "bucket".to_string(),
                prefix: "prefix%".to_string(),
                after: None,
                max_keys: 10,
            })
            .await
            .unwrap();
        assert_eq!(
            listed.objects.len(),
            1,
            "SQL wildcard bytes must stay literal"
        );
        assert_eq!(listed.objects[0].logical, logical);

        let now = unix_time_ms();
        let binding = ManagedListCursorBinding {
            tenant_id: tenant.clone(),
            bucket: "bucket".to_string(),
            prefix: "prefix%".to_string(),
            delimiter: Some("/".to_string()),
            version: ManagedListVersion::V2,
        };
        let cursor = repository
            .create_list_cursor(
                ManagedListCursorRequest {
                    binding: binding.clone(),
                    position: ManagedListCursorPosition {
                        last_key: Some("prefix%/key".to_string()),
                        last_common_prefix: None,
                    },
                    response_state: serde_json::json!({"keys": ["prefix%/key"]}),
                    final_page: false,
                },
                now,
            )
            .await
            .unwrap();
        assert_eq!(cursor.fence, fence);
        assert_eq!(
            cursor.response_state_bytes,
            serde_json::to_vec(&cursor.response_state).unwrap().len() as u64
        );
        assert!(matches!(
            repository
                .create_list_cursor(
                    ManagedListCursorRequest {
                        binding: binding.clone(),
                        position: ManagedListCursorPosition {
                            last_key: None,
                            last_common_prefix: None,
                        },
                        response_state: serde_json::Value::String(
                            "x".repeat(MANAGED_LIST_CURSOR_RESPONSE_MAX_BYTES as usize),
                        ),
                        final_page: false,
                    },
                    now,
                )
                .await,
            Err(maskura_gateway::managed::ManagedError::CursorLimitExceeded)
        ));
        let oversized_bytes = vec![b'x'; MANAGED_LIST_CURSOR_RESPONSE_MAX_BYTES as usize + 1];
        assert!(
            managed_list_cursor::Entity::insert(managed_list_cursor::ActiveModel {
                cursor_id: Set(uuid::Uuid::new_v4()),
                predecessor_cursor_id: Set(None),
                tenant_id: Set(tenant.clone()),
                namespace_epoch: Set(fence.namespace_epoch as i64),
                routing_epoch: Set(fence.routing_epoch as i64),
                bucket: Set("bucket".to_string()),
                prefix: Set(String::new()),
                delimiter: Set(None),
                list_version: Set("V2".to_string()),
                last_key: Set(None),
                last_common_prefix: Set(None),
                response_state: Set(oversized_bytes.clone()),
                response_state_bytes: Set(oversized_bytes.len() as i64),
                final_page: Set(false),
                state: Set("ACTIVE".to_string()),
                created_at_ms: Set(now),
                expires_at_ms: Set(now + 60_000),
                first_used_at_ms: Set(None),
            })
            .exec(&db)
            .await
            .is_err(),
            "database cursor payload cap must reject direct oversized inserts"
        );
        let used = repository
            .use_list_cursor(cursor.id, &binding, now + 1)
            .await
            .unwrap();
        let replay = repository
            .use_list_cursor(cursor.id, &binding, now + 2)
            .await
            .unwrap();
        assert_eq!(used.state, ManagedListCursorState::Used);
        assert_eq!(replay.first_used_at_ms, used.first_used_at_ms);
        assert_eq!(replay.response_state, used.response_state);
        repository
            .advance_routing_epoch(&tenant, fence.routing_epoch)
            .await
            .unwrap();
        assert!(matches!(
            repository
                .use_list_cursor(cursor.id, &binding, now + 3)
                .await,
            Err(maskura_gateway::managed::ManagedError::CursorExpired)
        ));

        repository
            .enqueue(RepairRecord::placement(
                &committed.authority,
                Some(intent.backend_id.clone()),
                "placement-target".to_string(),
                RepairTargetRole::Primary,
                &Placement {
                    version: committed.authority.placement_version + 1,
                    primary_backend_id: "placement-target".to_string(),
                    replica_backend_id: None,
                },
            ))
            .await
            .unwrap();
        let placement_lease = repository
            .begin_physical_write(PhysicalWriteIntent {
                intent_id: uuid::Uuid::now_v7(),
                tenant_id: tenant.clone(),
                backend_id: "placement-target".to_string(),
                storage_identity: test_storage_identity(),
                credential_epoch: 1,
                provider_bucket: intent.provider_bucket.clone(),
                physical_key: intent.physical_key.clone(),
                versioning_mode: BackendVersioningMode::Enabled,
                versioning_capability: BackendVersioningCapability::Required,
                lease_owner: "placement-delete-race".to_string(),
            })
            .await
            .unwrap();
        let stale_placement = repository
            .claim_repairs("placement-delete-race", i64::MAX, 10)
            .await
            .unwrap()
            .into_iter()
            .find(|repair| {
                repair.kind == maskura_gateway::managed::RepairKind::Placement
                    && repair.target_backend_id == "placement-target"
            })
            .unwrap();

        let delete_request = ManagedDeleteRequest {
            operation_id: uuid::Uuid::now_v7(),
            receipt_id: uuid::Uuid::now_v7(),
            logical: intent.logical.clone(),
            placement: Placement {
                version: committed.authority.placement_version,
                primary_backend_id: committed.authority.primary_backend_id.clone(),
                replica_backend_id: committed.authority.replica_backend_id.clone(),
            },
            provider_bucket: intent.provider_bucket.clone(),
            occurred_at_micros: unix_time_ms() * 1_000,
            rate_version: 7,
            max_processed_bytes: 0,
        };
        let deleted = repository
            .commit_atomic_logical_delete(delete_request.clone())
            .await
            .unwrap();
        assert!(deleted.authority.tombstone);
        assert_eq!(deleted.usage.visible_logical_bytes, 0);
        assert_eq!(deleted.usage.physical_allocated_bytes, 6);
        assert_eq!(deleted.usage.active_operation_id, None);
        assert!(
            repository
                .pending_delete_settlements(10)
                .await
                .unwrap()
                .iter()
                .any(|operation| operation.intent.operation_id == delete_request.operation_id)
        );
        repository
            .mark_logical_operation_settled(delete_request.operation_id, delete_request.receipt_id)
            .await
            .unwrap();
        repository
            .mark_logical_operation_settled(delete_request.operation_id, delete_request.receipt_id)
            .await
            .unwrap();
        assert!(
            repository
                .pending_delete_settlements(10)
                .await
                .unwrap()
                .iter()
                .all(|operation| operation.intent.operation_id != delete_request.operation_id)
        );
        repository
            .commit_physical_write(&placement_lease, &[], Some("late-placement-version"))
            .await
            .unwrap();
        assert!(!repository.complete_repair(&stale_placement).await.unwrap());
        let cleanup = repository
            .claim_repairs("delete-cleanup", i64::MAX, 10)
            .await
            .unwrap();
        assert!(cleanup.iter().any(|repair| {
            repair.target_backend_id == "placement-target"
                && repair.target_role == RepairTargetRole::Cleanup
                && repair.generation == generation
        }));
        let advanced_authority = repository
            .commit_atomic_logical_delete(delete_request.clone())
            .await
            .unwrap()
            .authority;
        assert_eq!(advanced_authority, deleted.authority);
        let replay_after_overwrite = repository
            .finalize_logical_put(intent.operation_id, &lease, exact_commit, None)
            .await
            .unwrap();
        assert_eq!(replay_after_overwrite.authority, advanced_authority);

        let placement_versions = repository
            .physical_versions(
                &tenant,
                "placement-target",
                &intent.provider_bucket,
                &intent.physical_key,
            )
            .await
            .unwrap();
        assert_eq!(placement_versions.len(), 1);
        repository
            .forget_physical_version(&placement_versions[0])
            .await
            .unwrap();

        let versions = repository
            .physical_versions(
                &tenant,
                &intent.backend_id,
                &intent.provider_bucket,
                &intent.physical_key,
            )
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);
        let (first_delete, second_delete) = tokio::join!(
            repository.forget_physical_version(&versions[0]),
            repository.forget_physical_version(&versions[1]),
        );
        first_delete.unwrap();
        second_delete.unwrap();
        assert_eq!(
            repository
                .workspace_usage(&tenant)
                .await
                .unwrap()
                .unwrap()
                .physical_allocated_bytes,
            0
        );
        assert_eq!(
            repository
                .logical_operation(intent.operation_id)
                .await
                .unwrap()
                .unwrap()
                .released_physical_bytes,
            6
        );

        managed_list_cursor::Entity::delete_many()
            .filter(managed_list_cursor::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_object_repair::Entity::delete_many()
            .filter(managed_object_repair::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_object_authority::Entity::delete_many()
            .filter(managed_object_authority::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_workspace_usage::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
        managed_logical_operation::Entity::delete_many()
            .filter(managed_logical_operation::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
    });
}

#[test]
fn postgres_managed_zero_byte_put_is_ledgered_and_committed() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = PostgresManagedRepository::new(pool.clone());
        let tenant = format!("managed-zero-unit-{}", uuid::Uuid::new_v4());
        let logical = LogicalObjectKey::new(&tenant, "bucket", "empty");
        let generation = uuid::Uuid::now_v7();
        let fence = repository.route_fence(&tenant).await.unwrap();
        let intent = ManagedLogicalOperationIntent {
            operation_id: uuid::Uuid::now_v7(),
            receipt_id: uuid::Uuid::now_v7(),
            logical: logical.clone(),
            kind: ManagedMutationKind::Put,
            generation,
            fence,
            expected_authority_cas: None,
            prior_logical_size: 0,
            primary_child_operation_id: uuid::Uuid::now_v7(),
            backend_id: "primary".to_string(),
            provider_bucket: "provider-bucket".to_string(),
            physical_key: generation_physical_key(&logical, generation),
            occurred_at_ms: unix_time_ms(),
            rate_version: 1,
            route: UsageRoute::PutObject,
            request_kind: RequestKind::Write,
            max_processed_bytes: 0,
            publication_recipe: Some(publication_recipe("primary")),
        };
        repository
            .insert_logical_operation(intent.clone())
            .await
            .unwrap();
        let usage = repository
            .reserve_logical_operation(intent.operation_id, 0)
            .await
            .unwrap();
        assert_eq!(usage.active_operation_id, Some(intent.operation_id));
        let mut child = test_physical_intent(
            intent.primary_child_operation_id,
            &tenant,
            &intent.backend_id,
            &intent.provider_bucket,
            &intent.physical_key,
            "zero-byte-writer",
        );
        child.versioning_capability = BackendVersioningCapability::Required;
        let lease = repository.begin_physical_write(child).await.unwrap();
        repository
            .record_logical_usage(
                intent.operation_id,
                ManagedUsageEvidence {
                    expected_output_digest: Some("empty-digest".to_string()),
                    expected_output_size: 0,
                    source_bytes: 0,
                    processed_bytes: 0,
                    payload: serde_json::json!({"zero_byte": true}),
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
        let exact_commit = ExactPhysicalCommit {
            selected_version_id: Some("empty-version".to_string()),
            superseded_version_ids: Vec::new(),
            version_history_complete: true,
        };
        insert_committed_child(&pool, &intent, "empty-digest", 0, &exact_commit).await;
        let committed = repository
            .finalize_logical_put(intent.operation_id, &lease, exact_commit, None)
            .await
            .unwrap();
        assert_eq!(committed.operation.committed_physical_bytes, 0);
        assert_eq!(committed.usage.visible_logical_bytes, 0);
        assert_eq!(committed.usage.physical_allocated_bytes, 0);
        assert_eq!(
            managed_physical_object_version::Entity::find()
                .filter(managed_physical_object_version::Column::TenantId.eq(&tenant))
                .count(&db)
                .await
                .unwrap(),
            1
        );

        managed_physical_object_version::Entity::delete_many()
            .filter(managed_physical_object_version::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_object_authority::Entity::delete_many()
            .filter(managed_object_authority::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_workspace_usage::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
        managed_logical_operation::Entity::delete_many()
            .filter(managed_logical_operation::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
    });
}

#[test]
fn postgres_managed_admission_is_atomic() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = PostgresManagedRepository::new(pool);
        let tenant = format!("managed-admit-unit-{}", uuid::Uuid::new_v4());
        let fence = repository.route_fence(&tenant).await.unwrap();
        let intent = |key: &str| {
            let logical = LogicalObjectKey::new(&tenant, "bucket", key);
            let generation = uuid::Uuid::now_v7();
            ManagedLogicalOperationIntent {
                operation_id: uuid::Uuid::now_v7(),
                receipt_id: uuid::Uuid::now_v7(),
                logical: logical.clone(),
                kind: ManagedMutationKind::Put,
                generation,
                fence,
                expected_authority_cas: None,
                prior_logical_size: 0,
                primary_child_operation_id: uuid::Uuid::now_v7(),
                backend_id: "primary".to_string(),
                provider_bucket: "provider-bucket".to_string(),
                physical_key: generation_physical_key(&logical, generation),
                occurred_at_ms: unix_time_ms(),
                rate_version: 1,
                route: UsageRoute::PutObject,
                request_kind: RequestKind::Write,
                max_processed_bytes: 0,
                publication_recipe: Some(publication_recipe("primary")),
            }
        };
        let first = intent("first");
        let second = intent("second");
        let (admitted, usage) = repository
            .admit_logical_operation(first.clone(), 0)
            .await
            .unwrap();
        assert_eq!(admitted.state, ManagedLogicalOperationState::Open);
        assert_eq!(usage.active_operation_id, Some(first.operation_id));
        // The workspace admits one managed mutation at a time, so a second
        // admission must fail...
        assert!(matches!(
            repository.admit_logical_operation(second.clone(), 0).await,
            Err(maskura_gateway::managed::ManagedError::MutationInProgress)
        ));
        // ...and must leave no logical operation behind (atomic admission).
        assert!(
            repository
                .logical_operation(second.operation_id)
                .await
                .unwrap()
                .is_none(),
            "a failed admission must not commit a dangling Intent row"
        );
        assert_eq!(
            repository
                .workspace_usage(&tenant)
                .await
                .unwrap()
                .unwrap()
                .active_operation_id,
            Some(first.operation_id)
        );

        managed_workspace_usage::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
        managed_logical_operation::Entity::delete_many()
            .filter(managed_logical_operation::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
    });
}

#[test]
fn postgres_logical_child_abort_is_atomic() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = PostgresManagedRepository::new(pool.clone());
        let tenant = format!("managed-abort-unit-{}", uuid::Uuid::new_v4());
        let logical = LogicalObjectKey::new(&tenant, "bucket", "aborted");
        let generation = uuid::Uuid::now_v7();
        let intent = ManagedLogicalOperationIntent {
            operation_id: uuid::Uuid::now_v7(),
            receipt_id: uuid::Uuid::now_v7(),
            logical: logical.clone(),
            kind: ManagedMutationKind::Put,
            generation,
            fence: repository.route_fence(&tenant).await.unwrap(),
            expected_authority_cas: None,
            prior_logical_size: 0,
            primary_child_operation_id: uuid::Uuid::now_v7(),
            backend_id: "primary".to_string(),
            provider_bucket: "provider-bucket".to_string(),
            physical_key: generation_physical_key(&logical, generation),
            occurred_at_ms: unix_time_ms(),
            rate_version: 1,
            route: UsageRoute::PutObject,
            request_kind: RequestKind::Write,
            max_processed_bytes: 3,
            publication_recipe: Some(publication_recipe("primary")),
        };
        repository
            .insert_logical_operation(intent.clone())
            .await
            .unwrap();
        repository
            .reserve_logical_operation(intent.operation_id, 6)
            .await
            .unwrap();
        let lease = repository
            .begin_physical_write(test_physical_intent(
                intent.primary_child_operation_id,
                &tenant,
                &intent.backend_id,
                &intent.provider_bucket,
                &intent.physical_key,
                "abort-writer",
            ))
            .await
            .unwrap();
        assert!(matches!(
            repository.abort_physical_write(&lease).await,
            Err(maskura_gateway::managed::ManagedError::Conflict)
        ));
        assert!(matches!(
            repository
                .abort_logical_put(
                    intent.operation_id,
                    Some(&lease),
                    LogicalAbortProof::ChildProvenAborted,
                    "unverified_child_abort",
                    None,
                )
                .await,
            Err(maskura_gateway::managed::ManagedError::Conflict)
        ));
        let journal = PostgresOperationJournal::new(pool.clone());
        let destination = ObjectDestination {
            backend_id: intent.backend_id.clone(),
            bucket: intent.provider_bucket.clone(),
            logical_key: logical.object_key(),
            physical_key: intent.physical_key.clone(),
            workspace_binding: None,
        };
        journal
            .insert_intent(OperationRecord::scoped_intent(
                intent.primary_child_operation_id,
                destination,
                ExpectedObject::default(),
                tenant.clone(),
                intent.fence.namespace_epoch,
            ))
            .await
            .unwrap();
        journal
            .set_open(intent.primary_child_operation_id, None)
            .await
            .unwrap();
        journal
            .transition(
                intent.primary_child_operation_id,
                OperationState::Open,
                OperationState::Aborting,
                None,
            )
            .await
            .unwrap();
        let observed_at = unix_time_ms();
        assert!(
            !journal
                .confirm_exact_absence(intent.primary_child_operation_id, observed_at, 0)
                .await
                .unwrap()
        );
        journal
            .transition(
                intent.primary_child_operation_id,
                OperationState::Aborting,
                OperationState::ProvenAborted,
                None,
            )
            .await
            .unwrap();
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
        assert_eq!(
            repository
                .workspace_usage(&tenant)
                .await
                .unwrap()
                .unwrap()
                .physical_allocated_bytes,
            0
        );
        let versions = repository
            .physical_versions(
                &tenant,
                &intent.backend_id,
                &intent.provider_bucket,
                &intent.physical_key,
            )
            .await
            .unwrap();
        assert!(versions.is_empty());
        assert_eq!(
            repository
                .workspace_usage(&tenant)
                .await
                .unwrap()
                .unwrap()
                .physical_allocated_bytes,
            0
        );

        managed_object_repair::Entity::delete_many()
            .filter(managed_object_repair::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        object_operation::Entity::delete_by_id(intent.primary_child_operation_id)
            .exec(&db)
            .await
            .unwrap();
        managed_workspace_usage::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
        managed_logical_operation::Entity::delete_many()
            .filter(managed_logical_operation::Column::TenantId.eq(&tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&tenant)
            .exec(&db)
            .await
            .unwrap();
    });
}

#[test]
fn postgres_managed_quota_and_cursor_limits_hold_under_concurrency() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = Arc::new(PostgresManagedRepository::new(pool));
        let quota_tenant = format!("managed-quota-race-{}", uuid::Uuid::new_v4());
        let fence = repository.route_fence(&quota_tenant).await.unwrap();
        let make_intent = |key: &str| {
            let logical = LogicalObjectKey::new(&quota_tenant, "bucket", key);
            let generation = uuid::Uuid::now_v7();
            ManagedLogicalOperationIntent {
                operation_id: uuid::Uuid::now_v7(),
                receipt_id: uuid::Uuid::now_v7(),
                logical: logical.clone(),
                kind: ManagedMutationKind::Put,
                generation,
                fence,
                expected_authority_cas: None,
                prior_logical_size: 0,
                primary_child_operation_id: uuid::Uuid::now_v7(),
                backend_id: "primary".to_string(),
                provider_bucket: "provider-bucket".to_string(),
                physical_key: generation_physical_key(&logical, generation),
                occurred_at_ms: unix_time_ms(),
                rate_version: 1,
                route: UsageRoute::PutObject,
                request_kind: RequestKind::Write,
                max_processed_bytes: 1,
                publication_recipe: Some(publication_recipe("primary")),
            }
        };
        let first_intent = make_intent("first");
        let second_intent = make_intent("second");
        repository
            .insert_logical_operation(first_intent.clone())
            .await
            .unwrap();
        repository
            .insert_logical_operation(second_intent.clone())
            .await
            .unwrap();
        let (first_reservation, second_reservation) = tokio::join!(
            repository.reserve_logical_operation(first_intent.operation_id, 1),
            repository.reserve_logical_operation(second_intent.operation_id, 1),
        );
        assert_eq!(
            usize::from(first_reservation.is_ok()) + usize::from(second_reservation.is_ok()),
            1
        );
        let winner = first_reservation
            .ok()
            .or_else(|| second_reservation.ok())
            .and_then(|usage| usage.active_operation_id)
            .unwrap();
        let loser = if winner == first_intent.operation_id {
            second_intent.operation_id
        } else {
            first_intent.operation_id
        };
        repository
            .prove_logical_abort(winner, "race_cleanup", None)
            .await
            .unwrap();
        repository
            .prove_logical_abort(loser, "race_cleanup", None)
            .await
            .unwrap();

        let cursor_tenant = format!("managed-cursor-race-{}", uuid::Uuid::new_v4());
        let binding = ManagedListCursorBinding {
            tenant_id: cursor_tenant.clone(),
            bucket: "bucket".to_string(),
            prefix: String::new(),
            delimiter: None,
            version: ManagedListVersion::V2,
        };
        let request = ManagedListCursorRequest {
            binding: binding.clone(),
            position: ManagedListCursorPosition {
                last_key: None,
                last_common_prefix: None,
            },
            response_state: serde_json::json!({}),
            final_page: false,
        };
        let now = unix_time_ms();
        for _ in 0..MANAGED_LIST_CURSOR_WORKSPACE_LIMIT - 1 {
            repository
                .create_list_cursor(request.clone(), now)
                .await
                .unwrap();
        }
        let (first_cursor, second_cursor) = tokio::join!(
            repository.create_list_cursor(request.clone(), now),
            repository.create_list_cursor(request, now),
        );
        assert_eq!(
            usize::from(first_cursor.is_ok()) + usize::from(second_cursor.is_ok()),
            1,
            "serializable cursor creation must admit only the final available slot"
        );
        assert_eq!(
            managed_list_cursor::Entity::find()
                .filter(managed_list_cursor::Column::TenantId.eq(&cursor_tenant))
                .count(&db)
                .await
                .unwrap(),
            MANAGED_LIST_CURSOR_WORKSPACE_LIMIT
        );

        managed_list_cursor::Entity::delete_many()
            .filter(managed_list_cursor::Column::TenantId.eq(&cursor_tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&cursor_tenant)
            .exec(&db)
            .await
            .unwrap();
        managed_workspace_usage::Entity::delete_by_id(&quota_tenant)
            .exec(&db)
            .await
            .unwrap();
        managed_logical_operation::Entity::delete_many()
            .filter(managed_logical_operation::Column::TenantId.eq(&quota_tenant))
            .exec(&db)
            .await
            .unwrap();
        managed_namespace::Entity::delete_by_id(&quota_tenant)
            .exec(&db)
            .await
            .unwrap();
    });
}
