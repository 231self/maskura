use super::*;

#[test]
fn postgres_operation_journal_persists_canonical_ambiguous_completion() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let journal = PostgresOperationJournal::new(pool);
        let operation = OperationRecord::intent(
            ObjectDestination {
                backend_id: "db-test".to_string(),
                bucket: "bucket".to_string(),
                logical_key: format!("logical-{}", uuid::Uuid::new_v4()),
                physical_key: format!("physical-{}", uuid::Uuid::new_v4()),
                workspace_binding: None,
            },
            ExpectedObject {
                digest: Some("sha256:test".to_string()),
                size: Some(4),
                metadata: Default::default(),
            },
        );
        journal.insert_intent(operation.clone()).await.unwrap();
        journal
            .set_open(operation.id, Some("upload-id"))
            .await
            .unwrap();
        let part = PartRecord {
            operation_id: operation.id,
            part_number: 1,
            etag: "etag-1".to_string(),
            size_bytes: 4,
            digest: "sha256:part".to_string(),
            created_at_ms: 1,
        };
        journal.record_part(part.clone()).await.unwrap();
        journal.record_part(part).await.unwrap();
        journal
            .transition(
                operation.id,
                OperationState::Open,
                OperationState::Completing,
                None,
            )
            .await
            .unwrap();
        journal
            .transition(
                operation.id,
                OperationState::Completing,
                OperationState::CommitUnknown,
                None,
            )
            .await
            .unwrap();
        journal
            .append_evidence(EvidenceRecord::new(
                operation.id,
                "lost_complete_response",
                serde_json::json!({"retry": false}),
            ))
            .await
            .unwrap();

        let persisted = journal.get(operation.id).await.unwrap().unwrap();
        assert_eq!(persisted.state, OperationState::CommitUnknown);
        assert_eq!(persisted.upload_id.as_deref(), Some("upload-id"));
        assert_eq!(journal.parts(operation.id).await.unwrap().len(), 1);
        assert_eq!(journal.evidence(operation.id).await.unwrap().len(), 1);

        object_operation::Entity::delete_by_id(operation.id)
            .exec(&db)
            .await
            .expect("delete operation journal test row");
    });
}

#[test]
fn postgres_operation_journal_client_reference_cas_and_retirement_are_durable() {
    with_pool(|pool| async move {
        let journal = PostgresOperationJournal::new(pool);
        let operation = OperationRecord::intent(
            ObjectDestination {
                backend_id: "db-test".to_string(),
                bucket: "bucket".to_string(),
                logical_key: "logical".to_string(),
                physical_key: format!("physical-{}", uuid::Uuid::new_v4()),
                workspace_binding: None,
            },
            ExpectedObject::default(),
        );
        journal.insert_intent(operation.clone()).await.unwrap();
        assert_eq!(
            journal
                .get(operation.id)
                .await
                .unwrap()
                .unwrap()
                .client_multipart_upload_id,
            None
        );
        journal
            .compare_and_set_client_multipart_upload_reference(
                operation.id,
                None,
                Some("client-upload"),
            )
            .await
            .unwrap();
        assert!(
            journal
                .compare_and_set_client_multipart_upload_reference(
                    operation.id,
                    None,
                    Some("stale"),
                )
                .await
                .is_err()
        );
        journal.set_open(operation.id, None).await.unwrap();
        journal
            .transition(
                operation.id,
                OperationState::Open,
                OperationState::Aborting,
                None,
            )
            .await
            .unwrap();
        journal
            .transition(
                operation.id,
                OperationState::Aborting,
                OperationState::ProvenAborted,
                None,
            )
            .await
            .unwrap();
        assert!(
            journal
                .retire_terminal(operation.id, OperationState::ProvenAborted, None)
                .await
                .is_err()
        );
        journal
            .retire_terminal(
                operation.id,
                OperationState::ProvenAborted,
                Some("client-upload"),
            )
            .await
            .unwrap();
    });
}

#[test]
fn postgres_workspace_destination_survives_restart_in_every_recovery_state() {
    with_pool(|pool| async move {
        for target_state in [
            OperationState::Open,
            OperationState::Completing,
            OperationState::CommitUnknown,
        ] {
            let journal = PostgresOperationJournal::new(pool.clone());
            let operation_id = uuid::Uuid::now_v7();
            let binding = WorkspaceDestinationBinding {
                backend_config_version: format!("config-{operation_id}"),
                capability_attestation_id: format!("attestation-{operation_id}"),
                routing_epoch: 7,
                routing_lease_id: uuid::Uuid::now_v7(),
                routing_fencing_token: 11,
            };
            let operation = OperationRecord::direct_intent(
                maskura_gateway::transaction::DirectOperationScope {
                    operation_id,
                    tenant_id: "workspace-restart".to_string(),
                },
                ObjectDestination {
                    backend_id: "PerUserS3".to_string(),
                    bucket: "bucket".to_string(),
                    logical_key: "logical".to_string(),
                    physical_key: "physical".to_string(),
                    workspace_binding: Some(binding.clone()),
                },
                ExpectedObject::default(),
            );
            journal.insert_intent(operation).await.unwrap();
            journal
                .set_open(operation_id, Some("upload-id"))
                .await
                .unwrap();
            if matches!(
                target_state,
                OperationState::Completing | OperationState::CommitUnknown
            ) {
                journal
                    .transition(
                        operation_id,
                        OperationState::Open,
                        OperationState::Completing,
                        None,
                    )
                    .await
                    .unwrap();
            }
            if target_state == OperationState::CommitUnknown {
                journal
                    .transition(
                        operation_id,
                        OperationState::Completing,
                        OperationState::CommitUnknown,
                        None,
                    )
                    .await
                    .unwrap();
            }

            let restarted = PostgresOperationJournal::new(pool.clone())
                .get(operation_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(restarted.state, target_state);
            assert_eq!(restarted.destination.workspace_binding, Some(binding));
            let persisted = serde_json::to_string(&restarted.destination).unwrap();
            assert!(!persisted.contains("secret"));
            assert!(!persisted.contains("access-key"));
        }
    });
}

#[test]
fn postgres_evidence_foreign_key_requires_a_matching_operation_intent() {
    with_pool(|pool| async move {
        let journal = PostgresOperationJournal::new(pool);
        let missing_operation_id = uuid::Uuid::now_v7();
        let error = journal
            .append_evidence(EvidenceRecord::new(
                missing_operation_id,
                "usage",
                serde_json::json!({"source": "memory-sink-regression"}),
            ))
            .await
            .expect_err("evidence without an operation intent must violate the FK");
        assert!(error.to_string().contains("journal persistence failed"));
    });
}
