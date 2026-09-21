use super::super::*;
use super::*;

#[tokio::test]
async fn multipart_crash_recovery_restores_exact_precommit_pipeline_evidence() {
    let journal: Arc<dyn OperationJournal> =
        Arc::new(crate::transaction::InMemoryOperationJournal::new());
    let identity = multipart_completion_operation_identity("upload-a", "fingerprint-a");
    let authorization = identity.authorization(
        "bucket-a",
        UsageRoute::CompleteMultipartUpload,
        RequestKind::Write,
        128,
    );
    let grant = test_grant(&authorization);
    let pipeline_evidence = crate::control::PipelineEvidence {
        revision: "revision-a".to_string(),
        fingerprint: "fingerprint-a".to_string(),
        components: "component-a".to_string(),
        fuel_consumed: 77,
        duration_ms: 9,
        spool_mode: "none".to_string(),
    };
    let precommit_result = MultipartCompletionResult {
        etag: None,
        checksum_sha256: "output-sha".to_string(),
        version_id: None,
        source_bytes: 32,
        size_bytes: 24,
        pipeline_evidence: Some(pipeline_evidence.clone()),
    };
    insert_test_usage_intent(&journal, identity.operation_id).await;
    persist_usage_evidence(
        Some(&journal),
        &multipart_completion_event(&grant, &precommit_result),
    )
    .await
    .unwrap();

    let mut operation = OperationRecord::direct_intent(
        DirectOperationScope {
            operation_id: identity.operation_id,
            tenant_id: "workspace-a".to_string(),
        },
        ObjectDestination {
            backend_id: "S3".to_string(),
            bucket: "bucket-a".to_string(),
            logical_key: "key-a".to_string(),
            physical_key: "key-a".to_string(),
            workspace_binding: None,
        },
        ExpectedObject {
            digest: Some("output-sha".to_string()),
            size: Some(24),
            metadata: Default::default(),
        },
    );
    operation.state = OperationState::Committed;
    operation.committed = Some(StoredObjectMeta {
        etag: Some("\"etag-a\"".to_string()),
        version_id: Some("version-a".to_string()),
        ..StoredObjectMeta::default()
    });
    let lease = CompletionLease {
        fencing_token: 1,
        selected_parts: vec![MultipartPart {
            upload_id: "upload-a".to_string(),
            part_number: 1,
            attempt: 1,
            artifact_key: "artifact-a".to_string(),
            etag: "\"part-a\"".to_string(),
            checksum_sha256: "part-sha".to_string(),
            size_bytes: 32,
            created_at_ms: now_ms(),
        }],
        cleanup_parts: Vec::new(),
    };

    let recovered =
        recovered_multipart_result(Some(&journal), operation, &lease, identity.receipt_id)
            .await
            .unwrap();
    assert_eq!(recovered.pipeline_evidence, Some(pipeline_evidence));
    assert_eq!(recovered.source_bytes, 32);
    assert_eq!(recovered.size_bytes, 24);
    assert_eq!(recovered.checksum_sha256, "output-sha");
}

#[test]
fn operation_identities_are_server_generated_and_completion_is_stable() {
    let first = request_operation_identity();
    let second = request_operation_identity();
    assert_eq!(first.receipt_id.get_version_num(), 7);
    assert_eq!(first.operation_id.get_version_num(), 5);
    assert_eq!(
        first.operation_id,
        operation_id_for_receipt(first.receipt_id)
    );
    assert_ne!(first.receipt_id, first.operation_id);
    assert_ne!(first.receipt_id, second.receipt_id);
    assert_ne!(first.operation_id, second.operation_id);
    let multipart = multipart_completion_operation_identity("upload-1", "fingerprint-a");
    assert_eq!(
        multipart,
        multipart_completion_operation_identity("upload-1", "fingerprint-a")
    );
    assert_ne!(
        multipart,
        multipart_completion_operation_identity("upload-2", "fingerprint-a")
    );
    assert_ne!(
        multipart,
        multipart_completion_operation_identity("upload-1", "fingerprint-b")
    );
    assert_eq!(multipart.receipt_id.get_version_num(), 5);
    assert_eq!(multipart.operation_id.get_version_num(), 5);
    assert_ne!(multipart.receipt_id, multipart.operation_id);
}

#[test]
fn managed_and_multipart_namespaces_use_workspace_identity_not_user_identity() {
    let auth = Auth {
        context: AuthenticatedRequestContext {
            user_id: "user-a".to_string(),
            workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-b").unwrap(),
        },
        credential_policy_id: "credential".to_string(),
        public_key_pem: None,
        stable_key: None,
    };

    let logical = managed_logical_key(&auth, "bucket", "key");
    let multipart = multipart_identity(&auth, "bucket", "key", "upload");
    assert_eq!(logical.tenant_id, "workspace-b");
    assert_eq!(multipart.tenant_id, "workspace-b");
    assert_ne!(logical.tenant_id, auth.context.user_id);
}

#[tokio::test]
async fn multipart_success_and_exact_replay_meter_with_one_stable_identity() {
    let control = Arc::new(RecordingControlPlane::default());
    let journal: Arc<dyn OperationJournal> =
        Arc::new(crate::transaction::InMemoryOperationJournal::new());
    let context = AuthenticatedRequestContext {
        user_id: "user-a".to_string(),
        workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-a").unwrap(),
    };
    let operation = multipart_completion_operation_identity("upload-a", "fingerprint-a");
    let authorization = operation.authorization(
        "bucket-a",
        UsageRoute::CompleteMultipartUpload,
        RequestKind::Write,
        64,
    );
    insert_test_usage_intent(&journal, operation.operation_id).await;
    let grant = test_grant(&authorization);

    let result = MultipartCompletionResult {
        etag: Some("\"etag\"".to_string()),
        checksum_sha256: "sha".to_string(),
        version_id: None,
        source_bytes: 32,
        size_bytes: 24,
        pipeline_evidence: None,
    };
    for _ in 0..2 {
        record_durable_operation_with_event(
            Some(&journal),
            control.clone(),
            &context,
            multipart_completion_event(&grant, &result),
            "key-a",
        )
        .await
        .unwrap();
    }

    {
        let calls = control.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
        assert_eq!(calls[0].event.operation_id(), authorization.operation_id());
        assert_eq!(calls[0].event.route(), UsageRoute::CompleteMultipartUpload);
        assert_eq!(calls[0].event.processed_bytes(), 32);
    }
    let evidence = journal.evidence(operation.operation_id).await.unwrap();
    assert_eq!(evidence.len(), 1);
    assert!(evidence.iter().all(|record| record.kind == "usage"));
    let receipt_id = operation.receipt_id.to_string();
    assert!(
        evidence
            .iter()
            .all(|record| record.detail["receipt_id"].as_str() == Some(receipt_id.as_str()))
    );
}

#[test]
fn multipart_pipeline_restore_accepts_new_static_and_rejects_legacy_or_tampered_state() {
    let limits = PipelineLimits::default();
    let resolution = crate::pipeline::PipelineResolution {
        locator: crate::pipeline::PipelineLocator {
            revision: "static".to_string(),
            fingerprint: crate::pipeline::resolution_fingerprint(
                crate::pipeline::PipelineDirection::Write,
                &[],
                true,
                limits,
            ),
        },
        steps: Vec::new(),
        policy_generation: None,
        explicit_passthrough: true,
        limits,
    };
    let snapshot = serde_json::to_value(&resolution).unwrap();
    assert_eq!(restore_multipart_pipeline(&snapshot).unwrap(), resolution);

    let legacy = serde_json::json!([{
        "id": Uuid::new_v4(),
        "name": "legacy",
        "version": "0.1.0",
        "enabled": true,
        "description": ""
    }]);
    assert!(matches!(
        restore_multipart_pipeline(&legacy),
        Err(MultipartPipelineRestoreError::LegacyRawSnapshot)
    ));

    let mut tampered = snapshot;
    tampered["explicit_passthrough"] = serde_json::Value::Bool(false);
    assert!(matches!(
        restore_multipart_pipeline(&tampered),
        Err(MultipartPipelineRestoreError::Invalid(_))
    ));
}

#[tokio::test]
async fn multipart_post_commit_failure_does_not_release_reservation() {
    let control = RecordingControlPlane::default();
    let context = AuthenticatedRequestContext {
        user_id: "user-a".to_string(),
        workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-a").unwrap(),
    };
    let operation = multipart_completion_operation_identity("upload-a", "fingerprint-a");
    let authorization = operation.authorization(
        "bucket",
        UsageRoute::CompleteMultipartUpload,
        RequestKind::Write,
        64,
    );
    let grant = test_grant(&authorization);

    let response = multipart_completion_failure_response(
        &control,
        &context,
        &grant,
        "key",
        MultipartCompletionError::PreserveReservation(Box::new(MultipartCompletionError::Staging(
            StagingError::Fenced,
        ))),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(control.releases.lock().unwrap().is_empty());
}

#[cfg(test)]
#[test]
fn staged_multipart_startup_requires_every_production_dependency() {
    let complete = MultipartStartupDependencies {
        durable_wrapping: true,
        database: true,
        endpoint: true,
        bucket: true,
        access_key: true,
        secret_key: true,
        region: true,
        directory: true,
        tenant_quota: true,
        global_quota: true,
    };
    validate_multipart_startup(MultipartPersistenceMode::HostedStaged, complete).unwrap();
    validate_multipart_startup(
        MultipartPersistenceMode::Reject,
        MultipartStartupDependencies {
            durable_wrapping: false,
            ..complete
        },
    )
    .unwrap();

    let missing_one: [fn(&mut MultipartStartupDependencies); 10] = [
        |value| value.durable_wrapping = false,
        |value| value.database = false,
        |value| value.endpoint = false,
        |value| value.bucket = false,
        |value| value.access_key = false,
        |value| value.secret_key = false,
        |value| value.region = false,
        |value| value.directory = false,
        |value| value.tenant_quota = false,
        |value| value.global_quota = false,
    ];
    for remove in missing_one {
        let mut incomplete = complete;
        remove(&mut incomplete);
        assert!(
            validate_multipart_startup(MultipartPersistenceMode::HostedStaged, incomplete).is_err()
        );
    }
}

#[cfg(test)]
#[test]
fn local_staged_persistence_requires_no_hosted_dependencies() {
    let missing = MultipartStartupDependencies {
        durable_wrapping: false,
        database: false,
        endpoint: false,
        bucket: false,
        access_key: false,
        secret_key: false,
        region: false,
        directory: false,
        tenant_quota: false,
        global_quota: false,
    };
    let mode = multipart_persistence_mode(MultipartMode::Staged, true);
    assert_eq!(mode, MultipartPersistenceMode::LocalStaged);
    validate_multipart_startup(mode, missing).unwrap();
    assert_eq!(
        multipart_persistence_mode(MultipartMode::Staged, false),
        MultipartPersistenceMode::HostedStaged
    );
    assert_eq!(
        multipart_persistence_mode(MultipartMode::Reject, true),
        MultipartPersistenceMode::Reject
    );
}

#[cfg(test)]
#[tokio::test]
async fn multipart_recovery_orders_artifacts_before_expiry_and_retries_on_next_run() {
    let root = std::env::temp_dir().join(format!("maskura-startup-recovery-{}", Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let runtime = Arc::new(LocalStorageRuntime::new(root.clone()).await.unwrap());
    let artifacts = runtime.staging_artifacts();
    let staging = Arc::new(MultipartStaging {
        repository: runtime.multipart_repository(),
        directory: artifacts.temporary_root().to_path_buf(),
        artifacts,
        wrapping: runtime.wrapping(),
    });
    let coordinator = Arc::new(
        MultipartCompletionCoordinator::new(
            staging.repository.clone(),
            runtime.operation_journal(),
        )
        .unwrap()
        .with_file_proof(runtime.file_store()),
    );
    let recovery = MultipartRecoveryRuntime {
        staging: staging.clone(),
        coordinator,
        file_store: Some(runtime.file_store()),
        service_storage: Arc::new(ServiceStorage::new(Vec::new())),
    };
    let now = now_ms();
    let identity = MultipartIdentity {
        tenant_id: "tenant".to_string(),
        credential_policy_id: "policy".to_string(),
        bucket: "bucket".to_string(),
        key: "key".to_string(),
        upload_id: Uuid::now_v7().to_string(),
    };
    staging
        .repository
        .create(MultipartUpload {
            identity: identity.clone(),
            namespace_epoch: None,
            snapshot: MultipartSnapshot {
                metadata: Default::default(),
                tags: Default::default(),
                checksum_mode: None,
                destination: serde_json::json!({"kind":"file"}),
                plugin_snapshot: serde_json::json!({}),
                max_staged_bytes: 1024,
            },
            lifecycle: MultipartLifecycle::Open,
            staged_bytes: 0,
            reserved_bytes: 0,
            created_at_ms: now.saturating_sub(2),
            expires_at_ms: now.saturating_sub(1),
            updated_at_ms: now.saturating_sub(2),
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
    let unknown = root.join(".maskura/multipart/artifacts/unknown");
    std::fs::write(&unknown, b"unknown").unwrap();

    assert!(recovery.run_once(now, 16).await.is_err());
    assert_eq!(
        staging
            .repository
            .get_authorized(&identity)
            .await
            .unwrap()
            .lifecycle,
        MultipartLifecycle::Open
    );

    std::fs::remove_file(unknown).unwrap();
    recovery.run_once(now, 16).await.unwrap();
    assert_eq!(
        staging
            .repository
            .get_authorized(&identity)
            .await
            .unwrap()
            .lifecycle,
        MultipartLifecycle::Expired
    );
    drop(runtime);
    std::fs::remove_dir_all(root).unwrap();
}
