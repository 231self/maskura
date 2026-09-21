use super::super::*;
use super::*;

#[tokio::test]
async fn terminal_journal_crash_window_releases_workspace_lease_idempotently() {
    for state in [OperationState::Committed, OperationState::ProvenAborted] {
        let repository = Arc::new(TerminalLeaseRepository::default());
        let operation = terminal_workspace_operation(state);
        let repository_trait: Arc<dyn WorkspaceStorageRepository> = repository.clone();

        // Simulates process loss after the journal terminal transition but
        // before the request worker settles its routing lease.
        settle_terminal_workspace_lease(&repository_trait, &operation)
            .await
            .unwrap();
        settle_terminal_workspace_lease(&repository_trait, &operation)
            .await
            .unwrap();

        assert_eq!(repository.settlements.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn managed_delete_releases_only_definite_precommit_failures() {
    let context = AuthenticatedRequestContext {
        user_id: "user-a".to_string(),
        workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-a").unwrap(),
    };
    let operation = request_operation_identity();
    let authorization =
        operation.authorization("bucket-a", UsageRoute::DeleteObject, RequestKind::Write, 0);
    let grant = test_grant(&authorization);

    let definite = RecordingControlPlane::default();
    let response = managed_delete_failure_response(
        &definite,
        &context,
        &grant,
        "key-a",
        crate::managed::ManagedDeleteError::PreCommit(crate::managed::ManagedError::Conflict),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        definite.releases.lock().unwrap().as_slice(),
        &[grant.operation_id()]
    );

    let uncertain = RecordingControlPlane::default();
    let response = managed_delete_failure_response(
        &uncertain,
        &context,
        &grant,
        "key-a",
        crate::managed::ManagedDeleteError::CommitUnknown(crate::managed::ManagedError::Conflict),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(uncertain.releases.lock().unwrap().is_empty());
}

#[tokio::test]
async fn persist_usage_evidence_writes_durable_journal_record() {
    let journal: Arc<dyn OperationJournal> =
        Arc::new(crate::transaction::InMemoryOperationJournal::new());
    let authorization = UsageAuthorization::new(
        Uuid::now_v7(),
        Uuid::now_v7(),
        "bucket",
        UsageRoute::PutObject,
        RequestKind::Write,
        64,
    );
    let pipeline_evidence = crate::control::PipelineEvidence {
        revision: "revision-7".to_string(),
        fingerprint: "fingerprint".to_string(),
        components: "component-a,component-b".to_string(),
        fuel_consumed: 123,
        duration_ms: 45,
        spool_mode: "encrypted".to_string(),
    };
    let event = UsageEvent::from_grant(&test_grant(&authorization), 64, 32)
        .with_pipeline_evidence(pipeline_evidence);
    insert_test_usage_intent(&journal, event.operation_id()).await;
    persist_usage_evidence(Some(&journal), &event)
        .await
        .unwrap();

    let evidence = journal.evidence(event.operation_id()).await.unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].kind, "usage");
    assert_eq!(
        evidence[0].detail["receipt_id"].as_str().unwrap(),
        event.receipt_id().to_string()
    );
    assert_eq!(evidence[0].detail["source_bytes"].as_u64(), Some(64));
    assert_eq!(evidence[0].detail["output_bytes"].as_u64(), Some(32));
    assert_eq!(evidence[0].detail["processed_bytes"].as_u64(), Some(64));
    assert_eq!(
        evidence[0].detail["occurred_at"],
        serde_json::json!(event.occurred_at())
    );
    assert_eq!(evidence[0].detail["rate_version"].as_i64(), Some(7));
    assert_eq!(evidence[0].detail["route"].as_str(), Some("PutObject"));
    assert_eq!(evidence[0].detail["kind"].as_str(), Some("write"));
    assert_eq!(evidence[0].detail["bucket"].as_str(), Some("bucket"));
    assert_eq!(
        evidence[0].detail["pipeline_evidence"],
        serde_json::json!({
            "revision": "revision-7",
            "fingerprint": "fingerprint",
            "components": "component-a,component-b",
            "fuel_consumed": 123,
            "duration_ms": 45,
            "spool_mode": "encrypted",
        })
    );
}

#[tokio::test]
async fn precommit_usage_evidence_failure_is_not_suppressed() {
    let concrete = Arc::new(crate::transaction::InMemoryOperationJournal::new());
    concrete.fail_next_evidence_appends(1);
    let journal: Arc<dyn OperationJournal> = concrete;
    let authorization = UsageAuthorization::new(
        Uuid::now_v7(),
        Uuid::now_v7(),
        "bucket",
        UsageRoute::PutObject,
        RequestKind::Write,
        8,
    );
    let event = UsageEvent::from_grant(&test_grant(&authorization), 8, 8);
    insert_test_usage_intent(&journal, event.operation_id()).await;

    assert!(
        persist_usage_evidence(Some(&journal), &event)
            .await
            .is_err()
    );
    assert!(
        journal
            .evidence(event.operation_id())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn postgres_journal_does_not_receive_evidence_for_dev_memory_sink() {
    let concrete = Arc::new(crate::transaction::InMemoryOperationJournal::new());
    // This models Postgres' evidence FK: any accidental append is a hard
    // failure because a memory sink has no object_operations row.
    concrete.fail_next_evidence_appends(1);
    let journal: Arc<dyn OperationJournal> = concrete;
    let sink = MemorySinkTransaction::new(
        Arc::new(MemoryStore::new()),
        "bucket",
        "key",
        "text/plain",
        1024,
    )
    .unwrap();
    let authorization = UsageAuthorization::new(
        Uuid::now_v7(),
        Uuid::now_v7(),
        "bucket",
        UsageRoute::PutObject,
        RequestKind::Write,
        8,
    );
    let event = UsageEvent::from_grant(&test_grant(&authorization), 8, 8);

    persist_transaction_usage_evidence(Some(&journal), sink.durable_operation_id(), &event)
        .await
        .unwrap();
    assert!(
        journal
            .evidence(event.operation_id())
            .await
            .unwrap()
            .is_empty()
    );
}

#[test]
fn direct_handler_scope_uses_authorization_operation_and_workspace() {
    let auth = Auth {
        context: AuthenticatedRequestContext {
            user_id: "user-a".to_string(),
            workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-b").unwrap(),
        },
        credential_policy_id: "credential".to_string(),
        public_key_pem: None,
        stable_key: None,
    };
    let operation = request_operation_identity();
    let authorization =
        operation.authorization("bucket", UsageRoute::PutObject, RequestKind::Write, 64);
    let grant = test_grant(&authorization);

    let scope = direct_operation_scope(
        AuthorizedOperation {
            auth: &auth,
            grant: &grant,
        },
        grant.operation_id(),
    );

    assert_eq!(scope.operation_id, authorization.operation_id());
    assert_eq!(scope.tenant_id, "workspace-b");
}

#[tokio::test]
async fn commit_unknown_failure_does_not_release_reservation() {
    let control = RecordingControlPlane::default();
    let context = AuthenticatedRequestContext {
        user_id: "user-a".to_string(),
        workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-a").unwrap(),
    };
    let operation = request_operation_identity();
    let authorization =
        operation.authorization("bucket", UsageRoute::PutObject, RequestKind::Write, 64);
    let grant = test_grant(&authorization);

    let response = streaming_put_failure_response(
        &control,
        &context,
        &grant,
        "key",
        StreamingPutError::PreserveReservation(Box::new(StreamingPutError::Transaction(
            TransactionError::CompletionAmbiguous,
        ))),
    )
    .await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(control.releases.lock().unwrap().is_empty());
}

#[tokio::test]
async fn pipeline_failure_taxonomy_is_stable_bounded_and_opaque() {
    for (code, status, s3_code) in [
        (
            maskura_error::codes::WASM_ADMISSION,
            StatusCode::SERVICE_UNAVAILABLE,
            "SlowDown",
        ),
        (
            maskura_error::codes::CONFIG_INVALID,
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
        ),
        (
            maskura_error::codes::POLICY_TAMPERED,
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
        ),
        (
            maskura_error::codes::COMPONENT_LOAD,
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
        ),
        (
            maskura_error::codes::INTERNAL,
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
        ),
    ] {
        let response = pipeline_error_response(
            "key",
            &maskura_error::MaskuraError::new(code, "PRINTABLE_GRANTED_SECRET"),
        );
        assert_eq!(response.status(), status);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains(&format!("<Code>{s3_code}</Code>")));
        assert!(!body.contains("PRINTABLE_GRANTED_SECRET"));
    }
}
