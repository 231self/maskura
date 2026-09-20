//! In-crate tests for the gateway `server` module.
//!
//! Relocated from `server.rs`; kept inside the `server` module so private
//! items remain reachable via `super`.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use axum::body::Body;
use bytes::Bytes;
use http_body::{Frame, SizeHint};

use super::*;

#[test]
fn byte_range_parser_preserves_single_range_semantics_with_u64_offsets() {
    for (range, expected) in [
        (
            None,
            ByteRange {
                start: 0,
                length: 10,
                content_range: None,
            },
        ),
        (
            Some("bytes=0-3"),
            ByteRange {
                start: 0,
                length: 4,
                content_range: Some("bytes 0-3/10".to_string()),
            },
        ),
        (
            Some("bytes=4-"),
            ByteRange {
                start: 4,
                length: 6,
                content_range: Some("bytes 4-9/10".to_string()),
            },
        ),
        (
            Some("bytes=-3"),
            ByteRange {
                start: 7,
                length: 3,
                content_range: Some("bytes 7-9/10".to_string()),
            },
        ),
        (
            Some("bytes=7-30"),
            ByteRange {
                start: 7,
                length: 3,
                content_range: Some("bytes 7-9/10".to_string()),
            },
        ),
    ] {
        assert_eq!(parse_byte_range(10, range).unwrap(), expected);
    }

    assert_eq!(
        parse_byte_range(u64::MAX, Some("bytes=4294967296-4294967297")).unwrap(),
        ByteRange {
            start: 4_294_967_296,
            length: 2,
            content_range: Some(format!("bytes 4294967296-4294967297/{}", u64::MAX)),
        }
    );
    assert_eq!(
        parse_byte_range(0, None).unwrap(),
        ByteRange {
            start: 0,
            length: 0,
            content_range: None,
        }
    );
}

#[test]
fn byte_range_parser_rejects_malformed_and_unsatisfiable_ranges() {
    for (object_length, range) in [
        (10, "bytes=1-2,4-5"),
        (10, "items=1-2"),
        (10, "bytes=-0"),
        (10, "bytes=8-7"),
        (10, "bytes=10-"),
        (10, "bytes=x-2"),
        (0, "bytes=0-0"),
    ] {
        assert!(matches!(
            parse_byte_range(object_length, Some(range)),
            Err(OpenObjectError::InvalidRange {
                object_length: actual
            }) if actual == object_length
        ));
    }
}

fn test_grant(authorization: &UsageAuthorization) -> AuthorizationGrant {
    AuthorizationGrant::new(
        authorization,
        chrono::DateTime::parse_from_rfc3339("2026-08-31T12:34:56Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        7,
    )
}

#[derive(Default)]
struct TerminalLeaseRepository {
    settled: tokio::sync::Mutex<Option<(Uuid, WorkspaceOperationOutcome)>>,
    settlements: AtomicUsize,
}

#[async_trait::async_trait]
impl WorkspaceStorageRepository for TerminalLeaseRepository {
    async fn resolve_workspace(&self, user_id: &str) -> Result<WorkspaceId, WorkspaceStorageError> {
        WorkspaceId::new(user_id)
    }

    async fn get_runtime_config(
        &self,
        _workspace_id: &WorkspaceId,
    ) -> Result<Option<crate::workspace_storage::RuntimeBackendConfig>, WorkspaceStorageError> {
        Ok(None)
    }

    async fn release_streaming_operation_lease(
        &self,
        _workspace_id: &WorkspaceId,
        lease: &WorkspaceOperationLease,
        outcome: WorkspaceOperationOutcome,
    ) -> Result<(), WorkspaceStorageError> {
        let mut settled = self.settled.lock().await;
        if let Some(existing) = *settled {
            return if existing == (lease.operation_id, outcome) {
                Ok(())
            } else {
                Err(WorkspaceStorageError::Repository(
                    "terminal lease settlement conflict".to_string(),
                ))
            };
        }
        *settled = Some((lease.operation_id, outcome));
        self.settlements.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn get_public_config(
        &self,
        _workspace_id: &WorkspaceId,
    ) -> Result<BackendConfigResponse, WorkspaceStorageError> {
        Ok(BackendConfigResponse::unconfigured())
    }

    async fn put_config(
        &self,
        _workspace_id: &WorkspaceId,
        _request: BackendConfigRequest,
    ) -> Result<BackendConfigResponse, WorkspaceStorageError> {
        Err(WorkspaceStorageError::UnsupportedConfig(
            "test repository is immutable".to_string(),
        ))
    }
}

fn terminal_workspace_operation(state: OperationState) -> OperationRecord {
    let operation_id = Uuid::now_v7();
    let mut operation = OperationRecord::direct_intent(
        DirectOperationScope {
            operation_id,
            tenant_id: "workspace-a".to_string(),
        },
        ObjectDestination {
            backend_id: "PerUserS3".to_string(),
            bucket: "bucket".to_string(),
            logical_key: "key".to_string(),
            physical_key: "key".to_string(),
            workspace_binding: Some(WorkspaceDestinationBinding {
                backend_config_version: "config-v1".to_string(),
                capability_attestation_id: "attestation-v1".to_string(),
                routing_epoch: 7,
                routing_lease_id: Uuid::now_v7(),
                routing_fencing_token: 11,
            }),
        },
        ExpectedObject::default(),
    );
    operation.state = state;
    if state == OperationState::Committed {
        operation.committed = Some(StoredObjectMeta::default());
    }
    operation
}

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

#[test]
fn avro_content_types_are_distinguished_from_text_formats() {
    for content_type in [
        "application/avro",
        "application/x-avro; charset=binary",
        "application/vnd.apache.avro+binary",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
        assert!(is_avro_content_type(&headers));
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    assert!(!is_avro_content_type(&headers));
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct UsageCall {
    context: AuthenticatedRequestContext,
    event: UsageEvent,
}

#[derive(Default)]
struct RecordingControlPlane {
    calls: std::sync::Mutex<Vec<UsageCall>>,
    releases: std::sync::Mutex<Vec<Uuid>>,
    failure: Option<MeteringError>,
}

#[async_trait::async_trait]
impl ControlPlane for RecordingControlPlane {
    async fn authorize(
        &self,
        _context: &AuthenticatedRequestContext,
        authorization: &UsageAuthorization,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        Ok(AuthorizationDecision::Granted(test_grant(authorization)))
    }

    async fn release(
        &self,
        _context: &AuthenticatedRequestContext,
        operation_id: Uuid,
    ) -> Result<(), AuthorizationError> {
        self.releases.lock().unwrap().push(operation_id);
        Ok(())
    }

    async fn record(
        &self,
        context: &AuthenticatedRequestContext,
        event: &UsageEvent,
    ) -> Result<(), MeteringError> {
        self.calls.lock().unwrap().push(UsageCall {
            context: context.clone(),
            event: event.clone(),
        });
        self.failure.map_or(Ok(()), Err)
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

struct PrivateAddressResolver;

#[async_trait::async_trait]
impl crate::backend::AddressResolver for PrivateAddressResolver {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
        Ok(vec![std::net::SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            port,
        )])
    }
}

#[derive(Default)]
struct CountingWorkspaceStorageRepository {
    put_calls: AtomicUsize,
}

#[async_trait::async_trait]
impl WorkspaceStorageRepository for CountingWorkspaceStorageRepository {
    async fn resolve_workspace(&self, user_id: &str) -> Result<WorkspaceId, WorkspaceStorageError> {
        WorkspaceId::new(user_id)
    }

    async fn get_runtime_config(
        &self,
        _workspace_id: &WorkspaceId,
    ) -> Result<Option<crate::workspace_storage::RuntimeBackendConfig>, WorkspaceStorageError> {
        Ok(None)
    }

    async fn get_public_config(
        &self,
        _workspace_id: &WorkspaceId,
    ) -> Result<BackendConfigResponse, WorkspaceStorageError> {
        Ok(BackendConfigResponse::unconfigured())
    }

    async fn put_config(
        &self,
        _workspace_id: &WorkspaceId,
        _request: BackendConfigRequest,
    ) -> Result<BackendConfigResponse, WorkspaceStorageError> {
        self.put_calls.fetch_add(1, Ordering::SeqCst);
        Ok(BackendConfigResponse::unconfigured())
    }
}

#[test]
fn startup_storage_boundary_requires_explicit_single_tenant_or_managed_storage() {
    let mut config = Config::default();
    assert!(!explicit_single_tenant_mode(&config, false));
    assert!(explicit_single_tenant_mode(&config, true));

    config.auth.disabled = true;
    assert!(explicit_single_tenant_mode(&config, false));
    config.auth.disabled = false;
    config.storage.single_tenant = true;
    assert!(explicit_single_tenant_mode(&config, false));

    assert!(validate_storage_boundary_startup(false, true, true).is_err());
    assert!(validate_storage_boundary_startup(false, false, false).is_err());
    assert!(validate_storage_boundary_startup(false, false, true).is_ok());
    assert!(validate_storage_boundary_startup(true, true, false).is_ok());
    assert!(validate_storage_boundary_startup(true, false, false).is_ok());
}

#[test]
fn auto_local_profile_uses_resolved_storage_config_and_operator_inputs() {
    let mut config = Config::default();
    assert!(auto_local_appliance_with_operator_state(
        &config, false, false
    ));
    assert!(!auto_local_appliance_with_operator_state(
        &config, true, false
    ));
    assert!(!auto_local_appliance_with_operator_state(
        &config, false, true
    ));

    config.storage.s3_endpoint = Some("http://minio:9000".to_string());
    assert!(!auto_local_appliance_with_operator_state(
        &config, false, false
    ));
    config.storage.s3_endpoint = None;
    config.storage.mode = Some("local".to_string());
    assert!(!auto_local_appliance_with_operator_state(
        &config, false, false
    ));
    config.storage.mode = None;
    config.storage.local_dir = Some("./data".to_string());
    assert!(!auto_local_appliance_with_operator_state(
        &config, false, false
    ));
    config.storage.local_dir = None;
    config.storage.single_tenant = true;
    assert!(!auto_local_appliance_with_operator_state(
        &config, false, false
    ));
}

#[test]
fn auto_local_defaults_do_not_override_explicit_feature_modes() {
    let defaults = Config::default();
    assert_eq!(
        effective_multipart_mode(&defaults, true),
        MultipartMode::Staged
    );
    assert_eq!(
        effective_streaming_read_mode(&defaults, true),
        StreamingReadMode::Passthrough
    );

    let explicit = Config::from_toml_str(
            "[features]\nmultipart_mode = \"reject\"\nstreaming_read_mode = \"off\"\n\n[wasm]\nfilter_component = \"/tmp/noop.wasm\"\n",
        )
        .unwrap();
    assert_eq!(
        effective_multipart_mode(&explicit, true),
        MultipartMode::Reject
    );
    assert_eq!(
        effective_streaming_read_mode(&explicit, true),
        StreamingReadMode::Off
    );
    assert!(explicit.filter_component_is_explicit());
}

#[test]
fn non_durable_journal_is_global_local_debug_only() {
    let journal: Arc<dyn OperationJournal> =
        Arc::new(crate::transaction::InMemoryOperationJournal::new());
    assert_eq!(
        direct_journal_allowed(BackendKind::GlobalS3, Some(&journal), true, true),
        cfg!(debug_assertions)
    );
    assert!(!direct_journal_allowed(
        BackendKind::GlobalS3,
        Some(&journal),
        false,
        true
    ));
    assert!(!direct_journal_allowed(
        BackendKind::GlobalS3,
        Some(&journal),
        true,
        false
    ));
    assert!(!direct_journal_allowed(
        BackendKind::PerUserS3,
        Some(&journal),
        true,
        true
    ));
}

async fn insert_test_usage_intent(journal: &Arc<dyn OperationJournal>, operation_id: Uuid) {
    journal
        .insert_intent(OperationRecord::direct_intent(
            DirectOperationScope {
                operation_id,
                tenant_id: "workspace-test".to_string(),
            },
            ObjectDestination {
                backend_id: "test".to_string(),
                bucket: "bucket".to_string(),
                logical_key: "key".to_string(),
                physical_key: "key".to_string(),
                workspace_binding: None,
            },
            ExpectedObject::default(),
        ))
        .await
        .unwrap();
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

#[tokio::test]
async fn dashboard_rejects_workspace_endpoint_before_persistence() {
    let repository = CountingWorkspaceStorageRepository::default();
    let policy = WorkspaceEndpointPolicy::new(
        false,
        ["objects.example".to_string()],
        Vec::<String>::new(),
        Arc::new(PrivateAddressResolver),
    )
    .unwrap();
    let result = validate_and_put_workspace_backend(
        &repository,
        &policy,
        &WorkspaceId::new("workspace").unwrap(),
        BackendConfigRequest {
            backend_type: BackendType::S3Compatible,
            endpoint: "https://objects.example".to_string(),
            access_key: "access".to_string(),
            secret_key: "secret".to_string(),
            region: "us-east-1".to_string(),
            role_arn: String::new(),
            external_id: None,
        },
    )
    .await;

    assert!(matches!(
        result,
        Err(WorkspaceStorageError::InvalidConfig(_))
    ));
    assert_eq!(repository.put_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn metered_read_records_admitted_bytes_before_returning_the_body() {
    let control = Arc::new(RecordingControlPlane::default());
    let operation = OperationIdentity {
        receipt_id: Uuid::now_v7(),
        operation_id: Uuid::now_v7(),
    };
    let auth = Auth {
        context: AuthenticatedRequestContext {
            user_id: "user-a".to_string(),
            workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-a").unwrap(),
        },
        credential_policy_id: "test".to_string(),
        public_key_pem: None,
        stable_key: None,
    };
    let authorization =
        operation.authorization("bucket-a", UsageRoute::GetObject, RequestKind::Read, 1024);
    let grant = test_grant(&authorization);
    let response = metered_read_response(
        control.clone(),
        &auth,
        &grant,
        "key-a",
        None,
        axum::response::Response::new(Body::from("range")),
        None,
    )
    .await;
    assert_eq!(
        *control.calls.lock().unwrap(),
        vec![UsageCall {
            context: auth.context.clone(),
            event: UsageEvent::from_grant(&grant, 5, 5),
        }]
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), b"range");
}

#[tokio::test]
async fn metered_read_failure_replaces_the_stream_with_a_generic_s3_error() {
    let control = Arc::new(RecordingControlPlane {
        failure: Some(MeteringError::Unavailable),
        ..RecordingControlPlane::default()
    });
    let auth = Auth {
        context: AuthenticatedRequestContext {
            user_id: "user-a".to_string(),
            workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-a").unwrap(),
        },
        credential_policy_id: "test".to_string(),
        public_key_pem: None,
        stable_key: None,
    };
    let operation = OperationIdentity {
        receipt_id: Uuid::now_v7(),
        operation_id: Uuid::now_v7(),
    };
    let authorization =
        operation.authorization("bucket-a", UsageRoute::GetObject, RequestKind::Read, 1024);
    let grant = test_grant(&authorization);
    let response = metered_read_response(
        control,
        &auth,
        &grant,
        "key-a",
        None,
        axum::response::Response::new(Body::from("range")),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("<Code>ServiceUnavailable</Code>"));
    assert!(!body.contains("database"));
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

#[tokio::test]
async fn definitive_provider_failure_has_stable_opaque_s3_response() {
    let response = streaming_put_error_response(
        "key",
        StreamingPutError::Transaction(TransactionError::Backend(
            crate::transaction::BackendError::definitive("PRINTABLE_PROVIDER_AUTHORIZATION_DETAIL"),
        )),
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("<Code>ServiceUnavailable</Code>"));
    assert!(!body.contains("PRINTABLE_PROVIDER_AUTHORIZATION_DETAIL"));
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

struct PollTrackingBody {
    polls: Arc<AtomicUsize>,
    data: Option<Bytes>,
}

struct GeneratedLineBody {
    remaining: u64,
    frame_bytes: usize,
}

impl http_body::Body for PollTrackingBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(self.data.take().map(|data| Ok(Frame::data(data))))
    }
}

impl http_body::Body for GeneratedLineBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let len = self.remaining.min(self.frame_bytes as u64) as usize;
        self.remaining -= len as u64;
        let mut data = vec![b'x'; len];
        data[len - 1] = b'\n';
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(data)))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

fn metadata(version_id: Option<&str>, etag: Option<&str>, content_type: &str) -> ObjectMetadata {
    let mut metadata = ObjectMetadata {
        version_id: version_id.map(str::to_owned),
        ..ObjectMetadata::default()
    };
    metadata.insert(header::CONTENT_TYPE, content_type);
    if let Some(etag) = etag {
        metadata.insert(header::ETAG, etag);
    }
    metadata
}

#[test]
fn transformed_source_binding_requires_a_version_or_matching_strong_etag() {
    let versioned = metadata(Some("v1"), None, "text/plain");
    assert!(transformed_source_matches_preflight(
        &versioned,
        &metadata(Some("v1"), None, "text/plain")
    ));
    assert!(!transformed_source_matches_preflight(
        &versioned,
        &metadata(Some("v2"), None, "text/plain")
    ));
    let suspended = metadata(Some("null"), None, "text/plain");
    assert!(
        !transformed_source_matches_preflight(
            &suspended,
            &metadata(Some("null"), None, "text/plain")
        ),
        "S3 versioning-suspended null versions are mutable and need a matching ETag"
    );

    let unversioned = metadata(None, Some("\"source-a\""), "text/plain");
    assert!(transformed_source_matches_preflight(
        &unversioned,
        &metadata(None, Some("\"source-a\""), "text/plain")
    ));
    assert!(!transformed_source_matches_preflight(
        &unversioned,
        &metadata(None, Some("\"source-b\""), "text/plain")
    ));
    assert!(!transformed_source_matches_preflight(
        &unversioned,
        &metadata(None, Some("W/\"source-a\""), "text/plain")
    ));
    assert!(!transformed_source_matches_preflight(
        &metadata(None, None, "text/plain"),
        &metadata(None, None, "text/plain")
    ));
}

#[test]
fn transformed_preflight_rejects_source_header_changes_without_polling_source() {
    let polls = Arc::new(AtomicUsize::new(0));
    let object = OpenedObject::new(
        StatusCode::OK,
        metadata(None, Some("\"source-a\""), "application/octet-stream"),
        Body::new(PollTrackingBody {
            polls: Arc::clone(&polls),
            data: Some(Bytes::from_static(b"must not be read")),
        }),
        BodyLimits::default(),
    );
    let params = S3Query::default();
    assert!(transformed_read_preflight(&HeaderMap::new(), &params, &object.metadata).is_err());
    assert_eq!(polls.load(Ordering::SeqCst), 0);

    let before = metadata(None, Some("\"source-a\""), "text/plain");
    let after = metadata(None, Some("\"source-a\""), "application/json");
    assert!(transformed_read_preflight(&HeaderMap::new(), &params, &before).is_ok());
    assert!(transformed_read_preflight(&HeaderMap::new(), &params, &after).is_ok());
    assert_ne!(
        transformed_read_preflight(&HeaderMap::new(), &params, &before).unwrap(),
        transformed_read_preflight(&HeaderMap::new(), &params, &after).unwrap(),
        "the GET representation cannot change source format after HEAD"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn transformed_source_returns_post_finish_fuel_for_spooled_evidence() {
    let component = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/components/noop.component.wasm"),
    )
    .expect("noop.component.wasm; run just build-plugins");
    let registry = PluginRegistry::new();
    registry.import("noop", &component).unwrap();
    let pipeline = registry
        .snapshot()
        .start_streaming_session(
            maskura_wasm_runtime::Session {
                format: "text".to_string(),
                content_type: "text/plain".to_string(),
                policy_version: 0,
                operation: maskura_wasm_runtime::Operation::Read,
                config_json: None,
                public_key_pem: None,
                stable_key: None,
                stable_fields: None,
            },
            maskura_wasm_runtime::CancellationToken::new(),
        )
        .await
        .unwrap();
    let object = OpenedObject::new(
        StatusCode::OK,
        metadata(None, Some("\"source-a\""), "text/plain"),
        Body::from("line\n"),
        BodyLimits::default(),
    );

    let fuel =
        process_transformed_source(object, pipeline, Format::Text, 1024, |_| async { Ok(()) })
            .await
            .unwrap();
    assert!(
        fuel > 0,
        "completed pipeline evidence must use measured fuel"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn successful_drop_all_direct_read_keeps_measured_finish_evidence() {
    let component = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-components/test-transformer.component.wasm"),
    )
    .expect("test-transformer.component.wasm; run just build-plugins");
    let registry = Arc::new(PluginRegistry::new());
    registry
        .import_with_capabilities(
            "dropper",
            &component,
            PluginCapabilities {
                prefix_safe_for_read: true,
            },
        )
        .unwrap();
    let resolver = crate::pipeline::StaticPipelineResolver::new(registry.clone());
    let resolution = crate::pipeline::PipelineResolver::resolve(
        &resolver,
        "workspace-a",
        "bucket-a",
        crate::pipeline::PipelineDirection::Read,
    )
    .await
    .unwrap();
    let snapshot = registry
        .snapshot_for(&resolution, registry.as_ref())
        .await
        .unwrap();
    let mut pipeline = snapshot
        .clone()
        .start_streaming_session(
            maskura_wasm_runtime::Session {
                format: "text".to_string(),
                content_type: "text/plain".to_string(),
                policy_version: 0,
                operation: maskura_wasm_runtime::Operation::Read,
                config_json: None,
                public_key_pem: None,
                stable_key: None,
                stable_fields: None,
            },
            maskura_wasm_runtime::CancellationToken::new(),
        )
        .await
        .unwrap();

    assert!(
        pipeline
            .process(crate::record::Record::new("drop", "\n"))
            .await
            .unwrap()
            .is_none()
    );
    let (_, fuel_consumed) = pipeline.finish().await.unwrap();
    let evidence = snapshot
        .pipeline_evidence(fuel_consumed, 5, "none")
        .unwrap();
    assert_eq!(evidence.fuel_consumed, fuel_consumed);
    assert!(evidence.fuel_consumed > 0);
    assert_eq!(evidence.duration_ms, 5);
    assert_eq!(evidence.spool_mode, "none");
}

#[tokio::test(flavor = "current_thread")]
async fn transformed_record_pipeline_has_fixed_rss_for_a_gibibyte_source() {
    const GIB: u64 = 1024 * 1024 * 1024;
    const FRAME_BYTES: usize = 64 * 1024;
    // Unit tests run in parallel with Wasmtime initialization elsewhere in
    // this process. This still catches whole-object buffering while leaving
    // room for unrelated allocator arena growth.
    const MAX_RSS_GROWTH: u64 = 256 * 1024 * 1024;

    let before = peak_rss_bytes();
    let registry = PluginRegistry::new();
    let pipeline = registry
        .snapshot()
        .start_streaming_session(
            maskura_wasm_runtime::Session {
                format: "text".to_string(),
                content_type: "text/plain".to_string(),
                policy_version: 0,
                operation: maskura_wasm_runtime::Operation::Write,
                config_json: None,
                public_key_pem: None,
                stable_key: None,
                stable_fields: None,
            },
            maskura_wasm_runtime::CancellationToken::new(),
        )
        .await
        .unwrap();
    let object = OpenedObject::new(
        StatusCode::OK,
        metadata(None, Some("\"source-a\""), "text/plain"),
        Body::new(GeneratedLineBody {
            remaining: GIB,
            frame_bytes: FRAME_BYTES,
        }),
        BodyLimits {
            max_frame_bytes: FRAME_BYTES,
            max_bytes: GIB,
        },
    );
    let output_bytes = Arc::new(AtomicU64::new(0));
    process_transformed_source(object, pipeline, Format::Text, FRAME_BYTES, {
        let output_bytes = Arc::clone(&output_bytes);
        move |bytes| {
            let output_bytes = Arc::clone(&output_bytes);
            async move {
                output_bytes.fetch_add(bytes.len() as u64, Ordering::SeqCst);
                Ok(())
            }
        }
    })
    .await
    .unwrap();
    let after = peak_rss_bytes();

    assert_eq!(output_bytes.load(Ordering::SeqCst), GIB);
    assert!(
        after.saturating_sub(before) <= MAX_RSS_GROWTH,
        "transformed 1 GiB stream grew peak RSS by {} MiB (limit {} MiB)",
        after.saturating_sub(before) / (1024 * 1024),
        MAX_RSS_GROWTH / (1024 * 1024),
    );
}

fn peak_rss_bytes() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the provided rusage on success, and
    // the pointer remains valid for the duration of the call.
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(result, 0, "getrusage failed");
    // SAFETY: a successful getrusage initialized the value.
    let usage = unsafe { usage.assume_init() };
    #[cfg(target_os = "macos")]
    {
        usage.ru_maxrss as u64
    }
    #[cfg(not(target_os = "macos"))]
    {
        usage.ru_maxrss as u64 * 1024
    }
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

#[cfg(test)]
mod mcp_token_response_tests {
    use super::{McpToken, mcp_token_responses};

    fn token(credential_id: Option<&str>, workspace_id: Option<&str>, hash: &str) -> McpToken {
        McpToken {
            credential_id: credential_id.map(str::to_string),
            token_hash: hash.to_string(),
            user_id: "user-a".to_string(),
            workspace_id: workspace_id.map(str::to_string),
            label: "test".to_string(),
            created_at: "0".to_string(),
            expires_at: None,
        }
    }

    #[test]
    fn omits_unusable_legacy_rows_without_hiding_valid_tokens() {
        let responses = mcp_token_responses(vec![
            token(None, Some("workspace-a"), "legacy-hash"),
            token(
                Some("01995f4d-42ff-7000-8000-000000000000"),
                None,
                "unbound-hash",
            ),
            token(
                Some("01995f4d-42ff-7000-8000-000000000001"),
                Some("workspace-a"),
                "valid-hash",
            ),
        ]);

        assert_eq!(responses.len(), 1);
        assert_eq!(
            responses[0].credential_id,
            "01995f4d-42ff-7000-8000-000000000001"
        );
        assert_eq!(responses[0].token_hash, "valid-hash");
    }
}

#[cfg(test)]
mod auth_tests {
    use super::supabase_jwt_validation;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, decode, encode};

    #[test]
    fn accepts_supabase_authenticated_audience() {
        let secret = b"test-secret";
        let issuer = "https://example.supabase.co/auth/v1";
        let claims = serde_json::json!({
            "sub": "user-123",
            "iss": issuer,
            "aud": "authenticated",
            "exp": u64::MAX,
        });
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .expect("encode token");
        let validation = supabase_jwt_validation(Algorithm::HS256, issuer);

        let decoded =
            decode::<serde_json::Value>(&token, &DecodingKey::from_secret(secret), &validation)
                .expect("valid Supabase token");

        assert_eq!(decoded.claims["sub"], "user-123");
    }
}

#[cfg(test)]
mod demo_limiter_tests {
    use std::path::Path;
    use std::time::Duration;

    use super::{ApiDoc, DemoLimitError, DemoLimiter, build_demo_pipelines};
    use utoipa::OpenApi;

    #[test]
    fn rejects_a_fifth_concurrent_operation_without_counting_it_as_a_start() {
        let limiter = DemoLimiter::with_limits(4, 5, Duration::from_secs(60));
        let permits: Vec<_> = (0..4)
            .map(|_| limiter.try_start().expect("first four operations start"))
            .collect();
        assert!(matches!(
            limiter.try_start(),
            Err(DemoLimitError::Concurrent)
        ));

        drop(permits);
        assert!(limiter.try_start().is_ok());
    }

    #[test]
    fn rejects_more_than_thirty_starts_in_the_window() {
        let limiter = DemoLimiter::with_limits(4, 30, Duration::from_secs(60));
        for _ in 0..30 {
            drop(limiter.try_start().expect("operation starts within limit"));
        }
        assert!(matches!(limiter.try_start(), Err(DemoLimitError::Rate)));
    }

    #[test]
    fn dedicated_demo_snapshots_are_ordered_and_join_fails_closed() {
        let components = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/components");
        let pii = std::fs::read(components.join("pii-default.component.wasm"))
            .expect("pii-default.component.wasm; run just build-plugins");
        let stable = std::fs::read(components.join("stable-encrypt.component.wasm"))
            .expect("stable-encrypt.component.wasm; run just build-plugins");

        let unavailable = build_demo_pipelines(&pii, None, 1_000_000_000).unwrap();
        assert!(unavailable.join.is_none());
        assert_eq!(
            unavailable
                .safe
                .plugin_infos()
                .into_iter()
                .map(|plugin| plugin.name)
                .collect::<Vec<_>>(),
            ["pii-default"]
        );

        let malformed = build_demo_pipelines(&pii, Some(b"not a component"), 1_000_000_000)
            .expect("safe demo remains available when stable-encrypt is malformed");
        assert!(malformed.join.is_none());

        let available = build_demo_pipelines(&pii, Some(&stable), 1_000_000_000).unwrap();
        assert_eq!(
            available
                .join
                .expect("valid bundled stable component enables join")
                .plugin_infos()
                .into_iter()
                .map(|plugin| plugin.name)
                .collect::<Vec<_>>(),
            ["stable-encrypt", "pii-default"]
        );
    }

    #[test]
    fn stateless_demo_process_is_not_published_in_openapi() {
        let document = serde_json::to_value(ApiDoc::openapi()).unwrap();
        assert_eq!(document["info"]["title"], "Maskura Gateway API");
        assert_eq!(document["info"]["version"], env!("CARGO_PKG_VERSION"));
        assert!(
            document["paths"]
                .get("/dashboard/api/demo/process")
                .is_none()
        );
        for schema in [
            "DemoMode",
            "DemoProcessRequest",
            "DemoProcessedRecord",
            "DemoProcessResponse",
            "DemoErrorResponse",
        ] {
            assert!(document["components"]["schemas"].get(schema).is_none());
        }
    }

    #[test]
    fn credential_schemas_and_mcp_dashboard_paths_are_published() {
        let document = serde_json::to_value(ApiDoc::openapi()).unwrap();
        assert!(document["paths"]["/dashboard/api/mcp-tokens"].is_object());
        for schema in ["ApiKeyResponse", "ListKeyResponse"] {
            assert!(
                document["components"]["schemas"][schema]["properties"]["workspace_id"].is_object()
            );
        }
        for schema in ["McpTokenResponse", "McpTokenCreatedResponse"] {
            assert!(
                document["components"]["schemas"][schema]["properties"]["credential_id"]
                    .is_object()
            );
            assert!(
                document["components"]["schemas"][schema]["properties"]["workspace_id"].is_object()
            );
        }
    }
}

#[cfg(test)]
mod multipart_completion_tests {
    use super::parse_complete_multipart_xml;

    #[test]
    fn complete_xml_is_strict_ordered_and_entity_free() {
        let parts = parse_complete_multipart_xml(
            br#"<?xml version="1.0"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"one"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"two"</ETag><ChecksumSHA256>abc</ChecksumSHA256></Part></CompleteMultipartUpload>"#,
        )
        .unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1].checksum_sha256.as_deref(), Some("abc"));
        assert!(parse_complete_multipart_xml(
            br#"<CompleteMultipartUpload><Part><PartNumber>2</PartNumber><ETag>"two"</ETag></Part><Part><PartNumber>1</PartNumber><ETag>"one"</ETag></Part></CompleteMultipartUpload>"#,
        )
        .is_err());
        assert!(parse_complete_multipart_xml(
            br#"<!DOCTYPE x [<!ENTITY boom "boom">]><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>&boom;</ETag></Part></CompleteMultipartUpload>"#,
        )
        .is_err());
    }

    #[test]
    fn complete_xml_accepts_quoted_hex_etags() {
        let parts = parse_complete_multipart_xml(
            br#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"c56e589acfa9d79113ff4c36f72d0228"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"cde8de78ea9269548adfcd9f7505ae9b"</ETag></Part></CompleteMultipartUpload>"#,
        )
        .expect("two-part complete XML with quoted hex ETags must parse");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].etag, "\"c56e589acfa9d79113ff4c36f72d0228\"");
    }
}

#[cfg(test)]
mod s3_provider_capability_tests {
    use maskura_customer_config::config::{
        MultipartMode as ConfigMultipartMode, StreamingReadMode as ConfigStreamingReadMode,
        StreamingS3Provider,
    };

    use super::*;

    #[test]
    fn resolved_feature_config_drives_gateway_modes_and_capabilities() {
        for provider in [
            StreamingS3Provider::Aws,
            StreamingS3Provider::Minio,
            StreamingS3Provider::R2,
            StreamingS3Provider::B2,
        ] {
            let mut config = Config::default();
            config.features.streaming_s3_provider = Some(provider);
            let capabilities = configured_s3_streaming_capabilities(&config);
            assert!(
                capabilities.is_some(),
                "configured provider must enable direct S3 streaming"
            );
            let capabilities = capabilities.expect("capabilities present");
            assert!(capabilities.supports_conditional_reads());
            assert!(capabilities.supports_response_checksums());
        }

        let mut config = Config::default();
        assert!(configured_s3_streaming_capabilities(&config).is_none());
        assert!(configured_managed_streaming_capabilities(&config).is_none());
        assert_eq!(multipart_mode(&config), MultipartMode::Reject);
        assert_eq!(
            StreamingReadMode::from_config(&config),
            StreamingReadMode::Off
        );

        config.features.managed_streaming_transactional = true;
        config.features.multipart_mode = ConfigMultipartMode::Staged;
        config.features.streaming_read_mode = ConfigStreamingReadMode::Transformed;
        assert!(configured_managed_streaming_capabilities(&config).is_some());
        assert_eq!(multipart_mode(&config), MultipartMode::Staged);
        assert_eq!(
            StreamingReadMode::from_config(&config),
            StreamingReadMode::Transformed
        );
    }

    #[test]
    fn resolved_limits_preserve_immutable_safety_caps() {
        let mut config = Config::default();
        let defaults = source_body_limits(&config).unwrap();
        assert_eq!(
            defaults.max_frame_bytes,
            crate::object::DEFAULT_MAX_SOURCE_FRAME_BYTES
        );
        assert_eq!(defaults.max_bytes, crate::object::DEFAULT_MAX_SOURCE_BYTES);
        assert_eq!(legacy_max_object_bytes(&config), LEGACY_MAX_OBJECT_BYTES);
        assert_eq!(
            dev_memory_max_object_bytes(&config),
            LEGACY_MAX_OBJECT_BYTES
        );

        config.limits.source_max_frame_bytes = Some(4096);
        config.limits.max_object_bytes = Some(u64::MAX);
        config.limits.max_pipeline_output_bytes = Some(u64::MAX);
        config.limits.legacy_max_object_bytes = Some(u64::MAX);
        config.limits.dev_memory_max_object_bytes = Some(u64::MAX);
        let limits = source_body_limits(&config).unwrap();
        assert_eq!(limits.max_frame_bytes, 4096);
        assert_eq!(limits.max_bytes, crate::object::DEFAULT_MAX_SOURCE_BYTES);
        assert_eq!(
            max_pipeline_output_bytes(&config),
            PipelineLimits::default().max_output_bytes
        );
        assert_eq!(legacy_max_object_bytes(&config), LEGACY_MAX_OBJECT_BYTES);
        assert_eq!(dev_memory_max_object_bytes(&config), 64 * 1024 * 1024);
    }

    #[test]
    fn resolved_wasm_config_drives_paths_fuel_and_prefix_capabilities() {
        let mut config = Config::default();
        config.wasm.filter_component = Some("/tmp/filter.component.wasm".to_string());
        config.wasm.fuel = Some(123_456);
        config.wasm.prefix_safe_component_hashes = vec!["AB".repeat(32)];

        assert_eq!(
            component_path(&config),
            PathBuf::from("/tmp/filter.component.wasm")
        );
        assert_eq!(pipeline_fuel(&config), 123_456);
        assert!(prefix_safe_component_hashes(&config).contains(&"ab".repeat(32)));
    }

    #[test]
    fn resolved_spool_managed_and_multipart_config_drives_runtime_values() {
        let mut config = Config::default();
        assert_eq!(spool_limits(&config, 1024), (1024, 2048));
        assert_eq!(
            multipart_quota_bytes(&config, 1024),
            (
                1024 * MAX_ACTIVE_UPLOADS as u64,
                4096 * MAX_ACTIVE_UPLOADS as u64
            )
        );
        assert_eq!(managed_placement_version(&config), PLACEMENT_VERSION_V1);

        config.spool.max_object_bytes = Some(512);
        config.spool.quota_bytes = Some(1536);
        config.multipart_staging.tenant_quota_bytes = Some(2048);
        config.multipart_staging.global_quota_bytes = Some(4096);
        config.managed.placement_version = Some(7);
        assert_eq!(spool_limits(&config, 1024), (512, 1536));
        assert_eq!(multipart_quota_bytes(&config, 1024), (2048, 4096));
        assert_eq!(managed_placement_version(&config), 7);

        config.spool.max_object_bytes = Some(4096);
        config.spool.quota_bytes = Some(4096);
        assert_eq!(spool_limits(&config, 1024), (1024, 4096));
    }

    #[tokio::test]
    async fn configured_local_root_fails_closed_on_persisted_secret_mismatch() {
        let keys = KeyStore::new();
        let workspace = WorkspaceId::new("workspace").unwrap();
        ensure_configured_local_root(&keys, "root-user", "first-secret", &workspace)
            .await
            .unwrap();
        ensure_configured_local_root(&keys, "root-user", "first-secret", &workspace)
            .await
            .unwrap();

        let error =
            ensure_configured_local_root(&keys, "root-user", "different-secret", &workspace)
                .await
                .unwrap_err();
        assert!(error.to_string().contains("do not match"));
        assert!(
            keys.resolve_credentials("root-user", "first-secret")
                .await
                .unwrap()
                .is_some()
        );
    }
}

#[cfg(test)]
mod multipart_listing_validation_tests {
    use super::*;

    fn part(number: u32, size: u64) -> MultipartPart {
        MultipartPart {
            upload_id: "upload-1".to_string(),
            part_number: number,
            attempt: 1,
            artifact_key: format!("artifact-{number}"),
            etag: format!("\"etag-{number}\""),
            checksum_sha256: hex::encode([number as u8; 32]),
            size_bytes: size,
            created_at_ms: 1_700_000_000_000,
        }
    }

    fn listing_upload(key: &str, upload_id: &str) -> MultipartUpload {
        MultipartUpload {
            identity: MultipartIdentity {
                tenant_id: "tenant-1".to_string(),
                credential_policy_id: "credential-1".to_string(),
                bucket: "bucket".to_string(),
                key: key.to_string(),
                upload_id: upload_id.to_string(),
            },
            namespace_epoch: None,
            snapshot: MultipartSnapshot {
                metadata: std::collections::BTreeMap::new(),
                tags: std::collections::BTreeMap::new(),
                checksum_mode: None,
                destination: serde_json::json!({"kind": "file"}),
                plugin_snapshot: serde_json::json!({}),
                max_staged_bytes: 0,
            },
            lifecycle: MultipartLifecycle::Open,
            staged_bytes: 0,
            reserved_bytes: 0,
            created_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_000_000_000 + 86_400_000,
            updated_at_ms: 1_700_000_000_000,
            tombstone_until_ms: None,
            complete_request_fingerprint: None,
            completion_lease_owner: None,
            completion_lease_expires_at_ms: None,
            completion_fencing_token: 0,
            destination_operation_id: None,
            publishing_started_at_ms: None,
            destination_commit: None,
            completion_result: None,
        }
    }

    #[test]
    fn list_multipart_uploads_xml_round_trips_markers_prefixes_and_encoding() {
        let upload = listing_upload("directory/key with space", "upload-1");
        let page = ListMultipartUploadsPage {
            uploads: vec![upload],
            common_prefixes: vec!["directory/".to_string()],
            is_truncated: true,
            next_key_marker: Some("directory/key with space".to_string()),
            next_upload_id_marker: Some("upload-1".to_string()),
        };
        let xml = list_multipart_uploads_xml(
            "bucket",
            "directory/",
            Some("/"),
            Some("directory/"),
            Some("upload-1"),
            1000,
            &page,
            true,
        );
        assert!(xml.contains("<KeyMarker>directory%2F</KeyMarker>"));
        assert!(xml.contains("<NextKeyMarker>directory%2Fkey%20with%20space</NextKeyMarker>"));
        assert!(xml.contains("<NextUploadIdMarker>upload-1</NextUploadIdMarker>"));
        assert!(xml.contains("<EncodingType>url</EncodingType>"));
        assert!(xml.contains("<CommonPrefixes><Prefix>directory%2F</Prefix></CommonPrefixes>"));
        assert!(xml.contains("<Upload><Key>directory%2Fkey%20with%20space</Key>"));
        assert!(xml.contains("<StorageClass>STANDARD</StorageClass>"));
        assert!(xml.contains("<IsTruncated>true</IsTruncated>"));
        assert!(xml.contains("<MaxUploads>1000</MaxUploads>"));
        xmlparser::Tokenizer::from(xml.as_str()).for_each(|token| {
            token.expect("generated XML must be well-formed");
        });
    }

    #[test]
    fn list_multipart_uploads_xml_plain_keys_are_xml_escaped() {
        let upload = listing_upload("a&b<c", "upload-2");
        let page = ListMultipartUploadsPage {
            uploads: vec![upload],
            common_prefixes: Vec::new(),
            is_truncated: false,
            next_key_marker: None,
            next_upload_id_marker: None,
        };
        let xml = list_multipart_uploads_xml("bucket", "", None, None, None, 1000, &page, false);
        assert!(xml.contains("<Key>a&amp;b&lt;c</Key>"));
        assert!(!xml.contains("<Key>a&b<c</Key>"));
        assert!(!xml.contains("<EncodingType>url</EncodingType>"));
    }

    #[test]
    fn list_parts_xml_includes_pagination_fields() {
        let xml = list_parts_xml(
            "bucket",
            "key",
            "upload-1",
            1,
            10,
            &[part(2, 100), part(3, 200)],
            true,
        );
        assert!(xml.contains("<PartNumberMarker>1</PartNumberMarker>"));
        assert!(xml.contains("<NextPartNumberMarker>3</NextPartNumberMarker>"));
        assert!(xml.contains("<MaxParts>10</MaxParts>"));
        assert!(xml.contains("<IsTruncated>true</IsTruncated>"));
        assert!(xml.contains("<PartNumber>2</PartNumber><LastModified>"));
        assert!(xml.contains("<ChecksumSHA256>"));
        xmlparser::Tokenizer::from(xml.as_str()).for_each(|token| {
            token.expect("generated XML must be well-formed");
        });
    }

    #[test]
    fn completion_part_sizes_allow_zero_final_but_reject_small_nonfinal_parts() {
        let minimum = MIN_MULTIPART_NONFINAL_PART_BYTES;
        assert!(validate_completion_part_sizes(&[part(1, 0)]).is_ok());
        assert!(validate_completion_part_sizes(&[part(1, minimum), part(2, 0)]).is_ok());
        assert!(validate_completion_part_sizes(&[part(1, minimum), part(2, 1)]).is_ok());
        assert_eq!(
            validate_completion_part_sizes(&[part(1, minimum - 1), part(2, minimum)]),
            Err(CompletionPartSizeError::NonFinalTooSmall {
                part_number: 1,
                size_bytes: minimum - 1,
            })
        );
        assert_eq!(
            validate_completion_part_sizes(&[part(1, 0), part(2, 0)]),
            Err(CompletionPartSizeError::NonFinalTooSmall {
                part_number: 1,
                size_bytes: 0,
            })
        );
    }

    #[test]
    fn completion_part_sizes_reject_assembled_ceiling_overruns() {
        let ceiling = MAX_MULTIPART_ASSEMBLED_SOURCE_BYTES;
        let minimum = MIN_MULTIPART_NONFINAL_PART_BYTES;
        assert_eq!(
            validate_completion_part_sizes(&[part(1, minimum), part(2, ceiling - minimum + 1),]),
            Err(CompletionPartSizeError::AssembledTooLarge(ceiling + 1))
        );
        assert!(
            validate_completion_part_sizes(&[part(1, minimum), part(2, ceiling - minimum),])
                .is_ok()
        );
    }

    #[test]
    fn staged_part_reservation_accepts_zero_and_rejects_missing_and_oversized() {
        use axum::http::{HeaderMap, HeaderValue};
        let zero = HeaderMap::from_iter([(header::CONTENT_LENGTH, HeaderValue::from_static("0"))]);
        assert_eq!(staged_part_reservation(&zero), Ok(0));
        let missing = HeaderMap::new();
        assert_eq!(
            staged_part_reservation(&missing),
            Err(PartReservationError::Missing)
        );
        let oversized = HeaderMap::from_iter([(
            header::CONTENT_LENGTH,
            HeaderValue::from_static("5368709121"),
        )]);
        assert_eq!(
            staged_part_reservation(&oversized),
            Err(PartReservationError::TooLarge(MAX_MULTIPART_PART_BYTES + 1))
        );
        let decoded = HeaderMap::from_iter([(
            HeaderName::from_static("x-amz-decoded-content-length"),
            HeaderValue::from_static("0"),
        )]);
        assert_eq!(staged_part_reservation(&decoded), Ok(0));
    }

    #[test]
    fn stored_metadata_partitions_content_headers_from_user_metadata() {
        let mut snapshot = MultipartSnapshot {
            metadata: std::collections::BTreeMap::new(),
            tags: std::collections::BTreeMap::new(),
            checksum_mode: Some("SHA256".to_string()),
            destination: serde_json::json!({"kind": "file"}),
            plugin_snapshot: serde_json::json!({}),
            max_staged_bytes: 0,
        };
        snapshot
            .metadata
            .insert("content-type".into(), "text/plain".into());
        snapshot
            .metadata
            .insert("content-encoding".into(), "gzip".into());
        snapshot.metadata.insert("project".into(), "maskura".into());
        snapshot.tags.insert("team".into(), "data".into());
        let stored = multipart_stored_metadata(&snapshot);
        assert_eq!(
            stored
                .representation_headers
                .get("content-encoding")
                .map(String::as_str),
            Some("gzip")
        );
        assert!(!stored.representation_headers.contains_key("content-type"));
        assert_eq!(
            stored.user_metadata.get("project").map(String::as_str),
            Some("maskura")
        );
        assert_eq!(stored.user_metadata.len(), 1);
        assert_eq!(stored.tags.get("team").map(String::as_str), Some("data"));
        assert_eq!(stored.checksum_algorithm.as_deref(), Some("SHA256"));
        assert!(validate_multipart_checksum_mode(&snapshot).is_ok());
        snapshot.checksum_mode = Some("CRC32".to_string());
        assert_eq!(
            validate_multipart_checksum_mode(&snapshot),
            Err("unsupported checksum algorithm; supported values are SHA256")
        );
    }

    #[test]
    fn single_put_metadata_partitions_headers_like_multipart() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-type",
            axum::http::HeaderValue::from_static("text/plain"),
        );
        headers.insert(
            "content-encoding",
            axum::http::HeaderValue::from_static("gzip"),
        );
        headers.insert(
            "x-amz-meta-project",
            axum::http::HeaderValue::from_static("maskura"),
        );
        headers.insert(
            "x-amz-tagging",
            axum::http::HeaderValue::from_static("team=data"),
        );
        headers.insert(
            "x-amz-checksum-algorithm",
            axum::http::HeaderValue::from_static("SHA256"),
        );
        let stored = single_put_stored_metadata(&headers);
        assert_eq!(
            stored
                .representation_headers
                .get("content-encoding")
                .map(String::as_str),
            Some("gzip")
        );
        assert!(!stored.representation_headers.contains_key("content-type"));
        assert_eq!(
            stored.user_metadata.get("project").map(String::as_str),
            Some("maskura")
        );
        assert_eq!(stored.user_metadata.len(), 1);
        assert_eq!(stored.tags.get("team").map(String::as_str), Some("data"));
        assert_eq!(stored.checksum_algorithm.as_deref(), Some("SHA256"));
    }

    #[test]
    fn streaming_put_defaults_missing_content_type_to_octet_stream() {
        let empty = HeaderMap::new();
        assert_eq!(
            streaming_format(&empty).unwrap(),
            (Format::Binary, "application/octet-stream".to_string())
        );

        let mut octet = HeaderMap::new();
        octet.insert(
            header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/octet-stream"),
        );
        assert_eq!(
            streaming_format(&octet).unwrap(),
            (Format::Binary, "application/octet-stream".to_string())
        );

        let mut binary = HeaderMap::new();
        binary.insert(
            header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("binary/octet-stream"),
        );
        assert_eq!(
            streaming_format(&binary).unwrap(),
            (Format::Binary, "binary/octet-stream".to_string())
        );
    }
}
