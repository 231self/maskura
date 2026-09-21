use super::*;
use crate::control::NoopControlPlane;
use crate::file_multipart_repository::FileMultipartRepository;
use crate::managed::{
    InMemoryManagedRepository, ManagedSettlementState, PostgresManagedRepository,
};
use crate::multipart_staging::{DestinationCommitPermit, MultipartIdentity, StagingQuotaLimits};
use std::sync::Mutex;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::routing::any;

type ProviderRequests = Arc<Mutex<Vec<(Method, String)>>>;

#[test]
fn service_backend_parser_accepts_exact_valid_entries() {
    let backends = parse_service_backends(
            "aws|https://s3.us-east-1.amazonaws.com|us-east-1|bucket.one|AKIA123|secret+/=;r2|https://account.r2.cloudflarestorage.com|auto|bucket-two|key|secret",
        )
        .unwrap();

    assert_eq!(backends.len(), 2);
    assert_eq!(backends[0].provider, "aws");
    assert_eq!(backends[1].bucket, "bucket-two");

    let managed = parse_service_backends(
            "b2|managed-primary|account-123|2|https://s3.us-east-005.backblazeb2.com|us-east-005|managed-bucket|rotated-key|rotated-secret",
        )
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(managed.provider_kind(), "b2");
    assert_eq!(managed.provider_instance_id(), Some("managed-primary"));
    assert_eq!(managed.provider_account_id(), Some("account-123"));
    assert_eq!(managed.credential_epoch(), Some(2));
    assert_eq!(managed.placement_weight, 1);
    assert_eq!(managed.placement_capacity_units, 1);
    assert_eq!(managed.id(), "b2:managed-primary");
    assert_eq!(
        managed.storage_identity().unwrap().canonical_endpoint,
        "https://s3.us-east-005.backblazeb2.com/"
    );
    let weighted = parse_service_backends(
            "b2|managed-secondary|account-123|3|4|5|https://s3.us-east-005.backblazeb2.com|us-east-005|managed-bucket-two|rotated-key|rotated-secret",
        )
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(weighted.placement_weight, 4);
    assert_eq!(weighted.placement_capacity_units, 5);
    assert!(
        parse_service_backends(
            "b2|managed-primary|2|https://s3.example|us-east-1|bucket|key|secret"
        )
        .unwrap_err()
        .contains("nine managed identity fields")
    );
}

#[test]
fn transactional_managed_launch_requires_identified_b2_or_aws_pool_with_static_policy() {
    let repository = Arc::new(InMemoryManagedRepository::new());
    let managed = parse_service_backends(
            "b2|managed-primary|account-123|1|https://s3.us-east-005.backblazeb2.com|us-east-005|managed-bucket|key|secret",
        )
        .unwrap();
    let storage = ServiceStorage::with_management(
        managed,
        repository.clone(),
        ManagedStreamingMode::Enforce,
        PLACEMENT_VERSION_V1,
    );
    assert!(storage.validate_managed_launch_configuration().is_ok());

    let mixed_pool = parse_service_backends(
            "b2|managed-primary|account-123|1|1|1|https://s3.us-east-005.backblazeb2.com|us-east-005|managed-bucket|key|secret;aws|managed-replica|account-456|2|3|2|https://s3.us-east-1.amazonaws.com|us-east-1|managed-bucket-two|key|secret",
        )
        .unwrap();
    assert!(
        ServiceStorage::with_management(
            mixed_pool,
            repository.clone(),
            ManagedStreamingMode::Enforce,
            PLACEMENT_VERSION_V1,
        )
        .validate_managed_launch_configuration()
        .is_ok()
    );

    let mut missing_epoch = parse_service_backends(
            "aws|managed-primary|account-123|1|https://s3.us-east-1.amazonaws.com|us-east-1|bucket|key|secret",
        )
        .unwrap();
    missing_epoch[0].credential_epoch = None;
    let mut invalid_placement = parse_service_backends(
            "b2|managed-primary|account-123|1|https://s3.us-east-005.backblazeb2.com|us-east-005|bucket|key|secret",
        )
        .unwrap();
    invalid_placement[0].placement_weight = 0;

    for invalid in [
            Vec::new(),
            parse_service_backends(
                "r2|provider-one|account-123|1|https://s3.example|us-east-1|bucket|key|secret",
            )
            .unwrap(),
            parse_service_backends(
                "minio|provider-one|account-123|1|https://s3.example|us-east-1|bucket|key|secret",
            )
            .unwrap(),
            parse_service_backends(
                "custom|provider-one|account-123|1|https://s3.example|us-east-1|bucket|key|secret",
            )
            .unwrap(),
            parse_service_backends(
                "AWS|provider-one|account-123|1|https://s3.example|us-east-1|bucket|key|secret",
            )
            .unwrap(),
            parse_service_backends(
                "B2|provider-one|account-123|1|https://s3.example|us-east-1|bucket|key|secret",
            )
            .unwrap(),
            parse_service_backends(
                "b2|https://s3.example|us-east-1|bucket|key|secret",
            )
            .unwrap(),
            parse_service_backends(
                "b2|managed-primary|account-123|1|http://s3.example|us-east-1|bucket|key|secret",
            )
            .unwrap(),
            parse_service_backends(
                "aws|managed-primary|account-123|1|http://s3.example|us-east-1|bucket|key|secret",
            )
            .unwrap(),
            parse_service_backends(
                "b2|duplicate|account-1|1|1|1|https://s3.example|us-east-1|bucket-one|key|secret;b2|duplicate|account-2|1|1|1|https://s3.example|us-east-1|bucket-two|key|secret",
            )
            .unwrap(),
            missing_epoch,
            invalid_placement,
        ] {
            let storage = ServiceStorage::with_management(
                invalid,
                repository.clone(),
                ManagedStreamingMode::Enforce,
                PLACEMENT_VERSION_V1,
            );
            assert!(storage.validate_managed_launch_configuration().is_err());
        }
    for invalid_policy in [
        "b2|one|account-1|1|0|1|https://s3.example|us-east-1|bucket|key|secret",
        "b2|one|account-1|1|1|0|https://s3.example|us-east-1|bucket|key|secret",
        "b2|one|account-1|1|18446744073709551615|2|https://s3.example|us-east-1|bucket|key|secret",
    ] {
        assert!(parse_service_backends(invalid_policy).is_err());
    }
}

#[test]
fn managed_placement_is_weighted_order_independent_and_has_distinct_replica() {
    let first = parse_service_backends(
            "b2|one|account-1|1|1|1|https://s3.example|us-east-1|bucket-one|key|secret;b2|two|account-2|1|3|1|https://s3.example|us-east-1|bucket-two|key|secret;b2|three|account-3|1|2|1|https://s3.example|us-east-1|bucket-three|key|secret",
        )
        .unwrap();
    let second = vec![first[2].clone(), first[0].clone(), first[1].clone()];
    let logical = LogicalObjectKey::new("tenant", "bucket", "key");
    let first_placement = ServiceStorage::new(first).placement(&logical).unwrap();
    let second_placement = ServiceStorage::new(second).placement(&logical).unwrap();
    assert_eq!(first_placement, second_placement);
    assert_ne!(
        first_placement.primary_backend_id,
        first_placement.replica_backend_id.unwrap()
    );
}

#[test]
fn service_backend_parser_rejects_missing_extra_and_empty_fields() {
    for value in [
        "aws|https://s3.example|us-east-1|bucket|access",
        "aws|https://s3.example|us-east-1|bucket|access|secret|extra",
        "aws|https://s3.example|us-east-1|bucket|access|secret;",
        "",
    ] {
        assert!(parse_service_backends(value).is_err(), "accepted {value:?}");
    }

    for empty_field in 0..6 {
        let mut fields = [
            "aws",
            "https://s3.example",
            "us-east-1",
            "bucket",
            "access",
            "secret",
        ];
        fields[empty_field] = " ";
        assert!(
            parse_service_backends(&fields.join("|")).is_err(),
            "accepted empty field {empty_field}",
        );
    }
}

#[test]
fn service_backend_parser_rejects_malformed_fields_without_echoing_values() {
    let malformed = [
        "aws/provider|https://s3.example|us-east-1|bucket|access|secret",
        "aws|not-a-url|us-east-1|bucket|access|secret",
        "aws|https://user@s3.example|us-east-1|bucket|access|secret",
        "aws|https://s3.example?credential=secret|us-east-1|bucket|access|secret",
        "aws|https://s3.example|us/east/1|bucket|access|secret",
        "aws|https://s3.example|us-east-1|bucket/name|access|secret",
        "aws|https://s3.example|us-east-1|bucket|ACCESS KEY VALUE|secret",
        "aws|https://s3.example|us-east-1|bucket|access|secret\nvalue",
    ];
    for value in malformed {
        let error = parse_service_backends(value).unwrap_err();
        assert!(!error.contains(value));
        assert!(!error.contains("credential=secret"));
        assert!(!error.contains("ACCESS KEY VALUE"));
        assert!(!error.contains("secret\nvalue"));
    }
}

async fn purge_provider_mock(
    State(requests): State<ProviderRequests>,
    method: Method,
    uri: Uri,
) -> axum::response::Response {
    requests
        .lock()
        .unwrap()
        .push((method.clone(), uri.to_string()));
    if method == Method::GET && uri.query() == Some("versioning") {
        axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/xml")
            .body(Body::from(
                r#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>"#,
            ))
            .unwrap()
    } else if method == Method::HEAD {
        axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap()
    } else {
        axum::response::Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap()
    }
}

fn authority() -> ObjectAuthority {
    ObjectAuthority {
        logical: LogicalObjectKey::new("tenant", "bucket", "key"),
        generation: uuid::Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap(),
        digest: "abc123".to_string(),
        size: 42,
        metadata: BTreeMap::new(),
        placement_version: 1,
        primary_backend_id: "primary".to_string(),
        primary_version_id: None,
        replica_backend_id: Some("replica".to_string()),
        primary_status: CopyStatus::Ready,
        replica_status: CopyStatus::Ready,
        tombstone: false,
        cas_version: 1,
        created_at_ms: 0,
        updated_at_ms: 0,
    }
}

fn purge_request() -> NamespacePurgeRequest {
    NamespacePurgeRequest {
        tenant_id: "tenant".to_string(),
        operation_id: uuid::Uuid::now_v7(),
    }
}

fn managed_test_capabilities() -> BackendCapabilities {
    BackendCapabilities {
        incomplete_upload_discovery:
            crate::transaction::IncompleteUploadDiscovery::ExactKeyAndStartTime,
        abort_incomplete_upload: true,
        cleanup_sla: Some(Duration::from_secs(60)),
        lifecycle_rule: true,
        versioning: crate::transaction::VersioningCapability::Optional,
        conditional_reads: crate::transaction::ConditionalReadCapability::VersionAndEtag,
        response_checksums: crate::transaction::ResponseChecksumCapability::Standard,
        list_operations: crate::transaction::ListCapability::V1AndV2,
        multipart_responses: crate::transaction::MultipartResponseCapability::Standard,
        completion_reconciliation:
            crate::transaction::CompletionReconciliation::HeadWithOperationIdentity,
    }
}

fn test_storage_identity() -> ProviderStorageIdentity {
    ProviderStorageIdentity {
        provider_kind: "test".to_string(),
        provider_instance_id: "managed-primary".to_string(),
        provider_account_id: "test-account".to_string(),
        canonical_endpoint: "https://provider.example/".to_string(),
        region: "test-region-1".to_string(),
    }
}

async fn assert_default_purge_is_unsupported(storage: &ServiceStorage) {
    let request = purge_request();
    assert!(matches!(
        storage.purge_namespace(&request).await.unwrap(),
        NamespacePurgeStatus::Unsupported { .. }
    ));
    assert!(matches!(
        storage.namespace_purge_status(&request).await.unwrap(),
        NamespacePurgeStatus::Unsupported { .. }
    ));
}

#[tokio::test]
async fn namespace_purge_without_authority_is_explicitly_unsupported() {
    let storage = ServiceStorage::new(Vec::new());
    let request = purge_request();
    assert_eq!(
        storage.purge_namespace(&request).await.unwrap(),
        NamespacePurgeStatus::Unsupported {
            reason: "managed namespace purge requires an authority repository".to_string(),
        }
    );
    assert_eq!(
        storage.namespace_purge_status(&request).await.unwrap(),
        NamespacePurgeStatus::Unsupported {
            reason: "managed namespace purge status requires an authority repository".to_string(),
        }
    );
}

#[tokio::test]
async fn empty_namespace_purge_delegates_and_completes_in_memory() {
    let storage = ServiceStorage::with_management(
        Vec::new(),
        Arc::new(InMemoryManagedRepository::new()),
        ManagedStreamingMode::Enforce,
        PLACEMENT_VERSION_V1,
    )
    .with_managed_capabilities(Some(managed_test_capabilities()));
    assert_eq!(
        storage.purge_namespace(&purge_request()).await.unwrap(),
        NamespacePurgeStatus::Complete {
            deleted_versions: 0,
        }
    );
}

#[tokio::test]
async fn committed_delete_settlement_is_replayed_from_durable_operation() {
    let repository = Arc::new(InMemoryManagedRepository::new());
    let backend = parse_service_backends(
            "b2|managed-primary|account-123|1|https://provider.example|test-region|provider-bucket|key|secret",
        )
        .unwrap()
        .pop()
        .unwrap();
    let storage = ServiceStorage::with_management(
        vec![backend],
        repository.clone(),
        ManagedStreamingMode::Enforce,
        PLACEMENT_VERSION_V1,
    );
    let operation_id = uuid::Uuid::now_v7();
    let receipt_id = uuid::Uuid::now_v7();
    let occurred_at_micros = crate::transaction::unix_time_ms() * 1_000 + 123;
    storage
        .delete_authoritative(
            &LogicalObjectKey::new("workspace", "bucket", "missing"),
            operation_id,
            receipt_id,
            occurred_at_micros,
            1,
            0,
        )
        .await
        .unwrap();

    let pending = repository.pending_delete_settlements(10).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].evidence.as_ref().unwrap().payload["occurred_at_micros"],
        occurred_at_micros
    );
    let second_operation_id = uuid::Uuid::now_v7();
    let second_receipt_id = uuid::Uuid::now_v7();
    storage
        .delete_authoritative(
            &LogicalObjectKey::new("workspace", "bucket", "other-missing"),
            second_operation_id,
            second_receipt_id,
            occurred_at_micros + 1,
            1,
            0,
        )
        .await
        .unwrap();
    let oldest = repository.pending_delete_settlements(1).await.unwrap()[0]
        .intent
        .clone();
    repository
        .defer_delete_settlement(oldest.operation_id, oldest.receipt_id)
        .await
        .unwrap();
    assert_ne!(
        repository.pending_delete_settlements(1).await.unwrap()[0]
            .intent
            .operation_id,
        oldest.operation_id
    );
    assert_eq!(
        storage
            .reconcile_managed_delete_settlements(&NoopControlPlane, 10)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        repository
            .logical_operation(operation_id)
            .await
            .unwrap()
            .unwrap()
            .settlement_state,
        ManagedSettlementState::Settled
    );
    assert!(
        repository
            .pending_delete_settlements(10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn namespace_purge_requires_enforce_mode_without_connecting_to_postgres() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgresql://postgres:postgres@127.0.0.1:1/postgres")
        .unwrap();
    let storage = ServiceStorage::with_management(
        Vec::new(),
        Arc::new(PostgresManagedRepository::new(pool)),
        ManagedStreamingMode::Off,
        PLACEMENT_VERSION_V1,
    );
    assert_default_purge_is_unsupported(&storage).await;
}

#[tokio::test]
async fn namespace_purge_deletes_and_verifies_exact_provider_version() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .fallback(any(purge_provider_mock))
        .with_state(requests.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let provider = parse_service_backends(&format!(
        "b2|managed-primary|account-123|1|{endpoint}|us-east-005|bucket|key-one|secret-one"
    ))
    .unwrap()
    .pop()
    .unwrap();
    let repository = Arc::new(InMemoryManagedRepository::new());
    let intent_id = uuid::Uuid::now_v7();
    let lease = repository
        .begin_physical_write(PhysicalWriteIntent {
            intent_id,
            tenant_id: "tenant".to_string(),
            backend_id: provider.id(),
            storage_identity: provider.storage_identity().unwrap(),
            credential_epoch: provider.credential_epoch().unwrap(),
            provider_bucket: "bucket".to_string(),
            physical_key: "managed/physical".to_string(),
            versioning_mode: BackendVersioningMode::Unversioned,
            versioning_capability: BackendVersioningCapability::Optional,
            lease_owner: "writer".to_string(),
        })
        .await
        .unwrap();
    repository
        .commit_physical_write(&lease, &[], Some("version-1"))
        .await
        .unwrap();
    let rotated_provider = parse_service_backends(&format!(
        "b2|managed-primary|account-123|2|{endpoint}|us-east-005|bucket|key-two|secret-two"
    ))
    .unwrap()
    .pop()
    .unwrap();
    assert_eq!(provider.id(), rotated_provider.id());
    assert_eq!(
        provider.storage_identity(),
        rotated_provider.storage_identity()
    );
    assert!(rotated_provider.matches_persisted_identity(
        &provider.storage_identity().unwrap(),
        provider.credential_epoch().unwrap()
    ));
    assert!(!provider.matches_persisted_identity(
        &rotated_provider.storage_identity().unwrap(),
        rotated_provider.credential_epoch().unwrap()
    ));
    let storage = ServiceStorage::with_management(
        vec![rotated_provider],
        repository,
        ManagedStreamingMode::Enforce,
        PLACEMENT_VERSION_V1,
    )
    .with_managed_capabilities(Some(managed_test_capabilities()));
    assert_eq!(
        storage.purge_namespace(&purge_request()).await.unwrap(),
        NamespacePurgeStatus::Complete {
            deleted_versions: 1,
        }
    );
    {
        let requests = requests.lock().unwrap();
        assert!(requests.iter().any(|(method, uri)| {
            method == Method::DELETE
                && uri.starts_with("/bucket/managed/physical?")
                && uri.contains("versionId=version-1")
        }));
        assert!(requests.iter().any(|(method, uri)| {
            method == Method::HEAD
                && uri.starts_with("/bucket/managed/physical?")
                && uri.contains("versionId=version-1")
        }));
    }
    let request_count_after_valid_deletion = requests.lock().unwrap().len();
    let mismatched_identity = PhysicalVersionTarget {
        tenant_id: "tenant".to_string(),
        namespace_epoch: 1,
        backend_id: "b2:managed-primary".to_string(),
        storage_identity: ProviderStorageIdentity {
            provider_account_id: "different-account".to_string(),
            ..storage.backends[0].storage_identity().unwrap()
        },
        credential_epoch: storage.backends[0].credential_epoch().unwrap(),
        provider_bucket: "bucket".to_string(),
        physical_key: "managed/physical".to_string(),
        version_id: Some("version-2".to_string()),
        versioning_mode: BackendVersioningMode::Unversioned,
        versioning_capability: BackendVersioningCapability::Optional,
        write_operation_id: uuid::Uuid::now_v7(),
    };
    assert!(
        storage
            .delete_and_verify_purge_target(&mismatched_identity)
            .await
            .unwrap_err()
            .contains("identity changed")
    );
    let mismatched_endpoint = PhysicalVersionTarget {
        storage_identity: ProviderStorageIdentity {
            canonical_endpoint: "https://other-location.example/".to_string(),
            ..storage.backends[0].storage_identity().unwrap()
        },
        ..mismatched_identity.clone()
    };
    assert!(
        storage
            .delete_and_verify_purge_target(&mismatched_endpoint)
            .await
            .unwrap_err()
            .contains("identity changed")
    );
    assert_eq!(
        requests.lock().unwrap().len(),
        request_count_after_valid_deletion,
        "account or endpoint rotation must fail before issuing deletion"
    );
    let changed_versioning = PhysicalVersionTarget {
        storage_identity: storage.backends[0].storage_identity().unwrap(),
        version_id: None,
        versioning_mode: BackendVersioningMode::Enabled,
        ..mismatched_identity
    };
    assert!(
        storage
            .delete_and_verify_purge_target(&changed_versioning)
            .await
            .unwrap_err()
            .contains("versioning mode changed")
    );
    let unprovable_unversioned = PhysicalVersionTarget {
        versioning_mode: BackendVersioningMode::Unversioned,
        ..changed_versioning
    };
    assert!(
        storage
            .delete_and_verify_purge_target(&unprovable_unversioned)
            .await
            .unwrap_err()
            .contains("cannot prove an unversioned ledger target")
    );
    server.abort();
}

#[tokio::test]
async fn namespace_purge_blocks_unknown_provider_without_forgetting_target() {
    let repository = Arc::new(InMemoryManagedRepository::new());
    let intent_id = uuid::Uuid::now_v7();
    let lease = repository
        .begin_physical_write(PhysicalWriteIntent {
            intent_id,
            tenant_id: "tenant".to_string(),
            backend_id: "missing:bucket".to_string(),
            storage_identity: test_storage_identity(),
            credential_epoch: 1,
            provider_bucket: "bucket".to_string(),
            physical_key: "managed/physical".to_string(),
            versioning_mode: BackendVersioningMode::Enabled,
            versioning_capability: BackendVersioningCapability::Optional,
            lease_owner: "writer".to_string(),
        })
        .await
        .unwrap();
    repository
        .commit_physical_write(&lease, &[], Some("version-1"))
        .await
        .unwrap();
    let storage = ServiceStorage::with_management(
        Vec::new(),
        repository,
        ManagedStreamingMode::Enforce,
        PLACEMENT_VERSION_V1,
    );
    assert!(matches!(
        storage.purge_namespace(&purge_request()).await.unwrap(),
        NamespacePurgeStatus::Blocked { reason }
            if reason.contains("unknown managed backend")
    ));
}

#[tokio::test]
async fn abort_after_lost_put_response_and_retry_ambiguity_preserves_blocking_intent() {
    let repository = Arc::new(InMemoryManagedRepository::new());
    let operation_id = uuid::Uuid::now_v7();
    let lease = repository
        .begin_physical_write(PhysicalWriteIntent {
            intent_id: operation_id,
            tenant_id: "tenant".to_string(),
            backend_id: "mock:bucket".to_string(),
            storage_identity: test_storage_identity(),
            credential_epoch: 1,
            provider_bucket: "bucket".to_string(),
            physical_key: "managed/physical".to_string(),
            versioning_mode: BackendVersioningMode::Enabled,
            versioning_capability: BackendVersioningCapability::Optional,
            lease_owner: "writer".to_string(),
        })
        .await
        .unwrap();
    let journal = Arc::new(crate::transaction::InMemoryOperationJournal::new());
    let operation = crate::transaction::OperationRecord::scoped_intent(
        operation_id,
        ObjectDestination {
            backend_id: "mock:bucket".to_string(),
            bucket: "bucket".to_string(),
            logical_key: "bucket/key".to_string(),
            physical_key: "managed/physical".to_string(),
            workspace_binding: None,
        },
        ExpectedObject::default(),
        "tenant".to_string(),
        lease.namespace_epoch,
    );
    journal.insert_intent(operation).await.unwrap();
    journal.set_open(operation_id, None).await.unwrap();
    journal
        .transition(
            operation_id,
            OperationState::Open,
            OperationState::Completing,
            None,
        )
        .await
        .unwrap();
    journal
        .transition(
            operation_id,
            OperationState::Completing,
            OperationState::Committed,
            Some(&StoredObjectMeta {
                etag: Some("retry-etag".to_string()),
                version_id: Some("observed-retry-version".to_string()),
                superseded_version_ids: Vec::new(),
                version_history_complete: false,
            }),
        )
        .await
        .unwrap();
    let committed = journal.get(operation_id).await.unwrap().unwrap();
    let authority: Arc<dyn ManagedRepository> = repository.clone();
    assert!(matches!(
        settle_managed_intent_from_journal(&authority, &lease, &committed).await,
        Err(TransactionError::CompletionAmbiguous)
    ));
    let request = NamespacePurgeRequest {
        tenant_id: "tenant".to_string(),
        operation_id: uuid::Uuid::now_v7(),
    };
    assert!(matches!(
        repository.purge_namespace(&request).await.unwrap(),
        NamespacePurgeStatus::Blocked { reason }
            if reason.contains("ambiguous provider version history")
    ));
    assert_eq!(
        repository
            .pending_physical_write_intents(10)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn multi_instance_reconciler_skips_fresh_and_recovers_expired_terminal_intent() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .fallback(any(purge_provider_mock))
        .with_state(requests);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider = ServiceBackend {
        provider: "mock".to_string(),
        provider_instance_id: Some("managed-primary".to_string()),
        provider_account_id: Some("test-account".to_string()),
        credential_epoch: Some(1),
        placement_weight: 1,
        placement_capacity_units: 1,
        endpoint: format!("http://{}", listener.local_addr().unwrap()),
        region: "us-east-1".to_string(),
        bucket: "bucket".to_string(),
        access_key: "key".to_string(),
        secret_key: "secret".to_string(),
    };
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let repository = Arc::new(InMemoryManagedRepository::new());
    let operation_id = uuid::Uuid::now_v7();
    let lease = repository
        .begin_physical_write(PhysicalWriteIntent {
            intent_id: operation_id,
            tenant_id: "tenant".to_string(),
            backend_id: provider.id(),
            storage_identity: provider.storage_identity().unwrap(),
            credential_epoch: provider.credential_epoch().unwrap(),
            provider_bucket: provider.bucket.clone(),
            physical_key: "managed/physical".to_string(),
            versioning_mode: BackendVersioningMode::Unversioned,
            versioning_capability: BackendVersioningCapability::Optional,
            lease_owner: "writer".to_string(),
        })
        .await
        .unwrap();
    let journal = Arc::new(crate::transaction::InMemoryOperationJournal::new());
    journal
        .insert_intent(crate::transaction::OperationRecord::scoped_intent(
            operation_id,
            ObjectDestination {
                backend_id: provider.id(),
                bucket: provider.bucket.clone(),
                logical_key: "bucket/key".to_string(),
                physical_key: "managed/physical".to_string(),
                workspace_binding: None,
            },
            ExpectedObject::default(),
            "tenant".to_string(),
            lease.namespace_epoch,
        ))
        .await
        .unwrap();
    journal.set_open(operation_id, None).await.unwrap();
    journal
        .transition(
            operation_id,
            OperationState::Open,
            OperationState::Completing,
            None,
        )
        .await
        .unwrap();
    journal
        .transition(
            operation_id,
            OperationState::Completing,
            OperationState::Committed,
            Some(&StoredObjectMeta {
                etag: Some("etag".to_string()),
                version_id: None,
                superseded_version_ids: Vec::new(),
                version_history_complete: true,
            }),
        )
        .await
        .unwrap();
    let storage = ServiceStorage::with_management(
        vec![provider],
        repository.clone(),
        ManagedStreamingMode::Enforce,
        PLACEMENT_VERSION_V1,
    )
    .with_managed_capabilities(Some(managed_test_capabilities()));
    assert_eq!(
        storage
            .reconcile_managed_write_intents(
                journal.clone(),
                managed_test_capabilities(),
                Duration::ZERO,
                10,
            )
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        repository
            .pending_physical_write_intents(10)
            .await
            .unwrap()
            .len(),
        1,
        "another instance must not claim a fresh leased intent"
    );
    repository
        .renew_physical_write_intent(&lease, crate::transaction::unix_time_ms().saturating_sub(1))
        .await
        .unwrap();
    storage
        .reconcile_managed_write_intents(journal, managed_test_capabilities(), Duration::ZERO, 10)
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
            .physical_versions(
                "tenant",
                &storage.backends[0].id(),
                "bucket",
                "managed/physical",
            )
            .await
            .unwrap()
            .len(),
        1
    );
    server.abort();
}

#[test]
fn stale_replica_metadata_can_never_match_current_authority() {
    let authority = authority();
    let current = std::collections::HashMap::from([
        (
            "maskura-generation".to_string(),
            authority.generation.to_string(),
        ),
        ("maskura-sha256".to_string(), authority.digest.clone()),
        ("maskura-size".to_string(), authority.size.to_string()),
    ]);
    assert!(ServiceStorage::metadata_matches(
        Some(&current),
        Some(authority.size as i64),
        &authority,
        false,
    ));

    let mut stale_generation = current.clone();
    stale_generation.insert(
        "maskura-generation".to_string(),
        uuid::Uuid::now_v7().to_string(),
    );
    assert!(!ServiceStorage::metadata_matches(
        Some(&stale_generation),
        Some(authority.size as i64),
        &authority,
        false,
    ));
    let mut stale_digest = current.clone();
    stale_digest.insert("maskura-sha256".to_string(), "old".to_string());
    assert!(!ServiceStorage::metadata_matches(
        Some(&stale_digest),
        Some(authority.size as i64),
        &authority,
        false,
    ));
    assert!(!ServiceStorage::metadata_matches(
        Some(&current),
        Some(41),
        &authority,
        false,
    ));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailurePoint {
    Write,
    Verify,
    Complete,
}

#[derive(Default)]
struct FakeDestinationState {
    pointers: Vec<usize>,
    completion_authorities: Vec<&'static str>,
}

type SharedFakeState = Arc<Mutex<FakeDestinationState>>;
type SharedEvents = Arc<Mutex<Vec<String>>>;
type FakeManagedSink = (
    ManagedReplicatedSink,
    SharedFakeState,
    SharedFakeState,
    SharedEvents,
);

struct FakeDestination {
    label: &'static str,
    failure: Option<FailurePoint>,
    state: SharedFakeState,
    events: SharedEvents,
}

impl FakeDestination {
    fn new(
        label: &'static str,
        failure: Option<FailurePoint>,
        events: SharedEvents,
    ) -> (Self, SharedFakeState) {
        let state = Arc::new(Mutex::new(FakeDestinationState::default()));
        (
            Self {
                label,
                failure,
                state: state.clone(),
                events,
            },
            state,
        )
    }

    fn fail(&self, point: FailurePoint) -> Result<(), TransactionError> {
        if self.failure == Some(point) {
            Err(TransactionError::Publication(format!(
                "scripted {} {point:?} failure",
                self.label
            )))
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait]
impl ManagedDestination for FakeDestination {
    fn physical_lease(&self) -> crate::managed::PhysicalWriteLease {
        crate::managed::PhysicalWriteLease {
            intent_id: uuid::Uuid::nil(),
            namespace_epoch: 1,
            owner: self.label.to_string(),
            token: uuid::Uuid::nil(),
        }
    }

    async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("{}-write", self.label));
        self.state
            .lock()
            .unwrap()
            .pointers
            .push(chunk.as_ptr() as usize);
        self.fail(FailurePoint::Write)
    }

    async fn verify_output(
        &mut self,
        _expected_size: u64,
        _expected_sha256: &str,
    ) -> Result<(), TransactionError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("{}-verify", self.label));
        self.fail(FailurePoint::Verify)
    }

    async fn complete(
        &mut self,
        authority: &DestinationCommitAuthority,
    ) -> Result<StoredObjectMeta, TransactionError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("{}-complete", self.label));
        self.state
            .lock()
            .unwrap()
            .completion_authorities
            .push(match authority {
                DestinationCommitAuthority::SinglePut => "single-put",
                DestinationCommitAuthority::ClientMultipart(_) => "client-multipart",
            });
        self.fail(FailurePoint::Complete)?;
        Ok(StoredObjectMeta::default())
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        self.events
            .lock()
            .unwrap()
            .push(format!("{}-abort", self.label));
        Ok(())
    }
}

fn fake_managed_sink(
    repository: Arc<InMemoryManagedRepository>,
    logical: LogicalObjectKey,
    expected_cas: Option<u64>,
    primary_failure: Option<FailurePoint>,
    replica_failure: Option<FailurePoint>,
) -> FakeManagedSink {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (primary, primary_state) = FakeDestination::new("primary", primary_failure, events.clone());
    let (replica, replica_state) = FakeDestination::new("replica", replica_failure, events.clone());
    (
        ManagedReplicatedSink {
            repository,
            logical,
            generation: uuid::Uuid::now_v7(),
            placement: Placement {
                version: 1,
                primary_backend_id: "primary".to_string(),
                replica_backend_id: Some("replica".to_string()),
            },
            logical_operation_id: None,
            expected_cas,
            metadata: BTreeMap::from([("content-type".to_string(), "text/plain".to_string())]),
            primary: Box::new(primary),
            replica: Some(Box::new(replica)),
            output: None,
            finished: false,
        },
        primary_state,
        replica_state,
        events,
    )
}

#[tokio::test]
async fn managed_replica_failures_never_block_authoritative_primary() {
    for failure in [
        FailurePoint::Write,
        FailurePoint::Verify,
        FailurePoint::Complete,
    ] {
        let repository = Arc::new(InMemoryManagedRepository::new());
        let logical = LogicalObjectKey::new("tenant", "bucket", &format!("key-{failure:?}"));
        let (mut sink, primary, replica, events) = fake_managed_sink(
            repository.clone(),
            logical.clone(),
            None,
            None,
            Some(failure),
        );
        let chunk = Bytes::from_static(b"abc");
        sink.write(chunk).await.unwrap();
        sink.verify_output(
            3,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .await
        .unwrap();
        sink.complete(DestinationCommitAuthority::SinglePut)
            .await
            .unwrap();

        assert_eq!(
            primary.lock().unwrap().completion_authorities,
            ["single-put"]
        );
        if failure != FailurePoint::Write && failure != FailurePoint::Verify {
            assert_eq!(
                replica.lock().unwrap().completion_authorities,
                ["single-put"]
            );
        }

        let authority = repository.get(&logical).await.unwrap().unwrap();
        assert_eq!(authority.primary_status, CopyStatus::Ready);
        assert_eq!(authority.replica_status, CopyStatus::RepairPending);
        if failure == FailurePoint::Write {
            assert_eq!(
                primary.lock().unwrap().pointers,
                replica.lock().unwrap().pointers,
                "Bytes sent to primary and replica are shallow clones"
            );
        }
        let events = events.lock().unwrap();
        if let (Some(primary), Some(replica)) = (
            events.iter().position(|event| event == "primary-complete"),
            events.iter().position(|event| event == "replica-complete"),
        ) {
            assert!(primary < replica, "primary completes before replica");
        }
    }
}

#[tokio::test]
async fn managed_sink_rejects_mismatched_multipart_operation_before_propagation() {
    let repository = Arc::new(InMemoryManagedRepository::new());
    let logical = LogicalObjectKey::new("tenant", "bucket", "key");
    let (mut sink, primary, _, _) =
        fake_managed_sink(repository, logical.clone(), None, None, None);
    let expected_operation_id = uuid::Uuid::now_v7();
    sink.logical_operation_id = Some(expected_operation_id);
    sink.write(Bytes::from_static(b"abc")).await.unwrap();
    sink.verify_output(
        3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    )
    .await
    .unwrap();
    let root = std::env::temp_dir().join(format!(
        "maskura-managed-authority-{}",
        uuid::Uuid::now_v7()
    ));
    let permit_repository = Arc::new(
        FileMultipartRepository::open(root.clone(), StagingQuotaLimits::new(1024, 1024).unwrap())
            .unwrap(),
    );
    let identity = MultipartIdentity {
        tenant_id: logical.tenant_id.clone(),
        credential_policy_id: "policy".to_string(),
        bucket: logical.bucket.clone(),
        key: logical.key.clone(),
        upload_id: uuid::Uuid::now_v7().to_string(),
    };
    let authority = DestinationCommitAuthority::client_multipart(
        permit_repository,
        identity.clone(),
        DestinationCommitPermit {
            upload_id: identity.upload_id,
            completion_fingerprint: "fingerprint".to_string(),
            fencing_token: 1,
            operation_id: uuid::Uuid::now_v7(),
        },
    );

    assert!(matches!(
        sink.complete(authority).await,
        Err(TransactionError::CommitAuthority(_))
    ));
    assert!(primary.lock().unwrap().completion_authorities.is_empty());
    tokio::fs::remove_dir_all(root).await.unwrap();
}

#[tokio::test]
async fn managed_primary_failures_and_cas_races_never_publish_stale_data() {
    for failure in [
        FailurePoint::Write,
        FailurePoint::Verify,
        FailurePoint::Complete,
    ] {
        let repository = Arc::new(InMemoryManagedRepository::new());
        let logical = LogicalObjectKey::new("tenant", "bucket", &format!("primary-{failure:?}"));
        let (mut sink, _, _, _) = fake_managed_sink(
            repository.clone(),
            logical.clone(),
            None,
            Some(failure),
            None,
        );
        let write = sink.write(Bytes::from_static(b"abc")).await;
        if failure == FailurePoint::Write {
            assert!(write.is_err());
        } else {
            write.unwrap();
            let verify = sink
                .verify_output(
                    3,
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                )
                .await;
            if failure == FailurePoint::Verify {
                assert!(verify.is_err());
            } else {
                verify.unwrap();
                assert!(
                    sink.complete(DestinationCommitAuthority::SinglePut)
                        .await
                        .is_err()
                );
            }
        }
        assert!(repository.get(&logical).await.unwrap().is_none());
    }

    let repository = Arc::new(InMemoryManagedRepository::new());
    let logical = LogicalObjectKey::new("tenant", "bucket", "cas-race");
    let (mut stale, _, _, _) =
        fake_managed_sink(repository.clone(), logical.clone(), None, None, None);
    stale.write(Bytes::from_static(b"abc")).await.unwrap();
    stale
        .verify_output(
            3,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .await
        .unwrap();
    let mut winner = authority();
    winner.logical = logical.clone();
    repository.publish(winner.clone(), None).await.unwrap();
    assert!(
        stale
            .complete(DestinationCommitAuthority::SinglePut)
            .await
            .is_err()
    );
    assert_eq!(
        repository.get(&logical).await.unwrap().unwrap().generation,
        winner.generation
    );
}

#[test]
fn managed_logical_sink_separates_commit_and_usage_journal_identities() {
    let repository = Arc::new(InMemoryManagedRepository::new());
    let logical = LogicalObjectKey::new("tenant", "bucket", "key");
    let (inner, _, _, _) = fake_managed_sink(repository.clone(), logical, None, None, None);
    let operation_id = uuid::Uuid::now_v7();
    let sink = ManagedLogicalSink {
        inner: Box::new(inner),
        repository,
        operation_id,
        expected_output_size: None,
        expected_output_digest: None,
        usage_recorded: false,
        committed: false,
    };

    assert_eq!(sink.durable_operation_id(), Some(operation_id));
    assert_eq!(sink.usage_journal_operation_id(), None);
}

#[tokio::test]
async fn managed_streaming_put_admission_fails_closed_without_durable_prerequisites() {
    let repository = Arc::new(InMemoryManagedRepository::new());
    let backends = parse_service_backends(
            "b2|managed-primary|account-123|1|https://s3.us-east-005.backblazeb2.com|us-east-005|managed-bucket|key|secret",
        )
        .unwrap();
    let enforce = Arc::new(ServiceStorage::with_management(
        backends,
        repository.clone(),
        ManagedStreamingMode::Enforce,
        PLACEMENT_VERSION_V1,
    ));
    let logical = LogicalObjectKey::new("tenant-streaming-admission", "bucket", "key.json");

    // A non-durable journal fails closed before admission.
    let journal = Arc::new(crate::transaction::InMemoryOperationJournal::new());
    let error = match enforce
        .clone()
        .begin_managed_put_sink(
            journal.clone(),
            managed_test_capabilities(),
            logical.clone(),
            "application/json",
            uuid::Uuid::now_v7(),
            uuid::Uuid::now_v7(),
            crate::transaction::unix_time_ms(),
            1,
            1024,
            None,
            0,
        )
        .await
    {
        Ok(_) => panic!("managed admission unexpectedly succeeded without a durable journal"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("durable operation journal"),
        "unexpected admission error: {error}"
    );

    // Off mode fails closed even when every other prerequisite is present.
    let off = Arc::new(ServiceStorage::with_management(
            parse_service_backends(
                "b2|managed-primary|account-123|1|https://s3.us-east-005.backblazeb2.com|us-east-005|managed-bucket|key|secret",
            )
            .unwrap(),
            repository.clone(),
            ManagedStreamingMode::Off,
            PLACEMENT_VERSION_V1,
        ));
    let error = match off
        .begin_managed_put_sink(
            journal,
            managed_test_capabilities(),
            logical,
            "application/json",
            uuid::Uuid::now_v7(),
            uuid::Uuid::now_v7(),
            crate::transaction::unix_time_ms(),
            1,
            1024,
            None,
            0,
        )
        .await
    {
        Ok(_) => panic!("managed admission unexpectedly succeeded in off mode"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("mutation"),
        "unexpected admission error: {error}"
    );
}

#[tokio::test]
async fn placement_reconciliation_advances_without_copy_and_deduplicates_repairs() {
    let repository = Arc::new(InMemoryManagedRepository::new());
    let storage = ServiceStorage::with_management(
            parse_service_backends(
                "b2|one|account-1|1|https://s3.example|us-east-1|bucket-one|key|secret;b2|two|account-2|1|https://s3.example|us-east-1|bucket-two|key|secret",
            ).unwrap(),
            repository.clone(),
            ManagedStreamingMode::Enforce,
            2,
        );
    let logical = LogicalObjectKey::new("tenant-placement", "bucket", "ready");
    let desired = storage.placement(&logical).unwrap();
    let ready = ObjectAuthority {
        logical: logical.clone(),
        generation: uuid::Uuid::now_v7(),
        digest: "digest".to_string(),
        size: 3,
        metadata: BTreeMap::new(),
        placement_version: 1,
        primary_backend_id: desired.primary_backend_id.clone(),
        primary_version_id: None,
        replica_backend_id: desired.replica_backend_id.clone(),
        primary_status: CopyStatus::Ready,
        replica_status: if desired.replica_backend_id.is_some() {
            CopyStatus::Ready
        } else {
            CopyStatus::Absent
        },
        tombstone: false,
        cas_version: 0,
        created_at_ms: 0,
        updated_at_ms: 0,
    };
    let ready = repository.publish(ready, None).await.unwrap();
    storage
        .reconcile_authority_placement(&ready, &desired)
        .await
        .unwrap();
    assert_eq!(
        repository
            .get(&logical)
            .await
            .unwrap()
            .unwrap()
            .placement_version,
        2
    );
    assert!(
        repository
            .claim_repairs("no-copy", crate::transaction::unix_time_ms() + 1_000, 10)
            .await
            .unwrap()
            .is_empty()
    );

    let stale = LogicalObjectKey::new("tenant-placement", "bucket", "stale");
    let mut stale_authority = repository.get(&logical).await.unwrap().unwrap();
    stale_authority.logical = stale.clone();
    stale_authority.generation = uuid::Uuid::now_v7();
    stale_authority.placement_version = 1;
    stale_authority.primary_backend_id = "old".to_string();
    stale_authority.replica_backend_id = None;
    stale_authority.primary_status = CopyStatus::Ready;
    stale_authority.replica_status = CopyStatus::Absent;
    let stale_authority = repository.publish(stale_authority, None).await.unwrap();
    storage
        .reconcile_authority_placement(&stale_authority, &storage.placement(&stale).unwrap())
        .await
        .unwrap();
    storage
        .reconcile_authority_placement(&stale_authority, &storage.placement(&stale).unwrap())
        .await
        .unwrap();
    let repairs = repository
        .claim_repairs(
            "deduplicated",
            crate::transaction::unix_time_ms() + 1_000,
            10,
        )
        .await
        .unwrap();
    assert_eq!(repairs.len(), 2, "one leg per desired primary and replica");
}
