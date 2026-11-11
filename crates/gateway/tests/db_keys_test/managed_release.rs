//! Release-only integration cases. Each exact test MUST run in its own cleared
//! process with a new launcher-attested DB/root. Environment-required entries
//! are explicitly ignored by ordinary cargo test, NOT accepted as release
//! coverage. The release launcher must execute every exact entry with --ignored.
use super::managed_release_fixture::*;
use super::*;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use maskura_gateway::managed::ManagedLogicalOperation;
use maskura_gateway::service_storage::ServiceStorage;
use maskura_gateway::transaction::{
    AwsS3TransactionBackend, DIRECT_PART_BYTES, DestinationCommitAuthority, ManagedChildRole,
    ManagedOperationScope, TransactionBackend,
};
use sea_orm::QueryOrder;
use std::collections::BTreeSet;

const BUCKET: &str = "release-logical";

struct Credentials {
    access: String,
    secret: String,
}

async fn http(
    client: &reqwest::Client,
    endpoint: &str,
    credentials: &Credentials,
    method: Method,
    path: &str,
    body: Vec<u8>,
    representation: Option<Representation>,
) -> (StatusCode, axum::http::HeaderMap, Bytes) {
    let mut request = client
        .request(method, format!("{endpoint}{path}"))
        .header("x-maskura-access-key", &credentials.access)
        .header("x-maskura-secret-key", &credentials.secret)
        .body(body);
    if let Some(representation) = representation {
        request = request
            .header(header::CONTENT_TYPE, CONTENT_TYPE)
            .header("x-amz-meta-content-type", "customer-type")
            .header("x-amz-meta-content-encoding", "customer-encoding");
        if let Some(encoding) = representation.encoding() {
            request = request.header(header::CONTENT_ENCODING, encoding);
        }
    }
    let response = must(
        request.send().await,
        "release authenticated HTTP transport failed",
    );
    let status = response.status();
    let headers = response.headers().clone();
    assert!(
        response
            .content_length()
            .is_none_or(|n| n <= 32 * 1024 * 1024),
        "release HTTP response exceeded bound"
    );
    let bytes = must(response.bytes().await, "release HTTP body read failed");
    assert!(
        bytes.len() <= 32 * 1024 * 1024,
        "release HTTP body exceeded bound"
    );
    (status, headers, bytes)
}

async fn read_http(
    client: &reqwest::Client,
    endpoint: &str,
    credentials: &Credentials,
    pool: &PgPool,
    key: &str,
    expected: &[u8],
    representation: Representation,
) {
    let parent = operation(pool, key).await;
    // Explicit authored PASSTHROUGH returns provider metadata, including trusted
    // transaction bindings. This does NOT describe protected transformed reads.
    let bindings = ExpectedPhysical {
        bytes: expected,
        representation,
        operation_id: parent.intent.primary_child_operation_id,
        generation: parent.intent.generation,
        instance: "release-primary",
        account: "release-account",
        credential_epoch: 1,
        selected_version: "", // wire metadata only, not a version claim
    }
    .wire_metadata();
    let (status, headers, bytes) = http(
        client,
        endpoint,
        credentials,
        Method::HEAD,
        &format!("/{BUCKET}/{key}"),
        Vec::new(),
        None,
    )
    .await;
    assert!(
        status == StatusCode::OK && bytes.is_empty(),
        "release successful HEAD failed"
    );
    assert!(
        representation_matches(&headers, representation)
            && wire_metadata_matches(&headers, &bindings),
        "release passthrough HEAD representation/trusted bindings failed"
    );
    assert!(
        headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            == Some(expected.len()),
        "release HEAD size failed"
    );
    let (status, headers, bytes) = http(
        client,
        endpoint,
        credentials,
        Method::GET,
        &format!("/{BUCKET}/{key}"),
        Vec::new(),
        None,
    )
    .await;
    assert!(status == StatusCode::OK, "release successful GET failed");
    assert!(
        representation_matches(&headers, representation)
            && wire_metadata_matches(&headers, &bindings),
        "release passthrough GET representation/trusted bindings failed"
    );
    assert!(bytes.as_ref() == expected, "release GET exact bytes failed");
}

async fn operation(pool: &PgPool, key: &str) -> ManagedLogicalOperation {
    let models = must(
        managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::TenantId.eq(TENANT))
            .filter(managed_logical_operation::Column::Bucket.eq(BUCKET))
            .filter(managed_logical_operation::Column::LogicalKey.eq(key))
            .all(&sea_db(pool.clone()))
            .await,
        "release logical operation query failed",
    );
    assert!(
        models.len() == 1,
        "release expected one durable logical operation"
    );
    must(
        PostgresManagedRepository::new(pool.clone())
            .logical_operation(models[0].operation_id)
            .await,
        "release logical operation unavailable",
    )
    .expect("release logical operation missing")
}

async fn assert_publication(
    pool: &PgPool,
    provider: &Provider,
    key: &str,
    expected: &[u8],
    route: UsageRoute,
    representation: Representation,
) {
    let logical = LogicalObjectKey::new(TENANT, BUCKET, key);
    let repository = PostgresManagedRepository::new(pool.clone());
    let operation = operation(pool, key).await;
    let authority = must(
        repository.get(&logical).await,
        "release authority unavailable",
    )
    .expect("release authority missing");
    let recipe = operation
        .intent
        .publication_recipe
        .as_ref()
        .expect("release recipe missing");
    assert!(
        operation.state == ManagedLogicalOperationState::Committed
            && recipe.metadata == representation.journal_metadata()
            && authority.metadata == representation.journal_metadata()
            && authority.generation == operation.intent.generation
            && authority.size == expected.len() as u64
            && authority.digest == digest(expected)
            && authority.primary_backend_id == "b2:release-primary"
            && authority.primary_status == CopyStatus::Ready
            && !authority.tombstone,
        "release PG recipe/authority publication failed"
    );
    let evidence = operation
        .evidence
        .as_ref()
        .expect("release usage evidence missing");
    assert!(
        evidence.expected_output_digest.as_deref() == Some(digest(expected).as_str())
            && evidence.expected_output_size == expected.len() as u64
            && evidence.source_bytes == expected.len() as u64
            && evidence.processed_bytes == expected.len() as u64
            && evidence.payload["route"] == route.as_str(),
        "release durable usage evidence failed"
    );
    let journal = PostgresOperationJournal::new(pool.clone());
    let child = must(
        journal
            .get(operation.intent.primary_child_operation_id)
            .await,
        "release child journal unavailable",
    )
    .expect("release child journal missing");
    let committed = child
        .committed
        .as_ref()
        .expect("release child commit missing");
    assert!(
        child.state == OperationState::Committed
            && committed.version_history_complete
            && committed.version_id == authority.primary_version_id
            && child.destination.physical_key == operation.intent.physical_key
            && child.destination.bucket == PRIMARY
            && child.expected.size == Some(expected.len() as u64)
            && child.expected.digest.as_deref() == Some(digest(expected).as_str()),
        "release child journal/authority binding failed"
    );
    for (name, value) in representation.journal_metadata() {
        assert!(
            child.expected.metadata.get(&name) == Some(&value),
            "release child metadata changed"
        );
    }
    let versions = provider.versions(PRIMARY, &operation.intent.physical_key);
    let selected = versions
        .iter()
        .find(|v| Some(&v.id) == authority.primary_version_id.as_ref())
        .expect("release selected physical version missing");
    assert!(
        selected.bytes.as_ref() == expected,
        "release provider exact bytes failed"
    );
    assert!(
        representation_matches(&selected.headers, representation),
        "release provider representation mismatch"
    );
    for (name, value) in [
        ("x-amz-meta-maskura-operation-id", child.id.to_string()),
        (
            "x-amz-meta-maskura-generation",
            authority.generation.to_string(),
        ),
        (
            "x-amz-meta-maskura-provider-instance",
            "release-primary".into(),
        ),
        (
            "x-amz-meta-maskura-provider-account",
            "release-account".into(),
        ),
        ("x-amz-meta-maskura-credential-epoch", "1".into()),
        ("x-amz-meta-maskura-sha256", digest(expected)),
        ("x-amz-meta-maskura-size", expected.len().to_string()),
        ("x-amz-server-side-encryption", "AES256".into()),
    ] {
        assert!(
            selected.headers.get(name).and_then(|v| v.to_str().ok()) == Some(value.as_str()),
            "release physical identity/metadata/SSE failed"
        );
    }
    let targets = must(
        repository
            .physical_versions(
                TENANT,
                &authority.primary_backend_id,
                PRIMARY,
                &operation.intent.physical_key,
            )
            .await,
        "release version ledger unavailable",
    );
    let expected_ids: BTreeSet<_> = committed
        .superseded_version_ids
        .iter()
        .cloned()
        .chain(committed.version_id.iter().cloned())
        .collect();
    assert!(
        targets
            .iter()
            .filter_map(|v| v.version_id.clone())
            .collect::<BTreeSet<_>>()
            == expected_ids,
        "release physical version history ledger failed"
    );
    assert!(
        targets
            .iter()
            .all(|v| v.storage_identity.provider_kind == "b2"
                && v.storage_identity.provider_instance_id == "release-primary"
                && v.storage_identity.provider_account_id == "release-account"
                && v.credential_epoch == 1
                && v.versioning_mode == BackendVersioningMode::Enabled),
        "release physical version identity failed"
    );
}

fn large_parts() -> (Vec<u8>, Vec<u8>) {
    let mut record = vec![b's'; 64 * 1024];
    record[64 * 1024 - 1] = b'\n';
    let first = record.repeat(DIRECT_PART_BYTES / record.len());
    (first, record)
}

#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn managed_release_http_put_multipart_restart_and_replay() {
    const CASE: &str = "http";
    let fixture_owner = Fixture::start(CASE, false);
    let fixture = &fixture_owner;
    let provider_owner = fixture.provider.clone();
    let provider = &provider_owner;
    let endpoint_owner = fixture.endpoint.clone();
    let endpoint = &endpoint_owner;
    let (credentials_owner, upload_id_owner, completion_xml_owner) = with_release_pool(
        CASE,
        |pool| async move {
            let state =
                build_release_state(endpoint, Arc::new(MultipartBillingControl::default())).await;
            let (secret, created) = must(
                state
                    .keys
                    .create_key(
                        "release-user",
                        &WorkspaceId::new(TENANT).expect("literal workspace"),
                        "release-test",
                        0,
                        None,
                    )
                    .await,
                "release persisted API key creation failed",
            );
            let credentials = Credentials {
                access: created.key_id,
                secret,
            };
            let db_key = must(
                api_key::Entity::find()
                    .filter(api_key::Column::KeyId.eq(&credentials.access))
                    .one(&sea_db(pool.clone()))
                    .await,
                "release PG key query failed",
            )
            .expect("release PG key missing");
            assert!(
                db_key.workspace_id.as_deref() == Some(TENANT),
                "release key scope was not persisted"
            );
            let (client, gateway) = serve_gateway(state, fixture).await;
            let unauthorized = must(
                client
                    .put(format!("{gateway}/{BUCKET}/unauthorized"))
                    .body("synthetic\n")
                    .send()
                    .await,
                "release unauthorized probe failed",
            );
            assert!(
                unauthorized.status() == StatusCode::FORBIDDEN
                    || unauthorized.status() == StatusCode::UNAUTHORIZED,
                "release router accepted missing API credentials"
            );
            assert!(
                provider.mutation_count(PRIMARY) == 0,
                "release unauthenticated request mutated provider"
            );
            let ordinary = b"ordinary synthetic record\n";
            let (status, _, _) = http(
                &client,
                &gateway,
                &credentials,
                Method::PUT,
                &format!("/{BUCKET}/ordinary.txt"),
                ordinary.to_vec(),
                Some(Representation::Ordinary),
            )
            .await;
            assert!(
                status == StatusCode::OK,
                "release managed ordinary PUT failed"
            );
            read_http(
                &client,
                &gateway,
                &credentials,
                &pool,
                "ordinary.txt",
                ordinary,
                Representation::Ordinary,
            )
            .await;
            assert_publication(
                &pool,
                provider,
                "ordinary.txt",
                ordinary,
                UsageRoute::PutObject,
                Representation::Ordinary,
            )
            .await;
            let (status, _, body) = http(
                &client,
                &gateway,
                &credentials,
                Method::POST,
                &format!("/{BUCKET}/multipart.txt?uploads"),
                Vec::new(),
                Some(Representation::Identity),
            )
            .await;
            assert!(
                status == StatusCode::OK,
                "release managed MPU initiation failed"
            );
            let text = must(
                std::str::from_utf8(&body),
                "release MPU initiation XML invalid",
            );
            let upload_id = extract_xml(text, "UploadId");
            assert!(!upload_id.is_empty(), "release MPU initiation ID missing");
            let (first, last) = large_parts();
            let mut etags = Vec::new();
            for (index, body) in [first, last].into_iter().enumerate() {
                let (status, headers, _) = http(
                    &client,
                    &gateway,
                    &credentials,
                    Method::PUT,
                    &format!(
                        "/{BUCKET}/multipart.txt?uploadId={upload_id}&partNumber={}",
                        index + 1
                    ),
                    body,
                    None,
                )
                .await;
                assert!(
                    status == StatusCode::OK,
                    "release managed UploadPart failed"
                );
                etags.push(
                    headers
                        .get(header::ETAG)
                        .and_then(|v| v.to_str().ok())
                        .expect("release part ETag missing")
                        .to_owned(),
                );
            }
            let completion_xml = format!(
                "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part></CompleteMultipartUpload>",
                etags[0], etags[1]
            );
            (credentials, upload_id, completion_xml)
        },
    );
    let credentials = &credentials_owner;
    let upload_id = &upload_id_owner;
    let completion_xml = &completion_xml_owner;
    // with_release_pool has destroyed the first runtime and its background
    // workers. Provider TLS and PG alone survive; no old AppState can assist.
    let completed_etag_owner = with_release_pool(CASE, |pool| async move {
        let state =
            build_release_state(endpoint, Arc::new(MultipartBillingControl::default())).await;
        let (client, gateway) = serve_gateway(state, fixture).await;
        let (status, _, body) = http(
            &client,
            &gateway,
            credentials,
            Method::POST,
            &format!("/{BUCKET}/multipart.txt?uploadId={upload_id}"),
            completion_xml.as_bytes().to_vec(),
            None,
        )
        .await;
        assert!(
            status == StatusCode::OK,
            "release post-restart managed completion failed"
        );
        let completed_etag = extract_xml(
            must(std::str::from_utf8(&body), "release completion XML invalid"),
            "ETag",
        );
        let (first, last) = large_parts();
        let expected = [first, last].concat();
        assert!(
            expected.len() > DIRECT_PART_BYTES,
            "release provider MPU threshold not crossed"
        );
        read_http(
            &client,
            &gateway,
            credentials,
            &pool,
            "multipart.txt",
            &expected,
            Representation::Identity,
        )
        .await;
        assert_publication(
            &pool,
            provider,
            "multipart.txt",
            &expected,
            UsageRoute::CompleteMultipartUpload,
            Representation::Identity,
        )
        .await;
        assert!(
            provider.operation_count(PRIMARY, "create") >= 2
                && provider.operation_count(PRIMARY, "part") >= 2
                && provider.operation_count(PRIMARY, "copy") >= 2
                && provider.operation_count(PRIMARY, "complete") >= 2,
            "release did not execute genuine provider MPU plus conditional metadata copy"
        );
        let op = operation(&pool, "multipart.txt").await;
        let child = must(
            PostgresOperationJournal::new(pool)
                .get(op.intent.primary_child_operation_id)
                .await,
            "release multipart child query failed",
        )
        .expect("release multipart child missing");
        assert!(
            !child
                .committed
                .expect("release multipart commit missing")
                .superseded_version_ids
                .is_empty(),
            "release MPU did not bind superseded physical version"
        );
        let history = provider.history(PRIMARY, &op.intent.physical_key);
        assert!(
            history.len() == 2
                && history[0].bytes == history[1].bytes
                && !history[0].headers.contains_key("x-amz-meta-maskura-sha256")
                && !history[0].headers.contains_key("x-amz-meta-maskura-size")
                && history[1].headers.contains_key("x-amz-meta-maskura-sha256")
                && history.iter().all(|v| v
                    .headers
                    .get("x-amz-server-side-encryption")
                    .and_then(|v| v.to_str().ok())
                    == Some("AES256")),
            "release initiation metadata was not genuinely frozen and finalized with SSE"
        );
        completed_etag
    });
    let completed_etag = &completed_etag_owner;
    with_release_pool(CASE, |pool| async move {
        let state =
            build_release_state(endpoint, Arc::new(MultipartBillingControl::default())).await;
        let (client, gateway) = serve_gateway(state, fixture).await;
        let before = provider.mutation_count(PRIMARY);
        let (status, _, body) = http(
            &client,
            &gateway,
            credentials,
            Method::POST,
            &format!("/{BUCKET}/multipart.txt?uploadId={upload_id}"),
            completion_xml.as_bytes().to_vec(),
            None,
        )
        .await;
        assert!(
            status == StatusCode::OK,
            "release reopened completion replay failed"
        );
        assert!(
            extract_xml(
                must(std::str::from_utf8(&body), "release replay XML invalid"),
                "ETag"
            ) == *completed_etag,
            "release replay changed completion identity"
        );
        assert!(
            provider.mutation_count(PRIMARY) == before,
            "release replay added a provider mutation"
        );
        read_http(
            &client,
            &gateway,
            credentials,
            &pool,
            "ordinary.txt",
            b"ordinary synthetic record\n",
            Representation::Ordinary,
        )
        .await;
        let (first, last) = large_parts();
        let expected = [first, last].concat();
        read_http(
            &client,
            &gateway,
            credentials,
            &pool,
            "multipart.txt",
            &expected,
            Representation::Identity,
        )
        .await;
        assert_publication(
            &pool,
            provider,
            "multipart.txt",
            &expected,
            UsageRoute::CompleteMultipartUpload,
            Representation::Identity,
        )
        .await;
    });
    // No gateway runtime or detached gateway workers remain in this final
    // marker-only DB closure. Provider/TLS shutdown must also finish first.
    with_release_pool(CASE, |_pool| async move {
        fixture.finish();
        complete(CASE);
    });
}

async fn admit(
    pool: &PgPool,
    service: &ServiceStorage,
    key: &str,
) -> ManagedLogicalOperationIntent {
    let repository = PostgresManagedRepository::new(pool.clone());
    let logical = LogicalObjectKey::new(TENANT, BUCKET, key);
    let placement = service
        .placement(&logical)
        .expect("release placement missing");
    let backend = service
        .backends
        .iter()
        .find(|b| b.id() == placement.primary_backend_id)
        .expect("release selected backend missing");
    let generation = uuid::Uuid::now_v7();
    let operation_id = uuid::Uuid::now_v7();
    let fence = must(
        repository.route_fence(TENANT).await,
        "release namespace fence failed",
    );
    let destination = ObjectDestination {
        backend_id: backend.id(),
        bucket: backend.bucket.clone(),
        logical_key: logical.object_key(),
        physical_key: generation_physical_key(&logical, generation),
        workspace_binding: None,
    };
    let child = ManagedOperationScope::deterministic_child(
        operation_id,
        TENANT.into(),
        fence.namespace_epoch,
        &destination,
        ManagedChildRole::Primary,
    );
    let intent = ManagedLogicalOperationIntent {
        operation_id,
        receipt_id: uuid::Uuid::now_v7(),
        logical,
        kind: ManagedMutationKind::Put,
        generation,
        fence,
        expected_authority_cas: None,
        prior_logical_size: 0,
        primary_child_operation_id: child.operation_id,
        backend_id: backend.id(),
        provider_bucket: backend.bucket.clone(),
        physical_key: destination.physical_key,
        occurred_at_ms: unix_time_ms(),
        rate_version: 1,
        route: UsageRoute::PutObject,
        request_kind: RequestKind::Write,
        max_processed_bytes: 4096,
        publication_recipe: Some(ManagedPublicationRecipe {
            version: MANAGED_PUBLICATION_RECIPE_VERSION,
            placement_version: 1,
            primary_backend_id: placement.primary_backend_id,
            replica_status: if placement.replica_backend_id.is_some() {
                CopyStatus::RepairPending
            } else {
                CopyStatus::Absent
            },
            replica_backend_id: placement.replica_backend_id,
            primary_status: CopyStatus::Ready,
            metadata: identity_metadata(),
        }),
    };
    must(
        repository
            .admit_logical_operation(intent.clone(), 64 * 1024)
            .await,
        "release logical admission failed",
    );
    intent
}

async fn usage(pool: &PgPool, intent: &ManagedLogicalOperationIntent, bytes: &[u8]) {
    must(
        PostgresManagedRepository::new(pool.clone())
            .record_logical_usage_and_begin_completion(
                intent.operation_id,
                ManagedUsageEvidence {
                    expected_output_digest: Some(digest(bytes)),
                    expected_output_size: bytes.len() as u64,
                    source_bytes: bytes.len() as u64,
                    processed_bytes: bytes.len() as u64,
                    payload: serde_json::json!({"route": "PutObject", "synthetic": true}),
                },
            )
            .await,
        "release usage/completion transition failed",
    );
}

async fn seed_nonterminal(pool: &PgPool, fixture: &Fixture) -> ManagedLogicalOperationIntent {
    let service = fixture.service(pool.clone());
    let intent = admit(pool, &service, "recovery.txt").await;
    let backend = fixture.backends().remove(0);
    let client = backend
        .build_client()
        .await
        .expect("release normal provider client missing");
    let transaction = AwsS3TransactionBackend::new_managed_b2(client.clone(), capabilities());
    let repository = PostgresManagedRepository::new(pool.clone());
    let lease = must(
        repository
            .begin_physical_write(PhysicalWriteIntent {
                intent_id: intent.primary_child_operation_id,
                tenant_id: TENANT.into(),
                backend_id: backend.id(),
                storage_identity: backend
                    .storage_identity()
                    .expect("release storage identity missing"),
                credential_epoch: 1,
                provider_bucket: backend.bucket.clone(),
                physical_key: intent.physical_key.clone(),
                versioning_mode: BackendVersioningMode::Enabled,
                versioning_capability: BackendVersioningCapability::Optional,
                lease_owner: "release-crash-writer".into(),
            })
            .await,
        "release crash physical intent failed",
    );
    let mut child_metadata = identity_metadata();
    child_metadata.extend(BTreeMap::from([
        ("maskura-generation".into(), intent.generation.to_string()),
        ("maskura-provider-instance".into(), "release-primary".into()),
        ("maskura-provider-account".into(), "release-account".into()),
        ("maskura-credential-epoch".into(), "1".into()),
    ]));
    let mut child = OperationRecord::scoped_intent(
        intent.primary_child_operation_id,
        ObjectDestination {
            backend_id: backend.id(),
            bucket: PRIMARY.into(),
            logical_key: intent.logical.object_key(),
            physical_key: intent.physical_key.clone(),
            workspace_binding: None,
        },
        ExpectedObject {
            metadata: child_metadata,
            ..Default::default()
        },
        TENANT.into(),
        lease.namespace_epoch,
    );
    let journal = PostgresOperationJournal::new(pool.clone());
    must(
        journal.insert_intent(child.clone()).await,
        "release crash journal admission failed",
    );
    let upload = must(
        transaction.create_multipart(&child).await,
        "release real provider crash MPU creation failed",
    );
    must(
        journal.set_open(child.id, Some(&upload)).await,
        "release crash journal open failed",
    );
    let bytes = Bytes::from_static(b"recovery synthetic record\n");
    let etag = must(
        transaction
            .upload_part(&child, &upload, 1, bytes.clone())
            .await,
        "release real provider crash MPU part failed",
    );
    must(
        journal
            .record_part(PartRecord {
                operation_id: child.id,
                part_number: 1,
                etag: etag.clone(),
                size_bytes: bytes.len() as u64,
                digest: digest(&bytes),
                created_at_ms: unix_time_ms(),
            })
            .await,
        "release crash journal part failed",
    );
    child.expected.digest = Some(digest(&bytes));
    child.expected.size = Some(bytes.len() as u64);
    must(
        journal.set_expected(child.id, &child.expected).await,
        "release crash output freeze failed",
    );
    usage(pool, &intent, &bytes).await;
    must(
        journal
            .transition(
                child.id,
                OperationState::Open,
                OperationState::Completing,
                None,
            )
            .await,
        "release crash journal completing failed",
    );
    // Actual provider completion, deliberately stop BEFORE the adapter's
    // metadata rewrite/journal commit. This is a nonterminal crash boundary,
    // not a manually committed child or a product metadata matcher.
    let output = must(
        client
            .complete_multipart_upload()
            .bucket(PRIMARY)
            .key(&intent.physical_key)
            .upload_id(&upload)
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .parts(CompletedPart::builder().part_number(1).e_tag(etag).build())
                    .build(),
            )
            .send()
            .await,
        "release real provider crash completion failed",
    );
    assert!(
        output.version_id().is_some(),
        "release crash version missing"
    );
    let stored = fixture.provider.versions(PRIMARY, &intent.physical_key);
    assert!(
        stored.len() == 1
            && !stored[0].headers.contains_key("x-amz-meta-maskura-sha256")
            && stored[0]
                .headers
                .get("x-amz-server-side-encryption")
                .and_then(|v| v.to_str().ok())
                == Some("AES256"),
        "release provider did not preserve genuine initiation metadata/SSE"
    );
    must(
        repository.renew_physical_write_intent(&lease, 0).await,
        "release crash lease expiration failed",
    );
    must(
        managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(0_i64),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(intent.operation_id))
            .exec(&sea_db(pool.clone()))
            .await,
        "release crash parent age failed",
    );
    must(
        object_operation::Entity::update_many()
            .col_expr(object_operation::Column::UpdatedAtMs, Expr::value(0_i64))
            .filter(object_operation::Column::Id.eq(child.id))
            .exec(&sea_db(pool.clone()))
            .await,
        "release crash child age failed",
    );
    intent
}

fn recovery_case(case: &'static str, tamper: Option<(&'static str, &'static str)>) {
    let fixture_owner = Fixture::start(case, false);
    let fixture = &fixture_owner;
    let intent_owner = with_release_pool(case, |pool| async move {
        let intent = seed_nonterminal(&pool, fixture).await;
        if let Some((key, value)) = tamper {
            let db = sea_db(pool.clone());
            let repository = PostgresManagedRepository::new(pool.clone());
            let frozen_parent = must(
                repository.logical_operation(intent.operation_id).await,
                "release tamper parent query failed",
            )
            .expect("release tamper parent missing");
            let mut expected_child = must(
                object_operation::Entity::find_by_id(intent.primary_child_operation_id)
                    .one(&db)
                    .await,
                "release tamper child query failed",
            )
            .expect("release tamper child missing");
            assert!(
                expected_child.state == "COMPLETING"
                    && expected_child.committed_version_id.is_none(),
                "release tamper requires the recorded nonterminal crash boundary"
            );
            if key == "physical-key" {
                let updated = must(
                    object_operation::Entity::update_many()
                        .col_expr(
                            object_operation::Column::PhysicalKey,
                            Expr::value("managed/wrong-physical-key"),
                        )
                        .filter(object_operation::Column::Id.eq(intent.primary_child_operation_id))
                        .exec(&sea_db(pool.clone()))
                        .await,
                    "release child destination tamper setup failed",
                );
                assert!(
                    updated.rows_affected == 1,
                    "release destination tamper affected wrong row count"
                );
                expected_child.physical_key = "managed/wrong-physical-key".into();
            } else if key == "versioning" {
                let updated = must(
                    managed_physical_write_intent::Entity::update_many()
                        .col_expr(
                            managed_physical_write_intent::Column::VersioningMode,
                            Expr::value("SUSPENDED"),
                        )
                        .filter(
                            managed_physical_write_intent::Column::IntentId
                                .eq(intent.primary_child_operation_id),
                        )
                        .exec(&sea_db(pool.clone()))
                        .await,
                    "release versioning tamper setup failed",
                );
                assert!(
                    updated.rows_affected == 1,
                    "release versioning tamper affected wrong row count"
                );
            } else {
                // Intentional TEST corruption after recording the genuine crash
                // boundary. Production set_expected correctly refuses Completing;
                // do not loosen that journal guard or pretend this is a writer.
                let mut changed: BTreeMap<String, String> = must(
                    serde_json::from_value(expected_child.expected_metadata.clone()),
                    "release stored metadata decode failed",
                );
                changed.insert(key.into(), value.into());
                let json = must(
                    serde_json::to_value(changed),
                    "release tamper metadata serialization failed",
                );
                let updated = must(
                    object_operation::Entity::update_many()
                        .col_expr(
                            object_operation::Column::ExpectedMetadata,
                            Expr::value(json.clone()),
                        )
                        .filter(object_operation::Column::Id.eq(intent.primary_child_operation_id))
                        .filter(object_operation::Column::State.eq("COMPLETING"))
                        .filter(object_operation::Column::TenantId.eq(TENANT))
                        .exec(&db)
                        .await,
                    "release exact-child metadata corruption failed",
                );
                assert!(
                    updated.rows_affected == 1,
                    "release metadata tamper affected wrong row count"
                );
                expected_child.expected_metadata = json;
            }
            let after_child = must(
                object_operation::Entity::find_by_id(intent.primary_child_operation_id)
                    .one(&db)
                    .await,
                "release tamper child verification failed",
            )
            .expect("release tampered child missing");
            assert!(
                after_child == expected_child && after_child.state == "COMPLETING",
                "release tamper changed unrelated child fields/digest/size/state"
            );
            assert!(
                must(
                    repository.logical_operation(intent.operation_id).await,
                    "release frozen parent verification failed"
                ) == Some(frozen_parent),
                "release fixture corruption changed frozen parent recipe or evidence"
            );
        }
        intent
    });
    let intent = &intent_owner;
    let before = fixture.provider.mutation_count(PRIMARY);
    let frozen_versions_owner = fixture.provider.versions(PRIMARY, &intent.physical_key);
    let frozen_versions = &frozen_versions_owner;
    with_release_pool(case, |pool| async move {
        let service = fixture.service(pool.clone());
        let journal = Arc::new(PostgresOperationJournal::new(pool.clone()));
        let repository = PostgresManagedRepository::new(pool.clone());
        let before_usage = must(
            repository.workspace_usage(TENANT).await,
            "release recovery usage query failed",
        );
        assert!(
            must(
                journal.get(intent.primary_child_operation_id).await,
                "release nonterminal child query failed"
            )
            .expect("release nonterminal child missing")
            .state
                == OperationState::Completing,
            "release recovery child was prematurely committed"
        );
        let count = must(
            service
                .reconcile_managed_logical_operations(
                    journal.clone(),
                    capabilities(),
                    Duration::ZERO,
                    1,
                )
                .await,
            "release actual service recovery failed",
        );
        assert!(
            count == 1,
            "release actual service recovery did not claim one parent"
        );
        let recovered = must(
            repository.logical_operation(intent.operation_id).await,
            "release recovered parent unavailable",
        )
        .expect("release recovered parent missing");
        assert!(
            recovered.intent == *intent,
            "release recovery changed frozen publication recipe/intent"
        );
        let child = must(
            journal.get(intent.primary_child_operation_id).await,
            "release recovered child unavailable",
        )
        .expect("release recovered child missing");
        if let Some((key, _)) = tamper {
            let reason = match key {
                "physical-key" => "child_evidence_mismatch",
                "versioning" => "provider_binding_mismatch",
                _ => "child_metadata_mismatch",
            };
            assert!(
                recovered.state == ManagedLogicalOperationState::RecoveryBlocked
                    && recovered.last_error_class.as_deref() == Some(reason)
                    && child.state == OperationState::Completing,
                "release negative recovery did not durably block before child reconciliation"
            );
            assert!(
                fixture.provider.mutation_count(PRIMARY) == before
                    && fixture.provider.versions(PRIMARY, &intent.physical_key) == *frozen_versions,
                "release negative recovery mutated provider"
            );
            assert!(
                must(
                    repository.get(&intent.logical).await,
                    "release blocked authority query failed"
                )
                .is_none(),
                "release negative recovery published authority"
            );
            assert!(
                must(
                    repository.workspace_usage(TENANT).await,
                    "release blocked usage query failed"
                ) == before_usage,
                "release negative recovery changed reservation/usage authority"
            );
            assert!(
                must(
                    repository
                        .physical_versions(
                            TENANT,
                            &intent.backend_id,
                            PRIMARY,
                            &intent.physical_key
                        )
                        .await,
                    "release blocked ledger query failed"
                )
                .is_empty(),
                "release negative recovery published physical versions"
            );
        } else {
            assert!(
                child.state == OperationState::Committed
                    && child
                        .committed
                        .as_ref()
                        .is_some_and(|v| v.version_history_complete),
                "release valid nonterminal recovery did not commit exact child"
            );
            assert_publication(
                &pool,
                &fixture.provider,
                "recovery.txt",
                b"recovery synthetic record\n",
                UsageRoute::PutObject,
                Representation::Identity,
            )
            .await;
            assert!(
                fixture.provider.operation_count(PRIMARY, "copy") > 0
                    && fixture.provider.mutation_count(PRIMARY) > before,
                "release valid recovery did not perform genuine metadata finalization"
            );
        }
    });
    with_release_pool(case, |pool| async move {
        let repository = PostgresManagedRepository::new(pool.clone());
        let reopened = must(
            repository.logical_operation(intent.operation_id).await,
            "release reopen parent unavailable",
        )
        .expect("release reopen parent missing");
        assert!(
            reopened.intent == *intent,
            "release reopened frozen recipe changed"
        );
        if tamper.is_some() {
            assert!(
                reopened.state == ManagedLogicalOperationState::RecoveryBlocked
                    && must(
                        repository.get(&intent.logical).await,
                        "release reopened authority failed"
                    )
                    .is_none()
                    && fixture.provider.mutation_count(PRIMARY) == before,
                "release negative recovery block did not survive reopen"
            );
        } else {
            assert_publication(
                &pool,
                &fixture.provider,
                "recovery.txt",
                b"recovery synthetic record\n",
                UsageRoute::PutObject,
                Representation::Identity,
            )
            .await;
        }
        fixture.finish();
        complete(case);
    });
}

#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn managed_release_recovery_valid() {
    recovery_case("recovery-valid", None);
}
#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn managed_release_recovery_customer() {
    recovery_case(
        "recovery-customer",
        Some((":maskura:user:content-type", "tampered")),
    );
}
#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn managed_release_recovery_content_type() {
    recovery_case(
        "recovery-content-type",
        Some(("content-type", "text/plain; charset=us-ascii")),
    );
}
#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn managed_release_recovery_encoding() {
    recovery_case(
        "recovery-encoding",
        Some((":maskura:representation:content-encoding", "br")),
    );
}
#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn managed_release_recovery_identity() {
    recovery_case(
        "recovery-identity",
        Some(("maskura-provider-account", "other-account")),
    );
}
#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn managed_release_recovery_codec() {
    recovery_case("recovery-codec", Some((":maskura:metadata-version", "999")));
}
#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn managed_release_recovery_physical_key() {
    recovery_case("recovery-physical-key", Some(("physical-key", "unused")));
}
#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn managed_release_recovery_versioning() {
    recovery_case("recovery-versioning", Some(("versioning", "unused")));
}

async fn repair_rows(pool: &PgPool) -> Vec<managed_object_repair::Model> {
    must(
        managed_object_repair::Entity::find()
            .filter(managed_object_repair::Column::TenantId.eq(TENANT))
            .order_by_asc(managed_object_repair::Column::CreatedAtMs)
            .all(&sea_db(pool.clone()))
            .await,
        "release repair rows unavailable",
    )
}

async fn target_counts(pool: &PgPool, backend_id: &str) -> (u64, u64, u64) {
    let db = sea_db(pool.clone());
    let journals = must(
        object_operation::Entity::find()
            .filter(object_operation::Column::BackendId.eq(backend_id))
            .count(&db)
            .await,
        "release target journal count failed",
    );
    let intents = must(
        managed_physical_write_intent::Entity::find()
            .filter(managed_physical_write_intent::Column::BackendId.eq(backend_id))
            .count(&db)
            .await,
        "release target intent count failed",
    );
    let versions = must(
        managed_physical_object_version::Entity::find()
            .filter(managed_physical_object_version::Column::BackendId.eq(backend_id))
            .count(&db)
            .await,
        "release target version count failed",
    );
    (journals, intents, versions)
}

async fn assert_repaired_target(
    pool: &PgPool,
    fixture: &Fixture,
    intent: &ManagedLogicalOperationIntent,
    target_id: &str,
    target_bucket: &str,
) {
    let configured = fixture
        .backends()
        .into_iter()
        .find(|b| b.id() == target_id)
        .expect("release configured repair target missing");
    let ledger = must(
        PostgresManagedRepository::new(pool.clone())
            .physical_versions(TENANT, target_id, target_bucket, &intent.physical_key)
            .await,
        "release repaired target ledger unavailable",
    );
    assert!(
        ledger.len() == 1,
        "release repair must publish one exact target physical version"
    );
    let row = &ledger[0];
    assert!(
        row.write_operation_id != intent.primary_child_operation_id
            && row.backend_id == target_id
            && row.provider_bucket == target_bucket
            && row.physical_key == intent.physical_key
            && row.tenant_id == TENANT
            && row.namespace_epoch == intent.fence.namespace_epoch
            && row.storage_identity
                == configured
                    .storage_identity()
                    .expect("release configured target identity missing")
            && row.credential_epoch
                == configured
                    .credential_epoch()
                    .expect("release configured epoch missing")
            && row.versioning_mode == BackendVersioningMode::Enabled
            && row.versioning_capability == BackendVersioningCapability::Optional,
        "release target ledger is not bound to the actual repair child/configured identity"
    );
    let child = must(
        PostgresOperationJournal::new(pool.clone())
            .get(row.write_operation_id)
            .await,
        "release repair child journal unavailable",
    )
    .expect("release actual repair child missing");
    let committed = child
        .committed
        .as_ref()
        .expect("release repair child commit missing");
    let selected_id = committed
        .version_id
        .as_deref()
        .expect("release repair committed version missing");
    assert!(
        child.id == row.write_operation_id
            && child.state == OperationState::Committed
            && committed.version_history_complete
            && row.version_id.as_deref() == Some(selected_id)
            && child.tenant_id.as_deref() == Some(TENANT)
            && child.namespace_epoch == Some(intent.fence.namespace_epoch)
            && child.destination.backend_id == target_id
            && child.destination.bucket == target_bucket
            && child.destination.physical_key == intent.physical_key
            && child.destination.logical_key == intent.logical.object_key(),
        "release repair child committed version/destination/scope binding failed"
    );
    let copies = fixture
        .provider
        .versions(target_bucket, &intent.physical_key);
    assert!(
        copies.len() == 1,
        "release repair target has unexpected provider version inventory"
    );
    let selected = copies
        .iter()
        .find(|v| v.id == selected_id)
        .expect("release exact repaired provider version missing");
    let expected = ExpectedPhysical {
        bytes: b"repair synthetic record\n",
        representation: Representation::Identity,
        operation_id: row.write_operation_id,
        generation: intent.generation,
        instance: configured
            .provider_instance_id()
            .expect("release configured target instance missing"),
        account: configured
            .provider_account_id()
            .expect("release configured target account missing"),
        credential_epoch: configured
            .credential_epoch()
            .expect("release configured target epoch missing"),
        selected_version: selected_id,
    };
    assert!(
        child.expected.metadata == expected.child_metadata()
            && child.expected.digest.as_deref() == Some(digest(expected.bytes).as_str())
            && child.expected.size == Some(expected.bytes.len() as u64)
            && committed.etag.as_deref() == Some(selected.etag.as_str())
            && physical_object_matches(selected, &expected),
        "release actual repaired target lost customer/representation/physical identity/digest/size/version/SSE binding"
    );
    // These pure CLONE controls test the oracle, not a product rejection path.
    // They leave the valid actual provider object and PG rows untouched.
    assert_corrupt_clone_controls(selected, &expected);
}

fn repair_case(case: &'static str, tamper: bool) {
    let fixture_owner = Fixture::start(case, true);
    let fixture = &fixture_owner;
    let (intent_owner, source_bucket_owner, target_bucket_owner) =
        with_release_pool(case, |pool| async move {
            let service = fixture.service(pool.clone());
            let intent = admit(&pool, &service, "repair.txt").await;
            let repository = PostgresManagedRepository::new(pool.clone());
            let mut sink = must(
                service
                    .begin_authoritative_sink_for_operation(
                        Arc::new(PostgresOperationJournal::new(pool.clone())),
                        capabilities(),
                        intent.logical.clone(),
                        CONTENT_TYPE,
                        intent.operation_id,
                        ManagedOperationScope {
                            operation_id: intent.primary_child_operation_id,
                            tenant_id: TENANT.into(),
                            namespace_epoch: intent.fence.namespace_epoch,
                        },
                        intent.generation,
                    )
                    .await,
                "release actual service repair seed sink failed",
            );
            let bytes = Bytes::from_static(b"repair synthetic record\n");
            must(
                sink.write(bytes.clone()).await,
                "release service repair seed write failed",
            );
            must(
                sink.verify_output(bytes.len() as u64, &digest(&bytes))
                    .await,
                "release service repair seed verify failed",
            );
            usage(&pool, &intent, &bytes).await;
            must(
                sink.complete(DestinationCommitAuthority::SinglePut).await,
                "release actual service repair seed commit failed",
            );
            let authority = must(
                repository.get(&intent.logical).await,
                "release repair seed authority failed",
            )
            .expect("release repair seed authority missing");
            assert!(
                authority.replica_status == CopyStatus::RepairPending,
                "release initial transaction did not queue genuine replica repair"
            );
            let backends = fixture.backends();
            let source_bucket = backends
                .iter()
                .find(|b| b.id() == authority.primary_backend_id)
                .expect("release repair source backend missing")
                .bucket
                .clone();
            let target_id = authority
                .replica_backend_id
                .as_ref()
                .expect("release repair target missing");
            let target_bucket = backends
                .iter()
                .find(|b| b.id() == *target_id)
                .expect("release repair target backend missing")
                .bucket
                .clone();
            // This architecture intentionally queues replicas rather than attempting
            // them during the primary transaction. Inject a real failure in that
            // queued replica leg; do not invent a synchronous replication attempt.
            fixture.provider.fail_writes(&target_bucket, true);
            let before = fixture.provider.mutation_count(&target_bucket);
            assert!(
                must(
                    service
                        .repair_due(
                            Arc::new(PostgresOperationJournal::new(pool.clone())),
                            capabilities(),
                            "release-injected-replica-failure",
                            1
                        )
                        .await,
                    "release injected replica repair failed"
                ) == 1,
                "release replica repair was not claimed"
            );
            assert!(
                fixture.provider.mutation_count(&target_bucket) > before,
                "release injected replica failure did not reach actual target mutation"
            );
            fixture.provider.fail_writes(&target_bucket, false);
            let rows = repair_rows(&pool).await;
            assert!(
                rows.len() == 1
                    && rows[0].state == "PENDING"
                    && rows[0].attempts == 1
                    && rows[0].lease_token.is_none()
                    && rows[0].not_before_ms > unix_time_ms(),
                "release injected replica repair did not persist real retry semantics"
            );
            must(
                managed_object_repair::Entity::update_many()
                    .col_expr(
                        managed_object_repair::Column::NotBeforeMs,
                        Expr::value(0_i64),
                    )
                    .filter(managed_object_repair::Column::Id.eq(rows[0].id))
                    .exec(&sea_db(pool.clone()))
                    .await,
                "release retry scheduling setup failed",
            );
            (intent, source_bucket, target_bucket)
        });
    let intent = &intent_owner;
    let source_bucket = &source_bucket_owner;
    let target_bucket = &target_bucket_owner;
    // Destroying setup's runtime also ends failed child cleanup tasks before
    // the zero-target-mutation observation window begins.
    if tamper {
        fixture
            .provider
            .tamper_latest_type(source_bucket, &intent.physical_key);
    }
    let target_before = fixture.provider.mutation_count(target_bucket);
    let reads_before = fixture.provider.operation_count(source_bucket, "get");
    let (expected_authority, expected_recipe) = with_release_pool(case, |pool| async move {
        let repository = PostgresManagedRepository::new(pool.clone());
        let authority = must(
            repository.get(&intent.logical).await,
            "release pre-repair authority failed",
        )
        .expect("release pre-repair authority missing");
        let op = operation(&pool, "repair.txt").await;
        assert!(
            op.intent == *intent
                && authority.metadata == identity_metadata()
                && authority.generation == intent.generation
                && authority.size == b"repair synthetic record\n".len() as u64
                && authority.digest == digest(b"repair synthetic record\n"),
            "release pre-repair parent/expected metadata/bytes binding changed"
        );
        let target_id = authority
            .replica_backend_id
            .as_ref()
            .expect("release target identity missing");
        let counts = target_counts(&pool, target_id).await;
        let versions = fixture
            .provider
            .versions(target_bucket, &intent.physical_key);
        let service = fixture.service(pool.clone());
        assert!(
            must(
                service
                    .repair_due(
                        Arc::new(PostgresOperationJournal::new(pool.clone())),
                        capabilities(),
                        "release-actual-repair",
                        1
                    )
                    .await,
                "release actual repair_due failed"
            ) == 1,
            "release actual repair_due did not claim one repair"
        );
        assert!(
            fixture.provider.operation_count(source_bucket, "get") > reads_before,
            "release repair did not read actual provider source"
        );
        let rows = repair_rows(&pool).await;
        let after = must(
            repository.get(&intent.logical).await,
            "release post-repair authority failed",
        )
        .expect("release post-repair authority missing");
        assert!(
            operation(&pool, "repair.txt")
                .await
                .intent
                .publication_recipe
                == op.intent.publication_recipe,
            "release repair modified frozen publication recipe"
        );
        if tamper {
            assert!(
                fixture.provider.mutation_count(target_bucket) == target_before
                    && fixture
                        .provider
                        .versions(target_bucket, &intent.physical_key)
                        == versions
                    && target_counts(&pool, target_id).await == counts
                    && after == authority,
                "release rejected source mutated target/journal/intent/version/authority"
            );
            assert!(
                rows.len() == 1
                    && rows[0].state == "PENDING"
                    && rows[0].attempts == 2
                    && rows[0].not_before_ms > unix_time_ms()
                    && rows[0].lease_owner.is_none()
                    && rows[0].lease_token.is_none()
                    && rows[0].lease_expires_at_ms.is_none()
                    && rows[0].last_error.as_deref()
                        == Some("repair source generation metadata does not match authority"),
                "release source rejection did not persist actual pending retry/lease semantics"
            );
        } else {
            assert!(
                rows.len() == 1
                    && rows[0].state == "DONE"
                    && after.replica_status == CopyStatus::Ready
                    && after.cas_version == authority.cas_version + 1
                    && after.generation == authority.generation
                    && after.digest == authority.digest
                    && after.size == authority.size
                    && after.metadata == authority.metadata,
                "release valid repair did not durably publish expected authority readiness"
            );
            assert_repaired_target(&pool, fixture, intent, target_id, target_bucket).await;
        }
        (after, op.intent.publication_recipe)
    });
    with_release_pool(case, |pool| async move {
        let reopened = must(
            PostgresManagedRepository::new(pool.clone())
                .get(&intent.logical)
                .await,
            "release repaired authority reopen failed",
        )
        .expect("release reopened authority missing");
        assert!(
            reopened == expected_authority,
            "release repair authority did not survive reopen"
        );
        assert!(
            operation(&pool, "repair.txt")
                .await
                .intent
                .publication_recipe
                == expected_recipe,
            "release repaired recipe did not survive reopen"
        );
        let rows = repair_rows(&pool).await;
        assert!(
            rows.len() == 1 && rows[0].state == if tamper { "PENDING" } else { "DONE" },
            "release repair state did not survive reopen"
        );
        if tamper {
            assert!(
                fixture.provider.mutation_count(target_bucket) == target_before,
                "release rejected repair added a late target mutation"
            );
        } else {
            assert_repaired_target(
                &pool,
                fixture,
                intent,
                reopened
                    .replica_backend_id
                    .as_deref()
                    .expect("release reopened repair target missing"),
                target_bucket,
            )
            .await;
        }
        fixture.finish();
        complete(case);
    });
}

#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn managed_release_repair_valid() {
    repair_case("repair-valid", false);
}
#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn managed_release_repair_source_mismatch() {
    repair_case("repair-source-mismatch", true);
}

fn specific_certificate_cause(error: &(dyn std::error::Error + 'static), mode: TlsMode) -> bool {
    // No new rustls dependency is needed. Require the std::io::Error boundary
    // produced by tokio-rustls and its exact locked-rustls certificate cause,
    // not a broad SDK error string, timeout, TLS alert, EOF, or refused socket.
    // A dependency's diagnostic change must fail closed and be re-reviewed.
    let mut current = Some(error);
    for _ in 0..16 {
        let Some(error) = current else {
            return false;
        };
        if let Some(io) = error.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::InvalidData
            && io
                .get_ref()
                .is_some_and(|cause| cause.to_string() == mode.certificate_cause())
        {
            return true;
        }
        current = error.source();
    }
    false
}

fn tls_rejection_case(case: &'static str, mode: TlsMode) {
    // Fresh exact-case process is mandatory: native TLS roots are cached.
    let fixture_owner = Fixture::start_tls_mode(case, false, mode);
    let fixture = &fixture_owner;
    let address = fixture.numeric_tls_address();
    assert!(
        address.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        "release TLS rejection endpoint was not numeric loopback"
    );
    let stream = must(
        std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1)),
        "release TLS rejection listener was not reachable",
    );
    must(
        stream.shutdown(std::net::Shutdown::Both),
        "release TLS reachability probe shutdown failed",
    );
    drop(stream);
    with_release_pool(case, |_pool| async move {
        assert!(
            fixture
                .provider
                .0
                .lock()
                .expect("release fixture lock")
                .calls
                .is_empty(),
            "release TLS rejection control had unexpected preflight HTTP dispatch"
        );
        let backend = fixture.backends().remove(0);
        assert!(
            backend.endpoint == fixture.endpoint
                && backend.endpoint == format!("https://{address}"),
            "release TLS rejection did not use the same reachable numeric endpoint"
        );
        // Unchanged real ServiceBackend::build_client: normal chain/name checks,
        // static synthetic provider credentials, no custom connector or danger_*.
        let client = backend
            .build_client()
            .await
            .expect("release TLS rejection SDK client missing");
        let result = must(
            tokio::time::timeout(
                Duration::from_secs(20),
                client.get_bucket_versioning().bucket(PRIMARY).send(),
            )
            .await,
            "release TLS rejection SDK request timed out",
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("release SDK accepted invalid certificate"),
        };
        assert!(
            matches!(&error, aws_sdk_s3::error::SdkError::DispatchFailure(_))
                && specific_certificate_cause(&error, mode),
            "release SDK failed without the required specific certificate-verification cause"
        );
        let no_dispatch = {
            let provider = fixture.provider.0.lock().expect("release fixture lock");
            provider.calls.is_empty()
        };
        assert!(
            no_dispatch
                && fixture.provider.mutation_count(PRIMARY) == 0
                && fixture.provider.mutation_count(SECONDARY) == 0
                && fixture.provider.mutation_count(STAGING) == 0,
            "release invalid TLS certificate reached provider HTTP dispatch or mutation"
        );
    });
    // The SDK runtime is fully gone before group/listener shutdown and marker.
    with_release_pool(case, |_pool| async move {
        fixture.finish();
        complete(case);
    });
}

#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn managed_release_tls_unrelated_ca() {
    tls_rejection_case("tls-unrelated-ca", TlsMode::UnrelatedCa);
}
#[test]
#[ignore = "requires owned managed release qualification launcher"]
fn managed_release_tls_wrong_numeric_san() {
    tls_rejection_case("tls-wrong-numeric-san", TlsMode::WrongName);
}
