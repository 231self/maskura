//! Postgres-backed key store integration tests.
//!
//! These run only when `DATABASE_URL` points at a reachable Postgres
//! (e.g. local Supabase: `postgresql://postgres:postgres@127.0.0.1:54322/postgres`).
//! Migrations are applied automatically. Without `DATABASE_URL` the tests
//! skip.

use aes_gcm::aead::{Aead, KeyInit};

use aes_gcm::{Aes256Gcm, Nonce};

use base64::Engine;

use base64::engine::general_purpose::STANDARD as B64;

use maskura_customer_config::Config;

use maskura_gateway::entity::api_key;

use maskura_gateway::entity::managed_list_cursor;

use maskura_gateway::entity::managed_logical_operation;

use maskura_gateway::entity::managed_namespace;

use maskura_gateway::entity::managed_namespace_purge;

use maskura_gateway::entity::managed_object_authority;

use maskura_gateway::entity::managed_object_repair;

use maskura_gateway::entity::managed_physical_object_version;

use maskura_gateway::entity::managed_workspace_usage;

use maskura_gateway::entity::multipart_upload;

use maskura_gateway::entity::object_operation;

use maskura_gateway::key_cipher::{KeyWrapping, LocalKeyWrapping, SecretCipher};

use maskura_gateway::managed::{
    AuthorityListQuery, AuthorityPlacementPageQuery, BackendVersioningCapability,
    BackendVersioningMode, CopyStatus, ExactPhysicalCommit, InMemoryManagedRepository,
    LogicalAbortProof, LogicalObjectKey, MANAGED_LIST_CURSOR_RESPONSE_MAX_BYTES,
    MANAGED_LIST_CURSOR_WORKSPACE_LIMIT, MANAGED_PUBLICATION_RECIPE_VERSION, ManagedDeleteRequest,
    ManagedListCursorBinding, ManagedListCursorPosition, ManagedListCursorRequest,
    ManagedListCursorState, ManagedListVersion, ManagedLogicalOperationIntent,
    ManagedLogicalOperationState, ManagedMutationKind, ManagedPublicationRecipe, ManagedRepository,
    ManagedRouteFence, ManagedUsageEvidence, NamespacePurgeRequest, NamespacePurgeStatus,
    ObjectAuthority, PhysicalWriteIntent, Placement, PostgresManagedRepository,
    ProviderStorageIdentity, RepairRecord, RepairTargetRole, generation_physical_key,
};

use maskura_gateway::multipart_staging::{
    ARTIFACT_PREFIX, CompletePart, CompletionAcquire, DestinationCommitPermit,
    MultipartCompletionResult, MultipartIdentity, MultipartLifecycle, MultipartPart,
    MultipartRepository, MultipartSnapshot, MultipartUpload, PostgresMultipartRepository,
};

use maskura_gateway::store::{KeyRepository, PostgresKeyStore, sha256_hash};

use maskura_gateway::transaction::{
    EvidenceRecord, ExpectedObject, ObjectDestination, OperationJournal, OperationRecord,
    OperationState, PartRecord, PostgresOperationJournal, StoredObjectMeta,
    WorkspaceDestinationBinding,
};

use maskura_gateway::workspace_storage::WorkspaceId;

use sea_orm::sea_query::Expr;

use sea_orm::{
    ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    SqlxPostgresConnector,
};

use sqlx::PgPool;

use sqlx::postgres::PgPoolOptions;

use std::collections::{BTreeMap, HashMap};

use std::pin::Pin;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use std::sync::{Arc, Mutex, mpsc};

use std::task::{Context, Poll};

use std::time::Duration;

use axum::body::Body;

use axum::extract::State;

use axum::http::{Method, Request, StatusCode, header};

use maskura_gateway::control::{
    AuthenticatedRequestContext, AuthorizationDecision, AuthorizationError, AuthorizationGrant,
    ControlPlane, MeteringError, RequestKind, UsageAuthorization, UsageEvent, UsageRoute,
};

use maskura_gateway::server::{build_router, build_state};

use tower::ServiceExt;

const TEST_KEK: [u8; 32] = [7; 32];

const TEST_PUBLIC_KEY_PEM: &str =
    include_str!("../../../../tests/fixtures/pii/crypto/hybrid-public.pem");

const TEST_PUBLIC_KEY_2_PEM: &str =
    include_str!("../../../../tests/fixtures/pii/crypto/hybrid-public-2.pem");

static DB_TEST_LOCK: Mutex<()> = Mutex::new(());

fn publication_recipe(primary_backend_id: &str) -> ManagedPublicationRecipe {
    ManagedPublicationRecipe {
        version: MANAGED_PUBLICATION_RECIPE_VERSION,
        placement_version: 1,
        primary_backend_id: primary_backend_id.to_string(),
        replica_backend_id: None,
        metadata: BTreeMap::new(),
        primary_status: CopyStatus::Ready,
        replica_status: CopyStatus::Absent,
    }
}

#[derive(Default)]
struct MultipartBillingControl {
    authorizations: Mutex<Vec<(AuthenticatedRequestContext, UsageAuthorization)>>,
    grants: Mutex<HashMap<uuid::Uuid, AuthorizationGrant>>,
    releases: Mutex<Vec<(AuthenticatedRequestContext, uuid::Uuid)>>,
    events: Mutex<Vec<(AuthenticatedRequestContext, UsageEvent)>>,
}

#[async_trait::async_trait]
impl ControlPlane for MultipartBillingControl {
    async fn authorize(
        &self,
        context: &AuthenticatedRequestContext,
        authorization: &UsageAuthorization,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        self.authorizations
            .lock()
            .unwrap()
            .push((context.clone(), authorization.clone()));
        let grant = self
            .grants
            .lock()
            .unwrap()
            .entry(authorization.operation_id())
            .or_insert_with(|| AuthorizationGrant::new(authorization, chrono::Utc::now(), 1))
            .clone();
        Ok(AuthorizationDecision::Granted(grant))
    }

    async fn release(
        &self,
        context: &AuthenticatedRequestContext,
        operation_id: uuid::Uuid,
    ) -> Result<(), AuthorizationError> {
        self.releases
            .lock()
            .unwrap()
            .push((context.clone(), operation_id));
        Ok(())
    }

    async fn record(
        &self,
        context: &AuthenticatedRequestContext,
        event: &UsageEvent,
    ) -> Result<(), MeteringError> {
        self.events
            .lock()
            .unwrap()
            .push((context.clone(), event.clone()));
        Ok(())
    }
}

fn unix_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
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

fn test_physical_intent(
    intent_id: uuid::Uuid,
    tenant_id: &str,
    backend_id: &str,
    provider_bucket: &str,
    physical_key: &str,
    lease_owner: &str,
) -> PhysicalWriteIntent {
    PhysicalWriteIntent {
        intent_id,
        tenant_id: tenant_id.to_string(),
        backend_id: backend_id.to_string(),
        storage_identity: test_storage_identity(),
        credential_epoch: 1,
        provider_bucket: provider_bucket.to_string(),
        physical_key: physical_key.to_string(),
        versioning_mode: BackendVersioningMode::Enabled,
        versioning_capability: BackendVersioningCapability::Optional,
        lease_owner: lease_owner.to_string(),
    }
}

async fn insert_committed_child(
    pool: &PgPool,
    intent: &ManagedLogicalOperationIntent,
    digest: &str,
    size: u64,
    result: &ExactPhysicalCommit,
) {
    let journal = PostgresOperationJournal::new(pool.clone());
    let expected = ExpectedObject {
        digest: Some(digest.to_string()),
        size: Some(size),
        metadata: BTreeMap::new(),
    };
    journal
        .insert_intent(OperationRecord::scoped_intent(
            intent.primary_child_operation_id,
            ObjectDestination {
                backend_id: intent.backend_id.clone(),
                bucket: intent.provider_bucket.clone(),
                logical_key: intent.logical.object_key(),
                physical_key: intent.physical_key.clone(),
                workspace_binding: None,
            },
            expected,
            intent.logical.tenant_id.clone(),
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
            OperationState::Completing,
            None,
        )
        .await
        .unwrap();
    journal
        .transition(
            intent.primary_child_operation_id,
            OperationState::Completing,
            OperationState::Committed,
            Some(&StoredObjectMeta {
                etag: Some("test-etag".to_string()),
                version_id: result.selected_version_id.clone(),
                superseded_version_ids: result.superseded_version_ids.clone(),
                version_history_complete: result.version_history_complete,
            }),
        )
        .await
        .unwrap();
}

async fn assert_physical_intent_duplicate_contract(
    repository: &dyn ManagedRepository,
    tenant_id: &str,
) {
    let intent = test_physical_intent(
        uuid::Uuid::now_v7(),
        tenant_id,
        "provider:managed-primary",
        "provider-bucket",
        "managed/physical-key",
        "contract-writer",
    );
    let lease = repository
        .begin_physical_write(intent.clone())
        .await
        .unwrap();
    assert_eq!(
        repository
            .begin_physical_write(intent.clone())
            .await
            .unwrap(),
        lease
    );

    let conflicts = [
        PhysicalWriteIntent {
            physical_key: "managed/other-key".to_string(),
            ..intent.clone()
        },
        PhysicalWriteIntent {
            lease_owner: "other-writer".to_string(),
            ..intent.clone()
        },
        PhysicalWriteIntent {
            credential_epoch: 2,
            ..intent.clone()
        },
        PhysicalWriteIntent {
            storage_identity: ProviderStorageIdentity {
                provider_account_id: "other-account".to_string(),
                ..intent.storage_identity.clone()
            },
            ..intent.clone()
        },
    ];
    for conflicting in conflicts {
        assert!(matches!(
            repository.begin_physical_write(conflicting).await,
            Err(maskura_gateway::managed::ManagedError::RecoveryBlocked(_))
        ));
    }
    let pending = repository.pending_physical_write_intents(10).await.unwrap();
    let matching: Vec<_> = pending
        .iter()
        .filter(|pending| pending.intent.intent_id == intent.intent_id)
        .collect();
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].intent, intent);
    assert_eq!(matching[0].lease, lease);
    repository.abort_physical_write(&lease).await.unwrap();
}

async fn ledger_managed_test_version(
    repository: &PostgresManagedRepository,
    tenant_id: &str,
    backend_id: &str,
    physical_key: &str,
) -> String {
    let intent_id = uuid::Uuid::now_v7();
    let version_id = format!("version-{intent_id}");
    let lease = repository
        .begin_physical_write(test_physical_intent(
            intent_id,
            tenant_id,
            backend_id,
            "test-provider-bucket",
            physical_key,
            "db-test-writer",
        ))
        .await
        .unwrap();
    repository
        .commit_physical_write(&lease, &[], Some(&version_id))
        .await
        .unwrap();
    version_id
}

fn sea_db(pool: PgPool) -> DatabaseConnection {
    SqlxPostgresConnector::from_sqlx_postgres_pool(pool)
}

fn v1_envelope(secret: &str) -> String {
    let wrapping = LocalKeyWrapping::with_kek(TEST_KEK);
    let dek = [3u8; 32];
    let wrapped = wrapping.wrap(&dek).expect("wrap v1 test DEK");
    let nonce = [4u8; 12];
    let cipher = Aes256Gcm::new_from_slice(&dek).expect("valid AES-256 key");
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), secret.as_bytes())
        .expect("encrypt v1 test secret");
    format!(
        "v1:{}:{}:{}",
        B64.encode(wrapped),
        B64.encode(nonce),
        B64.encode(ciphertext)
    )
}

async fn update_secret_state(
    db: &DatabaseConnection,
    key_id: &str,
    secret_hash: Option<&str>,
    envelope: &str,
) {
    let mut update = api_key::Entity::update_many().col_expr(
        api_key::Column::SecretEncrypted,
        Expr::value(Some(envelope.to_string())),
    );
    if let Some(secret_hash) = secret_hash {
        update = update.col_expr(
            api_key::Column::SecretHash,
            Expr::value(secret_hash.to_string()),
        );
    }
    let result = update
        .filter(api_key::Column::KeyId.eq(key_id.to_string()))
        .exec(db)
        .await
        .expect("update test API key secret state");
    assert_eq!(result.rows_affected, 1);
}

async fn fetch_api_key(db: &DatabaseConnection, key_id: &str) -> api_key::Model {
    api_key::Entity::find()
        .filter(api_key::Column::KeyId.eq(key_id.to_string()))
        .one(db)
        .await
        .expect("fetch test API key")
        .expect("test API key exists")
}

async fn delete_api_key(db: &DatabaseConnection, key_id: &str) {
    let result = api_key::Entity::delete_many()
        .filter(api_key::Column::KeyId.eq(key_id.to_string()))
        .exec(db)
        .await
        .expect("delete test API key");
    assert_eq!(result.rows_affected, 1);
}

struct BlockingWrapping {
    inner: LocalKeyWrapping,
    entered: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl std::fmt::Debug for BlockingWrapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingWrapping").finish_non_exhaustive()
    }
}

impl KeyWrapping for BlockingWrapping {
    fn wrap(&self, dek: &[u8]) -> anyhow::Result<Vec<u8>> {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            entered.send(()).expect("signal blocked rewrap");
            self.release
                .lock()
                .unwrap()
                .recv()
                .expect("release blocked rewrap");
        }
        self.inner.wrap(dek)
    }

    fn unwrap(&self, wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.inner.unwrap(wrapped)
    }
}

/// Connect to `DATABASE_URL` (skipping only if unset), apply
/// migrations, then run `body` on a single Tokio runtime.
fn with_pool<F, Fut>(body: F)
where
    F: FnOnce(PgPool) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let _guard = DB_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("SKIP: DATABASE_URL not set");
            return;
        };
        // A concurrent rewrap intentionally has a reader, conditional writer,
        // and verifier in flight. Keep the test pool above the production
        // default so its cleanup cannot be starved by those handles.
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&url)
            .await
            .expect("DATABASE_URL must be reachable when configured");
        maskura_gateway::run_engine_migrations(&pool)
            .await
            .expect("migrations should apply");
        body(pool.clone()).await;
        pool.close().await;
    });
}

fn auth_headers(ak: &str, sk: &str) -> Vec<(&'static str, String)> {
    vec![
        ("x-maskura-access-key", ak.to_string()),
        ("x-maskura-secret-key", sk.to_string()),
    ]
}

fn add_headers(req: Request<Body>, hdrs: &[(&'static str, String)]) -> Request<Body> {
    let (mut parts, body) = req.into_parts();
    for (name, value) in hdrs {
        parts.headers.insert(*name, value.parse().unwrap());
    }
    Request::from_parts(parts, body)
}

fn extract_xml(xml: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    xml.split(&open)
        .nth(1)
        .and_then(|rest| rest.split(&close).next())
        .unwrap_or_default()
        .to_string()
}

type MockObjects = Arc<tokio::sync::Mutex<HashMap<String, Vec<u8>>>>;

#[derive(Clone, Default)]
struct MockS3State {
    objects: MockObjects,
    multipart_parts: Arc<tokio::sync::Mutex<HashMap<String, Vec<u8>>>>,
    block_destination_put: Arc<AtomicBool>,
    destination_put_count: Arc<AtomicUsize>,
    destination_put_started: Arc<tokio::sync::Notify>,
    release_destination_put: Arc<tokio::sync::Notify>,
    omit_destination_head_length: Arc<AtomicBool>,
    fail_destination_delete: Arc<AtomicBool>,
}

impl MockS3State {
    async fn wait_for_destination_put_after(&self, previous: usize) {
        loop {
            let notified = self.destination_put_started.notified();
            if self.destination_put_count.load(Ordering::Acquire) > previous {
                return;
            }
            notified.await;
        }
    }
}

struct UnknownSizeEmptyBody;

impl http_body::Body for UnknownSizeEmptyBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(None)
    }
}

const MOCK_STAGING_BUCKET: &str = "staging-bucket";

/// Decodes the SigV4 streaming (`aws-chunked`) framing the SDK applies to a
/// non-replayable PutObject body. Frames are `<hex-size>;chunk-signature=...`
/// headers followed by the raw chunk bytes; a zero-size chunk ends the body.
fn decode_aws_chunked(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let line_end = data[pos..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|index| pos + index)
            .unwrap_or(data.len());
        let line = &data[pos..line_end];
        let size_str = line.split(|byte| *byte == b';').next().unwrap_or(b"");
        let size =
            usize::from_str_radix(std::str::from_utf8(size_str).unwrap_or_default().trim(), 16)
                .unwrap_or(0);
        pos = line_end.saturating_add(2);
        if size == 0 || pos.saturating_add(size) > data.len() {
            break;
        }
        out.extend_from_slice(&data[pos..pos + size]);
        pos += size;
        if data.get(pos..pos + 2) == Some(b"\r\n") {
            pos += 2;
        }
    }
    out
}

/// Minimal S3-compatible object store backing `S3StagingArtifactStore`. The
/// staging store only needs PutObject/GetObject/DeleteObject/ListObjectsV2,
/// and the AWS SDK addresses a custom endpoint path-style (`/{bucket}/{key}`).
async fn mock_s3_handler(
    State(state): State<MockS3State>,
    request: Request<Body>,
) -> axum::response::Response {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().trim_start_matches('/').to_string();
    let query = parts.uri.query().unwrap_or_default().to_string();
    let query_value = |name: &str| {
        query.split('&').find_map(|entry| {
            entry
                .strip_prefix(name)
                .and_then(|value| value.strip_prefix('='))
        })
    };

    if parts.method == Method::POST
        && query
            .split('&')
            .any(|value| value == "uploads" || value == "uploads=")
    {
        let upload_id = uuid::Uuid::now_v7().to_string();
        let xml = format!(
            "<InitiateMultipartUploadResult><Bucket>{}</Bucket><Key>{path}</Key><UploadId>{upload_id}</UploadId></InitiateMultipartUploadResult>",
            path.split('/').next().unwrap_or_default()
        );
        return axum::response::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/xml")
            .body(Body::from(xml))
            .unwrap();
    }

    if parts.method == Method::GET && query.contains("list-type=2") {
        let prefix = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("prefix="))
            .unwrap_or_default()
            .replace("%2F", "/");
        let objects = state.objects.lock().await;
        let mut keys: Vec<String> = objects
            .keys()
            .filter(|key| key.starts_with(&prefix))
            .cloned()
            .collect();
        keys.sort();
        let mut xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>{MOCK_STAGING_BUCKET}</Name><Prefix>{prefix}</Prefix><KeyCount>{}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>"#,
            keys.len()
        );
        for object_key in keys {
            xml.push_str(&format!(
                "<Contents><Key>{object_key}</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>{}</Size></Contents>",
                objects.get(&object_key).map_or(0, Vec::len)
            ));
        }
        xml.push_str("</ListBucketResult>");
        return axum::response::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/xml")
            .body(Body::from(xml))
            .unwrap();
    }

    let key = path
        .strip_prefix(&format!("{MOCK_STAGING_BUCKET}/"))
        .map(str::to_owned)
        .unwrap_or_else(|| path.clone());

    match parts.method {
        Method::PUT => {
            if let (Some(upload_id), Some(part_number)) =
                (query_value("uploadId"), query_value("partNumber"))
            {
                if state.block_destination_put.load(Ordering::Acquire) {
                    state.destination_put_count.fetch_add(1, Ordering::AcqRel);
                    state.destination_put_started.notify_waiters();
                    while state.block_destination_put.load(Ordering::Acquire) {
                        let released = state.release_destination_put.notified();
                        if !state.block_destination_put.load(Ordering::Acquire) {
                            break;
                        }
                        released.await;
                    }
                }
                let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024)
                    .await
                    .unwrap_or_default();
                state
                    .multipart_parts
                    .lock()
                    .await
                    .insert(format!("{upload_id}/{part_number}"), bytes.to_vec());
                return axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::ETAG, format!("\"mock-part-{part_number}\""))
                    .body(Body::empty())
                    .unwrap();
            }
            if !path.starts_with(&format!("{MOCK_STAGING_BUCKET}/"))
                && state.block_destination_put.load(Ordering::Acquire)
            {
                state.destination_put_count.fetch_add(1, Ordering::AcqRel);
                state.destination_put_started.notify_waiters();
                while state.block_destination_put.load(Ordering::Acquire) {
                    let released = state.release_destination_put.notified();
                    if !state.block_destination_put.load(Ordering::Acquire) {
                        break;
                    }
                    released.await;
                }
            }
            let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024)
                .await
                .unwrap_or_default();
            let decoded = if parts
                .headers
                .get(header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.contains("aws-chunked"))
            {
                decode_aws_chunked(&bytes)
            } else {
                bytes.to_vec()
            };
            state.objects.lock().await.insert(key, decoded);
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .header(header::ETAG, "\"mock-etag\"")
                .body(Body::empty())
                .unwrap()
        }
        Method::POST => {
            let Some(upload_id) = query_value("uploadId") else {
                return axum::response::Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::empty())
                    .unwrap();
            };
            let _completion = axum::body::to_bytes(body, 64 * 1024 * 1024)
                .await
                .unwrap_or_default();
            let mut parts = state
                .multipart_parts
                .lock()
                .await
                .iter()
                .filter_map(|(part_key, bytes)| {
                    part_key
                        .strip_prefix(&format!("{upload_id}/"))
                        .and_then(|number| number.parse::<u32>().ok())
                        .map(|number| (number, bytes.clone()))
                })
                .collect::<Vec<_>>();
            parts.sort_by_key(|(number, _)| *number);
            let mut assembled = Vec::new();
            for (_, bytes) in &parts {
                assembled.extend_from_slice(bytes);
            }
            state.objects.lock().await.insert(path.clone(), assembled);
            state
                .multipart_parts
                .lock()
                .await
                .retain(|part_key, _| !part_key.starts_with(&format!("{upload_id}/")));
            let bucket = path.split('/').next().unwrap_or_default();
            let key = path.strip_prefix(&format!("{bucket}/")).unwrap_or_default();
            let xml = format!(
                "<CompleteMultipartUploadResult><Location>/{path}</Location><Bucket>{bucket}</Bucket><Key>{key}</Key><ETag>\"mock-etag\"</ETag></CompleteMultipartUploadResult>"
            );
            axum::response::Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Method::GET => {
            let objects = state.objects.lock().await;
            match objects.get(&key) {
                Some(bytes) => axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_LENGTH, bytes.len().to_string())
                    .body(Body::from(bytes.clone()))
                    .unwrap(),
                None => axum::response::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap(),
            }
        }
        Method::HEAD => {
            let objects = state.objects.lock().await;
            match objects.get(&key) {
                Some(bytes) => {
                    let mut response = axum::response::Response::builder()
                        .status(StatusCode::OK)
                        .header(header::ETAG, "\"mock-etag\"");
                    if !state.omit_destination_head_length.load(Ordering::Acquire) {
                        response = response.header(header::CONTENT_LENGTH, bytes.len().to_string());
                    }
                    response.body(Body::new(UnknownSizeEmptyBody)).unwrap()
                }
                None => axum::response::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap(),
            }
        }
        Method::DELETE => {
            if !path.starts_with(&format!("{MOCK_STAGING_BUCKET}/"))
                && state.fail_destination_delete.load(Ordering::Acquire)
            {
                return axum::response::Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap();
            }
            state.objects.lock().await.remove(&key);
            axum::response::Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap()
        }
        _ => axum::response::Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::empty())
            .unwrap(),
    }
}

async fn upload_part(
    app: &axum::Router,
    hdrs: &[(&'static str, String)],
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    body: &[u8],
) -> String {
    let req = add_headers(
        Request::builder()
            .method("PUT")
            .uri(format!(
                "/{bucket}/{key}?partNumber={part_number}&uploadId={upload_id}"
            ))
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CONTENT_LENGTH, body.len().to_string())
            .body(Body::from(body.to_vec()))
            .unwrap(),
        hdrs,
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "UploadPart {part_number}");
    resp.headers()
        .get(header::ETAG)
        .expect("UploadPart ETag")
        .to_str()
        .unwrap()
        .to_string()
}

async fn state_assertions_for_unknown_head_and_ambiguous_delete(
    app: &axum::Router,
    headers: &[(&'static str, String)],
    bucket: &str,
    key: &str,
    mock_state: &MockS3State,
    control: &MultipartBillingControl,
) {
    let releases_before = control.releases.lock().unwrap().len();
    mock_state
        .omit_destination_head_length
        .store(true, Ordering::Release);
    let head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri(format!("/{bucket}/{key}"))
            .body(Body::empty())
            .unwrap(),
        headers,
    );
    let response = app.clone().oneshot(head).await.unwrap();
    mock_state
        .omit_destination_head_length
        .store(false, Ordering::Release);
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let head_operation = control
        .authorizations
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .1
        .operation_id();
    assert_eq!(control.releases.lock().unwrap().len(), releases_before + 1);
    assert_eq!(
        control.releases.lock().unwrap().last().unwrap().1,
        head_operation
    );

    mock_state
        .fail_destination_delete
        .store(true, Ordering::Release);
    let delete = add_headers(
        Request::builder()
            .method("DELETE")
            .uri(format!("/{bucket}/{key}"))
            .body(Body::empty())
            .unwrap(),
        headers,
    );
    let response = app.clone().oneshot(delete).await.unwrap();
    mock_state
        .fail_destination_delete
        .store(false, Ordering::Release);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let delete_authorization = control
        .authorizations
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .1
        .clone();
    assert_eq!(delete_authorization.route(), UsageRoute::DeleteObject);
    assert_eq!(control.releases.lock().unwrap().len(), releases_before + 1);
    assert!(
        control
            .releases
            .lock()
            .unwrap()
            .iter()
            .all(|(_, operation_id)| *operation_id != delete_authorization.operation_id())
    );
}

mod journal;
mod keys;
mod managed;
mod migrations;
mod multipart;
