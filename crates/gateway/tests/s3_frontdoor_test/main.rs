//! S3 front door integration tests: filter roundtrip, listing, bucket
//! rejection, multipart, and SigV4 verification.
//!
//! These build the real gateway state (in-memory keystore + MemoryStore) via
//! `build_state`, so the Wasm filter component must exist first
//! (`just build-plugins`).

use axum::Router;

use axum::body::Body;

use axum::http::{Request, StatusCode, header};

use bytes::Bytes;

use http_body::{Frame, SizeHint};

use http_body_util::BodyExt as _;

use maskura_customer_config::Config;

use maskura_customer_config::config::{
    StreamingReadMode as ConfigStreamingReadMode, StreamingS3Provider,
};

use maskura_gateway::Gateway;

use maskura_gateway::backend::{
    AddressResolver, PresignedHttpPolicy, TokioAddressResolver, WorkspaceEndpointPolicy,
};

use maskura_gateway::control::{
    AuthenticatedRequestContext, AuthorizationDecision, AuthorizationError, AuthorizationGrant,
    BlockReason, ControlPlane, MeteringError, NoopControlPlane, RequestKind, UsageAuthorization,
    UsageEvent, UsageRoute,
};

use maskura_gateway::file_store::FileStore;

use maskura_gateway::key_cipher::{KeyWrapping, LocalKeyWrapping, SecretCipher, default_wrapping};

use maskura_gateway::mcp::{
    DeleteObjectRequest, GetObjectRequest, ListObjectsRequest, PutObjectRequest, ToolRequest,
    ToolResult,
};

use maskura_gateway::object::BodyLimits;

use maskura_gateway::pipeline::{
    ComponentSource, PipelineDirection, PipelineResolution, PipelineResolver,
    StaticPipelineResolver,
};

use maskura_gateway::plugin_registry::{PipelineLimits, PluginRegistry};

use maskura_gateway::server::{
    AppState, InvocationError, InvocationLimits, StatePipelineTemplate, StreamingReadMode,
    TrustedInvocationContext, build_router, build_state_with_pipeline_template, invoke_mcp,
};

use maskura_gateway::sigv4::SigV4Policy;

use maskura_gateway::store::{
    FileKeyStore, KeyRepository, KeyStore, MAX_CREDENTIAL_LABEL_BYTES, MAX_CREDENTIAL_TTL_SECONDS,
    MAX_PUBLIC_KEY_PEM_BYTES, PostgresKeyStore,
};

use maskura_gateway::transaction::{
    BackendCapabilities, CompletionReconciliation, ConditionalReadCapability,
    InMemoryOperationJournal, IncompleteUploadDiscovery, ListCapability,
    MultipartResponseCapability, OperationJournal, ResponseChecksumCapability, SpoolQuota,
    VersioningCapability,
};

use maskura_gateway::workspace_storage::{
    BackendConfigRequest, BackendConfigResponse, BackendConfigVersionId, CapabilityAttestationId,
    InMemoryWorkspaceStorageRepository, RuntimeBackendConfig, S3CapabilityAttestation,
    S3ProviderFamily, S3StreamingPermissions, WorkspaceId, WorkspaceStorageError,
    WorkspaceStorageRepository, WorkspaceStorageResolution, WorkspaceStreamingBackendIdentity,
};

use std::collections::VecDeque;

use std::convert::Infallible;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use std::pin::Pin;

use std::process::Stdio;

use std::sync::atomic::{AtomicUsize, Ordering};

use std::sync::{Arc, Mutex, OnceLock};

use std::task::{Context, Poll};

use std::time::Duration;

use tokio::io::AsyncWriteExt as _;

use tokio::process::Command;

use tower::ServiceExt;

const TEST_PUBLIC_KEY_PEM: &str =
    include_str!("../../../../tests/fixtures/pii/crypto/hybrid-public.pem");

const TEST_PUBLIC_KEY_2_PEM: &str =
    include_str!("../../../../tests/fixtures/pii/crypto/hybrid-public-2.pem");

const TEST_RATE_VERSION: i32 = 7;

fn test_occurred_at() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-08-31T12:34:56.123456Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
}

fn test_authorization_grant(authorization: &UsageAuthorization) -> AuthorizationGrant {
    AuthorizationGrant::new(authorization, test_occurred_at(), TEST_RATE_VERSION)
}

struct PollTrackingBody {
    polls: Arc<AtomicUsize>,
    data: Option<Bytes>,
}

struct FrameSequenceBody {
    frames: VecDeque<Result<Frame<Bytes>, std::io::Error>>,
}

struct ChannelBody {
    receiver: tokio::sync::mpsc::Receiver<Bytes>,
}

struct FixedPublicResolver;

#[async_trait::async_trait]
impl AddressResolver for FixedPublicResolver {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            port,
        )])
    }
}

struct RejectingAttestedRepository;

#[async_trait::async_trait]
impl WorkspaceStorageRepository for RejectingAttestedRepository {
    async fn resolve_workspace(&self, user_id: &str) -> Result<WorkspaceId, WorkspaceStorageError> {
        WorkspaceId::new(user_id)
    }

    async fn get_runtime_config(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<RuntimeBackendConfig>, WorkspaceStorageError> {
        Ok(self.get_runtime_resolution(workspace_id).await?.config)
    }

    async fn get_runtime_resolution(
        &self,
        _workspace_id: &WorkspaceId,
    ) -> Result<WorkspaceStorageResolution, WorkspaceStorageError> {
        Ok(WorkspaceStorageResolution::persisted_attested(
            RuntimeBackendConfig::S3Compatible {
                endpoint: "https://s3.us-east-1.amazonaws.com".to_string(),
                access_key: "access".to_string(),
                secret_key: "secret".to_string(),
                region: "us-east-1".to_string(),
            },
            7,
            WorkspaceStreamingBackendIdentity {
                config_version: BackendConfigVersionId::new("config-v1").unwrap(),
                attestation: S3CapabilityAttestation {
                    id: CapabilityAttestationId::new("attestation-v1").unwrap(),
                    provider: S3ProviderFamily::Aws,
                    capabilities: BackendCapabilities {
                        incomplete_upload_discovery:
                            IncompleteUploadDiscovery::ExactKeyAndStartTime,
                        abort_incomplete_upload: true,
                        cleanup_sla: Some(Duration::from_secs(60)),
                        lifecycle_rule: false,
                        versioning: VersioningCapability::Optional,
                        conditional_reads: ConditionalReadCapability::Etag,
                        response_checksums: ResponseChecksumCapability::Unsupported,
                        list_operations: ListCapability::V1AndV2,
                        multipart_responses: MultipartResponseCapability::Standard,
                        completion_reconciliation:
                            CompletionReconciliation::HeadWithOperationIdentity,
                    },
                    permissions: S3StreamingPermissions {
                        put_object: true,
                        create_multipart_upload: true,
                        upload_part: true,
                        complete_multipart_upload: true,
                        abort_multipart_upload: true,
                        list_multipart_uploads: true,
                        list_parts: true,
                        head_object: true,
                        read_operation_metadata: true,
                        list_object_versions: false,
                        delete_object_version: false,
                    },
                    exact_version_recovery: false,
                },
            },
        ))
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

impl FrameSequenceBody {
    fn data(frames: impl IntoIterator<Item = Bytes>) -> Self {
        Self {
            frames: frames
                .into_iter()
                .map(|frame| Ok(Frame::data(frame)))
                .collect(),
        }
    }
}

impl http_body::Body for FrameSequenceBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.frames.pop_front())
    }
}

impl http_body::Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.receiver
            .poll_recv(cx)
            .map(|value| value.map(|bytes| Ok(Frame::data(bytes))))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecordedUsage {
    context: AuthenticatedRequestContext,
    event: UsageEvent,
}

#[derive(Debug, Default)]
struct RecordingMeteringControl {
    events: Mutex<Vec<RecordedUsage>>,
    attempts: Mutex<Vec<maskura_gateway::control::PipelineAttempt>>,
    authorizations: Mutex<Vec<(AuthenticatedRequestContext, UsageAuthorization)>>,
    releases: Mutex<Vec<(AuthenticatedRequestContext, uuid::Uuid)>>,
    authorization_failure: Option<AuthorizationError>,
    block_reason: Option<BlockReason>,
    failure: Option<MeteringError>,
}

#[derive(Debug, Default)]
struct BlockingSettlementControl {
    record_started: tokio::sync::Notify,
    finish_record: tokio::sync::Notify,
    events: Mutex<Vec<UsageEvent>>,
    releases: AtomicUsize,
}

#[async_trait::async_trait]
impl ControlPlane for BlockingSettlementControl {
    async fn authorize(
        &self,
        _context: &AuthenticatedRequestContext,
        authorization: &UsageAuthorization,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        Ok(AuthorizationDecision::Granted(test_authorization_grant(
            authorization,
        )))
    }

    async fn release(
        &self,
        _context: &AuthenticatedRequestContext,
        _operation_id: uuid::Uuid,
    ) -> Result<(), AuthorizationError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn record(
        &self,
        _context: &AuthenticatedRequestContext,
        event: &UsageEvent,
    ) -> Result<(), MeteringError> {
        self.events.lock().unwrap().push(event.clone());
        self.record_started.notify_one();
        self.finish_record.notified().await;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct PipelineAttemptControl {
    resolved: Arc<std::sync::atomic::AtomicBool>,
    authorizations: AtomicUsize,
    releases: AtomicUsize,
    usage: AtomicUsize,
    attempts: Mutex<Vec<maskura_gateway::control::PipelineAttempt>>,
}

#[async_trait::async_trait]
impl ControlPlane for PipelineAttemptControl {
    async fn authorize(
        &self,
        _context: &AuthenticatedRequestContext,
        authorization: &UsageAuthorization,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        assert!(
            self.resolved.load(Ordering::Acquire),
            "pipeline resolution must precede authorization"
        );
        self.authorizations.fetch_add(1, Ordering::Relaxed);
        Ok(AuthorizationDecision::Granted(test_authorization_grant(
            authorization,
        )))
    }

    async fn release(
        &self,
        _context: &AuthenticatedRequestContext,
        _operation_id: uuid::Uuid,
    ) -> Result<(), AuthorizationError> {
        self.releases.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn record(
        &self,
        _context: &AuthenticatedRequestContext,
        _event: &UsageEvent,
    ) -> Result<(), MeteringError> {
        self.usage.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn record_pipeline_attempt(
        &self,
        _context: &AuthenticatedRequestContext,
        attempt: &maskura_gateway::control::PipelineAttempt,
    ) -> Result<(), MeteringError> {
        self.attempts.lock().unwrap().push(attempt.clone());
        Ok(())
    }
}

struct TestPipelineResolver {
    resolution: PipelineResolution,
    calls: Mutex<Vec<(String, String, PipelineDirection)>>,
    resolved: Arc<std::sync::atomic::AtomicBool>,
    failure_code: Option<&'static str>,
}

#[async_trait::async_trait]
impl PipelineResolver for TestPipelineResolver {
    async fn resolve(
        &self,
        workspace_id: &str,
        bucket: &str,
        direction: PipelineDirection,
    ) -> Result<PipelineResolution, maskura_error::MaskuraError> {
        self.calls
            .lock()
            .unwrap()
            .push((workspace_id.to_string(), bucket.to_string(), direction));
        self.resolved.store(true, Ordering::Release);
        if let Some(code) = self.failure_code {
            return Err(maskura_error::MaskuraError::new(
                code,
                "private resolver detail",
            ));
        }
        let mut resolution = self.resolution.clone();
        resolution.locator.fingerprint = maskura_gateway::pipeline::resolution_fingerprint(
            direction,
            &resolution.steps,
            resolution.explicit_passthrough,
            resolution.limits,
        );
        Ok(resolution)
    }
}

struct CorruptComponentSource;

#[async_trait::async_trait]
impl ComponentSource for CorruptComponentSource {
    async fn load(&self, _component_hash: &str) -> Result<Bytes, maskura_error::MaskuraError> {
        Ok(Bytes::from_static(b"corrupt artifact bytes"))
    }
}

struct FixedComponentSource(Bytes);

#[async_trait::async_trait]
impl ComponentSource for FixedComponentSource {
    async fn load(&self, _component_hash: &str) -> Result<Bytes, maskura_error::MaskuraError> {
        Ok(self.0.clone())
    }
}

struct SwitchingResolver {
    current: Mutex<PipelineResolution>,
    first_resolved: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

#[async_trait::async_trait]
impl PipelineResolver for SwitchingResolver {
    async fn resolve(
        &self,
        _workspace_id: &str,
        _bucket: &str,
        direction: PipelineDirection,
    ) -> Result<PipelineResolution, maskura_error::MaskuraError> {
        let mut resolution = self.current.lock().unwrap().clone();
        resolution.locator.fingerprint = maskura_gateway::pipeline::resolution_fingerprint(
            direction,
            &resolution.steps,
            resolution.explicit_passthrough,
            resolution.limits,
        );
        if let Some(sender) = self.first_resolved.lock().unwrap().take() {
            let _ = sender.send(());
        }
        Ok(resolution)
    }
}

#[async_trait::async_trait]
impl ControlPlane for RecordingMeteringControl {
    async fn authorize(
        &self,
        context: &AuthenticatedRequestContext,
        authorization: &UsageAuthorization,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        self.authorizations
            .lock()
            .unwrap()
            .push((context.clone(), authorization.clone()));
        if let Some(error) = self.authorization_failure {
            return Err(error);
        }
        if let Some(reason) = self.block_reason.clone() {
            return Ok(AuthorizationDecision::Blocked(reason));
        }
        Ok(AuthorizationDecision::Granted(test_authorization_grant(
            authorization,
        )))
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
        self.events.lock().unwrap().push(RecordedUsage {
            context: context.clone(),
            event: event.clone(),
        });
        self.failure.map_or(Ok(()), Err)
    }

    async fn record_pipeline_attempt(
        &self,
        _context: &AuthenticatedRequestContext,
        attempt: &maskura_gateway::control::PipelineAttempt,
    ) -> Result<(), MeteringError> {
        self.attempts.lock().unwrap().push(attempt.clone());
        Ok(())
    }
}

#[derive(Debug)]
struct RetryMeteringControl {
    failures_remaining: AtomicUsize,
    calls: Mutex<Vec<UsageEvent>>,
    releases: AtomicUsize,
}

#[async_trait::async_trait]
impl ControlPlane for RetryMeteringControl {
    async fn authorize(
        &self,
        _context: &AuthenticatedRequestContext,
        authorization: &UsageAuthorization,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        Ok(AuthorizationDecision::Granted(test_authorization_grant(
            authorization,
        )))
    }

    async fn release(
        &self,
        _context: &AuthenticatedRequestContext,
        _operation_id: uuid::Uuid,
    ) -> Result<(), AuthorizationError> {
        self.releases.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    async fn record(
        &self,
        _context: &AuthenticatedRequestContext,
        event: &UsageEvent,
    ) -> Result<(), MeteringError> {
        self.calls.lock().unwrap().push(event.clone());
        self.failures_remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .map_or(Ok(()), |_| Err(MeteringError::Unavailable))
    }
}

#[derive(Debug, Default)]
struct StaleGrantControl {
    previous: Mutex<Option<UsageAuthorization>>,
}

#[async_trait::async_trait]
impl ControlPlane for StaleGrantControl {
    async fn authorize(
        &self,
        _context: &AuthenticatedRequestContext,
        authorization: &UsageAuthorization,
    ) -> Result<AuthorizationDecision, AuthorizationError> {
        let previous = self.previous.lock().unwrap().replace(authorization.clone());
        Ok(AuthorizationDecision::Granted(test_authorization_grant(
            previous.as_ref().unwrap_or(authorization),
        )))
    }

    async fn release(
        &self,
        _context: &AuthenticatedRequestContext,
        _operation_id: uuid::Uuid,
    ) -> Result<(), AuthorizationError> {
        Ok(())
    }

    async fn record(
        &self,
        _context: &AuthenticatedRequestContext,
        _event: &UsageEvent,
    ) -> Result<(), MeteringError> {
        Ok(())
    }
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

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.data.as_ref().map_or(0, Bytes::len) as u64)
    }
}

fn test_pipeline_template() -> &'static StatePipelineTemplate {
    static PIPELINES: OnceLock<StatePipelineTemplate> = OnceLock::new();
    PIPELINES.get_or_init(|| {
        // SAFETY: the process-wide fixture initializes the environment once,
        // before any test state reads it.
        unsafe {
            std::env::set_var("AUTH_DISABLED", "0");
            std::env::set_var("MASKURA_SINGLE_TENANT", "1");
            std::env::set_var("MASKURA_WORKSPACE_ENDPOINT_PRIVATE_ALLOWLIST", "127.0.0.1");
            std::env::remove_var("MASKURA_WORKSPACE_ENDPOINT_ALLOWLIST");
            std::env::remove_var("DATABASE_URL");
            std::env::remove_var("MASKURA_KEYS_FILE");
            std::env::remove_var("S3_ENDPOINT");
            std::env::remove_var("MASKURA_SECRET_KEK");
            std::env::remove_var("MASKURA_SERVICE_BUCKETS");
            std::env::remove_var("MASKURA_LEGACY_MAX_OBJECT_BYTES");
            std::env::remove_var("MASKURA_MAX_OBJECT_BYTES");
            std::env::remove_var("MASKURA_MAX_PIPELINE_OUTPUT_BYTES");
            std::env::remove_var("MASKURA_STREAMING_READ_MODE");
            std::env::remove_var("MASKURA_TRANSFORMED_READ_SPOOL");
            std::env::remove_var("MASKURA_PREFIX_SAFE_COMPONENT_HASHES");
            std::env::remove_var("MASKURA_SPOOL_DIR");
            std::env::remove_var("MASKURA_SPOOL_MAX_OBJECT_BYTES");
            std::env::remove_var("MASKURA_SPOOL_QUOTA_BYTES");
            std::env::remove_var("MASKURA_STREAMING_S3_PROVIDER");
            std::env::remove_var("MASKURA_MANAGED_STREAMING_MODE");
            std::env::remove_var("MASKURA_MANAGED_STREAMING_TRANSACTIONAL");
            std::env::remove_var("MASKURA_MANAGED_PLACEMENT_VERSION");
            std::env::remove_var("MASKURA_DEV_MEMORY_STREAMING");
            std::env::remove_var("MASKURA_MULTIPART_MODE");
            // Phase 12 removed the legacy buffered PUT/GET path entirely; the
            // streaming in-memory dev backend is the only write/read path left.
            std::env::set_var("MASKURA_STREAMING_READ_MODE", "passthrough");
            std::env::set_var("MASKURA_DEV_MEMORY_STREAMING", "1");
            // Load the built filter components so the full pipeline (including
            // stable-encrypt) is available for joinable-read tests.
            let components =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/components");
            std::env::set_var("MASKURA_PLUGINS_DIR", components);
        }
        let config = Config::resolve(None).expect("resolve pipeline config");
        StatePipelineTemplate::from_config(&config).expect("compile test pipeline components")
    })
}

fn test_config() -> Config {
    let _ = test_pipeline_template();
    Config::resolve(None).expect("resolve test config")
}

async fn test_state() -> Arc<AppState> {
    let config = test_config();
    build_state_with_pipeline_template(
        Arc::new(NoopControlPlane),
        default_wrapping().expect("wrapping"),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        test_pipeline_template(),
        &config,
    )
    .await
    .expect("build_state")
}

async fn trusted_context(state: &Arc<AppState>, workspace_id: &str) -> TrustedInvocationContext {
    let (token, _) = state
        .keys
        .create_mcp_token(
            "hosted-user",
            &WorkspaceId::new(workspace_id).unwrap(),
            "test-hosted-mcp",
            0,
        )
        .await
        .unwrap();
    TrustedInvocationContext::new(state.keys.resolve_mcp_token(&token).await.unwrap().unwrap())
}

async fn router() -> (Router, Arc<AppState>) {
    let state = test_state().await;
    (build_router(state.clone()), state)
}

fn unavailable_key_store() -> Arc<dyn KeyRepository> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(25))
        .connect_lazy("postgresql://postgres:postgres@127.0.0.1:1/maskura")
        .unwrap();
    Arc::new(PostgresKeyStore::new(pool))
}

#[derive(Debug)]
struct FailingUnwrapWrapping(LocalKeyWrapping);

impl KeyWrapping for FailingUnwrapWrapping {
    fn wrap(&self, dek: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.0.wrap(dek)
    }

    fn unwrap(&self, _wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
        Err(anyhow::anyhow!("wrapping provider unavailable"))
    }
}

async fn make_key(state: &Arc<AppState>) -> (String, String) {
    make_key_for(state, "test-user").await
}

async fn make_key_for(state: &Arc<AppState>, user_id: &str) -> (String, String) {
    let (secret, created) = state
        .keys
        .create_key(
            user_id,
            &WorkspaceId::new(user_id).unwrap(),
            "sigv4-test",
            0,
            None,
        )
        .await
        .expect("create test API key");
    (created.key_id, secret)
}

fn configure_dashboard_jwt(state: &mut Arc<AppState>, user_id: &str) -> String {
    let secret = b"public-key-dashboard-secret";
    let issuer = "https://example.supabase.co/auth/v1";
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &serde_json::json!({
            "sub": user_id,
            "iss": issuer,
            "aud": "authenticated",
            "exp": u64::MAX,
        }),
        &jsonwebtoken::EncodingKey::from_secret(secret),
    )
    .unwrap();
    let state_mut = Arc::get_mut(state).expect("test state is uniquely owned");
    state_mut.supabase_url = "https://example.supabase.co".to_string();
    state_mut.jwt_decoder = Some(Arc::new(jsonwebtoken::DecodingKey::from_secret(secret)));
    token
}

fn public_key_request(key_id: &str, public_key_pem: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri("/dashboard/api/keys/public-key")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "key_id": key_id,
                "public_key_pem": public_key_pem,
            })
            .to_string(),
        ))
        .unwrap()
}

fn test_transformer_component() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test-components/test-transformer.component.wasm");
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{}: run `just build-plugins` first: {error}",
            path.display()
        )
    })
}

async fn unsafe_transformed_test_state(later_filter: bool) -> Arc<AppState> {
    let mut state = test_state().await;
    let spool_dir = std::env::temp_dir().join(format!(
        "maskura-read-spool-failure-{}",
        uuid::Uuid::now_v7()
    ));
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Transformed;
    state_mut.transformed_read_spool_enabled = true;
    state_mut.spool_config.directory = spool_dir;
    state_mut.spool_config.max_object_bytes = 1024;
    state_mut.spool_quota = Arc::new(SpoolQuota::new(2048));
    for plugin in state.plugins.list() {
        state.plugins.set_enabled(&plugin.id, false);
    }
    if later_filter {
        state
            .plugins
            .import(
                "test-noop-before-reject",
                &read_component("noop.component.wasm"),
            )
            .unwrap();
    }
    state
        .plugins
        .import("test-failure", &test_transformer_component())
        .unwrap();
    state
}

async fn direct_passthrough_test_state(control: Arc<dyn ControlPlane>) -> Arc<AppState> {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Transformed;
    state_mut.transformed_read_spool_enabled = false;
    state_mut.control = control;
    for plugin in state_mut.plugins.list() {
        state_mut.plugins.set_enabled(&plugin.id, false);
    }
    state_mut.store.put(
        "direct",
        "records.txt",
        Bytes::from_static(b"first\nsecond\n"),
        "text/plain",
    );
    state_mut
        .store
        .put("direct", "empty.txt", Bytes::new(), "text/plain");
    state
}

fn read_component(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/components")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{}: run `just build-plugins` first: {error}",
            path.display()
        )
    })
}

fn auth_headers(ak: &str, sk: &str) -> Vec<(&'static str, String)> {
    vec![
        ("x-maskura-access-key", ak.to_string()),
        ("x-maskura-secret-key", sk.to_string()),
    ]
}

fn add_headers(req: Request<Body>, hdrs: &[(&'static str, String)]) -> Request<Body> {
    let (mut parts, body) = req.into_parts();
    for (k, v) in hdrs {
        parts.headers.insert(*k, v.parse().unwrap());
    }
    Request::from_parts(parts, body)
}

async fn collect_data_frames(mut body: Body) -> Result<(Bytes, Vec<usize>), axum::Error> {
    let mut data = Vec::new();
    let mut frame_lengths = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Ok(frame) = frame.into_data() {
            frame_lengths.push(frame.len());
            data.extend_from_slice(&frame);
        }
    }
    Ok((Bytes::from(data), frame_lengths))
}

fn append_headers(req: Request<Body>, hdrs: &[(&'static str, String)]) -> Request<Body> {
    let (mut parts, body) = req.into_parts();
    for (name, value) in hdrs {
        parts.headers.append(*name, value.parse().unwrap());
    }
    Request::from_parts(parts, body)
}

fn assert_hardened_object_headers(headers: &axum::http::HeaderMap) {
    assert_eq!(headers[header::CACHE_CONTROL], "private, no-store");
    assert!(!headers.contains_key(header::AGE));
    assert!(!headers.contains_key(header::EXPIRES));
    assert_eq!(headers[header::CONTENT_DISPOSITION], "attachment");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(
        headers["content-security-policy"],
        "sandbox; default-src 'none'; base-uri 'none'; form-action 'none'"
    );
}

fn assert_s3_error_has_only_expected_xml_elements(document: &str) {
    let elements: Vec<_> = xmlparser::Tokenizer::from(document)
        .map(|token| token.expect("generated error must be well-formed XML"))
        .filter_map(|token| match token {
            xmlparser::Token::ElementStart { local, .. } => Some(local.as_str().to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(elements, ["Error", "Code", "Message", "Key", "RequestId"]);
}

async fn spawn_presigned_upstream() -> (String, tokio::task::JoinHandle<()>) {
    async fn object(
        method: axum::http::Method,
        headers: axum::http::HeaderMap,
    ) -> axum::response::Response {
        let range = headers
            .get(header::RANGE)
            .and_then(|value| value.to_str().ok());
        let (status, body, content_range) = if range == Some("bytes=2-5") {
            (StatusCode::PARTIAL_CONTENT, "2345", Some("bytes 2-5/10"))
        } else {
            (StatusCode::OK, "0123456789", None)
        };
        let mut response = axum::response::Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CONTENT_ENCODING, "identity")
            .header(
                header::CONTENT_DISPOSITION,
                "inline; filename=attacker-controlled.html",
            )
            .header("content-security-policy", "default-src * 'unsafe-inline'")
            .header("x-content-type-options", "off")
            .header(header::CONTENT_LANGUAGE, "en")
            .header(header::CACHE_CONTROL, "public, max-age=3600")
            .header(header::AGE, "600")
            .header(header::EXPIRES, "Wed, 19 Aug 2026 10:00:00 GMT")
            .header(header::ETAG, "\"upstream-etag\"")
            .header(header::LAST_MODIFIED, "Wed, 19 Aug 2026 09:00:00 GMT")
            .header("x-amz-checksum-sha256", "checksum")
            .header("x-amz-meta-project", "safe-metadata")
            .header("x-amz-version-id", "version-7")
            .header("x-goog-component-count", "2")
            .header("x-goog-custom-time", "2026-08-19T09:00:00Z")
            .header("x-goog-encryption-algorithm", "AES256")
            .header("x-goog-encryption-key-sha256", "key-checksum")
            .header("x-goog-expiration", "Wed, 19 Aug 2026 10:00:00 GMT")
            .header("x-goog-generation", "123456")
            .header("x-goog-hash", "crc32c=abcd")
            .header("x-goog-meta-project", "safe-gcs-metadata")
            .header("x-goog-metageneration", "9")
            .header("x-goog-object-lock-mode", "GOVERNANCE")
            .header(
                "x-goog-object-lock-retain-until-date",
                "2027-08-19T09:00:00Z",
            )
            .header("x-goog-storage-class", "STANDARD")
            .header("x-goog-stored-content-encoding", "identity")
            .header("x-goog-stored-content-length", "10")
            .header(header::SET_COOKIE, "session=attacker; Secure")
            .header("access-control-allow-origin", "https://attacker.example")
            .header(header::LOCATION, "https://attacker.example/redirect")
            .header("refresh", "0;url=https://attacker.example/redirect")
            .header("report-to", r#"{"group":"attacker"}"#)
            .header(
                "reporting-endpoints",
                "attacker=\"https://attacker.example\"",
            )
            .header(header::WWW_AUTHENTICATE, "Basic realm=attacker")
            .header("authentication-info", "nextnonce=attacker")
            .header("connection", "x-upstream-private")
            .header("x-upstream-private", "remove-me")
            .header(header::ACCEPT_RANGES, "bytes");
        if let Some(checksum_mode) = headers.get("x-amz-checksum-mode") {
            response = response.header("x-amz-meta-request-checksum-mode", checksum_mode.clone());
        }
        if let Some(content_range) = content_range {
            response = response.header(header::CONTENT_RANGE, content_range);
        }
        if method == axum::http::Method::HEAD {
            response = response.header(header::CONTENT_LENGTH, "10");
            response.body(Body::empty()).unwrap()
        } else {
            response = response.header(header::CONTENT_LENGTH, body.len().to_string());
            response.body(Body::from(body)).unwrap()
        }
    }

    async fn redirect() -> axum::response::Response {
        axum::response::Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/object")
            .body(Body::empty())
            .unwrap()
    }

    async fn html_error() -> axum::response::Response {
        axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_TYPE, "text/html")
            .header(header::CONTENT_DISPOSITION, "inline; filename=error.html")
            .header(header::CACHE_CONTROL, "public, max-age=3600")
            .header(header::AGE, "600")
            .header(header::EXPIRES, "Wed, 19 Aug 2026 10:00:00 GMT")
            .header("content-security-policy", "default-src * 'unsafe-inline'")
            .header("x-content-type-options", "off")
            .header(header::SET_COOKIE, "error=attacker")
            .body(Body::from("<script>attack()</script>"))
            .unwrap()
    }

    let app = axum::Router::new()
        .route("/object", axum::routing::get(object).head(object))
        .route("/not-found", axum::routing::get(html_error))
        .route("/redirect", axum::routing::get(redirect));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{address}"), task)
}

fn signed_request(
    access_key: &str,
    secret: &str,
    method: &str,
    uri: &str,
    body: &[u8],
    headers: &[(&'static str, &str)],
) -> Request<Body> {
    use aws_sigv4::http_request::SignableBody;
    signed_request_with_signable(
        access_key,
        secret,
        method,
        uri,
        body,
        headers,
        SignableBody::Bytes(body),
    )
}

fn signed_request_with_signable<'a>(
    access_key: &str,
    secret: &str,
    method: &str,
    uri: &str,
    body: &'a [u8],
    headers: &[(&'static str, &str)],
    signable: aws_sigv4::http_request::SignableBody<'a>,
) -> Request<Body> {
    use aws_credential_types::Credentials;
    use aws_sigv4::http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableRequest, SigningParams, SigningSettings,
        UriPathNormalizationMode, sign,
    };
    use aws_sigv4::sign::v4;
    use std::time::SystemTime;

    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

    let identity: aws_smithy_runtime_api::client::identity::Identity =
        Credentials::new(access_key, secret, None, None, "test").into();
    let params: SigningParams = v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name("s3")
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .unwrap()
        .into();

    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body.to_vec()))
        .unwrap();
    for &(name, value) in headers {
        req.headers_mut().append(name, value.parse().unwrap());
    }
    let signable = SignableRequest::new(
        method,
        uri,
        req.headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap())),
        signable,
    )
    .unwrap();
    let instructions = sign(signable, &params).unwrap().into_parts().0;
    instructions.apply_to_request_http1x(&mut req);
    // The signer covered `host`; the outgoing request must carry it too.
    let authority = req
        .uri()
        .authority()
        .expect("absolute uri")
        .as_str()
        .to_string();
    req.headers_mut().insert("host", authority.parse().unwrap());
    req
}

fn presigned_request(
    access_key: &str,
    secret: &str,
    method: &str,
    uri: &str,
    headers: &[(&'static str, &str)],
) -> Request<Body> {
    use aws_credential_types::Credentials;
    use aws_sigv4::http_request::{
        PercentEncodingMode, SignableBody, SignableRequest, SignatureLocation, SigningParams,
        SigningSettings, UriPathNormalizationMode, sign,
    };
    use aws_sigv4::sign::v4;
    use std::time::SystemTime;

    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.signature_location = SignatureLocation::QueryParams;
    settings.expires_in = Some(Duration::from_secs(300));

    let identity: aws_smithy_runtime_api::client::identity::Identity =
        Credentials::new(access_key, secret, None, None, "test").into();
    let params: SigningParams = v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name("s3")
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .unwrap()
        .into();

    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    for &(name, value) in headers {
        req.headers_mut().append(name, value.parse().unwrap());
    }
    let signable = SignableRequest::new(
        method,
        uri,
        req.headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap())),
        SignableBody::UnsignedPayload,
    )
    .unwrap();
    let instructions = sign(signable, &params).unwrap().into_parts().0;
    instructions.apply_to_request_http1x(&mut req);
    let authority = req
        .uri()
        .authority()
        .expect("absolute uri")
        .as_str()
        .to_string();
    req.headers_mut().insert("host", authority.parse().unwrap());
    req
}

async fn post_demo_process(app: &Router, body: serde_json::Value) -> axum::response::Response {
    post_demo_process_body(app, Body::from(body.to_string())).await
}

async fn post_demo_process_body(app: &Router, body: Body) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/api/demo/process")
                .header(header::CONTENT_TYPE, "application/json")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap()
}

fn assert_demo_security_headers(response: &axum::response::Response) {
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "private, no-store"
    );
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
}

fn assert_demo_response_headers(response: &axum::response::Response) {
    assert_demo_security_headers(response);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
}

async fn demo_response_json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()
}

mod auth;
mod demo;
mod managed;
mod mcp;
mod metering;
mod misc;
mod multipart;
mod objects;
mod pipeline;
mod sigv4;
mod streaming;
