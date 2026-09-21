//! In-crate tests for the gateway `server` module, split by area.
//!
//! Each submodule covers one concern; shared fixtures live here.

//! In-crate tests for the gateway `server` module.
//!
//! Relocated from `server.rs`; kept inside the `server` module so private
//! items remain reachable via `super`.

pub(crate) use std::convert::Infallible;

pub(crate) use std::pin::Pin;

pub(crate) use std::sync::Arc;

pub(crate) use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub(crate) use std::task::{Context, Poll};

pub(crate) use axum::body::Body;

pub(crate) use bytes::Bytes;

pub(crate) use http_body::{Frame, SizeHint};

use super::*;

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

mod admin;
mod auth;
mod lifecycle;
mod multipart;
mod s3;
