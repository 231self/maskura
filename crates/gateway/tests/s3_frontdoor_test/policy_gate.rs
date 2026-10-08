//! Policy-gate coverage matrix (policy-approval Slice 3).
//!
//! Every `PolicyOperation` variant must be presented to the configured
//! [`PolicyGate`] on its data-plane path, including hosted MCP dispatch which
//! reaches `s3_put`/`s3_get` in process. If a new handler (or operation) ships
//! without a gate call, the matrix assertion below fails.
//!
//! Deliberately out of claim (not object-data policy surface in v1):
//! `ListParts` (part listings of caller-owned uploads), `ListBuckets`, and
//! bucket create/delete admin ops. `ListMultipartUploads` is gated as
//! `PolicyOperation::List` with the requested prefix: in-progress upload
//! listings disclose key names, the same disclosure surface ListObjects
//! scopes to approved prefixes.

use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use async_trait::async_trait;
use maskura_customer_config::config::{
    MultipartMode as ConfigMultipartMode, StreamingReadMode as ConfigStreamingReadMode,
};
use maskura_error::MaskuraError;
use maskura_gateway::policy_gate::{PolicyBinding, PolicyGate, PolicyRequest, VerifiedPolicy};
use maskura_pipeline_config::{
    DestinationBinding, PolicyLimits, PolicyOperation, ResolvedDestination, StorageMode,
};

#[derive(Default)]
struct RecordingPolicyGate {
    calls: Mutex<Vec<(PolicyOperation, String, String)>>,
}

impl RecordingPolicyGate {
    fn operations(&self) -> BTreeSet<PolicyOperation> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(operation, _, _)| *operation)
            .collect()
    }

    fn count(&self, operation: PolicyOperation) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(seen, _, _)| *seen == operation)
            .count()
    }
}

#[async_trait]
impl PolicyGate for RecordingPolicyGate {
    async fn enforce(&self, request: &PolicyRequest<'_>) -> Result<VerifiedPolicy, MaskuraError> {
        self.calls.lock().unwrap().push((
            request.operation,
            request.bucket.to_string(),
            request.key.to_string(),
        ));
        Ok(VerifiedPolicy::unbound())
    }
}

/// Staged multipart and transformed reads are config-explicit features; a
/// TOML file sets the explicit flags the same way operator deployment does.
/// The feature fields are pinned after resolve because the process-wide
/// `test_pipeline_template` fixture force-sets env overrides (including
/// `MASKURA_STREAMING_READ_MODE=passthrough`) that would otherwise stomp the
/// file depending on test order.
fn coverage_config() -> (Config, std::path::PathBuf) {
    let scratch = std::env::temp_dir().join(format!(
        "maskura-policy-gate-coverage-{}",
        uuid::Uuid::now_v7()
    ));
    std::fs::create_dir_all(&scratch).expect("create coverage scratch dir");
    let path = scratch.join("config.toml");
    std::fs::write(
        &path,
        format!(
            "[features]\nmultipart_mode = \"staged\"\nstreaming_read_mode = \"transformed\"\ntransformed_read_spool = true\n[storage]\nlocal_dir = \"{}\"\nmode = \"local\"\nsingle_tenant = true\n",
            scratch.display()
        ),
    )
    .expect("write coverage config");
    let mut config = Config::resolve(Some(&path)).expect("resolve coverage config");
    config.features.multipart_mode = ConfigMultipartMode::Staged;
    config.features.streaming_read_mode = ConfigStreamingReadMode::Transformed;
    config.features.transformed_read_spool = true;
    assert_eq!(config.features.multipart_mode, ConfigMultipartMode::Staged);
    (config, scratch)
}

async fn coverage_router() -> (Router, Arc<AppState>, Arc<RecordingPolicyGate>) {
    let (config, _scratch) = coverage_config();
    let mut state = build_state_with_pipeline_template(
        Arc::new(NoopControlPlane),
        default_wrapping().expect("wrapping"),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        test_pipeline_template(),
        &config,
    )
    .await
    .expect("build_state");
    let gate = Arc::new(RecordingPolicyGate::default());
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .policy_gate = Some(gate.clone());
    (build_router(state.clone()), state, gate)
}

fn upload_id_from(body: &str) -> String {
    let start = body
        .find("<UploadId>")
        .expect("create response carries UploadId")
        + "<UploadId>".len();
    let end = body[start..].find("</UploadId>").expect("closed UploadId") + start;
    body[start..end].to_string()
}

#[tokio::test]
async fn policy_gate_covers_every_data_plane_operation() {
    let (app, state, gate) = coverage_router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let create_bucket = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bucket")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(create_bucket).await.unwrap().status(),
        StatusCode::OK
    );

    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bucket/object")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("payload"))
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(put).await.unwrap().status(),
        StatusCode::OK
    );

    let raw_get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bucket/object")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    app.clone().oneshot(raw_get).await.unwrap();

    let processed_get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bucket/object")
            .header("x-maskura-process", "read")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let processed_response = app.clone().oneshot(processed_get).await.unwrap();
    let processed_status = processed_response.status();
    let processed_body = axum::body::to_bytes(processed_response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        processed_status,
        StatusCode::OK,
        "transformed read must succeed: {}",
        String::from_utf8_lossy(&processed_body)
    );

    let head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/bucket/object")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    app.clone().oneshot(head).await.unwrap();

    let list = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bucket?prefix=data/")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    app.clone().oneshot(list).await.unwrap();

    let uploads_listing = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bucket?uploads")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    app.clone().oneshot(uploads_listing).await.unwrap();

    let create = add_headers(
        Request::builder()
            .method("POST")
            .uri("/bucket/multipart-object?uploads")
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let create_response = app.clone().oneshot(create).await.unwrap();
    let create_status = create_response.status();
    let create_body = axum::body::to_bytes(create_response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        create_status,
        StatusCode::OK,
        "staged multipart create must succeed: {}",
        String::from_utf8_lossy(&create_body)
    );
    let upload_id = upload_id_from(&String::from_utf8_lossy(&create_body));

    let part = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bucket/multipart-object?partNumber=1&uploadId=untrusted")
            .header(header::CONTENT_LENGTH, "7")
            .body(Body::from("payload"))
            .unwrap(),
        &hdrs,
    );
    app.clone().oneshot(part).await.unwrap();

    let complete = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/bucket/multipart-object?uploadId={upload_id}"))
            .header(header::CONTENT_TYPE, "application/xml")
            .body(Body::from(
                "<CompleteMultipartUpload></CompleteMultipartUpload>",
            ))
            .unwrap(),
        &hdrs,
    );
    app.clone().oneshot(complete).await.unwrap();

    let abort = add_headers(
        Request::builder()
            .method("DELETE")
            .uri("/bucket/multipart-object?uploadId=untrusted")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    app.clone().oneshot(abort).await.unwrap();

    let delete = add_headers(
        Request::builder()
            .method("DELETE")
            .uri("/bucket/object")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    app.clone().oneshot(delete).await.unwrap();

    let expected: BTreeSet<PolicyOperation> = [
        PolicyOperation::Put,
        PolicyOperation::ProcessedGet,
        PolicyOperation::RawGet,
        PolicyOperation::Head,
        PolicyOperation::List,
        PolicyOperation::Delete,
        PolicyOperation::MultipartCreate,
        PolicyOperation::MultipartUpload,
        PolicyOperation::MultipartComplete,
        PolicyOperation::MultipartAbort,
    ]
    .into_iter()
    .collect();
    assert_eq!(
        gate.operations(),
        expected,
        "every PolicyOperation must pass through the gate on its data-plane path; calls: {:?}",
        gate.calls.lock().unwrap()
    );

    // Both listing shapes present `List` with the requested prefix as the
    // gate key: the plain LIST call with `prefix=data/`, and `?uploads`
    // (key-name disclosure surface) with the empty requested prefix.
    {
        let calls = gate.calls.lock().unwrap();
        assert!(
            calls.iter().any(
                |(operation, bucket, key)| *operation == PolicyOperation::List
                    && bucket == "bucket"
                    && key == "data/"
            ),
            "the plain LIST call must present List with its prefix as the gate key; calls: {calls:?}"
        );
        assert!(
            calls.iter().any(
                |(operation, bucket, key)| *operation == PolicyOperation::List
                    && bucket == "bucket"
                    && key.is_empty()
            ),
            "ListMultipartUploads must present List with the requested prefix as the gate key; calls: {calls:?}"
        );
    }

    // Hosted MCP dispatches to the same handlers in process: it must inherit
    // enforcement rather than bypassing the seam.
    let create_trusted_bucket = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/trusted")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone()
            .oneshot(create_trusted_bucket)
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let context = trusted_context(&state, "policy-gate-ws").await;
    let puts_before = gate.count(PolicyOperation::Put);
    let result = invoke_mcp(
        state.clone(),
        context,
        uuid::Uuid::now_v7(),
        ToolRequest::PutObject(PutObjectRequest {
            bucket: "trusted".to_string(),
            key: "record.txt".to_string(),
            body: "payload".to_string(),
            content_type: "text/plain".to_string(),
        }),
        InvocationLimits::default(),
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .expect("mcp put");
    assert!(matches!(result, ToolResult::PutObject(_)));
    assert_eq!(
        gate.count(PolicyOperation::Put),
        puts_before + 1,
        "invoke_mcp must present Put to the gate"
    );
}

#[tokio::test]
async fn gate_rejection_denies_the_request_with_a_typed_policy_code() {
    struct DenyAll;

    #[async_trait]
    impl PolicyGate for DenyAll {
        async fn enforce(
            &self,
            _request: &PolicyRequest<'_>,
        ) -> Result<VerifiedPolicy, MaskuraError> {
            Err(MaskuraError::new(
                maskura_error::codes::POLICY_DENIED,
                "state mismatch",
            ))
        }
    }

    let (config, _scratch) = coverage_config();
    let mut state = build_state_with_pipeline_template(
        Arc::new(NoopControlPlane),
        default_wrapping().expect("wrapping"),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        test_pipeline_template(),
        &config,
    )
    .await
    .expect("build_state");
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .policy_gate = Some(Arc::new(DenyAll));
    let app = build_router(state.clone());
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bucket/object")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("payload"))
            .unwrap(),
        &hdrs,
    );
    let response = app.oneshot(put).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("<Code>policy.denied</Code>"),
        "policy code must be the S3 <Code>, got: {body}"
    );
}

#[tokio::test]
async fn check_use_drift_denies_the_request() {
    // A bound verdict whose frozen destination no longer matches the resolved
    // selection must be rejected at the call site (check/use discipline), not
    // silently executed against the drifted target.
    struct DriftGate;

    #[async_trait]
    impl PolicyGate for DriftGate {
        async fn enforce(
            &self,
            request: &PolicyRequest<'_>,
        ) -> Result<VerifiedPolicy, MaskuraError> {
            let destination = DestinationBinding::Concrete {
                destination: ResolvedDestination {
                    mode: StorageMode::S3Compatible,
                    endpoint: "https://drifted.example.com".into(),
                    bucket: "signed-bucket".into(),
                    region: "region-1".into(),
                    role_arn: None,
                    configuration_version_id: Some("cfg-1".into()),
                    configuration_sha256: "c".repeat(64),
                },
            };
            Ok(VerifiedPolicy {
                binding: Some(PolicyBinding {
                    workspace_id: request.workspace_id.to_string(),
                    operation: request.operation,
                    route_prefix: String::new(),
                    envelope_digest: "e".repeat(64),
                    envelope_version: 1,
                    effective_state_digest: "d".repeat(64),
                    receipt_seq: 1,
                    receipt_body_digest: "b".repeat(64),
                    authorization_epoch: 1,
                    destination,
                    managed_placement: None,
                    limits: PolicyLimits {
                        record_max_bytes: 1024,
                        object_max_bytes: 4096,
                        memory_bytes: 67_108_864,
                        fuel: 10_000_000,
                        deadline_ms: 30_000,
                    },
                }),
            })
        }
    }

    let (config, _scratch) = coverage_config();
    let mut state = build_state_with_pipeline_template(
        Arc::new(NoopControlPlane),
        default_wrapping().expect("wrapping"),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        test_pipeline_template(),
        &config,
    )
    .await
    .expect("build_state");
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .policy_gate = Some(Arc::new(DriftGate));
    let app = build_router(state.clone());
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bucket/object")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("payload"))
            .unwrap(),
        &hdrs,
    );
    let response = app.oneshot(put).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("<Code>policy.denied</Code>"),
        "check/use drift must deny with policy.denied, got: {body}"
    );
}

#[tokio::test]
async fn check_use_match_allows_the_request() {
    // A bound verdict whose frozen destination equals the resolved selection
    // must execute — the check is a drift guard, not a blanket rejection.
    struct MatchGate;

    #[async_trait]
    impl PolicyGate for MatchGate {
        async fn enforce(
            &self,
            request: &PolicyRequest<'_>,
        ) -> Result<VerifiedPolicy, MaskuraError> {
            Ok(VerifiedPolicy {
                binding: Some(PolicyBinding {
                    workspace_id: request.workspace_id.to_string(),
                    operation: request.operation,
                    route_prefix: String::new(),
                    envelope_digest: "e".repeat(64),
                    envelope_version: 1,
                    effective_state_digest: "d".repeat(64),
                    receipt_seq: 1,
                    receipt_body_digest: "b".repeat(64),
                    authorization_epoch: 1,
                    destination: request.snapshot.binding.clone(),
                    managed_placement: request.snapshot.managed_placement(),
                    limits: PolicyLimits {
                        record_max_bytes: 1024,
                        object_max_bytes: 4096,
                        memory_bytes: 67_108_864,
                        fuel: 10_000_000,
                        deadline_ms: 30_000,
                    },
                }),
            })
        }
    }

    let (config, _scratch) = coverage_config();
    let mut state = build_state_with_pipeline_template(
        Arc::new(NoopControlPlane),
        default_wrapping().expect("wrapping"),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        test_pipeline_template(),
        &config,
    )
    .await
    .expect("build_state");
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .policy_gate = Some(Arc::new(MatchGate));
    let app = build_router(state.clone());
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let create_bucket = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bucket")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(create_bucket).await.unwrap().status(),
        StatusCode::OK
    );

    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bucket/object")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("payload"))
            .unwrap(),
        &hdrs,
    );
    let response = app.oneshot(put).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a matching binding must execute, not be rejected by the drift guard"
    );
}

// --- policy session limits and frozen multipart verdicts (P4.1g / P4.1h) ---

fn roomy_limits() -> PolicyLimits {
    PolicyLimits {
        record_max_bytes: 1024,
        object_max_bytes: 4096,
        memory_bytes: 67_108_864,
        fuel: 10_000_000,
        deadline_ms: 30_000,
    }
}

fn tiny_limits() -> PolicyLimits {
    PolicyLimits {
        object_max_bytes: 1,
        ..roomy_limits()
    }
}

/// A bound verdict whose destination and managed placement mirror the request
/// snapshot (so check/use consumes it) and whose limits come from the caller.
fn bound_verdict(request: &PolicyRequest<'_>, limits: PolicyLimits) -> VerifiedPolicy {
    VerifiedPolicy {
        binding: Some(PolicyBinding {
            workspace_id: request.workspace_id.to_string(),
            operation: request.operation,
            route_prefix: String::new(),
            envelope_digest: "e".repeat(64),
            envelope_version: 1,
            effective_state_digest: "d".repeat(64),
            receipt_seq: 1,
            receipt_body_digest: "b".repeat(64),
            authorization_epoch: 1,
            destination: request.snapshot.binding.clone(),
            managed_placement: request.snapshot.managed_placement(),
            limits,
        }),
    }
}

/// Bound verdicts with limits keyed by `PolicyOperation`, so a create-time
/// verdict and a complete-time verdict can differ across the multipart
/// lifecycle (the statefulness the min-limits tests need).
struct LimitsByOperationGate {
    limits: BTreeMap<PolicyOperation, PolicyLimits>,
    default: PolicyLimits,
}

#[async_trait]
impl PolicyGate for LimitsByOperationGate {
    async fn enforce(&self, request: &PolicyRequest<'_>) -> Result<VerifiedPolicy, MaskuraError> {
        let limits = self
            .limits
            .get(&request.operation)
            .copied()
            .unwrap_or(self.default);
        Ok(bound_verdict(request, limits))
    }
}

async fn gated_router(gate: Arc<dyn PolicyGate>) -> (Router, Arc<AppState>) {
    let (config, _scratch) = coverage_config();
    let mut state = build_state_with_pipeline_template(
        Arc::new(NoopControlPlane),
        default_wrapping().expect("wrapping"),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        test_pipeline_template(),
        &config,
    )
    .await
    .expect("build_state");
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .policy_gate = Some(gate);
    (build_router(state.clone()), state)
}

/// Bucket first: an object PUT against a missing file bucket 404s and masks
/// the assertion under test.
async fn create_bucket(app: &Router, hdrs: &[(&'static str, String)]) {
    let create_bucket = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bucket")
            .body(Body::empty())
            .unwrap(),
        hdrs,
    );
    assert_eq!(
        app.clone().oneshot(create_bucket).await.unwrap().status(),
        StatusCode::OK
    );
}

async fn put_object(app: &Router, hdrs: &[(&'static str, String)]) {
    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bucket/object")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("payload"))
            .unwrap(),
        hdrs,
    );
    assert_eq!(
        app.clone().oneshot(put).await.unwrap().status(),
        StatusCode::OK
    );
}

async fn transformed_get(
    app: &Router,
    hdrs: &[(&'static str, String)],
) -> axum::response::Response {
    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bucket/object")
            .header("x-maskura-process", "read")
            .body(Body::empty())
            .unwrap(),
        hdrs,
    );
    app.clone().oneshot(get).await.unwrap()
}

async fn create_upload(app: &Router, hdrs: &[(&'static str, String)], key: &str) -> String {
    let create = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/bucket/{key}?uploads"))
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .unwrap(),
        hdrs,
    );
    let response = app.clone().oneshot(create).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "staged multipart create must succeed: {}",
        String::from_utf8_lossy(&body)
    );
    upload_id_from(&String::from_utf8_lossy(&body))
}

async fn upload_part(
    app: &Router,
    hdrs: &[(&'static str, String)],
    key: &str,
    upload_id: &str,
) -> String {
    let part = add_headers(
        Request::builder()
            .method("PUT")
            .uri(format!("/bucket/{key}?partNumber=1&uploadId={upload_id}"))
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CONTENT_LENGTH, "7")
            .body(Body::from("payload"))
            .unwrap(),
        hdrs,
    );
    let response = app.clone().oneshot(part).await.unwrap();
    let status = response.status();
    assert_eq!(status, StatusCode::OK, "staged part upload must succeed");
    response
        .headers()
        .get(header::ETAG)
        .expect("UploadPart ETag")
        .to_str()
        .expect("UploadPart ETag text")
        .to_string()
}

fn complete_xml(etag: &str) -> String {
    format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
    )
}

async fn complete_upload(
    app: &Router,
    hdrs: &[(&'static str, String)],
    key: &str,
    upload_id: &str,
    etag: &str,
) -> axum::response::Response {
    let body = complete_xml(etag);
    let complete = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/bucket/{key}?uploadId={upload_id}"))
            .body(Body::from(body))
            .unwrap(),
        hdrs,
    );
    app.clone().oneshot(complete).await.unwrap()
}

/// Drive create → part → complete under per-operation policy limits and hand
/// back the completion response for the caller's assertions.
async fn multipart_complete_with_limits(
    create_limits: PolicyLimits,
    complete_limits: PolicyLimits,
) -> axum::response::Response {
    let gate = Arc::new(LimitsByOperationGate {
        limits: BTreeMap::from([
            (PolicyOperation::MultipartCreate, create_limits),
            (PolicyOperation::MultipartComplete, complete_limits),
        ]),
        default: roomy_limits(),
    });
    let (app, state) = gated_router(gate).await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    create_bucket(&app, &hdrs).await;
    let upload_id = create_upload(&app, &hdrs, "multipart-object").await;
    let etag = upload_part(&app, &hdrs, "multipart-object", &upload_id).await;
    complete_upload(&app, &hdrs, "multipart-object", &upload_id, &etag).await
}

#[tokio::test]
async fn check_use_limits_constrain_transformed_read_session() {
    // A bound verdict's limits must reach the transformed-read wasm session:
    // `min(policy, operator)` on the fields a policy governs. One byte of
    // admitted input rejects the 7-byte object, while the identical request
    // under roomy limits succeeds.
    let gate = Arc::new(LimitsByOperationGate {
        limits: BTreeMap::from([(PolicyOperation::ProcessedGet, tiny_limits())]),
        default: roomy_limits(),
    });
    let (app, state) = gated_router(gate).await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    create_bucket(&app, &hdrs).await;
    put_object(&app, &hdrs).await;

    let rejected = transformed_get(&app, &hdrs).await;
    let rejected_status = rejected.status();
    let rejected_body = axum::body::to_bytes(rejected.into_body(), usize::MAX)
        .await
        .unwrap();
    let rejected_body = String::from_utf8_lossy(&rejected_body);
    assert!(
        !rejected_status.is_success(),
        "policy limits must bound the transformed-read session: {rejected_status} {rejected_body}"
    );
    // LIMIT_INPUT_BYTES maps through pipeline_error_response to EntityTooLarge.
    assert_eq!(rejected_status, StatusCode::BAD_REQUEST, "{rejected_body}");
    assert!(
        rejected_body.contains("<Code>EntityTooLarge</Code>"),
        "tiny object_max_bytes must reject the source object: {rejected_body}"
    );

    // Control: the same request under roomy limits succeeds.
    let gate = Arc::new(LimitsByOperationGate {
        limits: BTreeMap::new(),
        default: roomy_limits(),
    });
    let (app, state) = gated_router(gate).await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    create_bucket(&app, &hdrs).await;
    put_object(&app, &hdrs).await;
    let allowed = transformed_get(&app, &hdrs).await;
    assert_eq!(
        allowed.status(),
        StatusCode::OK,
        "roomy limits must not reject the transformed read"
    );
}

#[tokio::test]
async fn complete_session_limits_use_min_of_frozen_and_current() {
    // Direction A — loosening cannot widen an admitted upload: the create-time
    // tiny bound is retained via min_policy_limits even though the current
    // policy is roomy.
    let loosened = multipart_complete_with_limits(tiny_limits(), roomy_limits()).await;
    let status = loosened.status();
    let body = axum::body::to_bytes(loosened.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(
        !status.is_success(),
        "the frozen tiny bound must survive policy loosening: {status} {body}"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.contains("<Code>EntityTooLarge</Code>"),
        "min(frozen tiny, current roomy) must reject the 7-byte source: {body}"
    );

    // Direction B — tightening applies immediately: the fresh tiny bound wins
    // over the roomy create-time admission.
    let tightened = multipart_complete_with_limits(roomy_limits(), tiny_limits()).await;
    let status = tightened.status();
    let body = axum::body::to_bytes(tightened.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(
        !status.is_success(),
        "a tightened current policy must apply at completion: {status} {body}"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.contains("<Code>EntityTooLarge</Code>"),
        "min(frozen roomy, current tiny) must reject the 7-byte source: {body}"
    );

    // Control — both approvals roomy: the completion session runs and the
    // upload completes.
    let control = multipart_complete_with_limits(roomy_limits(), roomy_limits()).await;
    let status = control.status();
    let body = axum::body::to_bytes(control.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(
        status,
        StatusCode::OK,
        "roomy frozen and current verdicts must complete: {body}"
    );
    assert!(
        body.contains("CompleteMultipartUploadResult"),
        "completion must publish the assembled object: {body}"
    );
}

#[tokio::test]
async fn complete_policy_limits_error_fails_closed() {
    // Structurally invalid limits (a zeroed governed field) make
    // `PipelineSnapshot::constrained` fail with CONFIG_INVALID before the
    // completion session starts: fail closed through
    // `MultipartCompletionError::Policy` → `policy_error_response`. The
    // non-policy code routes through `s3_error::internal_error`, which
    // hard-codes the `InternalError` document; the exact machine code is
    // pinned here so a routing change is caught.
    let invalid = PolicyLimits {
        record_max_bytes: 0,
        ..roomy_limits()
    };
    let response = multipart_complete_with_limits(roomy_limits(), invalid).await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(
        !status.is_success(),
        "zero policy limits must fail closed at completion: {status} {body}"
    );
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "policy_error_response maps non-policy codes to internal_error: {body}"
    );
    assert!(
        body.contains("<Code>InternalError</Code>"),
        "internal_error hard-codes the InternalError document: {body}"
    );
}

#[tokio::test]
async fn frozen_policy_survives_the_multipart_lifecycle() {
    // A bound create-time verdict is persisted into the staged upload and
    // re-checked against every fresh resolution (part upload, list-parts,
    // abort, complete). Acceptance through the whole lifecycle proves the
    // frozen re-check matches the fresh selection.
    let gate = Arc::new(LimitsByOperationGate {
        limits: BTreeMap::new(),
        default: roomy_limits(),
    });
    let (app, state) = gated_router(gate).await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    create_bucket(&app, &hdrs).await;

    // create → part → list-parts → complete
    let upload_id = create_upload(&app, &hdrs, "lifecycle-object").await;
    let etag = upload_part(&app, &hdrs, "lifecycle-object", &upload_id).await;
    let list_parts = add_headers(
        Request::builder()
            .method("GET")
            .uri(format!("/bucket/lifecycle-object?uploadId={upload_id}"))
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let list_response = app.clone().oneshot(list_parts).await.unwrap();
    let list_status = list_response.status();
    let list_body = axum::body::to_bytes(list_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let list_body = String::from_utf8_lossy(&list_body);
    assert_eq!(
        list_status,
        StatusCode::OK,
        "frozen verdict must accept list-parts: {list_body}"
    );
    assert!(
        list_body.contains("<ListPartsResult"),
        "unexpected list-parts body: {list_body}"
    );
    let complete = complete_upload(&app, &hdrs, "lifecycle-object", &upload_id, &etag).await;
    let complete_status = complete.status();
    let complete_body = axum::body::to_bytes(complete.into_body(), usize::MAX)
        .await
        .unwrap();
    let complete_body = String::from_utf8_lossy(&complete_body);
    assert_eq!(
        complete_status,
        StatusCode::OK,
        "frozen verdict must accept completion: {complete_body}"
    );
    assert!(
        complete_body.contains("CompleteMultipartUploadResult"),
        "{complete_body}"
    );

    // create → part → abort
    let aborted_id = create_upload(&app, &hdrs, "aborted-object").await;
    upload_part(&app, &hdrs, "aborted-object", &aborted_id).await;
    let abort = add_headers(
        Request::builder()
            .method("DELETE")
            .uri(format!("/bucket/aborted-object?uploadId={aborted_id}"))
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let abort_response = app.clone().oneshot(abort).await.unwrap();
    assert_eq!(
        abort_response.status(),
        StatusCode::NO_CONTENT,
        "frozen verdict must accept abort of a caller-owned upload"
    );
}

#[tokio::test]
async fn list_multipart_uploads_is_gated() {
    // In-progress upload listings disclose key names; they present as List
    // with the requested prefix and run behind the same gate as ListObjects.
    struct DenyAll;

    #[async_trait]
    impl PolicyGate for DenyAll {
        async fn enforce(
            &self,
            _request: &PolicyRequest<'_>,
        ) -> Result<VerifiedPolicy, MaskuraError> {
            Err(MaskuraError::new(
                maskura_error::codes::POLICY_DENIED,
                "state mismatch",
            ))
        }
    }

    let (app, state) = gated_router(Arc::new(DenyAll)).await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let denied = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bucket?uploads")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.oneshot(denied).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("<Code>policy.denied</Code>"),
        "ListMultipartUploads must run behind the gate: {body}"
    );

    // An approved gate lists normally; the requested prefix is what the gate
    // saw as the List key.
    let gate = Arc::new(LimitsByOperationGate {
        limits: BTreeMap::new(),
        default: roomy_limits(),
    });
    let (app, state) = gated_router(gate).await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let allowed = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bucket?uploads&prefix=data/")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.oneshot(allowed).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "an approved List verdict must list uploads"
    );
}
