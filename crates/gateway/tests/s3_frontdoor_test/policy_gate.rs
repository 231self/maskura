//! Policy-gate coverage matrix (policy-approval Slice 3).
//!
//! Every `PolicyOperation` variant must be presented to the configured
//! [`PolicyGate`] on its data-plane path, including hosted MCP dispatch which
//! reaches `s3_put`/`s3_get` in process. If a new handler (or operation) ships
//! without a gate call, the matrix assertion below fails.
//!
//! Deliberately out of claim (not object-data policy surface in v1):
//! `ListObjects` part listings (`ListParts`), `ListBuckets`, and bucket
//! create/delete admin ops.

use super::*;

use std::collections::BTreeSet;
use std::sync::Mutex;

use async_trait::async_trait;
use maskura_customer_config::config::{
    MultipartMode as ConfigMultipartMode, StreamingReadMode as ConfigStreamingReadMode,
};
use maskura_error::MaskuraError;
use maskura_gateway::policy_gate::{PolicyGate, PolicyRequest, VerifiedPolicy};
use maskura_pipeline_config::PolicyOperation;

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
