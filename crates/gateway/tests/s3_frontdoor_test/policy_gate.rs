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
//!
//! # Format-adapter rows (Lance)
//!
//! Format adapters ride the same gate seam (the gate call sites are
//! format-blind) but add format-specific dispatch and fail-closed behavior
//! behind their feature gates. The Lance rows below (the ADR 0022 policy
//! pair for the Lance codec) pin that surface. Row names name the adapter
//! seam each path invokes.
//!
//! | Row (path × scenario) | Expected | Seam | Pinned by |
//! |---|---|---|---|
//! | EffectiveState entry × `lance` adapter | `format: "lance"` + pinned `adapter_sha256`, keyed to the `MASKURA_ENABLE_LANCE` gate | `effective_state::ResolvedRoute` | `lance_effective_state_entry_is_keyed_to_the_lance_feature_gate` |
//! | Single PUT × Lance content types × gate closed | 501 before body read, nothing stored (`Put` still presented to the gate) | `s3_upload.rs::streaming_lance_single_put` | `streaming_lance_single_put_gate_closed_rejects_501_before_the_body` |
//! | Single PUT × Lance content types × gate open | 200, `Put` presented to the gate | `s3_upload.rs::streaming_lance_single_put` | `streaming_lance_single_put_presents_put_to_the_policy_gate` |
//! | Staged multipart completion × Lance × frozen admission | 200 through the Lance completion path; `MultipartComplete` presented with the frozen create-time verdict | `multipart.rs::complete_staged_lance_multipart` | `complete_staged_lance_multipart_serves_under_the_frozen_verdict` |
//! | Processed GET × Lance × `Range` / `partNumber` | `InvalidRequest` before decode | `s3_objects.rs::lance_transformed_read_response` | `lance_transformed_read_response_rejects_range_and_part_number` |
//! | Processed GET × Lance × gate open | complete-output staging (200 served from the spool); staging disabled or undecodable input fails closed — never a raw fallback | `s3_objects.rs::lance_transformed_read_response` | `lance_transformed_read_response_stages_complete_output_without_raw_fallback` |
//! | Processed GET × Lance × gate closed | rejected (`InvalidRequest`), no raw bytes disclosed | `s3_objects.rs::lance_transformed_read_response` | `lance_processed_read_gate_closed_is_rejected` |
//! | Raw GET / HEAD / byte-range × stored Lance object | **unprocessed** passthrough over the stored representation (`RawGet`/`Head`, never `ProcessedGet`) | (no adapter seam — the raw path is format-blind) | `lance_raw_get_head_and_byte_range_stay_unprocessed_passthrough` |
//! | Metering / pipeline evidence × Lance | the existing binary-adapter rows (`UsageRoute::PutObject`/`GetObject`; `CommonTypeBinaryReductor` + envelope per `lance/tests.rs::process_lance_emits_the_typed_envelope_schema`); no new metering route | `control::UsageEvent` | `lance_metering_reuses_the_binary_adapter_rows` |
//!
//! Avro-gap note: the earlier binary adapter has **no** rows here — the Avro
//! seams (`streaming_avro_single_put`, `complete_staged_avro_multipart`,
//! `avro_transformed_read_response`) and their gate-closed 501 /
//! `InvalidRequest` behavior were never matrix-tested. The Lance rows above
//! establish the format-adapter row pattern; Avro rows mirroring them are a
//! noted coverage gap, not a behavior change.

use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use async_trait::async_trait;
use maskura_customer_config::config::MultipartMode as ConfigMultipartMode;
use maskura_error::MaskuraError;
use maskura_gateway::policy_gate::{
    PolicyBinding, PolicyGate, PolicyRequest, VERIFIED_POLICY_SCHEMA_VERSION, VerifiedPolicy,
};
use maskura_pipeline_config::{
    DestinationBinding, PolicyLimits, PolicyOperation, ResolvedDestination, StorageMode,
};

#[derive(Default)]
struct RecordingPolicyGate {
    calls: Mutex<Vec<(PolicyOperation, String, String, bool)>>,
    /// Return bound verdicts (mirroring each request's snapshot and
    /// [`roomy_limits`]) instead of unbound ones, so `MultipartCreate`
    /// freezes evidence the continuation requests must carry back to the
    /// gate.
    bind: bool,
}

impl RecordingPolicyGate {
    /// A recording gate whose verdicts are bound, so the multipart freeze
    /// point persists a frozen admission for continuations to present.
    fn bound() -> Self {
        Self {
            bind: true,
            ..Default::default()
        }
    }

    fn operations(&self) -> BTreeSet<PolicyOperation> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(operation, _, _, _)| *operation)
            .collect()
    }

    fn count(&self, operation: PolicyOperation) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(seen, _, _, _)| *seen == operation)
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
            request.frozen.is_some(),
        ));
        if self.bind {
            return Ok(bound_verdict(request, roomy_limits()));
        }
        Ok(VerifiedPolicy::unbound())
    }
}

/// Staged multipart and transformed reads are config-explicit features; a
/// TOML file sets the explicit flags the same way operator deployment does.
/// The feature fields are pinned after resolve because the process-wide
/// `test_pipeline_template` fixture force-sets env overrides that would
/// otherwise stomp the file depending on test order.
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
            "[features]\nmultipart_mode = \"staged\"\ntransformed_read_spool = true\n[storage]\nlocal_dir = \"{}\"\nmode = \"local\"\nsingle_tenant = true\n",
            scratch.display()
        ),
    )
    .expect("write coverage config");
    let mut config = Config::resolve(Some(&path)).expect("resolve coverage config");
    config.features.multipart_mode = ConfigMultipartMode::Staged;
    config.features.transformed_read_spool = true;
    assert_eq!(config.features.multipart_mode, ConfigMultipartMode::Staged);
    (config, scratch)
}

async fn coverage_router() -> (Router, Arc<AppState>, Arc<RecordingPolicyGate>) {
    coverage_router_with(Arc::new(RecordingPolicyGate::default()), |_| {}).await
}

/// The coverage router with a caller-chosen gate and state tuning applied
/// before the router is built: the router holds `Arc<AppState>` clones, so
/// state must be final at build time. This is how the format-adapter rows
/// key the `lance` gate (`binary_lance_enabled`) on and off per scenario.
async fn coverage_router_with(
    gate: Arc<RecordingPolicyGate>,
    tune: impl FnOnce(&mut AppState),
) -> (Router, Arc<AppState>, Arc<RecordingPolicyGate>) {
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
    {
        let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
        state_mut.policy_gate = Some(gate.clone());
        tune(state_mut);
    }
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
    // One recorded gate shared by two scopes: the kinds presented to the gate
    // are assignment-driven under the mandatory read pipeline (a protected
    // scope presents ProcessedGet and denies HEAD before the gate; an explicit
    // passthrough scope presents RawGet and admits HEAD).
    let gate = Arc::new(RecordingPolicyGate::default());
    let (app, state, gate) = coverage_router_with(gate, |_| {}).await;
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

    // A protected scope denies HEAD before the gate (transformed metadata is
    // not available); the passthrough drive below covers the gated Head op.
    let head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/bucket/object")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let head_response = app.clone().oneshot(head).await.unwrap();
    assert_eq!(head_response.status(), StatusCode::BAD_REQUEST);

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

    // Continuation requests load the staged upload before the gate (a missing
    // upload answers no_such_upload regardless of gate outcome), so the part
    // and abort branches need real upload ids to reach the gate seam.
    let part = add_headers(
        Request::builder()
            .method("PUT")
            .uri(format!(
                "/bucket/multipart-object?partNumber=1&uploadId={upload_id}"
            ))
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

    let abort_target = create_upload(&app, &hdrs, "abort-target").await;
    let abort = add_headers(
        Request::builder()
            .method("DELETE")
            .uri(format!("/bucket/abort-target?uploadId={abort_target}"))
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

    // The explicit passthrough drive: reads present RawGet and HEAD reaches
    // the gate (the legacy read-selection header is inert).
    let (raw_app, raw_state, gate) =
        coverage_router_with(gate.clone(), apply_explicit_passthrough).await;
    let (raw_ak, raw_sk) = make_key(&raw_state).await;
    let raw_hdrs = auth_headers(&raw_ak, &raw_sk);
    let raw_get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bucket/object")
            .body(Body::empty())
            .unwrap(),
        &raw_hdrs,
    );
    raw_app.clone().oneshot(raw_get).await.unwrap();
    let raw_head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/bucket/object")
            .body(Body::empty())
            .unwrap(),
        &raw_hdrs,
    );
    raw_app.clone().oneshot(raw_head).await.unwrap();

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
                |(operation, bucket, key, _)| *operation == PolicyOperation::List
                    && bucket == "bucket"
                    && key == "data/"
            ),
            "the plain LIST call must present List with its prefix as the gate key; calls: {calls:?}"
        );
        assert!(
            calls.iter().any(
                |(operation, bucket, key, _)| *operation == PolicyOperation::List
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
                schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
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
                schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
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
        schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
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
async fn multipart_continuations_carry_the_frozen_verdict_to_the_gate() {
    // Slice 3 / spec §7.4: `MultipartCreate` is the freeze point and presents
    // no frozen verdict; part upload, complete, and abort are continuation
    // requests and must present the create-time frozen admission to the gate
    // (`frozen: Some`) so in-flight uploads keep their approved state across
    // envelope rotation/expiry. Single-shot operations (PUT/GET) carry no
    // frozen verdict.
    let gate = Arc::new(RecordingPolicyGate::bound());
    let (app, state) = gated_router(gate.clone()).await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    create_bucket(&app, &hdrs).await;
    put_object(&app, &hdrs).await;
    let raw_get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bucket/object")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let get_response = app.clone().oneshot(raw_get).await.unwrap();
    assert_eq!(
        get_response.status(),
        StatusCode::OK,
        "the single-shot raw GET must succeed under the bound gate"
    );

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
    assert_eq!(
        list_status,
        StatusCode::OK,
        "list-parts must accept the frozen verdict: {}",
        String::from_utf8_lossy(&list_body)
    );
    let complete = complete_upload(&app, &hdrs, "lifecycle-object", &upload_id, &etag).await;
    let complete_status = complete.status();
    let complete_body = axum::body::to_bytes(complete.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        complete_status,
        StatusCode::OK,
        "complete must accept the frozen verdict: {}",
        String::from_utf8_lossy(&complete_body)
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
        "abort must accept the frozen verdict"
    );

    let calls = gate.calls.lock().unwrap();
    // Continuations present the create-time frozen admission to the gate.
    for operation in [
        PolicyOperation::MultipartUpload,
        PolicyOperation::MultipartComplete,
        PolicyOperation::MultipartAbort,
    ] {
        assert!(
            calls
                .iter()
                .any(|(seen, _, _, frozen)| *seen == operation && *frozen),
            "{operation:?} must present the frozen create-time verdict to the gate; calls: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .filter(|(seen, _, _, _)| *seen == operation)
                .all(|(_, _, _, frozen)| *frozen),
            "every {operation:?} call must carry the frozen verdict; calls: {calls:?}"
        );
    }
    // The freeze point and single-shot operations carry none.
    assert!(
        calls
            .iter()
            .any(|(seen, _, _, frozen)| *seen == PolicyOperation::MultipartCreate && !*frozen),
        "MultipartCreate must reach the gate as the freeze point without a frozen verdict; calls: {calls:?}"
    );
    for operation in [
        PolicyOperation::MultipartCreate,
        PolicyOperation::Put,
        PolicyOperation::RawGet,
    ] {
        assert!(
            calls
                .iter()
                .all(|(seen, _, _, frozen)| *seen != operation || !*frozen),
            "{operation:?} must present no frozen verdict to the gate; calls: {calls:?}"
        );
    }
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

// ---------------------------------------------------------------------------
// Format-adapter rows (Lance) — see the "Format-adapter rows (Lance)" table
// in the module docs. Each fn pins one row.
// ---------------------------------------------------------------------------

/// Canonical Lance media type (the adapter also accepts `application/x-lance`
/// and `application/vnd.lance` — see `s3_upload.rs::lance_media_type`).
const LANCE_MEDIA_TYPE: &str = "application/vnd.apache.lance";

/// Reference-written structural v2.2 fixture (`lance/tests.rs` decodes it).
const LANCE_INT_V2_2: &[u8] = include_bytes!("../fixtures/lance/int_v2_2.lance");

/// Reference-written v2.0 fixture with an `email` string column (the fixture
/// the codec's envelope test encrypts).
const LANCE_MIXED_V2_0: &[u8] = include_bytes!("../fixtures/lance/mixed_v2_0.lance");

/// The `lance` gate on: `MASKURA_ENABLE_LANCE` / `features.enable_lance`
/// resolved into the runtime `binary_lance_enabled` state the adapter seams
/// check.
fn with_lance_enabled(state: &mut AppState) {
    state.binary_lance_enabled = true;
}

async fn create_upload_with_content_type(
    app: &Router,
    hdrs: &[(&'static str, String)],
    key: &str,
    content_type: &str,
) -> String {
    let create = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/bucket/{key}?uploads"))
            .header(header::CONTENT_TYPE, content_type)
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

async fn upload_part_bytes(
    app: &Router,
    hdrs: &[(&'static str, String)],
    key: &str,
    upload_id: &str,
    body: &[u8],
) -> String {
    let part = add_headers(
        Request::builder()
            .method("PUT")
            .uri(format!("/bucket/{key}?partNumber=1&uploadId={upload_id}"))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, body.len().to_string())
            .body(Body::from(body.to_vec()))
            .unwrap(),
        hdrs,
    );
    let response = app.clone().oneshot(part).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "staged part upload");
    response
        .headers()
        .get(header::ETAG)
        .expect("UploadPart ETag")
        .to_str()
        .expect("UploadPart ETag text")
        .to_string()
}

fn lance_object_get(key: &str, process: bool) -> axum::http::request::Builder {
    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("/bucket/{key}"));
    if process {
        builder = builder.header("x-maskura-process", "read");
    }
    builder
}

/// Plant a stored object directly in the coverage router's local file store:
/// the read rows need a stored Lance representation to read, and a
/// gate-closed (or pre-codec) gateway refuses to write one through the
/// adapter.
async fn plant_object(
    state: &Arc<AppState>,
    bucket: &str,
    key: &str,
    data: &[u8],
    content_type: &str,
) {
    state
        .file_store
        .as_ref()
        .expect("coverage config uses local file storage")
        .put(
            bucket,
            key,
            bytes::Bytes::copy_from_slice(data),
            content_type,
        )
        .await
        .expect("plant stored object");
}

/// The stored representation of `key` as raw passthrough serves it.
async fn raw_get_body(app: &Router, hdrs: &[(&'static str, String)], key: &str) -> Vec<u8> {
    let raw_get = add_headers(
        lance_object_get(key, false).body(Body::empty()).unwrap(),
        hdrs,
    );
    let response = app.clone().oneshot(raw_get).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "raw passthrough must serve the stored object"
    );
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

/// The `EffectiveState` entry for the `lance` adapter is keyed to the
/// `MASKURA_ENABLE_LANCE` gate: the route's `format` name is the feature-gate
/// key (`features.enable_lance` → `binary_lance_enabled`), and non-byte
/// entries pin their adapter implementation (`adapter_sha256`; entry
/// validation is unit-pinned in
/// `pipeline-config/src/effective_state.rs::lance_adapter_entry_pins_the_adapter_and_fails_closed_unpinned`).
#[tokio::test]
async fn lance_effective_state_entry_is_keyed_to_the_lance_feature_gate() {
    use maskura_pipeline_config::{
        EFFECTIVE_STATE_SCHEMA_VERSION, EffectiveState, ResolvedLimits, ResolvedRoute, ResolvedStep,
    };

    let entry = ResolvedRoute {
        bucket: "tenant".into(),
        prefix: "data/".into(),
        operation: PolicyOperation::Put,
        destination_id: "dest".into(),
        assignment_id: "assignment".into(),
        revision_id: "revision".into(),
        resolution_fingerprint: "f".repeat(64),
        explicit_passthrough: false,
        format: "lance".into(),
        adapter_sha256: Some("a".repeat(64)),
        limits: ResolvedLimits {
            processing: PolicyLimits {
                record_max_bytes: 1024,
                object_max_bytes: 4096,
                memory_bytes: 67_108_864,
                fuel: 10_000_000,
                deadline_ms: 30_000,
            },
            output_max_bytes: 8192,
            table_entries: 10_000,
            stack_bytes: 524_288,
            max_plugins: 10,
        },
        steps: vec![ResolvedStep {
            component_sha256: "a".repeat(64),
            plugin_version_id: "plugin-version".into(),
            world: "maskura:plugin/transformer@0.1.0".into(),
            enabled: true,
            config_json: None,
            grants: BTreeSet::new(),
            prefix_safe_for_read: false,
        }],
    };
    let state = EffectiveState {
        schema_version: EFFECTIVE_STATE_SCHEMA_VERSION,
        audience: "https://maskura.dev".into(),
        workspace_id: "ws-1".into(),
        destinations: [(
            "dest".into(),
            DestinationBinding::Concrete {
                destination: ResolvedDestination {
                    mode: StorageMode::S3Compatible,
                    endpoint: "https://s3.example.com/".into(),
                    bucket: "objects".into(),
                    region: "region".into(),
                    role_arn: None,
                    configuration_version_id: Some("config-version-1".into()),
                    configuration_sha256: "d".repeat(64),
                },
            },
        )]
        .into(),
        routes: vec![entry.clone()],
    };
    state
        .validate()
        .expect("the pinned lance adapter entry validates");

    // The entry's format name is exactly the feature-gate key: the same name
    // selects the adapter spec whose `FeatureGate` the runtime consults, and
    // the gate env alias is `MASKURA_ENABLE_LANCE`.
    let spec = maskura_gateway::format::FormatSpec::for_name(&entry.format)
        .expect("the lance entry names a known adapter");
    assert_eq!(spec, &maskura_gateway::format::LANCE_SPEC);
    assert_eq!(
        spec.feature_gate,
        Some(maskura_gateway::format::FeatureGate {
            name: "lance",
            enabled_by_default: false,
        })
    );
    assert!(!maskura_gateway::format::EnabledBinaryFormats::NONE.is_enabled(spec));
    assert!(maskura_gateway::format::EnabledBinaryFormats::ALL.is_enabled(spec));
    assert_eq!(
        maskura_customer_config::aliases::ENABLE_LANCE.name(),
        "MASKURA_ENABLE_LANCE"
    );

    // The gate key chain end to end: `features.enable_lance` populates the
    // runtime `binary_lance_enabled` state the adapter's data-plane seams
    // check, and the adapter is default-off.
    let mut config = test_config();
    config.features.enable_lance = true;
    let enabled = build_state_with_pipeline_template(
        Arc::new(NoopControlPlane),
        default_wrapping().expect("wrapping"),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        test_pipeline_template(),
        &config,
    )
    .await
    .expect("build_state");
    assert!(enabled.binary_lance_enabled);
    let (_app, closed, _gate) = coverage_router().await;
    assert!(
        !closed.binary_lance_enabled,
        "the lance adapter gate is closed by default"
    );
}

/// Row (a), gate closed: a single PUT with Lance content types is rejected
/// 501 before the body is read and nothing is stored. The policy gate still
/// covers the path (`Put` is presented before the adapter dispatch), so a
/// gate-closed Lance write can never widen the unenforced surface.
#[tokio::test]
async fn streaming_lance_single_put_gate_closed_rejects_501_before_the_body() {
    let (app, state, gate) = coverage_router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    create_bucket(&app, &hdrs).await;
    let polls = Arc::new(AtomicUsize::new(0));
    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bucket/gate-closed.lance")
            .header(header::CONTENT_TYPE, LANCE_MEDIA_TYPE)
            .body(Body::new(PollTrackingBody {
                polls: polls.clone(),
                data: Some(Bytes::copy_from_slice(LANCE_INT_V2_2)),
            }))
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(put).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_IMPLEMENTED,
        "gate-closed Lance writes are rejected 501 (MASKURA_ENABLE_LANCE unset)"
    );
    assert_eq!(
        polls.load(Ordering::SeqCst),
        0,
        "the gate-closed rejection must happen before the body is read"
    );
    assert!(
        state
            .file_store
            .as_ref()
            .expect("coverage config uses local file storage")
            .head("bucket", "gate-closed.lance")
            .await
            .expect("file store head")
            .is_none(),
        "a gate-closed Lance write stores nothing"
    );
    assert_eq!(
        gate.count(PolicyOperation::Put),
        1,
        "the policy gate covers the Lance write path even when the adapter gate is closed"
    );
}

/// Row (a), gate open: the single PUT runs through
/// `s3_upload.rs::streaming_lance_single_put` and presents `Put` to the
/// policy gate; the stored output is the codec's processed Lance file.
#[tokio::test]
async fn streaming_lance_single_put_presents_put_to_the_policy_gate() {
    let (app, state, gate) =
        coverage_router_with(Arc::new(RecordingPolicyGate::default()), with_lance_enabled).await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    create_bucket(&app, &hdrs).await;
    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bucket/object.lance")
            .header(header::CONTENT_TYPE, LANCE_MEDIA_TYPE)
            .body(Body::from(LANCE_INT_V2_2.to_vec()))
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(put).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "gate-open Lance single PUT serves through streaming_lance_single_put"
    );
    let stored = raw_get_body(&app, &hdrs, "object.lance").await;
    assert!(
        stored.ends_with(b"LANC"),
        "the stored representation is a processed Lance file"
    );
    assert!(
        gate.calls
            .lock()
            .unwrap()
            .iter()
            .any(
                |(operation, bucket, key, frozen)| *operation == PolicyOperation::Put
                    && bucket == "bucket"
                    && key == "object.lance"
                    && !*frozen
            ),
        "streaming_lance_single_put must present Put to the policy gate; calls: {:?}",
        gate.calls.lock().unwrap()
    );
}

/// Row (b): staged multipart completion with Lance content types runs through
/// `multipart.rs::complete_staged_lance_multipart` under the frozen
/// create-time admission — the `MultipartComplete` verdict the completion
/// path presents carries the frozen verdict persisted at create time.
#[tokio::test]
async fn complete_staged_lance_multipart_serves_under_the_frozen_verdict() {
    let (app, state, gate) =
        coverage_router_with(Arc::new(RecordingPolicyGate::bound()), with_lance_enabled).await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    create_bucket(&app, &hdrs).await;
    let upload_id =
        create_upload_with_content_type(&app, &hdrs, "multipart-object.lance", LANCE_MEDIA_TYPE)
            .await;
    let etag = upload_part_bytes(
        &app,
        &hdrs,
        "multipart-object.lance",
        &upload_id,
        LANCE_INT_V2_2,
    )
    .await;
    let complete = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!(
                "/bucket/multipart-object.lance?uploadId={upload_id}"
            ))
            .body(Body::from(complete_xml(&etag)))
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(complete).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "Lance multipart completion serves under the frozen admission: {}",
        String::from_utf8_lossy(&body)
    );
    let stored = raw_get_body(&app, &hdrs, "multipart-object.lance").await;
    assert!(
        stored.ends_with(b"LANC"),
        "the completed object is a processed Lance file"
    );
    // Frozen policy verdicts cover the completion path: the completion's gate
    // verdict is checked against the admission frozen at create time.
    let calls = gate.calls.lock().unwrap();
    assert!(
        calls.iter().any(|(operation, _, _, frozen)| *operation
            == PolicyOperation::MultipartCreate
            && !*frozen),
        "the create request freezes the admission; calls: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|(operation, _bucket, key, frozen)| *operation
                == PolicyOperation::MultipartComplete
                && key == "multipart-object.lance"
                && *frozen),
        "complete_staged_lance_multipart must run under the frozen create-time verdict; calls: {calls:?}"
    );
}

/// Row (c), preflight: processed reads reject `Range` and `partNumber`
/// before any Lance decode, with the typed `InvalidRequest` code.
#[tokio::test]
async fn lance_transformed_read_response_rejects_range_and_part_number() {
    let (app, state, _gate) =
        coverage_router_with(Arc::new(RecordingPolicyGate::default()), with_lance_enabled).await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    plant_object(
        &state,
        "bucket",
        "ranged.lance",
        LANCE_INT_V2_2,
        LANCE_MEDIA_TYPE,
    )
    .await;

    let ranged = add_headers(
        lance_object_get("ranged.lance", true)
            .header(header::RANGE, "bytes=0-3")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(ranged).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("<Code>InvalidRequest</Code>")
            && body.contains("Range is not supported for transformed reads"),
        "Range must be rejected before any Lance decode: {body}"
    );

    let part_number = add_headers(
        lance_object_get("ranged.lance", true)
            .uri("/bucket/ranged.lance?partNumber=1")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(part_number).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("<Code>InvalidRequest</Code>")
            && body.contains("part-number reads are not supported for transformed reads"),
        "partNumber must be rejected before any Lance decode: {body}"
    );
}

/// Row (c): processed reads stage the complete filtered output before any
/// body is disclosed — staging is mandatory (`transformed_read_spool`), and
/// failures never fall back to raw bytes.
#[tokio::test]
async fn lance_transformed_read_response_stages_complete_output_without_raw_fallback() {
    // Complete-output staging serves: the response is the fully processed
    // Lance file, not a byte copy of the stored representation.
    let (app, state, _gate) =
        coverage_router_with(Arc::new(RecordingPolicyGate::default()), with_lance_enabled).await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    plant_object(
        &state,
        "bucket",
        "object.lance",
        LANCE_MIXED_V2_0,
        LANCE_MEDIA_TYPE,
    )
    .await;
    let processed = add_headers(
        lance_object_get("object.lance", true)
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(processed).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the processed read stages the complete output and serves it"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        body.ends_with(b"LANC"),
        "the response is a complete Lance file"
    );
    assert!(
        body.len() != LANCE_MIXED_V2_0.len() || body[..] != LANCE_MIXED_V2_0[..],
        "the processed output is the staged re-encoded file, not raw bytes"
    );

    // Staging is enforced, not advisory: without the encrypted read spool the
    // complete-output read fails closed — never a raw fallback.
    let (app, state, _gate) =
        coverage_router_with(Arc::new(RecordingPolicyGate::default()), |state| {
            with_lance_enabled(state);
            state.transformed_read_spool_enabled = false;
        })
        .await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    plant_object(
        &state,
        "bucket",
        "object.lance",
        LANCE_MIXED_V2_0,
        LANCE_MEDIA_TYPE,
    )
    .await;
    let processed = add_headers(
        lance_object_get("object.lance", true)
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(processed).await.unwrap();
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "an unstaged Lance processed read must fail closed"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        !body
            .windows(LANCE_MIXED_V2_0.len())
            .any(|w| w == LANCE_MIXED_V2_0),
        "a failed processed read must never disclose raw bytes"
    );

    // Undecodable input fails closed through the pipeline error mapping —
    // still no raw fallback.
    plant_object(
        &state,
        "bucket",
        "invalid.lance",
        b"not a lance file",
        LANCE_MEDIA_TYPE,
    )
    .await;
    let processed = add_headers(
        lance_object_get("invalid.lance", true)
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(processed).await.unwrap();
    assert!(
        !response.status().is_success(),
        "an undecodable Lance object must fail its processed read"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        !body
            .windows(b"not a lance file".len())
            .any(|w| w == b"not a lance file"),
        "a failed processed read must never disclose raw bytes"
    );
}

/// Row (c) / requirement 3, read side: with the `lance` gate closed
/// (`MASKURA_ENABLE_LANCE` unset), processed reads over stored Lance objects
/// are rejected — and never fall back to the raw stored bytes.
#[tokio::test]
async fn lance_processed_read_gate_closed_is_rejected() {
    let (app, state, _gate) = coverage_router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    plant_object(
        &state,
        "bucket",
        "object.lance",
        LANCE_INT_V2_2,
        LANCE_MEDIA_TYPE,
    )
    .await;
    let processed = add_headers(
        lance_object_get("object.lance", true)
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(processed).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "gate-closed processed reads over Lance objects are rejected"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("<Code>InvalidRequest</Code>"),
        "the gate-closed rejection keeps the typed S3 code: {text}"
    );
    assert!(
        !body
            .windows(LANCE_INT_V2_2.len())
            .any(|window| window == LANCE_INT_V2_2),
        "a gate-closed processed read must never disclose raw bytes"
    );
}

/// Row (d): raw GET, HEAD, and byte-range reads over stored Lance objects are
/// **unprocessed** passthrough over the stored representation — the policy
/// gate sees `RawGet`/`Head` (never `ProcessedGet`), the adapter is not
/// invoked, and the bytes are returned unchanged.
#[tokio::test]
async fn lance_raw_get_head_and_byte_range_stay_unprocessed_passthrough() {
    // Deliberately gate CLOSED: raw passthrough must not depend on the
    // adapter feature gate at all.
    let (app, state, gate) = coverage_router_with(
        Arc::new(RecordingPolicyGate::default()),
        apply_explicit_passthrough,
    )
    .await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    plant_object(
        &state,
        "bucket",
        "object.lance",
        LANCE_INT_V2_2,
        LANCE_MEDIA_TYPE,
    )
    .await;

    let raw_get = add_headers(
        lance_object_get("object.lance", false)
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(raw_get).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        body.as_ref(),
        LANCE_INT_V2_2,
        "raw GET returns the stored representation unchanged"
    );

    let ranged = add_headers(
        lance_object_get("object.lance", false)
            .header(header::RANGE, "bytes=0-3")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(ranged).await.unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        body.as_ref(),
        &LANCE_INT_V2_2[..4],
        "byte-range reads slice the stored representation verbatim"
    );

    let head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/bucket/object.lance")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(head).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(LANCE_MEDIA_TYPE),
        "HEAD reports the stored representation's metadata"
    );

    // Explicitly *unprocessed*: the gate saw RawGet/Head and no ProcessedGet.
    let calls = gate.calls.lock().unwrap();
    assert!(
        calls
            .iter()
            .any(|(operation, _, _, _)| *operation == PolicyOperation::RawGet),
        "raw GET must present RawGet; calls: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|(operation, _, _, _)| *operation == PolicyOperation::Head),
        "HEAD must present Head; calls: {calls:?}"
    );
    assert_eq!(
        calls
            .iter()
            .filter(|(operation, _, _, _)| *operation == PolicyOperation::ProcessedGet)
            .count(),
        0,
        "raw passthrough paths must never claim processed reads; calls: {calls:?}"
    );
}

/// Requirement 4: pipeline evidence and receipt metering for Lance reuse the
/// existing binary-adapter rows — the same `UsageRoute` rows every object
/// meters on (there is no, and must be no, format-specific metering route),
/// with the binary-adapter evidence treatment. The Lance pipeline identity
/// (`CommonTypeBinaryReductor` + `EnvelopeBinaryTransform`) is asserted
/// through the envelope effect below and at unit level by
/// `lance/tests.rs::process_lance_emits_the_typed_envelope_schema`.
#[tokio::test]
async fn lance_metering_reuses_the_binary_adapter_rows() {
    let control = Arc::new(RecordingMeteringControl::default());
    let metering = control.clone();
    let (app, state, _gate) =
        coverage_router_with(Arc::new(RecordingPolicyGate::default()), move |state| {
            with_lance_enabled(state);
            state.control = metering.clone();
            state.source_body_limits.max_bytes = 64 * 1024 * 1024;
            state.max_pipeline_output_bytes = 64 * 1024 * 1024;
        })
        .await;
    // A key with the hybrid public key attached so the envelope transform
    // runs on its declared target.
    let (secret, created) = state
        .keys
        .create_key(
            "test-user",
            &WorkspaceId::new("test-user").unwrap(),
            "lance-metering",
            0,
            Some(TEST_PUBLIC_KEY_PEM.to_string()),
        )
        .await
        .expect("create test API key");
    let hdrs = auth_headers(&created.key_id, &secret);
    create_bucket(&app, &hdrs).await;

    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bucket/metered.lance")
            .header(header::CONTENT_TYPE, LANCE_MEDIA_TYPE)
            .header("x-maskura-encrypt-fields", "email")
            .body(Body::from(LANCE_MIXED_V2_0.to_vec()))
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(put).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let raw_get = add_headers(
        lance_object_get("metered.lance", false)
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(raw_get).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let stored = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        !stored
            .windows(b"ada@example.com".len())
            .any(|window| window == b"ada@example.com"),
        "the Lance pipeline runs the binary-adapter envelope transform"
    );

    let processed = add_headers(
        lance_object_get("metered.lance", true)
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let response = app.clone().oneshot(processed).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    let events = control.events.lock().unwrap().clone();
    assert_eq!(
        events
            .iter()
            .map(|call| {
                (
                    call.event.kind(),
                    call.event.route(),
                    call.event.pipeline_evidence().is_some(),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            // The existing binary-adapter rows: standard object routes, the
            // binary-adapter evidence treatment, and no format-specific
            // metering route anywhere.
            (RequestKind::Write, UsageRoute::PutObject, false),
            (RequestKind::Read, UsageRoute::GetObject, false),
            (RequestKind::Read, UsageRoute::GetObject, false),
        ],
        "Lance must reuse the existing binary-adapter metering rows"
    );
}
