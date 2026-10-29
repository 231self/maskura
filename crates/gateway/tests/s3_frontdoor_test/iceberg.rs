//! Iceberg enforced-path matrix rows (ADR 0028 §7).
//!
//! Every row of the table-format adapter's enforced-path contract is pinned
//! here against the real gateway state and router:
//!
//! - **table-root processed write, gate closed** — 501 before the body is
//!   read, nothing stored;
//! - **table-root processed write, gate open** — the walk + atomic commit run,
//!   and the operation meters through the existing binary-adapter rows (no
//!   new metering route) behind the same policy gate;
//! - **table-root processed read** — complete-output staging (a preview;
//!   nothing stored), never a raw fallback, `Range`/`partNumber` rejected;
//! - **raw per-object GET/HEAD/byte-range** — *unprocessed* passthrough over
//!   the stored representation regardless of the gate;
//! - **partial processed operations inside a table root** — fail closed with
//!   the named `unsupported.table_operation` error, gate-independent.
//!
//! The golden tables under `tests/fixtures/iceberg/` are written by pyiceberg
//! (see `tests/fixtures/iceberg/generate_fixtures.py`). The production
//! data-file seam is the fail-closed stub until the Parquet codec (ADR 0027)
//! is wired, so the commit row runs the zero-data-file `v2_empty` table and
//! the "no raw fallback" row exercises a table that carries data files.

use super::*;

use std::path::PathBuf;

use maskura_error::MaskuraError;
use maskura_gateway::policy_gate::{PolicyGate, PolicyRequest, VerifiedPolicy};
use maskura_pipeline_config::PolicyOperation;

const ICEBERG_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/iceberg");
const BUCKET: &str = "bucket";

/// Loads one golden pyiceberg table into the in-memory store at its fixture
/// keys (bucket `bucket`, key `<fixture>/<relative path>`).
fn load_fixture(state: &AppState, name: &str) {
    let root = PathBuf::from(ICEBERG_FIXTURES).join(name);
    let mut stack = vec![(root.clone(), String::new())];
    while let Some((dir, relative)) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read fixture dir") {
            let entry = entry.expect("fixture entry");
            let file_name = entry.file_name().to_string_lossy().to_string();
            let relative = if relative.is_empty() {
                file_name.clone()
            } else {
                format!("{relative}/{file_name}")
            };
            if entry.file_type().expect("fixture type").is_dir() {
                stack.push((entry.path(), relative));
                continue;
            }
            let bytes = std::fs::read(entry.path()).expect("read fixture file");
            let content_type = if file_name.ends_with(".json") {
                "application/json"
            } else if file_name.ends_with(".avro") {
                "application/avro"
            } else if file_name.ends_with(".parquet") {
                "application/vnd.apache.parquet"
            } else {
                "text/plain"
            };
            state
                .store
                .put(BUCKET, &format!("{name}/{relative}"), bytes, content_type);
        }
    }
}

fn fixture_bytes(name: &str, relative: &str) -> Vec<u8> {
    std::fs::read(PathBuf::from(ICEBERG_FIXTURES).join(name).join(relative))
        .expect("read fixture file")
}

/// Test state with the transformed-read stack enabled and the Iceberg gate
/// open or closed as requested. Everything else mirrors `test_config`.
async fn iceberg_state(gate_open: bool) -> Arc<AppState> {
    let mut config = test_config();
    config.features.transformed_read_spool = true;
    config.features.enable_iceberg = gate_open;
    config.features.dev_memory_streaming = true;
    build_state_with_pipeline_template(
        Arc::new(NoopControlPlane),
        default_wrapping().expect("wrapping"),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        test_pipeline_template(),
        &config,
    )
    .await
    .expect("build iceberg test state")
}

/// A gate that records the operations presented to it and admits everything
/// unbound (the table path must hit the same seam as every other operation).
#[derive(Default)]
struct RecordingGate {
    calls: Mutex<Vec<(PolicyOperation, String)>>,
}

#[async_trait::async_trait]
impl PolicyGate for RecordingGate {
    async fn enforce(&self, request: &PolicyRequest<'_>) -> Result<VerifiedPolicy, MaskuraError> {
        self.calls
            .lock()
            .unwrap()
            .push((request.operation, request.key.to_string()));
        Ok(VerifiedPolicy::unbound())
    }
}

fn put_request(uri: &str, body: Body, hdrs: &[(&'static str, String)]) -> Request<Body> {
    add_headers(
        Request::builder()
            .method("PUT")
            .uri(uri)
            .body(body)
            .unwrap(),
        hdrs,
    )
}

/// Row: table-root processed write, gate closed = 501 before body read,
/// nothing stored.
#[tokio::test]
async fn table_root_processed_write_gate_closed_is_501_before_the_body_is_read() {
    let state = iceberg_state(false).await;
    load_fixture(&state, "v2_empty");
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let app = build_router(state.clone());

    let polls = Arc::new(AtomicUsize::new(0));
    let source = fixture_bytes(
        "v2_empty",
        "metadata/00000-2440e43d-7df5-4e36-984c-633a0da038e6.metadata.json",
    );
    let request = put_request(
        "/bucket/v2_empty/metadata/00001-deadbeef.metadata.json",
        Body::new(PollTrackingBody {
            polls: polls.clone(),
            data: Some(Bytes::from(source)),
        }),
        &hdrs,
    );
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_IMPLEMENTED,
        "a gate-closed table-root write must reject 501"
    );
    assert_eq!(
        polls.load(Ordering::SeqCst),
        0,
        "the gate-closed rejection must happen before the body is polled"
    );
    assert!(
        state
            .store
            .get(BUCKET, "v2_empty/metadata/00001-deadbeef.metadata.json")
            .is_none(),
        "nothing may be stored on a gate-closed table-root write"
    );
}

/// Row: partial processed operations inside a table root fail closed with the
/// named `unsupported.table_operation` error — gate-independent.
#[tokio::test]
async fn partial_processed_operations_inside_a_table_root_fail_closed() {
    // The gate is *closed* here: the named rejection must not depend on it.
    let state = iceberg_state(false).await;
    load_fixture(&state, "v2_empty");
    load_fixture(&state, "v1_unpartitioned");
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let app = build_router(state.clone());

    // A data file, the version pointer, and a manifest layer: all strict
    // sub-units of a table root.
    let writes = [
        (
            "/bucket/v1_unpartitioned/data/00000-0-493d66e1-4bbc-4173-9675-ad5a45ba2cf2.parquet",
            "v1_unpartitioned/data/00000-0-493d66e1-4bbc-4173-9675-ad5a45ba2cf2.parquet",
        ),
        (
            "/bucket/v2_empty/metadata/version-hint.text",
            "v2_empty/metadata/version-hint.text",
        ),
        (
            "/bucket/v1_unpartitioned/metadata/493d66e1-4bbc-4173-9675-ad5a45ba2cf2-m0.avro",
            "v1_unpartitioned/metadata/493d66e1-4bbc-4173-9675-ad5a45ba2cf2-m0.avro",
        ),
    ];
    for (uri, key) in writes {
        let before = state.store.get(BUCKET, key).expect("fixture object exists");
        let response = app
            .clone()
            .oneshot(put_request(uri, Body::from("half-transformed"), &hdrs))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(
            body.contains("<Code>unsupported.table_operation</Code>"),
            "partial processed write must fail with the named error, got: {body}"
        );
        let after = state.store.get(BUCKET, key).expect("fixture object exists");
        assert_eq!(
            after.data, before.data,
            "a rejected partial processed write must not modify the stored table"
        );
    }

    // A processed read of a data file is the same named rejection — never an
    // ordinary (or transformed) object read.
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/bucket/v1_unpartitioned/data/00000-0-493d66e1-4bbc-4173-9675-ad5a45ba2cf2.parquet")
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains("<Code>unsupported.table_operation</Code>"),
        "partial processed read must fail with the named error"
    );

    // Multipart is single-object-only for table units: a multipart create of a
    // table root document fails closed the same way.
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("POST")
                .uri("/bucket/v2_empty/metadata/00001-deadbeef.metadata.json?uploads")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONTENT_LENGTH, "0")
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains("<Code>unsupported.table_operation</Code>"),
        "a multipart create of a table unit must fail with the named error"
    );
}

/// Row: table-root processed read — complete-output staging, no raw fallback,
/// Range and part-number rejected before any walk.
#[tokio::test]
async fn table_root_processed_read_stages_complete_output_without_raw_fallback() {
    let state = iceberg_state(true).await;
    load_fixture(&state, "v2_empty");
    load_fixture(&state, "v1_unpartitioned");
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let app = build_router(state.clone());

    let current = "v2_empty/metadata/00000-2440e43d-7df5-4e36-984c-633a0da038e6.metadata.json";
    let raw = fixture_bytes(
        "v2_empty",
        "metadata/00000-2440e43d-7df5-4e36-984c-633a0da038e6.metadata.json",
    );
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/bucket/{current}"))
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-maskura-iceberg-preview")
            .map(|v| v.to_str().unwrap()),
        Some("1"),
        "the staged output is the commit preview, marked as such"
    );
    assert_hardened_object_headers(response.headers());
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_ne!(
        body.as_ref(),
        raw.as_slice(),
        "the staged output must be the transformed document, never the raw stored bytes"
    );
    let preview: serde_json::Value = serde_json::from_slice(&body).expect("preview is JSON");
    assert!(
        preview.get("current-snapshot-id").is_some(),
        "the preview carries the committed snapshot state"
    );

    // Range and part-number reads are rejected before any walk.
    for (uri, needle) in [
        (
            format!("/bucket/{current}"),
            "Range is not supported for transformed reads",
        ),
        (
            format!("/bucket/{current}?partNumber=1"),
            "part-number reads are not supported for transformed reads",
        ),
    ] {
        let mut builder = Request::builder()
            .method("GET")
            .uri(&uri)
            .header("x-maskura-process", "read");
        if needle.starts_with("Range") {
            builder = builder.header(header::RANGE, "bytes=0-3");
        }
        let response = app
            .clone()
            .oneshot(add_headers(builder.body(Body::empty()).unwrap(), &hdrs))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains(needle),
            "{uri} must reject with {needle:?}"
        );
    }

    // No raw fallback: a table whose data files the production seam cannot
    // transform fails the processed read — it never serves the stored bytes.
    let current =
        "v1_unpartitioned/metadata/00001-b9cfb811-4d98-4720-b065-35c4459734b4.metadata.json";
    let raw = fixture_bytes(
        "v1_unpartitioned",
        "metadata/00001-b9cfb811-4d98-4720-b065-35c4459734b4.metadata.json",
    );
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/bucket/{current}"))
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        ))
        .await
        .unwrap();
    assert!(!response.status().is_success());
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_ne!(
        body.as_ref(),
        raw.as_slice(),
        "a failed processed read must never fall back to the raw stored bytes"
    );
}

/// Row: raw per-object GET/HEAD/byte-range reads are unprocessed passthrough
/// over the stored representation, regardless of the gate.
#[tokio::test]
async fn raw_reads_of_table_units_are_unprocessed_passthrough() {
    // Gate closed: raw reads never consult the table layer or the gate.
    let mut state = iceberg_state(false).await;
    apply_explicit_passthrough(Arc::get_mut(&mut state).expect("test state is uniquely owned"));
    load_fixture(&state, "v2_empty");
    load_fixture(&state, "v2_multi_snapshot");
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let control = Arc::new(RecordingMeteringControl::default());
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .control = control.clone();
    let app = build_router(state.clone());

    // Raw GET of the version pointer returns the stored bytes unchanged.
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/bucket/v2_empty/metadata/version-hint.text")
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], &b"0\n"[..], "raw GET is verbatim");

    // Raw byte-range read of a manifest layer slices the stored bytes.
    let manifest = "v2_multi_snapshot/metadata/ead578b0-ce87-4293-af4f-060194cc737b-m0.avro";
    let stored = fixture_bytes(
        "v2_multi_snapshot",
        "metadata/ead578b0-ce87-4293-af4f-060194cc737b-m0.avro",
    );
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/bucket/{manifest}"))
                .header(header::RANGE, "bytes=0-3")
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        &body[..],
        &stored[..4],
        "a raw byte-range read must slice the stored representation"
    );

    // Raw HEAD of a data file reports the stored object's facts.
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("HEAD")
                .uri("/bucket/v2_multi_snapshot/data/category=red/00000-0-ead578b0-ce87-4293-af4f-060194cc737b.parquet")
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok()),
        Some(
            fixture_bytes(
                "v2_multi_snapshot",
                "data/category=red/00000-0-ead578b0-ce87-4293-af4f-060194cc737b.parquet"
            )
            .len()
        )
    );

    // The recorded usage reuses the exact metering rows of every other raw
    // per-object read (the binary-adapter rows), and the operations are
    // marked *unprocessed*: no filter pipeline ran, so no pipeline evidence
    // is attached.
    let events = control.events.lock().unwrap().clone();
    assert_eq!(events.len(), 3, "GET, ranged GET, and HEAD meter once each");
    assert_eq!(
        events
            .iter()
            .map(|usage| (
                usage.event.kind(),
                usage.event.route(),
                usage.event.output_bytes()
            ))
            .collect::<Vec<_>>(),
        vec![
            (RequestKind::Read, UsageRoute::GetObject, 2),
            (RequestKind::Read, UsageRoute::GetObject, 4),
            (RequestKind::Read, UsageRoute::HeadObject, 0),
        ],
        "raw table-unit reads meter exactly like raw per-object reads"
    );
    assert!(
        events
            .iter()
            .all(|usage| usage.event.pipeline_evidence().is_none()),
        "raw table-unit reads must be marked unprocessed (no filter pipeline)"
    );
}

/// Row: table-root processed write, gate open — the walk + atomic commit run,
/// the policy gate covers the path, and metering reuses the binary-adapter
/// rows (no new metering route).
#[tokio::test]
async fn table_root_processed_write_commits_behind_the_gate_and_reuses_metering() {
    let state = iceberg_state(true).await;
    load_fixture(&state, "v2_empty");
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let control = Arc::new(RecordingMeteringControl::default());
    let gate = Arc::new(RecordingGate::default());
    let mut state = state;
    {
        let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
        state_mut.control = control.clone();
        state_mut.policy_gate = Some(gate.clone());
    }
    let app = build_router(state.clone());

    let source = fixture_bytes(
        "v2_empty",
        "metadata/00000-2440e43d-7df5-4e36-984c-633a0da038e6.metadata.json",
    );
    let source_len = source.len();
    let response = app
        .clone()
        .oneshot(put_request(
            "/bucket/v2_empty/metadata/00001-c0ffee42.metadata.json",
            Body::from(source),
            &hdrs,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the zero-data-file table must walk and commit through the production seam"
    );

    // The commit swapped the version pointer and stored the new document.
    let hint = state
        .store
        .get(BUCKET, "v2_empty/metadata/version-hint.text")
        .expect("version-hint exists");
    assert_eq!(
        &hint.data[..],
        &b"1\n"[..],
        "the atomic commit point is the version-hint pointer swap"
    );
    let committed = state
        .store
        .get(BUCKET, "v2_empty/metadata/00001-c0ffee42.metadata.json")
        .expect("committed metadata document exists");
    let committed: serde_json::Value =
        serde_json::from_slice(&committed.data).expect("committed metadata is JSON");
    assert!(
        committed.get("current-snapshot-id").is_some(),
        "the committed document covers the new snapshot"
    );

    // The table path is behind the same policy gate as every other operation.
    {
        let calls = gate.calls.lock().unwrap();
        assert!(
            calls
                .iter()
                .any(|(operation, key)| *operation == PolicyOperation::Put
                    && key == "v2_empty/metadata/00001-c0ffee42.metadata.json"),
            "the table-root processed write must present Put to the gate; calls: {calls:?}"
        );
    }

    // Metering reuse: the exact same usage rows as the binary adapters —
    // PutObject with source/output bytes, no new metering route.
    let events = control.events.lock().unwrap().clone();
    assert_eq!(events.len(), 1, "the table-root write meters exactly once");
    assert_eq!(events[0].event.route(), UsageRoute::PutObject);
    assert_eq!(events[0].event.kind(), RequestKind::Write);
    assert_eq!(events[0].event.source_bytes(), source_len as u64);
    assert!(
        events[0].event.output_bytes() > 0,
        "the rewritten table state is metered as output"
    );
}
