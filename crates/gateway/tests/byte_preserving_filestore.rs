//! FileStore acceptance for byte-preserving storage scopes (ADR 0036).
//!
//! The reported failure ran against the local FileStore. This test drives the
//! real router with that backend (staged multipart enabled, Iceberg gate
//! open — the hardest case) and verifies:
//!
//! - a first table metadata JSON write is stored byte-for-byte;
//! - a multipart round trip publishes the exact parts;
//! - a failed conditional write leaves the previous object unchanged;
//! - both objects survive a FileStore restart.
//!
//! The Wasm filter component must be built first (`just build-plugins`).

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use maskura_customer_config::Config;
use maskura_customer_config::config::MultipartMode as ConfigMultipartMode;
use maskura_gateway::byte_preserving::BytePreservingScopes;
use maskura_gateway::control::NoopControlPlane;
use maskura_gateway::key_cipher::LocalKeyWrapping;
use maskura_gateway::server::{
    AppState, StatePipelineTemplate, build_router, build_state_with_pipeline_template,
};
use maskura_gateway::workspace_storage::{InMemoryWorkspaceStorageRepository, WorkspaceId};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tower::ServiceExt;

const BUCKET: &str = "warehouse";

const FIRST_METADATA_JSON: &[u8] =
    br#"{ "format-version" : 2,  "location":"s3://warehouse/probe",  "schemas": [] }"#;

fn temp_root() -> PathBuf {
    std::env::temp_dir().join(format!("maskura-byte-preserving-{}", uuid::Uuid::now_v7()))
}

async fn build_state(root: &Path) -> Arc<AppState> {
    let mut config = Config::resolve(None).expect("resolve config");
    config.auth.disabled = false;
    config.storage.mode = Some("local".to_string());
    config.storage.local_dir = Some(root.display().to_string());
    config.storage.single_tenant = true;
    config.storage.s3_endpoint = None;
    config.keys.keys_file = None;
    config.keys.bootstrap_key = None;
    config.features.enable_iceberg = true;
    config.features.multipart_mode = ConfigMultipartMode::Staged;
    config.spool.dir = Some(root.join("spool").display().to_string());
    let template = StatePipelineTemplate::from_config_with_executor(
        &config,
        maskura_wasm_runtime::ExecutorConfig {
            workers: 8,
            queue_capacity: 64,
            guest_memory_budget_bytes: 4 * 1024 * 1024 * 1024,
        },
    )
    .expect("compile test pipeline");
    let mut state = build_state_with_pipeline_template(
        Arc::new(NoopControlPlane),
        Arc::new(LocalKeyWrapping::with_kek([0x42; 32])),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        &template,
        &config,
    )
    .await
    .expect("build FileStore state");
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .byte_preserving =
        BytePreservingScopes::parse(Some(BUCKET)).expect("valid scope configuration");
    state
}

async fn credentials(state: &Arc<AppState>) -> Vec<(&'static str, String)> {
    let (secret, created) = state
        .keys
        .create_key(
            "demo-user",
            &WorkspaceId::new("demo-user").unwrap(),
            "byte-preserving",
            0,
            None,
        )
        .await
        .expect("create API key");
    vec![
        ("x-maskura-access-key", created.key_id),
        ("x-maskura-secret-key", secret),
    ]
}

fn add_headers(request: Request<Body>, headers: &[(&'static str, String)]) -> Request<Body> {
    let (mut parts, body) = request.into_parts();
    for (name, value) in headers {
        parts.headers.insert(*name, value.parse().unwrap());
    }
    Request::from_parts(parts, body)
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body")
        .to_vec()
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

async fn put(
    app: &Router,
    uri: &str,
    content_type: &str,
    body: &[u8],
    headers: &[(&'static str, String)],
) -> axum::response::Response {
    app.clone()
        .oneshot(add_headers(
            Request::builder()
                .method("PUT")
                .uri(uri)
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(body.to_vec()))
                .unwrap(),
            headers,
        ))
        .await
        .unwrap()
}

async fn get(app: &Router, uri: &str, headers: &[(&'static str, String)]) -> Vec<u8> {
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
            headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "GET {uri}");
    body_bytes(response).await
}

#[tokio::test]
async fn catalog_objects_round_trip_through_the_filestore_and_survive_restart() {
    let root = temp_root();
    let state = build_state(&root).await;
    state
        .file_store
        .as_ref()
        .expect("local FileStore")
        .create_bucket(BUCKET)
        .await
        .expect("create bucket");
    let app = build_router(state.clone());
    let headers = credentials(&state).await;

    let metadata_uri = format!("/{BUCKET}/probe/metadata/00000-probe.metadata.json");
    let response = put(
        &app,
        &metadata_uri,
        "application/octet-stream",
        FIRST_METADATA_JSON,
        &headers,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "first metadata write with the Iceberg gate open"
    );

    // Multipart round trip in the same scope: the object is the concatenated
    // part bytes, with no table or format processing.
    let multipart_uri = format!("/{BUCKET}/probe/data/00000-0-x.parquet");
    let part_body: Vec<u8> = b"PAR1multipart-catalog-bytes".to_vec();
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("{multipart_uri}?uploads"))
                .body(Body::empty())
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "create multipart");
    let upload_id = extract_xml(
        &String::from_utf8_lossy(&body_bytes(response).await),
        "UploadId",
    );
    assert!(!upload_id.is_empty());

    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("PUT")
                .uri(format!("{multipart_uri}?uploadId={upload_id}&partNumber=1"))
                .header(header::CONTENT_TYPE, "application/vnd.apache.parquet")
                .header(header::CONTENT_LENGTH, part_body.len().to_string())
                .body(Body::from(part_body.clone()))
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();
    let status = response.status();
    if status != StatusCode::OK {
        panic!(
            "upload part returned {status}: {}",
            String::from_utf8_lossy(&body_bytes(response).await)
        );
    }
    let part_etag = response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("part ETag")
        .to_string();

    let complete = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{part_etag}</ETag></Part></CompleteMultipartUpload>"
    );
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("{multipart_uri}?uploadId={upload_id}"))
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(complete))
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "complete multipart: {}",
        String::from_utf8_lossy(&body_bytes(response).await)
    );

    assert_eq!(
        get(&app, &metadata_uri, &headers).await,
        FIRST_METADATA_JSON
    );
    assert_eq!(get(&app, &multipart_uri, &headers).await, part_body);

    // A failed conditional write leaves the previous object unchanged.
    let mut conditional = headers.clone();
    conditional.push(("if-none-match", "*".to_string()));
    let response = put(
        &app,
        &metadata_uri,
        "application/octet-stream",
        b"{\"format-version\":2}",
        &conditional,
    )
    .await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        get(&app, &metadata_uri, &headers).await,
        FIRST_METADATA_JSON
    );

    // The same contract applies to a conditional multipart completion.
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("{multipart_uri}?uploads"))
                .body(Body::empty())
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let second_upload = extract_xml(
        &String::from_utf8_lossy(&body_bytes(response).await),
        "UploadId",
    );
    let replacement = b"PAR1replacement".to_vec();
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "{multipart_uri}?uploadId={second_upload}&partNumber=1"
                ))
                .header(header::CONTENT_TYPE, "application/vnd.apache.parquet")
                .header(header::CONTENT_LENGTH, replacement.len().to_string())
                .body(Body::from(replacement.clone()))
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let replacement_etag = response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("part ETag")
        .to_string();
    let complete = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{replacement_etag}</ETag></Part></CompleteMultipartUpload>"
    );
    let mut conditional_complete = headers.clone();
    conditional_complete.push(("if-none-match", "*".to_string()));
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("{multipart_uri}?uploadId={second_upload}"))
                .header(header::CONTENT_TYPE, "application/xml")
                .body(Body::from(complete))
                .unwrap(),
            &conditional_complete,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::PRECONDITION_FAILED,
        "conditional multipart completion must not replace the object"
    );
    assert_eq!(get(&app, &multipart_uri, &headers).await, part_body);

    // Restart the FileStore over the same root: both objects survive.
    drop(app);
    drop(state);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let state = build_state(&root).await;
    let app = build_router(state.clone());
    let headers = credentials(&state).await;
    assert_eq!(
        get(&app, &metadata_uri, &headers).await,
        FIRST_METADATA_JSON,
        "metadata survives restart"
    );
    assert_eq!(
        get(&app, &multipart_uri, &headers).await,
        part_body,
        "multipart data survives restart"
    );

    drop(app);
    drop(state);
    std::fs::remove_dir_all(&root).ok();
}
