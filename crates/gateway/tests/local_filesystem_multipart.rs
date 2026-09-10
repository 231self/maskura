//! Standalone local-filesystem multipart lifecycle over real HTTP.
//!
//! Task 14 of `docs/plans/2026-09-08-local-filesystem-multipart-phase-2.md`:
//! one temporary root, no Postgres (`DATABASE_URL`), no external S3 endpoint,
//! no cloud credentials, no configured KEK, and no staging bucket. The gateway
//! is built with `MASKURA_STORAGE_MODE=local` +
//! `MASKURA_MULTIPART_MODE=staged`, so `MultipartPersistenceMode::LocalStaged`
//! wires the durable `LocalStorageRuntime` root lock, `FileStore`,
//! `FileMultipartRepository`, file wrapping key, operation journal, file
//! artifacts, and the `MultipartCompletionCoordinator` with file proofs.
//!
//! The Wasm filter component must be built first (`just build-plugins`).

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use maskura_gateway::control::NoopControlPlane;
use maskura_gateway::key_cipher::default_wrapping;
use maskura_gateway::server::{
    AppState, StatePipelineTemplate, build_router, build_state_with_pipeline_template,
};
use maskura_gateway::workspace_storage::{InMemoryWorkspaceStorageRepository, WorkspaceId};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use uuid::Uuid;

/// Every test in this binary mutates the process environment, so all state
/// building is serialized behind one lock. Tests must acquire it before any
/// `std::env` mutation and hold it until every router/state is dropped.
static ENV_LOCK: Mutex<()> = Mutex::new(());

const PLAINTEXT_EMAIL_A: &str = "alice@example.com";
const PLAINTEXT_EMAIL_B: &str = "bob@example.org";
const CLASSIFIED_PHRASE: &str = "classified@corp.example";
/// Every raw marker is an email-like secret; after the pipeline runs, the raw
/// bytes must never be observable anywhere under the storage root.
const RAW_MARKERS: [&str; 3] = [PLAINTEXT_EMAIL_A, PLAINTEXT_EMAIL_B, CLASSIFIED_PHRASE];

const PART_ONE_MARKER: &str = "PART-ONE-SEGMENT";
const PART_THREE_MARKER: &str = "PART-THREE-V2";
const REDACTED_EMAIL: &str = "[REDACTED_EMAIL]";

const NON_FINAL_MIN_BYTES: usize = 5 * 1024 * 1024;

struct EnvRestore {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvRestore {
    fn new() -> Self {
        Self { saved: Vec::new() }
    }

    fn capture(&mut self, name: &'static str) {
        if !self.saved.iter().any(|(saved, _)| *saved == name) {
            let previous = std::env::var(name).ok();
            self.saved.push((name, previous));
        }
    }

    fn remove(&mut self, name: &'static str) {
        self.capture(name);
        // SAFETY: edition-2024 marks these process-global mutations unsafe, and
        // every test in this binary is serialized behind `ENV_LOCK`.
        unsafe { std::env::remove_var(name) };
    }

    fn set(&mut self, name: &'static str, value: &str) {
        self.capture(name);
        // SAFETY: same serialization as `remove`.
        unsafe { std::env::set_var(name, value) };
    }

    fn restore(&mut self) {
        for (name, previous) in self.saved.drain(..).rev() {
            // SAFETY: the env lock is still held while restoring.
            unsafe {
                match previous {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Clears every host-side configuration the test must not inherit.
fn remove_host_configuration(env: &mut EnvRestore) {
    for name in [
        "DATABASE_URL",
        "S3_ENDPOINT",
        "MASKURA_SECRET_KEK",
        "MASKURA_SERVICE_BUCKETS",
        "S3_ACCESS_KEY_ID",
        "S3_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "MASKURA_KEYS_FILE",
        "MASKURA_DEFAULT_PLUGIN",
        "MASKURA_MULTIPART_STAGING_DIR",
        "MASKURA_MULTIPART_STAGING_ENDPOINT",
        "MASKURA_MULTIPART_STAGING_BUCKET",
        "MASKURA_MULTIPART_STAGING_ACCESS_KEY_ID",
        "MASKURA_MULTIPART_STAGING_SECRET_ACCESS_KEY",
        "MASKURA_MULTIPART_STAGING_REGION",
        "MASKURA_MULTIPART_STAGING_TENANT_QUOTA_BYTES",
        "MASKURA_MULTIPART_STAGING_GLOBAL_QUOTA_BYTES",
        "MASKURA_DEV_MEMORY_STREAMING",
        "MASKURA_SPOOL_DIR",
        "MASKURA_TRANSFORMED_READ_SPOOL",
        "MASKURA_MANAGED_STREAMING_MODE",
        "MASKURA_MANAGED_STREAMING_TRANSACTIONAL",
    ] {
        env.remove(name);
    }
}

fn auth_headers(access_key: &str, secret_key: &str) -> Vec<(&'static str, String)> {
    vec![
        ("x-maskura-access-key", access_key.to_string()),
        ("x-maskura-secret-key", secret_key.to_string()),
    ]
}

fn add_headers(request: Request<Body>, headers: &[(&'static str, String)]) -> Request<Body> {
    let (mut parts, body) = request.into_parts();
    for (name, value) in headers {
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

fn occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body")
        .to_vec()
}

async fn build_isolated_state() -> anyhow::Result<Arc<AppState>> {
    let pipeline_template = StatePipelineTemplate::from_env()?;
    build_state_with_pipeline_template(
        Arc::new(NoopControlPlane),
        default_wrapping()?,
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        &pipeline_template,
    )
    .await
}

async fn build_test_state() -> Arc<AppState> {
    build_isolated_state()
        .await
        .expect("build local-filesystem multipart state")
}

async fn make_credentials(state: &Arc<AppState>) -> (String, String) {
    let workspace = state
        .workspace_storage
        .resolve_workspace("demo-user")
        .await
        .expect("resolve demo workspace");
    let (secret, created) = state
        .keys
        .create_key(
            "demo-user",
            &WorkspaceId::new("demo-user").unwrap(),
            "local-multipart",
            0,
            None,
        )
        .await
        .expect("create test API key");
    assert_eq!(created.workspace_id.as_deref(), Some(workspace.as_str()));
    (created.key_id, secret)
}

fn part_one_body() -> Vec<u8> {
    let mut part = String::from(PART_ONE_MARKER);
    part.push('\n');
    part.push_str("first record contact ");
    part.push_str(PLAINTEXT_EMAIL_A);
    part.push_str(" now\nclassified line ");
    part.push_str(CLASSIFIED_PHRASE);
    part.push('\n');
    let filler_line = format!("{}\n", "x".repeat(100));
    while part.len() < NON_FINAL_MIN_BYTES.saturating_add(256) {
        part.push_str(&filler_line);
    }
    part.push('\n');
    part.into_bytes()
}

fn part_three_v1_body() -> Vec<u8> {
    format!("PART-THREE-V1\ncontact {PLAINTEXT_EMAIL_A} now\n").into_bytes()
}

fn part_three_v2_body() -> Vec<u8> {
    format!("PART-THREE-V2\ncontact {PLAINTEXT_EMAIL_B} now\n").into_bytes()
}

fn abort_part_body() -> Vec<u8> {
    format!("abort-part contact {PLAINTEXT_EMAIL_B} now\n").into_bytes()
}

fn complete_xml(parts: &[(u32, &str)]) -> String {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (number, etag) in parts {
        xml.push_str(&format!(
            "<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    xml
}

async fn upload_part(
    app: &Router,
    headers: &[(&'static str, String)],
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    body: &[u8],
) -> String {
    let request = add_headers(
        Request::builder()
            .method("PUT")
            .uri(format!(
                "/{bucket}/{key}?partNumber={part_number}&uploadId={upload_id}"
            ))
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CONTENT_LENGTH, body.len().to_string())
            .body(Body::from(body.to_vec()))
            .unwrap(),
        headers,
    );
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    if status != StatusCode::OK {
        let body = String::from_utf8_lossy(&body_bytes(response).await).to_string();
        panic!("UploadPart {part_number} into {upload_id} returned {status}: {body}");
    }
    response
        .headers()
        .get(header::ETAG)
        .expect("UploadPart ETag")
        .to_str()
        .expect("UploadPart ETag header text")
        .to_string()
}

async fn initiate_upload(
    app: &Router,
    headers: &[(&'static str, String)],
    bucket: &str,
    key: &str,
) -> String {
    initiate_upload_with_metadata(app, headers, bucket, key, &[]).await
}

async fn initiate_upload_with_metadata(
    app: &Router,
    headers: &[(&'static str, String)],
    bucket: &str,
    key: &str,
    metadata: &[(&'static str, &'static str)],
) -> String {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/{bucket}/{key}?uploads"))
        .header(header::CONTENT_TYPE, "text/plain");
    for (name, value) in metadata {
        builder = builder.header(*name, *value);
    }
    let request = add_headers(builder.body(Body::empty()).unwrap(), headers);
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "CreateMultipartUpload for {bucket}/{key}"
    );
    let xml = String::from_utf8(body_bytes(response).await).expect("initiate XML is utf-8");
    assert!(xml.contains("InitiateMultipartUploadResult"), "{xml}");
    let upload_id = extract_xml(&xml, "UploadId");
    assert!(!upload_id.is_empty(), "{xml}");
    upload_id
}

fn get_request(headers: &[(&'static str, String)], method: &str, uri: &str) -> Request<Body> {
    add_headers(
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
        headers,
    )
}

fn get_request_with_checksum_mode(
    headers: &[(&'static str, String)],
    method: &str,
    uri: &str,
) -> Request<Body> {
    let request = get_request(headers, method, uri);
    let mut builder = Request::builder()
        .method(request.method().clone())
        .uri(request.uri().clone());
    for (name, value) in request.headers() {
        builder = builder.header(name, value);
    }
    builder
        .header("x-amz-checksum-mode", "ENABLED")
        .body(Body::empty())
        .unwrap()
}

async fn get_status_and_text(
    app: &Router,
    headers: &[(&'static str, String)],
    method: &str,
    uri: &str,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(get_request(headers, method, uri))
        .await
        .unwrap();
    let status = response.status();
    let body = String::from_utf8(body_bytes(response).await).expect("response body is utf-8");
    (status, body)
}

fn assert_plaintext_never_leaks(text: &str) {
    for marker in RAW_MARKERS {
        assert!(
            !text.contains(marker),
            "raw marker {marker:?} must never be stored"
        );
    }
}

fn assert_headers_echoed(
    headers: &axum::http::HeaderMap,
    expected_etag: &str,
    expected_checksum_sha256: bool,
) {
    assert_eq!(
        headers
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok()),
        Some(expected_etag),
        "object ETag"
    );
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/plain"),
        "content type"
    );
    assert_eq!(
        headers
            .get("x-amz-meta-project")
            .and_then(|value| value.to_str().ok()),
        Some("alpha"),
        "x-amz-meta-project propagation"
    );
    assert_eq!(
        headers
            .get("x-amz-tagging")
            .and_then(|value| value.to_str().ok()),
        Some("team=data"),
        "x-amz-tagging propagation"
    );
    let checksum = headers
        .get("x-amz-checksum-sha256")
        .and_then(|value| value.to_str().ok());
    assert_eq!(
        checksum.is_some(),
        expected_checksum_sha256,
        "x-amz-checksum-sha256 propagation"
    );
    if expected_checksum_sha256 {
        assert_eq!(checksum.map(str::len), Some(64), "sha256 is hex encoded");
    }
}

fn assert_list_parts_full(xml: &str) {
    assert!(xml.contains("<ListPartsResult"), "{xml}");
    assert!(xml.contains("<PartNumber>1</PartNumber>"), "{xml}");
    assert!(xml.contains("<PartNumber>3</PartNumber>"), "{xml}");
    assert!(
        xml.contains("<PartNumberMarker>0</PartNumberMarker>"),
        "{xml}"
    );
    assert!(xml.contains("<MaxParts>1000</MaxParts>"), "{xml}");
    assert!(xml.contains("<IsTruncated>false</IsTruncated>"), "{xml}");
}

fn collect_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Drives the complete client-visible lifecycle, drops the first gateway,
/// restarts on the same root, verifies durability, then inspects every file
/// under the root for plaintext markers.
///
/// A synchronous `#[test]` holds the process-env lock while the tokio runtime
/// drives the async lifecycle, so the `std::sync::Mutex` guard is never held
/// across an `.await` in the same async body (clippy `await_holding_lock`).
#[test]
fn local_filesystem_multipart_lifecycle_over_http() {
    let _guard = ENV_LOCK.lock().expect("env lock poisoned");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build test tokio runtime");
    runtime.block_on(run_single_lifecycle());
}

async fn run_single_lifecycle() {
    let root = std::env::temp_dir().join(format!("maskura-local-multipart-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root).expect("create temporary storage root");

    let mut env = EnvRestore::new();
    remove_host_configuration(&mut env);
    env.set("AUTH_DISABLED", "0");
    env.set("MASKURA_SINGLE_TENANT", "1");
    env.set("MASKURA_STORAGE_MODE", "local");
    env.set("MASKURA_LOCAL_STORAGE_DIR", &root.to_string_lossy());
    env.set("MASKURA_MULTIPART_MODE", "staged");
    env.set("MASKURA_STREAMING_READ_MODE", "passthrough");
    let components = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/components");
    assert!(
        components.is_dir(),
        "built filter components missing at {}; run `just build-plugins`",
        components.display()
    );

    run_lifecycle(&root).await;

    drop(env);
    let _ = std::fs::remove_dir_all(&root);
}

async fn run_lifecycle(root: &Path) {
    let state = build_test_state().await;
    let app = build_router(state.clone());
    let (access_key, secret_key) = make_credentials(&state).await;
    let headers = auth_headers(&access_key, &secret_key);

    let bucket = "bucket-main";
    let object_key = "final.txt";
    let aborted_key = "aborted.txt";
    let list_bucket = "bucket-list";

    // ---- Phase 1: initiate -------------------------------------------------
    let upload_id = initiate_upload_with_metadata(
        &app,
        &headers,
        bucket,
        object_key,
        &[
            ("x-amz-meta-project", "alpha"),
            ("x-amz-tagging", "team=data"),
            ("x-amz-checksum-algorithm", "SHA256"),
        ],
    )
    .await;

    // ---- Phase 2: out-of-order parts with replacement ----------------------
    // Part 3 first, then part 1, then part 3 again with different content.
    let part_one = part_one_body();
    assert!(
        part_one.len() >= NON_FINAL_MIN_BYTES,
        "the non-final part must satisfy the five MiB minimum"
    );

    let etag_three_v1 = upload_part(
        &app,
        &headers,
        bucket,
        object_key,
        &upload_id,
        3,
        &part_three_v1_body(),
    )
    .await;
    let etag_one = upload_part(&app, &headers, bucket, object_key, &upload_id, 1, &part_one).await;
    let etag_three_v2 = upload_part(
        &app,
        &headers,
        bucket,
        object_key,
        &upload_id,
        3,
        &part_three_v2_body(),
    )
    .await;
    assert_ne!(
        etag_three_v1, etag_three_v2,
        "replaced part must change ETag"
    );

    // ---- Phase 3: ListParts ------------------------------------------------
    let (status, list_xml) = get_status_and_text(
        &app,
        &headers,
        "GET",
        &format!("/{bucket}/{object_key}?uploadId={upload_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{list_xml}");
    assert_list_parts_full(&list_xml);

    let (status, page_one) = get_status_and_text(
        &app,
        &headers,
        "GET",
        &format!("/{bucket}/{object_key}?uploadId={upload_id}&max-parts=1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page_one}");
    assert!(
        page_one.contains("<PartNumber>1</PartNumber>"),
        "{page_one}"
    );
    assert!(
        !page_one.contains("<PartNumber>3</PartNumber>"),
        "{page_one}"
    );
    assert!(
        page_one.contains("<IsTruncated>true</IsTruncated>"),
        "{page_one}"
    );
    assert_eq!(
        extract_xml(&page_one, "NextPartNumberMarker"),
        "1",
        "{page_one}"
    );

    let (status, page_two) = get_status_and_text(
        &app,
        &headers,
        "GET",
        &format!("/{bucket}/{object_key}?uploadId={upload_id}&max-parts=1&part-number-marker=1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page_two}");
    assert!(
        !page_two.contains("<PartNumber>1</PartNumber>"),
        "{page_two}"
    );
    assert!(
        page_two.contains("<PartNumber>3</PartNumber>"),
        "{page_two}"
    );
    assert!(
        page_two.contains("<IsTruncated>false</IsTruncated>"),
        "{page_two}"
    );

    // ---- Phase 4: ListMultipartUploads -------------------------------------
    let alpha_key = "docs/alpha.txt";
    let beta_key = "docs/beta.txt";
    let alpha_upload_id = initiate_upload(&app, &headers, list_bucket, alpha_key).await;
    let beta_upload_id = initiate_upload(&app, &headers, list_bucket, beta_key).await;

    let (status, list_uploads) =
        get_status_and_text(&app, &headers, "GET", &format!("/{list_bucket}?uploads")).await;
    assert_eq!(status, StatusCode::OK, "{list_uploads}");
    assert!(
        list_uploads.contains("<ListMultipartUploadsResult xmlns="),
        "{list_uploads}"
    );
    assert_eq!(
        occurrences(&list_uploads, "<Upload><Key>"),
        2,
        "{list_uploads}"
    );
    assert!(
        list_uploads.contains(&format!("<Key>{alpha_key}</Key>")),
        "{list_uploads}"
    );
    assert!(
        list_uploads.contains(&format!("<Key>{beta_key}</Key>")),
        "{list_uploads}"
    );
    assert!(
        list_uploads.contains(&format!("<UploadId>{alpha_upload_id}</UploadId>")),
        "{list_uploads}"
    );
    assert!(
        list_uploads.contains(&format!("<UploadId>{beta_upload_id}</UploadId>")),
        "{list_uploads}"
    );
    assert_eq!(
        occurrences(&list_uploads, "<StorageClass>STANDARD</StorageClass>"),
        2,
        "{list_uploads}"
    );
    assert!(list_uploads.contains("<Initiated>"), "{list_uploads}");
    assert!(
        list_uploads.contains("<IsTruncated>false</IsTruncated>"),
        "{list_uploads}"
    );

    let (status, prefixed) = get_status_and_text(
        &app,
        &headers,
        "GET",
        &format!("/{list_bucket}?uploads&prefix=docs/"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{prefixed}");
    assert_eq!(occurrences(&prefixed, "<Upload><Key>"), 2, "{prefixed}");

    // First page truncates to alpha and returns continuation markers.
    let (status, first_page) = get_status_and_text(
        &app,
        &headers,
        "GET",
        &format!("/{list_bucket}?uploads&prefix=docs/&max-uploads=1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first_page}");
    assert!(
        first_page.contains(&format!("<Key>{alpha_key}</Key>")),
        "{first_page}"
    );
    assert!(
        !first_page.contains(&format!("<Key>{beta_key}</Key>")),
        "{first_page}"
    );
    assert!(
        first_page.contains("<IsTruncated>true</IsTruncated>"),
        "{first_page}"
    );
    assert_eq!(
        extract_xml(&first_page, "NextKeyMarker"),
        alpha_key,
        "{first_page}"
    );
    assert_eq!(
        extract_xml(&first_page, "NextUploadIdMarker"),
        alpha_upload_id,
        "{first_page}"
    );

    // Second page resumes with key-marker and upload-id-marker.
    let (status, second_page) = get_status_and_text(
        &app,
        &headers,
        "GET",
        &format!(
            "/{list_bucket}?uploads&prefix=docs/&max-uploads=1&key-marker={alpha_key}&upload-id-marker={alpha_upload_id}"
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{second_page}");
    assert!(
        !second_page.contains(&format!("<Key>{alpha_key}</Key>")),
        "{second_page}"
    );
    assert!(
        second_page.contains(&format!("<Key>{beta_key}</Key>")),
        "{second_page}"
    );
    assert!(
        second_page.contains("<IsTruncated>false</IsTruncated>"),
        "{second_page}"
    );

    // ---- Phase 5: completion ------------------------------------------------
    let completion = complete_xml(&[(1, &etag_one), (3, &etag_three_v2)]);
    let request = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/{bucket}/{object_key}?uploadId={upload_id}"))
            .body(Body::from(completion.clone()))
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(request).await.unwrap();
    let complete_status = response.status();
    let complete_body = String::from_utf8(body_bytes(response).await).expect("completion XML");
    assert_eq!(
        complete_status,
        StatusCode::OK,
        "CompleteMultipartUpload: {complete_body}"
    );
    assert!(
        complete_body.contains("CompleteMultipartUploadResult"),
        "{complete_body}"
    );
    let completed_etag = extract_xml(&complete_body, "ETag");
    assert!(!completed_etag.is_empty(), "{complete_body}");

    // ---- Phase 6: GET / HEAD of the assembled object ------------------------
    let get_response = app
        .clone()
        .oneshot(get_request_with_checksum_mode(
            &headers,
            "GET",
            &format!("/{bucket}/{object_key}"),
        ))
        .await
        .unwrap();
    assert_eq!(
        get_response.status(),
        StatusCode::OK,
        "GET assembled object"
    );
    let get_headers = get_response.headers().clone();
    let completed_body = body_bytes(get_response).await;
    let completed_text = String::from_utf8_lossy(&completed_body).to_string();
    assert_headers_echoed(&get_headers, &completed_etag, true);
    assert_plaintext_never_leaks(&completed_text);
    assert!(completed_text.contains(REDACTED_EMAIL), "{completed_text}");
    assert!(
        completed_text.contains(PART_ONE_MARKER),
        "part one content present: {completed_text}"
    );
    assert!(
        completed_text.contains(PART_THREE_MARKER),
        "replacement part three content present: {completed_text}"
    );
    let one = completed_text.find(PART_ONE_MARKER).expect("marker one");
    let three = completed_text
        .find(PART_THREE_MARKER)
        .expect("marker three");
    assert!(one < three, "parts assembled in part-number order");

    let head_response = app
        .clone()
        .oneshot(get_request_with_checksum_mode(
            &headers,
            "HEAD",
            &format!("/{bucket}/{object_key}"),
        ))
        .await
        .unwrap();
    assert_eq!(
        head_response.status(),
        StatusCode::OK,
        "HEAD assembled object"
    );
    assert_headers_echoed(head_response.headers(), &completed_etag, true);

    // ---- Phase 7: exact replay and conflicting completion -------------------
    let replay = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/{bucket}/{object_key}?uploadId={upload_id}"))
            .body(Body::from(completion.clone()))
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(replay).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "exact completion replay");
    let replay_body = String::from_utf8(body_bytes(response).await).expect("replay XML");
    assert_eq!(
        extract_xml(&replay_body, "ETag"),
        completed_etag,
        "{replay_body}"
    );

    let conflicting = complete_xml(&[(1, &etag_one), (3, &etag_three_v1)]);
    let conflict = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/{bucket}/{object_key}?uploadId={upload_id}"))
            .body(Body::from(conflicting))
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(conflict).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "conflicting completion"
    );
    let conflict_body = String::from_utf8(body_bytes(response).await).expect("conflict XML");
    assert!(
        conflict_body.contains("conflicting CompleteMultipartUpload request")
            || conflict_body.contains("InvalidPart"),
        "{conflict_body}"
    );

    // The conflict must not corrupt the committed object.
    let get_after_conflict = app
        .clone()
        .oneshot(get_request(
            &headers,
            "GET",
            &format!("/{bucket}/{object_key}"),
        ))
        .await
        .unwrap();
    assert_eq!(get_after_conflict.status(), StatusCode::OK);
    assert_eq!(body_bytes(get_after_conflict).await, completed_body);

    // ---- Phase 8: abort flow ------------------------------------------------
    let abort_upload_id = initiate_upload(&app, &headers, bucket, aborted_key).await;
    let _abort_etag = upload_part(
        &app,
        &headers,
        bucket,
        aborted_key,
        &abort_upload_id,
        1,
        &abort_part_body(),
    )
    .await;

    let delete = add_headers(
        Request::builder()
            .method("DELETE")
            .uri(format!(
                "/{bucket}/{aborted_key}?uploadId={abort_upload_id}"
            ))
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(delete).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "AbortMultipartUpload"
    );

    // The aborted upload resolves as a terminal record with no parts until its
    // tombstone retires.
    let (status, aborted_parts) = get_status_and_text(
        &app,
        &headers,
        "GET",
        &format!("/{bucket}/{aborted_key}?uploadId={abort_upload_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{aborted_parts}");
    assert!(!aborted_parts.contains("<PartNumber>"), "{aborted_parts}");

    // A never-created upload id reports NoSuchUpload.
    let ghost_id = Uuid::now_v7().to_string();
    let (status, ghost_parts) = get_status_and_text(
        &app,
        &headers,
        "GET",
        &format!("/{bucket}/{aborted_key}?uploadId={ghost_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{ghost_parts}");
    assert!(ghost_parts.contains("NoSuchUpload"), "{ghost_parts}");

    // A second abort is idempotent (the already-Aborted lifecycle is a no-op).
    let delete = add_headers(
        Request::builder()
            .method("DELETE")
            .uri(format!(
                "/{bucket}/{aborted_key}?uploadId={abort_upload_id}"
            ))
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(delete).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "repeat abort");

    // The completed object is unaffected by the abort.
    let get_after_abort = app
        .clone()
        .oneshot(get_request(
            &headers,
            "GET",
            &format!("/{bucket}/{object_key}"),
        ))
        .await
        .unwrap();
    assert_eq!(get_after_abort.status(), StatusCode::OK);
    assert_eq!(body_bytes(get_after_abort).await, completed_body);

    // The aborted upload no longer appears in ListMultipartUploads.
    let (status, main_list) =
        get_status_and_text(&app, &headers, "GET", &format!("/{bucket}?uploads")).await;
    assert_eq!(status, StatusCode::OK, "{main_list}");
    assert!(!main_list.contains("<Upload><Key>"), "{main_list}");
    assert!(
        main_list.contains("<IsTruncated>false</IsTruncated>"),
        "{main_list}"
    );

    drop(app);
    drop(state);

    // ---- Phase 9: restart on the same root ----------------------------------
    // Dropping the last Arc<AppState> releases the LocalStorageRuntime root
    // lock; rebuild a fresh router/state on the same directory.
    let restarted_state = build_test_state().await;
    let restarted_app = build_router(restarted_state.clone());

    let (status, restarted_get) = get_status_and_text(
        &restarted_app,
        &headers,
        "GET",
        &format!("/{bucket}/{object_key}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{restarted_get}");
    assert_eq!(restarted_get, completed_text);
    assert_plaintext_never_leaks(&restarted_get);
    assert!(restarted_get.contains(REDACTED_EMAIL), "{restarted_get}");

    let head_after_restart = restarted_app
        .clone()
        .oneshot(get_request_with_checksum_mode(
            &headers,
            "HEAD",
            &format!("/{bucket}/{object_key}"),
        ))
        .await
        .unwrap();
    assert_eq!(head_after_restart.status(), StatusCode::OK);
    assert_headers_echoed(head_after_restart.headers(), &completed_etag, true);

    // The completed and aborted uploads are not listed after restart; the still
    // open uploads in the list bucket persist.
    let (status, main_list) = get_status_and_text(
        &restarted_app,
        &headers,
        "GET",
        &format!("/{bucket}?uploads"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{main_list}");
    assert!(!main_list.contains("<Upload><Key>"), "{main_list}");

    let (status, docs_list) = get_status_and_text(
        &restarted_app,
        &headers,
        "GET",
        &format!("/{list_bucket}?uploads&prefix=docs/"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{docs_list}");
    assert_eq!(occurrences(&docs_list, "<Upload><Key>"), 2, "{docs_list}");

    let (status, aborted_after) = get_status_and_text(
        &restarted_app,
        &headers,
        "GET",
        &format!("/{bucket}/{aborted_key}?uploadId={abort_upload_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{aborted_after}");
    assert!(!aborted_after.contains("<PartNumber>"), "{aborted_after}");

    // ---- Phase 10: filesystem inspection ------------------------------------
    // Every file under the root -- object data, metadata, artifacts, snapshots,
    // journal events, commit proofs, keys, and the wrapping key -- must never
    // contain a raw marker. The completed object data file stores the redacted
    // representation and must byte-match what GET returned.
    assert!(root.join(".maskura").is_dir(), ".maskura root exists");

    let mut files = Vec::new();
    collect_files(root, &mut files);
    assert!(!files.is_empty(), "storage root is populated");

    let mut object_data_files = Vec::new();
    for path in &files {
        let bytes = std::fs::read(path).expect("read file under root");
        for marker in RAW_MARKERS {
            assert!(
                !contains_bytes(&bytes, marker.as_bytes()),
                "plaintext marker {marker:?} leaked into {}",
                path.display()
            );
        }
        if contains_bytes(&bytes, REDACTED_EMAIL.as_bytes()) {
            object_data_files.push((path.clone(), bytes));
        }
    }

    assert_eq!(
        object_data_files.len(),
        1,
        "exactly one completed object data file holds the redacted body"
    );
    let (object_data_path, object_data) = &object_data_files[0];
    assert_eq!(
        object_data.as_slice(),
        completed_body.as_slice(),
        "object data file matches GET body at {}",
        object_data_path.display()
    );

    drop(restarted_app);
    drop(restarted_state);
}

#[test]
fn local_multipart_restart_matrix_keeps_completed_object_atomic() {
    let _guard = ENV_LOCK.lock().expect("env lock poisoned");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build test tokio runtime");
    runtime.block_on(run_restart_matrix());
}

/// Task 15 crash/retirement matrix over real HTTP: an existing object is
/// atomically replaced by multipart completion, then every durable boundary
/// that follows (completion result, exact replay, second restart) is crossed
/// with a full state rebuild from the same root. GET must always observe
/// exactly one complete version of the object -- never the prior body, a
/// partial assembly, or a torn publish.
async fn run_restart_matrix() {
    let root = std::env::temp_dir().join(format!("maskura-local-matrix-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root).expect("create temporary storage root");

    let mut env = EnvRestore::new();
    remove_host_configuration(&mut env);
    env.set("AUTH_DISABLED", "0");
    env.set("MASKURA_SINGLE_TENANT", "1");
    env.set("MASKURA_STORAGE_MODE", "local");
    env.set("MASKURA_LOCAL_STORAGE_DIR", &root.to_string_lossy());
    env.set("MASKURA_MULTIPART_MODE", "staged");
    env.set("MASKURA_STREAMING_READ_MODE", "passthrough");
    let components = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/components");
    assert!(
        components.is_dir(),
        "built filter components missing at {}; run `just build-plugins`",
        components.display()
    );

    let bucket = "bucket-main";
    let key = "matrix.txt";
    let prior_body = "PRIOR-EXACT-VERSION\n".as_bytes().to_vec();
    let replacement = format!("PART-NEW-VERSION\ncontact {PLAINTEXT_EMAIL_A} now\n").into_bytes();
    let (state, app, access_key, secret_key) = build_local_state().await;
    let headers = auth_headers(&access_key, &secret_key);

    // A completed single PUT installs the object that multipart completion must
    // atomically replace without ever exposing a partial assembly.
    let put_response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("PUT")
                .uri(format!("/{bucket}/{key}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .header(header::CONTENT_LENGTH, prior_body.len().to_string())
                .body(Body::from(prior_body.clone()))
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(put_response.status(), StatusCode::OK, "prior single PUT");

    let (status, first_get) =
        get_status_and_text(&app, &headers, "GET", &format!("/{bucket}/{key}")).await;
    assert_eq!(status, StatusCode::OK, "{first_get}");
    assert_eq!(first_get.as_bytes(), prior_body.as_slice());

    // Single-part multipart: part 1 is the final part, so it needs no five MiB
    // minimum. Completion replaces the prior object as one atomic generation.
    let upload_id = initiate_upload(&app, &headers, bucket, key).await;
    let etag = upload_part(&app, &headers, bucket, key, &upload_id, 1, &replacement).await;
    let completion = complete_xml(&[(1, &etag)]);
    let complete_request = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/{bucket}/{key}?uploadId={upload_id}"))
            .body(Body::from(completion.clone()))
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(complete_request).await.unwrap();
    let complete_status = response.status();
    let complete_body = String::from_utf8(body_bytes(response).await).expect("completion XML");
    assert_eq!(
        complete_status,
        StatusCode::OK,
        "CompleteMultipartUpload: {complete_body}"
    );
    let completed_etag = extract_xml(&complete_body, "ETag");
    assert!(!completed_etag.is_empty(), "{complete_body}");
    drop(app);
    drop(state);

    // ---- Restart after the completion result --------------------------------
    // The completed representation is the canonical durable body: the redacted
    // replacement only. It must never be the prior single-PUT version, a
    // partial assembly, or a torn publish.
    let replacement_marker = "PART-NEW-VERSION";
    let (state, app, _, _) = build_local_state().await;
    let (status, after_restart) =
        get_status_and_text(&app, &headers, "GET", &format!("/{bucket}/{key}")).await;
    assert_eq!(status, StatusCode::OK, "{after_restart}");
    assert!(
        after_restart.contains(replacement_marker),
        "{after_restart}"
    );
    assert!(after_restart.contains(REDACTED_EMAIL), "{after_restart}");
    assert!(
        !after_restart.contains("PRIOR-EXACT-VERSION"),
        "{after_restart}"
    );
    assert_plaintext_never_leaks(&after_restart);

    // ---- Restart with the upload tombstoned, then exact replay --------------
    let replay_request = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/{bucket}/{key}?uploadId={upload_id}"))
            .body(Body::from(completion.clone()))
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(replay_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "exact completion replay");
    let replay_body = String::from_utf8(body_bytes(response).await).expect("replay XML");
    assert_eq!(
        extract_xml(&replay_body, "ETag"),
        completed_etag,
        "{replay_body}"
    );
    drop(app);
    drop(state);

    // ---- Restart after the replay and verify the durable body once more -----
    let (state, app, _, _) = build_local_state().await;
    let (status, final_get) =
        get_status_and_text(&app, &headers, "GET", &format!("/{bucket}/{key}")).await;
    assert_eq!(status, StatusCode::OK, "{final_get}");
    assert_eq!(
        final_get, after_restart,
        "body is stable across every restart boundary"
    );
    assert!(!final_get.contains("PRIOR-EXACT-VERSION"), "{final_get}");
    drop(app);
    drop(state);

    drop(env);
    let _ = std::fs::remove_dir_all(&root);
}

/// Build a fresh isolated local-staged state plus router and credentials for
/// one restart matrix test.
async fn build_local_state() -> (Arc<AppState>, Router, String, String) {
    let state = build_test_state().await;
    let router = build_router(state.clone());
    let (access_key, secret_key) = make_credentials(&state).await;
    (state, router, access_key, secret_key)
}
