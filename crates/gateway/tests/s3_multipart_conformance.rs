//! Local-filesystem S3 multipart conformance and SDK interoperability.
//!
//! Task 16 of `docs/plans/2026-09-08-local-filesystem-multipart-phase-2.md`
//! and `docs/plans/2026-09-09-local-filesystem-multipart-implementation-handover.md`:
//! extend the original LocalStack/MinIO-derived FileStore scenarios with
//! multipart happy path, part replacement, list pagination, completion errors,
//! atomic overwrite, abort, replay, difficult keys, and restart — without
//! copying MinIO AGPL source.
//!
//! The authoritative scenario list comes from the Phase 2 plan section 16
//! (general S3 conformance and SDK interoperability), which requires running an
//! unmodified Rust AWS SDK multipart flow against a real TCP listener and
//! retaining opt-in AWS CLI and boto3 coverage when those clients are
//! installed. Every test builds the real gateway with
//! `MASKURA_STORAGE_MODE=local` + `MASKURA_MULTIPART_MODE=staged`
//! (`MultipartPersistenceMode::LocalStaged`) over one temporary root with no
//! Postgres, external S3 endpoint, cloud credentials, or configured KEK.
//!
//! SDK SigV4 is trusted over plain loopback HTTP via `MASKURA_SIGV4_TRUSTED_TLS=1`
//! so the unmodified Rust SDK's default payload-signing mode is accepted.
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
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::process::Command;
use tower::ServiceExt;
use uuid::Uuid;

/// Every test in this binary mutates the process environment, so all state
/// building is serialized behind one lock. Tests must acquire it before any
/// `std::env` mutation and hold it until every router/state is dropped.
static ENV_LOCK: Mutex<()> = Mutex::new(());

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
        "MASKURA_SIGV4_REGION",
        "MASKURA_SIGV4_TRUSTED_TLS",
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
            "s3-conformance",
            0,
            None,
        )
        .await
        .expect("create test API key");
    assert_eq!(created.workspace_id.as_deref(), Some(workspace.as_str()));
    (created.key_id, secret)
}

fn configure_local_staged_env(env: &mut EnvRestore, root: &Path) {
    remove_host_configuration(env);
    env.set("AUTH_DISABLED", "0");
    env.set("MASKURA_SINGLE_TENANT", "1");
    env.set("MASKURA_STORAGE_MODE", "local");
    env.set("MASKURA_LOCAL_STORAGE_DIR", &root.to_string_lossy());
    env.set("MASKURA_MULTIPART_MODE", "staged");
    env.set("MASKURA_STREAMING_READ_MODE", "passthrough");
    env.set("MASKURA_SIGV4_TRUSTED_TLS", "1");
    let components = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/components");
    assert!(
        components.is_dir(),
        "built filter components missing at {}; run `just build-plugins`",
        components.display()
    );
}

async fn build_local_state() -> (Arc<AppState>, Router, String, String) {
    let state = build_test_state().await;
    let router = build_router(state.clone());
    let (access_key, secret_key) = make_credentials(&state).await;
    (state, router, access_key, secret_key)
}

/// Binds a real TCP listener and serves the router until the join handle is
/// aborted or the tokio runtime drops.
async fn spawn_listener(app: Router) -> (tokio::task::JoinHandle<()>, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let address = listener.local_addr().expect("listener address");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve gateway");
    });
    (handle, format!("http://{address}"))
}

/// Unmodified Rust AWS SDK client pointed at a plain-HTTP path-style endpoint.
fn sdk_client(endpoint: &str, access_key: &str, secret_key: &str) -> aws_sdk_s3::Client {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            access_key.to_string(),
            secret_key.to_string(),
            None,
            None,
            "s3-multipart-conformance",
        ))
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(endpoint)
        .force_path_style(true)
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

async fn sdk_get_text(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> (String, String) {
    let output = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("SDK GetObject");
    let etag = output.e_tag.clone().unwrap_or_default();
    let bytes = output
        .body
        .collect()
        .await
        .expect("collect SDK GetObject body")
        .into_bytes();
    (String::from_utf8_lossy(&bytes).to_string(), etag)
}

/// Returns the service error code for an SDK dispatch failure, if the response
/// carried a parseable S3 error code.
fn sdk_error_code<E>(error: &aws_sdk_s3::error::SdkError<E>) -> Option<String>
where
    E: std::error::Error + aws_smithy_types::error::metadata::ProvideErrorMetadata,
{
    error
        .as_service_error()
        .and_then(aws_smithy_types::error::metadata::ProvideErrorMetadata::code)
        .map(str::to_string)
}

/// A deterministic 5 MiB+ non-final part carrying one PII email record.
fn big_part(marker: &str, contact: &str) -> Vec<u8> {
    let mut body = format!("{marker}\ncontact {contact} now\n");
    let filler = format!("{}\n", "x".repeat(80));
    while body.len() < NON_FINAL_MIN_BYTES.saturating_add(32) {
        body.push_str(&filler);
    }
    body.push('\n');
    body.into_bytes()
}

fn small_part(marker: &str, contact: &str) -> Vec<u8> {
    format!("{marker}\ncontact {contact} now\n").into_bytes()
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

async fn upload_part_raw(
    app: &Router,
    headers: &[(&'static str, String)],
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    body: &[u8],
) -> String {
    let encoded_key = encode_key(key);
    let request = add_headers(
        Request::builder()
            .method("PUT")
            .uri(format!(
                "/{bucket}/{encoded_key}?partNumber={part_number}&uploadId={upload_id}"
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

async fn initiate_upload_raw(
    app: &Router,
    headers: &[(&'static str, String)],
    bucket: &str,
    key: &str,
) -> String {
    let encoded_key = encode_key(key);
    let request = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/{bucket}/{encoded_key}?uploads"))
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::empty())
            .unwrap(),
        headers,
    );
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

async fn complete_upload_raw(
    app: &Router,
    headers: &[(&'static str, String)],
    bucket: &str,
    key: &str,
    upload_id: &str,
    xml: &str,
) -> (StatusCode, String) {
    let encoded_key = encode_key(key);
    let request = add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/{bucket}/{encoded_key}?uploadId={upload_id}"))
            .body(Body::from(xml.to_string()))
            .unwrap(),
        headers,
    );
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = String::from_utf8(body_bytes(response).await).expect("completion body utf-8");
    (status, body)
}

async fn get_text_raw(
    app: &Router,
    headers: &[(&'static str, String)],
    bucket: &str,
    encoded_key: &str,
) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/{bucket}/{encoded_key}"))
                .body(Body::empty())
                .unwrap(),
            headers,
        ))
        .await
        .unwrap();
    let status = response.status();
    let body = String::from_utf8(body_bytes(response).await).expect("GET body utf-8");
    (status, body)
}

/// Percent-encodes every byte of an object key that is not URL-safe, while
/// preserving `/` separators, so raw HTTP requests reach the router with a
/// correct request-target that axum decodes back to the exact key bytes.
fn encode_key(key: &str) -> String {
    let mut out = String::new();
    for byte in key.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn assert_redacted_clean(text: &str, raw: &str) {
    assert!(
        !text.contains(raw),
        "raw marker {raw:?} must never be stored"
    );
    assert!(text.contains(REDACTED_EMAIL), "{text}");
}

// ===========================================================================
// SDK scenarios over a real TCP listener
// ===========================================================================

#[test]
fn sdk_multipart_lifecycle_completes_over_real_tcp() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build test tokio runtime");
    runtime.block_on(run_sdk_multipart_lifecycle());
}

async fn run_sdk_multipart_lifecycle() {
    let root = std::env::temp_dir().join(format!("maskura-sdk-multi-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root).expect("create temporary storage root");

    let mut env = EnvRestore::new();
    configure_local_staged_env(&mut env, &root);

    let (state, app, access_key, secret_key) = build_local_state().await;
    let (server, endpoint) = spawn_listener(app).await;
    let client = sdk_client(&endpoint, &access_key, &secret_key);

    let bucket = "sdk-multi";
    let key = "lifecycle.txt";
    let contact_one = "sdk-lifecycle@example.com";
    let contact_two = "sdk-lifecycle-2@example.org";

    let created = client
        .create_multipart_upload()
        .bucket(bucket)
        .key(key)
        .content_type("text/plain")
        .send()
        .await
        .expect("SDK CreateMultipartUpload");
    let upload_id = created.upload_id().expect("upload id").to_string();

    let part_one = big_part("LIFECYCLE-PART-ONE", contact_one);
    let part_two = small_part("LIFECYCLE-PART-TWO", contact_two);
    let etag_one = client
        .upload_part()
        .bucket(bucket)
        .key(key)
        .upload_id(&upload_id)
        .part_number(1)
        .body(aws_sdk_s3::primitives::ByteStream::from(part_one.clone()))
        .send()
        .await
        .expect("SDK UploadPart 1")
        .e_tag
        .expect("UploadPart 1 ETag");
    let etag_two = client
        .upload_part()
        .bucket(bucket)
        .key(key)
        .upload_id(&upload_id)
        .part_number(2)
        .body(aws_sdk_s3::primitives::ByteStream::from(part_two.clone()))
        .send()
        .await
        .expect("SDK UploadPart 2")
        .e_tag
        .expect("UploadPart 2 ETag");
    assert_ne!(etag_one, etag_two);

    // ListParts pagination: one part per page across two pages.
    let first_page = client
        .list_parts()
        .bucket(bucket)
        .key(key)
        .upload_id(&upload_id)
        .part_number_marker("0")
        .max_parts(1)
        .send()
        .await
        .expect("SDK ListParts page one");
    assert_eq!(first_page.is_truncated(), Some(true));
    let first = first_page.parts();
    assert_eq!(first.len(), 1, "first page part count");
    assert_eq!(first[0].part_number(), Some(1));
    assert_eq!(first[0].e_tag().map(str::to_string), Some(etag_one.clone()));

    let second_page = client
        .list_parts()
        .bucket(bucket)
        .key(key)
        .upload_id(&upload_id)
        .part_number_marker(first_page.next_part_number_marker().expect("next marker"))
        .max_parts(1)
        .send()
        .await
        .expect("SDK ListParts page two");
    assert_eq!(second_page.is_truncated(), Some(false));
    let second = second_page.parts();
    assert_eq!(second.len(), 1, "second page part count");
    assert_eq!(second[0].part_number(), Some(2));
    assert_eq!(
        second[0].e_tag().map(str::to_string),
        Some(etag_two.clone())
    );

    // CompleteMultipartUpload with the two staged parts in ascending order.
    let completed = client
        .complete_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(&upload_id)
        .multipart_upload(
            aws_sdk_s3::types::CompletedMultipartUpload::builder()
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(1)
                        .e_tag(&etag_one)
                        .build(),
                )
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(2)
                        .e_tag(&etag_two)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .expect("SDK CompleteMultipartUpload");
    let completed_etag = completed.e_tag.expect("completion ETag");
    assert!(!completed_etag.is_empty());

    // GET reflects the redacted assembled object, never a partial or raw body.
    let (text, get_etag) = sdk_get_text(&client, bucket, key).await;
    assert_eq!(get_etag, completed_etag, "GET ETag echoes completion ETag");
    assert_redacted_clean(&text, contact_one);
    assert_redacted_clean(&text, contact_two);
    let one = text.find("LIFECYCLE-PART-ONE").expect("marker one");
    let two = text.find("LIFECYCLE-PART-TWO").expect("marker two");
    assert!(one < two, "parts assembled in ascending part order");
    assert_eq!(text.matches(REDACTED_EMAIL).count(), 2, "{text}");

    let head = client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("SDK HeadObject");
    assert_eq!(head.e_tag().map(str::to_string), Some(completed_etag));
    assert_eq!(
        head.content_length(),
        Some(i64::try_from(text.len()).expect("body length fits i64"))
    );
    assert_eq!(head.content_type(), Some("text/plain"));

    // DELETE then HEAD reports 404 NotFound through the unmodified SDK.
    client
        .delete_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect("SDK DeleteObject");
    let head_error = client
        .head_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .expect_err("SDK HeadObject after delete must fail");
    assert_eq!(
        sdk_error_code(&head_error).as_deref(),
        Some("NotFound"),
        "{head_error:?}"
    );

    server.abort();
    drop(state);
    drop(env);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn sdk_multipart_replacement_overwrites_single_put_atomically() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build test tokio runtime");
    runtime.block_on(run_sdk_multipart_replacement());
}

async fn run_sdk_multipart_replacement() {
    let root = std::env::temp_dir().join(format!("maskura-sdk-overwrite-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root).expect("create temporary storage root");

    let mut env = EnvRestore::new();
    configure_local_staged_env(&mut env, &root);

    let (state, app, access_key, secret_key) = build_local_state().await;
    let (server, endpoint) = spawn_listener(app).await;
    let client = sdk_client(&endpoint, &access_key, &secret_key);

    let bucket = "sdk-overwrite";
    let key = "doc.txt";
    let original_raw = "ORIGINAL-SINGLE-PUT-VERSION\n";
    let contact_one = "replacement-v1@example.com";
    let contact_two = "replacement-final@example.com";

    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .content_type("text/plain")
        .body(aws_sdk_s3::primitives::ByteStream::from_static(
            original_raw.as_bytes(),
        ))
        .send()
        .await
        .expect("SDK single PUT");
    let (original_text, _) = sdk_get_text(&client, bucket, key).await;
    assert!(original_text.contains("ORIGINAL-SINGLE-PUT-VERSION"));

    // Multipart completion must atomically replace that object.
    let upload_id = client
        .create_multipart_upload()
        .bucket(bucket)
        .key(key)
        .content_type("text/plain")
        .send()
        .await
        .expect("SDK CreateMultipartUpload")
        .upload_id()
        .expect("upload id")
        .to_string();

    let first_version = big_part("REPLACEMENT-V1-MARKER", contact_one);
    let first_etag = client
        .upload_part()
        .bucket(bucket)
        .key(key)
        .upload_id(&upload_id)
        .part_number(1)
        .body(aws_sdk_s3::primitives::ByteStream::from(first_version))
        .send()
        .await
        .expect("SDK UploadPart 1 v1")
        .e_tag
        .expect("UploadPart 1 v1 ETag");

    // Part replacement: the same part number is uploaded again before
    // completion; ListParts must show only the latest version.
    let final_version = big_part("REPLACEMENT-FINAL-MARKER", contact_two);
    let final_etag = client
        .upload_part()
        .bucket(bucket)
        .key(key)
        .upload_id(&upload_id)
        .part_number(1)
        .body(aws_sdk_s3::primitives::ByteStream::from(final_version))
        .send()
        .await
        .expect("SDK UploadPart 1 replacement")
        .e_tag
        .expect("UploadPart 1 replacement ETag");
    assert_ne!(first_etag, final_etag);

    let listed = client
        .list_parts()
        .bucket(bucket)
        .key(key)
        .upload_id(&upload_id)
        .send()
        .await
        .expect("SDK ListParts after replacement");
    let parts = listed.parts();
    assert_eq!(parts.len(), 1, "replacement leaves one part");
    assert_eq!(
        parts[0].e_tag().map(str::to_string),
        Some(final_etag.clone())
    );

    client
        .complete_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(&upload_id)
        .multipart_upload(
            aws_sdk_s3::types::CompletedMultipartUpload::builder()
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(1)
                        .e_tag(&final_etag)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .expect("SDK CompleteMultipartUpload");

    let (replaced_text, _) = sdk_get_text(&client, bucket, key).await;
    assert!(
        replaced_text.contains("REPLACEMENT-FINAL-MARKER"),
        "{replaced_text}"
    );
    assert!(
        !replaced_text.contains("REPLACEMENT-V1-MARKER"),
        "old part version must not survive replacement: {replaced_text}"
    );
    assert_redacted_clean(&replaced_text, contact_two);
    assert!(
        !replaced_text.contains("ORIGINAL-SINGLE-PUT-VERSION"),
        "multipart completion must atomically overwrite the prior object: {replaced_text}"
    );
    assert_eq!(
        replaced_text.matches(REDACTED_EMAIL).count(),
        1,
        "{replaced_text}"
    );

    server.abort();
    drop(state);
    drop(env);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn sdk_multipart_abort_list_uploads_and_no_such_upload() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build test tokio runtime");
    runtime.block_on(run_sdk_multipart_abort_and_errors());
}

async fn run_sdk_multipart_abort_and_errors() {
    let root = std::env::temp_dir().join(format!("maskura-sdk-abort-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root).expect("create temporary storage root");

    let mut env = EnvRestore::new();
    configure_local_staged_env(&mut env, &root);

    let (state, app, access_key, secret_key) = build_local_state().await;

    let bucket = "sdk-uploads";
    let keep_key = "alpha.txt";
    let abort_key = "beta.txt";
    let (server, endpoint) = spawn_listener(app).await;
    let client = sdk_client(&endpoint, &access_key, &secret_key);

    let keep_upload = client
        .create_multipart_upload()
        .bucket(bucket)
        .key(keep_key)
        .content_type("text/plain")
        .send()
        .await
        .expect("create alpha upload")
        .upload_id()
        .expect("alpha upload id")
        .to_string();
    let abort_upload = client
        .create_multipart_upload()
        .bucket(bucket)
        .key(abort_key)
        .content_type("text/plain")
        .send()
        .await
        .expect("create beta upload")
        .upload_id()
        .expect("beta upload id")
        .to_string();

    let keep_contact = "alpha-kept@example.com";
    let keep_body = small_part("ALPHA-KEPT", keep_contact);
    let keep_etag = client
        .upload_part()
        .bucket(bucket)
        .key(keep_key)
        .upload_id(&keep_upload)
        .part_number(1)
        .body(aws_sdk_s3::primitives::ByteStream::from(keep_body))
        .send()
        .await
        .expect("upload alpha part")
        .e_tag
        .expect("alpha part ETag");

    // Abort one upload through the unmodified SDK.
    client
        .abort_multipart_upload()
        .bucket(bucket)
        .key(abort_key)
        .upload_id(&abort_upload)
        .send()
        .await
        .expect("SDK AbortMultipartUpload");

    // The aborted upload id is terminal: ListParts returns an empty list.
    let aborted_parts = client
        .list_parts()
        .bucket(bucket)
        .key(abort_key)
        .upload_id(&abort_upload)
        .send()
        .await
        .expect("ListParts on an aborted upload");
    assert!(
        aborted_parts.parts().is_empty(),
        "aborted upload has no parts"
    );

    // Never-created upload ids resolve to NoSuchUpload across operations.
    let ghost = Uuid::now_v7().to_string();
    let ghost_part_error = client
        .upload_part()
        .bucket(bucket)
        .key(keep_key)
        .upload_id(&ghost)
        .part_number(1)
        .body(aws_sdk_s3::primitives::ByteStream::from_static(b"ghost\n"))
        .send()
        .await
        .expect_err("UploadPart into a ghost upload must fail");
    assert_eq!(
        sdk_error_code(&ghost_part_error).as_deref(),
        Some("NoSuchUpload"),
        "{ghost_part_error:?}"
    );
    let ghost_parts_error = client
        .list_parts()
        .bucket(bucket)
        .key(keep_key)
        .upload_id(&ghost)
        .send()
        .await
        .expect_err("ListParts on a ghost upload must fail");
    assert_eq!(
        sdk_error_code(&ghost_parts_error).as_deref(),
        Some("NoSuchUpload"),
        "{ghost_parts_error:?}"
    );
    let ghost_complete_error = client
        .complete_multipart_upload()
        .bucket(bucket)
        .key(keep_key)
        .upload_id(&ghost)
        .multipart_upload(
            aws_sdk_s3::types::CompletedMultipartUpload::builder()
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(1)
                        .e_tag("\"ghost\"")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .expect_err("CompleteMultipartUpload on a ghost upload must fail");
    assert_eq!(
        sdk_error_code(&ghost_complete_error).as_deref(),
        Some("NoSuchUpload"),
        "{ghost_complete_error:?}"
    );

    // The surviving upload still completes and is readable.
    client
        .complete_multipart_upload()
        .bucket(bucket)
        .key(keep_key)
        .upload_id(&keep_upload)
        .multipart_upload(
            aws_sdk_s3::types::CompletedMultipartUpload::builder()
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(1)
                        .e_tag(&keep_etag)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .expect("complete surviving upload");
    let (text, _) = sdk_get_text(&client, bucket, keep_key).await;
    assert!(text.contains("ALPHA-KEPT"), "{text}");
    assert_redacted_clean(&text, keep_contact);

    server.abort();
    drop(state);
    drop(env);
    let _ = std::fs::remove_dir_all(&root);
}

// ===========================================================================
// Raw HTTP conformance scenarios (tower oneshot against the built router)
// ===========================================================================

#[test]
fn http_conformance_completion_errors_pagination_helpers_and_replay() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build test tokio runtime");
    runtime.block_on(run_completion_error_conformance());
}

async fn run_completion_error_conformance() {
    let root = std::env::temp_dir().join(format!("maskura-http-errors-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root).expect("create temporary storage root");

    let mut env = EnvRestore::new();
    configure_local_staged_env(&mut env, &root);

    let (state, app, access_key, secret_key) = build_local_state().await;
    let headers = auth_headers(&access_key, &secret_key);

    let bucket = "sdk-errors";
    let key = "errors.txt";
    let contact_two = "error-two@example.com";
    let contact_final = "error-final@example.org";

    let upload_id = initiate_upload_raw(&app, &headers, bucket, key).await;

    // A tiny non-final part 1 is staged so EntityTooSmall can be observed, then
    // a second (final) small part is staged.
    let tiny_one = small_part("TINY-NONFINAL", "error-tiny@example.com");
    let etag_tiny_one =
        upload_part_raw(&app, &headers, bucket, key, &upload_id, 1, &tiny_one).await;
    let part_two = small_part("ERROR-PART-TWO", contact_two);
    let etag_two = upload_part_raw(&app, &headers, bucket, key, &upload_id, 2, &part_two).await;

    // Completion of a non-final part below 5 MiB fails closed with
    // EntityTooSmall before any publication work starts.
    let (status, body) = complete_upload_raw(
        &app,
        &headers,
        bucket,
        key,
        &upload_id,
        &complete_xml(&[(1, &etag_tiny_one), (2, &etag_two)]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("EntityTooSmall"), "{body}");

    // A real non-final part replaces the tiny one.
    let big_one = big_part("ERROR-PART-ONE", contact_final);
    let etag_one = upload_part_raw(&app, &headers, bucket, key, &upload_id, 1, &big_one).await;
    assert_ne!(etag_one, etag_tiny_one);

    // A fabricated part ETag reports InvalidPart.
    let (status, body) = complete_upload_raw(
        &app,
        &headers,
        bucket,
        key,
        &upload_id,
        &complete_xml(&[(1, "\"not-the-staged-etag\""), (2, &etag_two)]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("InvalidPart"), "{body}");

    // Part numbers out of ascending order report InvalidPartOrder.
    let (status, body) = complete_upload_raw(
        &app,
        &headers,
        bucket,
        key,
        &upload_id,
        &complete_xml(&[(2, &etag_two), (1, &etag_one)]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("InvalidPartOrder"), "{body}");

    // Selecting a part that was never staged reports InvalidPart.
    let (status, body) = complete_upload_raw(
        &app,
        &headers,
        bucket,
        key,
        &upload_id,
        &complete_xml(&[(1, &etag_one), (3, "\"missing-part\""), (2, &etag_two)]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("InvalidPart"), "{body}");

    // The valid ascending completion succeeds.
    let valid = complete_xml(&[(1, &etag_one), (2, &etag_two)]);
    let (status, body) = complete_upload_raw(&app, &headers, bucket, key, &upload_id, &valid).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let completed_etag = extract_xml(&body, "ETag");
    assert!(!completed_etag.is_empty(), "{body}");

    let (status, text) = get_text_raw(&app, &headers, bucket, key).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(text.contains("ERROR-PART-ONE"), "{text}");
    assert!(text.contains("ERROR-PART-TWO"), "{text}");
    assert_redacted_clean(&text, contact_two);
    assert_redacted_clean(&text, contact_final);
    assert!(!text.contains("TINY-NONFINAL"), "{text}");
    let one = text.find("ERROR-PART-ONE").expect("marker one");
    let two = text.find("ERROR-PART-TWO").expect("marker two");
    assert!(one < two, "assembled in part order");

    // Exact completion replay is idempotent and echoes the committed ETag.
    let (status, replay_body) =
        complete_upload_raw(&app, &headers, bucket, key, &upload_id, &valid).await;
    assert_eq!(status, StatusCode::OK, "{replay_body}");
    assert_eq!(
        extract_xml(&replay_body, "ETag"),
        completed_etag,
        "{replay_body}"
    );

    // A conflicting completion (different part selection) is rejected without
    // corrupting the committed object.
    let (status, conflict_body) = complete_upload_raw(
        &app,
        &headers,
        bucket,
        key,
        &upload_id,
        &complete_xml(&[(1, &etag_one)]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{conflict_body}");
    assert!(
        conflict_body.contains("conflicting CompleteMultipartUpload request")
            || conflict_body.contains("InvalidPart"),
        "{conflict_body}"
    );
    let (status, after_conflict) = get_text_raw(&app, &headers, bucket, key).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after_conflict, text, "conflict must not change the object");

    drop(app);
    drop(state);
    drop(env);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn http_conformance_difficult_keys_survive_multipart_and_restart() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build test tokio runtime");
    runtime.block_on(run_difficult_keys_conformance());
}

async fn run_difficult_keys_conformance() {
    let root = std::env::temp_dir().join(format!("maskura-http-keys-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root).expect("create temporary storage root");

    let mut env = EnvRestore::new();
    configure_local_staged_env(&mut env, &root);

    let (state, app, access_key, secret_key) = build_local_state().await;
    let headers = auth_headers(&access_key, &secret_key);
    let bucket = "sdk-keys";

    // Keys that stress path encoding, reserved characters, unicode, and nested
    // directories while staying within S3 path addressing.
    let cases: &[(&str, &str, &str)] = &[
        (
            "space dir/odd name.txt",
            "ODD-SPACE-KEY",
            "odd-space@example.com",
        ),
        (
            "ampers&question?hash#key.txt",
            "RESERVED-KEY",
            "reserved-key@example.com",
        ),
        (
            "日本語/レコード v1.txt",
            "UNICODE-KEY",
            "unicode@example.com",
        ),
        (
            "deep/nest/key,comma;semi.txt",
            "NESTED-KEY",
            "nested@example.com",
        ),
    ];

    let mut first_gets = Vec::new();
    for (key, marker, contact) in cases {
        let upload_id = initiate_upload_raw(&app, &headers, bucket, key).await;
        let body = small_part(marker, contact);
        let etag = upload_part_raw(&app, &headers, bucket, key, &upload_id, 1, &body).await;
        let (status, completed) = complete_upload_raw(
            &app,
            &headers,
            bucket,
            key,
            &upload_id,
            &complete_xml(&[(1, &etag)]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "key {key:?}: {completed}");
        assert!(
            completed.contains("CompleteMultipartUploadResult"),
            "{completed}"
        );

        let encoded = encode_key(key);
        let (status, text) = get_text_raw(&app, &headers, bucket, &encoded).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET key {key:?} (encoded {encoded})"
        );
        assert!(text.contains(marker), "key {key:?}: {text}");
        assert_redacted_clean(&text, contact);
        first_gets.push(text);
    }

    // A second upload over the same key list must not leak the first object,
    // and restarting the gateway must preserve exact bytes for every key.
    drop(app);
    drop(state);

    let (restarted_state, restarted_app) = {
        let state = build_test_state().await;
        let app = build_router(state.clone());
        (state, app)
    };
    for ((key, marker, _contact), expected) in cases.iter().zip(&first_gets) {
        let encoded = encode_key(key);
        let (status, text) = get_text_raw(&restarted_app, &headers, bucket, &encoded).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET after restart key {key:?} ({marker})"
        );
        assert_eq!(text.as_bytes(), expected.as_bytes());
    }

    drop(restarted_app);
    drop(restarted_state);
    drop(env);
    let _ = std::fs::remove_dir_all(&root);
}

// ===========================================================================
// Optional external-client coverage (AWS CLI + boto3), gated the same way as
// the FileStore frontdoor suite: `MASKURA_RUN_EXTERNAL_CLIENT_INTEROP=1`.
// ===========================================================================

#[test]
fn external_aws_cli_and_boto3_multipart_interoperate() {
    let _guard = ENV_LOCK.lock().expect("env lock poisoned");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build test tokio runtime");
    runtime.block_on(run_external_multipart_interop());
}

async fn run_external_multipart_interop() {
    if std::env::var("MASKURA_RUN_EXTERNAL_CLIENT_INTEROP").as_deref() != Ok("1") {
        return;
    }
    let aws_available = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new("aws")
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .is_ok_and(|result| result.is_ok_and(|output| output.status.success()));
    let boto3_available = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new("python3")
            .args(["-c", "import boto3"])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .is_ok_and(|result| result.is_ok_and(|output| output.status.success()));
    assert!(
        aws_available,
        "MASKURA_RUN_EXTERNAL_CLIENT_INTEROP requires AWS CLI"
    );
    assert!(
        boto3_available,
        "MASKURA_RUN_EXTERNAL_CLIENT_INTEROP requires boto3"
    );

    let root = std::env::temp_dir().join(format!("maskura-external-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&root).expect("create temporary storage root");

    let mut env = EnvRestore::new();
    configure_local_staged_env(&mut env, &root);

    let (state, _, access_key, secret_key) = build_local_state().await;
    let app = build_router(state.clone());
    let (server, endpoint) = spawn_listener(app).await;

    let bucket = "external-multi";
    let key = "external.txt";
    let contact = "external-client@example.com";
    let part_one_path = root.join("part-one.txt");
    let part_two_path = root.join("part-two.txt");
    std::fs::write(
        &part_one_path,
        big_part("EXTERNAL-CLI-PART-ONE", contact).as_slice(),
    )
    .expect("write CLI part one file");
    std::fs::write(
        &part_two_path,
        small_part("EXTERNAL-CLI-PART-TWO", "external-two@example.com"),
    )
    .expect("write CLI part two file");

    async fn aws_output(args: &[&str], access_key: &str, secret_key: &str) -> std::process::Output {
        tokio::time::timeout(
            Duration::from_secs(60),
            Command::new("aws")
                .args(args)
                .env("AWS_ACCESS_KEY_ID", access_key)
                .env("AWS_SECRET_ACCESS_KEY", secret_key)
                .env("AWS_EC2_METADATA_DISABLED", "true")
                .env("AWS_REQUEST_CHECKSUM_CALCULATION", "when_required")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("AWS CLI timed out")
        .expect("run AWS CLI")
    }
    let aws_base: Vec<&str> = vec!["--endpoint-url", endpoint.as_str(), "--region", "us-east-1"];

    let mut create_args = vec![
        "s3api",
        "create-multipart-upload",
        "--bucket",
        bucket,
        "--key",
        key,
    ];
    create_args.extend(aws_base.iter().copied());
    let created_output = aws_output(&create_args, &access_key, &secret_key).await;
    assert!(
        created_output.status.success(),
        "aws create-multipart-upload failed: {}",
        String::from_utf8_lossy(&created_output.stderr)
    );
    let created_json: serde_json::Value =
        serde_json::from_slice(&created_output.stdout).expect("parse create JSON");
    let upload_id = created_json["UploadId"]
        .as_str()
        .expect("created upload id")
        .to_string();

    let part_one_arg = part_one_path.to_string_lossy().to_string();
    let mut part_one_args = vec![
        "s3api",
        "upload-part",
        "--bucket",
        bucket,
        "--key",
        key,
        "--upload-id",
        upload_id.as_str(),
        "--part-number",
        "1",
        "--body",
        part_one_arg.as_str(),
    ];
    part_one_args.extend(aws_base.iter().copied());
    let part_one_output = aws_output(&part_one_args, &access_key, &secret_key).await;
    assert!(
        part_one_output.status.success(),
        "aws upload-part 1 failed: {}",
        String::from_utf8_lossy(&part_one_output.stderr)
    );
    let part_one_json: serde_json::Value =
        serde_json::from_slice(&part_one_output.stdout).expect("parse part one JSON");
    let etag_one = part_one_json["ETag"]
        .as_str()
        .expect("part one ETag")
        .to_string();

    let part_two_arg = part_two_path.to_string_lossy().to_string();
    let mut part_two_args = vec![
        "s3api",
        "upload-part",
        "--bucket",
        bucket,
        "--key",
        key,
        "--upload-id",
        upload_id.as_str(),
        "--part-number",
        "2",
        "--body",
        part_two_arg.as_str(),
    ];
    part_two_args.extend(aws_base.iter().copied());
    let part_two_output = aws_output(&part_two_args, &access_key, &secret_key).await;
    assert!(
        part_two_output.status.success(),
        "aws upload-part 2 failed: {}",
        String::from_utf8_lossy(&part_two_output.stderr)
    );
    let part_two_json: serde_json::Value =
        serde_json::from_slice(&part_two_output.stdout).expect("parse part two JSON");
    let etag_two = part_two_json["ETag"]
        .as_str()
        .expect("part two ETag")
        .to_string();

    let multipart_json = serde_json::json!({
        "Parts": [
            {"PartNumber": 1, "ETag": etag_one},
            {"PartNumber": 2, "ETag": etag_two},
        ]
    })
    .to_string();
    let mut complete_args = vec![
        "s3api",
        "complete-multipart-upload",
        "--bucket",
        bucket,
        "--key",
        key,
        "--upload-id",
        &upload_id,
        "--multipart-upload",
        &multipart_json,
    ];
    complete_args.extend(aws_base.iter().copied());
    let complete_output = aws_output(&complete_args, &access_key, &secret_key).await;
    assert!(
        complete_output.status.success(),
        "aws complete-multipart-upload failed: {}",
        String::from_utf8_lossy(&complete_output.stderr)
    );

    if boto3_available {
        let script = r#"
import boto3, os
from botocore.config import Config
response = boto3.client(
    "s3",
    endpoint_url=os.environ["MASKURA_TEST_ENDPOINT"],
    region_name="us-east-1",
    aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    config=Config(s3={"addressing_style": "path"}),
).get_object(Bucket="external-multi", Key="external.txt")
body = response["Body"].read().decode("utf-8")
open(os.environ["MASKURA_TEST_BODY_PATH"], "w").write(body)
"#;
        let body_path = root.join("external-body.txt");
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            Command::new("python3")
                .args(["-c", script])
                .env("MASKURA_TEST_ENDPOINT", &endpoint)
                .env(
                    "MASKURA_TEST_BODY_PATH",
                    body_path.to_string_lossy().into_owned(),
                )
                .env("AWS_ACCESS_KEY_ID", &access_key)
                .env("AWS_SECRET_ACCESS_KEY", &secret_key)
                .env("AWS_EC2_METADATA_DISABLED", "true")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("boto3 timed out")
        .expect("run boto3");
        assert!(
            output.status.success(),
            "boto3 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = std::fs::read_to_string(&body_path).expect("read boto3 body");
        assert!(text.contains("EXTERNAL-CLI-PART-ONE"), "{text}");
        assert!(text.contains("EXTERNAL-CLI-PART-TWO"), "{text}");
        assert_redacted_clean(&text, contact);
        assert!(!text.contains("external-two@example.com"), "{text}");
    }

    server.abort();
    drop(state);
    drop(env);
    let _ = std::fs::remove_dir_all(&root);
}
