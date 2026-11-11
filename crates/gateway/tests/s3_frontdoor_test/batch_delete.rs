//! S3 Multi-Object Delete (`POST /{bucket}?delete`) conformance.
//!
//! The batch is an envelope over the single-key gated delete path: per key the
//! policy verdict, storage delete, and usage receipt run unchanged, and every
//! key lands in the response as `<Deleted>` or `<Error>`. Systemic failures
//! (bad auth, malformed XML, oversized bodies) fail the request before any key
//! is touched. These rows pin the filestore-visible contract: quiet mode,
//! missing keys reported `<Deleted>`, partial denial, the 1000-key and
//! 128-KiB caps, and idempotent re-deletes.

use super::*;

use async_trait::async_trait;
use maskura_error::MaskuraError;
use maskura_gateway::policy_gate::{PolicyGate, PolicyRequest, VerifiedPolicy};
use maskura_pipeline_config::PolicyOperation;

/// A gate that denies Delete for exactly the named keys and admits everything
/// else (reads of the denied keys must still answer, so the per-key outcome
/// can be observed).
struct DenyKeysGate {
    denied: Vec<String>,
    calls: Mutex<Vec<(PolicyOperation, String)>>,
}

#[async_trait]
impl PolicyGate for DenyKeysGate {
    async fn enforce(&self, request: &PolicyRequest<'_>) -> Result<VerifiedPolicy, MaskuraError> {
        self.calls
            .lock()
            .unwrap()
            .push((request.operation, request.key.to_string()));
        if request.operation == PolicyOperation::Delete
            && self.denied.iter().any(|key| key == request.key)
        {
            return Err(MaskuraError::new(
                maskura_error::codes::POLICY_DENIED,
                "state mismatch",
            ));
        }
        Ok(VerifiedPolicy::unbound())
    }
}

/// A filestore-backed router (the durable local backend the conformance rows
/// are about), planted directly instead of through PUTs where the row is
/// about the delete surface only.
async fn filestore_state() -> (Arc<AppState>, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("maskura-batch-delete-{}", uuid::Uuid::now_v7()));
    let mut state = explicit_passthrough_test_state(None).await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.file_store = Some(Arc::new(FileStore::new(root.clone()).await.unwrap()));
    (state, root)
}

fn delete_objects_request(
    bucket: &str,
    body: &str,
    hdrs: &[(&'static str, String)],
) -> Request<Body> {
    add_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/{bucket}?delete"))
            .header(header::CONTENT_TYPE, "application/xml")
            .body(Body::from(body.to_string()))
            .unwrap(),
        hdrs,
    )
}

/// (kind, key, code) for each envelope entry, in document order. `kind` is
/// `Deleted` or `Error`; `code` is `Some` only for `Error` entries.
fn envelope_entries(xml: &str) -> Vec<(String, String, Option<String>)> {
    let mut entries: Vec<(String, String, Option<String>)> = Vec::new();
    let mut field: Option<&'static str> = None;
    let mut text = String::new();
    for token in xmlparser::Tokenizer::from(xml) {
        match token.expect("response envelope must be well-formed XML") {
            xmlparser::Token::ElementStart { local, .. } => match local.as_str() {
                "Deleted" => entries.push(("Deleted".to_string(), String::new(), None)),
                "Error" => entries.push(("Error".to_string(), String::new(), None)),
                "Key" => {
                    field = Some("Key");
                    text.clear();
                }
                "Code" => {
                    field = Some("Code");
                    text.clear();
                }
                _ => {}
            },
            xmlparser::Token::Text { text: value, .. } if field.is_some() => {
                text.push_str(value.as_str())
            }
            xmlparser::Token::ElementEnd {
                end: xmlparser::ElementEnd::Close(_, name),
                ..
            } if name.as_str() == "Key" || name.as_str() == "Code" => {
                if let Some(entry) = entries.last_mut() {
                    match field {
                        Some("Key") => entry.1 = text.clone(),
                        Some("Code") => entry.2 = Some(text.clone()),
                        _ => {}
                    }
                }
                field = None;
            }
            _ => {}
        }
    }
    entries
}

fn deleted_keys(xml: &str) -> Vec<String> {
    envelope_entries(xml)
        .into_iter()
        .filter(|(kind, _, _)| kind == "Deleted")
        .map(|(_, key, _)| key)
        .collect()
}

fn error_entries(xml: &str) -> Vec<(String, String)> {
    envelope_entries(xml)
        .into_iter()
        .filter(|(kind, _, _)| kind == "Error")
        .map(|(_, key, code)| (key, code.unwrap_or_default()))
        .collect()
}

async fn response_xml(response: axum::response::Response) -> String {
    String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

fn batch_body(quiet: bool, keys: &[&str]) -> String {
    let quiet_element = if quiet { "<Quiet>true</Quiet>" } else { "" };
    let objects: String = keys
        .iter()
        .map(|key| format!("<Object><Key>{key}</Key></Object>"))
        .collect();
    format!("<Delete>{quiet_element}{objects}</Delete>")
}

#[tokio::test]
async fn batch_delete_rejects_bad_content_md5_before_deleting() {
    use base64::Engine as _;
    use md5::{Digest as _, Md5};
    let (state, _root) = filestore_state().await;
    let (ak, sk) = make_key(&state).await;
    let store = state.file_store.as_ref().unwrap();
    store
        .put(
            "batch",
            "keep.txt",
            Bytes::from_static(b"synthetic"),
            "text/plain",
        )
        .await
        .unwrap();
    let body = batch_body(false, &["keep.txt"]);
    let app = build_router(state.clone());
    for digest in ["AAAAAAAAAAAAAAAAAAAAAA==", "not-base64"] {
        let mut request = delete_objects_request("batch", &body, &auth_headers(&ak, &sk));
        request
            .headers_mut()
            .insert("content-md5", digest.parse().unwrap());
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(store.head("batch", "keep.txt").await.unwrap().is_some());
    }
    let valid = base64::engine::general_purpose::STANDARD.encode(Md5::digest(body.as_bytes()));
    let mut request = delete_objects_request("batch", &body, &auth_headers(&ak, &sk));
    request
        .headers_mut()
        .insert("content-md5", valid.parse().unwrap());
    assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::OK);
    assert!(store.head("batch", "keep.txt").await.unwrap().is_none());
    // The launcher cleans its owned TMPDIR after the child exits.
}

#[tokio::test]
async fn batch_delete_content_md5_covers_decoded_aws_chunked_body_and_keeps_transport_integrity() {
    use aws_sigv4::http_request::SignableBody;
    use base64::Engine as _;
    use crc::{CRC_32_ISO_HDLC, Crc};
    use md5::{Digest as _, Md5};
    let (mut state, _root) = filestore_state().await;
    Arc::get_mut(&mut state).unwrap().sigv4_policy = SigV4Policy::new("us-east-1", true);
    let (ak, sk) = make_key(&state).await;
    let store = state.file_store.as_ref().unwrap();
    store
        .put(
            "batch",
            "keep.txt",
            Bytes::from_static(b"public synthetic"),
            "text/plain",
        )
        .await
        .unwrap();
    let body = batch_body(false, &["keep.txt"]);
    let good_md5 = base64::engine::general_purpose::STANDARD.encode(Md5::digest(body.as_bytes()));
    let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let checksum = base64::engine::general_purpose::STANDARD
        .encode(crc.checksum(body.as_bytes()).to_be_bytes());
    let length = body.len().to_string();
    let app = build_router(state.clone());
    for (md5, trailer, deleted) in [
        ("AAAAAAAAAAAAAAAAAAAAAA==", checksum.as_str(), false),
        (good_md5.as_str(), "AAAAAA==", false),
        (good_md5.as_str(), checksum.as_str(), true),
    ] {
        let framed = format!(
            "{:X}\r\n{body}\r\n0\r\nx-amz-checksum-crc32:{trailer}\r\n\r\n",
            body.len()
        );
        let request = signed_request_with_signable(
            &ak,
            &sk,
            "POST",
            "http://maskura.local/batch?delete",
            framed.as_bytes(),
            &[
                ("content-type", "application/xml"),
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", length.as_str()),
                ("x-amz-sdk-checksum-algorithm", "CRC32"),
                ("x-amz-trailer", "x-amz-checksum-crc32"),
                ("content-md5", md5),
            ],
            SignableBody::StreamingUnsignedPayloadTrailer,
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            if deleted {
                StatusCode::OK
            } else {
                StatusCode::BAD_REQUEST
            }
        );
        assert_eq!(
            store.head("batch", "keep.txt").await.unwrap().is_none(),
            deleted
        );
    }
}

#[tokio::test]
async fn batch_delete_rejects_bad_signed_crc32_before_deleting() {
    let (state, _root) = filestore_state().await;
    let (ak, sk) = make_key(&state).await;
    state
        .file_store
        .as_ref()
        .unwrap()
        .put(
            "batch",
            "keep.txt",
            Bytes::from_static(b"synthetic"),
            "text/plain",
        )
        .await
        .unwrap();
    let body = batch_body(false, &["keep.txt"]);
    let request = signed_request(
        &ak,
        &sk,
        "POST",
        "http://maskura.local/batch?delete",
        body.as_bytes(),
        &[
            ("content-type", "application/xml"),
            ("x-amz-checksum-crc32", "AAAAAA=="),
        ],
    );
    let response = build_router(state.clone()).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        state
            .file_store
            .as_ref()
            .unwrap()
            .head("batch", "keep.txt")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
#[ignore = "requires locally installed boto3"]
async fn boto3_delete_objects_interoperates_with_gateway() {
    let (mut state, _root) = filestore_state().await;
    Arc::get_mut(&mut state).unwrap().sigv4_policy = SigV4Policy::new("us-east-1", true);
    let (access_key, secret) = make_key(&state).await;
    state
        .file_store
        .as_ref()
        .unwrap()
        .put(
            "batch",
            "synthetic.txt",
            Bytes::from_static(b"synthetic"),
            "text/plain",
        )
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let app = build_router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let script = r#"
import boto3, os
from botocore.config import Config
s3 = boto3.client('s3', endpoint_url=os.environ['MASKURA_TEST_ENDPOINT'], region_name='us-east-1',
                  aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'], aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
                  config=Config(s3={'addressing_style': 'path'}, retries={'max_attempts': 0}))
r = s3.delete_objects(Bucket='batch', Delete={'Objects': [{'Key':'synthetic.txt'}, {'Key':'missing.txt'}]})
assert {item['Key'] for item in r.get('Deleted', [])} == {'synthetic.txt', 'missing.txt'}, r
assert not r.get('Errors'), r
r = s3.delete_objects(Bucket='batch', Delete={'Objects': [{'Key':'synthetic.txt'}], 'Quiet': True})
assert not r.get('Deleted') and not r.get('Errors'), r
"#;
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        Command::new("python3")
            .args(["-c", script])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").expect("isolated PATH"))
            .env("HOME", std::env::var_os("HOME").expect("isolated HOME"))
            .env("TMPDIR", std::env::temp_dir())
            .env("MASKURA_TEST_ENDPOINT", endpoint)
            .env("AWS_ACCESS_KEY_ID", access_key)
            .env("AWS_SECRET_ACCESS_KEY", secret)
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .expect("python3 must be available");
    server.abort();
    assert!(
        output.status.success(),
        "boto3 failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        state
            .file_store
            .as_ref()
            .unwrap()
            .head("batch", "synthetic.txt")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn filestore_batch_delete_answers_every_key_and_is_idempotent() {
    let (state, _root) = filestore_state().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let app = build_router(state.clone());
    for key in ["a.txt", "b.txt", "c.txt"] {
        state
            .file_store
            .as_ref()
            .unwrap()
            .put("batch", key, Bytes::from_static(b"payload"), "text/plain")
            .await
            .unwrap();
    }

    let keys = ["a.txt", "b.txt", "c.txt", "never-existed.txt"];
    for attempt in 0..2 {
        let response = app
            .clone()
            .oneshot(delete_objects_request(
                "batch",
                &batch_body(false, &keys),
                &hdrs,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "attempt {attempt}");
        let xml = response_xml(response).await;
        let mut deleted = deleted_keys(&xml);
        deleted.sort();
        assert_eq!(
            deleted,
            ["a.txt", "b.txt", "c.txt", "never-existed.txt"],
            "every key must be answered <Deleted>, including missing keys; attempt {attempt}: {xml}"
        );
        assert!(error_entries(&xml).is_empty(), "{xml}");
    }

    // The keys are gone: a listing is empty and a single GET is 404.
    let list = add_headers(
        Request::builder()
            .method("GET")
            .uri("/batch")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let xml = response_xml(app.clone().oneshot(list).await.unwrap()).await;
    assert!(!xml.contains("<Key>"), "batch must be emptied: {xml}");
    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/batch/a.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(get).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    // The launcher cleans its owned TMPDIR after the child exits.
}

#[tokio::test]
async fn filestore_batch_delete_quiet_mode_suppresses_deleted_but_not_error_entries() {
    let (state, _root) = filestore_state().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let gate = Arc::new(DenyKeysGate {
        denied: vec!["denied.txt".to_string()],
        calls: Mutex::default(),
    });
    let mut state = state;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .policy_gate = Some(gate);
    let app = build_router(state.clone());
    for key in ["kept.txt", "denied.txt"] {
        state
            .file_store
            .as_ref()
            .unwrap()
            .put("batch", key, Bytes::from_static(b"payload"), "text/plain")
            .await
            .unwrap();
    }

    let keys = ["kept.txt", "denied.txt", "missing.txt"];
    let response = app
        .clone()
        .oneshot(delete_objects_request(
            "batch",
            &batch_body(true, &keys),
            &hdrs,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let xml = response_xml(response).await;
    assert!(
        !xml.contains("<Deleted>"),
        "quiet mode must suppress Deleted entries: {xml}"
    );
    assert_eq!(
        error_entries(&xml),
        [("denied.txt".to_string(), "policy.denied".to_string())],
        "quiet mode must never suppress Error entries: {xml}"
    );
    // The launcher cleans its owned TMPDIR after the child exits.
}

#[tokio::test]
async fn filestore_batch_delete_partial_denial_proceeds_per_key() {
    let (state, _root) = filestore_state().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let gate = Arc::new(DenyKeysGate {
        denied: vec!["denied.txt".to_string()],
        calls: Mutex::default(),
    });
    let mut state = state;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .policy_gate = Some(gate.clone());
    let app = build_router(state.clone());
    for key in ["first.txt", "denied.txt", "last.txt"] {
        state
            .file_store
            .as_ref()
            .unwrap()
            .put("batch", key, Bytes::from_static(b"payload"), "text/plain")
            .await
            .unwrap();
    }

    let keys = ["first.txt", "denied.txt", "last.txt", "missing.txt"];
    let response = app
        .clone()
        .oneshot(delete_objects_request(
            "batch",
            &batch_body(false, &keys),
            &hdrs,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let xml = response_xml(response).await;
    let mut deleted = deleted_keys(&xml);
    deleted.sort();
    assert_eq!(
        deleted,
        ["first.txt", "last.txt", "missing.txt"],
        "denial must be per key; the rest proceed: {xml}"
    );
    assert_eq!(
        error_entries(&xml),
        [("denied.txt".to_string(), "policy.denied".to_string())],
        "the denied key lands in Error with its typed code: {xml}"
    );
    // A batch of N keys is N gated Delete operations.
    let mut calls = gate.calls.lock().unwrap().clone();
    calls.sort_by(|a, b| a.1.cmp(&b.1));
    assert_eq!(
        calls
            .iter()
            .map(|(operation, key)| (*operation, key.as_str()))
            .collect::<Vec<_>>(),
        [
            (PolicyOperation::Delete, "denied.txt"),
            (PolicyOperation::Delete, "first.txt"),
            (PolicyOperation::Delete, "last.txt"),
            (PolicyOperation::Delete, "missing.txt"),
        ],
        "every key must present its own Delete verdict"
    );
    // The denied key survives; the others are gone.
    let denied_get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/batch/denied.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(denied_get).await.unwrap().status(),
        StatusCode::OK
    );
    let first_get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/batch/first.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(first_get).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    // The launcher cleans its owned TMPDIR after the child exits.
}

#[tokio::test]
async fn filestore_batch_delete_accepts_exactly_1000_keys() {
    let (state, _root) = filestore_state().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let app = build_router(state.clone());
    let keys: Vec<String> = (0..1000).map(|index| format!("k{index}")).collect();
    for key in &keys {
        state
            .file_store
            .as_ref()
            .unwrap()
            .put("batch", key, Bytes::from_static(b"p"), "text/plain")
            .await
            .unwrap();
    }
    let body = batch_body(false, &keys.iter().map(String::as_str).collect::<Vec<_>>());
    let response = app
        .clone()
        .oneshot(delete_objects_request("batch", &body, &hdrs))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let xml = response_xml(response).await;
    assert_eq!(
        deleted_keys(&xml).len(),
        1000,
        "exactly 1000 keys must be accepted and answered"
    );
    // The launcher cleans its owned TMPDIR after the child exits.
}

#[tokio::test]
async fn filestore_batch_delete_rejects_1001_keys_before_touching_any_key() {
    let (state, _root) = filestore_state().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let app = build_router(state.clone());
    for key in ["victim-a.txt", "victim-b.txt"] {
        state
            .file_store
            .as_ref()
            .unwrap()
            .put("batch", key, Bytes::from_static(b"payload"), "text/plain")
            .await
            .unwrap();
    }
    // The planted keys are listed first: a non-atomic implementation would
    // delete them before discovering the cap is exceeded.
    let mut keys = vec!["victim-a.txt".to_string(), "victim-b.txt".to_string()];
    keys.extend((0..999).map(|index| format!("k{index}")));
    let body = batch_body(false, &keys.iter().map(String::as_str).collect::<Vec<_>>());
    let response = app
        .clone()
        .oneshot(delete_objects_request("batch", &body, &hdrs))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let xml = response_xml(response).await;
    assert!(xml.contains("<Code>MalformedXML</Code>"), "{xml}");
    for key in ["victim-a.txt", "victim-b.txt"] {
        let get = add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/batch/{key}"))
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        );
        assert_eq!(
            app.clone().oneshot(get).await.unwrap().status(),
            StatusCode::OK,
            "{key} must survive a rejected batch"
        );
    }
    // The launcher cleans its owned TMPDIR after the child exits.
}

#[tokio::test]
async fn filestore_batch_delete_rejects_oversized_bodies_before_touching_any_key() {
    let (state, _root) = filestore_state().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let app = build_router(state.clone());
    state
        .file_store
        .as_ref()
        .unwrap()
        .put(
            "batch",
            "victim.txt",
            Bytes::from_static(b"payload"),
            "text/plain",
        )
        .await
        .unwrap();
    let giant = "x".repeat(128 * 1024);
    let body = format!(
        "<Delete><Object><Key>victim.txt</Key></Object><Object><Key>{giant}</Key></Object></Delete>"
    );
    let response = app
        .clone()
        .oneshot(delete_objects_request("batch", &body, &hdrs))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let xml = response_xml(response).await;
    assert!(xml.contains("<Code>EntityTooLarge</Code>"), "{xml}");
    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/batch/victim.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(get).await.unwrap().status(),
        StatusCode::OK,
        "no key may be deleted by a rejected batch"
    );
    // The launcher cleans its owned TMPDIR after the child exits.
}

#[tokio::test]
async fn filestore_batch_delete_rejects_malformed_xml_and_bad_auth_before_touching_any_key() {
    let (state, _root) = filestore_state().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let app = build_router(state.clone());
    state
        .file_store
        .as_ref()
        .unwrap()
        .put(
            "batch",
            "victim.txt",
            Bytes::from_static(b"payload"),
            "text/plain",
        )
        .await
        .unwrap();

    for body in [
        "<Delete><Object><Key>victim.txt</Key></Object",
        "<!DOCTYPE Delete [<!ENTITY x \"boom\">]><Delete><Object><Key>&x;</Key></Object></Delete>",
        "<Delete><Object><Key>victim.txt</Key><VersionId>v</VersionId></Object></Delete>",
    ] {
        let response = app
            .clone()
            .oneshot(delete_objects_request("batch", body, &hdrs))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        let xml = response_xml(response).await;
        assert!(xml.contains("<Code>MalformedXML</Code>"), "{xml}");
    }

    let bad_auth = add_headers(
        Request::builder()
            .method("POST")
            .uri("/batch?delete")
            .header(header::CONTENT_TYPE, "application/xml")
            .body(Body::from(batch_body(false, &["victim.txt"])))
            .unwrap(),
        &[
            ("x-maskura-access-key", ak.clone()),
            ("x-maskura-secret-key", "wrong-secret".to_string()),
        ],
    );
    let response = app.clone().oneshot(bad_auth).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/batch/victim.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(get).await.unwrap().status(),
        StatusCode::OK,
        "no key may be deleted by a rejected batch"
    );
    // The launcher cleans its owned TMPDIR after the child exits.
}

#[tokio::test]
async fn batch_delete_records_one_usage_receipt_per_key() {
    let control = Arc::new(RecordingMeteringControl::default());
    let state = explicit_passthrough_test_state(Some(control.clone())).await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let app = build_router(state.clone());
    for key in ["a.txt", "b.txt", "c.txt"] {
        state
            .store
            .put("batch", key, Bytes::from_static(b"payload"), "text/plain");
    }

    let response = app
        .clone()
        .oneshot(delete_objects_request(
            "batch",
            &batch_body(false, &["a.txt", "b.txt", "c.txt"]),
            &hdrs,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let events = control.events.lock().unwrap().clone();
    assert_eq!(
        events.len(),
        3,
        "a 3-key batch is 3 auditable deletes, not one opaque one"
    );
    assert!(events.iter().all(|call| {
        call.context.user_id == "test-user"
            && call.event.bucket() == "batch"
            && call.event.route() == UsageRoute::DeleteObject
    }));
    let mut receipts: Vec<_> = events.iter().map(|call| call.event.receipt_id()).collect();
    receipts.sort();
    receipts.dedup();
    assert_eq!(
        receipts.len(),
        3,
        "each key must produce its own usage receipt"
    );
}

#[tokio::test]
async fn the_delete_subresource_is_routed_only_on_bucket_level_post() {
    let (state, _root) = filestore_state().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);
    let app = build_router(state.clone());

    for (method, uri) in [
        ("POST", "/batch/key?delete"),
        ("GET", "/batch?delete"),
        ("PUT", "/batch?delete"),
        ("DELETE", "/batch?delete"),
        ("POST", "/batch?deleteSomething"),
        ("POST", "/batch"),
    ] {
        let response = app
            .clone()
            .oneshot(add_headers(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/xml")
                    .body(Body::from(batch_body(false, &["k"])))
                    .unwrap(),
                &hdrs,
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_IMPLEMENTED,
            "{method} {uri} must not route to batch delete"
        );
    }
}
