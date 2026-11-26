//! Byte-preserving storage scopes and conditional writes (ADR 0036/0037).
//!
//! An external table catalog (for example an Iceberg REST catalog) owns its
//! commit lifecycle. The operator declares its bucket/prefix as a
//! byte-preserving scope; covered keys are stored and served exactly as
//! written, with no table classification and no format adapter. These tests
//! pin that matrix, the config/selection boundary, and the conditional-write
//! contract on the real router.

use super::*;

use maskura_gateway::byte_preserving::BytePreservingScopes;
use maskura_gateway::sigv4::SigV4Policy;

/// Builds state with the Iceberg gate in the requested position and the
/// operator scope set. The scope is normally parsed from the environment at
/// startup; tests override the validated value on a uniquely-owned state so
/// parallel tests never race on process globals.
async fn scoped_state(gate_open: bool, scopes: Option<&str>) -> Arc<AppState> {
    let mut config = test_config();
    config.features.enable_iceberg = gate_open;
    let mut state = build_state_with_pipeline_template(
        Arc::new(NoopControlPlane),
        fixture_wrapping(),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        test_pipeline_template(),
        &config,
    )
    .await
    .expect("build scoped state");
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .byte_preserving = BytePreservingScopes::parse(scopes).expect("valid scope configuration");
    state
}

fn put_request(
    uri: &str,
    content_type: &str,
    body: &[u8],
    headers: &[(&'static str, String)],
) -> Request<Body> {
    add_headers(
        Request::builder()
            .method("PUT")
            .uri(uri)
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body.to_vec()))
            .unwrap(),
        headers,
    )
}

fn simple_request(method: &str, uri: &str, headers: &[(&'static str, String)]) -> Request<Body> {
    add_headers(
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
        headers,
    )
}

async fn read_body(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body")
        .to_vec()
}

/// A first table metadata document, exactly as a catalog writes it: unusual
/// spacing and key order prove the bytes are never re-serialized.
const FIRST_METADATA_JSON: &[u8] =
    br#"{ "format-version" : 2,  "location":"s3://warehouse/probe",  "schemas": [] }"#;

#[tokio::test]
async fn scope_stores_catalog_objects_byte_for_byte() {
    let state = scoped_state(false, Some("warehouse/probe")).await;
    let app = build_router(state.clone());
    let (access_key, secret_key) = make_key(&state).await;
    let headers = auth_headers(&access_key, &secret_key);
    let metadata_uri = "/warehouse/probe/metadata/00000-probe.metadata.json";

    // The exact reported failure: a first metadata JSON write. Gate closed,
    // content type octet-stream.
    let response = app
        .clone()
        .oneshot(put_request(
            metadata_uri,
            "application/octet-stream",
            FIRST_METADATA_JSON,
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "in-scope catalog write must not hit the Iceberg gate"
    );

    // `application/json` would be re-serialized by the record decoder; the
    // scope must bypass it.
    let json_uri = "/warehouse/probe/metadata/00001-probe.metadata.json";
    let json_body = br#"{ "format-version" : 2,  "snapshots": [ { "snapshot-id": 1 } ] }"#;
    let response = app
        .clone()
        .oneshot(put_request(
            json_uri,
            "application/json",
            json_body,
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Manifest and data-file media types select adapters outside the scope.
    let manifest = b"Obj\x01manifest-bytes";
    let data_file = b"PAR1parquet-bytes";
    for (uri, content_type, body) in [
        (
            "/warehouse/probe/metadata/snap-1-0-x.avro",
            "application/avro",
            manifest.as_slice(),
        ),
        (
            "/warehouse/probe/data/00000-0-x.parquet",
            "application/vnd.apache.parquet",
            data_file.as_slice(),
        ),
        (
            "/warehouse/probe/metadata/version-hint.text",
            "text/plain",
            b"0\n".as_slice(),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(put_request(uri, content_type, body, &headers))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri} round trip");
    }

    for (uri, content_type, expected) in [
        (
            metadata_uri,
            "application/octet-stream",
            FIRST_METADATA_JSON,
        ),
        (json_uri, "application/json", json_body.as_slice()),
        (
            "/warehouse/probe/metadata/snap-1-0-x.avro",
            "application/avro",
            manifest.as_slice(),
        ),
        (
            "/warehouse/probe/data/00000-0-x.parquet",
            "application/vnd.apache.parquet",
            data_file.as_slice(),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(simple_request("GET", uri, &headers))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri} read");
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(content_type),
            "{uri} content type is preserved"
        );
        assert_eq!(read_body(response).await, expected, "{uri} bytes");
    }

    // HEAD serves the stored metadata: catalogs depend on it.
    let response = app
        .clone()
        .oneshot(simple_request("HEAD", metadata_uri, &headers))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some(FIRST_METADATA_JSON.len().to_string().as_str())
    );

    // Conditional writes work inside the scope: catalogs use them to guard a
    // first commit.
    let mut create = headers.clone();
    create.push(("if-none-match", "*".to_string()));
    let response = app
        .clone()
        .oneshot(put_request(
            "/warehouse/probe/metadata/00002-probe.metadata.json",
            "application/octet-stream",
            FIRST_METADATA_JSON,
            &create,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .oneshot(put_request(
            "/warehouse/probe/metadata/00002-probe.metadata.json",
            "application/octet-stream",
            FIRST_METADATA_JSON,
            &create,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn scope_round_trips_signed_fixed_length_and_chunked_puts() {
    use aws_sigv4::http_request::SignableBody;
    use base64::Engine as _;
    use crc::{CRC_32_ISO_HDLC, Crc};

    let mut state = scoped_state(false, Some("warehouse")).await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .sigv4_policy = SigV4Policy::new("us-east-1", true);
    let app = build_router(state.clone());
    let (access_key, secret_key) = make_key(&state).await;

    let fixed_uri = "http://maskura.local/warehouse/fixed/metadata/00000-fixed.metadata.json";
    let request = signed_request(
        &access_key,
        &secret_key,
        "PUT",
        fixed_uri,
        FIRST_METADATA_JSON,
        &[("content-type", "application/octet-stream")],
    );
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "fixed-length signed PUT");

    // AWS SigV4 streaming framing (`aws-chunked`), the transport shape the
    // reported catalog request used.
    let chunked_uri = "http://maskura.local/warehouse/chunked/metadata/00000-chunked.metadata.json";
    let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let checksum = base64::engine::general_purpose::STANDARD
        .encode(crc.checksum(FIRST_METADATA_JSON).to_be_bytes());
    let framed = format!(
        "{:X}\r\n{}\r\n0\r\nx-amz-checksum-crc32:{checksum}\r\n\r\n",
        FIRST_METADATA_JSON.len(),
        String::from_utf8_lossy(FIRST_METADATA_JSON)
    );
    let decoded_length = FIRST_METADATA_JSON.len().to_string();
    let request = signed_request_with_signable(
        &access_key,
        &secret_key,
        "PUT",
        chunked_uri,
        framed.as_bytes(),
        &[
            ("content-type", "application/octet-stream"),
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", decoded_length.as_str()),
            ("x-amz-sdk-checksum-algorithm", "CRC32"),
            ("x-amz-trailer", "x-amz-checksum-crc32"),
        ],
        SignableBody::StreamingUnsignedPayloadTrailer,
    );
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "chunked signed PUT");

    for uri in [
        "/warehouse/fixed/metadata/00000-fixed.metadata.json",
        "/warehouse/chunked/metadata/00000-chunked.metadata.json",
    ] {
        let response = app
            .clone()
            .oneshot(simple_request(
                "GET",
                uri,
                &auth_headers(&access_key, &secret_key),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        assert_eq!(
            read_body(response).await,
            FIRST_METADATA_JSON,
            "{uri} bytes"
        );
    }
}

#[tokio::test]
async fn the_scope_cannot_be_selected_by_a_request() {
    let gate_closed = scoped_state(false, Some("warehouse/probe")).await;
    let app = build_router(gate_closed.clone());
    let (access_key, secret_key) = make_key(&gate_closed).await;
    let mut headers = auth_headers(&access_key, &secret_key);

    // A header, a query parameter, and a key suffix cannot grant the scope.
    headers.extend([
        ("x-maskura-byte-preserving", "1".to_string()),
        ("x-maskura-storage-mode", "byte-preserving".to_string()),
    ]);
    for uri in [
        // Outside the declared prefix inside the bucket.
        "/warehouse/other/metadata/00000-probe.metadata.json",
        // A sibling prefix that shares the covered prefix's characters.
        "/warehouse/probe2/metadata/00000-probe.metadata.json",
        // Outside the declared bucket, with the would-be selector in the query.
        "/other/probe/metadata/00000-probe.metadata.json?byte-preserving=1",
    ] {
        let response = app
            .clone()
            .oneshot(put_request(
                uri,
                "application/octet-stream",
                FIRST_METADATA_JSON,
                &headers,
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_IMPLEMENTED,
            "{uri} must keep the default gate-closed rejection"
        );
    }

    // The covered key still works against the same state.
    let response = app
        .clone()
        .oneshot(put_request(
            "/warehouse/probe/metadata/00000-probe.metadata.json",
            "application/octet-stream",
            FIRST_METADATA_JSON,
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_same_key_outside_the_scope_keeps_the_adapter_verdict() {
    // Gate closed: 501 before the body is read, nothing stored.
    let closed = scoped_state(false, Some("warehouse")).await;
    let app = build_router(closed.clone());
    let (access_key, secret_key) = make_key(&closed).await;
    let headers = auth_headers(&access_key, &secret_key);
    let uri = "/bucket/probe/metadata/00000-probe.metadata.json";
    let response = app
        .clone()
        .oneshot(put_request(
            uri,
            "application/octet-stream",
            FIRST_METADATA_JSON,
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert!(
        closed
            .store
            .get("bucket", "probe/metadata/00000-probe.metadata.json")
            .is_none()
    );

    // Gate open: the adapter still demands an existing table state.
    let open = scoped_state(true, Some("warehouse")).await;
    let app = build_router(open.clone());
    let (access_key, secret_key) = make_key(&open).await;
    let headers = auth_headers(&access_key, &secret_key);
    let response = app
        .clone()
        .oneshot(put_request(
            uri,
            "application/octet-stream",
            FIRST_METADATA_JSON,
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "processed scope keeps the missing-metadata rejection"
    );
}

#[tokio::test]
async fn invalid_credentials_and_checksums_are_still_rejected_in_scope() {
    let state = scoped_state(false, Some("warehouse")).await;
    let app = build_router(state.clone());
    let (access_key, secret_key) = make_key(&state).await;
    let uri = "/warehouse/probe/metadata/00000-probe.metadata.json";

    let response = app
        .clone()
        .oneshot(put_request(
            uri,
            "application/octet-stream",
            FIRST_METADATA_JSON,
            &auth_headers(&access_key, "not-the-secret"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        state
            .store
            .get("warehouse", "probe/metadata/00000-probe.metadata.json")
            .is_none()
    );

    let mut headers = auth_headers(&access_key, &secret_key);
    headers.push(("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==".to_string()));
    let response = app
        .clone()
        .oneshot(put_request(
            uri,
            "application/octet-stream",
            FIRST_METADATA_JSON,
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "checksum mismatch stays rejected"
    );
    assert!(
        state
            .store
            .get("warehouse", "probe/metadata/00000-probe.metadata.json")
            .is_none()
    );
}

async fn object_etag(app: &Router, uri: &str, headers: &[(&'static str, String)]) -> String {
    let response = app
        .clone()
        .oneshot(simple_request("HEAD", uri, headers))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{uri} HEAD");
    response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("HEAD returns an entity tag")
        .to_string()
}

#[tokio::test]
async fn conditional_writes_compare_and_swap_and_keep_the_previous_object() {
    // Raw reads keep the mechanics observable; the conditional contract is
    // independent of the read pipeline (and of the byte-preserving scope,
    // which the last block exercises).
    let state = explicit_passthrough_test_state(None).await;
    let app = build_router(state.clone());
    let (access_key, secret_key) = make_key(&state).await;
    let headers = auth_headers(&access_key, &secret_key);
    let uri = "/demo/conditional.bin";

    let mut create = headers.clone();
    create.push(("if-none-match", "*".to_string()));
    let response = app
        .clone()
        .oneshot(put_request(
            uri,
            "application/octet-stream",
            b"first",
            &create,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "create-if-absent");

    // A second create-if-absent fails and leaves the first object unchanged.
    let response = app
        .clone()
        .oneshot(put_request(
            uri,
            "application/octet-stream",
            b"second",
            &create,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    let response = app
        .clone()
        .oneshot(simple_request("GET", uri, &headers))
        .await
        .unwrap();
    assert_eq!(read_body(response).await, b"first");

    let first_etag = object_etag(&app, uri, &headers).await;

    // A matching entity tag publishes the replacement.
    let mut matching = headers.clone();
    matching.push(("if-match", first_etag.clone()));
    let response = app
        .clone()
        .oneshot(put_request(
            uri,
            "application/octet-stream",
            b"second",
            &matching,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // A stale entity tag fails and the second object stays.
    let response = app
        .clone()
        .oneshot(put_request(
            uri,
            "application/octet-stream",
            b"third",
            &matching,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    let response = app
        .clone()
        .oneshot(simple_request("GET", uri, &headers))
        .await
        .unwrap();
    assert_eq!(read_body(response).await, b"second");

    // Combining both conditional headers is an invalid request.
    let mut both = headers.clone();
    both.push(("if-match", "*".to_string()));
    both.push(("if-none-match", "*".to_string()));
    let response = app
        .clone()
        .oneshot(put_request(uri, "application/octet-stream", b"x", &both))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
