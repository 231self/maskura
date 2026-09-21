use super::*;

#[tokio::test]
async fn put_get_roundtrip_filters_pii() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/demo/notes.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("contact a@b.com now"))
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "PUT should succeed");

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/demo/notes.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("[REDACTED_EMAIL]"), "email redacted: {text}");
    assert!(
        !text.contains("a@b.com"),
        "raw email must not be stored: {text}"
    );
}

#[tokio::test]
async fn put_with_unsupported_content_encoding_is_rejected_without_polling_body() {
    let state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let app = build_router(state.clone());

    for encoding in ["gzip", "aws-chunked,gzip", "br"] {
        let polls = Arc::new(AtomicUsize::new(0));
        let request = add_headers(
            Request::builder()
                .method("PUT")
                .uri("/enc/object.txt")
                .header(header::CONTENT_TYPE, "text/plain")
                .header(header::CONTENT_ENCODING, encoding)
                .body(Body::new(PollTrackingBody {
                    polls: polls.clone(),
                    data: Some(Bytes::from_static(b"compressed bytes must not be read")),
                }))
                .unwrap(),
            &auth_headers(&access_key, &secret_key),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Content-Encoding {encoding} must be rejected"
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            0,
            "Content-Encoding {encoding} PUT must not buffer the body"
        );
    }
    assert!(state.store.get("enc", "object.txt").is_none());
}

#[tokio::test]
async fn memory_list_continuations_are_opaque_bound_and_tamper_resistant() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    for key in ["a.txt", "b.txt"] {
        state
            .store
            .put("page", key, Bytes::from_static(b"x"), "text/plain");
    }
    let page = add_headers(
        Request::builder()
            .method("GET")
            .uri("/page?list-type=2&max-keys=1")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(page).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let xml = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let token = xml
        .split("<NextContinuationToken>")
        .nth(1)
        .and_then(|value| value.split("</NextContinuationToken>").next())
        .expect("truncated listing has next token");
    assert!(!token.contains("a.txt"));

    let next = add_headers(
        Request::builder()
            .method("GET")
            .uri(format!(
                "/page?list-type=2&max-keys=1&continuation-token={token}"
            ))
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(next).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Key>b.txt</Key>"));

    let bad = add_headers(
        Request::builder()
            .method("GET")
            .uri("/page?list-type=2&continuation-token=not-a-token")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(bad).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let zero_page = add_headers(
        Request::builder()
            .method("GET")
            .uri("/page?list-type=2&max-keys=0")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(zero_page).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<IsTruncated>false</IsTruncated>"));

    for key in ["logs/one/a.txt", "logs/two/a.txt"] {
        state
            .store
            .put("page", key, Bytes::from_static(b"x"), "text/plain");
    }
    let delimiter_page = add_headers(
        Request::builder()
            .method("GET")
            .uri("/page?list-type=2&prefix=logs%2F&delimiter=%2F&max-keys=1")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(delimiter_page).await.unwrap();
    let xml = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(xml.contains("<Prefix>logs/one/</Prefix>"));
    let token = xml
        .split("<NextContinuationToken>")
        .nth(1)
        .and_then(|value| value.split("</NextContinuationToken>").next())
        .expect("delimiter page has a next token");
    let next_delimiter_page = add_headers(
        Request::builder()
            .method("GET")
            .uri(format!(
                "/page?list-type=2&prefix=logs%2F&delimiter=%2F&max-keys=1&continuation-token={token}"
            ))
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.oneshot(next_delimiter_page).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Prefix>logs/two/</Prefix>"));
    assert!(!xml.contains("<Prefix>logs/one/</Prefix>"));
}

#[tokio::test]
async fn list_buckets_at_root() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/mybkt/obj")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("x"))
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(put).await.unwrap().status(),
        StatusCode::OK
    );

    let list = add_headers(
        Request::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(list).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Name>mybkt</Name>"), "bucket missing: {xml}");
}

#[tokio::test]
async fn create_bucket_is_rejected() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let mb = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/new-bucket")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(mb).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(
        xml.contains("AccessDenied"),
        "expected S3 AccessDenied: {xml}"
    );
}

#[tokio::test]
async fn head_and_delete_remain_available() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bkt/lifecycle.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("payload"))
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(put).await.unwrap().status(),
        StatusCode::OK
    );

    let head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/bkt/lifecycle.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let head_response = app.clone().oneshot(head).await.unwrap();
    assert_eq!(head_response.status(), StatusCode::OK);
    assert!(head_response.headers().contains_key(header::CONTENT_LENGTH));

    let delete = add_headers(
        Request::builder()
            .method("DELETE")
            .uri("/bkt/lifecycle.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.clone().oneshot(delete).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bkt/lifecycle.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    assert_eq!(
        app.oneshot(get).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn conditional_get_and_head_preserve_object_identity_without_a_body() {
    let mut state = test_state().await;
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    state.store.put(
        "conditional",
        "object.txt",
        Bytes::from_static(b"conditional payload"),
        "text/plain",
    );
    let etag = state
        .store
        .metadata("conditional", "object.txt")
        .expect("stored object metadata")
        .2;
    let control = Arc::new(RecordingMeteringControl::default());
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .control = control.clone();
    let app = build_router(state);

    let not_modified = add_headers(
        Request::builder()
            .method("GET")
            .uri("/conditional/object.txt")
            .header(header::IF_NONE_MATCH, &etag)
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(not_modified).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(response.headers()[header::ETAG], etag);
    assert_hardened_object_headers(response.headers());
    assert!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );

    let failed_match = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/conditional/object.txt")
            .header(header::IF_MATCH, "\"different\"")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.oneshot(failed_match).await.unwrap();
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(response.headers()[header::ETAG], etag);
    assert_hardened_object_headers(response.headers());
    assert!(control.events.lock().unwrap().is_empty());
    let authorizations = control.authorizations.lock().unwrap();
    let releases = control.releases.lock().unwrap();
    assert_eq!(authorizations.len(), 2);
    assert_eq!(releases.len(), 2);
    for ((_, authorization), (_, released)) in authorizations.iter().zip(releases.iter()) {
        assert_eq!(authorization.operation_id(), *released);
    }
    assert_eq!(authorizations[0].1.route(), UsageRoute::GetObject);
    assert_eq!(authorizations[1].1.route(), UsageRoute::HeadObject);
}

#[tokio::test]
async fn object_get_forces_browser_safe_download_headers_for_html() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.store.put(
        "download",
        "attacker-name.html",
        bytes::Bytes::from_static(b"<script>document.cookie='stolen=1'</script>"),
        "text/html; charset=utf-8",
    );
    let (ak, sk) = make_key(&state).await;
    let app = build_router(state);
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/download/attacker-name.html")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    assert_hardened_object_headers(response.headers());
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "<script>document.cookie='stolen=1'</script>"
    );
}

#[tokio::test]
async fn percent_decoded_object_and_bucket_resources_cannot_inject_s3_error_xml() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let encoded = "%3CInjected%3Eresource%3C%2FInjected%3E%26%22%27";

    for (method, uri, status) in [
        ("GET", format!("/escape/{encoded}"), StatusCode::NOT_FOUND),
        ("PUT", format!("/{encoded}"), StatusCode::FORBIDDEN),
    ] {
        let response = app
            .clone()
            .oneshot(add_headers(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
                &headers,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_hardened_object_headers(response.headers());
        let body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        assert_s3_error_has_only_expected_xml_elements(&body);
        assert!(!body.contains("<Injected>"));
        assert!(
            body.contains("&lt;Injected&gt;resource&lt;/Injected&gt;&amp;&quot;&apos;"),
            "escaped resource missing from {body}"
        );
    }
}

#[tokio::test]
async fn content_md5_covers_source_bytes_before_transformation() {
    use base64::Engine as _;
    use md5::{Digest as _, Md5};

    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .dev_memory_streaming_enabled = true;
    let (access_key, secret_key) = make_key(&state).await;
    let app = build_router(state.clone());
    let input = b"contact a@b.com now\n";
    let output = b"contact [REDACTED_EMAIL] now\n";
    let source_md5 = base64::engine::general_purpose::STANDARD.encode(Md5::digest(input));
    let output_md5 = base64::engine::general_purpose::STANDARD.encode(Md5::digest(output));

    let accepted = signed_request(
        &access_key,
        &secret_key,
        "PUT",
        "http://maskura.local/md5/source.txt",
        input,
        &[("content-type", "text/plain"), ("content-md5", &source_md5)],
    );
    assert_eq!(
        app.clone().oneshot(accepted).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        state.store.get("md5", "source.txt").unwrap().data,
        Bytes::from_static(output)
    );

    for (key, digest) in [
        ("transformed.txt", output_md5.as_str()),
        ("malformed.txt", "not-base64"),
        ("wrong-length.txt", "aGVsbG8="),
    ] {
        let request = signed_request(
            &access_key,
            &secret_key,
            "PUT",
            &format!("http://maskura.local/md5/{key}"),
            input,
            &[("content-type", "text/plain"), ("content-md5", digest)],
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{key}");
        assert!(state.store.get("md5", key).is_none(), "{key}");
    }
}

#[tokio::test]
async fn tsv_roundtrip_filters_and_preserves() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let body = "email\tcard\tnote\nalice@example.com\t4111111111111111\thi\nbob@test.org\t5500005555555559\tbye\n";
    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/demo/data.tsv")
            .header(header::CONTENT_TYPE, "text/tab-separated-values")
            .body(Body::from(body))
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "TSV PUT should succeed");

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/demo/data.tsv")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let out = String::from_utf8_lossy(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .to_string();

    assert!(
        out.contains("[REDACTED_EMAIL]"),
        "TSV email redacted: {out}"
    );
    assert!(out.contains("[REDACTED_CARD]"), "TSV card redacted: {out}");
    assert!(out.contains("note"), "TSV header preserved: {out}");
    assert!(out.contains("hi"), "TSV non-PII value preserved: {out}");
    assert!(out.contains("bye"), "TSV second record preserved: {out}");
}

#[tokio::test]
async fn unmodified_rust_sdk_default_put_is_accepted() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .sigv4_policy = SigV4Policy::new("us-east-1", true);
    let (access_key, secret) = make_key(&state).await;
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let config = aws_sdk_s3::Config::builder()
        .behavior_version_latest()
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            access_key,
            secret,
            None,
            None,
            "phase-4-rust-sdk",
        ))
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .endpoint_url(format!("http://{address}"))
        .force_path_style(true)
        .build();
    let client = aws_sdk_s3::Client::from_conf(config);
    client
        .put_object()
        .bucket("sdk-bucket")
        .key("default-put.txt")
        .content_type("text/plain")
        .body(aws_sdk_s3::primitives::ByteStream::from_static(
            b"SDK contact sdk@example.com",
        ))
        .send()
        .await
        .expect("unmodified Rust SDK PUT");

    let stored = state
        .store
        .get("sdk-bucket", "default-put.txt")
        .expect("SDK object stored only after integrity verification");
    let text = String::from_utf8_lossy(&stored.data);
    assert!(text.contains("[REDACTED_EMAIL]"), "stored body: {text}");
    assert!(!text.contains("sdk@example.com"), "stored body: {text}");
    server.abort();
}

#[tokio::test]
async fn in_flight_put_keeps_the_assignment_frozen_before_body_polling() {
    let mut state = test_state().await;
    let frozen = StaticPipelineResolver::new(state.plugins.clone())
        .resolve("seed", "seed", PipelineDirection::Write)
        .await
        .unwrap();
    let mut replacement = frozen.clone();
    replacement.locator.revision = "replacement".to_string();
    replacement.steps.clear();
    replacement.explicit_passthrough = true;
    let (resolved_sender, resolved_receiver) = tokio::sync::oneshot::channel();
    let resolver = Arc::new(SwitchingResolver {
        current: Mutex::new(frozen),
        first_resolved: Mutex::new(Some(resolved_sender)),
    });
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.gateway = Arc::new(
        state_mut
            .gateway
            .as_ref()
            .clone()
            .with_resolver(resolver.clone(), state_mut.plugins.clone()),
    );
    let credentials = make_key(&state).await;
    let app = build_router(state);
    let (body_sender, body_receiver) = tokio::sync::mpsc::channel(1);
    let request = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/freeze/object.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::new(ChannelBody {
                receiver: body_receiver,
            }))
            .unwrap(),
        &auth_headers(&credentials.0, &credentials.1),
    );
    let request_task = tokio::spawn(app.clone().oneshot(request));
    resolved_receiver
        .await
        .expect("request resolves before polling the body");
    *resolver.current.lock().unwrap() = replacement;
    body_sender
        .send(Bytes::from_static(b"alice@example.com"))
        .await
        .unwrap();
    drop(body_sender);
    let response = request_task.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/freeze/object.txt")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&credentials.0, &credentials.1),
        ))
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body, "[REDACTED_EMAIL]");
}
