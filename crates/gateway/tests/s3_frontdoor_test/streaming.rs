use super::*;

#[tokio::test]
async fn streaming_put_is_frame_invariant_and_preserves_separators() {
    let input = b"contact a@b.com now\r\nsecond line\n";
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.auth_disabled = true;
    state_mut.dev_memory_streaming_enabled = true;
    state_mut.source_body_limits.max_frame_bytes = input.len().max(1);
    let app = build_router(state.clone());
    for split in 0..=input.len() {
        let key = format!("split-{split}.txt");
        let body = Body::new(FrameSequenceBody::data([
            Bytes::copy_from_slice(&input[..split]),
            Bytes::copy_from_slice(&input[split..]),
        ]));
        let request = Request::builder()
            .method("PUT")
            .uri(format!("/stream/{key}"))
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(body)
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "split {split}");
        let stored = state.store.get("stream", &key).expect("committed object");
        assert_eq!(
            stored.data,
            Bytes::from_static(b"contact [REDACTED_EMAIL] now\r\nsecond line\n"),
            "split {split}"
        );
    }
}

#[tokio::test]
async fn streaming_put_limit_failure_has_no_partial_visibility() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.auth_disabled = true;
    state_mut.dev_memory_streaming_enabled = true;
    state_mut.source_body_limits.max_frame_bytes = 4;
    state_mut.source_body_limits.max_bytes = 7;
    let app = build_router(state.clone());
    let request = Request::builder()
        .method("PUT")
        .uri("/stream/too-large.txt")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::new(FrameSequenceBody::data([
            Bytes::from_static(b"1234"),
            Bytes::from_static(b"5678"),
        ])))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&response_body).contains("<Code>EntityTooLarge</Code>"));
    assert!(state.store.get("stream", "too-large.txt").is_none());
}

#[tokio::test]
async fn streaming_read_off_rejects_get_without_buffering() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Off;
    let app = build_router(state.clone());

    // Read mode off: GET rejects without buffering or disclosing the object.
    state.store.put(
        "off",
        "object.txt",
        Bytes::from_static(b"payload"),
        "text/plain",
    );
    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/off/object.txt")
            .body(Body::empty())
            .unwrap(),
        &auth_headers(&access_key, &secret_key),
    );
    let response = app.oneshot(get).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&body).contains("payload"),
        "read-mode-off GET must not buffer the object body"
    );
}

#[tokio::test]
async fn unsupported_streaming_backend_is_rejected_without_polling_body() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.dev_memory_streaming_enabled = false;
    let app = build_router(state);
    let polls = Arc::new(AtomicUsize::new(0));
    let request = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/stream/unsupported.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::new(PollTrackingBody {
                polls: polls.clone(),
                data: Some(Bytes::from_static(b"must not be read")),
            }))
            .unwrap(),
        &auth_headers(&access_key, &secret_key),
    );
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn avro_acquires_workspace_lease_before_first_body_poll() {
    let config = test_config();
    let mut state = build_state_with_pipeline_template(
        Arc::new(NoopControlPlane),
        default_wrapping().expect("wrapping"),
        Arc::new(RejectingAttestedRepository),
        test_pipeline_template(),
        &config,
    )
    .await
    .expect("build attested test state");
    let (access_key, secret_key) = make_key(&state).await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.binary_avro_enabled = true;
    state_mut.dev_memory_streaming_enabled = false;
    let journal: Arc<dyn OperationJournal> = Arc::new(InMemoryOperationJournal::durable_for_test());
    state_mut.operation_journal = Some(journal);
    state_mut.workspace_endpoint_policy = WorkspaceEndpointPolicy::new(
        true,
        Vec::<String>::new(),
        Vec::<String>::new(),
        Arc::new(FixedPublicResolver),
    )
    .unwrap();
    let app = build_router(state);
    let polls = Arc::new(AtomicUsize::new(0));
    let request = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/stream/rejected.avro")
            .header(header::CONTENT_TYPE, "application/avro")
            .body(Body::new(PollTrackingBody {
                polls: polls.clone(),
                data: Some(Bytes::from_static(b"must not be read")),
            }))
            .unwrap(),
        &auth_headers(&access_key, &secret_key),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        polls.load(Ordering::SeqCst),
        0,
        "default-rejecting lease repository must fail before Avro body polling"
    );
}

#[tokio::test]
async fn avro_decoder_failure_aborts_admitted_sink_without_visibility() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.binary_avro_enabled = true;
    state_mut.dev_memory_streaming_enabled = true;
    let app = build_router(state.clone());
    let request = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/stream/invalid.avro")
            .header(header::CONTENT_TYPE, "application/avro")
            .body(Body::from("not an Avro object container"))
            .unwrap(),
        &auth_headers(&access_key, &secret_key),
    );

    let response = app.oneshot(request).await.unwrap();
    assert!(!response.status().is_success());
    assert!(state.store.get("stream", "invalid.avro").is_none());
}

#[tokio::test]
#[ignore = "soak: run via `just soak-streaming` or the weekly workflow"]
async fn soak_streaming_roundtrip_holds_under_repetition() {
    let iterations = std::env::var("MASKURA_SOAK_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(200);
    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    let headers = auth_headers(&access_key, &secret_key);

    for i in 0..iterations {
        let key = format!("roundtrip-{i}.txt");
        let body = format!("contact person-{i}@example.com card 4111111111111111");

        let put = add_headers(
            Request::builder()
                .method("PUT")
                .uri(format!("/soak/{key}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(body))
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(put).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "soak PUT {i}");

        let get = add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/soak/{key}"))
                .body(Body::empty())
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(get).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "soak GET {i}");
        let stored = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&stored);
        assert!(
            text.contains("REDACTED_EMAIL"),
            "soak GET {i} redacted: {text}"
        );
        assert!(
            !text.contains("@example.com"),
            "soak GET {i} leaked PII: {text}"
        );
    }
}

#[tokio::test]
async fn streaming_memory_get_preserves_range_and_head_metadata() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.store.put(
        "range",
        "object.txt",
        bytes::Bytes::from_static(b"0123456789"),
        "text/plain",
    );
    state_mut.store.put(
        "range",
        "unsafe<name>&.txt",
        bytes::Bytes::from_static(b"0123456789"),
        "text/plain",
    );
    state_mut
        .store
        .put("range", "empty.txt", bytes::Bytes::new(), "text/plain");
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let app = build_router(state);

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/range/object.txt")
            .header(header::RANGE, "bytes=2-5")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(get).await.unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "4");
    assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 2-5/10");
    assert_eq!(response.headers()[header::ACCEPT_RANGES], "bytes");
    assert_hardened_object_headers(response.headers());
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "2345"
    );

    let suffix = add_headers(
        Request::builder()
            .method("GET")
            .uri("/range/object.txt")
            .header(header::RANGE, "bytes=-3")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(suffix).await.unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "3");
    assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 7-9/10");
    assert_hardened_object_headers(response.headers());
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "789"
    );

    for (uri, range, object_length, escaped_key) in [
        (
            "/range/unsafe%3Cname%3E%26.txt",
            "bytes=20-30",
            10,
            "unsafe&lt;name&gt;&amp;.txt",
        ),
        ("/range/object.txt", "not-a-byte-range", 10, "object.txt"),
        ("/range/empty.txt", "bytes=0-0", 0, "empty.txt"),
    ] {
        let invalid = add_headers(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::RANGE, range)
                .body(Body::empty())
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(invalid).await.unwrap();
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            response.headers()[header::CONTENT_RANGE],
            format!("bytes */{object_length}")
        );
        assert_hardened_object_headers(response.headers());
        let body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert_s3_error_has_only_expected_xml_elements(&body);
        assert!(body.contains("<Code>InvalidRange</Code>"), "{body}");
        assert!(
            body.contains(&format!("<Key>{escaped_key}</Key>")),
            "{body}"
        );
        assert!(!body.contains("<name>"), "{body}");
    }

    let head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/range/object.txt")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.oneshot(head).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "10");
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
    assert_hardened_object_headers(response.headers());
    assert!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn streaming_file_get_preserves_frames_ranges_and_metadata_only_head() {
    let root =
        std::env::temp_dir().join(format!("maskura-file-frontdoor-{}", uuid::Uuid::now_v7()));
    let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
    let payload = Bytes::from_static(b"0123456789abcdefghij");
    let stored = store
        .put("range", "object.txt", payload.clone(), "text/plain")
        .await
        .unwrap();
    store
        .put("range", "empty.txt", Bytes::new(), "text/plain")
        .await
        .unwrap();

    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.source_body_limits = BodyLimits {
        max_frame_bytes: 4,
        max_bytes: 1024,
    };
    state_mut.file_store = Some(store);
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let app = build_router(state);

    let full = add_headers(
        Request::builder()
            .method("GET")
            .uri("/range/object.txt")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(full).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_LENGTH],
        payload.len().to_string()
    );
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
    assert_eq!(response.headers()[header::ETAG], stored.etag);
    assert_eq!(response.headers()[header::ACCEPT_RANGES], "bytes");
    assert_hardened_object_headers(response.headers());
    let (body, frames) = collect_data_frames(response.into_body()).await.unwrap();
    assert_eq!(body, payload);
    assert!(frames.len() > 2);
    assert!(frames.iter().all(|length| *length <= 4));

    for (range, expected_range, expected_body) in [
        ("bytes=0-3", "bytes 0-3/20", "0123"),
        ("bytes=4-", "bytes 4-19/20", "456789abcdefghij"),
        ("bytes=-3", "bytes 17-19/20", "hij"),
        ("bytes=16-100", "bytes 16-19/20", "ghij"),
    ] {
        let request = add_headers(
            Request::builder()
                .method("GET")
                .uri("/range/object.txt")
                .header(header::RANGE, range)
                .body(Body::empty())
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT, "{range}");
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH],
            expected_body.len().to_string()
        );
        assert_eq!(response.headers()[header::CONTENT_RANGE], expected_range);
        assert_eq!(response.headers()[header::ETAG], stored.etag);
        let (body, frames) = collect_data_frames(response.into_body()).await.unwrap();
        assert_eq!(body, expected_body, "{range}");
        assert!(frames.iter().all(|length| *length <= 4), "{range}");
    }

    for (uri, range, object_length) in [
        ("/range/object.txt", "not-a-byte-range", 20),
        ("/range/object.txt", "bytes=0-1,4-5", 20),
        ("/range/object.txt", "bytes=-0", 20),
        ("/range/object.txt", "bytes=8-7", 20),
        ("/range/empty.txt", "bytes=0-0", 0),
    ] {
        let request = add_headers(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header(header::RANGE, range)
                .body(Body::empty())
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::RANGE_NOT_SATISFIABLE,
            "{range}"
        );
        assert_eq!(
            response.headers()[header::CONTENT_RANGE],
            format!("bytes */{object_length}")
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("<Code>InvalidRange</Code>"));
    }

    let objects_dir = root.join("buckets/range/objects");
    for entry in std::fs::read_dir(&objects_dir).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/range/object.txt")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(head).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_LENGTH],
        payload.len().to_string()
    );
    assert_eq!(response.headers()[header::ETAG], stored.etag);
    assert!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty()
    );

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/range/object.txt")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.oneshot(get).await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn streaming_file_get_enforces_source_limit_during_body_read() {
    let root = std::env::temp_dir().join(format!("maskura-file-limit-{}", uuid::Uuid::now_v7()));
    let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
    store
        .put(
            "limit",
            "object.txt",
            Bytes::from_static(b"123456789"),
            "text/plain",
        )
        .await
        .unwrap();
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.source_body_limits = BodyLimits {
        max_frame_bytes: 4,
        max_bytes: 7,
    };
    state_mut.file_store = Some(store);
    let (ak, sk) = make_key(&state).await;
    let response = build_router(state)
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/limit/object.txt")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let error = collect_data_frames(response.into_body()).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("source body is at least 8 bytes")
    );
    assert!(!error.to_string().contains("123456789"));
    std::fs::remove_dir_all(root).unwrap();
}

// These are original Rust scenarios based on observable behavior covered by
// LocalStack's Apache-2.0 S3 suite and MinIO Mint's cross-SDK compatibility suite.

#[tokio::test]
async fn transformed_read_is_rejected_without_exposing_raw_data() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    // Seed RAW data at rest — as if written by the user's own S3 client or a
    // pre-existing bucket (write-time pipeline not involved).
    state.store.put(
        "rawbkt",
        "doc.json",
        br#"{"email":"alice@example.com","card":"4111111111111111","note":"hi"}"#.to_vec(),
        "application/json",
    );

    // Plain GET returns raw (PII intact).
    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/rawbkt/doc.json")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(get).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let raw = String::from_utf8_lossy(&body);
    assert!(
        raw.contains("alice@example.com"),
        "raw read keeps PII: {raw}"
    );

    let transformed_get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/rawbkt/doc.json")
            .header("x-maskura-process", "read")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(transformed_get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let rejected = String::from_utf8_lossy(&body);
    assert!(
        rejected.contains("<Code>NotImplemented</Code>"),
        "typed rejection: {rejected}"
    );
    assert!(
        !rejected.contains("alice@example.com") && !rejected.contains("4111111111111111"),
        "rejection must not leak raw PII: {rejected}"
    );
}

#[tokio::test]
async fn transformed_read_is_rejected_before_object_lookup() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/rawbkt/does-not-exist.json")
            .header("x-maskura-process", "true")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Code>NotImplemented</Code>"), "{xml}");
    assert!(!xml.contains("NoSuchKey"), "lookup must not run: {xml}");
}

#[tokio::test]
async fn legacy_body_limit_no_longer_bounds_streaming_put_or_passthrough_get() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .legacy_max_object_bytes = 8;
    let app = build_router(state.clone());
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    // The legacy buffered PUT path is gone: the configured legacy cap no
    // longer bounds a streaming PUT, which is instead capped by the dev
    // memory sink (16 MiB default).
    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/limits/custom.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("abcdefghij"))
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(put).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "legacy cap must not bound PUT"
    );
    assert!(state.store.get("limits", "custom.txt").is_some());

    // Passthrough GET streams the stored object regardless of the legacy cap.
    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/limits/custom.txt")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        body.as_ref(),
        b"abcdefghij",
        "passthrough GET must not buffer or reject against the legacy cap"
    );
}

#[tokio::test]
async fn stable_transformed_reads_are_rejected_without_disclosure() {
    let (app, state) = router().await;

    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    // Two raw records sharing a join key (email), different notes.
    state.store.put(
        "j1",
        "a.json",
        br#"{"email":"alice@example.com","note":"first"}"#.to_vec(),
        "application/json",
    );
    state.store.put(
        "j1",
        "b.json",
        br#"{"email":"alice@example.com","note":"second"}"#.to_vec(),
        "application/json",
    );

    let get = |key: &str| {
        add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/j1/{key}"))
                .header("x-maskura-process", "read")
                .header("x-maskura-stable-fields", "email")
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        )
    };

    let ra = app.clone().oneshot(get("a.json")).await.unwrap();
    let rb = app.clone().oneshot(get("b.json")).await.unwrap();
    assert_eq!(ra.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(rb.status(), StatusCode::NOT_IMPLEMENTED);
    let ta = String::from_utf8_lossy(
        &axum::body::to_bytes(ra.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .to_string();
    let tb = String::from_utf8_lossy(
        &axum::body::to_bytes(rb.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .to_string();

    assert!(!ta.contains("alice@example.com"), "a leaks PII: {ta}");
    assert!(!tb.contains("alice@example.com"), "b leaks PII: {tb}");
    assert!(ta.contains("<Code>NotImplemented</Code>"), "{ta}");
    assert!(tb.contains("<Code>NotImplemented</Code>"), "{tb}");
}

#[tokio::test]
async fn unsafe_transformed_read_stages_then_sanitizes_source_headers() {
    let mut state = test_state().await;
    let spool_dir = std::env::temp_dir().join(format!(
        "maskura-read-spool-router-{}",
        uuid::Uuid::now_v7()
    ));
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    let control = Arc::new(RecordingMeteringControl::default());
    state_mut.streaming_read_mode = StreamingReadMode::Transformed;
    state_mut.transformed_read_spool_enabled = true;
    state_mut.spool_config.directory = spool_dir.clone();
    state_mut.spool_config.max_object_bytes = 1024;
    state_mut.spool_quota = Arc::new(SpoolQuota::new(2048));
    state_mut.control = control.clone();
    state.store.put(
        "read",
        "raw.txt",
        Bytes::from_static(b"contact alice@example.com\n"),
        "text/plain; charset=utf-8",
    );
    let (ak, sk) = make_key(&state).await;
    let app = build_router(state);
    let response = app
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/read/raw.txt")
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    assert_hardened_object_headers(response.headers());
    assert!(!response.headers().contains_key(header::ETAG));
    assert!(!response.headers().contains_key(header::ACCEPT_RANGES));
    assert!(!response.headers().contains_key(header::CONTENT_RANGE));
    assert!(!response.headers().contains_key("x-amz-version-id"));
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "contact [REDACTED_EMAIL]\n"
    );
    assert!(
        std::fs::read_dir(&spool_dir).unwrap().next().is_none(),
        "staged ciphertext must be removed after replay"
    );
    let events = control.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0]
            .event
            .pipeline_evidence()
            .expect("unsafe read records pipeline evidence")
            .spool_mode,
        "encrypted"
    );
}

#[tokio::test]
async fn transformed_read_rejects_range_part_head_encoding_and_unknown_format() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Transformed;
    state_mut.transformed_read_spool_enabled = true;
    state.store.put(
        "read",
        "good.txt",
        Bytes::from_static(b"secret"),
        "text/plain",
    );
    state.store.put(
        "read",
        "unknown.bin",
        Bytes::from_static(b"alice@example.com"),
        "application/octet-stream",
    );
    let (ak, sk) = make_key(&state).await;
    let app = build_router(state);
    for (method, uri, extra_header) in [
        ("GET", "/read/good.txt", Some((header::RANGE, "bytes=0-1"))),
        ("GET", "/read/good.txt?partNumber=1", None),
        ("HEAD", "/read/good.txt", None),
        ("GET", "/read/unknown.bin", None),
    ] {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-maskura-process", "read");
        if let Some((name, value)) = extra_header {
            request = request.header(name, value);
        }
        let response = app
            .clone()
            .oneshot(add_headers(
                request.body(Body::empty()).unwrap(),
                &auth_headers(&ak, &sk),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{method} {uri}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        if method != "HEAD" {
            assert!(String::from_utf8_lossy(&body).contains("<Code>InvalidRequest</Code>"));
        }
        assert!(!String::from_utf8_lossy(&body).contains("alice@example.com"));
    }
}

#[tokio::test]
async fn unsafe_transformed_read_refuses_unavailable_staging_without_disclosure() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Transformed;
    state_mut.transformed_read_spool_enabled = true;
    state_mut.spool_config.max_object_bytes = 4;
    state_mut.spool_quota = Arc::new(SpoolQuota::new(4));
    state.store.put(
        "read",
        "large.txt",
        Bytes::from_static(b"alice@example.com"),
        "text/plain",
    );
    let (ak, sk) = make_key(&state).await;
    let response = build_router(state)
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/read/large.txt")
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Code>ServiceUnavailable</Code>"));
    assert!(!String::from_utf8_lossy(&body).contains("alice@example.com"));
}

#[tokio::test]
async fn unsafe_transformed_failures_never_disclose_early_late_or_finish_output() {
    for (name, payload, stable_fields, later_filter, status) in [
        (
            "early reject",
            "reject sensitive-source",
            None,
            false,
            StatusCode::BAD_REQUEST,
        ),
        (
            "later reject",
            "reject sensitive-source",
            None,
            true,
            StatusCode::BAD_REQUEST,
        ),
        (
            "transform trap",
            "trap sensitive-source",
            None,
            false,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (
            "finish trap",
            "safe-before-finish",
            Some("finish-trap"),
            false,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ] {
        let state = unsafe_transformed_test_state(later_filter).await;
        state
            .store
            .put("read", "failure.txt", payload, "text/plain");
        let (ak, sk) = make_key(&state).await;
        let mut request = Request::builder()
            .method("GET")
            .uri("/read/failure.txt")
            .header("x-maskura-process", "read");
        if let Some(stable_fields) = stable_fields {
            request = request.header("x-maskura-stable-fields", stable_fields);
        }
        let response = build_router(state)
            .oneshot(add_headers(
                request.body(Body::empty()).unwrap(),
                &auth_headers(&ak, &sk),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{name}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&body).contains(payload),
            "{name} disclosed source bytes: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[tokio::test]
async fn unsafe_transformed_source_limit_has_no_disclosure() {
    let mut state = unsafe_transformed_test_state(false).await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .source_body_limits = BodyLimits {
        max_frame_bytes: 4,
        max_bytes: 4,
    };
    state.store.put("read", "limit.txt", "12345", "text/plain");
    let (ak, sk) = make_key(&state).await;
    let response = build_router(state)
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/read/limit.txt")
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("12345"));
}

#[tokio::test]
async fn nonempty_prefix_safe_reads_stream_and_settle_without_spool() {
    async fn unknown_length_source(
        method: axum::http::Method,
        uri: axum::http::Uri,
    ) -> axum::response::Response {
        let empty = method == axum::http::Method::HEAD || uri.path().ends_with("/empty.txt");
        let body = if empty {
            Body::new(FrameSequenceBody::data(std::iter::empty::<Bytes>()))
        } else {
            Body::new(FrameSequenceBody::data([Bytes::from_static(b"one\ntwo\n")]))
        };
        let mut response = axum::response::Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::ETAG, "\"unknown-length\"");
        if !empty {
            response = response.header(header::CONTENT_LENGTH, "8");
        }
        response.body(body).unwrap()
    }

    let upstream = Router::new().route(
        "/{bucket}/{*key}",
        axum::routing::get(unknown_length_source).head(unknown_length_source),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, upstream).await.unwrap();
    });

    let mut state = test_state().await;
    let control = Arc::new(RecordingMeteringControl::default());
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    let spool_dir = std::env::temp_dir().join(format!(
        "maskura-direct-read-no-spool-{}",
        uuid::Uuid::now_v7()
    ));
    let spool_quota = Arc::new(SpoolQuota::new(2048));
    state_mut.streaming_read_mode = StreamingReadMode::Transformed;
    state_mut.transformed_read_spool_enabled = false;
    state_mut.spool_config.directory = spool_dir.clone();
    state_mut.spool_config.max_object_bytes = 1024;
    state_mut.spool_quota = spool_quota.clone();
    state_mut.control = control.clone();
    state_mut.s3_client = Some(aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "source-access",
                "source-secret",
                None,
                None,
                "unknown-length-source",
            ))
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .endpoint_url(format!("http://{address}"))
            .force_path_style(true)
            .build(),
    ));
    for plugin in state.plugins.list() {
        state.plugins.set_enabled(&plugin.id, false);
    }
    let (ak, sk) = make_key(&state).await;
    let app = build_router(state);
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/read/empty.txt")
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "private, no-store"
    );
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "0");
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        ""
    );

    let response = app
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/read/nonempty.txt")
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(header::CONTENT_LENGTH));
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "one\ntwo\n"
    );

    assert_eq!(
        control
            .events
            .lock()
            .unwrap()
            .iter()
            .map(|call| {
                (
                    call.event.kind(),
                    call.event.route(),
                    call.event.source_bytes(),
                    call.event.output_bytes(),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (RequestKind::Read, UsageRoute::GetObject, 0, 0),
            (RequestKind::Read, UsageRoute::GetObject, 8, 8),
        ]
    );
    let events = control.events.lock().unwrap();
    for event in events.iter() {
        let evidence = event
            .event
            .pipeline_evidence()
            .expect("completed prefix-safe read must retain measured evidence");
        assert_eq!(evidence.revision, "static");
        assert_eq!(evidence.fuel_consumed, 0);
        assert_eq!(evidence.spool_mode, "none");
        assert!(evidence.components.starts_with("v1:0:"));
    }
    assert_eq!(spool_quota.reserved_bytes(), 0);
    assert!(
        std::fs::read_dir(&spool_dir)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(true),
        "direct reads must not create encrypted spool files"
    );
    task.abort();
}

#[tokio::test]
async fn direct_read_retries_the_exact_terminal_event_before_eof() {
    let control = Arc::new(RetryMeteringControl {
        failures_remaining: AtomicUsize::new(2),
        calls: Mutex::default(),
        releases: AtomicUsize::new(0),
    });
    let state = direct_passthrough_test_state(control.clone()).await;
    let credentials = make_key(&state).await;
    let response = build_router(state)
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/direct/records.txt")
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&credentials.0, &credentials.1),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "first\nsecond\n"
    );
    let calls = control.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert!(calls.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(
        calls[0]
            .pipeline_evidence()
            .expect("direct settlement includes evidence")
            .spool_mode,
        "none"
    );
    assert_eq!(control.releases.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn direct_read_settlement_exhaustion_errors_after_disclosure_and_preserves_reservation() {
    let control = Arc::new(RetryMeteringControl {
        failures_remaining: AtomicUsize::new(usize::MAX),
        calls: Mutex::default(),
        releases: AtomicUsize::new(0),
    });
    let state = direct_passthrough_test_state(control.clone()).await;
    let credentials = make_key(&state).await;
    let response = build_router(state)
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/direct/records.txt")
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&credentials.0, &credentials.1),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let first = http_body_util::BodyExt::frame(&mut body)
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert!(
        !first.is_empty(),
        "transformed output is disclosed before settlement"
    );
    let mut terminal_error = None;
    while let Some(frame) = http_body_util::BodyExt::frame(&mut body).await {
        if let Err(error) = frame {
            terminal_error = Some(error);
            break;
        }
    }
    assert!(terminal_error.is_some());
    assert_eq!(control.calls.lock().unwrap().len(), 3);
    assert_eq!(control.releases.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn direct_read_client_cancellation_after_disclosure_preserves_recoverable_reservation() {
    let control = Arc::new(RecordingMeteringControl::default());
    let state = direct_passthrough_test_state(control.clone()).await;
    let credentials = make_key(&state).await;
    let app = build_router(state);
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/direct/records.txt")
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&credentials.0, &credentials.1),
        ))
        .await
        .unwrap();
    let mut body = response.into_body();
    let first = http_body_util::BodyExt::frame(&mut body)
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert!(!first.is_empty());
    drop(body);
    tokio::task::yield_now().await;
    assert!(control.events.lock().unwrap().is_empty());
    assert!(control.releases.lock().unwrap().is_empty());

    let response = app
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/direct/empty.txt")
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&credentials.0, &credentials.1),
        ))
        .await
        .unwrap();
    drop(response.into_body());
    tokio::task::yield_now().await;
    assert_eq!(control.releases.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn direct_read_terminal_plugin_error_never_settles_customer_usage() {
    let component = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-components/test-transformer.component.wasm"),
    )
    .expect("test-transformer.component.wasm; run just build-plugins");
    let registry = Arc::new(PluginRegistry::new());
    registry.import("prefix-safe-test", &component).unwrap();
    let mut resolution = StaticPipelineResolver::new(registry.clone())
        .resolve("seed", "seed", PipelineDirection::Read)
        .await
        .unwrap();
    resolution.steps[0].capabilities.prefix_safe_for_read = true;
    let resolver = Arc::new(TestPipelineResolver {
        resolution,
        calls: Mutex::default(),
        resolved: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        failure_code: None,
    });
    let execution_registry = Arc::new(PluginRegistry::new());
    let mut state = test_state().await;
    let control = Arc::new(RecordingMeteringControl::default());
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Transformed;
    state_mut.transformed_read_spool_enabled = false;
    state_mut.control = control.clone();
    state_mut.plugins = execution_registry.clone();
    state_mut.gateway = Arc::new(
        Gateway::with_registry(
            maskura_wasm_runtime::FilterEngine::new(&component).unwrap(),
            execution_registry,
        )
        .with_resolver(resolver, Arc::new(FixedComponentSource(component.into()))),
    );
    state_mut.store.put(
        "direct",
        "failure.txt",
        Bytes::from_static(b"safe\ntrap\n"),
        "text/plain",
    );
    let credentials = make_key(&state).await;
    let response = build_router(state)
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/direct/failure.txt")
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&credentials.0, &credentials.1),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let first = http_body_util::BodyExt::frame(&mut body)
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first, "safe");
    let mut disclosed = first.to_vec();
    let mut terminal_error = false;
    while let Some(frame) = http_body_util::BodyExt::frame(&mut body).await {
        match frame {
            Ok(frame) => disclosed.extend_from_slice(&frame.into_data().unwrap()),
            Err(_) => {
                terminal_error = true;
                break;
            }
        }
    }
    assert!(terminal_error);
    assert_eq!(disclosed, b"safe\n");
    tokio::task::yield_now().await;
    assert!(control.events.lock().unwrap().is_empty());
    assert!(control.releases.lock().unwrap().is_empty());
    assert_eq!(control.attempts.lock().unwrap().len(), 1);
}
