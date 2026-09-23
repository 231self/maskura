use super::*;

#[tokio::test]
async fn presigned_transport_failure_never_discloses_signed_url_material() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let mut state = test_state().await;
    let control = Arc::new(RecordingMeteringControl::default());
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.control = control.clone();
    state_mut.presigned_http_policy = PresignedHttpPolicy::new(
        Vec::<String>::new(),
        ["127.0.0.1".to_string()],
        true,
        Duration::ZERO,
        Arc::new(TokioAddressResolver),
    )
    .unwrap();
    let (ak, sk) = make_key(&state).await;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let signed_url = format!(
        "https://{address}/object?X-Amz-Credential=AKIA_TEST%2F20260828%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=DO_NOT_DISCLOSE&Expires={expires}"
    );
    let app = build_router(state);
    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/proxy/transport-failure")
                .header("x-maskura-backend-url", &signed_url)
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_hardened_object_headers(response.headers());
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("We encountered an internal error."), "{body}");
    let address = address.to_string();
    for sensitive in [
        signed_url.as_str(),
        "AKIA_TEST",
        "X-Amz-Credential",
        "X-Amz-Signature",
        "DO_NOT_DISCLOSE",
        address.as_str(),
    ] {
        assert!(
            !body.contains(sensitive),
            "response leaked {sensitive}: {body}"
        );
    }

    let delete_response = app
        .oneshot(add_headers(
            Request::builder()
                .method("DELETE")
                .uri("/proxy/transport-failure")
                .header("x-maskura-backend-url", &signed_url)
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&ak, &sk),
        ))
        .await
        .unwrap();
    assert_eq!(delete_response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let authorizations = control.authorizations.lock().unwrap();
    let releases = control.releases.lock().unwrap();
    assert_eq!(authorizations.len(), 2);
    assert_eq!(releases.len(), 1);
    assert_eq!(releases[0].1, authorizations[0].1.operation_id());
    assert_ne!(releases[0].1, authorizations[1].1.operation_id());
    assert_eq!(authorizations[1].1.route(), UsageRoute::DeleteObject);
}

#[tokio::test]
async fn presigned_http_responses_are_hardened_without_losing_object_semantics() {
    let (upstream, task) = spawn_presigned_upstream().await;
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.presigned_http_policy = PresignedHttpPolicy::new(
        Vec::<String>::new(),
        ["127.0.0.1".to_string()],
        true,
        Duration::ZERO,
        Arc::new(TokioAddressResolver),
    )
    .unwrap();
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let app = build_router(state);
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;

    let get = add_headers(
        Request::builder()
            .method("GET")
            .uri("/proxy/object")
            .header(header::RANGE, "bytes=2-5")
            .header("x-amz-checksum-mode", "ENABLED")
            .header(
                "x-maskura-backend-url",
                format!("{upstream}/object?Expires={expires}"),
            )
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(get).await.unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    for (name, expected) in [
        (header::CONTENT_LENGTH.as_str(), "4"),
        (header::CONTENT_RANGE.as_str(), "bytes 2-5/10"),
        (header::CONTENT_TYPE.as_str(), "text/plain"),
        (header::CONTENT_ENCODING.as_str(), "identity"),
        (header::CONTENT_LANGUAGE.as_str(), "en"),
        (header::ETAG.as_str(), "\"upstream-etag\""),
        (
            header::LAST_MODIFIED.as_str(),
            "Wed, 19 Aug 2026 09:00:00 GMT",
        ),
        ("x-amz-checksum-sha256", "checksum"),
        ("x-amz-meta-project", "safe-metadata"),
        ("x-amz-meta-request-checksum-mode", "ENABLED"),
        ("x-amz-version-id", "version-7"),
        ("x-goog-component-count", "2"),
        ("x-goog-custom-time", "2026-08-19T09:00:00Z"),
        ("x-goog-encryption-algorithm", "AES256"),
        ("x-goog-encryption-key-sha256", "key-checksum"),
        ("x-goog-expiration", "Wed, 19 Aug 2026 10:00:00 GMT"),
        ("x-goog-generation", "123456"),
        ("x-goog-hash", "crc32c=abcd"),
        ("x-goog-meta-project", "safe-gcs-metadata"),
        ("x-goog-metageneration", "9"),
        ("x-goog-object-lock-mode", "GOVERNANCE"),
        (
            "x-goog-object-lock-retain-until-date",
            "2027-08-19T09:00:00Z",
        ),
        ("x-goog-storage-class", "STANDARD"),
        ("x-goog-stored-content-encoding", "identity"),
        ("x-goog-stored-content-length", "10"),
    ] {
        assert_eq!(response.headers()[name], expected, "header {name}");
    }
    assert_hardened_object_headers(response.headers());
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "*",
        "the gateway CORS policy must replace the untrusted upstream value"
    );
    for dropped in [
        "set-cookie",
        "location",
        "refresh",
        "report-to",
        "reporting-endpoints",
        "www-authenticate",
        "authentication-info",
        "connection",
        "x-upstream-private",
    ] {
        assert!(
            !response.headers().contains_key(dropped),
            "untrusted upstream header {dropped} was forwarded"
        );
    }
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "2345"
    );

    let head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/proxy/object")
            .header(
                "x-maskura-backend-url",
                format!("{upstream}/object?Expires={expires}"),
            )
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(head).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "10");
    assert_eq!(response.headers()[header::ETAG], "\"upstream-etag\"");
    assert_hardened_object_headers(response.headers());
    assert!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty()
    );

    let list = add_headers(
        Request::builder()
            .method("GET")
            .uri("/proxy?list-type=2")
            .header(
                "x-maskura-backend-url",
                format!("{upstream}/object?Expires={expires}"),
            )
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(list).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_hardened_object_headers(response.headers());
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "0123456789"
    );

    let non_success = add_headers(
        Request::builder()
            .method("GET")
            .uri("/proxy/missing")
            .header(
                "x-maskura-backend-url",
                format!("{upstream}/not-found?Expires={expires}"),
            )
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(non_success).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html");
    assert_hardened_object_headers(response.headers());
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "<script>attack()</script>"
    );

    let redirect = add_headers(
        Request::builder()
            .method("GET")
            .uri("/proxy/redirect")
            .header(
                "x-maskura-backend-url",
                format!("{upstream}/redirect?Expires={expires}"),
            )
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.oneshot(redirect).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    task.abort();
}

#[tokio::test]
async fn sigv4_signed_request_accepted_and_rejected() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let uri = "http://maskura.local/demo/signed.txt";

    // Correct signature → 200.
    let req = signed_request(
        &ak,
        &sk,
        "PUT",
        uri,
        b"hello world",
        &[("content-type", "text/plain")],
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    if status != StatusCode::OK {
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        eprintln!("DEBUG first resp body: {:?}", body);
    }
    assert_eq!(status, StatusCode::OK, "valid SigV4 should pass");

    // Wrong secret → 403.
    let req = signed_request(&ak, "not-the-secret", "PUT", uri, b"hello world", &[]);
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "tampered signature must fail"
    );

    // Unknown access key → 403.
    let req = signed_request("maskura_unknown", &sk, "PUT", uri, b"hello world", &[]);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "unknown key must fail"
    );
}

#[tokio::test]
async fn sigv4_wrapping_provider_failure_returns_generic_service_unavailable() {
    let mut state = test_state().await;
    let cipher = Arc::new(SecretCipher::new(Arc::new(FailingUnwrapWrapping(
        LocalKeyWrapping::with_kek([7; 32]),
    ))));
    let store = Arc::new(KeyStore::with_cipher(cipher));
    let (secret, created) = store
        .create_key(
            "test-user",
            &WorkspaceId::new("test-user").unwrap(),
            "unwrap-outage",
            0,
            None,
        )
        .await
        .unwrap();
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .keys = store;
    let app = build_router(state);
    let request = signed_request(
        &created.key_id,
        &secret,
        "PUT",
        "http://maskura.local/outage/unwrap.txt",
        b"sensitive",
        &[],
    );

    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("<Code>ServiceUnavailable</Code>"));
    assert!(!body.contains("wrapping"));
    assert!(!body.contains("sensitive"));
}

#[tokio::test]
async fn sigv4_signed_semantic_headers_accept_and_detect_mutation_or_removal() {
    enum HeaderChange {
        None,
        Replace(&'static str, &'static str),
        Remove(&'static str),
    }

    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    for (index, (name, change, expected)) in [
        ("unchanged", HeaderChange::None, StatusCode::OK),
        (
            "mutated content type",
            HeaderChange::Replace("content-type", "application/json"),
            StatusCode::FORBIDDEN,
        ),
        (
            "removed content type",
            HeaderChange::Remove("content-type"),
            StatusCode::FORBIDDEN,
        ),
        (
            "mutated dynamic metadata",
            HeaderChange::Replace("x-amz-meta-dynamic-name", "two"),
            StatusCode::FORBIDDEN,
        ),
        (
            "removed legacy semantic header",
            HeaderChange::Remove("x-maskura-process"),
            StatusCode::FORBIDDEN,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let uri = format!("http://maskura.local/semantic/signed-{index}.txt");
        let request = signed_request(
            &access_key,
            &secret_key,
            "PUT",
            &uri,
            b"semantic body",
            &[
                ("content-type", "text/plain"),
                ("x-maskura-process", "write"),
                ("x-amz-meta-dynamic-name", "one"),
            ],
        );
        let (mut parts, body) = request.into_parts();
        match change {
            HeaderChange::None => {}
            HeaderChange::Replace(header, value) => {
                parts.headers.insert(header, value.parse().unwrap());
            }
            HeaderChange::Remove(header) => {
                parts.headers.remove(header);
            }
        }
        let response = app
            .clone()
            .oneshot(Request::from_parts(parts, body))
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{name}");
        if expected == StatusCode::FORBIDDEN {
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(
                String::from_utf8_lossy(&body).contains("<Code>SignatureDoesNotMatch</Code>"),
                "{name}: {}",
                String::from_utf8_lossy(&body)
            );
        }
    }
}

#[tokio::test]
async fn sigv4_signs_the_exact_canonical_semantic_header_names() {
    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;

    for (index, (name, value)) in [
        ("x-maskura-process", "write"),
        ("x-maskura-encrypt-fields", "email"),
    ]
    .into_iter()
    .enumerate()
    {
        let request = signed_request(
            &access_key,
            &secret_key,
            "PUT",
            &format!("http://maskura.local/sigv4-canonical/{index}.txt"),
            b"signed canonical",
            &[("content-type", "text/plain"), (name, value)],
        );
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK,
            "signed {name}"
        );
    }

    let duplicate = signed_request(
        &access_key,
        &secret_key,
        "PUT",
        "http://maskura.local/sigv4-canonical/duplicate.txt",
        b"duplicate semantic header",
        &[
            ("content-type", "text/plain"),
            ("x-maskura-process", "write"),
            ("x-maskura-process", "read"),
        ],
    );
    assert_eq!(
        app.oneshot(duplicate).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn sigv4_rejects_ambiguous_or_noncanonical_integrity_headers_before_body_polling() {
    enum HeaderShape {
        Raw(&'static str),
        Duplicate {
            signed: &'static str,
            first: &'static str,
            second: &'static str,
        },
    }

    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    for (index, (name, shape)) in [
        (
            "x-maskura-stable-fields",
            HeaderShape::Duplicate {
                signed: "email,account_id",
                first: "email",
                second: "account_id",
            },
        ),
        (
            "x-maskura-backend-url",
            HeaderShape::Duplicate {
                signed: "https://storage.example/one,https://storage.example/two",
                first: "https://storage.example/one",
                second: "https://storage.example/two",
            },
        ),
        (
            "content-type",
            HeaderShape::Duplicate {
                signed: "text/plain;charset=utf-8",
                first: "text/plain",
                second: "charset=utf-8",
            },
        ),
        (
            "x-amz-meta-project",
            HeaderShape::Duplicate {
                signed: "one,two",
                first: "one",
                second: "two",
            },
        ),
        (
            "x-maskura-stable-fields",
            HeaderShape::Raw(" email, account_id"),
        ),
        (
            "x-maskura-stable-fields",
            HeaderShape::Raw("email, account_id "),
        ),
        (
            "x-maskura-backend-url",
            HeaderShape::Raw("\thttps://storage.example/object"),
        ),
        (
            "content-type",
            HeaderShape::Raw("text/plain;  charset=utf-8"),
        ),
        (
            "content-md5",
            HeaderShape::Raw("CY9rzUYh03PK3k6DJie09g==\t"),
        ),
        ("x-amz-tagging", HeaderShape::Raw(" project=one&owner=two")),
    ]
    .into_iter()
    .enumerate()
    {
        let signed_value = match &shape {
            HeaderShape::Raw(value) => *value,
            HeaderShape::Duplicate { signed, .. } => *signed,
        };
        let mut signed_headers = Vec::with_capacity(2);
        if name != "content-type" {
            signed_headers.push(("content-type", "text/plain"));
        }
        signed_headers.push((name, signed_value));
        let uri = format!("http://maskura.local/semantic/shape-{index}.txt");
        let request = signed_request(
            &access_key,
            &secret_key,
            "PUT",
            &uri,
            b"must not be polled",
            &signed_headers,
        );
        let (mut parts, _) = request.into_parts();
        if let HeaderShape::Duplicate { first, second, .. } = shape {
            parts.headers.remove(name);
            parts.headers.append(name, first.parse().unwrap());
            parts.headers.append(name, second.parse().unwrap());
        }
        let polls = Arc::new(AtomicUsize::new(0));
        let request = Request::from_parts(
            parts,
            Body::new(PollTrackingBody {
                polls: polls.clone(),
                data: Some(Bytes::from_static(b"must not be polled")),
            }),
        );

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{name}");
        assert_eq!(polls.load(Ordering::SeqCst), 0, "{name}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("<Code>SignatureDoesNotMatch</Code>"),
            "{name}: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[tokio::test]
async fn sigv4_rejects_unsigned_integrity_header_injection_before_polling_the_body() {
    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    for (index, (name, value)) in [
        ("x-maskura-storage-mode", "managed"),
        ("x-maskura-backend-url", "https://storage.example/object"),
        ("x-maskura-process", "read"),
        ("x-maskura-stable-fields", "email"),
        ("content-type", "text/plain"),
        ("content-encoding", "gzip"),
        ("content-md5", "CY9rzUYh03PK3k6DJie09g=="),
        ("x-amz-meta-dynamic-name", "metadata"),
    ]
    .into_iter()
    .enumerate()
    {
        let uri = format!("http://maskura.local/semantic/unsigned-{index}.txt");
        let request = signed_request(
            &access_key,
            &secret_key,
            "PUT",
            &uri,
            b"must not be polled",
            &[],
        );
        let (mut parts, _) = request.into_parts();
        parts.headers.insert(name, value.parse().unwrap());
        let polls = Arc::new(AtomicUsize::new(0));
        let request = Request::from_parts(
            parts,
            Body::new(PollTrackingBody {
                polls: polls.clone(),
                data: Some(Bytes::from_static(b"must not be polled")),
            }),
        );

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{name}");
        assert_eq!(polls.load(Ordering::SeqCst), 0, "{name}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("<Code>SignatureDoesNotMatch</Code>"),
            "{name}: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            String::from_utf8_lossy(&body).contains(
                "The request signature we calculated does not match the signature you provided."
            ),
            "{name} must use the generic 403 message"
        );
        assert!(
            !String::from_utf8_lossy(&body).contains(name),
            "{name} must not be disclosed by the generic rejection"
        );
    }
}

#[tokio::test]
async fn presigned_host_only_get_accepts_but_appended_protected_headers_are_rejected() {
    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    state.store.put(
        "presigned",
        "object.txt",
        Bytes::from_static(b"presigned body"),
        "text/plain",
    );
    let uri = "https://maskura.local/presigned/object.txt";

    let response = app
        .clone()
        .oneshot(presigned_request(&access_key, &secret_key, "GET", uri, &[]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "presigned body"
    );

    for (name, value) in [
        ("x-amz-user-agent", "unsigned-agent"),
        ("x-amz-checksum-mode", "ENABLED"),
    ] {
        let request = presigned_request(&access_key, &secret_key, "GET", uri, &[]);
        let (mut parts, body) = request.into_parts();
        parts.headers.insert(name, value.parse().unwrap());
        let response = app
            .clone()
            .oneshot(Request::from_parts(parts, body))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "unsigned signer exclusion {name}"
        );
    }

    let response = app
        .clone()
        .oneshot(presigned_request(
            &access_key,
            &secret_key,
            "GET",
            uri,
            &[("x-amz-meta-dynamic-name", "signed")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    for (name, value) in [
        ("x-maskura-process", "read"),
        ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
        ("x-amz-meta-dynamic-name", "appended"),
        ("x-amz-tagging", "project=appended"),
    ] {
        let request = presigned_request(&access_key, &secret_key, "GET", uri, &[]);
        let (mut parts, body) = request.into_parts();
        parts.headers.insert(name, value.parse().unwrap());
        let response = app
            .clone()
            .oneshot(Request::from_parts(parts, body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{name}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("<Code>SignatureDoesNotMatch</Code>"),
            "{name}: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[tokio::test]
async fn non_sigv4_api_key_auth_rejects_duplicate_semantic_headers() {
    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    let request = append_headers(
        add_headers(
            Request::builder()
                .method("PUT")
                .uri("/semantic/api-key.txt")
                .header(header::CONTENT_TYPE, "text/plain")
                .header("x-amz-meta-dynamic-name", "metadata")
                .body(Body::from("API key body"))
                .unwrap(),
            &auth_headers(&access_key, &secret_key),
        ),
        &[
            ("x-maskura-process", " write ".to_string()),
            ("x-maskura-process", "read".to_string()),
        ],
    );

    assert_eq!(
        app.oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert!(state.store.get("semantic", "api-key.txt").is_none());
}

#[tokio::test]
async fn streaming_sigv4_hash_is_checked_before_atomic_commit() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.dev_memory_streaming_enabled = true;
    let (access_key, secret_key) = make_key(&state).await;
    let app = build_router(state.clone());
    let uri = "http://maskura.local/stream/signed-stream.txt";
    let input = b"contact a@b.com now\n";

    let request = signed_request(
        &access_key,
        &secret_key,
        "PUT",
        uri,
        input,
        &[("content-type", "text/plain")],
    );
    let (parts, _) = request.into_parts();
    let request = Request::from_parts(
        parts,
        Body::new(FrameSequenceBody::data([
            Bytes::copy_from_slice(&input[..7]),
            Bytes::copy_from_slice(&input[7..]),
        ])),
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        state
            .store
            .get("stream", "signed-stream.txt")
            .expect("committed object")
            .data,
        Bytes::from_static(b"contact [REDACTED_EMAIL] now\n")
    );

    let bad_uri = "http://maskura.local/stream/tampered-stream.txt";
    let request = signed_request(
        &access_key,
        &secret_key,
        "PUT",
        bad_uri,
        input,
        &[("content-type", "text/plain")],
    );
    let (parts, _) = request.into_parts();
    let request = Request::from_parts(parts, Body::from("tampered body\n"));
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(state.store.get("stream", "tampered-stream.txt").is_none());
}

#[tokio::test]
async fn sigv4_get_object_roundtrip() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;

    // PUT via SigV4.
    let uri = "http://maskura.local/bkt/signed.txt";
    let req = signed_request(
        &ak,
        &sk,
        "PUT",
        uri,
        b"content a@b.com",
        &[("content-type", "text/plain")],
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // GET via SigV4 returns the filtered object.
    let req = signed_request(&ak, &sk, "GET", uri, b"", &[]);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("[REDACTED_EMAIL]"),
        "sigv4 GET filtered: {text}"
    );
}

#[tokio::test]
async fn sigv4_tampered_body_rejected() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let uri = "http://maskura.local/bkt/tamper.txt";

    // Sign body A, then send body B with the A-signature -> 403.
    let req = signed_request(
        &ak,
        &sk,
        "PUT",
        uri,
        b"AAAA",
        &[("content-type", "text/plain")],
    );
    let (parts, _old_body) = req.into_parts();
    let req = Request::from_parts(parts, Body::from("BBBB"));
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "body tampering must be rejected by SigV4"
    );
}

#[tokio::test]
async fn invalid_sigv4_headers_are_rejected_without_polling_put_body() {
    let (app, state) = router().await;
    let (ak, _sk) = make_key(&state).await;
    let uri = "http://maskura.local/bkt/unpolled.txt";
    let signed = signed_request(&ak, "wrong-secret", "PUT", uri, b"sensitive body", &[]);
    let (parts, _) = signed.into_parts();
    let polls = Arc::new(AtomicUsize::new(0));
    let request = Request::from_parts(
        parts,
        Body::new(PollTrackingBody {
            polls: polls.clone(),
            data: Some(Bytes::from_static(b"sensitive body")),
        }),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn valid_sigv4_seed_polls_then_rejects_payload_hash_mismatch() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let uri = "http://maskura.local/bkt/hash-mismatch.txt";
    let signed = signed_request(
        &ak,
        &sk,
        "PUT",
        uri,
        b"claimed body",
        &[("content-type", "text/plain")],
    );
    let (parts, _) = signed.into_parts();
    let polls = Arc::new(AtomicUsize::new(0));
    let request = Request::from_parts(
        parts,
        Body::new(PollTrackingBody {
            polls: polls.clone(),
            data: Some(Bytes::from_static(b"different body")),
        }),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(polls.load(Ordering::SeqCst) > 0);
    assert!(state.store.get("bkt", "hash-mismatch.txt").is_none());
}

#[tokio::test]
async fn aws_cli_streaming_unsigned_trailer_put_is_accepted() {
    use aws_sigv4::http_request::SignableBody;
    use base64::Engine as _;
    use crc::{CRC_32_ISO_HDLC, Crc};

    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .sigv4_policy = SigV4Policy::new("us-east-1", true);
    let (ak, sk) = make_key(&state).await;
    let app = build_router(state.clone());

    let data = b"streaming trailer payload";
    let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let mut digest = crc.digest();
    digest.update(data);
    let checksum =
        base64::engine::general_purpose::STANDARD.encode(digest.finalize().to_be_bytes());
    let framed = format!(
        "{:X}\r\n{}\r\n0\r\nx-amz-checksum-crc32:{checksum}\r\n\r\n",
        data.len(),
        String::from_utf8_lossy(data)
    );
    let headers: &[(&'static str, &str)] = &[
        ("content-encoding", "aws-chunked"),
        ("x-amz-decoded-content-length", "25"),
        ("x-amz-sdk-checksum-algorithm", "CRC32"),
        ("x-amz-trailer", "x-amz-checksum-crc32"),
    ];
    let request = signed_request_with_signable(
        &ak,
        &sk,
        "PUT",
        "http://maskura.local/cli/stream.txt",
        framed.as_bytes(),
        headers,
        SignableBody::StreamingUnsignedPayloadTrailer,
    );
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body).into_owned();
    assert_eq!(
        status,
        StatusCode::OK,
        "aws-cli style STREAMING-UNSIGNED-PAYLOAD-TRAILER PUT must pass seed verify: {body}"
    );
    assert!(!body.contains("SignatureDoesNotMatch"), "{body}");
    assert!(state.store.get("cli", "stream.txt").is_some());
}
