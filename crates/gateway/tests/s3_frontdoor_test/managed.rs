use super::*;

#[tokio::test]
async fn filestore_conformance_bucket_object_lifecycle_survives_restart() {
    let root =
        std::env::temp_dir().join(format!("maskura-file-lifecycle-{}", uuid::Uuid::now_v7()));
    let mut state = test_state().await;
    let keys = state.keys.clone();
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.file_store = Some(Arc::new(FileStore::new(root.clone()).await.unwrap()));
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let app = build_router(state.clone());

    let create = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/conformance")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.clone().oneshot(create).await.unwrap().status(),
        StatusCode::OK
    );

    for body in ["first generation", "replacement generation"] {
        let put = add_headers(
            Request::builder()
                .method("PUT")
                .uri("/conformance/object.txt")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(body))
                .unwrap(),
            &headers,
        );
        assert_eq!(
            app.clone().oneshot(put).await.unwrap().status(),
            StatusCode::OK
        );
    }
    let zero = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/conformance/empty")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.clone().oneshot(zero).await.unwrap().status(),
        StatusCode::OK
    );

    let nonempty_delete = add_headers(
        Request::builder()
            .method("DELETE")
            .uri("/conformance")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(nonempty_delete).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Code>BucketNotEmpty</Code>"));

    drop(app);
    drop(state);
    let mut restarted = test_state().await;
    let state_mut = Arc::get_mut(&mut restarted).expect("test state is uniquely owned");
    state_mut.keys = keys;
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.file_store = Some(Arc::new(FileStore::new(root.clone()).await.unwrap()));
    let app = build_router(restarted);

    let list_buckets = add_headers(
        Request::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(list_buckets).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Name>conformance</Name>"));

    let list_objects = add_headers(
        Request::builder()
            .method("GET")
            .uri("/conformance?list-type=2")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let body = axum::body::to_bytes(
        app.clone().oneshot(list_objects).await.unwrap().into_body(),
        usize::MAX,
    )
    .await
    .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Key>empty</Key>"));
    assert!(xml.contains("<Key>object.txt</Key>"));
    assert!(xml.contains("<KeyCount>2</KeyCount>"));

    for (key, expected) in [
        ("object.txt", Bytes::from_static(b"replacement generation")),
        ("empty", Bytes::new()),
    ] {
        let get = add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/conformance/{key}"))
                .body(Body::empty())
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(get).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_length = response.headers()[header::CONTENT_LENGTH].clone();
        let etag = response.headers()[header::ETAG].clone();
        assert_eq!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
            expected
        );

        let head = add_headers(
            Request::builder()
                .method("HEAD")
                .uri(format!("/conformance/{key}"))
                .body(Body::empty())
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(head).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_LENGTH], content_length);
        assert_eq!(response.headers()[header::ETAG], etag);
        assert!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .is_empty()
        );

        for _ in 0..2 {
            let delete = add_headers(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/conformance/{key}"))
                    .body(Body::empty())
                    .unwrap(),
                &headers,
            );
            assert_eq!(
                app.clone().oneshot(delete).await.unwrap().status(),
                StatusCode::NO_CONTENT
            );
        }
    }

    let delete_bucket = add_headers(
        Request::builder()
            .method("DELETE")
            .uri("/conformance")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.clone().oneshot(delete_bucket).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let list_buckets = add_headers(
        Request::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let body = axum::body::to_bytes(
        app.oneshot(list_buckets).await.unwrap().into_body(),
        usize::MAX,
    )
    .await
    .unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("<Name>conformance</Name>"));
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn filestore_list_and_head_on_missing_bucket_return_no_such_bucket() {
    let root = std::env::temp_dir().join(format!("maskura-file-missing-{}", uuid::Uuid::now_v7()));
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .file_store = Some(Arc::new(FileStore::new(root.clone()).await.unwrap()));
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let app = build_router(state);

    // ListObjects v1, ListObjects v2, and HEAD on a bucket that was never
    // created must all report NoSuchBucket rather than an empty success:
    // an empty 200 hides a typo'd or missing bucket from every S3 client,
    // and `head-bucket` would then claim the bucket exists.
    for (method, uri) in [
        ("GET", "/absent"),
        ("GET", "/absent?list-type=2"),
        ("HEAD", "/absent"),
    ] {
        let request = add_headers(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{method} {uri} must be NoSuchBucket"
        );
        if method == "GET" {
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let xml = String::from_utf8_lossy(&body);
            assert!(
                xml.contains("<Code>NoSuchBucket</Code>"),
                "{method} {uri}: {xml}"
            );
        }
    }

    // An existing bucket still lists with an empty 200, so the guard only
    // rejects genuinely absent buckets.
    let create = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/absent")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.clone().oneshot(create).await.unwrap().status(),
        StatusCode::OK
    );
    let list = add_headers(
        Request::builder()
            .method("GET")
            .uri("/absent?list-type=2")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(list).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<KeyCount>0</KeyCount>"), "{xml}");

    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn filestore_conformance_lists_v1_v2_prefix_delimiter_and_pages() {
    let root = std::env::temp_dir().join(format!("maskura-file-list-{}", uuid::Uuid::now_v7()));
    let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
    store.create_bucket("listing").await.unwrap();
    for key in ["a.txt", "b.txt", "logs/one.txt", "logs/two.txt"] {
        store
            .put("listing", key, Bytes::from_static(b"x"), "text/plain")
            .await
            .unwrap();
    }
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .file_store = Some(store);
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let app = build_router(state);

    let first = add_headers(
        Request::builder()
            .method("GET")
            .uri("/listing?list-type=2&max-keys=1")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.clone().oneshot(first).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let xml = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(xml.contains("<Key>a.txt</Key>"));
    assert!(xml.contains("<KeyCount>1</KeyCount>"));
    assert!(xml.contains("<IsTruncated>true</IsTruncated>"));
    let token = xml
        .split("<NextContinuationToken>")
        .nth(1)
        .and_then(|value| value.split("</NextContinuationToken>").next())
        .unwrap();

    let second = add_headers(
        Request::builder()
            .method("GET")
            .uri(format!(
                "/listing?list-type=2&max-keys=1&continuation-token={token}"
            ))
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let body = axum::body::to_bytes(
        app.clone().oneshot(second).await.unwrap().into_body(),
        usize::MAX,
    )
    .await
    .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Key>b.txt</Key>"));
    assert!(!xml.contains("<Key>a.txt</Key>"));

    let grouped = add_headers(
        Request::builder()
            .method("GET")
            .uri("/listing?list-type=2&delimiter=%2F")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let body = axum::body::to_bytes(
        app.clone().oneshot(grouped).await.unwrap().into_body(),
        usize::MAX,
    )
    .await
    .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Key>a.txt</Key>"));
    assert!(xml.contains("<Key>b.txt</Key>"));
    assert!(xml.contains("<CommonPrefixes><Prefix>logs/</Prefix></CommonPrefixes>"));
    assert!(xml.contains("<KeyCount>3</KeyCount>"));

    let v1 = add_headers(
        Request::builder()
            .method("GET")
            .uri("/listing?max-keys=1&marker=a.txt")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let body = axum::body::to_bytes(
        app.clone().oneshot(v1).await.unwrap().into_body(),
        usize::MAX,
    )
    .await
    .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Marker>a.txt</Marker>"));
    assert!(xml.contains("<Key>b.txt</Key>"));
    assert!(xml.contains("<NextMarker>b.txt</NextMarker>"));

    for uri in [
        "/listing?continuation-token=invalid",
        "/listing?list-type=2&encoding-type=base64",
    ] {
        let request = add_headers(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
            &headers,
        );
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn filestore_conformance_preserves_encoded_key_identity_and_list_encoding() {
    let root = std::env::temp_dir().join(format!("maskura-file-keys-{}", uuid::Uuid::now_v7()));
    let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
    store.create_bucket("keys").await.unwrap();
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.file_store = Some(store);
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let app = build_router(state);
    let cases = [
        ("space%20key", "space key", "space%20key"),
        ("literal%252Fkey", "literal%2Fkey", "literal%252Fkey"),
        ("xml%26%3Ckey", "xml&<key", "xml%26%3Ckey"),
        ("caf%C3%A9", "café", "caf%C3%A9"),
    ];

    for (uri_key, _, _) in cases {
        let put = add_headers(
            Request::builder()
                .method("PUT")
                .uri(format!("/keys/{uri_key}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(uri_key.to_string()))
                .unwrap(),
            &headers,
        );
        assert_eq!(
            app.clone().oneshot(put).await.unwrap().status(),
            StatusCode::OK,
            "{uri_key}"
        );
        let get = add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/keys/{uri_key}"))
                .body(Body::empty())
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(get).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri_key}");
        assert_eq!(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
            uri_key
        );
    }

    let list = add_headers(
        Request::builder()
            .method("GET")
            .uri("/keys?list-type=2&encoding-type=url")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let body = axum::body::to_bytes(
        app.clone().oneshot(list).await.unwrap().into_body(),
        usize::MAX,
    )
    .await
    .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<EncodingType>url</EncodingType>"));
    for (_, logical_key, encoded_key) in cases {
        assert!(xml.contains(encoded_key), "{logical_key}: {xml}");
    }

    let list = add_headers(
        Request::builder()
            .method("GET")
            .uri("/keys?list-type=2")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let body = axum::body::to_bytes(app.oneshot(list).await.unwrap().into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Key>space key</Key>"));
    assert!(xml.contains("<Key>literal%2Fkey</Key>"));
    assert!(xml.contains("<Key>xml&amp;&lt;key</Key>"));
    assert!(xml.contains("<Key>café</Key>"));
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn filestore_conformance_conditions_and_missing_key_precede_range() {
    let root =
        std::env::temp_dir().join(format!("maskura-file-conditions-{}", uuid::Uuid::now_v7()));
    let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
    store.create_bucket("conditions").await.unwrap();
    let stored = store
        .put(
            "conditions",
            "object",
            Bytes::from_static(b"abcdefgh"),
            "text/plain",
        )
        .await
        .unwrap();
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Passthrough;
    state_mut.file_store = Some(store);
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let app = build_router(state);

    for (header_name, header_value, status) in [
        (header::IF_MATCH, stored.etag.as_str(), StatusCode::OK),
        (
            header::IF_MATCH,
            "\"wrong\"",
            StatusCode::PRECONDITION_FAILED,
        ),
        (
            header::IF_NONE_MATCH,
            stored.etag.as_str(),
            StatusCode::NOT_MODIFIED,
        ),
        (header::IF_NONE_MATCH, "\"wrong\"", StatusCode::OK),
    ] {
        let request = add_headers(
            Request::builder()
                .method("GET")
                .uri("/conditions/object")
                .header(&header_name, header_value)
                .body(Body::empty())
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), status, "{header_name}: {header_value}");
        if status != StatusCode::OK {
            assert!(
                axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
    }

    let missing = add_headers(
        Request::builder()
            .method("GET")
            .uri("/conditions/missing")
            .header(header::RANGE, "bytes=100-200")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    let response = app.oneshot(missing).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Code>NoSuchKey</Code>"));
    assert!(!xml.contains("InvalidRange"));
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn managed_storage_isolates_users() {
    // The per-user namespace ({uid}/{bucket}/{key}) is the isolation guarantee
    // for Maskura-managed storage. It is enforced by the key prefix the gateway
    // builds in s3_put/s3_get when service storage is configured, and by
    // per-key authentication. This test asserts the authentication half:
    // user1's credentials authenticate as user1, user2's as user2, and neither
    // can act as the other. The namespace prefix itself is exercised
    // end-to-end against real B2 by e2e-b2.sh / e2e-hosted.sh.
    let (app, state) = router().await;
    let (sk1, created1) = state
        .keys
        .create_key(
            "user-one",
            &WorkspaceId::new("user-one").unwrap(),
            "ns-test",
            0,
            None,
        )
        .await
        .expect("create user-one API key");
    let ak1 = created1.key_id;
    let (sk2, created2) = state
        .keys
        .create_key(
            "user-two",
            &WorkspaceId::new("user-two").unwrap(),
            "ns-test",
            0,
            None,
        )
        .await
        .expect("create user-two API key");
    let ak2 = created2.key_id;
    let h1 = auth_headers(&ak1, &sk1);
    let h2 = auth_headers(&ak2, &sk2);

    // Each key can write with its own credentials.
    let put1 = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/u1/obj.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("one"))
            .unwrap(),
        &h1,
    );
    assert_eq!(
        app.clone().oneshot(put1).await.unwrap().status(),
        StatusCode::OK,
        "user1 write"
    );

    let put2 = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/u2/obj.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("two"))
            .unwrap(),
        &h2,
    );
    assert_eq!(
        app.clone().oneshot(put2).await.unwrap().status(),
        StatusCode::OK,
        "user2 write"
    );

    // Cross-credential attempts must fail: user1's secret is not valid for
    // user2's access key (and vice versa).
    let cross = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/u2/obj.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("evil"))
            .unwrap(),
        &[
            ("x-maskura-access-key", ak2.clone()),
            ("x-maskura-secret-key", sk1.clone()),
        ],
    );
    let resp = app.clone().oneshot(cross).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "user1 secret must not work for user2 key"
    );

    let cross2 = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/u1/obj.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("evil"))
            .unwrap(),
        &[
            ("x-maskura-access-key", ak1.clone()),
            ("x-maskura-secret-key", sk2.clone()),
        ],
    );
    let resp = app.oneshot(cross2).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "user2 secret must not work for user1 key"
    );
}
