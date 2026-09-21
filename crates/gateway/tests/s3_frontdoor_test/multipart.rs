use super::*;

#[tokio::test]
async fn unsupported_multipart_destination_is_rejected_before_body_polling() {
    let state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let headers = auth_headers(&access_key, &secret_key);
    let initiation = add_headers(
        Request::builder()
            .method("POST")
            .uri("/bucket/object?uploads")
            .header("x-maskura-backend-url", "https://example.com/signed")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        build_router(state.clone())
            .oneshot(initiation)
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_IMPLEMENTED
    );

    let polls = Arc::new(AtomicUsize::new(0));
    let request = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/bucket/object?partNumber=1&uploadId=legacy")
            .header("x-maskura-backend-url", "https://example.com/signed")
            .header(header::CONTENT_LENGTH, "7")
            .body(Body::new(PollTrackingBody {
                polls: polls.clone(),
                data: Some(Bytes::from_static(b"payload")),
            }))
            .unwrap(),
        &headers,
    );

    let response = build_router(state).oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn all_multipart_operations_are_rejected() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .legacy_max_object_bytes = 1;
    let app = build_router(state.clone());
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    for (method, uri, body) in [
        ("POST", "/bkt/object?uploads", "create"),
        (
            "PUT",
            "/bkt/object?partNumber=1&uploadId=untrusted",
            "raw part must not be stored",
        ),
        ("GET", "/bkt/object?uploadId=untrusted", ""),
        (
            "POST",
            "/bkt/object?uploadId=untrusted",
            "complete body must not be consumed",
        ),
        ("DELETE", "/bkt/object?uploadId=untrusted", ""),
    ] {
        let request = add_headers(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::from(body))
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED, "{method} {uri}");
        let response_body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&response_body).contains("<Code>NotImplemented</Code>"),
            "{method} {uri}"
        );
    }

    assert!(state.store.get("bkt", "object").is_none());
}
