use super::*;

#[tokio::test]
async fn demo_redact_runs_pipeline() {
    let (app, _state) = router().await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/api/demo/redact")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"text":"contact alice@example.com card 4111111111111111"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "private, no-store");
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let redacted = v["redacted"].as_str().unwrap_or("");
    assert!(
        redacted.contains("[REDACTED_EMAIL]"),
        "email redacted: {redacted}"
    );
    assert!(
        redacted.contains("[REDACTED_CARD]"),
        "card redacted: {redacted}"
    );
}

#[tokio::test]
async fn demo_process_is_stateless_ordered_and_supports_safe_and_join_modes() {
    let (app, state) = router().await;
    assert!(state.store.list_keys().is_empty());
    for plugin in state.plugins.list() {
        state.plugins.set_enabled(&plugin.id, false);
    }
    let records = serde_json::json!([
        {
            "email": "alice@example.com",
            "card": "4111111111111111",
            "note": "first"
        },
        {
            "email": "alice@example.com",
            "card": "4111111111111111",
            "note": "second"
        },
        {
            "email": "bob@example.com",
            "card": "4111111111111111",
            "note": "third"
        }
    ]);

    let safe = post_demo_process(
        &app,
        serde_json::json!({"records": records, "mode": "safe"}),
    )
    .await;
    assert_eq!(safe.status(), StatusCode::OK);
    assert_demo_response_headers(&safe);
    let safe = demo_response_json(safe).await;
    assert_eq!(safe["mode"], "safe");
    assert_eq!(safe["records"][0]["record"], 1);
    assert_eq!(safe["records"][1]["record"], 2);
    assert_eq!(safe["records"][2]["record"], 3);
    for (index, note) in ["first", "second", "third"].into_iter().enumerate() {
        let body: serde_json::Value =
            serde_json::from_str(safe["records"][index]["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["email"], "[REDACTED_EMAIL]");
        assert_eq!(body["card"], "[REDACTED_CARD]");
        assert_eq!(body["note"], note);
    }

    let join = post_demo_process(
        &app,
        serde_json::json!({"records": records, "mode": "join"}),
    )
    .await;
    assert_eq!(join.status(), StatusCode::OK);
    assert_demo_response_headers(&join);
    let join = demo_response_json(join).await;
    assert_eq!(join["mode"], "join");
    let first: serde_json::Value =
        serde_json::from_str(join["records"][0]["body"].as_str().unwrap()).unwrap();
    let second: serde_json::Value =
        serde_json::from_str(join["records"][1]["body"].as_str().unwrap()).unwrap();
    let third: serde_json::Value =
        serde_json::from_str(join["records"][2]["body"].as_str().unwrap()).unwrap();
    assert_ne!(first["email"], "alice@example.com");
    assert_eq!(first["email"], second["email"]);
    assert_ne!(first["email"], third["email"]);
    assert_eq!(first["note"], "first");
    assert_eq!(second["note"], "second");
    assert_eq!(third["note"], "third");
    assert_eq!(first["card"], "[REDACTED_CARD]");

    let next_request = post_demo_process(
        &app,
        serde_json::json!({
            "records": [{"email": "alice@example.com"}],
            "mode": "join"
        }),
    )
    .await;
    assert_eq!(next_request.status(), StatusCode::OK);
    let next_request = demo_response_json(next_request).await;
    let next_email: serde_json::Value =
        serde_json::from_str(next_request["records"][0]["body"].as_str().unwrap()).unwrap();
    assert_ne!(first["email"], next_email["email"]);
    assert!(state.store.list_keys().is_empty());
}

#[tokio::test]
async fn demo_process_rejects_raw_unknown_and_malformed_modes() {
    let (app, _state) = router().await;
    for mode in ["raw", "unknown", "SAFE"] {
        let response = post_demo_process(
            &app,
            serde_json::json!({"records": [{"value": 1}], "mode": mode}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_demo_response_headers(&response);
        let body = demo_response_json(response).await;
        assert_eq!(body["code"], "invalid_request");
        assert_eq!(body["message"], "Invalid demo request");
    }
}

#[tokio::test]
async fn demo_process_enforces_record_and_canonical_input_limits() {
    let (app, _state) = router().await;
    for records in [
        serde_json::json!([]),
        serde_json::Value::Array(vec![serde_json::Value::Null; 11]),
    ] {
        let response = post_demo_process(
            &app,
            serde_json::json!({"records": records, "mode": "safe"}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_demo_response_headers(&response);
        assert_eq!(
            demo_response_json(response).await["code"],
            "invalid_record_count"
        );
    }

    let response = post_demo_process(
        &app,
        serde_json::json!({
            "records": ["x".repeat(64 * 1024)],
            "mode": "safe"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_demo_response_headers(&response);
    assert_eq!(
        demo_response_json(response).await["code"],
        "input_too_large"
    );

    let response = post_demo_process_body(&app, Body::from(vec![b' '; 512 * 1024 + 1])).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_demo_response_headers(&response);
    assert_eq!(
        demo_response_json(response).await["code"],
        "input_too_large"
    );
}

#[tokio::test]
async fn demo_process_enforces_aggregate_output_limit() {
    let state = test_state().await;
    for plugin in state.plugins.list() {
        state.plugins.set_enabled(&plugin.id, false);
    }
    let app = build_router(state);
    let response = post_demo_process(
        &app,
        serde_json::json!({
            "records": ["a@b.co ".repeat(7_000)],
            "mode": "safe"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_demo_response_headers(&response);
    let body = demo_response_json(response).await;
    assert_eq!(body["code"], "output_too_large");
    assert_eq!(body["message"], "Demo output exceeds 64 KiB");
}

#[tokio::test]
async fn demo_process_enforces_serialized_json_response_limit() {
    let (app, _state) = router().await;
    let response = post_demo_process(
        &app,
        serde_json::json!({
            "records": ["\\".repeat(30_000)],
            "mode": "safe"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_demo_response_headers(&response);
    assert_eq!(
        demo_response_json(response).await["code"],
        "output_too_large"
    );
}

#[tokio::test]
async fn malformed_demo_bodies_consume_the_global_start_allowance() {
    let (app, _state) = router().await;
    for _ in 0..30 {
        let response = post_demo_process_body(&app, Body::from("{")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_demo_response_headers(&response);
    }
    let response = post_demo_process(
        &app,
        serde_json::json!({"records": [{"value": 1}], "mode": "safe"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_demo_response_headers(&response);
    assert_eq!(demo_response_json(response).await["code"], "rate_limited");
}

#[tokio::test]
async fn legacy_demo_paths_are_gone_without_storage_or_plaintext() {
    let (app, state) = router().await;
    let plaintext = "legacy-user@example.com";

    let store = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/dashboard/api/demo/store")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"records":[{{"email":"{plaintext}"}}]}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(store.status(), StatusCode::GONE);
    assert_demo_security_headers(&store);
    let body = axum::body::to_bytes(store.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&body).contains(plaintext));
    assert!(state.store.list_keys().is_empty());

    let read = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/dashboard/api/demo/read?id=1&mode=raw")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read.status(), StatusCode::GONE);
    assert_demo_security_headers(&read);
    let body = axum::body::to_bytes(read.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&body).contains(plaintext));
    assert!(state.store.list_keys().is_empty());

    let process = post_demo_process(
        &app,
        serde_json::json!({
            "records": [{"email": plaintext}],
            "mode": "safe"
        }),
    )
    .await;
    assert_eq!(process.status(), StatusCode::OK);
    assert_demo_response_headers(&process);
    let process = demo_response_json(process).await;
    let processed: serde_json::Value =
        serde_json::from_str(process["records"][0]["body"].as_str().unwrap()).unwrap();
    assert_eq!(processed["email"], "[REDACTED_EMAIL]");
    assert!(state.store.list_keys().is_empty());
}

#[tokio::test]
async fn legacy_demo_tombstones_handle_every_method_before_cors_and_s3() {
    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    let plaintext = "must-not-be-stored@example.com";

    for base_path in ["/dashboard/api/demo/store", "/dashboard/api/demo/read"] {
        for (method, query) in [
            ("CONNECT", "transport=legacy"),
            ("DELETE", "versionId=legacy"),
            ("GET", "id=1&mode=raw"),
            ("HEAD", "id=1&mode=raw"),
            ("OPTIONS", "preflight=legacy"),
            ("PATCH", "mode=raw"),
            ("POST", "uploads"),
            ("PUT", "overwrite=true"),
            ("TRACE", "mode=raw"),
        ] {
            let path = format!("{base_path}?{query}");
            let mut request = Request::builder()
                .method(method)
                .uri(path.as_str())
                .header(header::CONTENT_TYPE, "text/plain");
            if method == "OPTIONS" {
                request = request
                    .header(header::ORIGIN, "https://example.test")
                    .header("access-control-request-method", "POST");
            }
            let response = app
                .clone()
                .oneshot(add_headers(
                    request.body(Body::from(plaintext)).unwrap(),
                    &auth_headers(&access_key, &secret_key),
                ))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::GONE,
                "method: {method}, path: {path}"
            );
            assert_demo_security_headers(&response);
            if method == "OPTIONS" {
                assert!(
                    !response
                        .headers()
                        .contains_key("access-control-allow-origin")
                );
            }
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(body.is_empty(), "method: {method}, path: {path}");
            assert!(!String::from_utf8_lossy(&body).contains(plaintext));
            assert!(state.store.list_keys().is_empty());
        }
    }

    let cors = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/dashboard/api/demo/process")
                .header(header::ORIGIN, "https://example.test")
                .header("access-control-request-method", "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cors.status(), StatusCode::OK);
    assert_eq!(cors.headers()["access-control-allow-origin"], "*");
}
