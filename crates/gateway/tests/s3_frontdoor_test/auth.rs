use super::*;

#[tokio::test]
async fn backend_api_requires_real_auth_rejects_unsupported_config_and_never_returns_secrets() {
    let mut state = test_state().await;
    let secret = b"dashboard-test-secret";
    let issuer = "https://example.supabase.co/auth/v1";
    let claims = serde_json::json!({
        "sub": "dashboard-user",
        "iss": issuer,
        "aud": "authenticated",
        "exp": u64::MAX,
    });
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret),
    )
    .unwrap();
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.supabase_url = "https://example.supabase.co".to_string();
    state_mut.jwt_decoder = Some(Arc::new(jsonwebtoken::DecodingKey::from_secret(secret)));
    let app = build_router(state);

    let unauthenticated = Request::builder()
        .method("PUT")
        .uri("/dashboard/api/backend")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"backend_type":"s3_compatible","endpoint":"http://127.0.0.1:9000","access_key":"access","secret_key":"secret","region":"us-east-1"}"#,
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(unauthenticated).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    let incomplete_aws_role = Request::builder()
        .method("PUT")
        .uri("/dashboard/api/backend")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"backend_type":"aws_role","role_arn":"arn:aws:iam::123456789012:role/maskura"}"#,
        ))
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(incomplete_aws_role)
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );

    let configured = Request::builder()
        .method("PUT")
        .uri("/dashboard/api/backend")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"backend_type":"s3_compatible","endpoint":"http://127.0.0.1:9000","access_key":"access","secret_key":"secret","region":"us-east-1"}"#,
        ))
        .unwrap();
    let response = app.clone().oneshot(configured).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response_json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response_json["configured"], true);
    assert!(response_json.get("access_key").is_none());
    assert!(response_json.get("secret_key").is_none());

    let get = Request::builder()
        .uri("/dashboard/api/backend")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(get).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response_json["endpoint"], "http://127.0.0.1:9000");
    assert_eq!(response_json["access_key_configured"], true);
    assert_eq!(response_json["secret_key_configured"], true);
    assert!(!String::from_utf8_lossy(&body).contains("\"access_key\":"));
    assert!(!String::from_utf8_lossy(&body).contains("\"secret_key\":"));

    let managed = Request::builder()
        .method("PUT")
        .uri("/dashboard/api/backend")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"backend_type":"managed"}"#))
        .unwrap();
    let response = app.oneshot(managed).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response_json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        response_json,
        serde_json::json!({
            "configured": true,
            "backend_type": "managed",
            "endpoint": null,
            "region": null,
            "role_arn": null,
            "external_id": null,
            "access_key_configured": false,
            "secret_key_configured": false,
        })
    );
}

#[tokio::test]
async fn create_key_persistence_failure_returns_unavailable_without_secret() {
    let mut state = test_state().await;
    let blocking_parent = std::env::temp_dir().join(format!(
        "maskura-create-key-failure-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&blocking_parent).unwrap();
    let file_store = FileKeyStore::new(blocking_parent.join("keys.json")).unwrap();
    std::fs::remove_dir_all(&blocking_parent).unwrap();
    std::fs::write(&blocking_parent, "not a directory").unwrap();
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.keys = Arc::new(file_store);
    state_mut.auth_disabled = true;
    let app = build_router(state);

    let request = Request::builder()
        .method("POST")
        .uri("/dashboard/api/keys")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"label":"failure-test"}"#))
        .unwrap();
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "headers: {:?}",
        response.headers()
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), br#"{"error":"internal_error"}"#);
    assert!(!String::from_utf8_lossy(&body).contains("maskura_secret_"));
    std::fs::remove_file(blocking_parent).unwrap();
}

#[tokio::test]
async fn public_key_persistence_failure_returns_generic_503_and_rolls_back() {
    let mut state = test_state().await;
    let parent = std::env::temp_dir().join(format!(
        "maskura-public-key-handler-{}",
        uuid::Uuid::new_v4()
    ));
    let durable_parent = parent.with_extension("durable");
    std::fs::create_dir_all(&parent).unwrap();
    let path = parent.join("keys.json");
    let file_store = Arc::new(FileKeyStore::new(path.clone()).unwrap());
    let (secret_key, created) = file_store
        .create_key(
            "test-user",
            &WorkspaceId::new("test-user").unwrap(),
            "persist-failure",
            0,
            None,
        )
        .await
        .unwrap();
    let key_id = created.key_id;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .keys = file_store.clone();
    let app = build_router(state);
    std::fs::rename(&parent, &durable_parent).unwrap();
    std::fs::write(&parent, "not a directory").unwrap();

    let request = add_headers(
        public_key_request(&key_id, TEST_PUBLIC_KEY_PEM),
        &auth_headers(&key_id, &secret_key),
    );
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(body.is_empty(), "persistence failure body must be generic");
    assert!(!String::from_utf8_lossy(&body).contains("BEGIN PUBLIC KEY"));
    assert!(!String::from_utf8_lossy(&body).contains(&secret_key));
    assert!(
        file_store
            .get_key(&key_id)
            .await
            .unwrap()
            .unwrap()
            .public_key_pem
            .is_none(),
        "failed persistence must roll back the in-memory value"
    );
    std::fs::remove_file(&parent).unwrap();
    std::fs::rename(&durable_parent, &parent).unwrap();
    drop(file_store);

    let restarted = FileKeyStore::new(path).unwrap();
    assert!(
        restarted
            .get_key(&key_id)
            .await
            .unwrap()
            .unwrap()
            .public_key_pem
            .is_none(),
        "failed persistence must not appear after restart"
    );
    std::fs::remove_dir_all(parent).unwrap();
}

#[tokio::test]
async fn dashboard_credential_repository_failures_return_generic_503() {
    let mut state = test_state().await;
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.keys = unavailable_key_store();
    state_mut.auth_disabled = true;
    let app = build_router(state);
    let requests = [
        Request::builder()
            .uri("/dashboard/api/me")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/dashboard/api/keys")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/dashboard/api/keys")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"label":"unavailable"}"#))
            .unwrap(),
        Request::builder()
            .method("DELETE")
            .uri("/dashboard/api/keys")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"key_id":"maskura_missing"}"#))
            .unwrap(),
        Request::builder()
            .uri("/dashboard/api/mcp-tokens")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/dashboard/api/mcp-tokens")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"label":"unavailable"}"#))
            .unwrap(),
        Request::builder()
            .method("DELETE")
            .uri("/dashboard/api/mcp-tokens")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"token_hash":"{}"}}"#,
                "a".repeat(64)
            )))
            .unwrap(),
        add_headers(
            public_key_request("maskura_missing", TEST_PUBLIC_KEY_PEM),
            &auth_headers("maskura_missing", "maskura_secret_missing"),
        ),
    ];

    for request in requests {
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(!body.contains("maskura_secret_"));
        assert!(!body.contains("maskura_mcp_"));
        assert!(!body.contains("Postgres"));
        assert!(!body.contains("127.0.0.1"));
    }
}

#[tokio::test]
async fn credential_authentication_store_failures_return_s3_service_unavailable() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .keys = unavailable_key_store();
    let app = build_router(state);
    let requests = [
        add_headers(
            Request::builder()
                .method("PUT")
                .uri("/outage/key.txt")
                .body(Body::from("sensitive"))
                .unwrap(),
            &auth_headers("maskura_missing", "maskura_secret_missing"),
        ),
        Request::builder()
            .method("PUT")
            .uri("/outage/token.txt")
            .header("authorization", "Bearer maskura_mcp_missing")
            .body(Body::from("sensitive"))
            .unwrap(),
    ];

    for request in requests {
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("<Code>ServiceUnavailable</Code>"));
        assert!(!body.contains("sensitive"));
        assert!(!body.contains("Postgres"));
        assert!(!body.contains("127.0.0.1"));
    }
}

#[tokio::test]
async fn public_key_mutation_rejects_unauthenticated_requests_in_production_and_local_mode() {
    for auth_disabled in [false, true] {
        let mut state = test_state().await;
        let (key_id, _) = make_key(&state).await;
        Arc::get_mut(&mut state)
            .expect("test state is uniquely owned")
            .auth_disabled = auth_disabled;
        let app = build_router(state.clone());

        let response = app
            .oneshot(public_key_request(&key_id, "rejected-pem"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            state
                .keys
                .get_key(&key_id)
                .await
                .unwrap()
                .unwrap()
                .public_key_pem
                .is_none(),
            "rejected request must not mutate the key"
        );
    }
}

#[tokio::test]
async fn auth_headers_accept_the_canonical_maskura_names() {
    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;

    let canonical = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/aliases/canonical.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("canonical"))
            .unwrap(),
        &auth_headers(&access_key, &secret_key),
    );
    assert_eq!(
        app.clone().oneshot(canonical).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn public_key_mutation_rejects_incomplete_or_invalid_api_key_credentials() {
    let state = test_state().await;
    let (key_id, secret_key) = make_key(&state).await;
    let app = build_router(state.clone());
    let requests = [
        add_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[("x-maskura-access-key", key_id.clone())],
        ),
        add_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[("x-maskura-secret-key", secret_key.clone())],
        ),
        add_headers(
            public_key_request(&key_id, "rejected-pem"),
            &auth_headers(&key_id, "wrong-secret"),
        ),
        add_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[("authorization", format!("Bearer {key_id}:wrong-secret"))],
        ),
    ];

    for request in requests {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            state
                .keys
                .get_key(&key_id)
                .await
                .unwrap()
                .unwrap()
                .public_key_pem
                .is_none(),
            "rejected credentials must not mutate the key"
        );
    }
}

#[tokio::test]
async fn public_key_mutation_rejects_duplicate_security_headers_without_mutation() {
    let state = test_state().await;
    let (key_id, secret_key) = make_key(&state).await;
    let mcp_token = state
        .keys
        .create_mcp_token(
            "test-user",
            &WorkspaceId::new("test-user").unwrap(),
            "duplicate-test",
            0,
        )
        .await
        .unwrap()
        .0;
    let app = build_router(state.clone());
    let bearer = format!("Bearer {key_id}:{secret_key}");
    let requests = [
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("authorization", bearer.clone()),
                ("authorization", bearer.clone()),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-maskura-access-key", key_id.clone()),
                ("x-maskura-access-key", key_id.clone()),
                ("x-maskura-secret-key", secret_key.clone()),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-maskura-access-key", key_id.clone()),
                ("x-maskura-secret-key", secret_key.clone()),
                ("x-maskura-secret-key", secret_key.clone()),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-maskura-mcp-token", mcp_token.clone()),
                ("x-maskura-mcp-token", mcp_token.clone()),
            ],
        ),
    ];

    for request in requests {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            state
                .keys
                .get_key(&key_id)
                .await
                .unwrap()
                .unwrap()
                .public_key_pem
                .is_none(),
            "duplicate credential headers must not mutate the key"
        );
    }
}

#[tokio::test]
async fn public_key_mutation_rejects_mixed_credential_classes_without_mutation() {
    let mut state = test_state().await;
    let (key_id, secret_key) = make_key(&state).await;
    let mcp_token = state
        .keys
        .create_mcp_token(
            "test-user",
            &WorkspaceId::new("test-user").unwrap(),
            "mixed-test",
            0,
        )
        .await
        .unwrap()
        .0;
    let jwt = configure_dashboard_jwt(&mut state, "test-user");
    let app = build_router(state.clone());
    let api_bearer = format!("Bearer {key_id}:{secret_key}");
    let requests = [
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-maskura-access-key", key_id.clone()),
                ("x-maskura-secret-key", secret_key.clone()),
                ("authorization", api_bearer.clone()),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-maskura-access-key", key_id.clone()),
                ("x-maskura-secret-key", secret_key.clone()),
                ("authorization", format!("Bearer {jwt}")),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-maskura-mcp-token", mcp_token.clone()),
                ("x-maskura-access-key", key_id.clone()),
                ("x-maskura-secret-key", secret_key.clone()),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-maskura-mcp-token", mcp_token.clone()),
                ("authorization", format!("Bearer {jwt}")),
            ],
        ),
        append_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[
                ("x-maskura-mcp-token", mcp_token),
                ("authorization", api_bearer),
            ],
        ),
    ];

    for request in requests {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(
            state
                .keys
                .get_key(&key_id)
                .await
                .unwrap()
                .unwrap()
                .public_key_pem
                .is_none(),
            "mixed credential classes must not mutate the key"
        );
    }
}

#[tokio::test]
async fn public_key_mutation_accepts_own_key_via_headers_and_bearer() {
    let state = test_state().await;
    let (header_key, header_secret) = make_key(&state).await;
    let (bearer_key, bearer_secret) = make_key(&state).await;
    let app = build_router(state.clone());

    let header_request = add_headers(
        public_key_request(&header_key, TEST_PUBLIC_KEY_PEM),
        &auth_headers(&header_key, &header_secret),
    );
    assert_eq!(
        app.clone().oneshot(header_request).await.unwrap().status(),
        StatusCode::OK
    );

    let bearer_request = add_headers(
        public_key_request(&bearer_key, TEST_PUBLIC_KEY_2_PEM),
        &[(
            "authorization",
            format!("Bearer {bearer_key}:{bearer_secret}"),
        )],
    );
    assert_eq!(
        app.oneshot(bearer_request).await.unwrap().status(),
        StatusCode::OK
    );

    assert_eq!(
        state
            .keys
            .get_key(&header_key)
            .await
            .unwrap()
            .unwrap()
            .public_key_pem
            .as_deref(),
        Some(TEST_PUBLIC_KEY_PEM.trim())
    );
    assert_eq!(
        state
            .keys
            .get_key(&bearer_key)
            .await
            .unwrap()
            .unwrap()
            .public_key_pem
            .as_deref(),
        Some(TEST_PUBLIC_KEY_2_PEM.trim())
    );
}

#[tokio::test]
async fn local_public_key_mutation_accepts_real_target_credentials() {
    let mut state = test_state().await;
    let (key_id, secret_key) = make_key(&state).await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .auth_disabled = true;
    let app = build_router(state.clone());
    let request = add_headers(
        public_key_request(&key_id, TEST_PUBLIC_KEY_PEM),
        &auth_headers(&key_id, &secret_key),
    );

    assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        state
            .keys
            .get_key(&key_id)
            .await
            .unwrap()
            .unwrap()
            .public_key_pem
            .as_deref(),
        Some(TEST_PUBLIC_KEY_PEM.trim())
    );
}

#[tokio::test]
async fn public_key_mutation_rejects_invalid_pem_before_persistence() {
    let state = test_state().await;
    let (key_id, secret_key) = make_key(&state).await;
    let app = build_router(state.clone());

    for public_key_pem in [
        "not an RSA public key".to_string(),
        "x".repeat(MAX_PUBLIC_KEY_PEM_BYTES + 1),
    ] {
        let request = add_headers(
            public_key_request(&key_id, &public_key_pem),
            &auth_headers(&key_id, &secret_key),
        );
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert!(
        state
            .keys
            .get_key(&key_id)
            .await
            .unwrap()
            .unwrap()
            .public_key_pem
            .is_none()
    );
}

#[tokio::test]
async fn api_key_public_key_mutation_hides_and_rejects_sibling_and_foreign_keys() {
    let state = test_state().await;
    let (credential_key, credential_secret) = make_key_for(&state, "owner-a").await;
    let (sibling_key, _) = make_key_for(&state, "owner-a").await;
    let (foreign_key, _) = make_key_for(&state, "owner-b").await;
    let app = build_router(state.clone());
    let mut rejection_bodies = Vec::new();

    for target in [&sibling_key, &foreign_key] {
        let request = add_headers(
            public_key_request(target, "rejected-pem"),
            &auth_headers(&credential_key, &credential_secret),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        rejection_bodies.push(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        );
    }
    assert_eq!(rejection_bodies[0], rejection_bodies[1]);
    assert_eq!(rejection_bodies[0].as_ref(), b"key not found");
    for key_id in [&credential_key, &sibling_key, &foreign_key] {
        assert!(
            state
                .keys
                .get_key(key_id)
                .await
                .unwrap()
                .unwrap()
                .public_key_pem
                .is_none(),
            "rejected cross-key request must not mutate any key"
        );
    }
}

#[tokio::test]
async fn jwt_public_key_mutation_is_scoped_to_dashboard_user_ownership() {
    let mut state = test_state().await;
    let (owned_key, _) = make_key_for(&state, "dashboard-user").await;
    let (second_owned_key, _) = make_key_for(&state, "dashboard-user").await;
    let (foreign_key, _) = make_key_for(&state, "another-user").await;
    let token = configure_dashboard_jwt(&mut state, "dashboard-user");
    let app = build_router(state.clone());

    for (key_id, pem) in [
        (&owned_key, TEST_PUBLIC_KEY_PEM),
        (&second_owned_key, TEST_PUBLIC_KEY_2_PEM),
    ] {
        let request = add_headers(
            public_key_request(key_id, pem),
            &[("authorization", format!("Bearer {token}"))],
        );
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );
    }

    let foreign_request = add_headers(
        public_key_request(&foreign_key, TEST_PUBLIC_KEY_PEM),
        &[("authorization", format!("Bearer {token}"))],
    );
    assert_eq!(
        app.oneshot(foreign_request).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );

    assert_eq!(
        state
            .keys
            .get_key(&owned_key)
            .await
            .unwrap()
            .unwrap()
            .public_key_pem
            .as_deref(),
        Some(TEST_PUBLIC_KEY_PEM.trim())
    );
    assert_eq!(
        state
            .keys
            .get_key(&second_owned_key)
            .await
            .unwrap()
            .unwrap()
            .public_key_pem
            .as_deref(),
        Some(TEST_PUBLIC_KEY_2_PEM.trim())
    );
    assert!(
        state
            .keys
            .get_key(&foreign_key)
            .await
            .unwrap()
            .unwrap()
            .public_key_pem
            .is_none(),
        "wrong-owner JWT must not mutate the target"
    );
}

#[tokio::test]
async fn create_key_still_accepts_an_initial_public_key() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .auth_disabled = true;
    let app = build_router(state.clone());
    let request = Request::builder()
        .method("POST")
        .uri("/dashboard/api/keys")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "label": "created-with-public-key",
                "public_key_pem": TEST_PUBLIC_KEY_2_PEM,
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let key_id = body["key_id"].as_str().unwrap();
    assert_eq!(body["public_key_pem"], TEST_PUBLIC_KEY_2_PEM.trim());
    assert_eq!(
        state
            .keys
            .get_key(key_id)
            .await
            .unwrap()
            .unwrap()
            .public_key_pem
            .as_deref(),
        Some(TEST_PUBLIC_KEY_2_PEM.trim())
    );
}

#[tokio::test]
async fn credential_mutation_endpoints_enforce_input_and_body_boundaries() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .auth_disabled = true;
    let app = build_router(state);

    for (label, expected) in [
        ("a".repeat(MAX_CREDENTIAL_LABEL_BYTES), StatusCode::OK),
        (
            "a".repeat(MAX_CREDENTIAL_LABEL_BYTES + 1),
            StatusCode::BAD_REQUEST,
        ),
        ("control\nlabel".to_string(), StatusCode::BAD_REQUEST),
        ("   ".to_string(), StatusCode::BAD_REQUEST),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/dashboard/api/keys")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "label": label }).to_string(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            expected
        );
    }

    for (expires_in, expected) in [
        (MAX_CREDENTIAL_TTL_SECONDS, StatusCode::OK),
        (MAX_CREDENTIAL_TTL_SECONDS + 1, StatusCode::BAD_REQUEST),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/dashboard/api/keys")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "label": "ttl", "expires_in": expires_in }).to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected);
        if expected == StatusCode::OK {
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert!(body["expires_at"].as_str().is_some());
        }
    }

    for public_key_pem in [
        "not a PEM".to_string(),
        "x".repeat(MAX_PUBLIC_KEY_PEM_BYTES + 1),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/dashboard/api/keys")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "label": "invalid pem",
                    "public_key_pem": public_key_pem,
                })
                .to_string(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }

    for (expires_in, expected) in [
        (MAX_CREDENTIAL_TTL_SECONDS, StatusCode::OK),
        (MAX_CREDENTIAL_TTL_SECONDS + 1, StatusCode::BAD_REQUEST),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/dashboard/api/mcp-tokens")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "label": "agent", "expires_in": expires_in }).to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected);
        if expected == StatusCode::OK {
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert!(body["expires_at"].as_str().is_some());
        }
    }

    for (method, uri, body) in [
        ("POST", "/dashboard/api/keys", "x".repeat(20 * 1024)),
        (
            "PUT",
            "/dashboard/api/keys/public-key",
            "x".repeat(20 * 1024),
        ),
        ("DELETE", "/dashboard/api/keys", "x".repeat(2048)),
        ("POST", "/dashboard/api/mcp-tokens", "x".repeat(2048)),
        ("DELETE", "/dashboard/api/mcp-tokens", "x".repeat(2048)),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}

#[tokio::test]
async fn global_admin_routes_only_mount_in_local_auth_disabled_mode() {
    let state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let headers = auth_headers(&access_key, &secret_key);
    let app = build_router(state.clone());
    let plugin_count = state.plugins.list().len();

    let import = add_headers(
        Request::builder()
            .method("POST")
            .uri("/dashboard/api/plugins")
            .header(header::CONTENT_TYPE, "application/wasm")
            .body(Body::from("not a wasm component"))
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.clone().oneshot(import).await.unwrap().status(),
        StatusCode::NOT_IMPLEMENTED
    );
    assert_eq!(state.plugins.list().len(), plugin_count);

    let objects = add_headers(
        Request::builder()
            .uri("/dashboard/api/objects")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.oneshot(objects).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );

    let mut local_state = test_state().await;
    Arc::get_mut(&mut local_state)
        .expect("test state is uniquely owned")
        .auth_disabled = true;
    let local_app = build_router(local_state);
    let response = local_app
        .oneshot(
            Request::builder()
                .uri("/dashboard/api/plugins")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_objects_returns_keys_and_prefixes() {
    let (app, state) = router().await;
    let (ak, sk) = make_key(&state).await;
    let hdrs = auth_headers(&ak, &sk);

    for key in ["logs/a.txt", "logs/b.txt", "meta.json"] {
        let put = add_headers(
            Request::builder()
                .method("PUT")
                .uri(format!("/bkt/{key}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("data"))
                .unwrap(),
            &hdrs,
        );
        assert_eq!(
            app.clone().oneshot(put).await.unwrap().status(),
            StatusCode::OK
        );
    }

    let list = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bkt?list-type=2")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(list).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_hardened_object_headers(resp.headers());
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Key>logs/a.txt</Key>"), "missing key: {xml}");
    assert!(xml.contains("<Key>logs/b.txt</Key>"), "missing key: {xml}");
    assert!(xml.contains("<Key>meta.json</Key>"), "missing key: {xml}");
    assert!(xml.contains("<KeyCount>3</KeyCount>"), "bad count: {xml}");

    // Prefix listing with delimiter groups logs/ into a CommonPrefix.
    let list = add_headers(
        Request::builder()
            .method("GET")
            .uri("/bkt?list-type=2&prefix=&delimiter=%2F")
            .body(Body::empty())
            .unwrap(),
        &hdrs,
    );
    let resp = app.clone().oneshot(list).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(
        xml.contains("<CommonPrefixes><Prefix>logs/</Prefix></CommonPrefixes>"),
        "no common prefix: {xml}"
    );
    assert!(
        xml.contains("<Key>meta.json</Key>"),
        "top-level key missing: {xml}"
    );
    assert!(
        !xml.contains("logs/a.txt"),
        "folder keys should be grouped: {xml}"
    );
}

#[tokio::test]
async fn non_expiring_key_works() {
    let (app, state) = router().await;
    // expires_in=0 means never expires.
    let (sk, created) = state
        .keys
        .create_key(
            "never-exp",
            &WorkspaceId::new("never-exp").unwrap(),
            "exp",
            0,
            None,
        )
        .await
        .expect("create non-expiring API key");
    let ak = created.key_id;
    let hdrs = auth_headers(&ak, &sk);
    let put = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/demo/x.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("x"))
            .unwrap(),
        &hdrs,
    );
    let resp = app.oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "non-expiring key must work");
}
