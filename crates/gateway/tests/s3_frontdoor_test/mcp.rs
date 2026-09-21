use super::*;

#[tokio::test]
async fn mcp_tokens_cannot_mutate_public_keys() {
    let state = test_state().await;
    let (key_id, _) = make_key_for(&state, "mcp-user").await;
    let token = state
        .keys
        .create_mcp_token(
            "mcp-user",
            &WorkspaceId::new("mcp-user").unwrap(),
            "mutation-test",
            0,
        )
        .await
        .unwrap()
        .0;
    let app = build_router(state.clone());
    let requests = [
        add_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[("authorization", format!("Bearer {token}"))],
        ),
        add_headers(
            public_key_request(&key_id, "rejected-pem"),
            &[("x-maskura-mcp-token", token)],
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
            "MCP rejection must leave the target unchanged"
        );
    }
}

#[tokio::test]
async fn mcp_token_roundtrip_and_auth() {
    let (app, state) = router().await;

    // Create an MCP token.
    let token = state
        .keys
        .create_mcp_token(
            "mcp-user",
            &WorkspaceId::new("mcp-user").unwrap(),
            "agent",
            0,
        )
        .await
        .unwrap()
        .0;
    assert!(token.starts_with("maskura_mcp_"), "token prefix: {token}");

    // Use it as a Bearer token to write.
    let put = Request::builder()
        .method("PUT")
        .uri("/mcpbkt/obj.txt")
        .header(header::CONTENT_TYPE, "text/plain")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::from("hello a@b.com"))
        .unwrap();
    let resp = app.clone().oneshot(put).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "MCP bearer write");

    // Read back (filtered).
    let get = Request::builder()
        .method("GET")
        .uri("/mcpbkt/obj.txt")
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(get).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("[REDACTED_EMAIL]"),
        "MCP write filtered: {text}"
    );

    // A forged token must be rejected.
    let bad = Request::builder()
        .method("PUT")
        .uri("/mcpbkt/obj.txt")
        .header("Authorization", "Bearer maskura_mcp_forged_token_0000")
        .body(Body::from("x"))
        .unwrap();
    let resp = app.clone().oneshot(bad).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "forged MCP token rejected"
    );

    // Delete works (returns 200/204).
    let hash = maskura_gateway::store::sha256_hash(&token);
    assert!(
        state
            .keys
            .delete_mcp_token(&hash, "mcp-user")
            .await
            .unwrap()
    );
    assert!(
        !state
            .keys
            .delete_mcp_token(&hash, "mcp-user")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn mcp_token_identity_is_workspace_bound() {
    let (app, state) = router().await;
    let t1 = state
        .keys
        .create_mcp_token(
            "user-a",
            &WorkspaceId::new("workspace-a").unwrap(),
            "agent",
            0,
        )
        .await
        .unwrap()
        .0;
    let t2 = state
        .keys
        .create_mcp_token(
            "user-b",
            &WorkspaceId::new("workspace-b").unwrap(),
            "agent",
            0,
        )
        .await
        .unwrap()
        .0;

    // user-a can write; user-b's token cannot read user-a's in-memory object
    // under a different identity via the dashboard key list (identity binding).
    let put = Request::builder()
        .method("PUT")
        .uri("/abkt/o.txt")
        .header(header::CONTENT_TYPE, "text/plain")
        .header("Authorization", format!("Bearer {t1}"))
        .body(Body::from("data"))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(put).await.unwrap().status(),
        StatusCode::OK
    );

    // Tokens resolve to immutable user/workspace principals.
    let uid1 = state.keys.resolve_mcp_token(&t1).await.unwrap().unwrap();
    let uid2 = state.keys.resolve_mcp_token(&t2).await.unwrap().unwrap();
    assert_ne!(uid1, uid2, "tokens must bind to distinct principals");
    assert_eq!(uid1.context().user_id, "user-a");
    assert_eq!(uid1.context().workspace_id.as_str(), "workspace-a");
    assert_eq!(uid2.context().user_id, "user-b");
    assert_eq!(uid2.context().workspace_id.as_str(), "workspace-b");
}

#[tokio::test]
async fn trusted_mcp_invocation_uses_gateway_pipeline_without_auth_headers() {
    let state = test_state().await;
    let context = trusted_context(&state, "hosted-workspace").await;
    let cancellation = tokio_util::sync::CancellationToken::new();
    let put = invoke_mcp(
        state.clone(),
        context.clone(),
        uuid::Uuid::now_v7(),
        ToolRequest::PutObject(PutObjectRequest {
            bucket: "trusted".to_string(),
            key: "record.txt".to_string(),
            body: "contact alice@example.com".to_string(),
            content_type: "text/plain".to_string(),
        }),
        InvocationLimits::default(),
        cancellation.clone(),
    )
    .await
    .unwrap();
    assert!(matches!(put, ToolResult::PutObject(_)));

    let get = invoke_mcp(
        state,
        context,
        uuid::Uuid::now_v7(),
        ToolRequest::GetObject(GetObjectRequest {
            bucket: "trusted".to_string(),
            key: "record.txt".to_string(),
            process: false,
        }),
        InvocationLimits::default(),
        cancellation,
    )
    .await
    .unwrap();
    let ToolResult::GetObject(get) = get else {
        panic!("expected get result")
    };
    assert!(get.body.contains("[REDACTED_EMAIL]"));
}

#[tokio::test]
async fn trusted_mcp_invocation_enforces_limits_and_cancellation() {
    let state = test_state().await;
    let context = trusted_context(&state, "hosted-workspace").await;
    let request = || {
        ToolRequest::PutObject(PutObjectRequest {
            bucket: "trusted".to_string(),
            key: "bounded.txt".to_string(),
            body: "too large".to_string(),
            content_type: "text/plain".to_string(),
        })
    };
    let error = invoke_mcp(
        state.clone(),
        context.clone(),
        uuid::Uuid::now_v7(),
        request(),
        InvocationLimits::new(2, 8 * 1024 * 1024, std::time::Duration::from_secs(30)).unwrap(),
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, InvocationError::Invalid(_)));

    let cancellation = tokio_util::sync::CancellationToken::new();
    cancellation.cancel();
    let error = invoke_mcp(
        state,
        context,
        uuid::Uuid::now_v7(),
        request(),
        InvocationLimits::default(),
        cancellation,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, InvocationError::Cancelled));
}

#[tokio::test]
async fn trusted_mcp_operation_ids_reject_conflicting_complete_identities() {
    let state = test_state().await;
    state
        .store
        .put("trusted", "source.txt", "value", "text/plain");
    let context = trusted_context(&state, "hosted-workspace").await;

    let cases = [
        (
            ToolRequest::PutObject(PutObjectRequest {
                bucket: "trusted".into(),
                key: "put-a.txt".into(),
                body: "a".into(),
                content_type: "text/plain".into(),
            }),
            ToolRequest::PutObject(PutObjectRequest {
                bucket: "trusted".into(),
                key: "put-b.txt".into(),
                body: "b".into(),
                content_type: "text/plain".into(),
            }),
        ),
        (
            ToolRequest::GetObject(GetObjectRequest {
                bucket: "trusted".into(),
                key: "source.txt".into(),
                process: false,
            }),
            ToolRequest::GetObject(GetObjectRequest {
                bucket: "trusted".into(),
                key: "other.txt".into(),
                process: false,
            }),
        ),
        (
            ToolRequest::ListObjects(ListObjectsRequest {
                bucket: "trusted".into(),
                prefix: String::new(),
                continuation_token: None,
                max_keys: Some(10),
                delimiter: None,
                start_after: None,
            }),
            ToolRequest::ListObjects(ListObjectsRequest {
                bucket: "trusted".into(),
                prefix: "other".into(),
                continuation_token: None,
                max_keys: Some(10),
                delimiter: Some("/".into()),
                start_after: None,
            }),
        ),
        (
            ToolRequest::DeleteObject(DeleteObjectRequest {
                bucket: "trusted".into(),
                key: "source.txt".into(),
            }),
            ToolRequest::DeleteObject(DeleteObjectRequest {
                bucket: "trusted".into(),
                key: "other.txt".into(),
            }),
        ),
    ];

    for (first, conflict) in cases {
        let operation_id = uuid::Uuid::now_v7();
        let cancellation = tokio_util::sync::CancellationToken::new();
        let first_result = invoke_mcp(
            state.clone(),
            context.clone(),
            operation_id,
            first.clone(),
            InvocationLimits::default(),
            cancellation.clone(),
        )
        .await;
        assert!(!matches!(first_result, Err(InvocationError::Invalid(_))));
        let exact_retry = invoke_mcp(
            state.clone(),
            context.clone(),
            operation_id,
            first,
            InvocationLimits::default(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert!(!matches!(exact_retry, Err(InvocationError::Invalid(_))));
        let conflict = invoke_mcp(
            state.clone(),
            context.clone(),
            operation_id,
            conflict,
            InvocationLimits::default(),
            cancellation,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(conflict, InvocationError::Invalid(message) if message.contains("already bound"))
        );
    }
}

#[test]
fn trusted_mcp_limits_have_non_configurable_hard_ceilings() {
    assert!(InvocationLimits::new(0, 1, Duration::from_secs(1)).is_err());
    assert!(
        InvocationLimits::new(
            maskura_gateway::mcp::MAX_TEXT_BODY_BYTES + 1,
            1,
            Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(
        InvocationLimits::new(
            1,
            maskura_gateway::server::MAX_INVOCATION_RESPONSE_BYTES + 1,
            Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(InvocationLimits::new(1, 1, Duration::ZERO).is_err());
    assert!(InvocationLimits::new(1, 1, Duration::from_secs(121)).is_err());
}

#[tokio::test]
async fn active_trusted_mcp_cancellation_releases_precommit_reservation() {
    let control = Arc::new(RecordingMeteringControl::default());
    let config = test_config();
    let state = build_state_with_pipeline_template(
        control.clone(),
        default_wrapping().expect("wrapping"),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        test_pipeline_template(),
        &config,
    )
    .await
    .unwrap();
    let context = trusted_context(&state, "hosted-workspace").await;
    let cancellation = tokio_util::sync::CancellationToken::new();
    let operation_cancellation = cancellation.clone();
    let operation = tokio::spawn(invoke_mcp(
        state,
        context,
        uuid::Uuid::now_v7(),
        ToolRequest::PutObject(PutObjectRequest {
            bucket: "trusted".into(),
            key: "cancelled.txt".into(),
            body: "contact alice@example.com\n".repeat(100_000),
            content_type: "text/plain".into(),
        }),
        InvocationLimits::default(),
        operation_cancellation,
    ));
    while control.authorizations.lock().unwrap().is_empty() {
        tokio::task::yield_now().await;
    }
    cancellation.cancel();

    assert!(matches!(
        operation.await.unwrap(),
        Err(InvocationError::Cancelled)
    ));
    assert_eq!(control.releases.lock().unwrap().len(), 1);
    assert!(control.events.lock().unwrap().is_empty());
}
