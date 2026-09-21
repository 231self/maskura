use super::*;

#[tokio::test]
async fn empty_pipeline_preserves_binary_bytes() {
    let mut state = test_state().await;
    for plugin in state.plugins.list() {
        state.plugins.set_enabled(&plugin.id, false);
    }
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.auth_disabled = true;
    state_mut.dev_memory_streaming_enabled = true;
    let app = build_router(state.clone());

    let binary = Bytes::from_static(b"\x89PNG\r\n\x1a\n\x00\xff\xfe\xfd non-utf8 \x80\x81");
    let request = Request::builder()
        .method("PUT")
        .uri("/stream/blob.bin")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, binary.len().to_string())
        .body(Body::from(binary.clone()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let stored = state
        .store
        .get("stream", "blob.bin")
        .expect("binary stored verbatim");
    assert_eq!(stored.data, binary);
}

#[tokio::test]
async fn pipeline_expansion_past_output_cap_releases_before_sink_commit() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let component_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/components/pii-default.component.wasm");
    let component = std::fs::read(component_path).expect("built pii-default component");
    let fuel = maskura_gateway::plugin_registry::DEFAULT_PIPELINE_FUEL;
    let registry = Arc::new(
        PluginRegistry::with_options(
            fuel,
            PipelineLimits {
                max_input_bytes: 64,
                max_output_bytes: 20,
                max_expansion_factor: 32,
                max_expansion_slack_bytes: 64,
                max_cumulative_fuel: fuel,
                ..PipelineLimits::default()
            },
            maskura_wasm_runtime::ExecutorConfig::default(),
        )
        .unwrap(),
    );
    registry.import("pii-default", &component).unwrap();
    let control = Arc::new(RecordingMeteringControl::default());
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.gateway = Arc::new(Gateway::with_registry(
        maskura_wasm_runtime::FilterEngine::with_fuel(&component, fuel).unwrap(),
        registry.clone(),
    ));
    state_mut.plugins = registry;
    state_mut.source_body_limits.max_bytes = 64;
    state_mut.max_pipeline_output_bytes = 20;
    state_mut.control = control.clone();

    let response = build_router(state.clone())
        .oneshot(add_headers(
            Request::builder()
                .method("PUT")
                .uri("/limited/expanded.txt")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("contact a@b.com now"))
                .unwrap(),
            &auth_headers(&access_key, &secret_key),
        ))
        .await
        .unwrap();

    let status = response.status();
    let response_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&response_body)
    );
    assert!(String::from_utf8_lossy(&response_body).contains("<Code>EntityTooLarge</Code>"));
    assert!(state.store.get("limited", "expanded.txt").is_none());
    assert!(control.events.lock().unwrap().is_empty());
    let authorizations = control.authorizations.lock().unwrap();
    let releases = control.releases.lock().unwrap();
    assert_eq!(authorizations.len(), 1);
    assert_eq!(authorizations[0].1.max_processed_bytes(), 64);
    assert_eq!(
        releases.as_slice(),
        &[(
            authorizations[0].0.clone(),
            authorizations[0].1.operation_id()
        )]
    );
}

#[tokio::test]
async fn resolver_precedes_authorization_and_isolates_workspace_bucket_and_direction() {
    let mut state = test_state().await;
    let baseline = StaticPipelineResolver::new(state.plugins.clone())
        .resolve("seed", "seed", PipelineDirection::Write)
        .await
        .unwrap();
    let resolved = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let resolver = Arc::new(TestPipelineResolver {
        resolution: baseline,
        calls: Mutex::default(),
        resolved: resolved.clone(),
        failure_code: None,
    });
    let control = Arc::new(PipelineAttemptControl {
        resolved,
        ..PipelineAttemptControl::default()
    });
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.streaming_read_mode = StreamingReadMode::Transformed;
    state_mut.transformed_read_spool_enabled = true;
    state_mut.control = control.clone();
    state_mut.gateway = Arc::new(
        state_mut
            .gateway
            .as_ref()
            .clone()
            .with_resolver(resolver.clone(), state_mut.plugins.clone()),
    );
    let first = make_key_for(&state, "workspace-a").await;
    let second = make_key_for(&state, "workspace-b").await;
    let app = build_router(state);

    for (credentials, key) in [(&first, "a.txt"), (&second, "b.txt")] {
        control.resolved.store(false, Ordering::Release);
        let response = app
            .clone()
            .oneshot(add_headers(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/same-bucket/{key}"))
                    .header(header::CONTENT_TYPE, "text/plain")
                    .body(Body::from("alice@example.com"))
                    .unwrap(),
                &auth_headers(&credentials.0, &credentials.1),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    control.resolved.store(false, Ordering::Release);
    let response = app
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/same-bucket/a.txt")
                .header("x-maskura-process", "read")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&first.0, &first.1),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let calls = resolver.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            (
                "workspace-a".to_string(),
                "same-bucket".to_string(),
                PipelineDirection::Write,
            ),
            (
                "workspace-b".to_string(),
                "same-bucket".to_string(),
                PipelineDirection::Write,
            ),
            (
                "workspace-a".to_string(),
                "same-bucket".to_string(),
                PipelineDirection::Read,
            ),
        ]
    );
    assert_eq!(control.authorizations.load(Ordering::Relaxed), 3);
    assert_eq!(control.usage.load(Ordering::Relaxed), 3);
    assert!(control.attempts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn resolver_outage_and_artifact_corruption_fail_closed_without_body_or_charge() {
    for artifact_corruption in [false, true] {
        let mut state = test_state().await;
        let mut resolution = StaticPipelineResolver::new(state.plugins.clone())
            .resolve("seed", "seed", PipelineDirection::Write)
            .await
            .unwrap();
        if artifact_corruption {
            resolution.steps[0].component_hash = "a".repeat(64);
        }
        let resolved = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let resolver = Arc::new(TestPipelineResolver {
            resolution,
            calls: Mutex::default(),
            resolved: resolved.clone(),
            failure_code: (!artifact_corruption).then_some(maskura_error::codes::INTERNAL),
        });
        let control = Arc::new(PipelineAttemptControl {
            resolved,
            ..PipelineAttemptControl::default()
        });
        let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
        state_mut.control = control.clone();
        let source: Arc<dyn ComponentSource> = if artifact_corruption {
            Arc::new(CorruptComponentSource)
        } else {
            state_mut.plugins.clone()
        };
        state_mut.gateway = Arc::new(
            state_mut
                .gateway
                .as_ref()
                .clone()
                .with_resolver(resolver, source),
        );
        let credentials = make_key(&state).await;
        let polls = Arc::new(AtomicUsize::new(0));
        let response = build_router(state)
            .oneshot(add_headers(
                Request::builder()
                    .method("PUT")
                    .uri("/failure/object.txt")
                    .header(header::CONTENT_TYPE, "text/plain")
                    .body(Body::new(PollTrackingBody {
                        polls: polls.clone(),
                        data: Some(Bytes::from_static(b"must-not-be-polled")),
                    }))
                    .unwrap(),
                &auth_headers(&credentials.0, &credentials.1),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("<Code>InternalError</Code>"));
        assert!(!body.contains("private resolver detail"));
        assert!(!body.contains("corrupt artifact bytes"));
        assert_eq!(polls.load(Ordering::Relaxed), 0);
        assert_eq!(control.usage.load(Ordering::Relaxed), 0);
        assert_eq!(control.attempts.lock().unwrap().len(), 1);
        if artifact_corruption {
            assert_eq!(control.authorizations.load(Ordering::Relaxed), 1);
            assert_eq!(control.releases.load(Ordering::Relaxed), 1);
        } else {
            assert_eq!(control.authorizations.load(Ordering::Relaxed), 0);
            assert_eq!(control.releases.load(Ordering::Relaxed), 0);
        }
    }
}
