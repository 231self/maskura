use super::*;

#[tokio::test]
async fn resolved_feature_limit_and_wasm_config_populates_state_without_late_env_reads() {
    let root =
        std::env::temp_dir().join(format!("maskura-resolved-config-{}", uuid::Uuid::new_v4()));
    let mut config = test_config();
    config.supabase.url = Some("https://config-snapshot.supabase.co".to_string());
    config.features.streaming_read_mode = ConfigStreamingReadMode::Transformed;
    config.features.transformed_read_spool = true;
    config.features.enable_avro = true;
    config.features.streaming_s3_provider = Some(StreamingS3Provider::Aws);
    config.limits.source_max_frame_bytes = Some(4096);
    config.limits.max_object_bytes = Some(2 * 1024 * 1024);
    config.limits.max_pipeline_output_bytes = Some(1024 * 1024);
    config.limits.legacy_max_object_bytes = Some(8192);
    config.limits.dev_memory_max_object_bytes = Some(16_384);
    config.wasm.fuel = Some(123_456);
    config.spool.dir = Some(root.join("spool").display().to_string());
    config.spool.max_object_bytes = Some(512 * 1024);
    config.spool.quota_bytes = Some(1024 * 1024);
    let keys_file = root.join("keys/keys.json");
    config.keys.keys_file = Some(keys_file.display().to_string());
    config.managed.placement_version = Some(7);
    config.multipart_staging.endpoint = Some("https://staging.example.com".to_string());
    config.multipart_staging.bucket = Some("staging-bucket".to_string());
    config.multipart_staging.region = Some("config-region-1".to_string());
    config.multipart_staging.dir = Some(root.join("multipart").display().to_string());
    config.multipart_staging.tenant_quota_bytes = Some(2 * 1024 * 1024);
    config.multipart_staging.global_quota_bytes = Some(4 * 1024 * 1024);
    config.sigv4.region = Some("config-region-1".to_string());
    config.sigv4.trusted_tls = true;
    config.allowlists.workspace_endpoint = vec!["storage.example.com".to_string()];
    config.allowlists.workspace_endpoint_private = vec!["127.0.0.1".to_string()];
    config.allowlists.presigned_http = vec!["download.example.com".to_string()];
    config.allowlists.presigned_http_private = vec!["127.0.0.1".to_string()];
    config.allowlists.presigned_http_allow_http = true;
    config.allowlists.presigned_http_min_validity_secs = Some(45);
    config.validate().expect("valid resolved config snapshot");

    let pipeline_template =
        StatePipelineTemplate::from_config(&config).expect("compile configured pipeline");
    let state = build_state_with_pipeline_template(
        Arc::new(NoopControlPlane),
        default_wrapping().expect("wrapping"),
        Arc::new(InMemoryWorkspaceStorageRepository::new()),
        &pipeline_template,
        &config,
    )
    .await
    .expect("build configured state");

    assert_eq!(state.streaming_read_mode, StreamingReadMode::Transformed);
    assert!(state.transformed_read_spool_enabled);
    assert!(state.binary_avro_enabled);
    assert!(state.s3_streaming_capabilities.is_some());
    assert_eq!(state.source_body_limits.max_frame_bytes, 4096);
    assert_eq!(state.source_body_limits.max_bytes, 2 * 1024 * 1024);
    assert_eq!(state.max_pipeline_output_bytes, 1024 * 1024);
    assert_eq!(state.legacy_max_object_bytes, 8192);
    assert_eq!(state.dev_memory_max_object_bytes, 16_384);
    assert_eq!(state.supabase_url, "https://config-snapshot.supabase.co");
    assert_eq!(state.spool_config.directory, root.join("spool"));
    assert_eq!(state.spool_config.max_object_bytes, 512 * 1024);

    state
        .keys
        .create_key(
            "config-snapshot",
            &WorkspaceId::new("config-snapshot").unwrap(),
            "config-snapshot",
            0,
            None,
        )
        .await
        .expect("configured key store persists");
    assert!(keys_file.is_file());

    let app = build_router(state.clone());
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let html = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("https://config-snapshot.supabase.co"));

    drop(app);
    drop(state);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn public_engine_migration_helper_compiles_for_private_integration() {
    let _helper = maskura_gateway::run_engine_migrations;
}

#[tokio::test]
async fn available_aws_cli_and_boto3_interoperate() {
    if std::env::var("MASKURA_RUN_EXTERNAL_CLIENT_INTEROP").as_deref() != Ok("1") {
        return;
    }
    let aws_available = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new("aws")
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .is_ok_and(|result| result.is_ok_and(|output| output.status.success()));
    let boto3_available = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new("python3")
            .args(["-c", "import boto3"])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .is_ok_and(|result| result.is_ok_and(|output| output.status.success()));
    assert!(
        aws_available,
        "MASKURA_RUN_EXTERNAL_CLIENT_INTEROP requires AWS CLI"
    );
    assert!(
        boto3_available,
        "MASKURA_RUN_EXTERNAL_CLIENT_INTEROP requires boto3"
    );

    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .sigv4_policy = SigV4Policy::new("us-east-1", true);
    let (access_key, secret) = make_key(&state).await;
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let endpoint = format!("http://{address}");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    if aws_available {
        let endpoint = endpoint.clone();
        let access_key = access_key.clone();
        let secret = secret.clone();
        let mut child = Command::new("aws")
            .args([
                "s3",
                "cp",
                "-",
                "s3://cli-bucket/default.txt",
                "--endpoint-url",
                &endpoint,
                "--region",
                "us-east-1",
                "--no-progress",
                "--content-type",
                "text/plain",
            ])
            .env("AWS_ACCESS_KEY_ID", access_key)
            .env("AWS_SECRET_ACCESS_KEY", secret)
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("start AWS CLI");
        child
            .stdin
            .take()
            .expect("AWS CLI stdin")
            .write_all(b"CLI contact cli@example.com")
            .await
            .expect("write AWS CLI body");
        let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
            .await
            .expect("AWS CLI timed out")
            .expect("wait for AWS CLI");
        assert!(
            output.status.success(),
            "AWS CLI failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(state.store.get("cli-bucket", "default.txt").is_some());
    }

    if boto3_available {
        let script = r#"
import boto3, os
from botocore.config import Config
boto3.client(
    "s3",
    endpoint_url=os.environ["MASKURA_TEST_ENDPOINT"],
    region_name="us-east-1",
    aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    config=Config(s3={"addressing_style": "path"}),
).put_object(Bucket="boto-bucket", Key="default.txt", Body=b"boto contact boto@example.com", ContentType="text/plain")
"#;
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            Command::new("python3")
                .args(["-c", script])
                .env("MASKURA_TEST_ENDPOINT", &endpoint)
                .env("AWS_ACCESS_KEY_ID", &access_key)
                .env("AWS_SECRET_ACCESS_KEY", &secret)
                .env("AWS_EC2_METADATA_DISABLED", "true")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("boto3 timed out")
        .expect("run boto3");
        assert!(
            output.status.success(),
            "boto3 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(state.store.get("boto-bucket", "default.txt").is_some());
    }
    server.abort();
}

#[tokio::test]
async fn cancellation_during_committed_settlement_returns_success_without_release() {
    let control = Arc::new(BlockingSettlementControl::default());
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
    let operation = tokio::spawn(invoke_mcp(
        state,
        context,
        uuid::Uuid::now_v7(),
        ToolRequest::PutObject(PutObjectRequest {
            bucket: "trusted".into(),
            key: "committed.txt".into(),
            body: "stored".into(),
            content_type: "text/plain".into(),
        }),
        InvocationLimits::default(),
        cancellation.clone(),
    ));
    control.record_started.notified().await;
    cancellation.cancel();
    control.finish_record.notify_one();

    assert!(matches!(
        operation.await.unwrap(),
        Ok(ToolResult::PutObject(_))
    ));
    assert_eq!(control.events.lock().unwrap().len(), 1);
    assert_eq!(control.releases.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn legacy_body_limit_never_exceeds_hard_ceiling() {
    let mut state = test_state().await;
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .legacy_max_object_bytes = usize::MAX;
    let app = build_router(state.clone());
    let (ak, sk) = make_key(&state).await;
    let request = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/limits/default.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(vec![b'x'; 16 * 1024 * 1024 + 1]))
            .unwrap(),
        &auth_headers(&ak, &sk),
    );

    let resp = app.oneshot(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let xml = String::from_utf8_lossy(&body);
    assert!(xml.contains("<Code>EntityTooLarge</Code>"), "{xml}");
}
