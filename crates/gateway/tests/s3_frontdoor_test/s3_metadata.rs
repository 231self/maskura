//! Synthetic direct-S3 metadata round trips. No real provider or bucket is used.
use super::*;

#[derive(Default)]
struct ProviderState {
    object: Mutex<Option<(axum::http::HeaderMap, Bytes)>>,
    puts: AtomicUsize,
}

async fn provider(
    axum::extract::State(state): axum::extract::State<Arc<ProviderState>>,
    request: Request<Body>,
) -> axum::response::Response {
    let (parts, body) = request.into_parts();
    if parts.method == axum::http::Method::PUT {
        state.puts.fetch_add(1, Ordering::SeqCst);
        let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let mut metadata = axum::http::HeaderMap::new();
        for (name, value) in &parts.headers {
            if name == header::CONTENT_TYPE
                || name == header::CONTENT_ENCODING
                || name.as_str().starts_with("x-amz-meta-")
            {
                metadata.insert(name, value.clone());
            }
        }
        *state.object.lock().unwrap() = Some((metadata, body));
        return axum::response::Response::builder()
            .status(StatusCode::OK)
            .header(header::ETAG, "\"synthetic\"")
            .body(Body::empty())
            .unwrap();
    }
    let Some((headers, bytes)) = state.object.lock().unwrap().clone() else {
        return axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap();
    };
    let mut response = axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(header::ETAG, "\"synthetic\"")
        .header(header::CONTENT_LENGTH, bytes.len());
    for (name, value) in &headers {
        response = response.header(name, value);
    }
    response
        .body(if parts.method == axum::http::Method::HEAD {
            Body::empty()
        } else {
            Body::from(bytes)
        })
        .unwrap()
}

#[tokio::test]
async fn direct_s3_metadata_roundtrips_and_reserved_names_fail_before_provider_write() {
    let provider_state = Arc::new(ProviderState::default());
    let upstream = Router::new()
        .fallback(axum::routing::any(provider))
        .with_state(provider_state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let mut state = explicit_passthrough_test_state(None).await;
    let config = Arc::get_mut(&mut state).unwrap();
    config.operation_journal = Some(Arc::new(InMemoryOperationJournal::durable_for_test()));
    config.s3_streaming_capabilities = Some(BackendCapabilities {
        incomplete_upload_discovery: IncompleteUploadDiscovery::ExactKeyAndStartTime,
        abort_incomplete_upload: true,
        cleanup_sla: Some(Duration::from_secs(300)),
        lifecycle_rule: true,
        versioning: VersioningCapability::Optional,
        conditional_reads: ConditionalReadCapability::VersionAndEtag,
        response_checksums: ResponseChecksumCapability::Standard,
        list_operations: ListCapability::V1AndV2,
        multipart_responses: MultipartResponseCapability::Standard,
        completion_reconciliation: CompletionReconciliation::HeadWithOperationIdentity,
    });
    config.s3_client = Some(aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "synthetic",
                "synthetic",
                None,
                None,
                "test",
            ))
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .endpoint_url(endpoint)
            .force_path_style(true)
            .build(),
    ));
    let (ak, sk) = make_key(&state).await;
    let headers = auth_headers(&ak, &sk);
    let app = build_router(state);
    for marker in [Some("one"), Some("two"), None] {
        let mut put = Request::builder()
            .method("PUT")
            .uri("/metadata/synthetic.txt")
            .header(header::CONTENT_TYPE, "Text/Plain; charset=utf-8")
            .header("x-amz-meta-content-encoding", "customer");
        if let Some(value) = marker {
            put = put.header("x-amz-meta-project", value);
        }
        let response = app
            .clone()
            .oneshot(add_headers(
                put.body(Body::from("synthetic payload")).unwrap(),
                &headers,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        for method in ["HEAD", "GET"] {
            let request = add_headers(
                Request::builder()
                    .method(method)
                    .uri("/metadata/synthetic.txt")
                    .body(Body::empty())
                    .unwrap(),
                &headers,
            );
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE).unwrap(),
                "Text/Plain; charset=utf-8"
            );
            assert_eq!(
                response
                    .headers()
                    .get("x-amz-meta-content-encoding")
                    .and_then(|value| value.to_str().ok()),
                Some("customer")
            );
            assert_eq!(
                response
                    .headers()
                    .get("x-amz-meta-project")
                    .and_then(|value| value.to_str().ok()),
                marker
            );
        }
    }
    for name in [
        "x-amz-meta-maskura-operation-id",
        "x-amz-meta-maskura-size",
        "x-amz-meta-maskura-sha256",
        "x-amz-meta-maskura-generation",
        "x-amz-meta-maskura-provider-instance",
        "x-amz-meta-maskura-provider-account",
        "x-amz-meta-maskura-credential-epoch",
    ] {
        let before = provider_state.puts.load(Ordering::SeqCst);
        let request = add_headers(
            Request::builder()
                .method("PUT")
                .uri("/metadata/synthetic.txt")
                .header(header::CONTENT_TYPE, "text/plain")
                .header(name, "synthetic")
                .body(Body::from("synthetic payload"))
                .unwrap(),
            &headers,
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(provider_state.puts.load(Ordering::SeqCst), before, "{name}");
    }
    task.abort();
}
