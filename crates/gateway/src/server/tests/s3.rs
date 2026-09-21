use super::super::*;
use super::*;

#[test]
fn byte_range_parser_preserves_single_range_semantics_with_u64_offsets() {
    for (range, expected) in [
        (
            None,
            ByteRange {
                start: 0,
                length: 10,
                content_range: None,
            },
        ),
        (
            Some("bytes=0-3"),
            ByteRange {
                start: 0,
                length: 4,
                content_range: Some("bytes 0-3/10".to_string()),
            },
        ),
        (
            Some("bytes=4-"),
            ByteRange {
                start: 4,
                length: 6,
                content_range: Some("bytes 4-9/10".to_string()),
            },
        ),
        (
            Some("bytes=-3"),
            ByteRange {
                start: 7,
                length: 3,
                content_range: Some("bytes 7-9/10".to_string()),
            },
        ),
        (
            Some("bytes=7-30"),
            ByteRange {
                start: 7,
                length: 3,
                content_range: Some("bytes 7-9/10".to_string()),
            },
        ),
    ] {
        assert_eq!(parse_byte_range(10, range).unwrap(), expected);
    }

    assert_eq!(
        parse_byte_range(u64::MAX, Some("bytes=4294967296-4294967297")).unwrap(),
        ByteRange {
            start: 4_294_967_296,
            length: 2,
            content_range: Some(format!("bytes 4294967296-4294967297/{}", u64::MAX)),
        }
    );
    assert_eq!(
        parse_byte_range(0, None).unwrap(),
        ByteRange {
            start: 0,
            length: 0,
            content_range: None,
        }
    );
}

#[test]
fn byte_range_parser_rejects_malformed_and_unsatisfiable_ranges() {
    for (object_length, range) in [
        (10, "bytes=1-2,4-5"),
        (10, "items=1-2"),
        (10, "bytes=-0"),
        (10, "bytes=8-7"),
        (10, "bytes=10-"),
        (10, "bytes=x-2"),
        (0, "bytes=0-0"),
    ] {
        assert!(matches!(
            parse_byte_range(object_length, Some(range)),
            Err(OpenObjectError::InvalidRange {
                object_length: actual
            }) if actual == object_length
        ));
    }
}

#[test]
fn avro_content_types_are_distinguished_from_text_formats() {
    for content_type in [
        "application/avro",
        "application/x-avro; charset=binary",
        "application/vnd.apache.avro+binary",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
        assert!(is_avro_content_type(&headers));
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    assert!(!is_avro_content_type(&headers));
}

#[tokio::test]
async fn metered_read_records_admitted_bytes_before_returning_the_body() {
    let control = Arc::new(RecordingControlPlane::default());
    let operation = OperationIdentity {
        receipt_id: Uuid::now_v7(),
        operation_id: Uuid::now_v7(),
    };
    let auth = Auth {
        context: AuthenticatedRequestContext {
            user_id: "user-a".to_string(),
            workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-a").unwrap(),
        },
        credential_policy_id: "test".to_string(),
        public_key_pem: None,
        stable_key: None,
    };
    let authorization =
        operation.authorization("bucket-a", UsageRoute::GetObject, RequestKind::Read, 1024);
    let grant = test_grant(&authorization);
    let response = metered_read_response(
        control.clone(),
        &auth,
        &grant,
        "key-a",
        None,
        axum::response::Response::new(Body::from("range")),
        None,
    )
    .await;
    assert_eq!(
        *control.calls.lock().unwrap(),
        vec![UsageCall {
            context: auth.context.clone(),
            event: UsageEvent::from_grant(&grant, 5, 5),
        }]
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), b"range");
}

#[tokio::test]
async fn metered_read_failure_replaces_the_stream_with_a_generic_s3_error() {
    let control = Arc::new(RecordingControlPlane {
        failure: Some(MeteringError::Unavailable),
        ..RecordingControlPlane::default()
    });
    let auth = Auth {
        context: AuthenticatedRequestContext {
            user_id: "user-a".to_string(),
            workspace_id: crate::workspace_storage::WorkspaceId::new("workspace-a").unwrap(),
        },
        credential_policy_id: "test".to_string(),
        public_key_pem: None,
        stable_key: None,
    };
    let operation = OperationIdentity {
        receipt_id: Uuid::now_v7(),
        operation_id: Uuid::now_v7(),
    };
    let authorization =
        operation.authorization("bucket-a", UsageRoute::GetObject, RequestKind::Read, 1024);
    let grant = test_grant(&authorization);
    let response = metered_read_response(
        control,
        &auth,
        &grant,
        "key-a",
        None,
        axum::response::Response::new(Body::from("range")),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("<Code>ServiceUnavailable</Code>"));
    assert!(!body.contains("database"));
}

#[tokio::test]
async fn definitive_provider_failure_has_stable_opaque_s3_response() {
    let response = streaming_put_error_response(
        "key",
        StreamingPutError::Transaction(TransactionError::Backend(
            crate::transaction::BackendError::definitive("PRINTABLE_PROVIDER_AUTHORIZATION_DETAIL"),
        )),
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("<Code>ServiceUnavailable</Code>"));
    assert!(!body.contains("PRINTABLE_PROVIDER_AUTHORIZATION_DETAIL"));
}

#[test]
fn transformed_source_binding_requires_a_version_or_matching_strong_etag() {
    let versioned = metadata(Some("v1"), None, "text/plain");
    assert!(transformed_source_matches_preflight(
        &versioned,
        &metadata(Some("v1"), None, "text/plain")
    ));
    assert!(!transformed_source_matches_preflight(
        &versioned,
        &metadata(Some("v2"), None, "text/plain")
    ));
    let suspended = metadata(Some("null"), None, "text/plain");
    assert!(
        !transformed_source_matches_preflight(
            &suspended,
            &metadata(Some("null"), None, "text/plain")
        ),
        "S3 versioning-suspended null versions are mutable and need a matching ETag"
    );

    let unversioned = metadata(None, Some("\"source-a\""), "text/plain");
    assert!(transformed_source_matches_preflight(
        &unversioned,
        &metadata(None, Some("\"source-a\""), "text/plain")
    ));
    assert!(!transformed_source_matches_preflight(
        &unversioned,
        &metadata(None, Some("\"source-b\""), "text/plain")
    ));
    assert!(!transformed_source_matches_preflight(
        &unversioned,
        &metadata(None, Some("W/\"source-a\""), "text/plain")
    ));
    assert!(!transformed_source_matches_preflight(
        &metadata(None, None, "text/plain"),
        &metadata(None, None, "text/plain")
    ));
}

#[test]
fn transformed_preflight_rejects_source_header_changes_without_polling_source() {
    let polls = Arc::new(AtomicUsize::new(0));
    let object = OpenedObject::new(
        StatusCode::OK,
        metadata(None, Some("\"source-a\""), "application/octet-stream"),
        Body::new(PollTrackingBody {
            polls: Arc::clone(&polls),
            data: Some(Bytes::from_static(b"must not be read")),
        }),
        BodyLimits::default(),
    );
    let params = S3Query::default();
    assert!(transformed_read_preflight(&HeaderMap::new(), &params, &object.metadata).is_err());
    assert_eq!(polls.load(Ordering::SeqCst), 0);

    let before = metadata(None, Some("\"source-a\""), "text/plain");
    let after = metadata(None, Some("\"source-a\""), "application/json");
    assert!(transformed_read_preflight(&HeaderMap::new(), &params, &before).is_ok());
    assert!(transformed_read_preflight(&HeaderMap::new(), &params, &after).is_ok());
    assert_ne!(
        transformed_read_preflight(&HeaderMap::new(), &params, &before).unwrap(),
        transformed_read_preflight(&HeaderMap::new(), &params, &after).unwrap(),
        "the GET representation cannot change source format after HEAD"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn successful_drop_all_direct_read_keeps_measured_finish_evidence() {
    let component = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-components/test-transformer.component.wasm"),
    )
    .expect("test-transformer.component.wasm; run just build-plugins");
    let registry = Arc::new(PluginRegistry::new());
    registry
        .import_with_capabilities(
            "dropper",
            &component,
            PluginCapabilities {
                prefix_safe_for_read: true,
            },
        )
        .unwrap();
    let resolver = crate::pipeline::StaticPipelineResolver::new(registry.clone());
    let resolution = crate::pipeline::PipelineResolver::resolve(
        &resolver,
        "workspace-a",
        "bucket-a",
        crate::pipeline::PipelineDirection::Read,
    )
    .await
    .unwrap();
    let snapshot = registry
        .snapshot_for(&resolution, registry.as_ref())
        .await
        .unwrap();
    let mut pipeline = snapshot
        .clone()
        .start_streaming_session(
            maskura_wasm_runtime::Session {
                format: "text".to_string(),
                content_type: "text/plain".to_string(),
                policy_version: 0,
                operation: maskura_wasm_runtime::Operation::Read,
                config_json: None,
                public_key_pem: None,
                stable_key: None,
                stable_fields: None,
            },
            maskura_wasm_runtime::CancellationToken::new(),
        )
        .await
        .unwrap();

    assert!(
        pipeline
            .process(crate::record::Record::new("drop", "\n"))
            .await
            .unwrap()
            .is_none()
    );
    let (_, fuel_consumed) = pipeline.finish().await.unwrap();
    let evidence = snapshot
        .pipeline_evidence(fuel_consumed, 5, "none")
        .unwrap();
    assert_eq!(evidence.fuel_consumed, fuel_consumed);
    assert!(evidence.fuel_consumed > 0);
    assert_eq!(evidence.duration_ms, 5);
    assert_eq!(evidence.spool_mode, "none");
}

#[tokio::test(flavor = "current_thread")]
async fn transformed_record_pipeline_has_fixed_rss_for_a_gibibyte_source() {
    const GIB: u64 = 1024 * 1024 * 1024;
    const FRAME_BYTES: usize = 64 * 1024;
    // Unit tests run in parallel with Wasmtime initialization elsewhere in
    // this process. This still catches whole-object buffering while leaving
    // room for unrelated allocator arena growth.
    const MAX_RSS_GROWTH: u64 = 256 * 1024 * 1024;

    let before = peak_rss_bytes();
    let registry = PluginRegistry::new();
    let pipeline = registry
        .snapshot()
        .start_streaming_session(
            maskura_wasm_runtime::Session {
                format: "text".to_string(),
                content_type: "text/plain".to_string(),
                policy_version: 0,
                operation: maskura_wasm_runtime::Operation::Write,
                config_json: None,
                public_key_pem: None,
                stable_key: None,
                stable_fields: None,
            },
            maskura_wasm_runtime::CancellationToken::new(),
        )
        .await
        .unwrap();
    let object = OpenedObject::new(
        StatusCode::OK,
        metadata(None, Some("\"source-a\""), "text/plain"),
        Body::new(GeneratedLineBody {
            remaining: GIB,
            frame_bytes: FRAME_BYTES,
        }),
        BodyLimits {
            max_frame_bytes: FRAME_BYTES,
            max_bytes: GIB,
        },
    );
    let output_bytes = Arc::new(AtomicU64::new(0));
    process_transformed_source(object, pipeline, Format::Text, FRAME_BYTES, {
        let output_bytes = Arc::clone(&output_bytes);
        move |bytes| {
            let output_bytes = Arc::clone(&output_bytes);
            async move {
                output_bytes.fetch_add(bytes.len() as u64, Ordering::SeqCst);
                Ok(())
            }
        }
    })
    .await
    .unwrap();
    let after = peak_rss_bytes();

    assert_eq!(output_bytes.load(Ordering::SeqCst), GIB);
    assert!(
        after.saturating_sub(before) <= MAX_RSS_GROWTH,
        "transformed 1 GiB stream grew peak RSS by {} MiB (limit {} MiB)",
        after.saturating_sub(before) / (1024 * 1024),
        MAX_RSS_GROWTH / (1024 * 1024),
    );
}
