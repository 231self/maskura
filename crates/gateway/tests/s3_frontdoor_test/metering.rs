use super::*;

#[tokio::test]
async fn launch_contract_billable_handlers_generate_distinct_server_usage_event_identities() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let control = Arc::new(RecordingMeteringControl::default());
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.control = control.clone();
    state_mut.source_body_limits.max_bytes = 64 * 1024 * 1024;
    state_mut.max_pipeline_output_bytes = 64 * 1024 * 1024;
    let app = build_router(state);
    let headers = auth_headers(&access_key, &secret_key);

    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("PUT")
                .uri("/metered/object.txt")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("payload"))
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/metered/object.txt")
                .body(Body::empty())
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
        "payload"
    );

    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("HEAD")
                .uri("/metered/object.txt")
                .body(Body::empty())
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("HEAD")
                .uri("/metered/object.txt")
                .body(Body::empty())
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(add_headers(
            Request::builder()
                .method("DELETE")
                .uri("/metered/object.txt")
                .body(Body::empty())
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let events = control.events.lock().unwrap().clone();
    assert_eq!(events.len(), 5);
    assert!(events.iter().all(|call| {
        call.context.user_id == "test-user"
            && call.context.workspace_id.as_str() == "test-user"
            && call.event.bucket() == "metered"
            && call.event.occurred_at() == test_occurred_at()
            && call.event.rate_version() == TEST_RATE_VERSION
    }));
    assert_eq!(
        events
            .iter()
            .map(|call| {
                (
                    call.event.kind(),
                    call.event.route(),
                    call.event.source_bytes(),
                    call.event.output_bytes(),
                    call.event.processed_bytes(),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (RequestKind::Write, UsageRoute::PutObject, 7, 7, 7),
            (RequestKind::Read, UsageRoute::GetObject, 7, 7, 7),
            (RequestKind::Read, UsageRoute::HeadObject, 0, 0, 0),
            (RequestKind::Read, UsageRoute::HeadObject, 0, 0, 0),
            (RequestKind::Write, UsageRoute::DeleteObject, 0, 0, 0,),
        ]
    );
    assert!(events.iter().all(|call| {
        call.event.receipt_id().get_version_num() == 7
            && call.event.operation_id() != call.event.receipt_id()
            && call.event.operation_id().get_version_num() == 5
    }));
    assert_eq!(
        events
            .iter()
            .map(|call| call.event.receipt_id())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        events.len()
    );
    assert_ne!(events[2].event.receipt_id(), events[3].event.receipt_id());
    let write_pipeline = events[0]
        .event
        .pipeline_evidence()
        .expect("PUT records the resolved pipeline");
    assert_eq!(write_pipeline.revision, "static");
    assert!(!write_pipeline.fingerprint.is_empty());
    let component_parts = write_pipeline.components.split(':').collect::<Vec<_>>();
    assert_eq!(component_parts.len(), 3);
    assert_eq!(component_parts[0], "v1");
    assert!(component_parts[1].parse::<usize>().is_ok());
    assert_eq!(component_parts[2].len(), 64);
    assert!(
        events[1..]
            .iter()
            .all(|call| call.event.pipeline_evidence().is_none())
    );
    let authorizations = control.authorizations.lock().unwrap().clone();
    assert_eq!(authorizations.len(), events.len());
    for ((context, authorization), event) in authorizations.iter().zip(&events) {
        assert_eq!(context, &event.context);
        assert_eq!(authorization.operation_id(), event.event.operation_id());
        assert_eq!(authorization.receipt_id(), event.event.receipt_id());
        assert_eq!(authorization.bucket(), event.event.bucket());
        assert_eq!(authorization.kind(), event.event.kind());
        assert_eq!(authorization.route(), event.event.route());
    }
    assert_eq!(authorizations[0].1.pipeline_revision(), Some("static"));
    assert_eq!(
        authorizations[0].1.pipeline_fingerprint(),
        Some(write_pipeline.fingerprint.as_str())
    );
    assert!(
        authorizations[1..]
            .iter()
            .all(|(_, authorization)| authorization.pipeline_revision().is_none())
    );
    assert_eq!(
        authorizations
            .iter()
            .map(|(_, authorization)| authorization.max_processed_bytes())
            .collect::<Vec<_>>(),
        vec![64 * 1024 * 1024, 64 * 1024 * 1024, 0, 0, 0]
    );
    assert!(control.releases.lock().unwrap().is_empty());
}

#[tokio::test]
async fn metering_unavailable_after_put_returns_service_unavailable_without_rolling_back_data() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let control = Arc::new(RecordingMeteringControl {
        failure: Some(MeteringError::Unavailable),
        ..RecordingMeteringControl::default()
    });
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .control = control.clone();
    let app = build_router(state.clone());
    let headers = auth_headers(&access_key, &secret_key);

    let response = app
        .oneshot(add_headers(
            Request::builder()
                .method("PUT")
                .uri("/metered/persisted.txt")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("persisted"))
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Code>ServiceUnavailable</Code>"));
    assert_eq!(
        state
            .store
            .get("metered", "persisted.txt")
            .expect("backend mutation remains committed")
            .data,
        Bytes::from_static(b"persisted")
    );
    assert_eq!(control.events.lock().unwrap().len(), 1);
    assert!(
        control.releases.lock().unwrap().is_empty(),
        "a committed operation must not release its reservation when metering fails"
    );
}

#[tokio::test]
async fn launch_contract_supplied_metering_id_is_rejected_generically_before_mutation() {
    let (app, state) = router().await;
    let (access_key, secret_key) = make_key(&state).await;
    for (index, reserved_header) in [
        "x-maskura-metering-id",
        "x-maskura-operation-id",
        "x-maskura-usage-id",
        "x-maskura-metering-id",
        "x-maskura-operation-id",
        "x-maskura-usage-id",
    ]
    .into_iter()
    .enumerate()
    {
        let polls = Arc::new(AtomicUsize::new(0));
        let key = format!("rejected-{index}.txt");
        let request = add_headers(
            Request::builder()
                .method("PUT")
                .uri(format!("/metered/{key}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .header(reserved_header, "018f0f6e-7b31-7c1d-8f2f-84f808b9c175")
                .body(Body::new(PollTrackingBody {
                    polls: polls.clone(),
                    data: Some(Bytes::from_static(b"must not commit")),
                }))
                .unwrap(),
            &auth_headers(&access_key, &secret_key),
        );

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("<Code>InvalidRequest</Code>"));
        assert!(!body.contains("metering"));
        assert!(state.store.get("metered", &key).is_none());
    }
}

#[tokio::test]
async fn launch_contract_authorization_unavailable_returns_service_unavailable_before_mutation() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let control = Arc::new(RecordingMeteringControl {
        authorization_failure: Some(AuthorizationError::Unavailable),
        ..RecordingMeteringControl::default()
    });
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .control = control.clone();
    let app = build_router(state.clone());
    let polls = Arc::new(AtomicUsize::new(0));
    let request = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/authorization/unavailable.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::new(PollTrackingBody {
                polls: polls.clone(),
                data: Some(Bytes::from_static(b"must not commit")),
            }))
            .unwrap(),
        &auth_headers(&access_key, &secret_key),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Code>ServiceUnavailable</Code>"));
    assert!(control.events.lock().unwrap().is_empty());
    assert!(
        state
            .store
            .get("authorization", "unavailable.txt")
            .is_none()
    );
}

#[tokio::test]
async fn launch_contract_blocked_authorization_does_not_poll_or_release() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let control = Arc::new(RecordingMeteringControl {
        block_reason: Some(BlockReason::new("PaymentRequired", "out of credit")),
        ..RecordingMeteringControl::default()
    });
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .control = control.clone();
    let app = build_router(state.clone());
    let polls = Arc::new(AtomicUsize::new(0));
    let request = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/authorization/blocked.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::new(PollTrackingBody {
                polls: polls.clone(),
                data: Some(Bytes::from_static(b"must not commit")),
            }))
            .unwrap(),
        &auth_headers(&access_key, &secret_key),
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Code>PaymentRequired</Code>"));
    assert!(state.store.get("authorization", "blocked.txt").is_none());
    assert_eq!(control.authorizations.lock().unwrap().len(), 1);
    assert!(control.events.lock().unwrap().is_empty());
    assert!(control.releases.lock().unwrap().is_empty());
}

#[tokio::test]
async fn launch_contract_mismatched_grant_fails_closed_without_polling_body() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let control = Arc::new(StaleGrantControl::default());
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .control = control;
    let app = build_router(state.clone());
    let headers = auth_headers(&access_key, &secret_key);

    let seed = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/authorization/missing.txt")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.clone().oneshot(seed).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );

    let polls = Arc::new(AtomicUsize::new(0));
    let request = add_headers(
        Request::builder()
            .method("PUT")
            .uri("/authorization/mismatched.txt")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::new(PollTrackingBody {
                polls: polls.clone(),
                data: Some(Bytes::from_static(b"must not commit")),
            }))
            .unwrap(),
        &headers,
    );

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Code>ServiceUnavailable</Code>"));
    assert!(state.store.get("authorization", "mismatched.txt").is_none());
}

#[tokio::test]
async fn launch_contract_successful_list_records_receipt_and_failed_list_is_not_billed() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    state.store.put(
        "listed",
        "object.txt",
        Bytes::from_static(b"payload"),
        "text/plain",
    );
    let control = Arc::new(RecordingMeteringControl::default());
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .control = control.clone();
    let app = build_router(state);
    let headers = auth_headers(&access_key, &secret_key);

    let response = app
        .clone()
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/listed?list-type=2")
                .body(Body::empty())
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let events = control.events.lock().unwrap().clone();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].context.user_id, "test-user");
    assert_eq!(events[0].context.workspace_id.as_str(), "test-user");
    assert_eq!(events[0].event.bucket(), "listed");
    assert_eq!(events[0].event.kind(), RequestKind::Read);
    assert_eq!(events[0].event.route(), UsageRoute::ListObjects);
    assert_eq!(events[0].event.source_bytes(), 0);
    assert_eq!(events[0].event.output_bytes(), 0);
    assert_eq!(events[0].event.processed_bytes(), 0);
    assert_eq!(events[0].event.receipt_id().get_version_num(), 7);
    assert_eq!(events[0].event.operation_id().get_version_num(), 5);
    assert_eq!(events[0].event.occurred_at(), test_occurred_at());
    assert_eq!(events[0].event.rate_version(), TEST_RATE_VERSION);

    let response = app
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/listed?list-type=2&continuation-token=not-a-token")
                .body(Body::empty())
                .unwrap(),
            &headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(control.events.lock().unwrap().len(), 1);
    let authorizations = control.authorizations.lock().unwrap();
    let releases = control.releases.lock().unwrap();
    assert_eq!(authorizations.len(), 2);
    assert_eq!(releases.len(), 1);
    assert_eq!(releases[0].0, authorizations[1].0);
    assert_eq!(releases[0].1, authorizations[1].1.operation_id());
}

#[tokio::test]
async fn invalid_range_failed_head_and_failed_delete_release_exact_reservations() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    state.store.put(
        "failed",
        "object.txt",
        Bytes::from_static(b"payload"),
        "text/plain",
    );
    let control = Arc::new(RecordingMeteringControl::default());
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .control = control.clone();
    let app = build_router(state);
    let headers = auth_headers(&access_key, &secret_key);

    let invalid_range = add_headers(
        Request::builder()
            .method("GET")
            .uri("/failed/object.txt")
            .header(header::RANGE, "not-a-range")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.clone().oneshot(invalid_range).await.unwrap().status(),
        StatusCode::RANGE_NOT_SATISFIABLE
    );

    let missing_head = add_headers(
        Request::builder()
            .method("HEAD")
            .uri("/failed/missing.txt")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.clone().oneshot(missing_head).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );

    let failed_delete = add_headers(
        Request::builder()
            .method("DELETE")
            .uri("/failed/object.txt")
            .header("x-maskura-storage-mode", "managed")
            .body(Body::empty())
            .unwrap(),
        &headers,
    );
    assert_eq!(
        app.oneshot(failed_delete).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    assert!(control.events.lock().unwrap().is_empty());
    let authorizations = control.authorizations.lock().unwrap();
    let releases = control.releases.lock().unwrap();
    assert_eq!(authorizations.len(), 3);
    assert_eq!(releases.len(), 3);
    assert_eq!(
        authorizations
            .iter()
            .map(|(_, authorization)| authorization.route())
            .collect::<Vec<_>>(),
        vec![
            UsageRoute::GetObject,
            UsageRoute::HeadObject,
            UsageRoute::DeleteObject
        ]
    );
    for ((context, authorization), (released_context, operation_id)) in
        authorizations.iter().zip(releases.iter())
    {
        assert_eq!(context, released_context);
        assert_eq!(authorization.operation_id(), *operation_id);
    }
}

#[tokio::test]
async fn launch_contract_list_metering_failure_replaces_success_with_service_unavailable() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    let control = Arc::new(RecordingMeteringControl {
        failure: Some(MeteringError::Unavailable),
        ..RecordingMeteringControl::default()
    });
    Arc::get_mut(&mut state)
        .expect("test state is uniquely owned")
        .control = control.clone();
    let app = build_router(state);

    let response = app
        .oneshot(add_headers(
            Request::builder()
                .method("GET")
                .uri("/listed?list-type=2")
                .body(Body::empty())
                .unwrap(),
            &auth_headers(&access_key, &secret_key),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("<Code>ServiceUnavailable</Code>"));
    let events = control.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event.route(), UsageRoute::ListObjects);
    assert_eq!(events[0].event.source_bytes(), 0);
    assert_eq!(events[0].event.output_bytes(), 0);
    assert!(control.releases.lock().unwrap().is_empty());
}

#[tokio::test]
async fn oversized_get_and_head_release_before_metering() {
    let mut state = test_state().await;
    let (access_key, secret_key) = make_key(&state).await;
    state.store.put(
        "limited",
        "oversized.txt",
        Bytes::from_static(b"12345"),
        "text/plain",
    );
    let control = Arc::new(RecordingMeteringControl::default());
    let state_mut = Arc::get_mut(&mut state).expect("test state is uniquely owned");
    state_mut.source_body_limits.max_bytes = 4;
    state_mut.max_pipeline_output_bytes = 4;
    state_mut.control = control.clone();
    let app = build_router(state);
    let headers = auth_headers(&access_key, &secret_key);

    for method in ["GET", "HEAD"] {
        let response = app
            .clone()
            .oneshot(add_headers(
                Request::builder()
                    .method(method)
                    .uri("/limited/oversized.txt")
                    .body(Body::empty())
                    .unwrap(),
                &headers,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        if method == "GET" {
            assert!(String::from_utf8_lossy(&body).contains("<Code>EntityTooLarge</Code>"));
        }
    }

    assert!(control.events.lock().unwrap().is_empty());
    let authorizations = control.authorizations.lock().unwrap();
    let releases = control.releases.lock().unwrap();
    assert_eq!(authorizations.len(), 2);
    assert_eq!(releases.len(), 2);
    for ((context, authorization), (released_context, operation_id)) in
        authorizations.iter().zip(releases.iter())
    {
        assert_eq!(context, released_context);
        assert_eq!(authorization.operation_id(), *operation_id);
    }
}
