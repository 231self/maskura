use super::*;

#[test]
fn postgres_multipart_completion_cas_replay_and_fencing_are_durable() {
    with_pool(|pool| async move {
        let db = sea_db(pool.clone());
        let repository = PostgresMultipartRepository::new(pool);
        let upload_id = format!("completion-{}", uuid::Uuid::new_v4());
        let now = unix_time_ms();
        let identity = MultipartIdentity {
            tenant_id: "multipart-integration".to_string(),
            credential_policy_id: "key".to_string(),
            bucket: "bucket".to_string(),
            key: format!("object-{}", uuid::Uuid::new_v4()),
            upload_id: upload_id.clone(),
        };
        repository
            .create(MultipartUpload {
                identity: identity.clone(),
                namespace_epoch: None,
                snapshot: MultipartSnapshot {
                    metadata: Default::default(),
                    tags: Default::default(),
                    checksum_mode: None,
                    destination: serde_json::json!({"kind":"test"}),
                    plugin_snapshot: serde_json::json!([]),
                    max_staged_bytes: 1024,
                },
                lifecycle: MultipartLifecycle::Open,
                staged_bytes: 0,
                reserved_bytes: 0,
                created_at_ms: now,
                expires_at_ms: now + 60_000,
                updated_at_ms: now,
                tombstone_until_ms: None,
                complete_request_fingerprint: None,
                completion_lease_owner: None,
                completion_lease_expires_at_ms: None,
                completion_fencing_token: 0,
                destination_operation_id: None,
                publishing_started_at_ms: None,
                destination_commit: None,
                completion_result: None,
            })
            .await
            .expect("create multipart upload");
        repository
            .replace_part(
                &identity,
                MultipartPart {
                    upload_id: upload_id.clone(),
                    part_number: 1,
                    attempt: 1,
                    artifact_key: format!("artifact-{}", uuid::Uuid::new_v4()),
                    etag: "\"part\"".to_string(),
                    checksum_sha256: "part-sha".to_string(),
                    size_bytes: 3,
                    created_at_ms: now,
                },
            )
            .await
            .expect("persist part");
        let selected = [CompletePart {
            part_number: 1,
            etag: "\"part\"".to_string(),
            checksum_sha256: Some("part-sha".to_string()),
        }];
        let first = match repository
            .acquire_completion(&identity, "request", &selected, "worker-a", now + 10, now)
            .await
            .expect("acquire first lease")
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("expected acquired completion lease"),
        };
        let second = match repository
            .acquire_completion(
                &identity,
                "request",
                &selected,
                "worker-b",
                now + 30,
                now + 11,
            )
            .await
            .expect("take over expired lease")
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("expected takeover completion lease"),
        };
        assert!(second.fencing_token > first.fencing_token);
        assert!(
            repository
                .check_completion_lease(&identity, first.fencing_token, now + 12)
                .await
                .is_err()
        );
        let operation_id =
            DestinationCommitPermit::deterministic_operation_id(&identity, "request");
        let permit = repository
            .begin_destination_commit(
                &identity,
                "request",
                second.fencing_token,
                operation_id,
                now + 12,
            )
            .await
            .expect("begin destination commit");
        assert!(matches!(
            repository
                .acquire_completion(
                    &identity,
                    "request",
                    &selected,
                    "worker-c",
                    now + 100,
                    now + 50,
                )
                .await,
            Ok(CompletionAcquire::Busy)
        ));
        let mut stale = permit.clone();
        stale.fencing_token += 1;
        assert!(
            repository
                .validate_destination_commit_permit(&stale)
                .await
                .is_err()
        );
        assert!(
            repository
                .publishing_uploads(100)
                .await
                .unwrap()
                .iter()
                .any(|upload| upload.permit == permit)
        );
        repository
            .release_destination_commit_after_proven_absence(&permit, now + 51)
            .await
            .expect("release publication after proven absence");
        let third = match repository
            .acquire_completion(
                &identity,
                "request",
                &selected,
                "worker-c",
                now + 100,
                now + 52,
            )
            .await
            .expect("take over released publication")
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("expected completion takeover"),
        };
        let permit = repository
            .begin_destination_commit(
                &identity,
                "request",
                third.fencing_token,
                operation_id,
                now + 53,
            )
            .await
            .expect("begin replacement destination commit");
        let result = MultipartCompletionResult {
            etag: Some("\"result\"".to_string()),
            checksum_sha256: "result-sha".to_string(),
            version_id: Some("version".to_string()),
            source_bytes: 24,
            size_bytes: 42,
            pipeline_evidence: None,
        };
        repository
            .record_destination_commit(&permit, result.clone(), now + 54)
            .await
            .expect("record exact destination commit");
        repository
            .record_destination_commit(&permit, result.clone(), now + 55)
            .await
            .expect("replay exact destination commit");
        repository
            .complete_completion(&identity, &permit, result, now + 56)
            .await
            .expect("persist immutable result");
        assert!(matches!(
            repository
                .acquire_completion(&identity, "request", &selected, "retry", now + 80, now + 57)
                .await,
            Ok(CompletionAcquire::Replayed(_))
        ));
        assert!(
            repository
                .acquire_completion(
                    &identity,
                    "conflict",
                    &selected,
                    "retry",
                    now + 80,
                    now + 57
                )
                .await
                .is_err()
        );
        multipart_upload::Entity::delete_many()
            .filter(multipart_upload::Column::UploadId.eq(upload_id))
            .exec(&db)
            .await
            .expect("delete multipart completion test rows");
    });
}

/// Drives the full S3 multipart HTTP surface through `build_router` against a
/// durable Postgres repository and a mock S3 service used for both encrypted
/// staging and the direct destination. Runs only when `DATABASE_URL` is set.
#[test]
fn router_staged_multipart_flow_is_durable_and_idempotent() {
    with_pool(|pool| async move {
        let staging_dir = std::env::temp_dir().join(format!(
            "maskura-multipart-staging-{}",
            uuid::Uuid::new_v4()
        ));
        tokio::fs::create_dir_all(&staging_dir).await.unwrap();

        let mock_state = MockS3State::default();
        let objects = mock_state.objects.clone();
        let mock_app = axum::Router::new()
            .fallback(mock_s3_handler)
            .with_state(mock_state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let mock_task = tokio::spawn(async move {
            let _ = axum::serve(listener, mock_app).await;
        });

        // SAFETY: test-only process-global env mutation. Every test in this
        // binary is serialized on `DB_TEST_LOCK`, so no other test observes
        // these values concurrently.
        unsafe {
            std::env::set_var("AUTH_DISABLED", "0");
            std::env::set_var("MASKURA_SINGLE_TENANT", "1");
            std::env::remove_var("MASKURA_KEYS_FILE");
            std::env::set_var("S3_ENDPOINT", &endpoint);
            std::env::set_var("S3_ACCESS_KEY_ID", "destination-access");
            std::env::set_var("S3_SECRET_ACCESS_KEY", "destination-secret");
            std::env::remove_var("MASKURA_SERVICE_BUCKETS");
            std::env::remove_var("MASKURA_SECRET_KEK");
            std::env::set_var("MASKURA_STREAMING_S3_PROVIDER", "minio");
            std::env::remove_var("MASKURA_PLUGINS_DIR");
            std::env::remove_var("MASKURA_DEFAULT_PLUGIN");
            std::env::remove_var("MASKURA_MANAGED_STREAMING_MODE");
            std::env::remove_var("MASKURA_MANAGED_STREAMING_TRANSACTIONAL");
            std::env::set_var("MASKURA_STREAMING_READ_MODE", "passthrough");
            std::env::set_var("MASKURA_DEV_MEMORY_STREAMING", "1");
            std::env::set_var("MASKURA_MULTIPART_MODE", "staged");
            std::env::set_var(
                "MASKURA_MULTIPART_STAGING_DIR",
                staging_dir.to_str().unwrap(),
            );
            std::env::set_var("MASKURA_MULTIPART_STAGING_ENDPOINT", &endpoint);
            std::env::set_var("MASKURA_MULTIPART_STAGING_BUCKET", MOCK_STAGING_BUCKET);
            std::env::set_var("MASKURA_MULTIPART_STAGING_ACCESS_KEY_ID", "test-access");
            std::env::set_var("MASKURA_MULTIPART_STAGING_SECRET_ACCESS_KEY", "test-secret");
            std::env::set_var("MASKURA_MULTIPART_STAGING_REGION", "us-east-1");
            std::env::set_var("MASKURA_MULTIPART_STAGING_TENANT_QUOTA_BYTES", "67108864");
            std::env::set_var("MASKURA_MULTIPART_STAGING_GLOBAL_QUOTA_BYTES", "268435456");
        }

        let control = Arc::new(MultipartBillingControl::default());
        let config = Config::resolve(None).expect("resolve multipart test config");
        let state = build_state(
            control.clone(),
            Arc::new(LocalKeyWrapping::with_kek(TEST_KEK)),
            Arc::new(maskura_gateway::workspace_storage::InMemoryWorkspaceStorageRepository::new()),
            &config,
        )
        .await
        .expect("build_state with durable staged multipart");
        let (sk, created) = state
            .keys
            .create_key(
                "test-user",
                &WorkspaceId::new("test-user").unwrap(),
                "multipart-test",
                0,
                None,
            )
            .await
            .expect("create test API key");
        let ak = created.key_id;
        let app = build_router(state.clone());
        let hdrs = auth_headers(&ak, &sk);

        let bucket = format!("mp-bkt-{}", uuid::Uuid::new_v4());
        let key = format!("object-{}.txt", uuid::Uuid::new_v4());

        // CreateMultipartUpload.
        let create = add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/{bucket}/{key}?uploads"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(create).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "CreateMultipartUpload");
        let create_xml = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let upload_id = extract_xml(&create_xml, "UploadId");
        assert!(!upload_id.is_empty());

        // Use one small final part so this test focuses on durable restart,
        // fencing, replay, and publication rather than the separate
        // non-final-part size rule covered by multipart conformance tests.
        let part1_body: &[u8] = b"first line: alice@example.com\n";
        let etag1 = upload_part(&app, &hdrs, &bucket, &key, &upload_id, 1, part1_body).await;

        // ListParts.
        let list = add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/{bucket}/{key}?uploadId={upload_id}"))
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(list).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "ListParts");
        let list_xml = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            list_xml.contains("<PartNumber>1</PartNumber>"),
            "{list_xml}"
        );

        // Rebuild a fully independent gateway process against the same
        // Postgres and staging backend. Completion must use the persisted
        // immutable resolution rather than process-local plugin identities.
        let restarted_state = build_state(
            control.clone(),
            Arc::new(LocalKeyWrapping::with_kek(TEST_KEK)),
            Arc::new(maskura_gateway::workspace_storage::InMemoryWorkspaceStorageRepository::new()),
            &config,
        )
        .await
        .expect("restart gateway with durable staged multipart");
        let restarted_app = build_router(restarted_state);

        // CompleteMultipartUpload with the strict sorted XML document.
        let complete_xml = format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part></CompleteMultipartUpload>"
        );
        let complete = add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/{bucket}/{key}?uploadId={upload_id}"))
                .body(Body::from(complete_xml.clone()))
                .unwrap(),
            &hdrs,
        );
        mock_state
            .block_destination_put
            .store(true, Ordering::Release);
        let destination_puts_before = mock_state.destination_put_count.load(Ordering::Acquire);
        let first_completion = tokio::spawn(restarted_app.clone().oneshot(complete));
        tokio::time::timeout(
            Duration::from_secs(120),
            mock_state.wait_for_destination_put_after(destination_puts_before),
        )
        .await
        .expect("first completion reached the direct destination");
        let busy = add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/{bucket}/{key}?uploadId={upload_id}"))
                .body(Body::from(complete_xml.clone()))
                .unwrap(),
            &hdrs,
        );
        let busy_response = restarted_app.clone().oneshot(busy).await.unwrap();
        assert_eq!(
            busy_response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "concurrent exact completion must observe Busy"
        );
        assert!(
            control.releases.lock().unwrap().is_empty(),
            "Busy must not release the active worker's reservation"
        );
        mock_state
            .block_destination_put
            .store(false, Ordering::Release);
        mock_state.release_destination_put.notify_waiters();
        let resp = first_completion.await.unwrap().unwrap();
        let status = resp.status();
        let complete_body = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "CompleteMultipartUpload: {complete_body}"
        );
        let final_etag = extract_xml(&complete_body, "ETag");
        assert!(!final_etag.is_empty());

        // GET the assembled object: PII redacted and parts in part-number order.
        let get = add_headers(
            Request::builder()
                .method("GET")
                .uri(format!("/{bucket}/{key}"))
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(get).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "GET assembled object");
        let text = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("[REDACTED_EMAIL]"), "email redacted: {text}");
        assert!(
            !text.contains("alice@example.com"),
            "raw email leaked: {text}"
        );
        assert!(text.contains("first line:"), "first line present: {text}");

        // Re-POSTing the same complete XML replays the stored result.
        let replay = add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/{bucket}/{key}?uploadId={upload_id}"))
                .body(Body::from(complete_xml))
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(replay).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "idempotent completion replay"
        );
        let replay_body = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(extract_xml(&replay_body, "ETag"), final_etag);

        // A conflicting part set is rejected.
        let conflicting = "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"conflicting\"</ETag></Part></CompleteMultipartUpload>";
        let conflict_req = add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/{bucket}/{key}?uploadId={upload_id}"))
                .body(Body::from(conflicting))
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(conflict_req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "conflicting completion"
        );
        let completion_authorizations: Vec<_> = control
            .authorizations
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, authorization)| {
                authorization.route() == UsageRoute::CompleteMultipartUpload
            })
            .cloned()
            .collect();
        let completion_events: Vec<_> = control
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, event)| event.route() == UsageRoute::CompleteMultipartUpload)
            .cloned()
            .collect();
        assert_eq!(completion_authorizations.len(), 4);
        assert_eq!(completion_events.len(), 2);
        assert_eq!(completion_authorizations[0], completion_authorizations[1]);
        assert_eq!(completion_authorizations[0], completion_authorizations[2]);
        assert_eq!(completion_events[0], completion_events[1]);
        assert_eq!(
            completion_authorizations[0].1.operation_id(),
            completion_events[0].1.operation_id()
        );
        let journal_operation =
            object_operation::Entity::find_by_id(completion_authorizations[0].1.operation_id())
                .one(&sea_db(pool.clone()))
                .await
                .unwrap();
        assert!(
            journal_operation.is_none(),
            "terminal direct completion journal is retired after publication"
        );
        assert_ne!(
            completion_authorizations[0].1.operation_id(),
            completion_authorizations[3].1.operation_id()
        );
        assert_eq!(
            control.releases.lock().unwrap().as_slice(),
            &[(
                completion_authorizations[3].0.clone(),
                completion_authorizations[3].1.operation_id()
            )]
        );

        state_assertions_for_unknown_head_and_ambiguous_delete(
            &app,
            &hdrs,
            &bucket,
            &key,
            &mock_state,
            &control,
        )
        .await;

        // Abort is idempotent and removes the staged artifacts.
        let abort_key = format!("abort-{}.txt", uuid::Uuid::new_v4());
        let create = add_headers(
            Request::builder()
                .method("POST")
                .uri(format!("/{bucket}/{abort_key}?uploads"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        );
        let resp = app.clone().oneshot(create).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "abort CreateMultipartUpload");
        let create_xml = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let abort_upload_id = extract_xml(&create_xml, "UploadId");
        upload_part(
            &app,
            &hdrs,
            &bucket,
            &abort_key,
            &abort_upload_id,
            1,
            b"abort me: bob@example.com\n",
        )
        .await;
        assert!(
            !objects.lock().await.is_empty(),
            "staged artifact exists before abort"
        );

        let releases_before_abort = control.releases.lock().unwrap().len();
        PostgresMultipartRepository::fail_next_abort_after_update();
        let ambiguous_abort = add_headers(
            Request::builder()
                .method("DELETE")
                .uri(format!("/{bucket}/{abort_key}?uploadId={abort_upload_id}"))
                .body(Body::empty())
                .unwrap(),
            &hdrs,
        );
        let response = app.clone().oneshot(ambiguous_abort).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let abort_authorization = control
            .authorizations
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .1
            .clone();
        assert_eq!(
            abort_authorization.route(),
            UsageRoute::AbortMultipartUpload
        );
        assert_eq!(
            control.releases.lock().unwrap().len(),
            releases_before_abort,
            "post-mutation abort failure must preserve its reservation"
        );
        assert!(
            control
                .releases
                .lock()
                .unwrap()
                .iter()
                .all(|(_, operation_id)| *operation_id != abort_authorization.operation_id())
        );

        for _ in 0..2 {
            let abort = add_headers(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/{bucket}/{abort_key}?uploadId={abort_upload_id}"))
                    .body(Body::empty())
                    .unwrap(),
                &hdrs,
            );
            let resp = app.clone().oneshot(abort).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NO_CONTENT,
                "AbortMultipartUpload"
            );
        }
        assert!(
            objects
                .lock()
                .await
                .keys()
                .any(|key| !key.starts_with(ARTIFACT_PREFIX)),
            "completed destination remains visible after abort reconciliation"
        );

        mock_task.abort();
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
    });
}
