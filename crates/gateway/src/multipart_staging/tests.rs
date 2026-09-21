use super::*;
use crate::key_cipher::LocalKeyWrapping;
use crate::local_storage::LocalStorageRuntime;

#[tokio::test]
async fn memory_artifact_store_matches_shared_contract() {
    let directory =
        std::env::temp_dir().join(format!("maskura-memory-artifacts-{}", Uuid::now_v7()));
    std::fs::create_dir(&directory).unwrap();
    assert_artifact_store_contract(&MemoryStagingArtifactStore::default(), &directory).await;
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn s3_artifact_get_adapts_to_provider_neutral_reader() {
    use aws_config::Region;
    use aws_credential_types::Credentials;
    use axum::Router;
    use axum::body::Body;

    let app = Router::new().fallback(|| async {
        axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(axum::http::header::CONTENT_LENGTH, "10")
            .body(Body::from("ciphertext"))
            .unwrap()
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(endpoint)
        .credentials_provider(Credentials::new("key", "secret", None, None, "test"))
        .retry_config(crate::s3_safety::s3_retry_config())
        .load()
        .await;
    let client = aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::config::Builder::from(&config)
            .force_path_style(true)
            .build(),
    );
    let store = S3StagingArtifactStore::new(client, "staging".to_string());

    let mut reader = store.get("multipart/artifact").await.unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"ciphertext");
    server.abort();
}

#[test]
fn legacy_completion_result_json_defaults_new_accounting_fields() {
    let result: MultipartCompletionResult = serde_json::from_value(serde_json::json!({
        "etag": "\"legacy\"",
        "checksum_sha256": "legacy-sha",
        "version_id": null
    }))
    .unwrap();

    assert_eq!(result.source_bytes, 0);
    assert_eq!(result.size_bytes, 0);
    assert!(result.pipeline_evidence.is_none());
}

fn identity() -> MultipartIdentity {
    MultipartIdentity {
        tenant_id: "tenant-a".to_string(),
        credential_policy_id: "key-a".to_string(),
        bucket: "bucket".to_string(),
        key: "key".to_string(),
        upload_id: "upload".to_string(),
    }
}
fn snapshot() -> MultipartSnapshot {
    MultipartSnapshot {
        metadata: BTreeMap::new(),
        tags: BTreeMap::new(),
        checksum_mode: None,
        destination: serde_json::json!({"backend":"test"}),
        plugin_snapshot: serde_json::json!([]),
        max_staged_bytes: 1024,
    }
}
fn upload() -> MultipartUpload {
    let now = now_ms();
    MultipartUpload {
        identity: identity(),
        namespace_epoch: None,
        snapshot: snapshot(),
        lifecycle: MultipartLifecycle::Open,
        staged_bytes: 0,
        reserved_bytes: 0,
        created_at_ms: now,
        expires_at_ms: now + 1000,
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
    }
}

#[tokio::test]
async fn ownership_replacement_pagination_and_expiry_are_fenced() {
    let repo = Arc::new(InMemoryMultipartRepository::new());
    repo.create(upload()).await.unwrap();
    let mut thief = identity();
    thief.tenant_id = "tenant-b".to_string();
    assert!(matches!(
        repo.get_authorized(&thief).await,
        Err(StagingError::NotFound)
    ));
    let mut revoked_policy = identity();
    revoked_policy.credential_policy_id = "key-rotated".to_string();
    assert!(matches!(
        repo.get_authorized(&revoked_policy).await,
        Err(StagingError::NotFound)
    ));
    for number in [2, 1] {
        repo.replace_part(
            &identity(),
            MultipartPart {
                upload_id: "upload".to_string(),
                part_number: number,
                attempt: 1,
                artifact_key: format!("{number}"),
                etag: "etag".to_string(),
                checksum_sha256: "digest".to_string(),
                size_bytes: 10,
                created_at_ms: now_ms(),
            },
        )
        .await
        .unwrap();
    }
    let (parts, truncated) = repo.list_parts(&identity(), 0, 1).await.unwrap();
    assert_eq!(parts[0].part_number, 1);
    assert!(truncated);
    let previous = repo
        .replace_part(
            &identity(),
            MultipartPart {
                upload_id: "upload".to_string(),
                part_number: 1,
                attempt: 2,
                artifact_key: "new".to_string(),
                etag: "new".to_string(),
                checksum_sha256: "new".to_string(),
                size_bytes: 11,
                created_at_ms: now_ms(),
            },
        )
        .await
        .unwrap();
    assert_eq!(previous.unwrap().attempt, 1);
    assert!(repo.reap_expired(now_ms() + 2_000, 10).await.unwrap().len() >= 2);
}

#[tokio::test]
async fn replacement_race_keeps_one_current_attempt_across_restartable_repository_state() {
    let repo = Arc::new(InMemoryMultipartRepository::new());
    repo.create(upload()).await.unwrap();
    let first = MultipartPart {
        upload_id: "upload".to_string(),
        part_number: 1,
        attempt: 1,
        artifact_key: "first".to_string(),
        etag: "first".to_string(),
        checksum_sha256: "first".to_string(),
        size_bytes: 1,
        created_at_ms: now_ms(),
    };
    repo.replace_part(&identity(), first).await.unwrap();
    let candidate = |artifact: &str| MultipartPart {
        upload_id: "upload".to_string(),
        part_number: 1,
        attempt: 2,
        artifact_key: artifact.to_string(),
        etag: artifact.to_string(),
        checksum_sha256: artifact.to_string(),
        size_bytes: 2,
        created_at_ms: now_ms(),
    };
    let identity_left = identity();
    let identity_right = identity();
    let (left, right) = tokio::join!(
        repo.replace_part(&identity_left, candidate("left")),
        repo.replace_part(&identity_right, candidate("right"))
    );
    assert!(left.is_ok() ^ right.is_ok());
    let (parts, _) = repo.list_parts(&identity(), 0, 10).await.unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].attempt, 2);
}

#[tokio::test]
async fn ciphertext_does_not_contain_plaintext_and_aad_is_identity_bound() {
    let directory = std::env::temp_dir().join(format!("maskura-stage-test-{}", Uuid::now_v7()));
    let wrapping = Arc::new(LocalKeyWrapping::with_kek([7; 32]));
    let mut writer = EncryptedPartWriter::begin(
        &directory,
        &identity(),
        1,
        1,
        &snapshot(),
        1024,
        wrapping.clone(),
    )
    .await
    .unwrap();
    writer
        .write(Bytes::from_static(b"plain-secret-must-not-persist"))
        .await
        .unwrap();
    let finished = writer.finish().await.unwrap();
    let ciphertext = tokio::fs::read(&finished.path).await.unwrap();
    assert!(
        !ciphertext
            .windows(b"plain-secret-must-not-persist".len())
            .any(|value| value == b"plain-secret-must-not-persist")
    );
    let header_len =
        u32::from_be_bytes(ciphertext[MAGIC.len()..MAGIC.len() + 4].try_into().unwrap()) as usize;
    let header_end = MAGIC.len() + 4 + header_len;
    let header: ArtifactHeader =
        serde_json::from_slice(&ciphertext[MAGIC.len() + 4..header_end]).unwrap();
    let frame_len =
        u32::from_be_bytes(ciphertext[header_end..header_end + 4].try_into().unwrap()) as usize;
    let nonce = &ciphertext[header_end + 4..header_end + 4 + NONCE_LEN];
    let frame = &ciphertext[header_end + 4 + NONCE_LEN..header_end + 4 + NONCE_LEN + frame_len];
    let dek = wrapping
        .unwrap(&B64.decode(&header.wrapped_dek).unwrap())
        .unwrap();
    let cipher = Aes256Gcm::new_from_slice(&dek).unwrap();
    assert_eq!(
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: frame,
                    aad: &artifact_aad(&header, 0)
                }
            )
            .unwrap(),
        b"plain-secret-must-not-persist"
    );
    let mut moved = header;
    moved.tenant_id = "tenant-b".to_string();
    assert!(
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: frame,
                    aad: &artifact_aad(&moved, 0)
                }
            )
            .is_err()
    );
    finished.remove().await;
    let _ = tokio::fs::remove_dir(directory).await;
}

#[tokio::test]
async fn encrypted_parts_feed_one_decoder_across_record_and_utf8_boundaries() {
    let directory = std::env::temp_dir().join(format!("maskura-stage-test-{}", Uuid::now_v7()));
    let wrapping = Arc::new(LocalKeyWrapping::with_kek([8; 32]));
    let snapshot = snapshot();
    let mut first_writer = EncryptedPartWriter::begin(
        &directory,
        &identity(),
        1,
        1,
        &snapshot,
        1024,
        wrapping.clone(),
    )
    .await
    .unwrap();
    first_writer
        .write(Bytes::from_static(b"first \xc3"))
        .await
        .unwrap();
    let first = first_writer.finish().await.unwrap();
    let mut second_writer = EncryptedPartWriter::begin(
        &directory,
        &identity(),
        2,
        1,
        &snapshot,
        1024,
        wrapping.clone(),
    )
    .await
    .unwrap();
    second_writer
        .write(Bytes::from_static(b"\xa9\nsecond"))
        .await
        .unwrap();
    let second = second_writer.finish().await.unwrap();
    let parts = [(1, first), (2, second)];
    let mut decoder = crate::record::RecordDecoder::new(
        crate::Format::Text,
        crate::record::DecoderLimits::default(),
    )
    .unwrap();
    let mut records = Vec::new();
    for (number, finished) in &parts {
        let part = MultipartPart {
            upload_id: "upload".to_string(),
            part_number: *number,
            attempt: 1,
            artifact_key: format!("artifact-{number}"),
            etag: finished.etag.clone(),
            checksum_sha256: finished.checksum_sha256.clone(),
            size_bytes: finished.size_bytes,
            created_at_ms: now_ms(),
        };
        let ciphertext = tokio::fs::read(&finished.path).await.unwrap();
        let mut reader = EncryptedPartReader::open(
            aws_sdk_s3::primitives::ByteStream::from(ciphertext).into_async_read(),
            &identity(),
            &part,
            &snapshot,
            wrapping.clone(),
        )
        .await
        .unwrap();
        while let Some(chunk) = reader.next_chunk().await.unwrap() {
            decoder.push(&chunk).unwrap();
            while let Some(record) = decoder.next_record().unwrap() {
                records.push(record);
            }
        }
    }
    decoder.finish().unwrap();
    while let Some(record) = decoder.next_record().unwrap() {
        records.push(record);
    }
    assert_eq!(records[0], crate::record::Record::new("first é", "\n"));
    assert_eq!(records[1], crate::record::Record::new("second", ""));
    for (_, finished) in parts {
        finished.remove().await;
    }
    let _ = tokio::fs::remove_dir(directory).await;
}

#[tokio::test]
async fn ephemeral_wrapping_cannot_start_durable_staging() {
    let directory = std::env::temp_dir().join(format!("maskura-stage-test-{}", Uuid::now_v7()));
    let result = EncryptedPartWriter::begin(
        &directory,
        &identity(),
        1,
        1,
        &snapshot(),
        1,
        Arc::new(LocalKeyWrapping::ephemeral()),
    )
    .await;
    assert!(matches!(result, Err(StagingError::Unavailable)));
}

#[tokio::test]
async fn encrypted_part_decrypts_after_local_runtime_restart() {
    let root = std::env::temp_dir().join(format!("maskura-stage-restart-{}", Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let runtime = LocalStorageRuntime::new(root.clone()).await.unwrap();
    let staging = runtime.multipart_root().join("tmp");
    let snapshot = snapshot();
    let mut restart_identity = identity();
    restart_identity.upload_id = Uuid::now_v7().to_string();
    let mut writer = EncryptedPartWriter::begin(
        &staging,
        &restart_identity,
        1,
        1,
        &snapshot,
        1024,
        runtime.wrapping(),
    )
    .await
    .unwrap();
    writer
        .write(Bytes::from_static(b"survives-a-runtime-restart"))
        .await
        .unwrap();
    let finished = writer.finish().await.unwrap();
    let part = MultipartPart {
        upload_id: restart_identity.upload_id.clone(),
        part_number: 1,
        attempt: 1,
        artifact_key: format!(
            "{ARTIFACT_PREFIX}{}/{}/1/1",
            restart_identity.tenant_id, restart_identity.upload_id
        ),
        etag: finished.etag.clone(),
        checksum_sha256: finished.checksum_sha256.clone(),
        size_bytes: finished.size_bytes,
        created_at_ms: now_ms(),
    };
    runtime
        .staging_artifacts()
        .put_file(&part.artifact_key, &finished.path)
        .await
        .unwrap();
    drop(runtime);

    let restarted = LocalStorageRuntime::new(root.clone()).await.unwrap();
    let body = restarted
        .staging_artifacts()
        .get(&part.artifact_key)
        .await
        .unwrap();
    let mut reader = EncryptedPartReader::open(
        body,
        &restart_identity,
        &part,
        &snapshot,
        restarted.wrapping(),
    )
    .await
    .unwrap();

    assert_eq!(
        reader.next_chunk().await.unwrap().unwrap(),
        Bytes::from_static(b"survives-a-runtime-restart")
    );
    assert!(reader.next_chunk().await.unwrap().is_none());
    restarted
        .staging_artifacts()
        .delete(&part.artifact_key)
        .await
        .unwrap();
    drop(restarted);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn concurrent_reservations_cannot_overcommit_global_quota() {
    let repo = Arc::new(InMemoryMultipartRepository::with_quotas(
        StagingQuotaLimits::new(10, 10).unwrap(),
    ));
    let first = upload();
    let mut second = upload();
    second.identity.upload_id = "upload-2".to_string();
    second.identity.tenant_id = "tenant-b".to_string();
    repo.create(first).await.unwrap();
    repo.create(second).await.unwrap();
    let first_identity = identity();
    let mut second_identity = identity();
    second_identity.upload_id = "upload-2".to_string();
    second_identity.tenant_id = "tenant-b".to_string();
    let (left, right) = tokio::join!(
        repo.begin_part(&first_identity, 1, 6, now_ms()),
        repo.begin_part(&second_identity, 1, 6, now_ms()),
    );
    assert!(left.is_ok() ^ right.is_ok());
    assert!(matches!(
        left.err().or(right.err()),
        Some(StagingError::QuotaExceeded)
    ));
}

#[tokio::test]
async fn crash_after_artifact_put_is_reconciled_from_pending_outbox() {
    let repo = InMemoryMultipartRepository::with_quotas(StagingQuotaLimits::new(32, 32).unwrap());
    repo.create(upload()).await.unwrap();
    let pending = repo
        .begin_part(
            &identity(),
            1,
            8,
            now_ms() - RECONCILIATION_GRACE.as_millis() as i64 - 1,
        )
        .await
        .unwrap();
    let artifacts = MemoryStagingArtifactStore::default();
    let path = std::env::temp_dir().join(format!("maskura-crash-artifact-{}", Uuid::now_v7()));
    tokio::fs::write(&path, b"ciphertext-only-test-artifact")
        .await
        .unwrap();
    artifacts
        .put_file(&pending.artifact_key, &path)
        .await
        .unwrap();
    tokio::fs::remove_file(&path).await.unwrap();

    // Simulates process death between S3 PUT and the DB CURRENT transition.
    let candidates = repo.cleanup_candidates(now_ms(), 10).await.unwrap();
    assert_eq!(candidates.len(), 1);
    artifacts.delete(&candidates[0].artifact_key).await.unwrap();
    repo.confirm_artifact_deleted(&candidates[0].artifact_key)
        .await
        .unwrap();
    assert!(artifacts.list(ARTIFACT_PREFIX).await.unwrap().is_empty());
    assert_eq!(
        repo.get_authorized(&identity())
            .await
            .unwrap()
            .reserved_bytes,
        0
    );
}

fn complete_part(number: u32, etag: &str, checksum: Option<&str>) -> CompletePart {
    CompletePart {
        part_number: number,
        etag: etag.to_string(),
        checksum_sha256: checksum.map(ToOwned::to_owned),
    }
}

async fn current_part(
    repo: &InMemoryMultipartRepository,
    number: u32,
    etag: &str,
    checksum: &str,
) -> String {
    let pending = repo
        .begin_part(&identity(), number, 3, now_ms())
        .await
        .unwrap();
    repo.commit_part(
        &identity(),
        &pending,
        MultipartPart {
            upload_id: "upload".to_string(),
            part_number: number,
            attempt: pending.attempt,
            artifact_key: pending.artifact_key.clone(),
            etag: etag.to_string(),
            checksum_sha256: checksum.to_string(),
            size_bytes: 3,
            created_at_ms: now_ms(),
        },
    )
    .await
    .unwrap();
    pending.artifact_key
}

#[tokio::test]
async fn completion_replays_only_the_identical_durable_request() {
    let repo = Arc::new(InMemoryMultipartRepository::new());
    repo.create(upload()).await.unwrap();
    current_part(&repo, 1, "\"one\"", "sha-one").await;
    let request = vec![complete_part(1, "\"one\"", Some("sha-one"))];
    let lease = match repo
        .acquire_completion(&identity(), "fingerprint", &request, "worker-a", 100, 0)
        .await
        .unwrap()
    {
        CompletionAcquire::Acquired(lease) => lease,
        _ => panic!("expected completion lease"),
    };
    let permit = repo
        .begin_destination_commit(
            &identity(),
            "fingerprint",
            lease.fencing_token,
            DestinationCommitPermit::deterministic_operation_id(&identity(), "fingerprint"),
            1,
        )
        .await
        .unwrap();
    let result = MultipartCompletionResult {
        etag: Some("\"output\"".to_string()),
        checksum_sha256: "output-sha".to_string(),
        version_id: Some("version-a".to_string()),
        source_bytes: 24,
        size_bytes: 42,
        pipeline_evidence: None,
    };
    repo.record_destination_commit(&permit, result.clone(), 1)
        .await
        .unwrap();
    repo.complete_completion(&identity(), &permit, result, 1)
        .await
        .unwrap();
    assert!(matches!(
        repo.acquire_completion(&identity(), "fingerprint", &request, "worker-b", 200, 2)
            .await,
        Ok(CompletionAcquire::Replayed(MultipartCompletionResult { ref etag, ref checksum_sha256, ref version_id, source_bytes: 24, size_bytes: 42, pipeline_evidence: None }))
            if etag.as_deref() == Some("\"output\"")
                && checksum_sha256 == "output-sha"
                && version_id.as_deref() == Some("version-a")
    ));
    assert!(matches!(
        repo.acquire_completion(&identity(), "different", &request, "worker-b", 200, 2)
            .await,
        Err(StagingError::CompletionConflict)
    ));
}

#[tokio::test]
async fn authorized_upload_listing_is_stable_and_marker_paginated() {
    let repo = InMemoryMultipartRepository::new();
    for (key, upload_id) in [("b", "3"), ("a", "2"), ("dir/x", "4"), ("a", "1")] {
        let mut candidate = upload();
        candidate.identity.key = key.to_string();
        candidate.identity.upload_id = upload_id.to_string();
        repo.create(candidate).await.unwrap();
    }
    let request = ListMultipartUploadsRequest {
        tenant_id: "tenant-a".to_string(),
        credential_policy_id: "key-a".to_string(),
        bucket: "bucket".to_string(),
        prefix: String::new(),
        delimiter: None,
        key_marker: None,
        upload_id_marker: None,
        max_uploads: 2,
    };
    let first = repo.list_authorized_uploads(&request).await.unwrap();
    assert_eq!(
        first
            .uploads
            .iter()
            .map(|upload| (
                upload.identity.key.as_str(),
                upload.identity.upload_id.as_str()
            ))
            .collect::<Vec<_>>(),
        [("a", "1"), ("a", "2")]
    );
    assert!(first.is_truncated);
    let second = repo
        .list_authorized_uploads(&ListMultipartUploadsRequest {
            key_marker: first.next_key_marker,
            upload_id_marker: first.next_upload_id_marker,
            ..request.clone()
        })
        .await
        .unwrap();
    assert_eq!(
        second
            .uploads
            .iter()
            .map(|upload| upload.identity.key.as_str())
            .collect::<Vec<_>>(),
        ["b", "dir/x"]
    );
    let delimited = repo
        .list_authorized_uploads(&ListMultipartUploadsRequest {
            delimiter: Some("/".to_string()),
            max_uploads: 10,
            ..request.clone()
        })
        .await
        .unwrap();
    assert_eq!(delimited.common_prefixes, ["dir/"]);
    let unauthorized = repo
        .list_authorized_uploads(&ListMultipartUploadsRequest {
            tenant_id: "tenant-b".to_string(),
            max_uploads: 10,
            ..request
        })
        .await
        .unwrap();
    assert!(unauthorized.uploads.is_empty());
    assert!(unauthorized.common_prefixes.is_empty());
}

#[tokio::test]
async fn publishing_permits_fence_takeover_recovery_commit_and_retirement() {
    let repo = InMemoryMultipartRepository::new();
    repo.create(upload()).await.unwrap();
    let artifact_key = current_part(&repo, 1, "\"one\"", "sha-one").await;
    let selected = [complete_part(1, "\"one\"", Some("sha-one"))];
    let lease = match repo
        .acquire_completion(&identity(), "fingerprint", &selected, "worker-a", 100, 0)
        .await
        .unwrap()
    {
        CompletionAcquire::Acquired(lease) => lease,
        _ => panic!("expected completion lease"),
    };
    let operation_id =
        DestinationCommitPermit::deterministic_operation_id(&identity(), "fingerprint");
    let permit = repo
        .begin_destination_commit(
            &identity(),
            "fingerprint",
            lease.fencing_token,
            operation_id,
            1,
        )
        .await
        .unwrap();
    assert!(matches!(
        repo.acquire_completion(
            &identity(),
            "fingerprint",
            &selected,
            "worker-b",
            2000,
            1000
        )
        .await,
        Ok(CompletionAcquire::Busy)
    ));
    let mut stale = permit.clone();
    stale.fencing_token += 1;
    assert!(
        repo.validate_destination_commit_permit(&stale)
            .await
            .is_err()
    );
    assert_eq!(repo.publishing_uploads(10).await.unwrap()[0].permit, permit);
    assert!(
        repo.cleanup_candidates(i64::MAX, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repo.release_destination_commit_after_proven_absence(&stale, 2)
            .await
            .is_err()
    );
    repo.release_destination_commit_after_proven_absence(&permit, 2)
        .await
        .unwrap();
    assert!(
        repo.validate_destination_commit_permit(&permit)
            .await
            .is_err()
    );

    let lease = match repo
        .acquire_completion(&identity(), "fingerprint", &selected, "worker-b", 200, 3)
        .await
        .unwrap()
    {
        CompletionAcquire::Acquired(lease) => lease,
        _ => panic!("expected completion takeover"),
    };
    let permit = repo
        .begin_destination_commit(
            &identity(),
            "fingerprint",
            lease.fencing_token,
            operation_id,
            4,
        )
        .await
        .unwrap();
    let result = MultipartCompletionResult {
        etag: Some("\"output\"".to_string()),
        checksum_sha256: "output-sha".to_string(),
        version_id: Some("version".to_string()),
        source_bytes: 3,
        size_bytes: 4,
        pipeline_evidence: None,
    };
    repo.record_destination_commit(&permit, result.clone(), 5)
        .await
        .unwrap();
    repo.record_destination_commit(&permit, result.clone(), 6)
        .await
        .unwrap();
    assert!(
        repo.release_destination_commit_after_proven_absence(&permit, 7)
            .await
            .is_err()
    );
    repo.complete_completion(&identity(), &permit, result, 7)
        .await
        .unwrap();
    repo.confirm_artifact_deleted(&artifact_key).await.unwrap();
    assert!(
        repo.retire_terminal_uploads(i64::MAX, 10)
            .await
            .unwrap()
            .is_empty()
    );
    repo.clear_destination_commit_reference(&identity(), operation_id)
        .await
        .unwrap();
    assert_eq!(
        repo.retire_terminal_uploads(i64::MAX, 10)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn completion_lease_takeover_fences_the_stale_worker() {
    let repo = InMemoryMultipartRepository::new();
    repo.create(upload()).await.unwrap();
    current_part(&repo, 1, "\"one\"", "sha-one").await;
    let request = vec![complete_part(1, "\"one\"", None)];
    let first = match repo
        .acquire_completion(&identity(), "same", &request, "worker-a", 10, 0)
        .await
        .unwrap()
    {
        CompletionAcquire::Acquired(lease) => lease,
        _ => panic!("expected first lease"),
    };
    assert!(matches!(
        repo.acquire_completion(&identity(), "same", &request, "worker-b", 20, 1)
            .await,
        Ok(CompletionAcquire::Busy)
    ));
    let second = match repo
        .acquire_completion(&identity(), "same", &request, "worker-b", 30, 11)
        .await
        .unwrap()
    {
        CompletionAcquire::Acquired(lease) => lease,
        _ => panic!("expected takeover lease"),
    };
    assert!(second.fencing_token > first.fencing_token);
    assert!(matches!(
        repo.check_completion_lease(&identity(), first.fencing_token, 12)
            .await,
        Err(StagingError::Fenced)
    ));
    assert!(
        repo.check_completion_lease(&identity(), second.fencing_token, 12)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn completion_rejects_missing_extra_duplicate_and_conflicting_parts() {
    let repo = InMemoryMultipartRepository::new();
    repo.create(upload()).await.unwrap();
    current_part(&repo, 1, "\"one\"", "sha-one").await;
    assert!(matches!(
        repo.acquire_completion(
            &identity(),
            "missing",
            &[complete_part(2, "\"two\"", None)],
            "worker",
            10,
            0,
        )
        .await,
        Err(StagingError::InvalidPart)
    ));
    assert!(matches!(
        repo.acquire_completion(
            &identity(),
            "conflicting",
            &[complete_part(1, "\"wrong\"", Some("sha-one"))],
            "worker",
            10,
            0,
        )
        .await,
        Err(StagingError::InvalidPart)
    ));
    assert!(matches!(
        repo.acquire_completion(
            &identity(),
            "duplicate",
            &[
                complete_part(1, "\"one\"", None),
                complete_part(1, "\"one\"", None),
            ],
            "worker",
            10,
            0,
        )
        .await,
        Err(StagingError::InvalidPart)
    ));
}

#[tokio::test]
async fn abort_is_idempotent_and_wins_before_completion_acquisition() {
    let repo = InMemoryMultipartRepository::new();
    repo.create(upload()).await.unwrap();
    current_part(&repo, 1, "\"one\"", "sha-one").await;
    let parts = repo.abort(&identity(), 1).await.unwrap();
    assert_eq!(parts.len(), 1);
    assert!(repo.abort(&identity(), 2).await.unwrap().is_empty());
    repo.confirm_artifact_deleted(&parts[0].artifact_key)
        .await
        .unwrap();
    assert_eq!(
        repo.retire_terminal_uploads(i64::MAX, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(matches!(
        repo.acquire_completion(
            &identity(),
            "after-abort",
            &[complete_part(1, "\"one\"", None)],
            "worker",
            10,
            2,
        )
        .await,
        Err(StagingError::NotFound)
    ));
}

#[tokio::test]
async fn zero_byte_part_can_be_uploaded_listed_and_selected_as_the_final_part() {
    let repo = InMemoryMultipartRepository::new();
    repo.create(upload()).await.unwrap();
    let pending = repo
        .begin_part(&identity(), 1, 0, now_ms())
        .await
        .expect("a zero-byte reservation is a valid final part");
    let zero = MultipartPart {
        upload_id: "upload".to_string(),
        part_number: 1,
        attempt: pending.attempt,
        artifact_key: pending.artifact_key.clone(),
        etag: "\"empty\"".to_string(),
        checksum_sha256: "empty-sha".to_string(),
        size_bytes: 0,
        created_at_ms: now_ms(),
    };
    repo.commit_part(&identity(), &pending, zero.clone())
        .await
        .unwrap();
    let (parts, truncated) = repo.list_parts(&identity(), 0, 1000).await.unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].size_bytes, 0);
    assert!(!truncated);
    let lease = match repo
        .acquire_completion(
            &identity(),
            "zero-final",
            &[complete_part(1, "\"empty\"", Some("empty-sha"))],
            "worker",
            100,
            now_ms(),
        )
        .await
        .unwrap()
    {
        CompletionAcquire::Acquired(lease) => lease,
        _ => panic!("expected completion lease for a zero-byte final part"),
    };
    assert_eq!(lease.selected_parts.len(), 1);
    assert_eq!(lease.selected_parts[0].size_bytes, 0);
}
