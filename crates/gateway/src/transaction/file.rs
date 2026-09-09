use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use md5::{Digest, Md5};
use sha2::Sha256;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;

use crate::file_store::{FileStore, LocalCommitContext};

use super::{
    DestinationCommitAuthority, ObjectSinkTransaction, SinkCommitState, StoredObjectMeta,
    TransactionError,
};

/// Single-object local storage sink. Bytes are streamed to a private temp file;
/// the object becomes visible only when FileStore atomically replaces metadata.
pub struct FileSinkTransaction {
    store: Arc<FileStore>,
    bucket: String,
    key: String,
    content_type: String,
    temp_path: PathBuf,
    file: Option<File>,
    max_bytes: u64,
    bytes: u64,
    sha256: Sha256,
    md5: Md5,
    output_verified: bool,
    finished: bool,
    operation_id: Option<uuid::Uuid>,
}

impl FileSinkTransaction {
    pub async fn new(
        store: Arc<FileStore>,
        bucket: impl Into<String>,
        key: impl Into<String>,
        content_type: impl Into<String>,
        max_bytes: u64,
    ) -> Result<Self, TransactionError> {
        if max_bytes == 0 {
            return Err(TransactionError::CapacityExceeded);
        }
        let bucket = bucket.into();
        let key = key.into();
        let (temp_path, file) = store
            .create_temp_file(&bucket, &key)
            .await
            .map_err(file_error)?;
        Ok(Self {
            store,
            bucket,
            key,
            content_type: content_type.into(),
            temp_path,
            file: Some(file),
            max_bytes,
            bytes: 0,
            sha256: Sha256::new(),
            md5: Md5::new(),
            output_verified: false,
            finished: false,
            operation_id: None,
        })
    }

    pub async fn new_for_operation(
        store: Arc<FileStore>,
        bucket: impl Into<String>,
        key: impl Into<String>,
        content_type: impl Into<String>,
        max_bytes: u64,
        operation_id: uuid::Uuid,
    ) -> Result<Self, TransactionError> {
        let mut sink = Self::new(store, bucket, key, content_type, max_bytes).await?;
        sink.operation_id = Some(operation_id);
        Ok(sink)
    }
}

#[async_trait]
impl ObjectSinkTransaction for FileSinkTransaction {
    fn commit_state(&self) -> SinkCommitState {
        if self.finished {
            SinkCommitState::Committed
        } else {
            SinkCommitState::PreCommit
        }
    }

    fn durable_operation_id(&self) -> Option<uuid::Uuid> {
        self.operation_id
    }

    async fn write(&mut self, chunk: Bytes) -> Result<(), TransactionError> {
        if self.finished {
            return Err(TransactionError::Finished);
        }
        let next_bytes = self
            .bytes
            .checked_add(chunk.len() as u64)
            .ok_or(TransactionError::CapacityExceeded)?;
        if next_bytes > self.max_bytes {
            return Err(TransactionError::CapacityExceeded);
        }
        let file = self.file.as_mut().ok_or(TransactionError::Finished)?;
        file.write_all(&chunk).await.map_err(file_error)?;
        self.bytes = next_bytes;
        self.sha256.update(&chunk);
        self.md5.update(&chunk);
        self.output_verified = false;
        Ok(())
    }

    async fn verify_output(
        &mut self,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), TransactionError> {
        if self.bytes != expected_size
            || hex::encode(self.sha256.clone().finalize()) != expected_sha256
        {
            return Err(TransactionError::OutputMismatch);
        }
        self.output_verified = true;
        Ok(())
    }

    async fn complete(
        &mut self,
        authority: DestinationCommitAuthority,
    ) -> Result<StoredObjectMeta, TransactionError> {
        if self.finished {
            return Err(TransactionError::Finished);
        }
        if !self.output_verified {
            return Err(TransactionError::OutputMismatch);
        }
        authority
            .validate(self.operation_id, &self.bucket, &self.key)
            .await?;
        let file = self.file.take().ok_or(TransactionError::Finished)?;
        file.sync_all().await.map_err(file_error)?;
        drop(file);

        let etag = format!("\"{}\"", hex::encode(self.md5.clone().finalize()));
        match &authority {
            DestinationCommitAuthority::SinglePut => {
                self.store
                    .commit_temp(
                        &self.bucket,
                        &self.key,
                        &self.temp_path,
                        &self.content_type,
                        self.bytes,
                        &etag,
                    )
                    .await
                    .map_err(file_error)?;
            }
            DestinationCommitAuthority::ClientMultipart(multipart) => {
                let permit = &multipart.permit;
                let context = LocalCommitContext {
                    operation_id: permit.operation_id,
                    generation_id: permit.operation_id,
                    completion_fence: permit.fencing_token,
                    bucket: self.bucket.clone(),
                    key: self.key.clone(),
                    content_type: self.content_type.clone(),
                    expected_size: self.bytes,
                    expected_sha256: hex::encode(self.sha256.clone().finalize()),
                    representation_headers: BTreeMap::new(),
                    user_metadata: BTreeMap::new(),
                    tags: BTreeMap::new(),
                    checksum: None,
                };
                self.store
                    .prepare_transaction(&context)
                    .await
                    .map_err(file_error)?;
                authority.validate(None, &self.bucket, &self.key).await?;
                self.store
                    .publish_transaction(&self.temp_path, &context, &etag)
                    .await
                    .map_err(file_error)?;
            }
        }
        self.finished = true;
        Ok(StoredObjectMeta {
            etag: Some(etag),
            version_id: None,
            superseded_version_ids: Vec::new(),
            version_history_complete: true,
        })
    }

    async fn abort(&mut self) -> Result<(), TransactionError> {
        if self.finished {
            return Ok(());
        }
        self.file.take();
        match fs::remove_file(&self.temp_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(file_error(error)),
        }
        self.finished = true;
        Ok(())
    }
}

fn file_error(error: impl std::fmt::Display) -> TransactionError {
    TransactionError::Spool(format!("local FileStore: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_multipart_repository::FileMultipartRepository;
    use crate::multipart_staging::{
        CompletePart, CompletionAcquire, DestinationCommitPermit, MultipartIdentity,
        MultipartLifecycle, MultipartPart, MultipartRepository, MultipartSnapshot, MultipartUpload,
        StagingQuotaLimits,
    };

    fn test_root() -> PathBuf {
        std::env::temp_dir().join(format!("maskura-file-sink-{}", uuid::Uuid::now_v7()))
    }

    fn multipart_identity() -> MultipartIdentity {
        MultipartIdentity {
            tenant_id: "tenant".to_string(),
            credential_policy_id: "policy".to_string(),
            bucket: "bucket".to_string(),
            key: "key".to_string(),
            upload_id: "00000000-0000-0000-0000-000000000001".to_string(),
        }
    }

    async fn valid_authority(root: &std::path::Path) -> DestinationCommitAuthority {
        let identity = multipart_identity();
        let now = crate::multipart_staging::now_ms();
        let repository = Arc::new(
            FileMultipartRepository::open(
                root.join("multipart"),
                StagingQuotaLimits::new(1024, 1024).unwrap(),
            )
            .unwrap(),
        );
        repository
            .create(MultipartUpload {
                identity: identity.clone(),
                namespace_epoch: None,
                snapshot: MultipartSnapshot {
                    metadata: BTreeMap::new(),
                    tags: BTreeMap::new(),
                    checksum_mode: None,
                    destination: serde_json::json!({"kind": "file"}),
                    plugin_snapshot: serde_json::json!({}),
                    max_staged_bytes: 1024,
                },
                lifecycle: MultipartLifecycle::Open,
                staged_bytes: 0,
                reserved_bytes: 0,
                created_at_ms: now,
                expires_at_ms: now + 10_000,
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
            .unwrap();
        let pending = repository.begin_part(&identity, 1, 5, now).await.unwrap();
        repository
            .commit_part(
                &identity,
                &pending,
                MultipartPart {
                    upload_id: identity.upload_id.clone(),
                    part_number: 1,
                    attempt: pending.attempt,
                    artifact_key: pending.artifact_key.clone(),
                    etag: "\"part\"".to_string(),
                    checksum_sha256: "part-sha".to_string(),
                    size_bytes: 5,
                    created_at_ms: now,
                },
            )
            .await
            .unwrap();
        let completion_now = crate::multipart_staging::now_ms();
        let lease = match repository
            .acquire_completion(
                &identity,
                "fingerprint",
                &[CompletePart {
                    part_number: 1,
                    etag: "\"part\"".to_string(),
                    checksum_sha256: Some("part-sha".to_string()),
                }],
                "worker",
                completion_now + 1_000,
                completion_now,
            )
            .await
            .unwrap()
        {
            CompletionAcquire::Acquired(lease) => lease,
            _ => panic!("expected completion lease"),
        };
        let operation_id =
            DestinationCommitPermit::deterministic_operation_id(&identity, "fingerprint");
        let permit = repository
            .begin_destination_commit(
                &identity,
                "fingerprint",
                lease.fencing_token,
                operation_id,
                crate::multipart_staging::now_ms(),
            )
            .await
            .unwrap();
        DestinationCommitAuthority::client_multipart(repository, identity, permit)
    }

    async fn verified_sink(store: Arc<FileStore>) -> FileSinkTransaction {
        let mut sink = FileSinkTransaction::new(store, "bucket", "key", "text/plain", 64)
            .await
            .unwrap();
        sink.write(Bytes::from_static(b"hello")).await.unwrap();
        sink.verify_output(
            5,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        .await
        .unwrap();
        sink
    }

    #[tokio::test]
    async fn commits_verified_stream_without_buffering_the_object() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        let mut sink = FileSinkTransaction::new(store.clone(), "bucket", "key", "text/plain", 64)
            .await
            .unwrap();
        sink.write(Bytes::from_static(b"hello ")).await.unwrap();
        sink.write(Bytes::from_static(b"world")).await.unwrap();
        assert!(matches!(
            sink.verify_output(
                10,
                "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            )
            .await,
            Err(TransactionError::OutputMismatch)
        ));
        sink.verify_output(
            11,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        )
        .await
        .unwrap();
        let metadata = sink
            .complete(DestinationCommitAuthority::SinglePut)
            .await
            .unwrap();
        assert_eq!(
            metadata.etag.as_deref(),
            Some("\"5eb63bbbe01eeed093cb22bb8f5acdc3\"")
        );
        assert_eq!(sink.commit_state(), SinkCommitState::Committed);
        assert_eq!(
            store.get("bucket", "key").await.unwrap().unwrap().data,
            Bytes::from_static(b"hello world")
        );

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn rejects_overflow_and_abort_removes_temp_file() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        let mut sink = FileSinkTransaction::new(store.clone(), "bucket", "key", "text/plain", 3)
            .await
            .unwrap();
        sink.write(Bytes::from_static(b"abc")).await.unwrap();
        assert!(matches!(
            sink.write(Bytes::from_static(b"d")).await,
            Err(TransactionError::CapacityExceeded)
        ));
        sink.abort().await.unwrap();
        assert!(store.get("bucket", "key").await.unwrap().is_none());
        assert!(sink.abort().await.is_ok());

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn multipart_requires_a_present_matching_current_permit_before_publication() {
        for failure in ["missing", "destination", "stale"] {
            let root = test_root();
            let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
            let mut sink = verified_sink(store.clone()).await;
            let authority = if failure == "missing" {
                let repository = Arc::new(
                    FileMultipartRepository::open(
                        root.join("missing"),
                        StagingQuotaLimits::new(1024, 1024).unwrap(),
                    )
                    .unwrap(),
                );
                let identity = multipart_identity();
                DestinationCommitAuthority::client_multipart(
                    repository,
                    identity.clone(),
                    DestinationCommitPermit {
                        upload_id: identity.upload_id.clone(),
                        completion_fingerprint: "fingerprint".to_string(),
                        fencing_token: 1,
                        operation_id: DestinationCommitPermit::deterministic_operation_id(
                            &identity,
                            "fingerprint",
                        ),
                    },
                )
            } else {
                let mut authority = valid_authority(&root).await;
                if let DestinationCommitAuthority::ClientMultipart(authority) = &mut authority {
                    let identity = &mut authority.identity;
                    let permit = &mut authority.permit;
                    if failure == "destination" {
                        identity.key = "other-key".to_string();
                    } else {
                        permit.fencing_token += 1;
                    }
                }
                authority
            };

            assert!(matches!(
                sink.complete(authority).await,
                Err(TransactionError::CommitAuthority(_))
            ));
            assert!(store.get("bucket", "key").await.unwrap().is_none());
            sink.abort().await.unwrap();
            fs::remove_dir_all(root).await.unwrap();
        }
    }

    #[tokio::test]
    async fn multipart_revalidates_immediately_before_prepare_publish_transaction() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        let mut sink = verified_sink(store.clone()).await;
        let authority = valid_authority(&root).await;
        let permit = authority.permit().unwrap().clone();

        sink.complete(authority).await.unwrap();

        assert!(matches!(
            store
                .probe_commit(permit.operation_id, permit.operation_id)
                .await
                .unwrap(),
            crate::file_store::LocalCommitProbe::Committed(_)
        ));
        fs::remove_dir_all(root).await.unwrap();
    }
}
