use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use md5::{Digest, Md5};
use sha2::Sha256;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;

use crate::file_store::FileStore;

use super::{ObjectSinkTransaction, SinkCommitState, StoredObjectMeta, TransactionError};

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
        })
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

    async fn complete(&mut self) -> Result<StoredObjectMeta, TransactionError> {
        if self.finished {
            return Err(TransactionError::Finished);
        }
        if !self.output_verified {
            return Err(TransactionError::OutputMismatch);
        }
        let file = self.file.take().ok_or(TransactionError::Finished)?;
        file.sync_all().await.map_err(file_error)?;
        drop(file);

        let etag = format!("\"{}\"", hex::encode(self.md5.clone().finalize()));
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

    fn test_root() -> PathBuf {
        std::env::temp_dir().join(format!("maskura-file-sink-{}", uuid::Uuid::now_v7()))
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
        let metadata = sink.complete().await.unwrap();
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
}
