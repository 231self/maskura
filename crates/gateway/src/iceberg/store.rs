//! Object-store access for the table walker.
//!
//! A processed table operation reads and writes many objects (data files,
//! manifests, manifest lists, the table metadata JSON, the `version-hint`
//! pointer) inside one logical operation. Those objects are ordinary stored
//! objects in the request's bucket; this module is the only place the Iceberg
//! layer touches storage, so the walker and commit protocol stay testable
//! against any implementation.
//!
//! v1 supports the backends with direct object IO: the local file store, the
//! in-memory store, and S3-compatible clients. Managed service storage and
//! presigned-HTTP proxies fail closed (`unsupported.table_operation`): their
//! placement/authority machinery does not yet expose the multi-object
//! transactional shape a table commit needs.

use std::sync::Arc;

use aws_sdk_s3::primitives::ByteStream;
use maskura_error::{MaskuraError, codes};

use crate::file_store::FileStore;
use crate::store::MemoryStore;

fn store_error(detail: impl std::fmt::Display) -> MaskuraError {
    MaskuraError::new(codes::INTERNAL, format!("iceberg store: {detail}"))
}

/// Bucket-scoped object IO for the table walk and commit.
///
/// The walk's futures never cross a spawn boundary, so `Send` bounds are
/// carried by the callers (`async fn` in trait is deliberate here).
#[allow(async_fn_in_trait)]
pub trait TableStore {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, MaskuraError>;
    async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> Result<(), MaskuraError>;
    async fn delete(&self, key: &str) -> Result<bool, MaskuraError>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>, MaskuraError>;
}

/// Local file store objects.
pub struct FileTableStore {
    store: Arc<FileStore>,
    bucket: String,
}

impl FileTableStore {
    pub fn new(store: Arc<FileStore>, bucket: impl Into<String>) -> Self {
        Self {
            store,
            bucket: bucket.into(),
        }
    }
}

impl TableStore for FileTableStore {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, MaskuraError> {
        let Some(object) = self
            .store
            .open(&self.bucket, key)
            .await
            .map_err(store_error)?
        else {
            return Ok(None);
        };
        let mut reader = object.reader;
        let mut bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut bytes)
            .await
            .map_err(store_error)?;
        Ok(Some(bytes))
    }

    async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> Result<(), MaskuraError> {
        self.store
            .put(&self.bucket, key, bytes::Bytes::from(bytes), content_type)
            .await
            .map_err(store_error)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool, MaskuraError> {
        self.store
            .delete(&self.bucket, key)
            .await
            .map_err(store_error)
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MaskuraError> {
        let objects = self
            .store
            .list_objects(&self.bucket)
            .await
            .map_err(store_error)?;
        Ok(objects
            .into_iter()
            .map(|(key, ..)| key)
            .filter(|key| key.starts_with(prefix))
            .collect())
    }
}

/// In-memory store objects (single-tenant / test deployments).
pub struct MemoryTableStore {
    store: Arc<MemoryStore>,
    bucket: String,
}

impl MemoryTableStore {
    pub fn new(store: Arc<MemoryStore>, bucket: impl Into<String>) -> Self {
        Self {
            store,
            bucket: bucket.into(),
        }
    }
}

impl TableStore for MemoryTableStore {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, MaskuraError> {
        Ok(self
            .store
            .get(&self.bucket, key)
            .map(|object| object.data.to_vec()))
    }

    async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> Result<(), MaskuraError> {
        self.store.put(&self.bucket, key, bytes, content_type);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool, MaskuraError> {
        Ok(self.store.delete(&self.bucket, key))
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MaskuraError> {
        let head = format!("{}/", self.bucket);
        Ok(self
            .store
            .list_keys()
            .into_iter()
            .filter_map(|key| key.strip_prefix(&head).map(ToOwned::to_owned))
            .filter(|key| key.starts_with(prefix))
            .collect())
    }
}

/// S3-compatible client objects (per-workspace S3 backends and single-tenant
/// `S3_ENDPOINT`).
pub struct S3TableStore {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3TableStore {
    pub fn new(client: aws_sdk_s3::Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
        }
    }
}

impl TableStore for S3TableStore {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, MaskuraError> {
        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                if error
                    .as_service_error()
                    .is_some_and(|error| error.is_no_such_key())
                {
                    return Ok(None);
                }
                return Err(store_error(error));
            }
        };
        let bytes = response
            .body
            .collect()
            .await
            .map_err(store_error)?
            .into_bytes()
            .to_vec();
        Ok(Some(bytes))
    }

    async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> Result<(), MaskuraError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type(content_type)
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(store_error)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool, MaskuraError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(store_error)?;
        Ok(true)
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MaskuraError> {
        let mut keys = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .max_keys(1000);
            if let Some(token) = &continuation {
                request = request.continuation_token(token);
            }
            let response = request.send().await.map_err(store_error)?;
            for object in response.contents() {
                if let Some(key) = object.key() {
                    keys.push(key.to_string());
                }
            }
            if response.is_truncated() != Some(true) {
                break;
            }
            continuation = response.next_continuation_token().map(ToOwned::to_owned);
            if continuation.is_none() {
                break;
            }
        }
        Ok(keys)
    }
}

/// Bucket-scoped store chosen from a resolved backend.
///
/// v1 covers the backends with direct object IO. Managed service storage and
/// presigned-HTTP proxies have no multi-object transactional shape for a
/// table commit yet and fail closed (`unsupported.table_operation`) before
/// this type is built.
pub enum BackendTableStore {
    File(FileTableStore),
    Memory(MemoryTableStore),
    S3(S3TableStore),
}

impl TableStore for BackendTableStore {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, MaskuraError> {
        match self {
            Self::File(store) => store.get(key).await,
            Self::Memory(store) => store.get(key).await,
            Self::S3(store) => store.get(key).await,
        }
    }

    async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> Result<(), MaskuraError> {
        match self {
            Self::File(store) => store.put(key, bytes, content_type).await,
            Self::Memory(store) => store.put(key, bytes, content_type).await,
            Self::S3(store) => store.put(key, bytes, content_type).await,
        }
    }

    async fn delete(&self, key: &str) -> Result<bool, MaskuraError> {
        match self {
            Self::File(store) => store.delete(key).await,
            Self::Memory(store) => store.delete(key).await,
            Self::S3(store) => store.delete(key).await,
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MaskuraError> {
        match self {
            Self::File(store) => store.list(prefix).await,
            Self::Memory(store) => store.list(prefix).await,
            Self::S3(store) => store.list(prefix).await,
        }
    }
}
