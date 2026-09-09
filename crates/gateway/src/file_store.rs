use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use md5::{Digest as Md5Digest, Md5};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufWriter, SeekFrom, Take};
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;

use crate::filesystem_persistence::{FilesystemPersistence, PersistenceError};
use crate::store::StoredObject;

const FILE_OBJECT_METADATA_VERSION: u32 = 2;
const LOCAL_COMMIT_PROOF_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum FileStoreError {
    #[error("local storage bucket is invalid")]
    InvalidBucket,
    #[error("local storage object key is invalid")]
    InvalidKey,
    #[error("local storage bucket is not empty")]
    BucketNotEmpty,
    #[error("local storage metadata is corrupt: {0}")]
    CorruptMetadata(String),
    #[error("local storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("local storage metadata serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("local storage mutation may have committed: {0}")]
    MutationUnknown(String),
    #[error("local storage commit proof does not match the requested operation generation")]
    CommitProofMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileObjectMetadata {
    #[serde(default = "legacy_metadata_version")]
    schema_version: u32,
    key: String,
    content_type: String,
    etag: String,
    size: u64,
    data_file: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    representation_headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    user_metadata: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    tags: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checksum: Option<LocalChecksumState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    output_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generation_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion_fence: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LocalChecksumState {
    pub algorithm: String,
    pub value: String,
}

/// Backend-owned publication identity. A later fenced coordinator supplies
/// this only after obtaining its durable publishing permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCommitContext {
    pub operation_id: Uuid,
    pub generation_id: Uuid,
    pub completion_fence: u64,
    pub bucket: String,
    pub key: String,
    pub content_type: String,
    pub expected_size: u64,
    pub expected_sha256: String,
    pub representation_headers: BTreeMap<String, String>,
    pub user_metadata: BTreeMap<String, String>,
    pub tags: BTreeMap<String, String>,
    pub checksum: Option<LocalChecksumState>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedLocalCommitProof {
    pub schema_version: u32,
    pub operation_id: Uuid,
    pub generation_id: Uuid,
    pub completion_fence: u64,
    pub bucket: String,
    pub key: String,
    pub content_type: String,
    pub expected_size: u64,
    pub expected_sha256: String,
    pub representation_headers: BTreeMap<String, String>,
    pub user_metadata: BTreeMap<String, String>,
    pub tags: BTreeMap<String, String>,
    pub checksum: Option<LocalChecksumState>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommittedLocalCommitProof {
    pub schema_version: u32,
    pub prepared: PreparedLocalCommitProof,
    pub data_file: String,
    pub etag: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum LocalCommitProof {
    Prepared(PreparedLocalCommitProof),
    Committed(CommittedLocalCommitProof),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalCommitProbe {
    Absent,
    Prepared(PreparedLocalCommitProof),
    Published(CommittedLocalCommitProof),
    Committed(CommittedLocalCommitProof),
    Mismatch,
}

#[derive(Debug)]
pub struct FileObjectReader<R> {
    pub reader: R,
    pub object_length: u64,
    pub content_type: String,
    pub etag: String,
}

impl FileObjectReader<File> {
    pub async fn into_range(
        mut self,
        start: u64,
        length: u64,
    ) -> Result<FileObjectReader<Take<File>>, FileStoreError> {
        self.reader.seek(SeekFrom::Start(start)).await?;
        Ok(FileObjectReader {
            reader: self.reader.take(length),
            object_length: self.object_length,
            content_type: self.content_type,
            etag: self.etag,
        })
    }
}

/// Durable, single-node object storage rooted at a local directory.
///
/// Object content is version-named and metadata is a per-key atomic pointer.
/// A completed metadata rename is therefore the visibility commit: readers see
/// either the previous object version or the new complete version, never a
/// partially-written file.
#[derive(Debug)]
pub struct FileStore {
    root: PathBuf,
    mutation_lock: Arc<Mutex<()>>,
    persistence: FilesystemPersistence,
}

impl FileStore {
    /// Open a standalone store without acquiring the process-level root lock.
    ///
    /// This remains public for direct and integration consumers. Gateway
    /// startup must use `LocalStorageRuntime`, which holds the root lock before
    /// this store creates directories or removes stale temporary files.
    pub async fn new(root: PathBuf) -> Result<Self, FileStoreError> {
        Self::initialize(root).await
    }

    pub(crate) async fn open_locked(root: PathBuf) -> Result<Self, FileStoreError> {
        Self::initialize(root).await
    }

    async fn initialize(root: PathBuf) -> Result<Self, FileStoreError> {
        fs::create_dir_all(root.join("buckets")).await?;
        let metadata = fs::metadata(&root).await?;
        if !metadata.is_dir() {
            return Err(FileStoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "local storage root is not a directory",
            )));
        }
        let store = Self {
            root,
            mutation_lock: Arc::new(Mutex::new(())),
            persistence: FilesystemPersistence::default(),
        };
        store.remove_stale_temps().await?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub async fn put(
        self: &Arc<Self>,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        content_type: &str,
    ) -> Result<StoredObject, FileStoreError> {
        let data = data.into();
        let (temp_path, file) = self.create_temp_file(bucket, key).await?;
        let mut file = BufWriter::new(file);
        if let Err(error) = file.write_all(&data).await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(error.into());
        }
        if let Err(error) = file.flush().await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(error.into());
        }
        let file = file.into_inner();
        if let Err(error) = file.sync_all().await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(error.into());
        }
        drop(file);

        let mut hasher = Md5::new();
        hasher.update(&data);
        let etag = format!("\"{}\"", hex::encode(hasher.finalize()));
        self.commit_temp(
            bucket,
            key,
            &temp_path,
            content_type,
            data.len() as u64,
            &etag,
        )
        .await?;
        Ok(StoredObject {
            data,
            content_type: content_type.to_string(),
            etag,
        })
    }

    pub async fn open(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<FileObjectReader<File>>, FileStoreError> {
        let Some(metadata) = self.load_metadata(bucket, key).await? else {
            return Ok(None);
        };
        self.open_metadata(bucket, key, metadata).await
    }

    #[cfg(test)]
    pub async fn get(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<StoredObject>, FileStoreError> {
        let Some(mut object) = self.open(bucket, key).await? else {
            return Ok(None);
        };
        let mut data = Vec::new();
        object.reader.read_to_end(&mut data).await?;
        Ok(Some(StoredObject {
            data: Bytes::from(data),
            content_type: object.content_type,
            etag: object.etag,
        }))
    }

    pub async fn head(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<StoredObject>, FileStoreError> {
        Ok(self
            .load_metadata(bucket, key)
            .await?
            .map(|metadata| StoredObject {
                data: Bytes::new(),
                content_type: metadata.content_type,
                etag: metadata.etag,
            }))
    }

    pub async fn metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(u64, String, String)>, FileStoreError> {
        Ok(self
            .load_metadata(bucket, key)
            .await?
            .map(|metadata| (metadata.size, metadata.content_type, metadata.etag)))
    }

    pub async fn delete(&self, bucket: &str, key: &str) -> Result<bool, FileStoreError> {
        let _guard = self.mutation_lock.lock().await;
        let Some(metadata) = self.load_metadata(bucket, key).await? else {
            return Ok(false);
        };
        self.backfill_metadata_proof(bucket, &metadata).await?;
        let metadata_path = self.metadata_path(bucket, key)?;
        fs::remove_file(metadata_path).await?;
        if let Err(error) = fs::remove_file(self.data_path(bucket, &metadata.data_file)?).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(
                bucket,
                key, "local storage left an unreferenced object file: {error}"
            );
        }
        Ok(true)
    }

    pub async fn list_keys(&self) -> Result<Vec<String>, FileStoreError> {
        let mut buckets = match fs::read_dir(self.buckets_root()).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut keys = Vec::new();
        while let Some(bucket_entry) = buckets.next_entry().await? {
            if !bucket_entry.file_type().await?.is_dir() {
                continue;
            }
            let bucket = bucket_entry.file_name().to_string_lossy().into_owned();
            if validate_bucket(&bucket).is_err() {
                continue;
            }
            for (key, _, _) in self.list_objects(&bucket).await? {
                keys.push(format!("{bucket}/{key}"));
            }
        }
        keys.sort();
        Ok(keys)
    }

    pub async fn list_buckets(&self) -> Result<Vec<String>, FileStoreError> {
        let mut entries = match fs::read_dir(self.buckets_root()).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut buckets = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                let bucket = entry.file_name().to_string_lossy().into_owned();
                if validate_bucket(&bucket).is_ok() {
                    buckets.push(bucket);
                }
            }
        }
        buckets.sort();
        Ok(buckets)
    }

    pub async fn list_objects(
        &self,
        bucket: &str,
    ) -> Result<Vec<(String, String, u64)>, FileStoreError> {
        validate_bucket(bucket)?;
        let mut metadata = match fs::read_dir(self.metadata_dir(bucket)?).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut objects = Vec::new();
        while let Some(entry) = metadata.next_entry().await? {
            if !entry.file_type().await?.is_file()
                || entry
                    .path()
                    .extension()
                    .is_none_or(|extension| extension != "json")
            {
                continue;
            }
            let metadata = read_metadata_file(&entry.path()).await?;
            validate_key(&metadata.key)?;
            objects.push((metadata.key, metadata.etag, metadata.size));
        }
        objects.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(objects)
    }

    pub async fn create_bucket(&self, bucket: &str) -> Result<(), FileStoreError> {
        let _guard = self.mutation_lock.lock().await;
        self.ensure_bucket_layout(bucket).await
    }

    pub async fn delete_bucket(&self, bucket: &str) -> Result<bool, FileStoreError> {
        let _guard = self.mutation_lock.lock().await;
        validate_bucket(bucket)?;
        let bucket_dir = self.bucket_dir(bucket)?;
        let metadata_dir = bucket_dir.join("metadata");
        let mut entries = match fs::read_dir(&metadata_dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        let mut found_object = false;
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_file() {
                continue;
            }
            found_object = true;
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "json")
            {
                continue;
            }
            let metadata = read_metadata_file(&entry.path()).await?;
            self.backfill_metadata_proof(bucket, &metadata).await?;
        }
        if found_object {
            return Err(FileStoreError::BucketNotEmpty);
        }
        fs::remove_dir_all(bucket_dir).await?;
        Ok(true)
    }

    pub(crate) async fn create_temp_file(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(PathBuf, File), FileStoreError> {
        self.ensure_bucket_layout(bucket).await?;
        validate_key(key)?;
        let path = self
            .temp_dir(bucket)?
            .join(format!("{}.tmp", Uuid::now_v7()));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .await?;
        Ok((path, file))
    }

    pub(crate) async fn commit_temp(
        &self,
        bucket: &str,
        key: &str,
        temp_path: &Path,
        content_type: &str,
        size: u64,
        etag: &str,
    ) -> Result<(), FileStoreError> {
        let _guard = self.mutation_lock.lock().await;
        self.ensure_bucket_layout(bucket).await?;
        validate_key(key)?;

        let metadata_path = self.metadata_path(bucket, key)?;
        let previous = self.load_metadata(bucket, key).await?;
        if let Some(previous) = previous.as_ref() {
            self.backfill_metadata_proof(bucket, previous).await?;
        }
        let data_file = format!("{}.data", Uuid::now_v7());
        let data_path = self.data_path(bucket, &data_file)?;
        fs::rename(temp_path, &data_path).await?;
        sync_directory(self.objects_dir(bucket)?).await?;

        let metadata = FileObjectMetadata {
            schema_version: FILE_OBJECT_METADATA_VERSION,
            key: key.to_string(),
            content_type: content_type.to_string(),
            etag: etag.to_string(),
            size,
            data_file,
            representation_headers: BTreeMap::new(),
            user_metadata: BTreeMap::new(),
            tags: BTreeMap::new(),
            checksum: None,
            output_sha256: None,
            operation_id: None,
            generation_id: None,
            completion_fence: None,
        };
        write_metadata_atomically(&metadata_path, &metadata, false).await?;

        if let Some(previous) = previous
            && let Err(error) = fs::remove_file(self.data_path(bucket, &previous.data_file)?).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(
                bucket,
                key, "local storage left an unreferenced object file: {error}"
            );
        }
        Ok(())
    }

    pub async fn prepare_transaction(
        &self,
        context: &LocalCommitContext,
    ) -> Result<PreparedLocalCommitProof, FileStoreError> {
        validate_commit_context(context)?;
        let _guard = self.mutation_lock.lock().await;
        let prepared = PreparedLocalCommitProof::from(context);
        let path = self.commit_proof_path(context.operation_id);
        if let Some(existing) = self.load_commit_proof(context.operation_id).await? {
            return match existing {
                LocalCommitProof::Prepared(existing) if existing == prepared => Ok(existing),
                LocalCommitProof::Committed(existing) if existing.prepared == prepared => {
                    Ok(existing.prepared)
                }
                _ => Err(FileStoreError::CommitProofMismatch),
            };
        }
        self.write_commit_proof(&path, &LocalCommitProof::Prepared(prepared.clone()))
            .await?;
        Ok(prepared)
    }

    pub async fn publish_transaction(
        &self,
        temp_path: &Path,
        context: &LocalCommitContext,
        etag: &str,
    ) -> Result<CommittedLocalCommitProof, FileStoreError> {
        validate_commit_context(context)?;
        verify_transaction_temp(temp_path, context).await?;
        let _guard = self.mutation_lock.lock().await;
        let prepared = PreparedLocalCommitProof::from(context);
        match self.load_commit_proof(context.operation_id).await? {
            Some(LocalCommitProof::Prepared(existing)) if existing == prepared => {}
            Some(LocalCommitProof::Committed(existing)) if existing.prepared == prepared => {
                return Ok(existing);
            }
            _ => return Err(FileStoreError::CommitProofMismatch),
        }

        self.ensure_bucket_layout(&context.bucket).await?;
        let previous = self.load_metadata(&context.bucket, &context.key).await?;
        if let Some(previous) = previous.as_ref() {
            self.backfill_metadata_proof(&context.bucket, previous)
                .await?;
        }
        let data_file = format!("{}.data", context.generation_id);
        let data_path = self.data_path(&context.bucket, &data_file)?;
        fs::rename(temp_path, &data_path).await?;
        sync_directory(self.objects_dir(&context.bucket)?)
            .await
            .map_err(|error| FileStoreError::MutationUnknown(error.to_string()))?;

        let metadata = FileObjectMetadata {
            schema_version: FILE_OBJECT_METADATA_VERSION,
            key: context.key.clone(),
            content_type: context.content_type.clone(),
            etag: etag.to_string(),
            size: context.expected_size,
            data_file: data_file.clone(),
            representation_headers: context.representation_headers.clone(),
            user_metadata: context.user_metadata.clone(),
            tags: context.tags.clone(),
            checksum: context.checksum.clone(),
            output_sha256: Some(context.expected_sha256.clone()),
            operation_id: Some(context.operation_id),
            generation_id: Some(context.generation_id),
            completion_fence: Some(context.completion_fence),
        };
        write_metadata_atomically(
            &self.metadata_path(&context.bucket, &context.key)?,
            &metadata,
            true,
        )
        .await?;

        let committed = committed_proof(&metadata, prepared)?;
        if let Err(error) = self
            .write_commit_proof(
                &self.commit_proof_path(context.operation_id),
                &LocalCommitProof::Committed(committed.clone()),
            )
            .await
        {
            return Err(FileStoreError::MutationUnknown(error.to_string()));
        }

        if let Some(previous) = previous
            && previous.data_file != data_file
            && let Err(error) =
                fs::remove_file(self.data_path(&context.bucket, &previous.data_file)?).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(
                bucket = context.bucket,
                key = context.key,
                "local storage left an unreferenced object file: {error}"
            );
        }
        Ok(committed)
    }

    pub async fn probe_commit(
        &self,
        operation_id: Uuid,
        generation_id: Uuid,
    ) -> Result<LocalCommitProbe, FileStoreError> {
        let _guard = self.mutation_lock.lock().await;
        let Some(proof) = self.load_commit_proof(operation_id).await? else {
            return Ok(LocalCommitProbe::Absent);
        };
        match proof {
            LocalCommitProof::Committed(committed) => {
                Ok(if committed.prepared.generation_id == generation_id {
                    LocalCommitProbe::Committed(committed)
                } else {
                    LocalCommitProbe::Mismatch
                })
            }
            LocalCommitProof::Prepared(prepared) => {
                if prepared.generation_id != generation_id {
                    return Ok(LocalCommitProbe::Mismatch);
                }
                match self.load_metadata(&prepared.bucket, &prepared.key).await? {
                    Some(metadata)
                        if metadata.operation_id == Some(operation_id)
                            && metadata.generation_id == Some(generation_id) =>
                    {
                        Ok(LocalCommitProbe::Published(committed_proof(
                            &metadata, prepared,
                        )?))
                    }
                    Some(metadata) if metadata.operation_id.is_some() => {
                        Ok(LocalCommitProbe::Mismatch)
                    }
                    _ => Ok(LocalCommitProbe::Prepared(prepared)),
                }
            }
        }
    }

    pub async fn backfill_commit_proof(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<CommittedLocalCommitProof>, FileStoreError> {
        let _guard = self.mutation_lock.lock().await;
        let Some(metadata) = self.load_metadata(bucket, key).await? else {
            return Ok(None);
        };
        self.backfill_metadata_proof(bucket, &metadata).await
    }

    pub async fn retire_commit_proof(
        &self,
        operation_id: Uuid,
        generation_id: Uuid,
    ) -> Result<bool, FileStoreError> {
        let _guard = self.mutation_lock.lock().await;
        let Some(proof) = self.load_commit_proof(operation_id).await? else {
            return Ok(false);
        };
        let proof_generation = match proof {
            LocalCommitProof::Prepared(proof) => proof.generation_id,
            LocalCommitProof::Committed(proof) => proof.prepared.generation_id,
        };
        if proof_generation != generation_id {
            return Err(FileStoreError::CommitProofMismatch);
        }
        self.persistence
            .remove_file_durably(
                &self.commit_proof_path(operation_id),
                "commit proof retirement",
            )
            .map_err(persistence_error)
    }

    fn buckets_root(&self) -> PathBuf {
        self.root.join("buckets")
    }

    fn bucket_dir(&self, bucket: &str) -> Result<PathBuf, FileStoreError> {
        validate_bucket(bucket)?;
        Ok(self.buckets_root().join(bucket))
    }

    fn objects_dir(&self, bucket: &str) -> Result<PathBuf, FileStoreError> {
        Ok(self.bucket_dir(bucket)?.join("objects"))
    }

    fn metadata_dir(&self, bucket: &str) -> Result<PathBuf, FileStoreError> {
        Ok(self.bucket_dir(bucket)?.join("metadata"))
    }

    fn temp_dir(&self, bucket: &str) -> Result<PathBuf, FileStoreError> {
        Ok(self.bucket_dir(bucket)?.join("tmp"))
    }

    fn metadata_path(&self, bucket: &str, key: &str) -> Result<PathBuf, FileStoreError> {
        validate_key(key)?;
        Ok(self
            .metadata_dir(bucket)?
            .join(format!("{}.json", key_hash(key))))
    }

    fn data_path(&self, bucket: &str, data_file: &str) -> Result<PathBuf, FileStoreError> {
        let id = data_file
            .strip_suffix(".data")
            .and_then(|id| Uuid::parse_str(id).ok())
            .ok_or_else(|| FileStoreError::CorruptMetadata("invalid data filename".to_string()))?;
        Ok(self.objects_dir(bucket)?.join(format!("{id}.data")))
    }

    async fn ensure_bucket_layout(&self, bucket: &str) -> Result<(), FileStoreError> {
        validate_bucket(bucket)?;
        fs::create_dir_all(self.objects_dir(bucket)?).await?;
        fs::create_dir_all(self.metadata_dir(bucket)?).await?;
        fs::create_dir_all(self.temp_dir(bucket)?).await?;
        Ok(())
    }

    async fn load_metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<FileObjectMetadata>, FileStoreError> {
        let path = self.metadata_path(bucket, key)?;
        match read_metadata_file(&path).await {
            Ok(metadata) => {
                if !(1..=FILE_OBJECT_METADATA_VERSION).contains(&metadata.schema_version) {
                    return Err(FileStoreError::CorruptMetadata(format!(
                        "unsupported metadata schema version {}",
                        metadata.schema_version
                    )));
                }
                if metadata.key != key {
                    return Err(FileStoreError::CorruptMetadata(format!(
                        "metadata key does not match {bucket}/{key}"
                    )));
                }
                Ok(Some(metadata))
            }
            Err(FileStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    async fn open_metadata(
        &self,
        bucket: &str,
        key: &str,
        mut metadata: FileObjectMetadata,
    ) -> Result<Option<FileObjectReader<File>>, FileStoreError> {
        for attempt in 0..=1 {
            let file = match File::open(self.data_path(bucket, &metadata.data_file)?).await {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let Some(refreshed) = self.load_metadata(bucket, key).await? else {
                        return Ok(None);
                    };
                    if attempt == 0 && refreshed.data_file != metadata.data_file {
                        metadata = refreshed;
                        continue;
                    }
                    return Err(FileStoreError::CorruptMetadata(format!(
                        "metadata for {bucket}/{key} points to missing content"
                    )));
                }
                Err(error) => return Err(error.into()),
            };
            if file.metadata().await?.len() != metadata.size {
                return Err(FileStoreError::CorruptMetadata(format!(
                    "metadata size mismatch for {bucket}/{key}"
                )));
            }
            return Ok(Some(FileObjectReader {
                reader: file,
                object_length: metadata.size,
                content_type: metadata.content_type,
                etag: metadata.etag,
            }));
        }
        unreachable!("file open retry loop always returns")
    }

    async fn remove_stale_temps(&self) -> Result<(), FileStoreError> {
        let mut buckets = fs::read_dir(self.buckets_root()).await?;
        while let Some(bucket) = buckets.next_entry().await? {
            if !bucket.file_type().await?.is_dir() {
                continue;
            }
            let temp_dir = bucket.path().join("tmp");
            let mut files = match fs::read_dir(&temp_dir).await {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            while let Some(file) = files.next_entry().await? {
                if file.file_type().await?.is_file() {
                    fs::remove_file(file.path()).await?;
                }
            }
        }
        Ok(())
    }

    fn commit_proof_path(&self, operation_id: Uuid) -> PathBuf {
        self.root
            .join(".maskura")
            .join("commits")
            .join(format!("{operation_id}.json"))
    }

    async fn load_commit_proof(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<LocalCommitProof>, FileStoreError> {
        let path = self.commit_proof_path(operation_id);
        let persistence = self.persistence.clone();
        let snapshot = tokio::task::spawn_blocking(move || persistence.load_snapshot(&path))
            .await
            .map_err(|error| FileStoreError::Io(std::io::Error::other(error)))?
            .map_err(persistence_error)?;
        let Some(snapshot) = snapshot else {
            return Ok(None);
        };
        if snapshot.final_sequence != 0 {
            return Err(FileStoreError::CorruptMetadata(
                "commit proof snapshot has a nonzero sequence".into(),
            ));
        }
        let proof = snapshot.payload;
        let prepared = match &proof {
            LocalCommitProof::Prepared(prepared) => prepared,
            LocalCommitProof::Committed(committed) => {
                if committed.schema_version != LOCAL_COMMIT_PROOF_VERSION {
                    return Err(FileStoreError::CorruptMetadata(
                        "unsupported committed proof schema version".into(),
                    ));
                }
                &committed.prepared
            }
        };
        if prepared.schema_version != LOCAL_COMMIT_PROOF_VERSION
            || prepared.operation_id != operation_id
        {
            return Err(FileStoreError::CorruptMetadata(
                "commit proof identity or schema version is invalid".into(),
            ));
        }
        Ok(Some(proof))
    }

    async fn write_commit_proof(
        &self,
        path: &Path,
        proof: &LocalCommitProof,
    ) -> Result<(), FileStoreError> {
        let path = path.to_path_buf();
        let proof = proof.clone();
        let persistence = self.persistence.clone();
        tokio::task::spawn_blocking(move || persistence.atomic_write_snapshot(&path, 0, &proof))
            .await
            .map_err(|error| FileStoreError::Io(std::io::Error::other(error)))?
            .map_err(persistence_error)
    }

    async fn backfill_metadata_proof(
        &self,
        bucket: &str,
        metadata: &FileObjectMetadata,
    ) -> Result<Option<CommittedLocalCommitProof>, FileStoreError> {
        let (Some(operation_id), Some(generation_id), Some(completion_fence)) = (
            metadata.operation_id,
            metadata.generation_id,
            metadata.completion_fence,
        ) else {
            if metadata.operation_id.is_some()
                || metadata.generation_id.is_some()
                || metadata.completion_fence.is_some()
            {
                return Err(FileStoreError::CorruptMetadata(
                    "incomplete operation-aware object identity".into(),
                ));
            }
            return Ok(None);
        };
        let Some(output_sha256) = metadata.output_sha256.as_ref() else {
            return Err(FileStoreError::CorruptMetadata(
                "operation-aware metadata has no output checksum".into(),
            ));
        };
        let prepared = PreparedLocalCommitProof {
            schema_version: LOCAL_COMMIT_PROOF_VERSION,
            operation_id,
            generation_id,
            completion_fence,
            bucket: bucket.to_string(),
            key: metadata.key.clone(),
            content_type: metadata.content_type.clone(),
            expected_size: metadata.size,
            expected_sha256: output_sha256.clone(),
            representation_headers: metadata.representation_headers.clone(),
            user_metadata: metadata.user_metadata.clone(),
            tags: metadata.tags.clone(),
            checksum: metadata.checksum.clone(),
        };
        let committed = committed_proof(metadata, prepared)?;
        match self.load_commit_proof(operation_id).await? {
            Some(LocalCommitProof::Committed(existing)) if existing == committed => {
                return Ok(Some(existing));
            }
            Some(LocalCommitProof::Prepared(existing)) if existing == committed.prepared => {}
            None => {}
            _ => return Err(FileStoreError::CommitProofMismatch),
        }
        self.write_commit_proof(
            &self.commit_proof_path(operation_id),
            &LocalCommitProof::Committed(committed.clone()),
        )
        .await?;
        Ok(Some(committed))
    }
}

impl From<&LocalCommitContext> for PreparedLocalCommitProof {
    fn from(context: &LocalCommitContext) -> Self {
        Self {
            schema_version: LOCAL_COMMIT_PROOF_VERSION,
            operation_id: context.operation_id,
            generation_id: context.generation_id,
            completion_fence: context.completion_fence,
            bucket: context.bucket.clone(),
            key: context.key.clone(),
            content_type: context.content_type.clone(),
            expected_size: context.expected_size,
            expected_sha256: context.expected_sha256.clone(),
            representation_headers: context.representation_headers.clone(),
            user_metadata: context.user_metadata.clone(),
            tags: context.tags.clone(),
            checksum: context.checksum.clone(),
        }
    }
}

fn committed_proof(
    metadata: &FileObjectMetadata,
    prepared: PreparedLocalCommitProof,
) -> Result<CommittedLocalCommitProof, FileStoreError> {
    if prepared.schema_version != LOCAL_COMMIT_PROOF_VERSION
        || metadata.operation_id != Some(prepared.operation_id)
        || metadata.generation_id != Some(prepared.generation_id)
        || metadata.completion_fence != Some(prepared.completion_fence)
        || metadata.key != prepared.key
        || metadata.content_type != prepared.content_type
        || metadata.size != prepared.expected_size
        || metadata.output_sha256.as_deref() != Some(prepared.expected_sha256.as_str())
        || metadata.representation_headers != prepared.representation_headers
        || metadata.user_metadata != prepared.user_metadata
        || metadata.tags != prepared.tags
        || metadata.checksum != prepared.checksum
        || metadata.data_file != format!("{}.data", prepared.generation_id)
    {
        return Err(FileStoreError::CommitProofMismatch);
    }
    Ok(CommittedLocalCommitProof {
        schema_version: LOCAL_COMMIT_PROOF_VERSION,
        prepared,
        data_file: metadata.data_file.clone(),
        etag: metadata.etag.clone(),
    })
}

async fn verify_transaction_temp(
    temp_path: &Path,
    context: &LocalCommitContext,
) -> Result<(), FileStoreError> {
    let mut file = File::open(temp_path).await?;
    if file.metadata().await?.len() != context.expected_size {
        return Err(FileStoreError::CommitProofMismatch);
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if hex::encode(digest.finalize()) != context.expected_sha256 {
        return Err(FileStoreError::CommitProofMismatch);
    }
    Ok(())
}

fn validate_commit_context(context: &LocalCommitContext) -> Result<(), FileStoreError> {
    validate_bucket(&context.bucket)?;
    validate_key(&context.key)?;
    if context.expected_sha256.len() != 64
        || !context
            .expected_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || context.checksum.as_ref().is_some_and(|checksum| {
            checksum.algorithm != "sha256" || checksum.value != context.expected_sha256
        })
    {
        return Err(FileStoreError::CorruptMetadata(
            "invalid transaction output checksum".into(),
        ));
    }
    Ok(())
}

fn persistence_error(error: PersistenceError) -> FileStoreError {
    match error {
        PersistenceError::MutationUnknown { .. } => {
            FileStoreError::MutationUnknown(error.to_string())
        }
        PersistenceError::Corrupt(_)
        | PersistenceError::UnsupportedVersion(_)
        | PersistenceError::LimitExceeded(_) => FileStoreError::CorruptMetadata(error.to_string()),
        PersistenceError::Io { source, .. } => FileStoreError::Io(source),
        PersistenceError::ReloadRequired | PersistenceError::RootAlreadyLocked => {
            FileStoreError::Io(std::io::Error::other(error.to_string()))
        }
    }
}

const fn legacy_metadata_version() -> u32 {
    1
}

fn validate_bucket(bucket: &str) -> Result<(), FileStoreError> {
    if bucket.is_empty() || bucket == "." || bucket == ".." || bucket.contains(['/', '\\', '\0']) {
        return Err(FileStoreError::InvalidBucket);
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), FileStoreError> {
    if key.is_empty() || key.contains(['\\', '\0']) {
        return Err(FileStoreError::InvalidKey);
    }
    if key
        .split('/')
        .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(FileStoreError::InvalidKey);
    }
    if Path::new(key)
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(FileStoreError::InvalidKey);
    }
    Ok(())
}

fn key_hash(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

async fn read_metadata_file(path: &Path) -> Result<FileObjectMetadata, FileStoreError> {
    let bytes = fs::read(path).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn write_metadata_atomically(
    metadata_path: &Path,
    metadata: &FileObjectMetadata,
    require_directory_sync: bool,
) -> Result<(), FileStoreError> {
    let data = serde_json::to_vec(metadata)?;
    let parent = metadata_path.parent().ok_or_else(|| {
        FileStoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "metadata path has no parent",
        ))
    })?;
    let temporary = parent.join(format!(".{}.tmp", Uuid::now_v7()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .await?;
    if let Err(error) = file.write_all(&data).await {
        let _ = fs::remove_file(&temporary).await;
        return Err(error.into());
    }
    if let Err(error) = file.sync_all().await {
        let _ = fs::remove_file(&temporary).await;
        return Err(error.into());
    }
    drop(file);
    fs::rename(&temporary, metadata_path).await?;
    if let Err(error) = sync_directory(parent.to_path_buf()).await {
        if require_directory_sync {
            return Err(FileStoreError::MutationUnknown(error.to_string()));
        }
        warn!(path = %parent.display(), "local storage directory sync failed after committed metadata rename: {error}");
    }
    Ok(())
}

async fn sync_directory(path: PathBuf) -> Result<(), FileStoreError> {
    tokio::task::spawn_blocking(move || std::fs::File::open(path)?.sync_all())
        .await
        .map_err(|error| {
            FileStoreError::Io(std::io::Error::other(format!(
                "directory sync task failed: {error}"
            )))
        })??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::io::ReaderStream;

    async fn read_object<R>(reader: R, frame_bytes: usize) -> (Bytes, Vec<usize>)
    where
        R: tokio::io::AsyncRead + Send + Unpin + 'static,
    {
        use http_body_util::BodyExt as _;

        let mut body =
            axum::body::Body::from_stream(ReaderStream::with_capacity(reader, frame_bytes));
        let mut data = Vec::new();
        let mut frames = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.unwrap();
            if let Ok(frame) = frame.into_data() {
                frames.push(frame.len());
                data.extend_from_slice(&frame);
            }
        }
        (Bytes::from(data), frames)
    }

    fn test_root() -> PathBuf {
        std::env::temp_dir().join(format!("maskura-file-store-{}", Uuid::now_v7()))
    }

    fn commit_context(operation_id: Uuid, generation_id: Uuid) -> LocalCommitContext {
        LocalCommitContext {
            operation_id,
            generation_id,
            completion_fence: 7,
            bucket: "bucket".into(),
            key: "object".into(),
            content_type: "text/plain".into(),
            expected_size: 5,
            expected_sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
                .into(),
            representation_headers: BTreeMap::from([("content-language".into(), "en".into())]),
            user_metadata: BTreeMap::from([("owner".into(), "local".into())]),
            tags: BTreeMap::from([("stage".into(), "test".into())]),
            checksum: Some(LocalChecksumState {
                algorithm: "sha256".into(),
                value: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".into(),
            }),
        }
    }

    async fn transaction_temp(store: &FileStore) -> PathBuf {
        let (path, mut file) = store.create_temp_file("bucket", "object").await.unwrap();
        file.write_all(b"hello").await.unwrap();
        file.sync_all().await.unwrap();
        drop(file);
        path
    }

    async fn publish_test_transaction(
        store: &FileStore,
        context: &LocalCommitContext,
    ) -> CommittedLocalCommitProof {
        store.prepare_transaction(context).await.unwrap();
        let temp = transaction_temp(store).await;
        store
            .publish_transaction(&temp, context, "\"5d41402abc4b2a76b9719d911017c592\"")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn legacy_metadata_json_loads_without_new_fields() {
        let root = test_root();
        let store = FileStore::new(root.clone()).await.unwrap();
        store.ensure_bucket_layout("bucket").await.unwrap();
        let data_file = format!("{}.data", Uuid::now_v7());
        fs::write(store.data_path("bucket", &data_file).unwrap(), b"legacy")
            .await
            .unwrap();
        let metadata = serde_json::json!({
            "key": "object",
            "content_type": "text/plain",
            "etag": "\"legacy\"",
            "size": 6,
            "data_file": data_file,
        });
        fs::write(
            store.metadata_path("bucket", "object").unwrap(),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .await
        .unwrap();

        let loaded = store
            .load_metadata("bucket", "object")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.schema_version, 1);
        assert_eq!(loaded.data_file, metadata["data_file"].as_str().unwrap());
        assert!(loaded.operation_id.is_none());
        assert_eq!(
            store.get("bucket", "object").await.unwrap().unwrap().data,
            b"legacy"[..]
        );

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn transaction_publish_persists_exact_metadata_and_proof_across_restart() {
        let root = test_root();
        let store = FileStore::new(root.clone()).await.unwrap();
        let context = commit_context(Uuid::now_v7(), Uuid::now_v7());
        let committed = publish_test_transaction(&store, &context).await;

        assert_eq!(committed.prepared, PreparedLocalCommitProof::from(&context));
        assert_eq!(
            store
                .probe_commit(context.operation_id, context.generation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Committed(committed.clone())
        );
        let metadata = store
            .load_metadata("bucket", "object")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(metadata.schema_version, FILE_OBJECT_METADATA_VERSION);
        assert_eq!(
            metadata.data_file,
            format!("{}.data", context.generation_id)
        );
        assert_eq!(metadata.user_metadata, context.user_metadata);
        drop(store);

        let reopened = FileStore::new(root.clone()).await.unwrap();
        assert_eq!(
            reopened
                .probe_commit(context.operation_id, context.generation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Committed(committed)
        );
        assert_eq!(
            reopened
                .get("bucket", "object")
                .await
                .unwrap()
                .unwrap()
                .data,
            b"hello"[..]
        );

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn exact_probe_distinguishes_absence_preparation_and_mismatch() {
        let root = test_root();
        let store = FileStore::new(root.clone()).await.unwrap();
        let context = commit_context(Uuid::now_v7(), Uuid::now_v7());

        assert_eq!(
            store
                .probe_commit(Uuid::now_v7(), context.generation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Absent
        );
        let prepared = store.prepare_transaction(&context).await.unwrap();
        assert_eq!(
            store
                .probe_commit(context.operation_id, context.generation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Prepared(prepared)
        );
        assert_eq!(
            store
                .probe_commit(context.operation_id, Uuid::now_v7())
                .await
                .unwrap(),
            LocalCommitProbe::Mismatch
        );

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn published_pointer_backfills_receipt_after_pre_receipt_failure() {
        use crate::filesystem_persistence::FaultPoint;

        let root = test_root();
        let store = FileStore::new(root.clone()).await.unwrap();
        let context = commit_context(Uuid::now_v7(), Uuid::now_v7());
        store.prepare_transaction(&context).await.unwrap();
        store.persistence.fail_once(FaultPoint::PreWrite);
        let temp = transaction_temp(&store).await;

        assert!(matches!(
            store
                .publish_transaction(&temp, &context, "\"5d41402abc4b2a76b9719d911017c592\"")
                .await,
            Err(FileStoreError::MutationUnknown(_))
        ));
        let published = match store
            .probe_commit(context.operation_id, context.generation_id)
            .await
            .unwrap()
        {
            LocalCommitProbe::Published(published) => published,
            other => panic!("expected published pointer, got {other:?}"),
        };
        assert_eq!(
            store
                .backfill_commit_proof("bucket", "object")
                .await
                .unwrap(),
            Some(published.clone())
        );
        assert_eq!(
            store
                .probe_commit(context.operation_id, context.generation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Committed(published)
        );

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn post_rename_proof_sync_failure_is_explicitly_unknown_and_reloadable() {
        use crate::filesystem_persistence::FaultPoint;

        let root = test_root();
        let store = FileStore::new(root.clone()).await.unwrap();
        let context = commit_context(Uuid::now_v7(), Uuid::now_v7());
        store.persistence.fail_once(FaultPoint::ParentSync);

        assert!(matches!(
            store.prepare_transaction(&context).await,
            Err(FileStoreError::MutationUnknown(_))
        ));
        assert!(matches!(
            store
                .probe_commit(context.operation_id, context.generation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Prepared(_)
        ));

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn prepared_manifest_rename_failure_leaves_exact_operation_absent() {
        use crate::filesystem_persistence::FaultPoint;

        let root = test_root();
        let store = FileStore::new(root.clone()).await.unwrap();
        let context = commit_context(Uuid::now_v7(), Uuid::now_v7());
        store.persistence.fail_once(FaultPoint::Rename);

        assert!(matches!(
            store.prepare_transaction(&context).await,
            Err(FileStoreError::Io(_))
        ));
        assert_eq!(
            store
                .probe_commit(context.operation_id, context.generation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Absent
        );

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn committed_receipt_sync_failure_is_unknown_but_exactly_probeable() {
        use crate::filesystem_persistence::FaultPoint;

        let root = test_root();
        let store = FileStore::new(root.clone()).await.unwrap();
        let context = commit_context(Uuid::now_v7(), Uuid::now_v7());
        store.prepare_transaction(&context).await.unwrap();
        store.persistence.fail_once(FaultPoint::ParentSync);
        let temp = transaction_temp(&store).await;

        assert!(matches!(
            store
                .publish_transaction(&temp, &context, "\"5d41402abc4b2a76b9719d911017c592\"")
                .await,
            Err(FileStoreError::MutationUnknown(_))
        ));
        assert!(matches!(
            store
                .probe_commit(context.operation_id, context.generation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Committed(_)
        ));
        assert_eq!(
            store.get("bucket", "object").await.unwrap().unwrap().data,
            b"hello"[..]
        );

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn overwrite_and_delete_backfill_proof_before_removing_current_pointer() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        let first = commit_context(Uuid::now_v7(), Uuid::now_v7());
        publish_test_transaction(store.as_ref(), &first).await;
        assert!(
            store
                .retire_commit_proof(first.operation_id, first.generation_id)
                .await
                .unwrap()
        );

        store
            .put("bucket", "object", Bytes::from_static(b"new"), "text/plain")
            .await
            .unwrap();
        assert!(matches!(
            store
                .probe_commit(first.operation_id, first.generation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Committed(_)
        ));

        let second = commit_context(Uuid::now_v7(), Uuid::now_v7());
        publish_test_transaction(store.as_ref(), &second).await;
        assert!(
            store
                .retire_commit_proof(second.operation_id, second.generation_id)
                .await
                .unwrap()
        );
        assert!(store.delete("bucket", "object").await.unwrap());
        assert!(matches!(
            store
                .probe_commit(second.operation_id, second.generation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Committed(_)
        ));

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn bucket_delete_backfills_unresolved_pointer_and_keeps_bucket() {
        let root = test_root();
        let store = FileStore::new(root.clone()).await.unwrap();
        let context = commit_context(Uuid::now_v7(), Uuid::now_v7());
        publish_test_transaction(&store, &context).await;
        assert!(
            store
                .retire_commit_proof(context.operation_id, context.generation_id)
                .await
                .unwrap()
        );

        assert!(matches!(
            store.delete_bucket("bucket").await,
            Err(FileStoreError::BucketNotEmpty)
        ));
        assert!(matches!(
            store
                .probe_commit(context.operation_id, context.generation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Committed(_)
        ));
        assert!(store.root().join("buckets/bucket").exists());

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn retiring_matching_receipt_does_not_delete_visible_object() {
        let root = test_root();
        let store = FileStore::new(root.clone()).await.unwrap();
        let context = commit_context(Uuid::now_v7(), Uuid::now_v7());
        publish_test_transaction(&store, &context).await;

        assert!(matches!(
            store
                .retire_commit_proof(context.operation_id, Uuid::now_v7())
                .await,
            Err(FileStoreError::CommitProofMismatch)
        ));
        assert!(
            store
                .retire_commit_proof(context.operation_id, context.generation_id)
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .probe_commit(context.operation_id, context.generation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Absent
        );
        assert_eq!(
            store.get("bucket", "object").await.unwrap().unwrap().data,
            b"hello"[..]
        );

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn round_trips_and_lists_objects() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        let stored = store
            .put(
                "bucket",
                "nested/object.txt",
                Bytes::from_static(b"hello"),
                "text/plain",
            )
            .await
            .unwrap();
        assert_eq!(stored.etag, "\"5d41402abc4b2a76b9719d911017c592\"");

        let object = store
            .open("bucket", "nested/object.txt")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(object.object_length, 5);
        assert_eq!(object.content_type, "text/plain");
        assert_eq!(object.etag, stored.etag);
        let (data, frames) = read_object(object.reader, 2).await;
        assert_eq!(data, Bytes::from_static(b"hello"));
        assert!(frames.iter().all(|length| *length <= 2));
        assert_eq!(
            store.metadata("bucket", "nested/object.txt").await.unwrap(),
            Some((5, "text/plain".to_string(), stored.etag))
        );
        assert_eq!(
            store.list_keys().await.unwrap(),
            vec!["bucket/nested/object.txt"]
        );

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn overwrite_is_visible_as_one_complete_version() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        let first = store
            .put(
                "bucket",
                "object",
                Bytes::from_static(b"first"),
                "text/plain",
            )
            .await
            .unwrap();
        let second = store
            .put(
                "bucket",
                "object",
                Bytes::from_static(b"second"),
                "text/plain",
            )
            .await
            .unwrap();
        assert_ne!(first.etag, second.etag);
        let object = store.open("bucket", "object").await.unwrap().unwrap();
        assert_eq!(
            read_object(object.reader, 64).await.0,
            Bytes::from_static(b"second")
        );
        assert_eq!(store.list_keys().await.unwrap(), vec!["bucket/object"]);

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn delete_and_bucket_lifecycle_require_empty_bucket() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store.create_bucket("bucket").await.unwrap();
        assert_eq!(store.list_buckets().await.unwrap(), vec!["bucket"]);
        store
            .put(
                "bucket",
                "object",
                Bytes::from_static(b"data"),
                "application/octet-stream",
            )
            .await
            .unwrap();
        assert!(matches!(
            store.delete_bucket("bucket").await,
            Err(FileStoreError::BucketNotEmpty)
        ));
        assert!(store.delete("bucket", "object").await.unwrap());
        assert!(!store.delete("bucket", "object").await.unwrap());
        assert!(store.delete_bucket("bucket").await.unwrap());
        assert!(!store.delete_bucket("bucket").await.unwrap());

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn rejects_unsafe_bucket_and_key_paths() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        for bucket in ["", ".", "..", "bucket/name", "bucket\\name"] {
            assert!(matches!(
                store.create_bucket(bucket).await,
                Err(FileStoreError::InvalidBucket)
            ));
        }
        for key in ["", ".", "..", "dir/../object", "dir//object", "dir\\object"] {
            assert!(matches!(
                store
                    .put("bucket", key, Bytes::from_static(b"data"), "text/plain")
                    .await,
                Err(FileStoreError::InvalidKey)
            ));
        }

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn startup_removes_abandoned_temp_files() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        let (temporary, file) = store.create_temp_file("bucket", "object").await.unwrap();
        drop(file);
        assert!(temporary.exists());
        drop(store);

        let _reopened = FileStore::new(root.clone()).await.unwrap();
        assert!(!temporary.exists());
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn range_reader_stops_at_selected_length() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store
            .put(
                "bucket",
                "object",
                Bytes::from_static(b"0123456789"),
                "text/plain",
            )
            .await
            .unwrap();

        let object = store.open("bucket", "object").await.unwrap().unwrap();
        let object = object.into_range(3, 4).await.unwrap();
        let (data, frames) = read_object(object.reader, 2).await;
        assert_eq!(data, Bytes::from_static(b"3456"));
        assert!(frames.iter().all(|length| *length <= 2));

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn large_sparse_object_range_does_not_buffer_or_overread() {
        const OBJECT_LENGTH: u64 = 1024 * 1024 * 1024;
        const MARKER: &[u8] = b"range-end";
        const RANGE_START: u64 = OBJECT_LENGTH - MARKER.len() as u64;

        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        let (temp_path, mut file) = store.create_temp_file("bucket", "large").await.unwrap();
        file.set_len(OBJECT_LENGTH).await.unwrap();
        file.seek(SeekFrom::Start(RANGE_START)).await.unwrap();
        file.write_all(MARKER).await.unwrap();
        file.sync_all().await.unwrap();
        drop(file);
        store
            .commit_temp(
                "bucket",
                "large",
                &temp_path,
                "application/octet-stream",
                OBJECT_LENGTH,
                "\"sparse-test\"",
            )
            .await
            .unwrap();

        let object = store.open("bucket", "large").await.unwrap().unwrap();
        let object = object
            .into_range(RANGE_START, MARKER.len() as u64)
            .await
            .unwrap();
        let mut reader = object.reader;
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, MARKER);

        let mut file = reader.into_inner();
        assert_eq!(
            file.stream_position().await.unwrap(),
            RANGE_START + MARKER.len() as u64
        );

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn raced_overwrite_revalidates_and_opens_the_published_generation() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store
            .put("bucket", "object", Bytes::from_static(b"old"), "text/plain")
            .await
            .unwrap();
        let stale = store
            .load_metadata("bucket", "object")
            .await
            .unwrap()
            .unwrap();
        let published = store
            .put(
                "bucket",
                "object",
                Bytes::from_static(b"new generation"),
                "text/plain",
            )
            .await
            .unwrap();

        let object = store
            .open_metadata("bucket", "object", stale)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(object.etag, published.etag);
        assert_eq!(
            read_object(object.reader, 4).await.0,
            Bytes::from_static(b"new generation")
        );

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn raced_delete_revalidation_returns_missing() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store
            .put("bucket", "object", Bytes::from_static(b"old"), "text/plain")
            .await
            .unwrap();
        let stale = store
            .load_metadata("bucket", "object")
            .await
            .unwrap()
            .unwrap();
        assert!(store.delete("bucket", "object").await.unwrap());

        assert!(
            store
                .open_metadata("bucket", "object", stale)
                .await
                .unwrap()
                .is_none()
        );

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn revalidation_is_bounded_when_the_published_generation_is_corrupt() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store
            .put("bucket", "object", Bytes::from_static(b"old"), "text/plain")
            .await
            .unwrap();
        let stale = store
            .load_metadata("bucket", "object")
            .await
            .unwrap()
            .unwrap();
        store
            .put("bucket", "object", Bytes::from_static(b"new"), "text/plain")
            .await
            .unwrap();
        let published = store
            .load_metadata("bucket", "object")
            .await
            .unwrap()
            .unwrap();
        fs::remove_file(store.data_path("bucket", &published.data_file).unwrap())
            .await
            .unwrap();

        assert!(matches!(
            store.open_metadata("bucket", "object", stale).await,
            Err(FileStoreError::CorruptMetadata(_))
        ));

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn metadata_survives_missing_content_but_open_reports_corruption() {
        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store
            .put(
                "bucket",
                "object",
                Bytes::from_static(b"data"),
                "text/plain",
            )
            .await
            .unwrap();
        let metadata = store
            .load_metadata("bucket", "object")
            .await
            .unwrap()
            .unwrap();
        fs::remove_file(store.data_path("bucket", &metadata.data_file).unwrap())
            .await
            .unwrap();

        assert_eq!(
            store.metadata("bucket", "object").await.unwrap(),
            Some((4, "text/plain".to_string(), metadata.etag))
        );
        assert!(matches!(
            store.open("bucket", "object").await,
            Err(FileStoreError::CorruptMetadata(_))
        ));

        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn streamed_reader_uses_opened_object_limits_and_cancellation() {
        use crate::object::{BodyLimits, ObjectMetadata, OpenedObject};
        use http_body_util::BodyExt as _;

        let root = test_root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store
            .put(
                "bucket",
                "object",
                Bytes::from_static(b"123456789"),
                "text/plain",
            )
            .await
            .unwrap();
        let object = store.open("bucket", "object").await.unwrap().unwrap();
        let object_length = object.object_length;
        let object = object.into_range(0, object_length).await.unwrap();
        let body = axum::body::Body::from_stream(ReaderStream::with_capacity(object.reader, 4));
        let opened = OpenedObject::new(
            axum::http::StatusCode::OK,
            ObjectMetadata::default(),
            body,
            BodyLimits {
                max_frame_bytes: 4,
                max_bytes: 7,
            },
        );
        let cancellation = opened.cancellation.clone();

        let error = opened.body.collect().await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("source body is at least 8 bytes")
        );
        assert!(cancellation.is_cancelled());

        fs::remove_dir_all(root).await.unwrap();
    }
}
