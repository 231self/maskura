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

use crate::store::StoredObject;

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileObjectMetadata {
    key: String,
    content_type: String,
    etag: String,
    size: u64,
    data_file: String,
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
}

impl FileStore {
    pub async fn new(root: PathBuf) -> Result<Self, FileStoreError> {
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
        if entries.next_entry().await?.is_some() {
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
        let data_file = format!("{}.data", Uuid::now_v7());
        let data_path = self.data_path(bucket, &data_file)?;
        fs::rename(temp_path, &data_path).await?;
        sync_directory(self.objects_dir(bucket)?).await?;

        let metadata = FileObjectMetadata {
            key: key.to_string(),
            content_type: content_type.to_string(),
            etag: etag.to_string(),
            size,
            data_file,
        };
        write_metadata_atomically(&metadata_path, &metadata).await?;

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
