//! Durable S3 history. A single per-key manifest owns history and latest order.

use super::*;

const HISTORY_SCHEMA: u32 = 3;
const MAX_HISTORY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 16 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileVersioning {
    #[default]
    Unversioned,
    Enabled,
    Suspended,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BucketVersioning {
    schema_version: u32,
    state: FileVersioning,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionEntry {
    version_id: String,
    modified_ms: i64,
    /// None is a delete marker, never an empty data object.
    /// Require the field even when null; a damaged data entry must not silently
    /// turn into a marker merely because its object field is absent.
    #[serde(deserialize_with = "deserialize_version_object")]
    object: Option<FileObjectMetadata>,
}

fn deserialize_version_object<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<FileObjectMetadata>, D::Error> {
    Option::deserialize(deserializer)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectHistory {
    schema_version: u32,
    key: String,
    versions: Vec<VersionEntry>,
}

#[derive(Clone, Debug)]
pub struct FileVersion {
    pub key: String,
    pub version_id: String,
    pub is_latest: bool,
    pub delete_marker: bool,
    pub last_modified_ms: i64,
    pub size: u64,
    pub etag: String,
}

#[derive(Clone, Debug, Default)]
pub struct FileDeleteResult {
    pub existed: bool,
    pub version_id: Option<String>,
    pub delete_marker: bool,
}

pub(crate) fn validate_version_id(id: &str) -> Result<(), FileStoreError> {
    // IDs are opaque to callers; only our canonical UUIDs and S3's null sentinel
    // are accepted. A selector can never become a filesystem path.
    if id == "null" || Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == id) {
        Ok(())
    } else {
        Err(FileStoreError::InvalidVersion)
    }
}

async fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>, FileStoreError> {
    let file = File::open(path).await?;
    let metadata = file.metadata().await?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(FileStoreError::CorruptMetadata(
            "local metadata limit exceeded".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).await?;
    if bytes.len() as u64 > limit {
        return Err(FileStoreError::CorruptMetadata(
            "local metadata limit exceeded".into(),
        ));
    }
    Ok(bytes)
}

async fn read_history(path: &Path) -> Result<ObjectHistory, FileStoreError> {
    let bytes = bounded_read(path, MAX_HISTORY_BYTES).await?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let history =
        if value.get("schema_version").and_then(|v| v.as_u64()) == Some(HISTORY_SCHEMA.into()) {
            serde_json::from_value::<ObjectHistory>(value)?
        } else {
            let object: FileObjectMetadata = serde_json::from_value(value)?;
            if !(1..=FILE_OBJECT_METADATA_VERSION).contains(&object.schema_version)
                || object.version_id.is_some()
            {
                return Err(FileStoreError::CorruptMetadata(
                    "unsupported legacy metadata schema".into(),
                ));
            }
            ObjectHistory {
                schema_version: HISTORY_SCHEMA,
                key: object.key.clone(),
                versions: vec![VersionEntry {
                    version_id: "null".into(),
                    modified_ms: object.last_modified_ms.unwrap_or(0),
                    object: Some(object),
                }],
            }
        };
    validate_key(&history.key)?;
    if path.file_name().and_then(|v| v.to_str())
        != Some(format!("{}.json", key_hash(&history.key)).as_str())
    {
        return Err(FileStoreError::CorruptMetadata(
            "history key does not match path".into(),
        ));
    }
    let mut ids = std::collections::HashSet::new();
    for entry in &history.versions {
        if validate_version_id(&entry.version_id).is_err() || !ids.insert(&entry.version_id) {
            return Err(FileStoreError::CorruptMetadata(
                "invalid or duplicate version identity".into(),
            ));
        }
        if let Some(object) = &entry.object
            && (!(1..=FILE_OBJECT_METADATA_VERSION).contains(&object.schema_version)
                || object.key != history.key
                || object.version_id.as_deref().unwrap_or("null") != entry.version_id
                || object
                    .data_file
                    .strip_suffix(".data")
                    .and_then(|id| Uuid::parse_str(id).ok())
                    .is_none())
        {
            return Err(FileStoreError::CorruptMetadata(
                "version metadata identity mismatch".into(),
            ));
        }
    }
    Ok(history)
}

pub(super) async fn latest_metadata(
    path: &Path,
) -> Result<Option<FileObjectMetadata>, FileStoreError> {
    Ok(read_history(path)
        .await?
        .versions
        .into_iter()
        .next()
        .and_then(|v| v.object))
}

pub(super) async fn retained_metadata(
    path: &Path,
) -> Result<Vec<FileObjectMetadata>, FileStoreError> {
    Ok(read_history(path)
        .await?
        .versions
        .into_iter()
        .filter_map(|v| v.object)
        .collect())
}

pub(super) async fn has_versions(path: &Path) -> Result<bool, FileStoreError> {
    Ok(!read_history(path).await?.versions.is_empty())
}

pub(super) fn joined<T>(
    result: Result<Result<T, FileStoreError>, tokio::task::JoinError>,
) -> Result<T, FileStoreError> {
    result.map_err(|_| FileStoreError::MutationUnknown("local publication owner failed".into()))?
}

impl FileStore {
    pub(super) async fn validate_version_state(&self) -> Result<(), FileStoreError> {
        for bucket in self.list_buckets().await? {
            self.versioning(&bucket).await?;
            let mut entries = match fs::read_dir(self.metadata_dir(&bucket)?).await {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            while let Some(entry) = entries.next_entry().await? {
                if entry.path().extension().is_some_and(|e| e == "json") {
                    let history = read_history(&entry.path()).await?;
                    for entry in history.versions {
                        if let Some(object) = entry.object {
                            self.data_path(&bucket, &object.data_file)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) async fn generation_metadata(
        &self,
        bucket: &str,
        key: &str,
        operation: Uuid,
        generation: Uuid,
    ) -> Result<Option<FileObjectMetadata>, FileStoreError> {
        Ok(self
            .history(bucket, key)
            .await?
            .versions
            .into_iter()
            .filter_map(|entry| entry.object)
            .find(|object| {
                object.operation_id == Some(operation) && object.generation_id == Some(generation)
            }))
    }

    pub(super) async fn backfill_retained_proofs(&self) -> Result<usize, FileStoreError> {
        let _guard = self.mutation_lock.lock().await;
        let mut repaired = 0;
        for bucket in self.list_buckets().await? {
            let mut entries = match fs::read_dir(self.metadata_dir(&bucket)?).await {
                Ok(entries) => entries,
                // An interrupted first layout may contain only tmp/. There
                // cannot be a retained proof to repair without metadata/.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            while let Some(entry) = entries.next_entry().await? {
                if entry.path().extension().is_some_and(|e| e == "json") {
                    for object in retained_metadata(&entry.path()).await? {
                        if self
                            .backfill_metadata_proof(&bucket, &object)
                            .await?
                            .is_some()
                        {
                            repaired += 1;
                        }
                    }
                }
            }
        }
        Ok(repaired)
    }

    pub async fn versioning(&self, bucket: &str) -> Result<FileVersioning, FileStoreError> {
        let path = self.bucket_dir(bucket)?.join("versioning.json");
        let bytes = match bounded_read(&path, MAX_CONFIG_BYTES).await {
            Ok(bytes) => bytes,
            Err(FileStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(FileVersioning::Unversioned);
            }
            Err(error) => return Err(error),
        };
        let config: BucketVersioning = serde_json::from_slice(&bytes)?;
        if config.schema_version != 1 || config.state == FileVersioning::Unversioned {
            return Err(FileStoreError::CorruptMetadata(
                "invalid bucket versioning configuration".into(),
            ));
        }
        Ok(config.state)
    }

    pub async fn set_versioning(
        &self,
        bucket: &str,
        state: FileVersioning,
    ) -> Result<(), FileStoreError> {
        let store = self.clone();
        let bucket = bucket.to_owned();
        joined(
            tokio::spawn(async move {
                let _guard = store.mutation_lock.lock().await;
                if !store.bucket_exists(&bucket).await? {
                    return Err(FileStoreError::NoSuchBucket);
                }
                if state == FileVersioning::Unversioned {
                    return Err(FileStoreError::InvalidVersion);
                }
                store.versioning(&bucket).await?;
                let bytes = serde_json::to_vec(&BucketVersioning {
                    schema_version: 1,
                    state,
                })?;
                store
                    .write_version_bytes(store.bucket_dir(&bucket)?.join("versioning.json"), bytes)
                    .await
            })
            .await,
        )
    }

    async fn write_version_bytes(
        &self,
        path: PathBuf,
        bytes: Vec<u8>,
    ) -> Result<(), FileStoreError> {
        let persistence = self.persistence.clone();
        let root_lock = self._root_lock.clone();
        tokio::task::spawn_blocking(move || {
            let _root_lock = root_lock;
            persistence.atomic_write(&path, &bytes, "version publication")
        })
        .await
        .map_err(|_| FileStoreError::MutationUnknown("local persistence owner failed".into()))?
        .map_err(persistence_error)
    }

    async fn history(&self, bucket: &str, key: &str) -> Result<ObjectHistory, FileStoreError> {
        match read_history(&self.metadata_path(bucket, key)?).await {
            Ok(history) => Ok(history),
            Err(FileStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ObjectHistory {
                    schema_version: HISTORY_SCHEMA,
                    key: key.into(),
                    versions: Vec::new(),
                })
            }
            Err(error) => Err(error),
        }
    }

    async fn write_history(
        &self,
        bucket: &str,
        history: &ObjectHistory,
    ) -> Result<(), FileStoreError> {
        let bytes = serde_json::to_vec(history)?;
        if bytes.len() as u64 > MAX_HISTORY_BYTES {
            return Err(FileStoreError::HistoryFull);
        }
        self.write_version_bytes(self.metadata_path(bucket, &history.key)?, bytes)
            .await
    }

    /// Called only under the shared mutation guard, after the data directory sync.
    pub(super) async fn publish_version(
        &self,
        bucket: &str,
        mut object: FileObjectMetadata,
        state: FileVersioning,
    ) -> Result<FileObjectMetadata, FileStoreError> {
        let mut history = self.history(bucket, &object.key).await?;
        let id = if state == FileVersioning::Enabled {
            object
                .generation_id
                .unwrap_or_else(Uuid::new_v4)
                .to_string()
        } else {
            "null".into()
        };
        if id != "null" && history.versions.iter().any(|v| v.version_id == id) {
            return Err(FileStoreError::CommitProofMismatch);
        }
        let mut removed = Vec::new();
        if id == "null" {
            history.versions.retain(|entry| {
                if entry.version_id == "null" {
                    removed.push(entry.clone());
                    false
                } else {
                    true
                }
            });
        }
        for entry in history.versions.iter().chain(removed.iter()) {
            if let Some(previous) = &entry.object {
                self.backfill_metadata_proof(bucket, previous).await?;
            }
        }
        object.version_id = Some(id.clone());
        history.versions.insert(
            0,
            VersionEntry {
                version_id: id,
                modified_ms: object.last_modified_ms.unwrap_or(0),
                object: Some(object.clone()),
            },
        );
        self.write_history(bucket, &history).await?;
        self.discard_version_data(bucket, removed).await;
        Ok(object)
    }

    async fn discard_version_data(&self, bucket: &str, entries: Vec<VersionEntry>) {
        for entry in entries {
            if let Some(object) = entry.object {
                // Retain only unreachable files on cleanup failure. Never roll
                // back an already committed manifest or expose raw I/O details.
                if let Ok(path) = self.data_path(bucket, &object.data_file) {
                    let _ = fs::remove_file(path).await;
                }
            }
        }
    }

    async fn select_version(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&str>,
    ) -> Result<Option<(FileObjectMetadata, Option<String>)>, FileStoreError> {
        if !self.bucket_exists(bucket).await? {
            return Err(FileStoreError::NoSuchBucket);
        }
        if let Some(id) = version {
            validate_version_id(id)?;
        }
        let history = self.history(bucket, key).await?;
        let entry = match version {
            Some(id) => history
                .versions
                .into_iter()
                .find(|v| v.version_id == id)
                .ok_or(FileStoreError::NoSuchVersion)?,
            None => match history.versions.into_iter().next() {
                Some(v) => v,
                None => return Ok(None),
            },
        };
        let object = entry.object.ok_or(FileStoreError::DeleteMarker {
            version_id: entry.version_id.clone(),
            explicit: version.is_some(),
            last_modified_ms: entry.modified_ms,
        })?;
        let expose =
            version.is_some() || self.versioning(bucket).await? != FileVersioning::Unversioned;
        Ok(Some((object, expose.then_some(entry.version_id))))
    }

    pub async fn open_version(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&str>,
    ) -> Result<Option<FileObjectReader<File>>, FileStoreError> {
        let _guard = self.mutation_lock.lock().await;
        let Some((object, version_id)) = self.select_version(bucket, key, version).await? else {
            return Ok(None);
        };
        let reader = File::open(self.data_path(bucket, &object.data_file)?).await?;
        if reader.metadata().await?.len() != object.size {
            return Err(FileStoreError::CorruptMetadata(
                "version content size mismatch".into(),
            ));
        }
        Ok(Some(FileObjectReader {
            reader,
            object_length: object.size,
            content_type: object.content_type,
            etag: object.etag,
            last_modified_ms: object.last_modified_ms,
            representation_headers: object.representation_headers,
            user_metadata: object.user_metadata,
            tags: object.tags,
            checksum: object.checksum,
            version_id,
        }))
    }

    pub async fn stored_meta_version(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&str>,
    ) -> Result<Option<FileStoredMeta>, FileStoreError> {
        let _guard = self.mutation_lock.lock().await;
        Ok(self
            .select_version(bucket, key, version)
            .await?
            .map(|(metadata, version_id)| FileStoredMeta {
                size: metadata.size,
                content_type: metadata.content_type,
                etag: metadata.etag,
                last_modified_ms: metadata.last_modified_ms,
                representation_headers: metadata.representation_headers,
                user_metadata: metadata.user_metadata,
                tags: metadata.tags,
                checksum: metadata.checksum,
                version_id,
            }))
    }

    pub async fn delete_version(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&str>,
    ) -> Result<FileDeleteResult, FileStoreError> {
        if let Some(id) = version {
            validate_version_id(id)?;
        }
        let store = self.clone();
        let (bucket, key, version) = (
            bucket.to_owned(),
            key.to_owned(),
            version.map(str::to_owned),
        );
        joined(
            tokio::spawn(async move {
                let _guard = store.mutation_lock.lock().await;
                if !store.bucket_exists(&bucket).await? {
                    return Err(FileStoreError::NoSuchBucket);
                }
                let state = store.versioning(&bucket).await?;
                let mut history = store.history(&bucket, &key).await?;
                let mut removed = Vec::new();
                let result = if let Some(id) = &version {
                    let marker = history
                        .versions
                        .iter()
                        .find(|v| &v.version_id == id)
                        .is_some_and(|v| v.object.is_none());
                    history.versions.retain(|v| {
                        if &v.version_id == id {
                            removed.push(v.clone());
                            false
                        } else {
                            true
                        }
                    });
                    FileDeleteResult {
                        existed: !removed.is_empty(),
                        version_id: Some(id.clone()),
                        delete_marker: marker,
                    }
                } else if state != FileVersioning::Unversioned {
                    let id = if state == FileVersioning::Enabled {
                        Uuid::new_v4().to_string()
                    } else {
                        "null".into()
                    };
                    if id == "null" {
                        history.versions.retain(|v| {
                            if v.version_id == "null" {
                                removed.push(v.clone());
                                false
                            } else {
                                true
                            }
                        });
                    }
                    history.versions.insert(
                        0,
                        VersionEntry {
                            version_id: id.clone(),
                            modified_ms: crate::transaction::unix_time_ms(),
                            object: None,
                        },
                    );
                    FileDeleteResult {
                        existed: true,
                        version_id: Some(id),
                        delete_marker: true,
                    }
                } else {
                    removed.append(&mut history.versions);
                    FileDeleteResult {
                        existed: !removed.is_empty(),
                        ..Default::default()
                    }
                };
                for entry in &removed {
                    if let Some(object) = &entry.object {
                        store.backfill_metadata_proof(&bucket, object).await?;
                    }
                }
                // Even empty history is persisted, never removed before its parent
                // directory has a durable absence decision.
                store.write_history(&bucket, &history).await?;
                store.discard_version_data(&bucket, removed).await;
                Ok(result)
            })
            .await,
        )
    }

    pub async fn list_versions(&self, bucket: &str) -> Result<Vec<FileVersion>, FileStoreError> {
        let _guard = self.mutation_lock.lock().await;
        let mut result = Vec::new();
        let mut entries = match fs::read_dir(self.metadata_dir(bucket)?).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(result),
            Err(error) => return Err(error.into()),
        };
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_file()
                || entry.path().extension().is_none_or(|e| e != "json")
            {
                continue;
            }
            let history = read_history(&entry.path()).await?;
            for (index, version) in history.versions.into_iter().enumerate() {
                result.push(FileVersion {
                    key: history.key.clone(),
                    version_id: version.version_id,
                    is_latest: index == 0,
                    delete_marker: version.object.is_none(),
                    last_modified_ms: version.modified_ms,
                    size: version.object.as_ref().map_or(0, |o| o.size),
                    etag: version.object.map_or_else(String::new, |o| o.etag),
                });
            }
        }
        result.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        std::env::temp_dir().join(format!("maskura-versions-{}", Uuid::new_v4()))
    }

    #[tokio::test]
    async fn concurrent_versioned_overwrites_retain_every_commit() {
        let root = root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store.create_bucket("bucket").await.unwrap();
        store
            .set_versioning("bucket", FileVersioning::Enabled)
            .await
            .unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..16 {
            let store = store.clone();
            tasks.spawn(async move {
                store
                    .put("bucket", "key", index.to_string(), "text/plain")
                    .await
                    .unwrap();
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        let versions = store.list_versions("bucket").await.unwrap();
        assert_eq!(versions.len(), 16);
        assert_eq!(versions.iter().filter(|v| v.is_latest).count(), 1);
        assert_eq!(
            versions
                .iter()
                .map(|v| &v.version_id)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            16
        );
        let mut values = std::collections::BTreeSet::new();
        for version in versions {
            let mut object = store
                .open_version("bucket", "key", Some(&version.version_id))
                .await
                .unwrap()
                .unwrap();
            let mut bytes = String::new();
            object.reader.read_to_string(&mut bytes).await.unwrap();
            values.insert(bytes.parse::<usize>().unwrap());
        }
        assert_eq!(values, (0..16).collect());
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn history_faults_do_not_lose_committed_versions() {
        use crate::filesystem_persistence::FaultPoint;
        for fault in [
            FaultPoint::PreWrite,
            FaultPoint::PostWrite,
            FaultPoint::FileSync,
            FaultPoint::Rename,
            FaultPoint::ParentSync,
        ] {
            let root = root();
            let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
            store.create_bucket("bucket").await.unwrap();
            store
                .set_versioning("bucket", FileVersioning::Enabled)
                .await
                .unwrap();
            store
                .put("bucket", "key", "original", "text/plain")
                .await
                .unwrap();
            let original = store.list_versions("bucket").await.unwrap()[0]
                .version_id
                .clone();
            store.persistence.fail_once(fault);
            let error = store
                .put("bucket", "key", "replacement", "text/plain")
                .await
                .unwrap_err();
            assert_eq!(
                matches!(error, FileStoreError::MutationUnknown(_)),
                fault == FaultPoint::ParentSync
            );
            drop(store);
            let store = FileStore::new(root.clone()).await.unwrap();
            let versions = store.list_versions("bucket").await.unwrap();
            assert_eq!(
                versions.len(),
                if fault == FaultPoint::ParentSync {
                    2
                } else {
                    1
                }
            );
            let mut original = store
                .open_version("bucket", "key", Some(&original))
                .await
                .unwrap()
                .unwrap();
            let mut bytes = String::new();
            original.reader.read_to_string(&mut bytes).await.unwrap();
            assert_eq!(bytes, "original");
            fs::remove_dir_all(root).await.unwrap();
        }
    }

    #[tokio::test]
    async fn delete_fault_keeps_history_until_manifest_is_published() {
        use crate::filesystem_persistence::FaultPoint;
        let root = root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store.create_bucket("bucket").await.unwrap();
        store
            .set_versioning("bucket", FileVersioning::Enabled)
            .await
            .unwrap();
        store
            .put("bucket", "key", "keep", "text/plain")
            .await
            .unwrap();
        let id = store.list_versions("bucket").await.unwrap()[0]
            .version_id
            .clone();
        store.persistence.fail_once(FaultPoint::Rename);
        assert!(
            store
                .delete_version("bucket", "key", Some(&id))
                .await
                .is_err()
        );
        assert!(
            store
                .open_version("bucket", "key", Some(&id))
                .await
                .unwrap()
                .is_some()
        );
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn configuration_faults_preserve_the_prior_state_or_report_unknown() {
        use crate::filesystem_persistence::FaultPoint;
        for fault in [
            FaultPoint::PreWrite,
            FaultPoint::PostWrite,
            FaultPoint::FileSync,
            FaultPoint::Rename,
            FaultPoint::ParentSync,
        ] {
            let root = root();
            let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
            store.create_bucket("bucket").await.unwrap();
            store
                .set_versioning("bucket", FileVersioning::Enabled)
                .await
                .unwrap();
            store.persistence.fail_once(fault);
            let error = store
                .set_versioning("bucket", FileVersioning::Suspended)
                .await
                .unwrap_err();
            assert_eq!(
                matches!(error, FileStoreError::MutationUnknown(_)),
                fault == FaultPoint::ParentSync
            );
            drop(store);
            let store = FileStore::new(root.clone()).await.unwrap();
            assert_eq!(
                store.versioning("bucket").await.unwrap(),
                if fault == FaultPoint::ParentSync {
                    FileVersioning::Suspended
                } else {
                    FileVersioning::Enabled
                }
            );
            fs::remove_dir_all(root).await.unwrap();
        }
    }

    #[tokio::test]
    async fn history_at_capacity_rejects_growth_without_losing_versions_and_allows_delete() {
        let root = root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store.create_bucket("bucket").await.unwrap();
        store
            .set_versioning("bucket", FileVersioning::Enabled)
            .await
            .unwrap();
        store
            .put("bucket", "key", "retained", "text/plain")
            .await
            .unwrap();
        let mut history = store.history("bucket", "key").await.unwrap();
        let object = history.versions[0].object.as_mut().unwrap();
        object
            .user_metadata
            .insert("capacity-fixture".into(), String::new());
        let length = serde_json::to_vec(&history).unwrap().len();
        history.versions[0]
            .object
            .as_mut()
            .unwrap()
            .user_metadata
            .insert(
                "capacity-fixture".into(),
                "x".repeat(MAX_HISTORY_BYTES as usize - length),
            );
        store.write_history("bucket", &history).await.unwrap();
        let path = store.metadata_path("bucket", "key").unwrap();
        assert_eq!(fs::metadata(&path).await.unwrap().len(), MAX_HISTORY_BYTES);
        assert!(matches!(
            store.put("bucket", "key", "too much", "text/plain").await,
            Err(FileStoreError::HistoryFull)
        ));
        assert_eq!(store.list_versions("bucket").await.unwrap().len(), 1);
        let mut retained = store
            .open_version("bucket", "key", Some(&history.versions[0].version_id))
            .await
            .unwrap()
            .unwrap();
        let mut bytes = String::new();
        retained.reader.read_to_string(&mut bytes).await.unwrap();
        assert_eq!(bytes, "retained");
        store
            .delete_version("bucket", "key", Some(&history.versions[0].version_id))
            .await
            .unwrap();
        assert!(store.list_versions("bucket").await.unwrap().is_empty());
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_put_waiter_keeps_its_owned_version_publication() {
        let root = root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store.create_bucket("bucket").await.unwrap();
        store
            .set_versioning("bucket", FileVersioning::Enabled)
            .await
            .unwrap();
        store
            .put("bucket", "key", "before", "text/plain")
            .await
            .unwrap();
        let guard = store.mutation_lock.lock().await;
        let task_store = store.clone();
        let waiter =
            tokio::spawn(
                async move { task_store.put("bucket", "key", "after", "text/plain").await },
            );
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while Arc::strong_count(&store.mutation_lock) == 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        waiter.abort();
        let _ = waiter.await;
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if store.list_versions("bucket").await.unwrap().len() == 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(store);
        let store = FileStore::new(root.clone()).await.unwrap();
        let versions = store.list_versions("bucket").await.unwrap();
        for (version, expected) in versions.iter().zip(["after", "before"]) {
            let mut object = store
                .open_version("bucket", "key", Some(&version.version_id))
                .await
                .unwrap()
                .unwrap();
            let mut bytes = String::new();
            object.reader.read_to_string(&mut bytes).await.unwrap();
            assert_eq!(bytes, expected);
        }
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_publication_retains_root_ownership_after_runtime_and_caller_drop() {
        use crate::local_storage::{LocalStorageError, LocalStorageRuntime};
        let root = root();
        let runtime = LocalStorageRuntime::new(root.clone()).await.unwrap();
        let store = runtime.file_store();
        store.create_bucket("bucket").await.unwrap();
        store
            .set_versioning("bucket", FileVersioning::Enabled)
            .await
            .unwrap();
        store
            .put("bucket", "key", "before", "text/plain")
            .await
            .unwrap();
        let guard = store.mutation_lock.clone().lock_owned().await;
        let baseline = Arc::strong_count(&store.mutation_lock);
        let caller = store.clone();
        let waiter =
            tokio::spawn(async move { caller.put("bucket", "key", "after", "text/plain").await });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while Arc::strong_count(&store.mutation_lock) == baseline {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        waiter.abort();
        let _ = waiter.await;
        drop(store);
        drop(runtime);
        assert!(matches!(
            LocalStorageRuntime::new(root.clone()).await,
            Err(LocalStorageError::Persistence(
                PersistenceError::RootAlreadyLocked
            ))
        ));
        drop(guard);
        let reopened = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match LocalStorageRuntime::new(root.clone()).await {
                    Ok(runtime) => break runtime,
                    Err(LocalStorageError::Persistence(PersistenceError::RootAlreadyLocked)) => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("unexpected local reopen failure: {error}"),
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            reopened
                .file_store()
                .list_versions("bucket")
                .await
                .unwrap()
                .len(),
            2
        );
        drop(reopened);
        fs::remove_dir_all(root).await.unwrap();
    }

    #[test]
    fn queued_blocking_publication_keeps_root_lock_after_its_async_owner_is_aborted() {
        use crate::local_storage::LocalStorageRuntime;
        use std::time::Duration;
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        executor.block_on(async {
            let root = root();
            let runtime = LocalStorageRuntime::new(root.clone()).await.unwrap();
            let store = runtime.file_store();
            store.create_bucket("bucket").await.unwrap();
            let lease = store._root_lock.as_ref().unwrap().clone();
            let baseline = Arc::strong_count(&lease);
            let (release, blocked) = std::sync::mpsc::channel();
            let (started, ready) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                let _ = blocked.recv_timeout(Duration::from_secs(5));
            });
            ready.recv_timeout(Duration::from_secs(2)).unwrap();
            let path = store.bucket_dir("bucket").unwrap().join("versioning.json");
            let bytes = serde_json::to_vec(&BucketVersioning {
                schema_version: 1,
                state: FileVersioning::Enabled,
            })
            .unwrap();
            let owner_store = store.clone();
            let owner =
                tokio::spawn(async move { owner_store.write_version_bytes(path, bytes).await });
            tokio::time::timeout(Duration::from_secs(2), async {
                while Arc::strong_count(&lease) == baseline {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            owner.abort();
            let _ = owner.await;
            drop(store);
            drop(runtime);
            drop(lease);
            assert!(matches!(
                FilesystemPersistence::default().acquire_root_lock(&root),
                Err(PersistenceError::RootAlreadyLocked)
            ));
            release.send(()).unwrap();
            blocker.await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    match FilesystemPersistence::default().acquire_root_lock(&root) {
                        Ok(lease) => {
                            drop(lease);
                            break;
                        }
                        Err(PersistenceError::RootAlreadyLocked) => tokio::task::yield_now().await,
                        Err(error) => panic!("unexpected root-lock probe failure: {error}"),
                    }
                }
            })
            .await
            .unwrap();
            let reopened = LocalStorageRuntime::new(root.clone()).await.unwrap();
            assert_eq!(
                reopened.file_store().versioning("bucket").await.unwrap(),
                FileVersioning::Enabled
            );
            drop(reopened);
            fs::remove_dir_all(root).await.unwrap();
        });
    }

    #[tokio::test]
    async fn unknown_and_duplicate_history_and_oversized_config_fail_closed() {
        let root = root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store.create_bucket("bucket").await.unwrap();
        store
            .set_versioning("bucket", FileVersioning::Enabled)
            .await
            .unwrap();
        store.put("bucket", "key", "A", "text/plain").await.unwrap();
        let path = store.metadata_path("bucket", "key").unwrap();
        let bytes = fs::read(&path).await.unwrap();
        let mut malformed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        malformed["versions"][0]
            .as_object_mut()
            .unwrap()
            .remove("object");
        fs::write(&path, serde_json::to_vec(&malformed).unwrap())
            .await
            .unwrap();
        assert!(store.list_versions("bucket").await.is_err());
        let mut history: ObjectHistory = serde_json::from_slice(&bytes).unwrap();
        history.versions.push(history.versions[0].clone());
        fs::write(&path, serde_json::to_vec(&history).unwrap())
            .await
            .unwrap();
        assert!(store.list_versions("bucket").await.is_err());
        history.versions.pop();
        history.schema_version = 99;
        fs::write(&path, serde_json::to_vec(&history).unwrap())
            .await
            .unwrap();
        assert!(store.open_version("bucket", "key", None).await.is_err());
        fs::write(&path, bytes).await.unwrap();
        fs::write(
            store.bucket_dir("bucket").unwrap().join("versioning.json"),
            vec![b' '; MAX_CONFIG_BYTES as usize + 1],
        )
        .await
        .unwrap();
        assert!(store.versioning("bucket").await.is_err());
        assert!(FileStore::new(root.clone()).await.is_err());
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn multipart_unknown_publication_replays_the_same_version_after_marker_and_restart() {
        use crate::filesystem_persistence::FaultPoint;
        let root = root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store.create_bucket("bucket").await.unwrap();
        store
            .set_versioning("bucket", FileVersioning::Enabled)
            .await
            .unwrap();
        let body = b"multipart";
        let context = LocalCommitContext {
            operation_id: Uuid::new_v4(),
            generation_id: Uuid::new_v4(),
            completion_fence: 7,
            bucket: "bucket".into(),
            key: "key".into(),
            content_type: "text/plain".into(),
            expected_size: body.len() as u64,
            expected_sha256: hex::encode(Sha256::digest(body)),
            representation_headers: BTreeMap::new(),
            user_metadata: BTreeMap::new(),
            tags: BTreeMap::new(),
            checksum: None,
        };
        let (path, mut file) = store.create_temp_file("bucket", "key").await.unwrap();
        file.write_all(body).await.unwrap();
        file.sync_all().await.unwrap();
        drop(file);
        store.prepare_transaction(&context).await.unwrap();
        store.persistence.fail_once(FaultPoint::ParentSync);
        assert!(matches!(
            store.publish_transaction(&path, &context, "\"etag\"").await,
            Err(FileStoreError::MutationUnknown(_))
        ));
        store.delete_version("bucket", "key", None).await.unwrap();
        drop(store);
        let store = FileStore::new(root.clone()).await.unwrap();
        let proof = match store
            .probe_commit(context.operation_id, context.generation_id)
            .await
            .unwrap()
        {
            LocalCommitProbe::Published(proof) => proof,
            _ => panic!("retained version must establish exact publication"),
        };
        assert_eq!(
            proof.version_id.as_deref(),
            Some(context.generation_id.to_string().as_str())
        );
        let repaired = store
            .backfill_generation_proof("bucket", "key", context.operation_id, context.generation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(proof, repaired);
        let replay = store
            .publish_transaction(&path, &context, "\"etag\"")
            .await
            .unwrap();
        assert_eq!(replay, repaired);
        assert_eq!(store.list_versions("bucket").await.unwrap().len(), 2);
        store
            .delete_version("bucket", "key", proof.version_id.as_deref())
            .await
            .unwrap();
        assert!(matches!(
            store
                .probe_commit(context.operation_id, context.generation_id)
                .await
                .unwrap(),
            LocalCommitProbe::Committed(_)
        ));
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_configuration_waiter_does_not_cancel_owned_publication() {
        let root = root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store.create_bucket("bucket").await.unwrap();
        let guard = store.mutation_lock.lock().await;
        let task_store = store.clone();
        let waiter = tokio::spawn(async move {
            task_store
                .set_versioning("bucket", FileVersioning::Enabled)
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while Arc::strong_count(&store.mutation_lock) == 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        waiter.abort();
        let _ = waiter.await;
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if store.versioning("bucket").await.unwrap() == FileVersioning::Enabled {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn versions_keep_legacy_and_overwrites_across_reopen() {
        let root = root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store
            .put("bucket", "key", "legacy", "text/plain")
            .await
            .unwrap();
        store
            .set_versioning("bucket", FileVersioning::Enabled)
            .await
            .unwrap();
        store.put("bucket", "key", "A", "text/a").await.unwrap();
        store.put("bucket", "key", "B", "text/b").await.unwrap();
        let versions = store.list_versions("bucket").await.unwrap();
        assert_eq!(versions.len(), 3);
        assert_ne!(versions[0].version_id, versions[1].version_id);
        assert_eq!(versions[2].version_id, "null");
        assert!(versions[0].is_latest);
        assert!(!versions[1].is_latest);
        drop(store);
        let store = FileStore::new(root.clone()).await.unwrap();
        assert_eq!(
            store.versioning("bucket").await.unwrap(),
            FileVersioning::Enabled
        );
        for (entry, bytes) in versions.iter().zip(["B", "A", "legacy"]) {
            let mut object = store
                .open_version("bucket", "key", Some(&entry.version_id))
                .await
                .unwrap()
                .unwrap();
            let mut actual = Vec::new();
            object.reader.read_to_end(&mut actual).await.unwrap();
            assert_eq!(actual, bytes.as_bytes());
            assert_eq!(
                object.version_id.as_deref(),
                Some(entry.version_id.as_str())
            );
        }
        assert!(matches!(
            store
                .open_version("bucket", "key", Some(&Uuid::new_v4().to_string()))
                .await,
            Err(FileStoreError::NoSuchVersion)
        ));
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn suspended_null_replacement_markers_and_exact_delete() {
        let root = root();
        let store = Arc::new(FileStore::new(root.clone()).await.unwrap());
        store.create_bucket("bucket").await.unwrap();
        store
            .set_versioning("bucket", FileVersioning::Enabled)
            .await
            .unwrap();
        store.put("bucket", "key", "A", "text/plain").await.unwrap();
        let id = store.list_versions("bucket").await.unwrap()[0]
            .version_id
            .clone();
        let marker = store.delete_version("bucket", "key", None).await.unwrap();
        assert!(marker.delete_marker);
        assert!(matches!(
            store.open_version("bucket", "key", None).await,
            Err(FileStoreError::DeleteMarker {
                explicit: false,
                ..
            })
        ));
        assert!(store.list_objects("bucket").await.unwrap().is_empty());
        assert!(matches!(
            store.delete_bucket("bucket").await,
            Err(FileStoreError::BucketNotEmpty)
        ));
        assert!(
            store
                .open_version("bucket", "key", Some(&id))
                .await
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            store
                .open_version("bucket", "key", marker.version_id.as_deref())
                .await,
            Err(FileStoreError::DeleteMarker { explicit: true, .. })
        ));
        store
            .delete_version("bucket", "key", marker.version_id.as_deref())
            .await
            .unwrap();
        assert!(store.open("bucket", "key").await.unwrap().is_some());
        store
            .set_versioning("bucket", FileVersioning::Suspended)
            .await
            .unwrap();
        store
            .put("bucket", "key", "null A", "text/plain")
            .await
            .unwrap();
        store
            .put("bucket", "key", "null B", "text/plain")
            .await
            .unwrap();
        assert_eq!(store.list_versions("bucket").await.unwrap().len(), 2);
        let marker = store.delete_version("bucket", "key", None).await.unwrap();
        assert_eq!(marker.version_id.as_deref(), Some("null"));
        assert_eq!(store.list_versions("bucket").await.unwrap().len(), 2);
        store
            .delete_version("bucket", "key", Some("null"))
            .await
            .unwrap();
        store
            .delete_version("bucket", "key", Some(&id))
            .await
            .unwrap();
        assert!(store.list_versions("bucket").await.unwrap().is_empty());
        assert!(store.delete_bucket("bucket").await.unwrap());
        fs::remove_dir_all(root).await.unwrap();
    }
}
