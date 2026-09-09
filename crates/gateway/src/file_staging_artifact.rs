use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use async_trait::async_trait;
use tokio::io::AsyncReadExt as _;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::filesystem_persistence::{create_private_dir_all, sync_parent};
use crate::multipart_staging::{
    ARTIFACT_PREFIX, MAX_PARTS, StagedArtifact, StagingArtifactReader, StagingArtifactStore,
    StagingError,
};

const MAX_ARTIFACT_BYTES: u64 = 5 * 1024 * 1024 * 1024 * 1024;
const MAX_ARTIFACTS: usize = 1_000_000;

#[derive(Debug)]
pub(crate) struct FileStagingArtifactStore {
    artifacts: PathBuf,
    temporary: PathBuf,
    mutation_lock: Arc<Mutex<()>>,
    #[cfg(test)]
    faults: Arc<std::sync::Mutex<Vec<FaultPoint>>>,
}

impl FileStagingArtifactStore {
    pub(crate) fn open(root: PathBuf) -> Result<Self, StagingError> {
        ensure_private_directory(&root)?;
        let artifacts = root.join("artifacts");
        let temporary = root.join("tmp");
        ensure_private_directory(&artifacts)?;
        ensure_private_directory(&temporary)?;
        remove_abandoned_temporary_files(&artifacts)?;
        Ok(Self {
            artifacts,
            temporary,
            mutation_lock: Arc::new(Mutex::new(())),
            #[cfg(test)]
            faults: Arc::default(),
        })
    }

    pub(crate) fn temporary_root(&self) -> &Path {
        &self.temporary
    }

    fn canonical_path(&self, key: &str) -> Result<PathBuf, StagingError> {
        let artifact = ArtifactKey::parse(key)?;
        Ok(self
            .artifacts
            .join(artifact.tenant_id)
            .join(artifact.upload_id.to_string())
            .join(artifact.part_number.to_string())
            .join(format!("{}.part", artifact.attempt)))
    }

    fn validate_source(&self, source: &Path) -> Result<(), StagingError> {
        if source.parent() != Some(self.temporary.as_path()) {
            return Err(invalid(
                "artifact source is outside the controlled temporary directory",
            ));
        }
        validate_regular_file(source, "artifact source validation")?;
        let size = std::fs::metadata(source)
            .map_err(|error| persistence("artifact source metadata", error))?
            .len();
        if size > MAX_ARTIFACT_BYTES {
            return Err(invalid("artifact exceeds the 5 TiB size limit"));
        }
        Ok(())
    }

    fn prepare_parent(&self, path: &Path) -> Result<(), StagingError> {
        let relative = path
            .parent()
            .and_then(|parent| parent.strip_prefix(&self.artifacts).ok())
            .ok_or_else(|| invalid("artifact destination has no controlled parent"))?;
        let mut current = self.artifacts.clone();
        validate_directory(&current, "artifact root validation")?;
        for component in relative.components() {
            current.push(component.as_os_str());
            ensure_private_directory(&current)?;
        }
        Ok(())
    }

    fn validate_ancestors(&self, path: &Path) -> Result<(), StagingError> {
        let relative = path
            .parent()
            .and_then(|parent| parent.strip_prefix(&self.artifacts).ok())
            .ok_or_else(|| invalid("artifact path has no controlled parent"))?;
        let mut current = self.artifacts.clone();
        validate_directory(&current, "artifact root validation")?;
        for component in relative.components() {
            current.push(component.as_os_str());
            validate_directory(&current, "artifact directory validation")?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn fail_once(&self, point: FaultPoint) {
        self.faults.lock().unwrap().push(point);
    }

    #[cfg(test)]
    fn fault(&self, point: FaultPoint, published: bool) -> Result<(), StagingError> {
        let mut faults = self.faults.lock().unwrap();
        if let Some(index) = faults.iter().position(|candidate| *candidate == point) {
            faults.remove(index);
            let qualifier = if published { " may have committed" } else { "" };
            return Err(StagingError::Persistence(format!(
                "injected artifact publication failure{qualifier}"
            )));
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn fault(&self, _point: FaultPoint, _published: bool) -> Result<(), StagingError> {
        Ok(())
    }
}

#[async_trait]
impl StagingArtifactStore for FileStagingArtifactStore {
    async fn put_file(&self, key: &str, source: &Path) -> Result<(), StagingError> {
        let _guard = self.mutation_lock.lock().await;
        self.validate_source(source)?;
        let destination = self.canonical_path(key)?;
        self.prepare_parent(&destination)?;
        reject_non_regular_if_present(&destination, "artifact destination validation")?;
        let name = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("artifact destination has no file name"))?;
        let temporary = destination.with_file_name(format!(".{name}.{}.tmp", Uuid::now_v7()));

        self.fault(FaultPoint::BeforeMove, false)?;
        std::fs::rename(source, &temporary)
            .map_err(|error| persistence("same-filesystem artifact move", error))?;
        let result = (|| {
            sync_parent(source)
                .map_err(|error| mutation_unknown("artifact source parent sync", error))?;
            set_private_file_permissions(&temporary)?;
            validate_regular_file(&temporary, "artifact temporary validation")?;
            let file = std::fs::File::open(&temporary)
                .map_err(|error| persistence("artifact temporary open", error))?;
            file.sync_all()
                .map_err(|error| persistence("artifact file sync", error))?;
            drop(file);
            self.fault(FaultPoint::BeforePublish, false)?;
            std::fs::rename(&temporary, &destination)
                .map_err(|error| persistence("artifact publication", error))?;
            self.fault(FaultPoint::AfterPublish, true)?;
            sync_parent(&destination)
                .map_err(|error| mutation_unknown("artifact parent sync", error))?;
            Ok(())
        })();
        if temporary.exists() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    async fn get(&self, key: &str) -> Result<StagingArtifactReader, StagingError> {
        let path = self.canonical_path(key)?;
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(StagingError::NotFound);
            }
            Err(error) => return Err(persistence("artifact metadata", error)),
        };
        self.validate_ancestors(&path)?;
        if !metadata.file_type().is_file() {
            return Err(invalid("artifact is not a regular file"));
        }
        if metadata.len() > MAX_ARTIFACT_BYTES {
            return Err(invalid("artifact exceeds the 5 TiB size limit"));
        }
        let file = tokio::fs::File::open(&path)
            .await
            .map_err(|error| persistence("artifact open", error))?;
        let opened = file
            .metadata()
            .await
            .map_err(|error| persistence("opened artifact metadata", error))?;
        if !opened.is_file() || opened.len() != metadata.len() {
            return Err(invalid("artifact changed while it was opened"));
        }
        Ok(Box::pin(file.take(metadata.len())))
    }

    async fn delete(&self, key: &str) -> Result<(), StagingError> {
        let _guard = self.mutation_lock.lock().await;
        let path = self.canonical_path(key)?;
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(persistence("artifact delete metadata", error)),
        }
        self.validate_ancestors(&path)?;
        reject_non_regular_if_present(&path, "artifact delete validation")?;
        match std::fs::remove_file(&path) {
            Ok(()) => sync_parent(&path)
                .map_err(|error| mutation_unknown("artifact delete parent sync", error))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(persistence("artifact delete", error)),
        }
        remove_empty_parents(path.parent(), &self.artifacts)?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<StagedArtifact>, StagingError> {
        validate_prefix(prefix)?;
        validate_directory(&self.artifacts, "artifact root validation")?;
        let mut pending = vec![(self.artifacts.clone(), 0_usize)];
        let mut artifacts = Vec::new();
        while let Some((directory, depth)) = pending.pop() {
            let entries = std::fs::read_dir(&directory)
                .map_err(|error| persistence("artifact directory read", error))?;
            for entry in entries {
                let entry = entry.map_err(|error| persistence("artifact entry read", error))?;
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path)
                    .map_err(|error| persistence("artifact entry metadata", error))?;
                if metadata.file_type().is_symlink() {
                    return Err(invalid("artifact namespace contains a symlink"));
                }
                if metadata.is_dir() {
                    if depth >= 3 || !valid_path_component(&entry.file_name()) {
                        return Err(invalid("artifact namespace contains an unknown directory"));
                    }
                    pending.push((path, depth + 1));
                    continue;
                }
                if !metadata.is_file() || depth != 3 {
                    return Err(invalid("artifact namespace contains an unknown file"));
                }
                let key = artifact_key_from_path(&self.artifacts, &path)?;
                if key.starts_with(prefix) {
                    let modified_at_ms = i64::try_from(
                        metadata
                            .modified()
                            .map_err(|error| persistence("artifact modification time", error))?
                            .duration_since(UNIX_EPOCH)
                            .map_err(|_| invalid("artifact modification time predates the epoch"))?
                            .as_millis(),
                    )
                    .map_err(|_| invalid("artifact modification time is out of range"))?;
                    artifacts.push(StagedArtifact {
                        key,
                        modified_at_ms,
                    });
                    if artifacts.len() > MAX_ARTIFACTS {
                        return Err(invalid("artifact listing exceeds the entry limit"));
                    }
                }
            }
        }
        artifacts.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(artifacts)
    }
}

struct ArtifactKey<'a> {
    tenant_id: &'a str,
    upload_id: Uuid,
    part_number: u32,
    attempt: u32,
}

impl<'a> ArtifactKey<'a> {
    fn parse(key: &'a str) -> Result<Self, StagingError> {
        let suffix = key
            .strip_prefix(ARTIFACT_PREFIX)
            .ok_or_else(|| invalid("artifact key is outside the multipart namespace"))?;
        let mut components = suffix.split('/');
        let tenant_id = components.next().unwrap_or_default();
        let upload_id = components.next().unwrap_or_default();
        let part_number = components.next().unwrap_or_default();
        let attempt = components.next().unwrap_or_default();
        if components.next().is_some() || !valid_identifier(tenant_id) || tenant_id.len() > 128 {
            return Err(invalid("artifact key has invalid components"));
        }
        let upload_id = Uuid::parse_str(upload_id)
            .map_err(|_| invalid("artifact key has an invalid upload ID"))?;
        if upload_id.to_string() != components_value(suffix, 1) {
            return Err(invalid("artifact key has a non-canonical upload ID"));
        }
        let part_number = part_number
            .parse::<u32>()
            .map_err(|_| invalid("artifact key has an invalid part number"))?;
        let attempt = attempt
            .parse::<u32>()
            .map_err(|_| invalid("artifact key has an invalid attempt"))?;
        if part_number == 0 || part_number > MAX_PARTS || attempt == 0 {
            return Err(invalid("artifact key has an out-of-range number"));
        }
        Ok(Self {
            tenant_id,
            upload_id,
            part_number,
            attempt,
        })
    }
}

fn artifact_key_from_path(root: &Path, path: &Path) -> Result<String, StagingError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| invalid("artifact path escaped its root"))?;
    let components = relative
        .components()
        .map(|component| component.as_os_str().to_str().unwrap_or_default())
        .collect::<Vec<_>>();
    if components.len() != 4 {
        return Err(invalid("artifact path has an invalid depth"));
    }
    let attempt = components[3]
        .strip_suffix(".part")
        .ok_or_else(|| invalid("artifact file has an unknown suffix"))?;
    let key = format!(
        "{ARTIFACT_PREFIX}{}/{}/{}/{}",
        components[0], components[1], components[2], attempt
    );
    ArtifactKey::parse(&key)?;
    Ok(key)
}

fn validate_prefix(prefix: &str) -> Result<(), StagingError> {
    if prefix.len() > 512
        || !prefix.starts_with(ARTIFACT_PREFIX)
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
        || prefix.contains("//")
        || prefix
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        return Err(invalid("artifact list prefix is invalid"));
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn components_value(value: &str, index: usize) -> &str {
    value.split('/').nth(index).unwrap_or_default()
}

fn valid_path_component(value: &std::ffi::OsStr) -> bool {
    value.to_str().is_some_and(valid_identifier)
}

fn ensure_private_directory(path: &Path) -> Result<(), StagingError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(invalid("artifact directory is not a directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().map(Path::to_path_buf);
            create_private_dir_all(path)
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            if let Some(parent) = parent {
                sync_parent(&parent.join("entry"))
                    .map_err(|error| persistence("artifact directory parent sync", error))?;
            }
        }
        Err(error) => return Err(persistence("artifact directory metadata", error)),
    }
    validate_directory(path, "artifact directory validation")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| persistence("artifact directory permissions", error))?;
    }
    Ok(())
}

fn validate_directory(path: &Path, operation: &'static str) -> Result<(), StagingError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| persistence(operation, error))?;
    if !metadata.file_type().is_dir() {
        return Err(invalid(
            "artifact namespace contains a non-directory ancestor",
        ));
    }
    Ok(())
}

fn validate_regular_file(path: &Path, operation: &'static str) -> Result<(), StagingError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| persistence(operation, error))?;
    if !metadata.file_type().is_file() {
        return Err(invalid("artifact path is not a regular file"));
    }
    Ok(())
}

fn reject_non_regular_if_present(path: &Path, operation: &'static str) -> Result<(), StagingError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(invalid("artifact canonical path is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(persistence(operation, error)),
    }
}

fn set_private_file_permissions(path: &Path) -> Result<(), StagingError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| persistence("artifact permissions", error))?;
    }
    Ok(())
}

fn remove_abandoned_temporary_files(root: &Path) -> Result<(), StagingError> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)
            .map_err(|error| persistence("artifact startup scan", error))?
        {
            let entry = entry.map_err(|error| persistence("artifact startup entry", error))?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| persistence("artifact startup metadata", error))?;
            if metadata.file_type().is_symlink() {
                return Err(invalid("artifact namespace contains a symlink"));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with('.') && name.ends_with(".tmp"))
            {
                std::fs::remove_file(&path)
                    .map_err(|error| persistence("abandoned artifact removal", error))?;
                sync_parent(&path)
                    .map_err(|error| mutation_unknown("abandoned artifact parent sync", error))?;
            }
        }
    }
    Ok(())
}

fn remove_empty_parents(mut current: Option<&Path>, root: &Path) -> Result<(), StagingError> {
    while let Some(directory) = current {
        if directory == root {
            break;
        }
        match std::fs::remove_dir(directory) {
            Ok(()) => {
                sync_parent(directory)
                    .map_err(|error| mutation_unknown("artifact directory removal sync", error))?;
                current = directory.parent();
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::DirectoryNotEmpty | std::io::ErrorKind::NotFound
                ) =>
            {
                break;
            }
            Err(error) => return Err(persistence("artifact directory removal", error)),
        }
    }
    Ok(())
}

fn invalid(message: &'static str) -> StagingError {
    StagingError::Persistence(message.to_string())
}

fn persistence(operation: &'static str, error: std::io::Error) -> StagingError {
    StagingError::Persistence(format!("{operation} failed: {error}"))
}

fn mutation_unknown(operation: &'static str, error: std::io::Error) -> StagingError {
    StagingError::Persistence(format!("{operation} may have committed: {error}"))
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPoint {
    BeforeMove,
    BeforePublish,
    AfterPublish,
}

#[cfg(not(test))]
#[derive(Clone, Copy)]
enum FaultPoint {
    BeforeMove,
    BeforePublish,
    AfterPublish,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("maskura-artifacts-{}", Uuid::now_v7()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn key(part: u32, attempt: u32) -> String {
        format!("{ARTIFACT_PREFIX}tenant-a/{}/{part}/{attempt}", Uuid::nil())
    }

    fn source(store: &FileStagingArtifactStore, bytes: &[u8]) -> PathBuf {
        let path = store
            .temporary_root()
            .join(format!("{}.tmp", Uuid::now_v7()));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    async fn read(store: &FileStagingArtifactStore, key: &str) -> Result<Vec<u8>, StagingError> {
        let mut reader = store.get(key).await?;
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| persistence("test artifact read", error))?;
        Ok(bytes)
    }

    #[tokio::test]
    async fn file_store_matches_artifact_contract_and_restarts() {
        let directory = TempDir::new();
        let root = directory.0.join("multipart");
        let store = FileStagingArtifactStore::open(root.clone()).unwrap();
        crate::multipart_staging::assert_artifact_store_contract(&store, store.temporary_root())
            .await;
        let first = key(2, 1);
        let second = key(1, 1);

        store
            .put_file(&first, &source(&store, b"first"))
            .await
            .unwrap();
        store
            .put_file(&second, &source(&store, b"second"))
            .await
            .unwrap();
        store
            .put_file(&first, &source(&store, b"replacement"))
            .await
            .unwrap();
        assert_eq!(read(&store, &first).await.unwrap(), b"replacement");
        let listed = store.list(ARTIFACT_PREFIX).await.unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|artifact| &artifact.key)
                .collect::<Vec<_>>(),
            vec![&second, &first]
        );
        assert!(listed.iter().all(|artifact| artifact.modified_at_ms > 0));

        drop(store);
        let restarted = FileStagingArtifactStore::open(root).unwrap();
        assert_eq!(read(&restarted, &first).await.unwrap(), b"replacement");
        restarted.delete(&first).await.unwrap();
        restarted.delete(&first).await.unwrap();
        assert!(matches!(
            restarted.get(&first).await,
            Err(StagingError::NotFound)
        ));
        drop(restarted);
        let after_delete_restart =
            FileStagingArtifactStore::open(directory.0.join("multipart")).unwrap();
        assert!(matches!(
            after_delete_restart.get(&first).await,
            Err(StagingError::NotFound)
        ));
    }

    #[tokio::test]
    async fn readers_are_bounded_to_opened_file_length() {
        let directory = TempDir::new();
        let store = FileStagingArtifactStore::open(directory.0.join("multipart")).unwrap();
        let artifact_key = key(1, 1);
        store
            .put_file(&artifact_key, &source(&store, b"bounded"))
            .await
            .unwrap();
        let mut reader = store.get(&artifact_key).await.unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(store.canonical_path(&artifact_key).unwrap())
            .unwrap()
            .write_all(b"-later")
            .unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"bounded");
    }

    #[tokio::test]
    async fn rejects_traversal_sources_and_symlinks() {
        let directory = TempDir::new();
        let store = FileStagingArtifactStore::open(directory.0.join("multipart")).unwrap();
        let outside = directory.0.join("outside");
        std::fs::write(&outside, b"outside").unwrap();
        assert!(store.put_file(&key(1, 1), &outside).await.is_err());
        let controlled = source(&store, b"controlled");
        assert!(
            store
                .put_file("multipart/../bad/1/1", &controlled)
                .await
                .is_err()
        );

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, store.temporary_root().join("link.tmp")).unwrap();
            assert!(
                store
                    .put_file(&key(1, 1), &store.temporary_root().join("link.tmp"))
                    .await
                    .is_err()
            );
            let canonical = store.canonical_path(&key(1, 1)).unwrap();
            store.prepare_parent(&canonical).unwrap();
            std::os::unix::fs::symlink(&outside, canonical).unwrap();
            assert!(store.get(&key(1, 1)).await.is_err());
            assert!(store.list(ARTIFACT_PREFIX).await.is_err());
        }
    }

    #[tokio::test]
    async fn publication_failures_never_expose_partial_replacements() {
        let directory = TempDir::new();
        let root = directory.0.join("multipart");
        let store = FileStagingArtifactStore::open(root.clone()).unwrap();
        let artifact_key = key(1, 1);
        store
            .put_file(&artifact_key, &source(&store, b"old"))
            .await
            .unwrap();

        store.fail_once(FaultPoint::BeforePublish);
        assert!(
            store
                .put_file(&artifact_key, &source(&store, b"unpublished"))
                .await
                .is_err()
        );
        assert_eq!(read(&store, &artifact_key).await.unwrap(), b"old");

        store.fail_once(FaultPoint::AfterPublish);
        assert!(
            store
                .put_file(&artifact_key, &source(&store, b"published"))
                .await
                .is_err()
        );
        assert_eq!(read(&store, &artifact_key).await.unwrap(), b"published");
        drop(store);
        let restarted = FileStagingArtifactStore::open(root).unwrap();
        assert_eq!(read(&restarted, &artifact_key).await.unwrap(), b"published");
    }

    #[tokio::test]
    async fn startup_removes_temps_but_unknown_files_fail_closed() {
        let directory = TempDir::new();
        let root = directory.0.join("multipart");
        let store = FileStagingArtifactStore::open(root.clone()).unwrap();
        let canonical = store.canonical_path(&key(1, 1)).unwrap();
        store.prepare_parent(&canonical).unwrap();
        let abandoned = canonical.parent().unwrap().join(".attempt.part.dead.tmp");
        std::fs::write(&abandoned, b"ciphertext").unwrap();
        drop(store);
        let restarted = FileStagingArtifactStore::open(root).unwrap();
        assert!(!abandoned.exists());
        std::fs::write(canonical.parent().unwrap().join("unknown.bin"), b"unknown").unwrap();
        assert!(restarted.list(ARTIFACT_PREFIX).await.is_err());
    }
}
