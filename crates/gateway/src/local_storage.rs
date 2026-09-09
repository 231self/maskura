use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::file_store::{FileStore, FileStoreError};
use crate::filesystem_persistence::{FilesystemPersistence, PersistenceError, RootLock};

#[derive(Debug, thiserror::Error)]
pub(crate) enum LocalStorageError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    FileStore(#[from] FileStoreError),
}

/// Owns all process-scoped resources for one local filesystem storage root.
#[derive(Debug)]
pub(crate) struct LocalStorageRuntime {
    root: PathBuf,
    file_store: Arc<FileStore>,
    _root_lock: RootLock,
}

impl LocalStorageRuntime {
    pub(crate) async fn new(root: PathBuf) -> Result<Self, LocalStorageError> {
        let root_lock = FilesystemPersistence::default().acquire_root_lock(&root)?;
        let file_store = Arc::new(FileStore::open_locked(root.clone()).await?);
        Ok(Self {
            root,
            file_store,
            _root_lock: root_lock,
        })
    }

    pub(crate) fn file_store(&self) -> Arc<FileStore> {
        self.file_store.clone()
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    #[allow(dead_code, reason = "used by subsequent local Phase 2 components")]
    pub(crate) fn internal_root(&self) -> PathBuf {
        self.root.join(".maskura")
    }

    #[allow(dead_code, reason = "used by subsequent local Phase 2 components")]
    pub(crate) fn wrapping_key_path(&self) -> PathBuf {
        self.internal_root().join("wrapping.key")
    }

    #[allow(dead_code, reason = "used by subsequent local Phase 2 components")]
    pub(crate) fn multipart_root(&self) -> PathBuf {
        self.internal_root().join("multipart")
    }

    #[allow(dead_code, reason = "used by subsequent local Phase 2 components")]
    pub(crate) fn journal_root(&self) -> PathBuf {
        self.internal_root().join("journal")
    }

    #[allow(dead_code, reason = "used by subsequent local Phase 2 components")]
    pub(crate) fn commits_root(&self) -> PathBuf {
        self.internal_root().join("commits")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("maskura-local-runtime-{}", Uuid::now_v7()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn second_runtime_for_same_root_fails() {
        let directory = TempDir::new();
        let first = LocalStorageRuntime::new(directory.path().to_path_buf())
            .await
            .unwrap();

        let error = LocalStorageRuntime::new(directory.path().to_path_buf())
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            LocalStorageError::Persistence(PersistenceError::RootAlreadyLocked)
        ));
        drop(first);
    }

    #[tokio::test]
    async fn runtimes_for_distinct_roots_can_coexist() {
        let first_directory = TempDir::new();
        let second_directory = TempDir::new();

        let first = LocalStorageRuntime::new(first_directory.path().to_path_buf())
            .await
            .unwrap();
        let second = LocalStorageRuntime::new(second_directory.path().to_path_buf())
            .await
            .unwrap();

        assert_eq!(first.file_store().root(), first_directory.path());
        assert_eq!(second.file_store().root(), second_directory.path());
    }

    #[tokio::test]
    async fn dropping_runtime_releases_root_lock() {
        let directory = TempDir::new();
        let runtime = LocalStorageRuntime::new(directory.path().to_path_buf())
            .await
            .unwrap();
        drop(runtime);

        LocalStorageRuntime::new(directory.path().to_path_buf())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn stale_temp_cleanup_starts_only_after_lock_acquisition() {
        let directory = TempDir::new();
        let stale_temp = directory
            .path()
            .join("buckets")
            .join("bucket")
            .join("tmp")
            .join("stale.tmp");
        std::fs::create_dir_all(stale_temp.parent().unwrap()).unwrap();
        std::fs::write(&stale_temp, b"stale").unwrap();
        let held_lock = FilesystemPersistence::default()
            .acquire_root_lock(directory.path())
            .unwrap();

        let error = LocalStorageRuntime::new(directory.path().to_path_buf())
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            LocalStorageError::Persistence(PersistenceError::RootAlreadyLocked)
        ));
        assert!(stale_temp.exists());

        drop(held_lock);
        let runtime = LocalStorageRuntime::new(directory.path().to_path_buf())
            .await
            .unwrap();
        assert!(!stale_temp.exists());
        assert_eq!(runtime.root(), directory.path());
        assert_eq!(runtime.internal_root(), directory.path().join(".maskura"));
        assert_eq!(
            runtime.wrapping_key_path(),
            directory.path().join(".maskura/wrapping.key")
        );
        assert_eq!(
            runtime.multipart_root(),
            directory.path().join(".maskura/multipart")
        );
        assert_eq!(
            runtime.journal_root(),
            directory.path().join(".maskura/journal")
        );
        assert_eq!(
            runtime.commits_root(),
            directory.path().join(".maskura/commits")
        );
    }
}
