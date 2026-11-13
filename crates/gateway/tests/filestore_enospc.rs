//! Executed only on a dedicated, bounded tmpfs by test-filestore-enospc.sh.
#![cfg(target_os = "linux")]

use maskura_gateway::file_store::{FileStore, FileStoreError, FileVersioning};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore = "requires the dedicated 8 MiB tmpfs from scripts/test-filestore-enospc.sh"]
async fn full_filesystem_keeps_exact_history_and_configuration_without_false_success() {
    let mount = std::path::PathBuf::from(
        std::env::var_os("MASKURA_VERSIONING_ENOSPC_ROOT").expect("owned tmpfs required"),
    );
    assert!(mount.is_absolute() && mount.is_dir());
    let root = mount.join(format!("filestore-{}", uuid::Uuid::new_v4()));
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
    let version = store.list_versions("bucket").await.unwrap()[0]
        .version_id
        .clone();

    // Larger than the entire owned filesystem: real ENOSPC during content write.
    let error = store
        .put("bucket", "key", vec![b'x'; 12 * 1024 * 1024], "text/plain")
        .await
        .unwrap_err();
    assert!(matches!(error, FileStoreError::Io(ref error) if error.raw_os_error() == Some(28)));

    // Exhaust only the bounded tmpfs, then attempt configuration/manifest commits.
    let filler = root.join("capacity-fixture");
    let mut file = tokio::fs::File::create(&filler).await.unwrap();
    let block = [0_u8; 64 * 1024];
    let mut total = 0;
    loop {
        match file.write_all(&block).await {
            Ok(()) => {
                total += block.len();
                assert!(
                    total <= 8 * 1024 * 1024,
                    "filesystem is not the bounded fixture"
                );
            }
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(28));
                break;
            }
        }
    }
    drop(file);
    assert!(
        store
            .set_versioning("bucket", FileVersioning::Suspended)
            .await
            .is_err()
    );
    assert!(
        store
            .delete_version("bucket", "key", Some(&version))
            .await
            .is_err()
    );
    assert_eq!(
        store.versioning("bucket").await.unwrap(),
        FileVersioning::Enabled
    );
    let mut object = store
        .open_version("bucket", "key", Some(&version))
        .await
        .unwrap()
        .unwrap();
    let mut bytes = String::new();
    object.reader.read_to_string(&mut bytes).await.unwrap();
    assert_eq!(bytes, "retained");
    assert_eq!(store.list_versions("bucket").await.unwrap().len(), 1);
    tokio::fs::remove_file(filler).await.unwrap();
    drop(store);
    let store = FileStore::new(root.clone()).await.unwrap();
    assert_eq!(
        store.versioning("bucket").await.unwrap(),
        FileVersioning::Enabled
    );
    assert!(
        store
            .open_version("bucket", "key", Some(&version))
            .await
            .unwrap()
            .is_some()
    );
    store
        .delete_version("bucket", "key", Some(&version))
        .await
        .unwrap();
    assert!(store.list_versions("bucket").await.unwrap().is_empty());
    drop(store);
    tokio::fs::remove_dir_all(root).await.unwrap();
}
