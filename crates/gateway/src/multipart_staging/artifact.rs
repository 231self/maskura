//! Extracted from `multipart_staging.rs`; re-exported from `crate::multipart_staging`.

use super::*;

#[cfg(test)]
pub(crate) async fn assert_artifact_store_contract(
    store: &dyn StagingArtifactStore,
    source_root: &Path,
) {
    let upload_id = Uuid::nil();
    let first = format!("{ARTIFACT_PREFIX}tenant-a/{upload_id}/2/1");
    let second = format!("{ARTIFACT_PREFIX}tenant-a/{upload_id}/1/1");
    let write_source = |name: &str, bytes: &[u8]| {
        let path = source_root.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    };

    store
        .put_file(&first, &write_source("contract-first.tmp", b"first"))
        .await
        .unwrap();
    store
        .put_file(&second, &write_source("contract-second.tmp", b"second"))
        .await
        .unwrap();
    store
        .put_file(
            &first,
            &write_source("contract-replacement.tmp", b"replacement"),
        )
        .await
        .unwrap();

    let mut reader = store.get(&first).await.unwrap();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"replacement");
    let listed = store.list(ARTIFACT_PREFIX).await.unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|artifact| artifact.key.as_str())
            .collect::<Vec<_>>(),
        vec![second.as_str(), first.as_str()]
    );
    assert!(listed.iter().all(|artifact| artifact.modified_at_ms > 0));

    store.delete(&first).await.unwrap();
    store.delete(&first).await.unwrap();
    assert!(matches!(
        store.get(&first).await,
        Err(StagingError::NotFound)
    ));
    store.delete(&second).await.unwrap();
    let _ = std::fs::remove_file(source_root.join("contract-first.tmp"));
    let _ = std::fs::remove_file(source_root.join("contract-second.tmp"));
    let _ = std::fs::remove_file(source_root.join("contract-replacement.tmp"));
}

pub struct S3StagingArtifactStore {
    pub(crate) client: aws_sdk_s3::Client,
    pub(crate) bucket: String,
}

impl S3StagingArtifactStore {
    pub fn new(client: aws_sdk_s3::Client, bucket: String) -> Self {
        Self { client, bucket }
    }
}

#[async_trait]
impl StagingArtifactStore for S3StagingArtifactStore {
    async fn put_file(&self, key: &str, path: &Path) -> Result<(), StagingError> {
        let body = aws_sdk_s3::primitives::ByteStream::from_path(path)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body)
            .send()
            .await
            .map_err(|error| {
                StagingError::Persistence(record_s3_failure("staging_put", &error).to_string())
            })?;
        Ok(())
    }
    async fn get(&self, key: &str) -> Result<StagingArtifactReader, StagingError> {
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|error| {
                StagingError::Persistence(record_s3_failure("staging_get", &error).to_string())
            })?;
        let length = u64::try_from(output.content_length().unwrap_or_default()).map_err(|_| {
            StagingError::Persistence("staging artifact has a negative content length".to_string())
        })?;
        Ok(Box::pin(output.body.into_async_read().take(length)))
    }
    async fn delete(&self, key: &str) -> Result<(), StagingError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|error| {
                StagingError::Persistence(record_s3_failure("staging_delete", &error).to_string())
            })?;
        Ok(())
    }
    async fn list(&self, prefix: &str) -> Result<Vec<StagedArtifact>, StagingError> {
        let mut token = None;
        let mut artifacts = Vec::new();
        loop {
            let response = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix)
                .set_continuation_token(token)
                .send()
                .await
                .map_err(|error| {
                    StagingError::Persistence(record_s3_failure("staging_list", &error).to_string())
                })?;
            artifacts.extend(response.contents().iter().filter_map(|object| {
                Some(StagedArtifact {
                    key: object.key()?.to_string(),
                    modified_at_ms: object.last_modified()?.to_millis().ok()?,
                })
            }));
            if !response.is_truncated().unwrap_or(false) {
                break;
            }
            token = response.next_continuation_token().map(ToOwned::to_owned);
            if token.is_none() {
                return Err(StagingError::Persistence(
                    "truncated staging list without continuation token".to_string(),
                ));
            }
        }
        artifacts.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(artifacts)
    }
}

#[derive(Clone, Default)]
pub struct MemoryStagingArtifactStore {
    pub objects: Arc<Mutex<MemoryArtifacts>>,
}

pub(crate) type MemoryArtifacts = HashMap<String, (Vec<u8>, i64)>;

#[async_trait]
impl StagingArtifactStore for MemoryStagingArtifactStore {
    async fn put_file(&self, key: &str, path: &Path) -> Result<(), StagingError> {
        self.objects.lock().await.insert(
            key.to_string(),
            (
                tokio::fs::read(path)
                    .await
                    .map_err(|error| StagingError::Persistence(error.to_string()))?,
                now_ms(),
            ),
        );
        Ok(())
    }
    async fn get(&self, key: &str) -> Result<StagingArtifactReader, StagingError> {
        let bytes = self
            .objects
            .lock()
            .await
            .get(key)
            .map(|(bytes, _)| bytes.clone())
            .ok_or(StagingError::NotFound)?;
        let length = bytes.len() as u64;
        Ok(Box::pin(std::io::Cursor::new(bytes).take(length)))
    }
    async fn delete(&self, key: &str) -> Result<(), StagingError> {
        self.objects.lock().await.remove(key);
        Ok(())
    }
    async fn list(&self, prefix: &str) -> Result<Vec<StagedArtifact>, StagingError> {
        let mut artifacts = self
            .objects
            .lock()
            .await
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, (_, modified_at_ms))| StagedArtifact {
                key: key.clone(),
                modified_at_ms: *modified_at_ms,
            })
            .collect::<Vec<_>>();
        artifacts.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(artifacts)
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ArtifactHeader {
    pub(crate) wrapped_dek: String,
    pub(crate) tenant_id: String,
    pub(crate) upload_id: String,
    pub(crate) part_number: u32,
    pub(crate) attempt: u32,
    pub(crate) metadata_digest: String,
}

/// Streams plaintext input into an encrypted, mode-0600 temporary file.  The
/// file contains only an envelope header and AEAD ciphertext frames.
pub struct EncryptedPartWriter {
    pub(crate) path: PathBuf,
    pub(crate) file: tokio::fs::File,
    pub(crate) dek: [u8; 32],
    pub(crate) header: ArtifactHeader,
    pub(crate) chunk: u64,
    pub(crate) size_bytes: u64,
    pub(crate) max_bytes: u64,
    pub(crate) sha256: Sha256,
    pub(crate) md5: Md5,
}

impl Drop for EncryptedPartWriter {
    fn drop(&mut self) {
        // The only local staging representation is ciphertext.  Best-effort
        // unlink also covers malformed bodies and canceled client requests.
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl EncryptedPartWriter {
    pub async fn begin(
        directory: &Path,
        identity: &MultipartIdentity,
        part_number: u32,
        attempt: u32,
        metadata: &MultipartSnapshot,
        max_bytes: u64,
        wrapping: Arc<dyn KeyWrapping>,
    ) -> Result<Self, StagingError> {
        if !wrapping.is_durable() {
            return Err(StagingError::Unavailable);
        }
        tokio::fs::create_dir_all(directory)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let dek: [u8; 32] = rand::random();
        let metadata_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(metadata)
                .map_err(|error| StagingError::Persistence(error.to_string()))?,
        ));
        let header = ArtifactHeader {
            wrapped_dek: B64.encode(
                wrapping
                    .wrap(&dek)
                    .map_err(|error| StagingError::Crypto(error.to_string()))?,
            ),
            tenant_id: identity.tenant_id.clone(),
            upload_id: identity.upload_id.clone(),
            part_number,
            attempt,
            metadata_digest,
        };
        let encoded = serde_json::to_vec(&header)
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let path = directory.join(format!("{FILE_PREFIX}{}.enc", Uuid::now_v7()));
        let mut options = tokio::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        file.write_all(MAGIC).await.map_err(io_error)?;
        file.write_all(&(encoded.len() as u32).to_be_bytes())
            .await
            .map_err(io_error)?;
        file.write_all(&encoded).await.map_err(io_error)?;
        Ok(Self {
            path,
            file,
            dek,
            header,
            chunk: 0,
            size_bytes: 0,
            max_bytes,
            sha256: Sha256::new(),
            md5: Md5::new(),
        })
    }

    pub async fn write(&mut self, plaintext: Bytes) -> Result<(), StagingError> {
        if self
            .size_bytes
            .checked_add(plaintext.len() as u64)
            .ok_or(StagingError::QuotaExceeded)?
            > self.max_bytes
        {
            return Err(StagingError::QuotaExceeded);
        }
        let nonce: [u8; NONCE_LEN] = rand::random();
        let aad = artifact_aad(&self.header, self.chunk);
        let ciphertext = Aes256Gcm::new_from_slice(&self.dek)
            .map_err(|error| StagingError::Crypto(error.to_string()))?
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| StagingError::Crypto("part encryption failed".to_string()))?;
        self.file
            .write_all(&(ciphertext.len() as u32).to_be_bytes())
            .await
            .map_err(io_error)?;
        self.file.write_all(&nonce).await.map_err(io_error)?;
        self.file.write_all(&ciphertext).await.map_err(io_error)?;
        self.size_bytes = self
            .size_bytes
            .checked_add(plaintext.len() as u64)
            .ok_or(StagingError::QuotaExceeded)?;
        self.sha256.update(&plaintext);
        self.md5.update(&plaintext);
        self.chunk += 1;
        Ok(())
    }

    pub async fn finish(mut self) -> Result<FinishedPart, StagingError> {
        self.file.flush().await.map_err(io_error)?;
        self.file.sync_all().await.map_err(io_error)?;
        let path = std::mem::take(&mut self.path);
        Ok(FinishedPart {
            path,
            size_bytes: self.size_bytes,
            checksum_sha256: hex::encode(self.sha256.clone().finalize()),
            etag: format!("\"{}\"", hex::encode(self.md5.clone().finalize())),
        })
    }

    pub async fn cleanup_stale(
        directory: &Path,
        stale_after: Duration,
    ) -> Result<usize, StagingError> {
        let mut entries = match tokio::fs::read_dir(directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(io_error(error)),
        };
        let cutoff = SystemTime::now()
            .checked_sub(stale_after)
            .unwrap_or(UNIX_EPOCH);
        let mut removed = 0;
        while let Some(entry) = entries.next_entry().await.map_err(io_error)? {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let owned = name
                .strip_prefix(FILE_PREFIX)
                .and_then(|name| name.strip_suffix(".enc"))
                .and_then(|id| Uuid::parse_str(id).ok())
                .is_some();
            if !owned {
                continue;
            }
            let metadata = entry.metadata().await.map_err(io_error)?;
            if metadata.is_file() && metadata.modified().map_err(io_error)? <= cutoff {
                tokio::fs::remove_file(entry.path())
                    .await
                    .map_err(io_error)?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

pub struct FinishedPart {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub checksum_sha256: String,
    pub etag: String,
}

impl FinishedPart {
    pub async fn remove(&self) {
        let _ = tokio::fs::remove_file(&self.path).await;
    }
}

/// Incrementally authenticates and decrypts one staged artifact. It never
/// exposes a frame until the envelope identity, snapshot digest, and AEAD tag
/// have all been checked.
pub struct EncryptedPartReader<R> {
    pub(crate) reader: R,
    pub(crate) cipher: Aes256Gcm,
    pub(crate) header: ArtifactHeader,
    pub(crate) chunk: u64,
    pub(crate) finished: bool,
}

impl<R: AsyncRead + Unpin> EncryptedPartReader<R> {
    pub async fn open(
        mut reader: R,
        identity: &MultipartIdentity,
        part: &MultipartPart,
        snapshot: &MultipartSnapshot,
        wrapping: Arc<dyn KeyWrapping>,
    ) -> Result<Self, StagingError> {
        let mut magic = [0_u8; MAGIC.len()];
        reader.read_exact(&mut magic).await.map_err(io_error)?;
        if magic != MAGIC {
            return Err(StagingError::Crypto(
                "invalid staging artifact magic".to_string(),
            ));
        }
        let mut header_len = [0_u8; 4];
        reader.read_exact(&mut header_len).await.map_err(io_error)?;
        let header_len = u32::from_be_bytes(header_len) as usize;
        if header_len == 0 || header_len > MAX_ARTIFACT_HEADER_BYTES {
            return Err(StagingError::Crypto(
                "invalid staging artifact header".to_string(),
            ));
        }
        let mut encoded = vec![0_u8; header_len];
        reader.read_exact(&mut encoded).await.map_err(io_error)?;
        let header: ArtifactHeader = serde_json::from_slice(&encoded)
            .map_err(|_| StagingError::Crypto("invalid staging artifact header".to_string()))?;
        let expected_digest = hex::encode(Sha256::digest(
            serde_json::to_vec(snapshot)
                .map_err(|error| StagingError::Persistence(error.to_string()))?,
        ));
        if header.tenant_id != identity.tenant_id
            || header.upload_id != identity.upload_id
            || header.part_number != part.part_number
            || header.attempt != part.attempt
            || header.metadata_digest != expected_digest
        {
            return Err(StagingError::Crypto(
                "staging artifact identity mismatch".to_string(),
            ));
        }
        let dek = wrapping
            .unwrap(
                &B64.decode(&header.wrapped_dek)
                    .map_err(|_| StagingError::Crypto("invalid wrapped staging key".to_string()))?,
            )
            .map_err(|error| StagingError::Crypto(error.to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(&dek)
            .map_err(|error| StagingError::Crypto(error.to_string()))?;
        Ok(Self {
            reader,
            cipher,
            header,
            chunk: 0,
            finished: false,
        })
    }

    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, StagingError> {
        if self.finished {
            return Ok(None);
        }
        let mut length = [0_u8; 4];
        match self.reader.read_exact(&mut length).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                self.finished = true;
                return Ok(None);
            }
            Err(error) => return Err(io_error(error)),
        }
        let length = u32::from_be_bytes(length) as usize;
        if !(16..=MAX_ENCRYPTED_FRAME_BYTES).contains(&length) {
            return Err(StagingError::Crypto(
                "invalid staging artifact frame length".to_string(),
            ));
        }
        let mut nonce = [0_u8; NONCE_LEN];
        self.reader.read_exact(&mut nonce).await.map_err(io_error)?;
        let mut ciphertext = vec![0_u8; length];
        self.reader
            .read_exact(&mut ciphertext)
            .await
            .map_err(io_error)?;
        let aad = artifact_aad(&self.header, self.chunk);
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                StagingError::Crypto("staging artifact authentication failed".to_string())
            })?;
        self.chunk = self
            .chunk
            .checked_add(1)
            .ok_or_else(|| StagingError::Crypto("staging artifact chunk overflow".to_string()))?;
        Ok(Some(Bytes::from(plaintext)))
    }
}

pub(crate) fn artifact_aad(header: &ArtifactHeader, chunk: u64) -> Vec<u8> {
    format!(
        "maskura.multipart.stage.v1\0{}\0{}\0{}\0{}\0{}\0{}",
        header.tenant_id,
        header.upload_id,
        header.part_number,
        header.attempt,
        chunk,
        header.metadata_digest
    )
    .into_bytes()
}

pub(crate) fn io_error(_: std::io::Error) -> StagingError {
    StagingError::Persistence(record_s3_body_failure("staging_get_body").to_string())
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
