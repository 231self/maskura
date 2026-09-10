//! Envelope encryption for API key secrets.
//!
//! The gateway never stores plaintext API key secrets. Each secret is
//! encrypted with a fresh 256-bit data key (DEK) using AES-256-GCM, and the
//! DEK itself is wrapped by a [`KeyWrapping`] implementation so the master
//! key can live elsewhere (operator-provided `MASKURA_SECRET_KEK`, or a KMS key in
//! a follow-up). Decryption only happens in memory, on demand, to recompute a
//! SigV4 signature.
//!
//! Envelope formats:
//! - `v1:{base64(wrapped_dek)}:{base64(nonce)}:{base64(ciphertext+tag)}`
//! - `v2:{base64(wrapped_dek)}:{base64(nonce)}:{base64(ciphertext+tag)}`
//!
//! v2 authenticates the API key identity as AES-GCM additional authenticated
//! data (AAD), preventing an encrypted secret from being moved to another key.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fmt::{self, Debug};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::filesystem_persistence::{create_private_dir_all, sync_parent};

const LEGACY_ENVELOPE_VERSION: &str = "v1";
const ENVELOPE_VERSION: &str = "v2";
const AAD_DOMAIN: &[u8] = b"maskura.api-key.secret.v2\0";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const FILE_KEY_VERSION: u32 = 1;
const FILE_KEY_MAX_BYTES: u64 = 4096;
const FILE_KEY_CHECKSUM_DOMAIN: &[u8] = b"maskura.local-wrapping-key.v1\0";
const FILE_KEY_TEMP_PREFIX: &str = ".wrapping.key.";
const FILE_KEY_TEMP_SUFFIX: &str = ".tmp";

/// Wraps (encrypts) and unwraps (decrypts) the per-secret data key (DEK).
///
/// The OSS self-host binary uses [`LocalKeyWrapping`] with an operator
/// provided KEK. A KMS-backed implementation (AWS KMS `GenerateDataKey` /
/// `Decrypt`) can be added behind this trait so the gateway never holds the
/// master key.
pub trait KeyWrapping: Send + Sync + Debug {
    fn wrap(&self, dek: &[u8]) -> Result<Vec<u8>>;
    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>>;

    /// Whether ciphertext wrapped by this implementation remains decryptable
    /// after a gateway restart. Durable artifact staging must fail closed when
    /// this is false: losing a DEK would permanently strand tenant data.
    fn is_durable(&self) -> bool {
        false
    }
}

/// Wraps the DEK with a static 256-bit KEK using AES-256-GCM. The per-wrap
/// nonce is prepended to the ciphertext so the blob is self-describing.
pub struct LocalKeyWrapping {
    kek: [u8; KEY_LEN],
    durable: bool,
}

impl Debug for LocalKeyWrapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalKeyWrapping")
            .field("kek", &"[REDACTED]")
            .field("durable", &self.durable)
            .finish()
    }
}

impl Drop for LocalKeyWrapping {
    fn drop(&mut self) {
        self.kek.zeroize();
    }
}

impl LocalKeyWrapping {
    /// Read the KEK from `MASKURA_SECRET_KEK` (base64, 32 bytes).
    pub fn from_env() -> Result<Option<Self>> {
        match std::env::var("MASKURA_SECRET_KEK") {
            Ok(v) => {
                let kek = B64
                    .decode(v.trim())
                    .context("MASKURA_SECRET_KEK must be base64")?;
                let kek: [u8; KEY_LEN] = kek
                    .try_into()
                    .map_err(|_| anyhow!("MASKURA_SECRET_KEK must decode to 32 bytes"))?;
                Ok(Some(Self { kek, durable: true }))
            }
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(e) => Err(e).context("failed to read MASKURA_SECRET_KEK"),
        }
    }

    /// A KEK supplied directly (tests, key material from elsewhere).
    pub fn with_kek(kek: [u8; KEY_LEN]) -> Self {
        Self { kek, durable: true }
    }

    /// A random in-memory KEK. Used when no KEK is configured: secrets cannot
    /// be decrypted after a restart (SigV4 verification is lost; hash-based
    /// SDK auth still works).
    pub fn ephemeral() -> Self {
        let mut kek = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut kek);
        Self {
            kek,
            durable: false,
        }
    }
}

impl KeyWrapping for LocalKeyWrapping {
    fn wrap(&self, dek: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(&self.kek).map_err(anyhow::Error::msg)?;
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), dek)
            .map_err(|_| anyhow!("DEK wrap failed"))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        if wrapped.len() < NONCE_LEN {
            return Err(anyhow!("wrapped DEK too short"));
        }
        let (nonce, ct) = wrapped.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(&self.kek).map_err(anyhow::Error::msg)?;
        cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| anyhow!("DEK unwrap failed"))
    }

    fn is_durable(&self) -> bool {
        self.durable
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum FileKeyWrappingError {
    #[error("local wrapping key {operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("local wrapping key is corrupt: {0}")]
    Corrupt(String),
    #[error("unsupported local wrapping key version {0}")]
    UnsupportedVersion(u32),
    #[cfg(unix)]
    #[error("local wrapping key permissions must not grant group or other access")]
    InsecurePermissions,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileKeyRecord {
    version: u32,
    key: String,
    checksum: String,
}

/// A durable wrapping provider scoped to one locked local-storage root.
pub(crate) struct FileKeyWrapping {
    wrapping: LocalKeyWrapping,
}

impl Debug for FileKeyWrapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileKeyWrapping")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl FileKeyWrapping {
    /// The caller must hold the root lock before invoking this method.
    pub(crate) fn load_or_create(path: &Path) -> Result<Self, FileKeyWrappingError> {
        let wrapping = match load_file_key(path)? {
            Some(key) => LocalKeyWrapping::with_kek(key),
            None => LocalKeyWrapping::with_kek(publish_new_file_key(path)?),
        };
        cleanup_file_key_temporaries(path)?;
        Ok(Self { wrapping })
    }
}

impl KeyWrapping for FileKeyWrapping {
    fn wrap(&self, dek: &[u8]) -> Result<Vec<u8>> {
        self.wrapping.wrap(dek)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>> {
        self.wrapping.unwrap(wrapped)
    }

    fn is_durable(&self) -> bool {
        true
    }
}

fn publish_new_file_key(path: &Path) -> Result<[u8; KEY_LEN], FileKeyWrappingError> {
    let parent = path.parent().ok_or_else(|| {
        FileKeyWrappingError::Corrupt(format!("{} has no parent", path.display()))
    })?;
    create_private_dir_all(parent)
        .map_err(|error| FileKeyWrappingError::Corrupt(error.to_string()))?;

    let mut key = [0_u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    let mut record = FileKeyRecord {
        version: FILE_KEY_VERSION,
        key: B64.encode(key),
        checksum: hex::encode(file_key_checksum(FILE_KEY_VERSION, &key)),
    };
    let mut encoded = serde_json::to_vec(&record)
        .map_err(|error| FileKeyWrappingError::Corrupt(error.to_string()))?;
    record.key.zeroize();
    let temporary = file_key_temporary_path(path);
    let result = (|| {
        let mut file = create_private_file(&temporary)?;
        file.write_all(&encoded)
            .map_err(|source| file_key_io("temporary write", source))?;
        file.sync_all()
            .map_err(|source| file_key_io("temporary sync", source))?;
        drop(file);

        match std::fs::hard_link(&temporary, path) {
            Ok(()) => {
                std::fs::remove_file(&temporary)
                    .map_err(|source| file_key_io("temporary removal", source))?;
                sync_parent(path).map_err(|source| file_key_io("parent sync", source))?;
                Ok(key)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::remove_file(&temporary)
                    .map_err(|source| file_key_io("temporary removal", source))?;
                sync_parent(path).map_err(|source| file_key_io("parent sync", source))?;
                let existing = load_file_key(path)?.ok_or_else(|| {
                    FileKeyWrappingError::Corrupt(
                        "canonical key disappeared during publication".into(),
                    )
                })?;
                key.zeroize();
                Ok(existing)
            }
            Err(source) => Err(file_key_io("no-overwrite publication", source)),
        }
    })();
    if temporary.exists() {
        let _ = std::fs::remove_file(&temporary);
    }
    encoded.zeroize();
    if result.is_err() {
        key.zeroize();
    }
    result
}

fn load_file_key(path: &Path) -> Result<Option<[u8; KEY_LEN]>, FileKeyWrappingError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(file_key_io("metadata read", source)),
    };
    if !metadata.file_type().is_file() {
        return Err(FileKeyWrappingError::Corrupt(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    validate_file_key_permissions(&metadata)?;
    if metadata.len() == 0 || metadata.len() > FILE_KEY_MAX_BYTES {
        return Err(FileKeyWrappingError::Corrupt(
            "record has an invalid length".into(),
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|source| file_key_io("open", source))?;
    let opened_metadata = file
        .metadata()
        .map_err(|source| file_key_io("opened metadata read", source))?;
    if !opened_metadata.file_type().is_file() || !same_file(&metadata, &opened_metadata) {
        return Err(FileKeyWrappingError::Corrupt(
            "canonical file changed while opening".into(),
        ));
    }
    validate_file_key_permissions(&opened_metadata)?;
    let mut encoded = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut encoded)
        .map_err(|source| file_key_io("read", source))?;
    if encoded.len() as u64 != metadata.len() {
        return Err(FileKeyWrappingError::Corrupt(
            "canonical file changed while reading".into(),
        ));
    }
    let record: FileKeyRecord = serde_json::from_slice(&encoded)
        .map_err(|error| FileKeyWrappingError::Corrupt(format!("invalid record: {error}")))?;
    if record.version != FILE_KEY_VERSION {
        return Err(FileKeyWrappingError::UnsupportedVersion(record.version));
    }
    let decoded = B64
        .decode(record.key)
        .map_err(|_| FileKeyWrappingError::Corrupt("invalid key encoding".into()))?;
    let key: [u8; KEY_LEN] = decoded
        .try_into()
        .map_err(|_| FileKeyWrappingError::Corrupt("key must contain exactly 32 bytes".into()))?;
    let checksum = hex::decode(record.checksum)
        .map_err(|_| FileKeyWrappingError::Corrupt("invalid checksum encoding".into()))?;
    let expected = file_key_checksum(record.version, &key);
    if checksum.as_slice() != expected {
        return Err(FileKeyWrappingError::Corrupt("checksum mismatch".into()));
    }
    Ok(Some(key))
}

fn create_private_file(path: &Path) -> Result<File, FileKeyWrappingError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|source| file_key_io("temporary creation", source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| file_key_io("temporary permissions", source))?;
    }
    Ok(file)
}

fn cleanup_file_key_temporaries(path: &Path) -> Result<(), FileKeyWrappingError> {
    let parent = path.parent().ok_or_else(|| {
        FileKeyWrappingError::Corrupt(format!("{} has no parent", path.display()))
    })?;
    let entries = std::fs::read_dir(parent)
        .map_err(|source| file_key_io("temporary directory read", source))?;
    let mut removed = false;
    for entry in entries {
        let entry = entry.map_err(|source| file_key_io("temporary entry read", source))?;
        if !is_file_key_temporary(&entry.file_name()) {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|source| file_key_io("temporary metadata read", source))?;
        if !(file_type.is_file() || file_type.is_symlink()) {
            return Err(FileKeyWrappingError::Corrupt(format!(
                "{} is not a removable wrapping-key temporary",
                entry.path().display()
            )));
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(file_key_io("temporary cleanup", source)),
        }
    }
    if removed {
        sync_parent(path).map_err(|source| file_key_io("temporary cleanup sync", source))?;
    }
    Ok(())
}

fn file_key_temporary_path(path: &Path) -> PathBuf {
    path.parent()
        .expect("wrapping key path has a parent")
        .join(format!(
            "{FILE_KEY_TEMP_PREFIX}{}{FILE_KEY_TEMP_SUFFIX}",
            Uuid::now_v7()
        ))
}

fn is_file_key_temporary(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    name.strip_prefix(FILE_KEY_TEMP_PREFIX)
        .and_then(|name| name.strip_suffix(FILE_KEY_TEMP_SUFFIX))
        .is_some_and(|id| Uuid::parse_str(id).is_ok())
}

fn file_key_checksum(version: u32, key: &[u8; KEY_LEN]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(FILE_KEY_CHECKSUM_DOMAIN);
    digest.update(version.to_be_bytes());
    digest.update((key.len() as u64).to_be_bytes());
    digest.update(key);
    digest.finalize().into()
}

#[cfg(unix)]
fn validate_file_key_permissions(metadata: &std::fs::Metadata) -> Result<(), FileKeyWrappingError> {
    use std::os::unix::fs::PermissionsExt as _;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(FileKeyWrappingError::InsecurePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_file_key_permissions(
    _metadata: &std::fs::Metadata,
) -> Result<(), FileKeyWrappingError> {
    Ok(())
}

#[cfg(unix)]
fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(_left: &std::fs::Metadata, _right: &std::fs::Metadata) -> bool {
    true
}

fn file_key_io(operation: &'static str, source: std::io::Error) -> FileKeyWrappingError {
    FileKeyWrappingError::Io { operation, source }
}

/// Resolve the OSS self-host wrapping: `MASKURA_SECRET_KEK` if set, otherwise an
/// ephemeral key with a warning that SigV4 verification will not survive a
/// restart. KMS/Vault wrappers are injected by callers that construct their
/// own [`KeyWrapping`] and pass it to `build_state`.
pub fn default_wrapping() -> Result<Arc<dyn KeyWrapping>> {
    match LocalKeyWrapping::from_env()? {
        Some(wrapping) => Ok(Arc::new(wrapping)),
        None => {
            warn!(
                "MASKURA_SECRET_KEK is not set; API key secrets use an ephemeral key and SigV4 verification will not survive a restart"
            );
            Ok(Arc::new(LocalKeyWrapping::ephemeral()))
        }
    }
}

/// Encrypts and decrypts API key secrets at rest (envelope encryption).
#[derive(Debug)]
pub struct SecretCipher {
    wrapping: Arc<dyn KeyWrapping>,
}

impl SecretCipher {
    pub fn new(wrapping: Arc<dyn KeyWrapping>) -> Self {
        Self { wrapping }
    }

    /// Encrypt `secret`, returning a v2 envelope bound to `key_id`.
    pub fn encrypt(&self, key_id: &str, secret: &str) -> Result<String> {
        self.encrypt_with_version(ENVELOPE_VERSION, key_id, secret)
    }

    fn encrypt_with_version(&self, version: &str, key_id: &str, secret: &str) -> Result<String> {
        let mut dek = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut dek);
        let wrapped = self.wrapping.wrap(&dek)?;
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(&dek).map_err(anyhow::Error::msg)?;
        let ct = if version == ENVELOPE_VERSION {
            let aad = envelope_aad(key_id);
            cipher.encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: secret.as_bytes(),
                    aad: &aad,
                },
            )
        } else {
            cipher.encrypt(Nonce::from_slice(&nonce), secret.as_bytes())
        }
        .map_err(|_| anyhow!("secret encryption failed"))?;
        Ok(format!(
            "{version}:{}:{}:{}",
            B64.encode(wrapped),
            B64.encode(nonce),
            B64.encode(ct)
        ))
    }

    /// Decrypt a v1 or v2 envelope, preserving the original compatibility
    /// behavior that collapses invalid data and wrapping-provider errors.
    pub fn decrypt(&self, key_id: &str, blob: &str) -> Option<String> {
        self.decrypt_result(key_id, blob).ok().flatten()
    }

    /// Decrypt while distinguishing wrapping-provider failures from invalid
    /// envelope data. Credential repositories use this method so operational
    /// KMS/Vault outages can propagate instead of becoming authentication
    /// denials.
    pub fn decrypt_result(&self, key_id: &str, blob: &str) -> Result<Option<String>> {
        let parts: Vec<&str> = blob.splitn(4, ':').collect();
        if parts.len() != 4 || (parts[0] != ENVELOPE_VERSION && parts[0] != LEGACY_ENVELOPE_VERSION)
        {
            return Ok(None);
        }
        let Ok(wrapped) = B64.decode(parts[1]) else {
            return Ok(None);
        };
        let Ok(nonce) = B64.decode(parts[2]) else {
            return Ok(None);
        };
        if nonce.len() != NONCE_LEN {
            return Ok(None);
        }
        let Ok(ct) = B64.decode(parts[3]) else {
            return Ok(None);
        };
        let dek = self
            .wrapping
            .unwrap(&wrapped)
            .context("key wrapping provider failed to unwrap API key DEK")?;
        let Ok(cipher) = Aes256Gcm::new_from_slice(&dek) else {
            return Ok(None);
        };
        let plaintext = if parts[0] == ENVELOPE_VERSION {
            let aad = envelope_aad(key_id);
            cipher.decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ct.as_ref(),
                    aad: &aad,
                },
            )
        } else {
            cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref())
        };
        let Ok(plaintext) = plaintext else {
            return Ok(None);
        };
        Ok(String::from_utf8(plaintext).ok())
    }

    pub fn is_legacy_envelope(blob: &str) -> bool {
        blob.starts_with("v1:")
    }

    #[cfg(test)]
    pub(crate) fn encrypt_v1(&self, secret: &str) -> Result<String> {
        self.encrypt_with_version(LEGACY_ENVELOPE_VERSION, "", secret)
    }
}

fn envelope_aad(key_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + key_id.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(key_id.as_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    // env mutations must be serialized across tests.
    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    fn cipher_with_kek(kek: u8) -> SecretCipher {
        SecretCipher::new(Arc::new(LocalKeyWrapping::with_kek([kek; KEY_LEN])))
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("maskura-file-key-{}", Uuid::now_v7()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn key_path(&self) -> PathBuf {
            self.0.join(".maskura").join("wrapping.key")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn encode_file_key(version: u32, key: &[u8]) -> Vec<u8> {
        let checksum = if key.len() == KEY_LEN {
            file_key_checksum(version, key.try_into().unwrap())
        } else {
            [0_u8; 32]
        };
        serde_json::to_vec(&FileKeyRecord {
            version,
            key: B64.encode(key),
            checksum: hex::encode(checksum),
        })
        .unwrap()
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[derive(Debug)]
    struct FailingUnwrapper;

    impl KeyWrapping for FailingUnwrapper {
        fn wrap(&self, _dek: &[u8]) -> Result<Vec<u8>> {
            Err(anyhow!("unexpected wrap"))
        }

        fn unwrap(&self, _wrapped: &[u8]) -> Result<Vec<u8>> {
            Err(anyhow!("wrapping provider unavailable"))
        }
    }

    #[test]
    fn v2_roundtrip_local_kek() {
        let cipher = cipher_with_kek(7);
        let blob = cipher
            .encrypt("maskura_key_identity", "maskura_secret_secret_value_1234")
            .unwrap();
        assert!(blob.starts_with("v2:"));
        assert_eq!(
            cipher.decrypt("maskura_key_identity", &blob).as_deref(),
            Some("maskura_secret_secret_value_1234")
        );
    }

    #[test]
    fn v1_envelope_remains_compatible() {
        let cipher = cipher_with_kek(7);
        let blob = cipher.encrypt_v1("legacy-secret").unwrap();

        assert!(SecretCipher::is_legacy_envelope(&blob));
        assert_eq!(
            cipher.decrypt("any-key-id", &blob).as_deref(),
            Some("legacy-secret")
        );
    }

    #[test]
    fn v2_wrong_identity_fails() {
        let cipher = cipher_with_kek(7);
        let blob = cipher.encrypt("key-a", "secret").unwrap();

        assert_eq!(cipher.decrypt("key-b", &blob), None);
    }

    #[test]
    fn swapped_v2_envelopes_fail() {
        let cipher = cipher_with_kek(7);
        let envelope_a = cipher.encrypt("key-a", "secret-a").unwrap();
        let envelope_b = cipher.encrypt("key-b", "secret-b").unwrap();

        assert_eq!(cipher.decrypt("key-a", &envelope_b), None);
        assert_eq!(cipher.decrypt("key-b", &envelope_a), None);
    }

    #[test]
    fn tampered_v2_ciphertext_fails() {
        let cipher = cipher_with_kek(7);
        let blob = cipher.encrypt("key-a", "secret").unwrap();
        let mut parts: Vec<String> = blob.split(':').map(|s| s.to_string()).collect();
        let ct = B64.decode(&parts[3]).unwrap();
        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        parts[3] = B64.encode(tampered);
        assert_eq!(cipher.decrypt("key-a", &parts.join(":")), None);
    }

    #[test]
    fn wrong_kek_preserves_compatibility_and_is_a_fallible_unwrap_error() {
        let blob = cipher_with_kek(7).encrypt("key-a", "secret").unwrap();
        let other = cipher_with_kek(9);
        assert_eq!(other.decrypt("key-a", &blob), None);
        assert!(other.decrypt_result("key-a", &blob).is_err());
    }

    #[test]
    fn wrapping_provider_failure_is_an_operational_error() {
        let blob = cipher_with_kek(7).encrypt("key-a", "secret").unwrap();
        let cipher = SecretCipher::new(Arc::new(FailingUnwrapper));

        assert_eq!(cipher.decrypt("key-a", &blob), None);
        assert!(cipher.decrypt_result("key-a", &blob).is_err());
    }

    #[test]
    fn malformed_blob_returns_none() {
        let cipher = cipher_with_kek(7);
        assert_eq!(cipher.decrypt("key-a", "v1:not-base64:abc"), None);
        assert_eq!(cipher.decrypt("key-a", "v9:abc:def:ghi"), None);
        assert_eq!(cipher.decrypt("key-a", ""), None);
    }

    #[test]
    fn malformed_nonce_returns_none() {
        let cipher = cipher_with_kek(7);
        let blob = cipher.encrypt("key-a", "secret").unwrap();
        let mut parts: Vec<String> = blob.split(':').map(str::to_string).collect();
        parts[2] = B64.encode([0u8; NONCE_LEN - 1]);

        assert_eq!(cipher.decrypt("key-a", &parts.join(":")), None);
    }

    #[test]
    fn invalid_utf8_plaintext_returns_none() {
        let wrapping = Arc::new(LocalKeyWrapping::with_kek([7; KEY_LEN]));
        let dek = [5u8; KEY_LEN];
        let wrapped = wrapping.wrap(&dek).unwrap();
        let nonce = [3u8; NONCE_LEN];
        let cipher = Aes256Gcm::new_from_slice(&dek).unwrap();
        let aad = envelope_aad("key-a");
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &[0xff],
                    aad: &aad,
                },
            )
            .unwrap();
        let blob = format!(
            "v2:{}:{}:{}",
            B64.encode(wrapped),
            B64.encode(nonce),
            B64.encode(ciphertext)
        );
        let secret_cipher = SecretCipher::new(wrapping);

        assert_eq!(secret_cipher.decrypt("key-a", &blob), None);
    }

    #[test]
    fn env_kek_parses() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("MASKURA_SECRET_KEK", B64.encode([3u8; KEY_LEN])) };
        let w = LocalKeyWrapping::from_env()
            .expect("no env error")
            .expect("Some");
        let cipher = SecretCipher::new(Arc::new(w));
        let blob = cipher.encrypt("key-a", "x").unwrap();
        assert_eq!(cipher.decrypt("key-a", &blob).as_deref(), Some("x"));
    }

    #[test]
    fn env_kek_rejects_short_key() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("MASKURA_SECRET_KEK", B64.encode([1u8; 8])) };
        assert!(LocalKeyWrapping::from_env().is_err());
    }

    #[test]
    fn file_key_identity_survives_reload() {
        let directory = TempDir::new();
        let path = directory.key_path();
        let first = FileKeyWrapping::load_or_create(&path).unwrap();
        let wrapped = first.wrap(b"restart-sensitive-dek").unwrap();
        drop(first);

        let second = FileKeyWrapping::load_or_create(&path).unwrap();

        assert!(second.is_durable());
        assert_eq!(second.unwrap(&wrapped).unwrap(), b"restart-sensitive-dek");
    }

    #[test]
    fn malformed_file_key_is_rejected_without_overwrite() {
        let directory = TempDir::new();
        let path = directory.key_path();
        write_private(&path, b"not-json");
        let before = std::fs::read(&path).unwrap();

        assert!(matches!(
            FileKeyWrapping::load_or_create(&path),
            Err(FileKeyWrappingError::Corrupt(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn truncated_file_key_is_rejected_without_overwrite() {
        let directory = TempDir::new();
        let path = directory.key_path();
        let mut encoded = encode_file_key(FILE_KEY_VERSION, &[7; KEY_LEN]);
        encoded.truncate(encoded.len() / 2);
        write_private(&path, &encoded);

        assert!(matches!(
            FileKeyWrapping::load_or_create(&path),
            Err(FileKeyWrappingError::Corrupt(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), encoded);
    }

    #[test]
    fn wrong_file_key_length_is_rejected_without_overwrite() {
        let directory = TempDir::new();
        let path = directory.key_path();
        let encoded = encode_file_key(FILE_KEY_VERSION, &[7; KEY_LEN - 1]);
        write_private(&path, &encoded);

        assert!(matches!(
            FileKeyWrapping::load_or_create(&path),
            Err(FileKeyWrappingError::Corrupt(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), encoded);
    }

    #[test]
    fn file_key_checksum_corruption_is_rejected_without_overwrite() {
        let directory = TempDir::new();
        let path = directory.key_path();
        let mut record: FileKeyRecord =
            serde_json::from_slice(&encode_file_key(FILE_KEY_VERSION, &[7; KEY_LEN])).unwrap();
        record.checksum.replace_range(..2, "00");
        let encoded = serde_json::to_vec(&record).unwrap();
        write_private(&path, &encoded);

        assert!(matches!(
            FileKeyWrapping::load_or_create(&path),
            Err(FileKeyWrappingError::Corrupt(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), encoded);
    }

    #[test]
    fn unsupported_file_key_version_is_rejected_without_overwrite() {
        let directory = TempDir::new();
        let path = directory.key_path();
        let encoded = encode_file_key(FILE_KEY_VERSION + 1, &[7; KEY_LEN]);
        write_private(&path, &encoded);

        assert!(matches!(
            FileKeyWrapping::load_or_create(&path),
            Err(FileKeyWrappingError::UnsupportedVersion(2))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), encoded);
    }

    #[cfg(unix)]
    #[test]
    fn insecure_file_key_permissions_are_rejected_without_repair() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = TempDir::new();
        let path = directory.key_path();
        let encoded = encode_file_key(FILE_KEY_VERSION, &[7; KEY_LEN]);
        write_private(&path, &encoded);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        assert!(matches!(
            FileKeyWrapping::load_or_create(&path),
            Err(FileKeyWrappingError::InsecurePermissions)
        ));
        assert_eq!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_file_key_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new();
        let path = directory.key_path();
        let target = directory.0.join("target.key");
        let encoded = encode_file_key(FILE_KEY_VERSION, &[7; KEY_LEN]);
        write_private(&target, &encoded);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        symlink(&target, &path).unwrap();

        assert!(matches!(
            FileKeyWrapping::load_or_create(&path),
            Err(FileKeyWrappingError::Corrupt(_))
        ));
        assert_eq!(std::fs::read(&target).unwrap(), encoded);
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn non_regular_file_key_is_rejected_without_replacement() {
        let directory = TempDir::new();
        let path = directory.key_path();
        std::fs::create_dir_all(&path).unwrap();

        assert!(matches!(
            FileKeyWrapping::load_or_create(&path),
            Err(FileKeyWrappingError::Corrupt(_))
        ));
        assert!(path.is_dir());
    }

    #[test]
    fn recognized_crash_temporaries_are_removed_but_unrecognized_files_remain() {
        let directory = TempDir::new();
        let path = directory.key_path();
        FileKeyWrapping::load_or_create(&path).unwrap();
        let stale = file_key_temporary_path(&path);
        let unrelated = path.parent().unwrap().join(".wrapping.key.not-a-uuid.tmp");
        write_private(&stale, b"partial-or-complete-candidate");
        write_private(&unrelated, b"unrelated");

        FileKeyWrapping::load_or_create(&path).unwrap();

        assert!(!stale.exists());
        assert!(unrelated.exists());
    }
}
