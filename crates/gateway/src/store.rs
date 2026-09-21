use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
    SqlxPostgresConnector,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use uuid::Uuid;

use crate::entity::api_key;
use crate::entity::mcp_token;
use crate::hybrid::HybridPublicKey;
use crate::key_cipher::SecretCipher;
use crate::workspace_storage::WorkspaceId;

pub const MAX_CREDENTIAL_LABEL_BYTES: usize = 128;
pub const MAX_CREDENTIAL_TTL_SECONDS: u64 = 365 * 24 * 60 * 60;
pub const MAX_PUBLIC_KEY_PEM_BYTES: usize = 16 * 1024;
pub const MAX_ROOT_CREDENTIAL_BYTES: usize = 256;

#[derive(Debug, Clone)]
pub struct StoredObject {
    pub data: Bytes,
    pub content_type: String,
    pub etag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKey {
    pub key_id: String,
    pub secret_hash: String,
    #[serde(default)]
    pub secret_encrypted: Option<String>,
    pub user_id: String,
    #[serde(default)]
    pub workspace_id: Option<String>,
    pub label: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub public_key_pem: Option<String>,
}

/// MCP bearer token (`maskura_mcp_...`). The full token is the credential; only its
/// SHA-256 hash is stored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct McpToken {
    /// Stable credential UUID. Missing only in legacy file snapshots.
    #[serde(default)]
    pub credential_id: Option<String>,
    pub token_hash: String,
    pub user_id: String,
    #[serde(default)]
    pub workspace_id: Option<String>,
    pub label: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

/// Authenticated MCP credential identity returned atomically with its scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedMcpPrincipal {
    pub(crate) context: crate::control::AuthenticatedRequestContext,
    pub(crate) credential_id: Uuid,
    pub(crate) credential_policy_id: String,
}

impl AuthenticatedMcpPrincipal {
    pub fn context(&self) -> &crate::control::AuthenticatedRequestContext {
        &self.context
    }

    pub fn credential_id(&self) -> Uuid {
        self.credential_id
    }

    pub fn credential_policy_id(&self) -> &str {
        &self.credential_policy_id
    }
}

#[derive(Debug)]
pub struct MemoryStore {
    objects: RwLock<HashMap<String, StoredObject>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            objects: RwLock::new(HashMap::new()),
        }
    }

    fn object_key(bucket: &str, key: &str) -> String {
        format!("{}/{}", bucket, key)
    }

    pub fn put(
        &self,
        bucket: &str,
        key: &str,
        data: impl Into<Bytes>,
        content_type: &str,
    ) -> StoredObject {
        let etag = format!("\"{}\"", Uuid::new_v4());
        let obj = StoredObject {
            data: data.into(),
            content_type: content_type.to_string(),
            etag: etag.clone(),
        };
        self.objects
            .write()
            .unwrap()
            .insert(Self::object_key(bucket, key), obj.clone());
        obj
    }

    pub fn get(&self, bucket: &str, key: &str) -> Option<StoredObject> {
        self.objects
            .read()
            .unwrap()
            .get(&Self::object_key(bucket, key))
            .cloned()
    }

    pub fn head(&self, bucket: &str, key: &str) -> Option<StoredObject> {
        self.objects
            .read()
            .unwrap()
            .get(&Self::object_key(bucket, key))
            .map(|object| StoredObject {
                data: Bytes::new(),
                content_type: object.content_type.clone(),
                etag: object.etag.clone(),
            })
    }

    pub fn metadata(&self, bucket: &str, key: &str) -> Option<(usize, String, String)> {
        self.objects
            .read()
            .unwrap()
            .get(&Self::object_key(bucket, key))
            .map(|object| {
                (
                    object.data.len(),
                    object.content_type.clone(),
                    object.etag.clone(),
                )
            })
    }

    pub fn delete(&self, bucket: &str, key: &str) -> bool {
        self.objects
            .write()
            .unwrap()
            .remove(&Self::object_key(bucket, key))
            .is_some()
    }

    pub fn list_keys(&self) -> Vec<String> {
        self.objects.read().unwrap().keys().cloned().collect()
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct KeyStore {
    keys: RwLock<HashMap<String, ApiKey>>,
    mcp_tokens: RwLock<HashMap<String, McpToken>>,
    cipher: Option<Arc<SecretCipher>>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            mcp_tokens: RwLock::new(HashMap::new()),
            cipher: None,
        }
    }

    /// A keystore that can also encrypt/decrypt secrets for SigV4 verification.
    pub fn with_cipher(cipher: Arc<SecretCipher>) -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            mcp_tokens: RwLock::new(HashMap::new()),
            cipher: Some(cipher),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PostgresKeyStore {
    db: DatabaseConnection,
    cipher: Option<Arc<SecretCipher>>,
}

impl PostgresKeyStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        let db = SqlxPostgresConnector::from_sqlx_postgres_pool(pool);
        Self { db, cipher: None }
    }

    pub fn with_cipher(pool: sqlx::PgPool, cipher: Arc<SecretCipher>) -> Self {
        let db = SqlxPostgresConnector::from_sqlx_postgres_pool(pool);
        Self {
            db,
            cipher: Some(cipher),
        }
    }
}

/// Persistence for API keys. In-memory (`KeyStore`) or Postgres-backed
/// (`PostgresKeyStore`); selected by the presence of `DATABASE_URL`.
#[async_trait]
pub trait KeyRepository: Send + Sync {
    /// Create and persist a key, then return the plaintext secret and committed
    /// metadata. The secret is hashed (SHA-256) before storage and never
    /// returned when persistence fails.
    async fn create_key(
        &self,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
        expires_in: u64,
        public_key_pem: Option<String>,
    ) -> anyhow::Result<(String, ApiKey)>;

    /// Seed a preconfigured key id/secret pair (operator bootstrap). Rejects a
    /// malformed pair or a key id that already exists.
    async fn bootstrap_key(
        &self,
        key_id: &str,
        secret: &str,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
    ) -> anyhow::Result<ApiKey>;

    /// Seed the local-appliance root credential from an operator- or
    /// user-supplied access key + secret. Unlike [`Self::bootstrap_key`], the
    /// pair is not required to match the `maskura_`/`maskura_secret_` format:
    /// it is only bounded and control-character-free, mirroring the MinIO
    /// `ROOT_USER`/`ROOT_PASSWORD` contract.
    async fn bootstrap_root_credential(
        &self,
        access_key: &str,
        secret: &str,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
    ) -> anyhow::Result<ApiKey>;

    async fn set_public_key(
        &self,
        key_id: &str,
        user_id: &str,
        public_key_pem: &str,
    ) -> anyhow::Result<bool>;

    async fn get_key(&self, key_id: &str) -> anyhow::Result<Option<ApiKey>>;

    /// Decrypt the stored plaintext secret for `key_id` (used to verify SigV4
    /// signatures). Returns `None` for legacy keys that only have a hash.
    async fn decrypt_secret(&self, key_id: &str) -> anyhow::Result<Option<String>>;

    /// Validate an access key/secret pair and return its immutable principal
    /// plus the API key's public key PEM. Legacy unbound records return None.
    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> anyhow::Result<Option<(crate::control::AuthenticatedRequestContext, Option<String>)>>;

    /// Keys for a user, with the secret hash stripped.
    async fn list_for_user(&self, user_id: &str) -> anyhow::Result<Vec<ApiKey>>;

    async fn delete_key(&self, key_id: &str, user_id: &str) -> anyhow::Result<bool>;

    /// Create an MCP bearer token (`maskura_mcp_...`) and return the plaintext token
    /// (shown once). Only its SHA-256 hash is stored.
    async fn create_mcp_token(
        &self,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
        expires_in: u64,
    ) -> anyhow::Result<(String, McpToken)>;

    /// Validate an MCP bearer token and return its immutable principal.
    async fn resolve_mcp_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<AuthenticatedMcpPrincipal>>;

    /// MCP tokens for a user (hashes only).
    async fn list_mcp_tokens(&self, user_id: &str) -> anyhow::Result<Vec<McpToken>>;

    async fn delete_mcp_token(&self, token_hash: &str, user_id: &str) -> anyhow::Result<bool>;
}

pub fn canonicalize_credential_label(label: &str) -> anyhow::Result<String> {
    if label.chars().any(char::is_control) {
        anyhow::bail!("credential label must not contain control characters");
    }
    let label = label.trim();
    if label.is_empty() {
        anyhow::bail!("credential label must not be empty");
    }
    if label.len() > MAX_CREDENTIAL_LABEL_BYTES {
        anyhow::bail!("credential label must not exceed {MAX_CREDENTIAL_LABEL_BYTES} UTF-8 bytes");
    }
    Ok(label.to_string())
}

pub fn validate_credential_ttl(expires_in: u64) -> anyhow::Result<()> {
    if expires_in > MAX_CREDENTIAL_TTL_SECONDS {
        anyhow::bail!(
            "credential expiry must be 0 or at most {MAX_CREDENTIAL_TTL_SECONDS} seconds"
        );
    }
    Ok(())
}

pub fn canonicalize_public_key_pem(public_key_pem: &str) -> anyhow::Result<String> {
    if public_key_pem.len() > MAX_PUBLIC_KEY_PEM_BYTES {
        anyhow::bail!("public key PEM must not exceed {MAX_PUBLIC_KEY_PEM_BYTES} bytes");
    }
    let public_key_pem = public_key_pem.trim();
    if public_key_pem.is_empty() {
        anyhow::bail!("public key PEM must not be empty");
    }

    HybridPublicKey::parse_pem(public_key_pem).map_err(|e| {
        anyhow::anyhow!("public key PEM must contain a hybrid X25519 + ML-KEM-768 key: {e}")
    })?;

    Ok(public_key_pem.to_string())
}

#[allow(clippy::too_many_arguments)]
fn build_api_key(
    key_id: &str,
    user_id: &str,
    workspace_id: Option<String>,
    label: &str,
    secret_hash: String,
    secret_encrypted: Option<String>,
    created_at: String,
    expires_at: Option<String>,
    public_key_pem: Option<String>,
) -> ApiKey {
    ApiKey {
        key_id: key_id.to_string(),
        secret_hash,
        secret_encrypted,
        user_id: user_id.to_string(),
        workspace_id,
        label: label.to_string(),
        created_at,
        expires_at,
        public_key_pem,
    }
}

fn generate_api_key(
    user_id: &str,
    workspace_id: &WorkspaceId,
    label: &str,
    expires_in: u64,
    public_key_pem: Option<String>,
    cipher: Option<&SecretCipher>,
) -> anyhow::Result<(ApiKey, String)> {
    let label = canonicalize_credential_label(label)?;
    validate_credential_ttl(expires_in)?;
    let public_key_pem = public_key_pem
        .as_deref()
        .map(canonicalize_public_key_pem)
        .transpose()?;
    let key_id = format!("maskura_{}", Uuid::new_v4().to_string().replace('-', ""));
    let secret = format!(
        "maskura_secret_{}",
        Uuid::new_v4().to_string().replace('-', "")
    );
    let secret_hash = sha256_hash(&secret);
    let secret_encrypted = match cipher {
        Some(cipher) => Some(
            cipher
                .encrypt(&key_id, &secret)
                .context("API key secret encryption failed")?,
        ),
        None => {
            tracing::warn!("secret encryption is not configured; header authentication only");
            None
        }
    };
    let now = chrono_now().parse::<u64>().unwrap_or(0);
    let expires_at = if expires_in > 0 {
        Some(
            now.checked_add(expires_in)
                .context("API key expiry overflow")?
                .to_string(),
        )
    } else {
        None
    };
    let api_key = build_api_key(
        &key_id,
        user_id,
        Some(workspace_id.as_str().to_string()),
        &label,
        secret_hash,
        secret_encrypted,
        chrono_now(),
        expires_at,
        public_key_pem,
    );
    Ok((api_key, secret))
}

fn validate_bootstrap_key_id(key_id: &str) -> anyhow::Result<()> {
    let valid = key_id
        .strip_prefix("maskura_")
        .is_some_and(|rest| rest.len() == 32 && rest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if !valid {
        anyhow::bail!("bootstrap key id must match `maskura_<32-hex>`");
    }
    Ok(())
}

fn validate_bootstrap_secret(secret: &str) -> anyhow::Result<()> {
    let valid = secret
        .strip_prefix("maskura_secret_")
        .is_some_and(|rest| rest.len() == 32 && rest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if !valid {
        anyhow::bail!("bootstrap secret must match `maskura_secret_<32-hex>`");
    }
    Ok(())
}

fn bootstrap_api_key(
    key_id: &str,
    secret: &str,
    user_id: &str,
    workspace_id: &WorkspaceId,
    label: &str,
    cipher: Option<&SecretCipher>,
) -> anyhow::Result<(ApiKey, String)> {
    bootstrap_api_key_validated(key_id, secret, user_id, workspace_id, label, cipher, false)
}

/// Seed a local-appliance root credential whose access key/secret need not
/// match the `maskura_`/`maskura_secret_` format. Bounded and control-
/// character-free only.
fn bootstrap_root_api_key(
    key_id: &str,
    secret: &str,
    user_id: &str,
    workspace_id: &WorkspaceId,
    label: &str,
    cipher: Option<&SecretCipher>,
) -> anyhow::Result<(ApiKey, String)> {
    bootstrap_api_key_validated(key_id, secret, user_id, workspace_id, label, cipher, true)
}

fn validate_root_credential_part(value: &str, name: &str) -> anyhow::Result<()> {
    if value.is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    if value.chars().any(char::is_control) {
        anyhow::bail!("{name} must not contain control characters");
    }
    if value.len() > MAX_ROOT_CREDENTIAL_BYTES {
        anyhow::bail!("{name} must not exceed {MAX_ROOT_CREDENTIAL_BYTES} UTF-8 bytes");
    }
    Ok(())
}

fn bootstrap_api_key_validated(
    key_id: &str,
    secret: &str,
    user_id: &str,
    workspace_id: &WorkspaceId,
    label: &str,
    cipher: Option<&SecretCipher>,
    relaxed: bool,
) -> anyhow::Result<(ApiKey, String)> {
    if relaxed {
        validate_root_credential_part(key_id, "root access key")?;
        validate_root_credential_part(secret, "root secret key")?;
    } else {
        validate_bootstrap_key_id(key_id)?;
        validate_bootstrap_secret(secret)?;
    }
    let label = canonicalize_credential_label(label)?;
    let secret_hash = sha256_hash(secret);
    let secret_encrypted = match cipher {
        Some(cipher) => Some(
            cipher
                .encrypt(key_id, secret)
                .context("API key secret encryption failed")?,
        ),
        None => {
            tracing::warn!("secret encryption is not configured; header authentication only");
            None
        }
    };
    let api_key = build_api_key(
        key_id,
        user_id,
        Some(workspace_id.as_str().to_string()),
        &label,
        secret_hash,
        secret_encrypted,
        chrono_now(),
        None,
        None,
    );
    Ok((api_key, secret.to_string()))
}

fn generate_mcp_token(
    user_id: &str,
    workspace_id: &WorkspaceId,
    label: &str,
    expires_in: u64,
) -> anyhow::Result<(McpToken, String)> {
    let label = canonicalize_credential_label(label)?;
    validate_credential_ttl(expires_in)?;
    let token = format!(
        "maskura_mcp_{}",
        Uuid::new_v4().to_string().replace('-', "")
    );
    let now = chrono_now().parse::<u64>().unwrap_or(0);
    let expires_at = if expires_in > 0 {
        Some(
            now.checked_add(expires_in)
                .context("MCP token expiry overflow")?
                .to_string(),
        )
    } else {
        None
    };
    Ok((
        McpToken {
            credential_id: Some(Uuid::now_v7().to_string()),
            token_hash: sha256_hash(&token),
            user_id: user_id.to_string(),
            workspace_id: Some(workspace_id.as_str().to_string()),
            label,
            created_at: chrono_now(),
            expires_at,
        },
        token,
    ))
}

fn authenticated_mcp_principal(
    token: &McpToken,
    workspace_id: WorkspaceId,
) -> anyhow::Result<AuthenticatedMcpPrincipal> {
    let credential_id = match token.credential_id.as_deref() {
        Some(value) => value.parse().context("MCP credential ID is invalid")?,
        None => Uuid::new_v5(&Uuid::NAMESPACE_OID, token.token_hash.as_bytes()),
    };
    Ok(AuthenticatedMcpPrincipal {
        context: crate::control::AuthenticatedRequestContext {
            user_id: token.user_id.clone(),
            workspace_id,
        },
        credential_id,
        credential_policy_id: format!("mcp:{credential_id}"),
    })
}

fn listable_mcp_token(token: &McpToken) -> bool {
    token
        .credential_id
        .as_deref()
        .is_some_and(|credential_id| credential_id.parse::<Uuid>().is_ok())
        && token
            .workspace_id
            .as_deref()
            .is_some_and(|workspace_id| WorkspaceId::new(workspace_id.to_string()).is_ok())
}

fn decrypt_verified_secret(
    cipher: &SecretCipher,
    key_id: &str,
    secret_hash: &str,
    blob: &str,
) -> anyhow::Result<Option<(String, Option<String>)>> {
    let Some(secret) = cipher.decrypt_result(key_id, blob)? else {
        return Ok(None);
    };
    if sha256_hash(&secret) != secret_hash {
        tracing::warn!("decrypted API key secret failed hash verification");
        return Ok(None);
    }
    let rewrapped = if SecretCipher::is_legacy_envelope(blob) {
        Some(
            cipher
                .encrypt(key_id, &secret)
                .context("legacy API key secret rewrap encryption failed")?,
        )
    } else {
        None
    };
    Ok(Some((secret, rewrapped)))
}

fn compare_and_swap_envelope(
    keys: &RwLock<HashMap<String, ApiKey>>,
    key_id: &str,
    expected: &str,
    replacement: String,
) -> anyhow::Result<bool> {
    let mut keys = keys
        .write()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
    let Some(key) = keys.get_mut(key_id) else {
        return Ok(false);
    };
    if key.secret_encrypted.as_deref() != Some(expected) {
        return Ok(false);
    }
    key.secret_encrypted = Some(replacement);
    Ok(true)
}

#[derive(Debug, PartialEq, Eq)]
enum EnvelopeUpdate {
    Replaced,
    AlreadyRewrapped,
}

fn key_has_matching_v2_secret(
    cipher: &SecretCipher,
    key: &ApiKey,
    key_id: &str,
    secret_hash: &str,
    secret: &str,
) -> anyhow::Result<bool> {
    if key.key_id != key_id || key.secret_hash != secret_hash {
        return Ok(false);
    }
    let Some(blob) = key.secret_encrypted.as_deref() else {
        return Ok(false);
    };
    if !blob.starts_with("v2:") {
        return Ok(false);
    }
    Ok(decrypt_verified_secret(cipher, key_id, secret_hash, blob)?
        .is_some_and(|(current, rewrapped)| rewrapped.is_none() && current == secret))
}

fn replace_or_accept_rewrapped_envelope(
    keys: &RwLock<HashMap<String, ApiKey>>,
    cipher: &SecretCipher,
    key_id: &str,
    secret_hash: &str,
    secret: &str,
    expected: &str,
    replacement: String,
) -> anyhow::Result<Option<EnvelopeUpdate>> {
    if compare_and_swap_envelope(keys, key_id, expected, replacement)? {
        return Ok(Some(EnvelopeUpdate::Replaced));
    }
    let keys = keys
        .read()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
    let Some(current) = keys.get(key_id) else {
        return Ok(None);
    };
    Ok(
        key_has_matching_v2_secret(cipher, current, key_id, secret_hash, secret)?
            .then_some(EnvelopeUpdate::AlreadyRewrapped),
    )
}

fn set_public_key_in(
    keys: &RwLock<HashMap<String, ApiKey>>,
    key_id: &str,
    user_id: &str,
    public_key_pem: &str,
) -> anyhow::Result<bool> {
    let mut keys = keys
        .write()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
    if let Some(k) = keys.get_mut(key_id)
        && k.user_id == user_id
    {
        k.public_key_pem = Some(public_key_pem.to_string());
        return Ok(true);
    }
    Ok(false)
}

fn get_key_in(
    keys: &RwLock<HashMap<String, ApiKey>>,
    key_id: &str,
) -> anyhow::Result<Option<ApiKey>> {
    Ok(keys
        .read()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?
        .get(key_id)
        .cloned())
}

fn resolve_credentials_in(
    keys: &RwLock<HashMap<String, ApiKey>>,
    access_key: &str,
    secret_key: &str,
) -> anyhow::Result<Option<(crate::control::AuthenticatedRequestContext, Option<String>)>> {
    let keys = keys
        .read()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
    let Some(key) = keys.get(access_key) else {
        return Ok(None);
    };
    if key.secret_hash != sha256_hash(secret_key) {
        return Ok(None);
    }
    if is_expired(key.expires_at.as_deref()) {
        return Ok(None);
    }
    let Some(workspace_id) = key
        .workspace_id
        .clone()
        .and_then(|value| WorkspaceId::new(value).ok())
    else {
        return Ok(None);
    };
    Ok(Some((
        crate::control::AuthenticatedRequestContext {
            user_id: key.user_id.clone(),
            workspace_id,
        },
        key.public_key_pem.clone(),
    )))
}

fn list_for_user_in(
    keys: &RwLock<HashMap<String, ApiKey>>,
    user_id: &str,
) -> anyhow::Result<Vec<ApiKey>> {
    Ok(keys
        .read()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?
        .values()
        .filter(|k| k.user_id == user_id)
        .map(|k| {
            build_api_key(
                &k.key_id,
                &k.user_id,
                k.workspace_id.clone(),
                &k.label,
                String::new(),
                None,
                k.created_at.clone(),
                k.expires_at.clone(),
                k.public_key_pem.clone(),
            )
        })
        .collect())
}

fn delete_key_in(
    keys: &RwLock<HashMap<String, ApiKey>>,
    key_id: &str,
    user_id: &str,
) -> anyhow::Result<bool> {
    let mut keys = keys
        .write()
        .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
    if let Some(k) = keys.get(key_id)
        && k.user_id == user_id
    {
        keys.remove(key_id);
        return Ok(true);
    }
    Ok(false)
}

#[async_trait]
impl KeyRepository for KeyStore {
    async fn create_key(
        &self,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
        expires_in: u64,
        public_key_pem: Option<String>,
    ) -> anyhow::Result<(String, ApiKey)> {
        let (api_key, secret) = generate_api_key(
            user_id,
            workspace_id,
            label,
            expires_in,
            public_key_pem,
            self.cipher.as_deref(),
        )?;
        let key_id = api_key.key_id.clone();
        let committed = api_key.clone();
        self.keys
            .write()
            .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?
            .insert(key_id.clone(), api_key);
        Ok((secret, committed))
    }

    async fn bootstrap_key(
        &self,
        key_id: &str,
        secret: &str,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
    ) -> anyhow::Result<ApiKey> {
        let (api_key, _) = bootstrap_api_key(
            key_id,
            secret,
            user_id,
            workspace_id,
            label,
            self.cipher.as_deref(),
        )?;
        let committed = api_key.clone();
        let mut keys = self
            .keys
            .write()
            .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
        if keys.contains_key(key_id) {
            anyhow::bail!("bootstrap key id already exists");
        }
        keys.insert(key_id.to_string(), api_key);
        Ok(committed)
    }

    async fn bootstrap_root_credential(
        &self,
        access_key: &str,
        secret: &str,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
    ) -> anyhow::Result<ApiKey> {
        let (api_key, _) = bootstrap_root_api_key(
            access_key,
            secret,
            user_id,
            workspace_id,
            label,
            self.cipher.as_deref(),
        )?;
        let committed = api_key.clone();
        let mut keys = self
            .keys
            .write()
            .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
        if keys.contains_key(access_key) {
            anyhow::bail!("root access key already exists");
        }
        keys.insert(access_key.to_string(), api_key);
        Ok(committed)
    }

    async fn set_public_key(
        &self,
        key_id: &str,
        user_id: &str,
        public_key_pem: &str,
    ) -> anyhow::Result<bool> {
        let public_key_pem = canonicalize_public_key_pem(public_key_pem)?;
        set_public_key_in(&self.keys, key_id, user_id, &public_key_pem)
    }

    async fn get_key(&self, key_id: &str) -> anyhow::Result<Option<ApiKey>> {
        get_key_in(&self.keys, key_id)
    }

    async fn decrypt_secret(&self, key_id: &str) -> anyhow::Result<Option<String>> {
        let Some(cipher) = self.cipher.as_deref() else {
            return Ok(None);
        };
        let (secret_hash, blob) = {
            let keys = self
                .keys
                .read()
                .map_err(|_| anyhow::anyhow!("KeyStore API key lock poisoned"))?;
            let Some(key) = keys.get(key_id) else {
                return Ok(None);
            };
            let Some(blob) = key.secret_encrypted.clone() else {
                return Ok(None);
            };
            (key.secret_hash.clone(), blob)
        };
        let Some((secret, rewrapped)) =
            decrypt_verified_secret(cipher, key_id, &secret_hash, &blob)?
        else {
            return Ok(None);
        };
        if let Some(rewrapped) = rewrapped {
            let Some(_) = replace_or_accept_rewrapped_envelope(
                &self.keys,
                cipher,
                key_id,
                &secret_hash,
                &secret,
                &blob,
                rewrapped,
            )?
            else {
                return Ok(None);
            };
        }
        Ok(Some(secret))
    }

    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> anyhow::Result<Option<(crate::control::AuthenticatedRequestContext, Option<String>)>> {
        resolve_credentials_in(&self.keys, access_key, secret_key)
    }

    async fn list_for_user(&self, user_id: &str) -> anyhow::Result<Vec<ApiKey>> {
        list_for_user_in(&self.keys, user_id)
    }

    async fn delete_key(&self, key_id: &str, user_id: &str) -> anyhow::Result<bool> {
        delete_key_in(&self.keys, key_id, user_id)
    }

    async fn create_mcp_token(
        &self,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
        expires_in: u64,
    ) -> anyhow::Result<(String, McpToken)> {
        let (mcp, token) = generate_mcp_token(user_id, workspace_id, label, expires_in)?;
        self.mcp_tokens
            .write()
            .map_err(|_| anyhow::anyhow!("KeyStore MCP token lock poisoned"))?
            .insert(mcp.token_hash.clone(), mcp.clone());
        Ok((token, mcp))
    }

    async fn resolve_mcp_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<AuthenticatedMcpPrincipal>> {
        let hash = sha256_hash(token);
        let tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("KeyStore MCP token lock poisoned"))?;
        let Some(t) = tokens.get(&hash) else {
            return Ok(None);
        };
        if is_expired(t.expires_at.as_deref()) {
            return Ok(None);
        }
        let Some(workspace_id) = t
            .workspace_id
            .clone()
            .and_then(|value| WorkspaceId::new(value).ok())
        else {
            return Ok(None);
        };
        Ok(Some(authenticated_mcp_principal(t, workspace_id)?))
    }

    async fn list_mcp_tokens(&self, user_id: &str) -> anyhow::Result<Vec<McpToken>> {
        Ok(self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("KeyStore MCP token lock poisoned"))?
            .values()
            .filter(|t| t.user_id == user_id && listable_mcp_token(t))
            .cloned()
            .collect())
    }

    async fn delete_mcp_token(&self, token_hash: &str, user_id: &str) -> anyhow::Result<bool> {
        let mut tokens = self
            .mcp_tokens
            .write()
            .map_err(|_| anyhow::anyhow!("KeyStore MCP token lock poisoned"))?;
        if let Some(t) = tokens.get(token_hash)
            && t.user_id == user_id
        {
            tokens.remove(token_hash);
            return Ok(true);
        }
        Ok(false)
    }
}

/// Persistent key store backed by a JSON file (e.g. `~/.config/maskura/keys.json`).
///
/// Loads the file once at construction and rewrites it atomically (0600 on
/// unix) after every mutation, so API keys survive gateway restarts without
/// Postgres. This is the default in local mode (`AUTH_DISABLED=true` without
/// `DATABASE_URL`), or opt in explicitly with `MASKURA_KEYS_FILE`.
#[derive(Debug)]
pub struct FileKeyStore {
    keys: RwLock<HashMap<String, ApiKey>>,
    mcp_tokens: RwLock<HashMap<String, McpToken>>,
    // Every mutation shares one snapshot file. Writers take this lock first,
    // then acquire keys before mcp_tokens whenever both maps are needed.
    mutation_lock: Mutex<()>,
    #[cfg(test)]
    persist_hook: Mutex<Option<PersistTestHook>>,
    path: PathBuf,
    cipher: Option<Arc<SecretCipher>>,
}

#[cfg(test)]
#[derive(Debug)]
struct PersistTestHook {
    entered: std::sync::mpsc::SyncSender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

impl FileKeyStore {
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        let (keys, mut mcp_tokens) = load_file_store(&path)?;
        let migrated = assign_legacy_mcp_credential_ids(&mut mcp_tokens);
        ensure_file_store_parent(&path)?;
        let store = Self {
            keys: RwLock::new(keys),
            mcp_tokens: RwLock::new(mcp_tokens),
            mutation_lock: Mutex::new(()),
            #[cfg(test)]
            persist_hook: Mutex::new(None),
            path,
            cipher: None,
        };
        if migrated {
            store.persist()?;
        }
        Ok(store)
    }

    pub fn with_cipher(path: PathBuf, cipher: Arc<SecretCipher>) -> anyhow::Result<Self> {
        let (keys, mut mcp_tokens) = load_file_store(&path)?;
        let migrated = assign_legacy_mcp_credential_ids(&mut mcp_tokens);
        ensure_file_store_parent(&path)?;
        let store = Self {
            keys: RwLock::new(keys),
            mcp_tokens: RwLock::new(mcp_tokens),
            mutation_lock: Mutex::new(()),
            #[cfg(test)]
            persist_hook: Mutex::new(None),
            path,
            cipher: Some(cipher),
        };
        if migrated {
            store.persist()?;
        }
        Ok(store)
    }

    /// Default location for the local-mode keys file.
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("maskura")
            .join("keys.json")
    }

    /// Atomically write a caller-locked key snapshot to disk (0600 on unix).
    fn persist_snapshot(
        &self,
        keys: &HashMap<String, ApiKey>,
        mcp_tokens: &HashMap<String, McpToken>,
    ) -> anyhow::Result<()> {
        #[cfg(test)]
        if let Some(hook) = self
            .persist_hook
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore persist hook lock poisoned"))?
            .take()
        {
            hook.entered.send(()).unwrap();
            hook.resume.recv().unwrap();
        }
        #[derive(serde::Serialize)]
        struct Persisted<'a> {
            keys: &'a HashMap<String, ApiKey>,
            mcp_tokens: &'a HashMap<String, McpToken>,
        }
        let data = Persisted { keys, mcp_tokens };
        let json = serde_json::to_string_pretty(&data)?;
        ensure_file_store_parent(&self.path)?;
        let mut tmp_name = self.path.as_os_str().to_os_string();
        tmp_name.push(".tmp");
        let tmp = PathBuf::from(tmp_name);
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, &self.path)?;
        // Rename commits the snapshot. No error may escape after this point or
        // callers would roll back memory while disk contains the new state.
        #[cfg(unix)]
        {
            let parent = self
                .path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            if std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .is_err()
            {
                tracing::warn!("FileKeyStore parent directory sync failed after committed rename");
            }
        }
        Ok(())
    }

    fn persist(&self) -> anyhow::Result<()> {
        let keys = self
            .keys
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
        let mcp_tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?;
        self.persist_snapshot(&keys, &mcp_tokens)
    }
}

fn assign_legacy_mcp_credential_ids(tokens: &mut HashMap<String, McpToken>) -> bool {
    let mut migrated = false;
    for token in tokens.values_mut() {
        if token.credential_id.is_none() {
            token.credential_id =
                Some(Uuid::new_v5(&Uuid::NAMESPACE_OID, token.token_hash.as_bytes()).to_string());
            migrated = true;
        }
    }
    migrated
}

fn ensure_file_store_parent(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).context("FileKeyStore parent directory creation failed")?;
    }
    Ok(())
}

#[async_trait]
impl KeyRepository for FileKeyStore {
    async fn create_key(
        &self,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
        expires_in: u64,
        public_key_pem: Option<String>,
    ) -> anyhow::Result<(String, ApiKey)> {
        let (api_key, secret) = generate_api_key(
            user_id,
            workspace_id,
            label,
            expires_in,
            public_key_pem,
            self.cipher.as_deref(),
        )?;
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
        let key_id = api_key.key_id.clone();
        let inserted = api_key.clone();
        let mut keys = self
            .keys
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
        let mcp_tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
            .clone();
        let previous = keys.insert(key_id.clone(), api_key);
        if let Err(error) = self.persist_snapshot(&keys, &mcp_tokens) {
            if keys.get(&key_id) == Some(&inserted) {
                if let Some(previous) = previous {
                    keys.insert(key_id.clone(), previous);
                } else {
                    keys.remove(&key_id);
                }
            }
            return Err(error.context("FileKeyStore persist failed"));
        }
        Ok((secret, inserted))
    }

    async fn bootstrap_key(
        &self,
        key_id: &str,
        secret: &str,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
    ) -> anyhow::Result<ApiKey> {
        let (api_key, _) = bootstrap_api_key(
            key_id,
            secret,
            user_id,
            workspace_id,
            label,
            self.cipher.as_deref(),
        )?;
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
        let inserted = api_key.clone();
        let mut keys = self
            .keys
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
        if keys.contains_key(key_id) {
            anyhow::bail!("bootstrap key id already exists");
        }
        let mcp_tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
            .clone();
        keys.insert(key_id.to_string(), api_key);
        if let Err(error) = self.persist_snapshot(&keys, &mcp_tokens) {
            keys.remove(key_id);
            return Err(error.context("FileKeyStore persist failed"));
        }
        Ok(inserted)
    }

    async fn bootstrap_root_credential(
        &self,
        access_key: &str,
        secret: &str,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
    ) -> anyhow::Result<ApiKey> {
        let (api_key, _) = bootstrap_root_api_key(
            access_key,
            secret,
            user_id,
            workspace_id,
            label,
            self.cipher.as_deref(),
        )?;
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
        let inserted = api_key.clone();
        let mut keys = self
            .keys
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
        if keys.contains_key(access_key) {
            anyhow::bail!("root access key already exists");
        }
        let mcp_tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
            .clone();
        keys.insert(access_key.to_string(), api_key);
        if let Err(error) = self.persist_snapshot(&keys, &mcp_tokens) {
            keys.remove(access_key);
            return Err(error.context("FileKeyStore persist failed"));
        }
        Ok(inserted)
    }

    async fn set_public_key(
        &self,
        key_id: &str,
        user_id: &str,
        public_key_pem: &str,
    ) -> anyhow::Result<bool> {
        let public_key_pem = canonicalize_public_key_pem(public_key_pem)?;
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
        let mut keys = self
            .keys
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
        let mcp_tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
            .clone();
        let Some(key) = keys.get_mut(key_id) else {
            return Ok(false);
        };
        if key.user_id != user_id {
            return Ok(false);
        }
        let previous = key.public_key_pem.replace(public_key_pem.clone());
        if let Err(error) = self.persist_snapshot(&keys, &mcp_tokens) {
            if let Some(key) = keys.get_mut(key_id)
                && key.user_id == user_id
                && key.public_key_pem.as_deref() == Some(public_key_pem.as_str())
            {
                key.public_key_pem = previous;
            }
            return Err(error.context("FileKeyStore public key persist failed"));
        }
        Ok(true)
    }

    async fn get_key(&self, key_id: &str) -> anyhow::Result<Option<ApiKey>> {
        get_key_in(&self.keys, key_id)
    }

    async fn decrypt_secret(&self, key_id: &str) -> anyhow::Result<Option<String>> {
        let Some(cipher) = self.cipher.as_deref() else {
            return Ok(None);
        };
        let (secret_hash, blob) = {
            let keys = self
                .keys
                .read()
                .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
            let Some(key) = keys.get(key_id) else {
                return Ok(None);
            };
            let Some(blob) = key.secret_encrypted.clone() else {
                return Ok(None);
            };
            (key.secret_hash.clone(), blob)
        };
        let Some((secret, rewrapped)) =
            decrypt_verified_secret(cipher, key_id, &secret_hash, &blob)?
        else {
            return Ok(None);
        };
        if let Some(rewrapped) = rewrapped {
            let _mutation_guard = self
                .mutation_lock
                .lock()
                .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
            let mut keys = self
                .keys
                .write()
                .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
            let mcp_tokens = self
                .mcp_tokens
                .read()
                .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
                .clone();
            let update = if let Some(key) = keys.get_mut(key_id) {
                if key.secret_encrypted.as_deref() == Some(blob.as_str()) {
                    key.secret_encrypted = Some(rewrapped.clone());
                    Some(EnvelopeUpdate::Replaced)
                } else if key_has_matching_v2_secret(cipher, key, key_id, &secret_hash, &secret)? {
                    Some(EnvelopeUpdate::AlreadyRewrapped)
                } else {
                    None
                }
            } else {
                None
            };
            let Some(update) = update else {
                return Ok(None);
            };
            match update {
                EnvelopeUpdate::Replaced => {
                    if let Err(error) = self.persist_snapshot(&keys, &mcp_tokens) {
                        if let Some(key) = keys.get_mut(key_id)
                            && key.secret_encrypted.as_deref() == Some(rewrapped.as_str())
                        {
                            key.secret_encrypted = Some(blob);
                        }
                        return Err(
                            error.context("FileKeyStore legacy secret rewrap persist failed")
                        );
                    }
                }
                EnvelopeUpdate::AlreadyRewrapped => {}
            }
        }
        Ok(Some(secret))
    }

    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> anyhow::Result<Option<(crate::control::AuthenticatedRequestContext, Option<String>)>> {
        resolve_credentials_in(&self.keys, access_key, secret_key)
    }

    async fn list_for_user(&self, user_id: &str) -> anyhow::Result<Vec<ApiKey>> {
        list_for_user_in(&self.keys, user_id)
    }

    async fn delete_key(&self, key_id: &str, user_id: &str) -> anyhow::Result<bool> {
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
        let mut keys = self
            .keys
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?;
        let mcp_tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
            .clone();
        let Some(key) = keys.get(key_id) else {
            return Ok(false);
        };
        if key.user_id != user_id {
            return Ok(false);
        }
        let removed = keys.remove(key_id).expect("key existence checked");
        if let Err(error) = self.persist_snapshot(&keys, &mcp_tokens) {
            keys.insert(key_id.to_string(), removed);
            return Err(error.context("FileKeyStore key deletion persist failed"));
        }
        Ok(true)
    }

    async fn create_mcp_token(
        &self,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
        expires_in: u64,
    ) -> anyhow::Result<(String, McpToken)> {
        let (mcp, token) = generate_mcp_token(user_id, workspace_id, label, expires_in)?;
        let token_hash = mcp.token_hash.clone();
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
        let keys = self
            .keys
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?
            .clone();
        let inserted = mcp.clone();
        let mut tokens = self
            .mcp_tokens
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?;
        let previous = tokens.insert(token_hash.clone(), mcp);
        if let Err(error) = self.persist_snapshot(&keys, &tokens) {
            if tokens.get(&token_hash) == Some(&inserted) {
                if let Some(previous) = previous {
                    tokens.insert(token_hash.clone(), previous);
                } else {
                    tokens.remove(&token_hash);
                }
            }
            return Err(error.context("FileKeyStore MCP token creation persist failed"));
        }
        Ok((token, inserted))
    }

    async fn resolve_mcp_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<AuthenticatedMcpPrincipal>> {
        let hash = sha256_hash(token);
        let tokens = self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?;
        let Some(t) = tokens.get(&hash) else {
            return Ok(None);
        };
        if is_expired(t.expires_at.as_deref()) {
            return Ok(None);
        }
        let Some(workspace_id) = t
            .workspace_id
            .clone()
            .and_then(|value| WorkspaceId::new(value).ok())
        else {
            return Ok(None);
        };
        Ok(Some(authenticated_mcp_principal(t, workspace_id)?))
    }

    async fn list_mcp_tokens(&self, user_id: &str) -> anyhow::Result<Vec<McpToken>> {
        Ok(self
            .mcp_tokens
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?
            .values()
            .filter(|t| t.user_id == user_id && listable_mcp_token(t))
            .cloned()
            .collect())
    }

    async fn delete_mcp_token(&self, token_hash: &str, user_id: &str) -> anyhow::Result<bool> {
        let _mutation_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("FileKeyStore mutation lock poisoned"))?;
        let keys = self
            .keys
            .read()
            .map_err(|_| anyhow::anyhow!("FileKeyStore API key lock poisoned"))?
            .clone();
        let mut tokens = self
            .mcp_tokens
            .write()
            .map_err(|_| anyhow::anyhow!("FileKeyStore MCP token lock poisoned"))?;
        let Some(token) = tokens.get(token_hash) else {
            return Ok(false);
        };
        if token.user_id != user_id {
            return Ok(false);
        }
        let removed = tokens.remove(token_hash).expect("token existence checked");
        if let Err(error) = self.persist_snapshot(&keys, &tokens) {
            tokens.insert(token_hash.to_string(), removed);
            return Err(error.context("FileKeyStore MCP token deletion persist failed"));
        }
        Ok(true)
    }
}

impl From<api_key::Model> for ApiKey {
    fn from(m: api_key::Model) -> Self {
        build_api_key(
            &m.key_id,
            &m.user_id,
            m.workspace_id,
            &m.label,
            m.secret_hash,
            m.secret_encrypted,
            m.created_at.timestamp().to_string(),
            m.expires_at.map(|e| e.to_string()),
            m.public_key_pem,
        )
    }
}

async fn fetch_key(db: &DatabaseConnection, key_id: &str) -> anyhow::Result<Option<ApiKey>> {
    Ok(api_key::Entity::find()
        .filter(api_key::Column::KeyId.eq(key_id.to_string()))
        .one(db)
        .await
        .context("Postgres API key lookup failed")?
        .map(Into::into))
}

#[async_trait]
impl KeyRepository for PostgresKeyStore {
    async fn create_key(
        &self,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
        expires_in: u64,
        public_key_pem: Option<String>,
    ) -> anyhow::Result<(String, ApiKey)> {
        let (api_key, secret) = generate_api_key(
            user_id,
            workspace_id,
            label,
            expires_in,
            public_key_pem,
            self.cipher.as_deref(),
        )?;
        let expires_at = api_key
            .expires_at
            .as_deref()
            .map(str::parse::<i64>)
            .transpose()
            .context("API key expiry is outside the Postgres timestamp range")?;
        let model = api_key::ActiveModel {
            user_id: Set(api_key.user_id.clone()),
            workspace_id: Set(api_key.workspace_id.clone()),
            key_id: Set(api_key.key_id.clone()),
            secret_hash: Set(api_key.secret_hash.clone()),
            secret_encrypted: Set(api_key.secret_encrypted.clone()),
            label: Set(api_key.label.clone()),
            expires_at: Set(expires_at),
            public_key_pem: Set(api_key.public_key_pem.clone()),
            ..Default::default()
        };
        let inserted = model
            .insert(&self.db)
            .await
            .context("Postgres API key insert failed")?;
        Ok((secret, inserted.into()))
    }

    async fn bootstrap_key(
        &self,
        key_id: &str,
        secret: &str,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
    ) -> anyhow::Result<ApiKey> {
        let (api_key, _) = bootstrap_api_key(
            key_id,
            secret,
            user_id,
            workspace_id,
            label,
            self.cipher.as_deref(),
        )?;
        if fetch_key(&self.db, key_id).await?.is_some() {
            anyhow::bail!("bootstrap key id already exists");
        }
        let expires_at = api_key
            .expires_at
            .as_deref()
            .map(str::parse::<i64>)
            .transpose()
            .context("API key expiry is outside the Postgres timestamp range")?;
        let model = api_key::ActiveModel {
            user_id: Set(api_key.user_id.clone()),
            workspace_id: Set(api_key.workspace_id.clone()),
            key_id: Set(api_key.key_id.clone()),
            secret_hash: Set(api_key.secret_hash.clone()),
            secret_encrypted: Set(api_key.secret_encrypted.clone()),
            label: Set(api_key.label.clone()),
            expires_at: Set(expires_at),
            public_key_pem: Set(api_key.public_key_pem.clone()),
            ..Default::default()
        };
        let inserted = model
            .insert(&self.db)
            .await
            .context("Postgres API key insert failed")?;
        Ok(inserted.into())
    }

    async fn bootstrap_root_credential(
        &self,
        access_key: &str,
        secret: &str,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
    ) -> anyhow::Result<ApiKey> {
        let (api_key, _) = bootstrap_root_api_key(
            access_key,
            secret,
            user_id,
            workspace_id,
            label,
            self.cipher.as_deref(),
        )?;
        if fetch_key(&self.db, access_key).await?.is_some() {
            anyhow::bail!("root access key already exists");
        }
        let model = api_key::ActiveModel {
            user_id: Set(api_key.user_id.clone()),
            workspace_id: Set(api_key.workspace_id.clone()),
            key_id: Set(api_key.key_id.clone()),
            secret_hash: Set(api_key.secret_hash.clone()),
            secret_encrypted: Set(api_key.secret_encrypted.clone()),
            label: Set(api_key.label.clone()),
            expires_at: Set(None),
            public_key_pem: Set(api_key.public_key_pem.clone()),
            ..Default::default()
        };
        let inserted = model
            .insert(&self.db)
            .await
            .context("Postgres API key insert failed")?;
        Ok(inserted.into())
    }

    async fn set_public_key(
        &self,
        key_id: &str,
        user_id: &str,
        public_key_pem: &str,
    ) -> anyhow::Result<bool> {
        let public_key_pem = canonicalize_public_key_pem(public_key_pem)?;
        let result = api_key::Entity::update_many()
            .col_expr(
                api_key::Column::PublicKeyPem,
                Expr::value(Some(public_key_pem)),
            )
            .filter(api_key::Column::KeyId.eq(key_id.to_string()))
            .filter(api_key::Column::UserId.eq(user_id.to_string()))
            .exec(&self.db)
            .await
            .context("Postgres public key update failed")?;
        match result.rows_affected {
            0 => Ok(false),
            1 => Ok(true),
            rows => anyhow::bail!("Postgres public key update affected {rows} rows"),
        }
    }

    async fn get_key(&self, key_id: &str) -> anyhow::Result<Option<ApiKey>> {
        fetch_key(&self.db, key_id).await
    }

    async fn decrypt_secret(&self, key_id: &str) -> anyhow::Result<Option<String>> {
        let Some(cipher) = self.cipher.as_deref() else {
            return Ok(None);
        };
        let Some(key) = fetch_key(&self.db, key_id).await? else {
            return Ok(None);
        };
        let Some(blob) = key.secret_encrypted.clone() else {
            return Ok(None);
        };
        let Some((secret, rewrapped)) =
            decrypt_verified_secret(cipher, key_id, &key.secret_hash, &blob)?
        else {
            return Ok(None);
        };
        if let Some(rewrapped) = rewrapped {
            let result = api_key::Entity::update_many()
                .col_expr(
                    api_key::Column::SecretEncrypted,
                    Expr::value(Some(rewrapped)),
                )
                .filter(api_key::Column::KeyId.eq(key_id.to_string()))
                .filter(api_key::Column::SecretEncrypted.eq(blob.clone()))
                .exec(&self.db)
                .await;
            let reread = match result {
                Ok(update) if update.rows_affected == 1 => false,
                Ok(update) if update.rows_affected == 0 => true,
                Ok(update) => anyhow::bail!(
                    "Postgres legacy secret rewrap affected {} rows",
                    update.rows_affected
                ),
                Err(error) => {
                    let current = fetch_key(&self.db, key_id).await?;
                    if let Some(current) = current.as_ref()
                        && key_has_matching_v2_secret(
                            cipher,
                            current,
                            key_id,
                            &key.secret_hash,
                            &secret,
                        )?
                    {
                        return Ok(Some(secret));
                    }
                    return Err(
                        anyhow::Error::new(error).context("Postgres legacy secret rewrap failed")
                    );
                }
            };
            if reread {
                let Some(current) = fetch_key(&self.db, key_id).await? else {
                    return Ok(None);
                };
                if !key_has_matching_v2_secret(cipher, &current, key_id, &key.secret_hash, &secret)?
                {
                    return Ok(None);
                }
            }
        }
        Ok(Some(secret))
    }

    async fn resolve_credentials(
        &self,
        access_key: &str,
        secret_key: &str,
    ) -> anyhow::Result<Option<(crate::control::AuthenticatedRequestContext, Option<String>)>> {
        let Some(key) = fetch_key(&self.db, access_key).await? else {
            return Ok(None);
        };
        if key.secret_hash != sha256_hash(secret_key) {
            return Ok(None);
        }
        if is_expired(key.expires_at.as_deref()) {
            return Ok(None);
        }
        let Some(workspace_id) = key
            .workspace_id
            .and_then(|value| WorkspaceId::new(value).ok())
        else {
            return Ok(None);
        };
        Ok(Some((
            crate::control::AuthenticatedRequestContext {
                user_id: key.user_id,
                workspace_id,
            },
            key.public_key_pem,
        )))
    }

    async fn list_for_user(&self, user_id: &str) -> anyhow::Result<Vec<ApiKey>> {
        let rows = api_key::Entity::find()
            .filter(api_key::Column::UserId.eq(user_id.to_string()))
            .order_by_desc(api_key::Column::CreatedAt)
            .all(&self.db)
            .await
            .context("Postgres API key list failed")?;
        Ok(rows
            .into_iter()
            .map(|m| {
                let mut k: ApiKey = m.into();
                k.secret_hash = String::new();
                k.secret_encrypted = None;
                k
            })
            .collect())
    }

    async fn delete_key(&self, key_id: &str, user_id: &str) -> anyhow::Result<bool> {
        let result = api_key::Entity::delete_many()
            .filter(api_key::Column::KeyId.eq(key_id.to_string()))
            .filter(api_key::Column::UserId.eq(user_id.to_string()))
            .exec(&self.db)
            .await
            .context("Postgres API key delete failed")?;
        match result.rows_affected {
            0 => Ok(false),
            1 => Ok(true),
            rows => anyhow::bail!("Postgres API key delete affected {rows} rows"),
        }
    }

    async fn create_mcp_token(
        &self,
        user_id: &str,
        workspace_id: &WorkspaceId,
        label: &str,
        expires_in: u64,
    ) -> anyhow::Result<(String, McpToken)> {
        let (mcp, token) = generate_mcp_token(user_id, workspace_id, label, expires_in)?;
        let expires_at = mcp
            .expires_at
            .as_deref()
            .map(str::parse::<i64>)
            .transpose()
            .context("MCP token expiry is outside the Postgres timestamp range")?;
        let model = mcp_token::ActiveModel {
            id: Set(mcp
                .credential_id
                .as_deref()
                .expect("new MCP tokens have credential IDs")
                .parse()
                .context("generated MCP credential ID is invalid")?),
            user_id: Set(mcp.user_id.clone()),
            workspace_id: Set(mcp.workspace_id.clone()),
            token_hash: Set(mcp.token_hash.clone()),
            label: Set(mcp.label.clone()),
            expires_at: Set(expires_at),
            ..Default::default()
        };
        let inserted = model
            .insert(&self.db)
            .await
            .context("Postgres MCP token insert failed")?;
        Ok((
            token,
            McpToken {
                credential_id: Some(inserted.id.to_string()),
                token_hash: inserted.token_hash,
                user_id: inserted.user_id,
                workspace_id: inserted.workspace_id,
                label: inserted.label,
                created_at: inserted.created_at.to_string(),
                expires_at: inserted.expires_at.map(|value| value.to_string()),
            },
        ))
    }

    async fn resolve_mcp_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<AuthenticatedMcpPrincipal>> {
        let hash = sha256_hash(token);
        let row = mcp_token::Entity::find()
            .filter(mcp_token::Column::TokenHash.eq(hash))
            .one(&self.db)
            .await
            .context("Postgres MCP token lookup failed")?;
        let Some(row) = row else {
            return Ok(None);
        };
        if is_expired(row.expires_at.as_ref().map(|e| e.to_string()).as_deref()) {
            return Ok(None);
        }
        let Some(workspace_id) = row
            .workspace_id
            .and_then(|value| WorkspaceId::new(value).ok())
        else {
            return Ok(None);
        };
        let credential_id = row.id;
        Ok(Some(AuthenticatedMcpPrincipal {
            context: crate::control::AuthenticatedRequestContext {
                user_id: row.user_id,
                workspace_id,
            },
            credential_id,
            credential_policy_id: format!("mcp:{credential_id}"),
        }))
    }

    async fn list_mcp_tokens(&self, user_id: &str) -> anyhow::Result<Vec<McpToken>> {
        let rows = mcp_token::Entity::find()
            .filter(mcp_token::Column::UserId.eq(user_id.to_string()))
            .order_by_desc(mcp_token::Column::CreatedAt)
            .all(&self.db)
            .await
            .context("Postgres MCP token list failed")?;
        Ok(rows
            .into_iter()
            .map(|m| McpToken {
                credential_id: Some(m.id.to_string()),
                token_hash: m.token_hash,
                user_id: m.user_id,
                workspace_id: m.workspace_id,
                label: m.label,
                created_at: m.created_at.to_string(),
                expires_at: m.expires_at.map(|e| e.to_string()),
            })
            .filter(listable_mcp_token)
            .collect())
    }

    async fn delete_mcp_token(&self, token_hash: &str, user_id: &str) -> anyhow::Result<bool> {
        let result = mcp_token::Entity::delete_many()
            .filter(mcp_token::Column::TokenHash.eq(token_hash.to_string()))
            .filter(mcp_token::Column::UserId.eq(user_id.to_string()))
            .exec(&self.db)
            .await
            .context("Postgres MCP token delete failed")?;
        match result.rows_affected {
            0 => Ok(false),
            1 => Ok(true),
            rows => anyhow::bail!("Postgres MCP token delete affected {rows} rows"),
        }
    }
}

/// Load a persisted FileKeyStore payload (keys + mcp_tokens), tolerating the
/// legacy keys-only JSON shape.
fn load_file_store(
    path: &Path,
) -> anyhow::Result<(HashMap<String, ApiKey>, HashMap<String, McpToken>)> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Persisted {
        #[serde(default)]
        keys: HashMap<String, ApiKey>,
        #[serde(default)]
        mcp_tokens: HashMap<String, McpToken>,
    }
    let payload = match std::fs::read_to_string(path) {
        Ok(payload) => payload,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((HashMap::new(), HashMap::new()));
        }
        Err(error) => return Err(error).context("FileKeyStore snapshot read failed"),
    };
    if let Ok(data) = serde_json::from_str::<Persisted>(&payload) {
        return Ok((data.keys, data.mcp_tokens));
    }
    // Legacy shape: bare keys map.
    let keys = serde_json::from_str::<HashMap<String, ApiKey>>(&payload)
        .context("FileKeyStore snapshot is invalid as current and legacy formats")?;
    Ok((keys, HashMap::new()))
}

fn is_expired(expires_at: Option<&str>) -> bool {
    if let Some(exp) = expires_at {
        let now = chrono_now().parse::<u64>().unwrap_or(0);
        return exp.parse::<u64>().map_or(true, |ts| now >= ts);
    }
    false
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha256_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

fn chrono_now() -> String {
    use std::time::SystemTime;
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", ts)
}

#[cfg(test)]
mod tests;
