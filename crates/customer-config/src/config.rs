use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamingReadMode {
    #[default]
    Off,
    Passthrough,
    Transformed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultipartMode {
    #[default]
    Reject,
    Staged,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedStreamingMode {
    #[default]
    Off,
    Observe,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamingS3Provider {
    Aws,
    Minio,
    R2,
    B2,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub listen_addr: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub disabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub mode: Option<String>,
    pub s3_endpoint: Option<String>,
    pub s3_region: Option<String>,
    pub single_tenant: bool,
    pub local_dir: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SupabaseConfig {
    pub url: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FeaturesConfig {
    pub multipart_mode: MultipartMode,
    pub streaming_read_mode: StreamingReadMode,
    pub transformed_read_spool: bool,
    pub enable_avro: bool,
    pub streaming_s3_provider: Option<StreamingS3Provider>,
    pub dev_memory_streaming: bool,
    pub managed_streaming_mode: ManagedStreamingMode,
    pub managed_streaming_transactional: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WasmConfig {
    pub filter_component: Option<String>,
    pub plugins_dir: Option<String>,
    pub fuel: Option<u64>,
    pub prefix_safe_component_hashes: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub source_max_frame_bytes: Option<u64>,
    pub max_object_bytes: Option<u64>,
    pub max_pipeline_output_bytes: Option<u64>,
    pub legacy_max_object_bytes: Option<u64>,
    pub dev_memory_max_object_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SpoolConfig {
    pub dir: Option<String>,
    pub max_object_bytes: Option<u64>,
    pub quota_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeysConfig {
    pub keys_file: Option<String>,
    pub bootstrap_key: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManagedConfig {
    pub placement_version: Option<u32>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MultipartStagingConfig {
    pub endpoint: Option<String>,
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub dir: Option<String>,
    pub tenant_quota_bytes: Option<u64>,
    pub global_quota_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SigV4Config {
    pub region: Option<String>,
    pub trusted_tls: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllowlistsConfig {
    pub workspace_endpoint: Vec<String>,
    pub workspace_endpoint_private: Vec<String>,
    pub presigned_http: Vec<String>,
    pub presigned_http_private: Vec<String>,
    pub presigned_http_allow_http: bool,
    pub presigned_http_min_validity_secs: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub storage: StorageConfig,
    pub supabase: SupabaseConfig,
    pub features: FeaturesConfig,
    pub wasm: WasmConfig,
    pub limits: LimitsConfig,
    pub spool: SpoolConfig,
    pub keys: KeysConfig,
    pub managed: ManagedConfig,
    pub multipart_staging: MultipartStagingConfig,
    pub sigv4: SigV4Config,
    pub allowlists: AllowlistsConfig,
    explicit: ExplicitSettings,
}

#[derive(Debug, Clone, Default)]
struct ExplicitSettings {
    multipart_mode: bool,
    streaming_read_mode: bool,
    filter_component: bool,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ConfigWire {
    server: ServerConfig,
    auth: AuthConfig,
    storage: StorageConfig,
    supabase: SupabaseConfig,
    features: FeaturesWire,
    wasm: WasmConfig,
    limits: LimitsConfig,
    spool: SpoolConfig,
    keys: KeysConfig,
    managed: ManagedConfig,
    multipart_staging: MultipartStagingConfig,
    sigv4: SigV4Config,
    allowlists: AllowlistsConfig,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FeaturesWire {
    multipart_mode: Option<MultipartMode>,
    streaming_read_mode: Option<StreamingReadMode>,
    transformed_read_spool: bool,
    enable_avro: bool,
    streaming_s3_provider: Option<StreamingS3Provider>,
    dev_memory_streaming: bool,
    managed_streaming_mode: ManagedStreamingMode,
    managed_streaming_transactional: bool,
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ConfigWire::deserialize(deserializer)?;
        let explicit = ExplicitSettings {
            multipart_mode: wire.features.multipart_mode.is_some(),
            streaming_read_mode: wire.features.streaming_read_mode.is_some(),
            filter_component: wire.wasm.filter_component.is_some(),
        };
        Ok(Self {
            server: wire.server,
            auth: wire.auth,
            storage: wire.storage,
            supabase: wire.supabase,
            features: FeaturesConfig {
                multipart_mode: wire.features.multipart_mode.unwrap_or_default(),
                streaming_read_mode: wire.features.streaming_read_mode.unwrap_or_default(),
                transformed_read_spool: wire.features.transformed_read_spool,
                enable_avro: wire.features.enable_avro,
                streaming_s3_provider: wire.features.streaming_s3_provider,
                dev_memory_streaming: wire.features.dev_memory_streaming,
                managed_streaming_mode: wire.features.managed_streaming_mode,
                managed_streaming_transactional: wire.features.managed_streaming_transactional,
            },
            wasm: wire.wasm,
            limits: wire.limits,
            spool: wire.spool,
            keys: wire.keys,
            managed: wire.managed,
            multipart_staging: wire.multipart_staging,
            sigv4: wire.sigv4,
            allowlists: wire.allowlists,
            explicit,
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid configuration at `{path}`: {message}")]
pub struct ConfigError {
    pub path: String,
    pub message: String,
}

fn invalid(path: &str, message: impl Into<String>) -> ConfigError {
    ConfigError {
        path: path.to_string(),
        message: message.into(),
    }
}

impl From<crate::EnvError> for ConfigError {
    fn from(error: crate::EnvError) -> Self {
        match error {
            crate::EnvError::NotUnicode { name } => invalid(name, "must contain valid UTF-8"),
        }
    }
}

impl Config {
    pub fn from_toml_str(input: &str) -> Result<Self, ConfigError> {
        let config = Self::from_toml_str_unvalidated(input, "<input>")?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let config = Self::from_file_unvalidated(path)?;
        config.validate()?;
        Ok(config)
    }

    fn from_file_unvalidated(path: &Path) -> Result<Self, ConfigError> {
        let input = std::fs::read_to_string(path).map_err(|error| {
            invalid(
                &path.display().to_string(),
                format!("failed to read config file: {error}"),
            )
        })?;
        Self::from_toml_str_unvalidated(&input, &path.display().to_string())
    }

    fn from_toml_str_unvalidated(input: &str, source: &str) -> Result<Self, ConfigError> {
        toml::from_str(input).map_err(|error| invalid(source, format!("malformed TOML: {error}")))
    }

    /// Resolve the effective configuration with the documented precedence:
    /// compiled defaults, then the file at `path` (when present), then the
    /// environment-variable override layer, then validation.
    ///
    /// With `path` absent the result is identical to the historical
    /// env-plus-defaults behaviour, so a gateway booted without a config file
    /// behaves exactly as before.
    pub fn resolve(path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut config = match path {
            Some(path) => Self::from_file_unvalidated(path)?,
            None => Self::default(),
        };
        config.apply_env_overrides()?;
        config.validate()?;
        Ok(config)
    }

    /// Apply the documented environment-variable override layer on top of the
    /// file-sourced values. Every non-secret field is overridable; secrets stay
    /// env-only and are resolved by the gateway, not here.
    pub fn apply_env_overrides(&mut self) -> Result<(), ConfigError> {
        use crate::{aliases, resolve};

        if let Some(value) = std::env::var("LISTEN_ADDR").ok().filter(|v| !v.is_empty()) {
            self.server.listen_addr = Some(value);
        }
        if let Some(value) = env_bool("AUTH_DISABLED")? {
            self.auth.disabled = value;
        }
        if let Some(value) = std::env::var("S3_ENDPOINT").ok().filter(|v| !v.is_empty()) {
            self.storage.s3_endpoint = Some(value);
        }
        self.apply_s3_region_override(|name| std::env::var(name).ok());
        if let Some(value) = resolve(aliases::SINGLE_TENANT)? {
            self.storage.single_tenant = parse_bool("storage.single_tenant", &value)?;
        }
        if let Some(value) = resolve(aliases::LOCAL_STORAGE_DIR)? {
            self.storage.local_dir = Some(value);
        }
        if let Some(value) = resolve(aliases::STORAGE_MODE)? {
            self.storage.mode = Some(value);
        }
        if let Some(value) = std::env::var("SUPABASE_URL").ok().filter(|v| !v.is_empty()) {
            self.supabase.url = Some(value);
        }
        if let Some(value) = resolve(aliases::MULTIPART_MODE)? {
            self.features.multipart_mode = parse_multipart_mode(&value)?;
            self.explicit.multipart_mode = true;
        }
        if let Some(value) = resolve(aliases::STREAMING_READ_MODE)? {
            self.features.streaming_read_mode = parse_streaming_read_mode(&value)?;
            self.explicit.streaming_read_mode = true;
        }
        if let Some(value) = resolve(aliases::TRANSFORMED_READ_SPOOL)? {
            self.features.transformed_read_spool = value.eq_ignore_ascii_case("encrypted");
        }
        if let Some(value) = resolve(aliases::ENABLE_AVRO)? {
            self.features.enable_avro = parse_bool("features.enable_avro", &value)?;
        }
        if let Some(value) = resolve(aliases::STREAMING_S3_PROVIDER)? {
            self.features.streaming_s3_provider = Some(parse_streaming_provider(&value)?);
        }
        if let Some(value) = resolve(aliases::DEV_MEMORY_STREAMING)? {
            self.features.dev_memory_streaming =
                parse_bool("features.dev_memory_streaming", &value)?;
        }
        if let Ok(value) = std::env::var("MASKURA_MANAGED_STREAMING_MODE") {
            self.features.managed_streaming_mode = parse_managed_mode(&value)?;
        }
        if let Ok(value) = std::env::var("MASKURA_MANAGED_STREAMING_TRANSACTIONAL") {
            self.features.managed_streaming_transactional =
                parse_bool("features.managed_streaming_transactional", &value)?;
        }
        if let Some(value) = resolve(aliases::DEFAULT_PLUGIN)? {
            self.wasm.filter_component = Some(value);
            self.explicit.filter_component = true;
        }
        if let Some(value) = resolve(aliases::PLUGINS_DIR)? {
            self.wasm.plugins_dir = Some(value);
        }
        if let Some(value) = resolve(aliases::WASM_FUEL)? {
            self.wasm.fuel = Some(parse_u64("wasm.fuel", &value)?);
        }
        if let Some(value) = resolve(aliases::PREFIX_SAFE_COMPONENT_HASHES)? {
            self.wasm.prefix_safe_component_hashes = split_commas(&value);
        }
        if let Some(value) = resolve(aliases::SOURCE_MAX_FRAME_BYTES)? {
            self.limits.source_max_frame_bytes =
                Some(parse_u64("limits.source_max_frame_bytes", &value)?);
        }
        if let Some(value) = resolve(aliases::MAX_OBJECT_BYTES)? {
            self.limits.max_object_bytes = Some(parse_u64("limits.max_object_bytes", &value)?);
        }
        if let Some(value) = resolve(aliases::MAX_PIPELINE_OUTPUT_BYTES)? {
            self.limits.max_pipeline_output_bytes =
                Some(parse_u64("limits.max_pipeline_output_bytes", &value)?);
        }
        if let Some(value) = resolve(aliases::LEGACY_MAX_OBJECT_BYTES)? {
            self.limits.legacy_max_object_bytes =
                Some(parse_u64("limits.legacy_max_object_bytes", &value)?);
        }
        if let Some(value) = resolve(aliases::DEV_MEMORY_MAX_OBJECT_BYTES)? {
            self.limits.dev_memory_max_object_bytes =
                Some(parse_u64("limits.dev_memory_max_object_bytes", &value)?);
        }
        if let Some(value) = resolve(aliases::SPOOL_DIR)? {
            self.spool.dir = Some(value);
        }
        if let Some(value) = resolve(aliases::SPOOL_MAX_OBJECT_BYTES)? {
            self.spool.max_object_bytes = Some(parse_u64("spool.max_object_bytes", &value)?);
        }
        if let Some(value) = resolve(aliases::SPOOL_QUOTA_BYTES)? {
            self.spool.quota_bytes = Some(parse_u64("spool.quota_bytes", &value)?);
        }
        if let Some(value) = resolve(aliases::KEYS_FILE)? {
            self.keys.keys_file = Some(value);
        }
        if let Some(value) = resolve(aliases::BOOTSTRAP_KEY)? {
            self.keys.bootstrap_key = Some(value);
        }
        if let Ok(value) = std::env::var("MASKURA_MANAGED_PLACEMENT_VERSION") {
            self.managed.placement_version = Some(parse_u32("managed.placement_version", &value)?);
        }
        if let Ok(value) = std::env::var("MASKURA_MULTIPART_STAGING_ENDPOINT") {
            self.multipart_staging.endpoint = Some(value);
        }
        if let Ok(value) = std::env::var("MASKURA_MULTIPART_STAGING_BUCKET") {
            self.multipart_staging.bucket = Some(value);
        }
        if let Ok(value) = std::env::var("MASKURA_MULTIPART_STAGING_REGION") {
            self.multipart_staging.region = Some(value);
        }
        if let Ok(value) = std::env::var("MASKURA_MULTIPART_STAGING_DIR") {
            self.multipart_staging.dir = Some(value);
        }
        if let Ok(value) = std::env::var("MASKURA_MULTIPART_STAGING_TENANT_QUOTA_BYTES") {
            self.multipart_staging.tenant_quota_bytes =
                Some(parse_u64("multipart_staging.tenant_quota_bytes", &value)?);
        }
        if let Ok(value) = std::env::var("MASKURA_MULTIPART_STAGING_GLOBAL_QUOTA_BYTES") {
            self.multipart_staging.global_quota_bytes =
                Some(parse_u64("multipart_staging.global_quota_bytes", &value)?);
        }
        if let Some(value) = std::env::var("MASKURA_SIGV4_REGION")
            .ok()
            .filter(|v| !v.is_empty())
        {
            self.sigv4.region = Some(value);
        }
        if let Ok(value) = std::env::var("MASKURA_SIGV4_TRUSTED_TLS") {
            self.sigv4.trusted_tls = parse_bool("sigv4.trusted_tls", &value)?;
        }
        if let Ok(value) = std::env::var("MASKURA_WORKSPACE_ENDPOINT_ALLOWLIST") {
            self.allowlists.workspace_endpoint = split_commas(&value);
        }
        if let Ok(value) = std::env::var("MASKURA_WORKSPACE_ENDPOINT_PRIVATE_ALLOWLIST") {
            self.allowlists.workspace_endpoint_private = split_commas(&value);
        }
        if let Ok(value) = std::env::var("MASKURA_PRESIGNED_HTTP_ALLOWLIST") {
            self.allowlists.presigned_http = split_commas(&value);
        }
        if let Ok(value) = std::env::var("MASKURA_PRESIGNED_HTTP_PRIVATE_ALLOWLIST") {
            self.allowlists.presigned_http_private = split_commas(&value);
        }
        if let Ok(value) = std::env::var("MASKURA_PRESIGNED_HTTP_ALLOW_HTTP") {
            self.allowlists.presigned_http_allow_http =
                parse_bool("allowlists.presigned_http_allow_http", &value)?;
        }
        if let Ok(value) = std::env::var("MASKURA_PRESIGNED_HTTP_MIN_VALIDITY_SECS") {
            self.allowlists.presigned_http_min_validity_secs = Some(parse_u64(
                "allowlists.presigned_http_min_validity_secs",
                &value,
            )?);
        }

        self.validate()
    }

    fn apply_s3_region_override(&mut self, mut read: impl FnMut(&str) -> Option<String>) {
        if let Some(value) = ["S3_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"]
            .into_iter()
            .find_map(|name| read(name).filter(|value| !value.is_empty()))
        {
            self.storage.s3_region = Some(value);
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(addr) = self.server.listen_addr.as_deref() {
            addr.parse::<SocketAddr>().map_err(|error| {
                invalid(
                    "server.listen_addr",
                    format!("{addr:?} is not a valid socket address: {error}"),
                )
            })?;
        }

        validate_url("storage.s3_endpoint", self.storage.s3_endpoint.as_deref())?;
        if let Some(region) = self.storage.s3_region.as_deref()
            && region.is_empty()
        {
            return Err(invalid("storage.s3_region", "must not be empty"));
        }
        if let Some(directory) = self.storage.local_dir.as_deref()
            && directory.is_empty()
        {
            return Err(invalid("storage.local_dir", "must not be empty"));
        }
        if let Some(mode) = self.storage.mode.as_deref()
            && mode != "local"
        {
            return Err(invalid("storage.mode", "must be local when configured"));
        }
        validate_url("supabase.url", self.supabase.url.as_deref())?;

        for (index, hash) in self.wasm.prefix_safe_component_hashes.iter().enumerate() {
            if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(invalid(
                    &format!("wasm.prefix_safe_component_hashes[{index}]"),
                    "must be a 64-character hexadecimal SHA-256 digest",
                ));
            }
        }
        if let Some(fuel) = self.wasm.fuel
            && fuel == 0
        {
            return Err(invalid("wasm.fuel", "must be greater than zero"));
        }

        for (path, value) in [
            (
                "limits.source_max_frame_bytes",
                self.limits.source_max_frame_bytes,
            ),
            ("limits.max_object_bytes", self.limits.max_object_bytes),
            (
                "limits.max_pipeline_output_bytes",
                self.limits.max_pipeline_output_bytes,
            ),
            (
                "limits.legacy_max_object_bytes",
                self.limits.legacy_max_object_bytes,
            ),
            (
                "limits.dev_memory_max_object_bytes",
                self.limits.dev_memory_max_object_bytes,
            ),
        ] {
            if let Some(value) = value
                && value == 0
            {
                return Err(invalid(path, "must be greater than zero"));
            }
        }

        if let Some(max) = self.spool.max_object_bytes
            && max == 0
        {
            return Err(invalid(
                "spool.max_object_bytes",
                "must be greater than zero",
            ));
        }
        if let Some(quota) = self.spool.quota_bytes {
            if quota == 0 {
                return Err(invalid("spool.quota_bytes", "must be greater than zero"));
            }
            if let Some(max) = self.spool.max_object_bytes
                && quota < max
            {
                return Err(invalid(
                    "spool.quota_bytes",
                    "must be greater than or equal to spool.max_object_bytes",
                ));
            }
        }

        if let Some(version) = self.managed.placement_version
            && version == 0
        {
            return Err(invalid(
                "managed.placement_version",
                "must be greater than zero",
            ));
        }

        validate_url(
            "multipart_staging.endpoint",
            self.multipart_staging.endpoint.as_deref(),
        )?;
        for (path, value) in [
            (
                "multipart_staging.bucket",
                self.multipart_staging.bucket.as_deref(),
            ),
            (
                "multipart_staging.region",
                self.multipart_staging.region.as_deref(),
            ),
            (
                "multipart_staging.dir",
                self.multipart_staging.dir.as_deref(),
            ),
        ] {
            if let Some(value) = value
                && value.is_empty()
            {
                return Err(invalid(path, "must not be empty"));
            }
        }
        for (path, value) in [
            (
                "multipart_staging.tenant_quota_bytes",
                self.multipart_staging.tenant_quota_bytes,
            ),
            (
                "multipart_staging.global_quota_bytes",
                self.multipart_staging.global_quota_bytes,
            ),
        ] {
            if let Some(value) = value
                && value == 0
            {
                return Err(invalid(path, "must be greater than zero"));
            }
        }
        if let (Some(tenant), Some(global)) = (
            self.multipart_staging.tenant_quota_bytes,
            self.multipart_staging.global_quota_bytes,
        ) && tenant > global
        {
            return Err(invalid(
                "multipart_staging.tenant_quota_bytes",
                "must be less than or equal to multipart_staging.global_quota_bytes",
            ));
        }

        if let Some(region) = self.sigv4.region.as_deref()
            && region.is_empty()
        {
            return Err(invalid("sigv4.region", "must not be empty"));
        }

        validate_host_entries(
            "allowlists.workspace_endpoint",
            &self.allowlists.workspace_endpoint,
        )?;
        validate_host_entries(
            "allowlists.workspace_endpoint_private",
            &self.allowlists.workspace_endpoint_private,
        )?;
        validate_host_entries("allowlists.presigned_http", &self.allowlists.presigned_http)?;
        validate_host_entries(
            "allowlists.presigned_http_private",
            &self.allowlists.presigned_http_private,
        )?;
        if let Some(validity) = self.allowlists.presigned_http_min_validity_secs
            && validity == 0
        {
            return Err(invalid(
                "allowlists.presigned_http_min_validity_secs",
                "must be greater than zero",
            ));
        }

        self.validate_combinations()
    }

    fn validate_combinations(&self) -> Result<(), ConfigError> {
        let configured = usize::from(self.storage.s3_endpoint.is_some())
            + usize::from(self.storage.local_dir.is_some() || self.storage.mode.is_some());
        if configured > 1 {
            return Err(invalid(
                "storage",
                "s3_endpoint and local storage are mutually exclusive: set one",
            ));
        }

        if self.features.managed_streaming_mode != ManagedStreamingMode::Off
            && !self.features.managed_streaming_transactional
        {
            return Err(invalid(
                "features.managed_streaming_mode",
                "observe/enforce requires managed_streaming_transactional = true",
            ));
        }

        if self.features.streaming_read_mode == StreamingReadMode::Transformed
            && !self.features.transformed_read_spool
        {
            return Err(invalid(
                "features.streaming_read_mode",
                "transformed reads require transformed_read_spool = true",
            ));
        }

        Ok(())
    }

    pub fn multipart_mode_is_explicit(&self) -> bool {
        self.explicit.multipart_mode
    }

    pub fn streaming_read_mode_is_explicit(&self) -> bool {
        self.explicit.streaming_read_mode
    }

    pub fn filter_component_is_explicit(&self) -> bool {
        self.explicit.filter_component
    }
}

fn env_bool(name: &str) -> Result<Option<bool>, ConfigError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(parse_bool(name, &value)?)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(invalid(name, "must contain valid UTF-8")),
    }
}

fn parse_bool(path: &str, value: &str) -> Result<bool, ConfigError> {
    if value == "1" || value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value == "0" || value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(invalid(
            path,
            format!("{value:?} is not a valid boolean (use true/false)"),
        ))
    }
}

fn parse_u64(path: &str, value: &str) -> Result<u64, ConfigError> {
    value
        .parse::<u64>()
        .map_err(|_| invalid(path, format!("{value:?} is not a valid unsigned integer")))
}

fn parse_u32(path: &str, value: &str) -> Result<u32, ConfigError> {
    value
        .parse::<u32>()
        .map_err(|_| invalid(path, format!("{value:?} is not a valid unsigned integer")))
}

fn parse_multipart_mode(value: &str) -> Result<MultipartMode, ConfigError> {
    match value {
        "reject" => Ok(MultipartMode::Reject),
        "staged" => Ok(MultipartMode::Staged),
        other => Err(invalid(
            "features.multipart_mode",
            format!("{other:?} is not one of reject, staged"),
        )),
    }
}

fn parse_streaming_read_mode(value: &str) -> Result<StreamingReadMode, ConfigError> {
    match value {
        "off" => Ok(StreamingReadMode::Off),
        "passthrough" => Ok(StreamingReadMode::Passthrough),
        "transformed" => Ok(StreamingReadMode::Transformed),
        other => Err(invalid(
            "features.streaming_read_mode",
            format!("{other:?} is not one of off, passthrough, transformed"),
        )),
    }
}

fn parse_managed_mode(value: &str) -> Result<ManagedStreamingMode, ConfigError> {
    match value {
        "off" => Ok(ManagedStreamingMode::Off),
        "observe" => Ok(ManagedStreamingMode::Observe),
        "enforce" => Ok(ManagedStreamingMode::Enforce),
        other => Err(invalid(
            "features.managed_streaming_mode",
            format!("{other:?} is not one of off, observe, enforce"),
        )),
    }
}

fn parse_streaming_provider(value: &str) -> Result<StreamingS3Provider, ConfigError> {
    match value {
        "aws" => Ok(StreamingS3Provider::Aws),
        "minio" => Ok(StreamingS3Provider::Minio),
        "r2" => Ok(StreamingS3Provider::R2),
        "b2" => Ok(StreamingS3Provider::B2),
        other => Err(invalid(
            "features.streaming_s3_provider",
            format!("{other:?} is not one of aws, minio, r2, b2"),
        )),
    }
}

fn split_commas(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

fn validate_url(path: &str, value: Option<&str>) -> Result<(), ConfigError> {
    let Some(value) = value else {
        return Ok(());
    };
    let parsed = url::Url::parse(value)
        .map_err(|error| invalid(path, format!("{value:?} is not a valid URL: {error}")))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(invalid(path, format!("{value:?} must use http or https")));
    }
    Ok(())
}

fn validate_host_entries(path: &str, entries: &[String]) -> Result<(), ConfigError> {
    for (index, entry) in entries.iter().enumerate() {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(invalid(&format!("{path}[{index}]"), "must not be empty"));
        }
        if entry.contains("://") {
            return Err(invalid(
                &format!("{path}[{index}]"),
                format!("{entry:?} must be a host or *.suffix, not a URL"),
            ));
        }
        let host = entry.strip_prefix("*.").unwrap_or(entry);
        if host.is_empty()
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        {
            return Err(invalid(
                &format!("{path}[{index}]"),
                format!("{entry:?} is not a valid host or *.suffix"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Result<Config, ConfigError> {
        Config::from_toml_str(input)
    }

    #[test]
    fn accepts_empty_document() {
        assert!(parse("").is_ok());
    }

    #[test]
    fn rejects_unknown_top_level_table() {
        let error = parse("[unknown]\nx = 1\n").unwrap_err();
        assert!(error.message.contains("unknown field"));
    }

    #[test]
    fn rejects_unknown_nested_field() {
        let error = parse("[server]\nlisten_addr = \"0.0.0.0:9000\"\nport = 1\n").unwrap_err();
        assert!(error.message.contains("unknown field `port`"));
    }

    #[test]
    fn rejects_malformed_toml() {
        let error = parse("not [ valid toml").unwrap_err();
        assert!(error.message.contains("malformed TOML"));
    }

    #[test]
    fn rejects_wrong_value_type() {
        let error = parse("[auth]\ndisabled = \"yes\"\n").unwrap_err();
        assert!(error.message.contains("invalid type"));
    }

    #[test]
    fn parses_valid_full_config() {
        let config = parse(
            r#"
[server]
listen_addr = "127.0.0.1:9000"

[auth]
disabled = true

[storage]
s3_endpoint = "http://minio:9000"
s3_region = "us-east-1"
single_tenant = true

[supabase]
url = "https://example.supabase.co"

[features]
multipart_mode = "reject"
streaming_read_mode = "transformed"
transformed_read_spool = true
enable_avro = true
streaming_s3_provider = "minio"
dev_memory_streaming = true
managed_streaming_mode = "observe"
managed_streaming_transactional = true

[wasm]
filter_component = "/plugins/filter.wasm"
plugins_dir = "/plugins"
fuel = 1000000
prefix_safe_component_hashes = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]

[limits]
source_max_frame_bytes = 524288
max_object_bytes = 1048576
max_pipeline_output_bytes = 2097152
legacy_max_object_bytes = 4194304
dev_memory_max_object_bytes = 8388608

[spool]
dir = "/var/lib/maskura/spool"
max_object_bytes = 1048576
quota_bytes = 2097152

[keys]
keys_file = "/etc/maskura/keys.json"
bootstrap_key = "bootstrap"

[managed]
placement_version = 1

[multipart_staging]
endpoint = "https://staging.example.com"
bucket = "staging"
region = "us-west-2"
dir = "/var/lib/maskura/staging"
tenant_quota_bytes = 1048576
global_quota_bytes = 2097152

[sigv4]
region = "us-east-2"
trusted_tls = true

[allowlists]
workspace_endpoint = ["*.amazonaws.com"]
workspace_endpoint_private = ["minio.internal"]
presigned_http = ["objects.example.com"]
presigned_http_private = ["storage.internal"]
presigned_http_allow_http = true
presigned_http_min_validity_secs = 30
"#,
        )
        .unwrap();
        assert_eq!(config.server.listen_addr.as_deref(), Some("127.0.0.1:9000"));
        assert!(config.auth.disabled);
        assert_eq!(
            config.storage.s3_endpoint.as_deref(),
            Some("http://minio:9000")
        );
        assert_eq!(
            config.features.streaming_read_mode,
            StreamingReadMode::Transformed
        );
        assert_eq!(
            config.supabase.url.as_deref(),
            Some("https://example.supabase.co")
        );
        assert_eq!(config.wasm.fuel, Some(1_000_000));
        assert_eq!(config.limits.max_object_bytes, Some(1_048_576));
        assert_eq!(config.spool.quota_bytes, Some(2_097_152));
        assert_eq!(config.keys.bootstrap_key.as_deref(), Some("bootstrap"));
        assert_eq!(config.managed.placement_version, Some(1));
        assert_eq!(config.multipart_staging.global_quota_bytes, Some(2_097_152));
        assert!(config.sigv4.trusted_tls);
        assert_eq!(
            config.allowlists.presigned_http_private,
            vec!["storage.internal"]
        );
    }

    #[test]
    fn rejects_invalid_listen_addr() {
        let error = parse("[server]\nlisten_addr = \"not-an-addr\"\n").unwrap_err();
        assert_eq!(error.path, "server.listen_addr");
    }

    #[test]
    fn rejects_non_http_url() {
        let error = parse("[storage]\ns3_endpoint = \"ftp://example.com\"\n").unwrap_err();
        assert_eq!(error.path, "storage.s3_endpoint");
    }

    #[test]
    fn rejects_malformed_url() {
        let error = parse("[storage]\ns3_endpoint = \"::not-a-url::\"\n").unwrap_err();
        assert_eq!(error.path, "storage.s3_endpoint");
    }

    #[test]
    fn rejects_bad_component_hash_length() {
        let error = parse("[wasm]\nprefix_safe_component_hashes = [\"abcd\"]\n").unwrap_err();
        assert_eq!(error.path, "wasm.prefix_safe_component_hashes[0]");
    }

    #[test]
    fn rejects_non_hex_component_hash() {
        let error = parse(&format!(
            "[wasm]\nprefix_safe_component_hashes = [\"{}\"]\n",
            "z".repeat(64)
        ))
        .unwrap_err();
        assert_eq!(error.path, "wasm.prefix_safe_component_hashes[0]");
    }

    #[test]
    fn accepts_valid_component_hash() {
        let hash = "a".repeat(64);
        let config = parse(&format!(
            "[wasm]\nprefix_safe_component_hashes = [\"{hash}\"]\n"
        ))
        .unwrap();
        assert_eq!(config.wasm.prefix_safe_component_hashes, vec![hash]);
    }

    #[test]
    fn rejects_zero_byte_quotas() {
        for (key, field) in [
            ("source_max_frame_bytes", "limits.source_max_frame_bytes"),
            ("max_object_bytes", "limits.max_object_bytes"),
        ] {
            let error = parse(&format!("[limits]\n{key} = 0\n")).unwrap_err();
            assert_eq!(error.path, field, "field {field}");
        }
    }

    #[test]
    fn rejects_unknown_enum_value() {
        let error = parse("[features]\nmultipart_mode = \"bogus\"\n").unwrap_err();
        assert!(error.message.contains("unknown variant"));
    }

    #[test]
    fn rejects_mutually_exclusive_storage_modes() {
        let error =
            parse("[storage]\ns3_endpoint = \"http://minio:9000\"\nlocal_dir = \"/data\"\n")
                .unwrap_err();
        assert_eq!(error.path, "storage");
        assert!(error.message.contains("mutually exclusive"));
    }

    #[test]
    fn accepts_managed_observe_without_config_secrets() {
        assert!(parse(
            "[features]\nmanaged_streaming_mode = \"observe\"\nmanaged_streaming_transactional = true\n",
        )
        .is_ok());
    }

    #[test]
    fn rejects_managed_observe_without_transactional() {
        let error = parse("[features]\nmanaged_streaming_mode = \"enforce\"\n").unwrap_err();
        assert!(error.message.contains("managed_streaming_transactional"));
    }

    #[test]
    fn rejects_transformed_read_without_spool() {
        let error = parse("[features]\nstreaming_read_mode = \"transformed\"\n").unwrap_err();
        assert_eq!(error.path, "features.streaming_read_mode");
    }

    #[test]
    fn accepts_transformed_read_with_spool() {
        assert!(
            parse(
                "[features]\nstreaming_read_mode = \"transformed\"\ntransformed_read_spool = true\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn accepts_auto_local_staged_multipart_without_hosted_dependencies() {
        assert!(parse("[features]\nmultipart_mode = \"staged\"\n").is_ok());
    }

    #[test]
    fn accepts_local_staged_multipart_without_hosted_dependencies() {
        assert!(
            parse(
                r#"
[storage]
mode = "local"

[features]
multipart_mode = "staged"
"#
            )
            .is_ok()
        );
    }

    #[test]
    fn accepts_staged_multipart_with_dependencies() {
        assert!(
            parse(
                r#"
[features]
multipart_mode = "staged"

[multipart_staging]
endpoint = "http://minio:9000"
bucket = "staging"
region = "us-east-1"
dir = "/var/lib/maskura/staging"
"#
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_invalid_allowlist_host_entry() {
        let error =
            parse("[allowlists]\npresigned_http = [\"https://example.com\"]\n").unwrap_err();
        assert_eq!(error.path, "allowlists.presigned_http[0]");
    }

    #[test]
    fn accepts_wildcard_suffix_allowlist_entry() {
        let config =
            parse("[allowlists]\nworkspace_endpoint = [\"*.s3.amazonaws.com\"]\n").unwrap();
        assert_eq!(
            config.allowlists.workspace_endpoint,
            vec!["*.s3.amazonaws.com"]
        );
    }

    #[test]
    fn rejects_spool_quota_below_object_max() {
        let error = parse("[spool]\nmax_object_bytes = 100\nquota_bytes = 50\n").unwrap_err();
        assert_eq!(error.path, "spool.quota_bytes");
    }

    #[test]
    fn rejects_multipart_tenant_quota_above_global_quota() {
        let error =
            parse("[multipart_staging]\ntenant_quota_bytes = 101\nglobal_quota_bytes = 100\n")
                .unwrap_err();
        assert_eq!(error.path, "multipart_staging.tenant_quota_bytes");
    }

    #[test]
    fn accepts_multipart_tenant_quota_equal_to_global_quota() {
        assert!(
            parse("[multipart_staging]\ntenant_quota_bytes = 100\nglobal_quota_bytes = 100\n")
                .is_ok()
        );
    }

    #[test]
    fn applies_s3_region_fallback_precedence_without_erasing_file_value() {
        let cases = [
            (
                [
                    ("S3_REGION", "explicit"),
                    ("AWS_REGION", "aws"),
                    ("AWS_DEFAULT_REGION", "default"),
                ]
                .as_slice(),
                "explicit",
            ),
            (
                [("AWS_REGION", "aws"), ("AWS_DEFAULT_REGION", "default")].as_slice(),
                "aws",
            ),
            ([("AWS_DEFAULT_REGION", "default")].as_slice(), "default"),
        ];

        for (values, expected) in cases {
            let mut config = parse("[storage]\ns3_region = \"from-file\"\n").unwrap();
            config.apply_s3_region_override(|name| {
                values
                    .iter()
                    .find_map(|(key, value)| (*key == name).then(|| (*value).to_string()))
            });
            assert_eq!(config.storage.s3_region.as_deref(), Some(expected));
        }

        let mut config = parse("[storage]\ns3_region = \"from-file\"\n").unwrap();
        config.apply_s3_region_override(|_| None);
        assert_eq!(config.storage.s3_region.as_deref(), Some("from-file"));
    }

    fn write_temp_file(name: &str, contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "maskura-config-test-{}-{}-{}",
            std::process::id(),
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn resolve_without_file_yields_compiled_defaults() {
        let config = Config::resolve(None).unwrap();
        assert_eq!(config.server.listen_addr, None);
        assert!(!config.auth.disabled);
    }

    #[test]
    fn resolve_loads_file_values() {
        let path = write_temp_file(
            "valid",
            "[server]\nlisten_addr = \"127.0.0.1:9000\"\n\n[auth]\ndisabled = true\n",
        );
        let config = Config::resolve(Some(&path)).unwrap();
        assert_eq!(config.server.listen_addr.as_deref(), Some("127.0.0.1:9000"));
        assert!(config.auth.disabled);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_applies_environment_before_cross_field_validation() {
        let path = write_temp_file(
            "env-repairs-combination",
            "[features]\nstreaming_read_mode = \"transformed\"\n",
        );
        // SAFETY: this test owns this uncommon process variable for its brief
        // lifetime, and setting it to `encrypted` cannot invalidate other
        // configurations resolved concurrently.
        unsafe { std::env::set_var("MASKURA_TRANSFORMED_READ_SPOOL", "encrypted") };
        let config = Config::resolve(Some(&path)).unwrap();
        unsafe { std::env::remove_var("MASKURA_TRANSFORMED_READ_SPOOL") };
        assert!(config.features.transformed_read_spool);
        assert_eq!(
            config.features.streaming_read_mode,
            StreamingReadMode::Transformed
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn records_explicit_auto_local_feature_and_filter_settings() {
        const INPUT: &str = "[features]\nmultipart_mode = \"reject\"\nstreaming_read_mode = \"off\"\n\n[wasm]\nfilter_component = \"/tmp/noop.wasm\"\n";
        let config = parse(INPUT).unwrap();
        assert!(config.multipart_mode_is_explicit());
        assert!(config.streaming_read_mode_is_explicit());
        assert!(config.filter_component_is_explicit());

        #[derive(Deserialize)]
        struct EmbeddedConfig {
            #[serde(flatten)]
            base: Config,
        }
        let embedded: EmbeddedConfig = toml::from_str(INPUT).unwrap();
        assert!(embedded.base.multipart_mode_is_explicit());
        assert!(embedded.base.streaming_read_mode_is_explicit());
        assert!(embedded.base.filter_component_is_explicit());

        let defaults = Config::default();
        assert!(!defaults.multipart_mode_is_explicit());
        assert!(!defaults.streaming_read_mode_is_explicit());
        assert!(!defaults.filter_component_is_explicit());
    }

    #[test]
    fn resolve_rejects_missing_explicit_file() {
        let path = std::env::temp_dir().join(format!(
            "maskura-config-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let error = Config::resolve(Some(&path)).unwrap_err();
        assert!(
            error.message.contains("failed to read config file"),
            "{error}"
        );
    }

    #[test]
    fn resolve_rejects_malformed_file() {
        let path = write_temp_file("malformed", "not [ valid toml");
        let error = Config::resolve(Some(&path)).unwrap_err();
        assert!(error.message.contains("malformed TOML"), "{error}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_rejects_unknown_key() {
        let path = write_temp_file(
            "unknown",
            "[server]\nlisten_addr = \"0.0.0.0:9000\"\nport = 1\n",
        );
        let error = Config::resolve(Some(&path)).unwrap_err();
        assert!(error.message.contains("unknown field"), "{error}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_rejects_invalid_value() {
        let path = write_temp_file("invalid", "[features]\nmultipart_mode = \"bogus\"\n");
        let error = Config::resolve(Some(&path)).unwrap_err();
        assert!(error.message.contains("unknown variant"), "{error}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_secrets_in_file() {
        for (name, contents) in [
            (
                "service-buckets",
                "[storage]\nservice_buckets = [\"endpoint|region|bucket|access|secret|aws\"]\n",
            ),
            ("supabase-secret", "[supabase]\njwt_secret = \"hunter2\"\n"),
            (
                "multipart-secret",
                "[multipart_staging]\nsecret_access_key = \"hunter2\"\n",
            ),
        ] {
            let path = write_temp_file(name, contents);
            let error = Config::resolve(Some(&path)).unwrap_err();
            assert!(error.message.contains("unknown field"), "{error}");
            let _ = std::fs::remove_file(&path);
        }
    }
}
