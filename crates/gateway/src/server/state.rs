//! Gateway state types and configuration-derived limits.
//!
//! Extracted from `server.rs`. Items are re-exported from [`crate::server`].

use super::*;

#[derive(Clone)]
pub struct AppState {
    pub gateway: Arc<Gateway>,
    pub store: Arc<MemoryStore>,
    pub file_store: Option<Arc<FileStore>>,
    #[allow(
        dead_code,
        reason = "owns the local root lock for the AppState lifetime"
    )]
    pub(crate) local_storage: Option<Arc<LocalStorageRuntime>>,
    pub keys: Arc<dyn KeyRepository>,
    pub workspace_storage: Arc<dyn WorkspaceStorageRepository>,
    pub plugins: Arc<PluginRegistry>,
    pub service_storage: Arc<ServiceStorage>,
    pub s3_client: Option<Client>,
    pub supabase_url: String,
    pub supabase_anon_key: String,
    pub jwt_decoder: Option<Arc<jsonwebtoken::DecodingKey>>,
    pub auth_disabled: bool,
    pub explicit_single_tenant: bool,
    pub workspace_endpoint_policy: WorkspaceEndpointPolicy,
    pub control: Arc<dyn ControlPlane>,
    pub legacy_max_object_bytes: usize,
    pub streaming_read_mode: StreamingReadMode,
    pub source_body_limits: BodyLimits,
    pub max_pipeline_output_bytes: u64,
    pub presigned_http_policy: PresignedHttpPolicy,
    pub sigv4_cache: Arc<SigningKeyCache>,
    pub sigv4_policy: SigV4Policy,
    pub operation_journal: Option<Arc<dyn OperationJournal>>,
    pub s3_streaming_capabilities: Option<BackendCapabilities>,
    pub managed_streaming_capabilities: Option<BackendCapabilities>,
    pub spool_config: CompatibilitySpoolConfig,
    pub spool_quota: Arc<SpoolQuota>,
    /// Unsafe transformed reads are allowed only with encrypted durable staging.
    pub transformed_read_spool_enabled: bool,
    /// Enables the opt-in Avro OCF processing path. Disabled by default.
    pub binary_avro_enabled: bool,
    pub dev_memory_max_object_bytes: usize,
    pub dev_memory_streaming_enabled: bool,
    pub(crate) demo_pipelines: DemoPipelines,
    pub(crate) demo_limiter: Arc<DemoLimiter>,
    pub(crate) multipart: Arc<MultipartPersistenceBundle>,
    pub(crate) continuation_token_key: [u8; 32],
}

pub(crate) const LEGACY_MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const WORKSPACE_OPERATION_LEASE_TTL: Duration = Duration::from_secs(120);

pub(crate) const SIMPLE_CREDENTIAL_MUTATION_BODY_BYTES: usize = 1024;
pub(crate) const CREATE_KEY_BODY_BYTES: usize = MAX_PUBLIC_KEY_PEM_BYTES + 1024;
pub(crate) const SET_PUBLIC_KEY_BODY_BYTES: usize = MAX_PUBLIC_KEY_PEM_BYTES + 512;

/// Immutable startup pipeline artifacts that can produce isolated gateway
/// state without recompiling the same Wasm components.
#[doc(hidden)]
pub struct StatePipelineTemplate {
    pub(crate) engine: Arc<maskura_wasm_runtime::FilterEngine>,
    pub(crate) plugins: PluginRegistry,
    pub(crate) demo: DemoPipelineTemplate,
    pub(crate) max_pipeline_output_bytes: u64,
}

impl StatePipelineTemplate {
    #[doc(hidden)]
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let source_body_limits = source_body_limits(config)?;
        let explicit_component_path = component_path(config);
        let component_bytes = std::fs::read(&explicit_component_path)?;
        let pipeline_fuel = pipeline_fuel(config);
        let engine = Arc::new(maskura_wasm_runtime::FilterEngine::with_fuel(
            &component_bytes,
            pipeline_fuel,
        )?);
        let default_pipeline_limits = PipelineLimits::default();
        let max_pipeline_output_bytes = max_pipeline_output_bytes(config);
        let pipeline_limits = PipelineLimits {
            max_input_bytes: default_pipeline_limits
                .max_input_bytes
                .min(source_body_limits.max_bytes),
            max_output_bytes: max_pipeline_output_bytes,
            max_cumulative_fuel: pipeline_fuel,
            ..default_pipeline_limits
        };
        let plugins = PluginRegistry::with_options(
            pipeline_fuel,
            pipeline_limits,
            maskura_wasm_runtime::ExecutorConfig::default(),
        )?;
        let prefix_safe_hashes = prefix_safe_component_hashes(config);

        use sha2::Digest as _;
        let default_hash = hex::encode(sha2::Sha256::digest(&component_bytes));
        plugins.import_with_capabilities(
            "pii-default",
            &component_bytes,
            PluginCapabilities {
                prefix_safe_for_read: prefix_safe_hashes.contains(&default_hash),
            },
        )?;

        if let Some(plugin_dir) = &config.wasm.plugins_dir {
            let dir = std::path::Path::new(&plugin_dir);
            if dir.exists() {
                plugins.load_from_dir_with_capabilities_excluding(
                    dir,
                    &prefix_safe_hashes,
                    Some(&explicit_component_path),
                )?;
            }
        }

        let stable_demo_component = bundled_stable_component(config)?;
        let demo = build_demo_pipeline_template(
            &component_bytes,
            stable_demo_component.as_deref(),
            pipeline_fuel,
        )?;
        Ok(Self {
            engine,
            plugins,
            demo,
            max_pipeline_output_bytes,
        })
    }

    pub(crate) fn instantiate(
        &self,
    ) -> anyhow::Result<(Gateway, Arc<PluginRegistry>, DemoPipelines)> {
        let plugins = Arc::new(self.plugins.isolated_clone()?);
        let gateway = Gateway::with_shared_registry(Arc::clone(&self.engine), plugins.clone());
        Ok((gateway, plugins, self.demo.instantiate()?))
    }

    /// Disable every catalog plugin so the resolved pipeline is an explicit
    /// byte-preserving pass-through. The auto-local appliance starts this way;
    /// the transform pipeline remains available but opt-in.
    pub(crate) fn disable_all_plugins(&self) {
        for plugin in self.plugins.list() {
            self.plugins.set_enabled(&plugin.id, false);
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StreamingReadMode {
    #[default]
    Off,
    Passthrough,
    Transformed,
}

impl StreamingReadMode {
    pub(crate) fn from_config(config: &Config) -> Self {
        match config.features.streaming_read_mode {
            ConfigStreamingReadMode::Off => Self::Off,
            ConfigStreamingReadMode::Passthrough => Self::Passthrough,
            ConfigStreamingReadMode::Transformed => Self::Transformed,
        }
    }

    pub(crate) fn streams_passthrough(self) -> bool {
        matches!(self, Self::Passthrough | Self::Transformed)
    }
}

/// Imported plugins are unsafe by default. Operators may opt known component
/// digests into direct reads at process start; dashboard callers cannot raise
/// this capability and a digest cannot be re-registered with different flags.
pub(crate) fn prefix_safe_component_hashes(config: &Config) -> HashSet<String> {
    config
        .wasm
        .prefix_safe_component_hashes
        .iter()
        .map(|hash| hash.to_ascii_lowercase())
        .collect()
}

pub(crate) fn pipeline_fuel(config: &Config) -> u64 {
    config
        .wasm
        .fuel
        .unwrap_or(crate::plugin_registry::DEFAULT_PIPELINE_FUEL)
}

pub(crate) fn max_pipeline_output_bytes(config: &Config) -> u64 {
    let immutable_max = PipelineLimits::default().max_output_bytes;
    config
        .limits
        .max_pipeline_output_bytes
        .unwrap_or(immutable_max)
        .min(immutable_max)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum MultipartMode {
    #[default]
    Reject,
    Staged,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum MultipartPersistenceMode {
    #[default]
    Reject,
    LocalStaged,
    HostedStaged,
}

pub(crate) fn multipart_mode(config: &Config) -> MultipartMode {
    match config.features.multipart_mode {
        ConfigMultipartMode::Reject => MultipartMode::Reject,
        ConfigMultipartMode::Staged => MultipartMode::Staged,
    }
}

pub(crate) fn configured_s3_streaming_capabilities(config: &Config) -> Option<BackendCapabilities> {
    config.features.streaming_s3_provider?;
    Some(BackendCapabilities {
        incomplete_upload_discovery: IncompleteUploadDiscovery::ExactKeyAndStartTime,
        abort_incomplete_upload: true,
        cleanup_sla: Some(Duration::from_secs(5 * 60)),
        lifecycle_rule: true,
        versioning: VersioningCapability::Optional,
        conditional_reads: ConditionalReadCapability::VersionAndEtag,
        response_checksums: ResponseChecksumCapability::Standard,
        list_operations: ListCapability::V1AndV2,
        multipart_responses: MultipartResponseCapability::Standard,
        completion_reconciliation: CompletionReconciliation::HeadWithOperationIdentity,
    })
}

pub(crate) fn configured_managed_streaming_capabilities(
    config: &Config,
) -> Option<BackendCapabilities> {
    config
        .features
        .managed_streaming_transactional
        .then_some(BackendCapabilities {
            incomplete_upload_discovery: IncompleteUploadDiscovery::ExactKeyAndStartTime,
            abort_incomplete_upload: true,
            cleanup_sla: Some(Duration::from_secs(5 * 60)),
            lifecycle_rule: true,
            versioning: VersioningCapability::Optional,
            conditional_reads: ConditionalReadCapability::VersionAndEtag,
            response_checksums: ResponseChecksumCapability::Standard,
            list_operations: ListCapability::V1AndV2,
            multipart_responses: MultipartResponseCapability::Standard,
            completion_reconciliation: CompletionReconciliation::HeadWithOperationIdentity,
        })
}

pub(crate) fn legacy_max_object_bytes(config: &Config) -> usize {
    config
        .limits
        .legacy_max_object_bytes
        .unwrap_or(LEGACY_MAX_OBJECT_BYTES as u64)
        .min(LEGACY_MAX_OBJECT_BYTES as u64) as usize
}

pub(crate) fn dev_memory_max_object_bytes(config: &Config) -> usize {
    config
        .limits
        .dev_memory_max_object_bytes
        .unwrap_or(LEGACY_MAX_OBJECT_BYTES as u64)
        .min(64 * 1024 * 1024) as usize
}

pub(crate) fn multipart_quota_bytes(config: &Config, source_max_bytes: u64) -> (u64, u64) {
    let tenant = config
        .multipart_staging
        .tenant_quota_bytes
        .unwrap_or_else(|| source_max_bytes.saturating_mul(MAX_ACTIVE_UPLOADS as u64));
    let global = config
        .multipart_staging
        .global_quota_bytes
        .unwrap_or_else(|| tenant.saturating_mul(4));
    (tenant, global)
}

pub(crate) fn spool_limits(config: &Config, source_max_bytes: u64) -> (u64, u64) {
    let max_object = config
        .spool
        .max_object_bytes
        .unwrap_or(source_max_bytes)
        .min(source_max_bytes);
    let quota = config
        .spool
        .quota_bytes
        .filter(|value| *value >= max_object)
        .unwrap_or(max_object.saturating_mul(2));
    (max_object, quota)
}

pub(crate) fn managed_placement_version(config: &Config) -> u32 {
    config
        .managed
        .placement_version
        .unwrap_or(PLACEMENT_VERSION_V1)
}

pub(crate) async fn ensure_configured_local_root(
    keys: &dyn KeyRepository,
    access_key: &str,
    secret: &str,
    workspace: &WorkspaceId,
) -> anyhow::Result<()> {
    if keys.get_key(access_key).await?.is_none() {
        keys.bootstrap_root_credential(access_key, secret, "root", workspace, "local-root")
            .await?;
    } else if keys
        .resolve_credentials(access_key, secret)
        .await?
        .is_none()
    {
        anyhow::bail!("configured local root credentials do not match the persisted credential");
    }
    Ok(())
}

/// Derive the deterministic-encryption key for an API key secret:
/// two 32-byte HMAC-SHA256 outputs (`"maskura-stable-encrypt"` + counter) giving
/// the 64-byte key AES-256-SIV requires. The plugin receives only this
/// derived key, never the raw secret.
pub(crate) fn derive_stable_key(secret: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut out = Vec::with_capacity(64);
    for i in 1..=2u8 {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(b"maskura-stable-encrypt");
        mac.update(&[i]);
        out.extend_from_slice(&mac.finalize().into_bytes());
    }
    out
}
