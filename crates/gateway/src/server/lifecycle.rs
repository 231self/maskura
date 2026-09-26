//! Startup validation, configuration-derived state, and the state
//! constructor.
//!
//! Extracted from `server.rs`. Items are re-exported from [`crate::server`].

use super::*;

pub(crate) fn component_path(config: &Config) -> PathBuf {
    config
        .wasm
        .filter_component
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let installed = PathBuf::from("/app/components/pii-default.component.wasm");
            if installed.exists() {
                return installed;
            }
            let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            p.push("..");
            p.push("..");
            p.push("target");
            p.push("components");
            p.push("pii-default.component.wasm");
            p
        })
}

pub(crate) fn bundled_stable_component(config: &Config) -> anyhow::Result<Option<Vec<u8>>> {
    let directory = match &config.wasm.plugins_dir {
        Some(directory) => PathBuf::from(directory),
        None => {
            warn!("join demo disabled because MASKURA_PLUGINS_DIR is not configured");
            return Ok(None);
        }
    };
    let path = directory.join("stable-encrypt.component.wasm");
    match std::fs::read(&path) {
        Ok(component) => Ok(Some(component)),
        Err(error) => {
            warn!(
                "join demo disabled because {} is unavailable: {error}",
                path.display()
            );
            Ok(None)
        }
    }
}

/// Whether the gateway should boot as a zero-configuration local S3 appliance
/// (the MinIO replacement). True only when no hosted or external storage
/// configuration is present, so an explicit cloud/hosted deployment never
/// silently degrades into a local single-node store. Operator-only and secret
/// inputs (`MASKURA_SERVICE_BUCKETS`, `DATABASE_URL`) stay environment-sourced;
/// the customer settings come from the resolved config.
pub fn auto_local_appliance(config: &Config) -> bool {
    auto_local_appliance_with_operator_state(
        config,
        nonempty_env("MASKURA_SERVICE_BUCKETS"),
        nonempty_env("DATABASE_URL"),
    )
}

pub(crate) fn auto_local_appliance_with_operator_state(
    config: &Config,
    has_service_backends: bool,
    has_database: bool,
) -> bool {
    !has_service_backends
        && config.storage.s3_endpoint.is_none()
        && !has_database
        && config.storage.mode.is_none()
        && config.storage.local_dir.is_none()
        && !config.storage.single_tenant
}

/// The effective default listen address for the current profile: the MinIO
/// convention (9000) in auto-local mode, the historical gateway port (8080)
/// otherwise.
pub fn default_listen_addr(config: &Config) -> &'static str {
    if auto_local_appliance(config) {
        "0.0.0.0:9000"
    } else {
        "0.0.0.0:8080"
    }
}

pub(crate) fn effective_multipart_mode(config: &Config, auto_local: bool) -> MultipartMode {
    if auto_local && !config.multipart_mode_is_explicit() {
        MultipartMode::Staged
    } else {
        multipart_mode(config)
    }
}

pub(crate) fn effective_streaming_read_mode(
    config: &Config,
    auto_local: bool,
) -> StreamingReadMode {
    if auto_local && !config.streaming_read_mode_is_explicit() {
        StreamingReadMode::Passthrough
    } else {
        StreamingReadMode::from_config(config)
    }
}

pub(crate) fn explicit_single_tenant_mode(config: &Config, auto_local: bool) -> bool {
    config.auth.disabled || auto_local || config.storage.single_tenant
}

pub(crate) fn validate_storage_boundary_startup(
    explicit_single_tenant: bool,
    has_global_s3_endpoint: bool,
    has_service_backends: bool,
) -> anyhow::Result<()> {
    if !explicit_single_tenant && has_global_s3_endpoint {
        anyhow::bail!("S3_ENDPOINT is forbidden in multi-tenant mode");
    }
    if !explicit_single_tenant && !has_service_backends {
        anyhow::bail!("multi-tenant mode requires a non-empty MASKURA_SERVICE_BUCKETS");
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(crate) struct MultipartStartupDependencies {
    pub(crate) durable_wrapping: bool,
    pub(crate) database: bool,
    pub(crate) endpoint: bool,
    pub(crate) bucket: bool,
    pub(crate) access_key: bool,
    pub(crate) secret_key: bool,
    pub(crate) region: bool,
    pub(crate) directory: bool,
    pub(crate) tenant_quota: bool,
    pub(crate) global_quota: bool,
}

pub(crate) fn validate_multipart_startup(
    mode: MultipartPersistenceMode,
    dependencies: MultipartStartupDependencies,
) -> anyhow::Result<()> {
    if mode != MultipartPersistenceMode::HostedStaged {
        return Ok(());
    }
    let checks = [
        (dependencies.durable_wrapping, "durable key wrapping"),
        (dependencies.database, "DATABASE_URL"),
        (dependencies.endpoint, "MASKURA_MULTIPART_STAGING_ENDPOINT"),
        (dependencies.bucket, "MASKURA_MULTIPART_STAGING_BUCKET"),
        (
            dependencies.access_key,
            "MASKURA_MULTIPART_STAGING_ACCESS_KEY_ID",
        ),
        (
            dependencies.secret_key,
            "MASKURA_MULTIPART_STAGING_SECRET_ACCESS_KEY",
        ),
        (dependencies.region, "MASKURA_MULTIPART_STAGING_REGION"),
        (dependencies.directory, "MASKURA_MULTIPART_STAGING_DIR"),
        (
            dependencies.tenant_quota,
            "MASKURA_MULTIPART_STAGING_TENANT_QUOTA_BYTES",
        ),
        (
            dependencies.global_quota,
            "MASKURA_MULTIPART_STAGING_GLOBAL_QUOTA_BYTES",
        ),
    ];
    let missing = checks
        .into_iter()
        .filter_map(|(configured, name)| (!configured).then_some(name))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        anyhow::bail!(
            "staged multipart requires complete durable startup dependencies: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

pub(crate) fn multipart_persistence_mode(
    mode: MultipartMode,
    local_storage: bool,
) -> MultipartPersistenceMode {
    match (mode, local_storage) {
        (MultipartMode::Reject, _) => MultipartPersistenceMode::Reject,
        (MultipartMode::Staged, true) => MultipartPersistenceMode::LocalStaged,
        (MultipartMode::Staged, false) => MultipartPersistenceMode::HostedStaged,
    }
}

pub(crate) fn nonempty_env(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

pub(crate) fn source_body_limits(config: &Config) -> anyhow::Result<BodyLimits> {
    let max_frame_bytes = config
        .limits
        .source_max_frame_bytes
        .map(usize::try_from)
        .transpose()
        .map_err(|_| anyhow::anyhow!("limits.source_max_frame_bytes exceeds platform usize"))?
        .unwrap_or(crate::object::DEFAULT_MAX_SOURCE_FRAME_BYTES);
    Ok(BodyLimits {
        max_frame_bytes,
        max_bytes: config
            .limits
            .max_object_bytes
            .unwrap_or(crate::object::DEFAULT_MAX_SOURCE_BYTES)
            .min(crate::object::DEFAULT_MAX_SOURCE_BYTES),
    })
}

pub(crate) fn validate_managed_storage_at_launch(storage: &ServiceStorage) -> anyhow::Result<()> {
    storage
        .validate_managed_launch_configuration()
        .map_err(|detail| {
            anyhow::anyhow!("managed streaming configuration is invalid at launch: {detail}")
        })
}

#[cfg(test)]
#[test]
pub(crate) fn managed_storage_launch_validation_rejects_unsupported_provider_before_serving() {
    let backends = parse_service_backends(
        "r2|managed-primary|account-123|1|https://s3.example|us-east-1|bucket|key|secret",
    )
    .unwrap();
    let storage = ServiceStorage::with_management(
        backends,
        Arc::new(InMemoryManagedRepository::new()),
        ManagedStreamingMode::Enforce,
        PLACEMENT_VERSION_V1,
    );

    assert!(
        validate_managed_storage_at_launch(&storage)
            .unwrap_err()
            .to_string()
            .contains("invalid at launch")
    );
}

/// Build the engine state from resolved configuration, injecting the given
/// control plane and key-wrapping backend. Secrets remain environment-sourced.
/// This is the shared construction
/// path for both the OSS self-host binary (`NoopControlPlane` +
/// [`crate::key_cipher::default_wrapping`]) and the private SaaS control
/// plane (KMS/Vault-backed wrapping).
pub async fn build_state(
    control: Arc<dyn ControlPlane>,
    wrapping: Arc<dyn KeyWrapping>,
    workspace_storage: Arc<dyn WorkspaceStorageRepository>,
    config: &Config,
) -> anyhow::Result<Arc<AppState>> {
    let pipeline_template = StatePipelineTemplate::from_config(config)?;
    if auto_local_appliance(config) && !config.filter_component_is_explicit() {
        pipeline_template.disable_all_plugins();
    }
    build_state_with_pipeline_template(
        control,
        wrapping,
        workspace_storage,
        &pipeline_template,
        config,
    )
    .await
}

/// Build isolated state from startup artifacts that have already compiled the
/// configured Wasm components.
#[doc(hidden)]
pub async fn build_state_with_pipeline_template(
    control: Arc<dyn ControlPlane>,
    wrapping: Arc<dyn KeyWrapping>,
    workspace_storage: Arc<dyn WorkspaceStorageRepository>,
    pipeline_template: &StatePipelineTemplate,
    config: &Config,
) -> anyhow::Result<Arc<AppState>> {
    let s3_endpoint = config.storage.s3_endpoint.clone();
    let auto_local = auto_local_appliance(config);
    let auth_disabled = config.auth.disabled;
    let explicit_single_tenant = explicit_single_tenant_mode(config, auto_local);
    let service_backends = std::env::var("MASKURA_SERVICE_BUCKETS")
        .ok()
        .map(|value| parse_service_backends(&value))
        .transpose()
        .map_err(anyhow::Error::msg)?
        .unwrap_or_default();
    let local_storage_mode = config.storage.mode.clone();
    let local_storage_dir = config.storage.local_dir.clone();
    let local_storage_root = if auto_local {
        // The zero-config appliance defaults to the container's `/data` volume.
        // `MASKURA_LOCAL_STORAGE_DIR` still overrides it.
        let directory = PathBuf::from(local_storage_dir.unwrap_or_else(|| "/data".to_string()));
        Some(directory)
    } else {
        match (local_storage_mode.as_deref(), local_storage_dir) {
            (Some("local"), directory) => {
                let directory = PathBuf::from(directory.unwrap_or_else(|| "./data".to_string()));
                if !explicit_single_tenant {
                    anyhow::bail!("MASKURA_LOCAL_STORAGE_DIR requires single-tenant mode");
                }
                if s3_endpoint.is_some() || !service_backends.is_empty() {
                    anyhow::bail!(
                        "MASKURA_LOCAL_STORAGE_DIR is mutually exclusive with S3_ENDPOINT and MASKURA_SERVICE_BUCKETS"
                    );
                }
                Some(directory)
            }
            (None, Some(directory)) => {
                let directory = PathBuf::from(directory);
                if !explicit_single_tenant {
                    anyhow::bail!("MASKURA_LOCAL_STORAGE_DIR requires single-tenant mode");
                }
                if s3_endpoint.is_some() || !service_backends.is_empty() {
                    anyhow::bail!(
                        "MASKURA_LOCAL_STORAGE_DIR is mutually exclusive with S3_ENDPOINT and MASKURA_SERVICE_BUCKETS"
                    );
                }
                Some(directory)
            }
            (Some(_), _) => anyhow::bail!("MASKURA_STORAGE_MODE must be local when configured"),
            (None, None) => None,
        }
    };
    validate_storage_boundary_startup(
        explicit_single_tenant,
        s3_endpoint.is_some(),
        !service_backends.is_empty(),
    )?;
    let workspace_endpoint_policy =
        WorkspaceEndpointPolicy::from_config(explicit_single_tenant, &config.allowlists)
            .map_err(anyhow::Error::msg)?;

    let source_body_limits = source_body_limits(config)?;
    let max_pipeline_output_bytes = pipeline_template.max_pipeline_output_bytes;
    let (gateway, plugins, demo_pipelines) = pipeline_template.instantiate()?;

    let multipart_mode = effective_multipart_mode(config, auto_local);
    let multipart_persistence_mode =
        multipart_persistence_mode(multipart_mode, local_storage_root.is_some());
    let (multipart_tenant_quota_bytes, multipart_global_quota_bytes) =
        multipart_quota_bytes(config, source_body_limits.max_bytes);
    let multipart_quotas = (multipart_mode == MultipartMode::Staged)
        .then(|| {
            StagingQuotaLimits::new(multipart_tenant_quota_bytes, multipart_global_quota_bytes)
                .map_err(|_| {
                    anyhow::anyhow!("invalid multipart staging tenant/global quota configuration")
                })
        })
        .transpose()?;
    validate_multipart_startup(
        multipart_persistence_mode,
        MultipartStartupDependencies {
            durable_wrapping: wrapping.is_durable(),
            database: nonempty_env("DATABASE_URL"),
            endpoint: config.multipart_staging.endpoint.is_some(),
            bucket: config.multipart_staging.bucket.is_some(),
            access_key: nonempty_env("MASKURA_MULTIPART_STAGING_ACCESS_KEY_ID"),
            secret_key: nonempty_env("MASKURA_MULTIPART_STAGING_SECRET_ACCESS_KEY"),
            region: config.multipart_staging.region.is_some(),
            directory: config.multipart_staging.dir.is_some(),
            tenant_quota: config.multipart_staging.tenant_quota_bytes.is_some(),
            global_quota: config.multipart_staging.global_quota_bytes.is_some(),
        },
    )?;
    let local_storage = match local_storage_root {
        Some(root) => {
            let quotas = multipart_quotas
                .unwrap_or(StagingQuotaLimits::new(i64::MAX as u64, i64::MAX as u64)?);
            let runtime = Arc::new(LocalStorageRuntime::with_quotas(root, quotas).await?);
            info!(path = %runtime.root().display(), "Storage: local filesystem");
            Some(runtime)
        }
        None => None,
    };
    let file_store = local_storage.as_ref().map(|runtime| runtime.file_store());
    let wrapping = if multipart_persistence_mode == MultipartPersistenceMode::LocalStaged {
        local_storage
            .as_ref()
            .expect("local staged mode has a local runtime")
            .wrapping()
    } else {
        wrapping
    };

    // Envelope encryption for API key secrets (needed to verify SigV4).
    // The wrapping backend is injected by the caller so the engine stays
    // policy-free: OSS uses `default_wrapping()`, SaaS injects KMS/Vault.
    let cipher = Arc::new(SecretCipher::new(wrapping.clone()));

    let s3_client = match &s3_endpoint {
        Some(endpoint) => {
            let access_key = std::env::var("S3_ACCESS_KEY_ID")
                .or_else(|_| std::env::var("AWS_ACCESS_KEY_ID"))
                .ok();
            let secret_key = std::env::var("S3_SECRET_ACCESS_KEY")
                .or_else(|_| std::env::var("AWS_SECRET_ACCESS_KEY"))
                .ok();
            let region = config
                .storage
                .s3_region
                .clone()
                .unwrap_or_else(|| "us-east-1".to_string());
            match (access_key, secret_key) {
                (Some(ak), Some(sk)) => {
                    let creds = Credentials::new(ak, sk, None, None, "env");
                    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                        .region(Region::new(region))
                        .endpoint_url(endpoint)
                        .credentials_provider(creds)
                        .retry_config(s3_retry_config())
                        .timeout_config(s3_timeout_config())
                        .load()
                        .await;
                    let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
                        .force_path_style(true)
                        .build();
                    Some(Client::from_conf(s3_config))
                }
                _ => {
                    // No static key pair: defer to the AWS default credential
                    // provider chain (EC2 instance profile, ECS task role, EKS
                    // IRSA, SSO, OIDC web identity). This is the keyless path
                    // for AWS-hosted deployments; credentials resolve lazily.
                    info!(
                        "S3_ENDPOINT set without static keys; using the default AWS credential provider chain"
                    );
                    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                        .region(Region::new(region))
                        .endpoint_url(endpoint)
                        .retry_config(s3_retry_config())
                        .timeout_config(s3_timeout_config())
                        .load()
                        .await;
                    let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
                        .force_path_style(true)
                        .build();
                    Some(Client::from_conf(s3_config))
                }
            }
        }
        None => None,
    };

    let supabase_url = config
        .supabase
        .url
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:54321".to_string());
    let supabase_anon_key = std::env::var("SUPABASE_ANON_KEY")
        .unwrap_or_else(|_| "sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH".to_string());
    let supabase_jwt_secret = std::env::var("SUPABASE_JWT_SECRET").ok();

    let jwt_decoder = supabase_jwt_secret
        .map(|secret| Arc::new(jsonwebtoken::DecodingKey::from_secret(secret.as_bytes())));

    let managed_mode = match config.features.managed_streaming_mode {
        ConfigManagedStreamingMode::Off => ManagedStreamingMode::Off,
        ConfigManagedStreamingMode::Observe => ManagedStreamingMode::Observe,
        ConfigManagedStreamingMode::Enforce => ManagedStreamingMode::Enforce,
    };
    let managed_placement_version = managed_placement_version(config);
    let s3_streaming_capabilities = configured_s3_streaming_capabilities(config);
    let managed_streaming_capabilities = configured_managed_streaming_capabilities(config);
    let (spool_max_object_bytes, spool_quota_bytes) =
        spool_limits(config, source_body_limits.max_bytes);
    let spool_config = CompatibilitySpoolConfig {
        directory: config
            .spool
            .dir
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("maskura-spool")),
        max_object_bytes: spool_max_object_bytes,
        stale_after: Duration::from_secs(24 * 60 * 60),
    };
    let removed_spools = CompatibilitySpoolTransaction::cleanup_stale(&spool_config).await?;
    if removed_spools > 0 {
        info!(removed_spools, "removed stale spool files");
    }
    schedule_spool_cleanup(spool_config.clone());
    let spool_quota = Arc::new(SpoolQuota::new(spool_quota_bytes));
    let dev_memory_max_object_bytes = dev_memory_max_object_bytes(config);
    let dev_memory_streaming_enabled =
        explicit_single_tenant || config.features.dev_memory_streaming;

    // API key persistence: Postgres (Supabase) when DATABASE_URL is set,
    // a JSON file when MASKURA_KEYS_FILE is set, a default JSON file in local
    // mode (AUTH_DISABLED=true), and otherwise the in-memory KeyStore.
    let mut operation_journal: Option<Arc<dyn OperationJournal>> = None;
    let mut postgres_pool = None;
    let keys: Arc<dyn KeyRepository> = if let Some(runtime) = &local_storage {
        let keys_file = config
            .keys
            .keys_file
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| runtime.internal_root().join("keys.json"));
        info!(path = %keys_file.display(), "Key store: local file");
        if multipart_persistence_mode == MultipartPersistenceMode::LocalStaged {
            operation_journal = Some(runtime.operation_journal());
        }
        Arc::new(FileKeyStore::with_cipher(keys_file, cipher.clone())?)
    } else if let Ok(database_url) = std::env::var("DATABASE_URL") {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("failed to connect to DATABASE_URL");
        crate::run_engine_migrations(&pool)
            .await
            .expect("failed to run migrations");
        info!("Key store: Postgres (migrations applied)");
        operation_journal = Some(Arc::new(crate::transaction::PostgresOperationJournal::new(
            pool.clone(),
        )));
        postgres_pool = Some(pool.clone());
        Arc::new(PostgresKeyStore::with_cipher(pool, cipher.clone()))
    } else if let Some(keys_file) = &config.keys.keys_file {
        info!("Key store: file ({keys_file})");
        Arc::new(FileKeyStore::with_cipher(
            PathBuf::from(keys_file),
            cipher.clone(),
        )?)
    } else if auth_disabled {
        let path = FileKeyStore::default_path();
        info!("Key store: file ({}) (local mode)", path.display());
        Arc::new(FileKeyStore::with_cipher(path, cipher)?)
    } else {
        info!("Key store: in-memory (set DATABASE_URL or MASKURA_KEYS_FILE for persistence)");
        Arc::new(KeyStore::with_cipher(cipher))
    };
    #[cfg(debug_assertions)]
    if operation_journal.is_none() && auth_disabled && local_storage.is_none() {
        info!(
            "Operation journal: in-memory (dev local mode; streaming S3 PUT uses a non-durable journal)"
        );
        operation_journal = Some(Arc::new(crate::transaction::InMemoryOperationJournal::new()));
    }
    let managed_repository: Arc<dyn ManagedRepository> = if let Some(pool) = postgres_pool.clone() {
        Arc::new(PostgresManagedRepository::new(pool))
    } else {
        Arc::new(InMemoryManagedRepository::new())
    };
    let service_storage = Arc::new(
        ServiceStorage::with_management(
            service_backends,
            managed_repository.clone(),
            managed_mode,
            managed_placement_version,
        )
        .with_managed_capabilities(managed_streaming_capabilities),
    );
    validate_managed_storage_at_launch(&service_storage)?;
    if !service_storage.is_empty() {
        let policy = ManagedPlacementPolicy {
            version: managed_placement_version,
            fingerprint: placement_policy_fingerprint(
                managed_placement_version,
                service_storage.backends.iter().map(|backend| {
                    (
                        backend.id(),
                        backend.placement_weight,
                        backend.placement_capacity_units,
                    )
                }),
            ),
            backend_facts: service_storage
                .backends
                .iter()
                .map(|backend| ManagedPlacementBackendFact {
                    backend_id: backend.id(),
                    placement_weight: backend.placement_weight,
                    placement_capacity_units: backend.placement_capacity_units,
                })
                .collect(),
            activated_at_ms: crate::transaction::unix_time_ms(),
        };
        let recorded = managed_repository
            .record_placement_policy(&policy)
            .await
            .map_err(anyhow::Error::msg)?;
        if !recorded {
            anyhow::bail!(
                "MASKURA_MANAGED_PLACEMENT_VERSION {managed_placement_version} is already durable with a different backend policy fingerprint; bump the placement version to change the policy"
            );
        }
    }
    let multipart_staging = match multipart_persistence_mode {
        MultipartPersistenceMode::LocalStaged => {
            let runtime = local_storage
                .as_ref()
                .expect("local staged mode has a local runtime");
            let artifacts = runtime.staging_artifacts();
            Some(Arc::new(MultipartStaging {
                repository: runtime.multipart_repository(),
                directory: artifacts.temporary_root().to_path_buf(),
                artifacts,
                wrapping: runtime.wrapping(),
            }))
        }
        MultipartPersistenceMode::HostedStaged => {
            let pool = postgres_pool
                .clone()
                .expect("hosted staged dependencies were validated");
            let endpoint = config.multipart_staging.endpoint.clone();
            let bucket = config.multipart_staging.bucket.clone();
            let access_key = std::env::var("MASKURA_MULTIPART_STAGING_ACCESS_KEY_ID").ok();
            let secret_key = std::env::var("MASKURA_MULTIPART_STAGING_SECRET_ACCESS_KEY").ok();
            match (endpoint, bucket, access_key, secret_key) {
                (Some(endpoint), Some(bucket), Some(access_key), Some(secret_key)) => {
                    let region = config
                        .multipart_staging
                        .region
                        .clone()
                        .unwrap_or_else(|| "us-east-1".to_string());
                    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                        .region(Region::new(region))
                        .endpoint_url(endpoint)
                        .credentials_provider(Credentials::new(
                            access_key,
                            secret_key,
                            None,
                            None,
                            "multipart-staging",
                        ))
                        .retry_config(s3_retry_config())
                        .timeout_config(s3_timeout_config())
                        .load()
                        .await;
                    Some(Arc::new(MultipartStaging {
                        repository: Arc::new(PostgresMultipartRepository::with_quotas(
                            pool,
                            multipart_quotas.expect("staged multipart has validated quotas"),
                        )),
                        artifacts: Arc::new(S3StagingArtifactStore::new(
                            Client::new(&sdk_config),
                            bucket,
                        )),
                        directory: config
                            .multipart_staging
                            .dir
                            .as_ref()
                            .map(PathBuf::from)
                            .unwrap_or_else(|| spool_config.directory.join("multipart")),
                        wrapping: wrapping.clone(),
                    }))
                }
                _ => {
                    warn!(
                        "staged multipart requested without a complete Maskura-controlled staging backend; transformed multipart remains rejected"
                    );
                    None
                }
            }
        }
        MultipartPersistenceMode::Reject => None,
    };
    validate_mode(
        managed_mode,
        managed_repository.as_ref(),
        auth_disabled || cfg!(debug_assertions),
    )
    .await?;
    if managed_mode != ManagedStreamingMode::Off && managed_streaming_capabilities.is_none() {
        anyhow::bail!(
            "managed observe/enforce mode requires MASKURA_MANAGED_STREAMING_TRANSACTIONAL=true"
        );
    }
    let multipart_coordinator = match (&multipart_staging, &operation_journal) {
        (Some(staging), Some(journal)) => {
            let coordinator =
                MultipartCompletionCoordinator::new(staging.repository.clone(), journal.clone())?;
            let coordinator = if multipart_persistence_mode == MultipartPersistenceMode::LocalStaged
            {
                coordinator.with_file_proof(
                    file_store
                        .clone()
                        .expect("local staged mode has a file store"),
                )
            } else {
                coordinator
            };
            Some(Arc::new(coordinator))
        }
        (None, _) => None,
        (Some(_), None) => anyhow::bail!("staged multipart requires a durable operation journal"),
    };
    let multipart_recovery = multipart_staging
        .as_ref()
        .zip(multipart_coordinator.as_ref())
        .map(|(staging, coordinator)| {
            Arc::new(MultipartRecoveryRuntime {
                staging: staging.clone(),
                coordinator: coordinator.clone(),
                file_store: (multipart_persistence_mode == MultipartPersistenceMode::LocalStaged)
                    .then(|| file_store.clone())
                    .flatten(),
                service_storage: service_storage.clone(),
            })
        });
    let multipart = Arc::new(MultipartPersistenceBundle {
        mode: multipart_persistence_mode,
        staging: multipart_staging,
        coordinator: multipart_coordinator,
        recovery: multipart_recovery,
        worker: Mutex::new(None),
    });
    if let Some(recovery) = &multipart.recovery {
        recovery.run_once(now_ms(), 256).await?;
    }
    if managed_mode == ManagedStreamingMode::Enforce
        && let (Some(journal), Some(capabilities)) =
            (operation_journal.clone(), managed_streaming_capabilities)
    {
        service_storage
            .reconcile_managed_logical_operations(
                journal.clone(),
                capabilities,
                Duration::from_millis(crate::managed::PHYSICAL_WRITE_LEASE_MS as u64),
                256,
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        service_storage
            .reconcile_managed_delete_settlements(control.as_ref(), 256)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        service_storage
            .reconcile_managed_write_intents(
                journal,
                capabilities,
                Duration::from_millis(crate::managed::PHYSICAL_WRITE_LEASE_MS as u64),
                256,
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    }

    // Local mode: ensure a demo principal exists for plugin context. Auth is
    // disabled, so clients use non-secret placeholder credentials and the
    // generated key secret must never be written to process logs.
    if auth_disabled {
        let demo_workspace = workspace_storage.resolve_workspace("demo-user").await?;
        let existing = keys.list_for_user("demo-user").await?;
        if existing.is_empty() {
            let (_secret, _created) = keys
                .create_key("demo-user", &demo_workspace, "local-default", 0, None)
                .await?;
            info!("created local demo API key");
        }
    }

    // Operator bootstrap: seed a preconfigured key id/secret pair so headless
    // automation has a stable credential without the interactive mint step.
    // Idempotent: an existing key with the same id is left untouched.
    let bootstrap_key = config.keys.bootstrap_key.clone();
    let bootstrap_secret = resolve_customer_env(customer_env::BOOTSTRAP_SECRET)?;
    match (bootstrap_key, bootstrap_secret) {
        (Some(key_id), Some(secret)) => {
            if keys.get_key(&key_id).await?.is_none() {
                let workspace = workspace_storage.resolve_workspace("demo-user").await?;
                keys.bootstrap_key(&key_id, &secret, "demo-user", &workspace, "bootstrapped")
                    .await?;
                info!("bootstrapped API key");
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!(
                "MASKURA_BOOTSTRAP_KEY and MASKURA_BOOTSTRAP_SECRET must be set together"
            );
        }
        (None, None) => {}
    }

    // Local appliance: bootstrap a SigV4 root credential and the canonical
    // bucket. Explicit MASKURA_ROOT_USER/MASKURA_ROOT_PASSWORD override the
    // generated pair; otherwise a strong pair is generated and disclosed once.
    if auto_local {
        let workspace = workspace_storage.resolve_workspace("root").await?;
        let root_user = resolve_customer_env(customer_env::ROOT_USER)?;
        let root_password = resolve_customer_env(customer_env::ROOT_PASSWORD)?;
        match (root_user, root_password) {
            (Some(access_key), Some(secret)) => {
                ensure_configured_local_root(keys.as_ref(), &access_key, &secret, &workspace)
                    .await?;
            }
            (Some(_), None) | (None, Some(_)) => {
                anyhow::bail!("MASKURA_ROOT_USER and MASKURA_ROOT_PASSWORD must be set together");
            }
            (None, None) => {
                if keys.list_for_user("root").await?.is_empty() {
                    let (secret, created) = keys
                        .create_key("root", &workspace, "local-root", 0, None)
                        .await?;
                    // First-run disclosure only: the operator needs the secret
                    // once to configure an S3 client. Later starts reuse it.
                    info!(
                        access_key = %created.key_id,
                        secret_key = %secret,
                        "generated local root credentials (shown once)"
                    );
                }
            }
        }
        if let Some(file_store) = &file_store {
            let buckets = file_store
                .list_buckets()
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            if !buckets.iter().any(|bucket| bucket == "maskura") {
                file_store
                    .create_bucket("maskura")
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                info!("created canonical local bucket `maskura`");
            }
        }
    }

    let mut continuation_token_key = [0; 32];
    OsRng.fill_bytes(&mut continuation_token_key);
    let state = Arc::new(AppState {
        gateway: Arc::new(gateway),
        store: Arc::new(MemoryStore::new()),
        file_store,
        local_storage,
        keys,
        workspace_storage,
        plugins,
        service_storage,
        s3_client,
        supabase_url,
        supabase_anon_key,
        jwt_decoder,
        auth_disabled,
        explicit_single_tenant,
        workspace_endpoint_policy,
        control,
        policy_gate: None,
        legacy_max_object_bytes: legacy_max_object_bytes(config),
        streaming_read_mode: effective_streaming_read_mode(config, auto_local),
        source_body_limits,
        max_pipeline_output_bytes,
        presigned_http_policy: PresignedHttpPolicy::from_config(&config.allowlists)
            .map_err(anyhow::Error::msg)?,
        sigv4_cache: Arc::new(SigningKeyCache::standard()),
        sigv4_policy: SigV4Policy::from_config(&config.sigv4),
        operation_journal,
        s3_streaming_capabilities,
        managed_streaming_capabilities,
        spool_config,
        spool_quota,
        transformed_read_spool_enabled: config.features.transformed_read_spool,
        binary_avro_enabled: config.features.enable_avro,
        dev_memory_max_object_bytes,
        dev_memory_streaming_enabled,
        demo_pipelines,
        demo_limiter: Arc::new(DemoLimiter::new()),
        multipart,
        continuation_token_key,
    });
    if managed_mode != ManagedStreamingMode::Off
        && let (Some(journal), Some(capabilities)) = (
            state.operation_journal.clone(),
            state.managed_streaming_capabilities,
        )
    {
        let storage = state.service_storage.clone();
        let control = state.control.clone();
        tokio::spawn(async move {
            let owner = format!("managed-repair-{}", uuid::Uuid::now_v7());
            loop {
                if storage
                    .reconcile_managed_logical_operations(
                        journal.clone(),
                        capabilities,
                        Duration::from_millis(crate::managed::PHYSICAL_WRITE_LEASE_MS as u64),
                        64,
                    )
                    .await
                    .is_err()
                {
                    warn!(
                        error_category = "persistence",
                        "managed logical-operation reconciliation failed"
                    );
                }
                if storage
                    .reconcile_managed_write_intents(
                        journal.clone(),
                        capabilities,
                        Duration::from_millis(crate::managed::PHYSICAL_WRITE_LEASE_MS as u64),
                        64,
                    )
                    .await
                    .is_err()
                {
                    warn!(
                        error_category = "persistence",
                        "managed write-intent reconciliation failed"
                    );
                }
                if storage
                    .reconcile_managed_delete_settlements(control.as_ref(), 64)
                    .await
                    .is_err()
                {
                    warn!(
                        error_category = "persistence",
                        "managed DELETE settlement reconciliation failed"
                    );
                }
                if storage
                    .repair_due(journal.clone(), capabilities, &owner, 16)
                    .await
                    .is_err()
                {
                    warn!(
                        error_category = "persistence",
                        "managed repair worker failed"
                    );
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
    }
    state.multipart.start_worker();
    Ok(state)
}

#[derive(Clone, Copy, Debug)]
pub struct InvocationLimits {
    pub(crate) max_request_body_bytes: usize,
    pub(crate) max_response_body_bytes: usize,
    pub(crate) timeout: Duration,
}

pub const MAX_INVOCATION_RESPONSE_BYTES: usize = crate::mcp::MAX_TEXT_BODY_BYTES;
pub const MAX_INVOCATION_TIMEOUT: Duration = Duration::from_secs(120);

impl InvocationLimits {
    pub fn new(
        max_request_body_bytes: usize,
        max_response_body_bytes: usize,
        timeout: Duration,
    ) -> Result<Self, InvocationError> {
        if max_request_body_bytes == 0 || max_request_body_bytes > crate::mcp::MAX_TEXT_BODY_BYTES {
            return Err(InvocationError::Invalid(format!(
                "max_request_body_bytes must be between 1 and {}",
                crate::mcp::MAX_TEXT_BODY_BYTES
            )));
        }
        if max_response_body_bytes == 0 || max_response_body_bytes > MAX_INVOCATION_RESPONSE_BYTES {
            return Err(InvocationError::Invalid(format!(
                "max_response_body_bytes must be between 1 and {MAX_INVOCATION_RESPONSE_BYTES}"
            )));
        }
        if timeout.is_zero() || timeout > MAX_INVOCATION_TIMEOUT {
            return Err(InvocationError::Invalid(format!(
                "timeout must be between 1ns and {} seconds",
                MAX_INVOCATION_TIMEOUT.as_secs()
            )));
        }
        Ok(Self {
            max_request_body_bytes,
            max_response_body_bytes,
            timeout,
        })
    }
}

impl Default for InvocationLimits {
    fn default() -> Self {
        Self::new(
            crate::mcp::MAX_TEXT_BODY_BYTES,
            MAX_INVOCATION_RESPONSE_BYTES,
            Duration::from_secs(30),
        )
        .expect("default invocation limits are valid")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvocationError {
    #[error("invalid invocation: {0}")]
    Invalid(String),
    #[error("gateway returned {status}: {message}")]
    Gateway { status: u16, message: String },
    #[error("trusted invocation was cancelled")]
    Cancelled,
    #[error("trusted invocation timed out")]
    Timeout,
}

pub(crate) fn bind_mcp_operation(
    operation_id: Uuid,
    context: &crate::store::AuthenticatedMcpPrincipal,
    request: &crate::mcp::ToolRequest,
) -> Result<(), InvocationError> {
    use sha2::Digest as _;
    static BINDINGS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<Uuid, [u8; 32]>>,
    > = std::sync::OnceLock::new();
    const MAX_BINDINGS: usize = 100_000;

    let mut hasher = sha2::Sha256::new();
    hasher.update(context.context.workspace_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(context.credential_id.as_bytes());
    hasher.update([0]);
    hasher.update(context.credential_policy_id.as_bytes());
    hasher.update([0]);
    hasher.update(request.canonical_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bindings = BINDINGS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| InvocationError::Invalid("operation identity registry failed".to_string()))?;
    match bindings.get(&operation_id) {
        Some(existing) if existing == &digest => Ok(()),
        Some(_) => Err(InvocationError::Invalid(
            "operation_id was already bound to a different MCP operation".to_string(),
        )),
        None if bindings.len() >= MAX_BINDINGS => Err(InvocationError::Invalid(
            "operation identity registry is full".to_string(),
        )),
        None => {
            bindings.insert(operation_id, digest);
            Ok(())
        }
    }
}

pub(crate) async fn collect_invocation_body(
    mut body: axum::body::Body,
    limit: usize,
    cancellation: &tokio_util::sync::CancellationToken,
    committed: &std::sync::atomic::AtomicBool,
) -> Result<Vec<u8>, InvocationError> {
    let mut output = Vec::new();
    loop {
        let frame = if committed.load(std::sync::atomic::Ordering::Acquire) {
            body.frame().await
        } else {
            tokio::select! {
                _ = cancellation.cancelled() => {
                    if committed.load(std::sync::atomic::Ordering::Acquire) {
                        body.frame().await
                    } else {
                        return Err(InvocationError::Cancelled);
                    }
                }
                frame = body.frame() => frame,
            }
        };
        let Some(frame) = frame else {
            return Ok(output);
        };
        let frame = frame.map_err(|_| InvocationError::Gateway {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            message: "gateway response body failed".to_string(),
        })?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if output.len().saturating_add(data.len()) > limit {
            return Err(InvocationError::Gateway {
                status: StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
                message: format!("gateway response exceeds {limit} bytes"),
            });
        }
        output.extend_from_slice(&data);
    }
}

/// Invoke an MCP operation inside the gateway trust boundary.
///
/// The supplied principal is already authenticated by the hosting adapter.
/// It is carried in task-local state that network requests cannot create, and
/// the operation runs through the same handlers as S3 traffic. No credential,
/// authorization, backend-selection, or metering headers are accepted.
pub async fn invoke_mcp(
    state: Arc<AppState>,
    context: TrustedInvocationContext,
    operation_id: Uuid,
    request: crate::mcp::ToolRequest,
    limits: InvocationLimits,
    cancellation: tokio_util::sync::CancellationToken,
) -> Result<crate::mcp::ToolResult, InvocationError> {
    if cancellation.is_cancelled() {
        return Err(InvocationError::Cancelled);
    }
    if operation_id.is_nil() {
        return Err(InvocationError::Invalid(
            "operation_id must not be nil".to_string(),
        ));
    }
    request
        .validate(limits.max_request_body_bytes)
        .map_err(|error| InvocationError::Invalid(error.to_string()))?;
    bind_mcp_operation(operation_id, &context.principal, &request)?;
    let principal = context.principal;
    let effective_cancellation = tokio_util::sync::CancellationToken::new();
    let committed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let receipt_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, operation_id.as_bytes().as_slice());
    let trusted = TrustedInvocation {
        auth: authenticated_credential(
            principal.context,
            principal.credential_policy_id,
            None,
            None,
        ),
        operation: OperationIdentity {
            receipt_id,
            operation_id,
        },
        cancellation: effective_cancellation.clone(),
        committed: committed.clone(),
    };
    let invoke = async {
        let (response, result_kind) = match request {
            crate::mcp::ToolRequest::PutObject(request) => {
                let content_type = request.content_type.parse().map_err(|_| {
                    InvocationError::Invalid("content_type is not a valid HTTP value".to_string())
                })?;
                let mut request_headers = HeaderMap::new();
                request_headers.insert(header::CONTENT_TYPE, content_type);
                let mut http_request = Request::new(axum::body::Body::from(request.body));
                *http_request.method_mut() = Method::PUT;
                *http_request.headers_mut() = request_headers;
                let response = s3_put(
                    State(state.clone()),
                    Path((request.bucket.clone(), request.key.clone())),
                    Query(S3Query::default()),
                    http_request,
                )
                .await
                .into_response();
                (response, (0_u8, request.bucket, request.key))
            }
            crate::mcp::ToolRequest::GetObject(request) => {
                let mut headers = HeaderMap::new();
                if request.process {
                    headers.insert("x-maskura-process", "read".parse().unwrap());
                }
                let response = s3_get(
                    State(state.clone()),
                    Path((request.bucket, request.key)),
                    Query(S3Query::default()),
                    Method::GET,
                    Uri::from_static("/"),
                    headers,
                )
                .await
                .into_response();
                (response, (1, String::new(), String::new()))
            }
            crate::mcp::ToolRequest::ListObjects(request) => {
                let response = s3_list_objects(
                    State(state.clone()),
                    Path(request.bucket),
                    Query(S3Query {
                        list_type: Some("2".to_string()),
                        prefix: Some(request.prefix),
                        continuation_token: request.continuation_token,
                        max_keys: request.max_keys,
                        delimiter: request.delimiter,
                        start_after: request.start_after,
                        ..Default::default()
                    }),
                    Method::GET,
                    Uri::from_static("/"),
                    HeaderMap::new(),
                )
                .await
                .into_response();
                (response, (2, String::new(), String::new()))
            }
            crate::mcp::ToolRequest::DeleteObject(request) => {
                let response = s3_delete(
                    State(state.clone()),
                    Path((request.bucket.clone(), request.key.clone())),
                    Query(S3Query::default()),
                    Method::DELETE,
                    Uri::from_static("/"),
                    HeaderMap::new(),
                )
                .await
                .into_response();
                (response, (3, request.bucket, request.key))
            }
        };
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = collect_invocation_body(
            response.into_body(),
            limits.max_response_body_bytes,
            &cancellation,
            committed.as_ref(),
        )
        .await?;
        if !status.is_success() {
            return Err(InvocationError::Gateway {
                status: status.as_u16(),
                message: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        match result_kind {
            (0, bucket, key) => Ok(crate::mcp::ToolResult::PutObject(
                crate::mcp::MutationResult {
                    bucket,
                    key,
                    status: status.as_u16(),
                },
            )),
            (1, _, _) => String::from_utf8(body)
                .map(|body| {
                    crate::mcp::ToolResult::GetObject(crate::mcp::GetObjectResult {
                        body,
                        content_type,
                    })
                })
                .map_err(|_| InvocationError::Gateway {
                    status: status.as_u16(),
                    message: "gateway response is not valid UTF-8".to_string(),
                }),
            (2, _, _) => {
                let body = String::from_utf8(body).map_err(|_| InvocationError::Gateway {
                    status: status.as_u16(),
                    message: "gateway response is not valid UTF-8".to_string(),
                })?;
                crate::mcp::parse_list_objects_result(&body)
                    .map(crate::mcp::ToolResult::ListObjects)
                    .map_err(|error| InvocationError::Gateway {
                        status: status.as_u16(),
                        message: format!("invalid ListObjectsV2 response: {error}"),
                    })
            }
            (3, bucket, key) => Ok(crate::mcp::ToolResult::DeleteObject(
                crate::mcp::MutationResult {
                    bucket,
                    key,
                    status: status.as_u16(),
                },
            )),
            _ => unreachable!("invocation result kind is internal"),
        }
    };
    let scoped = TRUSTED_INVOCATION.scope(trusted, invoke);
    tokio::pin!(scoped);
    let deadline = tokio::time::sleep(limits.timeout);
    tokio::pin!(deadline);
    enum Interrupted {
        Cancelled,
        Timeout,
    }
    let interrupted = tokio::select! {
        result = &mut scoped => return result,
        _ = cancellation.cancelled() => Interrupted::Cancelled,
        _ = &mut deadline => Interrupted::Timeout,
    };
    effective_cancellation.cancel();
    let settled = scoped.await;
    if committed.load(std::sync::atomic::Ordering::Acquire) {
        return settled;
    }
    match settled {
        Ok(result) => Ok(result),
        _ => match interrupted {
            Interrupted::Cancelled => Err(InvocationError::Cancelled),
            Interrupted::Timeout => Err(InvocationError::Timeout),
        },
    }
}
