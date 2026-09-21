//! File-based pipeline resolution for OSS/self-hosted gateways.
//!
//! [`SignedTomlPipelineResolver`] selects a chain from a signed
//! [`PipelineFile`] by workspace/bucket/direction and maps each step's
//! [`PluginRef`] to a content-addressed local component. The source URI is
//! carried for identity and portability; OSS resolves every reference against
//! locally loaded components (remote fetching is not implemented).

use std::sync::Arc;

use async_trait::async_trait;
use maskura_error::{MaskuraError, codes};
use maskura_pipeline_config::{
    ConfigError, Direction as ConfigDirection, DirectionPipeline, PipelineFile, PluginRef, StepDef,
};
use maskura_wasm_runtime::SensitiveGrant;

use crate::pipeline::{
    PipelineDirection, PipelineLocator, PipelineResolution, PipelineResolver, PipelineStep,
    resolution_fingerprint,
};
use crate::plugin_registry::{
    PipelineLimits, PluginCapabilities, PluginRegistry, TRANSFORMER_WORLD,
};

/// One component available to file-based resolution.
#[derive(Clone, Debug)]
struct CatalogEntry {
    source: Option<String>,
    component_hash: String,
    name: String,
    version: String,
    world_version: String,
    capabilities: PluginCapabilities,
}

/// Resolves [`PluginRef`]s against the local component catalog.
#[derive(Clone, Debug, Default)]
pub struct LocalPluginCatalog {
    entries: Vec<CatalogEntry>,
}

impl LocalPluginCatalog {
    pub fn from_registry(registry: &PluginRegistry) -> Self {
        let entries = registry
            .catalog_records()
            .into_iter()
            .map(|record| CatalogEntry {
                source: record.source,
                component_hash: record.component_hash,
                name: record.name,
                version: record.version,
                world_version: record.world_version,
                capabilities: record.capabilities,
            })
            .collect();
        Self { entries }
    }

    fn lookup(&self, reference: &PluginRef) -> Result<&CatalogEntry, MaskuraError> {
        let by_digest = is_digest(&reference.name);
        let mut candidates: Vec<&CatalogEntry> = self
            .entries
            .iter()
            .filter(|entry| match &reference.source {
                Some(source) => entry.source.as_ref() == Some(source),
                None => entry
                    .source
                    .as_deref()
                    .is_none_or(|source| source.starts_with("file://")),
            })
            .filter(|entry| {
                if by_digest {
                    entry.component_hash == reference.name
                } else {
                    entry.name == reference.name
                }
            })
            .filter(|entry| reference.accepts_version(&entry.version))
            .collect();
        if candidates.is_empty() {
            return Err(MaskuraError::new(
                codes::WASM_INIT,
                format!("component {reference} is not available locally"),
            ));
        }
        candidates.sort_by(|a, b| {
            let a = semver::Version::parse(&a.version).expect("catalog versions are validated");
            let b = semver::Version::parse(&b.version).expect("catalog versions are validated");
            b.cmp_precedence(&a)
        });
        let selected = candidates[0];
        let selected_version =
            semver::Version::parse(&selected.version).expect("catalog versions are validated");
        if candidates.iter().skip(1).any(|candidate| {
            semver::Version::parse(&candidate.version)
                .is_ok_and(|candidate| candidate.cmp_precedence(&selected_version).is_eq())
                && candidate.component_hash != selected.component_hash
        }) {
            return Err(MaskuraError::new(
                codes::CONFIG_INVALID,
                format!("component {reference} resolves ambiguously to multiple digests"),
            ));
        }
        Ok(selected)
    }
}

impl CatalogEntry {
    fn to_pipeline_step(&self, step: &StepDef) -> Result<PipelineStep, MaskuraError> {
        if self.world_version != TRANSFORMER_WORLD {
            return Err(MaskuraError::new(
                codes::CONFIG_INVALID,
                format!(
                    "component {} uses unsupported world {:?}",
                    step.plugin, self.world_version
                ),
            ));
        }
        Ok(PipelineStep {
            component_hash: self.component_hash.clone(),
            plugin_version_id: None,
            enabled: step.enabled,
            version: Some(self.version.clone()),
            config_json: step.config_json().map_err(config_error)?,
            capabilities: self.capabilities,
            sensitive_grant: sensitive_grant(&step.grant),
        })
    }
}

/// Resolves the effective chain from a signed TOML pipeline file.
pub struct SignedTomlPipelineResolver {
    file: PipelineFile,
    revision: String,
    catalog: Arc<LocalPluginCatalog>,
    limits: PipelineLimits,
}

impl SignedTomlPipelineResolver {
    pub fn from_registry(
        file: PipelineFile,
        registry: &PluginRegistry,
    ) -> Result<Self, MaskuraError> {
        let revision = file.revision().map_err(config_error)?;
        Self::from_registry_with_revision(file, registry, revision)
    }

    pub fn from_registry_with_revision(
        file: PipelineFile,
        registry: &PluginRegistry,
        revision: String,
    ) -> Result<Self, MaskuraError> {
        let catalog = LocalPluginCatalog::from_registry(registry);
        let limits = registry.pipeline_limits();
        Self::new_with_revision(file, catalog, limits, revision)
    }

    pub fn new(
        file: PipelineFile,
        catalog: LocalPluginCatalog,
        limits: PipelineLimits,
    ) -> Result<Self, MaskuraError> {
        let revision = file.revision().map_err(config_error)?;
        Self::new_with_revision(file, catalog, limits, revision)
    }

    pub fn new_with_revision(
        file: PipelineFile,
        catalog: LocalPluginCatalog,
        limits: PipelineLimits,
        revision: String,
    ) -> Result<Self, MaskuraError> {
        let resolver = Self {
            file,
            revision,
            catalog: Arc::new(catalog),
            limits,
        };
        resolver.validate_all()?;
        Ok(resolver)
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn validate_all(&self) -> Result<(), MaskuraError> {
        if let Some(pipeline) = &self.file.write {
            self.validate_pipeline("write", pipeline)?;
        }
        if let Some(pipeline) = &self.file.read {
            self.validate_pipeline("read", pipeline)?;
        }
        for (bucket, scope) in &self.file.buckets {
            if let Some(pipeline) = &scope.write {
                self.validate_pipeline(&format!("buckets.{bucket}.write"), pipeline)?;
            }
            if let Some(pipeline) = &scope.read {
                self.validate_pipeline(&format!("buckets.{bucket}.read"), pipeline)?;
            }
        }
        for (workspace, scope) in &self.file.workspaces {
            if let Some(pipeline) = &scope.write {
                self.validate_pipeline(&format!("workspaces.{workspace}.write"), pipeline)?;
            }
            if let Some(pipeline) = &scope.read {
                self.validate_pipeline(&format!("workspaces.{workspace}.read"), pipeline)?;
            }
            for (bucket, nested) in &scope.buckets {
                if let Some(pipeline) = &nested.write {
                    self.validate_pipeline(
                        &format!("workspaces.{workspace}.buckets.{bucket}.write"),
                        pipeline,
                    )?;
                }
                if let Some(pipeline) = &nested.read {
                    self.validate_pipeline(
                        &format!("workspaces.{workspace}.buckets.{bucket}.read"),
                        pipeline,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn validate_pipeline(
        &self,
        label: &str,
        pipeline: &DirectionPipeline,
    ) -> Result<(), MaskuraError> {
        let enabled = pipeline.steps.iter().filter(|step| step.enabled).count();
        if enabled > self.limits.max_plugins {
            return Err(MaskuraError::new(
                codes::CONFIG_INVALID,
                format!(
                    "{label} has {enabled} enabled steps; maximum is {}",
                    self.limits.max_plugins
                ),
            ));
        }
        for step in &pipeline.steps {
            self.catalog.lookup(&step.plugin)?.to_pipeline_step(step)?;
        }
        Ok(())
    }
}

#[async_trait]
impl PipelineResolver for SignedTomlPipelineResolver {
    async fn resolve(
        &self,
        workspace_id: &str,
        bucket: &str,
        direction: PipelineDirection,
    ) -> Result<PipelineResolution, MaskuraError> {
        let config_direction = match direction {
            PipelineDirection::Write => ConfigDirection::Write,
            PipelineDirection::Read => ConfigDirection::Read,
        };
        let pipeline = self
            .file
            .select(workspace_id, bucket, config_direction)
            .map_err(config_error)?;

        let mut steps = Vec::with_capacity(pipeline.steps.len());
        for step in &pipeline.steps {
            let entry = self.catalog.lookup(&step.plugin)?;
            steps.push(entry.to_pipeline_step(step)?);
        }

        let fingerprint = resolution_fingerprint(
            direction,
            &steps,
            pipeline.explicit_passthrough,
            self.limits,
        );
        Ok(PipelineResolution {
            locator: PipelineLocator {
                revision: self.revision.clone(),
                fingerprint,
            },
            steps,
            policy_generation: None,
            explicit_passthrough: pipeline.explicit_passthrough,
            limits: self.limits,
        })
    }
}

fn is_digest(name: &str) -> bool {
    name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit())
}

fn config_error(error: ConfigError) -> MaskuraError {
    MaskuraError::new(error.code(), error.to_string())
}

fn sensitive_grant(grants: &[String]) -> SensitiveGrant {
    let mut grant = SensitiveGrant::NONE;
    for capability in grants {
        match capability.as_str() {
            "public_key_pem" => grant.public_key_pem = true,
            "entropy_seed" => grant.entropy_seed = true,
            "stable_key" => grant.stable_key = true,
            "stable_fields" => grant.stable_fields = true,
            _ => {}
        }
    }
    grant
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
schema_version = 1
signer_id = "acme-prod"

[write]
[[write.steps]]
plugin = "pii-default"

[[write.steps]]
plugin = "envelope-encrypt:1.2.0"
grant = ["public_key_pem"]
[write.steps.config]
mode = "hash"

[read]
[[read.steps]]
plugin = "envelope-decrypt"

[workspaces."ws-strict".write]
[[workspaces."ws-strict".write.steps]]
plugin = "stable-encrypt"
"#;

    fn entry(name: &str, version: &str, hash_byte: char) -> CatalogEntry {
        CatalogEntry {
            source: None,
            component_hash: hash_byte.to_string().repeat(64),
            name: name.to_string(),
            version: version.to_string(),
            world_version: TRANSFORMER_WORLD.to_string(),
            capabilities: PluginCapabilities::default(),
        }
    }

    fn sourced_entry(source: &str, name: &str, version: &str, hash_byte: char) -> CatalogEntry {
        CatalogEntry {
            source: Some(source.to_string()),
            ..entry(name, version, hash_byte)
        }
    }

    fn catalog() -> LocalPluginCatalog {
        LocalPluginCatalog {
            entries: vec![
                entry("pii-default", "0.1.0", 'a'),
                entry("envelope-encrypt", "0.1.0", 'b'),
                entry("envelope-encrypt", "1.2.0", 'c'),
                entry("envelope-decrypt", "0.1.0", 'd'),
                entry("stable-encrypt", "0.1.0", 'e'),
            ],
        }
    }

    fn resolver() -> SignedTomlPipelineResolver {
        let file = PipelineFile::from_toml_str(FILE).unwrap();
        SignedTomlPipelineResolver::new(file, catalog(), PipelineLimits::default()).unwrap()
    }

    #[test]
    fn lookup_resolves_name_and_highest_matching_version() {
        let catalog = catalog();
        let reference = PluginRef::parse("envelope-encrypt:1.2.0").unwrap();
        let found = catalog.lookup(&reference).unwrap();
        assert_eq!(found.component_hash, "c".repeat(64));

        let latest = PluginRef::parse("envelope-encrypt").unwrap();
        assert_eq!(catalog.lookup(&latest).unwrap().version, "1.2.0");
    }

    #[test]
    fn lookup_orders_versions_semantically() {
        let catalog = LocalPluginCatalog {
            entries: vec![
                entry("plugin", "2.0.0", 'a'),
                entry("plugin", "10.0.0", 'b'),
            ],
        };
        let selected = catalog
            .lookup(&PluginRef::parse("plugin").unwrap())
            .unwrap();
        assert_eq!(selected.version, "10.0.0");
    }

    #[test]
    fn lookup_enforces_qualified_source() {
        let catalog = LocalPluginCatalog {
            entries: vec![
                sourced_entry("file:///trusted", "plugin", "1.0.0", 'a'),
                sourced_entry("file:///other", "plugin", "1.0.0", 'b'),
            ],
        };
        let trusted = PluginRef::parse("file:///trusted:plugin:1.0.0").unwrap();
        assert_eq!(
            catalog.lookup(&trusted).unwrap().component_hash,
            "a".repeat(64)
        );
        let missing = PluginRef::parse("file:///missing:plugin:1.0.0").unwrap();
        assert!(catalog.lookup(&missing).is_err());
    }

    #[test]
    fn duplicate_identity_with_different_digests_is_rejected() {
        let catalog = LocalPluginCatalog {
            entries: vec![entry("plugin", "1.0.0", 'a'), entry("plugin", "1.0.0", 'b')],
        };
        assert!(
            catalog
                .lookup(&PluginRef::parse("plugin:1.0.0").unwrap())
                .is_err()
        );
    }

    #[test]
    fn equal_semver_precedence_with_different_digests_is_ambiguous() {
        let catalog = LocalPluginCatalog {
            entries: vec![
                entry("plugin", "1.0.0+first", 'a'),
                entry("plugin", "1.0.0+second", 'b'),
            ],
        };
        assert!(
            catalog
                .lookup(&PluginRef::parse("plugin").unwrap())
                .is_err()
        );
    }

    #[test]
    fn lookup_missing_component_is_an_error() {
        let error = catalog()
            .lookup(&PluginRef::parse("nope").unwrap())
            .unwrap_err();
        assert_eq!(error.code(), codes::WASM_INIT);
    }

    #[tokio::test]
    async fn resolve_maps_steps_and_verifies_fingerprint() {
        let resolution = resolver()
            .resolve("ws", "bucket", PipelineDirection::Write)
            .await
            .unwrap();
        assert_eq!(resolution.steps.len(), 2);
        assert_eq!(resolution.steps[0].component_hash, "a".repeat(64));
        assert_eq!(resolution.steps[1].component_hash, "c".repeat(64));
        assert_eq!(
            resolution.steps[1].config_json.as_deref(),
            Some("{\"mode\":\"hash\"}")
        );
        assert!(resolution.steps[1].sensitive_grant.public_key_pem);
        assert!(!resolution.steps[1].sensitive_grant.stable_key);
        assert_eq!(resolution.policy_generation, None);
        resolution
            .verify_fingerprint(PipelineDirection::Write)
            .unwrap();
    }

    #[tokio::test]
    async fn workspace_override_replaces_default() {
        let resolution = resolver()
            .resolve("ws-strict", "bucket", PipelineDirection::Write)
            .await
            .unwrap();
        assert_eq!(resolution.steps.len(), 1);
        assert_eq!(resolution.steps[0].component_hash, "e".repeat(64));
    }

    #[tokio::test]
    async fn unassigned_direction_fails_closed() {
        let file = PipelineFile::from_toml_str(
            r#"
schema_version = 1
signer_id = "acme-prod"
[write]
[[write.steps]]
plugin = "pii-default"
"#,
        )
        .unwrap();
        let resolver =
            SignedTomlPipelineResolver::new(file, catalog(), PipelineLimits::default()).unwrap();
        let error = resolver
            .resolve("ws", "bucket", PipelineDirection::Read)
            .await
            .unwrap_err();
        assert_eq!(error.code(), codes::CONFIG_INVALID);
    }

    #[test]
    fn invalid_shadowed_scope_fails_eager_validation() {
        let file = PipelineFile::from_toml_str(
            r#"
schema_version = 1
signer_id = "acme-prod"
[write]
[[write.steps]]
plugin = "pii-default"
[workspaces.ws.write]
[[workspaces.ws.write.steps]]
plugin = "missing"
[workspaces.ws.buckets.bucket.write]
[[workspaces.ws.buckets.bucket.write.steps]]
plugin = "stable-encrypt"
"#,
        )
        .unwrap();
        let error = SignedTomlPipelineResolver::new(file, catalog(), PipelineLimits::default())
            .err()
            .expect("shadowed missing component must fail at construction");
        assert_eq!(error.code(), codes::WASM_INIT);
    }

    #[test]
    fn unsigned_revision_override_is_preserved() {
        let file = PipelineFile::from_toml_str(FILE).unwrap();
        let resolver = SignedTomlPipelineResolver::new_with_revision(
            file,
            catalog(),
            PipelineLimits::default(),
            "unsigned-dev".to_string(),
        )
        .unwrap();
        assert_eq!(resolver.revision(), "unsigned-dev");
    }
}
