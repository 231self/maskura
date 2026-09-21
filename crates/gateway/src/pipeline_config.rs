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
    ConfigError, Direction as ConfigDirection, PipelineFile, PluginRef, StepDef,
};
use maskura_wasm_runtime::SensitiveGrant;

use crate::pipeline::{
    PipelineDirection, PipelineLocator, PipelineResolution, PipelineResolver, PipelineStep,
    resolution_fingerprint,
};
use crate::plugin_registry::{PipelineLimits, PluginCapabilities, PluginRegistry};

/// One component available to file-based resolution.
#[derive(Clone, Debug)]
struct CatalogEntry {
    component_hash: String,
    name: String,
    version: String,
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
            .catalog_entries()
            .into_iter()
            .map(|(info, component_hash, capabilities)| CatalogEntry {
                component_hash,
                name: info.name,
                version: info.version,
                capabilities,
            })
            .collect();
        Self { entries }
    }

    fn lookup(&self, reference: &PluginRef) -> Result<&CatalogEntry, MaskuraError> {
        let by_digest = is_digest(&reference.name);
        let mut candidates: Vec<&CatalogEntry> = self
            .entries
            .iter()
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
        // Deterministic "latest": highest version, import order breaking ties.
        candidates.sort_by(|a, b| b.version.cmp(&a.version));
        Ok(candidates[0])
    }
}

impl CatalogEntry {
    fn to_pipeline_step(&self, step: &StepDef) -> Result<PipelineStep, MaskuraError> {
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
    pub fn from_registry(file: PipelineFile, registry: &PluginRegistry) -> Self {
        let catalog = LocalPluginCatalog::from_registry(registry);
        let limits = registry.pipeline_limits();
        Self::new(file, catalog, limits)
    }

    pub fn new(file: PipelineFile, catalog: LocalPluginCatalog, limits: PipelineLimits) -> Self {
        let revision = file.revision();
        Self {
            file,
            revision,
            catalog: Arc::new(catalog),
            limits,
        }
    }

    pub fn revision(&self) -> &str {
        &self.revision
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
            .ok_or_else(|| {
                MaskuraError::new(
                    codes::CONFIG_INVALID,
                    format!(
                        "no {} pipeline is assigned for workspace {workspace_id:?} bucket {bucket:?}",
                        config_direction
                    ),
                )
            })?;

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
            component_hash: hash_byte.to_string().repeat(64),
            name: name.to_string(),
            version: version.to_string(),
            capabilities: PluginCapabilities::default(),
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
        SignedTomlPipelineResolver::new(file, catalog(), PipelineLimits::default())
    }

    #[test]
    fn lookup_resolves_name_and_highest_matching_version() {
        let catalog = catalog();
        let reference = PluginRef::parse("envelope-encrypt:1.2.0").unwrap();
        let found = catalog.lookup(&reference).unwrap();
        assert_eq!(found.component_hash, "c".repeat(64));

        let latest = PluginRef::parse("envelope-encrypt").unwrap();
        assert!(latest.accepts_version("1.2.0"));
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
        let resolver = SignedTomlPipelineResolver::new(file, catalog(), PipelineLimits::default());
        let error = resolver
            .resolve("ws", "bucket", PipelineDirection::Read)
            .await
            .unwrap_err();
        assert_eq!(error.code(), codes::CONFIG_INVALID);
    }
}
