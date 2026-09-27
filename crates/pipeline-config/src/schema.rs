use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::canonical::{is_hex64, sha256_hex};
use crate::direction::Direction;
use crate::error::ConfigError;
use crate::plugin_ref::PluginRef;
use crate::policy::PolicySection;

pub const SCHEMA_VERSION: u32 = 1;
pub const IDENTITY_VERSION: u32 = 1;

const ALLOWED_GRANTS: [&str; 4] = [
    "public_key_pem",
    "entropy_seed",
    "stable_key",
    "stable_fields",
];

/// A signed, hierarchical pipeline definition.
///
/// Scopes are the default (`write`/`read`), `buckets.<bucket>`,
/// `workspaces.<id>`, and `workspaces.<id>.buckets.<bucket>`. Each scope
/// carries dedicated, ordered write and read chains.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineFile {
    pub schema_version: u32,
    pub signer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<DirectionPipeline>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<DirectionPipeline>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub buckets: BTreeMap<String, ScopeOverride>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub workspaces: BTreeMap<String, WorkspaceScope>,
    /// Standing policy envelope bounds. Absence keeps the historical
    /// unsigned-bounds behavior; presence is covered by the envelope artifact
    /// digest (`revision`). Hosted enforcement is a separate integration;
    /// parsing or verifying this file does not enforce these bounds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicySection>,
    /// Versioned export identity: `slug:version` ↔ component digests. Names
    /// are display; digests are the signed identity. Old readers reject files
    /// that carry the section (fail closed); policy-aware readers must
    /// require it via [`PipelineFile::require_identity`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentitySection>,
}

/// Versioned `slug:version` ↔ component-digest export identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySection {
    /// Identity schema version; only [`IDENTITY_VERSION`] is defined.
    pub version: u32,
    /// One entry per distinct plugin reference used by the file's chains.
    /// The envelope `filters` lockfile is exactly this digest set.
    #[serde(default)]
    pub components: Vec<IdentityComponent>,
}

/// One name ↔ digest binding, shaped like the envelope's `FilterLockEntry`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityComponent {
    /// Exactly pinned `name:version` reference as written in `step.plugin`.
    pub plugin: PluginRef,
    /// 64 lowercase hex characters: the component byte digest.
    pub sha256: String,
    /// When present, every use of the component must hash to this config
    /// digest; when absent, configuration is free.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
}

impl IdentitySection {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != IDENTITY_VERSION {
            return Err(ConfigError::invalid(format!(
                "unsupported identity version {}; expected {IDENTITY_VERSION}",
                self.version
            )));
        }
        let mut seen = BTreeSet::new();
        for component in &self.components {
            if !component.plugin.is_exactly_pinned() {
                return Err(ConfigError::invalid(format!(
                    "identity component {} must pin an exact version",
                    component.plugin
                )));
            }
            if !is_hex64(&component.sha256) {
                return Err(ConfigError::invalid(
                    "identity sha256 must be 64 lowercase hex characters",
                ));
            }
            if let Some(config_hash) = &component.config_hash
                && !is_hex64(config_hash)
            {
                return Err(ConfigError::invalid(
                    "identity config_hash must be 64 lowercase hex characters",
                ));
            }
            if !seen.insert(String::from(component.plugin.clone())) {
                return Err(ConfigError::invalid(format!(
                    "duplicate identity component {}",
                    component.plugin
                )));
            }
        }
        Ok(())
    }

    pub fn get(&self, plugin: &PluginRef) -> Option<&IdentityComponent> {
        let key = String::from(plugin.clone());
        self.components
            .iter()
            .find(|component| String::from(component.plugin.clone()) == key)
    }
}

/// Config digest for identity entries and the envelope lockfile: SHA-256 over
/// the canonical sorted-key JSON text of the step configuration (the same
/// encoding as [`StepDef::config_json`] and the frozen resolution's
/// `config_json`).
pub fn config_hash_of(config_json: &str) -> String {
    sha256_hex(config_json.as_bytes())
}

/// Identity config digest for one step; `None` when the step has no config.
pub fn step_config_hash(step: &StepDef) -> Result<Option<String>, ConfigError> {
    Ok(step.config_json()?.map(|json| config_hash_of(&json)))
}

/// A workspace scope: default direction chains plus per-bucket overrides.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<DirectionPipeline>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<DirectionPipeline>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub buckets: BTreeMap<String, ScopeOverride>,
}

/// A non-workspace scope: direction chains only.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<DirectionPipeline>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<DirectionPipeline>,
}

/// One ordered chain for a single direction within a scope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectionPipeline {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub explicit_passthrough: bool,
    #[serde(default)]
    pub steps: Vec<StepDef>,
}

/// One ordered, content-addressed step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepDef {
    pub plugin: PluginRef,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant: Vec<String>,
    // Keep the nested `config` table last so TOML serialization emits all
    // key/value pairs before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<toml::Value>,
}

const fn enabled_by_default() -> bool {
    true
}

impl PipelineFile {
    pub fn from_toml_str(input: &str) -> Result<Self, ConfigError> {
        let file: Self = toml::from_str(input)?;
        file.validate()?;
        Ok(file)
    }

    /// Render the manifest as TOML, including any current signature.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|error| {
            ConfigError::invalid(format!("cannot serialize pipeline config: {error}"))
        })
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|error| {
            ConfigError::invalid(format!("cannot read {}: {error}", path.display()))
        })?;
        Self::from_toml_str(&raw)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ConfigError::invalid(format!(
                "unsupported schema_version {}; expected {SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.signer_id.trim().is_empty() {
            return Err(ConfigError::invalid("signer_id must not be empty"));
        }
        if let (Some(not_before), Some(expires_at)) = (self.not_before, self.expires_at)
            && not_before >= expires_at
        {
            return Err(ConfigError::invalid(
                "not_before must be strictly before expires_at",
            ));
        }
        if let Some(pipeline) = &self.write {
            pipeline.validate("write")?;
        }
        if let Some(pipeline) = &self.read {
            pipeline.validate("read")?;
        }
        for (bucket, scope) in &self.buckets {
            scope.validate(&format!("buckets.{bucket}"))?;
        }
        for (workspace, scope) in &self.workspaces {
            scope.validate(&format!("workspaces.{workspace}"))?;
        }
        if let Some(policy) = &self.policy {
            policy.validate()?;
        }
        if let Some(identity) = &self.identity {
            identity.validate()?;
            let mut used = BTreeSet::new();
            for (label, step) in self.each_step() {
                let plugin = String::from(step.plugin.clone());
                if !step.plugin.is_exactly_pinned() {
                    return Err(ConfigError::invalid(format!(
                        "{label} uses unpinned plugin {plugin}; identity requires exact versions"
                    )));
                }
                let entry = identity.get(&step.plugin).ok_or_else(|| {
                    ConfigError::invalid(format!(
                        "{label} uses plugin {plugin} with no identity entry"
                    ))
                })?;
                if let Some(expected) = &entry.config_hash
                    && step_config_hash(step)?.as_deref() != Some(expected)
                {
                    return Err(ConfigError::invalid(format!(
                        "{label} uses plugin {plugin} with a mismatched identity config_hash"
                    )));
                }
                used.insert(plugin);
            }
            for entry in &identity.components {
                if !used.contains(&String::from(entry.plugin.clone())) {
                    return Err(ConfigError::invalid(format!(
                        "identity component {} is not used by any chain",
                        entry.plugin
                    )));
                }
            }
        }
        Ok(())
    }

    /// Policy-aware readers must require the identity section: approving or
    /// verifying state without name ↔ digest bindings is a silent downgrade.
    pub fn require_identity(&self) -> Result<&IdentitySection, ConfigError> {
        self.identity.as_ref().ok_or_else(|| {
            ConfigError::invalid("policy identity section is required; this export carries none")
        })
    }

    /// Every step in every chain, with its scope label.
    fn each_step(&self) -> Vec<(String, &StepDef)> {
        fn walk<'a>(
            out: &mut Vec<(String, &'a StepDef)>,
            label: &str,
            pipeline: &'a DirectionPipeline,
        ) {
            for step in &pipeline.steps {
                out.push((label.to_string(), step));
            }
        }
        let mut steps = Vec::new();
        if let Some(pipeline) = &self.write {
            walk(&mut steps, "write", pipeline);
        }
        if let Some(pipeline) = &self.read {
            walk(&mut steps, "read", pipeline);
        }
        for (bucket, scope) in &self.buckets {
            if let Some(pipeline) = &scope.write {
                walk(&mut steps, &format!("buckets.{bucket}.write"), pipeline);
            }
            if let Some(pipeline) = &scope.read {
                walk(&mut steps, &format!("buckets.{bucket}.read"), pipeline);
            }
        }
        for (workspace, scope) in &self.workspaces {
            if let Some(pipeline) = &scope.write {
                walk(
                    &mut steps,
                    &format!("workspaces.{workspace}.write"),
                    pipeline,
                );
            }
            if let Some(pipeline) = &scope.read {
                walk(
                    &mut steps,
                    &format!("workspaces.{workspace}.read"),
                    pipeline,
                );
            }
            for (bucket, nested) in &scope.buckets {
                if let Some(pipeline) = &nested.write {
                    walk(
                        &mut steps,
                        &format!("workspaces.{workspace}.buckets.{bucket}.write"),
                        pipeline,
                    );
                }
                if let Some(pipeline) = &nested.read {
                    walk(
                        &mut steps,
                        &format!("workspaces.{workspace}.buckets.{bucket}.read"),
                        pipeline,
                    );
                }
            }
        }
        steps
    }

    /// Resolve the chain for `workspace_id`/`bucket`/`direction` using the
    /// precedence `workspace+bucket > workspace > bucket > default`. A more
    /// specific scope replaces rather than extends a chain.
    pub fn select(
        &self,
        workspace_id: &str,
        bucket: &str,
        direction: Direction,
    ) -> Result<&DirectionPipeline, ConfigError> {
        if let Some(workspace) = self.workspaces.get(workspace_id) {
            if let Some(scope) = workspace.buckets.get(bucket)
                && let Some(pipeline) = scope.get(direction)
            {
                return Ok(pipeline);
            }
            if let Some(pipeline) = workspace.get(direction) {
                return Ok(pipeline);
            }
        }
        if let Some(scope) = self.buckets.get(bucket)
            && let Some(pipeline) = scope.get(direction)
        {
            return Ok(pipeline);
        }
        self.get(direction).ok_or_else(|| {
            ConfigError::invalid(format!(
                "no {direction} pipeline is assigned for workspace {workspace_id:?} bucket {bucket:?}"
            ))
        })
    }

    pub fn get(&self, direction: Direction) -> Option<&DirectionPipeline> {
        match direction {
            Direction::Write => self.write.as_ref(),
            Direction::Read => self.read.as_ref(),
        }
    }
}

impl DirectionPipeline {
    fn validate(&self, label: &str) -> Result<(), ConfigError> {
        if !self.steps.iter().any(|step| step.enabled) && !self.explicit_passthrough {
            return Err(ConfigError::invalid(format!(
                "{label} has no enabled steps; set explicit_passthrough = true for an identity chain"
            )));
        }
        for (index, step) in self.steps.iter().enumerate() {
            step.validate(&format!("{label}.steps[{index}]"))?;
        }
        Ok(())
    }
}

impl StepDef {
    /// Canonical JSON rendering of step configuration for transformer worlds
    /// that expose `config-json`.
    pub fn config_json(&self) -> Result<Option<String>, ConfigError> {
        let Some(config) = &self.config else {
            return Ok(None);
        };
        let value = serde_json::to_value(config)
            .map_err(|error| ConfigError::invalid(format!("step config is invalid: {error}")))?;
        let rendered = serde_json::to_string(&value)
            .map_err(|error| ConfigError::invalid(format!("step config is invalid: {error}")))?;
        Ok(Some(rendered))
    }

    fn validate(&self, label: &str) -> Result<(), ConfigError> {
        for grant in &self.grant {
            if !ALLOWED_GRANTS.contains(&grant.as_str()) {
                return Err(ConfigError::invalid(format!(
                    "{label}: unsupported grant {grant:?}; expected one of {ALLOWED_GRANTS:?}"
                )));
            }
        }
        Ok(())
    }
}

impl ScopeOverride {
    fn validate(&self, label: &str) -> Result<(), ConfigError> {
        if let Some(pipeline) = &self.write {
            pipeline.validate(&format!("{label}.write"))?;
        }
        if let Some(pipeline) = &self.read {
            pipeline.validate(&format!("{label}.read"))?;
        }
        Ok(())
    }

    fn get(&self, direction: Direction) -> Option<&DirectionPipeline> {
        match direction {
            Direction::Write => self.write.as_ref(),
            Direction::Read => self.read.as_ref(),
        }
    }
}

impl WorkspaceScope {
    fn validate(&self, label: &str) -> Result<(), ConfigError> {
        if let Some(pipeline) = &self.write {
            pipeline.validate(&format!("{label}.write"))?;
        }
        if let Some(pipeline) = &self.read {
            pipeline.validate(&format!("{label}.read"))?;
        }
        for (bucket, scope) in &self.buckets {
            scope.validate(&format!("{label}.buckets.{bucket}"))?;
        }
        Ok(())
    }

    fn get(&self, direction: Direction) -> Option<&DirectionPipeline> {
        match direction {
            Direction::Write => self.write.as_ref(),
            Direction::Read => self.read.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
schema_version = 1
signer_id = "acme-prod"

[write]
[[write.steps]]
plugin = "pii-default"

[read]
[[read.steps]]
plugin = "envelope-decrypt"
"#;

    /// Exercises the full hierarchy from the design doc.
    const FULL: &str = r#"
schema_version = 1
signer_id = "acme-prod"

[write]
description = "applied to every PUT"
[[write.steps]]
plugin = "https://github.com/231self/maskura/plugins:stable-encrypt:1.2.0"
grant = ["stable_key", "stable_fields"]
[write.steps.config]
mode = "hash"
[[write.steps]]
plugin = "pii-default"
[[write.steps]]
plugin = "file:///srv/maskura/plugins:custom-redactor:0.2.0"

[read]
[[read.steps]]
plugin = "envelope-decrypt"
grant = ["public_key_pem"]

[workspaces."ws-1".write]
[[workspaces."ws-1".write.steps]]
plugin = "strict-redactor"

[workspaces."ws-1".buckets."tenant-a".write]
[[workspaces."ws-1".buckets."tenant-a".write.steps]]
plugin = "tenant-redactor"

[buckets."raw-events".write]
explicit_passthrough = true
"#;

    #[test]
    fn minimal_file_parses_with_default_and_direction_chains() {
        let file = PipelineFile::from_toml_str(MINIMAL).unwrap();
        assert_eq!(file.schema_version, SCHEMA_VERSION);
        assert_eq!(file.write.as_ref().unwrap().steps.len(), 1);
        assert_eq!(file.read.as_ref().unwrap().steps.len(), 1);
        assert!(file.buckets.is_empty());
        assert!(file.workspaces.is_empty());
    }

    #[test]
    fn full_hierarchy_parses() {
        let file = PipelineFile::from_toml_str(FULL).unwrap();
        let write = file.write.as_ref().unwrap();
        assert_eq!(write.steps.len(), 3);
        assert_eq!(write.steps[1].plugin.name, "pii-default");
        assert_eq!(write.steps[0].grant, ["stable_key", "stable_fields"]);
        assert_eq!(
            write.steps[0]
                .config
                .as_ref()
                .unwrap()
                .get("mode")
                .unwrap()
                .as_str(),
            Some("hash")
        );
        assert!(file.buckets.contains_key("raw-events"));
        assert!(
            file.workspaces
                .get("ws-1")
                .unwrap()
                .buckets
                .contains_key("tenant-a")
        );
    }

    #[test]
    fn unknown_top_level_key_is_rejected() {
        let input = format!("{MINIMAL}\nunexpected = true\n");
        assert!(PipelineFile::from_toml_str(&input).is_err());
    }

    #[test]
    fn unknown_step_key_is_rejected() {
        let input = r#"
schema_version = 1
signer_id = "acme-prod"
[write]
[[write.steps]]
plugin = "pii-default"
typo = true
"#;
        assert!(PipelineFile::from_toml_str(input).is_err());
    }

    #[test]
    fn empty_chain_requires_explicit_passthrough() {
        let input = r#"
schema_version = 1
signer_id = "acme-prod"
[write]
"#;
        let error = PipelineFile::from_toml_str(input).unwrap_err();
        assert!(error.to_string().contains("explicit_passthrough"));
    }

    #[test]
    fn empty_chain_with_explicit_passthrough_is_accepted() {
        let input = r#"
schema_version = 1
signer_id = "acme-prod"
[write]
explicit_passthrough = true
"#;
        let file = PipelineFile::from_toml_str(input).unwrap();
        assert!(file.write.as_ref().unwrap().steps.is_empty());
    }

    #[test]
    fn all_disabled_chain_requires_explicit_passthrough() {
        let input = r#"
schema_version = 1
signer_id = "acme-prod"
[write]
[[write.steps]]
plugin = "pii-default"
enabled = false
"#;
        let error = PipelineFile::from_toml_str(input).unwrap_err();
        assert!(error.to_string().contains("no enabled steps"));
    }

    #[test]
    fn all_disabled_chain_with_explicit_passthrough_is_accepted() {
        let input = r#"
schema_version = 1
signer_id = "acme-prod"
[write]
explicit_passthrough = true
[[write.steps]]
plugin = "pii-default"
enabled = false
"#;
        PipelineFile::from_toml_str(input).unwrap();
    }

    #[test]
    fn unsupported_grant_is_rejected() {
        let input = r#"
schema_version = 1
signer_id = "acme-prod"
[write]
[[write.steps]]
plugin = "pii-default"
grant = ["root"]
"#;
        assert!(PipelineFile::from_toml_str(input).is_err());
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let input = r#"
schema_version = 2
signer_id = "acme-prod"
[write]
[[write.steps]]
plugin = "pii-default"
"#;
        assert!(PipelineFile::from_toml_str(input).is_err());
    }

    fn step(plugin: &str) -> StepDef {
        StepDef {
            plugin: PluginRef::parse(plugin).unwrap(),
            enabled: true,
            config: None,
            grant: Vec::new(),
        }
    }

    #[test]
    fn selection_precedence_is_most_specific_first() {
        let mut file = PipelineFile::from_toml_str(FULL).unwrap();
        file.workspaces
            .get_mut("ws-1")
            .unwrap()
            .buckets
            .entry("tenant-a".to_string())
            .or_default()
            .read = Some(DirectionPipeline {
            description: None,
            explicit_passthrough: false,
            steps: vec![step("tenant-reader")],
        });
        file.workspaces
            .get_mut("ws-1")
            .unwrap()
            .buckets
            .entry("other".to_string())
            .or_default()
            .read = Some(DirectionPipeline {
            description: None,
            explicit_passthrough: false,
            steps: vec![step("bucket-reader")],
        });

        let selected = |workspace: &str, bucket: &str, direction| {
            file.select(workspace, bucket, direction).unwrap().steps[0]
                .plugin
                .name
                .clone()
        };

        assert_eq!(
            selected("ws-1", "tenant-a", Direction::Read),
            "tenant-reader"
        );
        assert_eq!(selected("ws-1", "other", Direction::Read), "bucket-reader");
        assert_eq!(
            selected("unknown", "no-such-bucket", Direction::Write),
            "stable-encrypt"
        );
    }

    #[test]
    fn bucket_scope_applies_to_any_workspace() {
        let file = PipelineFile::from_toml_str(FULL).unwrap();
        let pipeline = file.select("unknown-ws", "raw-events", Direction::Write);
        assert!(pipeline.unwrap().explicit_passthrough);
    }

    #[test]
    fn workspace_chain_replaces_default_for_that_workspace() {
        let file = PipelineFile::from_toml_str(FULL).unwrap();
        let selected = file.select("ws-1", "missing", Direction::Write).unwrap();
        assert_eq!(selected.steps[0].plugin.name, "strict-redactor");
    }

    #[test]
    fn unassigned_direction_returns_none() {
        let write_only = r#"
schema_version = 1
signer_id = "acme-prod"
[write]
[[write.steps]]
plugin = "pii-default"
"#;
        let file = PipelineFile::from_toml_str(write_only).unwrap();
        assert!(file.select("ws-1", "bucket", Direction::Read).is_err());
        assert!(file.select("ws-1", "bucket", Direction::Write).is_ok());
    }

    const IDENTITY: &str = r#"
schema_version = 1
signer_id = "acme-prod"

[write]
[[write.steps]]
plugin = "pii-default:1.0.0"
[write.steps.config]
mode = "redact"
[[write.steps]]
plugin = "envelope-decrypt:2.0.0"

[identity]
version = 1
[[identity.components]]
plugin = "pii-default:1.0.0"
sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
[[identity.components]]
plugin = "envelope-decrypt:2.0.0"
sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
"#;

    #[test]
    fn identity_section_parses_and_roundtrips() {
        let file = PipelineFile::from_toml_str(IDENTITY).unwrap();
        let identity = file.require_identity().expect("identity present");
        assert_eq!(identity.version, IDENTITY_VERSION);
        assert_eq!(identity.components.len(), 2);
        let rendered = file.to_toml_string().unwrap();
        let reparsed = PipelineFile::from_toml_str(&rendered).unwrap();
        assert_eq!(reparsed, file);
    }

    #[test]
    fn require_identity_fails_closed_without_the_section() {
        let file = PipelineFile::from_toml_str(MINIMAL).unwrap();
        let error = file.require_identity().expect_err("identity absent");
        assert!(error.to_string().contains("identity section is required"));
    }

    #[test]
    fn identity_validation_matrix_fails_closed() {
        let cases: [(&str, &str, &str); 4] = [
            (
                "bad version",
                r#"
schema_version = 1
signer_id = "acme-prod"
[write]
[[write.steps]]
plugin = "pii-default:1.0.0"
[identity]
version = 9
[[identity.components]]
plugin = "pii-default:1.0.0"
sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
"#,
                "unsupported identity version",
            ),
            (
                "uppercase digest",
                r#"
schema_version = 1
signer_id = "acme-prod"
[write]
[[write.steps]]
plugin = "pii-default:1.0.0"
[identity]
version = 1
[[identity.components]]
plugin = "pii-default:1.0.0"
sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#,
                "lowercase hex",
            ),
            (
                "short digest",
                r#"
schema_version = 1
signer_id = "acme-prod"
[write]
[[write.steps]]
plugin = "pii-default:1.0.0"
[identity]
version = 1
[[identity.components]]
plugin = "pii-default:1.0.0"
sha256 = "abc"
"#,
                "lowercase hex",
            ),
            (
                "unpinned plugin",
                r#"
schema_version = 1
signer_id = "acme-prod"
[write]
[[write.steps]]
plugin = "pii-default:1.0.0"
[identity]
version = 1
[[identity.components]]
plugin = "pii-default"
sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
"#,
                "exact version",
            ),
        ];
        for (label, toml, expected) in cases {
            let error = PipelineFile::from_toml_str(toml)
                .expect_err(label)
                .to_string();
            assert!(error.contains(expected), "{label}: {error}");
        }
    }

    #[test]
    fn duplicate_identity_components_fail() {
        let toml = IDENTITY.replace(
            "[[identity.components]]\nplugin = \"envelope-decrypt:2.0.0\"",
            "[[identity.components]]\nplugin = \"pii-default:1.0.0\"",
        );
        let error = PipelineFile::from_toml_str(&toml)
            .expect_err("duplicate component")
            .to_string();
        assert!(error.contains("duplicate identity component"), "{error}");
    }

    #[test]
    fn steps_without_identity_entries_fail() {
        let toml = IDENTITY.replace(
            "[[identity.components]]\nplugin = \"envelope-decrypt:2.0.0\"\nsha256 = \"2222222222222222222222222222222222222222222222222222222222222222\"",
            "",
        );
        let error = PipelineFile::from_toml_str(&toml)
            .expect_err("missing identity entry")
            .to_string();
        assert!(error.contains("no identity entry"), "{error}");
    }

    #[test]
    fn config_hash_is_canonical_json_sha256() {
        let file = PipelineFile::from_toml_str(IDENTITY).unwrap();
        let identity = file.require_identity().unwrap();
        let unconfigured = identity
            .get(&file.write.as_ref().unwrap().steps[1].plugin)
            .unwrap();
        assert!(unconfigured.config_hash.is_none());
        let configurable = identity
            .get(&file.write.as_ref().unwrap().steps[0].plugin)
            .unwrap();
        assert!(configurable.config_hash.is_none());
        let with_config = file.write.as_ref().unwrap().steps[0].clone();
        let hash = step_config_hash(&with_config).unwrap().expect("has config");
        assert_eq!(hash.len(), 64);
        assert_eq!(
            hash,
            config_hash_of(&with_config.config_json().unwrap().unwrap())
        );
    }

    #[test]
    fn pinned_config_hash_must_match_every_occurrence() {
        let mut file = PipelineFile::from_toml_str(IDENTITY).unwrap();
        let first = &file.write.as_ref().unwrap().steps[0];
        let hash = step_config_hash(first).unwrap().unwrap();
        file.identity.as_mut().unwrap().components[0].config_hash = Some(hash);
        file.validate().unwrap();
        file.write.as_mut().unwrap().steps[0].config =
            Some(toml::from_str("mode = 'drop'").unwrap());
        assert!(
            file.validate()
                .unwrap_err()
                .to_string()
                .contains("identity config_hash")
        );
    }

    #[test]
    fn identity_rejects_unreferenced_component() {
        let mut file = PipelineFile::from_toml_str(IDENTITY).unwrap();
        file.identity
            .as_mut()
            .unwrap()
            .components
            .push(IdentityComponent {
                plugin: PluginRef::parse("unused:1.0.0").unwrap(),
                sha256: "a".repeat(64),
                config_hash: None,
            });
        assert!(
            file.validate()
                .unwrap_err()
                .to_string()
                .contains("not used by any chain")
        );
    }

    #[test]
    fn signed_identity_digest_changes_revision_and_invalidates_signature() {
        let mut file = PipelineFile::from_toml_str(IDENTITY).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
        file.sign(&key).unwrap();
        let original = file.revision().unwrap();
        let mut roots = crate::signing::TrustRoots::new();
        roots.insert(file.signer_id.clone(), key.verifying_key());
        file.verify(&roots).unwrap();

        file.identity.as_mut().unwrap().components[0].sha256 = "a".repeat(64);
        assert_ne!(file.revision().unwrap(), original);
        assert!(file.verify(&roots).is_err());
    }
}
