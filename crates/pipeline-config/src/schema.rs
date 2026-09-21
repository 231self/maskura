use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::direction::Direction;
use crate::error::ConfigError;
use crate::plugin_ref::PluginRef;

pub const SCHEMA_VERSION: u32 = 1;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant: Vec<String>,
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
        Ok(())
    }

    /// Resolve the chain for `workspace_id`/`bucket`/`direction` using the
    /// precedence `workspace+bucket > workspace > bucket > default`. A more
    /// specific scope replaces rather than extends a chain.
    pub fn select(
        &self,
        workspace_id: &str,
        bucket: &str,
        direction: Direction,
    ) -> Option<&DirectionPipeline> {
        if let Some(workspace) = self.workspaces.get(workspace_id) {
            if let Some(scope) = workspace.buckets.get(bucket)
                && let Some(pipeline) = scope.get(direction)
            {
                return Some(pipeline);
            }
            if let Some(pipeline) = workspace.get(direction) {
                return Some(pipeline);
            }
        }
        if let Some(scope) = self.buckets.get(bucket)
            && let Some(pipeline) = scope.get(direction)
        {
            return Some(pipeline);
        }
        self.get(direction)
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
        if self.steps.is_empty() && !self.explicit_passthrough {
            return Err(ConfigError::invalid(format!(
                "{label} has no steps; set explicit_passthrough = true for an identity chain"
            )));
        }
        for (index, step) in self.steps.iter().enumerate() {
            step.validate(&format!("{label}.steps[{index}]"))?;
        }
        Ok(())
    }
}

impl StepDef {
    /// Canonical JSON rendering of the step config (v0.2 components only).
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
plugin = "file://dir/dirA/plugins:custom-redactor:0.2.0"

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
        assert!(file.select("ws-1", "bucket", Direction::Read).is_none());
        assert!(file.select("ws-1", "bucket", Direction::Write).is_some());
    }
}
