//! Versioned commitment to resolved runtime state, not a portable plugin-name export.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    ConfigError, PolicyLimits,
    canonical::{digest_of, is_hex64},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveState {
    pub schema_version: u32,
    pub audience: String,
    pub workspace_id: String,
    pub destinations: BTreeMap<String, ResolvedDestination>,
    /// Expanded effective routes. Unlisted operations/buckets/prefixes are denied.
    pub routes: Vec<ResolvedRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedDestination {
    pub mode: StorageMode,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub role_arn: Option<String>,
    /// Digest of the immutable normalized storage configuration, including
    /// credential/key-version references and managed placement policy. No secrets.
    pub configuration_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMode {
    Managed,
    S3Compatible,
    AwsRole,
    Presigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOperation {
    Put,
    ProcessedGet,
    RawGet,
    Head,
    List,
    Delete,
    MultipartCreate,
    MultipartUpload,
    MultipartComplete,
    MultipartAbort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRoute {
    pub bucket: String,
    pub prefix: String,
    pub operation: PolicyOperation,
    pub destination_id: String,
    pub assignment_id: String,
    pub revision_id: String,
    pub resolution_fingerprint: String,
    pub explicit_passthrough: bool,
    pub format: String,
    pub adapter_sha256: Option<String>,
    pub limits: ResolvedLimits,
    pub steps: Vec<ResolvedStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedLimits {
    pub processing: PolicyLimits,
    pub output_max_bytes: u64,
    pub table_entries: u64,
    pub stack_bytes: u64,
    pub max_plugins: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedStep {
    pub component_sha256: String,
    pub plugin_version_id: String,
    pub world: String,
    pub enabled: bool,
    pub config_json: Option<String>,
    pub grants: BTreeSet<String>,
    pub prefix_safe_for_read: bool,
}

impl EffectiveState {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1
            || self.workspace_id.trim().is_empty()
            || self.audience.trim().is_empty()
        {
            return Err(ConfigError::invalid(
                "invalid effective-state version or scope",
            ));
        }
        if self.destinations.len() > 1024 || self.routes.len() > 4096 {
            return Err(ConfigError::invalid(
                "effective state exceeds routing limits",
            ));
        }
        for (id, destination) in &self.destinations {
            let url = url::Url::parse(&destination.endpoint)
                .map_err(|_| ConfigError::invalid("invalid destination endpoint"))?;
            if id.trim().is_empty()
                || destination.bucket.trim().is_empty()
                || !is_hex64(&destination.configuration_sha256)
                || url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || (destination.mode == StorageMode::AwsRole
                    && (destination.region.trim().is_empty()
                        || destination.role_arn.as_deref().is_none_or(str::is_empty)))
            {
                return Err(ConfigError::invalid("invalid resolved destination"));
            }
        }
        let mut scopes = BTreeSet::new();
        for route in &self.routes {
            if route.bucket.trim().is_empty()
                || route.assignment_id.trim().is_empty()
                || route.revision_id.trim().is_empty()
                || !is_hex64(&route.resolution_fingerprint)
                || !self.destinations.contains_key(&route.destination_id)
                || !scopes.insert((&route.bucket, &route.prefix, route.operation))
            {
                return Err(ConfigError::invalid("invalid or duplicate resolved route"));
            }
            if route.format.is_empty()
                || route.adapter_sha256.as_ref().is_some_and(|v| !is_hex64(v))
                || (route.format != "bytes" && route.adapter_sha256.is_none())
            {
                return Err(ConfigError::invalid(
                    "non-byte routes must pin their adapter implementation",
                ));
            }
            let limits = &route.limits;
            let p = limits.processing;
            if [
                p.record_max_bytes,
                p.object_max_bytes,
                p.memory_bytes,
                p.fuel,
                p.deadline_ms,
                limits.output_max_bytes,
                limits.table_entries,
                limits.stack_bytes,
                limits.max_plugins,
            ]
            .contains(&0)
                || route.steps.len() > 1024
                || route.steps.len() as u64 > limits.max_plugins
            {
                return Err(ConfigError::invalid("invalid resolved runtime limits"));
            }
            if !route.explicit_passthrough
                && route.adapter_sha256.is_none()
                && !route.steps.iter().any(|s| s.enabled)
            {
                return Err(ConfigError::invalid(
                    "empty processing requires explicit passthrough",
                ));
            }
            for step in &route.steps {
                if !is_hex64(&step.component_sha256)
                    || step.plugin_version_id.trim().is_empty()
                    || step.world.trim().is_empty()
                    || step.grants.iter().any(|g| {
                        ![
                            "public_key_pem",
                            "entropy_seed",
                            "stable_key",
                            "stable_fields",
                        ]
                        .contains(&g.as_str())
                    })
                {
                    return Err(ConfigError::invalid("invalid resolved step"));
                }
                if let Some(config) = &step.config_json {
                    if config.len() > 65_536 {
                        return Err(ConfigError::invalid("step config exceeds limit"));
                    }
                    let value: serde_json::Value = serde_json::from_str(config)
                        .map_err(|_| ConfigError::invalid("invalid step JSON"))?;
                    if serde_json::to_string(&value)
                        .map_err(|_| ConfigError::invalid("invalid step JSON"))?
                        != *config
                    {
                        return Err(ConfigError::invalid(
                            "step JSON must use canonical sorted-key encoding",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ConfigError> {
        self.validate()?;
        digest_of(self)
    }
}

#[cfg(test)]
pub(crate) fn fixture() -> EffectiveState {
    EffectiveState {
        schema_version: 1,
        workspace_id: "ws-1".into(),
        audience: "https://maskura.dev".into(),
        destinations: [(
            "dest".into(),
            ResolvedDestination {
                mode: StorageMode::S3Compatible,
                endpoint: "https://s3.example.com".into(),
                bucket: "objects".into(),
                region: "region".into(),
                role_arn: None,
                configuration_sha256: "d".repeat(64),
            },
        )]
        .into(),
        routes: vec![ResolvedRoute {
            bucket: "tenant".into(),
            prefix: "data/".into(),
            operation: PolicyOperation::Put,
            destination_id: "dest".into(),
            assignment_id: "assignment".into(),
            revision_id: "revision".into(),
            resolution_fingerprint: "f".repeat(64),
            explicit_passthrough: false,
            format: "bytes".into(),
            adapter_sha256: None,
            limits: ResolvedLimits {
                processing: PolicyLimits {
                    record_max_bytes: 1024,
                    object_max_bytes: 4096,
                    memory_bytes: 67_108_864,
                    fuel: 10_000_000,
                    deadline_ms: 30_000,
                },
                output_max_bytes: 8192,
                table_entries: 10000,
                stack_bytes: 524288,
                max_plugins: 10,
            },
            steps: vec![ResolvedStep {
                component_sha256: "a".repeat(64),
                plugin_version_id: "plugin-version".into(),
                world: "maskura:plugin/transformer@0.1.0".into(),
                enabled: true,
                config_json: Some("{\"mode\":\"redact\"}".into()),
                grants: BTreeSet::new(),
                prefix_safe_for_read: false,
            }],
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_and_storage_changes_change_commitment() {
        let original = fixture();
        let mutations: Vec<fn(&mut EffectiveState)> = vec![
            |s| s.routes[0].steps[0].component_sha256 = "b".repeat(64),
            |s| s.routes[0].steps[0].plugin_version_id.push('2'),
            |s| s.routes[0].steps[0].config_json = Some("{}".into()),
            |s| {
                s.routes[0].steps[0].grants.insert("stable_key".into());
            },
            |s| s.routes[0].steps[0].prefix_safe_for_read = true,
            |s| s.routes[0].assignment_id.push('2'),
            |s| s.routes[0].revision_id.push('2'),
            |s| s.routes[0].resolution_fingerprint = "e".repeat(64),
            |s| s.routes[0].explicit_passthrough = true,
            |s| s.routes[0].operation = PolicyOperation::ProcessedGet,
            |s| s.routes[0].prefix.push('x'),
            |s| s.routes[0].limits.processing.fuel += 1,
            |s| s.routes[0].limits.stack_bytes += 1,
            |s| s.routes[0].limits.output_max_bytes += 1,
            |s| {
                s.destinations.get_mut("dest").unwrap().endpoint =
                    "https://other.example.com".into()
            },
            |s| s.destinations.get_mut("dest").unwrap().bucket.push('2'),
            |s| s.destinations.get_mut("dest").unwrap().configuration_sha256 = "c".repeat(64),
            |s| {
                s.routes[0].format = "avro".into();
                s.routes[0].adapter_sha256 = Some("a".repeat(64));
            },
        ];
        for mutate in mutations {
            let mut state = original.clone();
            mutate(&mut state);
            assert_ne!(state.digest().unwrap(), original.digest().unwrap());
        }
    }

    #[test]
    fn step_order_is_signed_and_invalid_routes_fail_closed() {
        let mut state = fixture();
        let mut second = state.routes[0].steps[0].clone();
        second.component_sha256 = "b".repeat(64);
        state.routes[0].steps.push(second);
        let digest = state.digest().unwrap();
        state.routes[0].steps.reverse();
        assert_ne!(state.digest().unwrap(), digest);
        state.routes.push(state.routes[0].clone());
        assert!(state.validate().is_err());
        let mut state = fixture();
        state.routes[0].destination_id = "missing".into();
        assert!(state.validate().is_err());
        let mut state = fixture();
        state.routes[0].steps[0].config_json = Some("{\"a\":1,\"a\":2}".into());
        assert!(state.validate().is_err());
    }
}
