//! Versioned commitment to resolved runtime state, not a portable plugin-name export.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    ConfigError, PolicyLimits,
    canonical::{digest_of, is_hex64},
};

pub const EFFECTIVE_STATE_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveState {
    pub schema_version: u32,
    pub audience: String,
    pub workspace_id: String,
    pub destinations: BTreeMap<String, DestinationBinding>,
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
    /// Append-only workspace backend configuration snapshot used to build the
    /// execution client. Presigned requests bind a declared target instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_version_id: Option<String>,
    /// Digest of the immutable normalized storage configuration, including
    /// credential/key-version references and managed placement policy. No secrets.
    pub configuration_sha256: String,
}

/// The v2 signed destination: a concrete physical target or the complete
/// managed placement topology from which physical targets are frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DestinationBinding {
    Concrete {
        destination: ResolvedDestination,
    },
    ManagedTopology {
        placement_version: u32,
        algorithm: ManagedPlacementAlgorithm,
        authority_sha256: String,
        /// Sorted by backend_id, with unique IDs and non-secret version facts.
        backends: Vec<ManagedBackend>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedPlacementAlgorithm {
    WeightedRendezvous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedBackend {
    pub backend_id: String,
    pub provider_kind: String,
    pub provider_instance_id: String,
    pub provider_account_id: String,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub placement_weight: u64,
    pub placement_capacity_units: u64,
    pub credential_epoch: u64,
    /// SHA-256 of immutable normalized non-secret configuration facts.
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
        if self.schema_version != EFFECTIVE_STATE_SCHEMA_VERSION
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
            if id.trim().is_empty() {
                return Err(ConfigError::invalid("invalid resolved destination id"));
            }
            destination.validate()?;
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

fn valid_https_endpoint(endpoint: &str) -> bool {
    let Ok(url) = url::Url::parse(endpoint) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.to_string() == endpoint
}

impl DestinationBinding {
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Concrete { destination } => {
                if !valid_https_endpoint(&destination.endpoint)
                    || destination.bucket.trim().is_empty()
                    || !is_hex64(&destination.configuration_sha256)
                    || destination.mode == StorageMode::Managed
                    || (destination.mode != StorageMode::Presigned
                        && destination.region.trim().is_empty())
                    || (destination.mode != StorageMode::Presigned
                        && destination
                            .configuration_version_id
                            .as_deref()
                            .is_none_or(|id| id.trim().is_empty()))
                    || (destination.mode == StorageMode::Presigned
                        && (destination.configuration_version_id.is_some()
                            || url::Url::parse(&destination.endpoint)
                                .is_ok_and(|url| url.path() != "/")))
                    || (destination.mode == StorageMode::AwsRole
                        && (destination.region.trim().is_empty()
                            || destination.role_arn.as_deref().is_none_or(str::is_empty)))
                    || (destination.mode != StorageMode::AwsRole && destination.role_arn.is_some())
                {
                    return Err(ConfigError::invalid("invalid concrete destination"));
                }
            }
            Self::ManagedTopology {
                placement_version,
                authority_sha256,
                backends,
                ..
            } => {
                if *placement_version == 0
                    || !is_hex64(authority_sha256)
                    || backends.is_empty()
                    || backends.len() > 64
                {
                    return Err(ConfigError::invalid("invalid managed topology"));
                }
                let mut previous = "";
                for backend in backends {
                    if backend.backend_id.trim().is_empty()
                        || backend.backend_id.as_str() <= previous
                        || backend.provider_kind.trim().is_empty()
                        || backend.provider_instance_id.trim().is_empty()
                        || backend.provider_account_id.trim().is_empty()
                        || !valid_https_endpoint(&backend.endpoint)
                        || backend.region.trim().is_empty()
                        || backend.bucket.trim().is_empty()
                        || backend.placement_weight == 0
                        || backend.placement_capacity_units == 0
                        || backend
                            .placement_weight
                            .checked_mul(backend.placement_capacity_units)
                            .is_none()
                        || backend.credential_epoch == 0
                        || !is_hex64(&backend.configuration_sha256)
                    {
                        return Err(ConfigError::invalid("invalid managed backend binding"));
                    }
                    previous = &backend.backend_id;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn fixture() -> EffectiveState {
    EffectiveState {
        schema_version: EFFECTIVE_STATE_SCHEMA_VERSION,
        workspace_id: "ws-1".into(),
        audience: "https://maskura.dev".into(),
        destinations: [(
            "dest".into(),
            DestinationBinding::Concrete {
                destination: ResolvedDestination {
                    mode: StorageMode::S3Compatible,
                    endpoint: "https://s3.example.com/".into(),
                    bucket: "objects".into(),
                    region: "region".into(),
                    role_arn: None,
                    configuration_version_id: Some("config-version-1".into()),
                    configuration_sha256: "d".repeat(64),
                },
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

    fn concrete(state: &mut EffectiveState) -> &mut ResolvedDestination {
        match state.destinations.get_mut("dest").unwrap() {
            DestinationBinding::Concrete { destination } => destination,
            DestinationBinding::ManagedTopology { .. } => panic!("expected concrete destination"),
        }
    }

    fn managed() -> DestinationBinding {
        DestinationBinding::ManagedTopology {
            placement_version: 2,
            algorithm: ManagedPlacementAlgorithm::WeightedRendezvous,
            authority_sha256: "e".repeat(64),
            backends: ["aws", "b2"]
                .into_iter()
                .map(|name| ManagedBackend {
                    backend_id: name.into(),
                    provider_kind: name.into(),
                    provider_instance_id: format!("{name}-instance"),
                    provider_account_id: format!("{name}-account"),
                    endpoint: format!("https://{name}.example.com/"),
                    region: "region".into(),
                    bucket: format!("{name}-physical"),
                    placement_weight: 2,
                    placement_capacity_units: 1,
                    credential_epoch: 3,
                    configuration_sha256: "a".repeat(64),
                })
                .collect(),
        }
    }

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
            |s| concrete(s).endpoint = "https://other.example.com/".into(),
            |s| concrete(s).bucket.push('2'),
            |s| concrete(s).configuration_sha256 = "c".repeat(64),
            |s| concrete(s).configuration_version_id = Some("config-version-2".into()),
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

    #[test]
    fn v2_concrete_and_managed_topology_round_trip_and_bind_all_physical_facts() {
        let mut state = fixture();
        let original = state.digest().unwrap();
        state.destinations.insert("dest".into(), managed());
        let managed_digest = state.digest().unwrap();
        assert_eq!(
            managed_digest,
            "3e38f445301ba62a1ebc18eda0a4b27ecd4d942fae89ac63ddf7eb7f76829374"
        );
        assert_ne!(managed_digest, original);
        let encoded = serde_json::to_value(&state).unwrap();
        assert_eq!(encoded["destinations"]["dest"]["kind"], "managed_topology");
        assert!(encoded.to_string().find("secret_key").is_none());
        assert_eq!(
            serde_json::from_value::<EffectiveState>(encoded).unwrap(),
            state
        );

        let mut variants: Vec<fn(&mut DestinationBinding)> = vec![
            |value| {
                if let DestinationBinding::ManagedTopology {
                    placement_version, ..
                } = value
                {
                    *placement_version += 1
                }
            },
            |value| {
                if let DestinationBinding::ManagedTopology {
                    authority_sha256, ..
                } = value
                {
                    *authority_sha256 = "f".repeat(64)
                }
            },
            |value| {
                if let DestinationBinding::ManagedTopology { backends, .. } = value {
                    backends[0].bucket.push('2')
                }
            },
            |value| {
                if let DestinationBinding::ManagedTopology { backends, .. } = value {
                    backends[0].provider_kind.push('2')
                }
            },
            |value| {
                if let DestinationBinding::ManagedTopology { backends, .. } = value {
                    backends[0].credential_epoch += 1
                }
            },
            |value| {
                if let DestinationBinding::ManagedTopology { backends, .. } = value {
                    backends[0].placement_capacity_units += 1
                }
            },
            |value| {
                if let DestinationBinding::ManagedTopology { backends, .. } = value {
                    backends[0].configuration_sha256 = "b".repeat(64)
                }
            },
        ];
        for mutate in variants.drain(..) {
            let mut changed = state.clone();
            mutate(changed.destinations.get_mut("dest").unwrap());
            assert_ne!(changed.digest().unwrap(), managed_digest);
        }
    }

    #[test]
    fn invalid_topology_and_legacy_schema_fail_closed() {
        let mut state = fixture();
        state.schema_version = 1;
        assert!(state.digest().is_err());
        state.schema_version = 2;
        concrete(&mut state).configuration_version_id = None;
        assert!(
            state.validate().is_err(),
            "unversioned workspace config cannot be approved"
        );
        state = fixture();
        concrete(&mut state).mode = StorageMode::Managed;
        assert!(
            state.validate().is_err(),
            "managed requires an approved topology"
        );
        state = fixture();
        let target = concrete(&mut state);
        target.mode = StorageMode::Presigned;
        target.configuration_version_id = None;
        target.region.clear();
        state.validate().unwrap();
        concrete(&mut state).endpoint = "https://s3.example.com/other-bucket/key".into();
        assert!(
            state.validate().is_err(),
            "presigned target must be an origin"
        );
        state = fixture();
        state.destinations.insert("dest".into(), managed());

        let invalid: Vec<fn(&mut ManagedBackend)> = vec![
            |backend| backend.credential_epoch = 0,
            |backend| backend.provider_account_id.clear(),
            |backend| backend.endpoint = "http://example.com/".into(),
            |backend| backend.placement_weight = 0,
            |backend| backend.configuration_sha256 = "short".into(),
        ];
        for mutate in invalid {
            let mut changed = state.clone();
            if let DestinationBinding::ManagedTopology { backends, .. } =
                changed.destinations.get_mut("dest").unwrap()
            {
                mutate(&mut backends[0]);
            }
            assert!(changed.validate().is_err());
        }

        let mut changed = state.clone();
        if let DestinationBinding::ManagedTopology { backends, .. } =
            changed.destinations.get_mut("dest").unwrap()
        {
            backends.reverse();
        }
        assert!(
            changed.validate().is_err(),
            "provider list must be canonical"
        );

        let mut changed = state.clone();
        if let DestinationBinding::ManagedTopology { backends, .. } =
            changed.destinations.get_mut("dest").unwrap()
        {
            backends[1].backend_id = backends[0].backend_id.clone();
        }
        assert!(
            changed.validate().is_err(),
            "duplicate providers are forbidden"
        );

        let mut unknown = serde_json::to_value(&state).unwrap();
        unknown["destinations"]["dest"]["unapproved"] = true.into();
        assert!(serde_json::from_value::<EffectiveState>(unknown).is_err());
        let mut leaked = serde_json::to_value(&state).unwrap();
        leaked["destinations"]["dest"]["backends"][0]["secret_key"] = "forbidden".into();
        assert!(serde_json::from_value::<EffectiveState>(leaked).is_err());
    }
}
