use serde::{Deserialize, Serialize};

use crate::canonical::is_hex64;
use crate::error::ConfigError;

/// The `[policy]` envelope section of a signed export: standing bounds that
/// rarely change and are approved once per rotation, then enforced on every
/// request by the trusted gateway (ADR 0022).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySection {
    pub workspace_id: String,
    pub destination_id: String,
    /// Bound buckets. An empty list denies every bucket.
    #[serde(default)]
    pub buckets: Vec<String>,
    /// Monotonic envelope version per workspace; must be >= 1.
    pub envelope_version: u64,
    /// Inclusive validity start, unix seconds.
    pub not_before: u64,
    /// Exclusive validity end, unix seconds.
    pub expires_at: u64,
    pub limits: PolicyLimits,
    /// Allowed key prefixes. An empty list denies every key.
    #[serde(default)]
    pub routes: Vec<PolicyRoute>,
    /// Allowed-filter lockfile. An empty list permits no component; only
    /// `explicit_passthrough` chains can run.
    #[serde(default)]
    pub filters: Vec<FilterLockEntry>,
}

/// Resource bounds pushed into the Wasm session and object path. Effective
/// limits are `min(policy, operator hard caps)` at the request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLimits {
    pub record_max_bytes: u64,
    pub object_max_bytes: u64,
    pub memory_bytes: u64,
    pub fuel: u64,
    pub deadline_ms: u64,
}

/// One allowed key prefix and its failure behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRoute {
    pub prefix: String,
    pub fail: FailBehavior,
}

/// v1 supports only reject-on-failure routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailBehavior {
    Reject,
}

/// One allowed component in the envelope lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterLockEntry {
    /// 64 lowercase hex characters: the component byte digest.
    pub sha256: String,
    /// When present the step configuration is pinned to this digest; when
    /// absent any configuration for the component hash is allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
}

impl PolicySection {
    /// Fail-closed structural validation of the envelope bounds.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.workspace_id.trim().is_empty() {
            return Err(ConfigError::invalid(
                "policy.workspace_id must not be empty",
            ));
        }
        if self.destination_id.trim().is_empty() {
            return Err(ConfigError::invalid(
                "policy.destination_id must not be empty",
            ));
        }
        if self.envelope_version < 1 {
            return Err(ConfigError::invalid("policy.envelope_version must be >= 1"));
        }
        if self.not_before >= self.expires_at {
            return Err(ConfigError::invalid(
                "policy.not_before must be strictly before policy.expires_at",
            ));
        }
        self.limits.validate()?;

        let mut buckets = std::collections::BTreeSet::new();
        for bucket in &self.buckets {
            if bucket.trim().is_empty() {
                return Err(ConfigError::invalid(
                    "policy.buckets must not contain empty names",
                ));
            }
            if !buckets.insert(bucket) {
                return Err(ConfigError::invalid(format!(
                    "policy.buckets contains duplicate {bucket:?}"
                )));
            }
        }

        let mut prefixes = std::collections::BTreeSet::new();
        for route in &self.routes {
            if !prefixes.insert(&route.prefix) {
                return Err(ConfigError::invalid(format!(
                    "policy.routes contains duplicate prefix {:?}",
                    route.prefix
                )));
            }
        }

        let mut hashes = std::collections::BTreeSet::new();
        for entry in &self.filters {
            if !is_hex64(&entry.sha256) {
                return Err(ConfigError::invalid(format!(
                    "policy.filters sha256 {:?} must be 64 lowercase hex characters",
                    entry.sha256
                )));
            }
            if let Some(config_hash) = &entry.config_hash
                && !is_hex64(config_hash)
            {
                return Err(ConfigError::invalid(format!(
                    "policy.filters config_hash {config_hash:?} must be 64 lowercase hex characters"
                )));
            }
            if !hashes.insert(&entry.sha256) {
                return Err(ConfigError::invalid(format!(
                    "policy.filters contains duplicate sha256 {}",
                    entry.sha256
                )));
            }
        }
        Ok(())
    }

    /// Time validity at `now` with `skew` seconds of bounded clock skew in
    /// either direction. `not_before` is inclusive, `expires_at` exclusive;
    /// the skew value is a policy choice, not a cryptographic necessity.
    pub fn valid_at(&self, now: u64, skew: u64) -> Result<(), ConfigError> {
        if now.saturating_add(skew) < self.not_before {
            return Err(ConfigError::signature(format!(
                "policy envelope is not valid before {} (now {now})",
                self.not_before
            )));
        }
        if now >= self.expires_at.saturating_add(skew) {
            return Err(ConfigError::signature(format!(
                "policy envelope expired at {} (now {now})",
                self.expires_at
            )));
        }
        Ok(())
    }
}

impl PolicyLimits {
    fn validate(&self) -> Result<(), ConfigError> {
        for (name, value) in [
            ("record_max_bytes", self.record_max_bytes),
            ("object_max_bytes", self.object_max_bytes),
            ("memory_bytes", self.memory_bytes),
            ("fuel", self.fuel),
            ("deadline_ms", self.deadline_ms),
        ] {
            if value == 0 {
                return Err(ConfigError::invalid(format!(
                    "policy.limits.{name} must be greater than 0"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> PolicySection {
        PolicySection {
            workspace_id: "ws-1".to_string(),
            destination_id: "dest-1".to_string(),
            buckets: vec!["tenant-a".to_string()],
            envelope_version: 1,
            not_before: 100,
            expires_at: 200,
            limits: PolicyLimits {
                record_max_bytes: 1024,
                object_max_bytes: 4096,
                memory_bytes: 67_108_864,
                fuel: 10_000_000,
                deadline_ms: 30_000,
            },
            routes: vec![PolicyRoute {
                prefix: "data/".to_string(),
                fail: FailBehavior::Reject,
            }],
            filters: vec![FilterLockEntry {
                sha256: "a".repeat(64),
                config_hash: None,
            }],
        }
    }

    #[test]
    fn minimal_envelope_validates() {
        minimal().validate().unwrap();
    }

    #[test]
    fn empty_workspace_is_rejected() {
        let mut policy = minimal();
        policy.workspace_id = "  ".to_string();
        assert!(
            policy
                .validate()
                .unwrap_err()
                .to_string()
                .contains("workspace_id")
        );
    }

    #[test]
    fn empty_destination_is_rejected() {
        let mut policy = minimal();
        policy.destination_id = String::new();
        assert!(
            policy
                .validate()
                .unwrap_err()
                .to_string()
                .contains("destination_id")
        );
    }

    #[test]
    fn envelope_version_must_be_at_least_one() {
        let mut policy = minimal();
        policy.envelope_version = 0;
        assert!(
            policy
                .validate()
                .unwrap_err()
                .to_string()
                .contains("envelope_version")
        );
    }

    #[test]
    fn not_before_must_precede_expiry() {
        let mut policy = minimal();
        policy.not_before = 200;
        policy.expires_at = 200;
        assert!(policy.validate().is_err());
        policy.not_before = 201;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn zero_limit_is_rejected() {
        let mut policy = minimal();
        policy.limits.fuel = 0;
        let error = policy.validate().unwrap_err();
        assert!(error.to_string().contains("fuel"));
    }

    #[test]
    fn duplicate_bucket_is_rejected() {
        let mut policy = minimal();
        policy.buckets.push("tenant-a".to_string());
        assert!(
            policy
                .validate()
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn empty_bucket_name_is_rejected() {
        let mut policy = minimal();
        policy.buckets.push(" ".to_string());
        assert!(policy.validate().is_err());
    }

    #[test]
    fn duplicate_route_prefix_is_rejected() {
        let mut policy = minimal();
        policy.routes.push(PolicyRoute {
            prefix: "data/".to_string(),
            fail: FailBehavior::Reject,
        });
        assert!(policy.validate().is_err());
    }

    #[test]
    fn short_filter_hash_is_rejected() {
        let mut policy = minimal();
        policy.filters[0].sha256 = "abc".to_string();
        assert!(
            policy
                .validate()
                .unwrap_err()
                .to_string()
                .contains("sha256")
        );
    }

    #[test]
    fn uppercase_filter_hash_is_rejected() {
        let mut policy = minimal();
        policy.filters[0].sha256 = "A".repeat(64);
        assert!(policy.validate().is_err());
    }

    #[test]
    fn bad_config_hash_is_rejected() {
        let mut policy = minimal();
        policy.filters[0].config_hash = Some("nope".to_string());
        assert!(policy.validate().is_err());
    }

    #[test]
    fn duplicate_filter_hash_is_rejected_even_with_different_config_pinning() {
        let mut policy = minimal();
        policy.filters.push(FilterLockEntry {
            sha256: "a".repeat(64),
            config_hash: Some("b".repeat(64)),
        });
        assert!(
            policy
                .validate()
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn empty_buckets_routes_and_filters_are_valid_deny_all_lists() {
        let mut policy = minimal();
        policy.buckets.clear();
        policy.routes.clear();
        policy.filters.clear();
        policy.validate().unwrap();
    }

    #[test]
    fn validity_window_boundaries() {
        let policy = minimal();
        policy.valid_at(100, 0).unwrap();
        policy.valid_at(199, 0).unwrap();
        assert!(policy.valid_at(200, 0).is_err());
        assert!(policy.valid_at(99, 0).is_err());
        // bounded skew moves both edges
        policy.valid_at(99, 1).unwrap();
        policy.valid_at(200, 1).unwrap();
        assert!(policy.valid_at(98, 1).is_err());
        assert!(policy.valid_at(201, 1).is_err());
    }

    #[test]
    fn deny_unknown_fields_on_toml_round_trip() {
        let toml_text = r#"
workspace_id = "ws-1"
destination_id = "dest-1"
buckets = ["tenant-a"]
envelope_version = 1
not_before = 100
expires_at = 200
unknown_key = true

[policy.limits]
record_max_bytes = 1024
object_max_bytes = 4096
memory_bytes = 67108864
fuel = 10000000
deadline_ms = 30000
"#;
        let error = toml::from_str::<PolicySection>(toml_text).unwrap_err();
        assert!(error.to_string().contains("unknown_key"));
    }

    #[test]
    fn fail_behavior_rejects_unknown_variants() {
        let toml_text = r#"
prefix = "data/"
fail = "ignore"
"#;
        assert!(toml::from_str::<PolicyRoute>(toml_text).is_err());
        let ok = toml::from_str::<PolicyRoute>(
            r#"
prefix = "data/"
fail = "reject"
"#,
        )
        .unwrap();
        assert_eq!(ok.fail, FailBehavior::Reject);
    }

    #[test]
    fn policy_section_toml_round_trip_preserves_bytes() {
        let policy = minimal();
        let rendered = toml::to_string_pretty(&policy).unwrap();
        let reparsed: PolicySection = toml::from_str(&rendered).unwrap();
        assert_eq!(reparsed, policy);
        // and through the canonical encoder
        assert_eq!(
            crate::canonical::canonical_cbor(&reparsed).unwrap(),
            crate::canonical::canonical_cbor(&policy).unwrap()
        );
    }
}
