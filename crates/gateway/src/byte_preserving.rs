//! Operator-declared byte-preserving S3 storage scopes (ADR 0036).
//!
//! An external table catalog (for example an Iceberg REST catalog such as
//! Apache Polaris) owns its own commit lifecycle. It writes objects that
//! Maskura's per-object format adapters cannot transform: table metadata JSON,
//! manifests, and data files that cross-reference each other. The catalog
//! commit is the new document; Maskura must store the individual objects
//! byte-for-byte and serve them back unchanged.
//!
//! This module holds the operator declaration for those buckets and key
//! prefixes. The scope is resolved from:
//!
//! - the operator setting ([`BytePreservingScopes::parse`], only reachable
//!   from server configuration), and
//! - the authenticated request's bucket, which the control-plane grant still
//!   has to admit;
//!
//! never from a key suffix, HTTP header, query parameter, or body shape. A
//! covered request bypasses table classification and every format adapter and
//! resolves to an explicit passthrough pipeline (empty chain), so the existing
//! byte-preserving primitives store and serve the bytes unchanged.
//!
//! Data in a byte-preserving scope is deliberately **unfiltered**: no Wasm
//! plugin runs on it. The operator declares the bucket as catalog storage, and
//! the docs state that consequence plainly.

use crate::pipeline::{
    PipelineDirection, PipelineLocator, PipelineResolution, resolution_fingerprint,
};
use crate::plugin_registry::PipelineLimits;

/// Revision identity of the synthetic byte-preserving resolution. Usage
/// authorization binds this value, so executing evidence names the assignment
/// instead of a catalog chain that never ran.
pub const BYTE_PRESERVING_REVISION: &str = "byte-preserving-scope-v1";

/// One declared `bucket` or `bucket/prefix` scope.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ScopeEntry {
    bucket: String,
    /// Normalized key prefix: empty for the whole bucket, otherwise ending
    /// with `/` so matching is segment-aligned.
    prefix: String,
}

impl ScopeEntry {
    fn parse(raw: &str) -> Result<Self, ScopeConfigError> {
        let entry = raw.trim();
        if entry.is_empty() {
            return Err(ScopeConfigError::Empty);
        }
        let (bucket, prefix) = match entry.split_once('/') {
            Some((bucket, prefix)) => (bucket, prefix),
            None => (entry, ""),
        };
        if bucket.is_empty() || !valid_bucket(bucket) {
            return Err(ScopeConfigError::Bucket(entry.to_string()));
        }
        let prefix = prefix.trim_end_matches('/');
        if prefix.is_empty() {
            return Ok(Self {
                bucket: bucket.to_string(),
                prefix: String::new(),
            });
        }
        if !valid_prefix(prefix) {
            return Err(ScopeConfigError::Prefix(entry.to_string()));
        }
        Ok(Self {
            bucket: bucket.to_string(),
            prefix: format!("{prefix}/"),
        })
    }

    fn covers(&self, bucket: &str, key: &str) -> bool {
        self.bucket == bucket
            && (self.prefix.is_empty()
                || key.starts_with(&self.prefix)
                || key == self.prefix.trim_end_matches('/'))
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.bucket == other.bucket
            && (self.prefix.is_empty()
                || other.prefix.is_empty()
                || self.prefix.starts_with(&other.prefix)
                || other.prefix.starts_with(&self.prefix))
    }
}

fn valid_bucket(bucket: &str) -> bool {
    bucket != "."
        && bucket != ".."
        && bucket
            .chars()
            .all(|c| !c.is_whitespace() && !c.is_control() && c != '/')
}

fn valid_prefix(prefix: &str) -> bool {
    prefix
        .split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        && prefix
            .chars()
            .all(|c| !c.is_whitespace() && !c.is_control())
}

/// Invalid operator configuration. Startup fails closed rather than guessing
/// which of two overlapping declarations owns a key.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScopeConfigError {
    #[error("byte-preserving scope list contains an empty entry")]
    Empty,
    #[error("byte-preserving scope entry {0:?} has an invalid bucket name")]
    Bucket(String),
    #[error("byte-preserving scope entry {0:?} has an invalid key prefix")]
    Prefix(String),
    #[error("byte-preserving scope entries {first:?} and {second:?} overlap")]
    Overlap { first: String, second: String },
}

/// Validated set of byte-preserving scopes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BytePreservingScopes {
    entries: Vec<ScopeEntry>,
}

impl BytePreservingScopes {
    /// Parses the comma-separated operator setting. `None` and an empty value
    /// both mean "no scope", which keeps every existing behavior unchanged.
    pub fn parse(raw: Option<&str>) -> Result<Self, ScopeConfigError> {
        let Some(raw) = raw else {
            return Ok(Self::default());
        };
        let mut scopes = Self::default();
        for raw_entry in raw.split(',') {
            if raw_entry.trim().is_empty() {
                if raw.trim().is_empty() {
                    continue;
                }
                return Err(ScopeConfigError::Empty);
            }
            let entry = ScopeEntry::parse(raw_entry)?;
            if let Some(existing) = scopes
                .entries
                .iter()
                .find(|existing| existing.overlaps(&entry))
            {
                return Err(ScopeConfigError::Overlap {
                    first: format_entry(existing),
                    second: format_entry(&entry),
                });
            }
            scopes.entries.push(entry);
        }
        Ok(scopes)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether operator configuration covers this bucket/key. Authorization is
    /// separate: the caller has already authenticated and the control plane
    /// still has to grant the operation.
    pub fn covers(&self, bucket: &str, key: &str) -> bool {
        self.entries.iter().any(|entry| entry.covers(bucket, key))
    }

    /// Whether any declared entry names this bucket. Used at startup to reject
    /// an ambiguous overlap with bucket-scoped transforms.
    pub fn conflicts_with_bucket(&self, bucket: &str) -> bool {
        self.entries.iter().any(|entry| entry.bucket == bucket)
    }
}

fn format_entry(entry: &ScopeEntry) -> String {
    if entry.prefix.is_empty() {
        entry.bucket.clone()
    } else {
        format!("{}/{}", entry.bucket, entry.prefix.trim_end_matches('/'))
    }
}

/// The synthetic resolution for a covered request: an empty chain with an
/// explicit passthrough flag, which the existing code already treats as
/// "store/serve the exact bytes".
pub fn byte_preserving_resolution(
    direction: PipelineDirection,
    limits: PipelineLimits,
) -> PipelineResolution {
    let steps = Vec::new();
    let fingerprint = resolution_fingerprint(direction, &steps, true, limits);
    PipelineResolution {
        locator: PipelineLocator {
            revision: BYTE_PRESERVING_REVISION.to_string(),
            fingerprint,
            assignment_id: None,
        },
        steps,
        policy_generation: None,
        explicit_passthrough: true,
        limits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_or_empty_setting_declares_nothing() {
        assert!(BytePreservingScopes::parse(None).unwrap().is_empty());
        assert!(BytePreservingScopes::parse(Some("")).unwrap().is_empty());
        assert!(BytePreservingScopes::parse(Some("   ")).unwrap().is_empty());
    }

    #[test]
    fn a_trailing_slash_is_normalized() {
        // `bucket/` is the whole bucket; a prefix keeps its segment boundary.
        let scopes = BytePreservingScopes::parse(Some("warehouse/, catalog/logs/")).unwrap();
        assert!(scopes.covers("warehouse", "any/key"));
        assert!(scopes.covers("catalog", "logs/00000.metadata.json"));
        assert!(!scopes.covers("catalog", "logs-2/00000.metadata.json"));
    }

    #[test]
    fn whole_bucket_and_prefix_entries_are_parsed() {
        let scopes =
            BytePreservingScopes::parse(Some("warehouse, catalogs/polaris, catalogs/trailing/"))
                .expect("valid configuration");
        assert_eq!(scopes.entries.len(), 3);
        assert_eq!(scopes.entries[0].prefix, "");
        assert_eq!(scopes.entries[1].prefix, "polaris/");
        assert_eq!(scopes.entries[2].prefix, "trailing/");
    }

    #[test]
    fn a_prefix_matches_only_at_a_segment_boundary() {
        let scopes = BytePreservingScopes::parse(Some("warehouse/catalog")).unwrap();
        assert!(scopes.covers("warehouse", "catalog/metadata/00000-x.metadata.json"));
        assert!(scopes.covers("warehouse", "catalog"));
        assert!(!scopes.covers("warehouse", "catalog-2/metadata/00000-x.metadata.json"));
        assert!(!scopes.covers("warehouse", "other/catalog/x"));
        assert!(!scopes.covers("other-bucket", "catalog/x"));
    }

    #[test]
    fn a_whole_bucket_covers_every_key() {
        let scopes = BytePreservingScopes::parse(Some("warehouse")).unwrap();
        assert!(scopes.covers("warehouse", "t/metadata/00000-x.metadata.json"));
        assert!(scopes.covers("warehouse", ""));
        assert!(!scopes.covers("warehouse-2", "t/metadata/00000-x.metadata.json"));
    }

    #[test]
    fn duplicate_and_overlapping_entries_fail_closed() {
        assert!(matches!(
            BytePreservingScopes::parse(Some("warehouse,warehouse")),
            Err(ScopeConfigError::Overlap { .. })
        ));
        assert!(matches!(
            BytePreservingScopes::parse(Some("warehouse,warehouse/logs")),
            Err(ScopeConfigError::Overlap { .. })
        ));
        assert!(matches!(
            BytePreservingScopes::parse(Some("warehouse/logs,warehouse/logs/raw")),
            Err(ScopeConfigError::Overlap { .. })
        ));
        // Sibling prefixes are distinct assignments.
        assert!(BytePreservingScopes::parse(Some("warehouse/logs,warehouse/data")).is_ok());
    }

    #[test]
    fn malformed_entries_are_rejected() {
        for raw in [
            "warehouse//logs",
            "warehouse/./logs",
            "warehouse/../logs",
            "ware house",
            "/logs",
            "warehouse/ /logs",
            "warehouse,,",
        ] {
            assert!(
                BytePreservingScopes::parse(Some(raw)).is_err(),
                "{raw:?} must be rejected"
            );
        }
    }

    #[test]
    fn the_synthetic_resolution_is_a_verified_passthrough() {
        let limits = PipelineLimits::default();
        for direction in [PipelineDirection::Write, PipelineDirection::Read] {
            let resolution = byte_preserving_resolution(direction, limits);
            assert!(resolution.explicit_passthrough);
            assert!(resolution.steps.is_empty());
            assert_eq!(resolution.locator.revision, BYTE_PRESERVING_REVISION);
            resolution
                .verify_fingerprint(direction)
                .expect("the synthetic resolution carries its own canonical fingerprint");
        }
        // The direction is part of the fingerprint: a read resolution cannot
        // be replayed as a write resolution.
        let write = byte_preserving_resolution(PipelineDirection::Write, limits);
        assert!(write.verify_fingerprint(PipelineDirection::Read).is_err());
    }
}
