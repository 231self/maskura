//! Extracted from `managed.rs`; re-exported from `crate::managed`.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Placement {
    pub version: u32,
    pub primary_backend_id: String,
    pub replica_backend_id: Option<String>,
}

/// Durable facts that define a placement policy version: the backends, their
/// weights, and their capacities, plus when the policy was activated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedPlacementPolicy {
    pub version: u32,
    pub fingerprint: String,
    pub backend_facts: Vec<ManagedPlacementBackendFact>,
    pub activated_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
pub struct ManagedPlacementBackendFact {
    pub backend_id: String,
    pub placement_weight: u64,
    pub placement_capacity_units: u64,
}

/// Canonical fingerprint of a placement policy: the version plus every
/// backend's identity, weight, and capacity in a stable order. A policy edit
/// changes the fingerprint, so a version bump is required to admit it.
pub fn placement_policy_fingerprint(
    version: u32,
    backends: impl IntoIterator<Item = (String, u64, u64)>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"s4-placement-policy\0");
    hasher.update(version.to_be_bytes());
    let mut facts: Vec<_> = backends.into_iter().collect();
    facts.sort();
    for (backend_id, weight, capacity) in facts {
        hash_field(&mut hasher, backend_id.as_bytes());
        hash_field(&mut hasher, &weight.to_be_bytes());
        hash_field(&mut hasher, &capacity.to_be_bytes());
    }
    hex::encode(hasher.finalize())
}

pub(crate) fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

pub fn rendezvous_score(
    placement_version: u32,
    tenant_id: &str,
    object_key: &str,
    backend_id: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"s4-rendezvous\0");
    hasher.update(placement_version.to_be_bytes());
    hash_field(&mut hasher, tenant_id.as_bytes());
    hash_field(&mut hasher, object_key.as_bytes());
    hash_field(&mut hasher, backend_id.as_bytes());
    hasher.finalize().into()
}

pub fn rendezvous_placement(
    placement_version: u32,
    tenant_id: &str,
    object_key: &str,
    backend_ids: impl IntoIterator<Item = String>,
) -> Option<Placement> {
    let mut scored: Vec<_> = backend_ids
        .into_iter()
        .map(|backend_id| {
            (
                rendezvous_score(placement_version, tenant_id, object_key, &backend_id),
                backend_id,
            )
        })
        .collect();
    scored.sort_by(|(left_score, left_id), (right_score, right_id)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_id.cmp(right_id))
    });
    scored.dedup_by(|(_, left), (_, right)| left == right);
    let primary_backend_id = scored.first()?.1.clone();
    let replica_backend_id = scored.get(1).map(|(_, id)| id.clone());
    Some(Placement {
        version: placement_version,
        primary_backend_id,
        replica_backend_id,
    })
}

/// Select a primary and distinct replica using weighted rendezvous hashing.
/// The placement version is part of the SHA-256 domain, so policy changes must
/// be accompanied by a version bump before they affect durable placement.
pub fn weighted_rendezvous_placement(
    placement_version: u32,
    tenant_id: &str,
    object_key: &str,
    backend_weights: impl IntoIterator<Item = (String, u64)>,
) -> Option<Placement> {
    let mut scored: Vec<_> = backend_weights
        .into_iter()
        .filter(|(_, weight)| *weight > 0)
        .map(|(backend_id, weight)| {
            let score = rendezvous_score(placement_version, tenant_id, object_key, &backend_id);
            let random = u64::from_be_bytes(score[..8].try_into().expect("SHA-256 prefix"));
            // Map the hash to (0, 1]; zero must remain selectable rather than
            // producing an infinite penalty.
            let uniform = (random as f64 + 1.0) / (u64::MAX as f64 + 1.0);
            (-uniform.ln() / weight as f64, backend_id)
        })
        .collect();
    scored.sort_by(|(left_score, left_id), (right_score, right_id)| {
        left_score
            .total_cmp(right_score)
            .then_with(|| left_id.cmp(right_id))
    });
    scored.dedup_by(|(_, left), (_, right)| left == right);
    let primary_backend_id = scored.first()?.1.clone();
    let replica_backend_id = scored.get(1).map(|(_, id)| id.clone());
    Some(Placement {
        version: placement_version,
        primary_backend_id,
        replica_backend_id,
    })
}

pub fn generation_physical_key(logical: &LogicalObjectKey, generation: Uuid) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, logical.tenant_id.as_bytes());
    hash_field(&mut hasher, logical.bucket.as_bytes());
    hash_field(&mut hasher, logical.key.as_bytes());
    format!(
        "__maskura/generations/{}/{}",
        hex::encode(hasher.finalize()),
        generation
    )
}
