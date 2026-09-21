//! Extracted from `managed.rs`; re-exported from `crate::managed`.

use super::*;

pub(crate) fn authority_from_model(
    model: managed_object_authority::Model,
) -> Result<ObjectAuthority, ManagedError> {
    Ok(ObjectAuthority {
        logical: LogicalObjectKey {
            tenant_id: model.tenant_id,
            bucket: model.bucket,
            key: model.logical_key,
        },
        generation: model.generation,
        digest: model.digest,
        size: u64::try_from(model.size_bytes)
            .map_err(|_| ManagedError::Corrupt("negative authority size".to_string()))?,
        metadata: serde_json::from_value(model.metadata)
            .map_err(|error| ManagedError::Corrupt(error.to_string()))?,
        placement_version: u32::try_from(model.placement_version)
            .map_err(|_| ManagedError::Corrupt("invalid placement version".to_string()))?,
        primary_backend_id: model.primary_backend_id,
        primary_version_id: model.primary_version_id,
        replica_backend_id: model.replica_backend_id,
        primary_status: CopyStatus::parse(&model.primary_status)?,
        replica_status: CopyStatus::parse(&model.replica_status)?,
        tombstone: model.tombstone,
        cas_version: u64::try_from(model.cas_version)
            .map_err(|_| ManagedError::Corrupt("invalid authority CAS version".to_string()))?,
        created_at_ms: model.created_at_ms,
        updated_at_ms: model.updated_at_ms,
    })
}

pub(crate) fn u64_from_i64(value: i64, field: &str) -> Result<u64, ManagedError> {
    u64::try_from(value).map_err(|_| ManagedError::Corrupt(format!("invalid {field}")))
}

pub(crate) fn i64_from_u64(value: u64, field: &str) -> Result<i64, ManagedError> {
    i64::try_from(value).map_err(|_| ManagedError::Corrupt(format!("{field} exceeds BIGINT")))
}

pub(crate) fn persistence(error: impl std::fmt::Display) -> ManagedError {
    ManagedError::Persistence(error.to_string())
}
