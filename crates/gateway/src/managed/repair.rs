//! Extracted from `managed.rs`; re-exported from `crate::managed`.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairKind {
    Replica,
    Placement,
    DeleteGeneration,
}

impl RepairKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Replica => "REPLICA",
            Self::Placement => "PLACEMENT",
            Self::DeleteGeneration => "DELETE_GENERATION",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "REPLICA" => Ok(Self::Replica),
            "PLACEMENT" => Ok(Self::Placement),
            "DELETE_GENERATION" => Ok(Self::DeleteGeneration),
            _ => Err(ManagedError::Corrupt(format!(
                "unknown managed repair kind {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairTargetRole {
    Primary,
    Replica,
    Cleanup,
}

impl RepairTargetRole {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "PRIMARY",
            Self::Replica => "REPLICA",
            Self::Cleanup => "CLEANUP",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "PRIMARY" => Ok(Self::Primary),
            "REPLICA" => Ok(Self::Replica),
            "CLEANUP" => Ok(Self::Cleanup),
            _ => Err(ManagedError::Corrupt(format!(
                "unknown managed repair target role {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairRecord {
    /// An opaque claim capability while leased; otherwise equal to `repair_id`.
    pub id: Uuid,
    pub repair_id: Uuid,
    pub kind: RepairKind,
    pub logical: LogicalObjectKey,
    pub namespace_epoch: u64,
    pub authority_cas_version: u64,
    pub generation: Uuid,
    pub digest: String,
    pub size: u64,
    pub metadata: BTreeMap<String, String>,
    pub physical_key: String,
    pub source_backend_id: Option<String>,
    pub target_backend_id: String,
    pub target_role: RepairTargetRole,
    pub placement_version: u32,
    pub placement_primary_backend_id: Option<String>,
    pub placement_replica_backend_id: Option<String>,
    pub attempts: u32,
    pub lease_owner: Option<String>,
    pub lease_token: Option<Uuid>,
    pub lease_expires_at_ms: Option<i64>,
    pub not_before_ms: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl RepairRecord {
    pub fn copy(
        kind: RepairKind,
        authority: &ObjectAuthority,
        source_backend_id: Option<String>,
        target_backend_id: String,
        target_role: RepairTargetRole,
        placement_version: u32,
    ) -> Self {
        let now = crate::transaction::unix_time_ms();
        let repair_id = Uuid::now_v7();
        Self {
            id: repair_id,
            repair_id,
            kind,
            logical: authority.logical.clone(),
            namespace_epoch: 0,
            authority_cas_version: authority.cas_version,
            generation: authority.generation,
            digest: authority.digest.clone(),
            size: authority.size,
            metadata: authority.metadata.clone(),
            physical_key: generation_physical_key(&authority.logical, authority.generation),
            source_backend_id,
            target_backend_id,
            target_role,
            placement_version,
            placement_primary_backend_id: None,
            placement_replica_backend_id: None,
            attempts: 0,
            lease_owner: None,
            lease_token: None,
            lease_expires_at_ms: None,
            not_before_ms: 0,
            created_at_ms: now,
            updated_at_ms: now,
        }
    }

    pub fn placement(
        authority: &ObjectAuthority,
        source_backend_id: Option<String>,
        target_backend_id: String,
        target_role: RepairTargetRole,
        placement: &Placement,
    ) -> Self {
        let mut repair = Self::copy(
            RepairKind::Placement,
            authority,
            source_backend_id,
            target_backend_id,
            target_role,
            placement.version,
        );
        repair.placement_primary_backend_id = Some(placement.primary_backend_id.clone());
        repair.placement_replica_backend_id = placement.replica_backend_id.clone();
        repair
    }
}

/// Counts of repair records grouped by their lifecycle state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RepairStateCounts {
    pub pending: u64,
    pub leased: u64,
    pub dead: u64,
}

pub(crate) fn cleanup_repairs(authority: &ObjectAuthority) -> Vec<RepairRecord> {
    let mut repairs = vec![RepairRecord::copy(
        RepairKind::DeleteGeneration,
        authority,
        None,
        authority.primary_backend_id.clone(),
        RepairTargetRole::Cleanup,
        authority.placement_version,
    )];
    if let Some(replica) = &authority.replica_backend_id {
        repairs.push(RepairRecord::copy(
            RepairKind::DeleteGeneration,
            authority,
            None,
            replica.clone(),
            RepairTargetRole::Cleanup,
            authority.placement_version,
        ));
    }
    repairs
}

pub(crate) fn stale_repair_cleanup(repair: &RepairRecord) -> RepairRecord {
    let now = crate::transaction::unix_time_ms();
    let repair_id = Uuid::now_v7();
    RepairRecord {
        id: repair_id,
        repair_id,
        kind: RepairKind::DeleteGeneration,
        logical: repair.logical.clone(),
        namespace_epoch: repair.namespace_epoch,
        authority_cas_version: repair.authority_cas_version,
        generation: repair.generation,
        digest: repair.digest.clone(),
        size: repair.size,
        metadata: repair.metadata.clone(),
        physical_key: repair.physical_key.clone(),
        source_backend_id: None,
        target_backend_id: repair.target_backend_id.clone(),
        target_role: RepairTargetRole::Cleanup,
        placement_version: repair.placement_version,
        placement_primary_backend_id: None,
        placement_replica_backend_id: None,
        attempts: 0,
        lease_owner: None,
        lease_token: None,
        lease_expires_at_ms: None,
        not_before_ms: 0,
        created_at_ms: now,
        updated_at_ms: now,
    }
}

pub(crate) fn publication_repairs(authority: &ObjectAuthority) -> Vec<RepairRecord> {
    match (&authority.replica_backend_id, authority.replica_status) {
        (Some(replica), CopyStatus::RepairPending) => vec![RepairRecord::copy(
            RepairKind::Replica,
            authority,
            Some(authority.primary_backend_id.clone()),
            replica.clone(),
            RepairTargetRole::Replica,
            authority.placement_version,
        )],
        _ => Vec::new(),
    }
}

pub(crate) fn placement_cleanup_repairs(
    previous: &ObjectAuthority,
    authority: &ObjectAuthority,
) -> Vec<RepairRecord> {
    let mut old_locations = vec![Some(previous.primary_backend_id.clone())];
    old_locations.push(previous.replica_backend_id.clone());
    old_locations
        .into_iter()
        .flatten()
        .filter(|backend| {
            backend != &authority.primary_backend_id
                && authority.replica_backend_id.as_deref() != Some(backend)
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .map(|backend| {
            RepairRecord::copy(
                RepairKind::DeleteGeneration,
                authority,
                None,
                backend,
                RepairTargetRole::Cleanup,
                authority.placement_version,
            )
        })
        .collect()
}

pub(crate) fn apply_repair_to_authority(
    authority: &mut ObjectAuthority,
    repair: &RepairRecord,
) -> Result<bool, ManagedError> {
    if repair.kind == RepairKind::Placement {
        let Some(primary) = repair.placement_primary_backend_id.as_deref() else {
            return Err(ManagedError::Corrupt(
                "placement repair has no requested primary backend".to_string(),
            ));
        };
        if repair.placement_version < authority.placement_version {
            return Ok(false);
        }
        match repair.target_role {
            RepairTargetRole::Primary if repair.target_backend_id == primary => {
                authority.primary_backend_id = primary.to_string();
                authority.primary_status = CopyStatus::Ready;
                if repair.placement_replica_backend_id.is_none() {
                    authority.replica_backend_id = None;
                    authority.replica_status = CopyStatus::Absent;
                }
            }
            RepairTargetRole::Replica
                if repair.placement_replica_backend_id.as_deref()
                    == Some(repair.target_backend_id.as_str()) =>
            {
                authority.replica_backend_id = Some(repair.target_backend_id.clone());
                authority.replica_status = CopyStatus::Ready;
            }
            _ => {
                return Err(ManagedError::Corrupt(
                    "placement repair target does not match requested placement".to_string(),
                ));
            }
        }
        if authority.primary_backend_id == primary
            && authority.primary_status == CopyStatus::Ready
            && match repair.placement_replica_backend_id.as_deref() {
                Some(replica) => {
                    authority.replica_backend_id.as_deref() == Some(replica)
                        && authority.replica_status == CopyStatus::Ready
                }
                None => {
                    authority.replica_backend_id.is_none()
                        && authority.replica_status == CopyStatus::Absent
                }
            }
        {
            authority.placement_version = repair.placement_version;
        }
        return Ok(true);
    }

    match repair.target_role {
        RepairTargetRole::Primary => {
            authority.primary_backend_id = repair.target_backend_id.clone();
            authority.primary_status = CopyStatus::Ready;
        }
        RepairTargetRole::Replica => {
            authority.replica_backend_id = Some(repair.target_backend_id.clone());
            authority.replica_status = CopyStatus::Ready;
        }
        RepairTargetRole::Cleanup => return Ok(false),
    }
    Ok(true)
}

pub(crate) fn repair_target_is_authoritative(
    authority: &ObjectAuthority,
    repair: &RepairRecord,
) -> bool {
    !authority.tombstone
        && authority.generation == repair.generation
        && (authority.primary_backend_id == repair.target_backend_id
            || authority.replica_backend_id.as_deref() == Some(repair.target_backend_id.as_str()))
}

pub(crate) fn repair_from_model(
    model: managed_object_repair::Model,
) -> Result<RepairRecord, ManagedError> {
    Ok(RepairRecord {
        id: model.lease_token.unwrap_or(model.id),
        repair_id: model.id,
        kind: RepairKind::parse(&model.kind)?,
        logical: LogicalObjectKey {
            tenant_id: model.tenant_id,
            bucket: model.bucket,
            key: model.logical_key,
        },
        namespace_epoch: u64::try_from(model.namespace_epoch)
            .map_err(|_| ManagedError::Corrupt("invalid repair namespace epoch".to_string()))?,
        authority_cas_version: u64::try_from(model.authority_cas_version)
            .map_err(|_| ManagedError::Corrupt("invalid repair authority CAS".to_string()))?,
        generation: model.generation,
        digest: model.digest,
        size: u64::try_from(model.size_bytes)
            .map_err(|_| ManagedError::Corrupt("negative repair size".to_string()))?,
        metadata: serde_json::from_value(model.metadata)
            .map_err(|error| ManagedError::Corrupt(error.to_string()))?,
        physical_key: model.physical_key,
        source_backend_id: model.source_backend_id,
        target_backend_id: model.target_backend_id,
        target_role: RepairTargetRole::parse(&model.target_role)?,
        placement_version: u32::try_from(model.placement_version)
            .map_err(|_| ManagedError::Corrupt("invalid repair placement version".to_string()))?,
        placement_primary_backend_id: model.placement_primary_backend_id,
        placement_replica_backend_id: model.placement_replica_backend_id,
        attempts: u32::try_from(model.attempts)
            .map_err(|_| ManagedError::Corrupt("negative repair attempts".to_string()))?,
        lease_owner: model.lease_owner,
        lease_token: model.lease_token,
        lease_expires_at_ms: model.lease_expires_at_ms,
        not_before_ms: model.not_before_ms,
        created_at_ms: model.created_at_ms,
        updated_at_ms: model.updated_at_ms,
    })
}

pub(crate) fn repair_active(
    repair: RepairRecord,
) -> Result<managed_object_repair::ActiveModel, ManagedError> {
    Ok(managed_object_repair::ActiveModel {
        id: Set(repair.repair_id),
        kind: Set(repair.kind.as_str().to_string()),
        state: Set("PENDING".to_string()),
        tenant_id: Set(repair.logical.tenant_id),
        namespace_epoch: Set(i64::try_from(repair.namespace_epoch).map_err(|_| {
            ManagedError::Corrupt("repair namespace epoch exceeds BIGINT".to_string())
        })?),
        authority_cas_version: Set(i64::try_from(repair.authority_cas_version).map_err(|_| {
            ManagedError::Corrupt("repair authority CAS exceeds BIGINT".to_string())
        })?),
        bucket: Set(repair.logical.bucket),
        logical_key: Set(repair.logical.key),
        generation: Set(repair.generation),
        digest: Set(repair.digest),
        size_bytes: Set(i64::try_from(repair.size)
            .map_err(|_| ManagedError::Corrupt("repair size exceeds BIGINT".to_string()))?),
        metadata: Set(serde_json::to_value(repair.metadata)
            .map_err(|error| ManagedError::Corrupt(error.to_string()))?),
        physical_key: Set(repair.physical_key),
        source_backend_id: Set(repair.source_backend_id),
        target_backend_id: Set(repair.target_backend_id),
        target_role: Set(repair.target_role.as_str().to_string()),
        placement_version: Set(i64::from(repair.placement_version)),
        placement_primary_backend_id: Set(repair.placement_primary_backend_id),
        placement_replica_backend_id: Set(repair.placement_replica_backend_id),
        attempts: Set(i32::try_from(repair.attempts)
            .map_err(|_| ManagedError::Corrupt("repair attempts exceed INTEGER".to_string()))?),
        lease_owner: Set(repair.lease_owner),
        lease_token: Set(None),
        lease_expires_at_ms: Set(repair.lease_expires_at_ms),
        not_before_ms: Set(repair.not_before_ms),
        last_error: Set(None),
        created_at_ms: Set(repair.created_at_ms),
        updated_at_ms: Set(repair.updated_at_ms),
    })
}
