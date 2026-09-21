//! Extracted from `managed.rs`; re-exported from `crate::managed`.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedPublicationRecipe {
    pub version: i32,
    pub placement_version: u32,
    pub primary_backend_id: String,
    pub replica_backend_id: Option<String>,
    pub metadata: BTreeMap<String, String>,
    pub primary_status: CopyStatus,
    pub replica_status: CopyStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactPhysicalCommit {
    pub selected_version_id: Option<String>,
    pub superseded_version_ids: Vec<String>,
    pub version_history_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedRecoveryClaim {
    pub operation: ManagedLogicalOperation,
    pub owner: String,
    pub token: Uuid,
    pub expires_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalAbortProof {
    /// No physical child was admitted and no provider mutation could start.
    NoChildStarted,
    /// The durable child journal reached `PROVEN_ABORTED` after exact absence.
    ChildProvenAborted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalWriteIntent {
    pub intent_id: Uuid,
    pub tenant_id: String,
    pub backend_id: String,
    pub storage_identity: ProviderStorageIdentity,
    pub credential_epoch: u64,
    pub provider_bucket: String,
    pub physical_key: String,
    pub versioning_mode: BackendVersioningMode,
    pub versioning_capability: BackendVersioningCapability,
    pub lease_owner: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalWriteLease {
    pub intent_id: Uuid,
    pub namespace_epoch: u64,
    pub owner: String,
    pub token: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurablePhysicalWriteIntent {
    pub intent: PhysicalWriteIntent,
    pub namespace_epoch: u64,
    pub blocked_reason: Option<String>,
    pub lease_expires_at_ms: i64,
    pub lease: PhysicalWriteLease,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalVersionTarget {
    pub tenant_id: String,
    pub namespace_epoch: u64,
    pub backend_id: String,
    pub storage_identity: ProviderStorageIdentity,
    pub credential_epoch: u64,
    pub provider_bucket: String,
    pub physical_key: String,
    pub version_id: Option<String>,
    pub versioning_mode: BackendVersioningMode,
    pub versioning_capability: BackendVersioningCapability,
    pub write_operation_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderStorageIdentity {
    pub provider_kind: String,
    pub provider_instance_id: String,
    pub provider_account_id: String,
    pub canonical_endpoint: String,
    pub region: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendVersioningMode {
    Unversioned,
    Enabled,
    Suspended,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendVersioningCapability {
    Unsupported,
    Optional,
    Required,
}

impl BackendVersioningCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "UNSUPPORTED",
            Self::Optional => "OPTIONAL",
            Self::Required => "REQUIRED",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "UNSUPPORTED" => Ok(Self::Unsupported),
            "OPTIONAL" => Ok(Self::Optional),
            "REQUIRED" => Ok(Self::Required),
            value => Err(ManagedError::Corrupt(format!(
                "unknown backend versioning capability {value:?}"
            ))),
        }
    }
}

impl BackendVersioningMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unversioned => "UNVERSIONED",
            Self::Enabled => "ENABLED",
            Self::Suspended => "SUSPENDED",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "UNVERSIONED" => Ok(Self::Unversioned),
            "ENABLED" => Ok(Self::Enabled),
            "SUSPENDED" => Ok(Self::Suspended),
            "UNKNOWN" => Ok(Self::Unknown),
            value => Err(ManagedError::Corrupt(format!(
                "unknown backend versioning mode {value:?}"
            ))),
        }
    }
}

pub(crate) fn physical_allocation(
    expected_size: u64,
    exact_version_count: u64,
) -> Result<u64, ManagedError> {
    if exact_version_count == 0 {
        return Err(ManagedError::Persistence(
            "managed logical operation cannot settle before its child is ledgered".to_string(),
        ));
    }
    expected_size
        .checked_mul(exact_version_count)
        .ok_or(ManagedError::QuotaExceeded)
}

pub(crate) fn validate_exact_physical_commit(
    result: &ExactPhysicalCommit,
) -> Result<(), ManagedError> {
    if !result.version_history_complete
        || result.selected_version_id.as_deref() == Some("")
        || result.superseded_version_ids.iter().any(String::is_empty)
    {
        return Err(ManagedError::RecoveryBlocked(
            "invalid_exact_version_history",
        ));
    }
    let versions = exact_version_ids(result);
    (versions.iter().collect::<HashSet<_>>().len() == versions.len())
        .then_some(())
        .ok_or(ManagedError::RecoveryBlocked("duplicate_exact_version"))
}

pub(crate) fn validate_physical_commit_versioning(
    intent: &PhysicalWriteIntent,
    result: &ExactPhysicalCommit,
) -> Result<(), ManagedError> {
    let versionless = result.selected_version_id.is_none();
    let provably_unversioned = intent.versioning_mode == BackendVersioningMode::Unversioned
        && intent.versioning_capability == BackendVersioningCapability::Unsupported;
    if intent.versioning_mode == BackendVersioningMode::Unknown
        || versionless != provably_unversioned
        || (versionless && !result.superseded_version_ids.is_empty())
    {
        return Err(ManagedError::RecoveryBlocked(
            "physical_versioning_contract_mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn physical_intent_supports_exact_history(intent: &PhysicalWriteIntent) -> bool {
    intent.versioning_mode != BackendVersioningMode::Unknown
        && (intent.versioning_mode != BackendVersioningMode::Unversioned
            || intent.versioning_capability == BackendVersioningCapability::Unsupported)
}

pub(crate) fn validate_durable_child_commit(
    child: Option<&object_operation::Model>,
    operation: &ManagedLogicalOperation,
    result: &ExactPhysicalCommit,
) -> Result<(), ManagedError> {
    let Some(child) = child else {
        return Err(ManagedError::RecoveryBlocked("missing_child_journal"));
    };
    let superseded =
        serde_json::from_value::<Vec<String>>(child.committed_superseded_version_ids.clone())
            .map_err(|_| ManagedError::RecoveryBlocked("corrupt_child_commit"))?;
    let evidence = operation
        .evidence
        .as_ref()
        .ok_or(ManagedError::RecoveryBlocked("missing_usage_evidence"))?;
    if child.state != "COMMITTED"
        || !child.committed_version_history_complete
        || child.tenant_id.as_deref() != Some(operation.intent.logical.tenant_id.as_str())
        || child.namespace_epoch != i64::try_from(operation.intent.fence.namespace_epoch).ok()
        || child.backend_id != operation.intent.backend_id
        || child.bucket != operation.intent.provider_bucket
        || child.logical_key != operation.intent.logical.object_key()
        || child.physical_key != operation.intent.physical_key
        || child.expected_digest != evidence.expected_output_digest
        || child.expected_size != i64::try_from(evidence.expected_output_size).ok()
        || child.committed_version_id != result.selected_version_id
        || superseded.len() != result.superseded_version_ids.len()
        || superseded.iter().collect::<HashSet<_>>()
            != result.superseded_version_ids.iter().collect::<HashSet<_>>()
    {
        return Err(ManagedError::RecoveryBlocked("child_commit_mismatch"));
    }
    Ok(())
}

pub(crate) fn exact_version_ids(result: &ExactPhysicalCommit) -> Vec<String> {
    result
        .superseded_version_ids
        .iter()
        .cloned()
        .chain(std::iter::once(
            result.selected_version_id.clone().unwrap_or_default(),
        ))
        .collect()
}

pub(crate) fn expected_physical_targets(
    intent: &PhysicalWriteIntent,
    namespace_epoch: u64,
    result: &ExactPhysicalCommit,
) -> Vec<PhysicalVersionTarget> {
    exact_version_ids(result)
        .into_iter()
        .map(|version_id| PhysicalVersionTarget {
            tenant_id: intent.tenant_id.clone(),
            namespace_epoch,
            backend_id: intent.backend_id.clone(),
            storage_identity: intent.storage_identity.clone(),
            credential_epoch: intent.credential_epoch,
            provider_bucket: intent.provider_bucket.clone(),
            physical_key: intent.physical_key.clone(),
            version_id: (!version_id.is_empty()).then_some(version_id),
            versioning_mode: intent.versioning_mode,
            versioning_capability: intent.versioning_capability,
            write_operation_id: intent.intent_id,
        })
        .collect()
}

pub(crate) fn validate_recovery_authority(
    operation: &ManagedLogicalOperation,
    claim: Option<&ManagedRecoveryClaim>,
    now: i64,
) -> Result<(), ManagedError> {
    match claim {
        Some(claim)
            if claim.operation.intent.operation_id == operation.intent.operation_id
                && operation.recovery_owner.as_deref() == Some(claim.owner.as_str())
                && operation.recovery_token == Some(claim.token)
                && operation.recovery_expires_at_ms == Some(claim.expires_at_ms)
                && claim.expires_at_ms > now =>
        {
            Ok(())
        }
        None if operation.recovery_owner.is_none()
            && operation.recovery_token.is_none()
            && operation.recovery_expires_at_ms.is_none() =>
        {
            Ok(())
        }
        _ => Err(ManagedError::Conflict),
    }
}

pub(crate) fn validate_physical_intent(intent: &PhysicalWriteIntent) -> Result<(), ManagedError> {
    let identity = &intent.storage_identity;
    if intent.tenant_id.is_empty()
        || intent.backend_id.is_empty()
        || intent.provider_bucket.is_empty()
        || intent.physical_key.is_empty()
        || intent.credential_epoch == 0
        || identity.provider_kind.is_empty()
        || identity.provider_instance_id.is_empty()
        || identity.provider_account_id.is_empty()
        || identity.canonical_endpoint.is_empty()
        || identity.region.is_empty()
    {
        return Err(ManagedError::Conflict);
    }
    Ok(())
}

pub(crate) fn physical_target_from_model(
    model: managed_physical_object_version::Model,
) -> Result<PhysicalVersionTarget, ManagedError> {
    Ok(PhysicalVersionTarget {
        tenant_id: model.tenant_id,
        namespace_epoch: u64::try_from(model.epoch)
            .map_err(|_| ManagedError::Corrupt("physical version epoch is invalid".to_string()))?,
        backend_id: model.backend_id,
        storage_identity: ProviderStorageIdentity {
            provider_kind: model.provider_kind,
            provider_instance_id: model.provider_instance_id,
            provider_account_id: model.provider_account_id,
            canonical_endpoint: model.canonical_endpoint,
            region: model.provider_region,
        },
        credential_epoch: u64_from_i64(
            model.credential_epoch,
            "physical version credential epoch",
        )?,
        provider_bucket: model.provider_bucket,
        physical_key: model.physical_key,
        version_id: (!model.version_id.is_empty()).then_some(model.version_id),
        versioning_mode: BackendVersioningMode::parse(&model.versioning_mode)?,
        versioning_capability: BackendVersioningCapability::parse(&model.versioning_capability)?,
        write_operation_id: model.write_operation_id,
    })
}

pub(crate) fn durable_physical_intent_from_model(
    intent: managed_physical_write_intent::Model,
) -> Result<DurablePhysicalWriteIntent, ManagedError> {
    let namespace_epoch = u64::try_from(intent.epoch)
        .map_err(|_| ManagedError::Corrupt("physical write intent epoch is invalid".to_string()))?;
    Ok(DurablePhysicalWriteIntent {
        namespace_epoch,
        blocked_reason: intent.last_error,
        lease_expires_at_ms: intent.lease_expires_at_ms,
        lease: PhysicalWriteLease {
            intent_id: intent.intent_id,
            namespace_epoch,
            owner: intent.lease_owner.clone(),
            token: intent.lease_token,
        },
        intent: PhysicalWriteIntent {
            intent_id: intent.intent_id,
            tenant_id: intent.tenant_id,
            backend_id: intent.backend_id,
            storage_identity: ProviderStorageIdentity {
                provider_kind: intent.provider_kind,
                provider_instance_id: intent.provider_instance_id,
                provider_account_id: intent.provider_account_id,
                canonical_endpoint: intent.canonical_endpoint,
                region: intent.provider_region,
            },
            credential_epoch: u64_from_i64(
                intent.credential_epoch,
                "physical write credential epoch",
            )?,
            provider_bucket: intent.provider_bucket,
            physical_key: intent.physical_key,
            versioning_mode: BackendVersioningMode::parse(&intent.versioning_mode)?,
            versioning_capability: BackendVersioningCapability::parse(
                &intent.versioning_capability,
            )?,
            lease_owner: intent.lease_owner,
        },
    })
}
