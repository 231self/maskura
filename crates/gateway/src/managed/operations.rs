//! Extracted from `managed.rs`; re-exported from `crate::managed`.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedLogicalOperationIntent {
    pub operation_id: Uuid,
    pub receipt_id: Uuid,
    pub logical: LogicalObjectKey,
    pub kind: ManagedMutationKind,
    pub generation: Uuid,
    pub fence: ManagedRouteFence,
    pub expected_authority_cas: Option<u64>,
    pub prior_logical_size: u64,
    pub primary_child_operation_id: Uuid,
    pub backend_id: String,
    pub provider_bucket: String,
    pub physical_key: String,
    pub occurred_at_ms: i64,
    pub rate_version: i32,
    pub route: UsageRoute,
    pub request_kind: RequestKind,
    pub max_processed_bytes: u64,
    pub publication_recipe: Option<ManagedPublicationRecipe>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedDeleteRequest {
    pub operation_id: Uuid,
    pub receipt_id: Uuid,
    pub logical: LogicalObjectKey,
    pub placement: Placement,
    pub provider_bucket: String,
    pub occurred_at_micros: i64,
    pub rate_version: i32,
    pub max_processed_bytes: u64,
}

pub(crate) fn delete_request_matches_operation(
    request: &ManagedDeleteRequest,
    operation: &ManagedLogicalOperation,
) -> bool {
    let intent = &operation.intent;
    intent.operation_id == request.operation_id
        && intent.receipt_id == request.receipt_id
        && intent.logical == request.logical
        && intent.kind == ManagedMutationKind::Delete
        && intent.backend_id == request.placement.primary_backend_id
        && intent.provider_bucket == request.provider_bucket
        && intent.occurred_at_ms == request.occurred_at_micros.div_euclid(1_000)
        && intent.rate_version == request.rate_version
        && intent.route == UsageRoute::DeleteObject
        && intent.request_kind == RequestKind::Write
        && intent.max_processed_bytes == request.max_processed_bytes
        && operation.evidence.as_ref().is_some_and(|evidence| {
            evidence
                .payload
                .get("occurred_at_micros")
                .and_then(serde_json::Value::as_i64)
                == Some(request.occurred_at_micros)
        })
        && intent.publication_recipe.as_ref().is_some_and(|recipe| {
            recipe.version == MANAGED_PUBLICATION_RECIPE_VERSION
                && recipe.placement_version == request.placement.version
                && recipe.primary_backend_id == request.placement.primary_backend_id
                && recipe.replica_backend_id == request.placement.replica_backend_id
                && recipe.metadata.is_empty()
                && recipe.primary_status == CopyStatus::Absent
                && recipe.replica_status == CopyStatus::Absent
        })
}

pub(crate) fn committed_delete_replay_authority(
    operation: &ManagedLogicalOperation,
    authority: Option<ObjectAuthority>,
) -> Result<ObjectAuthority, ManagedError> {
    let authority = authority.ok_or(ManagedError::Conflict)?;
    let committed_authority_version = operation
        .committed_authority_version
        .ok_or(ManagedError::Conflict)?;
    let original_tombstone_matches = authority.tombstone
        && authority.generation == operation.intent.generation
        && authority.digest.is_empty()
        && authority.size == 0;
    if authority.logical != operation.intent.logical
        || authority.cas_version < committed_authority_version
        || (authority.cas_version == committed_authority_version && !original_tombstone_matches)
    {
        return Err(ManagedError::Conflict);
    }
    Ok(authority)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedUsageEvidence {
    pub expected_output_digest: Option<String>,
    pub expected_output_size: u64,
    pub source_bytes: u64,
    pub processed_bytes: u64,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedLogicalOperation {
    pub intent: ManagedLogicalOperationIntent,
    pub evidence: Option<ManagedUsageEvidence>,
    pub reserved_physical_bytes: u64,
    pub committed_physical_bytes: u64,
    pub released_physical_bytes: u64,
    pub state: ManagedLogicalOperationState,
    pub committed_authority_version: Option<u64>,
    pub settlement_state: ManagedSettlementState,
    pub last_error_class: Option<String>,
    pub recovery_owner: Option<String>,
    pub recovery_token: Option<Uuid>,
    pub recovery_expires_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub committed_at_ms: Option<i64>,
    pub aborted_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedWorkspaceUsage {
    pub tenant_id: String,
    pub visible_logical_bytes: u64,
    pub physical_allocated_bytes: u64,
    pub reserved_bytes: u64,
    pub visible_limit_bytes: u64,
    pub replacement_headroom_bytes: u64,
    pub active_operation_id: Option<Uuid>,
    pub version: u64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedOperationCommit {
    pub operation: ManagedLogicalOperation,
    pub authority: ObjectAuthority,
    pub usage: ManagedWorkspaceUsage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedProvenPhysicalAllocation {
    pub authority: ObjectAuthority,
    pub allocated_bytes: u64,
}

pub(crate) fn request_kind_from_str(value: &str) -> Result<RequestKind, ManagedError> {
    match value {
        "write" => Ok(RequestKind::Write),
        "read" => Ok(RequestKind::Read),
        _ => Err(ManagedError::Corrupt(format!(
            "unknown managed request kind {value:?}"
        ))),
    }
}

pub(crate) fn usage_route_from_str(value: &str) -> Result<UsageRoute, ManagedError> {
    match value {
        "PutObject" => Ok(UsageRoute::PutObject),
        "GetObject" => Ok(UsageRoute::GetObject),
        "HeadObject" => Ok(UsageRoute::HeadObject),
        "ListObjects" => Ok(UsageRoute::ListObjects),
        "DeleteObject" => Ok(UsageRoute::DeleteObject),
        "AbortMultipartUpload" => Ok(UsageRoute::AbortMultipartUpload),
        "CompleteMultipartUpload" => Ok(UsageRoute::CompleteMultipartUpload),
        _ => Err(ManagedError::Corrupt(format!(
            "unknown managed usage route {value:?}"
        ))),
    }
}

pub(crate) fn logical_operation_from_model(
    model: managed_logical_operation::Model,
) -> Result<ManagedLogicalOperation, ManagedError> {
    let publication_recipe = match (
        model.publication_recipe_version,
        model.admitted_placement_version,
        model.recipe_primary_backend_id,
        model.authority_metadata,
        model.intended_primary_status,
        model.intended_replica_status,
    ) {
        (None, None, None, None, None, None) => None,
        (
            Some(version),
            Some(placement),
            Some(primary),
            Some(metadata),
            Some(primary_status),
            Some(replica_status),
        ) => Some(ManagedPublicationRecipe {
            version,
            placement_version: u32::try_from(placement).map_err(|_| {
                ManagedError::Corrupt("invalid admitted placement version".to_string())
            })?,
            primary_backend_id: primary,
            replica_backend_id: model.recipe_replica_backend_id,
            metadata: serde_json::from_value(metadata)
                .map_err(|_| ManagedError::Corrupt("invalid authority metadata".to_string()))?,
            primary_status: CopyStatus::parse(&primary_status)?,
            replica_status: CopyStatus::parse(&replica_status)?,
        }),
        _ => {
            return Err(ManagedError::Corrupt(
                "managed publication recipe is partially populated".to_string(),
            ));
        }
    };
    let evidence = match (
        model.expected_output_size,
        model.source_bytes,
        model.processed_bytes,
    ) {
        (None, None, None) if model.expected_output_digest.is_none() => None,
        (Some(output), Some(source), Some(processed)) => Some(ManagedUsageEvidence {
            expected_output_digest: model.expected_output_digest,
            expected_output_size: u64_from_i64(output, "managed expected output size")?,
            source_bytes: u64_from_i64(source, "managed source bytes")?,
            processed_bytes: u64_from_i64(processed, "managed processed bytes")?,
            payload: model.usage_evidence,
        }),
        _ => {
            return Err(ManagedError::Corrupt(
                "managed usage evidence is partially populated".to_string(),
            ));
        }
    };
    Ok(ManagedLogicalOperation {
        intent: ManagedLogicalOperationIntent {
            operation_id: model.operation_id,
            receipt_id: model.receipt_id,
            logical: LogicalObjectKey {
                tenant_id: model.tenant_id,
                bucket: model.bucket,
                key: model.logical_key,
            },
            kind: ManagedMutationKind::parse(&model.operation_kind)?,
            generation: model.generation,
            fence: ManagedRouteFence {
                namespace_epoch: u64_from_i64(model.namespace_epoch, "managed namespace epoch")?,
                routing_epoch: u64_from_i64(model.routing_epoch, "managed routing epoch")?,
            },
            expected_authority_cas: model
                .expected_authority_cas
                .map(|value| u64_from_i64(value, "managed expected authority CAS"))
                .transpose()?,
            prior_logical_size: u64_from_i64(
                model.prior_logical_size,
                "managed prior logical size",
            )?,
            primary_child_operation_id: model.primary_child_operation_id,
            backend_id: model.backend_id,
            provider_bucket: model.provider_bucket,
            physical_key: model.physical_key,
            occurred_at_ms: model.occurred_at_ms,
            rate_version: model.rate_version,
            route: usage_route_from_str(&model.usage_route)?,
            request_kind: request_kind_from_str(&model.request_kind)?,
            max_processed_bytes: u64_from_i64(
                model.max_processed_bytes,
                "managed maximum processed bytes",
            )?,
            publication_recipe,
        },
        evidence,
        reserved_physical_bytes: u64_from_i64(
            model.reserved_physical_bytes,
            "managed reserved physical bytes",
        )?,
        committed_physical_bytes: u64_from_i64(
            model.committed_physical_bytes,
            "managed committed physical bytes",
        )?,
        released_physical_bytes: u64_from_i64(
            model.released_physical_bytes,
            "managed released physical bytes",
        )?,
        state: ManagedLogicalOperationState::parse(&model.state)?,
        committed_authority_version: model
            .committed_authority_version
            .map(|value| u64_from_i64(value, "managed committed authority version"))
            .transpose()?,
        settlement_state: ManagedSettlementState::parse(&model.settlement_state)?,
        last_error_class: model.last_error_class,
        recovery_owner: model.recovery_owner,
        recovery_token: model.recovery_token,
        recovery_expires_at_ms: model.recovery_expires_at_ms,
        created_at_ms: model.created_at_ms,
        updated_at_ms: model.updated_at_ms,
        committed_at_ms: model.committed_at_ms,
        aborted_at_ms: model.aborted_at_ms,
    })
}

pub(crate) fn logical_operation_active(
    intent: &ManagedLogicalOperationIntent,
    now: i64,
) -> Result<managed_logical_operation::ActiveModel, ManagedError> {
    let recipe = intent.publication_recipe.as_ref();
    Ok(managed_logical_operation::ActiveModel {
        operation_id: Set(intent.operation_id),
        receipt_id: Set(intent.receipt_id),
        tenant_id: Set(intent.logical.tenant_id.clone()),
        bucket: Set(intent.logical.bucket.clone()),
        logical_key: Set(intent.logical.key.clone()),
        operation_kind: Set(intent.kind.as_str().to_string()),
        generation: Set(intent.generation),
        namespace_epoch: Set(i64_from_u64(
            intent.fence.namespace_epoch,
            "managed namespace epoch",
        )?),
        routing_epoch: Set(i64_from_u64(
            intent.fence.routing_epoch,
            "managed routing epoch",
        )?),
        expected_authority_cas: Set(intent
            .expected_authority_cas
            .map(|value| i64_from_u64(value, "managed expected authority CAS"))
            .transpose()?),
        prior_logical_size: Set(i64_from_u64(
            intent.prior_logical_size,
            "managed prior logical size",
        )?),
        primary_child_operation_id: Set(intent.primary_child_operation_id),
        backend_id: Set(intent.backend_id.clone()),
        provider_bucket: Set(intent.provider_bucket.clone()),
        physical_key: Set(intent.physical_key.clone()),
        expected_output_digest: Set(None),
        expected_output_size: Set(None),
        source_bytes: Set(None),
        processed_bytes: Set(None),
        reserved_physical_bytes: Set(0),
        committed_physical_bytes: Set(0),
        released_physical_bytes: Set(0),
        state: Set(ManagedLogicalOperationState::Intent.as_str().to_string()),
        committed_authority_version: Set(None),
        occurred_at_ms: Set(intent.occurred_at_ms),
        rate_version: Set(intent.rate_version),
        usage_route: Set(intent.route.as_str().to_string()),
        request_kind: Set(intent.request_kind.as_str().to_string()),
        max_processed_bytes: Set(i64_from_u64(
            intent.max_processed_bytes,
            "managed maximum processed bytes",
        )?),
        publication_recipe_version: Set(recipe.map(|recipe| recipe.version)),
        admitted_placement_version: Set(recipe.map(|recipe| i64::from(recipe.placement_version))),
        recipe_primary_backend_id: Set(recipe.map(|recipe| recipe.primary_backend_id.clone())),
        recipe_replica_backend_id: Set(recipe.and_then(|recipe| recipe.replica_backend_id.clone())),
        authority_metadata: Set(recipe
            .map(|recipe| serde_json::to_value(&recipe.metadata))
            .transpose()
            .map_err(|_| ManagedError::Conflict)?),
        intended_primary_status: Set(
            recipe.map(|recipe| recipe.primary_status.as_str().to_string())
        ),
        intended_replica_status: Set(
            recipe.map(|recipe| recipe.replica_status.as_str().to_string())
        ),
        usage_evidence: Set(serde_json::json!({})),
        settlement_state: Set(ManagedSettlementState::Pending.as_str().to_string()),
        last_error_class: Set(None),
        recovery_owner: Set(None),
        recovery_token: Set(None),
        recovery_expires_at_ms: Set(None),
        created_at_ms: Set(now),
        updated_at_ms: Set(now),
        committed_at_ms: Set(None),
        aborted_at_ms: Set(None),
    })
}

pub(crate) fn workspace_usage_from_model(
    model: managed_workspace_usage::Model,
) -> Result<ManagedWorkspaceUsage, ManagedError> {
    Ok(ManagedWorkspaceUsage {
        tenant_id: model.tenant_id,
        visible_logical_bytes: u64_from_i64(
            model.visible_logical_bytes,
            "managed visible logical bytes",
        )?,
        physical_allocated_bytes: u64_from_i64(
            model.physical_allocated_bytes,
            "managed physical allocated bytes",
        )?,
        reserved_bytes: u64_from_i64(model.reserved_bytes, "managed reserved bytes")?,
        visible_limit_bytes: u64_from_i64(model.visible_limit_bytes, "managed visible limit")?,
        replacement_headroom_bytes: u64_from_i64(
            model.replacement_headroom_bytes,
            "managed replacement headroom",
        )?,
        active_operation_id: model.active_operation_id,
        version: u64_from_i64(model.version, "managed usage version")?,
        created_at_ms: model.created_at_ms,
        updated_at_ms: model.updated_at_ms,
    })
}

pub(crate) fn validate_logical_intent(
    intent: &ManagedLogicalOperationIntent,
) -> Result<(), ManagedError> {
    if intent.logical.tenant_id.is_empty()
        || intent.logical.bucket.is_empty()
        || intent.backend_id.is_empty()
        || intent.provider_bucket.is_empty()
        || intent.physical_key.is_empty()
        || intent.fence.namespace_epoch == 0
        || intent.fence.routing_epoch == 0
        || intent.rate_version <= 0
        || intent.occurred_at_ms < 0
        || intent.request_kind != RequestKind::Write
        || !matches!(
            (intent.kind, intent.route),
            (ManagedMutationKind::Put, UsageRoute::PutObject)
                | (ManagedMutationKind::Delete, UsageRoute::DeleteObject)
        )
        || match intent.kind {
            ManagedMutationKind::Put => intent.publication_recipe.as_ref().is_none_or(|recipe| {
                recipe.version != MANAGED_PUBLICATION_RECIPE_VERSION
                    || recipe.placement_version == 0
                    || recipe.primary_backend_id != intent.backend_id
                    || recipe.primary_backend_id.is_empty()
                    || recipe.replica_backend_id.as_deref() == Some("")
                    || recipe.primary_status != CopyStatus::Ready
                    || (recipe.replica_backend_id.is_none()
                        && recipe.replica_status != CopyStatus::Absent)
                    || (recipe.replica_backend_id.is_some()
                        && recipe.replica_status != CopyStatus::RepairPending)
            }),
            ManagedMutationKind::Delete => intent.publication_recipe.is_some(),
        }
    {
        return Err(ManagedError::Conflict);
    }
    Ok(())
}
