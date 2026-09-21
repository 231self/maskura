//! Extracted from `managed.rs`; re-exported from `crate::managed`.

use super::*;

pub(crate) async fn insert_waiting_placement_cleanup<C>(
    db: &C,
    repair: RepairRecord,
) -> Result<(), ManagedError>
where
    C: sea_orm::ConnectionTrait,
{
    let mut active = repair_active(repair)?;
    active.state = Set("WAITING_CUTOVER".to_string());
    managed_object_repair::Entity::insert(active)
        .on_conflict(
            OnConflict::columns([
                managed_object_repair::Column::Kind,
                managed_object_repair::Column::Generation,
                managed_object_repair::Column::TargetBackendId,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec_without_returning(db)
        .await
        .map_err(persistence)?;
    Ok(())
}

pub(crate) async fn locked_namespace<C>(
    db: &C,
    tenant_id: &str,
) -> Result<managed_namespace::Model, ManagedError>
where
    C: ConnectionTrait,
{
    if let Some(namespace) = managed_namespace::Entity::find_by_id(tenant_id.to_string())
        .lock(LockType::Update)
        .one(db)
        .await
        .map_err(persistence)?
    {
        return Ok(namespace);
    }
    let now = crate::transaction::unix_time_ms();
    managed_namespace::Entity::insert(managed_namespace::ActiveModel {
        tenant_id: Set(tenant_id.to_string()),
        epoch: Set(1),
        routing_epoch: Set(1),
        state: Set("ACTIVE".to_string()),
        purge_operation_id: Set(None),
        created_at_ms: Set(now),
        updated_at_ms: Set(now),
    })
    .on_conflict(
        OnConflict::column(managed_namespace::Column::TenantId)
            .do_nothing()
            .to_owned(),
    )
    .exec_without_returning(db)
    .await
    .map_err(persistence)?;
    managed_namespace::Entity::find_by_id(tenant_id.to_string())
        .lock(LockType::Update)
        .one(db)
        .await
        .map_err(persistence)?
        .ok_or_else(|| ManagedError::Persistence("managed namespace disappeared".to_string()))
}

pub(crate) async fn locked_workspace_usage<C>(
    db: &C,
    tenant_id: &str,
) -> Result<managed_workspace_usage::Model, ManagedError>
where
    C: ConnectionTrait,
{
    if let Some(usage) = managed_workspace_usage::Entity::find_by_id(tenant_id.to_string())
        .lock(LockType::Update)
        .one(db)
        .await
        .map_err(persistence)?
    {
        return Ok(usage);
    }
    let now = crate::transaction::unix_time_ms();
    managed_workspace_usage::Entity::insert(managed_workspace_usage::ActiveModel {
        tenant_id: Set(tenant_id.to_string()),
        visible_logical_bytes: Set(0),
        physical_allocated_bytes: Set(0),
        reserved_bytes: Set(0),
        visible_limit_bytes: Set(i64_from_u64(
            MANAGED_VISIBLE_LIMIT_BYTES,
            "managed visible limit",
        )?),
        replacement_headroom_bytes: Set(i64_from_u64(
            MANAGED_REPLACEMENT_HEADROOM_BYTES,
            "managed replacement headroom",
        )?),
        active_operation_id: Set(None),
        version: Set(1),
        created_at_ms: Set(now),
        updated_at_ms: Set(now),
    })
    .on_conflict(
        OnConflict::column(managed_workspace_usage::Column::TenantId)
            .do_nothing()
            .to_owned(),
    )
    .exec_without_returning(db)
    .await
    .map_err(persistence)?;
    managed_workspace_usage::Entity::find_by_id(tenant_id.to_string())
        .lock(LockType::Update)
        .one(db)
        .await
        .map_err(persistence)?
        .ok_or_else(|| ManagedError::Persistence("managed usage row disappeared".to_string()))
}

pub(crate) async fn require_active_namespace<C>(
    db: &C,
    tenant_id: &str,
) -> Result<i64, ManagedError>
where
    C: ConnectionTrait,
{
    let namespace = locked_namespace(db, tenant_id).await?;
    if namespace.state != "ACTIVE" {
        return Err(ManagedError::NamespaceFenced);
    }
    Ok(namespace.epoch)
}

#[derive(Clone, Debug)]
pub struct PostgresManagedRepository {
    pub(crate) db: DatabaseConnection,
}

impl PostgresManagedRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            db: SqlxPostgresConnector::from_sqlx_postgres_pool(pool),
        }
    }

    pub(crate) async fn finalize_purge_if_ready(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let purge = managed_namespace_purge::Entity::find_by_id(request.operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .filter(|purge| purge.tenant_id == request.tenant_id);
        let Some(purge) = purge else {
            return Ok(NamespacePurgeStatus::Blocked {
                reason: "managed namespace purge operation was not found".to_string(),
            });
        };
        if purge.state == "COMPLETE" {
            return purge_status_from_model(purge);
        }

        let now = crate::transaction::unix_time_ms();
        managed_physical_object_version::Entity::update_many()
            .col_expr(
                managed_physical_object_version::Column::State,
                Expr::value("PURGE_PENDING"),
            )
            .col_expr(
                managed_physical_object_version::Column::PurgeOperationId,
                Expr::value(Some(request.operation_id)),
            )
            .col_expr(
                managed_physical_object_version::Column::LastError,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_physical_object_version::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_physical_object_version::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_physical_object_version::Column::Epoch.lte(purge.epoch))
            .filter(managed_physical_object_version::Column::State.eq("LIVE"))
            .exec(&txn)
            .await
            .map_err(persistence)?;

        let intents = managed_physical_write_intent::Entity::find()
            .filter(managed_physical_write_intent::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_physical_write_intent::Column::Epoch.lte(purge.epoch))
            .all(&txn)
            .await
            .map_err(persistence)?;
        let targets = managed_physical_object_version::Entity::find()
            .filter(managed_physical_object_version::Column::TenantId.eq(&request.tenant_id))
            .filter(
                managed_physical_object_version::Column::PurgeOperationId.eq(request.operation_id),
            )
            .all(&txn)
            .await
            .map_err(persistence)?;
        if let Some(intent) = intents.iter().find(|intent| intent.state == "BLOCKED") {
            let reason = intent
                .last_error
                .clone()
                .unwrap_or_else(|| "physical provider version history is ambiguous".to_string());
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }
        if !intents.is_empty() || targets.iter().any(|target| target.state == "PURGE_PENDING") {
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Running);
        }
        if let Some(target) = targets
            .iter()
            .find(|target| target.state == "PURGE_BLOCKED")
        {
            let reason = target
                .last_error
                .clone()
                .unwrap_or_else(|| "physical version deletion is blocked".to_string());
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }

        let unresolved_journal_rows = object_operation::Entity::find()
            .filter(object_operation::Column::TenantId.eq(&request.tenant_id))
            .filter(object_operation::Column::NamespaceEpoch.lte(purge.epoch))
            .filter(object_operation::Column::State.is_not_in([
                crate::transaction::OperationState::Committed.as_str(),
                crate::transaction::OperationState::ProvenAborted.as_str(),
            ]))
            .count(&txn)
            .await
            .map_err(persistence)?;
        if unresolved_journal_rows > 0 {
            let reason = "managed namespace has unresolved operation journal rows".to_string();
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }

        let unresolved_logical_operations = managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .count(&txn)
            .await
            .map_err(persistence)?;
        if unresolved_logical_operations > 0 {
            let reason = "managed namespace has unresolved logical operations".to_string();
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }

        // Multipart staging owns encrypted artifacts and quota accounting in a
        // separate repository. Completing purge while rows remain would leak
        // those artifacts, so fail closed instead of deleting metadata alone.
        let multipart_uploads = crate::entity::multipart_upload::Entity::find()
            .filter(crate::entity::multipart_upload::Column::TenantId.eq(&request.tenant_id))
            .filter(
                Condition::any()
                    .add(crate::entity::multipart_upload::Column::NamespaceEpoch.is_null())
                    .add(crate::entity::multipart_upload::Column::NamespaceEpoch.lte(purge.epoch)),
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
        let multipart_activities = managed_multipart_activity::Entity::find()
            .filter(managed_multipart_activity::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_multipart_activity::Column::NamespaceEpoch.lte(purge.epoch))
            .count(&txn)
            .await
            .map_err(persistence)?;
        if multipart_uploads > 0 || multipart_activities > 0 {
            let reason =
                "managed namespace has multipart staging artifacts that must be aborted first"
                    .to_string();
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }

        managed_object_repair::Entity::delete_many()
            .filter(managed_object_repair::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_object_repair::Column::NamespaceEpoch.lte(purge.epoch))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        object_operation::Entity::delete_many()
            .filter(object_operation::Column::TenantId.eq(&request.tenant_id))
            .filter(object_operation::Column::NamespaceEpoch.lte(purge.epoch))
            .filter(object_operation::Column::State.is_in([
                crate::transaction::OperationState::Committed.as_str(),
                crate::transaction::OperationState::ProvenAborted.as_str(),
            ]))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::ReleasedPhysicalBytes,
                Expr::col(managed_logical_operation::Column::CommittedPhysicalBytes).into(),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_logical_operation::Column::TenantId.eq(&request.tenant_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::VisibleLogicalBytes,
                Expr::value(0),
            )
            .col_expr(
                managed_workspace_usage::Column::PhysicalAllocatedBytes,
                Expr::value(0),
            )
            .col_expr(
                managed_workspace_usage::Column::ReservedBytes,
                Expr::value(0),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::col(managed_workspace_usage::Column::Version).add(1),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_workspace_usage::Column::TenantId.eq(&request.tenant_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_list_cursor::Entity::delete_many()
            .filter(managed_list_cursor::Column::TenantId.eq(&request.tenant_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_object_authority::Entity::delete_many()
            .filter(managed_object_authority::Column::TenantId.eq(&request.tenant_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_namespace::Entity::update_many()
            .col_expr(
                managed_namespace::Column::Epoch,
                Expr::value(purge.epoch.saturating_add(1)),
            )
            .col_expr(
                managed_namespace::Column::RoutingEpoch,
                Expr::col(managed_namespace::Column::RoutingEpoch).add(1),
            )
            .col_expr(managed_namespace::Column::State, Expr::value("ACTIVE"))
            .col_expr(
                managed_namespace::Column::PurgeOperationId,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(managed_namespace::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_namespace::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_namespace::Column::PurgeOperationId.eq(request.operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_namespace_purge::Entity::update_many()
            .col_expr(
                managed_namespace_purge::Column::State,
                Expr::value("COMPLETE"),
            )
            .col_expr(
                managed_namespace_purge::Column::BlockedReason,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_namespace_purge::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .col_expr(
                managed_namespace_purge::Column::CompletedAtMs,
                Expr::value(Some(now)),
            )
            .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        let mut complete = purge;
        complete.state = "COMPLETE".to_string();
        complete.completed_at_ms = Some(now);
        purge_status_from_model(complete)
    }
}

pub(crate) async fn insert_repair<C>(db: &C, repair: RepairRecord) -> Result<(), ManagedError>
where
    C: sea_orm::ConnectionTrait,
{
    let revival = repair.clone();
    let kind = repair.kind.as_str().to_string();
    let generation = repair.generation;
    let target = repair.target_backend_id.clone();
    let inserted = managed_object_repair::Entity::insert(repair_active(repair)?)
        .on_conflict(
            OnConflict::columns([
                managed_object_repair::Column::Kind,
                managed_object_repair::Column::Generation,
                managed_object_repair::Column::TargetBackendId,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec_without_returning(db)
        .await
        .map_err(persistence)?;
    if inserted == 1 {
        return Ok(());
    }
    let existing = managed_object_repair::Entity::find()
        .filter(managed_object_repair::Column::Kind.eq(kind))
        .filter(managed_object_repair::Column::Generation.eq(generation))
        .filter(managed_object_repair::Column::TargetBackendId.eq(target))
        .one(db)
        .await
        .map_err(persistence)?;
    let Some(existing) = existing else {
        return Err(ManagedError::Persistence(
            "managed repair conflict row disappeared".to_string(),
        ));
    };
    if existing.state == "DONE" {
        managed_object_repair::Entity::update_many()
            .col_expr(managed_object_repair::Column::State, Expr::value("PENDING"))
            .col_expr(
                managed_object_repair::Column::LeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_object_repair::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .col_expr(
                managed_object_repair::Column::NamespaceEpoch,
                Expr::value(i64::try_from(revival.namespace_epoch).map_err(|_| {
                    ManagedError::Corrupt("repair namespace epoch exceeds BIGINT".to_string())
                })?),
            )
            .col_expr(
                managed_object_repair::Column::AuthorityCasVersion,
                Expr::value(i64::try_from(revival.authority_cas_version).map_err(|_| {
                    ManagedError::Corrupt("repair authority CAS exceeds BIGINT".to_string())
                })?),
            )
            .col_expr(
                managed_object_repair::Column::SourceBackendId,
                Expr::value(revival.source_backend_id),
            )
            .col_expr(
                managed_object_repair::Column::PhysicalKey,
                Expr::value(revival.physical_key),
            )
            .col_expr(
                managed_object_repair::Column::Digest,
                Expr::value(revival.digest),
            )
            .col_expr(
                managed_object_repair::Column::SizeBytes,
                Expr::value(i64::try_from(revival.size).map_err(|_| {
                    ManagedError::Corrupt("repair size exceeds BIGINT".to_string())
                })?),
            )
            .col_expr(
                managed_object_repair::Column::Metadata,
                Expr::value(
                    serde_json::to_value(revival.metadata)
                        .map_err(|error| ManagedError::Corrupt(error.to_string()))?,
                ),
            )
            .col_expr(
                managed_object_repair::Column::TargetRole,
                Expr::value(revival.target_role.as_str()),
            )
            .col_expr(
                managed_object_repair::Column::PlacementVersion,
                Expr::value(i64::from(revival.placement_version)),
            )
            .col_expr(
                managed_object_repair::Column::PlacementPrimaryBackendId,
                Expr::value(revival.placement_primary_backend_id),
            )
            .col_expr(
                managed_object_repair::Column::PlacementReplicaBackendId,
                Expr::value(revival.placement_replica_backend_id),
            )
            .filter(managed_object_repair::Column::Id.eq(existing.id))
            .exec(db)
            .await
            .map_err(persistence)?;
    }
    Ok(())
}

pub(crate) fn authority_active(
    authority: &ObjectAuthority,
) -> Result<managed_object_authority::ActiveModel, ManagedError> {
    Ok(managed_object_authority::ActiveModel {
        tenant_id: Set(authority.logical.tenant_id.clone()),
        bucket: Set(authority.logical.bucket.clone()),
        logical_key: Set(authority.logical.key.clone()),
        generation: Set(authority.generation),
        digest: Set(authority.digest.clone()),
        size_bytes: Set(i64::try_from(authority.size)
            .map_err(|_| ManagedError::Corrupt("authority size exceeds BIGINT".to_string()))?),
        metadata: Set(serde_json::to_value(&authority.metadata)
            .map_err(|error| ManagedError::Corrupt(error.to_string()))?),
        placement_version: Set(i64::from(authority.placement_version)),
        primary_backend_id: Set(authority.primary_backend_id.clone()),
        primary_version_id: Set(authority.primary_version_id.clone()),
        replica_backend_id: Set(authority.replica_backend_id.clone()),
        primary_status: Set(authority.primary_status.as_str().to_string()),
        replica_status: Set(authority.replica_status.as_str().to_string()),
        tombstone: Set(authority.tombstone),
        cas_version: Set(i64::try_from(authority.cas_version)
            .map_err(|_| ManagedError::Corrupt("authority CAS exceeds BIGINT".to_string()))?),
        created_at_ms: Set(authority.created_at_ms),
        updated_at_ms: Set(authority.updated_at_ms),
    })
}

#[async_trait]
impl ManagedRepository for PostgresManagedRepository {
    fn is_durable(&self) -> bool {
        true
    }

    async fn assert_namespace_active(&self, tenant_id: &str) -> Result<(), ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        require_active_namespace(&txn, tenant_id).await?;
        txn.commit().await.map_err(persistence)
    }

    async fn route_fence(&self, tenant_id: &str) -> Result<ManagedRouteFence, ManagedError> {
        let namespace = locked_namespace(&self.db, tenant_id).await?;
        if namespace.state != "ACTIVE" {
            return Err(ManagedError::NamespaceFenced);
        }
        Ok(ManagedRouteFence {
            namespace_epoch: u64_from_i64(namespace.epoch, "managed namespace epoch")?,
            routing_epoch: u64_from_i64(namespace.routing_epoch, "managed routing epoch")?,
        })
    }

    async fn advance_routing_epoch(
        &self,
        tenant_id: &str,
        expected_routing_epoch: u64,
    ) -> Result<ManagedRouteFence, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, tenant_id).await?;
        if namespace.state != "ACTIVE" {
            return Err(ManagedError::NamespaceFenced);
        }
        let expected = i64_from_u64(expected_routing_epoch, "managed routing epoch")?;
        if namespace.routing_epoch != expected {
            return Err(ManagedError::Conflict);
        }
        let routing_epoch = expected
            .checked_add(1)
            .ok_or_else(|| ManagedError::Corrupt("managed routing epoch overflow".to_string()))?;
        managed_namespace::Entity::update_many()
            .col_expr(
                managed_namespace::Column::RoutingEpoch,
                Expr::value(routing_epoch),
            )
            .col_expr(
                managed_namespace::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(managed_namespace::Column::TenantId.eq(tenant_id))
            .filter(managed_namespace::Column::RoutingEpoch.eq(expected))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        Ok(ManagedRouteFence {
            namespace_epoch: u64_from_i64(namespace.epoch, "managed namespace epoch")?,
            routing_epoch: u64_from_i64(routing_epoch, "managed routing epoch")?,
        })
    }

    async fn insert_logical_operation(
        &self,
        intent: ManagedLogicalOperationIntent,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        validate_logical_intent(&intent)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &intent.logical.tenant_id).await?;
        if namespace.state != "ACTIVE" {
            return Err(ManagedError::NamespaceFenced);
        }
        if u64_from_i64(namespace.epoch, "managed namespace epoch")? != intent.fence.namespace_epoch
            || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                != intent.fence.routing_epoch
        {
            return Err(ManagedError::Conflict);
        }
        if let Some(existing) = managed_logical_operation::Entity::find_by_id(intent.operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
        {
            let operation = logical_operation_from_model(existing)?;
            if operation.intent != intent {
                return Err(ManagedError::Conflict);
            }
            txn.commit().await.map_err(persistence)?;
            return Ok(operation);
        }
        let child_intents =
            managed_physical_write_intent::Entity::find_by_id(intent.primary_child_operation_id)
                .count(&txn)
                .await
                .map_err(persistence)?;
        let child_versions = managed_physical_object_version::Entity::find()
            .filter(
                managed_physical_object_version::Column::WriteOperationId
                    .eq(intent.primary_child_operation_id),
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
        if child_intents != 0 || child_versions != 0 {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        managed_logical_operation::Entity::insert(logical_operation_active(&intent, now)?)
            .on_conflict(
                OnConflict::column(managed_logical_operation::Column::OperationId)
                    .do_nothing()
                    .to_owned(),
            )
            .exec_without_returning(&txn)
            .await
            .map_err(|_| ManagedError::Conflict)?;
        let operation = managed_logical_operation::Entity::find_by_id(intent.operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(logical_operation_from_model)?;
        if operation.intent != intent {
            return Err(ManagedError::Conflict);
        }
        txn.commit().await.map_err(persistence)?;
        Ok(operation)
    }

    async fn logical_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<ManagedLogicalOperation>, ManagedError> {
        managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .map(logical_operation_from_model)
            .transpose()
    }

    async fn pending_logical_operations(
        &self,
        limit: u64,
    ) -> Result<Vec<ManagedLogicalOperation>, ManagedError> {
        managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .order_by_asc(managed_logical_operation::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(logical_operation_from_model)
            .collect()
    }

    async fn pending_delete_settlements(
        &self,
        limit: u64,
    ) -> Result<Vec<ManagedLogicalOperation>, ManagedError> {
        managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::OperationKind.eq("DELETE"))
            .filter(
                managed_logical_operation::Column::State
                    .eq(ManagedLogicalOperationState::Committed.as_str()),
            )
            .filter(
                managed_logical_operation::Column::SettlementState
                    .eq(ManagedSettlementState::Pending.as_str()),
            )
            .order_by_asc(managed_logical_operation::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(logical_operation_from_model)
            .collect()
    }

    async fn mark_logical_operation_settled(
        &self,
        operation_id: Uuid,
        receipt_id: Uuid,
    ) -> Result<(), ManagedError> {
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::SettlementState,
                Expr::value(ManagedSettlementState::Settled.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .filter(managed_logical_operation::Column::ReceiptId.eq(receipt_id))
            .filter(managed_logical_operation::Column::OperationKind.eq("DELETE"))
            .filter(
                managed_logical_operation::Column::State
                    .eq(ManagedLogicalOperationState::Committed.as_str()),
            )
            .filter(
                managed_logical_operation::Column::SettlementState
                    .eq(ManagedSettlementState::Pending.as_str()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if updated.rows_affected == 1 {
            return Ok(());
        }
        self.logical_operation(operation_id)
            .await?
            .filter(|operation| {
                operation.intent.receipt_id == receipt_id
                    && operation.intent.kind == ManagedMutationKind::Delete
                    && operation.state == ManagedLogicalOperationState::Committed
                    && operation.settlement_state == ManagedSettlementState::Settled
            })
            .map(|_| ())
            .ok_or(ManagedError::Conflict)
    }

    async fn defer_delete_settlement(
        &self,
        operation_id: Uuid,
        receipt_id: Uuid,
    ) -> Result<(), ManagedError> {
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms().saturating_add(60_000)),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .filter(managed_logical_operation::Column::ReceiptId.eq(receipt_id))
            .filter(managed_logical_operation::Column::OperationKind.eq("DELETE"))
            .filter(
                managed_logical_operation::Column::State
                    .eq(ManagedLogicalOperationState::Committed.as_str()),
            )
            .filter(
                managed_logical_operation::Column::SettlementState
                    .eq(ManagedSettlementState::Pending.as_str()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        (updated.rows_affected == 1)
            .then_some(())
            .ok_or(ManagedError::Conflict)
    }

    async fn claim_stale_logical_operations(
        &self,
        owner: &str,
        stale_before_ms: i64,
        claim_expires_at_ms: i64,
        limit: u64,
    ) -> Result<Vec<ManagedRecoveryClaim>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        if owner.is_empty() || owner.len() > 256 || claim_expires_at_ms <= now {
            return Err(ManagedError::Conflict);
        }
        let candidates = managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::OperationKind.eq("PUT"))
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .filter(managed_logical_operation::Column::UpdatedAtMs.lte(stale_before_ms))
            .filter(
                Condition::any()
                    .add(managed_logical_operation::Column::RecoveryExpiresAtMs.is_null())
                    .add(managed_logical_operation::Column::RecoveryExpiresAtMs.lte(now)),
            )
            .order_by_asc(managed_logical_operation::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?;
        let mut claims = Vec::new();
        for candidate in candidates {
            let token = Uuid::now_v7();
            let updated = managed_logical_operation::Entity::update_many()
                .col_expr(
                    managed_logical_operation::Column::RecoveryOwner,
                    Expr::value(Some(owner.to_string())),
                )
                .col_expr(
                    managed_logical_operation::Column::RecoveryToken,
                    Expr::value(Some(token)),
                )
                .col_expr(
                    managed_logical_operation::Column::RecoveryExpiresAtMs,
                    Expr::value(Some(claim_expires_at_ms)),
                )
                .filter(managed_logical_operation::Column::OperationId.eq(candidate.operation_id))
                .filter(managed_logical_operation::Column::OperationKind.eq("PUT"))
                .filter(managed_logical_operation::Column::State.eq(&candidate.state))
                .filter(managed_logical_operation::Column::UpdatedAtMs.eq(candidate.updated_at_ms))
                .filter(managed_logical_operation::Column::UpdatedAtMs.lte(stale_before_ms))
                .filter(managed_logical_operation::Column::State.is_not_in([
                    ManagedLogicalOperationState::Committed.as_str(),
                    ManagedLogicalOperationState::ProvenAborted.as_str(),
                ]))
                .filter(
                    Condition::any()
                        .add(managed_logical_operation::Column::RecoveryExpiresAtMs.is_null())
                        .add(managed_logical_operation::Column::RecoveryExpiresAtMs.lte(now)),
                )
                .exec_with_returning(&self.db)
                .await
                .map_err(persistence)?;
            if let Some(model) = updated.into_iter().next() {
                claims.push(ManagedRecoveryClaim {
                    operation: logical_operation_from_model(model)?,
                    owner: owner.to_string(),
                    token,
                    expires_at_ms: claim_expires_at_ms,
                });
            }
        }
        Ok(claims)
    }

    async fn mark_logical_recovery_blocked(
        &self,
        claim: &ManagedRecoveryClaim,
        reason: &str,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::RecoveryBlocked.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::LastErrorClass,
                Expr::value(Some(reason.chars().take(128).collect::<String>())),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(
                managed_logical_operation::Column::OperationId
                    .eq(claim.operation.intent.operation_id),
            )
            .filter(managed_logical_operation::Column::RecoveryOwner.eq(&claim.owner))
            .filter(managed_logical_operation::Column::RecoveryToken.eq(claim.token))
            .filter(managed_logical_operation::Column::RecoveryExpiresAtMs.eq(claim.expires_at_ms))
            .filter(
                managed_logical_operation::Column::RecoveryExpiresAtMs
                    .gt(crate::transaction::unix_time_ms()),
            )
            .exec_with_returning(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .next()
            .ok_or(ManagedError::Conflict)?;
        logical_operation_from_model(updated)
    }

    async fn renew_logical_recovery_claim(
        &self,
        claim: &ManagedRecoveryClaim,
        claim_expires_at_ms: i64,
    ) -> Result<ManagedRecoveryClaim, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        if claim_expires_at_ms <= now {
            return Err(ManagedError::Conflict);
        }
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::RecoveryExpiresAtMs,
                Expr::value(Some(claim_expires_at_ms)),
            )
            .filter(
                managed_logical_operation::Column::OperationId
                    .eq(claim.operation.intent.operation_id),
            )
            .filter(managed_logical_operation::Column::RecoveryOwner.eq(&claim.owner))
            .filter(managed_logical_operation::Column::RecoveryToken.eq(claim.token))
            .filter(managed_logical_operation::Column::RecoveryExpiresAtMs.eq(claim.expires_at_ms))
            .filter(managed_logical_operation::Column::RecoveryExpiresAtMs.gt(now))
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .exec_with_returning(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .next()
            .ok_or(ManagedError::Conflict)?;
        Ok(ManagedRecoveryClaim {
            operation: logical_operation_from_model(updated)?,
            owner: claim.owner.clone(),
            token: claim.token,
            expires_at_ms: claim_expires_at_ms,
        })
    }

    async fn reserve_logical_operation(
        &self,
        operation_id: Uuid,
        physical_bytes: u64,
    ) -> Result<ManagedWorkspaceUsage, ManagedError> {
        let identity = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &identity.tenant_id).await?;
        let model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let operation = logical_operation_from_model(model.clone())?;
        if namespace.state != "ACTIVE"
            || u64_from_i64(namespace.epoch, "managed namespace epoch")?
                != operation.intent.fence.namespace_epoch
            || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                != operation.intent.fence.routing_epoch
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let mut usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
        if operation.state == ManagedLogicalOperationState::Open
            && operation.reserved_physical_bytes == physical_bytes
            && usage.active_operation_id == Some(operation_id)
        {
            txn.commit().await.map_err(persistence)?;
            return workspace_usage_from_model(usage);
        }
        if operation.state != ManagedLogicalOperationState::Intent {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::Open,
            });
        }
        if usage.active_operation_id.is_some() {
            return Err(ManagedError::MutationInProgress);
        }
        let physical = i64_from_u64(physical_bytes, "managed physical reservation")?;
        let next_reserved = usage
            .reserved_bytes
            .checked_add(physical)
            .ok_or(ManagedError::QuotaExceeded)?;
        let physical_bound = usage
            .visible_limit_bytes
            .checked_add(usage.replacement_headroom_bytes)
            .ok_or(ManagedError::QuotaExceeded)?;
        if usage
            .physical_allocated_bytes
            .checked_add(next_reserved)
            .is_none_or(|value| value > physical_bound)
        {
            return Err(ManagedError::QuotaExceeded);
        }
        let now = crate::transaction::unix_time_ms();
        usage.reserved_bytes = next_reserved;
        usage.active_operation_id = Some(operation_id);
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::ReservedBytes,
                Expr::value(usage.reserved_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(Some(operation_id)),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(
                managed_workspace_usage::Column::TenantId.eq(&operation.intent.logical.tenant_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::Open.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::ReservedPhysicalBytes,
                Expr::value(physical),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .filter(
                managed_logical_operation::Column::State
                    .eq(ManagedLogicalOperationState::Intent.as_str()),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        workspace_usage_from_model(usage)
    }

    async fn admit_logical_operation(
        &self,
        intent: ManagedLogicalOperationIntent,
        reservation_cap: u64,
    ) -> Result<(ManagedLogicalOperation, ManagedWorkspaceUsage), ManagedError> {
        validate_logical_intent(&intent)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &intent.logical.tenant_id).await?;
        if namespace.state != "ACTIVE" {
            return Err(ManagedError::NamespaceFenced);
        }
        if u64_from_i64(namespace.epoch, "managed namespace epoch")? != intent.fence.namespace_epoch
            || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                != intent.fence.routing_epoch
        {
            return Err(ManagedError::Conflict);
        }
        let mut operation = if let Some(existing) =
            managed_logical_operation::Entity::find_by_id(intent.operation_id)
                .one(&txn)
                .await
                .map_err(persistence)?
        {
            let operation = logical_operation_from_model(existing)?;
            if operation.intent != intent {
                return Err(ManagedError::Conflict);
            }
            operation
        } else {
            let child_intents = managed_physical_write_intent::Entity::find_by_id(
                intent.primary_child_operation_id,
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
            let child_versions = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::WriteOperationId
                        .eq(intent.primary_child_operation_id),
                )
                .count(&txn)
                .await
                .map_err(persistence)?;
            if child_intents != 0 || child_versions != 0 {
                return Err(ManagedError::Conflict);
            }
            let now = crate::transaction::unix_time_ms();
            managed_logical_operation::Entity::insert(logical_operation_active(&intent, now)?)
                .on_conflict(
                    OnConflict::column(managed_logical_operation::Column::OperationId)
                        .do_nothing()
                        .to_owned(),
                )
                .exec_without_returning(&txn)
                .await
                .map_err(|_| ManagedError::Conflict)?;
            let inserted = managed_logical_operation::Entity::find_by_id(intent.operation_id)
                .one(&txn)
                .await
                .map_err(persistence)?
                .ok_or(ManagedError::Conflict)?;
            let operation = logical_operation_from_model(inserted)?;
            if operation.intent != intent {
                return Err(ManagedError::Conflict);
            }
            operation
        };
        let mut usage = locked_workspace_usage(&txn, &intent.logical.tenant_id).await?;
        let available = usage
            .visible_limit_bytes
            .saturating_add(usage.replacement_headroom_bytes)
            .saturating_sub(usage.physical_allocated_bytes)
            .saturating_sub(usage.reserved_bytes);
        let available = u64::try_from(available).unwrap_or(u64::MAX).max(1);
        let physical_bytes = reservation_cap.min(available);
        if operation.state == ManagedLogicalOperationState::Open
            && operation.reserved_physical_bytes == physical_bytes
            && usage.active_operation_id == Some(intent.operation_id)
        {
            txn.commit().await.map_err(persistence)?;
            return Ok((operation, workspace_usage_from_model(usage)?));
        }
        if operation.state != ManagedLogicalOperationState::Intent {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::Open,
            });
        }
        if usage.active_operation_id.is_some() {
            return Err(ManagedError::MutationInProgress);
        }
        let physical = i64_from_u64(physical_bytes, "managed physical reservation")?;
        let next_reserved = usage
            .reserved_bytes
            .checked_add(physical)
            .ok_or(ManagedError::QuotaExceeded)?;
        let physical_bound = usage
            .visible_limit_bytes
            .checked_add(usage.replacement_headroom_bytes)
            .ok_or(ManagedError::QuotaExceeded)?;
        if usage
            .physical_allocated_bytes
            .checked_add(next_reserved)
            .is_none_or(|value| value > physical_bound)
        {
            return Err(ManagedError::QuotaExceeded);
        }
        let now = crate::transaction::unix_time_ms();
        usage.reserved_bytes = next_reserved;
        usage.active_operation_id = Some(intent.operation_id);
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::ReservedBytes,
                Expr::value(usage.reserved_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(Some(intent.operation_id)),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_workspace_usage::Column::TenantId.eq(&intent.logical.tenant_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::Open.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::ReservedPhysicalBytes,
                Expr::value(physical),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(intent.operation_id))
            .filter(
                managed_logical_operation::Column::State
                    .eq(ManagedLogicalOperationState::Intent.as_str()),
            )
            .exec_with_returning(&txn)
            .await
            .map_err(persistence)?;
        if updated.len() != 1 {
            return Err(ManagedError::Conflict);
        }
        operation = logical_operation_from_model(
            updated.into_iter().next().ok_or(ManagedError::Conflict)?,
        )?;
        txn.commit().await.map_err(persistence)?;
        let usage = workspace_usage_from_model(usage)?;
        Ok((operation, usage))
    }

    async fn record_logical_usage(
        &self,
        operation_id: Uuid,
        evidence: ManagedUsageEvidence,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        if evidence.processed_bytes != evidence.source_bytes.max(evidence.expected_output_size) {
            return Err(ManagedError::Conflict);
        }
        let txn = self.db.begin().await.map_err(persistence)?;
        let model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let existing = logical_operation_from_model(model)?;
        if existing.evidence.as_ref() == Some(&evidence) {
            txn.commit().await.map_err(persistence)?;
            return Ok(existing);
        }
        if existing.evidence.is_some()
            || existing.state == ManagedLogicalOperationState::Intent
            || existing.state.terminal()
            || evidence.processed_bytes > existing.intent.max_processed_bytes
            || (existing.intent.kind == ManagedMutationKind::Put
                && evidence.expected_output_digest.is_none())
            || (existing.intent.kind == ManagedMutationKind::Delete
                && (evidence.expected_output_size != 0
                    || evidence.source_bytes != 0
                    || evidence.processed_bytes != 0))
        {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::ExpectedOutputDigest,
                Expr::value(evidence.expected_output_digest.clone()),
            )
            .col_expr(
                managed_logical_operation::Column::ExpectedOutputSize,
                Expr::value(Some(i64_from_u64(
                    evidence.expected_output_size,
                    "managed expected output size",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::SourceBytes,
                Expr::value(Some(i64_from_u64(
                    evidence.source_bytes,
                    "managed source bytes",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::ProcessedBytes,
                Expr::value(Some(i64_from_u64(
                    evidence.processed_bytes,
                    "managed processed bytes",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::UsageEvidence,
                Expr::value(evidence.payload),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .exec_with_returning(&txn)
            .await
            .map_err(persistence)?
            .into_iter()
            .next()
            .ok_or(ManagedError::Conflict)
            .and_then(logical_operation_from_model)?;
        txn.commit().await.map_err(persistence)?;
        Ok(updated)
    }

    async fn transition_logical_operation(
        &self,
        operation_id: Uuid,
        from: ManagedLogicalOperationState,
        to: ManagedLogicalOperationState,
        error_class: Option<&str>,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        if !valid_logical_transition(from, to) {
            return Err(ManagedError::InvalidTransition { from, to });
        }
        let now = crate::transaction::unix_time_ms();
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(to.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::LastErrorClass,
                Expr::value(error_class.map(|value| value.chars().take(128).collect::<String>())),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .filter(managed_logical_operation::Column::State.eq(from.as_str()))
            .exec_with_returning(&self.db)
            .await
            .map_err(persistence)?;
        if updated.len() != 1 {
            return Err(ManagedError::Conflict);
        }
        logical_operation_from_model(updated.into_iter().next().ok_or(ManagedError::Conflict)?)
    }

    async fn record_logical_usage_and_begin_completion(
        &self,
        operation_id: Uuid,
        evidence: ManagedUsageEvidence,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        if evidence.processed_bytes != evidence.source_bytes.max(evidence.expected_output_size) {
            return Err(ManagedError::Conflict);
        }
        let txn = self.db.begin().await.map_err(persistence)?;
        let model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let existing = logical_operation_from_model(model)?;
        if existing.evidence.as_ref() == Some(&evidence) {
            // Idempotent retry: only an operation still in `Open` advances,
            // matching the two-step `record` then `Open -> Completing` behavior.
            if existing.state != ManagedLogicalOperationState::Open {
                return Err(ManagedError::Conflict);
            }
        } else {
            if existing.evidence.is_some()
                || existing.state == ManagedLogicalOperationState::Intent
                || existing.state.terminal()
                || evidence.processed_bytes > existing.intent.max_processed_bytes
                || (existing.intent.kind == ManagedMutationKind::Put
                    && evidence.expected_output_digest.is_none())
                || (existing.intent.kind == ManagedMutationKind::Delete
                    && (evidence.expected_output_size != 0
                        || evidence.source_bytes != 0
                        || evidence.processed_bytes != 0))
            {
                return Err(ManagedError::Conflict);
            }
        }
        let now = crate::transaction::unix_time_ms();
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::ExpectedOutputDigest,
                Expr::value(evidence.expected_output_digest.clone()),
            )
            .col_expr(
                managed_logical_operation::Column::ExpectedOutputSize,
                Expr::value(Some(i64_from_u64(
                    evidence.expected_output_size,
                    "managed expected output size",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::SourceBytes,
                Expr::value(Some(i64_from_u64(
                    evidence.source_bytes,
                    "managed source bytes",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::ProcessedBytes,
                Expr::value(Some(i64_from_u64(
                    evidence.processed_bytes,
                    "managed processed bytes",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::UsageEvidence,
                Expr::value(evidence.payload),
            )
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::Completing.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::LastErrorClass,
                Expr::value(None::<String>),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .filter(
                managed_logical_operation::Column::State
                    .eq(ManagedLogicalOperationState::Open.as_str()),
            )
            .exec_with_returning(&txn)
            .await
            .map_err(persistence)?;
        if updated.len() != 1 {
            return Err(ManagedError::Conflict);
        }
        let operation = logical_operation_from_model(
            updated.into_iter().next().ok_or(ManagedError::Conflict)?,
        )?;
        txn.commit().await.map_err(persistence)?;
        Ok(operation)
    }

    async fn finalize_logical_put(
        &self,
        operation_id: Uuid,
        physical_lease: &PhysicalWriteLease,
        result: ExactPhysicalCommit,
        recovery_claim: Option<&ManagedRecoveryClaim>,
    ) -> Result<ManagedOperationCommit, ManagedError> {
        validate_exact_physical_commit(&result)?;
        let identity = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &identity.tenant_id).await?;
        let operation_model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let operation = logical_operation_from_model(operation_model)?;
        let now = crate::transaction::unix_time_ms();
        if operation.state == ManagedLogicalOperationState::Committed {
            let persisted_authority = managed_object_authority::Entity::find_by_id((
                operation.intent.logical.tenant_id.clone(),
                operation.intent.logical.bucket.clone(),
                operation.intent.logical.key.clone(),
            ))
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(authority_from_model)?;
            let expected_versions = exact_version_ids(&result);
            let persisted_versions = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::WriteOperationId
                        .eq(operation.intent.primary_child_operation_id),
                )
                .all(&txn)
                .await
                .map_err(persistence)?;
            let persisted_ids = persisted_versions
                .iter()
                .map(|version| version.version_id.clone())
                .collect::<HashSet<_>>();
            let persisted_targets = persisted_versions
                .iter()
                .cloned()
                .map(physical_target_from_model)
                .collect::<Result<Vec<_>, _>>()?;
            let canonical_target = persisted_targets.first().ok_or(ManagedError::Conflict)?;
            let evidence = operation.evidence.as_ref().ok_or(ManagedError::Conflict)?;
            let recipe = operation
                .intent
                .publication_recipe
                .as_ref()
                .ok_or(ManagedError::Conflict)?;
            let committed_authority_version = operation
                .committed_authority_version
                .ok_or(ManagedError::Conflict)?;
            let original_authority_matches = persisted_authority.generation
                == operation.intent.generation
                && persisted_authority.digest
                    == evidence
                        .expected_output_digest
                        .clone()
                        .ok_or(ManagedError::Conflict)?
                && persisted_authority.size == evidence.expected_output_size
                && persisted_authority.metadata == recipe.metadata
                && persisted_authority.placement_version == recipe.placement_version
                && persisted_authority.primary_backend_id == recipe.primary_backend_id
                && persisted_authority.primary_version_id == result.selected_version_id
                && persisted_authority.replica_backend_id == recipe.replica_backend_id
                && persisted_authority.primary_status == recipe.primary_status
                && persisted_authority.replica_status == recipe.replica_status
                && !persisted_authority.tombstone;
            if persisted_authority.logical != operation.intent.logical
                || committed_authority_version
                    != operation
                        .intent
                        .expected_authority_cas
                        .unwrap_or(0)
                        .saturating_add(1)
                || persisted_authority.cas_version < committed_authority_version
                || (persisted_authority.cas_version == committed_authority_version
                    && !original_authority_matches)
                || persisted_ids != expected_versions.into_iter().collect()
                || persisted_versions
                    .iter()
                    .any(|version| version.state != "LIVE")
                || persisted_targets.iter().any(|target| {
                    target.tenant_id != operation.intent.logical.tenant_id
                        || target.namespace_epoch != operation.intent.fence.namespace_epoch
                        || target.backend_id != operation.intent.backend_id
                        || target.provider_bucket != operation.intent.provider_bucket
                        || target.physical_key != operation.intent.physical_key
                        || target.storage_identity != canonical_target.storage_identity
                        || target.credential_epoch != canonical_target.credential_epoch
                        || target.versioning_mode != canonical_target.versioning_mode
                        || target.versioning_capability != canonical_target.versioning_capability
                })
                || operation.committed_physical_bytes
                    != physical_allocation(
                        evidence.expected_output_size,
                        persisted_versions.len() as u64,
                    )?
            {
                return Err(ManagedError::Conflict);
            }
            let usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
            txn.commit().await.map_err(persistence)?;
            return Ok(ManagedOperationCommit {
                operation,
                authority: persisted_authority,
                usage: workspace_usage_from_model(usage)?,
            });
        }
        validate_recovery_authority(&operation, recovery_claim, now)?;
        if operation.intent.kind != ManagedMutationKind::Put
            || !matches!(
                operation.state,
                ManagedLogicalOperationState::Completing
                    | ManagedLogicalOperationState::CommitUnknown
                    | ManagedLogicalOperationState::RecoveryBlocked
            )
            || (operation.state == ManagedLogicalOperationState::RecoveryBlocked
                && recovery_claim.is_none())
        {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::Committed,
            });
        }
        let evidence = operation.evidence.clone().ok_or(ManagedError::Conflict)?;
        let recipe = operation
            .intent
            .publication_recipe
            .clone()
            .ok_or(ManagedError::Conflict)?;
        if recipe.version != MANAGED_PUBLICATION_RECIPE_VERSION
            || recipe.primary_backend_id != operation.intent.backend_id
        {
            return Err(ManagedError::Conflict);
        }
        if namespace.state != "ACTIVE"
            || u64_from_i64(namespace.epoch, "managed namespace epoch")?
                != operation.intent.fence.namespace_epoch
            || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                != operation.intent.fence.routing_epoch
        {
            return Err(ManagedError::RecoveryBlocked("namespace_fence_changed"));
        }
        let mut usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
        let existing_model = managed_object_authority::Entity::find_by_id((
            operation.intent.logical.tenant_id.clone(),
            operation.intent.logical.bucket.clone(),
            operation.intent.logical.key.clone(),
        ))
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?;
        let existing = existing_model
            .clone()
            .map(authority_from_model)
            .transpose()?;
        if physical_lease.intent_id != operation.intent.primary_child_operation_id {
            return Err(ManagedError::RecoveryBlocked("physical_intent_mismatch"));
        }
        let intent = managed_physical_write_intent::Entity::find_by_id(
            operation.intent.primary_child_operation_id,
        )
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?
        .ok_or(ManagedError::RecoveryBlocked("missing_physical_intent"))?;
        if intent.intent_id != operation.intent.primary_child_operation_id
            || intent.tenant_id != operation.intent.logical.tenant_id
            || intent.backend_id != operation.intent.backend_id
            || intent.provider_bucket != operation.intent.provider_bucket
            || intent.physical_key != operation.intent.physical_key
            || intent.epoch
                != i64_from_u64(
                    operation.intent.fence.namespace_epoch,
                    "managed namespace epoch",
                )?
        {
            return Err(ManagedError::RecoveryBlocked("physical_intent_mismatch"));
        }
        if intent.lease_owner != physical_lease.owner
            || intent.lease_token != physical_lease.token
            || intent.lease_expires_at_ms <= crate::transaction::unix_time_ms()
            || operation
                .recovery_owner
                .as_ref()
                .is_some_and(|owner| owner != &physical_lease.owner)
        {
            return Err(ManagedError::Conflict);
        }
        let durable_intent = durable_physical_intent_from_model(intent.clone())?;
        validate_physical_commit_versioning(&durable_intent.intent, &result)?;
        let child =
            object_operation::Entity::find_by_id(operation.intent.primary_child_operation_id)
                .lock(LockType::Update)
                .one(&txn)
                .await
                .map_err(persistence)?;
        validate_durable_child_commit(child.as_ref(), &operation, &result)?;
        let expected_targets = expected_physical_targets(
            &durable_intent.intent,
            physical_lease.namespace_epoch,
            &result,
        );
        for version_id in exact_version_ids(&result) {
            managed_physical_object_version::Entity::insert(
                managed_physical_object_version::ActiveModel {
                    tenant_id: Set(intent.tenant_id.clone()),
                    backend_id: Set(intent.backend_id.clone()),
                    provider_kind: Set(intent.provider_kind.clone()),
                    provider_instance_id: Set(intent.provider_instance_id.clone()),
                    provider_account_id: Set(intent.provider_account_id.clone()),
                    canonical_endpoint: Set(intent.canonical_endpoint.clone()),
                    provider_region: Set(intent.provider_region.clone()),
                    credential_epoch: Set(intent.credential_epoch),
                    provider_bucket: Set(intent.provider_bucket.clone()),
                    physical_key: Set(intent.physical_key.clone()),
                    versioning_mode: Set(intent.versioning_mode.clone()),
                    versioning_capability: Set(intent.versioning_capability.clone()),
                    write_operation_id: Set(intent.intent_id),
                    version_id: Set(version_id),
                    epoch: Set(intent.epoch),
                    state: Set("LIVE".to_string()),
                    purge_operation_id: Set(None),
                    last_error: Set(None),
                    created_at_ms: Set(now),
                    updated_at_ms: Set(now),
                },
            )
            .on_conflict(
                OnConflict::columns([
                    managed_physical_object_version::Column::TenantId,
                    managed_physical_object_version::Column::BackendId,
                    managed_physical_object_version::Column::ProviderBucket,
                    managed_physical_object_version::Column::PhysicalKey,
                    managed_physical_object_version::Column::VersionId,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec_without_returning(&txn)
            .await
            .map_err(persistence)?;
        }
        let child_version_models = managed_physical_object_version::Entity::find()
            .filter(
                managed_physical_object_version::Column::WriteOperationId
                    .eq(operation.intent.primary_child_operation_id),
            )
            .filter(
                managed_physical_object_version::Column::TenantId
                    .eq(&operation.intent.logical.tenant_id),
            )
            .filter(
                managed_physical_object_version::Column::BackendId.eq(&operation.intent.backend_id),
            )
            .filter(
                managed_physical_object_version::Column::ProviderBucket
                    .eq(&operation.intent.provider_bucket),
            )
            .filter(
                managed_physical_object_version::Column::PhysicalKey
                    .eq(&operation.intent.physical_key),
            )
            .all(&txn)
            .await
            .map_err(persistence)?;
        let child_versions = child_version_models
            .iter()
            .cloned()
            .map(physical_target_from_model)
            .collect::<Result<Vec<_>, _>>()?;
        let derived_physical_allocation =
            physical_allocation(evidence.expected_output_size, child_versions.len() as u64)?;
        if child_version_models
            .iter()
            .any(|version| version.state != "LIVE")
            || child_versions.len() != expected_targets.len()
            || expected_targets
                .iter()
                .any(|expected| !child_versions.contains(expected))
            || derived_physical_allocation > operation.reserved_physical_bytes
        {
            return Err(ManagedError::RecoveryBlocked("physical_version_mismatch"));
        }
        if existing.as_ref().map(|value| value.cas_version)
            != operation.intent.expected_authority_cas
            || existing
                .as_ref()
                .filter(|value| !value.tombstone)
                .map_or(0, |value| value.size)
                != operation.intent.prior_logical_size
        {
            return Err(ManagedError::RecoveryBlocked("authority_fence_changed"));
        }
        if usage.active_operation_id != Some(operation_id)
            || usage.reserved_bytes
                < i64_from_u64(
                    operation.reserved_physical_bytes,
                    "managed physical reservation",
                )?
        {
            return Err(ManagedError::Conflict);
        }
        let prior_size = i64_from_u64(operation.intent.prior_logical_size, "managed prior size")?;
        let output_size = i64_from_u64(evidence.expected_output_size, "managed output size")?;
        let visible = usage
            .visible_logical_bytes
            .checked_sub(prior_size)
            .and_then(|value| value.checked_add(output_size))
            .ok_or(ManagedError::QuotaExceeded)?;
        if visible > usage.visible_limit_bytes {
            return Err(ManagedError::QuotaExceeded);
        }
        let reserved = i64_from_u64(
            operation.reserved_physical_bytes,
            "managed physical reservation",
        )?;
        let allocated = i64_from_u64(derived_physical_allocation, "managed physical allocation")?;
        let mut authority = ObjectAuthority {
            logical: operation.intent.logical.clone(),
            generation: operation.intent.generation,
            digest: evidence
                .expected_output_digest
                .clone()
                .ok_or(ManagedError::Conflict)?,
            size: evidence.expected_output_size,
            metadata: recipe.metadata,
            placement_version: recipe.placement_version,
            primary_backend_id: recipe.primary_backend_id,
            primary_version_id: result.selected_version_id.clone(),
            replica_backend_id: recipe.replica_backend_id,
            primary_status: recipe.primary_status,
            replica_status: recipe.replica_status,
            tombstone: false,
            cas_version: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        authority.cas_version = operation
            .intent
            .expected_authority_cas
            .unwrap_or(0)
            .saturating_add(1);
        authority.created_at_ms = existing.as_ref().map_or(now, |value| value.created_at_ms);
        authority.updated_at_ms = now;
        match existing_model {
            None => {
                authority_active(&authority)?
                    .insert(&txn)
                    .await
                    .map_err(|_| ManagedError::Conflict)?;
            }
            Some(existing_model) => {
                let result = managed_object_authority::Entity::update_many()
                    .set(authority_active(&authority)?)
                    .filter(
                        managed_object_authority::Column::TenantId
                            .eq(&operation.intent.logical.tenant_id),
                    )
                    .filter(
                        managed_object_authority::Column::Bucket
                            .eq(&operation.intent.logical.bucket),
                    )
                    .filter(
                        managed_object_authority::Column::LogicalKey
                            .eq(&operation.intent.logical.key),
                    )
                    .filter(
                        managed_object_authority::Column::CasVersion.eq(existing_model.cas_version),
                    )
                    .exec(&txn)
                    .await
                    .map_err(persistence)?;
                if result.rows_affected != 1 {
                    return Err(ManagedError::Conflict);
                }
            }
        }
        for mut repair in publication_repairs(&authority) {
            repair.namespace_epoch = operation.intent.fence.namespace_epoch;
            insert_repair(&txn, repair).await?;
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                let targets = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId
                            .eq(&repair.logical.tenant_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::BackendId
                            .eq(&repair.target_backend_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::PhysicalKey
                            .eq(&repair.physical_key),
                    )
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if targets > 0 {
                    repair.namespace_epoch = operation.intent.fence.namespace_epoch;
                    insert_repair(&txn, repair).await?;
                }
            }
        }
        usage.visible_logical_bytes = visible;
        usage.physical_allocated_bytes = usage
            .physical_allocated_bytes
            .checked_add(allocated)
            .ok_or(ManagedError::QuotaExceeded)?;
        usage.reserved_bytes = usage
            .reserved_bytes
            .checked_sub(reserved)
            .ok_or(ManagedError::Conflict)?;
        usage.active_operation_id = None;
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::VisibleLogicalBytes,
                Expr::value(usage.visible_logical_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::PhysicalAllocatedBytes,
                Expr::value(usage.physical_allocated_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::ReservedBytes,
                Expr::value(usage.reserved_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(
                managed_workspace_usage::Column::TenantId.eq(&operation.intent.logical.tenant_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::Committed.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::CommittedPhysicalBytes,
                Expr::value(allocated),
            )
            .col_expr(
                managed_logical_operation::Column::CommittedAuthorityVersion,
                Expr::value(Some(i64_from_u64(
                    authority.cas_version,
                    "managed authority CAS",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .col_expr(
                managed_logical_operation::Column::CommittedAtMs,
                Expr::value(Some(now)),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        let committed = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(logical_operation_from_model)?;
        let deleted = managed_physical_write_intent::Entity::delete_many()
            .filter(managed_physical_write_intent::Column::IntentId.eq(physical_lease.intent_id))
            .filter(managed_physical_write_intent::Column::LeaseOwner.eq(&physical_lease.owner))
            .filter(managed_physical_write_intent::Column::LeaseToken.eq(physical_lease.token))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if deleted.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        txn.commit().await.map_err(persistence)?;
        Ok(ManagedOperationCommit {
            operation: committed,
            authority,
            usage: workspace_usage_from_model(usage)?,
        })
    }

    async fn commit_logical_delete(
        &self,
        operation_id: Uuid,
        placement: &Placement,
    ) -> Result<ManagedOperationCommit, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let operation_model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let operation = logical_operation_from_model(operation_model)?;
        if operation.state == ManagedLogicalOperationState::Committed {
            let authority = managed_object_authority::Entity::find_by_id((
                operation.intent.logical.tenant_id.clone(),
                operation.intent.logical.bucket.clone(),
                operation.intent.logical.key.clone(),
            ))
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(authority_from_model)?;
            if !authority.tombstone || authority.generation != operation.intent.generation {
                return Err(ManagedError::Conflict);
            }
            let usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
            txn.commit().await.map_err(persistence)?;
            return Ok(ManagedOperationCommit {
                operation,
                authority,
                usage: workspace_usage_from_model(usage)?,
            });
        }
        if operation.intent.kind != ManagedMutationKind::Delete
            || operation.reserved_physical_bytes != 0
            || operation.evidence.as_ref().is_none_or(|evidence| {
                evidence.expected_output_size != 0
                    || evidence.source_bytes != 0
                    || evidence.processed_bytes != 0
            })
            || !matches!(
                operation.state,
                ManagedLogicalOperationState::Completing
                    | ManagedLogicalOperationState::CommitUnknown
            )
        {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::Committed,
            });
        }
        let namespace = locked_namespace(&txn, &operation.intent.logical.tenant_id).await?;
        if namespace.state != "ACTIVE"
            || u64_from_i64(namespace.epoch, "managed namespace epoch")?
                != operation.intent.fence.namespace_epoch
            || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                != operation.intent.fence.routing_epoch
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let existing_model = managed_object_authority::Entity::find_by_id((
            operation.intent.logical.tenant_id.clone(),
            operation.intent.logical.bucket.clone(),
            operation.intent.logical.key.clone(),
        ))
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?;
        let existing = existing_model
            .clone()
            .map(authority_from_model)
            .transpose()?;
        if existing.as_ref().map(|value| value.cas_version)
            != operation.intent.expected_authority_cas
            || existing
                .as_ref()
                .filter(|value| !value.tombstone)
                .map_or(0, |value| value.size)
                != operation.intent.prior_logical_size
        {
            return Err(ManagedError::Conflict);
        }
        let mut usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
        if usage.active_operation_id != Some(operation_id) {
            return Err(ManagedError::Conflict);
        }
        let prior_size = i64_from_u64(operation.intent.prior_logical_size, "managed prior size")?;
        let visible = usage
            .visible_logical_bytes
            .checked_sub(prior_size)
            .ok_or(ManagedError::Conflict)?;
        let now = crate::transaction::unix_time_ms();
        let authority = ObjectAuthority {
            logical: operation.intent.logical.clone(),
            generation: operation.intent.generation,
            digest: String::new(),
            size: 0,
            metadata: BTreeMap::new(),
            placement_version: placement.version,
            primary_backend_id: placement.primary_backend_id.clone(),
            primary_version_id: None,
            replica_backend_id: placement.replica_backend_id.clone(),
            primary_status: CopyStatus::Absent,
            replica_status: CopyStatus::Absent,
            tombstone: true,
            cas_version: operation
                .intent
                .expected_authority_cas
                .unwrap_or(0)
                .saturating_add(1),
            created_at_ms: existing.as_ref().map_or(now, |value| value.created_at_ms),
            updated_at_ms: now,
        };
        match existing_model {
            None => {
                authority_active(&authority)?
                    .insert(&txn)
                    .await
                    .map_err(|_| ManagedError::Conflict)?;
            }
            Some(existing_model) => {
                let result = managed_object_authority::Entity::update_many()
                    .set(authority_active(&authority)?)
                    .filter(
                        managed_object_authority::Column::TenantId
                            .eq(&operation.intent.logical.tenant_id),
                    )
                    .filter(
                        managed_object_authority::Column::Bucket
                            .eq(&operation.intent.logical.bucket),
                    )
                    .filter(
                        managed_object_authority::Column::LogicalKey
                            .eq(&operation.intent.logical.key),
                    )
                    .filter(
                        managed_object_authority::Column::CasVersion.eq(existing_model.cas_version),
                    )
                    .exec(&txn)
                    .await
                    .map_err(persistence)?;
                if result.rows_affected != 1 {
                    return Err(ManagedError::Conflict);
                }
            }
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                let targets = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId
                            .eq(&repair.logical.tenant_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::BackendId
                            .eq(&repair.target_backend_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::PhysicalKey
                            .eq(&repair.physical_key),
                    )
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if targets > 0 {
                    repair.namespace_epoch = operation.intent.fence.namespace_epoch;
                    insert_repair(&txn, repair).await?;
                }
            }
        }
        usage.visible_logical_bytes = visible;
        usage.active_operation_id = None;
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::VisibleLogicalBytes,
                Expr::value(visible),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(
                managed_workspace_usage::Column::TenantId.eq(&operation.intent.logical.tenant_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::Committed.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::CommittedAuthorityVersion,
                Expr::value(Some(i64_from_u64(
                    authority.cas_version,
                    "managed authority CAS",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .col_expr(
                managed_logical_operation::Column::CommittedAtMs,
                Expr::value(Some(now)),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        let committed = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(logical_operation_from_model)?;
        txn.commit().await.map_err(persistence)?;
        Ok(ManagedOperationCommit {
            operation: committed,
            authority,
            usage: workspace_usage_from_model(usage)?,
        })
    }

    async fn commit_atomic_logical_delete(
        &self,
        request: ManagedDeleteRequest,
    ) -> Result<ManagedOperationCommit, ManagedDeleteError> {
        if request.logical.tenant_id.is_empty()
            || request.logical.bucket.is_empty()
            || request.placement.version == 0
            || request.placement.primary_backend_id.is_empty()
            || request.provider_bucket.is_empty()
            || request.rate_version <= 0
            || request.occurred_at_micros < 0
        {
            return Err(ManagedError::Conflict.into());
        }
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &request.logical.tenant_id).await?;
        if namespace.state != "ACTIVE" {
            return Err(ManagedError::NamespaceFenced.into());
        }
        let fence = ManagedRouteFence {
            namespace_epoch: u64_from_i64(namespace.epoch, "managed namespace epoch")?,
            routing_epoch: u64_from_i64(namespace.routing_epoch, "managed routing epoch")?,
        };
        let existing_operation =
            managed_logical_operation::Entity::find_by_id(request.operation_id)
                .lock(LockType::Update)
                .one(&txn)
                .await
                .map_err(persistence)?
                .map(logical_operation_from_model)
                .transpose()?;
        let mut usage = locked_workspace_usage(&txn, &request.logical.tenant_id).await?;
        let existing_model = managed_object_authority::Entity::find_by_id((
            request.logical.tenant_id.clone(),
            request.logical.bucket.clone(),
            request.logical.key.clone(),
        ))
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?;
        let existing = existing_model
            .clone()
            .map(authority_from_model)
            .transpose()?;
        let generation = existing
            .as_ref()
            .filter(|authority| authority.tombstone)
            .map_or_else(
                || Uuid::new_v5(&Uuid::NAMESPACE_URL, request.operation_id.as_bytes()),
                |authority| authority.generation,
            );
        let prior_logical_size = existing
            .as_ref()
            .filter(|authority| !authority.tombstone)
            .map_or(0, |authority| authority.size);
        let recipe = ManagedPublicationRecipe {
            version: MANAGED_PUBLICATION_RECIPE_VERSION,
            placement_version: request.placement.version,
            primary_backend_id: request.placement.primary_backend_id.clone(),
            replica_backend_id: request.placement.replica_backend_id.clone(),
            metadata: BTreeMap::new(),
            primary_status: CopyStatus::Absent,
            replica_status: CopyStatus::Absent,
        };
        let intent = ManagedLogicalOperationIntent {
            operation_id: request.operation_id,
            receipt_id: request.receipt_id,
            logical: request.logical.clone(),
            kind: ManagedMutationKind::Delete,
            generation,
            fence,
            expected_authority_cas: existing.as_ref().map(|authority| authority.cas_version),
            prior_logical_size,
            primary_child_operation_id: Uuid::new_v5(
                &Uuid::NAMESPACE_OID,
                request.operation_id.as_bytes(),
            ),
            backend_id: request.placement.primary_backend_id.clone(),
            provider_bucket: request.provider_bucket.clone(),
            physical_key: generation_physical_key(&request.logical, generation),
            occurred_at_ms: request.occurred_at_micros.div_euclid(1_000),
            rate_version: request.rate_version,
            route: UsageRoute::DeleteObject,
            request_kind: RequestKind::Write,
            max_processed_bytes: request.max_processed_bytes,
            publication_recipe: Some(recipe),
        };
        if let Some(operation) = existing_operation {
            if !delete_request_matches_operation(&request, &operation)
                || operation.state != ManagedLogicalOperationState::Committed
            {
                return Err(ManagedError::Conflict.into());
            }
            let authority = committed_delete_replay_authority(&operation, existing)?;
            txn.commit()
                .await
                .map_err(|error| ManagedDeleteError::CommitUnknown(persistence(error)))?;
            return Ok(ManagedOperationCommit {
                operation,
                authority,
                usage: workspace_usage_from_model(usage)?,
            });
        }
        if usage.active_operation_id.is_some() {
            return Err(ManagedError::MutationInProgress.into());
        }
        let now = crate::transaction::unix_time_ms();
        let authority = if existing
            .as_ref()
            .is_some_and(|authority| authority.tombstone)
        {
            existing.clone().ok_or(ManagedError::Conflict)?
        } else {
            let authority = ObjectAuthority {
                logical: request.logical.clone(),
                generation,
                digest: String::new(),
                size: 0,
                metadata: BTreeMap::new(),
                placement_version: request.placement.version,
                primary_backend_id: request.placement.primary_backend_id,
                primary_version_id: None,
                replica_backend_id: request.placement.replica_backend_id,
                primary_status: CopyStatus::Absent,
                replica_status: CopyStatus::Absent,
                tombstone: true,
                cas_version: existing
                    .as_ref()
                    .map_or(1, |authority| authority.cas_version.saturating_add(1)),
                created_at_ms: existing
                    .as_ref()
                    .map_or(now, |authority| authority.created_at_ms),
                updated_at_ms: now,
            };
            match existing_model {
                None => {
                    authority_active(&authority)?
                        .insert(&txn)
                        .await
                        .map_err(persistence)?;
                }
                Some(model) => {
                    let updated = managed_object_authority::Entity::update_many()
                        .set(authority_active(&authority)?)
                        .filter(
                            managed_object_authority::Column::TenantId
                                .eq(&request.logical.tenant_id),
                        )
                        .filter(
                            managed_object_authority::Column::Bucket.eq(&request.logical.bucket),
                        )
                        .filter(
                            managed_object_authority::Column::LogicalKey.eq(&request.logical.key),
                        )
                        .filter(managed_object_authority::Column::CasVersion.eq(model.cas_version))
                        .exec(&txn)
                        .await
                        .map_err(persistence)?;
                    if updated.rows_affected != 1 {
                        return Err(ManagedError::Conflict.into());
                    }
                }
            }
            authority
        };
        if let Some(previous) = existing.filter(|authority| !authority.tombstone) {
            for mut repair in cleanup_repairs(&previous) {
                let targets = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId
                            .eq(&repair.logical.tenant_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::BackendId
                            .eq(&repair.target_backend_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::PhysicalKey
                            .eq(&repair.physical_key),
                    )
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if targets > 0 {
                    repair.namespace_epoch = fence.namespace_epoch;
                    insert_repair(&txn, repair).await?;
                }
            }
        }
        let prior = i64_from_u64(prior_logical_size, "managed prior size")?;
        usage.visible_logical_bytes = usage
            .visible_logical_bytes
            .checked_sub(prior)
            .ok_or(ManagedError::Conflict)?;
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::VisibleLogicalBytes,
                Expr::value(usage.visible_logical_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_workspace_usage::Column::TenantId.eq(&request.logical.tenant_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        let evidence = ManagedUsageEvidence {
            expected_output_digest: None,
            expected_output_size: 0,
            source_bytes: 0,
            processed_bytes: 0,
            payload: serde_json::json!({
                "occurred_at_micros": request.occurred_at_micros,
            }),
        };
        let mut active = logical_operation_active(&intent, now)?;
        active.expected_output_size = Set(Some(0));
        active.source_bytes = Set(Some(0));
        active.processed_bytes = Set(Some(0));
        active.usage_evidence = Set(evidence.payload.clone());
        active.state = Set(ManagedLogicalOperationState::Committed.as_str().to_string());
        active.committed_authority_version = Set(Some(i64_from_u64(
            authority.cas_version,
            "managed authority CAS",
        )?));
        active.committed_at_ms = Set(Some(now));
        managed_logical_operation::Entity::insert(active)
            .exec_without_returning(&txn)
            .await
            .map_err(persistence)?;
        let operation = ManagedLogicalOperation {
            intent,
            evidence: Some(evidence),
            reserved_physical_bytes: 0,
            committed_physical_bytes: 0,
            released_physical_bytes: 0,
            state: ManagedLogicalOperationState::Committed,
            committed_authority_version: Some(authority.cas_version),
            settlement_state: ManagedSettlementState::Pending,
            last_error_class: None,
            recovery_owner: None,
            recovery_token: None,
            recovery_expires_at_ms: None,
            created_at_ms: now,
            updated_at_ms: now,
            committed_at_ms: Some(now),
            aborted_at_ms: None,
        };
        txn.commit()
            .await
            .map_err(|error| ManagedDeleteError::CommitUnknown(persistence(error)))?;
        Ok(ManagedOperationCommit {
            operation,
            authority,
            usage: workspace_usage_from_model(usage)?,
        })
    }

    async fn prove_logical_abort(
        &self,
        operation_id: Uuid,
        error_class: &str,
        physical: Option<ManagedProvenPhysicalAllocation>,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let operation = logical_operation_from_model(model)?;
        if operation.state == ManagedLogicalOperationState::ProvenAborted {
            txn.commit().await.map_err(persistence)?;
            return Ok(operation);
        }
        if operation.state == ManagedLogicalOperationState::Committed {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::ProvenAborted,
            });
        }
        let namespace = locked_namespace(&txn, &operation.intent.logical.tenant_id).await?;
        if u64_from_i64(namespace.epoch, "managed namespace epoch")?
            != operation.intent.fence.namespace_epoch
        {
            return Err(ManagedError::Conflict);
        }
        let child_versions = managed_physical_object_version::Entity::find()
            .filter(
                managed_physical_object_version::Column::WriteOperationId
                    .eq(operation.intent.primary_child_operation_id),
            )
            .filter(
                managed_physical_object_version::Column::TenantId
                    .eq(&operation.intent.logical.tenant_id),
            )
            .filter(
                managed_physical_object_version::Column::BackendId.eq(&operation.intent.backend_id),
            )
            .filter(
                managed_physical_object_version::Column::ProviderBucket
                    .eq(&operation.intent.provider_bucket),
            )
            .filter(
                managed_physical_object_version::Column::PhysicalKey
                    .eq(&operation.intent.physical_key),
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
        let allocated = match physical {
            None => {
                if child_versions != 0 {
                    return Err(ManagedError::Conflict);
                }
                0
            }
            Some(physical) => {
                let evidence = operation.evidence.as_ref().ok_or(ManagedError::Conflict)?;
                let derived = physical_allocation(physical.authority.size, child_versions)?;
                if child_versions == 0
                    || physical.authority.logical != operation.intent.logical
                    || physical.authority.generation != operation.intent.generation
                    || physical.authority.primary_backend_id != operation.intent.backend_id
                    || physical.authority.tombstone
                    || evidence.expected_output_size != physical.authority.size
                    || evidence.expected_output_digest.as_deref()
                        != Some(physical.authority.digest.as_str())
                    || physical.allocated_bytes != derived
                    || derived > operation.reserved_physical_bytes
                {
                    return Err(ManagedError::Conflict);
                }
                for mut repair in cleanup_repairs(&physical.authority) {
                    let targets = managed_physical_object_version::Entity::find()
                        .filter(
                            managed_physical_object_version::Column::TenantId
                                .eq(&repair.logical.tenant_id),
                        )
                        .filter(
                            managed_physical_object_version::Column::BackendId
                                .eq(&repair.target_backend_id),
                        )
                        .filter(
                            managed_physical_object_version::Column::PhysicalKey
                                .eq(&repair.physical_key),
                        )
                        .count(&txn)
                        .await
                        .map_err(persistence)?;
                    if targets > 0 {
                        repair.namespace_epoch = operation.intent.fence.namespace_epoch;
                        insert_repair(&txn, repair).await?;
                    }
                }
                derived
            }
        };
        let mut usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
        if operation.state != ManagedLogicalOperationState::Intent
            && usage.active_operation_id != Some(operation_id)
        {
            return Err(ManagedError::Conflict);
        }
        let reserved = i64_from_u64(
            operation.reserved_physical_bytes,
            "managed physical reservation",
        )?;
        let allocated = i64_from_u64(allocated, "managed physical allocation")?;
        usage.reserved_bytes = usage
            .reserved_bytes
            .checked_sub(reserved)
            .ok_or(ManagedError::Conflict)?;
        usage.physical_allocated_bytes = usage
            .physical_allocated_bytes
            .checked_add(allocated)
            .ok_or(ManagedError::QuotaExceeded)?;
        if usage.active_operation_id == Some(operation_id) {
            usage.active_operation_id = None;
        }
        let now = crate::transaction::unix_time_ms();
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::ReservedBytes,
                Expr::value(usage.reserved_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::PhysicalAllocatedBytes,
                Expr::value(usage.physical_allocated_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(usage.active_operation_id),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(
                managed_workspace_usage::Column::TenantId.eq(&operation.intent.logical.tenant_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::ProvenAborted.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::CommittedPhysicalBytes,
                Expr::value(allocated),
            )
            .col_expr(
                managed_logical_operation::Column::SettlementState,
                Expr::value(ManagedSettlementState::Released.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::LastErrorClass,
                Expr::value(Some(error_class.chars().take(128).collect::<String>())),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .col_expr(
                managed_logical_operation::Column::AbortedAtMs,
                Expr::value(Some(now)),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        let aborted = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(logical_operation_from_model)?;
        txn.commit().await.map_err(persistence)?;
        Ok(aborted)
    }

    async fn abort_logical_put(
        &self,
        operation_id: Uuid,
        physical_lease: Option<&PhysicalWriteLease>,
        proof: LogicalAbortProof,
        error_class: &str,
        recovery_claim: Option<&ManagedRecoveryClaim>,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        let identity = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        // All managed mutation transactions lock namespace -> logical -> usage
        // and current authority/physical intent last.
        let namespace = locked_namespace(&txn, &identity.tenant_id).await?;
        let model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let operation = logical_operation_from_model(model)?;
        if operation.state == ManagedLogicalOperationState::ProvenAborted {
            txn.commit().await.map_err(persistence)?;
            return Ok(operation);
        }
        let now = crate::transaction::unix_time_ms();
        validate_recovery_authority(&operation, recovery_claim, now)?;
        if operation.intent.kind != ManagedMutationKind::Put
            || operation.state == ManagedLogicalOperationState::Committed
        {
            return Err(ManagedError::Conflict);
        }
        if namespace.epoch
            != i64_from_u64(
                operation.intent.fence.namespace_epoch,
                "managed namespace epoch",
            )?
        {
            return Err(ManagedError::RecoveryBlocked("namespace_fence_changed"));
        }
        let mut usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
        let intent = managed_physical_write_intent::Entity::find_by_id(
            operation.intent.primary_child_operation_id,
        )
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?;
        let child_versions = managed_physical_object_version::Entity::find()
            .filter(
                managed_physical_object_version::Column::WriteOperationId
                    .eq(operation.intent.primary_child_operation_id),
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
        if child_versions != 0 {
            return Err(ManagedError::Conflict);
        }
        let child_journal =
            object_operation::Entity::find_by_id(operation.intent.primary_child_operation_id)
                .lock(LockType::Update)
                .one(&txn)
                .await
                .map_err(persistence)?;
        let child_proves_absence = child_journal.as_ref().is_some_and(|child| {
            child.state == "PROVEN_ABORTED"
                && child.exact_absence_observed_at_ms.is_some()
                && child.tenant_id.as_deref() == Some(operation.intent.logical.tenant_id.as_str())
                && child.namespace_epoch
                    == i64::try_from(operation.intent.fence.namespace_epoch).ok()
                && child.backend_id == operation.intent.backend_id
                && child.bucket == operation.intent.provider_bucket
                && child.logical_key == operation.intent.logical.object_key()
                && child.physical_key == operation.intent.physical_key
                && operation.evidence.as_ref().is_none_or(|evidence| {
                    child.expected_digest == evidence.expected_output_digest
                        && child.expected_size == i64::try_from(evidence.expected_output_size).ok()
                })
        });
        match (
            proof,
            physical_lease,
            intent.as_ref(),
            child_journal.as_ref(),
        ) {
            (LogicalAbortProof::NoChildStarted, None, None, None)
                if matches!(
                    operation.state,
                    ManagedLogicalOperationState::Intent | ManagedLogicalOperationState::Open
                ) => {}
            (LogicalAbortProof::NoChildStarted, Some(lease), Some(intent), None)
                if lease.intent_id == operation.intent.primary_child_operation_id
                    && intent.lease_owner == lease.owner
                    && intent.lease_token == lease.token
                    && intent.lease_expires_at_ms > now
                    && lease.namespace_epoch == operation.intent.fence.namespace_epoch => {}
            (LogicalAbortProof::ChildProvenAborted, Some(lease), Some(intent), Some(_))
                if child_proves_absence
                    && lease.intent_id == operation.intent.primary_child_operation_id
                    && intent.lease_owner == lease.owner
                    && intent.lease_token == lease.token
                    && intent.lease_expires_at_ms > now
                    && lease.namespace_epoch == operation.intent.fence.namespace_epoch => {}
            _ => return Err(ManagedError::Conflict),
        }
        if operation.state != ManagedLogicalOperationState::Intent
            && usage.active_operation_id != Some(operation_id)
        {
            return Err(ManagedError::Conflict);
        }
        let reserved = i64_from_u64(
            operation.reserved_physical_bytes,
            "managed physical reservation",
        )?;
        usage.reserved_bytes = usage
            .reserved_bytes
            .checked_sub(reserved)
            .ok_or(ManagedError::Conflict)?;
        if usage.active_operation_id == Some(operation_id) {
            usage.active_operation_id = None;
        }
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::ReservedBytes,
                Expr::value(usage.reserved_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(usage.active_operation_id),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(
                managed_workspace_usage::Column::TenantId.eq(&operation.intent.logical.tenant_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::ProvenAborted.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::SettlementState,
                Expr::value(ManagedSettlementState::Released.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::LastErrorClass,
                Expr::value(Some(error_class.chars().take(128).collect::<String>())),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .col_expr(
                managed_logical_operation::Column::AbortedAtMs,
                Expr::value(Some(now)),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if intent.is_some() {
            let deleted = managed_physical_write_intent::Entity::delete_by_id(
                operation.intent.primary_child_operation_id,
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
            if deleted.rows_affected != 1 {
                return Err(ManagedError::Conflict);
            }
        }
        let aborted = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(logical_operation_from_model)?;
        txn.commit().await.map_err(persistence)?;
        Ok(aborted)
    }

    async fn workspace_usage(
        &self,
        tenant_id: &str,
    ) -> Result<Option<ManagedWorkspaceUsage>, ManagedError> {
        managed_workspace_usage::Entity::find_by_id(tenant_id.to_string())
            .one(&self.db)
            .await
            .map_err(persistence)?
            .map(workspace_usage_from_model)
            .transpose()
    }

    async fn list_authority(
        &self,
        query: AuthorityListQuery,
    ) -> Result<AuthorityListPage, ManagedError> {
        if query.max_keys > MANAGED_AUTHORITY_LIST_MAX_KEYS {
            return Err(ManagedError::Conflict);
        }
        if query.max_keys == 0 {
            return Ok(AuthorityListPage {
                objects: Vec::new(),
                next_after: None,
            });
        }
        self.assert_namespace_active(&query.tenant_id).await?;
        let mut select = managed_object_authority::Entity::find()
            .filter(managed_object_authority::Column::TenantId.eq(&query.tenant_id))
            .filter(managed_object_authority::Column::Bucket.eq(&query.bucket))
            .filter(managed_object_authority::Column::Tombstone.eq(false))
            .filter(sea_orm::sea_query::SimpleExpr::from(PgFunc::starts_with(
                Expr::col((
                    managed_object_authority::Entity,
                    managed_object_authority::Column::LogicalKey,
                )),
                query.prefix.clone(),
            )))
            .order_by_asc(managed_object_authority::Column::LogicalKey)
            .limit(query.max_keys.saturating_add(1));
        if let Some(after) = &query.after {
            select = select.filter(managed_object_authority::Column::LogicalKey.gt(after));
        }
        let mut objects = select
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(authority_from_model)
            .collect::<Result<Vec<_>, _>>()?;
        let next_after = (objects.len() as u64 > query.max_keys)
            .then(|| objects[query.max_keys as usize - 1].logical.key.clone());
        objects.truncate(query.max_keys as usize);
        Ok(AuthorityListPage {
            objects,
            next_after,
        })
    }

    async fn list_authority_below_placement_version(
        &self,
        query: AuthorityPlacementPageQuery,
    ) -> Result<AuthorityPlacementPage, ManagedError> {
        if query.limit > MANAGED_AUTHORITY_LIST_MAX_KEYS || query.target_placement_version == 0 {
            return Err(ManagedError::Conflict);
        }
        if query.limit == 0 {
            return Ok(AuthorityPlacementPage {
                objects: Vec::new(),
                next_after: None,
            });
        }
        let mut select = managed_object_authority::Entity::find()
            .filter(managed_object_authority::Column::Tombstone.eq(false))
            .filter(
                managed_object_authority::Column::PlacementVersion
                    .lt(i64::from(query.target_placement_version)),
            )
            .order_by_asc(managed_object_authority::Column::TenantId)
            .order_by_asc(managed_object_authority::Column::Bucket)
            .order_by_asc(managed_object_authority::Column::LogicalKey)
            .limit(query.limit.saturating_add(1));
        if let Some(after) = &query.after {
            select = select.filter(
                Condition::any()
                    .add(managed_object_authority::Column::TenantId.gt(&after.tenant_id))
                    .add(
                        Condition::all()
                            .add(managed_object_authority::Column::TenantId.eq(&after.tenant_id))
                            .add(managed_object_authority::Column::Bucket.gt(&after.bucket)),
                    )
                    .add(
                        Condition::all()
                            .add(managed_object_authority::Column::TenantId.eq(&after.tenant_id))
                            .add(managed_object_authority::Column::Bucket.eq(&after.bucket))
                            .add(managed_object_authority::Column::LogicalKey.gt(&after.key)),
                    ),
            );
        }
        let mut objects = select
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(authority_from_model)
            .collect::<Result<Vec<_>, _>>()?;
        let next_after = (objects.len() as u64 > query.limit).then(|| {
            let authority = &objects[query.limit as usize - 1];
            AuthorityPlacementCursor {
                tenant_id: authority.logical.tenant_id.clone(),
                bucket: authority.logical.bucket.clone(),
                key: authority.logical.key.clone(),
            }
        });
        objects.truncate(query.limit as usize);
        Ok(AuthorityPlacementPage {
            objects,
            next_after,
        })
    }

    async fn authority_placement_stats(
        &self,
        target_placement_version: u32,
    ) -> Result<AuthorityPlacementStats, ManagedError> {
        if target_placement_version == 0 {
            return Err(ManagedError::Conflict);
        }
        let remaining = managed_object_authority::Entity::find()
            .filter(managed_object_authority::Column::Tombstone.eq(false))
            .filter(
                managed_object_authority::Column::PlacementVersion
                    .lt(i64::from(target_placement_version)),
            )
            .count(&self.db)
            .await
            .map_err(persistence)?;
        let oldest_updated_at_ms = managed_object_authority::Entity::find()
            .filter(managed_object_authority::Column::Tombstone.eq(false))
            .filter(
                managed_object_authority::Column::PlacementVersion
                    .lt(i64::from(target_placement_version)),
            )
            .order_by_asc(managed_object_authority::Column::UpdatedAtMs)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .map(|model| model.updated_at_ms);
        Ok(AuthorityPlacementStats {
            remaining,
            oldest_updated_at_ms,
        })
    }

    async fn create_list_cursor(
        &self,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let response_state = serialize_cursor_response_state(&request.response_state)?;
        let response_state_bytes = response_state.len() as u64;
        let txn = self
            .db
            .begin_with_config(Some(IsolationLevel::Serializable), None)
            .await
            .map_err(persistence)?;
        let namespace = locked_namespace(&txn, &request.binding.tenant_id).await?;
        if namespace.state != "ACTIVE" {
            return Err(ManagedError::NamespaceFenced);
        }
        let fence = ManagedRouteFence {
            namespace_epoch: u64_from_i64(namespace.epoch, "managed list cursor namespace epoch")?,
            routing_epoch: u64_from_i64(
                namespace.routing_epoch,
                "managed list cursor routing epoch",
            )?,
        };
        let workspace_count = managed_list_cursor::Entity::find()
            .filter(managed_list_cursor::Column::TenantId.eq(&request.binding.tenant_id))
            .filter(managed_list_cursor::Column::ExpiresAtMs.gt(now_ms))
            .count(&txn)
            .await
            .map_err(persistence)?;
        let global_count = managed_list_cursor::Entity::find()
            .filter(managed_list_cursor::Column::ExpiresAtMs.gt(now_ms))
            .count(&txn)
            .await
            .map_err(persistence)?;
        let workspace_cursor_bytes: Vec<i64> = managed_list_cursor::Entity::find()
            .select_only()
            .column(managed_list_cursor::Column::ResponseStateBytes)
            .filter(managed_list_cursor::Column::TenantId.eq(&request.binding.tenant_id))
            .filter(managed_list_cursor::Column::ExpiresAtMs.gt(now_ms))
            .into_tuple()
            .all(&txn)
            .await
            .map_err(persistence)?;
        let global_cursor_bytes: Vec<i64> = managed_list_cursor::Entity::find()
            .select_only()
            .column(managed_list_cursor::Column::ResponseStateBytes)
            .filter(managed_list_cursor::Column::ExpiresAtMs.gt(now_ms))
            .into_tuple()
            .all(&txn)
            .await
            .map_err(persistence)?;
        let workspace_bytes =
            workspace_cursor_bytes
                .into_iter()
                .try_fold(0_u64, |total, value| {
                    total
                        .checked_add(u64_from_i64(value, "managed workspace cursor bytes")?)
                        .ok_or(ManagedError::CursorLimitExceeded)
                })?;
        let global_bytes = global_cursor_bytes
            .into_iter()
            .try_fold(0_u64, |total, value| {
                total
                    .checked_add(u64_from_i64(value, "managed global cursor bytes")?)
                    .ok_or(ManagedError::CursorLimitExceeded)
            })?;
        if workspace_count >= MANAGED_LIST_CURSOR_WORKSPACE_LIMIT
            || global_count >= MANAGED_LIST_CURSOR_GLOBAL_LIMIT
            || workspace_bytes
                .checked_add(response_state_bytes)
                .is_none_or(|bytes| bytes > MANAGED_LIST_CURSOR_WORKSPACE_MAX_BYTES)
            || global_bytes
                .checked_add(response_state_bytes)
                .is_none_or(|bytes| bytes > MANAGED_LIST_CURSOR_GLOBAL_MAX_BYTES)
        {
            return Err(ManagedError::CursorLimitExceeded);
        }
        let cursor_id = Uuid::new_v4();
        let expires_at_ms = now_ms.saturating_add(MANAGED_LIST_CURSOR_TTL_MS);
        let model = managed_list_cursor::ActiveModel {
            cursor_id: Set(cursor_id),
            predecessor_cursor_id: Set(None),
            tenant_id: Set(request.binding.tenant_id),
            namespace_epoch: Set(i64_from_u64(
                fence.namespace_epoch,
                "managed list cursor namespace epoch",
            )?),
            routing_epoch: Set(i64_from_u64(
                fence.routing_epoch,
                "managed list cursor routing epoch",
            )?),
            bucket: Set(request.binding.bucket),
            prefix: Set(request.binding.prefix),
            delimiter: Set(request.binding.delimiter),
            list_version: Set(request.binding.version.as_str().to_string()),
            last_key: Set(request.position.last_key),
            last_common_prefix: Set(request.position.last_common_prefix),
            response_state: Set(response_state),
            response_state_bytes: Set(i64_from_u64(
                response_state_bytes,
                "managed list cursor response bytes",
            )?),
            final_page: Set(request.final_page),
            state: Set("ACTIVE".to_string()),
            created_at_ms: Set(now_ms),
            expires_at_ms: Set(expires_at_ms),
            first_used_at_ms: Set(None),
        }
        .insert(&txn)
        .await
        .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        list_cursor_from_model(model)
    }

    async fn create_list_cursor_successor(
        &self,
        predecessor_cursor_id: Uuid,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let existing = || async {
            managed_list_cursor::Entity::find()
                .filter(managed_list_cursor::Column::PredecessorCursorId.eq(predecessor_cursor_id))
                .one(&self.db)
                .await
                .map_err(persistence)?
                .map(list_cursor_from_model)
                .transpose()
        };
        if let Some(cursor) = existing().await? {
            if cursor.expires_at_ms <= now_ms
                || cursor.fence != self.route_fence(&cursor.binding.tenant_id).await?
            {
                return Err(ManagedError::CursorExpired);
            }
            return cursor_matches_request(&cursor, &request)
                .then_some(cursor)
                .ok_or(ManagedError::Conflict);
        }

        let created = self.create_list_cursor(request.clone(), now_ms).await?;
        let linked = managed_list_cursor::Entity::update_many()
            .col_expr(
                managed_list_cursor::Column::PredecessorCursorId,
                Expr::value(Some(predecessor_cursor_id)),
            )
            .filter(managed_list_cursor::Column::CursorId.eq(created.id))
            .filter(managed_list_cursor::Column::PredecessorCursorId.is_null())
            .exec(&self.db)
            .await;
        if linked
            .as_ref()
            .is_ok_and(|result| result.rows_affected == 1)
        {
            return Ok(created);
        }
        let _ = self.delete_list_cursor(created.id).await;
        let cursor = existing().await?.ok_or_else(|| {
            linked
                .err()
                .map(persistence)
                .unwrap_or(ManagedError::Conflict)
        })?;
        if cursor.expires_at_ms <= now_ms
            || cursor.fence != self.route_fence(&cursor.binding.tenant_id).await?
        {
            return Err(ManagedError::CursorExpired);
        }
        cursor_matches_request(&cursor, &request)
            .then_some(cursor)
            .ok_or(ManagedError::Conflict)
    }

    async fn use_list_cursor(
        &self,
        cursor_id: Uuid,
        binding: &ManagedListCursorBinding,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let model = managed_list_cursor::Entity::find_by_id(cursor_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::CursorExpired)?;
        let mut cursor = list_cursor_from_model(model)?;
        if cursor.expires_at_ms <= now_ms {
            managed_list_cursor::Entity::delete_by_id(cursor_id)
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Err(ManagedError::CursorExpired);
        }
        let namespace = managed_namespace::Entity::find_by_id(cursor.binding.tenant_id.clone())
            .lock(LockType::Share)
            .one(&txn)
            .await
            .map_err(persistence)?;
        if namespace
            .as_ref()
            .is_none_or(|namespace| namespace.state != "ACTIVE")
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let namespace = namespace.expect("active namespace checked above");
        if u64_from_i64(namespace.epoch, "managed namespace epoch")? != cursor.fence.namespace_epoch
            || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                != cursor.fence.routing_epoch
        {
            managed_list_cursor::Entity::delete_by_id(cursor_id)
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Err(ManagedError::CursorExpired);
        }
        if &cursor.binding != binding {
            return Err(ManagedError::CursorQueryMismatch);
        }
        if cursor.state == ManagedListCursorState::Active {
            managed_list_cursor::Entity::update_many()
                .col_expr(managed_list_cursor::Column::State, Expr::value("USED"))
                .col_expr(
                    managed_list_cursor::Column::FirstUsedAtMs,
                    Expr::value(Some(now_ms)),
                )
                .filter(managed_list_cursor::Column::CursorId.eq(cursor_id))
                .filter(managed_list_cursor::Column::State.eq("ACTIVE"))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            cursor.state = ManagedListCursorState::Used;
            cursor.first_used_at_ms = Some(now_ms);
        }
        txn.commit().await.map_err(persistence)?;
        Ok(cursor)
    }

    async fn delete_list_cursor(&self, cursor_id: Uuid) -> Result<(), ManagedError> {
        managed_list_cursor::Entity::delete_by_id(cursor_id)
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        Ok(())
    }

    async fn cleanup_expired_list_cursors(
        &self,
        now_ms: i64,
        limit: u64,
    ) -> Result<u64, ManagedError> {
        let ids: Vec<_> = managed_list_cursor::Entity::find()
            .filter(managed_list_cursor::Column::ExpiresAtMs.lte(now_ms))
            .order_by_asc(managed_list_cursor::Column::ExpiresAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(|cursor| cursor.cursor_id)
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }
        let result = managed_list_cursor::Entity::delete_many()
            .filter(managed_list_cursor::Column::CursorId.is_in(ids))
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        Ok(result.rows_affected)
    }

    async fn begin_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
    ) -> Result<u64, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let epoch = require_active_namespace(&txn, tenant_id).await?;
        let now = crate::transaction::unix_time_ms();
        managed_multipart_activity::ActiveModel {
            upload_id: Set(upload_id.to_string()),
            tenant_id: Set(tenant_id.to_string()),
            namespace_epoch: Set(epoch),
            state: Set("REGISTERING".to_string()),
            registration_expires_at_ms: Set(Some(now.saturating_add(10 * 60 * 1000))),
            created_at_ms: Set(now),
            updated_at_ms: Set(now),
        }
        .insert(&txn)
        .await
        .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        u64::try_from(epoch)
            .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))
    }

    async fn assert_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
        allow_purging: bool,
    ) -> Result<(), ManagedError> {
        let epoch = i64::try_from(namespace_epoch).map_err(|_| ManagedError::Conflict)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, tenant_id).await?;
        if namespace.epoch != epoch
            || (namespace.state != "ACTIVE" && !(allow_purging && namespace.state == "PURGING"))
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let activity = managed_multipart_activity::Entity::find_by_id(upload_id.to_string())
            .one(&txn)
            .await
            .map_err(persistence)?;
        if activity.is_none_or(|activity| {
            activity.tenant_id != tenant_id
                || activity.namespace_epoch != epoch
                || activity.state != "ACTIVE"
        }) {
            return Err(ManagedError::NamespaceFenced);
        }
        txn.commit().await.map_err(persistence)
    }

    async fn confirm_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        let epoch = i64::try_from(namespace_epoch).map_err(|_| ManagedError::Conflict)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, tenant_id).await?;
        if namespace.state != "ACTIVE" || namespace.epoch != epoch {
            return Err(ManagedError::NamespaceFenced);
        }
        if let Some(existing) =
            managed_multipart_activity::Entity::find_by_id(upload_id.to_string())
                .one(&txn)
                .await
                .map_err(persistence)?
            && existing.tenant_id == tenant_id
            && existing.namespace_epoch == epoch
            && existing.state == "ACTIVE"
        {
            txn.commit().await.map_err(persistence)?;
            return Ok(());
        }
        let result = managed_multipart_activity::Entity::update_many()
            .col_expr(
                managed_multipart_activity::Column::State,
                Expr::value("ACTIVE"),
            )
            .col_expr(
                managed_multipart_activity::Column::RegistrationExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                managed_multipart_activity::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(managed_multipart_activity::Column::UploadId.eq(upload_id))
            .filter(managed_multipart_activity::Column::TenantId.eq(tenant_id))
            .filter(managed_multipart_activity::Column::NamespaceEpoch.eq(epoch))
            .filter(managed_multipart_activity::Column::State.eq("REGISTERING"))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::NamespaceFenced);
        }
        txn.commit().await.map_err(persistence)
    }

    async fn reconcile_multipart_activities(&self, limit: u64) -> Result<u64, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let candidates = managed_multipart_activity::Entity::find()
            .filter(managed_multipart_activity::Column::State.eq("REGISTERING"))
            .filter(managed_multipart_activity::Column::RegistrationExpiresAtMs.lte(now))
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?;
        let count = candidates.len() as u64;
        for activity in candidates {
            let upload = crate::entity::multipart_upload::Entity::find()
                .filter(crate::entity::multipart_upload::Column::UploadId.eq(&activity.upload_id))
                .filter(crate::entity::multipart_upload::Column::TenantId.eq(&activity.tenant_id))
                .filter(
                    crate::entity::multipart_upload::Column::NamespaceEpoch
                        .eq(activity.namespace_epoch),
                )
                .one(&self.db)
                .await
                .map_err(persistence)?;
            if upload.is_some() {
                managed_multipart_activity::Entity::update_many()
                    .col_expr(
                        managed_multipart_activity::Column::State,
                        Expr::value("ACTIVE"),
                    )
                    .col_expr(
                        managed_multipart_activity::Column::RegistrationExpiresAtMs,
                        Expr::value(Option::<i64>::None),
                    )
                    .filter(managed_multipart_activity::Column::UploadId.eq(&activity.upload_id))
                    .filter(managed_multipart_activity::Column::State.eq("REGISTERING"))
                    .exec(&self.db)
                    .await
                    .map_err(persistence)?;
            } else {
                managed_multipart_activity::Entity::delete_many()
                    .filter(managed_multipart_activity::Column::UploadId.eq(&activity.upload_id))
                    .filter(managed_multipart_activity::Column::State.eq("REGISTERING"))
                    .filter(managed_multipart_activity::Column::RegistrationExpiresAtMs.lte(now))
                    .exec(&self.db)
                    .await
                    .map_err(persistence)?;
            }
        }
        Ok(count)
    }

    async fn finish_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        let epoch = i64::try_from(namespace_epoch).map_err(|_| ManagedError::Conflict)?;
        managed_multipart_activity::Entity::delete_many()
            .filter(managed_multipart_activity::Column::UploadId.eq(upload_id))
            .filter(managed_multipart_activity::Column::TenantId.eq(tenant_id))
            .filter(managed_multipart_activity::Column::NamespaceEpoch.eq(epoch))
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        Ok(())
    }

    async fn any_authority(&self) -> Result<bool, ManagedError> {
        Ok(managed_object_authority::Entity::find()
            .limit(1)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .is_some())
    }

    async fn get(
        &self,
        logical: &LogicalObjectKey,
    ) -> Result<Option<ObjectAuthority>, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        require_active_namespace(&txn, &logical.tenant_id).await?;
        let authority = managed_object_authority::Entity::find_by_id((
            logical.tenant_id.clone(),
            logical.bucket.clone(),
            logical.key.clone(),
        ))
        .one(&txn)
        .await
        .map_err(persistence)?
        .map(authority_from_model)
        .transpose()?;
        txn.commit().await.map_err(persistence)?;
        Ok(authority)
    }

    async fn publish(
        &self,
        mut authority: ObjectAuthority,
        expected_cas: Option<u64>,
    ) -> Result<ObjectAuthority, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace_epoch = require_active_namespace(&txn, &authority.logical.tenant_id).await?;
        if !authority.tombstone {
            let physical_key = generation_physical_key(&authority.logical, authority.generation);
            let primary_versions = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::TenantId
                        .eq(&authority.logical.tenant_id),
                )
                .filter(
                    managed_physical_object_version::Column::BackendId
                        .eq(&authority.primary_backend_id),
                )
                .filter(managed_physical_object_version::Column::PhysicalKey.eq(&physical_key))
                .count(&txn)
                .await
                .map_err(persistence)?;
            if primary_versions == 0 {
                return Err(ManagedError::Persistence(
                    "managed primary cannot publish before its physical versions are ledgered"
                        .to_string(),
                ));
            }
            if authority.replica_status == CopyStatus::Ready
                && let Some(replica) = &authority.replica_backend_id
            {
                let replica_versions = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId
                            .eq(&authority.logical.tenant_id),
                    )
                    .filter(managed_physical_object_version::Column::BackendId.eq(replica))
                    .filter(managed_physical_object_version::Column::PhysicalKey.eq(&physical_key))
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if replica_versions == 0 {
                    return Err(ManagedError::Persistence(
                        "managed replica cannot publish before its physical versions are ledgered"
                            .to_string(),
                    ));
                }
            }
        }
        let existing = managed_object_authority::Entity::find_by_id((
            authority.logical.tenant_id.clone(),
            authority.logical.bucket.clone(),
            authority.logical.key.clone(),
        ))
        .one(&txn)
        .await
        .map_err(persistence)?
        .map(authority_from_model)
        .transpose()?;
        if existing.as_ref().map(|value| value.cas_version) != expected_cas {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        authority.cas_version = expected_cas.unwrap_or(0).saturating_add(1);
        authority.created_at_ms = existing.as_ref().map_or(now, |value| value.created_at_ms);
        authority.updated_at_ms = now;
        match expected_cas {
            None => {
                authority_active(&authority)?
                    .insert(&txn)
                    .await
                    .map_err(|_| ManagedError::Conflict)?;
            }
            Some(expected) => {
                let active = authority_active(&authority)?;
                let result = managed_object_authority::Entity::update_many()
                    .set(active)
                    .filter(
                        managed_object_authority::Column::TenantId.eq(&authority.logical.tenant_id),
                    )
                    .filter(managed_object_authority::Column::Bucket.eq(&authority.logical.bucket))
                    .filter(managed_object_authority::Column::LogicalKey.eq(&authority.logical.key))
                    .filter(
                        managed_object_authority::Column::CasVersion
                            .eq(i64::try_from(expected).map_err(|_| ManagedError::Conflict)?),
                    )
                    .exec(&txn)
                    .await
                    .map_err(persistence)?;
                if result.rows_affected != 1 {
                    return Err(ManagedError::Conflict);
                }
            }
        }
        for mut repair in publication_repairs(&authority) {
            repair.namespace_epoch = u64::try_from(namespace_epoch)
                .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))?;
            insert_repair(&txn, repair).await?;
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                let targets = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId
                            .eq(&repair.logical.tenant_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::BackendId
                            .eq(&repair.target_backend_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::PhysicalKey
                            .eq(&repair.physical_key),
                    )
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if targets == 0 {
                    continue;
                }
                repair.namespace_epoch = u64::try_from(namespace_epoch)
                    .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))?;
                insert_repair(&txn, repair).await?;
            }
        }
        txn.commit().await.map_err(persistence)?;
        Ok(authority)
    }

    async fn record_placement_policy(
        &self,
        policy: &ManagedPlacementPolicy,
    ) -> Result<bool, ManagedError> {
        let version = i32::try_from(policy.version).map_err(|_| {
            ManagedError::Corrupt("placement policy version exceeds INTEGER".to_string())
        })?;
        let facts_json = serde_json::to_string(&policy.backend_facts).map_err(|error| {
            ManagedError::Corrupt(format!("placement policy facts serialize: {error}"))
        })?;
        managed_placement_policy_version::Entity::insert(
            managed_placement_policy_version::ActiveModel {
                version: Set(version),
                fingerprint: Set(policy.fingerprint.clone()),
                backend_facts: Set(facts_json),
                activated_at_ms: Set(policy.activated_at_ms),
            },
        )
        .on_conflict(
            OnConflict::column(managed_placement_policy_version::Column::Version)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(&self.db)
        .await
        .map_err(persistence)?;
        let existing = managed_placement_policy_version::Entity::find_by_id(version)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .ok_or_else(|| {
                ManagedError::Persistence("placement policy insert did not persist".to_string())
            })?;
        Ok(existing.fingerprint == policy.fingerprint)
    }

    async fn advance_placement_version(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: u64,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        require_active_namespace(&txn, &logical.tenant_id).await?;
        let authority = managed_object_authority::Entity::find_by_id((
            logical.tenant_id.clone(),
            logical.bucket.clone(),
            logical.key.clone(),
        ))
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?
        .map(authority_from_model)
        .transpose()?
        .ok_or(ManagedError::Conflict)?;
        let locations_match = authority.primary_backend_id == placement.primary_backend_id
            && authority.primary_status == CopyStatus::Ready
            && match placement.replica_backend_id.as_deref() {
                Some(replica) => {
                    authority.replica_backend_id.as_deref() == Some(replica)
                        && authority.replica_status == CopyStatus::Ready
                }
                None => {
                    authority.replica_backend_id.is_none()
                        && authority.replica_status == CopyStatus::Absent
                }
            };
        if authority.tombstone
            || authority.cas_version != expected_cas
            || placement.version <= authority.placement_version
            || !locations_match
        {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        let result = managed_object_authority::Entity::update_many()
            .col_expr(
                managed_object_authority::Column::PlacementVersion,
                Expr::value(i64::from(placement.version)),
            )
            .col_expr(
                managed_object_authority::Column::CasVersion,
                Expr::value(i64::try_from(expected_cas.saturating_add(1)).map_err(|_| {
                    ManagedError::Corrupt("authority CAS exceeds BIGINT".to_string())
                })?),
            )
            .col_expr(
                managed_object_authority::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_object_authority::Column::TenantId.eq(&logical.tenant_id))
            .filter(managed_object_authority::Column::Bucket.eq(&logical.bucket))
            .filter(managed_object_authority::Column::LogicalKey.eq(&logical.key))
            .filter(
                managed_object_authority::Column::CasVersion
                    .eq(i64::try_from(expected_cas).map_err(|_| ManagedError::Conflict)?),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        let advanced = managed_object_authority::Entity::find_by_id((
            logical.tenant_id.clone(),
            logical.bucket.clone(),
            logical.key.clone(),
        ))
        .one(&txn)
        .await
        .map_err(persistence)?
        .ok_or(ManagedError::Conflict)
        .and_then(authority_from_model)?;
        txn.commit().await.map_err(persistence)?;
        Ok(advanced)
    }

    async fn tombstone(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: Option<u64>,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError> {
        let existing = self.get(logical).await?;
        if existing.as_ref().map(|value| value.cas_version) != expected_cas {
            return Err(ManagedError::Conflict);
        }
        let generation = Uuid::now_v7();
        let now = crate::transaction::unix_time_ms();
        let tombstone = ObjectAuthority {
            logical: logical.clone(),
            generation,
            digest: String::new(),
            size: 0,
            metadata: BTreeMap::new(),
            placement_version: placement.version,
            primary_backend_id: placement.primary_backend_id.clone(),
            primary_version_id: None,
            replica_backend_id: placement.replica_backend_id.clone(),
            primary_status: CopyStatus::Absent,
            replica_status: CopyStatus::Absent,
            tombstone: true,
            cas_version: 0,
            created_at_ms: now,
            updated_at_ms: now,
        };
        self.publish(tombstone, expected_cas).await
    }

    async fn enqueue(&self, mut repair: RepairRecord) -> Result<(), ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace_epoch = require_active_namespace(&txn, &repair.logical.tenant_id).await?;
        let current = managed_object_authority::Entity::find_by_id((
            repair.logical.tenant_id.clone(),
            repair.logical.bucket.clone(),
            repair.logical.key.clone(),
        ))
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?
        .map(authority_from_model)
        .transpose()?;
        if repair.kind == RepairKind::DeleteGeneration {
            let targets = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::TenantId.eq(&repair.logical.tenant_id),
                )
                .filter(
                    managed_physical_object_version::Column::BackendId
                        .eq(&repair.target_backend_id),
                )
                .filter(
                    managed_physical_object_version::Column::PhysicalKey.eq(&repair.physical_key),
                )
                .all(&txn)
                .await
                .map_err(persistence)?;
            if targets.is_empty() {
                txn.commit().await.map_err(persistence)?;
                return Ok(());
            }
            if targets.iter().any(|target| target.epoch != namespace_epoch) {
                return Err(ManagedError::Conflict);
            }
        } else if current.as_ref().is_none_or(|authority| {
            authority.generation != repair.generation
                || authority.cas_version != repair.authority_cas_version
        }) {
            return Err(ManagedError::Conflict);
        }
        repair.namespace_epoch = u64::try_from(namespace_epoch)
            .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))?;
        insert_repair(&txn, repair).await?;
        txn.commit().await.map_err(persistence)
    }

    async fn claim_repairs(
        &self,
        owner: &str,
        lease_until_ms: i64,
        limit: u64,
    ) -> Result<Vec<RepairRecord>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let candidates = managed_object_repair::Entity::find()
            .filter(
                Condition::any()
                    .add(
                        Condition::all()
                            .add(managed_object_repair::Column::State.eq("PENDING"))
                            .add(managed_object_repair::Column::NotBeforeMs.lte(now)),
                    )
                    .add(
                        Condition::all()
                            .add(managed_object_repair::Column::State.eq("LEASED"))
                            .add(managed_object_repair::Column::LeaseExpiresAtMs.lte(now)),
                    ),
            )
            .order_by_asc(managed_object_repair::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?;
        let mut claimed = Vec::new();
        for candidate in candidates {
            let txn = self.db.begin().await.map_err(persistence)?;
            match require_active_namespace(&txn, &candidate.tenant_id).await {
                Ok(epoch) if epoch == candidate.namespace_epoch => {}
                Ok(_) => continue,
                Err(ManagedError::NamespaceFenced) => continue,
                Err(error) => return Err(error),
            }
            if candidate.kind == "DELETE_GENERATION" {
                let current = managed_object_authority::Entity::find_by_id((
                    candidate.tenant_id.clone(),
                    candidate.bucket.clone(),
                    candidate.logical_key.clone(),
                ))
                .lock(LockType::Update)
                .one(&txn)
                .await
                .map_err(persistence)?
                .map(authority_from_model)
                .transpose()?;
                if current.as_ref().is_some_and(|authority| {
                    !authority.tombstone
                        && authority.generation == candidate.generation
                        && (authority.primary_backend_id == candidate.target_backend_id
                            || authority.replica_backend_id.as_deref()
                                == Some(candidate.target_backend_id.as_str()))
                }) {
                    txn.commit().await.map_err(persistence)?;
                    continue;
                }
            }
            let lease_token = Uuid::now_v7();
            let result = managed_object_repair::Entity::update_many()
                .col_expr(managed_object_repair::Column::State, Expr::value("LEASED"))
                .col_expr(
                    managed_object_repair::Column::LeaseOwner,
                    Expr::value(Some(owner.to_string())),
                )
                .col_expr(
                    managed_object_repair::Column::LeaseExpiresAtMs,
                    Expr::value(Some(lease_until_ms)),
                )
                .col_expr(
                    managed_object_repair::Column::LeaseToken,
                    Expr::value(Some(lease_token)),
                )
                .col_expr(managed_object_repair::Column::UpdatedAtMs, Expr::value(now))
                .filter(managed_object_repair::Column::Id.eq(candidate.id))
                .filter(
                    Condition::any()
                        .add(managed_object_repair::Column::State.eq("PENDING"))
                        .add(
                            Condition::all()
                                .add(managed_object_repair::Column::State.eq("LEASED"))
                                .add(managed_object_repair::Column::LeaseExpiresAtMs.lte(now)),
                        ),
                )
                .exec(&txn)
                .await
                .map_err(persistence)?;
            if result.rows_affected == 1 {
                let mut record = repair_from_model(candidate)?;
                record.id = lease_token;
                record.lease_owner = Some(owner.to_string());
                record.lease_token = Some(lease_token);
                record.lease_expires_at_ms = Some(lease_until_ms);
                claimed.push(record);
            }
            txn.commit().await.map_err(persistence)?;
        }
        Ok(claimed)
    }

    async fn renew_repair(
        &self,
        lease_token: Uuid,
        lease_until_ms: i64,
    ) -> Result<(), ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let result = managed_object_repair::Entity::update_many()
            .col_expr(
                managed_object_repair::Column::LeaseExpiresAtMs,
                Expr::value(Some(lease_until_ms)),
            )
            .col_expr(managed_object_repair::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_object_repair::Column::State.eq("LEASED"))
            .filter(managed_object_repair::Column::LeaseToken.eq(lease_token))
            .filter(managed_object_repair::Column::LeaseExpiresAtMs.gt(now))
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        Ok(())
    }

    async fn complete_repair(&self, repair: &RepairRecord) -> Result<bool, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace_epoch = require_active_namespace(&txn, &repair.logical.tenant_id).await?;
        if u64::try_from(namespace_epoch).ok() != Some(repair.namespace_epoch) {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        if repair.lease_token != Some(repair.id) {
            return Err(ManagedError::Conflict);
        }
        let result = managed_object_repair::Entity::update_many()
            .col_expr(managed_object_repair::Column::State, Expr::value("DONE"))
            .col_expr(
                managed_object_repair::Column::LeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(managed_object_repair::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_object_repair::Column::Id.eq(repair.repair_id))
            .filter(managed_object_repair::Column::State.eq("LEASED"))
            .filter(managed_object_repair::Column::LeaseToken.eq(repair.id))
            .filter(managed_object_repair::Column::LeaseExpiresAtMs.gt(now))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        if repair.kind == RepairKind::DeleteGeneration {
            let remaining = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::TenantId.eq(&repair.logical.tenant_id),
                )
                .filter(
                    managed_physical_object_version::Column::BackendId
                        .eq(&repair.target_backend_id),
                )
                .filter(
                    managed_physical_object_version::Column::PhysicalKey.eq(&repair.physical_key),
                )
                .count(&txn)
                .await
                .map_err(persistence)?;
            if remaining != 0 {
                managed_object_repair::Entity::update_many()
                    .col_expr(managed_object_repair::Column::State, Expr::value("PENDING"))
                    .filter(managed_object_repair::Column::Id.eq(repair.repair_id))
                    .filter(managed_object_repair::Column::State.eq("DONE"))
                    .exec(&txn)
                    .await
                    .map_err(persistence)?;
                txn.commit().await.map_err(persistence)?;
                return Ok(false);
            }
        }
        let mut authority_updated = false;
        if repair.kind != RepairKind::DeleteGeneration {
            let target_versions = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::TenantId.eq(&repair.logical.tenant_id),
                )
                .filter(
                    managed_physical_object_version::Column::BackendId
                        .eq(&repair.target_backend_id),
                )
                .filter(
                    managed_physical_object_version::Column::PhysicalKey.eq(&repair.physical_key),
                )
                .count(&txn)
                .await
                .map_err(persistence)?;
            if target_versions == 0 {
                return Err(ManagedError::Persistence(
                    "managed repair cannot publish before target physical versions are ledgered"
                        .to_string(),
                ));
            }
            let current = managed_object_authority::Entity::find_by_id((
                repair.logical.tenant_id.clone(),
                repair.logical.bucket.clone(),
                repair.logical.key.clone(),
            ))
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .map(authority_from_model)
            .transpose()?;
            let cleanup_in_progress = managed_object_repair::Entity::find()
                .filter(managed_object_repair::Column::Kind.eq("DELETE_GENERATION"))
                .filter(managed_object_repair::Column::TenantId.eq(&repair.logical.tenant_id))
                .filter(managed_object_repair::Column::Bucket.eq(&repair.logical.bucket))
                .filter(managed_object_repair::Column::LogicalKey.eq(&repair.logical.key))
                .filter(managed_object_repair::Column::Generation.eq(repair.generation))
                .filter(
                    managed_object_repair::Column::TargetBackendId.eq(&repair.target_backend_id),
                )
                .filter(managed_object_repair::Column::State.eq("LEASED"))
                .count(&txn)
                .await
                .map_err(persistence)?
                != 0;
            if !cleanup_in_progress && let Some(mut authority) = current.clone() {
                let previous = authority.clone();
                if authority.generation == repair.generation
                    && authority.cas_version == repair.authority_cas_version
                    && !authority.tombstone
                    && apply_repair_to_authority(&mut authority, repair)?
                {
                    if authority != previous {
                        authority.cas_version = authority.cas_version.saturating_add(1);
                        authority.updated_at_ms = crate::transaction::unix_time_ms();
                        let result = managed_object_authority::Entity::update_many()
                            .set(authority_active(&authority)?)
                            .filter(
                                managed_object_authority::Column::TenantId
                                    .eq(&repair.logical.tenant_id),
                            )
                            .filter(
                                managed_object_authority::Column::Bucket.eq(&repair.logical.bucket),
                            )
                            .filter(
                                managed_object_authority::Column::LogicalKey
                                    .eq(&repair.logical.key),
                            )
                            .filter(
                                managed_object_authority::Column::Generation.eq(repair.generation),
                            )
                            .filter(
                                managed_object_authority::Column::CasVersion.eq(i64_from_u64(
                                    previous.cas_version,
                                    "managed authority CAS",
                                )?),
                            )
                            .exec(&txn)
                            .await
                            .map_err(persistence)?;
                        if result.rows_affected != 1 {
                            return Err(ManagedError::Conflict);
                        }
                    }
                    authority_updated = true;
                    if repair.kind == RepairKind::Placement {
                        for mut cleanup in placement_cleanup_repairs(&previous, &authority) {
                            cleanup.namespace_epoch = repair.namespace_epoch;
                            cleanup.placement_version = repair.placement_version;
                            insert_waiting_placement_cleanup(&txn, cleanup).await?;
                        }
                        if authority.placement_version == repair.placement_version {
                            managed_object_repair::Entity::update_many()
                                .col_expr(
                                    managed_object_repair::Column::State,
                                    Expr::value("PENDING"),
                                )
                                .col_expr(
                                    managed_object_repair::Column::UpdatedAtMs,
                                    Expr::value(crate::transaction::unix_time_ms()),
                                )
                                .filter(managed_object_repair::Column::State.eq("WAITING_CUTOVER"))
                                .filter(
                                    managed_object_repair::Column::TenantId
                                        .eq(&repair.logical.tenant_id),
                                )
                                .filter(
                                    managed_object_repair::Column::Bucket
                                        .eq(&repair.logical.bucket),
                                )
                                .filter(
                                    managed_object_repair::Column::LogicalKey
                                        .eq(&repair.logical.key),
                                )
                                .filter(
                                    managed_object_repair::Column::Generation.eq(repair.generation),
                                )
                                .filter(
                                    managed_object_repair::Column::PlacementVersion
                                        .eq(i64::from(repair.placement_version)),
                                )
                                .exec(&txn)
                                .await
                                .map_err(persistence)?;
                        }
                    }
                }
            }
            if !authority_updated
                && current
                    .as_ref()
                    .is_none_or(|authority| !repair_target_is_authoritative(authority, repair))
            {
                insert_repair(&txn, stale_repair_cleanup(repair)).await?;
            }
        }
        txn.commit().await.map_err(persistence)?;
        Ok(authority_updated)
    }

    async fn fail_repair(&self, lease_token: Uuid, error: &str) -> Result<(), ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let txn = self.db.begin().await.map_err(persistence)?;
        let model = managed_object_repair::Entity::find()
            .filter(managed_object_repair::Column::State.eq("LEASED"))
            .filter(managed_object_repair::Column::LeaseToken.eq(lease_token))
            .filter(managed_object_repair::Column::LeaseExpiresAtMs.gt(now))
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let attempts = model.attempts.saturating_add(1);
        let attempts = u32::try_from(attempts).unwrap_or(u32::MAX);
        let (state, not_before_ms) = if attempts >= MAX_REPAIR_ATTEMPTS {
            ("DEAD", 0)
        } else {
            ("PENDING", now.saturating_add(repair_backoff_ms(attempts)))
        };
        managed_object_repair::Entity::update_many()
            .col_expr(managed_object_repair::Column::State, Expr::value(state))
            .col_expr(
                managed_object_repair::Column::Attempts,
                Expr::value(i32::try_from(attempts).unwrap_or(i32::MAX)),
            )
            .col_expr(
                managed_object_repair::Column::NotBeforeMs,
                Expr::value(not_before_ms),
            )
            .col_expr(
                managed_object_repair::Column::LeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                managed_object_repair::Column::LastError,
                Expr::value(Some(error.chars().take(1024).collect::<String>())),
            )
            .col_expr(managed_object_repair::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_object_repair::Column::Id.eq(model.id))
            .filter(managed_object_repair::Column::State.eq("LEASED"))
            .filter(managed_object_repair::Column::LeaseToken.eq(lease_token))
            .filter(managed_object_repair::Column::LeaseExpiresAtMs.gt(now))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)
    }

    async fn repair_state_counts(&self) -> Result<RepairStateCounts, ManagedError> {
        let pending = managed_object_repair::Entity::find()
            .filter(managed_object_repair::Column::State.eq("PENDING"))
            .count(&self.db)
            .await
            .map_err(persistence)?;
        let leased = managed_object_repair::Entity::find()
            .filter(managed_object_repair::Column::State.eq("LEASED"))
            .count(&self.db)
            .await
            .map_err(persistence)?;
        let dead = managed_object_repair::Entity::find()
            .filter(managed_object_repair::Column::State.eq("DEAD"))
            .count(&self.db)
            .await
            .map_err(persistence)?;
        Ok(RepairStateCounts {
            pending,
            leased,
            dead,
        })
    }

    async fn begin_physical_write(
        &self,
        intent: PhysicalWriteIntent,
    ) -> Result<PhysicalWriteLease, ManagedError> {
        validate_physical_intent(&intent)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &intent.tenant_id).await?;
        let parent = managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::PrimaryChildOperationId.eq(intent.intent_id))
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .map(logical_operation_from_model)
            .transpose()?;
        let epoch = if let Some(parent) = &parent {
            let usage = locked_workspace_usage(&txn, &intent.tenant_id).await?;
            let recipe = parent
                .intent
                .publication_recipe
                .as_ref()
                .ok_or(ManagedError::Conflict)?;
            if namespace.state != "ACTIVE"
                || parent.state != ManagedLogicalOperationState::Open
                || usage.active_operation_id != Some(parent.intent.operation_id)
                || parent.intent.logical.tenant_id != intent.tenant_id
                || parent.intent.backend_id != intent.backend_id
                || parent.intent.provider_bucket != intent.provider_bucket
                || parent.intent.physical_key != intent.physical_key
                || recipe.version != MANAGED_PUBLICATION_RECIPE_VERSION
                || recipe.placement_version == 0
                || recipe.primary_backend_id != parent.intent.backend_id
                || !physical_intent_supports_exact_history(&intent)
                || recipe.primary_status != CopyStatus::Ready
                || (recipe.replica_backend_id.is_none()
                    && recipe.replica_status != CopyStatus::Absent)
                || (recipe.replica_backend_id.is_some()
                    && recipe.replica_status != CopyStatus::RepairPending)
                || u64_from_i64(namespace.epoch, "managed namespace epoch")?
                    != parent.intent.fence.namespace_epoch
                || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                    != parent.intent.fence.routing_epoch
            {
                return Err(ManagedError::Conflict);
            }
            namespace.epoch
        } else {
            if namespace.state != "ACTIVE" {
                return Err(ManagedError::NamespaceFenced);
            }
            namespace.epoch
        };
        let now = crate::transaction::unix_time_ms();
        let lease_token = Uuid::now_v7();
        let expected = intent.clone();
        let inserted = managed_physical_write_intent::Entity::insert(
            managed_physical_write_intent::ActiveModel {
                intent_id: Set(intent.intent_id),
                tenant_id: Set(intent.tenant_id),
                epoch: Set(epoch),
                backend_id: Set(intent.backend_id),
                provider_kind: Set(intent.storage_identity.provider_kind),
                provider_instance_id: Set(intent.storage_identity.provider_instance_id),
                provider_account_id: Set(intent.storage_identity.provider_account_id),
                canonical_endpoint: Set(intent.storage_identity.canonical_endpoint),
                provider_region: Set(intent.storage_identity.region),
                credential_epoch: Set(i64_from_u64(
                    intent.credential_epoch,
                    "physical write credential epoch",
                )?),
                provider_bucket: Set(intent.provider_bucket),
                physical_key: Set(intent.physical_key),
                versioning_mode: Set(intent.versioning_mode.as_str().to_string()),
                versioning_capability: Set(intent.versioning_capability.as_str().to_string()),
                state: Set("PENDING".to_string()),
                last_error: Set(None),
                lease_owner: Set(intent.lease_owner.clone()),
                lease_token: Set(lease_token),
                lease_expires_at_ms: Set(now.saturating_add(PHYSICAL_WRITE_LEASE_MS)),
                created_at_ms: Set(now),
                updated_at_ms: Set(now),
            },
        )
        .on_conflict(
            OnConflict::column(managed_physical_write_intent::Column::IntentId)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(&txn)
        .await
        .map_err(persistence)?;
        if inserted == 0 {
            let existing = managed_physical_write_intent::Entity::find_by_id(expected.intent_id)
                .one(&txn)
                .await
                .map_err(persistence)?
                .ok_or(ManagedError::Conflict)?;
            if existing.tenant_id != expected.tenant_id
                || existing.epoch != epoch
                || existing.backend_id != expected.backend_id
                || existing.provider_kind != expected.storage_identity.provider_kind
                || existing.provider_instance_id != expected.storage_identity.provider_instance_id
                || existing.provider_account_id != expected.storage_identity.provider_account_id
                || existing.canonical_endpoint != expected.storage_identity.canonical_endpoint
                || existing.provider_region != expected.storage_identity.region
                || u64_from_i64(existing.credential_epoch, "physical write credential epoch")?
                    != expected.credential_epoch
                || existing.provider_bucket != expected.provider_bucket
                || existing.physical_key != expected.physical_key
                || existing.versioning_mode != expected.versioning_mode.as_str()
                || existing.versioning_capability != expected.versioning_capability.as_str()
                || existing.lease_owner != expected.lease_owner
            {
                return Err(ManagedError::RecoveryBlocked("physical_intent_mismatch"));
            }
            txn.commit().await.map_err(persistence)?;
            return Ok(PhysicalWriteLease {
                intent_id: existing.intent_id,
                namespace_epoch: u64::try_from(existing.epoch)
                    .map_err(|_| ManagedError::Conflict)?,
                owner: existing.lease_owner,
                token: existing.lease_token,
            });
        }
        txn.commit().await.map_err(persistence)?;
        Ok(PhysicalWriteLease {
            intent_id: intent.intent_id,
            namespace_epoch: u64::try_from(epoch)
                .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))?,
            owner: intent.lease_owner,
            token: lease_token,
        })
    }

    async fn pending_physical_write_intents(
        &self,
        limit: u64,
    ) -> Result<Vec<DurablePhysicalWriteIntent>, ManagedError> {
        let logical_children = managed_logical_operation::Entity::find()
            .select_only()
            .column(managed_logical_operation::Column::PrimaryChildOperationId)
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .into_query();
        managed_physical_write_intent::Entity::find()
            .filter(
                managed_physical_write_intent::Column::IntentId.not_in_subquery(logical_children),
            )
            .order_by_asc(managed_physical_write_intent::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(durable_physical_intent_from_model)
            .collect()
    }

    async fn physical_write_intent(
        &self,
        intent_id: Uuid,
    ) -> Result<Option<DurablePhysicalWriteIntent>, ManagedError> {
        managed_physical_write_intent::Entity::find_by_id(intent_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .map(durable_physical_intent_from_model)
            .transpose()
    }

    async fn renew_physical_write_intent(
        &self,
        lease: &PhysicalWriteLease,
        lease_expires_at_ms: i64,
    ) -> Result<(), ManagedError> {
        let result = managed_physical_write_intent::Entity::update_many()
            .col_expr(
                managed_physical_write_intent::Column::LeaseExpiresAtMs,
                Expr::value(lease_expires_at_ms),
            )
            .col_expr(
                managed_physical_write_intent::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(managed_physical_write_intent::Column::IntentId.eq(lease.intent_id))
            .filter(managed_physical_write_intent::Column::LeaseOwner.eq(&lease.owner))
            .filter(managed_physical_write_intent::Column::LeaseToken.eq(lease.token))
            .filter(
                managed_physical_write_intent::Column::LeaseExpiresAtMs
                    .gt(crate::transaction::unix_time_ms()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        Ok(())
    }

    async fn claim_expired_physical_write_intent(
        &self,
        intent_id: Uuid,
        owner: &str,
        lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        let candidate = managed_physical_write_intent::Entity::find_by_id(intent_id)
            .one(&self.db)
            .await
            .map_err(persistence)?;
        let Some(candidate) = candidate else {
            return Ok(None);
        };
        let txn = self.db.begin().await.map_err(persistence)?;
        let _namespace = locked_namespace(&txn, &candidate.tenant_id).await?;
        let protected_parent = managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::PrimaryChildOperationId.eq(intent_id))
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .count(&txn)
            .await
            .map_err(persistence)?;
        if protected_parent != 0 {
            return Ok(None);
        }
        let token = Uuid::now_v7();
        let result = managed_physical_write_intent::Entity::update_many()
            .col_expr(
                managed_physical_write_intent::Column::LeaseOwner,
                Expr::value(owner.to_string()),
            )
            .col_expr(
                managed_physical_write_intent::Column::LeaseToken,
                Expr::value(token),
            )
            .col_expr(
                managed_physical_write_intent::Column::LeaseExpiresAtMs,
                Expr::value(lease_expires_at_ms),
            )
            .filter(managed_physical_write_intent::Column::IntentId.eq(intent_id))
            .filter(
                managed_physical_write_intent::Column::LeaseExpiresAtMs
                    .lte(crate::transaction::unix_time_ms()),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Ok(None);
        }
        let intent = managed_physical_write_intent::Entity::find_by_id(intent_id)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        txn.commit().await.map_err(persistence)?;
        Ok(Some(PhysicalWriteLease {
            intent_id,
            namespace_epoch: u64::try_from(intent.epoch).map_err(|_| ManagedError::Conflict)?,
            owner: owner.to_string(),
            token,
        }))
    }

    async fn claim_logical_physical_write_intent(
        &self,
        claim: &ManagedRecoveryClaim,
        lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        if lease_expires_at_ms <= now {
            return Err(ManagedError::Conflict);
        }
        let txn = self.db.begin().await.map_err(persistence)?;
        // Lock order for managed mutation transactions is namespace -> logical
        // operation -> workspace usage/current authority -> physical intent.
        let namespace = locked_namespace(&txn, &claim.operation.intent.logical.tenant_id).await?;
        let model =
            managed_logical_operation::Entity::find_by_id(claim.operation.intent.operation_id)
                .lock(LockType::Update)
                .one(&txn)
                .await
                .map_err(persistence)?
                .ok_or(ManagedError::Conflict)?;
        let operation = logical_operation_from_model(model)?;
        validate_recovery_authority(&operation, Some(claim), now)?;
        if operation.intent.kind != ManagedMutationKind::Put
            || namespace.epoch
                != i64_from_u64(
                    operation.intent.fence.namespace_epoch,
                    "managed namespace epoch",
                )?
        {
            return Err(ManagedError::Conflict);
        }
        let token = Uuid::now_v7();
        let updated = managed_physical_write_intent::Entity::update_many()
            .col_expr(
                managed_physical_write_intent::Column::LeaseOwner,
                Expr::value(claim.owner.clone()),
            )
            .col_expr(
                managed_physical_write_intent::Column::LeaseToken,
                Expr::value(token),
            )
            .col_expr(
                managed_physical_write_intent::Column::LeaseExpiresAtMs,
                Expr::value(lease_expires_at_ms),
            )
            .filter(
                managed_physical_write_intent::Column::IntentId
                    .eq(operation.intent.primary_child_operation_id),
            )
            .filter(managed_physical_write_intent::Column::LeaseExpiresAtMs.lte(now))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if updated.rows_affected != 1 {
            txn.commit().await.map_err(persistence)?;
            return Ok(None);
        }
        txn.commit().await.map_err(persistence)?;
        Ok(Some(PhysicalWriteLease {
            intent_id: operation.intent.primary_child_operation_id,
            namespace_epoch: operation.intent.fence.namespace_epoch,
            owner: claim.owner.clone(),
            token,
        }))
    }

    async fn commit_physical_write(
        &self,
        lease: &PhysicalWriteLease,
        superseded_version_ids: &[String],
        version_id: Option<&str>,
    ) -> Result<(), ManagedError> {
        if superseded_version_ids.iter().any(String::is_empty)
            || version_id.is_some_and(str::is_empty)
        {
            return Err(ManagedError::Conflict);
        }
        let txn = self.db.begin().await.map_err(persistence)?;
        if managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::PrimaryChildOperationId.eq(lease.intent_id))
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .count(&txn)
            .await
            .map_err(persistence)?
            != 0
        {
            return Err(ManagedError::Conflict);
        }
        let Some(intent) = managed_physical_write_intent::Entity::find_by_id(lease.intent_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
        else {
            // A committed retry and a confirmed abort are both terminal and
            // safe; neither can create a new provider version here.
            txn.commit().await.map_err(persistence)?;
            return Ok(());
        };
        if intent.lease_owner != lease.owner
            || intent.lease_token != lease.token
            || intent.lease_expires_at_ms <= crate::transaction::unix_time_ms()
        {
            return Err(ManagedError::Conflict);
        }
        let namespace = locked_namespace(&txn, &intent.tenant_id).await?;
        let now = crate::transaction::unix_time_ms();
        let purging = namespace.state == "PURGING";
        for recorded_version_id in superseded_version_ids
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(version_id.unwrap_or_default()))
        {
            managed_physical_object_version::Entity::insert(
                managed_physical_object_version::ActiveModel {
                    tenant_id: Set(intent.tenant_id.clone()),
                    backend_id: Set(intent.backend_id.clone()),
                    provider_kind: Set(intent.provider_kind.clone()),
                    provider_instance_id: Set(intent.provider_instance_id.clone()),
                    provider_account_id: Set(intent.provider_account_id.clone()),
                    canonical_endpoint: Set(intent.canonical_endpoint.clone()),
                    provider_region: Set(intent.provider_region.clone()),
                    credential_epoch: Set(intent.credential_epoch),
                    provider_bucket: Set(intent.provider_bucket.clone()),
                    physical_key: Set(intent.physical_key.clone()),
                    versioning_mode: Set(intent.versioning_mode.clone()),
                    versioning_capability: Set(intent.versioning_capability.clone()),
                    write_operation_id: Set(lease.intent_id),
                    version_id: Set(recorded_version_id.to_string()),
                    epoch: Set(intent.epoch),
                    state: Set(if purging {
                        "PURGE_PENDING".to_string()
                    } else {
                        "LIVE".to_string()
                    }),
                    purge_operation_id: Set(if purging {
                        namespace.purge_operation_id
                    } else {
                        None
                    }),
                    last_error: Set(None),
                    created_at_ms: Set(now),
                    updated_at_ms: Set(now),
                },
            )
            .on_conflict(
                OnConflict::columns([
                    managed_physical_object_version::Column::TenantId,
                    managed_physical_object_version::Column::BackendId,
                    managed_physical_object_version::Column::ProviderBucket,
                    managed_physical_object_version::Column::PhysicalKey,
                    managed_physical_object_version::Column::VersionId,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec_without_returning(&txn)
            .await
            .map_err(persistence)?;
        }
        managed_physical_write_intent::Entity::delete_by_id(lease.intent_id)
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)
    }

    async fn abort_physical_write(&self, lease: &PhysicalWriteLease) -> Result<(), ManagedError> {
        if managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::PrimaryChildOperationId.eq(lease.intent_id))
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .count(&self.db)
            .await
            .map_err(persistence)?
            != 0
        {
            return Err(ManagedError::Conflict);
        }
        let result = managed_physical_write_intent::Entity::delete_many()
            .filter(managed_physical_write_intent::Column::IntentId.eq(lease.intent_id))
            .filter(managed_physical_write_intent::Column::LeaseOwner.eq(&lease.owner))
            .filter(managed_physical_write_intent::Column::LeaseToken.eq(lease.token))
            .filter(
                managed_physical_write_intent::Column::LeaseExpiresAtMs
                    .gt(crate::transaction::unix_time_ms()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        (result.rows_affected == 1)
            .then_some(())
            .ok_or(ManagedError::Conflict)
    }

    async fn block_physical_write(
        &self,
        lease: &PhysicalWriteLease,
        reason: &str,
    ) -> Result<(), ManagedError> {
        let result = managed_physical_write_intent::Entity::update_many()
            .col_expr(
                managed_physical_write_intent::Column::State,
                Expr::value("BLOCKED"),
            )
            .col_expr(
                managed_physical_write_intent::Column::LastError,
                Expr::value(Some(reason.chars().take(1024).collect::<String>())),
            )
            .col_expr(
                managed_physical_write_intent::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(managed_physical_write_intent::Column::IntentId.eq(lease.intent_id))
            .filter(managed_physical_write_intent::Column::LeaseOwner.eq(&lease.owner))
            .filter(managed_physical_write_intent::Column::LeaseToken.eq(lease.token))
            .filter(
                managed_physical_write_intent::Column::LeaseExpiresAtMs
                    .gt(crate::transaction::unix_time_ms()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        (result.rows_affected == 1)
            .then_some(())
            .ok_or(ManagedError::Conflict)
    }

    async fn physical_versions(
        &self,
        tenant_id: &str,
        backend_id: &str,
        provider_bucket: &str,
        physical_key: &str,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        managed_physical_object_version::Entity::find()
            .filter(managed_physical_object_version::Column::TenantId.eq(tenant_id))
            .filter(managed_physical_object_version::Column::BackendId.eq(backend_id))
            .filter(managed_physical_object_version::Column::ProviderBucket.eq(provider_bucket))
            .filter(managed_physical_object_version::Column::PhysicalKey.eq(physical_key))
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(physical_target_from_model)
            .collect()
    }

    async fn forget_physical_version(
        &self,
        target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        // Exact versions for one child may be deleted concurrently. Locking the
        // parent makes one deleter observe the final empty child ledger.
        let operation = managed_logical_operation::Entity::find()
            .filter(
                managed_logical_operation::Column::PrimaryChildOperationId
                    .eq(target.write_operation_id),
            )
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .map(logical_operation_from_model)
            .transpose()?;
        let deleted = managed_physical_object_version::Entity::delete_many()
            .filter(managed_physical_object_version::Column::TenantId.eq(&target.tenant_id))
            .filter(managed_physical_object_version::Column::BackendId.eq(&target.backend_id))
            .filter(
                managed_physical_object_version::Column::ProviderBucket.eq(&target.provider_bucket),
            )
            .filter(managed_physical_object_version::Column::PhysicalKey.eq(&target.physical_key))
            .filter(
                managed_physical_object_version::Column::WriteOperationId
                    .eq(target.write_operation_id),
            )
            .filter(
                managed_physical_object_version::Column::VersionId
                    .eq(target.version_id.as_deref().unwrap_or_default()),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if deleted.rows_affected == 0 {
            txn.commit().await.map_err(persistence)?;
            return Ok(());
        }
        let remaining = managed_physical_object_version::Entity::find()
            .filter(
                managed_physical_object_version::Column::WriteOperationId
                    .eq(target.write_operation_id),
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
        if remaining == 0 {
            if let Some(operation) = operation {
                let released = operation
                    .committed_physical_bytes
                    .checked_sub(operation.released_physical_bytes)
                    .ok_or_else(|| {
                        ManagedError::Corrupt(
                            "managed operation released bytes exceed committed bytes".to_string(),
                        )
                    })?;
                if released > 0 {
                    let mut usage =
                        locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
                    let released = i64_from_u64(released, "managed released physical bytes")?;
                    usage.physical_allocated_bytes = usage
                        .physical_allocated_bytes
                        .checked_sub(released)
                        .ok_or_else(|| {
                            ManagedError::Corrupt(
                                "managed physical usage is below the child allocation".to_string(),
                            )
                        })?;
                    let now = crate::transaction::unix_time_ms();
                    usage.version = usage.version.saturating_add(1);
                    usage.updated_at_ms = now;
                    managed_workspace_usage::Entity::update_many()
                        .col_expr(
                            managed_workspace_usage::Column::PhysicalAllocatedBytes,
                            Expr::value(usage.physical_allocated_bytes),
                        )
                        .col_expr(
                            managed_workspace_usage::Column::Version,
                            Expr::value(usage.version),
                        )
                        .col_expr(
                            managed_workspace_usage::Column::UpdatedAtMs,
                            Expr::value(now),
                        )
                        .filter(
                            managed_workspace_usage::Column::TenantId
                                .eq(&operation.intent.logical.tenant_id),
                        )
                        .exec(&txn)
                        .await
                        .map_err(persistence)?;
                    managed_logical_operation::Entity::update_many()
                        .col_expr(
                            managed_logical_operation::Column::ReleasedPhysicalBytes,
                            Expr::value(i64_from_u64(
                                operation.committed_physical_bytes,
                                "managed committed physical bytes",
                            )?),
                        )
                        .col_expr(
                            managed_logical_operation::Column::UpdatedAtMs,
                            Expr::value(now),
                        )
                        .filter(
                            managed_logical_operation::Column::OperationId
                                .eq(operation.intent.operation_id),
                        )
                        .exec(&txn)
                        .await
                        .map_err(persistence)?;
                }
            }
            object_operation::Entity::delete_many()
                .filter(object_operation::Column::Id.eq(target.write_operation_id))
                .filter(object_operation::Column::State.is_in([
                    crate::transaction::OperationState::Committed.as_str(),
                    crate::transaction::OperationState::ProvenAborted.as_str(),
                ]))
                .exec(&txn)
                .await
                .map_err(persistence)?;
        }
        txn.commit().await.map_err(persistence)
    }

    async fn purge_namespace(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        if let Some(existing) = managed_namespace_purge::Entity::find_by_id(request.operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
        {
            if existing.tenant_id != request.tenant_id {
                return Ok(NamespacePurgeStatus::Blocked {
                    reason: "purge operation belongs to another namespace".to_string(),
                });
            }
            return self.finalize_purge_if_ready(request).await;
        }

        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &request.tenant_id).await?;
        if let Some(existing) = managed_namespace_purge::Entity::find_by_id(request.operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
        {
            txn.commit().await.map_err(persistence)?;
            if existing.tenant_id != request.tenant_id {
                return Ok(NamespacePurgeStatus::Blocked {
                    reason: "purge operation belongs to another namespace".to_string(),
                });
            }
            return self.finalize_purge_if_ready(request).await;
        }
        if namespace.state == "PURGING" {
            return Ok(NamespacePurgeStatus::Blocked {
                reason: "another managed namespace purge is already running".to_string(),
            });
        }
        let authorities = managed_object_authority::Entity::find()
            .filter(managed_object_authority::Column::TenantId.eq(&request.tenant_id))
            .all(&txn)
            .await
            .map_err(persistence)?;
        for authority_model in authorities {
            let authority = authority_from_model(authority_model)?;
            if authority.tombstone {
                continue;
            }
            let physical_key = generation_physical_key(&authority.logical, authority.generation);
            let required_backends = std::iter::once(authority.primary_backend_id.as_str()).chain(
                authority
                    .replica_backend_id
                    .as_deref()
                    .filter(|_| authority.replica_status == CopyStatus::Ready),
            );
            for backend_id in required_backends {
                let versions = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId.eq(&request.tenant_id),
                    )
                    .filter(managed_physical_object_version::Column::BackendId.eq(backend_id))
                    .filter(managed_physical_object_version::Column::PhysicalKey.eq(&physical_key))
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if versions == 0 {
                    return Ok(NamespacePurgeStatus::Blocked {
                        reason: format!(
                            "managed authority references unledgered physical versions on backend {backend_id}"
                        ),
                    });
                }
            }
        }
        let now = crate::transaction::unix_time_ms();
        managed_namespace_purge::Entity::insert(managed_namespace_purge::ActiveModel {
            operation_id: Set(request.operation_id),
            tenant_id: Set(request.tenant_id.clone()),
            epoch: Set(namespace.epoch),
            state: Set("RUNNING".to_string()),
            blocked_reason: Set(None),
            deleted_versions: Set(0),
            created_at_ms: Set(now),
            updated_at_ms: Set(now),
            completed_at_ms: Set(None),
        })
        .exec(&txn)
        .await
        .map_err(persistence)?;
        managed_namespace::Entity::update_many()
            .col_expr(managed_namespace::Column::State, Expr::value("PURGING"))
            .col_expr(
                managed_namespace::Column::PurgeOperationId,
                Expr::value(Some(request.operation_id)),
            )
            .col_expr(managed_namespace::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_namespace::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_namespace::Column::State.eq("ACTIVE"))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_physical_object_version::Entity::update_many()
            .col_expr(
                managed_physical_object_version::Column::State,
                Expr::value("PURGE_PENDING"),
            )
            .col_expr(
                managed_physical_object_version::Column::PurgeOperationId,
                Expr::value(Some(request.operation_id)),
            )
            .col_expr(
                managed_physical_object_version::Column::LastError,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_physical_object_version::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_physical_object_version::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_physical_object_version::Column::Epoch.lte(namespace.epoch))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        self.finalize_purge_if_ready(request).await
    }

    async fn namespace_purge_status(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        self.finalize_purge_if_ready(request).await
    }

    async fn purge_targets(
        &self,
        request: &NamespacePurgeRequest,
        limit: u64,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        let purge = managed_namespace_purge::Entity::find_by_id(request.operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?;
        if purge.as_ref().map(|value| value.tenant_id.as_str()) != Some(&request.tenant_id) {
            return Err(ManagedError::Conflict);
        }
        managed_physical_object_version::Entity::find()
            .filter(managed_physical_object_version::Column::TenantId.eq(&request.tenant_id))
            .filter(
                managed_physical_object_version::Column::PurgeOperationId.eq(request.operation_id),
            )
            .filter(
                Condition::any()
                    .add(managed_physical_object_version::Column::State.eq("PURGE_PENDING"))
                    .add(managed_physical_object_version::Column::State.eq("PURGE_BLOCKED")),
            )
            .order_by_asc(managed_physical_object_version::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(physical_target_from_model)
            .collect()
    }

    async fn mark_purge_target_deleted(
        &self,
        request: &NamespacePurgeRequest,
        target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let result = managed_physical_object_version::Entity::delete_many()
            .filter(managed_physical_object_version::Column::TenantId.eq(&target.tenant_id))
            .filter(managed_physical_object_version::Column::BackendId.eq(&target.backend_id))
            .filter(
                managed_physical_object_version::Column::ProviderBucket.eq(&target.provider_bucket),
            )
            .filter(managed_physical_object_version::Column::PhysicalKey.eq(&target.physical_key))
            .filter(
                managed_physical_object_version::Column::VersionId
                    .eq(target.version_id.as_deref().unwrap_or_default()),
            )
            .filter(
                managed_physical_object_version::Column::PurgeOperationId.eq(request.operation_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if result.rows_affected == 1 {
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::DeletedVersions,
                    Expr::col(managed_namespace_purge::Column::DeletedVersions).add(1),
                )
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("RUNNING"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Option::<String>::None),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            let remaining = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::WriteOperationId
                        .eq(target.write_operation_id),
                )
                .count(&txn)
                .await
                .map_err(persistence)?;
            if remaining == 0 {
                object_operation::Entity::delete_many()
                    .filter(object_operation::Column::Id.eq(target.write_operation_id))
                    .filter(object_operation::Column::State.is_in([
                        crate::transaction::OperationState::Committed.as_str(),
                        crate::transaction::OperationState::ProvenAborted.as_str(),
                    ]))
                    .exec(&txn)
                    .await
                    .map_err(persistence)?;
            }
        }
        txn.commit().await.map_err(persistence)
    }

    async fn mark_purge_target_blocked(
        &self,
        request: &NamespacePurgeRequest,
        target: &PhysicalVersionTarget,
        reason: &str,
    ) -> Result<(), ManagedError> {
        let reason = reason.chars().take(1024).collect::<String>();
        let now = crate::transaction::unix_time_ms();
        let txn = self.db.begin().await.map_err(persistence)?;
        managed_physical_object_version::Entity::update_many()
            .col_expr(
                managed_physical_object_version::Column::State,
                Expr::value("PURGE_BLOCKED"),
            )
            .col_expr(
                managed_physical_object_version::Column::LastError,
                Expr::value(Some(reason.clone())),
            )
            .col_expr(
                managed_physical_object_version::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_physical_object_version::Column::TenantId.eq(&target.tenant_id))
            .filter(managed_physical_object_version::Column::BackendId.eq(&target.backend_id))
            .filter(
                managed_physical_object_version::Column::ProviderBucket.eq(&target.provider_bucket),
            )
            .filter(managed_physical_object_version::Column::PhysicalKey.eq(&target.physical_key))
            .filter(
                managed_physical_object_version::Column::VersionId
                    .eq(target.version_id.as_deref().unwrap_or_default()),
            )
            .filter(
                managed_physical_object_version::Column::PurgeOperationId.eq(request.operation_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_namespace_purge::Entity::update_many()
            .col_expr(
                managed_namespace_purge::Column::State,
                Expr::value("BLOCKED"),
            )
            .col_expr(
                managed_namespace_purge::Column::BlockedReason,
                Expr::value(Some(reason)),
            )
            .col_expr(
                managed_namespace_purge::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)
    }
}
