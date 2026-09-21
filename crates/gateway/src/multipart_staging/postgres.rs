//! Extracted from `multipart_staging.rs`; re-exported from `crate::multipart_staging`.

use super::*;

#[derive(Clone, Debug)]
pub struct PostgresMultipartRepository {
    pub(crate) db: DatabaseConnection,
    pub(crate) quotas: StagingQuotaLimits,
}

impl PostgresMultipartRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self::with_quotas(
            pool,
            StagingQuotaLimits {
                tenant_bytes: i64::MAX as u64,
                global_bytes: i64::MAX as u64,
            },
        )
    }

    #[cfg(any(test, debug_assertions))]
    pub fn fail_next_abort_after_update() {
        FAIL_ABORT_AFTER_UPDATE.store(true, Ordering::Release);
    }

    pub fn with_quotas(pool: sqlx::PgPool, quotas: StagingQuotaLimits) -> Self {
        Self {
            db: SqlxPostgresConnector::from_sqlx_postgres_pool(pool),
            quotas,
        }
    }

    pub(crate) async fn release_artifact(&self, artifact_key: &str) -> Result<(), StagingError> {
        let tx = self
            .db
            .begin()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let attempt = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::ArtifactKey.eq(artifact_key.to_string()))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let Some(attempt) = attempt else {
            tx.commit()
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            return Ok(());
        };
        let upload = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(attempt.upload_id.clone()))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or_else(|| StagingError::Persistence("multipart upload disappeared".to_string()))?;
        let global_scope = global_quota_scope();
        let tenant_scope = tenant_quota_scope(&upload.tenant_id);
        let global = lock_quota(&tx, &global_scope).await?;
        let tenant = lock_quota(&tx, &tenant_scope).await?;
        let pending = attempt.lifecycle == "PENDING";
        let bytes = if pending {
            attempt.reserved_bytes
        } else {
            attempt.size_bytes
        };
        if bytes < 0 {
            return Err(StagingError::Persistence(
                "negative artifact bytes".to_string(),
            ));
        }
        let mut active: multipart_upload::ActiveModel = upload.clone().into();
        if pending {
            if upload.reserved_bytes < bytes
                || global.reserved_bytes < bytes
                || tenant.reserved_bytes < bytes
            {
                return Err(StagingError::Persistence(
                    "multipart reservation underflow".to_string(),
                ));
            }
            active.reserved_bytes = Set(upload.reserved_bytes - bytes);
        } else {
            if upload.staged_bytes < bytes
                || global.staged_bytes < bytes
                || tenant.staged_bytes < bytes
            {
                return Err(StagingError::Persistence(
                    "multipart staged bytes underflow".to_string(),
                ));
            }
            active.staged_bytes = Set(upload.staged_bytes - bytes);
        }
        let now = now_ms();
        active.updated_at_ms = Set(now);
        active
            .update(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        if pending {
            update_quota(
                &tx,
                global.clone(),
                global.staged_bytes,
                global.reserved_bytes - bytes,
                now,
            )
            .await?;
            update_quota(
                &tx,
                tenant.clone(),
                tenant.staged_bytes,
                tenant.reserved_bytes - bytes,
                now,
            )
            .await?;
        } else {
            update_quota(
                &tx,
                global.clone(),
                global.staged_bytes - bytes,
                global.reserved_bytes,
                now,
            )
            .await?;
            update_quota(
                &tx,
                tenant.clone(),
                tenant.staged_bytes - bytes,
                tenant.reserved_bytes,
                now,
            )
            .await?;
        }
        multipart_part_attempt::Entity::delete_by_id(attempt.id)
            .exec(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        tx.commit()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(())
    }
}

pub(crate) fn upload_model(
    upload: &MultipartUpload,
) -> Result<multipart_upload::ActiveModel, StagingError> {
    Ok(multipart_upload::ActiveModel {
        id: Set(Uuid::now_v7()),
        upload_id: Set(upload.identity.upload_id.clone()),
        lifecycle: Set(lifecycle_name(upload.lifecycle).to_string()),
        tenant_id: Set(upload.identity.tenant_id.clone()),
        namespace_epoch: Set(upload
            .namespace_epoch
            .map(i64::try_from)
            .transpose()
            .map_err(|_| {
                StagingError::Persistence("namespace epoch exceeds BIGINT".to_string())
            })?),
        credential_policy_id: Set(upload.identity.credential_policy_id.clone()),
        bucket: Set(upload.identity.bucket.clone()),
        object_key: Set(upload.identity.key.clone()),
        metadata: Set(serde_json::to_value(&upload.snapshot.metadata).map_err(json_error)?),
        tags: Set(serde_json::to_value(&upload.snapshot.tags).map_err(json_error)?),
        checksum_mode: Set(upload.snapshot.checksum_mode.clone()),
        destination: Set(upload.snapshot.destination.clone()),
        plugin_snapshot: Set(upload.snapshot.plugin_snapshot.clone()),
        limits: Set(serde_json::json!({"max_staged_bytes": upload.snapshot.max_staged_bytes})),
        staged_bytes: Set(
            i64::try_from(upload.staged_bytes).map_err(|_| StagingError::QuotaExceeded)?
        ),
        reserved_bytes: Set(
            i64::try_from(upload.reserved_bytes).map_err(|_| StagingError::QuotaExceeded)?
        ),
        expires_at_ms: Set(upload.expires_at_ms),
        tombstone_until_ms: Set(upload.tombstone_until_ms),
        complete_request_fingerprint: Set(upload.complete_request_fingerprint.clone()),
        completion_lease_owner: Set(upload.completion_lease_owner.clone()),
        completion_lease_expires_at_ms: Set(upload.completion_lease_expires_at_ms),
        completion_fencing_token: Set(i64::try_from(upload.completion_fencing_token).map_err(
            |_| StagingError::Persistence("invalid completion fencing token".to_string()),
        )?),
        destination_operation_id: Set(upload.destination_operation_id),
        publishing_started_at_ms: Set(upload.publishing_started_at_ms),
        destination_commit: Set(upload
            .destination_commit
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(json_error)?),
        completion_result: Set(upload
            .completion_result
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(json_error)?),
        created_at_ms: Set(upload.created_at_ms),
        updated_at_ms: Set(upload.updated_at_ms),
    })
}

pub(crate) fn lifecycle_name(lifecycle: MultipartLifecycle) -> &'static str {
    match lifecycle {
        MultipartLifecycle::Open => "OPEN",
        MultipartLifecycle::Completing => "COMPLETING",
        MultipartLifecycle::Publishing => "PUBLISHING",
        MultipartLifecycle::Completed => "COMPLETED",
        MultipartLifecycle::Aborted => "ABORTED",
        MultipartLifecycle::Expired => "EXPIRED",
    }
}

pub(crate) fn lifecycle(value: &str) -> Result<MultipartLifecycle, StagingError> {
    match value {
        "OPEN" => Ok(MultipartLifecycle::Open),
        "COMPLETING" => Ok(MultipartLifecycle::Completing),
        "PUBLISHING" => Ok(MultipartLifecycle::Publishing),
        "COMPLETED" => Ok(MultipartLifecycle::Completed),
        "ABORTED" => Ok(MultipartLifecycle::Aborted),
        "EXPIRED" => Ok(MultipartLifecycle::Expired),
        _ => Err(StagingError::Persistence(
            "invalid multipart lifecycle".to_string(),
        )),
    }
}

pub(crate) fn json_error(error: serde_json::Error) -> StagingError {
    StagingError::Persistence(error.to_string())
}

pub(crate) fn upload_from_model(
    model: multipart_upload::Model,
) -> Result<MultipartUpload, StagingError> {
    let metadata = serde_json::from_value(model.metadata).map_err(json_error)?;
    let tags = serde_json::from_value(model.tags).map_err(json_error)?;
    let max_staged_bytes = model
        .limits
        .get("max_staged_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| StagingError::Persistence("invalid multipart limits".to_string()))?;
    Ok(MultipartUpload {
        identity: MultipartIdentity {
            tenant_id: model.tenant_id,
            credential_policy_id: model.credential_policy_id,
            bucket: model.bucket,
            key: model.object_key,
            upload_id: model.upload_id,
        },
        namespace_epoch: model
            .namespace_epoch
            .map(u64::try_from)
            .transpose()
            .map_err(|_| StagingError::Persistence("invalid namespace epoch".to_string()))?,
        snapshot: MultipartSnapshot {
            metadata,
            tags,
            checksum_mode: model.checksum_mode,
            destination: model.destination,
            plugin_snapshot: model.plugin_snapshot,
            max_staged_bytes,
        },
        lifecycle: lifecycle(&model.lifecycle)?,
        staged_bytes: u64::try_from(model.staged_bytes)
            .map_err(|_| StagingError::Persistence("negative staged bytes".to_string()))?,
        reserved_bytes: u64::try_from(model.reserved_bytes)
            .map_err(|_| StagingError::Persistence("negative reserved bytes".to_string()))?,
        created_at_ms: model.created_at_ms,
        expires_at_ms: model.expires_at_ms,
        updated_at_ms: model.updated_at_ms,
        tombstone_until_ms: model.tombstone_until_ms,
        complete_request_fingerprint: model.complete_request_fingerprint,
        completion_lease_owner: model.completion_lease_owner,
        completion_lease_expires_at_ms: model.completion_lease_expires_at_ms,
        completion_fencing_token: u64::try_from(model.completion_fencing_token).map_err(|_| {
            StagingError::Persistence("negative completion fencing token".to_string())
        })?,
        destination_operation_id: model.destination_operation_id,
        publishing_started_at_ms: model.publishing_started_at_ms,
        destination_commit: model
            .destination_commit
            .map(serde_json::from_value)
            .transpose()
            .map_err(json_error)?,
        completion_result: model
            .completion_result
            .map(serde_json::from_value)
            .transpose()
            .map_err(json_error)?,
    })
}

pub(crate) fn part_from_model(
    model: multipart_part_attempt::Model,
) -> Result<MultipartPart, StagingError> {
    Ok(MultipartPart {
        upload_id: model.upload_id,
        part_number: u32::try_from(model.part_number).map_err(|_| StagingError::InvalidPart)?,
        attempt: u32::try_from(model.attempt).map_err(|_| StagingError::InvalidPart)?,
        artifact_key: model.artifact_key,
        etag: model.etag,
        checksum_sha256: model.checksum_sha256,
        size_bytes: u64::try_from(model.size_bytes)
            .map_err(|_| StagingError::Persistence("negative part size".to_string()))?,
        created_at_ms: model.created_at_ms,
    })
}

pub(crate) fn global_quota_scope() -> String {
    "global".to_string()
}

pub(crate) fn tenant_quota_scope(tenant_id: &str) -> String {
    format!("tenant:{tenant_id}")
}

pub(crate) fn as_i64(bytes: u64) -> Result<i64, StagingError> {
    i64::try_from(bytes).map_err(|_| StagingError::QuotaExceeded)
}

pub(crate) fn as_u64(bytes: i64) -> Result<u64, StagingError> {
    u64::try_from(bytes)
        .map_err(|_| StagingError::Persistence("negative byte accounting".to_string()))
}

pub(crate) async fn ensure_quota_scope(
    tx: &DatabaseTransaction,
    scope: String,
    limit_bytes: u64,
    now: i64,
) -> Result<(), StagingError> {
    multipart_staging_quota::Entity::insert(multipart_staging_quota::ActiveModel {
        scope: Set(scope),
        limit_bytes: Set(as_i64(limit_bytes)?),
        staged_bytes: Set(0),
        reserved_bytes: Set(0),
        updated_at_ms: Set(now),
    })
    .on_conflict(
        OnConflict::column(multipart_staging_quota::Column::Scope)
            .do_nothing()
            .to_owned(),
    )
    .exec_without_returning(tx)
    .await
    .map_err(|error| StagingError::Persistence(error.to_string()))?;
    Ok(())
}

pub(crate) async fn lock_quota(
    tx: &DatabaseTransaction,
    scope: &str,
) -> Result<multipart_staging_quota::Model, StagingError> {
    multipart_staging_quota::Entity::find_by_id(scope.to_string())
        .lock_exclusive()
        .one(tx)
        .await
        .map_err(|error| StagingError::Persistence(error.to_string()))?
        .ok_or_else(|| StagingError::Persistence("missing multipart quota scope".to_string()))
}

pub(crate) async fn update_quota(
    tx: &DatabaseTransaction,
    model: multipart_staging_quota::Model,
    staged_bytes: i64,
    reserved_bytes: i64,
    now: i64,
) -> Result<(), StagingError> {
    if staged_bytes < 0 || reserved_bytes < 0 {
        return Err(StagingError::Persistence(
            "negative multipart quota".to_string(),
        ));
    }
    let mut active: multipart_staging_quota::ActiveModel = model.into();
    active.staged_bytes = Set(staged_bytes);
    active.reserved_bytes = Set(reserved_bytes);
    active.updated_at_ms = Set(now);
    active
        .update(tx)
        .await
        .map_err(|error| StagingError::Persistence(error.to_string()))?;
    Ok(())
}

#[async_trait]
impl MultipartRepository for PostgresMultipartRepository {
    fn is_durable(&self) -> bool {
        true
    }
    async fn create(&self, upload: MultipartUpload) -> Result<(), StagingError> {
        let active = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::TenantId.eq(upload.identity.tenant_id.clone()))
            .filter(multipart_upload::Column::Lifecycle.eq("OPEN"))
            .count(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        if active >= MAX_ACTIVE_UPLOADS as u64 {
            return Err(StagingError::QuotaExceeded);
        }
        upload_model(&upload)?
            .insert(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(())
    }
    async fn get_authorized(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<MultipartUpload, StagingError> {
        multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::TenantId.eq(identity.tenant_id.clone()))
            .filter(
                multipart_upload::Column::CredentialPolicyId
                    .eq(identity.credential_policy_id.clone()),
            )
            .filter(multipart_upload::Column::Bucket.eq(identity.bucket.clone()))
            .filter(multipart_upload::Column::ObjectKey.eq(identity.key.clone()))
            .one(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)
            .and_then(upload_from_model)
    }
    async fn list_authorized_uploads(
        &self,
        request: &ListMultipartUploadsRequest,
    ) -> Result<ListMultipartUploadsPage, StagingError> {
        let uploads = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::TenantId.eq(&request.tenant_id))
            .filter(multipart_upload::Column::CredentialPolicyId.eq(&request.credential_policy_id))
            .filter(multipart_upload::Column::Bucket.eq(&request.bucket))
            .filter(multipart_upload::Column::Lifecycle.is_in(["OPEN", "COMPLETING", "PUBLISHING"]))
            .filter(multipart_upload::Column::ObjectKey.starts_with(&request.prefix))
            .order_by_asc(multipart_upload::Column::ObjectKey)
            .order_by_asc(multipart_upload::Column::UploadId)
            .all(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .into_iter()
            .map(upload_from_model)
            .collect::<Result<Vec<_>, _>>()?;
        paginate_multipart_uploads(uploads, request)
    }
    async fn replace_part(
        &self,
        identity: &MultipartIdentity,
        part: MultipartPart,
    ) -> Result<Option<MultipartPart>, StagingError> {
        if part.part_number == 0 || part.part_number > MAX_PARTS {
            return Err(StagingError::InvalidPart);
        }
        let transaction = self
            .db
            .begin()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let model = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::TenantId.eq(identity.tenant_id.clone()))
            .filter(
                multipart_upload::Column::CredentialPolicyId
                    .eq(identity.credential_policy_id.clone()),
            )
            .filter(multipart_upload::Column::Bucket.eq(identity.bucket.clone()))
            .filter(multipart_upload::Column::ObjectKey.eq(identity.key.clone()))
            .lock_exclusive()
            .one(&transaction)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)?;
        let mut upload = upload_from_model(model.clone())?;
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(StagingError::NotOpen);
        }
        let previous = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_part_attempt::Column::PartNumber.eq(part.part_number as i32))
            .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
            .one(&transaction)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .map(part_from_model)
            .transpose()?;
        if let Some(old) = &previous
            && part.attempt <= old.attempt
        {
            return Err(StagingError::Persistence(
                "stale part replacement".to_string(),
            ));
        }
        let next = upload
            .staged_bytes
            .saturating_sub(previous.as_ref().map_or(0, |old| old.size_bytes))
            .saturating_add(part.size_bytes);
        if next > upload.snapshot.max_staged_bytes {
            return Err(StagingError::QuotaExceeded);
        }
        if previous.is_some() {
            multipart_part_attempt::Entity::update_many()
                .col_expr(
                    multipart_part_attempt::Column::IsCurrent,
                    sea_orm::sea_query::Expr::value(false),
                )
                .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
                .filter(multipart_part_attempt::Column::PartNumber.eq(part.part_number as i32))
                .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
                .exec(&transaction)
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
        }
        multipart_part_attempt::ActiveModel {
            id: Set(Uuid::now_v7()),
            upload_id: Set(part.upload_id.clone()),
            part_number: Set(part.part_number as i32),
            attempt: Set(part.attempt as i32),
            artifact_key: Set(part.artifact_key.clone()),
            etag: Set(part.etag.clone()),
            checksum_sha256: Set(part.checksum_sha256.clone()),
            size_bytes: Set(
                i64::try_from(part.size_bytes).map_err(|_| StagingError::QuotaExceeded)?
            ),
            reserved_bytes: Set(0),
            lifecycle: Set("CURRENT".to_string()),
            is_current: Set(true),
            created_at_ms: Set(part.created_at_ms),
        }
        .insert(&transaction)
        .await
        .map_err(|error| StagingError::Persistence(error.to_string()))?;
        upload.staged_bytes = next;
        upload.updated_at_ms = now_ms();
        let mut active: multipart_upload::ActiveModel = model.into();
        active.staged_bytes = Set(next as i64);
        active.updated_at_ms = Set(upload.updated_at_ms);
        active
            .update(&transaction)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        transaction
            .commit()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(previous)
    }
    async fn begin_part(
        &self,
        identity: &MultipartIdentity,
        part_number: u32,
        reserved_bytes: u64,
        now: i64,
    ) -> Result<PendingPart, StagingError> {
        if part_number == 0 || part_number > MAX_PARTS {
            return Err(StagingError::InvalidPart);
        }
        let reserved = as_i64(reserved_bytes)?;
        let tx = self
            .db
            .begin()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let model = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::TenantId.eq(identity.tenant_id.clone()))
            .filter(
                multipart_upload::Column::CredentialPolicyId
                    .eq(identity.credential_policy_id.clone()),
            )
            .filter(multipart_upload::Column::Bucket.eq(identity.bucket.clone()))
            .filter(multipart_upload::Column::ObjectKey.eq(identity.key.clone()))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)?;
        let upload = upload_from_model(model.clone())?;
        if upload.lifecycle != MultipartLifecycle::Open || upload.expires_at_ms <= now {
            return Err(StagingError::NotOpen);
        }
        let upload_next = upload
            .staged_bytes
            .checked_add(upload.reserved_bytes)
            .and_then(|bytes| bytes.checked_add(reserved_bytes))
            .ok_or(StagingError::QuotaExceeded)?;
        if upload_next > upload.snapshot.max_staged_bytes {
            return Err(StagingError::QuotaExceeded);
        }
        // Always lock account first, then tenant, preventing cross-tenant deadlocks.
        let global_scope = global_quota_scope();
        let tenant_scope = tenant_quota_scope(&identity.tenant_id);
        ensure_quota_scope(&tx, global_scope.clone(), self.quotas.global_bytes, now).await?;
        ensure_quota_scope(&tx, tenant_scope.clone(), self.quotas.tenant_bytes, now).await?;
        let global = lock_quota(&tx, &global_scope).await?;
        let tenant = lock_quota(&tx, &tenant_scope).await?;
        for quota in [&global, &tenant] {
            let used = as_u64(quota.staged_bytes)?
                .checked_add(as_u64(quota.reserved_bytes)?)
                .ok_or(StagingError::QuotaExceeded)?;
            if used
                .checked_add(reserved_bytes)
                .ok_or(StagingError::QuotaExceeded)?
                > as_u64(quota.limit_bytes)?
            {
                return Err(StagingError::QuotaExceeded);
            }
        }
        let attempt = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_part_attempt::Column::PartNumber.eq(part_number as i32))
            .order_by_desc(multipart_part_attempt::Column::Attempt)
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .map(|value| u32::try_from(value.attempt).map_err(|_| StagingError::InvalidPart))
            .transpose()?
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StagingError::InvalidPart)?;
        let pending = PendingPart {
            upload_id: identity.upload_id.clone(),
            part_number,
            attempt,
            artifact_key: format!(
                "{ARTIFACT_PREFIX}{}/{}/{}/{}",
                identity.tenant_id,
                identity.upload_id,
                part_number,
                Uuid::now_v7()
            ),
            reserved_bytes,
        };
        multipart_part_attempt::ActiveModel {
            id: Set(Uuid::now_v7()),
            upload_id: Set(pending.upload_id.clone()),
            part_number: Set(part_number as i32),
            attempt: Set(attempt as i32),
            artifact_key: Set(pending.artifact_key.clone()),
            etag: Set(String::new()),
            checksum_sha256: Set(String::new()),
            size_bytes: Set(0),
            reserved_bytes: Set(reserved),
            lifecycle: Set("PENDING".to_string()),
            is_current: Set(false),
            created_at_ms: Set(now),
        }
        .insert(&tx)
        .await
        .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let mut active: multipart_upload::ActiveModel = model.into();
        active.reserved_bytes = Set(as_i64(
            upload
                .reserved_bytes
                .checked_add(reserved_bytes)
                .ok_or(StagingError::QuotaExceeded)?,
        )?);
        active.updated_at_ms = Set(now);
        active
            .update(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        update_quota(
            &tx,
            global.clone(),
            global.staged_bytes,
            global
                .reserved_bytes
                .checked_add(reserved)
                .ok_or(StagingError::QuotaExceeded)?,
            now,
        )
        .await?;
        update_quota(
            &tx,
            tenant.clone(),
            tenant.staged_bytes,
            tenant
                .reserved_bytes
                .checked_add(reserved)
                .ok_or(StagingError::QuotaExceeded)?,
            now,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(pending)
    }
    async fn commit_part(
        &self,
        identity: &MultipartIdentity,
        pending: &PendingPart,
        part: MultipartPart,
    ) -> Result<Vec<MultipartPart>, StagingError> {
        if part.upload_id != pending.upload_id
            || part.part_number != pending.part_number
            || part.attempt != pending.attempt
            || part.artifact_key != pending.artifact_key
            || part.size_bytes > pending.reserved_bytes
        {
            return Err(StagingError::InvalidPart);
        }
        let tx = self
            .db
            .begin()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let model = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::TenantId.eq(identity.tenant_id.clone()))
            .filter(
                multipart_upload::Column::CredentialPolicyId
                    .eq(identity.credential_policy_id.clone()),
            )
            .filter(multipart_upload::Column::Bucket.eq(identity.bucket.clone()))
            .filter(multipart_upload::Column::ObjectKey.eq(identity.key.clone()))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)?;
        let upload = upload_from_model(model.clone())?;
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(StagingError::NotOpen);
        }
        let pending_model = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::ArtifactKey.eq(pending.artifact_key.clone()))
            .filter(multipart_part_attempt::Column::Lifecycle.eq("PENDING"))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)?;
        if pending_model.upload_id != identity.upload_id
            || pending_model.reserved_bytes != as_i64(pending.reserved_bytes)?
        {
            return Err(StagingError::NotFound);
        }
        let previous: Vec<_> = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_part_attempt::Column::PartNumber.eq(part.part_number as i32))
            .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
            .all(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .into_iter()
            .map(part_from_model)
            .collect::<Result<_, _>>()?;
        let global_scope = global_quota_scope();
        let tenant_scope = tenant_quota_scope(&identity.tenant_id);
        let global = lock_quota(&tx, &global_scope).await?;
        let tenant = lock_quota(&tx, &tenant_scope).await?;
        let reserved = as_i64(pending.reserved_bytes)?;
        let actual = as_i64(part.size_bytes)?;
        if upload.reserved_bytes < pending.reserved_bytes
            || global.reserved_bytes < reserved
            || tenant.reserved_bytes < reserved
        {
            return Err(StagingError::Persistence(
                "multipart reservation missing".to_string(),
            ));
        }
        multipart_part_attempt::Entity::update_many()
            .col_expr(
                multipart_part_attempt::Column::IsCurrent,
                Expr::value(false),
            )
            .col_expr(
                multipart_part_attempt::Column::Lifecycle,
                Expr::value("RETIRED"),
            )
            .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_part_attempt::Column::PartNumber.eq(part.part_number as i32))
            .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
            .exec(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        multipart_part_attempt::Entity::update_many()
            .col_expr(multipart_part_attempt::Column::Etag, Expr::value(part.etag))
            .col_expr(
                multipart_part_attempt::Column::ChecksumSha256,
                Expr::value(part.checksum_sha256),
            )
            .col_expr(
                multipart_part_attempt::Column::SizeBytes,
                Expr::value(actual),
            )
            .col_expr(
                multipart_part_attempt::Column::ReservedBytes,
                Expr::value(0),
            )
            .col_expr(
                multipart_part_attempt::Column::Lifecycle,
                Expr::value("CURRENT"),
            )
            .col_expr(multipart_part_attempt::Column::IsCurrent, Expr::value(true))
            .filter(multipart_part_attempt::Column::ArtifactKey.eq(pending.artifact_key.clone()))
            .filter(multipart_part_attempt::Column::Lifecycle.eq("PENDING"))
            .exec(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let now = now_ms();
        let mut active: multipart_upload::ActiveModel = model.into();
        active.reserved_bytes = Set(as_i64(upload.reserved_bytes - pending.reserved_bytes)?);
        active.staged_bytes = Set(as_i64(
            upload
                .staged_bytes
                .checked_add(part.size_bytes)
                .ok_or(StagingError::QuotaExceeded)?,
        )?);
        active.updated_at_ms = Set(now);
        active
            .update(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        update_quota(
            &tx,
            global.clone(),
            global
                .staged_bytes
                .checked_add(actual)
                .ok_or(StagingError::QuotaExceeded)?,
            global.reserved_bytes - reserved,
            now,
        )
        .await?;
        update_quota(
            &tx,
            tenant.clone(),
            tenant
                .staged_bytes
                .checked_add(actual)
                .ok_or(StagingError::QuotaExceeded)?,
            tenant.reserved_bytes - reserved,
            now,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(previous)
    }
    async fn discard_pending(
        &self,
        identity: &MultipartIdentity,
        pending: &PendingPart,
    ) -> Result<(), StagingError> {
        let _ = identity;
        self.release_artifact(&pending.artifact_key).await
    }
    async fn cleanup_candidates(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<CleanupCandidate>, StagingError> {
        let attempts = multipart_part_attempt::Entity::find()
            .order_by_asc(multipart_part_attempt::Column::CreatedAtMs)
            .limit((limit.saturating_mul(4)) as u64)
            .all(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let mut result = Vec::new();
        for attempt in attempts {
            let upload = multipart_upload::Entity::find()
                .filter(multipart_upload::Column::UploadId.eq(attempt.upload_id.clone()))
                .one(&self.db)
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            let Some(upload) = upload else { continue };
            let pending_is_old = attempt.lifecycle == "PENDING"
                && attempt.created_at_ms <= now - RECONCILIATION_GRACE.as_millis() as i64;
            if matches!(
                upload.lifecycle.as_str(),
                "COMPLETED" | "ABORTED" | "EXPIRED"
            ) || attempt.lifecycle == "RETIRED"
                || pending_is_old
            {
                result.push(CleanupCandidate {
                    upload_id: attempt.upload_id,
                    artifact_key: attempt.artifact_key,
                });
                if result.len() == limit {
                    break;
                }
            }
        }
        Ok(result)
    }
    async fn confirm_artifact_deleted(&self, artifact_key: &str) -> Result<(), StagingError> {
        let attempt = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::ArtifactKey.eq(artifact_key.to_string()))
            .one(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        if attempt.is_none() {
            return Ok(());
        }
        self.release_artifact(artifact_key).await
    }
    async fn known_artifact_keys(&self) -> Result<HashMap<String, i64>, StagingError> {
        Ok(multipart_part_attempt::Entity::find()
            .all(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .into_iter()
            .map(|part| (part.artifact_key, part.created_at_ms))
            .collect())
    }
    async fn list_parts(
        &self,
        identity: &MultipartIdentity,
        marker: u32,
        limit: usize,
    ) -> Result<(Vec<MultipartPart>, bool), StagingError> {
        self.get_authorized(identity).await?;
        let mut parts: Vec<_> = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
            .filter(multipart_part_attempt::Column::PartNumber.gt(marker as i32))
            .order_by_asc(multipart_part_attempt::Column::PartNumber)
            .limit((limit + 1) as u64)
            .all(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .into_iter()
            .map(part_from_model)
            .collect::<Result<_, _>>()?;
        let truncated = parts.len() > limit;
        parts.truncate(limit);
        Ok((parts, truncated))
    }
    async fn acquire_completion(
        &self,
        identity: &MultipartIdentity,
        fingerprint: &str,
        parts: &[CompletePart],
        owner: &str,
        lease_expires_at_ms: i64,
        now: i64,
    ) -> Result<CompletionAcquire, StagingError> {
        let tx = self
            .db
            .begin()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let model = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::TenantId.eq(identity.tenant_id.clone()))
            .filter(
                multipart_upload::Column::CredentialPolicyId
                    .eq(identity.credential_policy_id.clone()),
            )
            .filter(multipart_upload::Column::Bucket.eq(identity.bucket.clone()))
            .filter(multipart_upload::Column::ObjectKey.eq(identity.key.clone()))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)?;
        let upload = upload_from_model(model.clone())?;
        if upload.lifecycle == MultipartLifecycle::Completed {
            let result = upload.completion_result.ok_or_else(|| {
                StagingError::Persistence("completed upload is missing its result".to_string())
            })?;
            tx.commit()
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            return if upload.complete_request_fingerprint.as_deref() == Some(fingerprint) {
                Ok(CompletionAcquire::Replayed(result))
            } else {
                Err(StagingError::CompletionConflict)
            };
        }
        if upload.lifecycle == MultipartLifecycle::Publishing {
            return if upload.complete_request_fingerprint.as_deref() == Some(fingerprint) {
                Ok(CompletionAcquire::Busy)
            } else {
                Err(StagingError::CompletionConflict)
            };
        }
        if upload.lifecycle == MultipartLifecycle::Aborted
            || upload.lifecycle == MultipartLifecycle::Expired
        {
            return Err(StagingError::NotOpen);
        }
        if upload.lifecycle == MultipartLifecycle::Completing
            && upload.complete_request_fingerprint.as_deref() != Some(fingerprint)
        {
            return Err(StagingError::CompletionConflict);
        }
        if upload.lifecycle == MultipartLifecycle::Completing
            && upload
                .completion_lease_expires_at_ms
                .is_some_and(|expires| expires > now)
        {
            tx.commit()
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            return Ok(CompletionAcquire::Busy);
        }
        if upload.lifecycle == MultipartLifecycle::Open && upload.expires_at_ms <= now {
            return Err(StagingError::NotOpen);
        }
        let cleanup_parts: Vec<_> = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
            .order_by_asc(multipart_part_attempt::Column::PartNumber)
            .all(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .into_iter()
            .map(part_from_model)
            .collect::<Result<_, _>>()?;
        let selected_parts = validate_selected_parts(&cleanup_parts, parts)?;
        let fencing_token = upload
            .completion_fencing_token
            .checked_add(1)
            .ok_or_else(|| {
                StagingError::Persistence("completion fencing token exhausted".to_string())
            })?;
        let mut active: multipart_upload::ActiveModel = model.into();
        active.lifecycle = Set("COMPLETING".to_string());
        active.complete_request_fingerprint = Set(Some(fingerprint.to_string()));
        active.completion_lease_owner = Set(Some(owner.to_string()));
        active.completion_lease_expires_at_ms = Set(Some(lease_expires_at_ms));
        active.completion_fencing_token = Set(i64::try_from(fencing_token).map_err(|_| {
            StagingError::Persistence("invalid completion fencing token".to_string())
        })?);
        active.updated_at_ms = Set(now);
        active
            .update(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        tx.commit()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(CompletionAcquire::Acquired(CompletionLease {
            fencing_token,
            selected_parts,
            cleanup_parts,
        }))
    }
    async fn renew_completion(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        lease_expires_at_ms: i64,
    ) -> Result<(), StagingError> {
        let result = multipart_upload::Entity::update_many()
            .col_expr(
                multipart_upload::Column::CompletionLeaseExpiresAtMs,
                Expr::value(Some(lease_expires_at_ms)),
            )
            .col_expr(multipart_upload::Column::UpdatedAtMs, Expr::value(now_ms()))
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::TenantId.eq(identity.tenant_id.clone()))
            .filter(multipart_upload::Column::Lifecycle.eq("COMPLETING"))
            .filter(
                multipart_upload::Column::CompletionFencingToken
                    .eq(i64::try_from(fencing_token).map_err(|_| StagingError::Fenced)?),
            )
            .exec(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        (result.rows_affected == 1)
            .then_some(())
            .ok_or(StagingError::Fenced)
    }
    async fn check_completion_lease(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        now: i64,
    ) -> Result<(), StagingError> {
        let upload = self.get_authorized(identity).await?;
        (upload.lifecycle == MultipartLifecycle::Completing
            && upload.completion_fencing_token == fencing_token
            && upload
                .completion_lease_expires_at_ms
                .is_some_and(|expires| expires > now))
        .then_some(())
        .ok_or(StagingError::Fenced)
    }
    async fn begin_destination_commit(
        &self,
        identity: &MultipartIdentity,
        fingerprint: &str,
        fencing_token: u64,
        operation_id: Uuid,
        now: i64,
    ) -> Result<DestinationCommitPermit, StagingError> {
        if operation_id
            != DestinationCommitPermit::deterministic_operation_id(identity, fingerprint)
        {
            return Err(StagingError::Fenced);
        }
        let tx = self
            .db
            .begin()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let model = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(&identity.upload_id))
            .filter(multipart_upload::Column::TenantId.eq(&identity.tenant_id))
            .filter(multipart_upload::Column::CredentialPolicyId.eq(&identity.credential_policy_id))
            .filter(multipart_upload::Column::Bucket.eq(&identity.bucket))
            .filter(multipart_upload::Column::ObjectKey.eq(&identity.key))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)?;
        let upload = upload_from_model(model.clone())?;
        if upload.lifecycle != MultipartLifecycle::Completing
            || upload.complete_request_fingerprint.as_deref() != Some(fingerprint)
            || upload.completion_fencing_token != fencing_token
            || upload
                .completion_lease_expires_at_ms
                .is_none_or(|expiry| expiry <= now)
        {
            return Err(StagingError::Fenced);
        }
        let mut active: multipart_upload::ActiveModel = model.into();
        active.lifecycle = Set("PUBLISHING".to_string());
        active.destination_operation_id = Set(Some(operation_id));
        active.publishing_started_at_ms = Set(Some(now));
        active.destination_commit = Set(None);
        active.completion_lease_owner = Set(None);
        active.completion_lease_expires_at_ms = Set(None);
        active.updated_at_ms = Set(now);
        active
            .update(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        tx.commit()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(DestinationCommitPermit {
            upload_id: identity.upload_id.clone(),
            completion_fingerprint: fingerprint.to_string(),
            fencing_token,
            operation_id,
        })
    }
    async fn validate_destination_commit_permit(
        &self,
        permit: &DestinationCommitPermit,
    ) -> Result<(), StagingError> {
        let upload = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(&permit.upload_id))
            .one(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::Fenced)
            .and_then(upload_from_model)?;
        permit_matches(&upload, permit)
            .then_some(())
            .ok_or(StagingError::Fenced)
    }
    async fn record_destination_commit(
        &self,
        permit: &DestinationCommitPermit,
        result: MultipartCompletionResult,
        now: i64,
    ) -> Result<(), StagingError> {
        let tx = self
            .db
            .begin()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let model = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(&permit.upload_id))
            .lock_exclusive()
            .one(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::Fenced)?;
        let upload = upload_from_model(model.clone())?;
        if !permit_matches(&upload, permit) {
            return Err(StagingError::Fenced);
        }
        let record = DestinationCommitRecord {
            operation_id: permit.operation_id,
            result,
            committed_at_ms: now,
        };
        if let Some(existing) = upload.destination_commit {
            return if existing.operation_id == record.operation_id
                && existing.result == record.result
            {
                Ok(())
            } else {
                Err(StagingError::CompletionConflict)
            };
        }
        let mut active: multipart_upload::ActiveModel = model.into();
        active.destination_commit = Set(Some(serde_json::to_value(record).map_err(json_error)?));
        active.updated_at_ms = Set(now);
        active
            .update(&tx)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        tx.commit()
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(())
    }
    async fn release_destination_commit_after_proven_absence(
        &self,
        permit: &DestinationCommitPermit,
        now: i64,
    ) -> Result<(), StagingError> {
        let updated = multipart_upload::Entity::update_many()
            .col_expr(
                multipart_upload::Column::Lifecycle,
                Expr::value("COMPLETING"),
            )
            .col_expr(
                multipart_upload::Column::DestinationOperationId,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                multipart_upload::Column::PublishingStartedAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                multipart_upload::Column::CompletionLeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                multipart_upload::Column::CompletionLeaseExpiresAtMs,
                Expr::value(Some(now)),
            )
            .col_expr(multipart_upload::Column::UpdatedAtMs, Expr::value(now))
            .filter(multipart_upload::Column::UploadId.eq(&permit.upload_id))
            .filter(multipart_upload::Column::Lifecycle.eq("PUBLISHING"))
            .filter(
                multipart_upload::Column::CompleteRequestFingerprint
                    .eq(&permit.completion_fingerprint),
            )
            .filter(
                multipart_upload::Column::CompletionFencingToken
                    .eq(i64::try_from(permit.fencing_token).map_err(|_| StagingError::Fenced)?),
            )
            .filter(multipart_upload::Column::DestinationOperationId.eq(permit.operation_id))
            .filter(multipart_upload::Column::DestinationCommit.is_null())
            .exec(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        (updated.rows_affected == 1)
            .then_some(())
            .ok_or(StagingError::Fenced)
    }
    async fn publishing_uploads(
        &self,
        limit: usize,
    ) -> Result<Vec<PublishingMultipartUpload>, StagingError> {
        multipart_upload::Entity::find()
            .filter(multipart_upload::Column::Lifecycle.eq("PUBLISHING"))
            .order_by_asc(multipart_upload::Column::PublishingStartedAtMs)
            .order_by_asc(multipart_upload::Column::UploadId)
            .limit(limit as u64)
            .all(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .into_iter()
            .map(upload_from_model)
            .map(|upload| upload.and_then(publishing_upload))
            .collect()
    }
    async fn complete_completion(
        &self,
        identity: &MultipartIdentity,
        permit: &DestinationCommitPermit,
        result: MultipartCompletionResult,
        now: i64,
    ) -> Result<(), StagingError> {
        let upload = self.get_authorized(identity).await?;
        if !permit_matches(&upload, permit)
            || upload
                .destination_commit
                .as_ref()
                .map(|commit| &commit.result)
                != Some(&result)
        {
            return Err(StagingError::Fenced);
        }
        let result_json = serde_json::to_value(&result).map_err(json_error)?;
        let updated = multipart_upload::Entity::update_many()
            .col_expr(
                multipart_upload::Column::Lifecycle,
                Expr::value("COMPLETED"),
            )
            .col_expr(
                multipart_upload::Column::CompletionResult,
                Expr::value(result_json),
            )
            .col_expr(
                multipart_upload::Column::CompletionLeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                multipart_upload::Column::CompletionLeaseExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                multipart_upload::Column::TombstoneUntilMs,
                Expr::value(Some(now + DEFAULT_EXPIRY.as_millis() as i64)),
            )
            .col_expr(multipart_upload::Column::UpdatedAtMs, Expr::value(now))
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::Lifecycle.eq("PUBLISHING"))
            .filter(
                multipart_upload::Column::CompletionFencingToken
                    .eq(i64::try_from(permit.fencing_token).map_err(|_| StagingError::Fenced)?),
            )
            .filter(multipart_upload::Column::DestinationOperationId.eq(permit.operation_id))
            .exec(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        (updated.rows_affected == 1)
            .then_some(())
            .ok_or(StagingError::Fenced)
    }
    async fn clear_destination_commit_reference(
        &self,
        identity: &MultipartIdentity,
        expected_operation_id: Uuid,
    ) -> Result<(), StagingError> {
        let updated = multipart_upload::Entity::update_many()
            .col_expr(
                multipart_upload::Column::DestinationOperationId,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                multipart_upload::Column::DestinationCommit,
                Expr::value(Option::<serde_json::Value>::None),
            )
            .col_expr(
                multipart_upload::Column::PublishingStartedAtMs,
                Expr::value(Option::<i64>::None),
            )
            .filter(multipart_upload::Column::UploadId.eq(&identity.upload_id))
            .filter(multipart_upload::Column::TenantId.eq(&identity.tenant_id))
            .filter(multipart_upload::Column::CredentialPolicyId.eq(&identity.credential_policy_id))
            .filter(multipart_upload::Column::Bucket.eq(&identity.bucket))
            .filter(multipart_upload::Column::ObjectKey.eq(&identity.key))
            .filter(multipart_upload::Column::Lifecycle.is_in(["COMPLETED", "ABORTED", "EXPIRED"]))
            .filter(multipart_upload::Column::DestinationOperationId.eq(expected_operation_id))
            .exec(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        (updated.rows_affected == 1)
            .then_some(())
            .ok_or(StagingError::Fenced)
    }
    async fn abort(
        &self,
        identity: &MultipartIdentity,
        now: i64,
    ) -> Result<Vec<MultipartPart>, AbortMutationError> {
        let upload = self
            .get_authorized(identity)
            .await
            .map_err(AbortMutationError::PreMutation)?;
        if upload.lifecycle == MultipartLifecycle::Aborted {
            return Ok(Vec::new());
        }
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(AbortMutationError::PreMutation(StagingError::NotOpen));
        }
        let result = multipart_upload::Entity::update_many()
            .col_expr(
                multipart_upload::Column::Lifecycle,
                sea_orm::sea_query::Expr::value("ABORTED"),
            )
            .col_expr(
                multipart_upload::Column::TombstoneUntilMs,
                sea_orm::sea_query::Expr::value(Some(now + DEFAULT_EXPIRY.as_millis() as i64)),
            )
            .filter(multipart_upload::Column::UploadId.eq(identity.upload_id.clone()))
            .filter(multipart_upload::Column::Lifecycle.eq("OPEN"))
            .exec(&self.db)
            .await
            .map_err(|error| {
                AbortMutationError::MutationUnknown(StagingError::Persistence(error.to_string()))
            })?;
        if result.rows_affected != 1 {
            return Err(AbortMutationError::PreMutation(StagingError::NotOpen));
        }
        #[cfg(any(test, debug_assertions))]
        if FAIL_ABORT_AFTER_UPDATE.swap(false, Ordering::AcqRel) {
            return Err(AbortMutationError::MutationUnknown(
                StagingError::Persistence("injected post-abort persistence failure".to_string()),
            ));
        }
        self.list_parts(identity, 0, MAX_PARTS as usize)
            .await
            .map(|value| value.0)
            .map_err(AbortMutationError::MutationUnknown)
    }
    async fn delete_terminal_upload(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<(), StagingError> {
        let upload = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::UploadId.eq(&identity.upload_id))
            .filter(multipart_upload::Column::TenantId.eq(&identity.tenant_id))
            .filter(multipart_upload::Column::CredentialPolicyId.eq(&identity.credential_policy_id))
            .filter(multipart_upload::Column::Bucket.eq(&identity.bucket))
            .filter(multipart_upload::Column::ObjectKey.eq(&identity.key))
            .one(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .ok_or(StagingError::NotFound)?;
        if !matches!(upload.lifecycle.as_str(), "ABORTED" | "EXPIRED") {
            return Err(StagingError::NotOpen);
        }
        if upload.destination_operation_id.is_some() {
            return Err(StagingError::Fenced);
        }
        let attempts = multipart_part_attempt::Entity::find()
            .filter(multipart_part_attempt::Column::UploadId.eq(&identity.upload_id))
            .count(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        if attempts > 0 {
            return Err(StagingError::Persistence(
                "multipart artifacts remain after cleanup".to_string(),
            ));
        }
        multipart_upload::Entity::delete_by_id(upload.id)
            .exec(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(())
    }
    async fn terminal_upload_candidates(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<MultipartIdentity>, StagingError> {
        multipart_upload::Entity::find()
            .filter(multipart_upload::Column::Lifecycle.is_in(["COMPLETED", "ABORTED", "EXPIRED"]))
            .filter(multipart_upload::Column::TombstoneUntilMs.lte(now_ms))
            .order_by_asc(multipart_upload::Column::UpdatedAtMs)
            .limit(limit as u64)
            .all(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?
            .into_iter()
            .map(upload_from_model)
            .map(|upload| upload.map(|upload| upload.identity))
            .collect()
    }
    async fn retire_terminal_uploads(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<RetiredMultipartUpload>, StagingError> {
        let candidates = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::Lifecycle.is_in(["COMPLETED", "ABORTED", "EXPIRED"]))
            .filter(multipart_upload::Column::TombstoneUntilMs.lte(now_ms))
            .order_by_asc(multipart_upload::Column::UpdatedAtMs)
            .limit(limit as u64)
            .all(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let mut retired = Vec::new();
        for upload in candidates {
            let attempts = multipart_part_attempt::Entity::find()
                .filter(multipart_part_attempt::Column::UploadId.eq(&upload.upload_id))
                .count(&self.db)
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            if attempts > 0 || upload.destination_operation_id.is_some() {
                continue;
            }
            multipart_upload::Entity::delete_by_id(upload.id)
                .exec(&self.db)
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            retired.push(RetiredMultipartUpload {
                upload_id: upload.upload_id,
                tenant_id: upload.tenant_id,
                namespace_epoch: upload
                    .namespace_epoch
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| {
                        StagingError::Persistence("invalid namespace epoch".to_string())
                    })?,
            });
        }
        Ok(retired)
    }
    async fn reap_expired(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<MultipartPart>, StagingError> {
        let uploads = multipart_upload::Entity::find()
            .filter(multipart_upload::Column::Lifecycle.eq("OPEN"))
            .filter(multipart_upload::Column::ExpiresAtMs.lte(now))
            .limit(limit as u64)
            .all(&self.db)
            .await
            .map_err(|error| StagingError::Persistence(error.to_string()))?;
        let mut parts = Vec::new();
        for model in uploads {
            multipart_upload::Entity::update_many()
                .col_expr(
                    multipart_upload::Column::Lifecycle,
                    sea_orm::sea_query::Expr::value("EXPIRED"),
                )
                .col_expr(
                    multipart_upload::Column::TombstoneUntilMs,
                    Expr::value(Some(now + DEFAULT_EXPIRY.as_millis() as i64)),
                )
                .col_expr(multipart_upload::Column::UpdatedAtMs, Expr::value(now))
                .filter(multipart_upload::Column::UploadId.eq(model.upload_id.clone()))
                .filter(multipart_upload::Column::Lifecycle.eq("OPEN"))
                .exec(&self.db)
                .await
                .map_err(|error| StagingError::Persistence(error.to_string()))?;
            parts.extend(
                multipart_part_attempt::Entity::find()
                    .filter(multipart_part_attempt::Column::UploadId.eq(model.upload_id))
                    .filter(multipart_part_attempt::Column::IsCurrent.eq(true))
                    .all(&self.db)
                    .await
                    .map_err(|error| StagingError::Persistence(error.to_string()))?
                    .into_iter()
                    .map(part_from_model)
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        Ok(parts)
    }
    async fn audit(&self, audit: CleanupAudit) -> Result<(), StagingError> {
        multipart_cleanup_audit::ActiveModel {
            id: Set(audit.id),
            upload_id: Set(audit.upload_id),
            kind: Set(audit.kind),
            detail: Set(audit.detail),
            created_at_ms: Set(audit.created_at_ms),
        }
        .insert(&self.db)
        .await
        .map_err(|error| StagingError::Persistence(error.to_string()))?;
        Ok(())
    }
}
