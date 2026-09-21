//! Extracted from `multipart_staging.rs`; re-exported from `crate::multipart_staging`.

use super::*;

#[derive(Default)]
pub(crate) struct MemoryState {
    pub(crate) uploads: HashMap<String, MultipartUpload>,
    pub(crate) parts: HashMap<(String, u32), MultipartPart>,
    pub(crate) attempts: HashMap<String, MemoryAttempt>,
    pub(crate) audits: Vec<CleanupAudit>,
    pub(crate) pending: HashMap<String, PendingPart>,
}

#[derive(Clone)]
pub(crate) struct MemoryAttempt {
    pub(crate) part: MultipartPart,
    pub(crate) reserved_bytes: u64,
    pub(crate) lifecycle: &'static str,
}

/// Test/development implementation. Production construction intentionally
/// requires a durable Postgres repository and never falls back to this type.
#[derive(Clone)]
pub struct InMemoryMultipartRepository {
    pub(crate) state: Arc<Mutex<MemoryState>>,
    pub(crate) quotas: StagingQuotaLimits,
}

impl InMemoryMultipartRepository {
    pub fn new() -> Self {
        Self::with_quotas(StagingQuotaLimits {
            tenant_bytes: i64::MAX as u64,
            global_bytes: i64::MAX as u64,
        })
    }

    pub fn with_quotas(quotas: StagingQuotaLimits) -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryState::default())),
            quotas,
        }
    }
}

impl Default for InMemoryMultipartRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MultipartRepository for InMemoryMultipartRepository {
    fn is_durable(&self) -> bool {
        false
    }

    async fn create(&self, upload: MultipartUpload) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let active = state
            .uploads
            .values()
            .filter(|candidate| {
                candidate.identity.tenant_id == upload.identity.tenant_id
                    && candidate.lifecycle == MultipartLifecycle::Open
            })
            .count();
        if active >= MAX_ACTIVE_UPLOADS {
            return Err(StagingError::QuotaExceeded);
        }
        if state
            .uploads
            .insert(upload.identity.upload_id.clone(), upload)
            .is_some()
        {
            return Err(StagingError::Persistence("duplicate upload id".to_string()));
        }
        Ok(())
    }

    async fn get_authorized(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<MultipartUpload, StagingError> {
        self.state
            .lock()
            .await
            .uploads
            .get(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .cloned()
            .ok_or(StagingError::NotFound)
    }

    async fn list_authorized_uploads(
        &self,
        request: &ListMultipartUploadsRequest,
    ) -> Result<ListMultipartUploadsPage, StagingError> {
        let uploads = self
            .state
            .lock()
            .await
            .uploads
            .values()
            .filter(|upload| {
                upload.identity.tenant_id == request.tenant_id
                    && upload.identity.credential_policy_id == request.credential_policy_id
                    && upload.identity.bucket == request.bucket
                    && matches!(
                        upload.lifecycle,
                        MultipartLifecycle::Open
                            | MultipartLifecycle::Completing
                            | MultipartLifecycle::Publishing
                    )
            })
            .cloned()
            .collect();
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
        let mut state = self.state.lock().await;
        let previous = state
            .parts
            .get(&(identity.upload_id.clone(), part.part_number))
            .cloned();
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(StagingError::NotFound)?;
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(StagingError::NotOpen);
        }
        let next = upload
            .staged_bytes
            .saturating_sub(previous.as_ref().map_or(0, |value| value.size_bytes))
            .saturating_add(part.size_bytes);
        if next > upload.snapshot.max_staged_bytes {
            return Err(StagingError::QuotaExceeded);
        }
        if let Some(previous) = &previous
            && part.attempt <= previous.attempt
        {
            return Err(StagingError::Persistence(
                "stale part replacement".to_string(),
            ));
        }
        upload.staged_bytes = next;
        upload.updated_at_ms = now_ms();
        state
            .parts
            .insert((identity.upload_id.clone(), part.part_number), part);
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
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(StagingError::NotFound)?;
        if upload.lifecycle != MultipartLifecycle::Open || upload.expires_at_ms <= now {
            return Err(StagingError::NotOpen);
        }
        if upload
            .staged_bytes
            .checked_add(upload.reserved_bytes)
            .and_then(|used| used.checked_add(reserved_bytes))
            .ok_or(StagingError::QuotaExceeded)?
            > upload.snapshot.max_staged_bytes
        {
            return Err(StagingError::QuotaExceeded);
        }
        let (tenant_used, global_used) =
            state
                .uploads
                .values()
                .fold((0u64, 0u64), |(tenant, global), candidate| {
                    let used = candidate
                        .staged_bytes
                        .saturating_add(candidate.reserved_bytes);
                    (
                        tenant
                            + if candidate.identity.tenant_id == identity.tenant_id {
                                used
                            } else {
                                0
                            },
                        global.saturating_add(used),
                    )
                });
        if tenant_used
            .checked_add(reserved_bytes)
            .ok_or(StagingError::QuotaExceeded)?
            > self.quotas.tenant_bytes
            || global_used
                .checked_add(reserved_bytes)
                .ok_or(StagingError::QuotaExceeded)?
                > self.quotas.global_bytes
        {
            return Err(StagingError::QuotaExceeded);
        }
        let attempt = state
            .attempts
            .values()
            .filter(|value| {
                value.part.upload_id == identity.upload_id && value.part.part_number == part_number
            })
            .map(|value| value.part.attempt)
            .max()
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
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .expect("upload checked above");
        upload.reserved_bytes += reserved_bytes;
        upload.updated_at_ms = now;
        let part = MultipartPart {
            upload_id: identity.upload_id.clone(),
            part_number,
            attempt,
            artifact_key: pending.artifact_key.clone(),
            etag: String::new(),
            checksum_sha256: String::new(),
            size_bytes: 0,
            created_at_ms: now,
        };
        state.attempts.insert(
            pending.artifact_key.clone(),
            MemoryAttempt {
                part,
                reserved_bytes,
                lifecycle: "PENDING",
            },
        );
        state
            .pending
            .insert(pending.artifact_key.clone(), pending.clone());
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
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .cloned()
            .ok_or(StagingError::NotFound)?;
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(StagingError::NotOpen);
        }
        let previous = state
            .parts
            .get(&(identity.upload_id.clone(), part.part_number))
            .cloned()
            .into_iter()
            .collect::<Vec<_>>();
        for old in &previous {
            if let Some(old_attempt) = state.attempts.get_mut(&old.artifact_key) {
                old_attempt.lifecycle = "RETIRED";
            }
        }
        {
            let attempt = state
                .attempts
                .get_mut(&pending.artifact_key)
                .ok_or(StagingError::NotFound)?;
            if attempt.lifecycle != "PENDING" || attempt.reserved_bytes != pending.reserved_bytes {
                return Err(StagingError::NotFound);
            }
            attempt.part = part.clone();
            attempt.reserved_bytes = 0;
            attempt.lifecycle = "CURRENT";
        }
        state.pending.remove(&pending.artifact_key);
        state
            .parts
            .insert((identity.upload_id.clone(), part.part_number), part.clone());
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .expect("upload checked above");
        upload.reserved_bytes = upload
            .reserved_bytes
            .checked_sub(pending.reserved_bytes)
            .ok_or_else(|| {
                StagingError::Persistence("multipart reservation missing".to_string())
            })?;
        upload.staged_bytes = upload
            .staged_bytes
            .checked_add(part.size_bytes)
            .ok_or(StagingError::QuotaExceeded)?;
        upload.updated_at_ms = now_ms();
        Ok(previous)
    }

    async fn discard_pending(
        &self,
        _identity: &MultipartIdentity,
        pending: &PendingPart,
    ) -> Result<(), StagingError> {
        self.confirm_artifact_deleted(&pending.artifact_key).await
    }

    async fn cleanup_candidates(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<CleanupCandidate>, StagingError> {
        let state = self.state.lock().await;
        Ok(state
            .attempts
            .iter()
            .filter_map(|(key, attempt)| {
                let upload = state.uploads.get(&attempt.part.upload_id)?;
                let old_pending = attempt.lifecycle == "PENDING"
                    && attempt.part.created_at_ms <= now - RECONCILIATION_GRACE.as_millis() as i64;
                (matches!(
                    upload.lifecycle,
                    MultipartLifecycle::Completed
                        | MultipartLifecycle::Aborted
                        | MultipartLifecycle::Expired
                ) || attempt.lifecycle == "RETIRED"
                    || old_pending)
                    .then(|| CleanupCandidate {
                        upload_id: attempt.part.upload_id.clone(),
                        artifact_key: key.clone(),
                    })
            })
            .take(limit)
            .collect())
    }

    async fn confirm_artifact_deleted(&self, artifact_key: &str) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let Some(attempt) = state.attempts.remove(artifact_key) else {
            return Ok(());
        };
        state.pending.remove(artifact_key);
        state
            .parts
            .retain(|_, part| part.artifact_key != artifact_key);
        let upload = state
            .uploads
            .get_mut(&attempt.part.upload_id)
            .ok_or_else(|| StagingError::Persistence("multipart upload disappeared".to_string()))?;
        if attempt.lifecycle == "PENDING" {
            upload.reserved_bytes = upload
                .reserved_bytes
                .checked_sub(attempt.reserved_bytes)
                .ok_or_else(|| {
                    StagingError::Persistence("multipart reservation underflow".to_string())
                })?;
        } else {
            upload.staged_bytes = upload
                .staged_bytes
                .checked_sub(attempt.part.size_bytes)
                .ok_or_else(|| {
                    StagingError::Persistence("multipart staged bytes underflow".to_string())
                })?;
        }
        upload.updated_at_ms = now_ms();
        Ok(())
    }

    async fn known_artifact_keys(&self) -> Result<HashMap<String, i64>, StagingError> {
        Ok(self
            .state
            .lock()
            .await
            .attempts
            .iter()
            .map(|(key, value)| (key.clone(), value.part.created_at_ms))
            .collect())
    }

    async fn list_parts(
        &self,
        identity: &MultipartIdentity,
        marker: u32,
        limit: usize,
    ) -> Result<(Vec<MultipartPart>, bool), StagingError> {
        self.get_authorized(identity).await?;
        let mut parts: Vec<_> = self
            .state
            .lock()
            .await
            .parts
            .values()
            .filter(|part| part.upload_id == identity.upload_id && part.part_number > marker)
            .cloned()
            .collect();
        parts.sort_by_key(|part| part.part_number);
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
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .cloned()
            .ok_or(StagingError::NotFound)?;
        if upload.lifecycle == MultipartLifecycle::Completed {
            let result = upload.completion_result.ok_or_else(|| {
                StagingError::Persistence("completed upload is missing its result".to_string())
            })?;
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
            return Ok(CompletionAcquire::Busy);
        }
        if upload.lifecycle == MultipartLifecycle::Open && upload.expires_at_ms <= now {
            return Err(StagingError::NotOpen);
        }
        let mut cleanup_parts: Vec<_> = state
            .parts
            .values()
            .filter(|part| part.upload_id == identity.upload_id)
            .cloned()
            .collect();
        cleanup_parts.sort_by_key(|part| part.part_number);
        let selected_parts = validate_selected_parts(&cleanup_parts, parts)?;
        let fencing_token = upload
            .completion_fencing_token
            .checked_add(1)
            .ok_or_else(|| {
                StagingError::Persistence("completion fencing token exhausted".to_string())
            })?;
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .expect("upload cloned above");
        upload.lifecycle = MultipartLifecycle::Completing;
        upload.complete_request_fingerprint = Some(fingerprint.to_string());
        upload.completion_lease_owner = Some(owner.to_string());
        upload.completion_lease_expires_at_ms = Some(lease_expires_at_ms);
        upload.completion_fencing_token = fencing_token;
        upload.updated_at_ms = now;
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
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(StagingError::NotFound)?;
        if upload.lifecycle != MultipartLifecycle::Completing
            || upload.completion_fencing_token != fencing_token
        {
            return Err(StagingError::Fenced);
        }
        upload.completion_lease_expires_at_ms = Some(lease_expires_at_ms);
        upload.updated_at_ms = now_ms();
        Ok(())
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
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(StagingError::NotFound)?;
        if upload.lifecycle != MultipartLifecycle::Completing
            || upload.complete_request_fingerprint.as_deref() != Some(fingerprint)
            || upload.completion_fencing_token != fencing_token
            || upload
                .completion_lease_expires_at_ms
                .is_none_or(|expiry| expiry <= now)
        {
            return Err(StagingError::Fenced);
        }
        upload.lifecycle = MultipartLifecycle::Publishing;
        upload.destination_operation_id = Some(operation_id);
        upload.publishing_started_at_ms = Some(now);
        upload.destination_commit = None;
        upload.completion_lease_owner = None;
        upload.completion_lease_expires_at_ms = None;
        upload.updated_at_ms = now;
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
        let state = self.state.lock().await;
        let upload = state
            .uploads
            .get(&permit.upload_id)
            .ok_or(StagingError::Fenced)?;
        permit_matches(upload, permit)
            .then_some(())
            .ok_or(StagingError::Fenced)
    }

    async fn record_destination_commit(
        &self,
        permit: &DestinationCommitPermit,
        result: MultipartCompletionResult,
        now: i64,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get_mut(&permit.upload_id)
            .ok_or(StagingError::Fenced)?;
        if !permit_matches(upload, permit) {
            return Err(StagingError::Fenced);
        }
        let record = DestinationCommitRecord {
            operation_id: permit.operation_id,
            result,
            committed_at_ms: now,
        };
        if let Some(existing) = &upload.destination_commit {
            return if existing.operation_id == record.operation_id
                && existing.result == record.result
            {
                Ok(())
            } else {
                Err(StagingError::CompletionConflict)
            };
        }
        upload.destination_commit = Some(record);
        upload.updated_at_ms = now;
        Ok(())
    }

    async fn release_destination_commit_after_proven_absence(
        &self,
        permit: &DestinationCommitPermit,
        now: i64,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get_mut(&permit.upload_id)
            .ok_or(StagingError::Fenced)?;
        if !permit_matches(upload, permit) || upload.destination_commit.is_some() {
            return Err(StagingError::Fenced);
        }
        upload.lifecycle = MultipartLifecycle::Completing;
        upload.destination_operation_id = None;
        upload.publishing_started_at_ms = None;
        upload.completion_lease_owner = None;
        upload.completion_lease_expires_at_ms = Some(now);
        upload.updated_at_ms = now;
        Ok(())
    }

    async fn publishing_uploads(
        &self,
        limit: usize,
    ) -> Result<Vec<PublishingMultipartUpload>, StagingError> {
        let mut uploads: Vec<_> = self
            .state
            .lock()
            .await
            .uploads
            .values()
            .filter(|upload| upload.lifecycle == MultipartLifecycle::Publishing)
            .cloned()
            .collect();
        uploads.sort_by_key(|upload| {
            (
                upload.publishing_started_at_ms.unwrap_or(i64::MIN),
                upload.identity.upload_id.clone(),
            )
        });
        uploads
            .into_iter()
            .take(limit)
            .map(publishing_upload)
            .collect()
    }

    async fn complete_completion(
        &self,
        identity: &MultipartIdentity,
        permit: &DestinationCommitPermit,
        result: MultipartCompletionResult,
        now: i64,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(StagingError::NotFound)?;
        if !permit_matches(upload, permit)
            || upload
                .destination_commit
                .as_ref()
                .map(|commit| &commit.result)
                != Some(&result)
        {
            return Err(StagingError::Fenced);
        }
        upload.lifecycle = MultipartLifecycle::Completed;
        upload.completion_result = Some(result);
        upload.completion_lease_owner = None;
        upload.completion_lease_expires_at_ms = None;
        upload.tombstone_until_ms = Some(now + DEFAULT_EXPIRY.as_millis() as i64);
        upload.updated_at_ms = now;
        Ok(())
    }

    async fn clear_destination_commit_reference(
        &self,
        identity: &MultipartIdentity,
        expected_operation_id: Uuid,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(StagingError::NotFound)?;
        if !matches!(
            upload.lifecycle,
            MultipartLifecycle::Completed
                | MultipartLifecycle::Aborted
                | MultipartLifecycle::Expired
        ) || upload.destination_operation_id != Some(expected_operation_id)
        {
            return Err(StagingError::Fenced);
        }
        upload.destination_operation_id = None;
        upload.destination_commit = None;
        upload.publishing_started_at_ms = None;
        Ok(())
    }

    async fn abort(
        &self,
        identity: &MultipartIdentity,
        now_ms: i64,
    ) -> Result<Vec<MultipartPart>, AbortMutationError> {
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get_mut(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(AbortMutationError::PreMutation(StagingError::NotFound))?;
        if upload.lifecycle != MultipartLifecycle::Open {
            if upload.lifecycle == MultipartLifecycle::Aborted {
                return Ok(Vec::new());
            }
            return Err(AbortMutationError::PreMutation(StagingError::NotOpen));
        }
        upload.lifecycle = MultipartLifecycle::Aborted;
        upload.tombstone_until_ms = Some(now_ms + DEFAULT_EXPIRY.as_millis() as i64);
        upload.updated_at_ms = now_ms;
        Ok(state
            .parts
            .extract_if(|(upload_id, _), _| upload_id == &identity.upload_id)
            .map(|(_, part)| part)
            .collect())
    }

    async fn delete_terminal_upload(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state
            .uploads
            .get(&identity.upload_id)
            .filter(|upload| same_identity(upload, identity))
            .ok_or(StagingError::NotFound)?;
        if !matches!(
            upload.lifecycle,
            MultipartLifecycle::Aborted | MultipartLifecycle::Expired
        ) || upload.destination_operation_id.is_some()
            || state
                .attempts
                .values()
                .any(|attempt| attempt.part.upload_id == identity.upload_id)
            || state
                .parts
                .values()
                .any(|part| part.upload_id == identity.upload_id)
            || state
                .pending
                .values()
                .any(|pending| pending.upload_id == identity.upload_id)
        {
            return Err(StagingError::Persistence(
                "multipart artifacts remain after cleanup".to_string(),
            ));
        }
        state.uploads.remove(&identity.upload_id);
        Ok(())
    }
    async fn terminal_upload_candidates(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<MultipartIdentity>, StagingError> {
        let state = self.state.lock().await;
        let mut uploads = state
            .uploads
            .values()
            .filter(|upload| {
                matches!(
                    upload.lifecycle,
                    MultipartLifecycle::Completed
                        | MultipartLifecycle::Aborted
                        | MultipartLifecycle::Expired
                ) && upload
                    .tombstone_until_ms
                    .is_some_and(|until| until <= now_ms)
            })
            .collect::<Vec<_>>();
        uploads.sort_by_key(|upload| (upload.updated_at_ms, upload.identity.upload_id.clone()));
        Ok(uploads
            .into_iter()
            .take(limit)
            .map(|upload| upload.identity.clone())
            .collect())
    }
    async fn retire_terminal_uploads(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<RetiredMultipartUpload>, StagingError> {
        let mut state = self.state.lock().await;
        let ids: Vec<_> = state
            .uploads
            .values()
            .filter(|upload| {
                matches!(
                    upload.lifecycle,
                    MultipartLifecycle::Completed
                        | MultipartLifecycle::Aborted
                        | MultipartLifecycle::Expired
                ) && upload
                    .tombstone_until_ms
                    .is_some_and(|until| until <= now_ms)
                    && !state
                        .attempts
                        .values()
                        .any(|attempt| attempt.part.upload_id == upload.identity.upload_id)
                    && !state
                        .pending
                        .values()
                        .any(|pending| pending.upload_id == upload.identity.upload_id)
                    && !state
                        .parts
                        .values()
                        .any(|part| part.upload_id == upload.identity.upload_id)
                    && upload.destination_operation_id.is_none()
            })
            .take(limit)
            .map(|upload| upload.identity.upload_id.clone())
            .collect();
        Ok(ids
            .into_iter()
            .filter_map(|upload_id| state.uploads.remove(&upload_id))
            .map(|upload| RetiredMultipartUpload {
                upload_id: upload.identity.upload_id,
                tenant_id: upload.identity.tenant_id,
                namespace_epoch: upload.namespace_epoch,
            })
            .collect())
    }

    async fn reap_expired(
        &self,
        now_ms: i64,
        limit: usize,
    ) -> Result<Vec<MultipartPart>, StagingError> {
        let mut state = self.state.lock().await;
        let ids: Vec<_> = state
            .uploads
            .values_mut()
            .filter(|upload| {
                upload.lifecycle == MultipartLifecycle::Open && upload.expires_at_ms <= now_ms
            })
            .take(limit)
            .map(|upload| {
                upload.lifecycle = MultipartLifecycle::Expired;
                upload.tombstone_until_ms = Some(now_ms + DEFAULT_EXPIRY.as_millis() as i64);
                upload.updated_at_ms = now_ms;
                upload.identity.upload_id.clone()
            })
            .collect();
        Ok(state
            .parts
            .extract_if(|(upload_id, _), _| ids.contains(upload_id))
            .map(|(_, part)| part)
            .collect())
    }

    async fn audit(&self, audit: CleanupAudit) -> Result<(), StagingError> {
        self.state.lock().await.audits.push(audit);
        Ok(())
    }
}
