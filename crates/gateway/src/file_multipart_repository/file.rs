//! Extracted from `file_multipart_repository.rs`; re-exported from `crate::file_multipart_repository`.

use super::*;

pub(crate) struct FileMultipartEntry {
    pub(crate) directory: PathBuf,
    pub(crate) reducer: FileMultipartReducer,
    pub(crate) log: EventLog,
}

pub(crate) struct FileMultipartState {
    pub(crate) uploads_root: PathBuf,
    pub(crate) persistence: FilesystemPersistence,
    pub(crate) quotas: StagingQuotaLimits,
    pub(crate) entries: BTreeMap<String, FileMultipartEntry>,
    pub(crate) poisoned: Option<String>,
}

#[derive(Debug)]
pub(crate) struct MutationFailure {
    pub(crate) error: StagingError,
    pub(crate) unknown: bool,
}

/// Durable, single-process multipart repository for a locked local storage root.
pub(crate) struct FileMultipartRepository {
    pub(crate) state: Mutex<FileMultipartState>,
}

impl std::fmt::Debug for FileMultipartRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileMultipartRepository")
            .finish_non_exhaustive()
    }
}

impl FileMultipartRepository {
    pub(crate) fn open(
        multipart_root: PathBuf,
        quotas: StagingQuotaLimits,
    ) -> Result<Self, StagingError> {
        Self::open_with_persistence(multipart_root, quotas, FilesystemPersistence::default())
    }

    pub(crate) fn open_with_persistence(
        multipart_root: PathBuf,
        quotas: StagingQuotaLimits,
        persistence: FilesystemPersistence,
    ) -> Result<Self, StagingError> {
        let uploads_root = multipart_root.join("uploads");
        prepare_uploads_root(&uploads_root)?;
        let entries = load_entries(&uploads_root, &persistence, quotas)?;
        Ok(Self {
            state: Mutex::new(FileMultipartState {
                uploads_root,
                persistence,
                quotas,
                entries,
                poisoned: None,
            }),
        })
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        multipart_root: PathBuf,
        quotas: StagingQuotaLimits,
        persistence: FilesystemPersistence,
    ) -> Result<Self, StagingError> {
        Self::open_with_persistence(multipart_root, quotas, persistence)
    }
}

impl FileMultipartState {
    pub(crate) fn ensure_healthy(&self) -> Result<(), StagingError> {
        match &self.poisoned {
            Some(error) => Err(StagingError::Persistence(error.clone())),
            None => Ok(()),
        }
    }

    pub(crate) fn upload(&self, upload_id: &str) -> Result<&MultipartUpload, StagingError> {
        self.entries
            .get(upload_id)
            .and_then(|entry| entry.reducer.snapshot().upload.as_ref())
            .ok_or(StagingError::NotFound)
    }

    pub(crate) fn authorized(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<&MultipartUpload, StagingError> {
        let upload = self.upload(&identity.upload_id)?;
        same_identity(upload, identity)
            .then_some(upload)
            .ok_or(StagingError::NotFound)
    }

    pub(crate) fn snapshots_with_candidate<'a>(
        &'a self,
        upload_id: &str,
        candidate: &'a FileMultipartSnapshotV1,
    ) -> impl Iterator<Item = &'a FileMultipartSnapshotV1> {
        self.entries
            .iter()
            .filter(move |(id, _)| id.as_str() != upload_id)
            .map(|(_, entry)| entry.reducer.snapshot())
            .chain(std::iter::once(candidate))
    }

    pub(crate) fn validate_candidate(
        &self,
        upload_id: &str,
        candidate: &FileMultipartSnapshotV1,
    ) -> Result<(), StagingError> {
        reconstruct_file_multipart_quotas(
            self.snapshots_with_candidate(upload_id, candidate),
            self.quotas,
        )
        .map(|_| ())
        .map_err(reducer_persistence_error)
    }

    pub(crate) fn reload_after_unknown(&mut self) {
        match load_entries(&self.uploads_root, &self.persistence, self.quotas) {
            Ok(entries) => {
                self.entries = entries;
                self.poisoned = None;
            }
            Err(error) => self.poisoned = Some(error.to_string()),
        }
    }

    pub(crate) fn apply_transition(
        &mut self,
        upload_id: &str,
        transition: FileMultipartTransitionV1,
    ) -> Result<(), MutationFailure> {
        self.ensure_healthy().map_err(pre_mutation)?;
        let entry = self.entries.get(upload_id).ok_or_else(|| {
            pre_mutation(StagingError::Persistence(
                "multipart upload state disappeared".to_string(),
            ))
        })?;
        let identity = entry
            .reducer
            .snapshot()
            .identity
            .clone()
            .ok_or_else(|| pre_mutation(corrupt_state("multipart identity is missing")))?;
        let sequence = entry
            .reducer
            .snapshot()
            .final_event_sequence
            .checked_add(1)
            .ok_or_else(|| pre_mutation(corrupt_state("multipart event sequence exhausted")))?;
        let event = FileMultipartEventV1 {
            schema_version: FILE_MULTIPART_SCHEMA_VERSION,
            sequence,
            event_id: Uuid::now_v7(),
            identity,
            transition,
        };
        let mut candidate = FileMultipartReducer::from_snapshot(entry.reducer.compacted_snapshot())
            .map_err(|error| pre_mutation(reducer_persistence_error(error)))?;
        candidate
            .apply(&event)
            .map_err(|error| pre_mutation(reducer_persistence_error(error)))?;
        self.validate_candidate(upload_id, candidate.snapshot())
            .map_err(pre_mutation)?;

        let append = self
            .entries
            .get_mut(upload_id)
            .expect("entry checked above")
            .log
            .append(&event);
        if let Err(error) = append {
            let unknown = error.mutation_unknown();
            if unknown {
                self.reload_after_unknown();
            }
            return Err(MutationFailure {
                error: persistence_error(error),
                unknown,
            });
        }

        let entry = self
            .entries
            .get_mut(upload_id)
            .expect("entry checked above");
        entry.reducer = candidate;
        if entry.log.should_compact() {
            let snapshot = entry.reducer.compacted_snapshot();
            match entry
                .log
                .compact(&entry.directory.join(SNAPSHOT_FILE), &snapshot)
            {
                Ok(()) => {
                    entry.reducer = FileMultipartReducer::from_snapshot(snapshot)
                        .expect("validated compacted multipart snapshot");
                }
                Err(error) if error.mutation_unknown() => self.reload_after_unknown(),
                Err(_) => {}
            }
        }
        self.ensure_healthy().map_err(|error| MutationFailure {
            error,
            unknown: true,
        })
    }

    pub(crate) fn create_upload(&mut self, upload: MultipartUpload) -> Result<(), MutationFailure> {
        self.ensure_healthy().map_err(pre_mutation)?;
        let upload_id = upload.identity.upload_id.clone();
        validate_upload_directory_name(&upload_id).map_err(pre_mutation)?;
        if self.entries.contains_key(&upload_id) {
            return Err(pre_mutation(StagingError::Persistence(
                "duplicate upload id".to_string(),
            )));
        }
        let event = FileMultipartEventV1 {
            schema_version: FILE_MULTIPART_SCHEMA_VERSION,
            sequence: 1,
            event_id: Uuid::now_v7(),
            identity: upload.identity.clone(),
            transition: FileMultipartTransitionV1::UploadCreated {
                upload: Box::new(upload),
            },
        };
        let mut candidate = FileMultipartReducer::empty();
        candidate
            .apply(&event)
            .map_err(|error| pre_mutation(reducer_persistence_error(error)))?;
        self.validate_candidate(&upload_id, candidate.snapshot())
            .map_err(pre_mutation)?;

        let directory = self.uploads_root.join(&upload_id);
        create_private_dir_all(&directory)
            .map_err(|error| pre_mutation(persistence_error(error)))?;
        sync_parent(&directory).map_err(|error| {
            pre_mutation(StagingError::Persistence(format!(
                "multipart upload directory sync failed: {error}"
            )))
        })?;
        let opened = self
            .persistence
            .open_event_log::<FileMultipartEventV1>(directory.join(EVENT_LOG_FILE), 0);
        let (mut log, existing) = match opened {
            Ok(value) => value,
            Err(error) => return Err(pre_mutation(persistence_error(error))),
        };
        if !existing.is_empty() {
            return Err(pre_mutation(corrupt_state(
                "new multipart event log was not empty",
            )));
        }
        match log.append(&event) {
            Ok(1) => {
                self.entries.insert(
                    upload_id,
                    FileMultipartEntry {
                        directory,
                        reducer: candidate,
                        log,
                    },
                );
                Ok(())
            }
            Ok(_) => Err(pre_mutation(corrupt_state(
                "new multipart event sequence is invalid",
            ))),
            Err(error) => {
                let unknown = error.mutation_unknown();
                if unknown {
                    self.reload_after_unknown();
                } else {
                    let _ = std::fs::remove_file(directory.join(EVENT_LOG_FILE));
                    let _ = std::fs::remove_dir(&directory);
                }
                Err(MutationFailure {
                    error: persistence_error(error),
                    unknown,
                })
            }
        }
    }
}

#[async_trait]
impl MultipartRepository for FileMultipartRepository {
    fn is_durable(&self) -> bool {
        true
    }

    async fn create(&self, upload: MultipartUpload) -> Result<(), StagingError> {
        self.state
            .lock()
            .await
            .create_upload(upload)
            .map_err(|failure| failure.error)
    }

    async fn get_authorized(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<MultipartUpload, StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        state.authorized(identity).cloned()
    }

    async fn list_authorized_uploads(
        &self,
        request: &ListMultipartUploadsRequest,
    ) -> Result<ListMultipartUploadsPage, StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        let uploads = state
            .entries
            .values()
            .filter_map(|entry| entry.reducer.snapshot().upload.as_ref())
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
        if part.upload_id != identity.upload_id
            || part.part_number == 0
            || part.part_number > MAX_PARTS
        {
            return Err(StagingError::InvalidPart);
        }
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?;
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(StagingError::NotOpen);
        }
        let previous = current_part(
            state.entries.get(&identity.upload_id).unwrap(),
            part.part_number,
        );
        if previous
            .as_ref()
            .is_some_and(|old| part.attempt <= old.attempt)
        {
            return Err(StagingError::Persistence(
                "stale part replacement".to_string(),
            ));
        }
        let updated_at_ms = now_ms().max(upload.updated_at_ms);
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::PartReplaced {
                    part,
                    updated_at_ms,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::QuotaExceeded))?;
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
        let upload = state.authorized(identity)?;
        if upload.lifecycle != MultipartLifecycle::Open || upload.expires_at_ms <= now {
            return Err(StagingError::NotOpen);
        }
        let entry = state.entries.get(&identity.upload_id).unwrap();
        let attempt = entry
            .reducer
            .snapshot()
            .attempts
            .iter()
            .filter(|attempt| attempt.part.part_number == part_number)
            .map(|attempt| attempt.part.attempt)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StagingError::InvalidPart)?;
        let pending = PendingPart {
            upload_id: identity.upload_id.clone(),
            part_number,
            attempt,
            artifact_key: format!(
                "multipart/{}/{}/{part_number}/{attempt}",
                identity.tenant_id, identity.upload_id
            ),
            reserved_bytes,
        };
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::PartReserved {
                    pending: pending.clone(),
                    created_at_ms: now,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::QuotaExceeded))?;
        Ok(pending)
    }

    async fn commit_part(
        &self,
        identity: &MultipartIdentity,
        pending: &PendingPart,
        part: MultipartPart,
    ) -> Result<Vec<MultipartPart>, StagingError> {
        if part.upload_id != pending.upload_id
            || pending.upload_id != identity.upload_id
            || part.part_number != pending.part_number
            || part.attempt != pending.attempt
            || part.artifact_key != pending.artifact_key
            || part.size_bytes > pending.reserved_bytes
        {
            return Err(StagingError::InvalidPart);
        }
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?;
        if upload.lifecycle != MultipartLifecycle::Open {
            return Err(StagingError::NotOpen);
        }
        let previous = current_part(
            state.entries.get(&identity.upload_id).unwrap(),
            part.part_number,
        )
        .into_iter()
        .collect();
        let updated_at_ms = now_ms().max(upload.updated_at_ms);
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::PartCommitted {
                    pending: pending.clone(),
                    part,
                    updated_at_ms,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::NotFound))?;
        Ok(previous)
    }

    async fn discard_pending(
        &self,
        identity: &MultipartIdentity,
        pending: &PendingPart,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        state.authorized(identity)?;
        if pending.upload_id != identity.upload_id {
            return Err(StagingError::NotFound);
        }
        let Some((upload_id, updated_at_ms)) = artifact_owner(&state, &pending.artifact_key) else {
            return Ok(());
        };
        if upload_id != identity.upload_id {
            return Err(StagingError::NotFound);
        }
        state
            .apply_transition(
                &upload_id,
                FileMultipartTransitionV1::ArtifactDeleted {
                    artifact_key: pending.artifact_key.clone(),
                    updated_at_ms,
                },
            )
            .map_err(|failure| failure.error)
    }

    async fn cleanup_candidates(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<CleanupCandidate>, StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        let cutoff = now.saturating_sub(RECONCILIATION_GRACE.as_millis() as i64);
        let mut candidates = Vec::new();
        for entry in state.entries.values() {
            let Some(upload) = &entry.reducer.snapshot().upload else {
                continue;
            };
            for attempt in &entry.reducer.snapshot().attempts {
                let eligible = matches!(
                    upload.lifecycle,
                    MultipartLifecycle::Completed
                        | MultipartLifecycle::Aborted
                        | MultipartLifecycle::Expired
                ) || attempt.lifecycle == FilePartAttemptLifecycleV1::Retired
                    || attempt.lifecycle == FilePartAttemptLifecycleV1::Pending
                        && attempt.part.created_at_ms <= cutoff;
                if eligible {
                    candidates.push((
                        attempt.part.created_at_ms,
                        CleanupCandidate {
                            upload_id: upload.identity.upload_id.clone(),
                            artifact_key: attempt.part.artifact_key.clone(),
                        },
                    ));
                }
            }
        }
        candidates.sort_by(|left, right| {
            (left.0, &left.1.artifact_key).cmp(&(right.0, &right.1.artifact_key))
        });
        Ok(candidates
            .into_iter()
            .take(limit)
            .map(|(_, candidate)| candidate)
            .collect())
    }

    async fn confirm_artifact_deleted(&self, artifact_key: &str) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        state.ensure_healthy()?;
        let Some((upload_id, updated_at_ms)) = artifact_owner(&state, artifact_key) else {
            return Ok(());
        };
        state
            .apply_transition(
                &upload_id,
                FileMultipartTransitionV1::ArtifactDeleted {
                    artifact_key: artifact_key.to_string(),
                    updated_at_ms,
                },
            )
            .map_err(|failure| failure.error)
    }

    async fn known_artifact_keys(&self) -> Result<HashMap<String, i64>, StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        Ok(state
            .entries
            .values()
            .flat_map(|entry| &entry.reducer.snapshot().attempts)
            .map(|attempt| {
                (
                    attempt.part.artifact_key.clone(),
                    attempt.part.created_at_ms,
                )
            })
            .collect())
    }

    async fn list_parts(
        &self,
        identity: &MultipartIdentity,
        marker: u32,
        limit: usize,
    ) -> Result<(Vec<MultipartPart>, bool), StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        state.authorized(identity)?;
        let mut parts = current_parts(state.entries.get(&identity.upload_id).unwrap());
        parts.retain(|part| part.part_number > marker);
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
        let upload = state.authorized(identity)?.clone();
        match upload.lifecycle {
            MultipartLifecycle::Completed => {
                let result = upload
                    .completion_result
                    .ok_or_else(|| corrupt_state("completed multipart upload has no result"))?;
                return if upload.complete_request_fingerprint.as_deref() == Some(fingerprint) {
                    Ok(CompletionAcquire::Replayed(result))
                } else {
                    Err(StagingError::CompletionConflict)
                };
            }
            MultipartLifecycle::Publishing => {
                return if upload.complete_request_fingerprint.as_deref() == Some(fingerprint) {
                    Ok(CompletionAcquire::Busy)
                } else {
                    Err(StagingError::CompletionConflict)
                };
            }
            MultipartLifecycle::Aborted | MultipartLifecycle::Expired => {
                return Err(StagingError::NotOpen);
            }
            MultipartLifecycle::Completing
                if upload.complete_request_fingerprint.as_deref() != Some(fingerprint) =>
            {
                return Err(StagingError::CompletionConflict);
            }
            MultipartLifecycle::Completing
                if upload
                    .completion_lease_expires_at_ms
                    .is_some_and(|expiry| expiry > now) =>
            {
                return Ok(CompletionAcquire::Busy);
            }
            MultipartLifecycle::Open if upload.expires_at_ms <= now => {
                return Err(StagingError::NotOpen);
            }
            _ => {}
        }
        let cleanup_parts = current_parts(state.entries.get(&identity.upload_id).unwrap());
        let selected_parts = select_parts(&cleanup_parts, parts)?;
        let fencing_token = upload
            .completion_fencing_token
            .checked_add(1)
            .ok_or_else(|| corrupt_state("completion fencing token exhausted"))?;
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::CompletionAcquired {
                    fingerprint: fingerprint.to_string(),
                    selected_parts: parts.to_vec(),
                    owner: owner.to_string(),
                    lease_expires_at_ms,
                    fencing_token,
                    updated_at_ms: now,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))?;
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
        let upload = state.authorized(identity)?;
        if upload.lifecycle != MultipartLifecycle::Completing
            || upload.completion_fencing_token != fencing_token
        {
            return Err(StagingError::Fenced);
        }
        let updated_at_ms = now_ms().max(upload.updated_at_ms);
        if lease_expires_at_ms <= updated_at_ms {
            return Err(StagingError::Fenced);
        }
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::CompletionRenewed {
                    fencing_token,
                    lease_expires_at_ms,
                    updated_at_ms,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))
    }

    async fn check_completion_lease(
        &self,
        identity: &MultipartIdentity,
        fencing_token: u64,
        now: i64,
    ) -> Result<(), StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        let upload = state.authorized(identity)?;
        (upload.lifecycle == MultipartLifecycle::Completing
            && upload.completion_fencing_token == fencing_token
            && upload
                .completion_lease_expires_at_ms
                .is_some_and(|expiry| expiry > now))
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
        let permit = DestinationCommitPermit {
            upload_id: identity.upload_id.clone(),
            completion_fingerprint: fingerprint.to_string(),
            fencing_token,
            operation_id,
        };
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?;
        if operation_id
            != DestinationCommitPermit::deterministic_operation_id(identity, fingerprint)
            || upload.lifecycle != MultipartLifecycle::Completing
            || upload.complete_request_fingerprint.as_deref() != Some(fingerprint)
            || upload.completion_fencing_token != fencing_token
            || upload
                .completion_lease_expires_at_ms
                .is_none_or(|expiry| expiry <= now)
        {
            return Err(StagingError::Fenced);
        }
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::DestinationCommitBegun {
                    permit: permit.clone(),
                    publishing_started_at_ms: now,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))?;
        Ok(permit)
    }

    async fn validate_destination_commit_permit(
        &self,
        permit: &DestinationCommitPermit,
    ) -> Result<(), StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        state
            .upload(&permit.upload_id)
            .is_ok_and(|upload| permit_matches(upload, permit))
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
            .upload(&permit.upload_id)
            .map_err(|_| StagingError::Fenced)?;
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
        state
            .apply_transition(
                &permit.upload_id,
                FileMultipartTransitionV1::DestinationCommitRecorded {
                    permit: permit.clone(),
                    record,
                    updated_at_ms: now,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))
    }

    async fn release_destination_commit_after_proven_absence(
        &self,
        permit: &DestinationCommitPermit,
        now: i64,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state
            .upload(&permit.upload_id)
            .map_err(|_| StagingError::Fenced)?;
        if !permit_matches(upload, permit) || upload.destination_commit.is_some() {
            return Err(StagingError::Fenced);
        }
        state
            .apply_transition(
                &permit.upload_id,
                FileMultipartTransitionV1::DestinationCommitReleased {
                    permit: permit.clone(),
                    updated_at_ms: now,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))
    }

    async fn publishing_uploads(
        &self,
        limit: usize,
    ) -> Result<Vec<PublishingMultipartUpload>, StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        let mut uploads = state
            .entries
            .values()
            .filter_map(|entry| entry.reducer.snapshot().upload.as_ref())
            .filter(|upload| upload.lifecycle == MultipartLifecycle::Publishing)
            .cloned()
            .collect::<Vec<_>>();
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
        let upload = state.authorized(identity)?;
        if !permit_matches(upload, permit)
            || upload
                .destination_commit
                .as_ref()
                .map(|record| &record.result)
                != Some(&result)
        {
            return Err(StagingError::Fenced);
        }
        let tombstone_until_ms = now
            .checked_add(DEFAULT_EXPIRY.as_millis() as i64)
            .ok_or_else(|| corrupt_state("multipart tombstone timestamp overflow"))?;
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::CompletionCompleted {
                    permit: permit.clone(),
                    result,
                    completed_at_ms: now,
                    tombstone_until_ms,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))
    }

    async fn clear_destination_commit_reference(
        &self,
        identity: &MultipartIdentity,
        expected_operation_id: Uuid,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?;
        if !matches!(
            upload.lifecycle,
            MultipartLifecycle::Completed
                | MultipartLifecycle::Aborted
                | MultipartLifecycle::Expired
        ) || upload.destination_operation_id != Some(expected_operation_id)
        {
            return Err(StagingError::Fenced);
        }
        let updated_at_ms = now_ms().max(upload.updated_at_ms);
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::DestinationCommitReferenceCleared {
                    expected_operation_id,
                    updated_at_ms,
                },
            )
            .map_err(|failure| map_reducer_failure(failure, StagingError::Fenced))
    }

    async fn abort(
        &self,
        identity: &MultipartIdentity,
        now: i64,
    ) -> Result<Vec<MultipartPart>, AbortMutationError> {
        let mut state = self.state.lock().await;
        let upload = state
            .authorized(identity)
            .map_err(AbortMutationError::PreMutation)?;
        if upload.lifecycle != MultipartLifecycle::Open {
            if upload.lifecycle == MultipartLifecycle::Aborted {
                return Ok(Vec::new());
            }
            return Err(AbortMutationError::PreMutation(StagingError::NotOpen));
        }
        let parts = current_parts(state.entries.get(&identity.upload_id).unwrap());
        let tombstone_until_ms = now
            .checked_add(DEFAULT_EXPIRY.as_millis() as i64)
            .ok_or(AbortMutationError::PreMutation(StagingError::Unavailable))?;
        match state.apply_transition(
            &identity.upload_id,
            FileMultipartTransitionV1::UploadAborted {
                aborted_at_ms: now,
                tombstone_until_ms,
            },
        ) {
            Ok(()) => Ok(parts),
            Err(failure) if failure.unknown => {
                Err(AbortMutationError::MutationUnknown(failure.error))
            }
            Err(failure) => Err(AbortMutationError::PreMutation(failure.error)),
        }
    }

    async fn delete_terminal_upload(
        &self,
        identity: &MultipartIdentity,
    ) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        let upload = state.authorized(identity)?;
        if !matches!(
            upload.lifecycle,
            MultipartLifecycle::Aborted | MultipartLifecycle::Expired
        ) || upload.destination_operation_id.is_some()
            || !state
                .entries
                .get(&identity.upload_id)
                .unwrap()
                .reducer
                .snapshot()
                .attempts
                .is_empty()
        {
            return Err(StagingError::Persistence(
                "multipart artifacts remain after cleanup".to_string(),
            ));
        }
        state
            .apply_transition(
                &identity.upload_id,
                FileMultipartTransitionV1::TerminalUploadDeleted,
            )
            .map_err(|failure| failure.error)
    }

    async fn terminal_upload_candidates(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<MultipartIdentity>, StagingError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        let mut uploads = state
            .entries
            .values()
            .filter_map(|entry| entry.reducer.snapshot().upload.as_ref())
            .filter(|upload| {
                matches!(
                    upload.lifecycle,
                    MultipartLifecycle::Completed
                        | MultipartLifecycle::Aborted
                        | MultipartLifecycle::Expired
                ) && upload.tombstone_until_ms.is_some_and(|until| until <= now)
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
        now: i64,
        limit: usize,
    ) -> Result<Vec<RetiredMultipartUpload>, StagingError> {
        let mut state = self.state.lock().await;
        state.ensure_healthy()?;
        let ids = state
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                let upload = entry.reducer.snapshot().upload.as_ref()?;
                (matches!(
                    upload.lifecycle,
                    MultipartLifecycle::Completed
                        | MultipartLifecycle::Aborted
                        | MultipartLifecycle::Expired
                ) && upload.tombstone_until_ms.is_some_and(|until| until <= now)
                    && entry.reducer.snapshot().attempts.is_empty()
                    && upload.destination_operation_id.is_none())
                .then(|| id.clone())
            })
            .take(limit)
            .collect::<Vec<_>>();
        let mut retired = Vec::with_capacity(ids.len());
        for id in ids {
            let upload = state.upload(&id)?.clone();
            state
                .apply_transition(
                    &id,
                    FileMultipartTransitionV1::TerminalUploadRetired { retired_at_ms: now },
                )
                .map_err(|failure| failure.error)?;
            retired.push(RetiredMultipartUpload {
                upload_id: upload.identity.upload_id,
                tenant_id: upload.identity.tenant_id,
                namespace_epoch: upload.namespace_epoch,
            });
        }
        Ok(retired)
    }

    async fn reap_expired(
        &self,
        now: i64,
        limit: usize,
    ) -> Result<Vec<MultipartPart>, StagingError> {
        let mut state = self.state.lock().await;
        state.ensure_healthy()?;
        let ids = state
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry
                    .reducer
                    .snapshot()
                    .upload
                    .as_ref()
                    .is_some_and(|upload| {
                        upload.lifecycle == MultipartLifecycle::Open && upload.expires_at_ms <= now
                    })
            })
            .map(|(id, _)| id.clone())
            .take(limit)
            .collect::<Vec<_>>();
        let mut parts = Vec::new();
        for id in ids {
            parts.extend(current_parts(state.entries.get(&id).unwrap()));
            let tombstone_until_ms = now
                .checked_add(DEFAULT_EXPIRY.as_millis() as i64)
                .ok_or_else(|| corrupt_state("multipart tombstone timestamp overflow"))?;
            state
                .apply_transition(
                    &id,
                    FileMultipartTransitionV1::UploadExpired {
                        expired_at_ms: now,
                        tombstone_until_ms,
                    },
                )
                .map_err(|failure| failure.error)?;
        }
        Ok(parts)
    }

    async fn audit(&self, audit: CleanupAudit) -> Result<(), StagingError> {
        let mut state = self.state.lock().await;
        state.ensure_healthy()?;
        let upload_id = audit.upload_id.clone();
        state.upload(&upload_id)?;
        state
            .apply_transition(
                &upload_id,
                FileMultipartTransitionV1::CleanupAudited { audit },
            )
            .map_err(|failure| failure.error)
    }
}

pub(crate) fn prepare_uploads_root(path: &Path) -> Result<(), StagingError> {
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && !metadata.file_type().is_dir()
    {
        return Err(corrupt_state("multipart uploads root is not a directory"));
    }
    create_private_dir_all(path).map_err(persistence_error)
}

pub(crate) fn load_entries(
    uploads_root: &Path,
    persistence: &FilesystemPersistence,
    quotas: StagingQuotaLimits,
) -> Result<BTreeMap<String, FileMultipartEntry>, StagingError> {
    prepare_uploads_root(uploads_root)?;
    let mut entries = BTreeMap::new();
    for item in std::fs::read_dir(uploads_root)
        .map_err(|error| corrupt_state(format!("cannot read multipart uploads root: {error}")))?
    {
        let item = item
            .map_err(|error| corrupt_state(format!("cannot inspect multipart upload: {error}")))?;
        let metadata = std::fs::symlink_metadata(item.path()).map_err(|error| {
            corrupt_state(format!("cannot inspect multipart upload state: {error}"))
        })?;
        if !metadata.file_type().is_dir() {
            return Err(corrupt_state("unknown file in multipart uploads root"));
        }
        let upload_id = item
            .file_name()
            .into_string()
            .map_err(|_| corrupt_state("multipart upload directory is not UTF-8"))?;
        validate_upload_directory_name(&upload_id)?;
        let directory = item.path();
        validate_upload_files(&directory)?;
        let snapshot_path = directory.join(SNAPSHOT_FILE);
        let snapshot = persistence
            .load_snapshot::<FileMultipartSnapshotV1>(&snapshot_path)
            .map_err(persistence_error)?;
        let (snapshot_sequence, snapshot) = match snapshot {
            Some(snapshot) => {
                if snapshot.final_sequence != snapshot.payload.final_event_sequence {
                    return Err(corrupt_state("multipart snapshot sequence mismatch"));
                }
                (snapshot.final_sequence, snapshot.payload)
            }
            None => (0, FileMultipartSnapshotV1::default()),
        };
        let mut reducer =
            FileMultipartReducer::from_snapshot(snapshot).map_err(reducer_persistence_error)?;
        let (log, events) = persistence
            .open_event_log::<FileMultipartEventV1>(
                directory.join(EVENT_LOG_FILE),
                snapshot_sequence,
            )
            .map_err(persistence_error)?;
        for logged in events {
            if logged.sequence != logged.payload.sequence {
                return Err(corrupt_state("multipart event sequence mismatch"));
            }
            reducer
                .apply(&logged.payload)
                .map_err(reducer_persistence_error)?;
        }
        let identity = reducer
            .snapshot()
            .identity
            .as_ref()
            .ok_or_else(|| corrupt_state("multipart upload directory has no identity"))?;
        if identity.upload_id != upload_id {
            return Err(corrupt_state(
                "multipart upload directory identity mismatch",
            ));
        }
        if entries
            .insert(
                upload_id,
                FileMultipartEntry {
                    directory,
                    reducer,
                    log,
                },
            )
            .is_some()
        {
            return Err(corrupt_state("duplicate multipart upload identity"));
        }
    }
    reconstruct_file_multipart_quotas(
        entries.values().map(|entry| entry.reducer.snapshot()),
        quotas,
    )
    .map_err(reducer_persistence_error)?;
    Ok(entries)
}

pub(crate) fn validate_upload_files(directory: &Path) -> Result<(), StagingError> {
    let mut has_log = false;
    for item in std::fs::read_dir(directory)
        .map_err(|error| corrupt_state(format!("cannot read multipart upload state: {error}")))?
    {
        let item = item
            .map_err(|error| corrupt_state(format!("cannot inspect multipart state: {error}")))?;
        let name = item.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| corrupt_state("multipart state filename is not UTF-8"))?;
        if name != SNAPSHOT_FILE && name != EVENT_LOG_FILE {
            return Err(corrupt_state("unknown file in multipart upload directory"));
        }
        let metadata = std::fs::symlink_metadata(item.path())
            .map_err(|error| corrupt_state(format!("cannot inspect multipart state: {error}")))?;
        if !metadata.file_type().is_file() {
            return Err(corrupt_state("multipart state path is not a regular file"));
        }
        has_log |= name == EVENT_LOG_FILE;
    }
    if !has_log {
        return Err(corrupt_state("multipart upload event log is missing"));
    }
    Ok(())
}

pub(crate) fn validate_upload_directory_name(upload_id: &str) -> Result<(), StagingError> {
    let parsed = Uuid::parse_str(upload_id)
        .map_err(|_| corrupt_state("local multipart upload id is not a UUID"))?;
    if parsed.to_string() != upload_id {
        return Err(corrupt_state("local multipart upload id is not canonical"));
    }
    Ok(())
}

pub(crate) fn current_part(entry: &FileMultipartEntry, part_number: u32) -> Option<MultipartPart> {
    entry
        .reducer
        .snapshot()
        .attempts
        .iter()
        .find(|attempt| {
            attempt.lifecycle == FilePartAttemptLifecycleV1::Current
                && attempt.part.part_number == part_number
        })
        .map(|attempt| attempt.part.clone())
}

pub(crate) fn current_parts(entry: &FileMultipartEntry) -> Vec<MultipartPart> {
    let mut parts = entry
        .reducer
        .snapshot()
        .attempts
        .iter()
        .filter(|attempt| attempt.lifecycle == FilePartAttemptLifecycleV1::Current)
        .map(|attempt| attempt.part.clone())
        .collect::<Vec<_>>();
    parts.sort_by_key(|part| part.part_number);
    parts
}

pub(crate) fn select_parts(
    current: &[MultipartPart],
    selected: &[CompletePart],
) -> Result<Vec<MultipartPart>, StagingError> {
    if selected.is_empty() || selected.len() > MAX_PARTS as usize {
        return Err(StagingError::InvalidPart);
    }
    let mut previous = 0;
    let mut result = Vec::with_capacity(selected.len());
    for requested in selected {
        if requested.part_number <= previous {
            return Err(StagingError::InvalidPart);
        }
        let part = current
            .iter()
            .find(|part| part.part_number == requested.part_number)
            .filter(|part| {
                part.etag == requested.etag
                    && requested
                        .checksum_sha256
                        .as_ref()
                        .is_none_or(|checksum| checksum == &part.checksum_sha256)
            })
            .ok_or(StagingError::InvalidPart)?;
        result.push(part.clone());
        previous = requested.part_number;
    }
    Ok(result)
}

pub(crate) fn artifact_owner(
    state: &FileMultipartState,
    artifact_key: &str,
) -> Option<(String, i64)> {
    state.entries.iter().find_map(|(upload_id, entry)| {
        entry
            .reducer
            .snapshot()
            .attempts
            .iter()
            .any(|attempt| attempt.part.artifact_key == artifact_key)
            .then(|| {
                let updated = entry
                    .reducer
                    .snapshot()
                    .upload
                    .as_ref()
                    .map_or_else(now_ms, |upload| now_ms().max(upload.updated_at_ms));
                (upload_id.clone(), updated)
            })
    })
}

pub(crate) fn persistence_error(error: PersistenceError) -> StagingError {
    StagingError::Persistence(error.to_string())
}

pub(crate) fn reducer_persistence_error(error: FileMultipartReducerError) -> StagingError {
    StagingError::Persistence(error.to_string())
}

pub(crate) fn corrupt_state(message: impl Into<String>) -> StagingError {
    StagingError::Persistence(message.into())
}

pub(crate) fn pre_mutation(error: StagingError) -> MutationFailure {
    MutationFailure {
        error,
        unknown: false,
    }
}

pub(crate) fn map_reducer_failure(
    failure: MutationFailure,
    semantic: StagingError,
) -> StagingError {
    if failure.unknown {
        failure.error
    } else if failure.error.to_string().contains("accounting") {
        semantic
    } else {
        failure.error
    }
}
