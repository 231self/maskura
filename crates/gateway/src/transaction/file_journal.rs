use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::filesystem_persistence::{
    EventLog, FilesystemPersistence, PersistenceError, create_private_dir_all, sync_parent,
};

use super::{
    EvidenceRecord, ExpectedObject, JournalError, OperationJournal, OperationRecord,
    OperationState, PartRecord, StoredObjectMeta, unix_time_ms,
};

const SCHEMA_VERSION: u32 = 1;
const SNAPSHOT_FILE: &str = "snapshot.json";
const EVENT_LOG_FILE: &str = "events.log";
const MAX_PARTS: usize = 10_000;
const MAX_EVIDENCE: usize = 4_096;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileOperationSnapshotV1 {
    schema_version: u32,
    final_event_sequence: u64,
    operation: Option<OperationRecord>,
    parts: Vec<PartRecord>,
    evidence: Vec<EvidenceRecord>,
}

impl Default for FileOperationSnapshotV1 {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            final_event_sequence: 0,
            operation: None,
            parts: Vec::new(),
            evidence: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FileOperationEventV1 {
    schema_version: u32,
    sequence: u64,
    operation_id: Uuid,
    transition: FileOperationTransitionV1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum FileOperationTransitionV1 {
    IntentInserted {
        operation: Box<OperationRecord>,
    },
    Opened {
        upload_id: Option<String>,
        updated_at_ms: i64,
    },
    ClientMultipartReferenceChanged {
        expected: Option<String>,
        next: Option<String>,
        updated_at_ms: i64,
    },
    ExpectedChanged {
        expected: ExpectedObject,
        updated_at_ms: i64,
    },
    StateChanged {
        expected: OperationState,
        next: OperationState,
        committed: Option<StoredObjectMeta>,
        updated_at_ms: i64,
    },
    PartRecorded {
        part: PartRecord,
    },
    EvidenceAppended {
        evidence: EvidenceRecord,
    },
    MutationLaunched {
        not_before_ms: i64,
        updated_at_ms: i64,
    },
    ExactAbsenceObserved {
        observed_at_ms: i64,
        updated_at_ms: i64,
    },
    Claimed {
        owner: String,
        lease_until_ms: i64,
    },
    TerminalRetired {
        expected_state: OperationState,
        expected_client_multipart_upload_id: Option<String>,
    },
}

#[derive(Clone, Debug)]
struct FileOperationReducer {
    snapshot: FileOperationSnapshotV1,
}

impl FileOperationReducer {
    fn empty() -> Self {
        Self {
            snapshot: FileOperationSnapshotV1::default(),
        }
    }

    fn from_snapshot(snapshot: FileOperationSnapshotV1) -> Result<Self, JournalError> {
        validate_snapshot(&snapshot)?;
        Ok(Self { snapshot })
    }

    fn apply(&mut self, event: &FileOperationEventV1) -> Result<(), JournalError> {
        if event.schema_version != SCHEMA_VERSION {
            return Err(corrupt(format!(
                "unsupported file operation event version {}",
                event.schema_version
            )));
        }
        let expected_sequence = self
            .snapshot
            .final_event_sequence
            .checked_add(1)
            .ok_or_else(|| corrupt("operation event sequence overflow"))?;
        if event.sequence != expected_sequence {
            return Err(corrupt("operation event sequence is invalid"));
        }
        let mut candidate = self.snapshot.clone();
        reduce_transition(&mut candidate, event)?;
        candidate.final_event_sequence = event.sequence;
        validate_snapshot(&candidate)?;
        self.snapshot = candidate;
        Ok(())
    }
}

fn reduce_transition(
    snapshot: &mut FileOperationSnapshotV1,
    event: &FileOperationEventV1,
) -> Result<(), JournalError> {
    match &event.transition {
        FileOperationTransitionV1::IntentInserted { operation } => {
            if snapshot.operation.is_some()
                || !snapshot.parts.is_empty()
                || !snapshot.evidence.is_empty()
            {
                return Err(conflict("duplicate operation id"));
            }
            if operation.id != event.operation_id || operation.state != OperationState::Intent {
                return Err(conflict("new operation must start in INTENT"));
            }
            snapshot.operation = Some(operation.as_ref().clone());
        }
        FileOperationTransitionV1::Opened {
            upload_id,
            updated_at_ms,
        } => {
            let operation = operation_mut(snapshot, event.operation_id)?;
            if operation.state != OperationState::Intent {
                return Err(conflict(format!(
                    "expected INTENT, found {}",
                    operation.state
                )));
            }
            set_updated_at(operation, *updated_at_ms)?;
            operation.state = OperationState::Open;
            operation.upload_id.clone_from(upload_id);
        }
        FileOperationTransitionV1::ClientMultipartReferenceChanged {
            expected,
            next,
            updated_at_ms,
        } => {
            let operation = operation_mut(snapshot, event.operation_id)?;
            if operation.client_multipart_upload_id != *expected {
                return Err(conflict(format!(
                    "operation {} client multipart reference changed",
                    event.operation_id
                )));
            }
            set_updated_at(operation, *updated_at_ms)?;
            operation.client_multipart_upload_id.clone_from(next);
        }
        FileOperationTransitionV1::ExpectedChanged {
            expected,
            updated_at_ms,
        } => {
            let operation = operation_mut(snapshot, event.operation_id)?;
            if !matches!(
                operation.state,
                OperationState::Intent | OperationState::Open
            ) {
                return Err(conflict(format!(
                    "operation {} cannot update expected output in {}",
                    event.operation_id, operation.state
                )));
            }
            set_updated_at(operation, *updated_at_ms)?;
            operation.expected = expected.clone();
        }
        FileOperationTransitionV1::StateChanged {
            expected,
            next,
            committed,
            updated_at_ms,
        } => {
            if !expected.can_transition_to(*next) {
                return Err(conflict(format!("illegal transition {expected} -> {next}")));
            }
            if (*next == OperationState::Committed) != committed.is_some() {
                return Err(conflict(
                    "COMMITTED transitions require object metadata only",
                ));
            }
            let operation = operation_mut(snapshot, event.operation_id)?;
            if operation.state != *expected {
                return Err(conflict(format!(
                    "expected {expected}, found {}",
                    operation.state
                )));
            }
            set_updated_at(operation, *updated_at_ms)?;
            operation.state = *next;
            operation.committed.clone_from(committed);
            operation.lease_owner = None;
            operation.lease_expires_at_ms = None;
        }
        FileOperationTransitionV1::PartRecorded { part } => {
            require_operation(snapshot, event.operation_id)?;
            if part.operation_id != event.operation_id || part.part_number <= 0 {
                return Err(conflict("uploaded part reference is invalid"));
            }
            match snapshot
                .parts
                .binary_search_by_key(&part.part_number, |old| old.part_number)
            {
                Ok(index) => {
                    let old = &snapshot.parts[index];
                    if old.etag != part.etag
                        || old.size_bytes != part.size_bytes
                        || old.digest != part.digest
                    {
                        return Err(conflict(format!(
                            "part {} retry body or result changed",
                            part.part_number
                        )));
                    }
                }
                Err(index) => {
                    if snapshot.parts.len() >= MAX_PARTS {
                        return Err(conflict("operation part bound exceeded"));
                    }
                    snapshot.parts.insert(index, part.clone());
                }
            }
        }
        FileOperationTransitionV1::EvidenceAppended { evidence } => {
            require_operation(snapshot, event.operation_id)?;
            if evidence.operation_id != event.operation_id {
                return Err(conflict("evidence operation reference is invalid"));
            }
            if let Some(old) = snapshot.evidence.iter().find(|old| old.id == evidence.id) {
                if old.operation_id != evidence.operation_id
                    || old.kind != evidence.kind
                    || old.detail != evidence.detail
                {
                    return Err(conflict("evidence id conflicts with an existing record"));
                }
            } else {
                if snapshot.evidence.len() >= MAX_EVIDENCE {
                    return Err(conflict("operation evidence bound exceeded"));
                }
                snapshot.evidence.push(evidence.clone());
            }
        }
        FileOperationTransitionV1::MutationLaunched {
            not_before_ms,
            updated_at_ms,
        } => {
            let operation = operation_mut(snapshot, event.operation_id)?;
            if operation.state.is_terminal() {
                return Err(conflict(
                    "terminal operation cannot launch a provider mutation",
                ));
            }
            checked_timestamp(*not_before_ms, "mutation not-before timestamp")?;
            set_updated_at(operation, *updated_at_ms)?;
            operation.mutation_not_before_ms = Some(
                operation
                    .mutation_not_before_ms
                    .unwrap_or(i64::MIN)
                    .max(*not_before_ms),
            );
            operation.exact_absence_observed_at_ms = None;
        }
        FileOperationTransitionV1::ExactAbsenceObserved {
            observed_at_ms,
            updated_at_ms,
        } => {
            let operation = operation_mut(snapshot, event.operation_id)?;
            checked_timestamp(*observed_at_ms, "exact absence timestamp")?;
            if operation.exact_absence_observed_at_ms.is_some() {
                return Err(conflict("exact absence was already observed"));
            }
            set_updated_at(operation, *updated_at_ms)?;
            operation.exact_absence_observed_at_ms = Some(*observed_at_ms);
        }
        FileOperationTransitionV1::Claimed {
            owner,
            lease_until_ms,
        } => {
            let operation = operation_mut(snapshot, event.operation_id)?;
            if operation.state.is_terminal() || owner.is_empty() {
                return Err(conflict("operation cannot be claimed"));
            }
            checked_timestamp(*lease_until_ms, "lease expiry timestamp")?;
            operation.lease_owner = Some(owner.clone());
            operation.lease_expires_at_ms = Some(*lease_until_ms);
        }
        FileOperationTransitionV1::TerminalRetired {
            expected_state,
            expected_client_multipart_upload_id,
        } => {
            if !expected_state.is_terminal() {
                return Err(conflict("journal retirement requires a terminal state"));
            }
            let operation = require_operation(snapshot, event.operation_id)?;
            if operation.state != *expected_state
                || operation.client_multipart_upload_id != *expected_client_multipart_upload_id
            {
                return Err(conflict(format!(
                    "operation {} terminal state or multipart reference changed",
                    event.operation_id
                )));
            }
            snapshot.operation = None;
            snapshot.parts.clear();
            snapshot.evidence.clear();
        }
    }
    Ok(())
}

fn validate_snapshot(snapshot: &FileOperationSnapshotV1) -> Result<(), JournalError> {
    if snapshot.schema_version != SCHEMA_VERSION {
        return Err(corrupt(format!(
            "unsupported file operation snapshot version {}",
            snapshot.schema_version
        )));
    }
    if snapshot.parts.len() > MAX_PARTS || snapshot.evidence.len() > MAX_EVIDENCE {
        return Err(corrupt("operation child record bound exceeded"));
    }
    let Some(operation) = &snapshot.operation else {
        if snapshot.parts.is_empty() && snapshot.evidence.is_empty() {
            return Ok(());
        }
        return Err(corrupt("retired operation retains child records"));
    };
    validate_operation(operation)?;
    let mut part_numbers = BTreeSet::new();
    let mut previous = None;
    for part in &snapshot.parts {
        checked_timestamp(part.created_at_ms, "part creation timestamp")?;
        if part.operation_id != operation.id
            || part.part_number <= 0
            || !part_numbers.insert(part.part_number)
            || previous.is_some_and(|old| old >= part.part_number)
        {
            return Err(corrupt("invalid or unsorted operation parts"));
        }
        previous = Some(part.part_number);
    }
    let mut evidence_ids = BTreeSet::new();
    for evidence in &snapshot.evidence {
        checked_timestamp(evidence.created_at_ms, "evidence creation timestamp")?;
        if evidence.operation_id != operation.id || !evidence_ids.insert(evidence.id) {
            return Err(corrupt("invalid operation evidence"));
        }
    }
    Ok(())
}

fn validate_operation(operation: &OperationRecord) -> Result<(), JournalError> {
    checked_timestamp(operation.created_at_ms, "operation creation timestamp")?;
    checked_timestamp(operation.updated_at_ms, "operation update timestamp")?;
    if operation.updated_at_ms < operation.created_at_ms {
        return Err(corrupt("operation update predates creation"));
    }
    for (value, name) in [
        (operation.lease_expires_at_ms, "lease expiry timestamp"),
        (
            operation.mutation_not_before_ms,
            "mutation not-before timestamp",
        ),
        (
            operation.exact_absence_observed_at_ms,
            "exact absence timestamp",
        ),
    ] {
        if let Some(value) = value {
            checked_timestamp(value, name)?;
        }
    }
    if operation.lease_owner.is_some() != operation.lease_expires_at_ms.is_some() {
        return Err(corrupt("partial operation lease"));
    }
    if operation.state == OperationState::Committed && operation.committed.is_none()
        || operation.state != OperationState::Committed && operation.committed.is_some()
    {
        return Err(corrupt("operation committed metadata does not match state"));
    }
    Ok(())
}

fn checked_timestamp(value: i64, name: &str) -> Result<(), JournalError> {
    if value < 0 {
        Err(corrupt(format!("negative {name}")))
    } else {
        Ok(())
    }
}

fn set_updated_at(operation: &mut OperationRecord, value: i64) -> Result<(), JournalError> {
    checked_timestamp(value, "operation update timestamp")?;
    if value < operation.created_at_ms {
        return Err(corrupt("operation update predates creation"));
    }
    operation.updated_at_ms = value;
    Ok(())
}

fn require_operation(
    snapshot: &FileOperationSnapshotV1,
    operation_id: Uuid,
) -> Result<&OperationRecord, JournalError> {
    snapshot
        .operation
        .as_ref()
        .filter(|operation| operation.id == operation_id)
        .ok_or(JournalError::NotFound(operation_id))
}

fn operation_mut(
    snapshot: &mut FileOperationSnapshotV1,
    operation_id: Uuid,
) -> Result<&mut OperationRecord, JournalError> {
    snapshot
        .operation
        .as_mut()
        .filter(|operation| operation.id == operation_id)
        .ok_or(JournalError::NotFound(operation_id))
}

struct FileOperationEntry {
    directory: PathBuf,
    reducer: FileOperationReducer,
    log: EventLog,
}

struct FileOperationState {
    root: PathBuf,
    persistence: FilesystemPersistence,
    entries: BTreeMap<Uuid, FileOperationEntry>,
    poisoned: Option<String>,
}

pub(crate) struct FileOperationJournal {
    state: Mutex<FileOperationState>,
}

impl std::fmt::Debug for FileOperationJournal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileOperationJournal")
            .finish_non_exhaustive()
    }
}

impl FileOperationJournal {
    pub(crate) fn open(root: PathBuf) -> Result<Self, JournalError> {
        Self::open_with_persistence(root, FilesystemPersistence::default())
    }

    fn open_with_persistence(
        root: PathBuf,
        persistence: FilesystemPersistence,
    ) -> Result<Self, JournalError> {
        prepare_root(&root)?;
        let entries = load_entries(&root, &persistence)?;
        Ok(Self {
            state: Mutex::new(FileOperationState {
                root,
                persistence,
                entries,
                poisoned: None,
            }),
        })
    }

    #[cfg(test)]
    fn open_for_test(
        root: PathBuf,
        persistence: FilesystemPersistence,
    ) -> Result<Self, JournalError> {
        Self::open_with_persistence(root, persistence)
    }
}

impl FileOperationState {
    fn ensure_healthy(&self) -> Result<(), JournalError> {
        match &self.poisoned {
            Some(error) => Err(JournalError::Persistence(error.clone())),
            None => Ok(()),
        }
    }

    fn reload_after_unknown(&mut self) {
        match load_entries(&self.root, &self.persistence) {
            Ok(entries) => {
                self.entries = entries;
                self.poisoned = None;
            }
            Err(error) => self.poisoned = Some(error.to_string()),
        }
    }

    fn append_transition(
        &mut self,
        operation_id: Uuid,
        transition: FileOperationTransitionV1,
    ) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        let entry = self
            .entries
            .get(&operation_id)
            .ok_or(JournalError::NotFound(operation_id))?;
        let sequence = entry
            .reducer
            .snapshot
            .final_event_sequence
            .checked_add(1)
            .ok_or_else(|| corrupt("operation event sequence overflow"))?;
        let event = FileOperationEventV1 {
            schema_version: SCHEMA_VERSION,
            sequence,
            operation_id,
            transition,
        };
        let mut candidate = FileOperationReducer::from_snapshot(entry.reducer.snapshot.clone())?;
        candidate.apply(&event)?;
        let append = self
            .entries
            .get_mut(&operation_id)
            .expect("entry checked above")
            .log
            .append(&event);
        if let Err(error) = append {
            if error.mutation_unknown() {
                self.reload_after_unknown();
            }
            return Err(persistence_error(error));
        }
        let entry = self
            .entries
            .get_mut(&operation_id)
            .expect("entry checked above");
        entry.reducer = candidate;
        if entry.log.should_compact() {
            let snapshot = entry.reducer.snapshot.clone();
            match entry
                .log
                .compact(&entry.directory.join(SNAPSHOT_FILE), &snapshot)
            {
                Ok(()) => {
                    entry.reducer = FileOperationReducer::from_snapshot(snapshot)
                        .expect("validated operation snapshot");
                }
                Err(error) if error.mutation_unknown() => self.reload_after_unknown(),
                Err(_) => {}
            }
        }
        self.ensure_healthy()
    }

    fn insert(&mut self, operation: OperationRecord) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        if operation.state != OperationState::Intent {
            return Err(conflict("new operation must start in INTENT"));
        }
        validate_operation(&operation)?;
        let operation_id = operation.id;
        if let Some(entry) = self.entries.get(&operation_id) {
            if entry.reducer.snapshot.operation.is_some() {
                return Err(conflict("duplicate operation id"));
            }
            return self.append_transition(
                operation_id,
                FileOperationTransitionV1::IntentInserted {
                    operation: Box::new(operation),
                },
            );
        }
        let directory = self.root.join(operation_id.to_string());
        create_private_dir_all(&directory).map_err(persistence_error)?;
        sync_parent(&directory).map_err(|error| {
            JournalError::Persistence(format!("operation directory sync failed: {error}"))
        })?;
        let (mut log, events) = self
            .persistence
            .open_event_log::<FileOperationEventV1>(directory.join(EVENT_LOG_FILE), 0)
            .map_err(persistence_error)?;
        if !events.is_empty() {
            return Err(corrupt("new operation event log was not empty"));
        }
        let event = FileOperationEventV1 {
            schema_version: SCHEMA_VERSION,
            sequence: 1,
            operation_id,
            transition: FileOperationTransitionV1::IntentInserted {
                operation: Box::new(operation),
            },
        };
        let mut reducer = FileOperationReducer::empty();
        reducer.apply(&event)?;
        match log.append(&event) {
            Ok(1) => {
                self.entries.insert(
                    operation_id,
                    FileOperationEntry {
                        directory,
                        reducer,
                        log,
                    },
                );
                Ok(())
            }
            Ok(_) => Err(corrupt("new operation event sequence is invalid")),
            Err(error) => {
                if error.mutation_unknown() {
                    self.reload_after_unknown();
                } else {
                    let _ = std::fs::remove_file(directory.join(EVENT_LOG_FILE));
                    let _ = std::fs::remove_dir(directory);
                }
                Err(persistence_error(error))
            }
        }
    }
}

#[async_trait]
impl OperationJournal for FileOperationJournal {
    fn is_durable(&self) -> bool {
        true
    }

    async fn insert_intent(&self, operation: OperationRecord) -> Result<(), JournalError> {
        self.state.lock().await.insert(operation)
    }

    async fn get(&self, operation_id: Uuid) -> Result<Option<OperationRecord>, JournalError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        Ok(state
            .entries
            .get(&operation_id)
            .and_then(|entry| entry.reducer.snapshot.operation.clone()))
    }

    async fn set_open(
        &self,
        operation_id: Uuid,
        upload_id: Option<&str>,
    ) -> Result<(), JournalError> {
        self.state.lock().await.append_transition(
            operation_id,
            FileOperationTransitionV1::Opened {
                upload_id: upload_id.map(ToOwned::to_owned),
                updated_at_ms: unix_time_ms(),
            },
        )
    }

    async fn compare_and_set_client_multipart_upload_reference(
        &self,
        operation_id: Uuid,
        expected: Option<&str>,
        next: Option<&str>,
    ) -> Result<(), JournalError> {
        self.state.lock().await.append_transition(
            operation_id,
            FileOperationTransitionV1::ClientMultipartReferenceChanged {
                expected: expected.map(ToOwned::to_owned),
                next: next.map(ToOwned::to_owned),
                updated_at_ms: unix_time_ms(),
            },
        )
    }

    async fn set_expected(
        &self,
        operation_id: Uuid,
        expected: &ExpectedObject,
    ) -> Result<(), JournalError> {
        self.state.lock().await.append_transition(
            operation_id,
            FileOperationTransitionV1::ExpectedChanged {
                expected: expected.clone(),
                updated_at_ms: unix_time_ms(),
            },
        )
    }

    async fn transition(
        &self,
        operation_id: Uuid,
        expected: OperationState,
        next: OperationState,
        committed: Option<&StoredObjectMeta>,
    ) -> Result<(), JournalError> {
        self.state.lock().await.append_transition(
            operation_id,
            FileOperationTransitionV1::StateChanged {
                expected,
                next,
                committed: committed.cloned(),
                updated_at_ms: unix_time_ms(),
            },
        )
    }

    async fn record_part(&self, part: PartRecord) -> Result<(), JournalError> {
        let operation_id = part.operation_id;
        self.state.lock().await.append_transition(
            operation_id,
            FileOperationTransitionV1::PartRecorded { part },
        )
    }

    async fn parts(&self, operation_id: Uuid) -> Result<Vec<PartRecord>, JournalError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        Ok(state
            .entries
            .get(&operation_id)
            .map(|entry| entry.reducer.snapshot.parts.clone())
            .unwrap_or_default())
    }

    async fn append_evidence(&self, evidence: EvidenceRecord) -> Result<(), JournalError> {
        let operation_id = evidence.operation_id;
        self.state.lock().await.append_transition(
            operation_id,
            FileOperationTransitionV1::EvidenceAppended { evidence },
        )
    }

    async fn evidence(&self, operation_id: Uuid) -> Result<Vec<EvidenceRecord>, JournalError> {
        let state = self.state.lock().await;
        state.ensure_healthy()?;
        Ok(state
            .entries
            .get(&operation_id)
            .map(|entry| entry.reducer.snapshot.evidence.clone())
            .unwrap_or_default())
    }

    async fn record_mutation_launch(
        &self,
        operation_id: Uuid,
        not_before_ms: i64,
    ) -> Result<(), JournalError> {
        self.state.lock().await.append_transition(
            operation_id,
            FileOperationTransitionV1::MutationLaunched {
                not_before_ms,
                updated_at_ms: unix_time_ms(),
            },
        )
    }

    async fn confirm_exact_absence(
        &self,
        operation_id: Uuid,
        observed_at_ms: i64,
        minimum_separation_ms: i64,
    ) -> Result<bool, JournalError> {
        checked_timestamp(observed_at_ms, "exact absence timestamp")?;
        if minimum_separation_ms < 0 {
            return Err(conflict("negative exact absence separation"));
        }
        let mut state = self.state.lock().await;
        state.ensure_healthy()?;
        let operation = state
            .entries
            .get(&operation_id)
            .and_then(|entry| entry.reducer.snapshot.operation.as_ref())
            .ok_or(JournalError::NotFound(operation_id))?;
        if operation
            .mutation_not_before_ms
            .is_some_and(|not_before| observed_at_ms < not_before)
        {
            return Ok(false);
        }
        if let Some(first) = operation.exact_absence_observed_at_ms {
            return Ok(observed_at_ms.saturating_sub(first) >= minimum_separation_ms);
        }
        state.append_transition(
            operation_id,
            FileOperationTransitionV1::ExactAbsenceObserved {
                observed_at_ms,
                updated_at_ms: unix_time_ms(),
            },
        )?;
        Ok(false)
    }

    async fn claim_reconcilable(
        &self,
        owner: &str,
        stale_before_ms: i64,
        lease_until_ms: i64,
        limit: u64,
    ) -> Result<Vec<OperationRecord>, JournalError> {
        checked_timestamp(stale_before_ms, "stale threshold timestamp")?;
        checked_timestamp(lease_until_ms, "lease expiry timestamp")?;
        if owner.is_empty() {
            return Err(conflict("claim owner is empty"));
        }
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let now = unix_time_ms();
        let mut state = self.state.lock().await;
        state.ensure_healthy()?;
        let mut candidates = state
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                let operation = entry.reducer.snapshot.operation.as_ref()?;
                (!operation.state.is_terminal()
                    && operation.updated_at_ms <= stale_before_ms
                    && operation
                        .lease_expires_at_ms
                        .is_none_or(|expiry| expiry < now))
                .then_some((operation.updated_at_ms, *id))
            })
            .collect::<Vec<_>>();
        candidates.sort_unstable();
        candidates.truncate(limit);
        let mut claimed = Vec::with_capacity(candidates.len());
        for (_, operation_id) in candidates {
            state.append_transition(
                operation_id,
                FileOperationTransitionV1::Claimed {
                    owner: owner.to_string(),
                    lease_until_ms,
                },
            )?;
            claimed.push(
                state.entries[&operation_id]
                    .reducer
                    .snapshot
                    .operation
                    .clone()
                    .expect("claimed operation remains present"),
            );
        }
        Ok(claimed)
    }

    async fn claim_reconcilable_operation(
        &self,
        operation_id: Uuid,
        owner: &str,
        stale_before_ms: i64,
        lease_until_ms: i64,
    ) -> Result<Option<OperationRecord>, JournalError> {
        checked_timestamp(stale_before_ms, "stale threshold timestamp")?;
        checked_timestamp(lease_until_ms, "lease expiry timestamp")?;
        if owner.is_empty() {
            return Err(conflict("claim owner is empty"));
        }
        let now = unix_time_ms();
        let mut state = self.state.lock().await;
        state.ensure_healthy()?;
        let Some(operation) = state
            .entries
            .get(&operation_id)
            .and_then(|entry| entry.reducer.snapshot.operation.as_ref())
        else {
            return Ok(None);
        };
        if operation.state.is_terminal()
            || operation.updated_at_ms > stale_before_ms
            || operation
                .lease_expires_at_ms
                .is_some_and(|expiry| expiry >= now)
        {
            return Ok(None);
        }
        state.append_transition(
            operation_id,
            FileOperationTransitionV1::Claimed {
                owner: owner.to_string(),
                lease_until_ms,
            },
        )?;
        Ok(state.entries[&operation_id]
            .reducer
            .snapshot
            .operation
            .clone())
    }

    async fn retire_terminal(
        &self,
        operation_id: Uuid,
        expected_state: OperationState,
        expected_client_multipart_upload_id: Option<&str>,
    ) -> Result<(), JournalError> {
        self.state.lock().await.append_transition(
            operation_id,
            FileOperationTransitionV1::TerminalRetired {
                expected_state,
                expected_client_multipart_upload_id: expected_client_multipart_upload_id
                    .map(ToOwned::to_owned),
            },
        )
    }
}

fn prepare_root(path: &Path) -> Result<(), JournalError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err(corrupt("operation journal root is not a directory"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(JournalError::Persistence(format!(
                "cannot inspect operation journal root: {error}"
            )));
        }
    }
    create_private_dir_all(path).map_err(persistence_error)
}

fn load_entries(
    root: &Path,
    persistence: &FilesystemPersistence,
) -> Result<BTreeMap<Uuid, FileOperationEntry>, JournalError> {
    prepare_root(root)?;
    let mut entries = BTreeMap::new();
    for item in std::fs::read_dir(root)
        .map_err(|error| corrupt(format!("cannot read operation journal root: {error}")))?
    {
        let item = item.map_err(|error| corrupt(format!("cannot inspect operation: {error}")))?;
        let metadata = std::fs::symlink_metadata(item.path())
            .map_err(|error| corrupt(format!("cannot inspect operation state: {error}")))?;
        if !metadata.file_type().is_dir() {
            return Err(corrupt("unknown file in operation journal root"));
        }
        let name = item
            .file_name()
            .into_string()
            .map_err(|_| corrupt("operation directory name is not UTF-8"))?;
        let operation_id = Uuid::parse_str(&name)
            .map_err(|_| corrupt("operation directory name is not a UUID"))?;
        if operation_id.to_string() != name {
            return Err(corrupt("operation directory UUID is not canonical"));
        }
        let directory = item.path();
        validate_entry_files(&directory)?;
        let loaded = persistence
            .load_snapshot::<FileOperationSnapshotV1>(&directory.join(SNAPSHOT_FILE))
            .map_err(persistence_error)?;
        let (snapshot_sequence, snapshot) = match loaded {
            Some(snapshot) => {
                if snapshot.final_sequence != snapshot.payload.final_event_sequence {
                    return Err(corrupt("operation snapshot sequence mismatch"));
                }
                (snapshot.final_sequence, snapshot.payload)
            }
            None => (0, FileOperationSnapshotV1::default()),
        };
        let mut reducer = FileOperationReducer::from_snapshot(snapshot)?;
        let (log, events) = persistence
            .open_event_log::<FileOperationEventV1>(
                directory.join(EVENT_LOG_FILE),
                snapshot_sequence,
            )
            .map_err(persistence_error)?;
        for logged in events {
            if logged.sequence != logged.payload.sequence {
                return Err(corrupt("operation event sequence mismatch"));
            }
            reducer.apply(&logged.payload)?;
        }
        if reducer
            .snapshot
            .operation
            .as_ref()
            .is_some_and(|operation| operation.id != operation_id)
        {
            return Err(corrupt("operation directory identity mismatch"));
        }
        if entries
            .insert(
                operation_id,
                FileOperationEntry {
                    directory,
                    reducer,
                    log,
                },
            )
            .is_some()
        {
            return Err(corrupt("duplicate operation identity"));
        }
    }
    Ok(entries)
}

fn validate_entry_files(directory: &Path) -> Result<(), JournalError> {
    let mut has_log = false;
    for item in std::fs::read_dir(directory)
        .map_err(|error| corrupt(format!("cannot read operation state: {error}")))?
    {
        let item =
            item.map_err(|error| corrupt(format!("cannot inspect operation state: {error}")))?;
        let name = item
            .file_name()
            .into_string()
            .map_err(|_| corrupt("operation state filename is not UTF-8"))?;
        if name != SNAPSHOT_FILE && name != EVENT_LOG_FILE {
            return Err(corrupt("unknown file in operation directory"));
        }
        let metadata = std::fs::symlink_metadata(item.path())
            .map_err(|error| corrupt(format!("cannot inspect operation state: {error}")))?;
        if !metadata.file_type().is_file() {
            return Err(corrupt("operation state path is not a regular file"));
        }
        has_log |= name == EVENT_LOG_FILE;
    }
    if !has_log {
        return Err(corrupt("operation event log is missing"));
    }
    Ok(())
}

fn conflict(message: impl Into<String>) -> JournalError {
    JournalError::Conflict(message.into())
}

fn corrupt(message: impl Into<String>) -> JournalError {
    JournalError::Corrupt(message.into())
}

fn persistence_error(error: PersistenceError) -> JournalError {
    match error {
        PersistenceError::Corrupt(message) => JournalError::Corrupt(message),
        PersistenceError::UnsupportedVersion(version) => {
            JournalError::Corrupt(format!("unsupported persistence version {version}"))
        }
        PersistenceError::LimitExceeded(message) => JournalError::Corrupt(message.to_string()),
        other => JournalError::Persistence(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::Arc;

    use super::*;
    use crate::filesystem_persistence::FaultPoint;
    use crate::transaction::journal::contract;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("maskura-file-journal-{}", Uuid::now_v7()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn old_operation() -> OperationRecord {
        let mut operation = contract::operation();
        operation.created_at_ms = 1;
        operation.updated_at_ms = 1;
        operation
    }

    fn reopen(root: &Path) -> FileOperationJournal {
        FileOperationJournal::open(root.to_path_buf()).unwrap()
    }

    async fn advance(journal: &dyn OperationJournal, id: Uuid, state: OperationState) {
        if matches!(
            state,
            OperationState::Open
                | OperationState::Completing
                | OperationState::CommitUnknown
                | OperationState::Committed
        ) {
            journal.set_open(id, Some("upload")).await.unwrap();
        }
        if matches!(
            state,
            OperationState::Completing | OperationState::CommitUnknown | OperationState::Committed
        ) {
            journal
                .transition(id, OperationState::Open, OperationState::Completing, None)
                .await
                .unwrap();
        }
        if matches!(
            state,
            OperationState::CommitUnknown | OperationState::Committed
        ) {
            journal
                .transition(
                    id,
                    OperationState::Completing,
                    OperationState::CommitUnknown,
                    None,
                )
                .await
                .unwrap();
        }
        if state == OperationState::Committed {
            journal
                .transition(
                    id,
                    OperationState::CommitUnknown,
                    OperationState::Committed,
                    Some(&StoredObjectMeta::default()),
                )
                .await
                .unwrap();
        }
        if matches!(
            state,
            OperationState::Aborting | OperationState::ProvenAborted
        ) {
            journal
                .transition(id, OperationState::Intent, OperationState::Aborting, None)
                .await
                .unwrap();
        }
        if state == OperationState::ProvenAborted {
            journal
                .transition(
                    id,
                    OperationState::Aborting,
                    OperationState::ProvenAborted,
                    None,
                )
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn file_journal_satisfies_shared_contract() {
        let directory = TempDir::new();
        let journal = reopen(directory.path());
        contract::run(&journal).await;
        drop(journal);
        let restarted = reopen(directory.path());
        assert_eq!(restarted.state.lock().await.entries.len(), 1);
        let operation_id = restarted
            .state
            .lock()
            .await
            .entries
            .keys()
            .next()
            .copied()
            .unwrap();
        assert!(restarted.get(operation_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn every_state_and_commit_unknown_survive_restart() {
        for state in OperationState::ALL {
            let directory = TempDir::new();
            let journal = reopen(directory.path());
            let operation = old_operation();
            journal.insert_intent(operation.clone()).await.unwrap();
            advance(&journal, operation.id, state).await;
            drop(journal);

            let restarted = reopen(directory.path());
            let stored = restarted.get(operation.id).await.unwrap().unwrap();
            assert_eq!(stored.state, state);
            assert_eq!(
                stored.committed.is_some(),
                state == OperationState::Committed
            );
        }
    }

    #[tokio::test]
    async fn parts_evidence_reference_and_claim_survive_restart() {
        let directory = TempDir::new();
        let operation = old_operation();
        let journal = reopen(directory.path());
        journal.insert_intent(operation.clone()).await.unwrap();
        journal
            .compare_and_set_client_multipart_upload_reference(operation.id, None, Some("client"))
            .await
            .unwrap();
        for part_number in [3, 1, 2] {
            journal
                .record_part(PartRecord {
                    operation_id: operation.id,
                    part_number,
                    etag: format!("etag-{part_number}"),
                    size_bytes: part_number as u64,
                    digest: format!("digest-{part_number}"),
                    created_at_ms: part_number.into(),
                })
                .await
                .unwrap();
        }
        for index in 0..3 {
            journal
                .append_evidence(EvidenceRecord {
                    id: Uuid::now_v7(),
                    operation_id: operation.id,
                    kind: format!("evidence-{index}"),
                    detail: serde_json::json!({"index": index}),
                    created_at_ms: index + 1,
                })
                .await
                .unwrap();
        }
        let lease_until = unix_time_ms() + 60_000;
        let claimed = journal
            .claim_reconcilable_operation(operation.id, "worker", unix_time_ms(), lease_until)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claimed.lease_owner.as_deref(), Some("worker"));
        drop(journal);

        let restarted = reopen(directory.path());
        let stored = restarted.get(operation.id).await.unwrap().unwrap();
        assert_eq!(stored.client_multipart_upload_id.as_deref(), Some("client"));
        assert_eq!(stored.lease_expires_at_ms, Some(lease_until));
        assert_eq!(
            restarted
                .parts(operation.id)
                .await
                .unwrap()
                .iter()
                .map(|part| part.part_number)
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(restarted.evidence(operation.id).await.unwrap().len(), 3);
        assert!(
            restarted
                .claim_reconcilable_operation(operation.id, "other", 2, lease_until + 1)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn bulk_claim_is_ordered_bounded_durable_and_respects_staleness() {
        let directory = TempDir::new();
        let journal = reopen(directory.path());
        let mut ids = Vec::new();
        for updated_at_ms in [3, 1, 2, 10] {
            let mut operation = old_operation();
            operation.created_at_ms = updated_at_ms;
            operation.updated_at_ms = updated_at_ms;
            ids.push((updated_at_ms, operation.id));
            journal.insert_intent(operation).await.unwrap();
        }
        let lease_until = unix_time_ms() + 60_000;
        let claimed = journal
            .claim_reconcilable("worker", 3, lease_until, 2)
            .await
            .unwrap();
        let mut expected = ids[..3].to_vec();
        expected.sort_unstable();
        assert_eq!(
            claimed.iter().map(|item| item.id).collect::<Vec<_>>(),
            expected[..2].iter().map(|item| item.1).collect::<Vec<_>>()
        );
        drop(journal);
        let restarted = reopen(directory.path());
        for id in expected[..2].iter().map(|item| item.1) {
            assert_eq!(
                restarted
                    .get(id)
                    .await
                    .unwrap()
                    .unwrap()
                    .lease_owner
                    .as_deref(),
                Some("worker")
            );
        }
    }

    #[tokio::test]
    async fn concurrent_mutations_are_serialized_without_lost_parts() {
        let directory = TempDir::new();
        let journal = Arc::new(reopen(directory.path()));
        let operation = old_operation();
        journal.insert_intent(operation.clone()).await.unwrap();
        let operation_id = operation.id;
        let mut tasks = Vec::new();
        for part_number in 1..=64 {
            let journal = journal.clone();
            tasks.push(tokio::spawn(async move {
                journal
                    .record_part(PartRecord {
                        operation_id,
                        part_number,
                        etag: part_number.to_string(),
                        size_bytes: 1,
                        digest: part_number.to_string(),
                        created_at_ms: part_number.into(),
                    })
                    .await
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(journal.parts(operation.id).await.unwrap().len(), 64);
    }

    #[tokio::test]
    async fn compaction_and_torn_tail_reopen_exactly() {
        let directory = TempDir::new();
        let operation = old_operation();
        let journal = reopen(directory.path());
        journal.insert_intent(operation.clone()).await.unwrap();
        for index in 0..300 {
            journal
                .append_evidence(EvidenceRecord {
                    id: Uuid::from_u128(index + 1),
                    operation_id: operation.id,
                    kind: "compact".to_string(),
                    detail: serde_json::json!(index),
                    created_at_ms: index as i64 + 1,
                })
                .await
                .unwrap();
        }
        drop(journal);
        let operation_dir = directory.path().join(operation.id.to_string());
        assert!(operation_dir.join(SNAPSHOT_FILE).is_file());
        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(operation_dir.join(EVENT_LOG_FILE))
            .unwrap();
        log.write_all(b"MSEL\x01torn").unwrap();
        log.sync_all().unwrap();
        drop(log);

        let restarted = reopen(directory.path());
        assert_eq!(restarted.evidence(operation.id).await.unwrap().len(), 300);
    }

    #[tokio::test]
    async fn corruption_unknown_files_and_symlinks_fail_closed() {
        let unknown = TempDir::new();
        std::fs::write(unknown.path().join("unknown"), b"data").unwrap();
        assert!(matches!(
            FileOperationJournal::open(unknown.path().to_path_buf()),
            Err(JournalError::Corrupt(_))
        ));

        let corrupt_dir = TempDir::new();
        let operation = old_operation();
        let journal = reopen(corrupt_dir.path());
        journal.insert_intent(operation.clone()).await.unwrap();
        drop(journal);
        let log_path = corrupt_dir
            .path()
            .join(operation.id.to_string())
            .join(EVENT_LOG_FILE);
        let mut bytes = std::fs::read(&log_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(log_path, bytes).unwrap();
        assert!(matches!(
            FileOperationJournal::open(corrupt_dir.path().to_path_buf()),
            Err(JournalError::Corrupt(_))
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let symlink_dir = TempDir::new();
            symlink(
                corrupt_dir.path(),
                symlink_dir.path().join(Uuid::now_v7().to_string()),
            )
            .unwrap();
            assert!(matches!(
                FileOperationJournal::open(symlink_dir.path().to_path_buf()),
                Err(JournalError::Corrupt(_))
            ));
        }
    }

    #[tokio::test]
    async fn append_mutation_unknown_reloads_committed_frame_under_lock() {
        let directory = TempDir::new();
        let persistence = FilesystemPersistence::default();
        let journal = FileOperationJournal::open_for_test(
            directory.path().to_path_buf(),
            persistence.clone(),
        )
        .unwrap();
        let operation = old_operation();
        journal.insert_intent(operation.clone()).await.unwrap();
        persistence.fail_once(FaultPoint::AppendSync);

        assert!(matches!(
            journal.set_open(operation.id, Some("upload")).await,
            Err(JournalError::Persistence(_))
        ));
        assert_eq!(
            journal.get(operation.id).await.unwrap().unwrap().state,
            OperationState::Open
        );
        drop(journal);
        assert_eq!(
            reopen(directory.path())
                .get(operation.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            OperationState::Open
        );
    }

    #[test]
    fn reducer_rejects_record_bounds_and_invalid_timestamps() {
        let operation = old_operation();
        let mut snapshot = FileOperationSnapshotV1 {
            operation: Some(operation.clone()),
            ..FileOperationSnapshotV1::default()
        };
        snapshot.parts = (1..=(MAX_PARTS + 1))
            .map(|part_number| PartRecord {
                operation_id: operation.id,
                part_number: i32::try_from(part_number).unwrap(),
                etag: "etag".to_string(),
                size_bytes: 1,
                digest: "digest".to_string(),
                created_at_ms: 1,
            })
            .collect();
        assert!(matches!(
            validate_snapshot(&snapshot),
            Err(JournalError::Corrupt(_))
        ));

        snapshot.parts.clear();
        snapshot.evidence = (0..=MAX_EVIDENCE)
            .map(|index| EvidenceRecord {
                id: Uuid::from_u128(index as u128 + 1),
                operation_id: operation.id,
                kind: "evidence".to_string(),
                detail: serde_json::Value::Null,
                created_at_ms: 1,
            })
            .collect();
        assert!(matches!(
            validate_snapshot(&snapshot),
            Err(JournalError::Corrupt(_))
        ));

        snapshot.evidence.clear();
        snapshot.operation.as_mut().unwrap().lease_expires_at_ms = Some(-1);
        snapshot.operation.as_mut().unwrap().lease_owner = Some("worker".to_string());
        assert!(matches!(
            validate_snapshot(&snapshot),
            Err(JournalError::Corrupt(_))
        ));
    }
}
