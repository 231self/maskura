use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const SNAPSHOT_VERSION: u32 = 1;
const FRAME_MAGIC: &[u8; 4] = b"MSEL";
const FRAME_VERSION: u8 = 1;
const FRAME_HEADER_BYTES: usize = 17;
const CHECKSUM_BYTES: usize = 32;
const MAX_SNAPSHOT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_LOG_BYTES: u64 = 32 * 1024 * 1024;
const MAX_EVENT_PAYLOAD_BYTES: usize = 1024 * 1024;
const COMPACT_AFTER_EVENTS: u64 = 256;
const COMPACT_AFTER_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PersistenceError {
    #[error("filesystem persistence {operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("filesystem persistence {operation} may have committed: {source}")]
    MutationUnknown {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("filesystem persistence data is corrupt: {0}")]
    Corrupt(String),
    #[error("unsupported filesystem persistence schema version {0}")]
    UnsupportedVersion(u64),
    #[error("filesystem persistence limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("filesystem persistence must be reloaded after an uncertain mutation")]
    ReloadRequired,
    #[error("the filesystem storage root is already locked by another process")]
    RootAlreadyLocked,
}

impl PersistenceError {
    pub(crate) fn mutation_unknown(&self) -> bool {
        matches!(self, Self::MutationUnknown { .. })
    }
}

#[derive(Debug)]
pub(crate) struct Snapshot<T> {
    pub(crate) final_sequence: u64,
    pub(crate) payload: T,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct SnapshotEnvelope {
    version: u32,
    final_sequence: u64,
    payload: serde_json::Value,
    checksum: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FilesystemPersistence {
    #[cfg(test)]
    faults: std::sync::Arc<std::sync::Mutex<Vec<FaultPoint>>>,
}

impl FilesystemPersistence {
    pub(crate) fn atomic_write_snapshot<T: Serialize>(
        &self,
        path: &Path,
        final_sequence: u64,
        payload: &T,
    ) -> Result<(), PersistenceError> {
        let payload = serde_json::to_value(payload)
            .map_err(|error| PersistenceError::Corrupt(error.to_string()))?;
        let canonical_payload = serde_json::to_vec(&payload)
            .map_err(|error| PersistenceError::Corrupt(error.to_string()))?;
        let envelope = SnapshotEnvelope {
            version: SNAPSHOT_VERSION,
            final_sequence,
            checksum: hex::encode(snapshot_checksum(final_sequence, &canonical_payload)),
            payload,
        };
        let encoded = serde_json::to_vec(&envelope)
            .map_err(|error| PersistenceError::Corrupt(error.to_string()))?;
        if encoded.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err(PersistenceError::LimitExceeded("snapshot exceeds 32 MiB"));
        }
        self.atomic_write(path, &encoded, "snapshot publication")
    }

    pub(crate) fn load_snapshot<T: DeserializeOwned>(
        &self,
        path: &Path,
    ) -> Result<Option<Snapshot<T>>, PersistenceError> {
        let Some(encoded) = read_regular_file(path, MAX_SNAPSHOT_BYTES, "snapshot read")? else {
            return Ok(None);
        };
        let envelope: SnapshotEnvelope = serde_json::from_slice(&encoded).map_err(|error| {
            PersistenceError::Corrupt(format!("invalid snapshot JSON: {error}"))
        })?;
        if envelope.version != SNAPSHOT_VERSION {
            return Err(PersistenceError::UnsupportedVersion(
                envelope.version.into(),
            ));
        }
        let canonical_payload = serde_json::to_vec(&envelope.payload)
            .map_err(|error| PersistenceError::Corrupt(error.to_string()))?;
        let expected = snapshot_checksum(envelope.final_sequence, &canonical_payload);
        let checksum = hex::decode(&envelope.checksum)
            .map_err(|_| PersistenceError::Corrupt("invalid snapshot checksum encoding".into()))?;
        if checksum.as_slice() != expected {
            return Err(PersistenceError::Corrupt(
                "snapshot checksum mismatch".into(),
            ));
        }
        let payload = serde_json::from_value(envelope.payload).map_err(|error| {
            PersistenceError::Corrupt(format!("invalid snapshot payload: {error}"))
        })?;
        Ok(Some(Snapshot {
            final_sequence: envelope.final_sequence,
            payload,
        }))
    }

    pub(crate) fn open_event_log<T: DeserializeOwned>(
        &self,
        path: impl Into<PathBuf>,
        snapshot_sequence: u64,
    ) -> Result<(EventLog, Vec<LoggedEvent<T>>), PersistenceError> {
        EventLog::open(path.into(), snapshot_sequence, self.clone())
    }

    pub(crate) fn acquire_root_lock(&self, root: &Path) -> Result<RootLock, PersistenceError> {
        create_private_dir_all(root)?;
        let path = root.join(".maskura").join("root.lock");
        create_private_dir_all(path.parent().expect("root lock has a parent"))?;
        reject_non_regular_if_present(&path, "root lock validation")?;
        let created = !path.exists();
        let file = open_owner_only(&path, true, false, true, "root lock open")?;
        if created {
            file.sync_all()
                .map_err(|source| io("root lock sync", source))?;
            sync_parent(&path).map_err(|source| io("root lock parent sync", source))?;
        }
        match file.try_lock() {
            Ok(()) => Ok(RootLock {
                file,
                #[cfg(test)]
                path,
            }),
            Err(std::fs::TryLockError::WouldBlock) => Err(PersistenceError::RootAlreadyLocked),
            Err(std::fs::TryLockError::Error(source)) => Err(io("root lock acquisition", source)),
        }
    }

    fn atomic_write(
        &self,
        path: &Path,
        bytes: &[u8],
        operation: &'static str,
    ) -> Result<(), PersistenceError> {
        let parent = required_parent(path)?;
        create_private_dir_all(parent)?;
        reject_non_regular_if_present(path, operation)?;
        self.fault(FaultPoint::PreWrite, operation, false)?;
        let temporary = unique_temporary_path(path);
        let result = (|| {
            let mut file = open_owner_only(&temporary, true, true, false, "temporary file create")?;
            file.write_all(bytes)
                .map_err(|source| io(operation, source))?;
            self.fault(FaultPoint::PostWrite, operation, false)?;
            self.fault(FaultPoint::FileSync, operation, false)?;
            file.sync_all().map_err(|source| io(operation, source))?;
            drop(file);
            self.fault(FaultPoint::Rename, operation, false)?;
            std::fs::rename(&temporary, path).map_err(|source| io(operation, source))?;
            self.fault(FaultPoint::ParentSync, operation, true)?;
            sync_parent(path).map_err(|source| unknown(operation, source))?;
            Ok(())
        })();
        if temporary.exists() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }

    #[cfg(not(test))]
    fn fault(
        &self,
        _point: FaultPoint,
        _operation: &'static str,
        _unknown: bool,
    ) -> Result<(), PersistenceError> {
        Ok(())
    }

    #[cfg(test)]
    fn fault(
        &self,
        point: FaultPoint,
        operation: &'static str,
        unknown_outcome: bool,
    ) -> Result<(), PersistenceError> {
        let mut faults = self.faults.lock().expect("fault injector lock poisoned");
        if let Some(index) = faults.iter().position(|candidate| *candidate == point) {
            faults.remove(index);
            let source = std::io::Error::other(format!("injected {point:?} failure"));
            return Err(if unknown_outcome {
                unknown(operation, source)
            } else {
                io(operation, source)
            });
        }
        Ok(())
    }

    #[cfg(test)]
    fn fail_once(&self, point: FaultPoint) {
        self.faults
            .lock()
            .expect("fault injector lock poisoned")
            .push(point);
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultPoint {
    PreWrite,
    PostWrite,
    FileSync,
    Rename,
    ParentSync,
    Append,
    AppendSync,
    CompactionAfterSnapshot,
}

#[cfg(not(test))]
#[derive(Clone, Copy)]
enum FaultPoint {
    PreWrite,
    PostWrite,
    FileSync,
    Rename,
    ParentSync,
    Append,
    AppendSync,
    CompactionAfterSnapshot,
}

#[derive(Debug)]
pub(crate) struct LoggedEvent<T> {
    pub(crate) sequence: u64,
    pub(crate) payload: T,
}

#[derive(Debug)]
pub(crate) struct EventLog {
    path: PathBuf,
    next_sequence: u64,
    event_count: u64,
    byte_len: u64,
    reload_required: bool,
    persistence: FilesystemPersistence,
}

impl EventLog {
    fn open<T: DeserializeOwned>(
        path: PathBuf,
        snapshot_sequence: u64,
        persistence: FilesystemPersistence,
    ) -> Result<(Self, Vec<LoggedEvent<T>>), PersistenceError> {
        let parent = required_parent(&path)?;
        create_private_dir_all(parent)?;
        reject_non_regular_if_present(&path, "event log validation")?;
        if !path.exists() {
            let file = open_owner_only(&path, true, true, false, "event log create")?;
            file.sync_all()
                .map_err(|source| io("event log create", source))?;
            sync_parent(&path).map_err(|source| io("event log parent sync", source))?;
        }
        let mut file = open_owner_only(&path, false, false, true, "event log open")?;
        let byte_len = file
            .metadata()
            .map_err(|source| io("event log metadata", source))?
            .len();
        if byte_len > MAX_LOG_BYTES {
            return Err(PersistenceError::LimitExceeded("event log exceeds 32 MiB"));
        }
        let mut bytes = Vec::with_capacity(byte_len as usize);
        file.read_to_end(&mut bytes)
            .map_err(|source| io("event log read", source))?;
        let replay = parse_frames::<T>(&bytes, snapshot_sequence)?;
        if replay.valid_bytes < bytes.len() {
            file.set_len(replay.valid_bytes as u64)
                .map_err(|source| unknown("torn event log repair", source))?;
            file.sync_data()
                .map_err(|source| unknown("torn event log repair", source))?;
        }
        let repaired_len = replay.valid_bytes as u64;
        let next_sequence = replay
            .last_sequence
            .unwrap_or(snapshot_sequence)
            .max(snapshot_sequence)
            .checked_add(1)
            .ok_or_else(|| PersistenceError::Corrupt("event sequence overflow".into()))?;
        Ok((
            Self {
                path,
                next_sequence,
                event_count: replay.frame_count,
                byte_len: repaired_len,
                reload_required: false,
                persistence,
            },
            replay.events,
        ))
    }

    pub(crate) fn append<T: Serialize>(&mut self, payload: &T) -> Result<u64, PersistenceError> {
        if self.reload_required {
            return Err(PersistenceError::ReloadRequired);
        }
        let payload = serde_json::to_value(payload)
            .and_then(|value| serde_json::to_vec(&value))
            .map_err(|error| PersistenceError::Corrupt(error.to_string()))?;
        if payload.len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(PersistenceError::LimitExceeded(
                "event payload exceeds 1 MiB",
            ));
        }
        let frame = encode_frame(self.next_sequence, &payload);
        if self.byte_len.saturating_add(frame.len() as u64) > MAX_LOG_BYTES {
            return Err(PersistenceError::LimitExceeded("event log exceeds 32 MiB"));
        }
        self.persistence
            .fault(FaultPoint::Append, "event append", false)?;
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|source| io("event append open", source))?;
        if let Err(source) = file.write_all(&frame) {
            self.reload_required = true;
            return Err(unknown("event append", source));
        }
        if let Err(error) = self
            .persistence
            .fault(FaultPoint::AppendSync, "event append sync", true)
            .and_then(|()| {
                file.sync_data()
                    .map_err(|source| unknown("event append sync", source))
            })
        {
            self.reload_required = true;
            return Err(error);
        }
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        self.event_count += 1;
        self.byte_len += frame.len() as u64;
        Ok(sequence)
    }

    pub(crate) fn should_compact(&self) -> bool {
        self.event_count >= COMPACT_AFTER_EVENTS || self.byte_len >= COMPACT_AFTER_BYTES
    }

    pub(crate) fn compact<T: Serialize>(
        &mut self,
        snapshot_path: &Path,
        payload: &T,
    ) -> Result<(), PersistenceError> {
        if self.reload_required {
            return Err(PersistenceError::ReloadRequired);
        }
        let final_sequence = self.next_sequence.saturating_sub(1);
        if let Err(error) =
            self.persistence
                .atomic_write_snapshot(snapshot_path, final_sequence, payload)
        {
            if error.mutation_unknown() {
                self.reload_required = true;
            }
            return Err(error);
        }
        if let Err(error) = self.persistence.fault(
            FaultPoint::CompactionAfterSnapshot,
            "event log compaction",
            true,
        ) {
            self.reload_required = true;
            return Err(error);
        }
        if let Err(error) = self
            .persistence
            .atomic_write(&self.path, &[], "event log compaction")
        {
            if error.mutation_unknown() {
                self.reload_required = true;
            }
            return Err(error);
        }
        self.event_count = 0;
        self.byte_len = 0;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct RootLock {
    file: File,
    #[cfg(test)]
    path: PathBuf,
}

#[cfg(test)]
impl RootLock {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RootLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

struct ParsedFrames<T> {
    events: Vec<LoggedEvent<T>>,
    valid_bytes: usize,
    frame_count: u64,
    last_sequence: Option<u64>,
}

fn parse_frames<T: DeserializeOwned>(
    bytes: &[u8],
    snapshot_sequence: u64,
) -> Result<ParsedFrames<T>, PersistenceError> {
    let mut offset = 0;
    let mut events = Vec::new();
    let mut previous_sequence = None;
    let mut frame_count = 0_u64;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        if remaining.len() < FRAME_HEADER_BYTES {
            break;
        }
        if &remaining[..4] != FRAME_MAGIC {
            return Err(PersistenceError::Corrupt(format!(
                "invalid event frame magic at offset {offset}"
            )));
        }
        let version = remaining[4];
        if version != FRAME_VERSION {
            return Err(PersistenceError::UnsupportedVersion(version.into()));
        }
        let sequence = u64::from_be_bytes(remaining[5..13].try_into().expect("fixed sequence"));
        let payload_len =
            u32::from_be_bytes(remaining[13..17].try_into().expect("fixed payload length"))
                as usize;
        if payload_len > MAX_EVENT_PAYLOAD_BYTES {
            return Err(PersistenceError::LimitExceeded(
                "event payload exceeds 1 MiB",
            ));
        }
        let frame_len = FRAME_HEADER_BYTES + payload_len + CHECKSUM_BYTES;
        if remaining.len() < frame_len {
            break;
        }
        match previous_sequence {
            Some(previous) if sequence != previous + 1 => {
                return Err(PersistenceError::Corrupt(format!(
                    "event sequence {sequence} does not follow {previous}"
                )));
            }
            None if sequence != 1 && sequence != snapshot_sequence.saturating_add(1) => {
                return Err(PersistenceError::Corrupt(format!(
                    "event log starts at unexpected sequence {sequence}"
                )));
            }
            _ => {}
        }
        let payload_end = FRAME_HEADER_BYTES + payload_len;
        let expected = Sha256::digest(&remaining[..payload_end]);
        if remaining[payload_end..frame_len] != expected[..] {
            return Err(PersistenceError::Corrupt(format!(
                "event checksum mismatch at sequence {sequence}"
            )));
        }
        if sequence > snapshot_sequence {
            let payload = serde_json::from_slice(&remaining[FRAME_HEADER_BYTES..payload_end])
                .map_err(|error| {
                    PersistenceError::Corrupt(format!(
                        "invalid event payload at sequence {sequence}: {error}"
                    ))
                })?;
            events.push(LoggedEvent { sequence, payload });
        }
        previous_sequence = Some(sequence);
        frame_count += 1;
        offset += frame_len;
    }
    Ok(ParsedFrames {
        events,
        valid_bytes: offset,
        frame_count,
        last_sequence: previous_sequence,
    })
}

fn encode_frame(sequence: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len() + CHECKSUM_BYTES);
    frame.extend_from_slice(FRAME_MAGIC);
    frame.push(FRAME_VERSION);
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    let checksum = Sha256::digest(&frame);
    frame.extend_from_slice(&checksum);
    frame
}

fn snapshot_checksum(final_sequence: u64, payload: &[u8]) -> [u8; CHECKSUM_BYTES] {
    let mut digest = Sha256::new();
    digest.update(SNAPSHOT_VERSION.to_be_bytes());
    digest.update(final_sequence.to_be_bytes());
    digest.update((payload.len() as u64).to_be_bytes());
    digest.update(payload);
    digest.finalize().into()
}

fn read_regular_file(
    path: &Path,
    maximum: u64,
    operation: &'static str,
) -> Result<Option<Vec<u8>>, PersistenceError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io(operation, source)),
    };
    if !metadata.file_type().is_file() {
        return Err(PersistenceError::Corrupt(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > maximum {
        return Err(PersistenceError::LimitExceeded(
            "file exceeds configured bound",
        ));
    }
    let mut file = File::open(path).map_err(|source| io(operation, source))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|source| io(operation, source))?;
    Ok(Some(bytes))
}

fn reject_non_regular_if_present(
    path: &Path,
    operation: &'static str,
) -> Result<(), PersistenceError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(PersistenceError::Corrupt(format!(
            "{operation}: {} is not a regular file",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io(operation, source)),
    }
}

fn open_owner_only(
    path: &Path,
    create: bool,
    create_new: bool,
    read: bool,
    operation: &'static str,
) -> Result<File, PersistenceError> {
    let mut options = OpenOptions::new();
    options
        .read(read)
        .write(true)
        .create(create)
        .create_new(create_new);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|source| io(operation, source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| io(operation, source))?;
    }
    Ok(file)
}

fn create_private_dir_all(path: &Path) -> Result<(), PersistenceError> {
    std::fs::create_dir_all(path).map_err(|source| io("directory creation", source))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|source| io("directory permissions", source))?;
    }
    Ok(())
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    #[cfg(unix)]
    {
        File::open(parent)?.sync_all()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(parent)?
            .sync_all()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = parent;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "directory synchronization is unsupported on this platform",
        ))
    }
}

fn unique_temporary_path(path: &Path) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    required_parent(path)
        .expect("validated destination parent")
        .join(format!(".{name}.{}.tmp", Uuid::now_v7()))
}

fn required_parent(path: &Path) -> Result<&Path, PersistenceError> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| PersistenceError::Corrupt(format!("{} has no parent", path.display())))
}

fn io(operation: &'static str, source: std::io::Error) -> PersistenceError {
    PersistenceError::Io { operation, source }
}

fn unknown(operation: &'static str, source: std::io::Error) -> PersistenceError {
    PersistenceError::MutationUnknown { operation, source }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct State {
        values: Vec<u64>,
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("maskura-persistence-{}", Uuid::now_v7()));
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

    #[test]
    fn atomic_snapshot_preserves_previous_value_before_rename() {
        let directory = TempDir::new();
        let path = directory.path().join("snapshot.json");
        let persistence = FilesystemPersistence::default();
        persistence
            .atomic_write_snapshot(&path, 1, &State { values: vec![1] })
            .unwrap();
        persistence.fail_once(FaultPoint::Rename);

        let error = persistence
            .atomic_write_snapshot(&path, 2, &State { values: vec![1, 2] })
            .unwrap_err();

        assert!(!error.mutation_unknown());
        let snapshot = persistence.load_snapshot::<State>(&path).unwrap().unwrap();
        assert_eq!(snapshot.final_sequence, 1);
        assert_eq!(snapshot.payload.values, vec![1]);
    }

    #[test]
    fn post_rename_sync_failure_is_mutation_unknown() {
        let directory = TempDir::new();
        let path = directory.path().join("snapshot.json");
        let persistence = FilesystemPersistence::default();
        persistence
            .atomic_write_snapshot(&path, 1, &State { values: vec![1] })
            .unwrap();
        persistence.fail_once(FaultPoint::ParentSync);

        let error = persistence
            .atomic_write_snapshot(&path, 2, &State { values: vec![1, 2] })
            .unwrap_err();

        assert!(error.mutation_unknown());
        let snapshot = persistence.load_snapshot::<State>(&path).unwrap().unwrap();
        assert_eq!(snapshot.final_sequence, 2);
        assert_eq!(snapshot.payload.values, vec![1, 2]);
    }

    #[test]
    fn event_log_replays_synced_frames_in_sequence() {
        let directory = TempDir::new();
        let path = directory.path().join("events.log");
        let persistence = FilesystemPersistence::default();
        let (mut log, events) = persistence.open_event_log::<u64>(&path, 0).unwrap();
        assert!(events.is_empty());
        assert_eq!(log.append(&10).unwrap(), 1);
        assert_eq!(log.append(&20).unwrap(), 2);

        let (_, events) = persistence.open_event_log::<u64>(&path, 0).unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            events.iter().map(|event| event.payload).collect::<Vec<_>>(),
            vec![10, 20]
        );
    }

    #[test]
    fn event_log_repairs_only_a_torn_tail() {
        let directory = TempDir::new();
        let path = directory.path().join("events.log");
        let persistence = FilesystemPersistence::default();
        let (mut log, _) = persistence.open_event_log::<u64>(&path, 0).unwrap();
        log.append(&10).unwrap();
        let valid_len = std::fs::metadata(&path).unwrap().len();
        let torn = encode_frame(2, b"20");
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&torn[..torn.len() - 7])
            .unwrap();

        let (mut repaired, events) = persistence.open_event_log::<u64>(&path, 0).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), valid_len);
        assert_eq!(repaired.append(&20).unwrap(), 2);
    }

    #[test]
    fn event_log_rejects_checksum_or_sequence_corruption() {
        let directory = TempDir::new();
        let checksum_path = directory.path().join("checksum.log");
        let persistence = FilesystemPersistence::default();
        let (mut log, _) = persistence
            .open_event_log::<u64>(&checksum_path, 0)
            .unwrap();
        log.append(&10).unwrap();
        let mut bytes = std::fs::read(&checksum_path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&checksum_path, bytes).unwrap();
        assert!(matches!(
            persistence.open_event_log::<u64>(&checksum_path, 0),
            Err(PersistenceError::Corrupt(_))
        ));

        let sequence_path = directory.path().join("sequence.log");
        let mut bytes = encode_frame(1, b"10");
        bytes.extend_from_slice(&encode_frame(3, b"30"));
        std::fs::write(&sequence_path, bytes).unwrap();
        assert!(matches!(
            persistence.open_event_log::<u64>(&sequence_path, 0),
            Err(PersistenceError::Corrupt(_))
        ));
    }

    #[test]
    fn compaction_crashes_replay_exactly_once() {
        let directory = TempDir::new();
        let snapshot_path = directory.path().join("snapshot.json");
        let log_path = directory.path().join("events.log");
        let persistence = FilesystemPersistence::default();
        let (mut log, _) = persistence.open_event_log::<u64>(&log_path, 0).unwrap();
        log.append(&1).unwrap();
        log.append(&2).unwrap();
        persistence.fail_once(FaultPoint::CompactionAfterSnapshot);

        let error = log
            .compact(&snapshot_path, &State { values: vec![1, 2] })
            .unwrap_err();

        assert!(error.mutation_unknown());
        assert!(matches!(
            log.append(&3),
            Err(PersistenceError::ReloadRequired)
        ));
        let snapshot = persistence
            .load_snapshot::<State>(&snapshot_path)
            .unwrap()
            .unwrap();
        let (mut recovered, events) = persistence
            .open_event_log::<u64>(&log_path, snapshot.final_sequence)
            .unwrap();
        assert!(events.is_empty());
        assert_eq!(recovered.append(&3).unwrap(), 3);
        recovered
            .compact(
                &snapshot_path,
                &State {
                    values: vec![1, 2, 3],
                },
            )
            .unwrap();
        let snapshot = persistence
            .load_snapshot::<State>(&snapshot_path)
            .unwrap()
            .unwrap();
        let (_, events) = persistence
            .open_event_log::<u64>(&log_path, snapshot.final_sequence)
            .unwrap();
        assert!(events.is_empty());
        assert_eq!(snapshot.payload.values, vec![1, 2, 3]);
    }

    #[test]
    fn root_lock_rejects_a_second_owner_and_releases_on_drop() {
        let directory = TempDir::new();
        let persistence = FilesystemPersistence::default();
        let first = persistence.acquire_root_lock(directory.path()).unwrap();
        assert!(first.path().ends_with(".maskura/root.lock"));
        assert!(matches!(
            persistence.acquire_root_lock(directory.path()),
            Err(PersistenceError::RootAlreadyLocked)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(first.path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(first);
        persistence.acquire_root_lock(directory.path()).unwrap();
    }

    #[test]
    fn append_sync_failure_requires_reload_and_recovers_written_frame() {
        let directory = TempDir::new();
        let path = directory.path().join("events.log");
        let persistence = FilesystemPersistence::default();
        let (mut log, _) = persistence.open_event_log::<u64>(&path, 0).unwrap();
        persistence.fail_once(FaultPoint::AppendSync);

        let error = log.append(&10).unwrap_err();

        assert!(error.mutation_unknown());
        assert!(matches!(
            log.append(&20),
            Err(PersistenceError::ReloadRequired)
        ));
        let (mut recovered, events) = persistence.open_event_log::<u64>(&path, 0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(recovered.append(&20).unwrap(), 2);
    }

    #[test]
    fn compaction_thresholds_are_exposed_without_automatic_mutation() {
        let directory = TempDir::new();
        let path = directory.path().join("events.log");
        let persistence = FilesystemPersistence::default();
        let (mut log, _) = persistence.open_event_log::<u64>(&path, 0).unwrap();
        for value in 0..COMPACT_AFTER_EVENTS {
            log.append(&value).unwrap();
        }
        assert!(log.should_compact());
    }
}
