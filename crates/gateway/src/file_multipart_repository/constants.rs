//! Extracted from `file_multipart_repository.rs`; re-exported from `crate::file_multipart_repository`.

pub(crate) const FILE_MULTIPART_SCHEMA_VERSION: u32 = 1;

pub(crate) const MAX_FILE_MULTIPART_AUDITS: usize = 256;

pub(crate) const MAX_FILE_MULTIPART_EVIDENCE_RECORDS: usize = 4_096;

pub(crate) const MAX_REPLAY_EVENTS: usize = 256;

pub(crate) const SNAPSHOT_FILE: &str = "snapshot.json";

pub(crate) const EVENT_LOG_FILE: &str = "events.log";
