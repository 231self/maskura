//! Pure state reduction for the durable local multipart repository.
//!
//! File framing, checksums, locking, and durable append are intentionally left
//! to the Task 8 adapter. This module owns the versioned persistence vocabulary
//! and rejects state that the adapter must never publish.

use crate::filesystem_persistence::{
    EventLog, FilesystemPersistence, PersistenceError, create_private_dir_all, sync_parent,
};
use crate::multipart_staging::{
    AbortMutationError, CleanupAudit, CleanupCandidate, CompletePart, CompletionAcquire,
    CompletionLease, DEFAULT_EXPIRY, DestinationCommitPermit, DestinationCommitRecord,
    ListMultipartUploadsPage, ListMultipartUploadsRequest, MAX_ACTIVE_UPLOADS, MAX_PARTS,
    MultipartCompletionResult, MultipartIdentity, MultipartLifecycle, MultipartPart,
    MultipartRepository, MultipartUpload, PendingPart, PublishingMultipartUpload,
    RECONCILIATION_GRACE, RetiredMultipartUpload, StagingError, StagingQuotaLimits, now_ms,
    paginate_multipart_uploads, permit_matches, publishing_upload, same_identity,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use tokio::sync::Mutex;
use uuid::Uuid;

mod constants;
mod file;
mod reducer;
mod types;

pub(crate) use constants::*;
pub(crate) use file::*;
pub(crate) use reducer::*;
pub(crate) use types::*;

#[cfg(test)]
mod tests;
