//! Phase 10 durable, encrypted staging for client multipart uploads.
//!
//! This module deliberately stops before completion.  It provides the durable
//! upload/part state machine and opaque encrypted artifacts that Phase 11 will
//! consume in part-number order.

use crate::entity::{
    multipart_cleanup_audit, multipart_part_attempt, multipart_staging_quota, multipart_upload,
};
use crate::key_cipher::KeyWrapping;
use crate::s3_safety::{record_s3_body_failure, record_s3_failure};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use md5::{Digest as _, Md5};
use rand::{RngCore, rngs::OsRng};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set, SqlxPostgresConnector,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
#[cfg(any(test, debug_assertions))]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use uuid::Uuid;

mod artifact;
mod constants;
mod listing;
mod memory;
mod postgres;
mod repository;
mod types;

pub(crate) use constants::*;
pub(crate) use listing::*;
pub(crate) use postgres::*;
pub(crate) use types::*;

pub use artifact::{
    EncryptedPartReader, EncryptedPartWriter, FinishedPart, MemoryStagingArtifactStore,
    S3StagingArtifactStore, now_ms,
};
pub use constants::{
    ARTIFACT_PREFIX, COMPLETION_LEASE, DEFAULT_EXPIRY, MAX_ACTIVE_UPLOADS,
    MAX_MULTIPART_UPLOADS_PAGE, MAX_PARTS, RECONCILIATION_GRACE,
};
pub use memory::InMemoryMultipartRepository;
pub use postgres::PostgresMultipartRepository;
pub use repository::{MultipartRepository, StagingArtifactStore};
pub use types::{
    AbortMutationError, CleanupAudit, CleanupCandidate, CompletePart, CompletionAcquire,
    CompletionLease, DestinationCommitPermit, DestinationCommitRecord, ListMultipartUploadsPage,
    ListMultipartUploadsRequest, MultipartCompletionResult, MultipartIdentity, MultipartLifecycle,
    MultipartPart, MultipartSnapshot, MultipartUpload, PendingPart, PublishingMultipartUpload,
    RetiredMultipartUpload, StagedArtifact, StagingArtifactReader, StagingError,
    StagingQuotaLimits, completion_fingerprint,
};

#[cfg(test)]
pub(crate) use artifact::{ArtifactHeader, artifact_aad, assert_artifact_store_contract};

#[cfg(test)]
mod tests;
