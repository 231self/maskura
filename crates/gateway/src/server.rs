//! Composable engine server: axum handlers + router + state construction.
//!
//! The engine is policy-free. Authorization (rate limits, quotas, billing)
//! and metering are injected through [`crate::control::ControlPlane`], held
//! in [`AppState`]. The OSS self-host binary builds this with
//! [`crate::control::NoopControlPlane`]; the private SaaS crate builds it with
//! its own control-plane implementation.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::types::ChecksumMode;
use aws_smithy_types::date_time::Format as DateTimeFormat;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, Method, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{Html, IntoResponse},
    routing::{any, delete, get, head, post, put},
};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use maskura_customer_config::config::{
    ManagedStreamingMode as ConfigManagedStreamingMode, MultipartMode as ConfigMultipartMode,
    StreamingReadMode as ConfigStreamingReadMode,
};
use maskura_customer_config::{Config, aliases as customer_env, resolve as resolve_customer_env};
use md5::Md5;
use rand::{RngCore, rngs::OsRng};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio_util::io::ReaderStream;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::backend::{
    BackendKind, BackendResolver, PresignedHttpPolicy, ResolvedBackend, StorageOperation,
    WorkspaceEndpointPolicy,
};
use crate::control::{
    AuthenticatedRequestContext, AuthorizationDecision, AuthorizationError, AuthorizationGrant,
    ControlPlane, MeteringError, PipelineAttempt, RequestKind, UsageAuthorization, UsageEvent,
    UsageRoute,
};
use crate::customer_headers;
use crate::file_store::{FileStore, LocalChecksumState};
use crate::integrity::{BodyVerifier, ContentMd5Verifier, IntegrityError};
use crate::key_cipher::{KeyWrapping, SecretCipher};
use crate::local_storage::LocalStorageRuntime;
use crate::managed::{
    AuthorityListQuery, InMemoryManagedRepository, LogicalObjectKey, ManagedPlacementBackendFact,
    ManagedPlacementPolicy, ManagedRepository, ManagedStreamingMode, PLACEMENT_VERSION_V1,
    PostgresManagedRepository, placement_policy_fingerprint, validate_mode,
};
use crate::multipart_completion::{
    MultipartCompletionCoordinator, MultipartCoordinatorError, append_usage_evidence,
    load_usage_evidence,
};
use crate::multipart_staging::{
    ARTIFACT_PREFIX, AbortMutationError, COMPLETION_LEASE, CleanupAudit, CompletePart,
    CompletionAcquire, CompletionLease, EncryptedPartReader, EncryptedPartWriter,
    ListMultipartUploadsPage, ListMultipartUploadsRequest, MAX_ACTIVE_UPLOADS,
    MultipartCompletionResult, MultipartIdentity, MultipartLifecycle, MultipartPart,
    MultipartRepository, MultipartSnapshot, MultipartUpload, PostgresMultipartRepository,
    S3StagingArtifactStore, StagedArtifact, StagingArtifactStore, StagingError, StagingQuotaLimits,
    completion_fingerprint, now_ms,
};
use crate::object::{
    BodyLimits, ChunkedBytesBody, ObjectMetadata, OpenedObject, filter_presigned_response_headers,
    harden_object_response_headers,
};
use crate::plugin_registry::{
    PipelineLimits, PipelineSnapshot, PluginCapabilities, PluginRegistry, StreamingPipelineSession,
};
use crate::read_spool::EncryptedReadSpool;
use crate::s3_error;
use crate::s3_safety::{S3Failure, record_s3_failure, s3_retry_config, s3_timeout_config};
use crate::service_storage::{ServiceStorage, parse_service_backends};
use crate::sigv4::{RequestAuthorization, SigV4Error, SigV4Policy, SigningKeyCache};
use crate::store::{
    FileKeyStore, KeyRepository, KeyStore, MAX_PUBLIC_KEY_PEM_BYTES, McpToken, MemoryStore,
    PostgresKeyStore, canonicalize_credential_label, canonicalize_public_key_pem,
    validate_credential_ttl,
};
use crate::transaction::{
    AbortSignal, AwsS3TransactionBackend, BackendCapabilities, BackendError, BackendErrorKind,
    CompatibilitySpoolConfig, CompatibilitySpoolTransaction, CompletionReconciliation,
    ConditionalReadCapability, DestinationCommitAuthority, DirectOperationScope, DirectS3Sink,
    ExpectedObject, FileSinkTransaction, IncompleteUploadDiscovery, JournalError, ListCapability,
    MemorySinkTransaction, MultipartResponseCapability, MultipartStoredMetadata, ObjectDestination,
    ObjectSinkTransaction, OperationJournal, OperationReconciler, OperationRecord, OperationState,
    ProviderMutationFence, ResponseChecksumCapability, SpoolQuota, StoredObjectMeta,
    TransactionError, VersioningCapability, WorkspaceDestinationBinding,
};
use crate::workspace_storage::{
    BackendConfigRequest, BackendConfigResponse, BackendType, WorkspaceId, WorkspaceOperationLease,
    WorkspaceOperationOutcome, WorkspaceStorageError, WorkspaceStorageRepository,
};
use crate::{Format, Gateway};

mod admin;
mod auth;
mod demo;
mod lifecycle;
mod multipart;
mod openapi;
mod routing;
mod s3_objects;
mod s3_upload;
mod state;
mod workspace_lease;

pub(crate) use admin::*;
pub(crate) use auth::*;
pub use auth::{Auth, TrustedInvocationContext, require_user_claims, require_user_id};
pub(crate) use demo::*;
pub(crate) use lifecycle::*;
pub use lifecycle::{
    InvocationError, InvocationLimits, MAX_INVOCATION_RESPONSE_BYTES, MAX_INVOCATION_TIMEOUT,
    auto_local_appliance, build_state, build_state_with_pipeline_template, default_listen_addr,
    invoke_mcp,
};
pub use multipart::reconcile_workspace_streaming_operation;
pub(crate) use multipart::*;
pub(crate) use openapi::*;
pub use routing::build_router;
pub(crate) use s3_objects::*;
pub(crate) use s3_upload::*;
pub(crate) use state::*;
pub use state::{AppState, StatePipelineTemplate, StreamingReadMode};
pub(crate) use workspace_lease::*;

#[cfg(test)]
mod tests;
