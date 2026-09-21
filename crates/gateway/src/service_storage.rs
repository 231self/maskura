use crate::control::{ControlPlane, RequestKind, UsageEvent, UsageRoute};
use crate::managed::{
    AuthorityListPage, AuthorityListQuery, AuthorityPlacementCursor, AuthorityPlacementPage,
    AuthorityPlacementPageQuery, AuthorityPlacementStats, BackendVersioningCapability,
    BackendVersioningMode, CopyStatus, DurablePhysicalWriteIntent, ExactPhysicalCommit,
    LogicalObjectKey, MANAGED_PUBLICATION_RECIPE_VERSION, ManagedDeleteError, ManagedDeleteRequest,
    ManagedError, ManagedLogicalOperationIntent, ManagedLogicalOperationState, ManagedMutationKind,
    ManagedPublicationRecipe, ManagedRepository, ManagedStreamingMode, ManagedUsageEvidence,
    NamespacePurgeRequest, NamespacePurgeStatus, ObjectAuthority, PLACEMENT_VERSION_V1,
    PhysicalVersionTarget, PhysicalWriteIntent, Placement, ProviderStorageIdentity, RepairKind,
    RepairRecord, RepairStateCounts, RepairTargetRole, generation_physical_key,
    weighted_rendezvous_placement,
};
use crate::s3_safety::{
    record_s3_body_failure, record_s3_failure, s3_retry_config, s3_timeout_config,
};
use crate::transaction::{
    AbortSignal, AwsS3TransactionBackend, BackendCapabilities, DestinationCommitAuthority,
    DirectS3Sink, ExpectedObject, ManagedChildRole, ManagedOperationScope, ObjectDestination,
    ObjectSinkTransaction, OperationJournal, OperationReconciler, OperationState, SinkCommitState,
    StoredObjectMeta, TransactionBackend, TransactionError, VersioningCapability,
};
use crate::workspace_storage::WorkspaceId;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Credentials, Region};
use bytes::Bytes;
use std::collections::{BTreeMap, HashSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, watch};
use tracing::{info, warn};

mod backend;
mod common;
mod core;
mod sinks;

pub(crate) use common::*;
pub(crate) use sinks::*;

pub use backend::{ServiceBackend, parse_service_backends};
pub use core::ServiceStorage;

#[cfg(test)]
mod tests;
