use crate::control::{RequestKind, UsageRoute};
use crate::entity::{
    managed_list_cursor, managed_logical_operation, managed_multipart_activity, managed_namespace,
    managed_namespace_purge, managed_object_authority, managed_object_repair,
    managed_physical_object_version, managed_physical_write_intent,
    managed_placement_policy_version, managed_workspace_usage, object_operation,
};
use async_trait::async_trait;
use sea_orm::sea_query::extension::postgres::PgFunc;
use sea_orm::sea_query::{Expr, LockType, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, EntityTrait,
    IsolationLevel, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, QueryTrait, Set,
    SqlxPostgresConnector, TransactionTrait,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

mod constants;
mod listing;
mod memory;
mod model;
mod operations;
mod physical;
mod placement;
mod postgres;
mod repair;
mod repository;
mod types;

pub(crate) use constants::*;
pub(crate) use listing::*;
pub(crate) use model::*;
pub(crate) use operations::*;
pub(crate) use physical::*;
pub(crate) use repair::*;
pub(crate) use types::*;

pub use constants::{
    MANAGED_AUTHORITY_LIST_MAX_KEYS, MANAGED_LIST_CURSOR_GLOBAL_LIMIT,
    MANAGED_LIST_CURSOR_GLOBAL_MAX_BYTES, MANAGED_LIST_CURSOR_RESPONSE_MAX_BYTES,
    MANAGED_LIST_CURSOR_TTL_MS, MANAGED_LIST_CURSOR_WORKSPACE_LIMIT,
    MANAGED_LIST_CURSOR_WORKSPACE_MAX_BYTES, MANAGED_PUBLICATION_RECIPE_VERSION,
    MANAGED_REPLACEMENT_HEADROOM_BYTES, MANAGED_VISIBLE_LIMIT_BYTES, MAX_REPAIR_ATTEMPTS,
    PHYSICAL_WRITE_LEASE_MS, PLACEMENT_VERSION_V1, REPAIR_BACKOFF_BASE_MS, REPAIR_BACKOFF_MAX_MS,
};
pub use listing::{
    AuthorityListPage, AuthorityListQuery, AuthorityPlacementCursor, AuthorityPlacementPage,
    AuthorityPlacementPageQuery, AuthorityPlacementStats, ManagedListCursor,
    ManagedListCursorBinding, ManagedListCursorPosition, ManagedListCursorRequest,
    ManagedListCursorState, ManagedListVersion, NamespacePurgeRequest, NamespacePurgeStatus,
};
pub use memory::InMemoryManagedRepository;
pub use operations::{
    ManagedDeleteRequest, ManagedLogicalOperation, ManagedLogicalOperationIntent,
    ManagedOperationCommit, ManagedProvenPhysicalAllocation, ManagedUsageEvidence,
    ManagedWorkspaceUsage,
};
pub use physical::{
    BackendVersioningCapability, BackendVersioningMode, DurablePhysicalWriteIntent,
    ExactPhysicalCommit, LogicalAbortProof, ManagedPublicationRecipe, ManagedRecoveryClaim,
    PhysicalVersionTarget, PhysicalWriteIntent, PhysicalWriteLease, ProviderStorageIdentity,
};
pub use placement::{
    ManagedPlacementBackendFact, ManagedPlacementPolicy, Placement, generation_physical_key,
    placement_policy_fingerprint, rendezvous_placement, rendezvous_score,
    weighted_rendezvous_placement,
};
pub use postgres::PostgresManagedRepository;
pub use repair::{RepairKind, RepairRecord, RepairStateCounts, RepairTargetRole};
pub use repository::ManagedRepository;
pub use types::{
    CopyStatus, LogicalObjectKey, ManagedDeleteError, ManagedError, ManagedLogicalOperationState,
    ManagedMutationKind, ManagedRouteFence, ManagedSettlementState, ManagedStreamingMode,
    ObjectAuthority,
};

/// Validate that the resolved streaming mode is supported by managed storage.
pub async fn validate_mode(
    mode: ManagedStreamingMode,
    repository: &dyn ManagedRepository,
    development: bool,
) -> Result<(), ManagedError> {
    if mode == ManagedStreamingMode::Off && repository.any_authority().await? {
        return Err(ManagedError::OffAfterAuthority);
    }
    if mode != ManagedStreamingMode::Off && !repository.is_durable() && !development {
        return Err(ManagedError::Persistence(
            "managed observe/enforce mode requires DATABASE_URL".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
