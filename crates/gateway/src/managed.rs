use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::sea_query::extension::postgres::PgFunc;
use sea_orm::sea_query::{Expr, LockType, OnConflict};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, EntityTrait,
    IsolationLevel, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, QueryTrait, Set,
    SqlxPostgresConnector, TransactionTrait,
};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::control::{RequestKind, UsageRoute};
use crate::entity::{
    managed_list_cursor, managed_logical_operation, managed_multipart_activity, managed_namespace,
    managed_namespace_purge, managed_object_authority, managed_object_repair,
    managed_physical_object_version, managed_physical_write_intent,
    managed_placement_policy_version, managed_workspace_usage, object_operation,
};

pub const PLACEMENT_VERSION_V1: u32 = 1;
pub const PHYSICAL_WRITE_LEASE_MS: i64 = 2 * 60 * 60 * 1000;
/// A repair that fails this many times is dead-lettered and no longer retried.
pub const MAX_REPAIR_ATTEMPTS: u32 = 8;
pub const REPAIR_BACKOFF_BASE_MS: i64 = 30_000;
pub const REPAIR_BACKOFF_MAX_MS: i64 = 4 * 60 * 60 * 1000;

/// Exponential backoff before a failed repair is eligible for retry.
fn repair_backoff_ms(attempts: u32) -> i64 {
    REPAIR_BACKOFF_BASE_MS
        .saturating_mul(1i64 << attempts.min(10))
        .min(REPAIR_BACKOFF_MAX_MS)
}
pub const MANAGED_VISIBLE_LIMIT_BYTES: u64 = 1024 * 1024 * 1024;
pub const MANAGED_REPLACEMENT_HEADROOM_BYTES: u64 = 128 * 1024 * 1024;
pub const MANAGED_LIST_CURSOR_TTL_MS: i64 = 15 * 60 * 1000;
pub const MANAGED_LIST_CURSOR_WORKSPACE_LIMIT: u64 = 100;
pub const MANAGED_LIST_CURSOR_GLOBAL_LIMIT: u64 = 10_000;
pub const MANAGED_LIST_CURSOR_RESPONSE_MAX_BYTES: u64 = 64 * 1024;
pub const MANAGED_LIST_CURSOR_WORKSPACE_MAX_BYTES: u64 = 1024 * 1024;
pub const MANAGED_LIST_CURSOR_GLOBAL_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const MANAGED_AUTHORITY_LIST_MAX_KEYS: u64 = 1_000;

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum ManagedStreamingMode {
    #[default]
    Off,
    Observe,
    Enforce,
}

impl ManagedStreamingMode {
    pub fn from_value(value: Option<&str>) -> Result<Self, ManagedError> {
        match value {
            None | Some("off") => Ok(Self::Off),
            Some("observe") => Ok(Self::Observe),
            Some("enforce") => Ok(Self::Enforce),
            Some(value) => Err(ManagedError::InvalidMode(value.to_string())),
        }
    }

    pub fn allows_mutations(self) -> bool {
        self == Self::Enforce
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LogicalObjectKey {
    pub tenant_id: String,
    pub bucket: String,
    pub key: String,
}

impl LogicalObjectKey {
    pub fn new(tenant_id: &str, bucket: &str, key: &str) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            bucket: bucket.to_string(),
            key: key.to_string(),
        }
    }

    pub fn object_key(&self) -> String {
        format!("{}/{}", self.bucket, self.key)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Placement {
    pub version: u32,
    pub primary_backend_id: String,
    pub replica_backend_id: Option<String>,
}

/// Durable facts that define a placement policy version: the backends, their
/// weights, and their capacities, plus when the policy was activated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedPlacementPolicy {
    pub version: u32,
    pub fingerprint: String,
    pub backend_facts: Vec<ManagedPlacementBackendFact>,
    pub activated_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize)]
pub struct ManagedPlacementBackendFact {
    pub backend_id: String,
    pub placement_weight: u64,
    pub placement_capacity_units: u64,
}

/// Canonical fingerprint of a placement policy: the version plus every
/// backend's identity, weight, and capacity in a stable order. A policy edit
/// changes the fingerprint, so a version bump is required to admit it.
pub fn placement_policy_fingerprint(
    version: u32,
    backends: impl IntoIterator<Item = (String, u64, u64)>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"s4-placement-policy\0");
    hasher.update(version.to_be_bytes());
    let mut facts: Vec<_> = backends.into_iter().collect();
    facts.sort();
    for (backend_id, weight, capacity) in facts {
        hash_field(&mut hasher, backend_id.as_bytes());
        hash_field(&mut hasher, &weight.to_be_bytes());
        hash_field(&mut hasher, &capacity.to_be_bytes());
    }
    hex::encode(hasher.finalize())
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

pub fn rendezvous_score(
    placement_version: u32,
    tenant_id: &str,
    object_key: &str,
    backend_id: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"s4-rendezvous\0");
    hasher.update(placement_version.to_be_bytes());
    hash_field(&mut hasher, tenant_id.as_bytes());
    hash_field(&mut hasher, object_key.as_bytes());
    hash_field(&mut hasher, backend_id.as_bytes());
    hasher.finalize().into()
}

pub fn rendezvous_placement(
    placement_version: u32,
    tenant_id: &str,
    object_key: &str,
    backend_ids: impl IntoIterator<Item = String>,
) -> Option<Placement> {
    let mut scored: Vec<_> = backend_ids
        .into_iter()
        .map(|backend_id| {
            (
                rendezvous_score(placement_version, tenant_id, object_key, &backend_id),
                backend_id,
            )
        })
        .collect();
    scored.sort_by(|(left_score, left_id), (right_score, right_id)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_id.cmp(right_id))
    });
    scored.dedup_by(|(_, left), (_, right)| left == right);
    let primary_backend_id = scored.first()?.1.clone();
    let replica_backend_id = scored.get(1).map(|(_, id)| id.clone());
    Some(Placement {
        version: placement_version,
        primary_backend_id,
        replica_backend_id,
    })
}

/// Select a primary and distinct replica using weighted rendezvous hashing.
/// The placement version is part of the SHA-256 domain, so policy changes must
/// be accompanied by a version bump before they affect durable placement.
pub fn weighted_rendezvous_placement(
    placement_version: u32,
    tenant_id: &str,
    object_key: &str,
    backend_weights: impl IntoIterator<Item = (String, u64)>,
) -> Option<Placement> {
    let mut scored: Vec<_> = backend_weights
        .into_iter()
        .filter(|(_, weight)| *weight > 0)
        .map(|(backend_id, weight)| {
            let score = rendezvous_score(placement_version, tenant_id, object_key, &backend_id);
            let random = u64::from_be_bytes(score[..8].try_into().expect("SHA-256 prefix"));
            // Map the hash to (0, 1]; zero must remain selectable rather than
            // producing an infinite penalty.
            let uniform = (random as f64 + 1.0) / (u64::MAX as f64 + 1.0);
            (-uniform.ln() / weight as f64, backend_id)
        })
        .collect();
    scored.sort_by(|(left_score, left_id), (right_score, right_id)| {
        left_score
            .total_cmp(right_score)
            .then_with(|| left_id.cmp(right_id))
    });
    scored.dedup_by(|(_, left), (_, right)| left == right);
    let primary_backend_id = scored.first()?.1.clone();
    let replica_backend_id = scored.get(1).map(|(_, id)| id.clone());
    Some(Placement {
        version: placement_version,
        primary_backend_id,
        replica_backend_id,
    })
}

pub fn generation_physical_key(logical: &LogicalObjectKey, generation: Uuid) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, logical.tenant_id.as_bytes());
    hash_field(&mut hasher, logical.bucket.as_bytes());
    hash_field(&mut hasher, logical.key.as_bytes());
    format!(
        "__maskura/generations/{}/{}",
        hex::encode(hasher.finalize()),
        generation
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyStatus {
    Ready,
    RepairPending,
    Absent,
}

impl CopyStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::RepairPending => "REPAIR_PENDING",
            Self::Absent => "ABSENT",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "READY" => Ok(Self::Ready),
            "REPAIR_PENDING" => Ok(Self::RepairPending),
            "ABSENT" => Ok(Self::Absent),
            _ => Err(ManagedError::Corrupt(format!(
                "unknown managed copy status {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectAuthority {
    pub logical: LogicalObjectKey,
    pub generation: Uuid,
    pub digest: String,
    pub size: u64,
    pub metadata: BTreeMap<String, String>,
    pub placement_version: u32,
    pub primary_backend_id: String,
    /// Exact provider version selected by this authority generation. `None`
    /// denotes a provider whose object is provably unversioned.
    pub primary_version_id: Option<String>,
    pub replica_backend_id: Option<String>,
    pub primary_status: CopyStatus,
    pub replica_status: CopyStatus,
    pub tombstone: bool,
    pub cas_version: u64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairKind {
    Replica,
    Placement,
    DeleteGeneration,
}

impl RepairKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Replica => "REPLICA",
            Self::Placement => "PLACEMENT",
            Self::DeleteGeneration => "DELETE_GENERATION",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "REPLICA" => Ok(Self::Replica),
            "PLACEMENT" => Ok(Self::Placement),
            "DELETE_GENERATION" => Ok(Self::DeleteGeneration),
            _ => Err(ManagedError::Corrupt(format!(
                "unknown managed repair kind {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairTargetRole {
    Primary,
    Replica,
    Cleanup,
}

impl RepairTargetRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "PRIMARY",
            Self::Replica => "REPLICA",
            Self::Cleanup => "CLEANUP",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "PRIMARY" => Ok(Self::Primary),
            "REPLICA" => Ok(Self::Replica),
            "CLEANUP" => Ok(Self::Cleanup),
            _ => Err(ManagedError::Corrupt(format!(
                "unknown managed repair target role {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairRecord {
    /// An opaque claim capability while leased; otherwise equal to `repair_id`.
    pub id: Uuid,
    pub repair_id: Uuid,
    pub kind: RepairKind,
    pub logical: LogicalObjectKey,
    pub namespace_epoch: u64,
    pub authority_cas_version: u64,
    pub generation: Uuid,
    pub digest: String,
    pub size: u64,
    pub metadata: BTreeMap<String, String>,
    pub physical_key: String,
    pub source_backend_id: Option<String>,
    pub target_backend_id: String,
    pub target_role: RepairTargetRole,
    pub placement_version: u32,
    pub placement_primary_backend_id: Option<String>,
    pub placement_replica_backend_id: Option<String>,
    pub attempts: u32,
    pub lease_owner: Option<String>,
    pub lease_token: Option<Uuid>,
    pub lease_expires_at_ms: Option<i64>,
    pub not_before_ms: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl RepairRecord {
    pub fn copy(
        kind: RepairKind,
        authority: &ObjectAuthority,
        source_backend_id: Option<String>,
        target_backend_id: String,
        target_role: RepairTargetRole,
        placement_version: u32,
    ) -> Self {
        let now = crate::transaction::unix_time_ms();
        let repair_id = Uuid::now_v7();
        Self {
            id: repair_id,
            repair_id,
            kind,
            logical: authority.logical.clone(),
            namespace_epoch: 0,
            authority_cas_version: authority.cas_version,
            generation: authority.generation,
            digest: authority.digest.clone(),
            size: authority.size,
            metadata: authority.metadata.clone(),
            physical_key: generation_physical_key(&authority.logical, authority.generation),
            source_backend_id,
            target_backend_id,
            target_role,
            placement_version,
            placement_primary_backend_id: None,
            placement_replica_backend_id: None,
            attempts: 0,
            lease_owner: None,
            lease_token: None,
            lease_expires_at_ms: None,
            not_before_ms: 0,
            created_at_ms: now,
            updated_at_ms: now,
        }
    }

    pub fn placement(
        authority: &ObjectAuthority,
        source_backend_id: Option<String>,
        target_backend_id: String,
        target_role: RepairTargetRole,
        placement: &Placement,
    ) -> Self {
        let mut repair = Self::copy(
            RepairKind::Placement,
            authority,
            source_backend_id,
            target_backend_id,
            target_role,
            placement.version,
        );
        repair.placement_primary_backend_id = Some(placement.primary_backend_id.clone());
        repair.placement_replica_backend_id = placement.replica_backend_id.clone();
        repair
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManagedError {
    #[error("invalid managed streaming mode {0:?}")]
    InvalidMode(String),
    #[error("managed mutations are disabled in {0:?} mode")]
    MutationDisabled(ManagedStreamingMode),
    #[error("managed mode off is invalid after authority exists")]
    OffAfterAuthority,
    #[error("managed authority compare-and-swap conflict")]
    Conflict,
    #[error("managed authority data is corrupt: {0}")]
    Corrupt(String),
    #[error("managed authority persistence failed: {0}")]
    Persistence(String),
    #[error("managed namespace is fenced for purge")]
    NamespaceFenced,
    #[error("managed operation transition from {from:?} to {to:?} is invalid")]
    InvalidTransition {
        from: ManagedLogicalOperationState,
        to: ManagedLogicalOperationState,
    },
    #[error("managed workspace already has an active mutation")]
    MutationInProgress,
    #[error("managed workspace capacity is exhausted")]
    QuotaExceeded,
    #[error("managed recovery evidence is deterministically blocked: {0}")]
    RecoveryBlocked(&'static str),
    #[error("managed list cursor is expired")]
    CursorExpired,
    #[error("managed list cursor does not match this query")]
    CursorQueryMismatch,
    #[error("managed list cursor capacity is exhausted")]
    CursorLimitExceeded,
}

#[derive(Debug, thiserror::Error)]
pub enum ManagedDeleteError {
    #[error(transparent)]
    PreCommit(#[from] ManagedError),
    #[error("managed delete commit outcome is unknown: {0}")]
    CommitUnknown(ManagedError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedMutationKind {
    Put,
    Delete,
}

impl ManagedMutationKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "PUT" => Ok(Self::Put),
            "DELETE" => Ok(Self::Delete),
            _ => Err(ManagedError::Corrupt(format!(
                "unknown managed mutation kind {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedLogicalOperationState {
    Intent,
    Open,
    Completing,
    CommitUnknown,
    RecoveryBlocked,
    Committed,
    ProvenAborted,
}

impl ManagedLogicalOperationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "INTENT",
            Self::Open => "OPEN",
            Self::Completing => "COMPLETING",
            Self::CommitUnknown => "COMMIT_UNKNOWN",
            Self::RecoveryBlocked => "RECOVERY_BLOCKED",
            Self::Committed => "COMMITTED",
            Self::ProvenAborted => "PROVEN_ABORTED",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "INTENT" => Ok(Self::Intent),
            "OPEN" => Ok(Self::Open),
            "COMPLETING" => Ok(Self::Completing),
            "COMMIT_UNKNOWN" => Ok(Self::CommitUnknown),
            "RECOVERY_BLOCKED" => Ok(Self::RecoveryBlocked),
            "COMMITTED" => Ok(Self::Committed),
            "PROVEN_ABORTED" => Ok(Self::ProvenAborted),
            _ => Err(ManagedError::Corrupt(format!(
                "unknown managed logical operation state {value:?}"
            ))),
        }
    }

    fn terminal(self) -> bool {
        matches!(self, Self::Committed | Self::ProvenAborted)
    }
}

fn valid_logical_transition(
    from: ManagedLogicalOperationState,
    to: ManagedLogicalOperationState,
) -> bool {
    matches!(
        (from, to),
        (
            ManagedLogicalOperationState::Open,
            ManagedLogicalOperationState::Completing
        ) | (
            ManagedLogicalOperationState::Open,
            ManagedLogicalOperationState::CommitUnknown
        ) | (
            ManagedLogicalOperationState::Completing,
            ManagedLogicalOperationState::CommitUnknown
        ) | (
            ManagedLogicalOperationState::CommitUnknown,
            ManagedLogicalOperationState::Completing
        )
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedSettlementState {
    Pending,
    Settled,
    Released,
}

impl ManagedSettlementState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Settled => "SETTLED",
            Self::Released => "RELEASED",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "PENDING" => Ok(Self::Pending),
            "SETTLED" => Ok(Self::Settled),
            "RELEASED" => Ok(Self::Released),
            _ => Err(ManagedError::Corrupt(format!(
                "unknown managed settlement state {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedRouteFence {
    pub namespace_epoch: u64,
    pub routing_epoch: u64,
}

pub const MANAGED_PUBLICATION_RECIPE_VERSION: i32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedPublicationRecipe {
    pub version: i32,
    pub placement_version: u32,
    pub primary_backend_id: String,
    pub replica_backend_id: Option<String>,
    pub metadata: BTreeMap<String, String>,
    pub primary_status: CopyStatus,
    pub replica_status: CopyStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactPhysicalCommit {
    pub selected_version_id: Option<String>,
    pub superseded_version_ids: Vec<String>,
    pub version_history_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedRecoveryClaim {
    pub operation: ManagedLogicalOperation,
    pub owner: String,
    pub token: Uuid,
    pub expires_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalAbortProof {
    /// No physical child was admitted and no provider mutation could start.
    NoChildStarted,
    /// The durable child journal reached `PROVEN_ABORTED` after exact absence.
    ChildProvenAborted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedLogicalOperationIntent {
    pub operation_id: Uuid,
    pub receipt_id: Uuid,
    pub logical: LogicalObjectKey,
    pub kind: ManagedMutationKind,
    pub generation: Uuid,
    pub fence: ManagedRouteFence,
    pub expected_authority_cas: Option<u64>,
    pub prior_logical_size: u64,
    pub primary_child_operation_id: Uuid,
    pub backend_id: String,
    pub provider_bucket: String,
    pub physical_key: String,
    pub occurred_at_ms: i64,
    pub rate_version: i32,
    pub route: UsageRoute,
    pub request_kind: RequestKind,
    pub max_processed_bytes: u64,
    pub publication_recipe: Option<ManagedPublicationRecipe>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedDeleteRequest {
    pub operation_id: Uuid,
    pub receipt_id: Uuid,
    pub logical: LogicalObjectKey,
    pub placement: Placement,
    pub provider_bucket: String,
    pub occurred_at_micros: i64,
    pub rate_version: i32,
    pub max_processed_bytes: u64,
}

fn delete_request_matches_operation(
    request: &ManagedDeleteRequest,
    operation: &ManagedLogicalOperation,
) -> bool {
    let intent = &operation.intent;
    intent.operation_id == request.operation_id
        && intent.receipt_id == request.receipt_id
        && intent.logical == request.logical
        && intent.kind == ManagedMutationKind::Delete
        && intent.backend_id == request.placement.primary_backend_id
        && intent.provider_bucket == request.provider_bucket
        && intent.occurred_at_ms == request.occurred_at_micros.div_euclid(1_000)
        && intent.rate_version == request.rate_version
        && intent.route == UsageRoute::DeleteObject
        && intent.request_kind == RequestKind::Write
        && intent.max_processed_bytes == request.max_processed_bytes
        && operation.evidence.as_ref().is_some_and(|evidence| {
            evidence
                .payload
                .get("occurred_at_micros")
                .and_then(serde_json::Value::as_i64)
                == Some(request.occurred_at_micros)
        })
        && intent.publication_recipe.as_ref().is_some_and(|recipe| {
            recipe.version == MANAGED_PUBLICATION_RECIPE_VERSION
                && recipe.placement_version == request.placement.version
                && recipe.primary_backend_id == request.placement.primary_backend_id
                && recipe.replica_backend_id == request.placement.replica_backend_id
                && recipe.metadata.is_empty()
                && recipe.primary_status == CopyStatus::Absent
                && recipe.replica_status == CopyStatus::Absent
        })
}

fn committed_delete_replay_authority(
    operation: &ManagedLogicalOperation,
    authority: Option<ObjectAuthority>,
) -> Result<ObjectAuthority, ManagedError> {
    let authority = authority.ok_or(ManagedError::Conflict)?;
    let committed_authority_version = operation
        .committed_authority_version
        .ok_or(ManagedError::Conflict)?;
    let original_tombstone_matches = authority.tombstone
        && authority.generation == operation.intent.generation
        && authority.digest.is_empty()
        && authority.size == 0;
    if authority.logical != operation.intent.logical
        || authority.cas_version < committed_authority_version
        || (authority.cas_version == committed_authority_version && !original_tombstone_matches)
    {
        return Err(ManagedError::Conflict);
    }
    Ok(authority)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedUsageEvidence {
    pub expected_output_digest: Option<String>,
    pub expected_output_size: u64,
    pub source_bytes: u64,
    pub processed_bytes: u64,
    pub payload: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedLogicalOperation {
    pub intent: ManagedLogicalOperationIntent,
    pub evidence: Option<ManagedUsageEvidence>,
    pub reserved_physical_bytes: u64,
    pub committed_physical_bytes: u64,
    pub released_physical_bytes: u64,
    pub state: ManagedLogicalOperationState,
    pub committed_authority_version: Option<u64>,
    pub settlement_state: ManagedSettlementState,
    pub last_error_class: Option<String>,
    pub recovery_owner: Option<String>,
    pub recovery_token: Option<Uuid>,
    pub recovery_expires_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub committed_at_ms: Option<i64>,
    pub aborted_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedWorkspaceUsage {
    pub tenant_id: String,
    pub visible_logical_bytes: u64,
    pub physical_allocated_bytes: u64,
    pub reserved_bytes: u64,
    pub visible_limit_bytes: u64,
    pub replacement_headroom_bytes: u64,
    pub active_operation_id: Option<Uuid>,
    pub version: u64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedOperationCommit {
    pub operation: ManagedLogicalOperation,
    pub authority: ObjectAuthority,
    pub usage: ManagedWorkspaceUsage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedProvenPhysicalAllocation {
    pub authority: ObjectAuthority,
    pub allocated_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityListQuery {
    pub tenant_id: String,
    pub bucket: String,
    pub prefix: String,
    pub after: Option<String>,
    pub max_keys: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityListPage {
    pub objects: Vec<ObjectAuthority>,
    pub next_after: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityPlacementCursor {
    pub tenant_id: String,
    pub bucket: String,
    pub key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityPlacementPageQuery {
    pub target_placement_version: u32,
    pub after: Option<AuthorityPlacementCursor>,
    pub limit: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityPlacementPage {
    pub objects: Vec<ObjectAuthority>,
    pub next_after: Option<AuthorityPlacementCursor>,
}

/// Aggregate view of authorities still below the target placement version.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthorityPlacementStats {
    pub remaining: u64,
    pub oldest_updated_at_ms: Option<i64>,
}

/// Counts of repair records grouped by their lifecycle state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RepairStateCounts {
    pub pending: u64,
    pub leased: u64,
    pub dead: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedListVersion {
    V1,
    V2,
}

impl ManagedListVersion {
    fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "V1",
            Self::V2 => "V2",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "V1" => Ok(Self::V1),
            "V2" => Ok(Self::V2),
            _ => Err(ManagedError::Corrupt(format!(
                "unknown managed list version {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedListCursorBinding {
    pub tenant_id: String,
    pub bucket: String,
    pub prefix: String,
    pub delimiter: Option<String>,
    pub version: ManagedListVersion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedListCursorPosition {
    pub last_key: Option<String>,
    pub last_common_prefix: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedListCursorState {
    Active,
    Used,
}

impl ManagedListCursorState {
    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "ACTIVE" => Ok(Self::Active),
            "USED" => Ok(Self::Used),
            _ => Err(ManagedError::Corrupt(format!(
                "unknown managed list cursor state {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedListCursor {
    pub id: Uuid,
    pub binding: ManagedListCursorBinding,
    pub fence: ManagedRouteFence,
    pub position: ManagedListCursorPosition,
    pub response_state: serde_json::Value,
    pub response_state_bytes: u64,
    pub final_page: bool,
    pub state: ManagedListCursorState,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub first_used_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedListCursorRequest {
    pub binding: ManagedListCursorBinding,
    pub position: ManagedListCursorPosition,
    pub response_state: serde_json::Value,
    pub final_page: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespacePurgeRequest {
    pub tenant_id: String,
    /// Idempotency key owned by the caller and persisted by implementations
    /// that support complete physical generation deletion.
    pub operation_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamespacePurgeStatus {
    Pending,
    Running,
    Complete { deleted_versions: u64 },
    Blocked { reason: String },
    Unsupported { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalWriteIntent {
    pub intent_id: Uuid,
    pub tenant_id: String,
    pub backend_id: String,
    pub storage_identity: ProviderStorageIdentity,
    pub credential_epoch: u64,
    pub provider_bucket: String,
    pub physical_key: String,
    pub versioning_mode: BackendVersioningMode,
    pub versioning_capability: BackendVersioningCapability,
    pub lease_owner: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalWriteLease {
    pub intent_id: Uuid,
    pub namespace_epoch: u64,
    pub owner: String,
    pub token: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurablePhysicalWriteIntent {
    pub intent: PhysicalWriteIntent,
    pub namespace_epoch: u64,
    pub blocked_reason: Option<String>,
    pub lease_expires_at_ms: i64,
    pub lease: PhysicalWriteLease,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhysicalVersionTarget {
    pub tenant_id: String,
    pub namespace_epoch: u64,
    pub backend_id: String,
    pub storage_identity: ProviderStorageIdentity,
    pub credential_epoch: u64,
    pub provider_bucket: String,
    pub physical_key: String,
    pub version_id: Option<String>,
    pub versioning_mode: BackendVersioningMode,
    pub versioning_capability: BackendVersioningCapability,
    pub write_operation_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderStorageIdentity {
    pub provider_kind: String,
    pub provider_instance_id: String,
    pub provider_account_id: String,
    pub canonical_endpoint: String,
    pub region: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendVersioningMode {
    Unversioned,
    Enabled,
    Suspended,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendVersioningCapability {
    Unsupported,
    Optional,
    Required,
}

impl BackendVersioningCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "UNSUPPORTED",
            Self::Optional => "OPTIONAL",
            Self::Required => "REQUIRED",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "UNSUPPORTED" => Ok(Self::Unsupported),
            "OPTIONAL" => Ok(Self::Optional),
            "REQUIRED" => Ok(Self::Required),
            value => Err(ManagedError::Corrupt(format!(
                "unknown backend versioning capability {value:?}"
            ))),
        }
    }
}

impl BackendVersioningMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unversioned => "UNVERSIONED",
            Self::Enabled => "ENABLED",
            Self::Suspended => "SUSPENDED",
            Self::Unknown => "UNKNOWN",
        }
    }

    fn parse(value: &str) -> Result<Self, ManagedError> {
        match value {
            "UNVERSIONED" => Ok(Self::Unversioned),
            "ENABLED" => Ok(Self::Enabled),
            "SUSPENDED" => Ok(Self::Suspended),
            "UNKNOWN" => Ok(Self::Unknown),
            value => Err(ManagedError::Corrupt(format!(
                "unknown backend versioning mode {value:?}"
            ))),
        }
    }
}

#[async_trait]
pub trait ManagedRepository: Send + Sync {
    fn is_durable(&self) -> bool;
    async fn assert_namespace_active(&self, _tenant_id: &str) -> Result<(), ManagedError> {
        Ok(())
    }
    async fn route_fence(&self, tenant_id: &str) -> Result<ManagedRouteFence, ManagedError>;
    async fn advance_routing_epoch(
        &self,
        tenant_id: &str,
        expected_routing_epoch: u64,
    ) -> Result<ManagedRouteFence, ManagedError>;
    async fn insert_logical_operation(
        &self,
        intent: ManagedLogicalOperationIntent,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    async fn logical_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<ManagedLogicalOperation>, ManagedError>;
    async fn pending_logical_operations(
        &self,
        limit: u64,
    ) -> Result<Vec<ManagedLogicalOperation>, ManagedError>;
    async fn pending_delete_settlements(
        &self,
        limit: u64,
    ) -> Result<Vec<ManagedLogicalOperation>, ManagedError>;
    async fn mark_logical_operation_settled(
        &self,
        operation_id: Uuid,
        receipt_id: Uuid,
    ) -> Result<(), ManagedError>;
    async fn defer_delete_settlement(
        &self,
        operation_id: Uuid,
        receipt_id: Uuid,
    ) -> Result<(), ManagedError>;
    async fn claim_stale_logical_operations(
        &self,
        owner: &str,
        stale_before_ms: i64,
        claim_expires_at_ms: i64,
        limit: u64,
    ) -> Result<Vec<ManagedRecoveryClaim>, ManagedError>;
    async fn mark_logical_recovery_blocked(
        &self,
        claim: &ManagedRecoveryClaim,
        reason: &str,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    async fn renew_logical_recovery_claim(
        &self,
        claim: &ManagedRecoveryClaim,
        claim_expires_at_ms: i64,
    ) -> Result<ManagedRecoveryClaim, ManagedError>;
    /// Reserve maximum provider exposure and acquire the workspace's only
    /// managed-mutation slot before a physical child may be created.
    async fn reserve_logical_operation(
        &self,
        operation_id: Uuid,
        physical_bytes: u64,
    ) -> Result<ManagedWorkspaceUsage, ManagedError>;
    /// Admit a logical operation and reserve its provider exposure in one
    /// transaction, clamping the reservation to the workspace's available
    /// physical headroom. Admission is atomic: on failure no logical operation
    /// is committed, so nothing is left for reconciliation to abort.
    async fn admit_logical_operation(
        &self,
        intent: ManagedLogicalOperationIntent,
        reservation_cap: u64,
    ) -> Result<(ManagedLogicalOperation, ManagedWorkspaceUsage), ManagedError>;
    async fn record_logical_usage(
        &self,
        operation_id: Uuid,
        evidence: ManagedUsageEvidence,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    async fn transition_logical_operation(
        &self,
        operation_id: Uuid,
        from: ManagedLogicalOperationState,
        to: ManagedLogicalOperationState,
        error_class: Option<&str>,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    /// Record usage evidence and advance the operation from `Open` to
    /// `Completing` in one transaction (one database round trip instead of two).
    async fn record_logical_usage_and_begin_completion(
        &self,
        operation_id: Uuid,
        evidence: ManagedUsageEvidence,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    async fn finalize_logical_put(
        &self,
        operation_id: Uuid,
        physical_lease: &PhysicalWriteLease,
        result: ExactPhysicalCommit,
        recovery_claim: Option<&ManagedRecoveryClaim>,
    ) -> Result<ManagedOperationCommit, ManagedError>;
    async fn commit_logical_delete(
        &self,
        operation_id: Uuid,
        placement: &Placement,
    ) -> Result<ManagedOperationCommit, ManagedError>;
    /// Persist the DELETE intent, evidence, tombstone, cleanup work, and usage
    /// accounting as one transaction after locking current authority.
    async fn commit_atomic_logical_delete(
        &self,
        request: ManagedDeleteRequest,
    ) -> Result<ManagedOperationCommit, ManagedDeleteError>;
    /// Mark an operation non-billable only after absence is proven. If a
    /// provider mutation occurred, transfer its reservation to allocated bytes
    /// and enqueue exact cleanup instead of releasing physical capacity early.
    async fn prove_logical_abort(
        &self,
        operation_id: Uuid,
        error_class: &str,
        physical: Option<ManagedProvenPhysicalAllocation>,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    /// Atomically consume a logical PUT child intent after exact non-mutation
    /// evidence, release its reservation/active slot, and mark the parent
    /// `PROVEN_ABORTED`. Logical children must never use the standalone physical
    /// abort path.
    async fn abort_logical_put(
        &self,
        operation_id: Uuid,
        physical_lease: Option<&PhysicalWriteLease>,
        proof: LogicalAbortProof,
        error_class: &str,
        recovery_claim: Option<&ManagedRecoveryClaim>,
    ) -> Result<ManagedLogicalOperation, ManagedError>;
    async fn workspace_usage(
        &self,
        tenant_id: &str,
    ) -> Result<Option<ManagedWorkspaceUsage>, ManagedError>;
    async fn list_authority(
        &self,
        query: AuthorityListQuery,
    ) -> Result<AuthorityListPage, ManagedError>;
    async fn list_authority_below_placement_version(
        &self,
        query: AuthorityPlacementPageQuery,
    ) -> Result<AuthorityPlacementPage, ManagedError>;
    async fn authority_placement_stats(
        &self,
        target_placement_version: u32,
    ) -> Result<AuthorityPlacementStats, ManagedError>;

    async fn create_list_cursor(
        &self,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError>;
    /// Create the next cached page exactly once for a cursor replay. Concurrent
    /// uses converge on the same successor row and therefore the same token.
    async fn create_list_cursor_successor(
        &self,
        predecessor_cursor_id: Uuid,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError>;
    async fn use_list_cursor(
        &self,
        cursor_id: Uuid,
        binding: &ManagedListCursorBinding,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError>;
    async fn delete_list_cursor(&self, cursor_id: Uuid) -> Result<(), ManagedError>;
    async fn cleanup_expired_list_cursors(
        &self,
        now_ms: i64,
        limit: u64,
    ) -> Result<u64, ManagedError>;
    async fn begin_multipart_activity(
        &self,
        _upload_id: &str,
        _tenant_id: &str,
    ) -> Result<u64, ManagedError> {
        Err(ManagedError::Persistence(
            "managed multipart epoch fencing is unsupported".to_string(),
        ))
    }
    async fn assert_multipart_activity(
        &self,
        _upload_id: &str,
        _tenant_id: &str,
        _namespace_epoch: u64,
        _allow_purging: bool,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed multipart epoch fencing is unsupported".to_string(),
        ))
    }
    async fn confirm_multipart_activity(
        &self,
        _upload_id: &str,
        _tenant_id: &str,
        _namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed multipart epoch fencing is unsupported".to_string(),
        ))
    }
    async fn reconcile_multipart_activities(&self, _limit: u64) -> Result<u64, ManagedError> {
        Ok(0)
    }
    async fn finish_multipart_activity(
        &self,
        _upload_id: &str,
        _tenant_id: &str,
        _namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed multipart epoch fencing is unsupported".to_string(),
        ))
    }
    async fn any_authority(&self) -> Result<bool, ManagedError>;
    async fn get(
        &self,
        logical: &LogicalObjectKey,
    ) -> Result<Option<ObjectAuthority>, ManagedError>;
    async fn publish(
        &self,
        authority: ObjectAuthority,
        expected_cas: Option<u64>,
    ) -> Result<ObjectAuthority, ManagedError>;
    async fn advance_placement_version(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: u64,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError>;
    /// Record a durable placement policy. Returns `Ok(false)` when a different
    /// policy (a different fingerprint) is already durable at the same version —
    /// a same-version edit that the caller must reject.
    async fn record_placement_policy(
        &self,
        policy: &ManagedPlacementPolicy,
    ) -> Result<bool, ManagedError>;
    async fn tombstone(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: Option<u64>,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError>;
    async fn enqueue(&self, repair: RepairRecord) -> Result<(), ManagedError>;
    async fn claim_repairs(
        &self,
        owner: &str,
        lease_until_ms: i64,
        limit: u64,
    ) -> Result<Vec<RepairRecord>, ManagedError>;
    async fn renew_repair(
        &self,
        lease_token: Uuid,
        lease_until_ms: i64,
    ) -> Result<(), ManagedError>;
    async fn complete_repair(&self, repair: &RepairRecord) -> Result<bool, ManagedError>;
    async fn fail_repair(&self, lease_token: Uuid, error: &str) -> Result<(), ManagedError>;
    async fn repair_state_counts(&self) -> Result<RepairStateCounts, ManagedError>;

    /// Persist a write intent before any provider operation can create a
    /// physical version. Implementations must reject a fenced namespace.
    async fn begin_physical_write(
        &self,
        _intent: PhysicalWriteIntent,
    ) -> Result<PhysicalWriteLease, ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn pending_physical_write_intents(
        &self,
        _limit: u64,
    ) -> Result<Vec<DurablePhysicalWriteIntent>, ManagedError> {
        Ok(Vec::new())
    }
    async fn physical_write_intent(
        &self,
        _intent_id: Uuid,
    ) -> Result<Option<DurablePhysicalWriteIntent>, ManagedError> {
        Ok(None)
    }
    async fn renew_physical_write_intent(
        &self,
        _lease: &PhysicalWriteLease,
        _lease_expires_at_ms: i64,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical write lease is unsupported".to_string(),
        ))
    }
    async fn claim_expired_physical_write_intent(
        &self,
        _intent_id: Uuid,
        _owner: &str,
        _lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        Ok(None)
    }
    async fn claim_logical_physical_write_intent(
        &self,
        _claim: &ManagedRecoveryClaim,
        _lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        Ok(None)
    }

    /// Atomically replace a durable write intent with its exact provider
    /// version. `None` denotes an unversioned object.
    async fn commit_physical_write(
        &self,
        _lease: &PhysicalWriteLease,
        _superseded_version_ids: &[String],
        _version_id: Option<&str>,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn abort_physical_write(&self, _lease: &PhysicalWriteLease) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn block_physical_write(
        &self,
        _lease: &PhysicalWriteLease,
        _reason: &str,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn physical_versions(
        &self,
        _tenant_id: &str,
        _backend_id: &str,
        _provider_bucket: &str,
        _physical_key: &str,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn forget_physical_version(
        &self,
        _target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed physical-version ledger is unsupported".to_string(),
        ))
    }

    async fn purge_targets(
        &self,
        _request: &NamespacePurgeRequest,
        _limit: u64,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        Ok(Vec::new())
    }

    async fn mark_purge_target_deleted(
        &self,
        _request: &NamespacePurgeRequest,
        _target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed namespace purge target tracking is unsupported".to_string(),
        ))
    }

    async fn mark_purge_target_blocked(
        &self,
        _request: &NamespacePurgeRequest,
        _target: &PhysicalVersionTarget,
        _reason: &str,
    ) -> Result<(), ManagedError> {
        Err(ManagedError::Persistence(
            "managed namespace purge target tracking is unsupported".to_string(),
        ))
    }

    /// Purge every physical generation owned by a managed tenant namespace.
    /// The default is deliberately unsupported: authority rows are not a full
    /// version ledger, so ListObjects-based deletion cannot prove completeness.
    async fn purge_namespace(
        &self,
        _request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        Ok(NamespacePurgeStatus::Unsupported {
            reason: "managed storage has no complete physical version ledger".to_string(),
        })
    }

    /// Query an idempotent purge operation without starting or advancing it.
    async fn namespace_purge_status(
        &self,
        _request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        Ok(NamespacePurgeStatus::Unsupported {
            reason: "managed storage has no complete physical version ledger".to_string(),
        })
    }
}

fn cleanup_repairs(authority: &ObjectAuthority) -> Vec<RepairRecord> {
    let mut repairs = vec![RepairRecord::copy(
        RepairKind::DeleteGeneration,
        authority,
        None,
        authority.primary_backend_id.clone(),
        RepairTargetRole::Cleanup,
        authority.placement_version,
    )];
    if let Some(replica) = &authority.replica_backend_id {
        repairs.push(RepairRecord::copy(
            RepairKind::DeleteGeneration,
            authority,
            None,
            replica.clone(),
            RepairTargetRole::Cleanup,
            authority.placement_version,
        ));
    }
    repairs
}

fn stale_repair_cleanup(repair: &RepairRecord) -> RepairRecord {
    let now = crate::transaction::unix_time_ms();
    let repair_id = Uuid::now_v7();
    RepairRecord {
        id: repair_id,
        repair_id,
        kind: RepairKind::DeleteGeneration,
        logical: repair.logical.clone(),
        namespace_epoch: repair.namespace_epoch,
        authority_cas_version: repair.authority_cas_version,
        generation: repair.generation,
        digest: repair.digest.clone(),
        size: repair.size,
        metadata: repair.metadata.clone(),
        physical_key: repair.physical_key.clone(),
        source_backend_id: None,
        target_backend_id: repair.target_backend_id.clone(),
        target_role: RepairTargetRole::Cleanup,
        placement_version: repair.placement_version,
        placement_primary_backend_id: None,
        placement_replica_backend_id: None,
        attempts: 0,
        lease_owner: None,
        lease_token: None,
        lease_expires_at_ms: None,
        not_before_ms: 0,
        created_at_ms: now,
        updated_at_ms: now,
    }
}

fn publication_repairs(authority: &ObjectAuthority) -> Vec<RepairRecord> {
    match (&authority.replica_backend_id, authority.replica_status) {
        (Some(replica), CopyStatus::RepairPending) => vec![RepairRecord::copy(
            RepairKind::Replica,
            authority,
            Some(authority.primary_backend_id.clone()),
            replica.clone(),
            RepairTargetRole::Replica,
            authority.placement_version,
        )],
        _ => Vec::new(),
    }
}

fn placement_cleanup_repairs(
    previous: &ObjectAuthority,
    authority: &ObjectAuthority,
) -> Vec<RepairRecord> {
    let mut old_locations = vec![Some(previous.primary_backend_id.clone())];
    old_locations.push(previous.replica_backend_id.clone());
    old_locations
        .into_iter()
        .flatten()
        .filter(|backend| {
            backend != &authority.primary_backend_id
                && authority.replica_backend_id.as_deref() != Some(backend)
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .map(|backend| {
            RepairRecord::copy(
                RepairKind::DeleteGeneration,
                authority,
                None,
                backend,
                RepairTargetRole::Cleanup,
                authority.placement_version,
            )
        })
        .collect()
}

fn apply_repair_to_authority(
    authority: &mut ObjectAuthority,
    repair: &RepairRecord,
) -> Result<bool, ManagedError> {
    if repair.kind == RepairKind::Placement {
        let Some(primary) = repair.placement_primary_backend_id.as_deref() else {
            return Err(ManagedError::Corrupt(
                "placement repair has no requested primary backend".to_string(),
            ));
        };
        if repair.placement_version < authority.placement_version {
            return Ok(false);
        }
        match repair.target_role {
            RepairTargetRole::Primary if repair.target_backend_id == primary => {
                authority.primary_backend_id = primary.to_string();
                authority.primary_status = CopyStatus::Ready;
                if repair.placement_replica_backend_id.is_none() {
                    authority.replica_backend_id = None;
                    authority.replica_status = CopyStatus::Absent;
                }
            }
            RepairTargetRole::Replica
                if repair.placement_replica_backend_id.as_deref()
                    == Some(repair.target_backend_id.as_str()) =>
            {
                authority.replica_backend_id = Some(repair.target_backend_id.clone());
                authority.replica_status = CopyStatus::Ready;
            }
            _ => {
                return Err(ManagedError::Corrupt(
                    "placement repair target does not match requested placement".to_string(),
                ));
            }
        }
        if authority.primary_backend_id == primary
            && authority.primary_status == CopyStatus::Ready
            && match repair.placement_replica_backend_id.as_deref() {
                Some(replica) => {
                    authority.replica_backend_id.as_deref() == Some(replica)
                        && authority.replica_status == CopyStatus::Ready
                }
                None => {
                    authority.replica_backend_id.is_none()
                        && authority.replica_status == CopyStatus::Absent
                }
            }
        {
            authority.placement_version = repair.placement_version;
        }
        return Ok(true);
    }

    match repair.target_role {
        RepairTargetRole::Primary => {
            authority.primary_backend_id = repair.target_backend_id.clone();
            authority.primary_status = CopyStatus::Ready;
        }
        RepairTargetRole::Replica => {
            authority.replica_backend_id = Some(repair.target_backend_id.clone());
            authority.replica_status = CopyStatus::Ready;
        }
        RepairTargetRole::Cleanup => return Ok(false),
    }
    Ok(true)
}

fn repair_target_is_authoritative(authority: &ObjectAuthority, repair: &RepairRecord) -> bool {
    !authority.tombstone
        && authority.generation == repair.generation
        && (authority.primary_backend_id == repair.target_backend_id
            || authority.replica_backend_id.as_deref() == Some(repair.target_backend_id.as_str()))
}

fn authority_from_model(
    model: managed_object_authority::Model,
) -> Result<ObjectAuthority, ManagedError> {
    Ok(ObjectAuthority {
        logical: LogicalObjectKey {
            tenant_id: model.tenant_id,
            bucket: model.bucket,
            key: model.logical_key,
        },
        generation: model.generation,
        digest: model.digest,
        size: u64::try_from(model.size_bytes)
            .map_err(|_| ManagedError::Corrupt("negative authority size".to_string()))?,
        metadata: serde_json::from_value(model.metadata)
            .map_err(|error| ManagedError::Corrupt(error.to_string()))?,
        placement_version: u32::try_from(model.placement_version)
            .map_err(|_| ManagedError::Corrupt("invalid placement version".to_string()))?,
        primary_backend_id: model.primary_backend_id,
        primary_version_id: model.primary_version_id,
        replica_backend_id: model.replica_backend_id,
        primary_status: CopyStatus::parse(&model.primary_status)?,
        replica_status: CopyStatus::parse(&model.replica_status)?,
        tombstone: model.tombstone,
        cas_version: u64::try_from(model.cas_version)
            .map_err(|_| ManagedError::Corrupt("invalid authority CAS version".to_string()))?,
        created_at_ms: model.created_at_ms,
        updated_at_ms: model.updated_at_ms,
    })
}

fn u64_from_i64(value: i64, field: &str) -> Result<u64, ManagedError> {
    u64::try_from(value).map_err(|_| ManagedError::Corrupt(format!("invalid {field}")))
}

fn i64_from_u64(value: u64, field: &str) -> Result<i64, ManagedError> {
    i64::try_from(value).map_err(|_| ManagedError::Corrupt(format!("{field} exceeds BIGINT")))
}

fn physical_allocation(expected_size: u64, exact_version_count: u64) -> Result<u64, ManagedError> {
    if exact_version_count == 0 {
        return Err(ManagedError::Persistence(
            "managed logical operation cannot settle before its child is ledgered".to_string(),
        ));
    }
    expected_size
        .checked_mul(exact_version_count)
        .ok_or(ManagedError::QuotaExceeded)
}

fn validate_exact_physical_commit(result: &ExactPhysicalCommit) -> Result<(), ManagedError> {
    if !result.version_history_complete
        || result.selected_version_id.as_deref() == Some("")
        || result.superseded_version_ids.iter().any(String::is_empty)
    {
        return Err(ManagedError::RecoveryBlocked(
            "invalid_exact_version_history",
        ));
    }
    let versions = exact_version_ids(result);
    (versions.iter().collect::<HashSet<_>>().len() == versions.len())
        .then_some(())
        .ok_or(ManagedError::RecoveryBlocked("duplicate_exact_version"))
}

fn validate_physical_commit_versioning(
    intent: &PhysicalWriteIntent,
    result: &ExactPhysicalCommit,
) -> Result<(), ManagedError> {
    let versionless = result.selected_version_id.is_none();
    let provably_unversioned = intent.versioning_mode == BackendVersioningMode::Unversioned
        && intent.versioning_capability == BackendVersioningCapability::Unsupported;
    if intent.versioning_mode == BackendVersioningMode::Unknown
        || versionless != provably_unversioned
        || (versionless && !result.superseded_version_ids.is_empty())
    {
        return Err(ManagedError::RecoveryBlocked(
            "physical_versioning_contract_mismatch",
        ));
    }
    Ok(())
}

fn physical_intent_supports_exact_history(intent: &PhysicalWriteIntent) -> bool {
    intent.versioning_mode != BackendVersioningMode::Unknown
        && (intent.versioning_mode != BackendVersioningMode::Unversioned
            || intent.versioning_capability == BackendVersioningCapability::Unsupported)
}

fn validate_durable_child_commit(
    child: Option<&object_operation::Model>,
    operation: &ManagedLogicalOperation,
    result: &ExactPhysicalCommit,
) -> Result<(), ManagedError> {
    let Some(child) = child else {
        return Err(ManagedError::RecoveryBlocked("missing_child_journal"));
    };
    let superseded =
        serde_json::from_value::<Vec<String>>(child.committed_superseded_version_ids.clone())
            .map_err(|_| ManagedError::RecoveryBlocked("corrupt_child_commit"))?;
    let evidence = operation
        .evidence
        .as_ref()
        .ok_or(ManagedError::RecoveryBlocked("missing_usage_evidence"))?;
    if child.state != "COMMITTED"
        || !child.committed_version_history_complete
        || child.tenant_id.as_deref() != Some(operation.intent.logical.tenant_id.as_str())
        || child.namespace_epoch != i64::try_from(operation.intent.fence.namespace_epoch).ok()
        || child.backend_id != operation.intent.backend_id
        || child.bucket != operation.intent.provider_bucket
        || child.logical_key != operation.intent.logical.object_key()
        || child.physical_key != operation.intent.physical_key
        || child.expected_digest != evidence.expected_output_digest
        || child.expected_size != i64::try_from(evidence.expected_output_size).ok()
        || child.committed_version_id != result.selected_version_id
        || superseded.len() != result.superseded_version_ids.len()
        || superseded.iter().collect::<HashSet<_>>()
            != result.superseded_version_ids.iter().collect::<HashSet<_>>()
    {
        return Err(ManagedError::RecoveryBlocked("child_commit_mismatch"));
    }
    Ok(())
}

fn exact_version_ids(result: &ExactPhysicalCommit) -> Vec<String> {
    result
        .superseded_version_ids
        .iter()
        .cloned()
        .chain(std::iter::once(
            result.selected_version_id.clone().unwrap_or_default(),
        ))
        .collect()
}

fn expected_physical_targets(
    intent: &PhysicalWriteIntent,
    namespace_epoch: u64,
    result: &ExactPhysicalCommit,
) -> Vec<PhysicalVersionTarget> {
    exact_version_ids(result)
        .into_iter()
        .map(|version_id| PhysicalVersionTarget {
            tenant_id: intent.tenant_id.clone(),
            namespace_epoch,
            backend_id: intent.backend_id.clone(),
            storage_identity: intent.storage_identity.clone(),
            credential_epoch: intent.credential_epoch,
            provider_bucket: intent.provider_bucket.clone(),
            physical_key: intent.physical_key.clone(),
            version_id: (!version_id.is_empty()).then_some(version_id),
            versioning_mode: intent.versioning_mode,
            versioning_capability: intent.versioning_capability,
            write_operation_id: intent.intent_id,
        })
        .collect()
}

fn validate_recovery_authority(
    operation: &ManagedLogicalOperation,
    claim: Option<&ManagedRecoveryClaim>,
    now: i64,
) -> Result<(), ManagedError> {
    match claim {
        Some(claim)
            if claim.operation.intent.operation_id == operation.intent.operation_id
                && operation.recovery_owner.as_deref() == Some(claim.owner.as_str())
                && operation.recovery_token == Some(claim.token)
                && operation.recovery_expires_at_ms == Some(claim.expires_at_ms)
                && claim.expires_at_ms > now =>
        {
            Ok(())
        }
        None if operation.recovery_owner.is_none()
            && operation.recovery_token.is_none()
            && operation.recovery_expires_at_ms.is_none() =>
        {
            Ok(())
        }
        _ => Err(ManagedError::Conflict),
    }
}

fn serialize_cursor_response_state(
    response_state: &serde_json::Value,
) -> Result<Vec<u8>, ManagedError> {
    let serialized = serde_json::to_vec(response_state).map_err(|error| {
        ManagedError::Corrupt(format!("invalid cursor response state: {error}"))
    })?;
    if serialized.len() as u64 > MANAGED_LIST_CURSOR_RESPONSE_MAX_BYTES {
        return Err(ManagedError::CursorLimitExceeded);
    }
    Ok(serialized)
}

fn cursor_matches_request(cursor: &ManagedListCursor, request: &ManagedListCursorRequest) -> bool {
    cursor.binding == request.binding
        && cursor.position == request.position
        && cursor.response_state == request.response_state
        && cursor.final_page == request.final_page
}

fn request_kind_from_str(value: &str) -> Result<RequestKind, ManagedError> {
    match value {
        "write" => Ok(RequestKind::Write),
        "read" => Ok(RequestKind::Read),
        _ => Err(ManagedError::Corrupt(format!(
            "unknown managed request kind {value:?}"
        ))),
    }
}

fn usage_route_from_str(value: &str) -> Result<UsageRoute, ManagedError> {
    match value {
        "PutObject" => Ok(UsageRoute::PutObject),
        "GetObject" => Ok(UsageRoute::GetObject),
        "HeadObject" => Ok(UsageRoute::HeadObject),
        "ListObjects" => Ok(UsageRoute::ListObjects),
        "DeleteObject" => Ok(UsageRoute::DeleteObject),
        "AbortMultipartUpload" => Ok(UsageRoute::AbortMultipartUpload),
        "CompleteMultipartUpload" => Ok(UsageRoute::CompleteMultipartUpload),
        _ => Err(ManagedError::Corrupt(format!(
            "unknown managed usage route {value:?}"
        ))),
    }
}

fn logical_operation_from_model(
    model: managed_logical_operation::Model,
) -> Result<ManagedLogicalOperation, ManagedError> {
    let publication_recipe = match (
        model.publication_recipe_version,
        model.admitted_placement_version,
        model.recipe_primary_backend_id,
        model.authority_metadata,
        model.intended_primary_status,
        model.intended_replica_status,
    ) {
        (None, None, None, None, None, None) => None,
        (
            Some(version),
            Some(placement),
            Some(primary),
            Some(metadata),
            Some(primary_status),
            Some(replica_status),
        ) => Some(ManagedPublicationRecipe {
            version,
            placement_version: u32::try_from(placement).map_err(|_| {
                ManagedError::Corrupt("invalid admitted placement version".to_string())
            })?,
            primary_backend_id: primary,
            replica_backend_id: model.recipe_replica_backend_id,
            metadata: serde_json::from_value(metadata)
                .map_err(|_| ManagedError::Corrupt("invalid authority metadata".to_string()))?,
            primary_status: CopyStatus::parse(&primary_status)?,
            replica_status: CopyStatus::parse(&replica_status)?,
        }),
        _ => {
            return Err(ManagedError::Corrupt(
                "managed publication recipe is partially populated".to_string(),
            ));
        }
    };
    let evidence = match (
        model.expected_output_size,
        model.source_bytes,
        model.processed_bytes,
    ) {
        (None, None, None) if model.expected_output_digest.is_none() => None,
        (Some(output), Some(source), Some(processed)) => Some(ManagedUsageEvidence {
            expected_output_digest: model.expected_output_digest,
            expected_output_size: u64_from_i64(output, "managed expected output size")?,
            source_bytes: u64_from_i64(source, "managed source bytes")?,
            processed_bytes: u64_from_i64(processed, "managed processed bytes")?,
            payload: model.usage_evidence,
        }),
        _ => {
            return Err(ManagedError::Corrupt(
                "managed usage evidence is partially populated".to_string(),
            ));
        }
    };
    Ok(ManagedLogicalOperation {
        intent: ManagedLogicalOperationIntent {
            operation_id: model.operation_id,
            receipt_id: model.receipt_id,
            logical: LogicalObjectKey {
                tenant_id: model.tenant_id,
                bucket: model.bucket,
                key: model.logical_key,
            },
            kind: ManagedMutationKind::parse(&model.operation_kind)?,
            generation: model.generation,
            fence: ManagedRouteFence {
                namespace_epoch: u64_from_i64(model.namespace_epoch, "managed namespace epoch")?,
                routing_epoch: u64_from_i64(model.routing_epoch, "managed routing epoch")?,
            },
            expected_authority_cas: model
                .expected_authority_cas
                .map(|value| u64_from_i64(value, "managed expected authority CAS"))
                .transpose()?,
            prior_logical_size: u64_from_i64(
                model.prior_logical_size,
                "managed prior logical size",
            )?,
            primary_child_operation_id: model.primary_child_operation_id,
            backend_id: model.backend_id,
            provider_bucket: model.provider_bucket,
            physical_key: model.physical_key,
            occurred_at_ms: model.occurred_at_ms,
            rate_version: model.rate_version,
            route: usage_route_from_str(&model.usage_route)?,
            request_kind: request_kind_from_str(&model.request_kind)?,
            max_processed_bytes: u64_from_i64(
                model.max_processed_bytes,
                "managed maximum processed bytes",
            )?,
            publication_recipe,
        },
        evidence,
        reserved_physical_bytes: u64_from_i64(
            model.reserved_physical_bytes,
            "managed reserved physical bytes",
        )?,
        committed_physical_bytes: u64_from_i64(
            model.committed_physical_bytes,
            "managed committed physical bytes",
        )?,
        released_physical_bytes: u64_from_i64(
            model.released_physical_bytes,
            "managed released physical bytes",
        )?,
        state: ManagedLogicalOperationState::parse(&model.state)?,
        committed_authority_version: model
            .committed_authority_version
            .map(|value| u64_from_i64(value, "managed committed authority version"))
            .transpose()?,
        settlement_state: ManagedSettlementState::parse(&model.settlement_state)?,
        last_error_class: model.last_error_class,
        recovery_owner: model.recovery_owner,
        recovery_token: model.recovery_token,
        recovery_expires_at_ms: model.recovery_expires_at_ms,
        created_at_ms: model.created_at_ms,
        updated_at_ms: model.updated_at_ms,
        committed_at_ms: model.committed_at_ms,
        aborted_at_ms: model.aborted_at_ms,
    })
}

fn logical_operation_active(
    intent: &ManagedLogicalOperationIntent,
    now: i64,
) -> Result<managed_logical_operation::ActiveModel, ManagedError> {
    let recipe = intent.publication_recipe.as_ref();
    Ok(managed_logical_operation::ActiveModel {
        operation_id: Set(intent.operation_id),
        receipt_id: Set(intent.receipt_id),
        tenant_id: Set(intent.logical.tenant_id.clone()),
        bucket: Set(intent.logical.bucket.clone()),
        logical_key: Set(intent.logical.key.clone()),
        operation_kind: Set(intent.kind.as_str().to_string()),
        generation: Set(intent.generation),
        namespace_epoch: Set(i64_from_u64(
            intent.fence.namespace_epoch,
            "managed namespace epoch",
        )?),
        routing_epoch: Set(i64_from_u64(
            intent.fence.routing_epoch,
            "managed routing epoch",
        )?),
        expected_authority_cas: Set(intent
            .expected_authority_cas
            .map(|value| i64_from_u64(value, "managed expected authority CAS"))
            .transpose()?),
        prior_logical_size: Set(i64_from_u64(
            intent.prior_logical_size,
            "managed prior logical size",
        )?),
        primary_child_operation_id: Set(intent.primary_child_operation_id),
        backend_id: Set(intent.backend_id.clone()),
        provider_bucket: Set(intent.provider_bucket.clone()),
        physical_key: Set(intent.physical_key.clone()),
        expected_output_digest: Set(None),
        expected_output_size: Set(None),
        source_bytes: Set(None),
        processed_bytes: Set(None),
        reserved_physical_bytes: Set(0),
        committed_physical_bytes: Set(0),
        released_physical_bytes: Set(0),
        state: Set(ManagedLogicalOperationState::Intent.as_str().to_string()),
        committed_authority_version: Set(None),
        occurred_at_ms: Set(intent.occurred_at_ms),
        rate_version: Set(intent.rate_version),
        usage_route: Set(intent.route.as_str().to_string()),
        request_kind: Set(intent.request_kind.as_str().to_string()),
        max_processed_bytes: Set(i64_from_u64(
            intent.max_processed_bytes,
            "managed maximum processed bytes",
        )?),
        publication_recipe_version: Set(recipe.map(|recipe| recipe.version)),
        admitted_placement_version: Set(recipe.map(|recipe| i64::from(recipe.placement_version))),
        recipe_primary_backend_id: Set(recipe.map(|recipe| recipe.primary_backend_id.clone())),
        recipe_replica_backend_id: Set(recipe.and_then(|recipe| recipe.replica_backend_id.clone())),
        authority_metadata: Set(recipe
            .map(|recipe| serde_json::to_value(&recipe.metadata))
            .transpose()
            .map_err(|_| ManagedError::Conflict)?),
        intended_primary_status: Set(
            recipe.map(|recipe| recipe.primary_status.as_str().to_string())
        ),
        intended_replica_status: Set(
            recipe.map(|recipe| recipe.replica_status.as_str().to_string())
        ),
        usage_evidence: Set(serde_json::json!({})),
        settlement_state: Set(ManagedSettlementState::Pending.as_str().to_string()),
        last_error_class: Set(None),
        recovery_owner: Set(None),
        recovery_token: Set(None),
        recovery_expires_at_ms: Set(None),
        created_at_ms: Set(now),
        updated_at_ms: Set(now),
        committed_at_ms: Set(None),
        aborted_at_ms: Set(None),
    })
}

fn workspace_usage_from_model(
    model: managed_workspace_usage::Model,
) -> Result<ManagedWorkspaceUsage, ManagedError> {
    Ok(ManagedWorkspaceUsage {
        tenant_id: model.tenant_id,
        visible_logical_bytes: u64_from_i64(
            model.visible_logical_bytes,
            "managed visible logical bytes",
        )?,
        physical_allocated_bytes: u64_from_i64(
            model.physical_allocated_bytes,
            "managed physical allocated bytes",
        )?,
        reserved_bytes: u64_from_i64(model.reserved_bytes, "managed reserved bytes")?,
        visible_limit_bytes: u64_from_i64(model.visible_limit_bytes, "managed visible limit")?,
        replacement_headroom_bytes: u64_from_i64(
            model.replacement_headroom_bytes,
            "managed replacement headroom",
        )?,
        active_operation_id: model.active_operation_id,
        version: u64_from_i64(model.version, "managed usage version")?,
        created_at_ms: model.created_at_ms,
        updated_at_ms: model.updated_at_ms,
    })
}

fn list_cursor_from_model(
    model: managed_list_cursor::Model,
) -> Result<ManagedListCursor, ManagedError> {
    let response_state_bytes = u64_from_i64(
        model.response_state_bytes,
        "managed list cursor response bytes",
    )?;
    if response_state_bytes != model.response_state.len() as u64
        || response_state_bytes > MANAGED_LIST_CURSOR_RESPONSE_MAX_BYTES
    {
        return Err(ManagedError::Corrupt(
            "managed list cursor response byte count is invalid".to_string(),
        ));
    }
    Ok(ManagedListCursor {
        id: model.cursor_id,
        binding: ManagedListCursorBinding {
            tenant_id: model.tenant_id,
            bucket: model.bucket,
            prefix: model.prefix,
            delimiter: model.delimiter,
            version: ManagedListVersion::parse(&model.list_version)?,
        },
        fence: ManagedRouteFence {
            namespace_epoch: u64_from_i64(
                model.namespace_epoch,
                "managed list cursor namespace epoch",
            )?,
            routing_epoch: u64_from_i64(model.routing_epoch, "managed list cursor routing epoch")?,
        },
        position: ManagedListCursorPosition {
            last_key: model.last_key,
            last_common_prefix: model.last_common_prefix,
        },
        response_state: serde_json::from_slice(&model.response_state).map_err(|error| {
            ManagedError::Corrupt(format!("invalid managed cursor response state: {error}"))
        })?,
        response_state_bytes,
        final_page: model.final_page,
        state: ManagedListCursorState::parse(&model.state)?,
        created_at_ms: model.created_at_ms,
        expires_at_ms: model.expires_at_ms,
        first_used_at_ms: model.first_used_at_ms,
    })
}

fn repair_from_model(model: managed_object_repair::Model) -> Result<RepairRecord, ManagedError> {
    Ok(RepairRecord {
        id: model.lease_token.unwrap_or(model.id),
        repair_id: model.id,
        kind: RepairKind::parse(&model.kind)?,
        logical: LogicalObjectKey {
            tenant_id: model.tenant_id,
            bucket: model.bucket,
            key: model.logical_key,
        },
        namespace_epoch: u64::try_from(model.namespace_epoch)
            .map_err(|_| ManagedError::Corrupt("invalid repair namespace epoch".to_string()))?,
        authority_cas_version: u64::try_from(model.authority_cas_version)
            .map_err(|_| ManagedError::Corrupt("invalid repair authority CAS".to_string()))?,
        generation: model.generation,
        digest: model.digest,
        size: u64::try_from(model.size_bytes)
            .map_err(|_| ManagedError::Corrupt("negative repair size".to_string()))?,
        metadata: serde_json::from_value(model.metadata)
            .map_err(|error| ManagedError::Corrupt(error.to_string()))?,
        physical_key: model.physical_key,
        source_backend_id: model.source_backend_id,
        target_backend_id: model.target_backend_id,
        target_role: RepairTargetRole::parse(&model.target_role)?,
        placement_version: u32::try_from(model.placement_version)
            .map_err(|_| ManagedError::Corrupt("invalid repair placement version".to_string()))?,
        placement_primary_backend_id: model.placement_primary_backend_id,
        placement_replica_backend_id: model.placement_replica_backend_id,
        attempts: u32::try_from(model.attempts)
            .map_err(|_| ManagedError::Corrupt("negative repair attempts".to_string()))?,
        lease_owner: model.lease_owner,
        lease_token: model.lease_token,
        lease_expires_at_ms: model.lease_expires_at_ms,
        not_before_ms: model.not_before_ms,
        created_at_ms: model.created_at_ms,
        updated_at_ms: model.updated_at_ms,
    })
}

fn repair_active(repair: RepairRecord) -> Result<managed_object_repair::ActiveModel, ManagedError> {
    Ok(managed_object_repair::ActiveModel {
        id: Set(repair.repair_id),
        kind: Set(repair.kind.as_str().to_string()),
        state: Set("PENDING".to_string()),
        tenant_id: Set(repair.logical.tenant_id),
        namespace_epoch: Set(i64::try_from(repair.namespace_epoch).map_err(|_| {
            ManagedError::Corrupt("repair namespace epoch exceeds BIGINT".to_string())
        })?),
        authority_cas_version: Set(i64::try_from(repair.authority_cas_version).map_err(|_| {
            ManagedError::Corrupt("repair authority CAS exceeds BIGINT".to_string())
        })?),
        bucket: Set(repair.logical.bucket),
        logical_key: Set(repair.logical.key),
        generation: Set(repair.generation),
        digest: Set(repair.digest),
        size_bytes: Set(i64::try_from(repair.size)
            .map_err(|_| ManagedError::Corrupt("repair size exceeds BIGINT".to_string()))?),
        metadata: Set(serde_json::to_value(repair.metadata)
            .map_err(|error| ManagedError::Corrupt(error.to_string()))?),
        physical_key: Set(repair.physical_key),
        source_backend_id: Set(repair.source_backend_id),
        target_backend_id: Set(repair.target_backend_id),
        target_role: Set(repair.target_role.as_str().to_string()),
        placement_version: Set(i64::from(repair.placement_version)),
        placement_primary_backend_id: Set(repair.placement_primary_backend_id),
        placement_replica_backend_id: Set(repair.placement_replica_backend_id),
        attempts: Set(i32::try_from(repair.attempts)
            .map_err(|_| ManagedError::Corrupt("repair attempts exceed INTEGER".to_string()))?),
        lease_owner: Set(repair.lease_owner),
        lease_token: Set(None),
        lease_expires_at_ms: Set(repair.lease_expires_at_ms),
        not_before_ms: Set(repair.not_before_ms),
        last_error: Set(None),
        created_at_ms: Set(repair.created_at_ms),
        updated_at_ms: Set(repair.updated_at_ms),
    })
}

fn persistence(error: impl std::fmt::Display) -> ManagedError {
    ManagedError::Persistence(error.to_string())
}

async fn insert_waiting_placement_cleanup<C>(
    db: &C,
    repair: RepairRecord,
) -> Result<(), ManagedError>
where
    C: sea_orm::ConnectionTrait,
{
    let mut active = repair_active(repair)?;
    active.state = Set("WAITING_CUTOVER".to_string());
    managed_object_repair::Entity::insert(active)
        .on_conflict(
            OnConflict::columns([
                managed_object_repair::Column::Kind,
                managed_object_repair::Column::Generation,
                managed_object_repair::Column::TargetBackendId,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec_without_returning(db)
        .await
        .map_err(persistence)?;
    Ok(())
}

async fn locked_namespace<C>(
    db: &C,
    tenant_id: &str,
) -> Result<managed_namespace::Model, ManagedError>
where
    C: ConnectionTrait,
{
    if let Some(namespace) = managed_namespace::Entity::find_by_id(tenant_id.to_string())
        .lock(LockType::Update)
        .one(db)
        .await
        .map_err(persistence)?
    {
        return Ok(namespace);
    }
    let now = crate::transaction::unix_time_ms();
    managed_namespace::Entity::insert(managed_namespace::ActiveModel {
        tenant_id: Set(tenant_id.to_string()),
        epoch: Set(1),
        routing_epoch: Set(1),
        state: Set("ACTIVE".to_string()),
        purge_operation_id: Set(None),
        created_at_ms: Set(now),
        updated_at_ms: Set(now),
    })
    .on_conflict(
        OnConflict::column(managed_namespace::Column::TenantId)
            .do_nothing()
            .to_owned(),
    )
    .exec_without_returning(db)
    .await
    .map_err(persistence)?;
    managed_namespace::Entity::find_by_id(tenant_id.to_string())
        .lock(LockType::Update)
        .one(db)
        .await
        .map_err(persistence)?
        .ok_or_else(|| ManagedError::Persistence("managed namespace disappeared".to_string()))
}

fn validate_logical_intent(intent: &ManagedLogicalOperationIntent) -> Result<(), ManagedError> {
    if intent.logical.tenant_id.is_empty()
        || intent.logical.bucket.is_empty()
        || intent.backend_id.is_empty()
        || intent.provider_bucket.is_empty()
        || intent.physical_key.is_empty()
        || intent.fence.namespace_epoch == 0
        || intent.fence.routing_epoch == 0
        || intent.rate_version <= 0
        || intent.occurred_at_ms < 0
        || intent.request_kind != RequestKind::Write
        || !matches!(
            (intent.kind, intent.route),
            (ManagedMutationKind::Put, UsageRoute::PutObject)
                | (ManagedMutationKind::Delete, UsageRoute::DeleteObject)
        )
        || match intent.kind {
            ManagedMutationKind::Put => intent.publication_recipe.as_ref().is_none_or(|recipe| {
                recipe.version != MANAGED_PUBLICATION_RECIPE_VERSION
                    || recipe.placement_version == 0
                    || recipe.primary_backend_id != intent.backend_id
                    || recipe.primary_backend_id.is_empty()
                    || recipe.replica_backend_id.as_deref() == Some("")
                    || recipe.primary_status != CopyStatus::Ready
                    || (recipe.replica_backend_id.is_none()
                        && recipe.replica_status != CopyStatus::Absent)
                    || (recipe.replica_backend_id.is_some()
                        && recipe.replica_status != CopyStatus::RepairPending)
            }),
            ManagedMutationKind::Delete => intent.publication_recipe.is_some(),
        }
    {
        return Err(ManagedError::Conflict);
    }
    Ok(())
}

fn validate_physical_intent(intent: &PhysicalWriteIntent) -> Result<(), ManagedError> {
    let identity = &intent.storage_identity;
    if intent.tenant_id.is_empty()
        || intent.backend_id.is_empty()
        || intent.provider_bucket.is_empty()
        || intent.physical_key.is_empty()
        || intent.credential_epoch == 0
        || identity.provider_kind.is_empty()
        || identity.provider_instance_id.is_empty()
        || identity.provider_account_id.is_empty()
        || identity.canonical_endpoint.is_empty()
        || identity.region.is_empty()
    {
        return Err(ManagedError::Conflict);
    }
    Ok(())
}

async fn locked_workspace_usage<C>(
    db: &C,
    tenant_id: &str,
) -> Result<managed_workspace_usage::Model, ManagedError>
where
    C: ConnectionTrait,
{
    if let Some(usage) = managed_workspace_usage::Entity::find_by_id(tenant_id.to_string())
        .lock(LockType::Update)
        .one(db)
        .await
        .map_err(persistence)?
    {
        return Ok(usage);
    }
    let now = crate::transaction::unix_time_ms();
    managed_workspace_usage::Entity::insert(managed_workspace_usage::ActiveModel {
        tenant_id: Set(tenant_id.to_string()),
        visible_logical_bytes: Set(0),
        physical_allocated_bytes: Set(0),
        reserved_bytes: Set(0),
        visible_limit_bytes: Set(i64_from_u64(
            MANAGED_VISIBLE_LIMIT_BYTES,
            "managed visible limit",
        )?),
        replacement_headroom_bytes: Set(i64_from_u64(
            MANAGED_REPLACEMENT_HEADROOM_BYTES,
            "managed replacement headroom",
        )?),
        active_operation_id: Set(None),
        version: Set(1),
        created_at_ms: Set(now),
        updated_at_ms: Set(now),
    })
    .on_conflict(
        OnConflict::column(managed_workspace_usage::Column::TenantId)
            .do_nothing()
            .to_owned(),
    )
    .exec_without_returning(db)
    .await
    .map_err(persistence)?;
    managed_workspace_usage::Entity::find_by_id(tenant_id.to_string())
        .lock(LockType::Update)
        .one(db)
        .await
        .map_err(persistence)?
        .ok_or_else(|| ManagedError::Persistence("managed usage row disappeared".to_string()))
}

async fn require_active_namespace<C>(db: &C, tenant_id: &str) -> Result<i64, ManagedError>
where
    C: ConnectionTrait,
{
    let namespace = locked_namespace(db, tenant_id).await?;
    if namespace.state != "ACTIVE" {
        return Err(ManagedError::NamespaceFenced);
    }
    Ok(namespace.epoch)
}

fn purge_status_from_model(
    purge: managed_namespace_purge::Model,
) -> Result<NamespacePurgeStatus, ManagedError> {
    match purge.state.as_str() {
        "RUNNING" => Ok(NamespacePurgeStatus::Running),
        "BLOCKED" => Ok(NamespacePurgeStatus::Blocked {
            reason: purge
                .blocked_reason
                .unwrap_or_else(|| "managed namespace purge is blocked".to_string()),
        }),
        "COMPLETE" => Ok(NamespacePurgeStatus::Complete {
            deleted_versions: u64::try_from(purge.deleted_versions).map_err(|_| {
                ManagedError::Corrupt("purge deleted-version count is invalid".to_string())
            })?,
        }),
        state => Err(ManagedError::Corrupt(format!(
            "unknown managed namespace purge state {state:?}"
        ))),
    }
}

fn physical_target_from_model(
    model: managed_physical_object_version::Model,
) -> Result<PhysicalVersionTarget, ManagedError> {
    Ok(PhysicalVersionTarget {
        tenant_id: model.tenant_id,
        namespace_epoch: u64::try_from(model.epoch)
            .map_err(|_| ManagedError::Corrupt("physical version epoch is invalid".to_string()))?,
        backend_id: model.backend_id,
        storage_identity: ProviderStorageIdentity {
            provider_kind: model.provider_kind,
            provider_instance_id: model.provider_instance_id,
            provider_account_id: model.provider_account_id,
            canonical_endpoint: model.canonical_endpoint,
            region: model.provider_region,
        },
        credential_epoch: u64_from_i64(
            model.credential_epoch,
            "physical version credential epoch",
        )?,
        provider_bucket: model.provider_bucket,
        physical_key: model.physical_key,
        version_id: (!model.version_id.is_empty()).then_some(model.version_id),
        versioning_mode: BackendVersioningMode::parse(&model.versioning_mode)?,
        versioning_capability: BackendVersioningCapability::parse(&model.versioning_capability)?,
        write_operation_id: model.write_operation_id,
    })
}

fn durable_physical_intent_from_model(
    intent: managed_physical_write_intent::Model,
) -> Result<DurablePhysicalWriteIntent, ManagedError> {
    let namespace_epoch = u64::try_from(intent.epoch)
        .map_err(|_| ManagedError::Corrupt("physical write intent epoch is invalid".to_string()))?;
    Ok(DurablePhysicalWriteIntent {
        namespace_epoch,
        blocked_reason: intent.last_error,
        lease_expires_at_ms: intent.lease_expires_at_ms,
        lease: PhysicalWriteLease {
            intent_id: intent.intent_id,
            namespace_epoch,
            owner: intent.lease_owner.clone(),
            token: intent.lease_token,
        },
        intent: PhysicalWriteIntent {
            intent_id: intent.intent_id,
            tenant_id: intent.tenant_id,
            backend_id: intent.backend_id,
            storage_identity: ProviderStorageIdentity {
                provider_kind: intent.provider_kind,
                provider_instance_id: intent.provider_instance_id,
                provider_account_id: intent.provider_account_id,
                canonical_endpoint: intent.canonical_endpoint,
                region: intent.provider_region,
            },
            credential_epoch: u64_from_i64(
                intent.credential_epoch,
                "physical write credential epoch",
            )?,
            provider_bucket: intent.provider_bucket,
            physical_key: intent.physical_key,
            versioning_mode: BackendVersioningMode::parse(&intent.versioning_mode)?,
            versioning_capability: BackendVersioningCapability::parse(
                &intent.versioning_capability,
            )?,
            lease_owner: intent.lease_owner,
        },
    })
}

#[derive(Clone, Debug)]
pub struct PostgresManagedRepository {
    db: DatabaseConnection,
}

impl PostgresManagedRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            db: SqlxPostgresConnector::from_sqlx_postgres_pool(pool),
        }
    }

    async fn finalize_purge_if_ready(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let purge = managed_namespace_purge::Entity::find_by_id(request.operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .filter(|purge| purge.tenant_id == request.tenant_id);
        let Some(purge) = purge else {
            return Ok(NamespacePurgeStatus::Blocked {
                reason: "managed namespace purge operation was not found".to_string(),
            });
        };
        if purge.state == "COMPLETE" {
            return purge_status_from_model(purge);
        }

        let now = crate::transaction::unix_time_ms();
        managed_physical_object_version::Entity::update_many()
            .col_expr(
                managed_physical_object_version::Column::State,
                Expr::value("PURGE_PENDING"),
            )
            .col_expr(
                managed_physical_object_version::Column::PurgeOperationId,
                Expr::value(Some(request.operation_id)),
            )
            .col_expr(
                managed_physical_object_version::Column::LastError,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_physical_object_version::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_physical_object_version::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_physical_object_version::Column::Epoch.lte(purge.epoch))
            .filter(managed_physical_object_version::Column::State.eq("LIVE"))
            .exec(&txn)
            .await
            .map_err(persistence)?;

        let intents = managed_physical_write_intent::Entity::find()
            .filter(managed_physical_write_intent::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_physical_write_intent::Column::Epoch.lte(purge.epoch))
            .all(&txn)
            .await
            .map_err(persistence)?;
        let targets = managed_physical_object_version::Entity::find()
            .filter(managed_physical_object_version::Column::TenantId.eq(&request.tenant_id))
            .filter(
                managed_physical_object_version::Column::PurgeOperationId.eq(request.operation_id),
            )
            .all(&txn)
            .await
            .map_err(persistence)?;
        if let Some(intent) = intents.iter().find(|intent| intent.state == "BLOCKED") {
            let reason = intent
                .last_error
                .clone()
                .unwrap_or_else(|| "physical provider version history is ambiguous".to_string());
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }
        if !intents.is_empty() || targets.iter().any(|target| target.state == "PURGE_PENDING") {
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Running);
        }
        if let Some(target) = targets
            .iter()
            .find(|target| target.state == "PURGE_BLOCKED")
        {
            let reason = target
                .last_error
                .clone()
                .unwrap_or_else(|| "physical version deletion is blocked".to_string());
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }

        let unresolved_journal_rows = object_operation::Entity::find()
            .filter(object_operation::Column::TenantId.eq(&request.tenant_id))
            .filter(object_operation::Column::NamespaceEpoch.lte(purge.epoch))
            .filter(object_operation::Column::State.is_not_in([
                crate::transaction::OperationState::Committed.as_str(),
                crate::transaction::OperationState::ProvenAborted.as_str(),
            ]))
            .count(&txn)
            .await
            .map_err(persistence)?;
        if unresolved_journal_rows > 0 {
            let reason = "managed namespace has unresolved operation journal rows".to_string();
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }

        let unresolved_logical_operations = managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .count(&txn)
            .await
            .map_err(persistence)?;
        if unresolved_logical_operations > 0 {
            let reason = "managed namespace has unresolved logical operations".to_string();
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }

        // Multipart staging owns encrypted artifacts and quota accounting in a
        // separate repository. Completing purge while rows remain would leak
        // those artifacts, so fail closed instead of deleting metadata alone.
        let multipart_uploads = crate::entity::multipart_upload::Entity::find()
            .filter(crate::entity::multipart_upload::Column::TenantId.eq(&request.tenant_id))
            .filter(
                Condition::any()
                    .add(crate::entity::multipart_upload::Column::NamespaceEpoch.is_null())
                    .add(crate::entity::multipart_upload::Column::NamespaceEpoch.lte(purge.epoch)),
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
        let multipart_activities = managed_multipart_activity::Entity::find()
            .filter(managed_multipart_activity::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_multipart_activity::Column::NamespaceEpoch.lte(purge.epoch))
            .count(&txn)
            .await
            .map_err(persistence)?;
        if multipart_uploads > 0 || multipart_activities > 0 {
            let reason =
                "managed namespace has multipart staging artifacts that must be aborted first"
                    .to_string();
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("BLOCKED"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Some(reason.clone())),
                )
                .col_expr(
                    managed_namespace_purge::Column::UpdatedAtMs,
                    Expr::value(now),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Ok(NamespacePurgeStatus::Blocked { reason });
        }

        managed_object_repair::Entity::delete_many()
            .filter(managed_object_repair::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_object_repair::Column::NamespaceEpoch.lte(purge.epoch))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        object_operation::Entity::delete_many()
            .filter(object_operation::Column::TenantId.eq(&request.tenant_id))
            .filter(object_operation::Column::NamespaceEpoch.lte(purge.epoch))
            .filter(object_operation::Column::State.is_in([
                crate::transaction::OperationState::Committed.as_str(),
                crate::transaction::OperationState::ProvenAborted.as_str(),
            ]))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::ReleasedPhysicalBytes,
                Expr::col(managed_logical_operation::Column::CommittedPhysicalBytes).into(),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_logical_operation::Column::TenantId.eq(&request.tenant_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::VisibleLogicalBytes,
                Expr::value(0),
            )
            .col_expr(
                managed_workspace_usage::Column::PhysicalAllocatedBytes,
                Expr::value(0),
            )
            .col_expr(
                managed_workspace_usage::Column::ReservedBytes,
                Expr::value(0),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::col(managed_workspace_usage::Column::Version).add(1),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_workspace_usage::Column::TenantId.eq(&request.tenant_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_list_cursor::Entity::delete_many()
            .filter(managed_list_cursor::Column::TenantId.eq(&request.tenant_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_object_authority::Entity::delete_many()
            .filter(managed_object_authority::Column::TenantId.eq(&request.tenant_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_namespace::Entity::update_many()
            .col_expr(
                managed_namespace::Column::Epoch,
                Expr::value(purge.epoch.saturating_add(1)),
            )
            .col_expr(
                managed_namespace::Column::RoutingEpoch,
                Expr::col(managed_namespace::Column::RoutingEpoch).add(1),
            )
            .col_expr(managed_namespace::Column::State, Expr::value("ACTIVE"))
            .col_expr(
                managed_namespace::Column::PurgeOperationId,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(managed_namespace::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_namespace::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_namespace::Column::PurgeOperationId.eq(request.operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_namespace_purge::Entity::update_many()
            .col_expr(
                managed_namespace_purge::Column::State,
                Expr::value("COMPLETE"),
            )
            .col_expr(
                managed_namespace_purge::Column::BlockedReason,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_namespace_purge::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .col_expr(
                managed_namespace_purge::Column::CompletedAtMs,
                Expr::value(Some(now)),
            )
            .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        let mut complete = purge;
        complete.state = "COMPLETE".to_string();
        complete.completed_at_ms = Some(now);
        purge_status_from_model(complete)
    }
}

async fn insert_repair<C>(db: &C, repair: RepairRecord) -> Result<(), ManagedError>
where
    C: sea_orm::ConnectionTrait,
{
    let revival = repair.clone();
    let kind = repair.kind.as_str().to_string();
    let generation = repair.generation;
    let target = repair.target_backend_id.clone();
    let inserted = managed_object_repair::Entity::insert(repair_active(repair)?)
        .on_conflict(
            OnConflict::columns([
                managed_object_repair::Column::Kind,
                managed_object_repair::Column::Generation,
                managed_object_repair::Column::TargetBackendId,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec_without_returning(db)
        .await
        .map_err(persistence)?;
    if inserted == 1 {
        return Ok(());
    }
    let existing = managed_object_repair::Entity::find()
        .filter(managed_object_repair::Column::Kind.eq(kind))
        .filter(managed_object_repair::Column::Generation.eq(generation))
        .filter(managed_object_repair::Column::TargetBackendId.eq(target))
        .one(db)
        .await
        .map_err(persistence)?;
    let Some(existing) = existing else {
        return Err(ManagedError::Persistence(
            "managed repair conflict row disappeared".to_string(),
        ));
    };
    if existing.state == "DONE" {
        managed_object_repair::Entity::update_many()
            .col_expr(managed_object_repair::Column::State, Expr::value("PENDING"))
            .col_expr(
                managed_object_repair::Column::LeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_object_repair::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .col_expr(
                managed_object_repair::Column::NamespaceEpoch,
                Expr::value(i64::try_from(revival.namespace_epoch).map_err(|_| {
                    ManagedError::Corrupt("repair namespace epoch exceeds BIGINT".to_string())
                })?),
            )
            .col_expr(
                managed_object_repair::Column::AuthorityCasVersion,
                Expr::value(i64::try_from(revival.authority_cas_version).map_err(|_| {
                    ManagedError::Corrupt("repair authority CAS exceeds BIGINT".to_string())
                })?),
            )
            .col_expr(
                managed_object_repair::Column::SourceBackendId,
                Expr::value(revival.source_backend_id),
            )
            .col_expr(
                managed_object_repair::Column::PhysicalKey,
                Expr::value(revival.physical_key),
            )
            .col_expr(
                managed_object_repair::Column::Digest,
                Expr::value(revival.digest),
            )
            .col_expr(
                managed_object_repair::Column::SizeBytes,
                Expr::value(i64::try_from(revival.size).map_err(|_| {
                    ManagedError::Corrupt("repair size exceeds BIGINT".to_string())
                })?),
            )
            .col_expr(
                managed_object_repair::Column::Metadata,
                Expr::value(
                    serde_json::to_value(revival.metadata)
                        .map_err(|error| ManagedError::Corrupt(error.to_string()))?,
                ),
            )
            .col_expr(
                managed_object_repair::Column::TargetRole,
                Expr::value(revival.target_role.as_str()),
            )
            .col_expr(
                managed_object_repair::Column::PlacementVersion,
                Expr::value(i64::from(revival.placement_version)),
            )
            .col_expr(
                managed_object_repair::Column::PlacementPrimaryBackendId,
                Expr::value(revival.placement_primary_backend_id),
            )
            .col_expr(
                managed_object_repair::Column::PlacementReplicaBackendId,
                Expr::value(revival.placement_replica_backend_id),
            )
            .filter(managed_object_repair::Column::Id.eq(existing.id))
            .exec(db)
            .await
            .map_err(persistence)?;
    }
    Ok(())
}

fn authority_active(
    authority: &ObjectAuthority,
) -> Result<managed_object_authority::ActiveModel, ManagedError> {
    Ok(managed_object_authority::ActiveModel {
        tenant_id: Set(authority.logical.tenant_id.clone()),
        bucket: Set(authority.logical.bucket.clone()),
        logical_key: Set(authority.logical.key.clone()),
        generation: Set(authority.generation),
        digest: Set(authority.digest.clone()),
        size_bytes: Set(i64::try_from(authority.size)
            .map_err(|_| ManagedError::Corrupt("authority size exceeds BIGINT".to_string()))?),
        metadata: Set(serde_json::to_value(&authority.metadata)
            .map_err(|error| ManagedError::Corrupt(error.to_string()))?),
        placement_version: Set(i64::from(authority.placement_version)),
        primary_backend_id: Set(authority.primary_backend_id.clone()),
        primary_version_id: Set(authority.primary_version_id.clone()),
        replica_backend_id: Set(authority.replica_backend_id.clone()),
        primary_status: Set(authority.primary_status.as_str().to_string()),
        replica_status: Set(authority.replica_status.as_str().to_string()),
        tombstone: Set(authority.tombstone),
        cas_version: Set(i64::try_from(authority.cas_version)
            .map_err(|_| ManagedError::Corrupt("authority CAS exceeds BIGINT".to_string()))?),
        created_at_ms: Set(authority.created_at_ms),
        updated_at_ms: Set(authority.updated_at_ms),
    })
}

#[async_trait]
impl ManagedRepository for PostgresManagedRepository {
    fn is_durable(&self) -> bool {
        true
    }

    async fn assert_namespace_active(&self, tenant_id: &str) -> Result<(), ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        require_active_namespace(&txn, tenant_id).await?;
        txn.commit().await.map_err(persistence)
    }

    async fn route_fence(&self, tenant_id: &str) -> Result<ManagedRouteFence, ManagedError> {
        let namespace = locked_namespace(&self.db, tenant_id).await?;
        if namespace.state != "ACTIVE" {
            return Err(ManagedError::NamespaceFenced);
        }
        Ok(ManagedRouteFence {
            namespace_epoch: u64_from_i64(namespace.epoch, "managed namespace epoch")?,
            routing_epoch: u64_from_i64(namespace.routing_epoch, "managed routing epoch")?,
        })
    }

    async fn advance_routing_epoch(
        &self,
        tenant_id: &str,
        expected_routing_epoch: u64,
    ) -> Result<ManagedRouteFence, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, tenant_id).await?;
        if namespace.state != "ACTIVE" {
            return Err(ManagedError::NamespaceFenced);
        }
        let expected = i64_from_u64(expected_routing_epoch, "managed routing epoch")?;
        if namespace.routing_epoch != expected {
            return Err(ManagedError::Conflict);
        }
        let routing_epoch = expected
            .checked_add(1)
            .ok_or_else(|| ManagedError::Corrupt("managed routing epoch overflow".to_string()))?;
        managed_namespace::Entity::update_many()
            .col_expr(
                managed_namespace::Column::RoutingEpoch,
                Expr::value(routing_epoch),
            )
            .col_expr(
                managed_namespace::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(managed_namespace::Column::TenantId.eq(tenant_id))
            .filter(managed_namespace::Column::RoutingEpoch.eq(expected))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        Ok(ManagedRouteFence {
            namespace_epoch: u64_from_i64(namespace.epoch, "managed namespace epoch")?,
            routing_epoch: u64_from_i64(routing_epoch, "managed routing epoch")?,
        })
    }

    async fn insert_logical_operation(
        &self,
        intent: ManagedLogicalOperationIntent,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        validate_logical_intent(&intent)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &intent.logical.tenant_id).await?;
        if namespace.state != "ACTIVE" {
            return Err(ManagedError::NamespaceFenced);
        }
        if u64_from_i64(namespace.epoch, "managed namespace epoch")? != intent.fence.namespace_epoch
            || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                != intent.fence.routing_epoch
        {
            return Err(ManagedError::Conflict);
        }
        if let Some(existing) = managed_logical_operation::Entity::find_by_id(intent.operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
        {
            let operation = logical_operation_from_model(existing)?;
            if operation.intent != intent {
                return Err(ManagedError::Conflict);
            }
            txn.commit().await.map_err(persistence)?;
            return Ok(operation);
        }
        let child_intents =
            managed_physical_write_intent::Entity::find_by_id(intent.primary_child_operation_id)
                .count(&txn)
                .await
                .map_err(persistence)?;
        let child_versions = managed_physical_object_version::Entity::find()
            .filter(
                managed_physical_object_version::Column::WriteOperationId
                    .eq(intent.primary_child_operation_id),
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
        if child_intents != 0 || child_versions != 0 {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        managed_logical_operation::Entity::insert(logical_operation_active(&intent, now)?)
            .on_conflict(
                OnConflict::column(managed_logical_operation::Column::OperationId)
                    .do_nothing()
                    .to_owned(),
            )
            .exec_without_returning(&txn)
            .await
            .map_err(|_| ManagedError::Conflict)?;
        let operation = managed_logical_operation::Entity::find_by_id(intent.operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(logical_operation_from_model)?;
        if operation.intent != intent {
            return Err(ManagedError::Conflict);
        }
        txn.commit().await.map_err(persistence)?;
        Ok(operation)
    }

    async fn logical_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<ManagedLogicalOperation>, ManagedError> {
        managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .map(logical_operation_from_model)
            .transpose()
    }

    async fn pending_logical_operations(
        &self,
        limit: u64,
    ) -> Result<Vec<ManagedLogicalOperation>, ManagedError> {
        managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .order_by_asc(managed_logical_operation::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(logical_operation_from_model)
            .collect()
    }

    async fn pending_delete_settlements(
        &self,
        limit: u64,
    ) -> Result<Vec<ManagedLogicalOperation>, ManagedError> {
        managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::OperationKind.eq("DELETE"))
            .filter(
                managed_logical_operation::Column::State
                    .eq(ManagedLogicalOperationState::Committed.as_str()),
            )
            .filter(
                managed_logical_operation::Column::SettlementState
                    .eq(ManagedSettlementState::Pending.as_str()),
            )
            .order_by_asc(managed_logical_operation::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(logical_operation_from_model)
            .collect()
    }

    async fn mark_logical_operation_settled(
        &self,
        operation_id: Uuid,
        receipt_id: Uuid,
    ) -> Result<(), ManagedError> {
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::SettlementState,
                Expr::value(ManagedSettlementState::Settled.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .filter(managed_logical_operation::Column::ReceiptId.eq(receipt_id))
            .filter(managed_logical_operation::Column::OperationKind.eq("DELETE"))
            .filter(
                managed_logical_operation::Column::State
                    .eq(ManagedLogicalOperationState::Committed.as_str()),
            )
            .filter(
                managed_logical_operation::Column::SettlementState
                    .eq(ManagedSettlementState::Pending.as_str()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if updated.rows_affected == 1 {
            return Ok(());
        }
        self.logical_operation(operation_id)
            .await?
            .filter(|operation| {
                operation.intent.receipt_id == receipt_id
                    && operation.intent.kind == ManagedMutationKind::Delete
                    && operation.state == ManagedLogicalOperationState::Committed
                    && operation.settlement_state == ManagedSettlementState::Settled
            })
            .map(|_| ())
            .ok_or(ManagedError::Conflict)
    }

    async fn defer_delete_settlement(
        &self,
        operation_id: Uuid,
        receipt_id: Uuid,
    ) -> Result<(), ManagedError> {
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms().saturating_add(60_000)),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .filter(managed_logical_operation::Column::ReceiptId.eq(receipt_id))
            .filter(managed_logical_operation::Column::OperationKind.eq("DELETE"))
            .filter(
                managed_logical_operation::Column::State
                    .eq(ManagedLogicalOperationState::Committed.as_str()),
            )
            .filter(
                managed_logical_operation::Column::SettlementState
                    .eq(ManagedSettlementState::Pending.as_str()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        (updated.rows_affected == 1)
            .then_some(())
            .ok_or(ManagedError::Conflict)
    }

    async fn claim_stale_logical_operations(
        &self,
        owner: &str,
        stale_before_ms: i64,
        claim_expires_at_ms: i64,
        limit: u64,
    ) -> Result<Vec<ManagedRecoveryClaim>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        if owner.is_empty() || owner.len() > 256 || claim_expires_at_ms <= now {
            return Err(ManagedError::Conflict);
        }
        let candidates = managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::OperationKind.eq("PUT"))
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .filter(managed_logical_operation::Column::UpdatedAtMs.lte(stale_before_ms))
            .filter(
                Condition::any()
                    .add(managed_logical_operation::Column::RecoveryExpiresAtMs.is_null())
                    .add(managed_logical_operation::Column::RecoveryExpiresAtMs.lte(now)),
            )
            .order_by_asc(managed_logical_operation::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?;
        let mut claims = Vec::new();
        for candidate in candidates {
            let token = Uuid::now_v7();
            let updated = managed_logical_operation::Entity::update_many()
                .col_expr(
                    managed_logical_operation::Column::RecoveryOwner,
                    Expr::value(Some(owner.to_string())),
                )
                .col_expr(
                    managed_logical_operation::Column::RecoveryToken,
                    Expr::value(Some(token)),
                )
                .col_expr(
                    managed_logical_operation::Column::RecoveryExpiresAtMs,
                    Expr::value(Some(claim_expires_at_ms)),
                )
                .filter(managed_logical_operation::Column::OperationId.eq(candidate.operation_id))
                .filter(managed_logical_operation::Column::OperationKind.eq("PUT"))
                .filter(managed_logical_operation::Column::State.eq(&candidate.state))
                .filter(managed_logical_operation::Column::UpdatedAtMs.eq(candidate.updated_at_ms))
                .filter(managed_logical_operation::Column::UpdatedAtMs.lte(stale_before_ms))
                .filter(managed_logical_operation::Column::State.is_not_in([
                    ManagedLogicalOperationState::Committed.as_str(),
                    ManagedLogicalOperationState::ProvenAborted.as_str(),
                ]))
                .filter(
                    Condition::any()
                        .add(managed_logical_operation::Column::RecoveryExpiresAtMs.is_null())
                        .add(managed_logical_operation::Column::RecoveryExpiresAtMs.lte(now)),
                )
                .exec_with_returning(&self.db)
                .await
                .map_err(persistence)?;
            if let Some(model) = updated.into_iter().next() {
                claims.push(ManagedRecoveryClaim {
                    operation: logical_operation_from_model(model)?,
                    owner: owner.to_string(),
                    token,
                    expires_at_ms: claim_expires_at_ms,
                });
            }
        }
        Ok(claims)
    }

    async fn mark_logical_recovery_blocked(
        &self,
        claim: &ManagedRecoveryClaim,
        reason: &str,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::RecoveryBlocked.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::LastErrorClass,
                Expr::value(Some(reason.chars().take(128).collect::<String>())),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(
                managed_logical_operation::Column::OperationId
                    .eq(claim.operation.intent.operation_id),
            )
            .filter(managed_logical_operation::Column::RecoveryOwner.eq(&claim.owner))
            .filter(managed_logical_operation::Column::RecoveryToken.eq(claim.token))
            .filter(managed_logical_operation::Column::RecoveryExpiresAtMs.eq(claim.expires_at_ms))
            .filter(
                managed_logical_operation::Column::RecoveryExpiresAtMs
                    .gt(crate::transaction::unix_time_ms()),
            )
            .exec_with_returning(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .next()
            .ok_or(ManagedError::Conflict)?;
        logical_operation_from_model(updated)
    }

    async fn renew_logical_recovery_claim(
        &self,
        claim: &ManagedRecoveryClaim,
        claim_expires_at_ms: i64,
    ) -> Result<ManagedRecoveryClaim, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        if claim_expires_at_ms <= now {
            return Err(ManagedError::Conflict);
        }
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::RecoveryExpiresAtMs,
                Expr::value(Some(claim_expires_at_ms)),
            )
            .filter(
                managed_logical_operation::Column::OperationId
                    .eq(claim.operation.intent.operation_id),
            )
            .filter(managed_logical_operation::Column::RecoveryOwner.eq(&claim.owner))
            .filter(managed_logical_operation::Column::RecoveryToken.eq(claim.token))
            .filter(managed_logical_operation::Column::RecoveryExpiresAtMs.eq(claim.expires_at_ms))
            .filter(managed_logical_operation::Column::RecoveryExpiresAtMs.gt(now))
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .exec_with_returning(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .next()
            .ok_or(ManagedError::Conflict)?;
        Ok(ManagedRecoveryClaim {
            operation: logical_operation_from_model(updated)?,
            owner: claim.owner.clone(),
            token: claim.token,
            expires_at_ms: claim_expires_at_ms,
        })
    }

    async fn reserve_logical_operation(
        &self,
        operation_id: Uuid,
        physical_bytes: u64,
    ) -> Result<ManagedWorkspaceUsage, ManagedError> {
        let identity = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &identity.tenant_id).await?;
        let model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let operation = logical_operation_from_model(model.clone())?;
        if namespace.state != "ACTIVE"
            || u64_from_i64(namespace.epoch, "managed namespace epoch")?
                != operation.intent.fence.namespace_epoch
            || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                != operation.intent.fence.routing_epoch
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let mut usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
        if operation.state == ManagedLogicalOperationState::Open
            && operation.reserved_physical_bytes == physical_bytes
            && usage.active_operation_id == Some(operation_id)
        {
            txn.commit().await.map_err(persistence)?;
            return workspace_usage_from_model(usage);
        }
        if operation.state != ManagedLogicalOperationState::Intent {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::Open,
            });
        }
        if usage.active_operation_id.is_some() {
            return Err(ManagedError::MutationInProgress);
        }
        let physical = i64_from_u64(physical_bytes, "managed physical reservation")?;
        let next_reserved = usage
            .reserved_bytes
            .checked_add(physical)
            .ok_or(ManagedError::QuotaExceeded)?;
        let physical_bound = usage
            .visible_limit_bytes
            .checked_add(usage.replacement_headroom_bytes)
            .ok_or(ManagedError::QuotaExceeded)?;
        if usage
            .physical_allocated_bytes
            .checked_add(next_reserved)
            .is_none_or(|value| value > physical_bound)
        {
            return Err(ManagedError::QuotaExceeded);
        }
        let now = crate::transaction::unix_time_ms();
        usage.reserved_bytes = next_reserved;
        usage.active_operation_id = Some(operation_id);
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::ReservedBytes,
                Expr::value(usage.reserved_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(Some(operation_id)),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(
                managed_workspace_usage::Column::TenantId.eq(&operation.intent.logical.tenant_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::Open.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::ReservedPhysicalBytes,
                Expr::value(physical),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .filter(
                managed_logical_operation::Column::State
                    .eq(ManagedLogicalOperationState::Intent.as_str()),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        workspace_usage_from_model(usage)
    }

    async fn admit_logical_operation(
        &self,
        intent: ManagedLogicalOperationIntent,
        reservation_cap: u64,
    ) -> Result<(ManagedLogicalOperation, ManagedWorkspaceUsage), ManagedError> {
        validate_logical_intent(&intent)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &intent.logical.tenant_id).await?;
        if namespace.state != "ACTIVE" {
            return Err(ManagedError::NamespaceFenced);
        }
        if u64_from_i64(namespace.epoch, "managed namespace epoch")? != intent.fence.namespace_epoch
            || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                != intent.fence.routing_epoch
        {
            return Err(ManagedError::Conflict);
        }
        let mut operation = if let Some(existing) =
            managed_logical_operation::Entity::find_by_id(intent.operation_id)
                .one(&txn)
                .await
                .map_err(persistence)?
        {
            let operation = logical_operation_from_model(existing)?;
            if operation.intent != intent {
                return Err(ManagedError::Conflict);
            }
            operation
        } else {
            let child_intents = managed_physical_write_intent::Entity::find_by_id(
                intent.primary_child_operation_id,
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
            let child_versions = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::WriteOperationId
                        .eq(intent.primary_child_operation_id),
                )
                .count(&txn)
                .await
                .map_err(persistence)?;
            if child_intents != 0 || child_versions != 0 {
                return Err(ManagedError::Conflict);
            }
            let now = crate::transaction::unix_time_ms();
            managed_logical_operation::Entity::insert(logical_operation_active(&intent, now)?)
                .on_conflict(
                    OnConflict::column(managed_logical_operation::Column::OperationId)
                        .do_nothing()
                        .to_owned(),
                )
                .exec_without_returning(&txn)
                .await
                .map_err(|_| ManagedError::Conflict)?;
            let inserted = managed_logical_operation::Entity::find_by_id(intent.operation_id)
                .one(&txn)
                .await
                .map_err(persistence)?
                .ok_or(ManagedError::Conflict)?;
            let operation = logical_operation_from_model(inserted)?;
            if operation.intent != intent {
                return Err(ManagedError::Conflict);
            }
            operation
        };
        let mut usage = locked_workspace_usage(&txn, &intent.logical.tenant_id).await?;
        let available = usage
            .visible_limit_bytes
            .saturating_add(usage.replacement_headroom_bytes)
            .saturating_sub(usage.physical_allocated_bytes)
            .saturating_sub(usage.reserved_bytes);
        let available = u64::try_from(available).unwrap_or(u64::MAX).max(1);
        let physical_bytes = reservation_cap.min(available);
        if operation.state == ManagedLogicalOperationState::Open
            && operation.reserved_physical_bytes == physical_bytes
            && usage.active_operation_id == Some(intent.operation_id)
        {
            txn.commit().await.map_err(persistence)?;
            return Ok((operation, workspace_usage_from_model(usage)?));
        }
        if operation.state != ManagedLogicalOperationState::Intent {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::Open,
            });
        }
        if usage.active_operation_id.is_some() {
            return Err(ManagedError::MutationInProgress);
        }
        let physical = i64_from_u64(physical_bytes, "managed physical reservation")?;
        let next_reserved = usage
            .reserved_bytes
            .checked_add(physical)
            .ok_or(ManagedError::QuotaExceeded)?;
        let physical_bound = usage
            .visible_limit_bytes
            .checked_add(usage.replacement_headroom_bytes)
            .ok_or(ManagedError::QuotaExceeded)?;
        if usage
            .physical_allocated_bytes
            .checked_add(next_reserved)
            .is_none_or(|value| value > physical_bound)
        {
            return Err(ManagedError::QuotaExceeded);
        }
        let now = crate::transaction::unix_time_ms();
        usage.reserved_bytes = next_reserved;
        usage.active_operation_id = Some(intent.operation_id);
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::ReservedBytes,
                Expr::value(usage.reserved_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(Some(intent.operation_id)),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_workspace_usage::Column::TenantId.eq(&intent.logical.tenant_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::Open.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::ReservedPhysicalBytes,
                Expr::value(physical),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(intent.operation_id))
            .filter(
                managed_logical_operation::Column::State
                    .eq(ManagedLogicalOperationState::Intent.as_str()),
            )
            .exec_with_returning(&txn)
            .await
            .map_err(persistence)?;
        if updated.len() != 1 {
            return Err(ManagedError::Conflict);
        }
        operation = logical_operation_from_model(
            updated.into_iter().next().ok_or(ManagedError::Conflict)?,
        )?;
        txn.commit().await.map_err(persistence)?;
        let usage = workspace_usage_from_model(usage)?;
        Ok((operation, usage))
    }

    async fn record_logical_usage(
        &self,
        operation_id: Uuid,
        evidence: ManagedUsageEvidence,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        if evidence.processed_bytes != evidence.source_bytes.max(evidence.expected_output_size) {
            return Err(ManagedError::Conflict);
        }
        let txn = self.db.begin().await.map_err(persistence)?;
        let model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let existing = logical_operation_from_model(model)?;
        if existing.evidence.as_ref() == Some(&evidence) {
            txn.commit().await.map_err(persistence)?;
            return Ok(existing);
        }
        if existing.evidence.is_some()
            || existing.state == ManagedLogicalOperationState::Intent
            || existing.state.terminal()
            || evidence.processed_bytes > existing.intent.max_processed_bytes
            || (existing.intent.kind == ManagedMutationKind::Put
                && evidence.expected_output_digest.is_none())
            || (existing.intent.kind == ManagedMutationKind::Delete
                && (evidence.expected_output_size != 0
                    || evidence.source_bytes != 0
                    || evidence.processed_bytes != 0))
        {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::ExpectedOutputDigest,
                Expr::value(evidence.expected_output_digest.clone()),
            )
            .col_expr(
                managed_logical_operation::Column::ExpectedOutputSize,
                Expr::value(Some(i64_from_u64(
                    evidence.expected_output_size,
                    "managed expected output size",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::SourceBytes,
                Expr::value(Some(i64_from_u64(
                    evidence.source_bytes,
                    "managed source bytes",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::ProcessedBytes,
                Expr::value(Some(i64_from_u64(
                    evidence.processed_bytes,
                    "managed processed bytes",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::UsageEvidence,
                Expr::value(evidence.payload),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .exec_with_returning(&txn)
            .await
            .map_err(persistence)?
            .into_iter()
            .next()
            .ok_or(ManagedError::Conflict)
            .and_then(logical_operation_from_model)?;
        txn.commit().await.map_err(persistence)?;
        Ok(updated)
    }

    async fn transition_logical_operation(
        &self,
        operation_id: Uuid,
        from: ManagedLogicalOperationState,
        to: ManagedLogicalOperationState,
        error_class: Option<&str>,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        if !valid_logical_transition(from, to) {
            return Err(ManagedError::InvalidTransition { from, to });
        }
        let now = crate::transaction::unix_time_ms();
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(to.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::LastErrorClass,
                Expr::value(error_class.map(|value| value.chars().take(128).collect::<String>())),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .filter(managed_logical_operation::Column::State.eq(from.as_str()))
            .exec_with_returning(&self.db)
            .await
            .map_err(persistence)?;
        if updated.len() != 1 {
            return Err(ManagedError::Conflict);
        }
        logical_operation_from_model(updated.into_iter().next().ok_or(ManagedError::Conflict)?)
    }

    async fn record_logical_usage_and_begin_completion(
        &self,
        operation_id: Uuid,
        evidence: ManagedUsageEvidence,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        if evidence.processed_bytes != evidence.source_bytes.max(evidence.expected_output_size) {
            return Err(ManagedError::Conflict);
        }
        let txn = self.db.begin().await.map_err(persistence)?;
        let model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let existing = logical_operation_from_model(model)?;
        if existing.evidence.as_ref() == Some(&evidence) {
            // Idempotent retry: only an operation still in `Open` advances,
            // matching the two-step `record` then `Open -> Completing` behavior.
            if existing.state != ManagedLogicalOperationState::Open {
                return Err(ManagedError::Conflict);
            }
        } else {
            if existing.evidence.is_some()
                || existing.state == ManagedLogicalOperationState::Intent
                || existing.state.terminal()
                || evidence.processed_bytes > existing.intent.max_processed_bytes
                || (existing.intent.kind == ManagedMutationKind::Put
                    && evidence.expected_output_digest.is_none())
                || (existing.intent.kind == ManagedMutationKind::Delete
                    && (evidence.expected_output_size != 0
                        || evidence.source_bytes != 0
                        || evidence.processed_bytes != 0))
            {
                return Err(ManagedError::Conflict);
            }
        }
        let now = crate::transaction::unix_time_ms();
        let updated = managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::ExpectedOutputDigest,
                Expr::value(evidence.expected_output_digest.clone()),
            )
            .col_expr(
                managed_logical_operation::Column::ExpectedOutputSize,
                Expr::value(Some(i64_from_u64(
                    evidence.expected_output_size,
                    "managed expected output size",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::SourceBytes,
                Expr::value(Some(i64_from_u64(
                    evidence.source_bytes,
                    "managed source bytes",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::ProcessedBytes,
                Expr::value(Some(i64_from_u64(
                    evidence.processed_bytes,
                    "managed processed bytes",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::UsageEvidence,
                Expr::value(evidence.payload),
            )
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::Completing.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::LastErrorClass,
                Expr::value(None::<String>),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .filter(
                managed_logical_operation::Column::State
                    .eq(ManagedLogicalOperationState::Open.as_str()),
            )
            .exec_with_returning(&txn)
            .await
            .map_err(persistence)?;
        if updated.len() != 1 {
            return Err(ManagedError::Conflict);
        }
        let operation = logical_operation_from_model(
            updated.into_iter().next().ok_or(ManagedError::Conflict)?,
        )?;
        txn.commit().await.map_err(persistence)?;
        Ok(operation)
    }

    async fn finalize_logical_put(
        &self,
        operation_id: Uuid,
        physical_lease: &PhysicalWriteLease,
        result: ExactPhysicalCommit,
        recovery_claim: Option<&ManagedRecoveryClaim>,
    ) -> Result<ManagedOperationCommit, ManagedError> {
        validate_exact_physical_commit(&result)?;
        let identity = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &identity.tenant_id).await?;
        let operation_model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let operation = logical_operation_from_model(operation_model)?;
        let now = crate::transaction::unix_time_ms();
        if operation.state == ManagedLogicalOperationState::Committed {
            let persisted_authority = managed_object_authority::Entity::find_by_id((
                operation.intent.logical.tenant_id.clone(),
                operation.intent.logical.bucket.clone(),
                operation.intent.logical.key.clone(),
            ))
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(authority_from_model)?;
            let expected_versions = exact_version_ids(&result);
            let persisted_versions = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::WriteOperationId
                        .eq(operation.intent.primary_child_operation_id),
                )
                .all(&txn)
                .await
                .map_err(persistence)?;
            let persisted_ids = persisted_versions
                .iter()
                .map(|version| version.version_id.clone())
                .collect::<HashSet<_>>();
            let persisted_targets = persisted_versions
                .iter()
                .cloned()
                .map(physical_target_from_model)
                .collect::<Result<Vec<_>, _>>()?;
            let canonical_target = persisted_targets.first().ok_or(ManagedError::Conflict)?;
            let evidence = operation.evidence.as_ref().ok_or(ManagedError::Conflict)?;
            let recipe = operation
                .intent
                .publication_recipe
                .as_ref()
                .ok_or(ManagedError::Conflict)?;
            let committed_authority_version = operation
                .committed_authority_version
                .ok_or(ManagedError::Conflict)?;
            let original_authority_matches = persisted_authority.generation
                == operation.intent.generation
                && persisted_authority.digest
                    == evidence
                        .expected_output_digest
                        .clone()
                        .ok_or(ManagedError::Conflict)?
                && persisted_authority.size == evidence.expected_output_size
                && persisted_authority.metadata == recipe.metadata
                && persisted_authority.placement_version == recipe.placement_version
                && persisted_authority.primary_backend_id == recipe.primary_backend_id
                && persisted_authority.primary_version_id == result.selected_version_id
                && persisted_authority.replica_backend_id == recipe.replica_backend_id
                && persisted_authority.primary_status == recipe.primary_status
                && persisted_authority.replica_status == recipe.replica_status
                && !persisted_authority.tombstone;
            if persisted_authority.logical != operation.intent.logical
                || committed_authority_version
                    != operation
                        .intent
                        .expected_authority_cas
                        .unwrap_or(0)
                        .saturating_add(1)
                || persisted_authority.cas_version < committed_authority_version
                || (persisted_authority.cas_version == committed_authority_version
                    && !original_authority_matches)
                || persisted_ids != expected_versions.into_iter().collect()
                || persisted_versions
                    .iter()
                    .any(|version| version.state != "LIVE")
                || persisted_targets.iter().any(|target| {
                    target.tenant_id != operation.intent.logical.tenant_id
                        || target.namespace_epoch != operation.intent.fence.namespace_epoch
                        || target.backend_id != operation.intent.backend_id
                        || target.provider_bucket != operation.intent.provider_bucket
                        || target.physical_key != operation.intent.physical_key
                        || target.storage_identity != canonical_target.storage_identity
                        || target.credential_epoch != canonical_target.credential_epoch
                        || target.versioning_mode != canonical_target.versioning_mode
                        || target.versioning_capability != canonical_target.versioning_capability
                })
                || operation.committed_physical_bytes
                    != physical_allocation(
                        evidence.expected_output_size,
                        persisted_versions.len() as u64,
                    )?
            {
                return Err(ManagedError::Conflict);
            }
            let usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
            txn.commit().await.map_err(persistence)?;
            return Ok(ManagedOperationCommit {
                operation,
                authority: persisted_authority,
                usage: workspace_usage_from_model(usage)?,
            });
        }
        validate_recovery_authority(&operation, recovery_claim, now)?;
        if operation.intent.kind != ManagedMutationKind::Put
            || !matches!(
                operation.state,
                ManagedLogicalOperationState::Completing
                    | ManagedLogicalOperationState::CommitUnknown
                    | ManagedLogicalOperationState::RecoveryBlocked
            )
            || (operation.state == ManagedLogicalOperationState::RecoveryBlocked
                && recovery_claim.is_none())
        {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::Committed,
            });
        }
        let evidence = operation.evidence.clone().ok_or(ManagedError::Conflict)?;
        let recipe = operation
            .intent
            .publication_recipe
            .clone()
            .ok_or(ManagedError::Conflict)?;
        if recipe.version != MANAGED_PUBLICATION_RECIPE_VERSION
            || recipe.primary_backend_id != operation.intent.backend_id
        {
            return Err(ManagedError::Conflict);
        }
        if namespace.state != "ACTIVE"
            || u64_from_i64(namespace.epoch, "managed namespace epoch")?
                != operation.intent.fence.namespace_epoch
            || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                != operation.intent.fence.routing_epoch
        {
            return Err(ManagedError::RecoveryBlocked("namespace_fence_changed"));
        }
        let mut usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
        let existing_model = managed_object_authority::Entity::find_by_id((
            operation.intent.logical.tenant_id.clone(),
            operation.intent.logical.bucket.clone(),
            operation.intent.logical.key.clone(),
        ))
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?;
        let existing = existing_model
            .clone()
            .map(authority_from_model)
            .transpose()?;
        if physical_lease.intent_id != operation.intent.primary_child_operation_id {
            return Err(ManagedError::RecoveryBlocked("physical_intent_mismatch"));
        }
        let intent = managed_physical_write_intent::Entity::find_by_id(
            operation.intent.primary_child_operation_id,
        )
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?
        .ok_or(ManagedError::RecoveryBlocked("missing_physical_intent"))?;
        if intent.intent_id != operation.intent.primary_child_operation_id
            || intent.tenant_id != operation.intent.logical.tenant_id
            || intent.backend_id != operation.intent.backend_id
            || intent.provider_bucket != operation.intent.provider_bucket
            || intent.physical_key != operation.intent.physical_key
            || intent.epoch
                != i64_from_u64(
                    operation.intent.fence.namespace_epoch,
                    "managed namespace epoch",
                )?
        {
            return Err(ManagedError::RecoveryBlocked("physical_intent_mismatch"));
        }
        if intent.lease_owner != physical_lease.owner
            || intent.lease_token != physical_lease.token
            || intent.lease_expires_at_ms <= crate::transaction::unix_time_ms()
            || operation
                .recovery_owner
                .as_ref()
                .is_some_and(|owner| owner != &physical_lease.owner)
        {
            return Err(ManagedError::Conflict);
        }
        let durable_intent = durable_physical_intent_from_model(intent.clone())?;
        validate_physical_commit_versioning(&durable_intent.intent, &result)?;
        let child =
            object_operation::Entity::find_by_id(operation.intent.primary_child_operation_id)
                .lock(LockType::Update)
                .one(&txn)
                .await
                .map_err(persistence)?;
        validate_durable_child_commit(child.as_ref(), &operation, &result)?;
        let expected_targets = expected_physical_targets(
            &durable_intent.intent,
            physical_lease.namespace_epoch,
            &result,
        );
        for version_id in exact_version_ids(&result) {
            managed_physical_object_version::Entity::insert(
                managed_physical_object_version::ActiveModel {
                    tenant_id: Set(intent.tenant_id.clone()),
                    backend_id: Set(intent.backend_id.clone()),
                    provider_kind: Set(intent.provider_kind.clone()),
                    provider_instance_id: Set(intent.provider_instance_id.clone()),
                    provider_account_id: Set(intent.provider_account_id.clone()),
                    canonical_endpoint: Set(intent.canonical_endpoint.clone()),
                    provider_region: Set(intent.provider_region.clone()),
                    credential_epoch: Set(intent.credential_epoch),
                    provider_bucket: Set(intent.provider_bucket.clone()),
                    physical_key: Set(intent.physical_key.clone()),
                    versioning_mode: Set(intent.versioning_mode.clone()),
                    versioning_capability: Set(intent.versioning_capability.clone()),
                    write_operation_id: Set(intent.intent_id),
                    version_id: Set(version_id),
                    epoch: Set(intent.epoch),
                    state: Set("LIVE".to_string()),
                    purge_operation_id: Set(None),
                    last_error: Set(None),
                    created_at_ms: Set(now),
                    updated_at_ms: Set(now),
                },
            )
            .on_conflict(
                OnConflict::columns([
                    managed_physical_object_version::Column::TenantId,
                    managed_physical_object_version::Column::BackendId,
                    managed_physical_object_version::Column::ProviderBucket,
                    managed_physical_object_version::Column::PhysicalKey,
                    managed_physical_object_version::Column::VersionId,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec_without_returning(&txn)
            .await
            .map_err(persistence)?;
        }
        let child_version_models = managed_physical_object_version::Entity::find()
            .filter(
                managed_physical_object_version::Column::WriteOperationId
                    .eq(operation.intent.primary_child_operation_id),
            )
            .filter(
                managed_physical_object_version::Column::TenantId
                    .eq(&operation.intent.logical.tenant_id),
            )
            .filter(
                managed_physical_object_version::Column::BackendId.eq(&operation.intent.backend_id),
            )
            .filter(
                managed_physical_object_version::Column::ProviderBucket
                    .eq(&operation.intent.provider_bucket),
            )
            .filter(
                managed_physical_object_version::Column::PhysicalKey
                    .eq(&operation.intent.physical_key),
            )
            .all(&txn)
            .await
            .map_err(persistence)?;
        let child_versions = child_version_models
            .iter()
            .cloned()
            .map(physical_target_from_model)
            .collect::<Result<Vec<_>, _>>()?;
        let derived_physical_allocation =
            physical_allocation(evidence.expected_output_size, child_versions.len() as u64)?;
        if child_version_models
            .iter()
            .any(|version| version.state != "LIVE")
            || child_versions.len() != expected_targets.len()
            || expected_targets
                .iter()
                .any(|expected| !child_versions.contains(expected))
            || derived_physical_allocation > operation.reserved_physical_bytes
        {
            return Err(ManagedError::RecoveryBlocked("physical_version_mismatch"));
        }
        if existing.as_ref().map(|value| value.cas_version)
            != operation.intent.expected_authority_cas
            || existing
                .as_ref()
                .filter(|value| !value.tombstone)
                .map_or(0, |value| value.size)
                != operation.intent.prior_logical_size
        {
            return Err(ManagedError::RecoveryBlocked("authority_fence_changed"));
        }
        if usage.active_operation_id != Some(operation_id)
            || usage.reserved_bytes
                < i64_from_u64(
                    operation.reserved_physical_bytes,
                    "managed physical reservation",
                )?
        {
            return Err(ManagedError::Conflict);
        }
        let prior_size = i64_from_u64(operation.intent.prior_logical_size, "managed prior size")?;
        let output_size = i64_from_u64(evidence.expected_output_size, "managed output size")?;
        let visible = usage
            .visible_logical_bytes
            .checked_sub(prior_size)
            .and_then(|value| value.checked_add(output_size))
            .ok_or(ManagedError::QuotaExceeded)?;
        if visible > usage.visible_limit_bytes {
            return Err(ManagedError::QuotaExceeded);
        }
        let reserved = i64_from_u64(
            operation.reserved_physical_bytes,
            "managed physical reservation",
        )?;
        let allocated = i64_from_u64(derived_physical_allocation, "managed physical allocation")?;
        let mut authority = ObjectAuthority {
            logical: operation.intent.logical.clone(),
            generation: operation.intent.generation,
            digest: evidence
                .expected_output_digest
                .clone()
                .ok_or(ManagedError::Conflict)?,
            size: evidence.expected_output_size,
            metadata: recipe.metadata,
            placement_version: recipe.placement_version,
            primary_backend_id: recipe.primary_backend_id,
            primary_version_id: result.selected_version_id.clone(),
            replica_backend_id: recipe.replica_backend_id,
            primary_status: recipe.primary_status,
            replica_status: recipe.replica_status,
            tombstone: false,
            cas_version: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        authority.cas_version = operation
            .intent
            .expected_authority_cas
            .unwrap_or(0)
            .saturating_add(1);
        authority.created_at_ms = existing.as_ref().map_or(now, |value| value.created_at_ms);
        authority.updated_at_ms = now;
        match existing_model {
            None => {
                authority_active(&authority)?
                    .insert(&txn)
                    .await
                    .map_err(|_| ManagedError::Conflict)?;
            }
            Some(existing_model) => {
                let result = managed_object_authority::Entity::update_many()
                    .set(authority_active(&authority)?)
                    .filter(
                        managed_object_authority::Column::TenantId
                            .eq(&operation.intent.logical.tenant_id),
                    )
                    .filter(
                        managed_object_authority::Column::Bucket
                            .eq(&operation.intent.logical.bucket),
                    )
                    .filter(
                        managed_object_authority::Column::LogicalKey
                            .eq(&operation.intent.logical.key),
                    )
                    .filter(
                        managed_object_authority::Column::CasVersion.eq(existing_model.cas_version),
                    )
                    .exec(&txn)
                    .await
                    .map_err(persistence)?;
                if result.rows_affected != 1 {
                    return Err(ManagedError::Conflict);
                }
            }
        }
        for mut repair in publication_repairs(&authority) {
            repair.namespace_epoch = operation.intent.fence.namespace_epoch;
            insert_repair(&txn, repair).await?;
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                let targets = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId
                            .eq(&repair.logical.tenant_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::BackendId
                            .eq(&repair.target_backend_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::PhysicalKey
                            .eq(&repair.physical_key),
                    )
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if targets > 0 {
                    repair.namespace_epoch = operation.intent.fence.namespace_epoch;
                    insert_repair(&txn, repair).await?;
                }
            }
        }
        usage.visible_logical_bytes = visible;
        usage.physical_allocated_bytes = usage
            .physical_allocated_bytes
            .checked_add(allocated)
            .ok_or(ManagedError::QuotaExceeded)?;
        usage.reserved_bytes = usage
            .reserved_bytes
            .checked_sub(reserved)
            .ok_or(ManagedError::Conflict)?;
        usage.active_operation_id = None;
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::VisibleLogicalBytes,
                Expr::value(usage.visible_logical_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::PhysicalAllocatedBytes,
                Expr::value(usage.physical_allocated_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::ReservedBytes,
                Expr::value(usage.reserved_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(
                managed_workspace_usage::Column::TenantId.eq(&operation.intent.logical.tenant_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::Committed.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::CommittedPhysicalBytes,
                Expr::value(allocated),
            )
            .col_expr(
                managed_logical_operation::Column::CommittedAuthorityVersion,
                Expr::value(Some(i64_from_u64(
                    authority.cas_version,
                    "managed authority CAS",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .col_expr(
                managed_logical_operation::Column::CommittedAtMs,
                Expr::value(Some(now)),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        let committed = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(logical_operation_from_model)?;
        let deleted = managed_physical_write_intent::Entity::delete_many()
            .filter(managed_physical_write_intent::Column::IntentId.eq(physical_lease.intent_id))
            .filter(managed_physical_write_intent::Column::LeaseOwner.eq(&physical_lease.owner))
            .filter(managed_physical_write_intent::Column::LeaseToken.eq(physical_lease.token))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if deleted.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        txn.commit().await.map_err(persistence)?;
        Ok(ManagedOperationCommit {
            operation: committed,
            authority,
            usage: workspace_usage_from_model(usage)?,
        })
    }

    async fn commit_logical_delete(
        &self,
        operation_id: Uuid,
        placement: &Placement,
    ) -> Result<ManagedOperationCommit, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let operation_model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let operation = logical_operation_from_model(operation_model)?;
        if operation.state == ManagedLogicalOperationState::Committed {
            let authority = managed_object_authority::Entity::find_by_id((
                operation.intent.logical.tenant_id.clone(),
                operation.intent.logical.bucket.clone(),
                operation.intent.logical.key.clone(),
            ))
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(authority_from_model)?;
            if !authority.tombstone || authority.generation != operation.intent.generation {
                return Err(ManagedError::Conflict);
            }
            let usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
            txn.commit().await.map_err(persistence)?;
            return Ok(ManagedOperationCommit {
                operation,
                authority,
                usage: workspace_usage_from_model(usage)?,
            });
        }
        if operation.intent.kind != ManagedMutationKind::Delete
            || operation.reserved_physical_bytes != 0
            || operation.evidence.as_ref().is_none_or(|evidence| {
                evidence.expected_output_size != 0
                    || evidence.source_bytes != 0
                    || evidence.processed_bytes != 0
            })
            || !matches!(
                operation.state,
                ManagedLogicalOperationState::Completing
                    | ManagedLogicalOperationState::CommitUnknown
            )
        {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::Committed,
            });
        }
        let namespace = locked_namespace(&txn, &operation.intent.logical.tenant_id).await?;
        if namespace.state != "ACTIVE"
            || u64_from_i64(namespace.epoch, "managed namespace epoch")?
                != operation.intent.fence.namespace_epoch
            || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                != operation.intent.fence.routing_epoch
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let existing_model = managed_object_authority::Entity::find_by_id((
            operation.intent.logical.tenant_id.clone(),
            operation.intent.logical.bucket.clone(),
            operation.intent.logical.key.clone(),
        ))
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?;
        let existing = existing_model
            .clone()
            .map(authority_from_model)
            .transpose()?;
        if existing.as_ref().map(|value| value.cas_version)
            != operation.intent.expected_authority_cas
            || existing
                .as_ref()
                .filter(|value| !value.tombstone)
                .map_or(0, |value| value.size)
                != operation.intent.prior_logical_size
        {
            return Err(ManagedError::Conflict);
        }
        let mut usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
        if usage.active_operation_id != Some(operation_id) {
            return Err(ManagedError::Conflict);
        }
        let prior_size = i64_from_u64(operation.intent.prior_logical_size, "managed prior size")?;
        let visible = usage
            .visible_logical_bytes
            .checked_sub(prior_size)
            .ok_or(ManagedError::Conflict)?;
        let now = crate::transaction::unix_time_ms();
        let authority = ObjectAuthority {
            logical: operation.intent.logical.clone(),
            generation: operation.intent.generation,
            digest: String::new(),
            size: 0,
            metadata: BTreeMap::new(),
            placement_version: placement.version,
            primary_backend_id: placement.primary_backend_id.clone(),
            primary_version_id: None,
            replica_backend_id: placement.replica_backend_id.clone(),
            primary_status: CopyStatus::Absent,
            replica_status: CopyStatus::Absent,
            tombstone: true,
            cas_version: operation
                .intent
                .expected_authority_cas
                .unwrap_or(0)
                .saturating_add(1),
            created_at_ms: existing.as_ref().map_or(now, |value| value.created_at_ms),
            updated_at_ms: now,
        };
        match existing_model {
            None => {
                authority_active(&authority)?
                    .insert(&txn)
                    .await
                    .map_err(|_| ManagedError::Conflict)?;
            }
            Some(existing_model) => {
                let result = managed_object_authority::Entity::update_many()
                    .set(authority_active(&authority)?)
                    .filter(
                        managed_object_authority::Column::TenantId
                            .eq(&operation.intent.logical.tenant_id),
                    )
                    .filter(
                        managed_object_authority::Column::Bucket
                            .eq(&operation.intent.logical.bucket),
                    )
                    .filter(
                        managed_object_authority::Column::LogicalKey
                            .eq(&operation.intent.logical.key),
                    )
                    .filter(
                        managed_object_authority::Column::CasVersion.eq(existing_model.cas_version),
                    )
                    .exec(&txn)
                    .await
                    .map_err(persistence)?;
                if result.rows_affected != 1 {
                    return Err(ManagedError::Conflict);
                }
            }
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                let targets = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId
                            .eq(&repair.logical.tenant_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::BackendId
                            .eq(&repair.target_backend_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::PhysicalKey
                            .eq(&repair.physical_key),
                    )
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if targets > 0 {
                    repair.namespace_epoch = operation.intent.fence.namespace_epoch;
                    insert_repair(&txn, repair).await?;
                }
            }
        }
        usage.visible_logical_bytes = visible;
        usage.active_operation_id = None;
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::VisibleLogicalBytes,
                Expr::value(visible),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(
                managed_workspace_usage::Column::TenantId.eq(&operation.intent.logical.tenant_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::Committed.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::CommittedAuthorityVersion,
                Expr::value(Some(i64_from_u64(
                    authority.cas_version,
                    "managed authority CAS",
                )?)),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .col_expr(
                managed_logical_operation::Column::CommittedAtMs,
                Expr::value(Some(now)),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        let committed = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(logical_operation_from_model)?;
        txn.commit().await.map_err(persistence)?;
        Ok(ManagedOperationCommit {
            operation: committed,
            authority,
            usage: workspace_usage_from_model(usage)?,
        })
    }

    async fn commit_atomic_logical_delete(
        &self,
        request: ManagedDeleteRequest,
    ) -> Result<ManagedOperationCommit, ManagedDeleteError> {
        if request.logical.tenant_id.is_empty()
            || request.logical.bucket.is_empty()
            || request.placement.version == 0
            || request.placement.primary_backend_id.is_empty()
            || request.provider_bucket.is_empty()
            || request.rate_version <= 0
            || request.occurred_at_micros < 0
        {
            return Err(ManagedError::Conflict.into());
        }
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &request.logical.tenant_id).await?;
        if namespace.state != "ACTIVE" {
            return Err(ManagedError::NamespaceFenced.into());
        }
        let fence = ManagedRouteFence {
            namespace_epoch: u64_from_i64(namespace.epoch, "managed namespace epoch")?,
            routing_epoch: u64_from_i64(namespace.routing_epoch, "managed routing epoch")?,
        };
        let existing_operation =
            managed_logical_operation::Entity::find_by_id(request.operation_id)
                .lock(LockType::Update)
                .one(&txn)
                .await
                .map_err(persistence)?
                .map(logical_operation_from_model)
                .transpose()?;
        let mut usage = locked_workspace_usage(&txn, &request.logical.tenant_id).await?;
        let existing_model = managed_object_authority::Entity::find_by_id((
            request.logical.tenant_id.clone(),
            request.logical.bucket.clone(),
            request.logical.key.clone(),
        ))
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?;
        let existing = existing_model
            .clone()
            .map(authority_from_model)
            .transpose()?;
        let generation = existing
            .as_ref()
            .filter(|authority| authority.tombstone)
            .map_or_else(
                || Uuid::new_v5(&Uuid::NAMESPACE_URL, request.operation_id.as_bytes()),
                |authority| authority.generation,
            );
        let prior_logical_size = existing
            .as_ref()
            .filter(|authority| !authority.tombstone)
            .map_or(0, |authority| authority.size);
        let recipe = ManagedPublicationRecipe {
            version: MANAGED_PUBLICATION_RECIPE_VERSION,
            placement_version: request.placement.version,
            primary_backend_id: request.placement.primary_backend_id.clone(),
            replica_backend_id: request.placement.replica_backend_id.clone(),
            metadata: BTreeMap::new(),
            primary_status: CopyStatus::Absent,
            replica_status: CopyStatus::Absent,
        };
        let intent = ManagedLogicalOperationIntent {
            operation_id: request.operation_id,
            receipt_id: request.receipt_id,
            logical: request.logical.clone(),
            kind: ManagedMutationKind::Delete,
            generation,
            fence,
            expected_authority_cas: existing.as_ref().map(|authority| authority.cas_version),
            prior_logical_size,
            primary_child_operation_id: Uuid::new_v5(
                &Uuid::NAMESPACE_OID,
                request.operation_id.as_bytes(),
            ),
            backend_id: request.placement.primary_backend_id.clone(),
            provider_bucket: request.provider_bucket.clone(),
            physical_key: generation_physical_key(&request.logical, generation),
            occurred_at_ms: request.occurred_at_micros.div_euclid(1_000),
            rate_version: request.rate_version,
            route: UsageRoute::DeleteObject,
            request_kind: RequestKind::Write,
            max_processed_bytes: request.max_processed_bytes,
            publication_recipe: Some(recipe),
        };
        if let Some(operation) = existing_operation {
            if !delete_request_matches_operation(&request, &operation)
                || operation.state != ManagedLogicalOperationState::Committed
            {
                return Err(ManagedError::Conflict.into());
            }
            let authority = committed_delete_replay_authority(&operation, existing)?;
            txn.commit()
                .await
                .map_err(|error| ManagedDeleteError::CommitUnknown(persistence(error)))?;
            return Ok(ManagedOperationCommit {
                operation,
                authority,
                usage: workspace_usage_from_model(usage)?,
            });
        }
        if usage.active_operation_id.is_some() {
            return Err(ManagedError::MutationInProgress.into());
        }
        let now = crate::transaction::unix_time_ms();
        let authority = if existing
            .as_ref()
            .is_some_and(|authority| authority.tombstone)
        {
            existing.clone().ok_or(ManagedError::Conflict)?
        } else {
            let authority = ObjectAuthority {
                logical: request.logical.clone(),
                generation,
                digest: String::new(),
                size: 0,
                metadata: BTreeMap::new(),
                placement_version: request.placement.version,
                primary_backend_id: request.placement.primary_backend_id,
                primary_version_id: None,
                replica_backend_id: request.placement.replica_backend_id,
                primary_status: CopyStatus::Absent,
                replica_status: CopyStatus::Absent,
                tombstone: true,
                cas_version: existing
                    .as_ref()
                    .map_or(1, |authority| authority.cas_version.saturating_add(1)),
                created_at_ms: existing
                    .as_ref()
                    .map_or(now, |authority| authority.created_at_ms),
                updated_at_ms: now,
            };
            match existing_model {
                None => {
                    authority_active(&authority)?
                        .insert(&txn)
                        .await
                        .map_err(persistence)?;
                }
                Some(model) => {
                    let updated = managed_object_authority::Entity::update_many()
                        .set(authority_active(&authority)?)
                        .filter(
                            managed_object_authority::Column::TenantId
                                .eq(&request.logical.tenant_id),
                        )
                        .filter(
                            managed_object_authority::Column::Bucket.eq(&request.logical.bucket),
                        )
                        .filter(
                            managed_object_authority::Column::LogicalKey.eq(&request.logical.key),
                        )
                        .filter(managed_object_authority::Column::CasVersion.eq(model.cas_version))
                        .exec(&txn)
                        .await
                        .map_err(persistence)?;
                    if updated.rows_affected != 1 {
                        return Err(ManagedError::Conflict.into());
                    }
                }
            }
            authority
        };
        if let Some(previous) = existing.filter(|authority| !authority.tombstone) {
            for mut repair in cleanup_repairs(&previous) {
                let targets = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId
                            .eq(&repair.logical.tenant_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::BackendId
                            .eq(&repair.target_backend_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::PhysicalKey
                            .eq(&repair.physical_key),
                    )
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if targets > 0 {
                    repair.namespace_epoch = fence.namespace_epoch;
                    insert_repair(&txn, repair).await?;
                }
            }
        }
        let prior = i64_from_u64(prior_logical_size, "managed prior size")?;
        usage.visible_logical_bytes = usage
            .visible_logical_bytes
            .checked_sub(prior)
            .ok_or(ManagedError::Conflict)?;
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::VisibleLogicalBytes,
                Expr::value(usage.visible_logical_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_workspace_usage::Column::TenantId.eq(&request.logical.tenant_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        let evidence = ManagedUsageEvidence {
            expected_output_digest: None,
            expected_output_size: 0,
            source_bytes: 0,
            processed_bytes: 0,
            payload: serde_json::json!({
                "occurred_at_micros": request.occurred_at_micros,
            }),
        };
        let mut active = logical_operation_active(&intent, now)?;
        active.expected_output_size = Set(Some(0));
        active.source_bytes = Set(Some(0));
        active.processed_bytes = Set(Some(0));
        active.usage_evidence = Set(evidence.payload.clone());
        active.state = Set(ManagedLogicalOperationState::Committed.as_str().to_string());
        active.committed_authority_version = Set(Some(i64_from_u64(
            authority.cas_version,
            "managed authority CAS",
        )?));
        active.committed_at_ms = Set(Some(now));
        managed_logical_operation::Entity::insert(active)
            .exec_without_returning(&txn)
            .await
            .map_err(persistence)?;
        let operation = ManagedLogicalOperation {
            intent,
            evidence: Some(evidence),
            reserved_physical_bytes: 0,
            committed_physical_bytes: 0,
            released_physical_bytes: 0,
            state: ManagedLogicalOperationState::Committed,
            committed_authority_version: Some(authority.cas_version),
            settlement_state: ManagedSettlementState::Pending,
            last_error_class: None,
            recovery_owner: None,
            recovery_token: None,
            recovery_expires_at_ms: None,
            created_at_ms: now,
            updated_at_ms: now,
            committed_at_ms: Some(now),
            aborted_at_ms: None,
        };
        txn.commit()
            .await
            .map_err(|error| ManagedDeleteError::CommitUnknown(persistence(error)))?;
        Ok(ManagedOperationCommit {
            operation,
            authority,
            usage: workspace_usage_from_model(usage)?,
        })
    }

    async fn prove_logical_abort(
        &self,
        operation_id: Uuid,
        error_class: &str,
        physical: Option<ManagedProvenPhysicalAllocation>,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let operation = logical_operation_from_model(model)?;
        if operation.state == ManagedLogicalOperationState::ProvenAborted {
            txn.commit().await.map_err(persistence)?;
            return Ok(operation);
        }
        if operation.state == ManagedLogicalOperationState::Committed {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::ProvenAborted,
            });
        }
        let namespace = locked_namespace(&txn, &operation.intent.logical.tenant_id).await?;
        if u64_from_i64(namespace.epoch, "managed namespace epoch")?
            != operation.intent.fence.namespace_epoch
        {
            return Err(ManagedError::Conflict);
        }
        let child_versions = managed_physical_object_version::Entity::find()
            .filter(
                managed_physical_object_version::Column::WriteOperationId
                    .eq(operation.intent.primary_child_operation_id),
            )
            .filter(
                managed_physical_object_version::Column::TenantId
                    .eq(&operation.intent.logical.tenant_id),
            )
            .filter(
                managed_physical_object_version::Column::BackendId.eq(&operation.intent.backend_id),
            )
            .filter(
                managed_physical_object_version::Column::ProviderBucket
                    .eq(&operation.intent.provider_bucket),
            )
            .filter(
                managed_physical_object_version::Column::PhysicalKey
                    .eq(&operation.intent.physical_key),
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
        let allocated = match physical {
            None => {
                if child_versions != 0 {
                    return Err(ManagedError::Conflict);
                }
                0
            }
            Some(physical) => {
                let evidence = operation.evidence.as_ref().ok_or(ManagedError::Conflict)?;
                let derived = physical_allocation(physical.authority.size, child_versions)?;
                if child_versions == 0
                    || physical.authority.logical != operation.intent.logical
                    || physical.authority.generation != operation.intent.generation
                    || physical.authority.primary_backend_id != operation.intent.backend_id
                    || physical.authority.tombstone
                    || evidence.expected_output_size != physical.authority.size
                    || evidence.expected_output_digest.as_deref()
                        != Some(physical.authority.digest.as_str())
                    || physical.allocated_bytes != derived
                    || derived > operation.reserved_physical_bytes
                {
                    return Err(ManagedError::Conflict);
                }
                for mut repair in cleanup_repairs(&physical.authority) {
                    let targets = managed_physical_object_version::Entity::find()
                        .filter(
                            managed_physical_object_version::Column::TenantId
                                .eq(&repair.logical.tenant_id),
                        )
                        .filter(
                            managed_physical_object_version::Column::BackendId
                                .eq(&repair.target_backend_id),
                        )
                        .filter(
                            managed_physical_object_version::Column::PhysicalKey
                                .eq(&repair.physical_key),
                        )
                        .count(&txn)
                        .await
                        .map_err(persistence)?;
                    if targets > 0 {
                        repair.namespace_epoch = operation.intent.fence.namespace_epoch;
                        insert_repair(&txn, repair).await?;
                    }
                }
                derived
            }
        };
        let mut usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
        if operation.state != ManagedLogicalOperationState::Intent
            && usage.active_operation_id != Some(operation_id)
        {
            return Err(ManagedError::Conflict);
        }
        let reserved = i64_from_u64(
            operation.reserved_physical_bytes,
            "managed physical reservation",
        )?;
        let allocated = i64_from_u64(allocated, "managed physical allocation")?;
        usage.reserved_bytes = usage
            .reserved_bytes
            .checked_sub(reserved)
            .ok_or(ManagedError::Conflict)?;
        usage.physical_allocated_bytes = usage
            .physical_allocated_bytes
            .checked_add(allocated)
            .ok_or(ManagedError::QuotaExceeded)?;
        if usage.active_operation_id == Some(operation_id) {
            usage.active_operation_id = None;
        }
        let now = crate::transaction::unix_time_ms();
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::ReservedBytes,
                Expr::value(usage.reserved_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::PhysicalAllocatedBytes,
                Expr::value(usage.physical_allocated_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(usage.active_operation_id),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(
                managed_workspace_usage::Column::TenantId.eq(&operation.intent.logical.tenant_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::ProvenAborted.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::CommittedPhysicalBytes,
                Expr::value(allocated),
            )
            .col_expr(
                managed_logical_operation::Column::SettlementState,
                Expr::value(ManagedSettlementState::Released.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::LastErrorClass,
                Expr::value(Some(error_class.chars().take(128).collect::<String>())),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .col_expr(
                managed_logical_operation::Column::AbortedAtMs,
                Expr::value(Some(now)),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        let aborted = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(logical_operation_from_model)?;
        txn.commit().await.map_err(persistence)?;
        Ok(aborted)
    }

    async fn abort_logical_put(
        &self,
        operation_id: Uuid,
        physical_lease: Option<&PhysicalWriteLease>,
        proof: LogicalAbortProof,
        error_class: &str,
        recovery_claim: Option<&ManagedRecoveryClaim>,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        let identity = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        // All managed mutation transactions lock namespace -> logical -> usage
        // and current authority/physical intent last.
        let namespace = locked_namespace(&txn, &identity.tenant_id).await?;
        let model = managed_logical_operation::Entity::find_by_id(operation_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let operation = logical_operation_from_model(model)?;
        if operation.state == ManagedLogicalOperationState::ProvenAborted {
            txn.commit().await.map_err(persistence)?;
            return Ok(operation);
        }
        let now = crate::transaction::unix_time_ms();
        validate_recovery_authority(&operation, recovery_claim, now)?;
        if operation.intent.kind != ManagedMutationKind::Put
            || operation.state == ManagedLogicalOperationState::Committed
        {
            return Err(ManagedError::Conflict);
        }
        if namespace.epoch
            != i64_from_u64(
                operation.intent.fence.namespace_epoch,
                "managed namespace epoch",
            )?
        {
            return Err(ManagedError::RecoveryBlocked("namespace_fence_changed"));
        }
        let mut usage = locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
        let intent = managed_physical_write_intent::Entity::find_by_id(
            operation.intent.primary_child_operation_id,
        )
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?;
        let child_versions = managed_physical_object_version::Entity::find()
            .filter(
                managed_physical_object_version::Column::WriteOperationId
                    .eq(operation.intent.primary_child_operation_id),
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
        if child_versions != 0 {
            return Err(ManagedError::Conflict);
        }
        let child_journal =
            object_operation::Entity::find_by_id(operation.intent.primary_child_operation_id)
                .lock(LockType::Update)
                .one(&txn)
                .await
                .map_err(persistence)?;
        let child_proves_absence = child_journal.as_ref().is_some_and(|child| {
            child.state == "PROVEN_ABORTED"
                && child.exact_absence_observed_at_ms.is_some()
                && child.tenant_id.as_deref() == Some(operation.intent.logical.tenant_id.as_str())
                && child.namespace_epoch
                    == i64::try_from(operation.intent.fence.namespace_epoch).ok()
                && child.backend_id == operation.intent.backend_id
                && child.bucket == operation.intent.provider_bucket
                && child.logical_key == operation.intent.logical.object_key()
                && child.physical_key == operation.intent.physical_key
                && operation.evidence.as_ref().is_none_or(|evidence| {
                    child.expected_digest == evidence.expected_output_digest
                        && child.expected_size == i64::try_from(evidence.expected_output_size).ok()
                })
        });
        match (
            proof,
            physical_lease,
            intent.as_ref(),
            child_journal.as_ref(),
        ) {
            (LogicalAbortProof::NoChildStarted, None, None, None)
                if matches!(
                    operation.state,
                    ManagedLogicalOperationState::Intent | ManagedLogicalOperationState::Open
                ) => {}
            (LogicalAbortProof::NoChildStarted, Some(lease), Some(intent), None)
                if lease.intent_id == operation.intent.primary_child_operation_id
                    && intent.lease_owner == lease.owner
                    && intent.lease_token == lease.token
                    && intent.lease_expires_at_ms > now
                    && lease.namespace_epoch == operation.intent.fence.namespace_epoch => {}
            (LogicalAbortProof::ChildProvenAborted, Some(lease), Some(intent), Some(_))
                if child_proves_absence
                    && lease.intent_id == operation.intent.primary_child_operation_id
                    && intent.lease_owner == lease.owner
                    && intent.lease_token == lease.token
                    && intent.lease_expires_at_ms > now
                    && lease.namespace_epoch == operation.intent.fence.namespace_epoch => {}
            _ => return Err(ManagedError::Conflict),
        }
        if operation.state != ManagedLogicalOperationState::Intent
            && usage.active_operation_id != Some(operation_id)
        {
            return Err(ManagedError::Conflict);
        }
        let reserved = i64_from_u64(
            operation.reserved_physical_bytes,
            "managed physical reservation",
        )?;
        usage.reserved_bytes = usage
            .reserved_bytes
            .checked_sub(reserved)
            .ok_or(ManagedError::Conflict)?;
        if usage.active_operation_id == Some(operation_id) {
            usage.active_operation_id = None;
        }
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        managed_workspace_usage::Entity::update_many()
            .col_expr(
                managed_workspace_usage::Column::ReservedBytes,
                Expr::value(usage.reserved_bytes),
            )
            .col_expr(
                managed_workspace_usage::Column::ActiveOperationId,
                Expr::value(usage.active_operation_id),
            )
            .col_expr(
                managed_workspace_usage::Column::Version,
                Expr::value(usage.version),
            )
            .col_expr(
                managed_workspace_usage::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(
                managed_workspace_usage::Column::TenantId.eq(&operation.intent.logical.tenant_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_logical_operation::Entity::update_many()
            .col_expr(
                managed_logical_operation::Column::State,
                Expr::value(ManagedLogicalOperationState::ProvenAborted.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::SettlementState,
                Expr::value(ManagedSettlementState::Released.as_str()),
            )
            .col_expr(
                managed_logical_operation::Column::LastErrorClass,
                Expr::value(Some(error_class.chars().take(128).collect::<String>())),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_logical_operation::Column::RecoveryExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                managed_logical_operation::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .col_expr(
                managed_logical_operation::Column::AbortedAtMs,
                Expr::value(Some(now)),
            )
            .filter(managed_logical_operation::Column::OperationId.eq(operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if intent.is_some() {
            let deleted = managed_physical_write_intent::Entity::delete_by_id(
                operation.intent.primary_child_operation_id,
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
            if deleted.rows_affected != 1 {
                return Err(ManagedError::Conflict);
            }
        }
        let aborted = managed_logical_operation::Entity::find_by_id(operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)
            .and_then(logical_operation_from_model)?;
        txn.commit().await.map_err(persistence)?;
        Ok(aborted)
    }

    async fn workspace_usage(
        &self,
        tenant_id: &str,
    ) -> Result<Option<ManagedWorkspaceUsage>, ManagedError> {
        managed_workspace_usage::Entity::find_by_id(tenant_id.to_string())
            .one(&self.db)
            .await
            .map_err(persistence)?
            .map(workspace_usage_from_model)
            .transpose()
    }

    async fn list_authority(
        &self,
        query: AuthorityListQuery,
    ) -> Result<AuthorityListPage, ManagedError> {
        if query.max_keys > MANAGED_AUTHORITY_LIST_MAX_KEYS {
            return Err(ManagedError::Conflict);
        }
        if query.max_keys == 0 {
            return Ok(AuthorityListPage {
                objects: Vec::new(),
                next_after: None,
            });
        }
        self.assert_namespace_active(&query.tenant_id).await?;
        let mut select = managed_object_authority::Entity::find()
            .filter(managed_object_authority::Column::TenantId.eq(&query.tenant_id))
            .filter(managed_object_authority::Column::Bucket.eq(&query.bucket))
            .filter(managed_object_authority::Column::Tombstone.eq(false))
            .filter(sea_orm::sea_query::SimpleExpr::from(PgFunc::starts_with(
                Expr::col((
                    managed_object_authority::Entity,
                    managed_object_authority::Column::LogicalKey,
                )),
                query.prefix.clone(),
            )))
            .order_by_asc(managed_object_authority::Column::LogicalKey)
            .limit(query.max_keys.saturating_add(1));
        if let Some(after) = &query.after {
            select = select.filter(managed_object_authority::Column::LogicalKey.gt(after));
        }
        let mut objects = select
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(authority_from_model)
            .collect::<Result<Vec<_>, _>>()?;
        let next_after = (objects.len() as u64 > query.max_keys)
            .then(|| objects[query.max_keys as usize - 1].logical.key.clone());
        objects.truncate(query.max_keys as usize);
        Ok(AuthorityListPage {
            objects,
            next_after,
        })
    }

    async fn list_authority_below_placement_version(
        &self,
        query: AuthorityPlacementPageQuery,
    ) -> Result<AuthorityPlacementPage, ManagedError> {
        if query.limit > MANAGED_AUTHORITY_LIST_MAX_KEYS || query.target_placement_version == 0 {
            return Err(ManagedError::Conflict);
        }
        if query.limit == 0 {
            return Ok(AuthorityPlacementPage {
                objects: Vec::new(),
                next_after: None,
            });
        }
        let mut select = managed_object_authority::Entity::find()
            .filter(managed_object_authority::Column::Tombstone.eq(false))
            .filter(
                managed_object_authority::Column::PlacementVersion
                    .lt(i64::from(query.target_placement_version)),
            )
            .order_by_asc(managed_object_authority::Column::TenantId)
            .order_by_asc(managed_object_authority::Column::Bucket)
            .order_by_asc(managed_object_authority::Column::LogicalKey)
            .limit(query.limit.saturating_add(1));
        if let Some(after) = &query.after {
            select = select.filter(
                Condition::any()
                    .add(managed_object_authority::Column::TenantId.gt(&after.tenant_id))
                    .add(
                        Condition::all()
                            .add(managed_object_authority::Column::TenantId.eq(&after.tenant_id))
                            .add(managed_object_authority::Column::Bucket.gt(&after.bucket)),
                    )
                    .add(
                        Condition::all()
                            .add(managed_object_authority::Column::TenantId.eq(&after.tenant_id))
                            .add(managed_object_authority::Column::Bucket.eq(&after.bucket))
                            .add(managed_object_authority::Column::LogicalKey.gt(&after.key)),
                    ),
            );
        }
        let mut objects = select
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(authority_from_model)
            .collect::<Result<Vec<_>, _>>()?;
        let next_after = (objects.len() as u64 > query.limit).then(|| {
            let authority = &objects[query.limit as usize - 1];
            AuthorityPlacementCursor {
                tenant_id: authority.logical.tenant_id.clone(),
                bucket: authority.logical.bucket.clone(),
                key: authority.logical.key.clone(),
            }
        });
        objects.truncate(query.limit as usize);
        Ok(AuthorityPlacementPage {
            objects,
            next_after,
        })
    }

    async fn authority_placement_stats(
        &self,
        target_placement_version: u32,
    ) -> Result<AuthorityPlacementStats, ManagedError> {
        if target_placement_version == 0 {
            return Err(ManagedError::Conflict);
        }
        let remaining = managed_object_authority::Entity::find()
            .filter(managed_object_authority::Column::Tombstone.eq(false))
            .filter(
                managed_object_authority::Column::PlacementVersion
                    .lt(i64::from(target_placement_version)),
            )
            .count(&self.db)
            .await
            .map_err(persistence)?;
        let oldest_updated_at_ms = managed_object_authority::Entity::find()
            .filter(managed_object_authority::Column::Tombstone.eq(false))
            .filter(
                managed_object_authority::Column::PlacementVersion
                    .lt(i64::from(target_placement_version)),
            )
            .order_by_asc(managed_object_authority::Column::UpdatedAtMs)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .map(|model| model.updated_at_ms);
        Ok(AuthorityPlacementStats {
            remaining,
            oldest_updated_at_ms,
        })
    }

    async fn create_list_cursor(
        &self,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let response_state = serialize_cursor_response_state(&request.response_state)?;
        let response_state_bytes = response_state.len() as u64;
        let txn = self
            .db
            .begin_with_config(Some(IsolationLevel::Serializable), None)
            .await
            .map_err(persistence)?;
        let namespace = locked_namespace(&txn, &request.binding.tenant_id).await?;
        if namespace.state != "ACTIVE" {
            return Err(ManagedError::NamespaceFenced);
        }
        let fence = ManagedRouteFence {
            namespace_epoch: u64_from_i64(namespace.epoch, "managed list cursor namespace epoch")?,
            routing_epoch: u64_from_i64(
                namespace.routing_epoch,
                "managed list cursor routing epoch",
            )?,
        };
        let workspace_count = managed_list_cursor::Entity::find()
            .filter(managed_list_cursor::Column::TenantId.eq(&request.binding.tenant_id))
            .filter(managed_list_cursor::Column::ExpiresAtMs.gt(now_ms))
            .count(&txn)
            .await
            .map_err(persistence)?;
        let global_count = managed_list_cursor::Entity::find()
            .filter(managed_list_cursor::Column::ExpiresAtMs.gt(now_ms))
            .count(&txn)
            .await
            .map_err(persistence)?;
        let workspace_cursor_bytes: Vec<i64> = managed_list_cursor::Entity::find()
            .select_only()
            .column(managed_list_cursor::Column::ResponseStateBytes)
            .filter(managed_list_cursor::Column::TenantId.eq(&request.binding.tenant_id))
            .filter(managed_list_cursor::Column::ExpiresAtMs.gt(now_ms))
            .into_tuple()
            .all(&txn)
            .await
            .map_err(persistence)?;
        let global_cursor_bytes: Vec<i64> = managed_list_cursor::Entity::find()
            .select_only()
            .column(managed_list_cursor::Column::ResponseStateBytes)
            .filter(managed_list_cursor::Column::ExpiresAtMs.gt(now_ms))
            .into_tuple()
            .all(&txn)
            .await
            .map_err(persistence)?;
        let workspace_bytes =
            workspace_cursor_bytes
                .into_iter()
                .try_fold(0_u64, |total, value| {
                    total
                        .checked_add(u64_from_i64(value, "managed workspace cursor bytes")?)
                        .ok_or(ManagedError::CursorLimitExceeded)
                })?;
        let global_bytes = global_cursor_bytes
            .into_iter()
            .try_fold(0_u64, |total, value| {
                total
                    .checked_add(u64_from_i64(value, "managed global cursor bytes")?)
                    .ok_or(ManagedError::CursorLimitExceeded)
            })?;
        if workspace_count >= MANAGED_LIST_CURSOR_WORKSPACE_LIMIT
            || global_count >= MANAGED_LIST_CURSOR_GLOBAL_LIMIT
            || workspace_bytes
                .checked_add(response_state_bytes)
                .is_none_or(|bytes| bytes > MANAGED_LIST_CURSOR_WORKSPACE_MAX_BYTES)
            || global_bytes
                .checked_add(response_state_bytes)
                .is_none_or(|bytes| bytes > MANAGED_LIST_CURSOR_GLOBAL_MAX_BYTES)
        {
            return Err(ManagedError::CursorLimitExceeded);
        }
        let cursor_id = Uuid::new_v4();
        let expires_at_ms = now_ms.saturating_add(MANAGED_LIST_CURSOR_TTL_MS);
        let model = managed_list_cursor::ActiveModel {
            cursor_id: Set(cursor_id),
            predecessor_cursor_id: Set(None),
            tenant_id: Set(request.binding.tenant_id),
            namespace_epoch: Set(i64_from_u64(
                fence.namespace_epoch,
                "managed list cursor namespace epoch",
            )?),
            routing_epoch: Set(i64_from_u64(
                fence.routing_epoch,
                "managed list cursor routing epoch",
            )?),
            bucket: Set(request.binding.bucket),
            prefix: Set(request.binding.prefix),
            delimiter: Set(request.binding.delimiter),
            list_version: Set(request.binding.version.as_str().to_string()),
            last_key: Set(request.position.last_key),
            last_common_prefix: Set(request.position.last_common_prefix),
            response_state: Set(response_state),
            response_state_bytes: Set(i64_from_u64(
                response_state_bytes,
                "managed list cursor response bytes",
            )?),
            final_page: Set(request.final_page),
            state: Set("ACTIVE".to_string()),
            created_at_ms: Set(now_ms),
            expires_at_ms: Set(expires_at_ms),
            first_used_at_ms: Set(None),
        }
        .insert(&txn)
        .await
        .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        list_cursor_from_model(model)
    }

    async fn create_list_cursor_successor(
        &self,
        predecessor_cursor_id: Uuid,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let existing = || async {
            managed_list_cursor::Entity::find()
                .filter(managed_list_cursor::Column::PredecessorCursorId.eq(predecessor_cursor_id))
                .one(&self.db)
                .await
                .map_err(persistence)?
                .map(list_cursor_from_model)
                .transpose()
        };
        if let Some(cursor) = existing().await? {
            if cursor.expires_at_ms <= now_ms
                || cursor.fence != self.route_fence(&cursor.binding.tenant_id).await?
            {
                return Err(ManagedError::CursorExpired);
            }
            return cursor_matches_request(&cursor, &request)
                .then_some(cursor)
                .ok_or(ManagedError::Conflict);
        }

        let created = self.create_list_cursor(request.clone(), now_ms).await?;
        let linked = managed_list_cursor::Entity::update_many()
            .col_expr(
                managed_list_cursor::Column::PredecessorCursorId,
                Expr::value(Some(predecessor_cursor_id)),
            )
            .filter(managed_list_cursor::Column::CursorId.eq(created.id))
            .filter(managed_list_cursor::Column::PredecessorCursorId.is_null())
            .exec(&self.db)
            .await;
        if linked
            .as_ref()
            .is_ok_and(|result| result.rows_affected == 1)
        {
            return Ok(created);
        }
        let _ = self.delete_list_cursor(created.id).await;
        let cursor = existing().await?.ok_or_else(|| {
            linked
                .err()
                .map(persistence)
                .unwrap_or(ManagedError::Conflict)
        })?;
        if cursor.expires_at_ms <= now_ms
            || cursor.fence != self.route_fence(&cursor.binding.tenant_id).await?
        {
            return Err(ManagedError::CursorExpired);
        }
        cursor_matches_request(&cursor, &request)
            .then_some(cursor)
            .ok_or(ManagedError::Conflict)
    }

    async fn use_list_cursor(
        &self,
        cursor_id: Uuid,
        binding: &ManagedListCursorBinding,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let model = managed_list_cursor::Entity::find_by_id(cursor_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::CursorExpired)?;
        let mut cursor = list_cursor_from_model(model)?;
        if cursor.expires_at_ms <= now_ms {
            managed_list_cursor::Entity::delete_by_id(cursor_id)
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Err(ManagedError::CursorExpired);
        }
        let namespace = managed_namespace::Entity::find_by_id(cursor.binding.tenant_id.clone())
            .lock(LockType::Share)
            .one(&txn)
            .await
            .map_err(persistence)?;
        if namespace
            .as_ref()
            .is_none_or(|namespace| namespace.state != "ACTIVE")
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let namespace = namespace.expect("active namespace checked above");
        if u64_from_i64(namespace.epoch, "managed namespace epoch")? != cursor.fence.namespace_epoch
            || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                != cursor.fence.routing_epoch
        {
            managed_list_cursor::Entity::delete_by_id(cursor_id)
                .exec(&txn)
                .await
                .map_err(persistence)?;
            txn.commit().await.map_err(persistence)?;
            return Err(ManagedError::CursorExpired);
        }
        if &cursor.binding != binding {
            return Err(ManagedError::CursorQueryMismatch);
        }
        if cursor.state == ManagedListCursorState::Active {
            managed_list_cursor::Entity::update_many()
                .col_expr(managed_list_cursor::Column::State, Expr::value("USED"))
                .col_expr(
                    managed_list_cursor::Column::FirstUsedAtMs,
                    Expr::value(Some(now_ms)),
                )
                .filter(managed_list_cursor::Column::CursorId.eq(cursor_id))
                .filter(managed_list_cursor::Column::State.eq("ACTIVE"))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            cursor.state = ManagedListCursorState::Used;
            cursor.first_used_at_ms = Some(now_ms);
        }
        txn.commit().await.map_err(persistence)?;
        Ok(cursor)
    }

    async fn delete_list_cursor(&self, cursor_id: Uuid) -> Result<(), ManagedError> {
        managed_list_cursor::Entity::delete_by_id(cursor_id)
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        Ok(())
    }

    async fn cleanup_expired_list_cursors(
        &self,
        now_ms: i64,
        limit: u64,
    ) -> Result<u64, ManagedError> {
        let ids: Vec<_> = managed_list_cursor::Entity::find()
            .filter(managed_list_cursor::Column::ExpiresAtMs.lte(now_ms))
            .order_by_asc(managed_list_cursor::Column::ExpiresAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(|cursor| cursor.cursor_id)
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }
        let result = managed_list_cursor::Entity::delete_many()
            .filter(managed_list_cursor::Column::CursorId.is_in(ids))
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        Ok(result.rows_affected)
    }

    async fn begin_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
    ) -> Result<u64, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let epoch = require_active_namespace(&txn, tenant_id).await?;
        let now = crate::transaction::unix_time_ms();
        managed_multipart_activity::ActiveModel {
            upload_id: Set(upload_id.to_string()),
            tenant_id: Set(tenant_id.to_string()),
            namespace_epoch: Set(epoch),
            state: Set("REGISTERING".to_string()),
            registration_expires_at_ms: Set(Some(now.saturating_add(10 * 60 * 1000))),
            created_at_ms: Set(now),
            updated_at_ms: Set(now),
        }
        .insert(&txn)
        .await
        .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        u64::try_from(epoch)
            .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))
    }

    async fn assert_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
        allow_purging: bool,
    ) -> Result<(), ManagedError> {
        let epoch = i64::try_from(namespace_epoch).map_err(|_| ManagedError::Conflict)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, tenant_id).await?;
        if namespace.epoch != epoch
            || (namespace.state != "ACTIVE" && !(allow_purging && namespace.state == "PURGING"))
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let activity = managed_multipart_activity::Entity::find_by_id(upload_id.to_string())
            .one(&txn)
            .await
            .map_err(persistence)?;
        if activity.is_none_or(|activity| {
            activity.tenant_id != tenant_id
                || activity.namespace_epoch != epoch
                || activity.state != "ACTIVE"
        }) {
            return Err(ManagedError::NamespaceFenced);
        }
        txn.commit().await.map_err(persistence)
    }

    async fn confirm_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        let epoch = i64::try_from(namespace_epoch).map_err(|_| ManagedError::Conflict)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, tenant_id).await?;
        if namespace.state != "ACTIVE" || namespace.epoch != epoch {
            return Err(ManagedError::NamespaceFenced);
        }
        if let Some(existing) =
            managed_multipart_activity::Entity::find_by_id(upload_id.to_string())
                .one(&txn)
                .await
                .map_err(persistence)?
            && existing.tenant_id == tenant_id
            && existing.namespace_epoch == epoch
            && existing.state == "ACTIVE"
        {
            txn.commit().await.map_err(persistence)?;
            return Ok(());
        }
        let result = managed_multipart_activity::Entity::update_many()
            .col_expr(
                managed_multipart_activity::Column::State,
                Expr::value("ACTIVE"),
            )
            .col_expr(
                managed_multipart_activity::Column::RegistrationExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                managed_multipart_activity::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(managed_multipart_activity::Column::UploadId.eq(upload_id))
            .filter(managed_multipart_activity::Column::TenantId.eq(tenant_id))
            .filter(managed_multipart_activity::Column::NamespaceEpoch.eq(epoch))
            .filter(managed_multipart_activity::Column::State.eq("REGISTERING"))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::NamespaceFenced);
        }
        txn.commit().await.map_err(persistence)
    }

    async fn reconcile_multipart_activities(&self, limit: u64) -> Result<u64, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let candidates = managed_multipart_activity::Entity::find()
            .filter(managed_multipart_activity::Column::State.eq("REGISTERING"))
            .filter(managed_multipart_activity::Column::RegistrationExpiresAtMs.lte(now))
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?;
        let count = candidates.len() as u64;
        for activity in candidates {
            let upload = crate::entity::multipart_upload::Entity::find()
                .filter(crate::entity::multipart_upload::Column::UploadId.eq(&activity.upload_id))
                .filter(crate::entity::multipart_upload::Column::TenantId.eq(&activity.tenant_id))
                .filter(
                    crate::entity::multipart_upload::Column::NamespaceEpoch
                        .eq(activity.namespace_epoch),
                )
                .one(&self.db)
                .await
                .map_err(persistence)?;
            if upload.is_some() {
                managed_multipart_activity::Entity::update_many()
                    .col_expr(
                        managed_multipart_activity::Column::State,
                        Expr::value("ACTIVE"),
                    )
                    .col_expr(
                        managed_multipart_activity::Column::RegistrationExpiresAtMs,
                        Expr::value(Option::<i64>::None),
                    )
                    .filter(managed_multipart_activity::Column::UploadId.eq(&activity.upload_id))
                    .filter(managed_multipart_activity::Column::State.eq("REGISTERING"))
                    .exec(&self.db)
                    .await
                    .map_err(persistence)?;
            } else {
                managed_multipart_activity::Entity::delete_many()
                    .filter(managed_multipart_activity::Column::UploadId.eq(&activity.upload_id))
                    .filter(managed_multipart_activity::Column::State.eq("REGISTERING"))
                    .filter(managed_multipart_activity::Column::RegistrationExpiresAtMs.lte(now))
                    .exec(&self.db)
                    .await
                    .map_err(persistence)?;
            }
        }
        Ok(count)
    }

    async fn finish_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        let epoch = i64::try_from(namespace_epoch).map_err(|_| ManagedError::Conflict)?;
        managed_multipart_activity::Entity::delete_many()
            .filter(managed_multipart_activity::Column::UploadId.eq(upload_id))
            .filter(managed_multipart_activity::Column::TenantId.eq(tenant_id))
            .filter(managed_multipart_activity::Column::NamespaceEpoch.eq(epoch))
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        Ok(())
    }

    async fn any_authority(&self) -> Result<bool, ManagedError> {
        Ok(managed_object_authority::Entity::find()
            .limit(1)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .is_some())
    }

    async fn get(
        &self,
        logical: &LogicalObjectKey,
    ) -> Result<Option<ObjectAuthority>, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        require_active_namespace(&txn, &logical.tenant_id).await?;
        let authority = managed_object_authority::Entity::find_by_id((
            logical.tenant_id.clone(),
            logical.bucket.clone(),
            logical.key.clone(),
        ))
        .one(&txn)
        .await
        .map_err(persistence)?
        .map(authority_from_model)
        .transpose()?;
        txn.commit().await.map_err(persistence)?;
        Ok(authority)
    }

    async fn publish(
        &self,
        mut authority: ObjectAuthority,
        expected_cas: Option<u64>,
    ) -> Result<ObjectAuthority, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace_epoch = require_active_namespace(&txn, &authority.logical.tenant_id).await?;
        if !authority.tombstone {
            let physical_key = generation_physical_key(&authority.logical, authority.generation);
            let primary_versions = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::TenantId
                        .eq(&authority.logical.tenant_id),
                )
                .filter(
                    managed_physical_object_version::Column::BackendId
                        .eq(&authority.primary_backend_id),
                )
                .filter(managed_physical_object_version::Column::PhysicalKey.eq(&physical_key))
                .count(&txn)
                .await
                .map_err(persistence)?;
            if primary_versions == 0 {
                return Err(ManagedError::Persistence(
                    "managed primary cannot publish before its physical versions are ledgered"
                        .to_string(),
                ));
            }
            if authority.replica_status == CopyStatus::Ready
                && let Some(replica) = &authority.replica_backend_id
            {
                let replica_versions = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId
                            .eq(&authority.logical.tenant_id),
                    )
                    .filter(managed_physical_object_version::Column::BackendId.eq(replica))
                    .filter(managed_physical_object_version::Column::PhysicalKey.eq(&physical_key))
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if replica_versions == 0 {
                    return Err(ManagedError::Persistence(
                        "managed replica cannot publish before its physical versions are ledgered"
                            .to_string(),
                    ));
                }
            }
        }
        let existing = managed_object_authority::Entity::find_by_id((
            authority.logical.tenant_id.clone(),
            authority.logical.bucket.clone(),
            authority.logical.key.clone(),
        ))
        .one(&txn)
        .await
        .map_err(persistence)?
        .map(authority_from_model)
        .transpose()?;
        if existing.as_ref().map(|value| value.cas_version) != expected_cas {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        authority.cas_version = expected_cas.unwrap_or(0).saturating_add(1);
        authority.created_at_ms = existing.as_ref().map_or(now, |value| value.created_at_ms);
        authority.updated_at_ms = now;
        match expected_cas {
            None => {
                authority_active(&authority)?
                    .insert(&txn)
                    .await
                    .map_err(|_| ManagedError::Conflict)?;
            }
            Some(expected) => {
                let active = authority_active(&authority)?;
                let result = managed_object_authority::Entity::update_many()
                    .set(active)
                    .filter(
                        managed_object_authority::Column::TenantId.eq(&authority.logical.tenant_id),
                    )
                    .filter(managed_object_authority::Column::Bucket.eq(&authority.logical.bucket))
                    .filter(managed_object_authority::Column::LogicalKey.eq(&authority.logical.key))
                    .filter(
                        managed_object_authority::Column::CasVersion
                            .eq(i64::try_from(expected).map_err(|_| ManagedError::Conflict)?),
                    )
                    .exec(&txn)
                    .await
                    .map_err(persistence)?;
                if result.rows_affected != 1 {
                    return Err(ManagedError::Conflict);
                }
            }
        }
        for mut repair in publication_repairs(&authority) {
            repair.namespace_epoch = u64::try_from(namespace_epoch)
                .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))?;
            insert_repair(&txn, repair).await?;
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                let targets = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId
                            .eq(&repair.logical.tenant_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::BackendId
                            .eq(&repair.target_backend_id),
                    )
                    .filter(
                        managed_physical_object_version::Column::PhysicalKey
                            .eq(&repair.physical_key),
                    )
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if targets == 0 {
                    continue;
                }
                repair.namespace_epoch = u64::try_from(namespace_epoch)
                    .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))?;
                insert_repair(&txn, repair).await?;
            }
        }
        txn.commit().await.map_err(persistence)?;
        Ok(authority)
    }

    async fn record_placement_policy(
        &self,
        policy: &ManagedPlacementPolicy,
    ) -> Result<bool, ManagedError> {
        let version = i32::try_from(policy.version).map_err(|_| {
            ManagedError::Corrupt("placement policy version exceeds INTEGER".to_string())
        })?;
        let facts_json = serde_json::to_string(&policy.backend_facts).map_err(|error| {
            ManagedError::Corrupt(format!("placement policy facts serialize: {error}"))
        })?;
        managed_placement_policy_version::Entity::insert(
            managed_placement_policy_version::ActiveModel {
                version: Set(version),
                fingerprint: Set(policy.fingerprint.clone()),
                backend_facts: Set(facts_json),
                activated_at_ms: Set(policy.activated_at_ms),
            },
        )
        .on_conflict(
            OnConflict::column(managed_placement_policy_version::Column::Version)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(&self.db)
        .await
        .map_err(persistence)?;
        let existing = managed_placement_policy_version::Entity::find_by_id(version)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .ok_or_else(|| {
                ManagedError::Persistence("placement policy insert did not persist".to_string())
            })?;
        Ok(existing.fingerprint == policy.fingerprint)
    }

    async fn advance_placement_version(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: u64,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        require_active_namespace(&txn, &logical.tenant_id).await?;
        let authority = managed_object_authority::Entity::find_by_id((
            logical.tenant_id.clone(),
            logical.bucket.clone(),
            logical.key.clone(),
        ))
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?
        .map(authority_from_model)
        .transpose()?
        .ok_or(ManagedError::Conflict)?;
        let locations_match = authority.primary_backend_id == placement.primary_backend_id
            && authority.primary_status == CopyStatus::Ready
            && match placement.replica_backend_id.as_deref() {
                Some(replica) => {
                    authority.replica_backend_id.as_deref() == Some(replica)
                        && authority.replica_status == CopyStatus::Ready
                }
                None => {
                    authority.replica_backend_id.is_none()
                        && authority.replica_status == CopyStatus::Absent
                }
            };
        if authority.tombstone
            || authority.cas_version != expected_cas
            || placement.version <= authority.placement_version
            || !locations_match
        {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        let result = managed_object_authority::Entity::update_many()
            .col_expr(
                managed_object_authority::Column::PlacementVersion,
                Expr::value(i64::from(placement.version)),
            )
            .col_expr(
                managed_object_authority::Column::CasVersion,
                Expr::value(i64::try_from(expected_cas.saturating_add(1)).map_err(|_| {
                    ManagedError::Corrupt("authority CAS exceeds BIGINT".to_string())
                })?),
            )
            .col_expr(
                managed_object_authority::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_object_authority::Column::TenantId.eq(&logical.tenant_id))
            .filter(managed_object_authority::Column::Bucket.eq(&logical.bucket))
            .filter(managed_object_authority::Column::LogicalKey.eq(&logical.key))
            .filter(
                managed_object_authority::Column::CasVersion
                    .eq(i64::try_from(expected_cas).map_err(|_| ManagedError::Conflict)?),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        let advanced = managed_object_authority::Entity::find_by_id((
            logical.tenant_id.clone(),
            logical.bucket.clone(),
            logical.key.clone(),
        ))
        .one(&txn)
        .await
        .map_err(persistence)?
        .ok_or(ManagedError::Conflict)
        .and_then(authority_from_model)?;
        txn.commit().await.map_err(persistence)?;
        Ok(advanced)
    }

    async fn tombstone(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: Option<u64>,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError> {
        let existing = self.get(logical).await?;
        if existing.as_ref().map(|value| value.cas_version) != expected_cas {
            return Err(ManagedError::Conflict);
        }
        let generation = Uuid::now_v7();
        let now = crate::transaction::unix_time_ms();
        let tombstone = ObjectAuthority {
            logical: logical.clone(),
            generation,
            digest: String::new(),
            size: 0,
            metadata: BTreeMap::new(),
            placement_version: placement.version,
            primary_backend_id: placement.primary_backend_id.clone(),
            primary_version_id: None,
            replica_backend_id: placement.replica_backend_id.clone(),
            primary_status: CopyStatus::Absent,
            replica_status: CopyStatus::Absent,
            tombstone: true,
            cas_version: 0,
            created_at_ms: now,
            updated_at_ms: now,
        };
        self.publish(tombstone, expected_cas).await
    }

    async fn enqueue(&self, mut repair: RepairRecord) -> Result<(), ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace_epoch = require_active_namespace(&txn, &repair.logical.tenant_id).await?;
        let current = managed_object_authority::Entity::find_by_id((
            repair.logical.tenant_id.clone(),
            repair.logical.bucket.clone(),
            repair.logical.key.clone(),
        ))
        .lock(LockType::Update)
        .one(&txn)
        .await
        .map_err(persistence)?
        .map(authority_from_model)
        .transpose()?;
        if repair.kind == RepairKind::DeleteGeneration {
            let targets = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::TenantId.eq(&repair.logical.tenant_id),
                )
                .filter(
                    managed_physical_object_version::Column::BackendId
                        .eq(&repair.target_backend_id),
                )
                .filter(
                    managed_physical_object_version::Column::PhysicalKey.eq(&repair.physical_key),
                )
                .all(&txn)
                .await
                .map_err(persistence)?;
            if targets.is_empty() {
                txn.commit().await.map_err(persistence)?;
                return Ok(());
            }
            if targets.iter().any(|target| target.epoch != namespace_epoch) {
                return Err(ManagedError::Conflict);
            }
        } else if current.as_ref().is_none_or(|authority| {
            authority.generation != repair.generation
                || authority.cas_version != repair.authority_cas_version
        }) {
            return Err(ManagedError::Conflict);
        }
        repair.namespace_epoch = u64::try_from(namespace_epoch)
            .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))?;
        insert_repair(&txn, repair).await?;
        txn.commit().await.map_err(persistence)
    }

    async fn claim_repairs(
        &self,
        owner: &str,
        lease_until_ms: i64,
        limit: u64,
    ) -> Result<Vec<RepairRecord>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let candidates = managed_object_repair::Entity::find()
            .filter(
                Condition::any()
                    .add(
                        Condition::all()
                            .add(managed_object_repair::Column::State.eq("PENDING"))
                            .add(managed_object_repair::Column::NotBeforeMs.lte(now)),
                    )
                    .add(
                        Condition::all()
                            .add(managed_object_repair::Column::State.eq("LEASED"))
                            .add(managed_object_repair::Column::LeaseExpiresAtMs.lte(now)),
                    ),
            )
            .order_by_asc(managed_object_repair::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?;
        let mut claimed = Vec::new();
        for candidate in candidates {
            let txn = self.db.begin().await.map_err(persistence)?;
            match require_active_namespace(&txn, &candidate.tenant_id).await {
                Ok(epoch) if epoch == candidate.namespace_epoch => {}
                Ok(_) => continue,
                Err(ManagedError::NamespaceFenced) => continue,
                Err(error) => return Err(error),
            }
            if candidate.kind == "DELETE_GENERATION" {
                let current = managed_object_authority::Entity::find_by_id((
                    candidate.tenant_id.clone(),
                    candidate.bucket.clone(),
                    candidate.logical_key.clone(),
                ))
                .lock(LockType::Update)
                .one(&txn)
                .await
                .map_err(persistence)?
                .map(authority_from_model)
                .transpose()?;
                if current.as_ref().is_some_and(|authority| {
                    !authority.tombstone
                        && authority.generation == candidate.generation
                        && (authority.primary_backend_id == candidate.target_backend_id
                            || authority.replica_backend_id.as_deref()
                                == Some(candidate.target_backend_id.as_str()))
                }) {
                    txn.commit().await.map_err(persistence)?;
                    continue;
                }
            }
            let lease_token = Uuid::now_v7();
            let result = managed_object_repair::Entity::update_many()
                .col_expr(managed_object_repair::Column::State, Expr::value("LEASED"))
                .col_expr(
                    managed_object_repair::Column::LeaseOwner,
                    Expr::value(Some(owner.to_string())),
                )
                .col_expr(
                    managed_object_repair::Column::LeaseExpiresAtMs,
                    Expr::value(Some(lease_until_ms)),
                )
                .col_expr(
                    managed_object_repair::Column::LeaseToken,
                    Expr::value(Some(lease_token)),
                )
                .col_expr(managed_object_repair::Column::UpdatedAtMs, Expr::value(now))
                .filter(managed_object_repair::Column::Id.eq(candidate.id))
                .filter(
                    Condition::any()
                        .add(managed_object_repair::Column::State.eq("PENDING"))
                        .add(
                            Condition::all()
                                .add(managed_object_repair::Column::State.eq("LEASED"))
                                .add(managed_object_repair::Column::LeaseExpiresAtMs.lte(now)),
                        ),
                )
                .exec(&txn)
                .await
                .map_err(persistence)?;
            if result.rows_affected == 1 {
                let mut record = repair_from_model(candidate)?;
                record.id = lease_token;
                record.lease_owner = Some(owner.to_string());
                record.lease_token = Some(lease_token);
                record.lease_expires_at_ms = Some(lease_until_ms);
                claimed.push(record);
            }
            txn.commit().await.map_err(persistence)?;
        }
        Ok(claimed)
    }

    async fn renew_repair(
        &self,
        lease_token: Uuid,
        lease_until_ms: i64,
    ) -> Result<(), ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let result = managed_object_repair::Entity::update_many()
            .col_expr(
                managed_object_repair::Column::LeaseExpiresAtMs,
                Expr::value(Some(lease_until_ms)),
            )
            .col_expr(managed_object_repair::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_object_repair::Column::State.eq("LEASED"))
            .filter(managed_object_repair::Column::LeaseToken.eq(lease_token))
            .filter(managed_object_repair::Column::LeaseExpiresAtMs.gt(now))
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        Ok(())
    }

    async fn complete_repair(&self, repair: &RepairRecord) -> Result<bool, ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace_epoch = require_active_namespace(&txn, &repair.logical.tenant_id).await?;
        if u64::try_from(namespace_epoch).ok() != Some(repair.namespace_epoch) {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        if repair.lease_token != Some(repair.id) {
            return Err(ManagedError::Conflict);
        }
        let result = managed_object_repair::Entity::update_many()
            .col_expr(managed_object_repair::Column::State, Expr::value("DONE"))
            .col_expr(
                managed_object_repair::Column::LeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(managed_object_repair::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_object_repair::Column::Id.eq(repair.repair_id))
            .filter(managed_object_repair::Column::State.eq("LEASED"))
            .filter(managed_object_repair::Column::LeaseToken.eq(repair.id))
            .filter(managed_object_repair::Column::LeaseExpiresAtMs.gt(now))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        if repair.kind == RepairKind::DeleteGeneration {
            let remaining = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::TenantId.eq(&repair.logical.tenant_id),
                )
                .filter(
                    managed_physical_object_version::Column::BackendId
                        .eq(&repair.target_backend_id),
                )
                .filter(
                    managed_physical_object_version::Column::PhysicalKey.eq(&repair.physical_key),
                )
                .count(&txn)
                .await
                .map_err(persistence)?;
            if remaining != 0 {
                managed_object_repair::Entity::update_many()
                    .col_expr(managed_object_repair::Column::State, Expr::value("PENDING"))
                    .filter(managed_object_repair::Column::Id.eq(repair.repair_id))
                    .filter(managed_object_repair::Column::State.eq("DONE"))
                    .exec(&txn)
                    .await
                    .map_err(persistence)?;
                txn.commit().await.map_err(persistence)?;
                return Ok(false);
            }
        }
        let mut authority_updated = false;
        if repair.kind != RepairKind::DeleteGeneration {
            let target_versions = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::TenantId.eq(&repair.logical.tenant_id),
                )
                .filter(
                    managed_physical_object_version::Column::BackendId
                        .eq(&repair.target_backend_id),
                )
                .filter(
                    managed_physical_object_version::Column::PhysicalKey.eq(&repair.physical_key),
                )
                .count(&txn)
                .await
                .map_err(persistence)?;
            if target_versions == 0 {
                return Err(ManagedError::Persistence(
                    "managed repair cannot publish before target physical versions are ledgered"
                        .to_string(),
                ));
            }
            let current = managed_object_authority::Entity::find_by_id((
                repair.logical.tenant_id.clone(),
                repair.logical.bucket.clone(),
                repair.logical.key.clone(),
            ))
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .map(authority_from_model)
            .transpose()?;
            let cleanup_in_progress = managed_object_repair::Entity::find()
                .filter(managed_object_repair::Column::Kind.eq("DELETE_GENERATION"))
                .filter(managed_object_repair::Column::TenantId.eq(&repair.logical.tenant_id))
                .filter(managed_object_repair::Column::Bucket.eq(&repair.logical.bucket))
                .filter(managed_object_repair::Column::LogicalKey.eq(&repair.logical.key))
                .filter(managed_object_repair::Column::Generation.eq(repair.generation))
                .filter(
                    managed_object_repair::Column::TargetBackendId.eq(&repair.target_backend_id),
                )
                .filter(managed_object_repair::Column::State.eq("LEASED"))
                .count(&txn)
                .await
                .map_err(persistence)?
                != 0;
            if !cleanup_in_progress && let Some(mut authority) = current.clone() {
                let previous = authority.clone();
                if authority.generation == repair.generation
                    && authority.cas_version == repair.authority_cas_version
                    && !authority.tombstone
                    && apply_repair_to_authority(&mut authority, repair)?
                {
                    if authority != previous {
                        authority.cas_version = authority.cas_version.saturating_add(1);
                        authority.updated_at_ms = crate::transaction::unix_time_ms();
                        let result = managed_object_authority::Entity::update_many()
                            .set(authority_active(&authority)?)
                            .filter(
                                managed_object_authority::Column::TenantId
                                    .eq(&repair.logical.tenant_id),
                            )
                            .filter(
                                managed_object_authority::Column::Bucket.eq(&repair.logical.bucket),
                            )
                            .filter(
                                managed_object_authority::Column::LogicalKey
                                    .eq(&repair.logical.key),
                            )
                            .filter(
                                managed_object_authority::Column::Generation.eq(repair.generation),
                            )
                            .filter(
                                managed_object_authority::Column::CasVersion.eq(i64_from_u64(
                                    previous.cas_version,
                                    "managed authority CAS",
                                )?),
                            )
                            .exec(&txn)
                            .await
                            .map_err(persistence)?;
                        if result.rows_affected != 1 {
                            return Err(ManagedError::Conflict);
                        }
                    }
                    authority_updated = true;
                    if repair.kind == RepairKind::Placement {
                        for mut cleanup in placement_cleanup_repairs(&previous, &authority) {
                            cleanup.namespace_epoch = repair.namespace_epoch;
                            cleanup.placement_version = repair.placement_version;
                            insert_waiting_placement_cleanup(&txn, cleanup).await?;
                        }
                        if authority.placement_version == repair.placement_version {
                            managed_object_repair::Entity::update_many()
                                .col_expr(
                                    managed_object_repair::Column::State,
                                    Expr::value("PENDING"),
                                )
                                .col_expr(
                                    managed_object_repair::Column::UpdatedAtMs,
                                    Expr::value(crate::transaction::unix_time_ms()),
                                )
                                .filter(managed_object_repair::Column::State.eq("WAITING_CUTOVER"))
                                .filter(
                                    managed_object_repair::Column::TenantId
                                        .eq(&repair.logical.tenant_id),
                                )
                                .filter(
                                    managed_object_repair::Column::Bucket
                                        .eq(&repair.logical.bucket),
                                )
                                .filter(
                                    managed_object_repair::Column::LogicalKey
                                        .eq(&repair.logical.key),
                                )
                                .filter(
                                    managed_object_repair::Column::Generation.eq(repair.generation),
                                )
                                .filter(
                                    managed_object_repair::Column::PlacementVersion
                                        .eq(i64::from(repair.placement_version)),
                                )
                                .exec(&txn)
                                .await
                                .map_err(persistence)?;
                        }
                    }
                }
            }
            if !authority_updated
                && current
                    .as_ref()
                    .is_none_or(|authority| !repair_target_is_authoritative(authority, repair))
            {
                insert_repair(&txn, stale_repair_cleanup(repair)).await?;
            }
        }
        txn.commit().await.map_err(persistence)?;
        Ok(authority_updated)
    }

    async fn fail_repair(&self, lease_token: Uuid, error: &str) -> Result<(), ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let txn = self.db.begin().await.map_err(persistence)?;
        let model = managed_object_repair::Entity::find()
            .filter(managed_object_repair::Column::State.eq("LEASED"))
            .filter(managed_object_repair::Column::LeaseToken.eq(lease_token))
            .filter(managed_object_repair::Column::LeaseExpiresAtMs.gt(now))
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        let attempts = model.attempts.saturating_add(1);
        let attempts = u32::try_from(attempts).unwrap_or(u32::MAX);
        let (state, not_before_ms) = if attempts >= MAX_REPAIR_ATTEMPTS {
            ("DEAD", 0)
        } else {
            ("PENDING", now.saturating_add(repair_backoff_ms(attempts)))
        };
        managed_object_repair::Entity::update_many()
            .col_expr(managed_object_repair::Column::State, Expr::value(state))
            .col_expr(
                managed_object_repair::Column::Attempts,
                Expr::value(i32::try_from(attempts).unwrap_or(i32::MAX)),
            )
            .col_expr(
                managed_object_repair::Column::NotBeforeMs,
                Expr::value(not_before_ms),
            )
            .col_expr(
                managed_object_repair::Column::LeaseOwner,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseToken,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                managed_object_repair::Column::LeaseExpiresAtMs,
                Expr::value(Option::<i64>::None),
            )
            .col_expr(
                managed_object_repair::Column::LastError,
                Expr::value(Some(error.chars().take(1024).collect::<String>())),
            )
            .col_expr(managed_object_repair::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_object_repair::Column::Id.eq(model.id))
            .filter(managed_object_repair::Column::State.eq("LEASED"))
            .filter(managed_object_repair::Column::LeaseToken.eq(lease_token))
            .filter(managed_object_repair::Column::LeaseExpiresAtMs.gt(now))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)
    }

    async fn repair_state_counts(&self) -> Result<RepairStateCounts, ManagedError> {
        let pending = managed_object_repair::Entity::find()
            .filter(managed_object_repair::Column::State.eq("PENDING"))
            .count(&self.db)
            .await
            .map_err(persistence)?;
        let leased = managed_object_repair::Entity::find()
            .filter(managed_object_repair::Column::State.eq("LEASED"))
            .count(&self.db)
            .await
            .map_err(persistence)?;
        let dead = managed_object_repair::Entity::find()
            .filter(managed_object_repair::Column::State.eq("DEAD"))
            .count(&self.db)
            .await
            .map_err(persistence)?;
        Ok(RepairStateCounts {
            pending,
            leased,
            dead,
        })
    }

    async fn begin_physical_write(
        &self,
        intent: PhysicalWriteIntent,
    ) -> Result<PhysicalWriteLease, ManagedError> {
        validate_physical_intent(&intent)?;
        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &intent.tenant_id).await?;
        let parent = managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::PrimaryChildOperationId.eq(intent.intent_id))
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .map(logical_operation_from_model)
            .transpose()?;
        let epoch = if let Some(parent) = &parent {
            let usage = locked_workspace_usage(&txn, &intent.tenant_id).await?;
            let recipe = parent
                .intent
                .publication_recipe
                .as_ref()
                .ok_or(ManagedError::Conflict)?;
            if namespace.state != "ACTIVE"
                || parent.state != ManagedLogicalOperationState::Open
                || usage.active_operation_id != Some(parent.intent.operation_id)
                || parent.intent.logical.tenant_id != intent.tenant_id
                || parent.intent.backend_id != intent.backend_id
                || parent.intent.provider_bucket != intent.provider_bucket
                || parent.intent.physical_key != intent.physical_key
                || recipe.version != MANAGED_PUBLICATION_RECIPE_VERSION
                || recipe.placement_version == 0
                || recipe.primary_backend_id != parent.intent.backend_id
                || !physical_intent_supports_exact_history(&intent)
                || recipe.primary_status != CopyStatus::Ready
                || (recipe.replica_backend_id.is_none()
                    && recipe.replica_status != CopyStatus::Absent)
                || (recipe.replica_backend_id.is_some()
                    && recipe.replica_status != CopyStatus::RepairPending)
                || u64_from_i64(namespace.epoch, "managed namespace epoch")?
                    != parent.intent.fence.namespace_epoch
                || u64_from_i64(namespace.routing_epoch, "managed routing epoch")?
                    != parent.intent.fence.routing_epoch
            {
                return Err(ManagedError::Conflict);
            }
            namespace.epoch
        } else {
            if namespace.state != "ACTIVE" {
                return Err(ManagedError::NamespaceFenced);
            }
            namespace.epoch
        };
        let now = crate::transaction::unix_time_ms();
        let lease_token = Uuid::now_v7();
        let expected = intent.clone();
        let inserted = managed_physical_write_intent::Entity::insert(
            managed_physical_write_intent::ActiveModel {
                intent_id: Set(intent.intent_id),
                tenant_id: Set(intent.tenant_id),
                epoch: Set(epoch),
                backend_id: Set(intent.backend_id),
                provider_kind: Set(intent.storage_identity.provider_kind),
                provider_instance_id: Set(intent.storage_identity.provider_instance_id),
                provider_account_id: Set(intent.storage_identity.provider_account_id),
                canonical_endpoint: Set(intent.storage_identity.canonical_endpoint),
                provider_region: Set(intent.storage_identity.region),
                credential_epoch: Set(i64_from_u64(
                    intent.credential_epoch,
                    "physical write credential epoch",
                )?),
                provider_bucket: Set(intent.provider_bucket),
                physical_key: Set(intent.physical_key),
                versioning_mode: Set(intent.versioning_mode.as_str().to_string()),
                versioning_capability: Set(intent.versioning_capability.as_str().to_string()),
                state: Set("PENDING".to_string()),
                last_error: Set(None),
                lease_owner: Set(intent.lease_owner.clone()),
                lease_token: Set(lease_token),
                lease_expires_at_ms: Set(now.saturating_add(PHYSICAL_WRITE_LEASE_MS)),
                created_at_ms: Set(now),
                updated_at_ms: Set(now),
            },
        )
        .on_conflict(
            OnConflict::column(managed_physical_write_intent::Column::IntentId)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(&txn)
        .await
        .map_err(persistence)?;
        if inserted == 0 {
            let existing = managed_physical_write_intent::Entity::find_by_id(expected.intent_id)
                .one(&txn)
                .await
                .map_err(persistence)?
                .ok_or(ManagedError::Conflict)?;
            if existing.tenant_id != expected.tenant_id
                || existing.epoch != epoch
                || existing.backend_id != expected.backend_id
                || existing.provider_kind != expected.storage_identity.provider_kind
                || existing.provider_instance_id != expected.storage_identity.provider_instance_id
                || existing.provider_account_id != expected.storage_identity.provider_account_id
                || existing.canonical_endpoint != expected.storage_identity.canonical_endpoint
                || existing.provider_region != expected.storage_identity.region
                || u64_from_i64(existing.credential_epoch, "physical write credential epoch")?
                    != expected.credential_epoch
                || existing.provider_bucket != expected.provider_bucket
                || existing.physical_key != expected.physical_key
                || existing.versioning_mode != expected.versioning_mode.as_str()
                || existing.versioning_capability != expected.versioning_capability.as_str()
                || existing.lease_owner != expected.lease_owner
            {
                return Err(ManagedError::RecoveryBlocked("physical_intent_mismatch"));
            }
            txn.commit().await.map_err(persistence)?;
            return Ok(PhysicalWriteLease {
                intent_id: existing.intent_id,
                namespace_epoch: u64::try_from(existing.epoch)
                    .map_err(|_| ManagedError::Conflict)?,
                owner: existing.lease_owner,
                token: existing.lease_token,
            });
        }
        txn.commit().await.map_err(persistence)?;
        Ok(PhysicalWriteLease {
            intent_id: intent.intent_id,
            namespace_epoch: u64::try_from(epoch)
                .map_err(|_| ManagedError::Corrupt("namespace epoch is invalid".to_string()))?,
            owner: intent.lease_owner,
            token: lease_token,
        })
    }

    async fn pending_physical_write_intents(
        &self,
        limit: u64,
    ) -> Result<Vec<DurablePhysicalWriteIntent>, ManagedError> {
        let logical_children = managed_logical_operation::Entity::find()
            .select_only()
            .column(managed_logical_operation::Column::PrimaryChildOperationId)
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .into_query();
        managed_physical_write_intent::Entity::find()
            .filter(
                managed_physical_write_intent::Column::IntentId.not_in_subquery(logical_children),
            )
            .order_by_asc(managed_physical_write_intent::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(durable_physical_intent_from_model)
            .collect()
    }

    async fn physical_write_intent(
        &self,
        intent_id: Uuid,
    ) -> Result<Option<DurablePhysicalWriteIntent>, ManagedError> {
        managed_physical_write_intent::Entity::find_by_id(intent_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
            .map(durable_physical_intent_from_model)
            .transpose()
    }

    async fn renew_physical_write_intent(
        &self,
        lease: &PhysicalWriteLease,
        lease_expires_at_ms: i64,
    ) -> Result<(), ManagedError> {
        let result = managed_physical_write_intent::Entity::update_many()
            .col_expr(
                managed_physical_write_intent::Column::LeaseExpiresAtMs,
                Expr::value(lease_expires_at_ms),
            )
            .col_expr(
                managed_physical_write_intent::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(managed_physical_write_intent::Column::IntentId.eq(lease.intent_id))
            .filter(managed_physical_write_intent::Column::LeaseOwner.eq(&lease.owner))
            .filter(managed_physical_write_intent::Column::LeaseToken.eq(lease.token))
            .filter(
                managed_physical_write_intent::Column::LeaseExpiresAtMs
                    .gt(crate::transaction::unix_time_ms()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Err(ManagedError::Conflict);
        }
        Ok(())
    }

    async fn claim_expired_physical_write_intent(
        &self,
        intent_id: Uuid,
        owner: &str,
        lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        let candidate = managed_physical_write_intent::Entity::find_by_id(intent_id)
            .one(&self.db)
            .await
            .map_err(persistence)?;
        let Some(candidate) = candidate else {
            return Ok(None);
        };
        let txn = self.db.begin().await.map_err(persistence)?;
        let _namespace = locked_namespace(&txn, &candidate.tenant_id).await?;
        let protected_parent = managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::PrimaryChildOperationId.eq(intent_id))
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .count(&txn)
            .await
            .map_err(persistence)?;
        if protected_parent != 0 {
            return Ok(None);
        }
        let token = Uuid::now_v7();
        let result = managed_physical_write_intent::Entity::update_many()
            .col_expr(
                managed_physical_write_intent::Column::LeaseOwner,
                Expr::value(owner.to_string()),
            )
            .col_expr(
                managed_physical_write_intent::Column::LeaseToken,
                Expr::value(token),
            )
            .col_expr(
                managed_physical_write_intent::Column::LeaseExpiresAtMs,
                Expr::value(lease_expires_at_ms),
            )
            .filter(managed_physical_write_intent::Column::IntentId.eq(intent_id))
            .filter(
                managed_physical_write_intent::Column::LeaseExpiresAtMs
                    .lte(crate::transaction::unix_time_ms()),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if result.rows_affected != 1 {
            return Ok(None);
        }
        let intent = managed_physical_write_intent::Entity::find_by_id(intent_id)
            .one(&txn)
            .await
            .map_err(persistence)?
            .ok_or(ManagedError::Conflict)?;
        txn.commit().await.map_err(persistence)?;
        Ok(Some(PhysicalWriteLease {
            intent_id,
            namespace_epoch: u64::try_from(intent.epoch).map_err(|_| ManagedError::Conflict)?,
            owner: owner.to_string(),
            token,
        }))
    }

    async fn claim_logical_physical_write_intent(
        &self,
        claim: &ManagedRecoveryClaim,
        lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        if lease_expires_at_ms <= now {
            return Err(ManagedError::Conflict);
        }
        let txn = self.db.begin().await.map_err(persistence)?;
        // Lock order for managed mutation transactions is namespace -> logical
        // operation -> workspace usage/current authority -> physical intent.
        let namespace = locked_namespace(&txn, &claim.operation.intent.logical.tenant_id).await?;
        let model =
            managed_logical_operation::Entity::find_by_id(claim.operation.intent.operation_id)
                .lock(LockType::Update)
                .one(&txn)
                .await
                .map_err(persistence)?
                .ok_or(ManagedError::Conflict)?;
        let operation = logical_operation_from_model(model)?;
        validate_recovery_authority(&operation, Some(claim), now)?;
        if operation.intent.kind != ManagedMutationKind::Put
            || namespace.epoch
                != i64_from_u64(
                    operation.intent.fence.namespace_epoch,
                    "managed namespace epoch",
                )?
        {
            return Err(ManagedError::Conflict);
        }
        let token = Uuid::now_v7();
        let updated = managed_physical_write_intent::Entity::update_many()
            .col_expr(
                managed_physical_write_intent::Column::LeaseOwner,
                Expr::value(claim.owner.clone()),
            )
            .col_expr(
                managed_physical_write_intent::Column::LeaseToken,
                Expr::value(token),
            )
            .col_expr(
                managed_physical_write_intent::Column::LeaseExpiresAtMs,
                Expr::value(lease_expires_at_ms),
            )
            .filter(
                managed_physical_write_intent::Column::IntentId
                    .eq(operation.intent.primary_child_operation_id),
            )
            .filter(managed_physical_write_intent::Column::LeaseExpiresAtMs.lte(now))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if updated.rows_affected != 1 {
            txn.commit().await.map_err(persistence)?;
            return Ok(None);
        }
        txn.commit().await.map_err(persistence)?;
        Ok(Some(PhysicalWriteLease {
            intent_id: operation.intent.primary_child_operation_id,
            namespace_epoch: operation.intent.fence.namespace_epoch,
            owner: claim.owner.clone(),
            token,
        }))
    }

    async fn commit_physical_write(
        &self,
        lease: &PhysicalWriteLease,
        superseded_version_ids: &[String],
        version_id: Option<&str>,
    ) -> Result<(), ManagedError> {
        if superseded_version_ids.iter().any(String::is_empty)
            || version_id.is_some_and(str::is_empty)
        {
            return Err(ManagedError::Conflict);
        }
        let txn = self.db.begin().await.map_err(persistence)?;
        if managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::PrimaryChildOperationId.eq(lease.intent_id))
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .count(&txn)
            .await
            .map_err(persistence)?
            != 0
        {
            return Err(ManagedError::Conflict);
        }
        let Some(intent) = managed_physical_write_intent::Entity::find_by_id(lease.intent_id)
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
        else {
            // A committed retry and a confirmed abort are both terminal and
            // safe; neither can create a new provider version here.
            txn.commit().await.map_err(persistence)?;
            return Ok(());
        };
        if intent.lease_owner != lease.owner
            || intent.lease_token != lease.token
            || intent.lease_expires_at_ms <= crate::transaction::unix_time_ms()
        {
            return Err(ManagedError::Conflict);
        }
        let namespace = locked_namespace(&txn, &intent.tenant_id).await?;
        let now = crate::transaction::unix_time_ms();
        let purging = namespace.state == "PURGING";
        for recorded_version_id in superseded_version_ids
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(version_id.unwrap_or_default()))
        {
            managed_physical_object_version::Entity::insert(
                managed_physical_object_version::ActiveModel {
                    tenant_id: Set(intent.tenant_id.clone()),
                    backend_id: Set(intent.backend_id.clone()),
                    provider_kind: Set(intent.provider_kind.clone()),
                    provider_instance_id: Set(intent.provider_instance_id.clone()),
                    provider_account_id: Set(intent.provider_account_id.clone()),
                    canonical_endpoint: Set(intent.canonical_endpoint.clone()),
                    provider_region: Set(intent.provider_region.clone()),
                    credential_epoch: Set(intent.credential_epoch),
                    provider_bucket: Set(intent.provider_bucket.clone()),
                    physical_key: Set(intent.physical_key.clone()),
                    versioning_mode: Set(intent.versioning_mode.clone()),
                    versioning_capability: Set(intent.versioning_capability.clone()),
                    write_operation_id: Set(lease.intent_id),
                    version_id: Set(recorded_version_id.to_string()),
                    epoch: Set(intent.epoch),
                    state: Set(if purging {
                        "PURGE_PENDING".to_string()
                    } else {
                        "LIVE".to_string()
                    }),
                    purge_operation_id: Set(if purging {
                        namespace.purge_operation_id
                    } else {
                        None
                    }),
                    last_error: Set(None),
                    created_at_ms: Set(now),
                    updated_at_ms: Set(now),
                },
            )
            .on_conflict(
                OnConflict::columns([
                    managed_physical_object_version::Column::TenantId,
                    managed_physical_object_version::Column::BackendId,
                    managed_physical_object_version::Column::ProviderBucket,
                    managed_physical_object_version::Column::PhysicalKey,
                    managed_physical_object_version::Column::VersionId,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec_without_returning(&txn)
            .await
            .map_err(persistence)?;
        }
        managed_physical_write_intent::Entity::delete_by_id(lease.intent_id)
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)
    }

    async fn abort_physical_write(&self, lease: &PhysicalWriteLease) -> Result<(), ManagedError> {
        if managed_logical_operation::Entity::find()
            .filter(managed_logical_operation::Column::PrimaryChildOperationId.eq(lease.intent_id))
            .filter(managed_logical_operation::Column::State.is_not_in([
                ManagedLogicalOperationState::Committed.as_str(),
                ManagedLogicalOperationState::ProvenAborted.as_str(),
            ]))
            .count(&self.db)
            .await
            .map_err(persistence)?
            != 0
        {
            return Err(ManagedError::Conflict);
        }
        let result = managed_physical_write_intent::Entity::delete_many()
            .filter(managed_physical_write_intent::Column::IntentId.eq(lease.intent_id))
            .filter(managed_physical_write_intent::Column::LeaseOwner.eq(&lease.owner))
            .filter(managed_physical_write_intent::Column::LeaseToken.eq(lease.token))
            .filter(
                managed_physical_write_intent::Column::LeaseExpiresAtMs
                    .gt(crate::transaction::unix_time_ms()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        (result.rows_affected == 1)
            .then_some(())
            .ok_or(ManagedError::Conflict)
    }

    async fn block_physical_write(
        &self,
        lease: &PhysicalWriteLease,
        reason: &str,
    ) -> Result<(), ManagedError> {
        let result = managed_physical_write_intent::Entity::update_many()
            .col_expr(
                managed_physical_write_intent::Column::State,
                Expr::value("BLOCKED"),
            )
            .col_expr(
                managed_physical_write_intent::Column::LastError,
                Expr::value(Some(reason.chars().take(1024).collect::<String>())),
            )
            .col_expr(
                managed_physical_write_intent::Column::UpdatedAtMs,
                Expr::value(crate::transaction::unix_time_ms()),
            )
            .filter(managed_physical_write_intent::Column::IntentId.eq(lease.intent_id))
            .filter(managed_physical_write_intent::Column::LeaseOwner.eq(&lease.owner))
            .filter(managed_physical_write_intent::Column::LeaseToken.eq(lease.token))
            .filter(
                managed_physical_write_intent::Column::LeaseExpiresAtMs
                    .gt(crate::transaction::unix_time_ms()),
            )
            .exec(&self.db)
            .await
            .map_err(persistence)?;
        (result.rows_affected == 1)
            .then_some(())
            .ok_or(ManagedError::Conflict)
    }

    async fn physical_versions(
        &self,
        tenant_id: &str,
        backend_id: &str,
        provider_bucket: &str,
        physical_key: &str,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        managed_physical_object_version::Entity::find()
            .filter(managed_physical_object_version::Column::TenantId.eq(tenant_id))
            .filter(managed_physical_object_version::Column::BackendId.eq(backend_id))
            .filter(managed_physical_object_version::Column::ProviderBucket.eq(provider_bucket))
            .filter(managed_physical_object_version::Column::PhysicalKey.eq(physical_key))
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(physical_target_from_model)
            .collect()
    }

    async fn forget_physical_version(
        &self,
        target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        // Exact versions for one child may be deleted concurrently. Locking the
        // parent makes one deleter observe the final empty child ledger.
        let operation = managed_logical_operation::Entity::find()
            .filter(
                managed_logical_operation::Column::PrimaryChildOperationId
                    .eq(target.write_operation_id),
            )
            .lock(LockType::Update)
            .one(&txn)
            .await
            .map_err(persistence)?
            .map(logical_operation_from_model)
            .transpose()?;
        let deleted = managed_physical_object_version::Entity::delete_many()
            .filter(managed_physical_object_version::Column::TenantId.eq(&target.tenant_id))
            .filter(managed_physical_object_version::Column::BackendId.eq(&target.backend_id))
            .filter(
                managed_physical_object_version::Column::ProviderBucket.eq(&target.provider_bucket),
            )
            .filter(managed_physical_object_version::Column::PhysicalKey.eq(&target.physical_key))
            .filter(
                managed_physical_object_version::Column::WriteOperationId
                    .eq(target.write_operation_id),
            )
            .filter(
                managed_physical_object_version::Column::VersionId
                    .eq(target.version_id.as_deref().unwrap_or_default()),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if deleted.rows_affected == 0 {
            txn.commit().await.map_err(persistence)?;
            return Ok(());
        }
        let remaining = managed_physical_object_version::Entity::find()
            .filter(
                managed_physical_object_version::Column::WriteOperationId
                    .eq(target.write_operation_id),
            )
            .count(&txn)
            .await
            .map_err(persistence)?;
        if remaining == 0 {
            if let Some(operation) = operation {
                let released = operation
                    .committed_physical_bytes
                    .checked_sub(operation.released_physical_bytes)
                    .ok_or_else(|| {
                        ManagedError::Corrupt(
                            "managed operation released bytes exceed committed bytes".to_string(),
                        )
                    })?;
                if released > 0 {
                    let mut usage =
                        locked_workspace_usage(&txn, &operation.intent.logical.tenant_id).await?;
                    let released = i64_from_u64(released, "managed released physical bytes")?;
                    usage.physical_allocated_bytes = usage
                        .physical_allocated_bytes
                        .checked_sub(released)
                        .ok_or_else(|| {
                            ManagedError::Corrupt(
                                "managed physical usage is below the child allocation".to_string(),
                            )
                        })?;
                    let now = crate::transaction::unix_time_ms();
                    usage.version = usage.version.saturating_add(1);
                    usage.updated_at_ms = now;
                    managed_workspace_usage::Entity::update_many()
                        .col_expr(
                            managed_workspace_usage::Column::PhysicalAllocatedBytes,
                            Expr::value(usage.physical_allocated_bytes),
                        )
                        .col_expr(
                            managed_workspace_usage::Column::Version,
                            Expr::value(usage.version),
                        )
                        .col_expr(
                            managed_workspace_usage::Column::UpdatedAtMs,
                            Expr::value(now),
                        )
                        .filter(
                            managed_workspace_usage::Column::TenantId
                                .eq(&operation.intent.logical.tenant_id),
                        )
                        .exec(&txn)
                        .await
                        .map_err(persistence)?;
                    managed_logical_operation::Entity::update_many()
                        .col_expr(
                            managed_logical_operation::Column::ReleasedPhysicalBytes,
                            Expr::value(i64_from_u64(
                                operation.committed_physical_bytes,
                                "managed committed physical bytes",
                            )?),
                        )
                        .col_expr(
                            managed_logical_operation::Column::UpdatedAtMs,
                            Expr::value(now),
                        )
                        .filter(
                            managed_logical_operation::Column::OperationId
                                .eq(operation.intent.operation_id),
                        )
                        .exec(&txn)
                        .await
                        .map_err(persistence)?;
                }
            }
            object_operation::Entity::delete_many()
                .filter(object_operation::Column::Id.eq(target.write_operation_id))
                .filter(object_operation::Column::State.is_in([
                    crate::transaction::OperationState::Committed.as_str(),
                    crate::transaction::OperationState::ProvenAborted.as_str(),
                ]))
                .exec(&txn)
                .await
                .map_err(persistence)?;
        }
        txn.commit().await.map_err(persistence)
    }

    async fn purge_namespace(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        if let Some(existing) = managed_namespace_purge::Entity::find_by_id(request.operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?
        {
            if existing.tenant_id != request.tenant_id {
                return Ok(NamespacePurgeStatus::Blocked {
                    reason: "purge operation belongs to another namespace".to_string(),
                });
            }
            return self.finalize_purge_if_ready(request).await;
        }

        let txn = self.db.begin().await.map_err(persistence)?;
        let namespace = locked_namespace(&txn, &request.tenant_id).await?;
        if let Some(existing) = managed_namespace_purge::Entity::find_by_id(request.operation_id)
            .one(&txn)
            .await
            .map_err(persistence)?
        {
            txn.commit().await.map_err(persistence)?;
            if existing.tenant_id != request.tenant_id {
                return Ok(NamespacePurgeStatus::Blocked {
                    reason: "purge operation belongs to another namespace".to_string(),
                });
            }
            return self.finalize_purge_if_ready(request).await;
        }
        if namespace.state == "PURGING" {
            return Ok(NamespacePurgeStatus::Blocked {
                reason: "another managed namespace purge is already running".to_string(),
            });
        }
        let authorities = managed_object_authority::Entity::find()
            .filter(managed_object_authority::Column::TenantId.eq(&request.tenant_id))
            .all(&txn)
            .await
            .map_err(persistence)?;
        for authority_model in authorities {
            let authority = authority_from_model(authority_model)?;
            if authority.tombstone {
                continue;
            }
            let physical_key = generation_physical_key(&authority.logical, authority.generation);
            let required_backends = std::iter::once(authority.primary_backend_id.as_str()).chain(
                authority
                    .replica_backend_id
                    .as_deref()
                    .filter(|_| authority.replica_status == CopyStatus::Ready),
            );
            for backend_id in required_backends {
                let versions = managed_physical_object_version::Entity::find()
                    .filter(
                        managed_physical_object_version::Column::TenantId.eq(&request.tenant_id),
                    )
                    .filter(managed_physical_object_version::Column::BackendId.eq(backend_id))
                    .filter(managed_physical_object_version::Column::PhysicalKey.eq(&physical_key))
                    .count(&txn)
                    .await
                    .map_err(persistence)?;
                if versions == 0 {
                    return Ok(NamespacePurgeStatus::Blocked {
                        reason: format!(
                            "managed authority references unledgered physical versions on backend {backend_id}"
                        ),
                    });
                }
            }
        }
        let now = crate::transaction::unix_time_ms();
        managed_namespace_purge::Entity::insert(managed_namespace_purge::ActiveModel {
            operation_id: Set(request.operation_id),
            tenant_id: Set(request.tenant_id.clone()),
            epoch: Set(namespace.epoch),
            state: Set("RUNNING".to_string()),
            blocked_reason: Set(None),
            deleted_versions: Set(0),
            created_at_ms: Set(now),
            updated_at_ms: Set(now),
            completed_at_ms: Set(None),
        })
        .exec(&txn)
        .await
        .map_err(persistence)?;
        managed_namespace::Entity::update_many()
            .col_expr(managed_namespace::Column::State, Expr::value("PURGING"))
            .col_expr(
                managed_namespace::Column::PurgeOperationId,
                Expr::value(Some(request.operation_id)),
            )
            .col_expr(managed_namespace::Column::UpdatedAtMs, Expr::value(now))
            .filter(managed_namespace::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_namespace::Column::State.eq("ACTIVE"))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_physical_object_version::Entity::update_many()
            .col_expr(
                managed_physical_object_version::Column::State,
                Expr::value("PURGE_PENDING"),
            )
            .col_expr(
                managed_physical_object_version::Column::PurgeOperationId,
                Expr::value(Some(request.operation_id)),
            )
            .col_expr(
                managed_physical_object_version::Column::LastError,
                Expr::value(Option::<String>::None),
            )
            .col_expr(
                managed_physical_object_version::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_physical_object_version::Column::TenantId.eq(&request.tenant_id))
            .filter(managed_physical_object_version::Column::Epoch.lte(namespace.epoch))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)?;
        self.finalize_purge_if_ready(request).await
    }

    async fn namespace_purge_status(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        self.finalize_purge_if_ready(request).await
    }

    async fn purge_targets(
        &self,
        request: &NamespacePurgeRequest,
        limit: u64,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        let purge = managed_namespace_purge::Entity::find_by_id(request.operation_id)
            .one(&self.db)
            .await
            .map_err(persistence)?;
        if purge.as_ref().map(|value| value.tenant_id.as_str()) != Some(&request.tenant_id) {
            return Err(ManagedError::Conflict);
        }
        managed_physical_object_version::Entity::find()
            .filter(managed_physical_object_version::Column::TenantId.eq(&request.tenant_id))
            .filter(
                managed_physical_object_version::Column::PurgeOperationId.eq(request.operation_id),
            )
            .filter(
                Condition::any()
                    .add(managed_physical_object_version::Column::State.eq("PURGE_PENDING"))
                    .add(managed_physical_object_version::Column::State.eq("PURGE_BLOCKED")),
            )
            .order_by_asc(managed_physical_object_version::Column::UpdatedAtMs)
            .limit(limit)
            .all(&self.db)
            .await
            .map_err(persistence)?
            .into_iter()
            .map(physical_target_from_model)
            .collect()
    }

    async fn mark_purge_target_deleted(
        &self,
        request: &NamespacePurgeRequest,
        target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        let txn = self.db.begin().await.map_err(persistence)?;
        let result = managed_physical_object_version::Entity::delete_many()
            .filter(managed_physical_object_version::Column::TenantId.eq(&target.tenant_id))
            .filter(managed_physical_object_version::Column::BackendId.eq(&target.backend_id))
            .filter(
                managed_physical_object_version::Column::ProviderBucket.eq(&target.provider_bucket),
            )
            .filter(managed_physical_object_version::Column::PhysicalKey.eq(&target.physical_key))
            .filter(
                managed_physical_object_version::Column::VersionId
                    .eq(target.version_id.as_deref().unwrap_or_default()),
            )
            .filter(
                managed_physical_object_version::Column::PurgeOperationId.eq(request.operation_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        if result.rows_affected == 1 {
            managed_namespace_purge::Entity::update_many()
                .col_expr(
                    managed_namespace_purge::Column::DeletedVersions,
                    Expr::col(managed_namespace_purge::Column::DeletedVersions).add(1),
                )
                .col_expr(
                    managed_namespace_purge::Column::State,
                    Expr::value("RUNNING"),
                )
                .col_expr(
                    managed_namespace_purge::Column::BlockedReason,
                    Expr::value(Option::<String>::None),
                )
                .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
                .exec(&txn)
                .await
                .map_err(persistence)?;
            let remaining = managed_physical_object_version::Entity::find()
                .filter(
                    managed_physical_object_version::Column::WriteOperationId
                        .eq(target.write_operation_id),
                )
                .count(&txn)
                .await
                .map_err(persistence)?;
            if remaining == 0 {
                object_operation::Entity::delete_many()
                    .filter(object_operation::Column::Id.eq(target.write_operation_id))
                    .filter(object_operation::Column::State.is_in([
                        crate::transaction::OperationState::Committed.as_str(),
                        crate::transaction::OperationState::ProvenAborted.as_str(),
                    ]))
                    .exec(&txn)
                    .await
                    .map_err(persistence)?;
            }
        }
        txn.commit().await.map_err(persistence)
    }

    async fn mark_purge_target_blocked(
        &self,
        request: &NamespacePurgeRequest,
        target: &PhysicalVersionTarget,
        reason: &str,
    ) -> Result<(), ManagedError> {
        let reason = reason.chars().take(1024).collect::<String>();
        let now = crate::transaction::unix_time_ms();
        let txn = self.db.begin().await.map_err(persistence)?;
        managed_physical_object_version::Entity::update_many()
            .col_expr(
                managed_physical_object_version::Column::State,
                Expr::value("PURGE_BLOCKED"),
            )
            .col_expr(
                managed_physical_object_version::Column::LastError,
                Expr::value(Some(reason.clone())),
            )
            .col_expr(
                managed_physical_object_version::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_physical_object_version::Column::TenantId.eq(&target.tenant_id))
            .filter(managed_physical_object_version::Column::BackendId.eq(&target.backend_id))
            .filter(
                managed_physical_object_version::Column::ProviderBucket.eq(&target.provider_bucket),
            )
            .filter(managed_physical_object_version::Column::PhysicalKey.eq(&target.physical_key))
            .filter(
                managed_physical_object_version::Column::VersionId
                    .eq(target.version_id.as_deref().unwrap_or_default()),
            )
            .filter(
                managed_physical_object_version::Column::PurgeOperationId.eq(request.operation_id),
            )
            .exec(&txn)
            .await
            .map_err(persistence)?;
        managed_namespace_purge::Entity::update_many()
            .col_expr(
                managed_namespace_purge::Column::State,
                Expr::value("BLOCKED"),
            )
            .col_expr(
                managed_namespace_purge::Column::BlockedReason,
                Expr::value(Some(reason)),
            )
            .col_expr(
                managed_namespace_purge::Column::UpdatedAtMs,
                Expr::value(now),
            )
            .filter(managed_namespace_purge::Column::OperationId.eq(request.operation_id))
            .exec(&txn)
            .await
            .map_err(persistence)?;
        txn.commit().await.map_err(persistence)
    }
}

#[derive(Default)]
struct MemoryState {
    authorities: HashMap<LogicalObjectKey, ObjectAuthority>,
    logical_operations: HashMap<Uuid, ManagedLogicalOperation>,
    workspace_usage: HashMap<String, ManagedWorkspaceUsage>,
    list_cursors: HashMap<Uuid, ManagedListCursor>,
    list_cursor_successors: HashMap<Uuid, Uuid>,
    repairs: HashMap<Uuid, (RepairRecord, String)>,
    physical_write_intents: HashMap<Uuid, PhysicalWriteIntent>,
    blocked_write_intents: HashMap<Uuid, String>,
    physical_write_leases: HashMap<Uuid, i64>,
    physical_write_tokens: HashMap<Uuid, Uuid>,
    physical_write_epochs: HashMap<Uuid, u64>,
    physical_versions: Vec<PhysicalVersionTarget>,
    fenced_namespaces: HashMap<String, Uuid>,
    purges: HashMap<Uuid, MemoryPurge>,
    namespace_epochs: HashMap<String, u64>,
    routing_epochs: HashMap<String, u64>,
    multipart_activities: HashMap<String, (String, u64)>,
    confirmed_multipart_activities: HashSet<String>,
    multipart_registration_expiry: HashMap<String, i64>,
    placement_policy_fingerprints: HashMap<u32, String>,
}

#[derive(Clone)]
struct MemoryPurge {
    tenant_id: String,
    status: NamespacePurgeStatus,
    deleted_versions: u64,
}

#[derive(Clone, Default)]
pub struct InMemoryManagedRepository {
    state: Arc<Mutex<MemoryState>>,
}

impl InMemoryManagedRepository {
    pub fn new() -> Self {
        Self::default()
    }

    fn workspace_usage<'a>(
        state: &'a mut MemoryState,
        tenant_id: &str,
    ) -> &'a mut ManagedWorkspaceUsage {
        let now = crate::transaction::unix_time_ms();
        state
            .workspace_usage
            .entry(tenant_id.to_string())
            .or_insert_with(|| ManagedWorkspaceUsage {
                tenant_id: tenant_id.to_string(),
                visible_logical_bytes: 0,
                physical_allocated_bytes: 0,
                reserved_bytes: 0,
                visible_limit_bytes: MANAGED_VISIBLE_LIMIT_BYTES,
                replacement_headroom_bytes: MANAGED_REPLACEMENT_HEADROOM_BYTES,
                active_operation_id: None,
                version: 1,
                created_at_ms: now,
                updated_at_ms: now,
            })
    }

    fn create_list_cursor_in_state(
        state: &mut MemoryState,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let response_state_bytes =
            serialize_cursor_response_state(&request.response_state)?.len() as u64;
        if state
            .fenced_namespaces
            .contains_key(&request.binding.tenant_id)
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let workspace_count = state
            .list_cursors
            .values()
            .filter(|cursor| {
                cursor.binding.tenant_id == request.binding.tenant_id
                    && cursor.expires_at_ms > now_ms
            })
            .count() as u64;
        let global_count = state
            .list_cursors
            .values()
            .filter(|cursor| cursor.expires_at_ms > now_ms)
            .count() as u64;
        let workspace_bytes = state
            .list_cursors
            .values()
            .filter(|cursor| {
                cursor.binding.tenant_id == request.binding.tenant_id
                    && cursor.expires_at_ms > now_ms
            })
            .try_fold(0_u64, |total, cursor| {
                total
                    .checked_add(cursor.response_state_bytes)
                    .ok_or(ManagedError::CursorLimitExceeded)
            })?;
        let global_bytes = state
            .list_cursors
            .values()
            .filter(|cursor| cursor.expires_at_ms > now_ms)
            .try_fold(0_u64, |total, cursor| {
                total
                    .checked_add(cursor.response_state_bytes)
                    .ok_or(ManagedError::CursorLimitExceeded)
            })?;
        if workspace_count >= MANAGED_LIST_CURSOR_WORKSPACE_LIMIT
            || global_count >= MANAGED_LIST_CURSOR_GLOBAL_LIMIT
            || workspace_bytes
                .checked_add(response_state_bytes)
                .is_none_or(|bytes| bytes > MANAGED_LIST_CURSOR_WORKSPACE_MAX_BYTES)
            || global_bytes
                .checked_add(response_state_bytes)
                .is_none_or(|bytes| bytes > MANAGED_LIST_CURSOR_GLOBAL_MAX_BYTES)
        {
            return Err(ManagedError::CursorLimitExceeded);
        }
        let fence = ManagedRouteFence {
            namespace_epoch: *state
                .namespace_epochs
                .entry(request.binding.tenant_id.clone())
                .or_insert(1),
            routing_epoch: *state
                .routing_epochs
                .entry(request.binding.tenant_id.clone())
                .or_insert(1),
        };
        let cursor = ManagedListCursor {
            id: Uuid::new_v4(),
            binding: request.binding,
            fence,
            position: request.position,
            response_state: request.response_state,
            response_state_bytes,
            final_page: request.final_page,
            state: ManagedListCursorState::Active,
            created_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(MANAGED_LIST_CURSOR_TTL_MS),
            first_used_at_ms: None,
        };
        state.list_cursors.insert(cursor.id, cursor.clone());
        Ok(cursor)
    }

    fn remove_list_cursor(state: &mut MemoryState, cursor_id: Uuid) {
        if let Some(successor_id) = state.list_cursor_successors.remove(&cursor_id) {
            Self::remove_list_cursor(state, successor_id);
        }
        state
            .list_cursor_successors
            .retain(|_, successor_id| *successor_id != cursor_id);
        state.list_cursors.remove(&cursor_id);
    }

    fn finish_purge(state: &mut MemoryState, operation_id: Uuid) -> NamespacePurgeStatus {
        let Some(purge) = state.purges.get(&operation_id).cloned() else {
            return NamespacePurgeStatus::Blocked {
                reason: "managed namespace purge operation was not found".to_string(),
            };
        };
        if matches!(purge.status, NamespacePurgeStatus::Complete { .. }) {
            return purge.status;
        }
        if let Some(reason) = state
            .blocked_write_intents
            .iter()
            .find_map(|(intent_id, reason)| {
                state
                    .physical_write_intents
                    .get(intent_id)
                    .filter(|intent| intent.tenant_id == purge.tenant_id)
                    .map(|_| reason.clone())
            })
        {
            let blocked = NamespacePurgeStatus::Blocked { reason };
            if let Some(purge) = state.purges.get_mut(&operation_id) {
                purge.status = blocked.clone();
            }
            return blocked;
        }
        if state.logical_operations.values().any(|operation| {
            operation.intent.logical.tenant_id == purge.tenant_id && !operation.state.terminal()
        }) {
            let blocked = NamespacePurgeStatus::Blocked {
                reason: "managed namespace has unresolved logical operations".to_string(),
            };
            if let Some(purge) = state.purges.get_mut(&operation_id) {
                purge.status = blocked.clone();
            }
            return blocked;
        }
        if state
            .physical_write_intents
            .values()
            .any(|intent| intent.tenant_id == purge.tenant_id)
            || state
                .physical_versions
                .iter()
                .any(|target| target.tenant_id == purge.tenant_id)
            || state
                .multipart_activities
                .values()
                .any(|(tenant_id, _)| tenant_id == &purge.tenant_id)
        {
            return purge.status;
        }
        state
            .authorities
            .retain(|logical, _| logical.tenant_id != purge.tenant_id);
        state
            .repairs
            .retain(|_, (repair, _)| repair.logical.tenant_id != purge.tenant_id);
        let now = crate::transaction::unix_time_ms();
        for operation in state
            .logical_operations
            .values_mut()
            .filter(|operation| operation.intent.logical.tenant_id == purge.tenant_id)
        {
            operation.released_physical_bytes = operation.committed_physical_bytes;
            operation.updated_at_ms = now;
        }
        if let Some(usage) = state.workspace_usage.get_mut(&purge.tenant_id) {
            usage.visible_logical_bytes = 0;
            usage.physical_allocated_bytes = 0;
            usage.reserved_bytes = 0;
            usage.active_operation_id = None;
            usage.version = usage.version.saturating_add(1);
            usage.updated_at_ms = now;
        }
        state
            .list_cursors
            .retain(|_, cursor| cursor.binding.tenant_id != purge.tenant_id);
        let live_cursor_ids = state.list_cursors.keys().copied().collect::<HashSet<_>>();
        state
            .list_cursor_successors
            .retain(|predecessor, successor| {
                live_cursor_ids.contains(predecessor) && live_cursor_ids.contains(successor)
            });
        state.fenced_namespaces.remove(&purge.tenant_id);
        *state
            .namespace_epochs
            .entry(purge.tenant_id.clone())
            .or_insert(1) += 1;
        *state
            .routing_epochs
            .entry(purge.tenant_id.clone())
            .or_insert(1) += 1;
        let complete = NamespacePurgeStatus::Complete {
            deleted_versions: purge.deleted_versions,
        };
        if let Some(purge) = state.purges.get_mut(&operation_id) {
            purge.status = complete.clone();
        }
        complete
    }
}

fn insert_memory_repair(state: &mut MemoryState, repair: RepairRecord) {
    let duplicate = state.repairs.iter_mut().find(|(_, (existing, _))| {
        existing.kind == repair.kind
            && existing.generation == repair.generation
            && existing.target_backend_id == repair.target_backend_id
    });
    if let Some((_, (existing, status))) = duplicate {
        if status == "DONE" {
            let repair_id = existing.repair_id;
            *existing = repair;
            existing.id = repair_id;
            existing.repair_id = repair_id;
            existing.updated_at_ms = crate::transaction::unix_time_ms();
            existing.lease_owner = None;
            existing.lease_token = None;
            existing.lease_expires_at_ms = None;
            *status = "PENDING".to_string();
        }
    } else {
        state
            .repairs
            .insert(repair.repair_id, (repair, "PENDING".to_string()));
    }
}

fn insert_memory_waiting_placement_cleanup(state: &mut MemoryState, repair: RepairRecord) {
    let duplicate = state.repairs.values().any(|(existing, _)| {
        existing.kind == repair.kind
            && existing.generation == repair.generation
            && existing.target_backend_id == repair.target_backend_id
    });
    if !duplicate {
        state
            .repairs
            .insert(repair.repair_id, (repair, "WAITING_CUTOVER".to_string()));
    }
}

#[async_trait]
impl ManagedRepository for InMemoryManagedRepository {
    fn is_durable(&self) -> bool {
        false
    }

    async fn assert_namespace_active(&self, tenant_id: &str) -> Result<(), ManagedError> {
        if self
            .state
            .lock()
            .await
            .fenced_namespaces
            .contains_key(tenant_id)
        {
            Err(ManagedError::NamespaceFenced)
        } else {
            Ok(())
        }
    }

    async fn route_fence(&self, tenant_id: &str) -> Result<ManagedRouteFence, ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let namespace_epoch = *state
            .namespace_epochs
            .entry(tenant_id.to_string())
            .or_insert(1);
        let routing_epoch = *state
            .routing_epochs
            .entry(tenant_id.to_string())
            .or_insert(1);
        Ok(ManagedRouteFence {
            namespace_epoch,
            routing_epoch,
        })
    }

    async fn advance_routing_epoch(
        &self,
        tenant_id: &str,
        expected_routing_epoch: u64,
    ) -> Result<ManagedRouteFence, ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let namespace_epoch = *state
            .namespace_epochs
            .entry(tenant_id.to_string())
            .or_insert(1);
        let routing_epoch = state
            .routing_epochs
            .entry(tenant_id.to_string())
            .or_insert(1);
        if *routing_epoch != expected_routing_epoch {
            return Err(ManagedError::Conflict);
        }
        *routing_epoch = routing_epoch
            .checked_add(1)
            .ok_or_else(|| ManagedError::Corrupt("managed routing epoch overflow".to_string()))?;
        Ok(ManagedRouteFence {
            namespace_epoch,
            routing_epoch: *routing_epoch,
        })
    }

    async fn insert_logical_operation(
        &self,
        intent: ManagedLogicalOperationIntent,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        validate_logical_intent(&intent)?;
        let mut state = self.state.lock().await;
        if state
            .fenced_namespaces
            .contains_key(&intent.logical.tenant_id)
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let namespace_epoch = *state
            .namespace_epochs
            .entry(intent.logical.tenant_id.clone())
            .or_insert(1);
        let routing_epoch = *state
            .routing_epochs
            .entry(intent.logical.tenant_id.clone())
            .or_insert(1);
        if intent.fence
            != (ManagedRouteFence {
                namespace_epoch,
                routing_epoch,
            })
        {
            return Err(ManagedError::Conflict);
        }
        if let Some(existing) = state.logical_operations.get(&intent.operation_id) {
            return (existing.intent == intent)
                .then(|| existing.clone())
                .ok_or(ManagedError::Conflict);
        }
        if state.logical_operations.values().any(|operation| {
            operation.intent.receipt_id == intent.receipt_id
                || operation.intent.primary_child_operation_id == intent.primary_child_operation_id
        }) || state
            .physical_write_intents
            .contains_key(&intent.primary_child_operation_id)
            || state
                .physical_versions
                .iter()
                .any(|target| target.write_operation_id == intent.primary_child_operation_id)
        {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        let operation = ManagedLogicalOperation {
            intent,
            evidence: None,
            reserved_physical_bytes: 0,
            committed_physical_bytes: 0,
            released_physical_bytes: 0,
            state: ManagedLogicalOperationState::Intent,
            committed_authority_version: None,
            settlement_state: ManagedSettlementState::Pending,
            last_error_class: None,
            recovery_owner: None,
            recovery_token: None,
            recovery_expires_at_ms: None,
            created_at_ms: now,
            updated_at_ms: now,
            committed_at_ms: None,
            aborted_at_ms: None,
        };
        state
            .logical_operations
            .insert(operation.intent.operation_id, operation.clone());
        Ok(operation)
    }

    async fn logical_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<ManagedLogicalOperation>, ManagedError> {
        Ok(self
            .state
            .lock()
            .await
            .logical_operations
            .get(&operation_id)
            .cloned())
    }

    async fn pending_logical_operations(
        &self,
        limit: u64,
    ) -> Result<Vec<ManagedLogicalOperation>, ManagedError> {
        let mut operations: Vec<_> = self
            .state
            .lock()
            .await
            .logical_operations
            .values()
            .filter(|operation| !operation.state.terminal())
            .cloned()
            .collect();
        operations.sort_by_key(|operation| operation.updated_at_ms);
        operations.truncate(limit as usize);
        Ok(operations)
    }

    async fn pending_delete_settlements(
        &self,
        limit: u64,
    ) -> Result<Vec<ManagedLogicalOperation>, ManagedError> {
        let mut operations: Vec<_> = self
            .state
            .lock()
            .await
            .logical_operations
            .values()
            .filter(|operation| {
                operation.intent.kind == ManagedMutationKind::Delete
                    && operation.state == ManagedLogicalOperationState::Committed
                    && operation.settlement_state == ManagedSettlementState::Pending
            })
            .cloned()
            .collect();
        operations.sort_by_key(|operation| operation.updated_at_ms);
        operations.truncate(limit as usize);
        Ok(operations)
    }

    async fn mark_logical_operation_settled(
        &self,
        operation_id: Uuid,
        receipt_id: Uuid,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get_mut(&operation_id)
            .ok_or(ManagedError::Conflict)?;
        if operation.intent.receipt_id != receipt_id
            || operation.intent.kind != ManagedMutationKind::Delete
            || operation.state != ManagedLogicalOperationState::Committed
            || !matches!(
                operation.settlement_state,
                ManagedSettlementState::Pending | ManagedSettlementState::Settled
            )
        {
            return Err(ManagedError::Conflict);
        }
        operation.settlement_state = ManagedSettlementState::Settled;
        operation.updated_at_ms = crate::transaction::unix_time_ms();
        Ok(())
    }

    async fn defer_delete_settlement(
        &self,
        operation_id: Uuid,
        receipt_id: Uuid,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get_mut(&operation_id)
            .ok_or(ManagedError::Conflict)?;
        if operation.intent.receipt_id != receipt_id
            || operation.intent.kind != ManagedMutationKind::Delete
            || operation.state != ManagedLogicalOperationState::Committed
            || operation.settlement_state != ManagedSettlementState::Pending
        {
            return Err(ManagedError::Conflict);
        }
        operation.updated_at_ms = crate::transaction::unix_time_ms().saturating_add(60_000);
        Ok(())
    }

    async fn claim_stale_logical_operations(
        &self,
        owner: &str,
        stale_before_ms: i64,
        claim_expires_at_ms: i64,
        limit: u64,
    ) -> Result<Vec<ManagedRecoveryClaim>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        if owner.is_empty() || owner.len() > 256 || claim_expires_at_ms <= now {
            return Err(ManagedError::Conflict);
        }
        let mut state = self.state.lock().await;
        let mut ids = state
            .logical_operations
            .values()
            .filter(|operation| {
                !operation.state.terminal()
                    && operation.intent.kind == ManagedMutationKind::Put
                    && operation.updated_at_ms <= stale_before_ms
                    && operation
                        .recovery_expires_at_ms
                        .is_none_or(|expires| expires <= now)
            })
            .map(|operation| (operation.updated_at_ms, operation.intent.operation_id))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.truncate(limit as usize);
        Ok(ids
            .into_iter()
            .map(|(_, operation_id)| {
                let token = Uuid::now_v7();
                let operation = state.logical_operations.get_mut(&operation_id).unwrap();
                operation.recovery_owner = Some(owner.to_string());
                operation.recovery_token = Some(token);
                operation.recovery_expires_at_ms = Some(claim_expires_at_ms);
                ManagedRecoveryClaim {
                    operation: operation.clone(),
                    owner: owner.to_string(),
                    token,
                    expires_at_ms: claim_expires_at_ms,
                }
            })
            .collect())
    }

    async fn mark_logical_recovery_blocked(
        &self,
        claim: &ManagedRecoveryClaim,
        reason: &str,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get_mut(&claim.operation.intent.operation_id)
            .ok_or(ManagedError::Conflict)?;
        if operation.recovery_owner.as_deref() != Some(&claim.owner)
            || operation.recovery_token != Some(claim.token)
            || operation.recovery_expires_at_ms != Some(claim.expires_at_ms)
            || claim.expires_at_ms <= crate::transaction::unix_time_ms()
            || operation.state.terminal()
        {
            return Err(ManagedError::Conflict);
        }
        operation.state = ManagedLogicalOperationState::RecoveryBlocked;
        operation.last_error_class = Some(reason.chars().take(128).collect());
        operation.recovery_owner = None;
        operation.recovery_token = None;
        operation.recovery_expires_at_ms = None;
        operation.updated_at_ms = crate::transaction::unix_time_ms();
        Ok(operation.clone())
    }

    async fn renew_logical_recovery_claim(
        &self,
        claim: &ManagedRecoveryClaim,
        claim_expires_at_ms: i64,
    ) -> Result<ManagedRecoveryClaim, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        if claim_expires_at_ms <= now {
            return Err(ManagedError::Conflict);
        }
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get_mut(&claim.operation.intent.operation_id)
            .ok_or(ManagedError::Conflict)?;
        if operation.state.terminal()
            || operation.recovery_owner.as_deref() != Some(&claim.owner)
            || operation.recovery_token != Some(claim.token)
            || operation.recovery_expires_at_ms != Some(claim.expires_at_ms)
            || claim.expires_at_ms <= now
        {
            return Err(ManagedError::Conflict);
        }
        operation.recovery_expires_at_ms = Some(claim_expires_at_ms);
        Ok(ManagedRecoveryClaim {
            operation: operation.clone(),
            owner: claim.owner.clone(),
            token: claim.token,
            expires_at_ms: claim_expires_at_ms,
        })
    }

    async fn reserve_logical_operation(
        &self,
        operation_id: Uuid,
        physical_bytes: u64,
    ) -> Result<ManagedWorkspaceUsage, ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get(&operation_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        if state
            .fenced_namespaces
            .contains_key(&operation.intent.logical.tenant_id)
            || state
                .namespace_epochs
                .get(&operation.intent.logical.tenant_id)
                .copied()
                .unwrap_or(1)
                != operation.intent.fence.namespace_epoch
            || state
                .routing_epochs
                .get(&operation.intent.logical.tenant_id)
                .copied()
                .unwrap_or(1)
                != operation.intent.fence.routing_epoch
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        if operation.state == ManagedLogicalOperationState::Open
            && operation.reserved_physical_bytes == physical_bytes
            && usage.active_operation_id == Some(operation_id)
        {
            return Ok(usage.clone());
        }
        if operation.state != ManagedLogicalOperationState::Intent {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::Open,
            });
        }
        if usage.active_operation_id.is_some() {
            return Err(ManagedError::MutationInProgress);
        }
        let bound = usage
            .visible_limit_bytes
            .checked_add(usage.replacement_headroom_bytes)
            .ok_or(ManagedError::QuotaExceeded)?;
        let reserved = usage
            .reserved_bytes
            .checked_add(physical_bytes)
            .ok_or(ManagedError::QuotaExceeded)?;
        if usage
            .physical_allocated_bytes
            .checked_add(reserved)
            .is_none_or(|value| value > bound)
        {
            return Err(ManagedError::QuotaExceeded);
        }
        let now = crate::transaction::unix_time_ms();
        usage.reserved_bytes = reserved;
        usage.active_operation_id = Some(operation_id);
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        let result = usage.clone();
        let operation = state.logical_operations.get_mut(&operation_id).unwrap();
        operation.reserved_physical_bytes = physical_bytes;
        operation.state = ManagedLogicalOperationState::Open;
        operation.updated_at_ms = now;
        Ok(result)
    }

    async fn admit_logical_operation(
        &self,
        intent: ManagedLogicalOperationIntent,
        reservation_cap: u64,
    ) -> Result<(ManagedLogicalOperation, ManagedWorkspaceUsage), ManagedError> {
        self.insert_logical_operation(intent.clone()).await?;
        let reserved = {
            let mut state = self.state.lock().await;
            let usage = Self::workspace_usage(&mut state, &intent.logical.tenant_id);
            let available = usage
                .visible_limit_bytes
                .saturating_add(usage.replacement_headroom_bytes)
                .saturating_sub(usage.physical_allocated_bytes)
                .saturating_sub(usage.reserved_bytes)
                .max(1);
            reservation_cap.min(available)
        };
        let usage = self
            .reserve_logical_operation(intent.operation_id, reserved)
            .await?;
        let operation = self
            .logical_operation(intent.operation_id)
            .await?
            .ok_or(ManagedError::Conflict)?;
        Ok((operation, usage))
    }

    async fn record_logical_usage(
        &self,
        operation_id: Uuid,
        evidence: ManagedUsageEvidence,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        if evidence.processed_bytes != evidence.source_bytes.max(evidence.expected_output_size) {
            return Err(ManagedError::Conflict);
        }
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get_mut(&operation_id)
            .ok_or(ManagedError::Conflict)?;
        if operation.evidence.as_ref() == Some(&evidence) {
            return Ok(operation.clone());
        }
        if operation.evidence.is_some()
            || operation.state == ManagedLogicalOperationState::Intent
            || operation.state.terminal()
            || evidence.processed_bytes > operation.intent.max_processed_bytes
            || (operation.intent.kind == ManagedMutationKind::Put
                && evidence.expected_output_digest.is_none())
            || (operation.intent.kind == ManagedMutationKind::Delete
                && (evidence.expected_output_size != 0
                    || evidence.source_bytes != 0
                    || evidence.processed_bytes != 0))
        {
            return Err(ManagedError::Conflict);
        }
        operation.evidence = Some(evidence);
        operation.updated_at_ms = crate::transaction::unix_time_ms();
        Ok(operation.clone())
    }

    async fn finalize_logical_put(
        &self,
        operation_id: Uuid,
        physical_lease: &PhysicalWriteLease,
        result: ExactPhysicalCommit,
        recovery_claim: Option<&ManagedRecoveryClaim>,
    ) -> Result<ManagedOperationCommit, ManagedError> {
        validate_exact_physical_commit(&result)?;
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get(&operation_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        let now = crate::transaction::unix_time_ms();
        if operation.state == ManagedLogicalOperationState::Committed {
            let persisted = state
                .authorities
                .get(&operation.intent.logical)
                .cloned()
                .ok_or(ManagedError::Conflict)?;
            let persisted_ids = state
                .physical_versions
                .iter()
                .filter(|version| {
                    version.write_operation_id == operation.intent.primary_child_operation_id
                })
                .map(|version| version.version_id.clone().unwrap_or_default())
                .collect::<HashSet<_>>();
            let persisted_targets = state
                .physical_versions
                .iter()
                .filter(|version| {
                    version.write_operation_id == operation.intent.primary_child_operation_id
                })
                .cloned()
                .collect::<Vec<_>>();
            let canonical_target = persisted_targets.first().ok_or(ManagedError::Conflict)?;
            let evidence = operation.evidence.as_ref().ok_or(ManagedError::Conflict)?;
            let recipe = operation
                .intent
                .publication_recipe
                .as_ref()
                .ok_or(ManagedError::Conflict)?;
            let committed_authority_version = operation
                .committed_authority_version
                .ok_or(ManagedError::Conflict)?;
            let original_authority_matches = persisted.generation == operation.intent.generation
                && persisted.digest
                    == evidence
                        .expected_output_digest
                        .clone()
                        .ok_or(ManagedError::Conflict)?
                && persisted.size == evidence.expected_output_size
                && persisted.metadata == recipe.metadata
                && persisted.placement_version == recipe.placement_version
                && persisted.primary_backend_id == recipe.primary_backend_id
                && persisted.primary_version_id == result.selected_version_id
                && persisted.replica_backend_id == recipe.replica_backend_id
                && persisted.primary_status == recipe.primary_status
                && persisted.replica_status == recipe.replica_status
                && !persisted.tombstone;
            if persisted.logical != operation.intent.logical
                || committed_authority_version
                    != operation
                        .intent
                        .expected_authority_cas
                        .unwrap_or(0)
                        .saturating_add(1)
                || persisted.cas_version < committed_authority_version
                || (persisted.cas_version == committed_authority_version
                    && !original_authority_matches)
                || persisted_ids != exact_version_ids(&result).into_iter().collect()
                || persisted_targets.iter().any(|target| {
                    target.tenant_id != operation.intent.logical.tenant_id
                        || target.namespace_epoch != operation.intent.fence.namespace_epoch
                        || target.backend_id != operation.intent.backend_id
                        || target.provider_bucket != operation.intent.provider_bucket
                        || target.physical_key != operation.intent.physical_key
                        || target.storage_identity != canonical_target.storage_identity
                        || target.credential_epoch != canonical_target.credential_epoch
                        || target.versioning_mode != canonical_target.versioning_mode
                        || target.versioning_capability != canonical_target.versioning_capability
                })
                || operation.committed_physical_bytes
                    != physical_allocation(
                        evidence.expected_output_size,
                        persisted_ids.len() as u64,
                    )?
            {
                return Err(ManagedError::Conflict);
            }
            let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
            return Ok(ManagedOperationCommit {
                operation,
                authority: persisted,
                usage: usage.clone(),
            });
        }
        validate_recovery_authority(&operation, recovery_claim, now)?;
        let evidence = operation.evidence.clone().ok_or(ManagedError::Conflict)?;
        let recipe = operation
            .intent
            .publication_recipe
            .clone()
            .ok_or(ManagedError::Conflict)?;
        if operation.intent.kind != ManagedMutationKind::Put
            || !matches!(
                operation.state,
                ManagedLogicalOperationState::Completing
                    | ManagedLogicalOperationState::CommitUnknown
                    | ManagedLogicalOperationState::RecoveryBlocked
            )
            || (operation.state == ManagedLogicalOperationState::RecoveryBlocked
                && recovery_claim.is_none())
            || recipe.version != MANAGED_PUBLICATION_RECIPE_VERSION
            || recipe.primary_backend_id != operation.intent.backend_id
        {
            return Err(ManagedError::Conflict);
        }
        if state
            .fenced_namespaces
            .contains_key(&operation.intent.logical.tenant_id)
            || state
                .namespace_epochs
                .get(&operation.intent.logical.tenant_id)
                .copied()
                .unwrap_or(1)
                != operation.intent.fence.namespace_epoch
            || state
                .routing_epochs
                .get(&operation.intent.logical.tenant_id)
                .copied()
                .unwrap_or(1)
                != operation.intent.fence.routing_epoch
        {
            return Err(ManagedError::RecoveryBlocked("namespace_fence_changed"));
        }
        let physical_intent = state
            .physical_write_intents
            .get(&physical_lease.intent_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        validate_physical_commit_versioning(&physical_intent, &result)?;
        if physical_lease.intent_id != operation.intent.primary_child_operation_id
            || physical_intent.tenant_id != operation.intent.logical.tenant_id
            || physical_intent.backend_id != operation.intent.backend_id
            || physical_intent.provider_bucket != operation.intent.provider_bucket
            || physical_intent.physical_key != operation.intent.physical_key
            || physical_intent.lease_owner != physical_lease.owner
            || state.physical_write_tokens.get(&physical_lease.intent_id)
                != Some(&physical_lease.token)
            || state.physical_write_epochs.get(&physical_lease.intent_id)
                != Some(&physical_lease.namespace_epoch)
            || state
                .physical_write_leases
                .get(&physical_lease.intent_id)
                .is_none_or(|expiry| *expiry <= crate::transaction::unix_time_ms())
            || operation
                .recovery_owner
                .as_ref()
                .is_some_and(|owner| owner != &physical_lease.owner)
        {
            return Err(ManagedError::Conflict);
        }
        let expected_targets =
            expected_physical_targets(&physical_intent, physical_lease.namespace_epoch, &result);
        let preexisting_targets = state
            .physical_versions
            .iter()
            .filter(|target| {
                target.write_operation_id == operation.intent.primary_child_operation_id
            })
            .cloned()
            .collect::<Vec<_>>();
        if preexisting_targets
            .iter()
            .any(|existing| !expected_targets.contains(existing))
        {
            return Err(ManagedError::RecoveryBlocked("physical_version_mismatch"));
        }
        for target in &expected_targets {
            if !state.physical_versions.iter().any(|existing| {
                existing.tenant_id == target.tenant_id
                    && existing.backend_id == target.backend_id
                    && existing.provider_bucket == target.provider_bucket
                    && existing.physical_key == target.physical_key
                    && existing.version_id == target.version_id
            }) {
                state.physical_versions.push(target.clone());
            }
        }
        let child_versions = state
            .physical_versions
            .iter()
            .filter(|target| {
                target.write_operation_id == operation.intent.primary_child_operation_id
                    && target.tenant_id == operation.intent.logical.tenant_id
                    && target.backend_id == operation.intent.backend_id
                    && target.provider_bucket == operation.intent.provider_bucket
                    && target.physical_key == operation.intent.physical_key
            })
            .cloned()
            .collect::<Vec<_>>();
        let derived_physical_allocation =
            physical_allocation(evidence.expected_output_size, child_versions.len() as u64)?;
        if child_versions.len() != expected_targets.len()
            || expected_targets
                .iter()
                .any(|expected| !child_versions.contains(expected))
            || derived_physical_allocation > operation.reserved_physical_bytes
        {
            return Err(ManagedError::RecoveryBlocked("physical_version_mismatch"));
        }
        let existing = state.authorities.get(&operation.intent.logical).cloned();
        if existing.as_ref().map(|value| value.cas_version)
            != operation.intent.expected_authority_cas
            || existing
                .as_ref()
                .filter(|value| !value.tombstone)
                .map_or(0, |value| value.size)
                != operation.intent.prior_logical_size
        {
            return Err(ManagedError::RecoveryBlocked("authority_fence_changed"));
        }
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        if usage.active_operation_id != Some(operation_id)
            || usage.reserved_bytes < operation.reserved_physical_bytes
        {
            return Err(ManagedError::Conflict);
        }
        let visible = usage
            .visible_logical_bytes
            .checked_sub(operation.intent.prior_logical_size)
            .and_then(|value| value.checked_add(evidence.expected_output_size))
            .ok_or(ManagedError::QuotaExceeded)?;
        if visible > usage.visible_limit_bytes {
            return Err(ManagedError::QuotaExceeded);
        }
        let mut authority = ObjectAuthority {
            logical: operation.intent.logical.clone(),
            generation: operation.intent.generation,
            digest: evidence
                .expected_output_digest
                .clone()
                .ok_or(ManagedError::Conflict)?,
            size: evidence.expected_output_size,
            metadata: recipe.metadata,
            placement_version: recipe.placement_version,
            primary_backend_id: recipe.primary_backend_id,
            primary_version_id: result.selected_version_id,
            replica_backend_id: recipe.replica_backend_id,
            primary_status: recipe.primary_status,
            replica_status: recipe.replica_status,
            tombstone: false,
            cas_version: 0,
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        authority.cas_version = operation
            .intent
            .expected_authority_cas
            .unwrap_or(0)
            .saturating_add(1);
        authority.created_at_ms = existing.as_ref().map_or(now, |value| value.created_at_ms);
        authority.updated_at_ms = now;
        let namespace_epoch = operation.intent.fence.namespace_epoch;
        state
            .authorities
            .insert(authority.logical.clone(), authority.clone());
        for mut repair in publication_repairs(&authority) {
            repair.namespace_epoch = namespace_epoch;
            insert_memory_repair(&mut state, repair);
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                if state.physical_versions.iter().any(|target| {
                    target.tenant_id == repair.logical.tenant_id
                        && target.backend_id == repair.target_backend_id
                        && target.physical_key == repair.physical_key
                }) {
                    repair.namespace_epoch = namespace_epoch;
                    insert_memory_repair(&mut state, repair);
                }
            }
        }
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        usage.visible_logical_bytes = visible;
        usage.physical_allocated_bytes = usage
            .physical_allocated_bytes
            .checked_add(derived_physical_allocation)
            .ok_or(ManagedError::QuotaExceeded)?;
        usage.reserved_bytes = usage
            .reserved_bytes
            .checked_sub(operation.reserved_physical_bytes)
            .ok_or(ManagedError::Conflict)?;
        usage.active_operation_id = None;
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        let committed_usage = usage.clone();
        let operation = state.logical_operations.get_mut(&operation_id).unwrap();
        operation.state = ManagedLogicalOperationState::Committed;
        operation.committed_physical_bytes = derived_physical_allocation;
        operation.committed_authority_version = Some(authority.cas_version);
        operation.updated_at_ms = now;
        operation.committed_at_ms = Some(now);
        operation.recovery_owner = None;
        operation.recovery_token = None;
        operation.recovery_expires_at_ms = None;
        let committed_operation = operation.clone();
        state
            .physical_write_intents
            .remove(&physical_lease.intent_id);
        state
            .blocked_write_intents
            .remove(&physical_lease.intent_id);
        state
            .physical_write_leases
            .remove(&physical_lease.intent_id);
        state
            .physical_write_tokens
            .remove(&physical_lease.intent_id);
        state
            .physical_write_epochs
            .remove(&physical_lease.intent_id);
        Ok(ManagedOperationCommit {
            operation: committed_operation,
            authority,
            usage: committed_usage,
        })
    }

    async fn commit_logical_delete(
        &self,
        operation_id: Uuid,
        placement: &Placement,
    ) -> Result<ManagedOperationCommit, ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get(&operation_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        if operation.state == ManagedLogicalOperationState::Committed {
            let authority = state
                .authorities
                .get(&operation.intent.logical)
                .cloned()
                .filter(|authority| {
                    authority.tombstone && authority.generation == operation.intent.generation
                })
                .ok_or(ManagedError::Conflict)?;
            let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
            return Ok(ManagedOperationCommit {
                operation,
                authority,
                usage: usage.clone(),
            });
        }
        if operation.intent.kind != ManagedMutationKind::Delete
            || operation.reserved_physical_bytes != 0
            || operation.evidence.as_ref().is_none_or(|evidence| {
                evidence.expected_output_size != 0
                    || evidence.source_bytes != 0
                    || evidence.processed_bytes != 0
            })
            || !matches!(
                operation.state,
                ManagedLogicalOperationState::Completing
                    | ManagedLogicalOperationState::CommitUnknown
            )
        {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::Committed,
            });
        }
        if state
            .fenced_namespaces
            .contains_key(&operation.intent.logical.tenant_id)
            || state
                .namespace_epochs
                .get(&operation.intent.logical.tenant_id)
                .copied()
                .unwrap_or(1)
                != operation.intent.fence.namespace_epoch
            || state
                .routing_epochs
                .get(&operation.intent.logical.tenant_id)
                .copied()
                .unwrap_or(1)
                != operation.intent.fence.routing_epoch
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let existing = state.authorities.get(&operation.intent.logical).cloned();
        if existing.as_ref().map(|value| value.cas_version)
            != operation.intent.expected_authority_cas
            || existing
                .as_ref()
                .filter(|value| !value.tombstone)
                .map_or(0, |value| value.size)
                != operation.intent.prior_logical_size
        {
            return Err(ManagedError::Conflict);
        }
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        if usage.active_operation_id != Some(operation_id) {
            return Err(ManagedError::Conflict);
        }
        let visible = usage
            .visible_logical_bytes
            .checked_sub(operation.intent.prior_logical_size)
            .ok_or(ManagedError::Conflict)?;
        let now = crate::transaction::unix_time_ms();
        let authority = ObjectAuthority {
            logical: operation.intent.logical.clone(),
            generation: operation.intent.generation,
            digest: String::new(),
            size: 0,
            metadata: BTreeMap::new(),
            placement_version: placement.version,
            primary_backend_id: placement.primary_backend_id.clone(),
            primary_version_id: None,
            replica_backend_id: placement.replica_backend_id.clone(),
            primary_status: CopyStatus::Absent,
            replica_status: CopyStatus::Absent,
            tombstone: true,
            cas_version: operation
                .intent
                .expected_authority_cas
                .unwrap_or(0)
                .saturating_add(1),
            created_at_ms: existing.as_ref().map_or(now, |value| value.created_at_ms),
            updated_at_ms: now,
        };
        state
            .authorities
            .insert(authority.logical.clone(), authority.clone());
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                if state.physical_versions.iter().any(|target| {
                    target.tenant_id == repair.logical.tenant_id
                        && target.backend_id == repair.target_backend_id
                        && target.physical_key == repair.physical_key
                }) {
                    repair.namespace_epoch = operation.intent.fence.namespace_epoch;
                    insert_memory_repair(&mut state, repair);
                }
            }
        }
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        usage.visible_logical_bytes = visible;
        usage.active_operation_id = None;
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        let committed_usage = usage.clone();
        let operation = state.logical_operations.get_mut(&operation_id).unwrap();
        operation.state = ManagedLogicalOperationState::Committed;
        operation.committed_authority_version = Some(authority.cas_version);
        operation.updated_at_ms = now;
        operation.committed_at_ms = Some(now);
        Ok(ManagedOperationCommit {
            operation: operation.clone(),
            authority,
            usage: committed_usage,
        })
    }

    async fn commit_atomic_logical_delete(
        &self,
        request: ManagedDeleteRequest,
    ) -> Result<ManagedOperationCommit, ManagedDeleteError> {
        if request.logical.tenant_id.is_empty()
            || request.logical.bucket.is_empty()
            || request.placement.version == 0
            || request.placement.primary_backend_id.is_empty()
            || request.provider_bucket.is_empty()
            || request.rate_version <= 0
            || request.occurred_at_micros < 0
        {
            return Err(ManagedError::Conflict.into());
        }
        let mut state = self.state.lock().await;
        if state
            .fenced_namespaces
            .contains_key(&request.logical.tenant_id)
        {
            return Err(ManagedError::NamespaceFenced.into());
        }
        let fence = ManagedRouteFence {
            namespace_epoch: state
                .namespace_epochs
                .get(&request.logical.tenant_id)
                .copied()
                .unwrap_or(1),
            routing_epoch: state
                .routing_epochs
                .get(&request.logical.tenant_id)
                .copied()
                .unwrap_or(1),
        };
        let existing = state.authorities.get(&request.logical).cloned();
        let generation = existing
            .as_ref()
            .filter(|authority| authority.tombstone)
            .map_or_else(
                || Uuid::new_v5(&Uuid::NAMESPACE_URL, request.operation_id.as_bytes()),
                |authority| authority.generation,
            );
        let prior_logical_size = existing
            .as_ref()
            .filter(|authority| !authority.tombstone)
            .map_or(0, |authority| authority.size);
        let intent = ManagedLogicalOperationIntent {
            operation_id: request.operation_id,
            receipt_id: request.receipt_id,
            logical: request.logical.clone(),
            kind: ManagedMutationKind::Delete,
            generation,
            fence,
            expected_authority_cas: existing.as_ref().map(|authority| authority.cas_version),
            prior_logical_size,
            primary_child_operation_id: Uuid::new_v5(
                &Uuid::NAMESPACE_OID,
                request.operation_id.as_bytes(),
            ),
            backend_id: request.placement.primary_backend_id.clone(),
            provider_bucket: request.provider_bucket.clone(),
            physical_key: generation_physical_key(&request.logical, generation),
            occurred_at_ms: request.occurred_at_micros.div_euclid(1_000),
            rate_version: request.rate_version,
            route: UsageRoute::DeleteObject,
            request_kind: RequestKind::Write,
            max_processed_bytes: request.max_processed_bytes,
            publication_recipe: Some(ManagedPublicationRecipe {
                version: MANAGED_PUBLICATION_RECIPE_VERSION,
                placement_version: request.placement.version,
                primary_backend_id: request.placement.primary_backend_id.clone(),
                replica_backend_id: request.placement.replica_backend_id.clone(),
                metadata: BTreeMap::new(),
                primary_status: CopyStatus::Absent,
                replica_status: CopyStatus::Absent,
            }),
        };
        if let Some(operation) = state.logical_operations.get(&request.operation_id).cloned() {
            if !delete_request_matches_operation(&request, &operation)
                || operation.state != ManagedLogicalOperationState::Committed
            {
                return Err(ManagedError::Conflict.into());
            }
            let authority = committed_delete_replay_authority(&operation, existing)?;
            let usage = Self::workspace_usage(&mut state, &request.logical.tenant_id).clone();
            return Ok(ManagedOperationCommit {
                operation,
                authority,
                usage,
            });
        }
        let usage = Self::workspace_usage(&mut state, &request.logical.tenant_id);
        if usage.active_operation_id.is_some() {
            return Err(ManagedError::MutationInProgress.into());
        }
        let visible = usage
            .visible_logical_bytes
            .checked_sub(prior_logical_size)
            .ok_or(ManagedError::Conflict)?;
        let now = crate::transaction::unix_time_ms();
        let authority = existing
            .as_ref()
            .filter(|authority| authority.tombstone)
            .cloned()
            .unwrap_or_else(|| ObjectAuthority {
                logical: request.logical.clone(),
                generation,
                digest: String::new(),
                size: 0,
                metadata: BTreeMap::new(),
                placement_version: request.placement.version,
                primary_backend_id: request.placement.primary_backend_id,
                primary_version_id: None,
                replica_backend_id: request.placement.replica_backend_id,
                primary_status: CopyStatus::Absent,
                replica_status: CopyStatus::Absent,
                tombstone: true,
                cas_version: existing
                    .as_ref()
                    .map_or(1, |authority| authority.cas_version.saturating_add(1)),
                created_at_ms: existing
                    .as_ref()
                    .map_or(now, |authority| authority.created_at_ms),
                updated_at_ms: now,
            });
        let repairs = existing
            .as_ref()
            .filter(|authority| !authority.tombstone)
            .into_iter()
            .flat_map(cleanup_repairs)
            .filter(|repair| {
                state.physical_versions.iter().any(|target| {
                    target.tenant_id == repair.logical.tenant_id
                        && target.backend_id == repair.target_backend_id
                        && target.physical_key == repair.physical_key
                })
            })
            .map(|mut repair| {
                repair.namespace_epoch = fence.namespace_epoch;
                repair
            })
            .collect::<Vec<_>>();
        state
            .authorities
            .insert(request.logical.clone(), authority.clone());
        for repair in repairs {
            insert_memory_repair(&mut state, repair);
        }
        let usage = Self::workspace_usage(&mut state, &request.logical.tenant_id);
        usage.visible_logical_bytes = visible;
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        let committed_usage = usage.clone();
        let evidence = ManagedUsageEvidence {
            expected_output_digest: None,
            expected_output_size: 0,
            source_bytes: 0,
            processed_bytes: 0,
            payload: serde_json::json!({
                "occurred_at_micros": request.occurred_at_micros,
            }),
        };
        let operation = ManagedLogicalOperation {
            intent,
            evidence: Some(evidence),
            reserved_physical_bytes: 0,
            committed_physical_bytes: 0,
            released_physical_bytes: 0,
            state: ManagedLogicalOperationState::Committed,
            committed_authority_version: Some(authority.cas_version),
            settlement_state: ManagedSettlementState::Pending,
            last_error_class: None,
            recovery_owner: None,
            recovery_token: None,
            recovery_expires_at_ms: None,
            created_at_ms: now,
            updated_at_ms: now,
            committed_at_ms: Some(now),
            aborted_at_ms: None,
        };
        state
            .logical_operations
            .insert(request.operation_id, operation.clone());
        Ok(ManagedOperationCommit {
            operation,
            authority,
            usage: committed_usage,
        })
    }

    async fn transition_logical_operation(
        &self,
        operation_id: Uuid,
        from: ManagedLogicalOperationState,
        to: ManagedLogicalOperationState,
        error_class: Option<&str>,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        if !valid_logical_transition(from, to) {
            return Err(ManagedError::InvalidTransition { from, to });
        }
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get_mut(&operation_id)
            .ok_or(ManagedError::Conflict)?;
        if operation.state != from {
            return Err(ManagedError::Conflict);
        }
        operation.state = to;
        operation.last_error_class =
            error_class.map(|value| value.chars().take(128).collect::<String>());
        operation.updated_at_ms = crate::transaction::unix_time_ms();
        Ok(operation.clone())
    }

    async fn record_logical_usage_and_begin_completion(
        &self,
        operation_id: Uuid,
        evidence: ManagedUsageEvidence,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        self.record_logical_usage(operation_id, evidence).await?;
        self.transition_logical_operation(
            operation_id,
            ManagedLogicalOperationState::Open,
            ManagedLogicalOperationState::Completing,
            None,
        )
        .await
    }

    async fn prove_logical_abort(
        &self,
        operation_id: Uuid,
        error_class: &str,
        physical: Option<ManagedProvenPhysicalAllocation>,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get(&operation_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        if operation.state == ManagedLogicalOperationState::ProvenAborted {
            return Ok(operation);
        }
        if operation.state == ManagedLogicalOperationState::Committed {
            return Err(ManagedError::InvalidTransition {
                from: operation.state,
                to: ManagedLogicalOperationState::ProvenAborted,
            });
        }
        if state
            .namespace_epochs
            .get(&operation.intent.logical.tenant_id)
            .copied()
            .unwrap_or(1)
            != operation.intent.fence.namespace_epoch
        {
            return Err(ManagedError::Conflict);
        }
        let child_version_count = state
            .physical_versions
            .iter()
            .filter(|target| {
                target.write_operation_id == operation.intent.primary_child_operation_id
                    && target.tenant_id == operation.intent.logical.tenant_id
                    && target.backend_id == operation.intent.backend_id
                    && target.provider_bucket == operation.intent.provider_bucket
                    && target.physical_key == operation.intent.physical_key
            })
            .count() as u64;
        let allocated = match physical {
            None => {
                if child_version_count != 0 {
                    return Err(ManagedError::Conflict);
                }
                0
            }
            Some(physical) => {
                let evidence = operation.evidence.as_ref().ok_or(ManagedError::Conflict)?;
                let derived = physical_allocation(physical.authority.size, child_version_count)?;
                if child_version_count == 0
                    || physical.authority.logical != operation.intent.logical
                    || physical.authority.generation != operation.intent.generation
                    || physical.authority.primary_backend_id != operation.intent.backend_id
                    || physical.authority.tombstone
                    || evidence.expected_output_size != physical.authority.size
                    || evidence.expected_output_digest.as_deref()
                        != Some(physical.authority.digest.as_str())
                    || physical.allocated_bytes != derived
                    || derived > operation.reserved_physical_bytes
                {
                    return Err(ManagedError::Conflict);
                }
                for mut repair in cleanup_repairs(&physical.authority) {
                    if state.physical_versions.iter().any(|target| {
                        target.tenant_id == repair.logical.tenant_id
                            && target.backend_id == repair.target_backend_id
                            && target.physical_key == repair.physical_key
                    }) {
                        repair.namespace_epoch = operation.intent.fence.namespace_epoch;
                        insert_memory_repair(&mut state, repair);
                    }
                }
                derived
            }
        };
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        if operation.state != ManagedLogicalOperationState::Intent
            && usage.active_operation_id != Some(operation_id)
        {
            return Err(ManagedError::Conflict);
        }
        usage.reserved_bytes = usage
            .reserved_bytes
            .checked_sub(operation.reserved_physical_bytes)
            .ok_or(ManagedError::Conflict)?;
        usage.physical_allocated_bytes = usage
            .physical_allocated_bytes
            .checked_add(allocated)
            .ok_or(ManagedError::QuotaExceeded)?;
        if usage.active_operation_id == Some(operation_id) {
            usage.active_operation_id = None;
        }
        let now = crate::transaction::unix_time_ms();
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        let operation = state.logical_operations.get_mut(&operation_id).unwrap();
        operation.state = ManagedLogicalOperationState::ProvenAborted;
        operation.committed_physical_bytes = allocated;
        operation.settlement_state = ManagedSettlementState::Released;
        operation.last_error_class = Some(error_class.chars().take(128).collect());
        operation.updated_at_ms = now;
        operation.aborted_at_ms = Some(now);
        Ok(operation.clone())
    }

    async fn abort_logical_put(
        &self,
        operation_id: Uuid,
        physical_lease: Option<&PhysicalWriteLease>,
        proof: LogicalAbortProof,
        error_class: &str,
        recovery_claim: Option<&ManagedRecoveryClaim>,
    ) -> Result<ManagedLogicalOperation, ManagedError> {
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get(&operation_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        if operation.state == ManagedLogicalOperationState::ProvenAborted {
            return Ok(operation);
        }
        let now = crate::transaction::unix_time_ms();
        validate_recovery_authority(&operation, recovery_claim, now)?;
        if operation.intent.kind != ManagedMutationKind::Put
            || operation.state == ManagedLogicalOperationState::Committed
        {
            return Err(ManagedError::Conflict);
        }
        if state
            .namespace_epochs
            .get(&operation.intent.logical.tenant_id)
            .copied()
            .unwrap_or(1)
            != operation.intent.fence.namespace_epoch
        {
            return Err(ManagedError::RecoveryBlocked("namespace_fence_changed"));
        }
        if state
            .physical_versions
            .iter()
            .any(|target| target.write_operation_id == operation.intent.primary_child_operation_id)
        {
            return Err(ManagedError::Conflict);
        }
        let intent = state
            .physical_write_intents
            .get(&operation.intent.primary_child_operation_id);
        match (proof, physical_lease, intent) {
            (LogicalAbortProof::NoChildStarted, None, None)
                if matches!(
                    operation.state,
                    ManagedLogicalOperationState::Intent | ManagedLogicalOperationState::Open
                ) => {}
            (
                LogicalAbortProof::NoChildStarted | LogicalAbortProof::ChildProvenAborted,
                Some(lease),
                Some(intent),
            ) if lease.intent_id == operation.intent.primary_child_operation_id
                && intent.lease_owner == lease.owner
                && state.physical_write_tokens.get(&lease.intent_id) == Some(&lease.token)
                && state.physical_write_epochs.get(&lease.intent_id)
                    == Some(&lease.namespace_epoch)
                && state
                    .physical_write_leases
                    .get(&lease.intent_id)
                    .is_some_and(|expiry| *expiry > now) => {}
            _ => return Err(ManagedError::Conflict),
        }
        let usage = Self::workspace_usage(&mut state, &operation.intent.logical.tenant_id);
        if operation.state != ManagedLogicalOperationState::Intent
            && usage.active_operation_id != Some(operation_id)
        {
            return Err(ManagedError::Conflict);
        }
        usage.reserved_bytes = usage
            .reserved_bytes
            .checked_sub(operation.reserved_physical_bytes)
            .ok_or(ManagedError::Conflict)?;
        if usage.active_operation_id == Some(operation_id) {
            usage.active_operation_id = None;
        }
        usage.version = usage.version.saturating_add(1);
        usage.updated_at_ms = now;
        let child_operation_id = operation.intent.primary_child_operation_id;
        let operation = state.logical_operations.get_mut(&operation_id).unwrap();
        operation.state = ManagedLogicalOperationState::ProvenAborted;
        operation.settlement_state = ManagedSettlementState::Released;
        operation.last_error_class = Some(error_class.chars().take(128).collect());
        operation.recovery_owner = None;
        operation.recovery_token = None;
        operation.recovery_expires_at_ms = None;
        operation.updated_at_ms = now;
        operation.aborted_at_ms = Some(now);
        let aborted = operation.clone();
        let _ = operation;
        state.physical_write_intents.remove(&child_operation_id);
        state.blocked_write_intents.remove(&child_operation_id);
        state.physical_write_leases.remove(&child_operation_id);
        state.physical_write_tokens.remove(&child_operation_id);
        state.physical_write_epochs.remove(&child_operation_id);
        Ok(aborted)
    }

    async fn workspace_usage(
        &self,
        tenant_id: &str,
    ) -> Result<Option<ManagedWorkspaceUsage>, ManagedError> {
        Ok(self
            .state
            .lock()
            .await
            .workspace_usage
            .get(tenant_id)
            .cloned())
    }

    async fn list_authority(
        &self,
        query: AuthorityListQuery,
    ) -> Result<AuthorityListPage, ManagedError> {
        if query.max_keys > MANAGED_AUTHORITY_LIST_MAX_KEYS {
            return Err(ManagedError::Conflict);
        }
        if query.max_keys == 0 {
            return Ok(AuthorityListPage {
                objects: Vec::new(),
                next_after: None,
            });
        }
        let state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(&query.tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let mut objects: Vec<_> = state
            .authorities
            .values()
            .filter(|authority| {
                authority.logical.tenant_id == query.tenant_id
                    && authority.logical.bucket == query.bucket
                    && !authority.tombstone
                    && authority.logical.key.starts_with(&query.prefix)
                    && query
                        .after
                        .as_ref()
                        .is_none_or(|after| authority.logical.key > *after)
            })
            .cloned()
            .collect();
        objects.sort_by(|left, right| left.logical.key.cmp(&right.logical.key));
        let next_after = (objects.len() as u64 > query.max_keys)
            .then(|| objects[query.max_keys as usize - 1].logical.key.clone());
        objects.truncate(query.max_keys as usize);
        Ok(AuthorityListPage {
            objects,
            next_after,
        })
    }

    async fn list_authority_below_placement_version(
        &self,
        query: AuthorityPlacementPageQuery,
    ) -> Result<AuthorityPlacementPage, ManagedError> {
        if query.limit > MANAGED_AUTHORITY_LIST_MAX_KEYS || query.target_placement_version == 0 {
            return Err(ManagedError::Conflict);
        }
        if query.limit == 0 {
            return Ok(AuthorityPlacementPage {
                objects: Vec::new(),
                next_after: None,
            });
        }
        let state = self.state.lock().await;
        let mut objects: Vec<_> = state
            .authorities
            .values()
            .filter(|authority| {
                !authority.tombstone
                    && authority.placement_version < query.target_placement_version
                    && query.after.as_ref().is_none_or(|after| {
                        (
                            authority.logical.tenant_id.as_str(),
                            authority.logical.bucket.as_str(),
                            authority.logical.key.as_str(),
                        ) > (
                            after.tenant_id.as_str(),
                            after.bucket.as_str(),
                            after.key.as_str(),
                        )
                    })
            })
            .cloned()
            .collect();
        objects.sort_by(|left, right| {
            (
                left.logical.tenant_id.as_str(),
                left.logical.bucket.as_str(),
                left.logical.key.as_str(),
            )
                .cmp(&(
                    right.logical.tenant_id.as_str(),
                    right.logical.bucket.as_str(),
                    right.logical.key.as_str(),
                ))
        });
        let next_after = (objects.len() as u64 > query.limit).then(|| {
            let authority = &objects[query.limit as usize - 1];
            AuthorityPlacementCursor {
                tenant_id: authority.logical.tenant_id.clone(),
                bucket: authority.logical.bucket.clone(),
                key: authority.logical.key.clone(),
            }
        });
        objects.truncate(query.limit as usize);
        Ok(AuthorityPlacementPage {
            objects,
            next_after,
        })
    }

    async fn authority_placement_stats(
        &self,
        target_placement_version: u32,
    ) -> Result<AuthorityPlacementStats, ManagedError> {
        if target_placement_version == 0 {
            return Err(ManagedError::Conflict);
        }
        let state = self.state.lock().await;
        let mut remaining = 0_u64;
        let mut oldest_updated_at_ms: Option<i64> = None;
        for authority in state.authorities.values() {
            if !authority.tombstone && authority.placement_version < target_placement_version {
                remaining = remaining.saturating_add(1);
                oldest_updated_at_ms = Some(
                    oldest_updated_at_ms.map_or(authority.updated_at_ms, |oldest| {
                        oldest.min(authority.updated_at_ms)
                    }),
                );
            }
        }
        Ok(AuthorityPlacementStats {
            remaining,
            oldest_updated_at_ms,
        })
    }

    async fn create_list_cursor(
        &self,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let mut state = self.state.lock().await;
        Self::create_list_cursor_in_state(&mut state, request, now_ms)
    }

    async fn create_list_cursor_successor(
        &self,
        predecessor_cursor_id: Uuid,
        request: ManagedListCursorRequest,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let mut state = self.state.lock().await;
        if let Some(successor_id) = state
            .list_cursor_successors
            .get(&predecessor_cursor_id)
            .copied()
        {
            let cursor = state
                .list_cursors
                .get(&successor_id)
                .cloned()
                .ok_or_else(|| {
                    ManagedError::Corrupt("managed cursor successor is missing".to_string())
                })?;
            let current_fence = ManagedRouteFence {
                namespace_epoch: state
                    .namespace_epochs
                    .get(&cursor.binding.tenant_id)
                    .copied()
                    .unwrap_or(1),
                routing_epoch: state
                    .routing_epochs
                    .get(&cursor.binding.tenant_id)
                    .copied()
                    .unwrap_or(1),
            };
            if cursor.expires_at_ms <= now_ms || cursor.fence != current_fence {
                return Err(ManagedError::CursorExpired);
            }
            return cursor_matches_request(&cursor, &request)
                .then_some(cursor)
                .ok_or(ManagedError::Conflict);
        }
        let cursor = Self::create_list_cursor_in_state(&mut state, request, now_ms)?;
        state
            .list_cursor_successors
            .insert(predecessor_cursor_id, cursor.id);
        Ok(cursor)
    }

    async fn use_list_cursor(
        &self,
        cursor_id: Uuid,
        binding: &ManagedListCursorBinding,
        now_ms: i64,
    ) -> Result<ManagedListCursor, ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(&binding.tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let Some(cursor) = state.list_cursors.get(&cursor_id).cloned() else {
            return Err(ManagedError::CursorExpired);
        };
        if cursor.expires_at_ms <= now_ms {
            Self::remove_list_cursor(&mut state, cursor_id);
            return Err(ManagedError::CursorExpired);
        }
        if &cursor.binding != binding {
            return Err(ManagedError::CursorQueryMismatch);
        }
        let current_fence = ManagedRouteFence {
            namespace_epoch: state
                .namespace_epochs
                .get(&cursor.binding.tenant_id)
                .copied()
                .unwrap_or(1),
            routing_epoch: state
                .routing_epochs
                .get(&cursor.binding.tenant_id)
                .copied()
                .unwrap_or(1),
        };
        if cursor.fence != current_fence {
            Self::remove_list_cursor(&mut state, cursor_id);
            return Err(ManagedError::CursorExpired);
        }
        let cursor = state
            .list_cursors
            .get_mut(&cursor_id)
            .ok_or(ManagedError::CursorExpired)?;
        if cursor.state == ManagedListCursorState::Active {
            cursor.state = ManagedListCursorState::Used;
            cursor.first_used_at_ms = Some(now_ms);
        }
        Ok(cursor.clone())
    }

    async fn delete_list_cursor(&self, cursor_id: Uuid) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        Self::remove_list_cursor(&mut state, cursor_id);
        Ok(())
    }

    async fn cleanup_expired_list_cursors(
        &self,
        now_ms: i64,
        limit: u64,
    ) -> Result<u64, ManagedError> {
        let mut state = self.state.lock().await;
        let mut expired: Vec<_> = state
            .list_cursors
            .values()
            .filter(|cursor| cursor.expires_at_ms <= now_ms)
            .map(|cursor| (cursor.expires_at_ms, cursor.id))
            .collect();
        expired.sort_unstable();
        expired.truncate(limit as usize);
        for (_, cursor_id) in &expired {
            Self::remove_list_cursor(&mut state, *cursor_id);
        }
        Ok(expired.len() as u64)
    }

    async fn begin_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
    ) -> Result<u64, ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let epoch = *state
            .namespace_epochs
            .entry(tenant_id.to_string())
            .or_insert(1);
        state
            .multipart_activities
            .insert(upload_id.to_string(), (tenant_id.to_string(), epoch));
        state.multipart_registration_expiry.insert(
            upload_id.to_string(),
            crate::transaction::unix_time_ms().saturating_add(10 * 60 * 1000),
        );
        Ok(epoch)
    }

    async fn assert_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
        allow_purging: bool,
    ) -> Result<(), ManagedError> {
        let state = self.state.lock().await;
        if state.namespace_epochs.get(tenant_id).copied().unwrap_or(1) != namespace_epoch
            || (state.fenced_namespaces.contains_key(tenant_id) && !allow_purging)
            || state.multipart_activities.get(upload_id)
                != Some(&(tenant_id.to_string(), namespace_epoch))
            || !state.confirmed_multipart_activities.contains(upload_id)
        {
            return Err(ManagedError::NamespaceFenced);
        }
        Ok(())
    }

    async fn confirm_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(tenant_id)
            || state.multipart_activities.get(upload_id)
                != Some(&(tenant_id.to_string(), namespace_epoch))
        {
            return Err(ManagedError::NamespaceFenced);
        }
        state
            .confirmed_multipart_activities
            .insert(upload_id.to_string());
        state.multipart_registration_expiry.remove(upload_id);
        Ok(())
    }

    async fn reconcile_multipart_activities(&self, limit: u64) -> Result<u64, ManagedError> {
        let mut state = self.state.lock().await;
        let now = crate::transaction::unix_time_ms();
        let expired: Vec<_> = state
            .multipart_registration_expiry
            .iter()
            .filter(|(_, expires)| **expires <= now)
            .take(limit as usize)
            .map(|(upload_id, _)| upload_id.clone())
            .collect();
        for upload_id in &expired {
            state.multipart_registration_expiry.remove(upload_id);
            state.multipart_activities.remove(upload_id);
        }
        Ok(expired.len() as u64)
    }

    async fn finish_multipart_activity(
        &self,
        upload_id: &str,
        tenant_id: &str,
        namespace_epoch: u64,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state.multipart_activities.get(upload_id)
            == Some(&(tenant_id.to_string(), namespace_epoch))
        {
            state.multipart_activities.remove(upload_id);
            state.confirmed_multipart_activities.remove(upload_id);
            state.multipart_registration_expiry.remove(upload_id);
        }
        Ok(())
    }

    async fn any_authority(&self) -> Result<bool, ManagedError> {
        Ok(!self.state.lock().await.authorities.is_empty())
    }

    async fn get(
        &self,
        logical: &LogicalObjectKey,
    ) -> Result<Option<ObjectAuthority>, ManagedError> {
        let state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(&logical.tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        Ok(state.authorities.get(logical).cloned())
    }

    async fn publish(
        &self,
        mut authority: ObjectAuthority,
        expected_cas: Option<u64>,
    ) -> Result<ObjectAuthority, ManagedError> {
        let mut state = self.state.lock().await;
        if state
            .fenced_namespaces
            .contains_key(&authority.logical.tenant_id)
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let existing = state.authorities.get(&authority.logical).cloned();
        if existing.as_ref().map(|value| value.cas_version) != expected_cas {
            return Err(ManagedError::Conflict);
        }
        let now = crate::transaction::unix_time_ms();
        authority.cas_version = expected_cas.unwrap_or(0).saturating_add(1);
        authority.created_at_ms = existing.as_ref().map_or(now, |value| value.created_at_ms);
        authority.updated_at_ms = now;
        let namespace_epoch = *state
            .namespace_epochs
            .entry(authority.logical.tenant_id.clone())
            .or_insert(1);
        state
            .authorities
            .insert(authority.logical.clone(), authority.clone());
        for mut repair in publication_repairs(&authority) {
            repair.namespace_epoch = namespace_epoch;
            insert_memory_repair(&mut state, repair);
        }
        if let Some(existing) = existing.filter(|value| !value.tombstone) {
            for mut repair in cleanup_repairs(&existing) {
                if !state.physical_versions.iter().any(|target| {
                    target.tenant_id == repair.logical.tenant_id
                        && target.backend_id == repair.target_backend_id
                        && target.physical_key == repair.physical_key
                }) {
                    continue;
                }
                repair.namespace_epoch = namespace_epoch;
                insert_memory_repair(&mut state, repair);
            }
        }
        Ok(authority)
    }

    async fn record_placement_policy(
        &self,
        policy: &ManagedPlacementPolicy,
    ) -> Result<bool, ManagedError> {
        let mut state = self.state.lock().await;
        if let Some(existing) = state.placement_policy_fingerprints.get(&policy.version) {
            return Ok(existing == &policy.fingerprint);
        }
        state
            .placement_policy_fingerprints
            .insert(policy.version, policy.fingerprint.clone());
        Ok(true)
    }

    async fn advance_placement_version(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: u64,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError> {
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(&logical.tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let authority = state
            .authorities
            .get_mut(logical)
            .ok_or(ManagedError::Conflict)?;
        let locations_match = authority.primary_backend_id == placement.primary_backend_id
            && authority.primary_status == CopyStatus::Ready
            && match placement.replica_backend_id.as_deref() {
                Some(replica) => {
                    authority.replica_backend_id.as_deref() == Some(replica)
                        && authority.replica_status == CopyStatus::Ready
                }
                None => {
                    authority.replica_backend_id.is_none()
                        && authority.replica_status == CopyStatus::Absent
                }
            };
        if authority.tombstone
            || authority.cas_version != expected_cas
            || placement.version <= authority.placement_version
            || !locations_match
        {
            return Err(ManagedError::Conflict);
        }
        authority.placement_version = placement.version;
        authority.cas_version = authority.cas_version.saturating_add(1);
        authority.updated_at_ms = crate::transaction::unix_time_ms();
        Ok(authority.clone())
    }

    async fn tombstone(
        &self,
        logical: &LogicalObjectKey,
        expected_cas: Option<u64>,
        placement: &Placement,
    ) -> Result<ObjectAuthority, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        self.publish(
            ObjectAuthority {
                logical: logical.clone(),
                generation: Uuid::now_v7(),
                digest: String::new(),
                size: 0,
                metadata: BTreeMap::new(),
                placement_version: placement.version,
                primary_backend_id: placement.primary_backend_id.clone(),
                primary_version_id: None,
                replica_backend_id: placement.replica_backend_id.clone(),
                primary_status: CopyStatus::Absent,
                replica_status: CopyStatus::Absent,
                tombstone: true,
                cas_version: 0,
                created_at_ms: now,
                updated_at_ms: now,
            },
            expected_cas,
        )
        .await
    }

    async fn enqueue(&self, mut repair: RepairRecord) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state
            .fenced_namespaces
            .contains_key(&repair.logical.tenant_id)
        {
            return Err(ManagedError::NamespaceFenced);
        }
        let current_epoch = *state
            .namespace_epochs
            .entry(repair.logical.tenant_id.clone())
            .or_insert(1);
        if repair.kind == RepairKind::DeleteGeneration {
            let targets: Vec<_> = state
                .physical_versions
                .iter()
                .filter(|target| {
                    target.tenant_id == repair.logical.tenant_id
                        && target.backend_id == repair.target_backend_id
                        && target.physical_key == repair.physical_key
                })
                .collect();
            if targets.is_empty() {
                return Ok(());
            }
            if targets
                .iter()
                .any(|target| target.namespace_epoch != current_epoch)
            {
                return Err(ManagedError::Conflict);
            }
        } else if state
            .authorities
            .get(&repair.logical)
            .is_none_or(|authority| {
                authority.generation != repair.generation
                    || authority.cas_version != repair.authority_cas_version
            })
        {
            return Err(ManagedError::Conflict);
        }
        repair.namespace_epoch = current_epoch;
        insert_memory_repair(&mut state, repair);
        Ok(())
    }

    async fn claim_repairs(
        &self,
        owner: &str,
        lease_until_ms: i64,
        limit: u64,
    ) -> Result<Vec<RepairRecord>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let mut state = self.state.lock().await;
        let fenced_namespaces = state.fenced_namespaces.clone();
        let namespace_epochs = state.namespace_epochs.clone();
        let authorities = state.authorities.clone();
        let mut candidates: Vec<_> = state
            .repairs
            .values_mut()
            .filter(|(repair, status)| {
                !fenced_namespaces.contains_key(&repair.logical.tenant_id)
                    && namespace_epochs
                        .get(&repair.logical.tenant_id)
                        .copied()
                        .unwrap_or(1)
                        == repair.namespace_epoch
                    && (status.as_str() == "PENDING"
                        || (status.as_str() == "LEASED"
                            && repair
                                .lease_expires_at_ms
                                .is_some_and(|expiry| expiry <= now)))
                    && repair.not_before_ms <= now
                    && !(repair.kind == RepairKind::DeleteGeneration
                        && authorities.get(&repair.logical).is_some_and(|authority| {
                            repair_target_is_authoritative(authority, repair)
                        }))
            })
            .collect();
        candidates.sort_by_key(|(repair, _)| repair.updated_at_ms);
        let mut claimed = Vec::new();
        for (repair, status) in candidates.into_iter().take(limit as usize) {
            let lease_token = Uuid::now_v7();
            *status = "LEASED".to_string();
            repair.id = lease_token;
            repair.lease_owner = Some(owner.to_string());
            repair.lease_token = Some(lease_token);
            repair.lease_expires_at_ms = Some(lease_until_ms);
            repair.updated_at_ms = now;
            claimed.push(repair.clone());
        }
        Ok(claimed)
    }

    async fn renew_repair(
        &self,
        lease_token: Uuid,
        lease_until_ms: i64,
    ) -> Result<(), ManagedError> {
        let now = crate::transaction::unix_time_ms();
        let mut state = self.state.lock().await;
        let Some((repair, status)) = state
            .repairs
            .values_mut()
            .find(|(repair, _)| repair.lease_token == Some(lease_token))
        else {
            return Err(ManagedError::Conflict);
        };
        if status != "LEASED"
            || repair
                .lease_expires_at_ms
                .is_none_or(|expiry| expiry <= now)
        {
            return Err(ManagedError::Conflict);
        }
        repair.lease_expires_at_ms = Some(lease_until_ms);
        repair.updated_at_ms = now;
        Ok(())
    }

    async fn complete_repair(&self, repair: &RepairRecord) -> Result<bool, ManagedError> {
        let mut state = self.state.lock().await;
        let now = crate::transaction::unix_time_ms();
        if repair.lease_token != Some(repair.id) {
            return Err(ManagedError::Conflict);
        }
        if state
            .namespace_epochs
            .get(&repair.logical.tenant_id)
            .copied()
            .unwrap_or(1)
            != repair.namespace_epoch
        {
            return Err(ManagedError::Conflict);
        }
        {
            let Some((stored, status)) = state.repairs.get_mut(&repair.repair_id) else {
                return Err(ManagedError::Conflict);
            };
            if status != "LEASED"
                || stored.lease_token != Some(repair.id)
                || stored
                    .lease_expires_at_ms
                    .is_none_or(|expiry| expiry <= now)
            {
                return Err(ManagedError::Conflict);
            }
            *status = "DONE".to_string();
            stored.lease_owner = None;
            stored.lease_token = None;
            stored.lease_expires_at_ms = None;
            stored.updated_at_ms = now;
        }
        if repair.kind == RepairKind::DeleteGeneration
            && state.physical_versions.iter().any(|target| {
                target.tenant_id == repair.logical.tenant_id
                    && target.backend_id == repair.target_backend_id
                    && target.physical_key == repair.physical_key
            })
        {
            let (_, status) = state.repairs.get_mut(&repair.repair_id).unwrap();
            *status = "PENDING".to_string();
            return Ok(false);
        }
        let mut updated = false;
        let mut cleanups = Vec::new();
        let mut activate_cleanup = false;
        let cleanup_in_progress = state.repairs.values().any(|(cleanup, status)| {
            cleanup.kind == RepairKind::DeleteGeneration
                && cleanup.logical == repair.logical
                && cleanup.generation == repair.generation
                && cleanup.target_backend_id == repair.target_backend_id
                && status == "LEASED"
        });
        if repair.kind != RepairKind::DeleteGeneration
            && !cleanup_in_progress
            && let Some(authority) = state.authorities.get_mut(&repair.logical)
            && authority.generation == repair.generation
            && authority.cas_version == repair.authority_cas_version
            && !authority.tombstone
        {
            let previous = authority.clone();
            if apply_repair_to_authority(authority, repair)? {
                authority.cas_version = authority.cas_version.saturating_add(1);
                authority.updated_at_ms = crate::transaction::unix_time_ms();
                updated = true;
                if repair.kind == RepairKind::Placement {
                    cleanups = placement_cleanup_repairs(&previous, authority);
                    activate_cleanup = authority.placement_version == repair.placement_version;
                }
            }
        }
        for mut cleanup in cleanups {
            cleanup.namespace_epoch = repair.namespace_epoch;
            cleanup.placement_version = repair.placement_version;
            insert_memory_waiting_placement_cleanup(&mut state, cleanup);
        }
        if activate_cleanup {
            for (cleanup, status) in state.repairs.values_mut() {
                if *status == "WAITING_CUTOVER"
                    && cleanup.logical == repair.logical
                    && cleanup.generation == repair.generation
                    && cleanup.placement_version == repair.placement_version
                {
                    *status = "PENDING".to_string();
                }
            }
        }
        if !updated
            && repair.kind != RepairKind::DeleteGeneration
            && state
                .authorities
                .get(&repair.logical)
                .is_none_or(|authority| !repair_target_is_authoritative(authority, repair))
            && state.physical_versions.iter().any(|target| {
                target.tenant_id == repair.logical.tenant_id
                    && target.backend_id == repair.target_backend_id
                    && target.physical_key == repair.physical_key
            })
        {
            insert_memory_repair(&mut state, stale_repair_cleanup(repair));
        }
        Ok(updated)
    }

    async fn fail_repair(&self, lease_token: Uuid, _error: &str) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        let now = crate::transaction::unix_time_ms();
        let Some((repair, status)) = state
            .repairs
            .values_mut()
            .find(|(repair, _)| repair.lease_token == Some(lease_token))
        else {
            return Err(ManagedError::Conflict);
        };
        if status != "LEASED"
            || repair
                .lease_expires_at_ms
                .is_none_or(|expiry| expiry <= now)
        {
            return Err(ManagedError::Conflict);
        }
        repair.attempts = repair.attempts.saturating_add(1);
        repair.lease_owner = None;
        repair.lease_token = None;
        repair.lease_expires_at_ms = None;
        repair.updated_at_ms = now;
        if repair.attempts >= MAX_REPAIR_ATTEMPTS {
            *status = "DEAD".to_string();
            repair.not_before_ms = 0;
        } else {
            *status = "PENDING".to_string();
            repair.not_before_ms = now.saturating_add(repair_backoff_ms(repair.attempts));
        }
        Ok(())
    }

    async fn repair_state_counts(&self) -> Result<RepairStateCounts, ManagedError> {
        let state = self.state.lock().await;
        let mut counts = RepairStateCounts::default();
        for (_, status) in state.repairs.values() {
            match status.as_str() {
                "LEASED" => counts.leased = counts.leased.saturating_add(1),
                "DEAD" => counts.dead = counts.dead.saturating_add(1),
                _ => counts.pending = counts.pending.saturating_add(1),
            }
        }
        Ok(counts)
    }

    async fn begin_physical_write(
        &self,
        intent: PhysicalWriteIntent,
    ) -> Result<PhysicalWriteLease, ManagedError> {
        validate_physical_intent(&intent)?;
        let mut state = self.state.lock().await;
        if state.fenced_namespaces.contains_key(&intent.tenant_id) {
            return Err(ManagedError::NamespaceFenced);
        }
        let namespace_epoch = *state
            .namespace_epochs
            .entry(intent.tenant_id.clone())
            .or_insert(1);
        let routing_epoch = *state
            .routing_epochs
            .entry(intent.tenant_id.clone())
            .or_insert(1);
        if let Some(parent) = state
            .logical_operations
            .values()
            .find(|operation| operation.intent.primary_child_operation_id == intent.intent_id)
            && (parent.state != ManagedLogicalOperationState::Open
                || parent
                    .intent
                    .publication_recipe
                    .as_ref()
                    .is_none_or(|recipe| {
                        recipe.version != MANAGED_PUBLICATION_RECIPE_VERSION
                            || recipe.placement_version == 0
                            || recipe.primary_backend_id != parent.intent.backend_id
                            || recipe.primary_status != CopyStatus::Ready
                            || (recipe.replica_backend_id.is_none()
                                && recipe.replica_status != CopyStatus::Absent)
                            || (recipe.replica_backend_id.is_some()
                                && recipe.replica_status != CopyStatus::RepairPending)
                    })
                || state
                    .workspace_usage
                    .get(&intent.tenant_id)
                    .is_none_or(|usage| {
                        usage.active_operation_id != Some(parent.intent.operation_id)
                    })
                || parent.intent.logical.tenant_id != intent.tenant_id
                || parent.intent.backend_id != intent.backend_id
                || parent.intent.provider_bucket != intent.provider_bucket
                || parent.intent.physical_key != intent.physical_key
                || !physical_intent_supports_exact_history(&intent)
                || namespace_epoch != parent.intent.fence.namespace_epoch
                || routing_epoch != parent.intent.fence.routing_epoch)
        {
            return Err(ManagedError::Conflict);
        }
        if let Some(existing) = state.physical_write_intents.get(&intent.intent_id) {
            if existing != &intent
                || state.physical_write_epochs.get(&intent.intent_id) != Some(&namespace_epoch)
            {
                return Err(ManagedError::RecoveryBlocked("physical_intent_mismatch"));
            }
            return Ok(PhysicalWriteLease {
                intent_id: intent.intent_id,
                namespace_epoch,
                owner: existing.lease_owner.clone(),
                token: state
                    .physical_write_tokens
                    .get(&intent.intent_id)
                    .copied()
                    .ok_or(ManagedError::Conflict)?,
            });
        }
        let intent_id = intent.intent_id;
        let owner = intent.lease_owner.clone();
        let token = Uuid::now_v7();
        state.physical_write_intents.insert(intent_id, intent);
        state.physical_write_leases.insert(
            intent_id,
            crate::transaction::unix_time_ms().saturating_add(PHYSICAL_WRITE_LEASE_MS),
        );
        state.physical_write_tokens.insert(intent_id, token);
        state
            .physical_write_epochs
            .insert(intent_id, namespace_epoch);
        Ok(PhysicalWriteLease {
            intent_id,
            namespace_epoch,
            owner,
            token,
        })
    }

    async fn pending_physical_write_intents(
        &self,
        limit: u64,
    ) -> Result<Vec<DurablePhysicalWriteIntent>, ManagedError> {
        let state = self.state.lock().await;
        Ok(state
            .physical_write_intents
            .values()
            .filter(|intent| {
                !state.logical_operations.values().any(|operation| {
                    !operation.state.terminal()
                        && operation.intent.primary_child_operation_id == intent.intent_id
                })
            })
            .take(limit as usize)
            .map(|intent| DurablePhysicalWriteIntent {
                intent: intent.clone(),
                namespace_epoch: state
                    .physical_write_epochs
                    .get(&intent.intent_id)
                    .copied()
                    .unwrap_or(1),
                blocked_reason: state.blocked_write_intents.get(&intent.intent_id).cloned(),
                lease_expires_at_ms: state
                    .physical_write_leases
                    .get(&intent.intent_id)
                    .copied()
                    .unwrap_or(0),
                lease: PhysicalWriteLease {
                    intent_id: intent.intent_id,
                    namespace_epoch: state
                        .physical_write_epochs
                        .get(&intent.intent_id)
                        .copied()
                        .unwrap_or(1),
                    owner: intent.lease_owner.clone(),
                    token: state
                        .physical_write_tokens
                        .get(&intent.intent_id)
                        .copied()
                        .unwrap_or(Uuid::nil()),
                },
            })
            .collect())
    }

    async fn physical_write_intent(
        &self,
        intent_id: Uuid,
    ) -> Result<Option<DurablePhysicalWriteIntent>, ManagedError> {
        let state = self.state.lock().await;
        Ok(state.physical_write_intents.get(&intent_id).map(|intent| {
            let namespace_epoch = state
                .physical_write_epochs
                .get(&intent_id)
                .copied()
                .unwrap_or(1);
            DurablePhysicalWriteIntent {
                intent: intent.clone(),
                namespace_epoch,
                blocked_reason: state.blocked_write_intents.get(&intent_id).cloned(),
                lease_expires_at_ms: state
                    .physical_write_leases
                    .get(&intent_id)
                    .copied()
                    .unwrap_or(0),
                lease: PhysicalWriteLease {
                    intent_id,
                    namespace_epoch,
                    owner: intent.lease_owner.clone(),
                    token: state
                        .physical_write_tokens
                        .get(&intent_id)
                        .copied()
                        .unwrap_or(Uuid::nil()),
                },
            }
        }))
    }

    async fn renew_physical_write_intent(
        &self,
        lease: &PhysicalWriteLease,
        lease_expires_at_ms: i64,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state
            .physical_write_intents
            .get(&lease.intent_id)
            .is_none_or(|intent| intent.lease_owner != lease.owner)
            || state.physical_write_tokens.get(&lease.intent_id) != Some(&lease.token)
            || state.physical_write_epochs.get(&lease.intent_id) != Some(&lease.namespace_epoch)
            || state
                .physical_write_leases
                .get(&lease.intent_id)
                .is_none_or(|expires| *expires <= crate::transaction::unix_time_ms())
        {
            return Err(ManagedError::Conflict);
        }
        state
            .physical_write_leases
            .insert(lease.intent_id, lease_expires_at_ms);
        Ok(())
    }

    async fn claim_expired_physical_write_intent(
        &self,
        intent_id: Uuid,
        owner: &str,
        lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        let mut state = self.state.lock().await;
        if state.logical_operations.values().any(|operation| {
            !operation.state.terminal() && operation.intent.primary_child_operation_id == intent_id
        }) {
            return Ok(None);
        }
        if state
            .physical_write_leases
            .get(&intent_id)
            .is_none_or(|expires| *expires > crate::transaction::unix_time_ms())
        {
            return Ok(None);
        }
        let token = Uuid::now_v7();
        let namespace_epoch = state
            .physical_write_epochs
            .get(&intent_id)
            .copied()
            .ok_or(ManagedError::Conflict)?;
        let intent = state
            .physical_write_intents
            .get_mut(&intent_id)
            .ok_or(ManagedError::Conflict)?;
        intent.lease_owner = owner.to_string();
        state.physical_write_tokens.insert(intent_id, token);
        state
            .physical_write_leases
            .insert(intent_id, lease_expires_at_ms);
        Ok(Some(PhysicalWriteLease {
            intent_id,
            namespace_epoch,
            owner: owner.to_string(),
            token,
        }))
    }

    async fn claim_logical_physical_write_intent(
        &self,
        claim: &ManagedRecoveryClaim,
        lease_expires_at_ms: i64,
    ) -> Result<Option<PhysicalWriteLease>, ManagedError> {
        let now = crate::transaction::unix_time_ms();
        if lease_expires_at_ms <= now {
            return Err(ManagedError::Conflict);
        }
        let mut state = self.state.lock().await;
        let operation = state
            .logical_operations
            .get(&claim.operation.intent.operation_id)
            .cloned()
            .ok_or(ManagedError::Conflict)?;
        validate_recovery_authority(&operation, Some(claim), now)?;
        let intent_id = operation.intent.primary_child_operation_id;
        if state
            .physical_write_leases
            .get(&intent_id)
            .is_none_or(|expires| *expires > now)
        {
            return Ok(None);
        }
        let intent = state
            .physical_write_intents
            .get_mut(&intent_id)
            .ok_or(ManagedError::Conflict)?;
        intent.lease_owner = claim.owner.clone();
        let token = Uuid::now_v7();
        state.physical_write_tokens.insert(intent_id, token);
        state
            .physical_write_leases
            .insert(intent_id, lease_expires_at_ms);
        Ok(Some(PhysicalWriteLease {
            intent_id,
            namespace_epoch: operation.intent.fence.namespace_epoch,
            owner: claim.owner.clone(),
            token,
        }))
    }

    async fn commit_physical_write(
        &self,
        lease: &PhysicalWriteLease,
        superseded_version_ids: &[String],
        version_id: Option<&str>,
    ) -> Result<(), ManagedError> {
        if superseded_version_ids.iter().any(String::is_empty)
            || version_id.is_some_and(str::is_empty)
        {
            return Err(ManagedError::Conflict);
        }
        let mut state = self.state.lock().await;
        if state.logical_operations.values().any(|operation| {
            !operation.state.terminal()
                && operation.intent.primary_child_operation_id == lease.intent_id
        }) {
            return Err(ManagedError::Conflict);
        }
        if state
            .physical_write_intents
            .get(&lease.intent_id)
            .is_none_or(|intent| intent.lease_owner != lease.owner)
            || state.physical_write_tokens.get(&lease.intent_id) != Some(&lease.token)
            || state.physical_write_epochs.get(&lease.intent_id) != Some(&lease.namespace_epoch)
            || state
                .physical_write_leases
                .get(&lease.intent_id)
                .is_none_or(|expires| *expires <= crate::transaction::unix_time_ms())
        {
            return Err(ManagedError::Conflict);
        }
        let intent = state
            .physical_write_intents
            .remove(&lease.intent_id)
            .unwrap();
        state.blocked_write_intents.remove(&lease.intent_id);
        state.physical_write_leases.remove(&lease.intent_id);
        state.physical_write_tokens.remove(&lease.intent_id);
        state.physical_write_epochs.remove(&lease.intent_id);
        for version_id in superseded_version_ids
            .iter()
            .map(|value| Some(value.clone()))
            .chain(std::iter::once(version_id.map(ToOwned::to_owned)))
        {
            let target = PhysicalVersionTarget {
                tenant_id: intent.tenant_id.clone(),
                namespace_epoch: lease.namespace_epoch,
                backend_id: intent.backend_id.clone(),
                storage_identity: intent.storage_identity.clone(),
                credential_epoch: intent.credential_epoch,
                provider_bucket: intent.provider_bucket.clone(),
                physical_key: intent.physical_key.clone(),
                version_id,
                versioning_mode: intent.versioning_mode,
                versioning_capability: intent.versioning_capability,
                write_operation_id: lease.intent_id,
            };
            let duplicate = state.physical_versions.iter().any(|existing| {
                existing.tenant_id == target.tenant_id
                    && existing.backend_id == target.backend_id
                    && existing.provider_bucket == target.provider_bucket
                    && existing.physical_key == target.physical_key
                    && existing.version_id == target.version_id
            });
            if !duplicate {
                state.physical_versions.push(target);
            }
        }
        Ok(())
    }

    async fn abort_physical_write(&self, lease: &PhysicalWriteLease) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state.logical_operations.values().any(|operation| {
            !operation.state.terminal()
                && operation.intent.primary_child_operation_id == lease.intent_id
        }) {
            return Err(ManagedError::Conflict);
        }
        if state.physical_write_tokens.get(&lease.intent_id) != Some(&lease.token)
            || state.physical_write_epochs.get(&lease.intent_id) != Some(&lease.namespace_epoch)
            || state
                .physical_write_leases
                .get(&lease.intent_id)
                .is_none_or(|expires| *expires <= crate::transaction::unix_time_ms())
        {
            return Err(ManagedError::Conflict);
        }
        state.physical_write_intents.remove(&lease.intent_id);
        state.blocked_write_intents.remove(&lease.intent_id);
        state.physical_write_leases.remove(&lease.intent_id);
        state.physical_write_tokens.remove(&lease.intent_id);
        state.physical_write_epochs.remove(&lease.intent_id);
        Ok(())
    }

    async fn block_physical_write(
        &self,
        lease: &PhysicalWriteLease,
        reason: &str,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        if state.physical_write_tokens.get(&lease.intent_id) != Some(&lease.token)
            || state.physical_write_epochs.get(&lease.intent_id) != Some(&lease.namespace_epoch)
            || state
                .physical_write_leases
                .get(&lease.intent_id)
                .is_none_or(|expires| *expires <= crate::transaction::unix_time_ms())
        {
            return Err(ManagedError::Conflict);
        }
        state
            .blocked_write_intents
            .insert(lease.intent_id, reason.to_string());
        Ok(())
    }

    async fn physical_versions(
        &self,
        tenant_id: &str,
        backend_id: &str,
        provider_bucket: &str,
        physical_key: &str,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        Ok(self
            .state
            .lock()
            .await
            .physical_versions
            .iter()
            .filter(|target| {
                target.tenant_id == tenant_id
                    && target.backend_id == backend_id
                    && target.provider_bucket == provider_bucket
                    && target.physical_key == physical_key
            })
            .cloned()
            .collect())
    }

    async fn forget_physical_version(
        &self,
        target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        let previous_len = state.physical_versions.len();
        state
            .physical_versions
            .retain(|candidate| candidate != target);
        if state.physical_versions.len() == previous_len
            || state
                .physical_versions
                .iter()
                .any(|candidate| candidate.write_operation_id == target.write_operation_id)
        {
            return Ok(());
        }
        let operation_id = state
            .logical_operations
            .iter()
            .find_map(|(operation_id, operation)| {
                (operation.intent.primary_child_operation_id == target.write_operation_id)
                    .then_some(*operation_id)
            });
        if let Some(operation_id) = operation_id {
            let operation = state.logical_operations.get(&operation_id).unwrap();
            let tenant_id = operation.intent.logical.tenant_id.clone();
            let committed = operation.committed_physical_bytes;
            let released = committed
                .checked_sub(operation.released_physical_bytes)
                .ok_or_else(|| {
                    ManagedError::Corrupt(
                        "managed operation released bytes exceed committed bytes".to_string(),
                    )
                })?;
            if released > 0 {
                let usage = Self::workspace_usage(&mut state, &tenant_id);
                usage.physical_allocated_bytes = usage
                    .physical_allocated_bytes
                    .checked_sub(released)
                    .ok_or_else(|| {
                        ManagedError::Corrupt(
                            "managed physical usage is below the child allocation".to_string(),
                        )
                    })?;
                let now = crate::transaction::unix_time_ms();
                usage.version = usage.version.saturating_add(1);
                usage.updated_at_ms = now;
                let operation = state.logical_operations.get_mut(&operation_id).unwrap();
                operation.released_physical_bytes = committed;
                operation.updated_at_ms = now;
            }
        }
        Ok(())
    }

    async fn purge_namespace(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        let mut state = self.state.lock().await;
        if let Some(purge) = state.purges.get(&request.operation_id) {
            if purge.tenant_id != request.tenant_id {
                return Ok(NamespacePurgeStatus::Blocked {
                    reason: "purge operation belongs to another namespace".to_string(),
                });
            }
            return Ok(Self::finish_purge(&mut state, request.operation_id));
        }
        if state.fenced_namespaces.contains_key(&request.tenant_id) {
            return Ok(NamespacePurgeStatus::Blocked {
                reason: "another managed namespace purge is already running".to_string(),
            });
        }
        for authority in state
            .authorities
            .values()
            .filter(|authority| authority.logical.tenant_id == request.tenant_id)
            .filter(|authority| !authority.tombstone)
        {
            let physical_key = generation_physical_key(&authority.logical, authority.generation);
            let required_backends = std::iter::once(authority.primary_backend_id.as_str()).chain(
                authority
                    .replica_backend_id
                    .as_deref()
                    .filter(|_| authority.replica_status == CopyStatus::Ready),
            );
            for backend_id in required_backends {
                if !state.physical_versions.iter().any(|target| {
                    target.tenant_id == request.tenant_id
                        && target.backend_id == backend_id
                        && target.physical_key == physical_key
                }) {
                    return Ok(NamespacePurgeStatus::Blocked {
                        reason: format!(
                            "managed authority references unledgered physical versions on backend {backend_id}"
                        ),
                    });
                }
            }
        }
        state
            .fenced_namespaces
            .insert(request.tenant_id.clone(), request.operation_id);
        state.purges.insert(
            request.operation_id,
            MemoryPurge {
                tenant_id: request.tenant_id.clone(),
                status: NamespacePurgeStatus::Running,
                deleted_versions: 0,
            },
        );
        Ok(Self::finish_purge(&mut state, request.operation_id))
    }

    async fn namespace_purge_status(
        &self,
        request: &NamespacePurgeRequest,
    ) -> Result<NamespacePurgeStatus, ManagedError> {
        let mut state = self.state.lock().await;
        Ok(Self::finish_purge(&mut state, request.operation_id))
    }

    async fn purge_targets(
        &self,
        request: &NamespacePurgeRequest,
        limit: u64,
    ) -> Result<Vec<PhysicalVersionTarget>, ManagedError> {
        let state = self.state.lock().await;
        if state
            .purges
            .get(&request.operation_id)
            .is_none_or(|purge| purge.tenant_id != request.tenant_id)
        {
            return Err(ManagedError::Conflict);
        }
        Ok(state
            .physical_versions
            .iter()
            .filter(|target| target.tenant_id == request.tenant_id)
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn mark_purge_target_deleted(
        &self,
        request: &NamespacePurgeRequest,
        target: &PhysicalVersionTarget,
    ) -> Result<(), ManagedError> {
        let mut state = self.state.lock().await;
        let before = state.physical_versions.len();
        state
            .physical_versions
            .retain(|candidate| candidate != target);
        if state.physical_versions.len() != before
            && let Some(purge) = state.purges.get_mut(&request.operation_id)
        {
            purge.deleted_versions = purge.deleted_versions.saturating_add(1);
            purge.status = NamespacePurgeStatus::Running;
        }
        Ok(())
    }

    async fn mark_purge_target_blocked(
        &self,
        request: &NamespacePurgeRequest,
        _target: &PhysicalVersionTarget,
        reason: &str,
    ) -> Result<(), ManagedError> {
        if let Some(purge) = self
            .state
            .lock()
            .await
            .purges
            .get_mut(&request.operation_id)
        {
            purge.status = NamespacePurgeStatus::Blocked {
                reason: reason.to_string(),
            };
        }
        Ok(())
    }
}

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
