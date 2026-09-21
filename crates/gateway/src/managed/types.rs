//! Extracted from `managed.rs`; re-exported from `crate::managed`.

use super::*;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyStatus {
    Ready,
    RepairPending,
    Absent,
}

impl CopyStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::RepairPending => "REPAIR_PENDING",
            Self::Absent => "ABSENT",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ManagedError> {
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
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ManagedError> {
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
    pub(crate) fn as_str(self) -> &'static str {
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

    pub(crate) fn parse(value: &str) -> Result<Self, ManagedError> {
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

    pub(crate) fn terminal(self) -> bool {
        matches!(self, Self::Committed | Self::ProvenAborted)
    }
}

pub(crate) fn valid_logical_transition(
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
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Settled => "SETTLED",
            Self::Released => "RELEASED",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ManagedError> {
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
