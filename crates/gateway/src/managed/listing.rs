//! Extracted from `managed.rs`; re-exported from `crate::managed`.

use super::*;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedListVersion {
    V1,
    V2,
}

impl ManagedListVersion {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "V1",
            Self::V2 => "V2",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ManagedError> {
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
    pub(crate) fn parse(value: &str) -> Result<Self, ManagedError> {
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

pub(crate) fn serialize_cursor_response_state(
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

pub(crate) fn cursor_matches_request(
    cursor: &ManagedListCursor,
    request: &ManagedListCursorRequest,
) -> bool {
    cursor.binding == request.binding
        && cursor.position == request.position
        && cursor.response_state == request.response_state
        && cursor.final_page == request.final_page
}

pub(crate) fn list_cursor_from_model(
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

pub(crate) fn purge_status_from_model(
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
