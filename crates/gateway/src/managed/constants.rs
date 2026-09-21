//! Extracted from `managed.rs`; re-exported from `crate::managed`.

pub const PLACEMENT_VERSION_V1: u32 = 1;

pub const PHYSICAL_WRITE_LEASE_MS: i64 = 2 * 60 * 60 * 1000;

/// A repair that fails this many times is dead-lettered and no longer retried.
pub const MAX_REPAIR_ATTEMPTS: u32 = 8;

pub const REPAIR_BACKOFF_BASE_MS: i64 = 30_000;

pub const REPAIR_BACKOFF_MAX_MS: i64 = 4 * 60 * 60 * 1000;

/// Exponential backoff before a failed repair is eligible for retry.
pub(crate) fn repair_backoff_ms(attempts: u32) -> i64 {
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

pub const MANAGED_PUBLICATION_RECIPE_VERSION: i32 = 1;
