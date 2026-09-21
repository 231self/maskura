//! Extracted from `multipart_staging.rs`; re-exported from `crate::multipart_staging`.

use super::*;

pub const MAX_ACTIVE_UPLOADS: usize = 16;

pub const MAX_PARTS: u32 = 10_000;

pub const MAX_MULTIPART_UPLOADS_PAGE: usize = 1_000;

pub const DEFAULT_EXPIRY: Duration = Duration::from_secs(24 * 60 * 60);

pub(crate) const MAGIC: &[u8] = b"MSKMP1\0";

pub(crate) const NONCE_LEN: usize = 12;

pub(crate) const FILE_PREFIX: &str = "maskura-multipart-";

pub const ARTIFACT_PREFIX: &str = "multipart/";

#[cfg(any(test, debug_assertions))]
pub(crate) static FAIL_ABORT_AFTER_UPDATE: AtomicBool = AtomicBool::new(false);

pub const RECONCILIATION_GRACE: Duration = Duration::from_secs(5 * 60);

pub const COMPLETION_LEASE: Duration = Duration::from_secs(30);

pub(crate) const MAX_ARTIFACT_HEADER_BYTES: usize = 64 * 1024;

pub(crate) const MAX_ENCRYPTED_FRAME_BYTES: usize = 8 * 1024 * 1024 + 16;
