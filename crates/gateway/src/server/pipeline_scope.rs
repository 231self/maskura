//! Byte-preserving scope resolution for the S3 request paths (ADR 0036).
//!
//! The pipeline resolver interface has no key, so prefix scopes cannot be
//! resolved inside it. These helpers run in the handlers, before resolution:
//! a covered request skips the resolver and executes the explicit passthrough
//! resolution instead. Every other request keeps the existing behavior.

use super::*;
use crate::byte_preserving::byte_preserving_resolution;

/// Whether operator configuration declares this bucket/key as external-catalog
/// storage. Authorization is separate and unchanged.
pub(crate) fn byte_preserving_covers(state: &AppState, bucket: &str, key: &str) -> bool {
    state.byte_preserving.covers(bucket, key)
}

/// Resolves the pipeline for one request, substituting the byte-preserving
/// passthrough resolution when the operator scope covers the key.
pub(crate) async fn resolve_request_pipeline(
    state: &AppState,
    workspace_id: &str,
    bucket: &str,
    key: &str,
    direction: crate::pipeline::PipelineDirection,
) -> Result<crate::pipeline::PipelineResolution, maskura_error::MaskuraError> {
    if state.byte_preserving.covers(bucket, key) {
        return Ok(byte_preserving_resolution(
            direction,
            state.plugins.pipeline_limits(),
        ));
    }
    state.gateway.resolve(workspace_id, bucket, direction).await
}

/// Managed service storage is the protected product path. A byte-preserving
/// scope must never silently bypass its transforms, so a covered request that
/// resolves to managed storage fails closed instead of degrading to a raw
/// write.
pub(crate) fn byte_preserving_backend_rejection(
    state: &AppState,
    bucket: &str,
    key: &str,
    backend: &ResolvedBackend,
) -> Option<maskura_error::MaskuraError> {
    if state.byte_preserving.covers(bucket, key) && matches!(backend, ResolvedBackend::Managed(_)) {
        return Some(maskura_error::MaskuraError::new(
            maskura_error::codes::CONFIG_INVALID,
            "the key is in a byte-preserving scope but the destination is managed storage; managed storage keeps its transforms (ADR 0036)",
        ));
    }
    None
}
