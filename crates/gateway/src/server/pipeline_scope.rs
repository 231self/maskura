//! Byte-preserving scope resolution for the S3 request paths (ADR 0036,
//! ADR 0038).
//!
//! The pipeline resolver's `resolve` has no key, so prefix scopes cannot be
//! resolved inside it. These helpers run in the handlers, before resolution:
//! a covered request skips classification and the format adapters and executes
//! the explicit passthrough resolution instead. Coverage has two sources: the
//! operator env scope (self-hosted, ADR 0036) and the resolver's key-aware
//! signed scope (hosted, ADR 0038). Every other request keeps the existing
//! behavior.

use super::*;
use crate::byte_preserving::byte_preserving_resolution;

/// A resolution plus whether it came from a byte-preserving scope (either
/// source). The flag drives the managed-destination fail-closed rejection.
pub(crate) struct ScopedResolution {
    pub resolution: crate::pipeline::PipelineResolution,
    pub byte_preserving: bool,
}

/// Coverage from either source: the operator env scope first (cheap, local),
/// then the resolver's signed key-aware scope. Authorization is separate and
/// unchanged; no client input selects coverage.
pub(crate) async fn byte_preserving_covers_async(
    state: &AppState,
    workspace_id: &str,
    bucket: &str,
    key: &str,
) -> bool {
    if state.byte_preserving.covers(bucket, key) {
        return true;
    }
    matches!(
        state
            .gateway
            .resolve_for_key(
                workspace_id,
                bucket,
                key,
                crate::pipeline::PipelineDirection::Write,
            )
            .await,
        Ok(Some(_))
    )
}

/// Resolves the pipeline for one request. Precedence: the resolver's signed
/// key-aware resolution (its locator, fingerprint, and limits come from the
/// signed route), then the operator env scope's local passthrough resolution,
/// then the normal resolver.
pub(crate) async fn resolve_request_pipeline(
    state: &AppState,
    workspace_id: &str,
    bucket: &str,
    key: &str,
    direction: crate::pipeline::PipelineDirection,
) -> Result<ScopedResolution, maskura_error::MaskuraError> {
    if let Some(resolution) = state
        .gateway
        .resolve_for_key(workspace_id, bucket, key, direction)
        .await?
    {
        return Ok(ScopedResolution {
            resolution,
            byte_preserving: true,
        });
    }
    if state.byte_preserving.covers(bucket, key) {
        return Ok(ScopedResolution {
            resolution: byte_preserving_resolution(direction, state.plugins.pipeline_limits()),
            byte_preserving: true,
        });
    }
    Ok(ScopedResolution {
        resolution: state
            .gateway
            .resolve(workspace_id, bucket, direction)
            .await?,
        byte_preserving: false,
    })
}

/// Managed service storage is the protected product path. A byte-preserving
/// scope must never silently bypass its transforms, so a covered request that
/// resolves to managed storage fails closed instead of degrading to a raw
/// write. Applies to both scope sources (ADR 0036, ADR 0038).
pub(crate) fn byte_preserving_backend_rejection(
    byte_preserving: bool,
    backend: &ResolvedBackend,
) -> Option<maskura_error::MaskuraError> {
    if byte_preserving && matches!(backend, ResolvedBackend::Managed(_)) {
        return Some(maskura_error::MaskuraError::new(
            maskura_error::codes::CONFIG_INVALID,
            "the key is in a byte-preserving scope but the destination is managed storage; managed storage keeps its transforms (ADR 0036)",
        ));
    }
    None
}
