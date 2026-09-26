//! Request-path policy enforcement seam (policy-approval Slice 3, ADR 0022).
//!
//! The gate runs at the [`crate::pipeline::PipelineResolution`] freeze point:
//! after pipeline freeze and backend resolution, before body processing and
//! storage selection. Every S3 data-plane handler — and the hosted MCP
//! dispatch, which calls those handlers in process — goes through
//! [`enforce_policy`]. The OSS engine leaves `policy_gate` unset and keeps its
//! historical behavior (ADR 0021); the hosted control plane wires a
//! digest-verifying gate behind the same seam.

use std::sync::Arc;

use async_trait::async_trait;
use maskura_error::MaskuraError;
use maskura_pipeline_config::{PolicyLimits, PolicyOperation, ResolvedDestination};
use serde::{Deserialize, Serialize};

use crate::backend::ResolvedBackend;
use crate::pipeline::{PipelineDirection, PipelineResolution};

/// One data-plane request presented to the policy gate.
pub struct PolicyRequest<'a> {
    /// Canonical workspace id of the authenticated principal.
    pub workspace_id: &'a str,
    /// The exact operation being attempted; unlisted operations are denied
    /// by a bound gate.
    pub operation: PolicyOperation,
    pub bucket: &'a str,
    pub key: &'a str,
    /// Frozen pipeline resolution. `None` on paths that execute no pipeline
    /// of their own (raw GET, HEAD, LIST, DELETE, multipart part upload and
    /// abort); a bound gate maps those to approved state either through the
    /// passthrough projection or the create-time frozen multipart evidence.
    pub resolution: Option<&'a PipelineResolution>,
    /// Candidate destination produced by backend resolution. After
    /// verification the request must execute against exactly this value —
    /// never a re-resolution of a mutable row (check/use discipline).
    pub destination: &'a ResolvedBackend,
    pub direction: PipelineDirection,
}

/// Approval evidence returned by the gate and retained in request context
/// through actual storage selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedPolicy {
    /// `None` when no gate is configured or the gate approved an unbound
    /// request; execution proceeds unconstrained (historical behavior).
    pub binding: Option<PolicyBinding>,
}

impl VerifiedPolicy {
    /// The unbound verdict used by [`NoopPolicyGate`] and the absent-gate
    /// path.
    pub fn unbound() -> Self {
        Self { binding: None }
    }

    pub fn is_bound(&self) -> bool {
        self.binding.is_some()
    }
}

/// Everything a bound gate freezes for one approved request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBinding {
    pub workspace_id: String,
    pub operation: PolicyOperation,
    /// Longest-prefix route match inside the approved effective state.
    pub route_prefix: String,
    /// Active envelope identity at verification time.
    pub envelope_digest: String,
    pub envelope_version: u64,
    /// Approved effective-state digest matched by the frozen resolution.
    pub effective_state_digest: String,
    /// Receipt chain-head evidence the verdict was checked against.
    pub receipt_seq: u64,
    pub receipt_body_digest: String,
    /// `signer_epoch + envelope_version + receipt seq` at verification.
    pub authorization_epoch: u64,
    /// Destination binding execution must use verbatim.
    pub destination: ResolvedDestination,
    /// `min(policy, operator caps)` to push into the wasm session.
    pub limits: PolicyLimits,
}

/// Request-path policy verdicts at the pipeline freeze point.
#[async_trait]
pub trait PolicyGate: Send + Sync {
    async fn enforce(&self, request: &PolicyRequest<'_>) -> Result<VerifiedPolicy, MaskuraError>;
}

/// Inert gate: every request is approved unbound. The explicit OSS default
/// (ADR 0021) — behavior is byte-identical to a missing gate.
pub struct NoopPolicyGate;

#[async_trait]
impl PolicyGate for NoopPolicyGate {
    async fn enforce(&self, _request: &PolicyRequest<'_>) -> Result<VerifiedPolicy, MaskuraError> {
        Ok(VerifiedPolicy::unbound())
    }
}

/// Enforce at one call site. A missing gate (OSS, or policy enforcement
/// inert) short-circuits to [`VerifiedPolicy::unbound`].
pub async fn enforce_policy(
    gate: Option<&Arc<dyn PolicyGate>>,
    request: PolicyRequest<'_>,
) -> Result<VerifiedPolicy, MaskuraError> {
    match gate {
        Some(gate) => gate.enforce(&request).await,
        None => Ok(VerifiedPolicy::unbound()),
    }
}

/// S3 XML error document for a policy-gate rejection. The machine-readable
/// policy code is the S3 `<Code>` element.
pub(crate) fn policy_error_response(key: &str, error: &MaskuraError) -> axum::response::Response {
    match error.code() {
        maskura_error::codes::POLICY_DENIED
        | maskura_error::codes::POLICY_UNPROVISIONED
        | maskura_error::codes::POLICY_EXPIRED
        | maskura_error::codes::POLICY_TAMPERED => {
            crate::s3_error::policy_error(key, error.code(), error.message())
        }
        _ => crate::s3_error::internal_error(key, error.code()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maskura_error::codes;

    fn request<'a>(destination: &'a ResolvedBackend) -> PolicyRequest<'a> {
        PolicyRequest {
            workspace_id: "ws-test",
            operation: PolicyOperation::Put,
            bucket: "bucket",
            key: "key",
            resolution: None,
            destination,
            direction: PipelineDirection::Write,
        }
    }

    fn presigned() -> ResolvedBackend {
        ResolvedBackend::PresignedHttp(url::Url::parse("https://store.example.com/upload").unwrap())
    }

    #[tokio::test]
    async fn noop_gate_approves_unbound() {
        let destination = presigned();
        let verdict = NoopPolicyGate
            .enforce(&request(&destination))
            .await
            .expect("noop gate never rejects");
        assert_eq!(verdict, VerifiedPolicy::unbound());
        assert!(!verdict.is_bound());
    }

    #[tokio::test]
    async fn missing_gate_short_circuits_to_unbound() {
        let destination = presigned();
        let verdict = enforce_policy(None, request(&destination))
            .await
            .expect("missing gate never rejects");
        assert!(!verdict.is_bound());
    }

    #[tokio::test]
    async fn configured_gate_receives_the_request() {
        struct RejectingGate;

        #[async_trait]
        impl PolicyGate for RejectingGate {
            async fn enforce(
                &self,
                request: &PolicyRequest<'_>,
            ) -> Result<VerifiedPolicy, MaskuraError> {
                assert_eq!(request.workspace_id, "ws-test");
                assert_eq!(request.operation, PolicyOperation::Put);
                assert!(request.resolution.is_none());
                Err(MaskuraError::new(codes::POLICY_DENIED, "denied"))
            }
        }

        let destination = presigned();
        let gate: Arc<dyn PolicyGate> = Arc::new(RejectingGate);
        let error = enforce_policy(Some(&gate), request(&destination))
            .await
            .expect_err("gate rejects");
        assert_eq!(error.code(), codes::POLICY_DENIED);
    }

    #[test]
    fn verified_policy_serde_roundtrip() {
        let bound = VerifiedPolicy {
            binding: Some(PolicyBinding {
                workspace_id: "ws-test".into(),
                operation: PolicyOperation::ProcessedGet,
                route_prefix: "data/".into(),
                envelope_digest: "e".repeat(64),
                envelope_version: 3,
                effective_state_digest: "d".repeat(64),
                receipt_seq: 7,
                receipt_body_digest: "b".repeat(64),
                authorization_epoch: 11,
                destination: ResolvedDestination {
                    mode: maskura_pipeline_config::StorageMode::S3Compatible,
                    endpoint: "https://s3.example.com".into(),
                    bucket: "objects".into(),
                    region: "region".into(),
                    role_arn: None,
                    configuration_sha256: "c".repeat(64),
                },
                limits: PolicyLimits {
                    record_max_bytes: 1024,
                    object_max_bytes: 4096,
                    memory_bytes: 67_108_864,
                    fuel: 10_000_000,
                    deadline_ms: 30_000,
                },
            }),
        };
        for verdict in [VerifiedPolicy::unbound(), bound] {
            let json = serde_json::to_string(&verdict).expect("serialize");
            let parsed: VerifiedPolicy = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed, verdict);
        }
    }

    #[test]
    fn policy_error_response_carries_the_policy_code() {
        let response = policy_error_response(
            "key",
            &MaskuraError::new(codes::POLICY_DENIED, "state mismatch"),
        );
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
        let internal = policy_error_response("key", &MaskuraError::new(codes::INTERNAL, "boom"));
        assert_eq!(
            internal.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
