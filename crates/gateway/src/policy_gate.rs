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
use maskura_pipeline_config::{DestinationBinding, PolicyLimits, PolicyOperation};
use serde::{Deserialize, Serialize};

use crate::backend::{DestinationSelectionSnapshot, ResolvedBackend};
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
    /// Non-secret destination snapshot captured at the same resolution.
    /// The gate verifies this against approved effective-state bindings.
    pub snapshot: &'a DestinationSelectionSnapshot,
    pub direction: PipelineDirection,
    /// Create-time frozen verdict retained on a staged multipart upload
    /// (Slice 3 / spec §7.4). `Some` only on multipart continuation requests
    /// (part upload, abort, complete) that carry the frozen admission;
    /// `None` for single-shot operations and for `MultipartCreate` (which is
    /// the freeze point). The gate validates continuations against it so
    /// in-flight uploads keep their approved state across envelope
    /// rotation/expiry.
    pub frozen: Option<&'a VerifiedPolicy>,
}

/// The evidence schema version written by this gateway into
/// [`VerifiedPolicy::schema_version`].
pub const VERIFIED_POLICY_SCHEMA_VERSION: u32 = 1;

/// Approval evidence returned by the gate and retained in request context
/// through actual storage selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedPolicy {
    /// Evidence schema version. Written as [`VERIFIED_POLICY_SCHEMA_VERSION`].
    /// Pre-versioning verdicts (v0.7.21) deserialize as 0 via `#[serde(default)]`
    /// and carry identical semantics; readers fail closed on versions above
    /// current (unknown future evidence).
    #[serde(default)]
    pub schema_version: u32,
    /// `None` when no gate is configured or the gate approved an unbound
    /// request; execution proceeds unconstrained (historical behavior).
    pub binding: Option<PolicyBinding>,
}

impl VerifiedPolicy {
    /// The unbound verdict used by [`NoopPolicyGate`] and the absent-gate
    /// path.
    pub fn unbound() -> Self {
        Self {
            schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
            binding: None,
        }
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
    /// Longest-prefix route match inside the approved effective state: the
    /// matched approved effective route's key prefix. Effective routes are
    /// whole-bucket today, so this is currently always `""`; it becomes
    /// meaningful when per-assignment key prefixes land. The envelope's
    /// declared key prefixes remain the gate-time key bound.
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
    pub destination: DestinationBinding,
    /// Per-key managed placement targets frozen at verification (`None` for
    /// non-managed destinations). Execution must select exactly these
    /// backends — never a re-placed rendezvous of a mutable ring.
    pub managed_placement: Option<(String, Option<String>)>,
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

/// Consume a gate verdict at the point of storage execution (check/use).
///
/// A bound [`PolicyBinding`] freezes the destination, the per-key managed
/// placement targets, and the effective limits execution must use. This re-checks
/// that the request-time [`DestinationSelectionSnapshot`] execution is about to
/// act on still matches the frozen binding (the resolution must not have drifted
/// between the gate and the commit), then hands the binding back so the caller
/// drives execution — and the wasm session limits — from the verified values.
///
/// A bound verdict whose selection no longer matches the binding is rejected
/// with [`codes::POLICY_DENIED`] (a state/bounds mismatch: the destination the
/// request would use is not the approved one). A verdict whose
/// [`VerifiedPolicy::schema_version`] is newer than
/// [`VERIFIED_POLICY_SCHEMA_VERSION`] is unknown future evidence and is
/// rejected with [`codes::POLICY_TAMPERED`] (fail closed). An unbound verdict
/// is inert (OSS behavior) and returns `Ok(None)`.
pub fn consume_policy<'a>(
    verdict: &'a VerifiedPolicy,
    snapshot: &DestinationSelectionSnapshot,
) -> Result<Option<&'a PolicyBinding>, MaskuraError> {
    reject_future_evidence(verdict)?;
    let Some(binding) = verdict.binding.as_ref() else {
        return Ok(None);
    };
    if !binding_matches_selection(binding, snapshot) {
        return Err(MaskuraError::new(
            maskura_error::codes::POLICY_DENIED,
            "policy binding does not match the resolved storage destination",
        ));
    }
    Ok(Some(binding))
}

/// Check/use against a create-time frozen verdict (Slice 3 / P4.1h).
///
/// Staged multipart uploads persist the verdict admitted at `MultipartCreate`;
/// every later operation on the upload (part upload, abort, complete,
/// list-parts) re-resolves its backend freshly and must prove that the frozen
/// approval still matches that fresh selection. A destination or managed
/// placement drift between the create-time admission and the later operation's
/// resolution is rejected with [`codes::POLICY_DENIED`] — a state/bounds
/// mismatch (spec §10), the same failure [`consume_policy`] produces.
///
/// `frozen: None` means the upload predates verdict freezing (or carries no
/// gate evidence at all) and preserves today's behavior: no frozen state to
/// re-check, so consumption is inert and returns `Ok(None)`. `Some(verdict)`
/// is consumed exactly as [`consume_policy`] consumes it — an unbound verdict
/// is likewise inert, a bound one is checked against the request-time
/// [`DestinationSelectionSnapshot`] and handed back for execution.
///
/// Scope: this re-checks destination identity and per-key managed placement
/// ONLY — that the frozen verdict belongs to *this* request (workspace, bucket,
/// key, upload) is enforced by the staging repository's `get_authorized`
/// identity filters at the load sites, and staleness (a revoked policy, an
/// expired envelope, an advanced receipt head) is deliberately not a freeze
/// failure — fresh per-request enforcement and [`min_policy_limits`] are the
/// tightening path.
///
/// As at [`consume_policy`], a frozen verdict carrying unknown future evidence
/// (a [`VerifiedPolicy::schema_version`] above
/// [`VERIFIED_POLICY_SCHEMA_VERSION`]) is rejected with
/// [`codes::POLICY_TAMPERED`] (fail closed) before any binding is handed to
/// execution.
pub fn consume_frozen_policy<'a>(
    frozen: Option<&'a VerifiedPolicy>,
    snapshot: &DestinationSelectionSnapshot,
) -> Result<Option<&'a PolicyBinding>, MaskuraError> {
    match frozen {
        Some(verdict) => {
            reject_future_evidence(verdict)?;
            consume_policy(verdict, snapshot)
        }
        None => Ok(None),
    }
}

/// The reader rule for durable verdict evidence: versions 0 (pre-versioning,
/// v0.7.21) and [`VERIFIED_POLICY_SCHEMA_VERSION`] are accepted; anything
/// newer is unknown future evidence and fails closed with
/// [`codes::POLICY_TAMPERED`].
fn reject_future_evidence(verdict: &VerifiedPolicy) -> Result<(), MaskuraError> {
    if verdict.schema_version > VERIFIED_POLICY_SCHEMA_VERSION {
        return Err(MaskuraError::new(
            maskura_error::codes::POLICY_TAMPERED,
            "verified policy evidence schema version is newer than this gateway",
        ));
    }
    Ok(())
}

/// The check/use predicate: does the request-time selection still equal the
/// frozen binding a bound gate approved?
pub fn binding_matches_selection(
    binding: &PolicyBinding,
    snapshot: &DestinationSelectionSnapshot,
) -> bool {
    destination_matches(&binding.destination, &snapshot.binding)
        && binding.managed_placement == snapshot.managed_placement()
}

/// Compare an approved destination binding against the request-time one.
///
/// For concrete destinations the request-time snapshot carries `bucket` as an
/// identity template (`String::new()`) while the approved binding carries the
/// signed logical bucket; the gate checks the route bucket separately, so this
/// compares the immutable identity fields only (mode, endpoint, region, role,
/// configuration version + digest) and treats `bucket` as non-identity. For a
/// managed topology the whole frozen ring is compared: a backend, credential
/// epoch, placement or authority change requires re-approval.
fn destination_matches(approved: &DestinationBinding, resolved: &DestinationBinding) -> bool {
    use maskura_pipeline_config::DestinationBinding as B;
    match (approved, resolved) {
        (B::Concrete { destination: a }, B::Concrete { destination: b }) => {
            concrete_identity_matches(a, b)
        }
        (
            B::ManagedTopology {
                placement_version: av,
                algorithm: aa,
                authority_sha256: ash,
                backends: ab,
            },
            B::ManagedTopology {
                placement_version: bv,
                algorithm: ba,
                authority_sha256: bsh,
                backends: bb,
            },
        ) => av == bv && aa == ba && ash == bsh && ab == bb,
        _ => false,
    }
}

/// Compare two concrete destinations on their immutable identity fields.
/// `bucket` is deliberately excluded: the request-time snapshot uses an empty
/// identity template and the approved binding carries the signed logical bucket
/// (checked separately against the route).
fn concrete_identity_matches(
    approved: &maskura_pipeline_config::ResolvedDestination,
    resolved: &maskura_pipeline_config::ResolvedDestination,
) -> bool {
    approved.mode == resolved.mode
        && approved.endpoint == resolved.endpoint
        && approved.region == resolved.region
        && approved.role_arn == resolved.role_arn
        && approved.configuration_version_id == resolved.configuration_version_id
        && approved.configuration_sha256 == resolved.configuration_sha256
}

/// Map the effective policy processing limits onto the wasm session's
/// [`crate::plugin_registry::PipelineLimits`], tightening only the fields a
/// policy governs so [`crate::plugin_registry::PipelineSnapshot::constrained`]
/// applies `min(policy, operator)` for those and leaves the operator's values
/// untouched for the rest (their "no extra constraint" sentinel is `MAX`, whose
/// `min` is a no-op). `PolicyLimits::memory_bytes` is the wasm engine sandbox
/// bound (`DEFAULT_GUEST_MEMORY_BYTES`) and is not a per-session pipeline
/// limit; it is enforced by the engine itself.
pub fn policy_session_limits(policy: &PolicyLimits) -> crate::plugin_registry::PipelineLimits {
    crate::plugin_registry::PipelineLimits {
        max_intermediate_record_bytes: policy.record_max_bytes.min(usize::MAX as u64) as usize,
        // No policy counterpart: leave the operator's value.
        max_plugin_finish_bytes: usize::MAX,
        max_input_bytes: policy.object_max_bytes,
        max_output_bytes: u64::MAX,
        max_expansion_factor: u64::MAX,
        max_expansion_slack_bytes: u64::MAX,
        max_plugins: usize::MAX,
        max_cumulative_fuel: policy.fuel,
        max_wall_time: std::time::Duration::from_millis(policy.deadline_ms),
    }
}

/// Field-wise `min` of two policy limit sets (Slice 3 / P4.1h).
///
/// When a staged multipart upload completes under both a create-time frozen
/// verdict and a freshly enforced verdict, the wasm session is bounded by
/// `min_policy_limits(frozen.limits, fresh.limits)`. This is fail-closed by
/// construction: execution never exceeds EITHER the create-time admission
/// ("retain frozen state across policy changes") OR the current policy
/// (tightening applies immediately). Staying within the minimum means staying
/// within every approval in force during the upload — the most auditable bound.
///
/// [`PolicyLimits::memory_bytes`] is the wasm engine sandbox bound
/// (`DEFAULT_GUEST_MEMORY_BYTES`, enforced by the engine;
/// [`policy_session_limits`] does not map it into the session) but is minimized
/// here too, for consistency: no field of the composed bound may exceed either
/// input.
pub fn min_policy_limits(a: &PolicyLimits, b: &PolicyLimits) -> PolicyLimits {
    PolicyLimits {
        record_max_bytes: a.record_max_bytes.min(b.record_max_bytes),
        object_max_bytes: a.object_max_bytes.min(b.object_max_bytes),
        memory_bytes: a.memory_bytes.min(b.memory_bytes),
        fuel: a.fuel.min(b.fuel),
        deadline_ms: a.deadline_ms.min(b.deadline_ms),
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

    fn request<'a>(
        destination: &'a ResolvedBackend,
        snapshot: &'a DestinationSelectionSnapshot,
    ) -> PolicyRequest<'a> {
        PolicyRequest {
            workspace_id: "ws-test",
            operation: PolicyOperation::Put,
            bucket: "bucket",
            key: "key",
            resolution: None,
            destination,
            snapshot,
            direction: PipelineDirection::Write,
            frozen: None,
        }
    }

    fn presigned() -> ResolvedBackend {
        ResolvedBackend::PresignedHttp(url::Url::parse("https://store.example.com/upload").unwrap())
    }

    fn presigned_snapshot() -> DestinationSelectionSnapshot {
        DestinationSelectionSnapshot {
            binding: maskura_pipeline_config::DestinationBinding::Concrete {
                destination: maskura_pipeline_config::ResolvedDestination {
                    mode: maskura_pipeline_config::StorageMode::Presigned,
                    endpoint: "https://store.example.com".into(),
                    bucket: String::new(),
                    region: String::new(),
                    role_arn: None,
                    configuration_version_id: None,
                    configuration_sha256: "a".repeat(64),
                },
            },
            selected_primary_backend_id: None,
            selected_replica_backend_id: None,
        }
    }

    #[tokio::test]
    async fn noop_gate_approves_unbound() {
        let destination = presigned();
        let snapshot = presigned_snapshot();
        let verdict = NoopPolicyGate
            .enforce(&request(&destination, &snapshot))
            .await
            .expect("noop gate never rejects");
        assert_eq!(verdict, VerifiedPolicy::unbound());
        assert!(!verdict.is_bound());
    }

    #[tokio::test]
    async fn missing_gate_short_circuits_to_unbound() {
        let destination = presigned();
        let snapshot = presigned_snapshot();
        let verdict = enforce_policy(None, request(&destination, &snapshot))
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
        let snapshot = presigned_snapshot();
        let gate: Arc<dyn PolicyGate> = Arc::new(RejectingGate);
        let error = enforce_policy(Some(&gate), request(&destination, &snapshot))
            .await
            .expect_err("gate rejects");
        assert_eq!(error.code(), codes::POLICY_DENIED);
    }

    #[test]
    fn verified_policy_serde_roundtrip() {
        let bound = VerifiedPolicy {
            schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
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
                destination: DestinationBinding::Concrete {
                    destination: maskura_pipeline_config::ResolvedDestination {
                        mode: maskura_pipeline_config::StorageMode::S3Compatible,
                        endpoint: "https://s3.example.com".into(),
                        bucket: "objects".into(),
                        region: "region".into(),
                        role_arn: None,
                        configuration_version_id: Some("config-version-1".into()),
                        configuration_sha256: "c".repeat(64),
                    },
                },
                managed_placement: None,
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

    // --- evidence schema versioning (Slice 3) ---

    fn verdict_with_schema_version(schema_version: u32) -> VerifiedPolicy {
        VerifiedPolicy {
            schema_version,
            binding: None,
        }
    }

    #[test]
    fn unbound_carries_the_current_schema_version() {
        assert_eq!(
            VerifiedPolicy::unbound().schema_version,
            VERIFIED_POLICY_SCHEMA_VERSION
        );
        assert_eq!(VERIFIED_POLICY_SCHEMA_VERSION, 1);
    }

    #[test]
    fn schema_version_round_trips_through_verdict_json() {
        let verdict = VerifiedPolicy {
            schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
            binding: Some(policy_binding(concrete_binding("my-bucket"), None)),
        };
        let json = serde_json::to_string(&verdict).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(
            value["schema_version"],
            serde_json::json!(1),
            "written evidence must carry the schema version"
        );
        let parsed: VerifiedPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.schema_version, VERIFIED_POLICY_SCHEMA_VERSION);
        assert_eq!(parsed, verdict, "round-trip must preserve the field");
    }

    #[test]
    fn schema_version_parses_from_json_with_or_without_the_key() {
        // Pre-versioning (v0.7.21) verdicts carry no key and parse as 0 with
        // identical semantics.
        let pre_versioning: VerifiedPolicy =
            serde_json::from_str(r#"{"binding":null}"#).expect("pre-versioning verdict parses");
        assert_eq!(pre_versioning.schema_version, 0);
        assert_eq!(
            pre_versioning,
            VerifiedPolicy {
                schema_version: 0,
                binding: None
            }
        );
        // Explicit current version parses as written.
        let current: VerifiedPolicy =
            serde_json::from_str(r#"{"schema_version":1,"binding":null}"#)
                .expect("current-version verdict parses");
        assert_eq!(current.schema_version, VERIFIED_POLICY_SCHEMA_VERSION);
        assert_eq!(current, VerifiedPolicy::unbound());
    }

    #[test]
    fn consume_policy_accepts_pre_versioning_schema_version() {
        // Version 0 (pre-versioning) carries identical semantics and must be
        // consumed normally, bound and unbound alike.
        let snapshot = concrete_snapshot("");
        let unbound = verdict_with_schema_version(0);
        assert!(
            consume_policy(&unbound, &snapshot)
                .expect("pre-versioning unbound verdict is inert")
                .is_none()
        );
        let bound = VerifiedPolicy {
            schema_version: 0,
            binding: Some(policy_binding(concrete_binding("my-bucket"), None)),
        };
        assert!(
            consume_policy(&bound, &snapshot)
                .expect("pre-versioning bound verdict is consumable")
                .is_some()
        );
    }

    #[test]
    fn consume_policy_rejects_future_schema_version() {
        // Unknown future evidence fails closed before any binding reaches
        // execution — for bound and unbound verdicts alike.
        let snapshot = concrete_snapshot("");
        let future_unbound = verdict_with_schema_version(VERIFIED_POLICY_SCHEMA_VERSION + 1);
        let error = consume_policy(&future_unbound, &snapshot)
            .expect_err("future evidence must fail closed");
        assert_eq!(error.code(), codes::POLICY_TAMPERED);
        assert_eq!(
            error.message(),
            "verified policy evidence schema version is newer than this gateway"
        );
        let future_bound = VerifiedPolicy {
            schema_version: VERIFIED_POLICY_SCHEMA_VERSION + 1,
            binding: Some(policy_binding(concrete_binding("my-bucket"), None)),
        };
        let error = consume_policy(&future_bound, &snapshot)
            .expect_err("future bound evidence must fail closed");
        assert_eq!(error.code(), codes::POLICY_TAMPERED);
    }

    #[test]
    fn consume_frozen_policy_rejects_future_schema_version() {
        // The frozen-reuse seam applies the same reader rule as consume_policy:
        // a persisted verdict from a newer gateway is unknown evidence.
        let snapshot = concrete_snapshot("");
        let future = verdict_with_schema_version(VERIFIED_POLICY_SCHEMA_VERSION + 1);
        let error = consume_frozen_policy(Some(&future), &snapshot)
            .expect_err("future frozen evidence must fail closed");
        assert_eq!(error.code(), codes::POLICY_TAMPERED);
        assert_eq!(
            error.message(),
            "verified policy evidence schema version is newer than this gateway"
        );
        // Versions 0 and 1 stay consumable through the frozen seam.
        for verdict in [verdict_with_schema_version(0), VerifiedPolicy::unbound()] {
            assert!(
                consume_frozen_policy(Some(&verdict), &snapshot)
                    .expect("known evidence versions are consumable")
                    .is_none()
            );
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

    // --- check/use consumption (P4.1) ---

    fn concrete_destination(bucket: &str) -> maskura_pipeline_config::ResolvedDestination {
        maskura_pipeline_config::ResolvedDestination {
            mode: maskura_pipeline_config::StorageMode::S3Compatible,
            endpoint: "https://s3.example.com".into(),
            bucket: bucket.into(),
            region: "region-1".into(),
            role_arn: None,
            configuration_version_id: Some("cfg-1".into()),
            configuration_sha256: "c".repeat(64),
        }
    }

    fn concrete_binding(bucket: &str) -> DestinationBinding {
        DestinationBinding::Concrete {
            destination: concrete_destination(bucket),
        }
    }

    fn concrete_snapshot(bucket_template: &str) -> DestinationSelectionSnapshot {
        DestinationSelectionSnapshot {
            binding: concrete_binding(bucket_template),
            selected_primary_backend_id: None,
            selected_replica_backend_id: None,
        }
    }

    fn policy_binding(
        destination: DestinationBinding,
        managed_placement: Option<(String, Option<String>)>,
    ) -> PolicyBinding {
        PolicyBinding {
            workspace_id: "ws-test".into(),
            operation: PolicyOperation::Put,
            route_prefix: String::new(),
            envelope_digest: "e".repeat(64),
            envelope_version: 1,
            effective_state_digest: "d".repeat(64),
            receipt_seq: 1,
            receipt_body_digest: "b".repeat(64),
            authorization_epoch: 1,
            destination,
            managed_placement,
            limits: PolicyLimits {
                record_max_bytes: 1024,
                object_max_bytes: 4096,
                memory_bytes: 67_108_864,
                fuel: 10_000_000,
                deadline_ms: 30_000,
            },
        }
    }

    fn managed_backend(id: &str) -> maskura_pipeline_config::ManagedBackend {
        maskura_pipeline_config::ManagedBackend {
            backend_id: id.into(),
            provider_kind: "b2".into(),
            provider_instance_id: String::new(),
            provider_account_id: String::new(),
            endpoint: "https://s3.example.com".into(),
            region: "region-1".into(),
            bucket: "physical".into(),
            placement_weight: 1,
            placement_capacity_units: 1,
            credential_epoch: 1,
            configuration_sha256: "a".repeat(64),
        }
    }

    fn managed_binding(
        backends: Vec<maskura_pipeline_config::ManagedBackend>,
    ) -> DestinationBinding {
        DestinationBinding::ManagedTopology {
            placement_version: 1,
            algorithm: maskura_pipeline_config::ManagedPlacementAlgorithm::WeightedRendezvous,
            authority_sha256: "f".repeat(64),
            backends,
        }
    }

    #[tokio::test]
    async fn consume_policy_unbound_is_inert() {
        let snapshot = concrete_snapshot("");
        let verdict = VerifiedPolicy::unbound();
        assert!(
            consume_policy(&verdict, &snapshot)
                .expect("unbound is inert")
                .is_none()
        );
    }

    #[tokio::test]
    async fn consume_policy_matches_across_the_bucket_template() {
        // Approved carries the signed logical bucket; the request-time snapshot
        // uses the empty identity template. Identity fields match, so this must
        // pass — the bucket is checked separately against the route.
        let snapshot = concrete_snapshot("");
        let verdict = VerifiedPolicy {
            schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
            binding: Some(policy_binding(concrete_binding("my-bucket"), None)),
        };
        let binding = consume_policy(&verdict, &snapshot)
            .expect("identity matches despite the bucket template")
            .expect("bound");
        assert_eq!(binding.route_prefix, "");
    }

    #[tokio::test]
    async fn consume_policy_rejects_endpoint_drift() {
        let snapshot = concrete_snapshot("");
        let mut binding = policy_binding(concrete_binding("my-bucket"), None);
        if let DestinationBinding::Concrete { destination } = &mut binding.destination {
            destination.endpoint = "https://evil.example.com".into();
        }
        let verdict = VerifiedPolicy {
            schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
            binding: Some(binding),
        };
        let error = consume_policy(&verdict, &snapshot).expect_err("endpoint drift is denied");
        assert_eq!(error.code(), codes::POLICY_DENIED);
    }

    #[tokio::test]
    async fn consume_policy_rejects_configuration_digest_drift() {
        let snapshot = concrete_snapshot("");
        let mut binding = policy_binding(concrete_binding("my-bucket"), None);
        if let DestinationBinding::Concrete { destination } = &mut binding.destination {
            destination.configuration_sha256 = "0".repeat(64);
        }
        let verdict = VerifiedPolicy {
            schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
            binding: Some(binding),
        };
        let error = consume_policy(&verdict, &snapshot).expect_err("digest drift is denied");
        assert_eq!(error.code(), codes::POLICY_DENIED);
    }

    #[tokio::test]
    async fn consume_policy_managed_topology_matches_when_unchanged() {
        let snapshot = DestinationSelectionSnapshot {
            binding: managed_binding(vec![managed_backend("b1"), managed_backend("b2")]),
            selected_primary_backend_id: Some("b1".into()),
            selected_replica_backend_id: Some("b2".into()),
        };
        let verdict = VerifiedPolicy {
            schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
            binding: Some(policy_binding(
                managed_binding(vec![managed_backend("b1"), managed_backend("b2")]),
                Some(("b1".into(), Some("b2".into()))),
            )),
        };
        let binding = consume_policy(&verdict, &snapshot)
            .expect("unchanged ring matches")
            .expect("bound");
        assert_eq!(
            binding.managed_placement,
            Some(("b1".into(), Some("b2".into())))
        );
    }

    #[tokio::test]
    async fn consume_policy_rejects_managed_ring_drift() {
        // A backend was added to the live ring after approval: the topology
        // digest no longer matches and must be denied (re-approval required).
        let snapshot = DestinationSelectionSnapshot {
            binding: managed_binding(vec![managed_backend("b1"), managed_backend("b2")]),
            selected_primary_backend_id: Some("b1".into()),
            selected_replica_backend_id: None,
        };
        let verdict = VerifiedPolicy {
            schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
            binding: Some(policy_binding(
                managed_binding(vec![managed_backend("b1")]),
                Some(("b1".into(), None)),
            )),
        };
        let error = consume_policy(&verdict, &snapshot).expect_err("ring drift is denied");
        assert_eq!(error.code(), codes::POLICY_DENIED);
    }

    #[tokio::test]
    async fn consume_policy_rejects_managed_placement_drift() {
        // The frozen per-key targets differ from what execution would select.
        let snapshot = DestinationSelectionSnapshot {
            binding: managed_binding(vec![managed_backend("b1")]),
            selected_primary_backend_id: Some("b1".into()),
            selected_replica_backend_id: None,
        };
        let verdict = VerifiedPolicy {
            schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
            binding: Some(policy_binding(
                managed_binding(vec![managed_backend("b1")]),
                None,
            )),
        };
        let error = consume_policy(&verdict, &snapshot).expect_err("placement drift is denied");
        assert_eq!(error.code(), codes::POLICY_DENIED);
    }

    #[test]
    fn binding_matches_selection_is_false_across_kinds() {
        // Concrete vs managed are never interchangeable.
        let binding = policy_binding(concrete_binding("my-bucket"), None);
        let snapshot = DestinationSelectionSnapshot {
            binding: managed_binding(vec![managed_backend("b1")]),
            selected_primary_backend_id: None,
            selected_replica_backend_id: None,
        };
        assert!(!binding_matches_selection(&binding, &snapshot));
    }

    #[test]
    fn policy_session_limits_tightens_only_policy_fields() {
        let policy = PolicyLimits {
            record_max_bytes: 1024,
            object_max_bytes: 4096,
            memory_bytes: 67_108_864,
            fuel: 10_000_000,
            deadline_ms: 30_000,
        };
        let limits = policy_session_limits(&policy);
        // Policy-governed fields map through.
        assert_eq!(limits.max_intermediate_record_bytes, 1024);
        assert_eq!(limits.max_input_bytes, 4096);
        assert_eq!(limits.max_cumulative_fuel, 10_000_000);
        assert_eq!(
            limits.max_wall_time,
            std::time::Duration::from_millis(30_000)
        );
        // Non-policy fields are the "no extra constraint" sentinel (min is a
        // no-op against the operator snapshot).
        assert_eq!(limits.max_plugin_finish_bytes, usize::MAX);
        assert_eq!(limits.max_output_bytes, u64::MAX);
        assert_eq!(limits.max_expansion_factor, u64::MAX);
        assert_eq!(limits.max_plugins, usize::MAX);
    }

    // --- frozen multipart verdict consumption + limit composition (P4.1h) ---

    fn limits(
        record_max_bytes: u64,
        object_max_bytes: u64,
        memory_bytes: u64,
        fuel: u64,
        deadline_ms: u64,
    ) -> PolicyLimits {
        PolicyLimits {
            record_max_bytes,
            object_max_bytes,
            memory_bytes,
            fuel,
            deadline_ms,
        }
    }

    #[test]
    fn consume_frozen_policy_none_is_inert() {
        // The upload predates verdict freezing (or carries no gate evidence):
        // nothing to re-check, so today's behavior is preserved.
        let snapshot = concrete_snapshot("");
        assert!(
            consume_frozen_policy(None, &snapshot)
                .expect("no frozen verdict is inert")
                .is_none()
        );
    }

    #[test]
    fn consume_frozen_policy_unbound_verdict_is_inert() {
        let snapshot = concrete_snapshot("");
        let verdict = VerifiedPolicy::unbound();
        assert!(
            consume_frozen_policy(Some(&verdict), &snapshot)
                .expect("unbound frozen verdict is inert")
                .is_none()
        );
    }

    #[test]
    fn consume_frozen_policy_delegates_to_consume_policy() {
        // A frozen bound verdict whose destination still matches the fresh
        // selection hands back exactly the binding consume_policy returns.
        let snapshot = concrete_snapshot("");
        let verdict = VerifiedPolicy {
            schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
            binding: Some(policy_binding(concrete_binding("my-bucket"), None)),
        };
        let frozen = consume_frozen_policy(Some(&verdict), &snapshot)
            .expect("frozen verdict matching the fresh selection is consumed")
            .expect("bound");
        let direct = consume_policy(&verdict, &snapshot)
            .expect("consume_policy accepts the same verdict")
            .expect("bound");
        assert_eq!(frozen, direct);
        assert_eq!(frozen.destination, direct.destination);
        assert_eq!(frozen.managed_placement, direct.managed_placement);
        assert_eq!(frozen.limits, direct.limits);
    }

    #[test]
    fn consume_frozen_policy_rejects_drift() {
        // The backend the later operation resolved is not the destination the
        // create-time verdict admitted: a state/bounds mismatch (spec §10).
        let snapshot = concrete_snapshot("");
        let mut binding = policy_binding(concrete_binding("my-bucket"), None);
        if let DestinationBinding::Concrete { destination } = &mut binding.destination {
            destination.endpoint = "https://evil.example.com".into();
        }
        let verdict = VerifiedPolicy {
            schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
            binding: Some(binding),
        };
        let error =
            consume_frozen_policy(Some(&verdict), &snapshot).expect_err("frozen drift is denied");
        assert_eq!(error.code(), codes::POLICY_DENIED);
    }

    #[test]
    fn consume_frozen_policy_rejects_managed_placement_drift() {
        // The frozen per-key placement targets differ from what the later
        // operation would select on the fresh resolution.
        let snapshot = DestinationSelectionSnapshot {
            binding: managed_binding(vec![managed_backend("b1")]),
            selected_primary_backend_id: Some("b1".into()),
            selected_replica_backend_id: None,
        };
        let verdict = VerifiedPolicy {
            schema_version: VERIFIED_POLICY_SCHEMA_VERSION,
            binding: Some(policy_binding(
                managed_binding(vec![managed_backend("b1")]),
                None,
            )),
        };
        let error = consume_frozen_policy(Some(&verdict), &snapshot)
            .expect_err("frozen placement drift is denied");
        assert_eq!(error.code(), codes::POLICY_DENIED);
    }

    #[test]
    fn min_policy_limits_picks_the_smallest_per_field() {
        // Each side is smaller on different fields; the result must take every
        // field from whichever input is smaller — never the larger one.
        let a = limits(1024, 8192, 33_554_432, 9_000_000, 60_000);
        let b = limits(2048, 4096, 67_108_864, 5_000_000, 30_000);
        let min = min_policy_limits(&a, &b);
        assert_eq!(min.record_max_bytes, 1024); // a
        assert_eq!(min.object_max_bytes, 4096); // b
        assert_eq!(min.memory_bytes, 33_554_432); // a
        assert_eq!(min.fuel, 5_000_000); // b
        assert_eq!(min.deadline_ms, 30_000); // b
    }

    #[test]
    fn min_policy_limits_is_componentwise_minimum() {
        let a = limits(1024, 8192, 33_554_432, 9_000_000, 60_000);
        let b = limits(2048, 4096, 67_108_864, 5_000_000, 30_000);
        let min = min_policy_limits(&a, &b);
        assert!(min.record_max_bytes <= a.record_max_bytes);
        assert!(min.record_max_bytes <= b.record_max_bytes);
        assert!(min.object_max_bytes <= a.object_max_bytes);
        assert!(min.object_max_bytes <= b.object_max_bytes);
        assert!(min.memory_bytes <= a.memory_bytes);
        assert!(min.memory_bytes <= b.memory_bytes);
        assert!(min.fuel <= a.fuel);
        assert!(min.fuel <= b.fuel);
        assert!(min.deadline_ms <= a.deadline_ms);
        assert!(min.deadline_ms <= b.deadline_ms);
    }

    #[test]
    fn min_policy_limits_is_commutative_and_idempotent() {
        let a = limits(1024, 8192, 33_554_432, 9_000_000, 60_000);
        let b = limits(2048, 4096, 67_108_864, 5_000_000, 30_000);
        assert_eq!(min_policy_limits(&a, &b), min_policy_limits(&b, &a));
        assert_eq!(min_policy_limits(&a, &a), a);
        assert_eq!(min_policy_limits(&b, &b), b);
    }

    #[test]
    fn min_policy_limits_composes_with_policy_session_limits() {
        // The wasm session built from the composed minimum never exceeds the
        // session either input alone would authorize, on any policy-governed
        // field. (`memory_bytes` is a wasm engine bound and is not mapped into
        // the session, so it has no session field to compare.)
        let a = limits(1024, 8192, 33_554_432, 9_000_000, 60_000);
        let b = limits(2048, 4096, 67_108_864, 5_000_000, 30_000);
        let composed = policy_session_limits(&min_policy_limits(&a, &b));
        for side in [policy_session_limits(&a), policy_session_limits(&b)] {
            assert!(composed.max_intermediate_record_bytes <= side.max_intermediate_record_bytes);
            assert!(composed.max_input_bytes <= side.max_input_bytes);
            assert!(composed.max_cumulative_fuel <= side.max_cumulative_fuel);
            assert!(composed.max_wall_time <= side.max_wall_time);
        }
    }
}
