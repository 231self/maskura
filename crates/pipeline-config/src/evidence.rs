//! EvidenceBundle v1 — the customer export artifact (Slice 4 spec §2).
//!
//! Packaging only: every cryptographic type inside the container already
//! exists in this crate ([`SignedReceipt`], [`Checkpoint`], [`WebAuthnProof`]).
//! The signatures cover the canonical-CBOR bodies (the sorted-JSON-keys
//! convention in [`crate::canonical`] — explicitly not RFC 8949 canonical
//! CBOR); this module only defines the JSON presentation and its fail-closed
//! parsing rules. Readers reject unknown `schema_version` values and unknown
//! fields outright.

use serde::{Deserialize, Serialize};

use crate::canonical::is_hex64;
use crate::error::ConfigError;
use crate::receipt::SignedReceipt;
use crate::trust::Checkpoint;
use crate::webauthn::WebAuthnProof;

/// EvidenceBundle container schema version. Unknown versions fail closed.
pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// Bounded `chain_tail` on `kind: "evidence"` bundles.
pub const MAX_CHAIN_TAIL: usize = 64;
/// Bounded `receipts` on `kind: "chain"` bundles.
pub const MAX_CHAIN_RECEIPTS: usize = 4_096;
/// Bounded `checkpoints` on `kind: "chain"` bundles.
pub const MAX_CHAIN_CHECKPOINTS: usize = 4_096;
/// Bounded retained witness acknowledgement records.
pub const MAX_WITNESS_RECORDS: usize = 64;
/// Bounded whole-artifact input.
pub const MAX_EVIDENCE_JSON_LEN: usize = 16 * 1024 * 1024;

/// The approval proof retained for offline verification (R6): the exact
/// assertion bytes plus the COSE algorithm association of the approving key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEvidence {
    /// The exact retained assertion. `proof.signature` carries the ASN.1 DER
    /// ES256 signature (base64url-no-pad); `client_data_json`,
    /// `authenticator_data`, and `credential_id` are retained verbatim so a
    /// verifier can re-derive `authenticatorData || SHA256(clientDataJSON)`
    /// and the challenge-to-receipt-digest binding without any server state.
    pub proof: WebAuthnProof,
    /// COSE algorithm identifier associated with the approving key;
    /// must be `-7` (ES256) in v1.
    pub cose_alg: i32,
}

/// A reserved external-witness acknowledgement record (spec §6 seam). These
/// records parse and are reported, but the witness program is gated: absence
/// is never blocking and presence is never witness verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessAcknowledgement {
    pub witness_id: String,
    pub acknowledged_at: u64,
    /// 64 lowercase hex: the receipt digest the witness acknowledged.
    pub receipt_sha256: String,
    /// Detached witness signature bytes (base64url-no-pad). Parsed only.
    pub signature: String,
}

/// `kind: "evidence"` — one landed publish approval export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifact {
    pub schema_version: u32,
    pub workspace_id: String,
    /// 64 lowercase hex SHA-256: the trust-root fingerprint this lineage is
    /// anchored to (equal to the post-publish checkpoint's
    /// `initial_bundle_sha256`).
    pub trust_root_fingerprint: String,
    /// The landed receipt (ReceiptBody v2/v3 in its canonical-CBOR-signed form).
    pub receipt: SignedReceipt,
    /// The post-publish Checkpoint v2.
    pub checkpoint: Checkpoint,
    /// The approval proof plus retained verification material (R6).
    pub approval: ApprovalEvidence,
    /// Optional bounded preceding receipts for context. Must form a
    /// contiguous run immediately before `receipt`; readers accept any
    /// presentation order but require exact sequence contiguity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain_tail: Vec<SignedReceipt>,
    /// Optional witness acknowledgement records (spec §6 seam).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness: Vec<WitnessAcknowledgement>,
}

/// `kind: "chain"` — a full receipt-chain export for whole-history
/// verification, as produced by the trust/receipt endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainArtifact {
    pub schema_version: u32,
    pub workspace_id: String,
    /// 64 lowercase hex SHA-256: the trust-root fingerprint of this lineage.
    pub trust_root_fingerprint: String,
    pub receipts: Vec<SignedReceipt>,
    pub checkpoints: Vec<Checkpoint>,
    /// Optional witness acknowledgement records (spec §6 seam).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness: Vec<WitnessAcknowledgement>,
}

/// The EvidenceBundle v1 container. JSON presentation with an explicit
/// `kind` tag and `schema_version`; both fail closed on unknown values.
// The variants hold whole JSON artifacts: sized by bounded parsing, not by
// stack traffic (the enum is built once per artifact).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceBundle {
    Evidence(EvidenceArtifact),
    Chain(ChainArtifact),
}

/// Which container form an artifact uses (also used in reports).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Evidence,
    Chain,
}

impl EvidenceBundle {
    pub fn kind(&self) -> EvidenceKind {
        match self {
            Self::Evidence(_) => EvidenceKind::Evidence,
            Self::Chain(_) => EvidenceKind::Chain,
        }
    }

    pub fn workspace_id(&self) -> &str {
        match self {
            Self::Evidence(artifact) => &artifact.workspace_id,
            Self::Chain(artifact) => &artifact.workspace_id,
        }
    }

    pub fn trust_root_fingerprint(&self) -> &str {
        match self {
            Self::Evidence(artifact) => &artifact.trust_root_fingerprint,
            Self::Chain(artifact) => &artifact.trust_root_fingerprint,
        }
    }

    /// The segment of receipts this artifact presents, ascending by `seq`.
    pub fn receipts(&self) -> Vec<&SignedReceipt> {
        match self {
            Self::Evidence(artifact) => {
                let mut receipts: Vec<&SignedReceipt> = artifact.chain_tail.iter().collect();
                receipts.push(&artifact.receipt);
                receipts
            }
            Self::Chain(artifact) => artifact.receipts.iter().collect(),
        }
    }

    /// Serialize to the JSON presentation.
    pub fn to_json(&self) -> Result<String, ConfigError> {
        serde_json::to_string_pretty(self)
            .map_err(|error| ConfigError::invalid(format!("cannot encode evidence: {error}")))
    }

    /// Parse the JSON presentation with fail-closed rules: unknown
    /// `schema_version`, unknown `kind`, and unknown fields are rejected.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        if json.len() > MAX_EVIDENCE_JSON_LEN {
            return Err(ConfigError::invalid(format!(
                "evidence exceeds size limit of {MAX_EVIDENCE_JSON_LEN} bytes"
            )));
        }
        let value: serde_json::Value = serde_json::from_str(json).map_err(|error| {
            ConfigError::invalid(format!("evidence is not valid JSON: {error}"))
        })?;
        let object = value
            .as_object()
            .ok_or_else(|| ConfigError::invalid("evidence must be a JSON object"))?;
        match object.get("schema_version") {
            Some(serde_json::Value::Number(version))
                if version.as_u64() == Some(u64::from(EVIDENCE_SCHEMA_VERSION)) => {}
            Some(serde_json::Value::Number(version)) => {
                return Err(ConfigError::invalid(format!(
                    "unsupported evidence schema_version {}; expected {EVIDENCE_SCHEMA_VERSION}",
                    version
                )));
            }
            Some(_) => {
                return Err(ConfigError::invalid(
                    "evidence schema_version must be an integer",
                ));
            }
            None => {
                return Err(ConfigError::invalid(
                    "evidence must declare schema_version explicitly",
                ));
            }
        }
        let kind = object
            .get("kind")
            .and_then(|kind| kind.as_str())
            .ok_or_else(|| ConfigError::invalid("evidence must carry kind"))?;
        // Deserialize the tagged variant payload directly: the `kind` tag is
        // consumed here and every remaining field goes through the variant's
        // `deny_unknown_fields` struct, so unknown fields always fail closed.
        let mut payload = object.clone();
        payload.remove("kind");
        let payload = serde_json::Value::Object(payload);
        let bundle = match kind {
            "evidence" => Self::Evidence(deserialize_payload::<EvidenceArtifact>(payload, kind)?),
            "chain" => Self::Chain(deserialize_payload::<ChainArtifact>(payload, kind)?),
            other => {
                return Err(ConfigError::invalid(format!(
                    "unknown evidence kind {other:?}; expected \"evidence\" or \"chain\""
                )));
            }
        };
        bundle.validate()?;
        Ok(bundle)
    }

    /// Structural validation of the container (shape, bounds, versioned
    /// sub-forms). Digest and signature checks live in [`crate::verify`].
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Evidence(artifact) => {
                if artifact.schema_version != EVIDENCE_SCHEMA_VERSION {
                    return Err(ConfigError::invalid(format!(
                        "unsupported evidence schema_version {}; expected {EVIDENCE_SCHEMA_VERSION}",
                        artifact.schema_version
                    )));
                }
                require_scope(&artifact.workspace_id, &artifact.trust_root_fingerprint)?;
                artifact.checkpoint.validate()?;
                if artifact.chain_tail.len() > MAX_CHAIN_TAIL {
                    return Err(ConfigError::invalid(format!(
                        "evidence chain_tail exceeds {MAX_CHAIN_TAIL} receipts"
                    )));
                }
                if artifact.approval.cose_alg != -7 {
                    return Err(ConfigError::invalid(format!(
                        "approval evidence cose_alg {} must be -7 (ES256)",
                        artifact.approval.cose_alg
                    )));
                }
                if artifact.witness.len() > MAX_WITNESS_RECORDS {
                    return Err(ConfigError::invalid(format!(
                        "evidence witness records exceed {MAX_WITNESS_RECORDS}"
                    )));
                }
                for record in &artifact.witness {
                    validate_witness(record)?;
                }
            }
            Self::Chain(artifact) => {
                if artifact.schema_version != EVIDENCE_SCHEMA_VERSION {
                    return Err(ConfigError::invalid(format!(
                        "unsupported evidence schema_version {}; expected {EVIDENCE_SCHEMA_VERSION}",
                        artifact.schema_version
                    )));
                }
                require_scope(&artifact.workspace_id, &artifact.trust_root_fingerprint)?;
                if artifact.receipts.is_empty() || artifact.receipts.len() > MAX_CHAIN_RECEIPTS {
                    return Err(ConfigError::invalid(format!(
                        "chain export must carry 1..={MAX_CHAIN_RECEIPTS} receipts"
                    )));
                }
                if artifact.checkpoints.len() > MAX_CHAIN_CHECKPOINTS {
                    return Err(ConfigError::invalid(format!(
                        "chain export checkpoints exceed {MAX_CHAIN_CHECKPOINTS}"
                    )));
                }
                for checkpoint in &artifact.checkpoints {
                    checkpoint.validate()?;
                }
                if artifact.witness.len() > MAX_WITNESS_RECORDS {
                    return Err(ConfigError::invalid(format!(
                        "evidence witness records exceed {MAX_WITNESS_RECORDS}"
                    )));
                }
                for record in &artifact.witness {
                    validate_witness(record)?;
                }
            }
        }
        Ok(())
    }
}

fn deserialize_payload<T: serde::de::DeserializeOwned>(
    payload: serde_json::Value,
    kind: &str,
) -> Result<T, ConfigError> {
    serde_json::from_value(payload).map_err(|error| {
        let detail = error.to_string();
        if detail.contains("unknown field") {
            ConfigError::invalid(format!(
                "evidence kind {kind:?} rejects unknown fields: {detail}"
            ))
        } else {
            ConfigError::invalid(format!("evidence kind {kind:?} is malformed: {detail}"))
        }
    })
}

fn require_scope(workspace_id: &str, trust_root_fingerprint: &str) -> Result<(), ConfigError> {
    if workspace_id.trim().is_empty() {
        return Err(ConfigError::invalid(
            "evidence workspace_id must not be empty",
        ));
    }
    if !is_hex64(trust_root_fingerprint) {
        return Err(ConfigError::invalid(
            "evidence trust_root_fingerprint must be 64 lowercase hex",
        ));
    }
    Ok(())
}

fn validate_witness(record: &WitnessAcknowledgement) -> Result<(), ConfigError> {
    if record.witness_id.trim().is_empty() {
        return Err(ConfigError::invalid(
            "witness acknowledgement witness_id must not be empty",
        ));
    }
    if !is_hex64(&record.receipt_sha256) {
        return Err(ConfigError::invalid(
            "witness acknowledgement receipt_sha256 must be 64 lowercase hex",
        ));
    }
    if record.signature.len() > 16_384 {
        return Err(ConfigError::invalid(
            "witness acknowledgement signature exceeds size limit",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "evidence_tests.rs"]
mod tests;
