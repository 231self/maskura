//! Verification facade (Slice 4 spec §3/§4).
//!
//! One entry point, [`verify_artifact`], implements the customer-side
//! verification pipeline over an [`EvidenceBundle`]: container/schema gate →
//! canonical-CBOR digest re-derivation → receipt body validation → chain
//! links → approval-proof verification against the locally pinned trust root →
//! signer transitions (trust resets rendered as discontinuities) → checkpoint
//! extension/freshness versus customer-retained checkpoints → validity at an
//! evaluated instant. Every step is fail-closed and emits a stable typed
//! finding.
//!
//! No new cryptography lives here: this module composes the existing
//! verifiers ([`crate::receipt`], [`crate::trust`], [`crate::webauthn`]).

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::canonical::{digest_of, is_hex64};
use crate::error::ConfigError;
use crate::evidence::{
    ApprovalEvidence, ChainArtifact, EvidenceArtifact, EvidenceBundle, EvidenceKind,
    WitnessAcknowledgement,
};
use crate::receipt::{
    ChainReport, GENESIS_PREV, ReceiptAction, SignedReceipt, verify_receipt, verify_receipt_chain,
    verify_receipt_suffix,
};
use crate::trust::{Checkpoint, TrustBundle};
use crate::webauthn::WebAuthnProof;

/// Stable report schema version. Readers fail closed on newer versions.
pub const VERIFICATION_REPORT_SCHEMA_VERSION: u32 = 1;

/// Clock-skew convention for evaluating "now" and historical instants (±60s),
/// matching the `policy.expired` boundary convention.
pub const CLOCK_SKEW_SECONDS: u64 = 60;

/// Witness status while the external witness program (A3) is gated.
pub const WITNESS_STATUS: &str = "not-witness-verified";

/// The complete reason reported when nothing links the artifact to customer-
/// retained history. Normative wording (spec §3).
pub const NO_PRIOR_CHECKPOINT: &str = "no prior checkpoint";

/// Evaluation options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerifyOptions {
    /// Unix seconds at which to evaluate validity. `None` = now.
    pub at: Option<u64>,
}

/// A locally established trust-root pin. Only customer-controlled input may
/// create one (an imported customer artifact or `policy trust add`); a
/// server-fetched bundle can never establish a pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPin {
    pub workspace_id: String,
    /// 64 lowercase hex: the pinned trust-root fingerprint.
    pub root_fingerprint: String,
    /// The imported COSE trust-bundle snapshot. When this snapshot is the
    /// genesis root (its digest equals `root_fingerprint`), full-chain
    /// verification from the pinned root is possible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<TrustBundle>,
}

/// Customer-side trust state for verification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustState {
    /// The local pin for the artifact's workspace, if one has been
    /// established. Unpinned verification is refused (spec §3 step 5).
    pub pin: Option<TrustPin>,
    /// Customer-retained checkpoints (the append-only local store), any
    /// workspace; verification filters to the artifact's lineage.
    pub retained: Vec<Checkpoint>,
}

/// Pipeline step names (stable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStep {
    Container,
    Digest,
    Receipt,
    Chain,
    Approval,
    SignerTransition,
    Checkpoint,
    Validity,
    Witness,
}

/// Stable typed finding codes (stable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCode {
    // container
    ParseError,
    SchemaRejected,
    KindRejected,
    UnknownField,
    BoundsExceeded,
    // digest / receipt
    DigestMismatch,
    ReceiptInvalid,
    // chain
    ChainInvalid,
    GenesisInvalid,
    // approval
    UnpinnedRoot,
    ApprovalInvalid,
    ApprovalMismatch,
    // signer transitions
    TransitionInvalid,
    Discontinuity,
    DiscontinuityNewRootNotAccepted,
    // checkpoint consistency
    FirstRun,
    ExtendedOk,
    Gap,
    RollbackSuspect,
    // validity
    Valid,
    NotYetValid,
    Expired,
    // witness
    NotWitnessVerified,
}

/// One typed finding. Verdict is `failed` if and only if any finding is fatal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub step: VerificationStep,
    pub code: FindingCode,
    pub fatal: bool,
    pub message: String,
}

impl Finding {
    fn info(step: VerificationStep, code: FindingCode, message: impl Into<String>) -> Self {
        Self {
            step,
            code,
            fatal: false,
            message: message.into(),
        }
    }

    fn fatal(step: VerificationStep, code: FindingCode, message: impl Into<String>) -> Self {
        Self {
            step,
            code,
            fatal: true,
            message: message.into(),
        }
    }
}

/// The verdict of the checks the pipeline ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every check passed. Read together with `completeness`: a `verified`
    /// verdict with `UNVERIFIED` completeness is self-consistent evidence
    /// that is not yet linked to customer-retained history.
    Verified,
    /// Verification failed or was refused.
    Failed,
}

/// Completeness honesty (normative, spec §3): never claim a complete history
/// without customer-retained checkpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Completeness {
    /// Nothing links the artifact to customer-retained history.
    Unverified { reason: String },
    /// The verified range was compared against retained history.
    Compared {
        from_seq: u64,
        to_seq: u64,
        retained_head_seq: u64,
    },
}

impl std::fmt::Display for Completeness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unverified { reason } => write!(f, "UNVERIFIED ({reason})"),
            Self::Compared {
                from_seq,
                to_seq,
                retained_head_seq,
            } => write!(
                f,
                "COMPARED (seq {from_seq}..={to_seq} against retained head {retained_head_seq})"
            ),
        }
    }
}

/// Witness status. While the external witness program (A3) is gated this is
/// always `not-witness-verified`; acknowledgement records parse but never
/// change it and absence is never blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessStatus {
    #[serde(rename = "not-witness-verified")]
    NotWitnessVerified,
}

/// Summary of the verified artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<EvidenceKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_receipt_sha256: Option<String>,
}

/// The stable, versioned verification report (spec §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReport {
    pub schema_version: u32,
    pub artifact: ArtifactSummary,
    /// The instant validity was evaluated at (`--at` or now).
    pub evaluated_at: u64,
    pub clock_skew_seconds: u64,
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    pub completeness: Completeness,
    pub witness: WitnessStatus,
}

impl VerificationReport {
    pub fn ok(&self) -> bool {
        self.verdict == Verdict::Verified
    }

    /// The checkpoint-consistency status from the findings, when reported.
    pub fn checkpoint_status(&self) -> Option<FindingCode> {
        self.findings
            .iter()
            .find(|finding| finding.step == VerificationStep::Checkpoint)
            .map(|finding| finding.code)
    }

    pub fn to_json(&self) -> Result<String, ConfigError> {
        serde_json::to_string_pretty(self)
            .map_err(|error| ConfigError::invalid(format!("cannot encode report: {error}")))
    }
}

struct Builder {
    evaluated_at: u64,
    findings: Vec<Finding>,
    fatal: bool,
    summary: ArtifactSummary,
    completeness: Completeness,
}

impl Builder {
    fn new(evaluated_at: u64) -> Self {
        Self {
            evaluated_at,
            findings: Vec::new(),
            fatal: false,
            summary: ArtifactSummary {
                kind: None,
                workspace_id: None,
                head_seq: None,
                head_receipt_sha256: None,
            },
            completeness: Completeness::Unverified {
                reason: NO_PRIOR_CHECKPOINT.to_string(),
            },
        }
    }

    fn push(&mut self, finding: Finding) {
        self.fatal |= finding.fatal;
        self.findings.push(finding);
    }

    fn info(&mut self, step: VerificationStep, code: FindingCode, message: impl Into<String>) {
        self.push(Finding::info(step, code, message));
    }

    fn fail(&mut self, step: VerificationStep, code: FindingCode, message: impl Into<String>) {
        self.push(Finding::fatal(step, code, message));
    }

    fn finish(self) -> VerificationReport {
        VerificationReport {
            schema_version: VERIFICATION_REPORT_SCHEMA_VERSION,
            artifact: self.summary,
            evaluated_at: self.evaluated_at,
            clock_skew_seconds: CLOCK_SKEW_SECONDS,
            verdict: if self.fatal {
                Verdict::Failed
            } else {
                Verdict::Verified
            },
            findings: self.findings,
            completeness: self.completeness,
            witness: WitnessStatus::NotWitnessVerified,
        }
    }
}

/// How the verified segment connects to the customer's trust state. Used to
/// render checkpoint-consistency status and completeness honestly.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Linkage {
    /// Full chain verified from the pinned genesis root bundle bytes.
    PinnedGenesis,
    /// Anchored on a customer-retained checkpoint at `at_seq`.
    Retained { at_seq: u64 },
    /// The head digest equals a customer-retained checkpoint (known history).
    Reconfirmed { at_seq: u64 },
    /// Nothing links the artifact to retained history; only self-consistency
    /// and the approval proof against the artifact-carried authority were
    /// checked (the bootstrap import case).
    SelfContained,
}

/// Run the complete verification pipeline over one artifact.
///
/// `trust_state` supplies the local pin (unpinned verification is refused)
/// and the customer-retained checkpoints. `opts.at` evaluates historical
/// validity at that instant; the default is now, with the ±60s skew
/// convention.
pub fn verify_artifact(
    input: &str,
    trust_state: &TrustState,
    opts: &VerifyOptions,
) -> VerificationReport {
    let evaluated_at = opts.at.unwrap_or_else(now_secs);
    let mut builder = Builder::new(evaluated_at);

    // Step 1: container parse + schema_version/kind gate (fail closed).
    let bundle = match EvidenceBundle::from_json(input) {
        Ok(bundle) => bundle,
        Err(error) => {
            let detail = error.to_string();
            let code = if detail.contains("unknown fields") {
                FindingCode::UnknownField
            } else if detail.contains("schema_version")
                || detail.contains("cose_alg")
                || detail.contains("ES256")
            {
                FindingCode::SchemaRejected
            } else if detail.contains("unknown evidence kind") || detail.contains("must carry kind")
            {
                FindingCode::KindRejected
            } else if detail.contains("size limit") || detail.contains("exceeds") {
                FindingCode::BoundsExceeded
            } else {
                FindingCode::ParseError
            };
            builder.fail(
                VerificationStep::Container,
                code,
                format!("container rejected: {detail}"),
            );
            return builder.finish();
        }
    };
    builder.summary.kind = Some(bundle.kind());
    builder.summary.workspace_id = Some(bundle.workspace_id().to_string());

    // Step 2: canonical-CBOR digest re-derivation over the signed bodies.
    let receipts = bundle.receipts();
    let mut seq_digest: BTreeMap<u64, String> = BTreeMap::new();
    let mut digest_failed = false;
    for receipt in &receipts {
        match digest_of(&receipt.body) {
            Ok(digest) => {
                seq_digest.insert(receipt.body.seq, digest);
            }
            Err(error) => {
                digest_failed = true;
                builder.fail(
                    VerificationStep::Digest,
                    FindingCode::DigestMismatch,
                    format!(
                        "canonical-CBOR digest re-derivation failed for seq {}: {error}",
                        receipt.body.seq
                    ),
                );
            }
        }
    }
    if digest_failed {
        return builder.finish();
    }

    // Step 3: receipt body validation (effective-state digest equality,
    // checked arithmetic, draft rejection — the receipt.rs invariants).
    for receipt in &receipts {
        if let Err(error) = receipt.body.validate() {
            builder.fail(
                VerificationStep::Receipt,
                FindingCode::ReceiptInvalid,
                format!("receipt body invalid at seq {}: {error}", receipt.body.seq),
            );
            return builder.finish();
        }
    }

    // Step 4: chain links (seq continuity, prev linkage, genesis shape,
    // container/checkpoint consistency).
    if seq_digest.len() != receipts.len() {
        builder.fail(
            VerificationStep::Chain,
            FindingCode::ChainInvalid,
            "artifact presents duplicate receipt sequences",
        );
        return builder.finish();
    }
    let mut segment: Vec<&SignedReceipt> = receipts.clone();
    segment.sort_by_key(|receipt| receipt.body.seq);
    for pair in 0..segment.len().saturating_sub(1) {
        let (current, next) = (segment[pair], segment[pair + 1]);
        let next_seq = current.body.seq.checked_add(1);
        let predecessor = seq_digest.get(&current.body.seq);
        if next_seq != Some(next.body.seq)
            || predecessor.map(String::as_str) != Some(next.body.prev_receipt_sha256.as_str())
        {
            builder.fail(
                VerificationStep::Chain,
                FindingCode::ChainInvalid,
                format!(
                    "chain link broken between seq {} and seq {} (sequence or predecessor mismatch)",
                    current.body.seq, next.body.seq
                ),
            );
            return builder.finish();
        }
    }
    let first = segment[0];
    let head = segment[segment.len() - 1];
    if first.body.seq == 1 && first.body.prev_receipt_sha256 != GENESIS_PREV {
        builder.fail(
            VerificationStep::Chain,
            FindingCode::GenesisInvalid,
            "genesis receipt must link to the all-zero predecessor digest",
        );
        return builder.finish();
    }
    let head_digest = seq_digest
        .get(&head.body.seq)
        .cloned()
        .expect("head digest derived in step 2");
    if let Err(error) = check_container_links(&bundle, &segment, &seq_digest) {
        builder.fail(
            VerificationStep::Chain,
            FindingCode::ChainInvalid,
            error.to_string(),
        );
        return builder.finish();
    }
    builder.summary.head_seq = Some(head.body.seq);
    builder.summary.head_receipt_sha256 = Some(head_digest.clone());

    // Step 5: approval-proof verification against the trust bundle matching
    // the local pin (unpinned → refuse).
    let Some(pin) = trust_state.pin.as_ref() else {
        builder.fail(
            VerificationStep::Approval,
            FindingCode::UnpinnedRoot,
            format!(
                "unpinned: no local trust root for workspace {:?}; approval verification refused \
                 (establish a pin with `maskura policy trust import` on your own artifact)",
                bundle.workspace_id()
            ),
        );
        return builder.finish();
    };
    if pin.workspace_id != bundle.workspace_id() {
        builder.fail(
            VerificationStep::Approval,
            FindingCode::UnpinnedRoot,
            format!(
                "unpinned: the local pin covers workspace {:?}, not {:?}",
                pin.workspace_id,
                bundle.workspace_id()
            ),
        );
        return builder.finish();
    }

    // Step 6 (first half): trust-reset discontinuity — a new root is verified
    // only after explicit acceptance. Never present continuity.
    if pin.root_fingerprint != bundle.trust_root_fingerprint() {
        builder.fail(
            VerificationStep::SignerTransition,
            FindingCode::DiscontinuityNewRootNotAccepted,
            format!(
                "discontinuity: new root not accepted (artifact root {} does not match pinned \
                 root {}; accept it explicitly with `maskura policy trust import --force` or \
                 `maskura policy trust add`)",
                short_fp(bundle.trust_root_fingerprint()),
                short_fp(&pin.root_fingerprint)
            ),
        );
        return builder.finish();
    }

    let retained: Vec<&Checkpoint> = trust_state
        .retained
        .iter()
        .filter(|checkpoint| {
            checkpoint.workspace_id == pin.workspace_id
                && checkpoint.initial_bundle_sha256 == pin.root_fingerprint
        })
        .collect();

    // Render recorded trust resets prominently as discontinuities before any
    // continuity claim (spec §3 step 6).
    let mut reset_sources: Vec<(String, &TrustBundle)> = Vec::new();
    if let Some(bundle_state) = pin.bundle.as_ref() {
        reset_sources.push(("pinned root".to_string(), bundle_state));
    }
    for checkpoint in &retained {
        reset_sources.push((
            format!("retained checkpoint {}", checkpoint.receipt_seq),
            &checkpoint.authorization,
        ));
    }
    match &bundle {
        EvidenceBundle::Evidence(artifact) => reset_sources.push((
            format!("checkpoint {}", artifact.checkpoint.receipt_seq),
            &artifact.checkpoint.authorization,
        )),
        EvidenceBundle::Chain(artifact) => {
            for checkpoint in &artifact.checkpoints {
                reset_sources.push((
                    format!("checkpoint {}", checkpoint.receipt_seq),
                    &checkpoint.authorization,
                ));
            }
        }
    }
    for (source, state) in reset_sources {
        for reset in &state.trust_resets {
            builder.info(
                VerificationStep::SignerTransition,
                FindingCode::Discontinuity,
                format!(
                    "discontinuity: trust reset recorded at epoch {} ({}); history is not \
                     continuous across a trust reset ({source})",
                    reset.epoch, reset.reason
                ),
            );
        }
    }

    // Select the starting authority and verify the segment.
    let genesis_root = pin.bundle.as_ref().filter(|root| {
        root.signer_epoch == 1
            && root.digest().ok().as_deref() == Some(pin.root_fingerprint.as_str())
    });
    let link_result = verify_segment(&segment, &seq_digest, pin, genesis_root, &retained, &bundle);
    let (report_head, linkage) = match link_result {
        Ok(outcome) => (outcome.head, outcome.linkage),
        Err((step, code, message)) => {
            builder.fail(step, code, message);
            return builder.finish();
        }
    };

    // Approval-block consistency (the retained R6 material must be the exact
    // assertion that was verified).
    if let EvidenceBundle::Evidence(artifact) = &bundle
        && let Err(error) = approval_matches(&artifact.approval, &artifact.receipt.proof)
    {
        builder.fail(
            VerificationStep::Approval,
            FindingCode::ApprovalMismatch,
            error.to_string(),
        );
        return builder.finish();
    }

    // Step 7: checkpoint consistency vs customer-retained heads. A retained
    // record that contradicts the presented history is a split-view/rollback
    // suspicion and is fatal regardless of how the segment verified.
    let retained_head = retained.iter().map(|c| c.receipt_seq).max();
    let head_seq = head.body.seq;
    let divergent = retained.iter().find(|checkpoint| {
        seq_digest
            .get(&checkpoint.receipt_seq)
            .is_some_and(|digest| digest != &checkpoint.receipt_sha256)
    });
    if let Some(divergent) = divergent {
        let artifact_digest = seq_digest
            .get(&divergent.receipt_seq)
            .cloned()
            .unwrap_or_default();
        builder.fail(
            VerificationStep::Checkpoint,
            FindingCode::RollbackSuspect,
            format!(
                "rollback-suspect: divergent history at seq {} (retained {} vs artifact {})",
                divergent.receipt_seq,
                short_fp(&divergent.receipt_sha256),
                short_fp(&artifact_digest)
            ),
        );
    } else if retained.is_empty() {
        builder.info(
            VerificationStep::Checkpoint,
            FindingCode::FirstRun,
            format!(
                "first-run: no prior checkpoint retained locally; nothing yet links this artifact \
                 to pinned history (completeness {UNVERIFIED_LABEL})"
            ),
        );
    } else {
        match &linkage {
            Linkage::PinnedGenesis | Linkage::Retained { .. } => {
                builder.info(
                    VerificationStep::Checkpoint,
                    FindingCode::ExtendedOk,
                    format!(
                        "extended-ok: verified seq {}..={} extends retained history (new head seq {})",
                        first.body.seq, head_seq, report_head.head_seq
                    ),
                );
            }
            Linkage::Reconfirmed { at_seq } => {
                builder.info(
                    VerificationStep::Checkpoint,
                    FindingCode::ExtendedOk,
                    format!(
                        "extended-ok: seq {}..={} re-confirms retained checkpoint {} (no new head)",
                        first.body.seq, head_seq, at_seq
                    ),
                );
            }
            Linkage::SelfContained => {
                if let Some(head_retained) = retained_head {
                    if head_seq < head_retained {
                        builder.fail(
                            VerificationStep::Checkpoint,
                            FindingCode::RollbackSuspect,
                            format!(
                                "rollback-suspect: artifact head seq {head_seq} is below retained \
                                 head seq {head_retained} and does not match a retained record at \
                                 its position"
                            ),
                        );
                    } else {
                        builder.fail(
                            VerificationStep::Checkpoint,
                            FindingCode::Gap,
                            format!(
                                "gap: retained head seq {head_retained} does not link to artifact \
                                 range {}..={head_seq} (missing intermediate receipts)",
                                first.body.seq
                            ),
                        );
                    }
                }
            }
        }
    }

    // Completeness honesty (normative).
    builder.completeness = match retained_head {
        None => Completeness::Unverified {
            reason: NO_PRIOR_CHECKPOINT.to_string(),
        },
        Some(retained_head_seq) => Completeness::Compared {
            from_seq: first.body.seq,
            to_seq: head_seq,
            retained_head_seq,
        },
    };

    // Step 8: validity at the evaluated instant (default now, ±60s skew).
    let mut valid = true;
    for receipt in &segment {
        if receipt.body.issued_at > evaluated_at.saturating_add(CLOCK_SKEW_SECONDS) {
            valid = false;
            builder.fail(
                VerificationStep::Validity,
                FindingCode::NotYetValid,
                format!(
                    "not-yet-valid: receipt seq {} was issued at {}, after the evaluated instant \
                     {evaluated_at} (+{CLOCK_SKEW_SECONDS}s skew)",
                    receipt.body.seq, receipt.body.issued_at
                ),
            );
        }
    }
    if valid {
        builder.info(
            VerificationStep::Validity,
            FindingCode::Valid,
            format!(
                "valid: the approval was established at or before evaluated instant \
                 {evaluated_at} (±{CLOCK_SKEW_SECONDS}s skew)"
            ),
        );
    }

    // Witness seam (spec §6): records parse, absence is never blocking, and
    // the status is never upgraded while the program is gated.
    let witness_records: usize = match &bundle {
        EvidenceBundle::Evidence(artifact) => artifact.witness.len(),
        EvidenceBundle::Chain(artifact) => artifact.witness.len(),
    };
    if witness_records == 0 {
        builder.info(
            VerificationStep::Witness,
            FindingCode::NotWitnessVerified,
            "witness: no acknowledgement records present (absence is never blocking); \
             not-witness-verified",
        );
    } else {
        builder.info(
            VerificationStep::Witness,
            FindingCode::NotWitnessVerified,
            format!(
                "witness: {witness_records} acknowledgement record(s) parsed but the external \
                 witness program is gated; not-witness-verified"
            ),
        );
    }

    builder.finish()
}

const UNVERIFIED_LABEL: &str = "UNVERIFIED (no prior checkpoint)";

/// Outcome of segment verification.
struct SegmentOutcome {
    head: ChainReport,
    linkage: Linkage,
}

type SegmentError = (VerificationStep, FindingCode, String);

fn verify_segment(
    segment: &[&SignedReceipt],
    seq_digest: &BTreeMap<u64, String>,
    pin: &TrustPin,
    genesis_root: Option<&TrustBundle>,
    retained: &[&Checkpoint],
    bundle: &EvidenceBundle,
) -> Result<SegmentOutcome, SegmentError> {
    let first = segment[0];
    let head = segment[segment.len() - 1];
    let head_digest = seq_digest
        .get(&head.body.seq)
        .map(String::as_str)
        .unwrap_or("");
    let owned: Vec<SignedReceipt> = segment.iter().map(|receipt| (*receipt).clone()).collect();

    // Case 1: a customer-retained checkpoint links at first.seq - 1.
    let previous = first
        .body
        .seq
        .checked_sub(1)
        .and_then(|previous_seq| retained.iter().find(|c| c.receipt_seq == previous_seq));
    if let Some(checkpoint) = previous {
        let chain = match genesis_root {
            Some(root) => verify_receipt_chain(&owned, root, Some(checkpoint)),
            None => verify_receipt_suffix(&owned, checkpoint, &pin.root_fingerprint),
        }
        .map_err(|error| {
            (
                VerificationStep::Approval,
                FindingCode::ApprovalInvalid,
                format!(
                    "approval verification failed against retained checkpoint {}: {error}",
                    checkpoint.receipt_seq
                ),
            )
        })?;
        return Ok(SegmentOutcome {
            head: chain,
            linkage: Linkage::Retained {
                at_seq: checkpoint.receipt_seq,
            },
        });
    }

    // Case 2: full history from the pinned genesis root bundle.
    if first.body.seq == 1
        && let Some(root) = genesis_root
    {
        let chain = verify_receipt_chain(&owned, root, None).map_err(|error| {
            (
                VerificationStep::Approval,
                FindingCode::ApprovalInvalid,
                format!("approval verification failed from the pinned root: {error}"),
            )
        })?;
        return Ok(SegmentOutcome {
            head: chain,
            linkage: Linkage::PinnedGenesis,
        });
    }

    // Case 3: an interior customer-retained checkpoint confirms part of the
    // presented run (gap fill via a chain export) — verify the suffix after
    // it; earlier receipts are context cross-checked against retained records
    // in step 7.
    let interior = retained
        .iter()
        .filter(|checkpoint| {
            checkpoint.receipt_seq >= first.body.seq
                && checkpoint.receipt_seq < head.body.seq
                && seq_digest
                    .get(&checkpoint.receipt_seq)
                    .is_some_and(|digest| digest == &checkpoint.receipt_sha256)
        })
        .max_by_key(|checkpoint| checkpoint.receipt_seq);
    if let Some(checkpoint) = interior {
        let suffix: Vec<SignedReceipt> = owned
            .iter()
            .filter(|receipt| receipt.body.seq > checkpoint.receipt_seq)
            .cloned()
            .collect();
        let chain = match genesis_root {
            Some(root) => verify_receipt_chain(&suffix, root, Some(checkpoint)),
            None => verify_receipt_suffix(&suffix, checkpoint, &pin.root_fingerprint),
        }
        .map_err(|error| {
            (
                VerificationStep::Approval,
                FindingCode::ApprovalInvalid,
                format!(
                    "approval verification failed against retained checkpoint {}: {error}",
                    checkpoint.receipt_seq
                ),
            )
        })?;
        return Ok(SegmentOutcome {
            head: chain,
            linkage: Linkage::Retained {
                at_seq: checkpoint.receipt_seq,
            },
        });
    }

    // Case 4: the head digest equals a customer-retained checkpoint — known
    // history being re-verified. The proof must still verify.
    let matching_head = retained
        .iter()
        .find(|c| c.receipt_seq == head.body.seq && c.receipt_sha256 == head_digest);
    if let Some(checkpoint) = matching_head
        && verify_self_contained(head, &checkpoint.authorization).is_ok()
    {
        return Ok(SegmentOutcome {
            head: checkpoint_report(checkpoint),
            linkage: Linkage::Reconfirmed {
                at_seq: checkpoint.receipt_seq,
            },
        });
    }

    // Case 5: self-contained verification against the artifact-carried
    // authority (bootstrap import / first run). Only the landed head receipt
    // carries an artifact-carried post-state; tail receipts are link-checked.
    let carried = carried_authority(bundle, head.body.seq);
    if let Some(authority) = carried {
        verify_self_contained(head, authority).map_err(|error| {
            (
                VerificationStep::Approval,
                FindingCode::ApprovalInvalid,
                format!(
                    "approval verification failed against the artifact-carried authority: {error}"
                ),
            )
        })?;
        return Ok(SegmentOutcome {
            head: self_contained_report(head, authority, pin),
            linkage: Linkage::SelfContained,
        });
    }

    Err((
        VerificationStep::Approval,
        FindingCode::ApprovalInvalid,
        format!(
            "no verifiable authority state for receipt seq {}: nothing links it to the pinned \
             root and the artifact does not carry its post-state",
            head.body.seq
        ),
    ))
}

/// Verify the head receipt against an artifact-carried authority state. This
/// is only sound when the carried post-state equals the pre-activation state
/// (no signer transition at the head receipt).
fn verify_self_contained(
    head: &SignedReceipt,
    authority: &TrustBundle,
) -> Result<crate::receipt::ReceiptStanding, ConfigError> {
    if head.body.action == ReceiptAction::ReplaceSigner || head.body.replacement.is_some() {
        return Err(ConfigError::approval(
            "signer transitions require a link to retained history or the pinned root",
        ));
    }
    verify_receipt(head, authority)
}

fn carried_authority(bundle: &EvidenceBundle, head_seq: u64) -> Option<&TrustBundle> {
    match bundle {
        EvidenceBundle::Evidence(artifact) => (artifact.checkpoint.receipt_seq == head_seq)
            .then_some(&artifact.checkpoint.authorization),
        EvidenceBundle::Chain(artifact) => artifact
            .checkpoints
            .iter()
            .find(|checkpoint| checkpoint.receipt_seq == head_seq)
            .map(|checkpoint| &checkpoint.authorization),
    }
}

fn checkpoint_report(checkpoint: &Checkpoint) -> ChainReport {
    ChainReport {
        head_seq: checkpoint.receipt_seq,
        head_receipt_sha256: checkpoint.receipt_sha256.clone(),
        envelope_digest: checkpoint.envelope_digest.clone(),
        envelope_version: checkpoint.envelope_version,
        effective_state_digest: checkpoint.effective_state_digest.clone(),
        initial_bundle_sha256: checkpoint.initial_bundle_sha256.clone(),
        authorization: checkpoint.authorization.clone(),
        receipt_count: 0,
        extends_checkpoint: true,
    }
}

fn self_contained_report(
    head: &SignedReceipt,
    authority: &TrustBundle,
    pin: &TrustPin,
) -> ChainReport {
    ChainReport {
        head_seq: head.body.seq,
        head_receipt_sha256: head.body.receipt_digest().unwrap_or_else(|_| String::new()),
        envelope_digest: head.body.envelope_digest.clone(),
        envelope_version: head.body.envelope_version,
        effective_state_digest: head.body.effective_state_digest.clone(),
        initial_bundle_sha256: pin.root_fingerprint.clone(),
        authorization: authority.clone(),
        receipt_count: 1,
        extends_checkpoint: false,
    }
}

/// Container-level linkage: the artifact's carried checkpoints must agree
/// with the presented receipts and the declared root fingerprint.
fn check_container_links(
    bundle: &EvidenceBundle,
    segment: &[&SignedReceipt],
    seq_digest: &BTreeMap<u64, String>,
) -> Result<(), ConfigError> {
    let head = segment[segment.len() - 1];
    let head_digest = seq_digest
        .get(&head.body.seq)
        .map(String::as_str)
        .unwrap_or("");
    let (workspace_id, fingerprint) = (bundle.workspace_id(), bundle.trust_root_fingerprint());
    match bundle {
        EvidenceBundle::Evidence(artifact) => check_checkpoint_link(
            &artifact.checkpoint,
            head,
            head_digest,
            workspace_id,
            fingerprint,
        ),
        EvidenceBundle::Chain(artifact) => {
            let mut seen = std::collections::BTreeSet::new();
            for checkpoint in &artifact.checkpoints {
                if checkpoint.workspace_id != workspace_id {
                    return Err(ConfigError::invalid(format!(
                        "checkpoint {} workspace does not match the container workspace",
                        checkpoint.receipt_seq
                    )));
                }
                if checkpoint.initial_bundle_sha256 != fingerprint {
                    return Err(ConfigError::invalid(format!(
                        "checkpoint {} is not bound to the declared trust root",
                        checkpoint.receipt_seq
                    )));
                }
                if !seen.insert(checkpoint.receipt_seq) {
                    return Err(ConfigError::invalid(format!(
                        "chain export carries duplicate checkpoint for seq {}",
                        checkpoint.receipt_seq
                    )));
                }
                if let Some(receipt) = segment
                    .iter()
                    .find(|receipt| receipt.body.seq == checkpoint.receipt_seq)
                {
                    let digest = seq_digest
                        .get(&checkpoint.receipt_seq)
                        .map(String::as_str)
                        .unwrap_or("");
                    check_checkpoint_link(checkpoint, receipt, digest, workspace_id, fingerprint)?;
                }
            }
            Ok(())
        }
    }
}

fn check_checkpoint_link(
    checkpoint: &Checkpoint,
    receipt: &SignedReceipt,
    receipt_digest: &str,
    workspace_id: &str,
    fingerprint: &str,
) -> Result<(), ConfigError> {
    if checkpoint.workspace_id != workspace_id {
        return Err(ConfigError::invalid(
            "checkpoint workspace does not match the container workspace",
        ));
    }
    if checkpoint.initial_bundle_sha256 != fingerprint {
        return Err(ConfigError::invalid(
            "checkpoint initial_bundle_sha256 does not match trust_root_fingerprint",
        ));
    }
    if checkpoint.receipt_seq != receipt.body.seq {
        return Err(ConfigError::invalid(format!(
            "checkpoint receipt_seq {} does not match the landed receipt seq {}",
            checkpoint.receipt_seq, receipt.body.seq
        )));
    }
    if checkpoint.receipt_sha256 != receipt_digest {
        return Err(ConfigError::invalid(
            "checkpoint receipt_sha256 does not match the landed receipt digest",
        ));
    }
    if checkpoint.envelope_digest != receipt.body.envelope_digest
        || checkpoint.envelope_version != receipt.body.envelope_version
        || checkpoint.effective_state_digest != receipt.body.effective_state_digest
    {
        return Err(ConfigError::invalid(
            "checkpoint envelope/effective-state fields do not match the landed receipt",
        ));
    }
    // The carried post-state must be the pre-activation authority the receipt
    // extended (identical unless the receipt applies a signer transition), so
    // a doctored carried state can never poison a later retained store.
    if receipt.body.replacement.is_none() {
        let carried = checkpoint
            .authorization
            .digest()
            .map_err(|error| ConfigError::invalid(format!("carried authority invalid: {error}")))?;
        if carried != receipt.body.authority_digest {
            return Err(ConfigError::invalid(
                "checkpoint authorization does not match the receipt's pre-activation authority",
            ));
        }
    }
    Ok(())
}

/// The retained R6 approval material must be exactly the assertion that was
/// verified with the receipt.
fn approval_matches(approval: &ApprovalEvidence, proof: &WebAuthnProof) -> Result<(), ConfigError> {
    if approval.cose_alg != -7 {
        return Err(ConfigError::invalid(format!(
            "approval evidence cose_alg {} must be -7 (ES256)",
            approval.cose_alg
        )));
    }
    if approval.proof != *proof {
        return Err(ConfigError::invalid(
            "approval evidence does not match the landed receipt's assertion \
             (credential id, clientDataJSON, authenticator data, or signature differs)",
        ));
    }
    Ok(())
}

fn short_fp(value: &str) -> String {
    let limit = 12.min(value.len());
    format!("{}…", &value[..limit])
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Re-exported for report rendering and tests.
pub fn witness_status() -> &'static str {
    WITNESS_STATUS
}

/// Check the container-level shapes that must hold before any crypto runs.
/// Exposed so `policy trust import` can reject malformed artifacts early.
pub fn check_evidence_shape(bundle: &EvidenceBundle) -> Result<(), ConfigError> {
    bundle.validate()
}

/// Witness acknowledgement records are parse-only while the program is gated.
pub fn parse_witness_records(bundle: &EvidenceBundle) -> Vec<&WitnessAcknowledgement> {
    match bundle {
        EvidenceBundle::Evidence(artifact) => artifact.witness.iter().collect(),
        EvidenceBundle::Chain(artifact) => artifact.witness.iter().collect(),
    }
}

/// Kind helpers kept next to the facade for CLI rendering.
pub fn evidence_kind(bundle: &EvidenceBundle) -> EvidenceKind {
    bundle.kind()
}

/// Structural helpers re-exported so the CLI can introspect an artifact
/// without duplicating container knowledge.
pub fn evidence_head_seq(bundle: &EvidenceBundle) -> u64 {
    bundle
        .receipts()
        .iter()
        .map(|receipt| receipt.body.seq)
        .max()
        .unwrap_or(0)
}

/// Parse-only view of a chain artifact's carried checkpoints.
pub fn chain_checkpoints(bundle: &EvidenceBundle) -> Vec<&Checkpoint> {
    match bundle {
        EvidenceBundle::Evidence(artifact) => vec![&artifact.checkpoint],
        EvidenceBundle::Chain(artifact) => artifact.checkpoints.iter().collect(),
    }
}

/// Parse-only view of a chain artifact's carried receipts.
pub fn chain_receipts(bundle: &EvidenceBundle) -> Vec<&SignedReceipt> {
    bundle.receipts()
}

/// True when the artifact's carried root fingerprint is hex64-shaped.
pub fn fingerprint_is_hex64(fingerprint: &str) -> bool {
    is_hex64(fingerprint)
}

/// Evidence/chain artifact accessors for the CLI's import path.
pub fn as_evidence(bundle: &EvidenceBundle) -> Option<&EvidenceArtifact> {
    match bundle {
        EvidenceBundle::Evidence(artifact) => Some(artifact),
        EvidenceBundle::Chain(_) => None,
    }
}

/// Chain artifact accessor for the CLI's import path.
pub fn as_chain(bundle: &EvidenceBundle) -> Option<&ChainArtifact> {
    match bundle {
        EvidenceBundle::Chain(artifact) => Some(artifact),
        EvidenceBundle::Evidence(_) => None,
    }
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
