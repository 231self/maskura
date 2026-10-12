//! Verification facade tests (Slice 4 spec §3, §7): golden paths, the tamper
//! table, the trust-reset discontinuity table, the pin invariants, the
//! completeness-honesty table, `--at` historical validity, and unknown-schema
//! fail-closed behavior.

use serde_json::json;

use super::*;
use crate::fixtures::{Golden, golden};

fn pin(golden: &Golden) -> TrustPin {
    TrustPin {
        workspace_id: golden.root.workspace_id.clone(),
        root_fingerprint: golden.root_fingerprint.clone(),
        bundle: Some(golden.root.clone()),
    }
}

/// A manual `trust add` pin: fingerprint only, no root bundle bytes.
fn pin_without_root_bytes(golden: &Golden) -> TrustPin {
    TrustPin {
        workspace_id: golden.root.workspace_id.clone(),
        root_fingerprint: golden.root_fingerprint.clone(),
        bundle: None,
    }
}

fn state(pin: Option<TrustPin>, retained: Vec<Checkpoint>) -> TrustState {
    TrustState { pin, retained }
}

fn verify(json: &str, trust: &TrustState, at: Option<u64>) -> VerificationReport {
    verify_artifact(json, trust, &VerifyOptions { at })
}

fn has(report: &VerificationReport, code: FindingCode) -> bool {
    report.findings.iter().any(|finding| finding.code == code)
}

fn message(report: &VerificationReport, code: FindingCode) -> String {
    report
        .findings
        .iter()
        .find(|finding| finding.code == code)
        .unwrap_or_else(|| panic!("missing finding {code:?}"))
        .message
        .clone()
}

// ---------------------------------------------------------------------------
// Golden paths
// ---------------------------------------------------------------------------

#[test]
fn first_run_verifies_self_consistently_with_unverified_completeness() {
    let golden = golden();
    let report = verify(
        &golden.evidence(0).to_json().unwrap(),
        &state(Some(pin(&golden)), Vec::new()),
        None,
    );
    assert_eq!(report.verdict, Verdict::Verified);
    assert_eq!(
        report.completeness,
        Completeness::Unverified {
            reason: NO_PRIOR_CHECKPOINT.to_string()
        }
    );
    assert_eq!(
        report.completeness.to_string(),
        "UNVERIFIED (no prior checkpoint)"
    );
    assert!(has(&report, FindingCode::FirstRun));
}

#[test]
fn anchored_extension_verifies_against_retained_checkpoint() {
    let golden = golden();
    let report = verify(
        &golden.evidence(1).to_json().unwrap(),
        &state(Some(pin(&golden)), vec![golden.checkpoints[0].clone()]),
        None,
    );
    assert_eq!(report.verdict, Verdict::Verified);
    assert_eq!(
        report.completeness,
        Completeness::Compared {
            from_seq: 2,
            to_seq: 2,
            retained_head_seq: 1,
        }
    );
    assert!(has(&report, FindingCode::ExtendedOk));
    assert_eq!(report.artifact.head_seq, Some(2));
}

#[test]
fn tail_receipts_verify_when_anchored() {
    let golden = golden();
    let report = verify(
        &golden.evidence_with_tail().to_json().unwrap(),
        &state(Some(pin(&golden)), vec![golden.checkpoints[0].clone()]),
        None,
    );
    assert_eq!(report.verdict, Verdict::Verified);
    assert!(has(&report, FindingCode::ExtendedOk));
    assert_eq!(report.artifact.head_seq, Some(3));
}

#[test]
fn chain_bundle_verifies_whole_history_from_the_pinned_root() {
    let golden = golden();
    let report = verify(
        &golden.chain().to_json().unwrap(),
        &state(Some(pin(&golden)), Vec::new()),
        None,
    );
    assert_eq!(report.verdict, Verdict::Verified);
    assert!(has(&report, FindingCode::FirstRun));
}

#[test]
fn chain_bundle_cross_checks_retained_history() {
    let golden = golden();
    let report = verify(
        &golden.chain().to_json().unwrap(),
        &state(
            Some(pin(&golden)),
            vec![
                golden.checkpoints[0].clone(),
                golden.checkpoints[1].clone(),
                golden.checkpoints[2].clone(),
            ],
        ),
        None,
    );
    assert_eq!(report.verdict, Verdict::Verified);
    assert!(has(&report, FindingCode::ExtendedOk));
    assert_eq!(
        report.completeness,
        Completeness::Compared {
            from_seq: 1,
            to_seq: 3,
            retained_head_seq: 3,
        }
    );
}

#[test]
fn interior_retained_checkpoint_fills_the_gap() {
    let golden = golden();
    // Segment [2, 3] with only checkpoint 2 retained: the suffix after the
    // interior anchor verifies, the tail receipt is context.
    let report = verify(
        &golden.evidence_with_tail().to_json().unwrap(),
        &state(Some(pin(&golden)), vec![golden.checkpoints[1].clone()]),
        None,
    );
    assert_eq!(report.verdict, Verdict::Verified);
    assert!(has(&report, FindingCode::ExtendedOk));
}

#[test]
fn reconfirmed_history_verifies() {
    let golden = golden();
    let report = verify(
        &golden.evidence(1).to_json().unwrap(),
        &state(Some(pin(&golden)), vec![golden.checkpoints[1].clone()]),
        None,
    );
    assert_eq!(report.verdict, Verdict::Verified);
    assert!(
        message(&report, FindingCode::ExtendedOk).contains("re-confirms"),
        "unexpected findings: {:?}",
        report.findings
    );
}

#[test]
fn suffix_verification_works_without_genesis_root_bytes() {
    let golden = golden();
    let report = verify(
        &golden.evidence(1).to_json().unwrap(),
        &state(
            Some(pin_without_root_bytes(&golden)),
            vec![golden.checkpoints[0].clone()],
        ),
        None,
    );
    assert_eq!(report.verdict, Verdict::Verified);
    assert!(has(&report, FindingCode::ExtendedOk));
}

// ---------------------------------------------------------------------------
// Pin invariants
// ---------------------------------------------------------------------------

#[test]
fn unpinned_verification_is_refused() {
    let golden = golden();
    let report = verify(
        &golden.evidence(0).to_json().unwrap(),
        &state(None, Vec::new()),
        None,
    );
    assert_eq!(report.verdict, Verdict::Failed);
    assert!(has(&report, FindingCode::UnpinnedRoot));
    assert!(!has(&report, FindingCode::Valid));
}

#[test]
fn pin_for_another_workspace_is_refused() {
    let golden = golden();
    let mut other = pin(&golden);
    other.workspace_id = "ws-2".into();
    let report = verify(
        &golden.evidence(0).to_json().unwrap(),
        &state(Some(other), Vec::new()),
        None,
    );
    assert_eq!(report.verdict, Verdict::Failed);
    assert!(has(&report, FindingCode::UnpinnedRoot));
}

#[test]
fn a_mismatched_root_never_verifies_against_the_pin() {
    let golden = golden();
    let report = verify(
        &golden.reset_evidence().to_json().unwrap(),
        &state(Some(pin(&golden)), Vec::new()),
        None,
    );
    assert_eq!(report.verdict, Verdict::Failed);
    assert!(!report.ok());
}

// ---------------------------------------------------------------------------
// Trust-reset discontinuity table
// ---------------------------------------------------------------------------

#[test]
fn trust_reset_renders_as_discontinuity() {
    let golden = golden();
    let mut accepted = pin(&golden);
    accepted.root_fingerprint = golden.reset_fingerprint.clone();
    accepted.bundle = Some(golden.reset_root.clone());
    let report = verify(
        &golden.reset_evidence().to_json().unwrap(),
        &state(Some(accepted), Vec::new()),
        None,
    );
    assert_eq!(report.verdict, Verdict::Verified);
    assert!(has(&report, FindingCode::Discontinuity));
    assert!(
        message(&report, FindingCode::Discontinuity)
            .starts_with("discontinuity: trust reset recorded at epoch 1"),
        "unexpected findings: {:?}",
        report.findings
    );
}

#[test]
fn new_root_not_accepted_reports_discontinuity_and_never_continuity() {
    let golden = golden();
    let report = verify(
        &golden.reset_evidence().to_json().unwrap(),
        &state(Some(pin(&golden)), Vec::new()),
        None,
    );
    assert_eq!(report.verdict, Verdict::Failed);
    assert!(has(&report, FindingCode::DiscontinuityNewRootNotAccepted));
    let text = message(&report, FindingCode::DiscontinuityNewRootNotAccepted);
    assert!(
        text.starts_with("discontinuity: new root not accepted"),
        "{text}"
    );
    assert!(
        text.contains("explicitly"),
        "must point at explicit acceptance: {text}"
    );
    // Continuity is never presented.
    assert!(!has(&report, FindingCode::ExtendedOk));
    assert!(!has(&report, FindingCode::Valid));
    assert_eq!(
        report.completeness,
        Completeness::Unverified {
            reason: NO_PRIOR_CHECKPOINT.to_string()
        }
    );
}

#[test]
fn accepted_new_root_verifies_only_after_explicit_acceptance() {
    let golden = golden();
    let rejected = verify(
        &golden.reset_evidence().to_json().unwrap(),
        &state(Some(pin(&golden)), Vec::new()),
        None,
    );
    assert!(!rejected.ok());
    // Explicit acceptance = the customer re-pins the new root (import --force
    // or `trust add`), which the facade sees as a new TrustPin.
    let mut accepted = pin(&golden);
    accepted.root_fingerprint = golden.reset_fingerprint.clone();
    accepted.bundle = Some(golden.reset_root.clone());
    let accepted_report = verify(
        &golden.reset_evidence().to_json().unwrap(),
        &state(Some(accepted), Vec::new()),
        None,
    );
    assert_eq!(accepted_report.verdict, Verdict::Verified);
}

// ---------------------------------------------------------------------------
// Tamper table (each field of the bundle)
// ---------------------------------------------------------------------------

fn tampered(mutate: impl FnOnce(&mut serde_json::Value)) -> String {
    let golden = golden();
    let mut value: serde_json::Value =
        serde_json::from_str(&golden.evidence(0).to_json().unwrap()).unwrap();
    mutate(&mut value);
    value.to_string()
}

fn assert_tamper_fails(json: &str, code: FindingCode) {
    let golden = golden();
    let report = verify(json, &state(Some(pin(&golden)), Vec::new()), None);
    assert_eq!(
        report.verdict,
        Verdict::Failed,
        "findings: {:?}",
        report.findings
    );
    assert!(
        has(&report, code),
        "expected {code:?}, got {:?}",
        report.findings
    );
}

#[test]
fn tamper_container_fields_fail_closed() {
    assert_tamper_fails(
        &tampered(|value| value["schema_version"] = 2.into()),
        FindingCode::SchemaRejected,
    );
    assert_tamper_fails(
        &tampered(|value| value["kind"] = "manifest".into()),
        FindingCode::KindRejected,
    );
    assert_tamper_fails(
        &tampered(|value| value["extra"] = 1.into()),
        FindingCode::UnknownField,
    );
    assert_tamper_fails(
        &tampered(|value| value["trust_root_fingerprint"] = "a".repeat(64).into()),
        FindingCode::ChainInvalid,
    );
    assert_tamper_fails(
        &tampered(|value| value["workspace_id"] = "ws-2".into()),
        FindingCode::ChainInvalid,
    );
}

#[test]
fn tamper_receipt_body_fields_fail_closed() {
    assert_tamper_fails(
        &tampered(|value| value["receipt"]["body"]["seq"] = 2.into()),
        FindingCode::ChainInvalid,
    );
    assert_tamper_fails(
        &tampered(|value| value["receipt"]["body"]["prev_receipt_sha256"] = "a".repeat(64).into()),
        FindingCode::GenesisInvalid,
    );
    assert_tamper_fails(
        &tampered(|value| value["receipt"]["body"]["envelope_digest"] = "a".repeat(64).into()),
        FindingCode::ChainInvalid,
    );
    assert_tamper_fails(
        &tampered(|value| value["receipt"]["body"]["envelope_version"] = 2.into()),
        FindingCode::ChainInvalid,
    );
    // Digest-changing mutations break the landed-receipt ↔ checkpoint link
    // first; `tamper_with_digest_repair_still_fails_at_the_proof` covers the
    // signature layer below it.
    assert_tamper_fails(
        &tampered(|value| value["receipt"]["body"]["signer_epoch"] = 2.into()),
        FindingCode::ChainInvalid,
    );
    assert_tamper_fails(
        &tampered(|value| value["receipt"]["body"]["authority_digest"] = "a".repeat(64).into()),
        FindingCode::ChainInvalid,
    );
    assert_tamper_fails(
        &tampered(|value| value["receipt"]["body"]["issued_at"] = 1_101.into()),
        FindingCode::ChainInvalid,
    );
    assert_tamper_fails(
        &tampered(|value| value["receipt"]["body"]["workspace_id"] = "ws-2".into()),
        FindingCode::ReceiptInvalid,
    );
    assert_tamper_fails(
        &tampered(|value| {
            value["receipt"]["body"]["audience"] = "https://other.example.com".into()
        }),
        FindingCode::ReceiptInvalid,
    );
    assert_tamper_fails(
        &tampered(|value| {
            value["receipt"]["body"]["effective_state"]["routes"][0]["steps"][0]["component_sha256"] =
                "b".repeat(64).into()
        }),
        FindingCode::ReceiptInvalid,
    );
    assert_tamper_fails(
        &tampered(|value| {
            value["receipt"]["body"]["effective_state_digest"] = "a".repeat(64).into()
        }),
        FindingCode::ReceiptInvalid,
    );
}

#[test]
fn tamper_with_digest_repair_still_fails_at_the_proof() {
    // Rewrite the effective state AND repair every digest: only the signed
    // challenge binding still catches the substitution.
    let golden = golden();
    let mut value: serde_json::Value =
        serde_json::from_str(&golden.evidence(0).to_json().unwrap()).unwrap();
    value["receipt"]["body"]["effective_state"]["routes"][0]["steps"][0]["component_sha256"] =
        "b".repeat(64).into();
    let effective: crate::EffectiveState =
        serde_json::from_value(value["receipt"]["body"]["effective_state"].clone()).unwrap();
    let repaired = effective.digest().unwrap();
    value["receipt"]["body"]["effective_state_digest"] = repaired.clone().into();
    value["checkpoint"]["effective_state_digest"] = repaired.into();
    let receipt: SignedReceipt = serde_json::from_value(value["receipt"].clone()).unwrap();
    let new_digest = receipt.body.receipt_digest().unwrap();
    value["checkpoint"]["receipt_sha256"] = new_digest.into();
    let report = verify(
        &value.to_string(),
        &state(Some(pin(&golden)), Vec::new()),
        None,
    );
    assert_eq!(report.verdict, Verdict::Failed);
    assert!(has(&report, FindingCode::ApprovalInvalid));
}

#[test]
fn tamper_proof_fields_fail_closed() {
    // ASN.1 DER ES256 signature bytes.
    assert_tamper_fails(
        &tampered(|value| value["receipt"]["proof"]["signature"] = "AA".into()),
        FindingCode::ApprovalInvalid,
    );
    // Retained clientDataJSON (origin).
    assert_tamper_fails(
        &tampered(|value| {
            let mut client: serde_json::Value = serde_json::from_str(
                value["receipt"]["proof"]["client_data_json"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            client["origin"] = "https://evil.example.com".into();
            value["receipt"]["proof"]["client_data_json"] = client.to_string().into();
        }),
        FindingCode::ApprovalInvalid,
    );
    // Retained clientDataJSON (challenge ↔ receipt digest binding).
    assert_tamper_fails(
        &tampered(|value| {
            let mut client: serde_json::Value = serde_json::from_str(
                value["receipt"]["proof"]["client_data_json"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            client["challenge"] = "AAAA".into();
            value["receipt"]["proof"]["client_data_json"] = client.to_string().into();
        }),
        FindingCode::ApprovalInvalid,
    );
    // Retained authenticator data (RP ID hash).
    assert_tamper_fails(
        &tampered(|value| value["receipt"]["proof"]["authenticator_data"] = "AAAA".into()),
        FindingCode::ApprovalInvalid,
    );
    // Credential id.
    assert_tamper_fails(
        &tampered(|value| value["receipt"]["proof"]["credential_id"] = "other-credential".into()),
        FindingCode::ApprovalInvalid,
    );
}

#[test]
fn tamper_checkpoint_fields_fail_closed() {
    assert_tamper_fails(
        &tampered(|value| value["checkpoint"]["receipt_seq"] = 2.into()),
        FindingCode::ChainInvalid,
    );
    assert_tamper_fails(
        &tampered(|value| value["checkpoint"]["receipt_sha256"] = "a".repeat(64).into()),
        FindingCode::ChainInvalid,
    );
    assert_tamper_fails(
        &tampered(|value| value["checkpoint"]["initial_bundle_sha256"] = "a".repeat(64).into()),
        FindingCode::ChainInvalid,
    );
    // A no-op mutation must still verify.
    let noop = tampered(|value| {
        let key = value["checkpoint"]["authorization"]["credentials"][0]["cose_public_key"].clone();
        value["checkpoint"]["authorization"]["credentials"][0]["cose_public_key"] = key;
    });
    let golden = golden();
    assert!(verify(&noop, &state(Some(pin(&golden)), Vec::new()), None).ok());
    // A doctored carried authority is caught even when the receipt verifies.
    assert_tamper_fails(
        &tampered(|value| {
            value["checkpoint"]["authorization"]["credentials"][0]["label"] = "attacker".into();
        }),
        FindingCode::ChainInvalid,
    );
}

#[test]
fn tamper_approval_block_is_detected() {
    // The retained R6 material must be the exact verified assertion.
    assert_tamper_fails(
        &tampered(|value| value["approval"]["proof"]["signature"] = "AA".into()),
        FindingCode::ApprovalMismatch,
    );
    assert_tamper_fails(
        &tampered(|value| value["approval"]["proof"]["credential_id"] = "other".into()),
        FindingCode::ApprovalMismatch,
    );
    assert_tamper_fails(
        &tampered(|value| value["approval"]["cose_alg"] = (-8).into()),
        FindingCode::SchemaRejected,
    );
}

// ---------------------------------------------------------------------------
// Completeness honesty table
// ---------------------------------------------------------------------------

#[test]
fn completeness_first_run_is_unverified() {
    let golden = golden();
    let report = verify(
        &golden.evidence(2).to_json().unwrap(),
        &state(Some(pin(&golden)), Vec::new()),
        None,
    );
    assert_eq!(
        report.completeness.to_string(),
        "UNVERIFIED (no prior checkpoint)"
    );
    assert!(has(&report, FindingCode::FirstRun));
}

#[test]
fn completeness_extended_reports_the_compared_range() {
    let golden = golden();
    let report = verify(
        &golden.evidence(2).to_json().unwrap(),
        &state(
            Some(pin(&golden)),
            vec![golden.checkpoints[0].clone(), golden.checkpoints[1].clone()],
        ),
        None,
    );
    assert_eq!(
        report.completeness.to_string(),
        "COMPARED (seq 3..=3 against retained head 2)"
    );
    assert!(has(&report, FindingCode::ExtendedOk));
}

#[test]
fn completeness_gap_is_reported_and_fatal() {
    let golden = golden();
    // Retained history at seq 1, artifact jumps to seq 3: nothing links them.
    let report = verify(
        &golden.evidence(2).to_json().unwrap(),
        &state(Some(pin(&golden)), vec![golden.checkpoints[0].clone()]),
        None,
    );
    assert_eq!(report.verdict, Verdict::Failed);
    assert!(has(&report, FindingCode::Gap));
    assert!(message(&report, FindingCode::Gap).starts_with("gap:"));
    assert_eq!(
        report.completeness,
        Completeness::Compared {
            from_seq: 3,
            to_seq: 3,
            retained_head_seq: 1,
        }
    );
}

#[test]
fn completeness_rollback_divergent_history_is_fatal() {
    let golden = golden();
    let mut divergent = golden.checkpoints[1].clone();
    divergent.receipt_sha256 = "a".repeat(64);
    let report = verify(
        &golden.evidence(1).to_json().unwrap(),
        &state(
            Some(pin(&golden)),
            vec![golden.checkpoints[0].clone(), divergent],
        ),
        None,
    );
    assert_eq!(report.verdict, Verdict::Failed);
    assert!(has(&report, FindingCode::RollbackSuspect));
    assert!(
        message(&report, FindingCode::RollbackSuspect).contains("divergent history"),
        "unexpected findings: {:?}",
        report.findings
    );
}

#[test]
fn completeness_rollback_below_retained_head_is_fatal() {
    let golden = golden();
    // Artifact head seq 2 while the customer already retained head seq 3, and
    // nothing links the artifact to the retained record at seq 2.
    let report = verify(
        &golden.evidence(1).to_json().unwrap(),
        &state(Some(pin(&golden)), vec![golden.checkpoints[2].clone()]),
        None,
    );
    assert_eq!(report.verdict, Verdict::Failed);
    assert!(has(&report, FindingCode::RollbackSuspect));
    assert!(
        message(&report, FindingCode::RollbackSuspect).contains("below retained head"),
        "unexpected findings: {:?}",
        report.findings
    );
}

// ---------------------------------------------------------------------------
// Validity (`--at` historical validity, default now ±60s skew)
// ---------------------------------------------------------------------------

#[test]
fn validity_at_historical_instant_before_issuance_fails() {
    let golden = golden();
    let report = verify(
        &golden.evidence(0).to_json().unwrap(),
        &state(Some(pin(&golden)), Vec::new()),
        Some(1_000),
    );
    assert_eq!(report.verdict, Verdict::Failed);
    assert!(has(&report, FindingCode::NotYetValid));
    assert_eq!(report.evaluated_at, 1_000);
}

#[test]
fn validity_at_historical_instant_after_issuance_passes() {
    let golden = golden();
    let report = verify(
        &golden.evidence(0).to_json().unwrap(),
        &state(Some(pin(&golden)), Vec::new()),
        Some(1_500),
    );
    assert_eq!(report.verdict, Verdict::Verified);
    assert!(has(&report, FindingCode::Valid));
}

#[test]
fn validity_boundary_uses_the_60_second_skew() {
    let golden = golden();
    let trust = state(Some(pin(&golden)), Vec::new());
    let json = golden.evidence(0).to_json().unwrap();
    // issued_at = 1100: valid at 1040 (within skew), not yet valid at 1039.
    assert!(verify(&json, &trust, Some(1_040)).ok());
    let boundary = verify(&json, &trust, Some(1_039));
    assert!(!boundary.ok());
    assert!(has(&boundary, FindingCode::NotYetValid));
}

#[test]
fn validity_defaults_to_now() {
    let golden = golden();
    let report = verify(
        &golden.evidence(0).to_json().unwrap(),
        &state(Some(pin(&golden)), Vec::new()),
        None,
    );
    assert!(report.evaluated_at > 1_700_000_000);
    assert_eq!(report.clock_skew_seconds, CLOCK_SKEW_SECONDS);
    assert!(has(&report, FindingCode::Valid));
}

// ---------------------------------------------------------------------------
// Unknown schema, witness seam, report shape
// ---------------------------------------------------------------------------

#[test]
fn unknown_schema_fails_closed_through_the_facade() {
    let golden = golden();
    let json = golden
        .evidence(0)
        .to_json()
        .unwrap()
        .replace("\"schema_version\": 1", "\"schema_version\": 99");
    let report = verify(&json, &state(Some(pin(&golden)), Vec::new()), None);
    assert_eq!(report.verdict, Verdict::Failed);
    assert!(has(&report, FindingCode::SchemaRejected));
    assert!(message(&report, FindingCode::SchemaRejected).contains("schema_version"));
}

#[test]
fn witness_status_is_never_upgraded_and_absence_is_not_blocking() {
    let golden = golden();
    let trust = state(Some(pin(&golden)), Vec::new());
    let with = verify(
        &golden.evidence_with_witness().to_json().unwrap(),
        &trust,
        None,
    );
    let without = verify(&golden.evidence(0).to_json().unwrap(), &trust, None);
    for report in [&with, &without] {
        assert_eq!(report.verdict, Verdict::Verified);
        assert_eq!(report.witness, WitnessStatus::NotWitnessVerified);
        assert!(has(report, FindingCode::NotWitnessVerified));
    }
    assert!(message(&with, FindingCode::NotWitnessVerified).contains("gated"));
    assert!(message(&without, FindingCode::NotWitnessVerified).contains("absence"));
}

#[test]
fn report_is_versioned_and_serializes() {
    let golden = golden();
    let report = verify(
        &golden.evidence(0).to_json().unwrap(),
        &state(Some(pin(&golden)), Vec::new()),
        None,
    );
    let json = report.to_json().unwrap();
    let parsed: VerificationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, report);
    assert_eq!(parsed.schema_version, VERIFICATION_REPORT_SCHEMA_VERSION);
    assert!(json.contains("\"witness\": \"not-witness-verified\""));
    assert!(json.contains("\"completeness\""));
    assert!(json.contains("\"verdict\""));
    assert!(json.contains("\"findings\""));
}

#[test]
fn report_rejects_unknown_fields() {
    let golden = golden();
    let report = verify(
        &golden.evidence(0).to_json().unwrap(),
        &state(Some(pin(&golden)), Vec::new()),
        None,
    );
    let mut value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    value["extra"] = json!(1);
    assert!(serde_json::from_value::<VerificationReport>(value).is_err());
}
