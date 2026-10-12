//! EvidenceBundle v1 container tests: fail-closed parsing, bounds, and the
//! committed golden vectors (Slice 4 spec §2, §7).

use super::*;
use crate::fixtures::{fixture_dir, golden, golden_files};

fn golden_json() -> String {
    golden().evidence(0).to_json().unwrap()
}

#[test]
fn round_trips_evidence_and_chain_containers() {
    let golden = golden();
    for bundle in [
        golden.evidence(0),
        golden.evidence_with_tail(),
        golden.chain(),
        golden.reset_evidence(),
        golden.evidence_with_witness(),
    ] {
        let json = bundle.to_json().unwrap();
        let parsed = EvidenceBundle::from_json(&json).unwrap();
        assert_eq!(parsed, bundle);
    }
}

#[test]
fn rejects_unknown_schema_version() {
    let mut value: serde_json::Value = serde_json::from_str(&golden_json()).unwrap();
    value["schema_version"] = 2.into();
    let error = EvidenceBundle::from_json(&value.to_string()).unwrap_err();
    assert!(error.to_string().contains("schema_version"));
}

#[test]
fn rejects_missing_or_malformed_schema_version() {
    let mut value: serde_json::Value = serde_json::from_str(&golden_json()).unwrap();
    value.as_object_mut().unwrap().remove("schema_version");
    let error = EvidenceBundle::from_json(&value.to_string()).unwrap_err();
    assert!(error.to_string().contains("schema_version"));

    value["schema_version"] = "1".into();
    let error = EvidenceBundle::from_json(&value.to_string()).unwrap_err();
    assert!(error.to_string().contains("schema_version"));
}

#[test]
fn rejects_unknown_and_missing_kind() {
    let mut value: serde_json::Value = serde_json::from_str(&golden_json()).unwrap();
    value["kind"] = "manifest".into();
    let error = EvidenceBundle::from_json(&value.to_string()).unwrap_err();
    assert!(error.to_string().contains("unknown evidence kind"));

    value.as_object_mut().unwrap().remove("kind");
    let error = EvidenceBundle::from_json(&value.to_string()).unwrap_err();
    assert!(error.to_string().contains("kind"));
}

#[test]
fn rejects_unknown_fields_at_every_level() {
    let top: serde_json::Value = serde_json::from_str(&golden_json()).unwrap();
    let mut value = top.clone();
    value["extra"] = 1.into();
    let error = EvidenceBundle::from_json(&value.to_string()).unwrap_err();
    assert!(error.to_string().contains("unknown fields"));

    // Unknown fields inside each typed section are rejected too.
    for pointer in [
        "/receipt/body",
        "/receipt/proof",
        "/checkpoint",
        "/checkpoint/authorization",
        "/checkpoint/authorization/credentials/0",
        "/approval",
        "/approval/proof",
    ] {
        let mut value = top.clone();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), 1.into());
        let error = EvidenceBundle::from_json(&value.to_string()).unwrap_err();
        assert!(
            error.to_string().contains("unknown fields"),
            "unknown field at {pointer} must be rejected: {error}"
        );
    }
}

#[test]
fn rejects_malformed_json_and_non_objects() {
    assert!(EvidenceBundle::from_json("{not json").is_err());
    assert!(EvidenceBundle::from_json("[]").is_err());
    assert!(EvidenceBundle::from_json("\"evidence\"").is_err());
}

#[test]
fn rejects_oversized_input() {
    let padding = "x".repeat(MAX_EVIDENCE_JSON_LEN + 1);
    let error = EvidenceBundle::from_json(&padding).unwrap_err();
    assert!(error.to_string().contains("size limit"));
}

#[test]
fn rejects_oversized_chain_tail() {
    let golden = golden();
    let EvidenceBundle::Evidence(mut artifact) = golden.evidence(2) else {
        panic!("golden evidence kind");
    };
    artifact.chain_tail = vec![golden.receipts[1].clone(); MAX_CHAIN_TAIL + 1];
    let error = EvidenceBundle::from_json(&EvidenceBundle::Evidence(artifact).to_json().unwrap())
        .unwrap_err();
    assert!(error.to_string().contains("chain_tail"));
}

#[test]
fn rejects_wrong_cose_algorithm_association() {
    let mut value: serde_json::Value = serde_json::from_str(&golden_json()).unwrap();
    value["approval"]["cose_alg"] = (-8).into();
    let error = EvidenceBundle::from_json(&value.to_string()).unwrap_err();
    assert!(error.to_string().contains("ES256"));
}

#[test]
fn rejects_non_hex64_root_fingerprint() {
    let mut value: serde_json::Value = serde_json::from_str(&golden_json()).unwrap();
    value["trust_root_fingerprint"] = "abc".into();
    let error = EvidenceBundle::from_json(&value.to_string()).unwrap_err();
    assert!(error.to_string().contains("trust_root_fingerprint"));
}

#[test]
fn witness_records_parse_and_absence_is_fine() {
    let golden = golden();
    let with = golden.evidence_with_witness();
    let parsed = EvidenceBundle::from_json(&with.to_json().unwrap()).unwrap();
    assert_eq!(parsed, with);
    assert_eq!(crate::verify::parse_witness_records(&parsed).len(), 1);
    let without = golden.evidence(0);
    assert!(crate::verify::parse_witness_records(&without).is_empty());
}

#[test]
fn rejects_oversized_witness_signature() {
    let golden = golden();
    let EvidenceBundle::Evidence(mut artifact) = golden.evidence_with_witness() else {
        panic!("golden evidence kind");
    };
    artifact.witness[0].signature = "x".repeat(20_000);
    let error = EvidenceBundle::from_json(&EvidenceBundle::Evidence(artifact).to_json().unwrap())
        .unwrap_err();
    assert!(error.to_string().contains("witness"));
}

#[test]
fn golden_vectors_are_committed_and_stable() {
    for (name, json) in golden_files() {
        let path = fixture_dir().join(&name);
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("missing golden vector {}: {error}", path.display()));
        assert_eq!(
            committed, json,
            "golden vector {name} drifted; regenerate with \
             `cargo test -p maskura-pipeline-config regenerate_policy_fixtures -- --ignored`"
        );
    }
}

/// Regenerates the committed golden vectors. Run explicitly:
/// `cargo test -p maskura-pipeline-config regenerate_policy_fixtures -- --ignored`
#[test]
#[ignore = "fixture generator"]
fn regenerate_policy_fixtures() {
    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).unwrap();
    for (name, json) in golden_files() {
        std::fs::write(dir.join(&name), json).unwrap();
    }
}
