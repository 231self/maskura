use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};

use super::*;
use crate::{
    effective_state::fixture,
    webauthn::test_support::{TestCredential, UP_UV, assert_proof, challenge, test_credential},
};

fn credential(cred: &TestCredential, epoch: u64) -> TrustCredential {
    TrustCredential::new(
        &cred.credential_id,
        "test",
        B64.encode(cred.cose.to_cose().unwrap()),
        CredentialStatus::Active,
        epoch,
        None,
    )
    .unwrap()
}

fn initial(cred: &TestCredential) -> TrustBundle {
    TrustBundle {
        schema_version: 1,
        workspace_id: "ws-1".into(),
        rp_id: "maskura.dev".into(),
        origins: vec!["https://maskura.dev".into()],
        audience: "https://maskura.dev".into(),
        signer_epoch: 1,
        credentials: vec![credential(cred, 1)],
        trust_resets: vec![],
    }
}

fn genesis_body(root: &TrustBundle) -> ReceiptBody {
    let effective_state = fixture();
    ReceiptBody {
        schema_version: RECEIPT_SCHEMA_VERSION,
        purpose: ReceiptPurpose::PolicyEnvelope,
        action: ReceiptAction::Activate,
        audience: root.audience.clone(),
        workspace_id: root.workspace_id.clone(),
        effective_state_digest: effective_state.digest().unwrap(),
        effective_state,
        envelope_digest: "e".repeat(64),
        envelope_version: 1,
        signer_epoch: 1,
        authority_digest: root.digest().unwrap(),
        seq: 1,
        prev_receipt_sha256: GENESIS_PREV.into(),
        issued_at: 1_100,
        replacement: None,
        replaced_credential_id: None,
    }
}

fn sign(
    body: ReceiptBody,
    cred: &TestCredential,
    replacement: Option<&TestCredential>,
) -> SignedReceipt {
    let mut ctx = challenge(
        body.challenge_kind(),
        &body.workspace_id,
        &body.receipt_digest().unwrap(),
    );
    ctx.issued_at = body.issued_at;
    ctx.expires_at = body.issued_at + 100;
    ctx.nonce = B64.encode([7; 32]);
    let proof = assert_proof(cred, &ctx, "maskura.dev", "https://maskura.dev", UP_UV);
    let counter_proof =
        replacement.map(|new| assert_proof(new, &ctx, "maskura.dev", "https://maskura.dev", UP_UV));
    SignedReceipt {
        body,
        proof,
        counter_proof,
    }
}

fn next(report: &ChainReport) -> ReceiptBody {
    let mut body = genesis_body(&report.authorization);
    body.purpose = ReceiptPurpose::PipelineExport;
    body.signer_epoch = report.authorization.signer_epoch;
    body.seq = report.head_seq + 1;
    body.prev_receipt_sha256 = report.head_receipt_sha256.clone();
    body.envelope_digest = report.envelope_digest.clone();
    body.envelope_version = report.envelope_version;
    body
}

fn rotation(body: ReceiptBody, old: &TestCredential, new: &TestCredential) -> SignedReceipt {
    let mut body = body;
    body.purpose = ReceiptPurpose::SignerAuthority;
    body.action = ReceiptAction::ReplaceSigner;
    body.replacement = Some(credential(new, body.signer_epoch + 1));
    body.replaced_credential_id = Some(old.credential_id.clone());
    sign(body, old, Some(new))
}

#[test]
fn envelope_metadata_is_signed_and_cannot_be_rebased_on_checkpoint() {
    let old = test_credential([7; 32]);
    let root = initial(&old);
    let receipt = sign(genesis_body(&root), &old, None);
    verify_receipt(&receipt, &root).unwrap();
    let mutations: Vec<fn(&mut ReceiptBody)> = vec![
        |b| b.seq = 51,
        |b| b.prev_receipt_sha256 = "a".repeat(64),
        |b| b.envelope_version = 99,
        |b| b.issued_at += 1,
        |b| b.signer_epoch = 2,
        |b| b.envelope_digest = "a".repeat(64),
        |b| b.authority_digest = "a".repeat(64),
    ];
    for change in mutations {
        let mut edited = receipt.clone();
        change(&mut edited.body);
        assert!(verify_receipt(&edited, &root).is_err());
    }
    let report = verify_receipt_chain(std::slice::from_ref(&receipt), &root, None).unwrap();
    let mut replay = receipt;
    replay.body.seq = 2;
    replay.body.prev_receipt_sha256 = report.head_receipt_sha256.clone();
    replay.body.envelope_version = 2;
    replay.body.envelope_digest = "a".repeat(64);
    assert!(verify_receipt_chain(&[replay], &root, Some(&report.checkpoint(1200))).is_err());
}

#[test]
fn rotation_derives_authority_from_pinned_old_key_and_signed_new_key() {
    let old = test_credential([7; 32]);
    let new = test_credential([8; 32]);
    let root = initial(&old);
    let genesis = sign(genesis_body(&root), &old, None);
    let start = verify_receipt_chain(std::slice::from_ref(&genesis), &root, None).unwrap();
    let transition = rotation(next(&start), &old, &new);
    let rotated =
        verify_receipt_chain(&[genesis.clone(), transition.clone()], &root, None).unwrap();
    assert_eq!(rotated.authorization.signer_epoch, 2);
    assert_eq!(rotated.authorization.credentials[0].revoked_epoch, Some(2));
    assert_eq!(
        rotated.authorization.credentials[1].parsed_key().unwrap(),
        new.cose
    );
    let publish = sign(next(&rotated), &new, None);
    let full = verify_receipt_chain(&[genesis, transition, publish.clone()], &root, None).unwrap();
    assert_eq!(full.head_seq, 3);
    let checkpoint =
        Checkpoint::from_json(&serde_json::to_string(&rotated.checkpoint(1200)).unwrap()).unwrap();
    let suffix = verify_receipt_chain(&[publish], &root, Some(&checkpoint)).unwrap();
    assert_eq!(full.head_receipt_sha256, suffix.head_receipt_sha256);
    assert_eq!(full.authorization, suffix.authorization);
    assert!(suffix.extends_checkpoint);
    let idle = verify_receipt_chain(&[], &root, Some(&checkpoint)).unwrap();
    assert_eq!(idle.head_seq, 2);
    assert!(verify_receipt_chain(&[], &root, None).is_err());
}

#[test]
fn replacement_id_and_key_substitution_are_rejected() {
    let old = test_credential([7; 32]);
    let new = test_credential([8; 32]);
    let attacker = test_credential([9; 32]);
    let root = initial(&old);
    let genesis = sign(genesis_body(&root), &old, None);
    let start = verify_receipt_chain(&[genesis], &root, None).unwrap();
    let valid = rotation(next(&start), &old, &new);
    verify_receipt(&valid, &root).unwrap();
    let mut body = valid.body.clone();
    body.replacement.as_mut().unwrap().credential_id = "nonexistent".into();
    let wrong_id = sign(body, &old, Some(&new));
    assert!(
        verify_receipt(&wrong_id, &root)
            .unwrap_err()
            .to_string()
            .contains("exact new credential")
    );
    let mut edited = valid.clone();
    edited.body.replacement.as_mut().unwrap().cose_public_key =
        B64.encode(attacker.cose.to_cose().unwrap());
    // Re-sign only the successor proof: the unchanged old approval must fail.
    let mut counter = sign(edited.body.clone(), &attacker, None).proof;
    counter.credential_id = new.credential_id.clone();
    edited.counter_proof = Some(counter);
    assert!(verify_receipt(&edited, &root).is_err());
    let mut no_counter = valid.clone();
    no_counter.counter_proof = None;
    assert!(verify_receipt(&no_counter, &root).is_err());
    let mut same = valid;
    same.counter_proof = Some(same.proof.clone());
    assert!(verify_receipt(&same, &root).is_err());
}

#[test]
fn epochs_cannot_skip_regress_or_reauthorize_revoked_key() {
    let old = test_credential([7; 32]);
    let new = test_credential([8; 32]);
    let root = initial(&old);
    let genesis = sign(genesis_body(&root), &old, None);
    let start = verify_receipt_chain(std::slice::from_ref(&genesis), &root, None).unwrap();
    let transition = rotation(next(&start), &old, &new);
    let rotated =
        verify_receipt_chain(&[genesis.clone(), transition.clone()], &root, None).unwrap();
    let mut old_epoch = next(&rotated);
    old_epoch.signer_epoch = 1;
    old_epoch.authority_digest = root.digest().unwrap();
    let invalid = sign(old_epoch, &old, None);
    assert!(
        verify_receipt_chain(
            &[genesis.clone(), transition.clone(), invalid.clone()],
            &root,
            None
        )
        .is_err()
    );
    assert!(verify_receipt_chain(&[invalid], &root, Some(&rotated.checkpoint(1200))).is_err());
    let invalid = sign(next(&rotated), &old, None);
    assert!(verify_receipt_chain(&[invalid], &root, Some(&rotated.checkpoint(1200))).is_err());
    let mut skip = next(&start);
    skip.signer_epoch = 2;
    skip.authority_digest = rotated.authorization.digest().unwrap();
    let skip = sign(skip, &new, None);
    assert!(verify_receipt_chain(&[genesis.clone(), skip], &root, None).is_err());
    // An updated bundle cannot substitute for verifying the transition.
    assert!(verify_receipt_chain(&[genesis, transition], &rotated.authorization, None).is_err());
}

#[test]
fn rotation_cannot_change_the_configuration_it_reapproves() {
    let old = test_credential([7; 32]);
    let new = test_credential([8; 32]);
    let root = initial(&old);
    let genesis = sign(genesis_body(&root), &old, None);
    let start = verify_receipt_chain(&[genesis], &root, None).unwrap();
    let mut body = next(&start);
    body.effective_state.routes[0].steps[0].component_sha256 = "b".repeat(64);
    body.effective_state_digest = body.effective_state.digest().unwrap();
    let transition = rotation(body, &old, &new);
    assert!(verify_receipt_chain(&[transition], &root, Some(&start.checkpoint(1200))).is_err());
}

#[test]
fn authorized_backup_retires_the_lost_key_not_itself() {
    let old = test_credential([7; 32]);
    let backup = test_credential([8; 32]);
    let new = test_credential([9; 32]);
    let mut root = initial(&old);
    root.credentials.push(credential(&backup, 1));
    let genesis = sign(genesis_body(&root), &old, None);
    let start = verify_receipt_chain(&[genesis], &root, None).unwrap();
    let mut body = next(&start);
    body.purpose = ReceiptPurpose::SignerAuthority;
    body.action = ReceiptAction::ReplaceSigner;
    body.replacement = Some(credential(&new, 2));
    body.replaced_credential_id = Some(old.credential_id.clone());
    let receipt = sign(body, &backup, Some(&new));
    let report = verify_receipt_chain(&[receipt], &root, Some(&start.checkpoint(1200))).unwrap();
    assert!(
        report
            .authorization
            .authorize(&old.credential_id, 2)
            .is_err()
    );
    assert_eq!(
        report
            .authorization
            .authorize(&backup.credential_id, 2)
            .unwrap(),
        ReceiptStanding::Current
    );
    assert_eq!(
        report
            .authorization
            .authorize(&new.credential_id, 2)
            .unwrap(),
        ReceiptStanding::Current
    );
}

#[test]
fn resolved_state_tamper_fails_even_if_export_metadata_is_unchanged() {
    let old = test_credential([7; 32]);
    let root = initial(&old);
    let signed = sign(genesis_body(&root), &old, None);
    let mut edited = signed.clone();
    edited
        .body
        .effective_state
        .destinations
        .get_mut("dest")
        .unwrap()
        .endpoint = "https://other.example.com".into();
    assert!(verify_receipt(&edited, &root).is_err());
    edited.body.effective_state_digest = edited.body.effective_state.digest().unwrap();
    assert!(verify_receipt(&edited, &root).is_err());
    let mut edited = signed;
    edited.body.effective_state.routes[0].steps[0].component_sha256 = "b".repeat(64);
    edited.body.effective_state_digest = edited.body.effective_state.digest().unwrap();
    assert!(verify_receipt(&edited, &root).is_err());
}

#[test]
fn checkpoint_preserves_envelope_version_and_authorization_boundaries() {
    let old = test_credential([7; 32]);
    let root = initial(&old);
    let mut first = genesis_body(&root);
    first.envelope_version = 10;
    let genesis = sign(first, &old, None);
    let report = verify_receipt_chain(&[genesis], &root, None).unwrap();
    let cp = report.checkpoint(1200);
    let mut lower = next(&report);
    lower.purpose = ReceiptPurpose::PolicyEnvelope;
    lower.envelope_version = 9;
    lower.envelope_digest = "a".repeat(64);
    assert!(verify_receipt_chain(&[sign(lower.clone(), &old, None)], &root, Some(&cp)).is_err());
    lower.envelope_version = 11;
    verify_receipt_chain(&[sign(lower, &old, None)], &root, Some(&cp)).unwrap();
    let mut wrong_root = cp.clone();
    wrong_root.initial_bundle_sha256 = "a".repeat(64);
    assert!(verify_receipt_chain(&[], &root, Some(&wrong_root)).is_err());
    let mut wrong_predecessor = next(&report);
    wrong_predecessor.prev_receipt_sha256 = "a".repeat(64);
    assert!(
        verify_receipt_chain(&[sign(wrong_predecessor, &old, None)], &root, Some(&cp)).is_err()
    );
    let mut gap = next(&report);
    gap.seq += 1;
    assert!(verify_receipt_chain(&[sign(gap, &old, None)], &root, Some(&cp)).is_err());
}

#[test]
fn checked_arithmetic_and_draft_rejection() {
    let old = test_credential([7; 32]);
    let root = initial(&old);
    let genesis = sign(genesis_body(&root), &old, None);
    let report = verify_receipt_chain(std::slice::from_ref(&genesis), &root, None).unwrap();
    let mut cp = report.checkpoint(1200);
    cp.receipt_seq = u64::MAX;
    assert!(
        verify_receipt_chain(std::slice::from_ref(&genesis), &root, Some(&cp))
            .unwrap_err()
            .to_string()
            .contains("overflow")
    );
    let mut body = next(&report);
    body.schema_version = 1;
    assert!(body.validate().is_err());
    let mut json = serde_json::to_value(report.checkpoint(1200)).unwrap();
    json.as_object_mut().unwrap().remove("authorization");
    assert!(Checkpoint::from_json(&json.to_string()).is_err());
}

#[test]
fn invalid_purpose_counter_scope_and_challenge_window_fail_closed() {
    let old = test_credential([7; 32]);
    let root = initial(&old);
    let genesis = sign(genesis_body(&root), &old, None);
    let mut bad = genesis.clone();
    bad.counter_proof = Some(bad.proof.clone());
    assert!(verify_receipt(&bad, &root).is_err());
    let mut bad = genesis.clone();
    bad.body.action = ReceiptAction::Rollback;
    assert!(verify_receipt(&bad, &root).is_err());
    let mut bad = genesis.clone();
    bad.body.workspace_id = "other".into();
    assert!(verify_receipt(&bad, &root).is_err());
    let mut bad = genesis;
    let mut ctx = challenge(
        ChallengeKind::Envelope,
        "ws-1",
        &bad.body.receipt_digest().unwrap(),
    );
    ctx.expires_at = bad.body.issued_at;
    bad.proof = assert_proof(&old, &ctx, "maskura.dev", "https://maskura.dev", UP_UV);
    assert!(verify_receipt(&bad, &root).is_err());
}

#[test]
fn trust_serialization_and_mutation_cannot_leave_stale_verification_keys() {
    let old = test_credential([7; 32]);
    let other = test_credential([8; 32]);
    let root = initial(&old);
    let genesis = sign(genesis_body(&root), &old, None);
    let direct: TrustBundle = serde_json::from_str(&serde_json::to_string(&root).unwrap()).unwrap();
    verify_receipt(&genesis, &direct).unwrap();
    let mut changed = root;
    changed.credentials[0].cose_public_key = B64.encode(other.cose.to_cose().unwrap());
    let parsed = TrustBundle::from_json(&serde_json::to_string(&changed).unwrap()).unwrap();
    assert_eq!(changed.digest().unwrap(), parsed.digest().unwrap());
    assert!(verify_receipt(&genesis, &changed).is_err());
    assert!(verify_receipt(&genesis, &parsed).is_err());
}

#[test]
fn v2_protocol_golden_vectors() {
    let old = test_credential([7; 32]);
    let new = test_credential([8; 32]);
    let root = initial(&old);
    let genesis = sign(genesis_body(&root), &old, None);
    let start = verify_receipt_chain(std::slice::from_ref(&genesis), &root, None).unwrap();
    let transition = rotation(next(&start), &old, &new);
    let report = verify_receipt_chain(&[genesis.clone(), transition.clone()], &root, None).unwrap();
    assert_eq!(
        root.digest().unwrap(),
        "e63aab8dbe12dd363d00d1f27ad6dd4d7bb42176943e78a489db7e9a8232bf4e"
    );
    assert_eq!(
        genesis.body.effective_state_digest,
        "f5d7895b527bd61aa3f4fefc5289ee369921c24451c3066393ffd5edaebdb486"
    );
    assert_eq!(
        genesis.body.receipt_digest().unwrap(),
        "f01425f056518fcf17996fb84ab88339e173b9cedcdc02c8a923b06a73e3470e"
    );
    assert_eq!(
        transition.body.receipt_digest().unwrap(),
        "b55803efd83b83beaf8a8b23d56e5c83dccf9137683749ccab6cb26313812e7a"
    );
    assert_eq!(
        digest_of(&report.checkpoint(1200)).unwrap(),
        "948f74f4a580f85283e03ef8805fe392b3b6c7b188a96264fe4dab2190dc299d"
    );
}
