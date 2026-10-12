//! Deterministic golden-fixture builders shared by the EvidenceBundle and
//! verification test suites, and by the committed interoperability vectors
//! under `tests/fixtures/policy/` (Slice 4 spec §4).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

use crate::effective_state::fixture;
use crate::evidence::{
    ApprovalEvidence, ChainArtifact, EVIDENCE_SCHEMA_VERSION, EvidenceArtifact, EvidenceBundle,
    WitnessAcknowledgement,
};
use crate::receipt::{
    ChainReport, GENESIS_PREV, RECEIPT_SCHEMA_VERSION, ReceiptAction, ReceiptBody, ReceiptPurpose,
    SignedReceipt, verify_receipt_chain,
};
use crate::trust::{Checkpoint, CredentialStatus, TrustBundle, TrustCredential, TrustReset};
use crate::webauthn::test_support::{
    TestCredential, UP_UV, assert_proof, challenge, test_credential,
};

pub(crate) const WORKSPACE: &str = "ws-1";
pub(crate) const RP_ID: &str = "maskura.dev";
pub(crate) const AUDIENCE: &str = "https://maskura.dev";

/// The committed fixture directory (`tests/fixtures/policy/` at the workspace
/// root) shared with the CLI integration suite.
pub(crate) fn fixture_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("policy")
}

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

pub(crate) fn genesis_bundle(cred: &TestCredential, resets: Vec<TrustReset>) -> TrustBundle {
    TrustBundle {
        schema_version: 1,
        workspace_id: WORKSPACE.into(),
        rp_id: RP_ID.into(),
        origins: vec![AUDIENCE.into()],
        audience: AUDIENCE.into(),
        signer_epoch: 1,
        credentials: vec![credential(cred, 1)],
        trust_resets: resets,
    }
}

pub(crate) fn genesis_body(root: &TrustBundle, issued_at: u64) -> ReceiptBody {
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
        signer_epoch: root.signer_epoch,
        authority_digest: root.digest().unwrap(),
        seq: 1,
        prev_receipt_sha256: GENESIS_PREV.into(),
        issued_at,
        replacement: None,
        replaced_credential_id: None,
    }
}

pub(crate) fn next_body(report: &ChainReport, issued_at: u64) -> ReceiptBody {
    let effective_state = fixture();
    ReceiptBody {
        schema_version: RECEIPT_SCHEMA_VERSION,
        purpose: ReceiptPurpose::PipelineExport,
        action: ReceiptAction::Activate,
        audience: report.authorization.audience.clone(),
        workspace_id: report.authorization.workspace_id.clone(),
        effective_state_digest: effective_state.digest().unwrap(),
        effective_state,
        envelope_digest: report.envelope_digest.clone(),
        envelope_version: report.envelope_version,
        signer_epoch: report.authorization.signer_epoch,
        authority_digest: report.authorization.digest().unwrap(),
        seq: report.head_seq + 1,
        prev_receipt_sha256: report.head_receipt_sha256.clone(),
        issued_at,
        replacement: None,
        replaced_credential_id: None,
    }
}

/// Deterministic assertion: fixed nonce per artifact, fixed ceremony window.
pub(crate) fn sign_with(body: ReceiptBody, cred: &TestCredential, nonce_byte: u8) -> SignedReceipt {
    let mut ctx = challenge(
        body.challenge_kind(),
        &body.workspace_id,
        &body.receipt_digest().unwrap(),
    );
    ctx.issued_at = body.issued_at;
    ctx.expires_at = body.issued_at + 100;
    ctx.nonce = B64.encode([nonce_byte; 32]);
    let proof = assert_proof(cred, &ctx, RP_ID, AUDIENCE, UP_UV);
    SignedReceipt {
        body,
        proof,
        counter_proof: None,
    }
}

/// One landed publish approval export (`kind: "evidence"`).
pub(crate) fn evidence_bundle(
    receipt: &SignedReceipt,
    checkpoint: &Checkpoint,
    root_fingerprint: &str,
    chain_tail: Vec<SignedReceipt>,
) -> EvidenceBundle {
    EvidenceBundle::Evidence(EvidenceArtifact {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        workspace_id: receipt.body.workspace_id.clone(),
        trust_root_fingerprint: root_fingerprint.to_string(),
        receipt: receipt.clone(),
        checkpoint: checkpoint.clone(),
        approval: ApprovalEvidence {
            proof: receipt.proof.clone(),
            cose_alg: -7,
        },
        chain_tail,
        witness: Vec::new(),
    })
}

/// The deterministic golden world: a three-receipt publish history on one
/// pinned root, plus an independent post-trust-reset root.
pub(crate) struct Golden {
    pub root: TrustBundle,
    pub root_fingerprint: String,
    pub receipts: Vec<SignedReceipt>,
    pub checkpoints: Vec<Checkpoint>,
    pub reset_root: TrustBundle,
    pub reset_fingerprint: String,
    pub reset_receipt: SignedReceipt,
    pub reset_checkpoint: Checkpoint,
}

impl Golden {
    /// The `kind: "evidence"` export for receipt `index` (0-based).
    pub fn evidence(&self, index: usize) -> EvidenceBundle {
        evidence_bundle(
            &self.receipts[index],
            &self.checkpoints[index],
            &self.root_fingerprint,
            Vec::new(),
        )
    }

    /// The `kind: "evidence"` export for receipt 2 carrying receipt 1 as a
    /// bounded `chain_tail`.
    pub fn evidence_with_tail(&self) -> EvidenceBundle {
        evidence_bundle(
            &self.receipts[2],
            &self.checkpoints[2],
            &self.root_fingerprint,
            vec![self.receipts[1].clone()],
        )
    }

    /// The `kind: "chain"` whole-history export.
    pub fn chain(&self) -> EvidenceBundle {
        EvidenceBundle::Chain(ChainArtifact {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            workspace_id: WORKSPACE.into(),
            trust_root_fingerprint: self.root_fingerprint.clone(),
            receipts: self.receipts.clone(),
            checkpoints: self.checkpoints.clone(),
            witness: Vec::new(),
        })
    }

    /// The post-trust-reset export on a new root.
    pub fn reset_evidence(&self) -> EvidenceBundle {
        evidence_bundle(
            &self.reset_receipt,
            &self.reset_checkpoint,
            &self.reset_fingerprint,
            Vec::new(),
        )
    }

    /// A witness-carrying variant of the first export (spec §6 seam).
    pub fn evidence_with_witness(&self) -> EvidenceBundle {
        let EvidenceBundle::Evidence(mut artifact) = self.evidence(0) else {
            panic!("golden evidence kind");
        };
        artifact.witness = vec![WitnessAcknowledgement {
            witness_id: "witness-1".into(),
            acknowledged_at: 1_150,
            receipt_sha256: artifact.receipt.body.receipt_digest().unwrap(),
            signature: B64.encode([9u8; 64]),
        }];
        EvidenceBundle::Evidence(artifact)
    }
}

pub(crate) fn golden() -> Golden {
    let old = test_credential([7; 32]);
    let root = genesis_bundle(&old, Vec::new());
    let root_fingerprint = root.digest().unwrap();

    let receipt1 = sign_with(genesis_body(&root, 1_100), &old, 1);
    let report1 = verify_receipt_chain(std::slice::from_ref(&receipt1), &root, None).unwrap();
    let checkpoint1 = report1.checkpoint(1_200);

    let receipt2 = sign_with(next_body(&report1, 1_200), &old, 2);
    let report2 =
        verify_receipt_chain(std::slice::from_ref(&receipt2), &root, Some(&checkpoint1)).unwrap();
    let checkpoint2 = report2.checkpoint(1_300);

    let receipt3 = sign_with(next_body(&report2, 1_300), &old, 3);
    let report3 =
        verify_receipt_chain(std::slice::from_ref(&receipt3), &root, Some(&checkpoint2)).unwrap();
    let checkpoint3 = report3.checkpoint(1_400);

    // A recorded trust reset starts a new independently pinned root.
    let reset_cred = test_credential([9; 32]);
    let reset_root = genesis_bundle(
        &reset_cred,
        vec![TrustReset {
            epoch: 1,
            recorded_at: 2_000,
            reason: "all authorized keys lost".into(),
        }],
    );
    let reset_fingerprint = reset_root.digest().unwrap();
    let reset_receipt = sign_with(genesis_body(&reset_root, 2_100), &reset_cred, 4);
    let reset_report =
        verify_receipt_chain(std::slice::from_ref(&reset_receipt), &reset_root, None).unwrap();
    let reset_checkpoint = reset_report.checkpoint(2_200);

    Golden {
        root,
        root_fingerprint,
        receipts: vec![receipt1, receipt2, receipt3],
        checkpoints: vec![checkpoint1, checkpoint2, checkpoint3],
        reset_root,
        reset_fingerprint,
        reset_receipt,
        reset_checkpoint,
    }
}

/// The committed golden vectors: `(file name, JSON text)`.
pub(crate) fn golden_files() -> Vec<(String, String)> {
    let golden = golden();
    vec![
        (
            "trust_root.json".into(),
            serde_json::to_string_pretty(&golden.root).unwrap(),
        ),
        (
            "checkpoint_seq1.json".into(),
            serde_json::to_string_pretty(&golden.checkpoints[0]).unwrap(),
        ),
        (
            "checkpoint_seq2.json".into(),
            serde_json::to_string_pretty(&golden.checkpoints[1]).unwrap(),
        ),
        (
            "checkpoint_seq3.json".into(),
            serde_json::to_string_pretty(&golden.checkpoints[2]).unwrap(),
        ),
        (
            "evidence_seq1.json".into(),
            golden.evidence(0).to_json().unwrap(),
        ),
        (
            "evidence_seq2.json".into(),
            golden.evidence(1).to_json().unwrap(),
        ),
        (
            "evidence_seq3_tail.json".into(),
            golden.evidence_with_tail().to_json().unwrap(),
        ),
        (
            "chain_seq1_to3.json".into(),
            golden.chain().to_json().unwrap(),
        ),
        (
            "evidence_reset_root.json".into(),
            golden.reset_evidence().to_json().unwrap(),
        ),
        (
            "trust_root_reset.json".into(),
            serde_json::to_string_pretty(&golden.reset_root).unwrap(),
        ),
    ]
}
