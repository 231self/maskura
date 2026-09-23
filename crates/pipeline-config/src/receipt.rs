//! Approval statements and ordered authorization transitions. These verify
//! customer intent relative to pinned trust, not remote execution or freshness.
use serde::{Deserialize, Serialize};

use crate::{
    ConfigError, EffectiveState,
    canonical::{canonical_cbor, digest_of, is_hex64},
    trust::{Checkpoint, CredentialStatus, TrustBundle, TrustCredential},
    webauthn::{AssertionExpectation, ChallengeKind, WebAuthnProof, verify_assertion},
};

/// Version 2 rejects the unshipped draft's partially signed envelope receipts.
pub const RECEIPT_SCHEMA_VERSION: u32 = 2;
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptPurpose {
    PipelineExport,
    PolicyEnvelope,
    SignerAuthority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptAction {
    Activate,
    Rollback,
    ReplaceSigner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptBody {
    pub schema_version: u32,
    pub purpose: ReceiptPurpose,
    pub action: ReceiptAction,
    pub audience: String,
    pub workspace_id: String,
    pub effective_state: EffectiveState,
    pub effective_state_digest: String,
    pub envelope_digest: String,
    pub envelope_version: u64,
    pub signer_epoch: u64,
    /// Digest of the trusted authorization state immediately before activation.
    pub authority_digest: String,
    pub seq: u64,
    pub prev_receipt_sha256: String,
    /// Frozen at begin; not an independently trusted completion timestamp.
    pub issued_at: u64,
    /// Complete replacement authority, including the public key, signed by both keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement: Option<TrustCredential>,
    /// Credential being retired; an authorized backup may approve its replacement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_credential_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReceipt {
    pub body: ReceiptBody,
    pub proof: WebAuthnProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter_proof: Option<WebAuthnProof>,
}

/// Credential validity relative to a caller-pinned epoch, never proof of latest history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptStanding {
    Current,
    Historical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    pub head_seq: u64,
    pub head_receipt_sha256: String,
    pub envelope_digest: String,
    pub envelope_version: u64,
    pub effective_state_digest: String,
    pub initial_bundle_sha256: String,
    pub authorization: TrustBundle,
    pub receipt_count: usize,
    pub extends_checkpoint: bool,
}

impl ChainReport {
    /// Persist locally only after successful verification; do not trust a
    /// checkpoint downloaded from the service as an independent anchor.
    pub fn checkpoint(&self, verified_at: u64) -> Checkpoint {
        Checkpoint {
            schema_version: crate::trust::CHECKPOINT_SCHEMA_VERSION,
            workspace_id: self.authorization.workspace_id.clone(),
            receipt_seq: self.head_seq,
            receipt_sha256: self.head_receipt_sha256.clone(),
            envelope_digest: self.envelope_digest.clone(),
            envelope_version: self.envelope_version,
            effective_state_digest: self.effective_state_digest.clone(),
            initial_bundle_sha256: self.initial_bundle_sha256.clone(),
            authorization: self.authorization.clone(),
            verified_at,
        }
    }
}

impl ReceiptBody {
    pub fn canonical_body(&self) -> Result<Vec<u8>, ConfigError> {
        self.validate()?;
        canonical_cbor(self)
    }

    pub fn receipt_digest(&self) -> Result<String, ConfigError> {
        self.validate()?;
        digest_of(self)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != RECEIPT_SCHEMA_VERSION
            || self.seq == 0
            || self.signer_epoch == 0
            || self.envelope_version == 0
        {
            return Err(ConfigError::invalid(
                "unsupported receipt version or zero sequence/epoch/version",
            ));
        }
        if self.workspace_id.trim().is_empty()
            || self.audience.trim().is_empty()
            || self.effective_state.workspace_id != self.workspace_id
            || self.effective_state.audience != self.audience
        {
            return Err(ConfigError::invalid(
                "receipt and effective-state scopes must match",
            ));
        }
        for hash in [
            &self.effective_state_digest,
            &self.envelope_digest,
            &self.authority_digest,
            &self.prev_receipt_sha256,
        ] {
            if !is_hex64(hash) {
                return Err(ConfigError::invalid(
                    "receipt digests must be lowercase SHA-256 hex",
                ));
            }
        }
        if self.effective_state.digest()? != self.effective_state_digest {
            return Err(ConfigError::invalid(
                "effective-state digest does not match resolved state",
            ));
        }
        match (self.purpose, self.action) {
            (ReceiptPurpose::PipelineExport, ReceiptAction::Activate | ReceiptAction::Rollback)
            | (ReceiptPurpose::PolicyEnvelope, ReceiptAction::Activate)
                if self.replacement.is_none() && self.replaced_credential_id.is_none() => {}
            (ReceiptPurpose::SignerAuthority, ReceiptAction::ReplaceSigner) => {
                let next = self
                    .signer_epoch
                    .checked_add(1)
                    .ok_or_else(|| ConfigError::invalid("authorization epoch overflow"))?;
                let replacement = self.replacement.as_ref().ok_or_else(|| {
                    ConfigError::invalid("signer transition requires replacement authority")
                })?;
                if self
                    .replaced_credential_id
                    .as_deref()
                    .is_none_or(|id| id.trim().is_empty())
                {
                    return Err(ConfigError::invalid(
                        "signer transition must identify the retired credential",
                    ));
                }
                replacement.parsed_key()?;
                if replacement.credential_id.trim().is_empty()
                    || replacement.label.trim().is_empty()
                    || replacement.status != CredentialStatus::Active
                    || replacement.revoked_epoch.is_some()
                    || replacement.authorized_from_epoch != next
                {
                    return Err(ConfigError::invalid(
                        "invalid replacement authority or successor epoch",
                    ));
                }
            }
            _ => {
                return Err(ConfigError::invalid(
                    "invalid receipt purpose/action/fields",
                ));
            }
        }
        Ok(())
    }

    fn challenge_kind(&self) -> ChallengeKind {
        match self.purpose {
            ReceiptPurpose::PolicyEnvelope => ChallengeKind::Envelope,
            ReceiptPurpose::PipelineExport => ChallengeKind::Receipt,
            ReceiptPurpose::SignerAuthority => ChallengeKind::Signer,
        }
    }
}

/// Verify against the trusted pre-activation authority. No authority is taken
/// from an updated server-supplied bundle. The chain reducer applies transitions.
pub fn verify_receipt(
    receipt: &SignedReceipt,
    authority: &TrustBundle,
) -> Result<ReceiptStanding, ConfigError> {
    authority.validate()?;
    let body = &receipt.body;
    body.validate()?;
    if body.workspace_id != authority.workspace_id
        || body.audience != authority.audience
        || body.signer_epoch != authority.signer_epoch
        || body.authority_digest != authority.digest()?
    {
        return Err(ConfigError::approval(
            "receipt does not extend the trusted authorization state",
        ));
    }
    if authority.authorize(&receipt.proof.credential_id, body.signer_epoch)?
        != ReceiptStanding::Current
    {
        return Err(ConfigError::approval(
            "approver is not currently authorized",
        ));
    }
    let expected = AssertionExpectation {
        kind: body.challenge_kind(),
        audience: body.audience.clone(),
        workspace_id: body.workspace_id.clone(),
        artifact_digest: body.receipt_digest()?,
        rp_id: authority.rp_id.clone(),
        origins: authority.origins.clone(),
    };
    let key = authority.lookup(&receipt.proof.credential_id)?.cose_key;
    verify_approval(&receipt.proof, &expected, &key, body.issued_at)?;

    match &body.replacement {
        Some(replacement) => {
            let retired = body
                .replaced_credential_id
                .as_deref()
                .ok_or_else(|| ConfigError::approval("missing retired credential"))?;
            if authority.authorize(retired, body.signer_epoch)? != ReceiptStanding::Current {
                return Err(ConfigError::approval(
                    "retired credential is not in the current authority",
                ));
            }
            let counter = receipt
                .counter_proof
                .as_ref()
                .ok_or_else(|| ConfigError::approval("replacement requires counter-proof"))?;
            if counter.credential_id != replacement.credential_id
                || counter.credential_id == receipt.proof.credential_id
                || authority
                    .credentials
                    .iter()
                    .any(|c| c.credential_id == replacement.credential_id)
            {
                return Err(ConfigError::approval(
                    "counter-proof must match the exact new credential",
                ));
            }
            let new_key = replacement.parsed_key()?;
            for credential in &authority.credentials {
                if credential.parsed_key()? == new_key {
                    return Err(ConfigError::approval(
                        "replacement must use a new public key",
                    ));
                }
            }
            verify_approval(counter, &expected, &new_key, body.issued_at)?;
        }
        None if receipt.counter_proof.is_some() => {
            return Err(ConfigError::approval("unexpected counter-proof"));
        }
        None => {}
    }
    Ok(ReceiptStanding::Current)
}

fn verify_approval(
    proof: &WebAuthnProof,
    expected: &AssertionExpectation,
    key: &crate::CoseEs256Key,
    issued_at: u64,
) -> Result<(), ConfigError> {
    let context = verify_assertion(proof, expected, key)?;
    // This checks signed timestamp consistency only. Live completion must
    // separately compare server time and atomically consume its stored challenge.
    if context.issued_at > issued_at || issued_at >= context.expires_at {
        return Err(ConfigError::approval(
            "receipt timestamp outside challenge window",
        ));
    }
    Ok(())
}

/// Verify a full chain from pinned genesis authority, or a suffix from an
/// independently retained checkpoint. Signature validity never implies freshness.
pub fn verify_receipt_chain(
    receipts: &[SignedReceipt],
    initial: &TrustBundle,
    checkpoint: Option<&Checkpoint>,
) -> Result<ChainReport, ConfigError> {
    initial.validate()?;
    if initial.signer_epoch != 1
        || initial.credentials.is_empty()
        || initial
            .credentials
            .iter()
            .any(|c| c.status != CredentialStatus::Active || c.authorized_from_epoch != 1)
    {
        return Err(ConfigError::approval(
            "full trust anchor must be the pinned genesis authority",
        ));
    }
    let root = initial.digest()?;
    let (mut authority, mut seq, mut head, mut envelope, mut version, mut state) = match checkpoint
    {
        Some(cp) => {
            cp.validate()?;
            if cp.initial_bundle_sha256 != root
                || cp.workspace_id != initial.workspace_id
                || cp.authorization.audience != initial.audience
                || cp.authorization.rp_id != initial.rp_id
                || cp.authorization.origins != initial.origins
                || cp.authorization.trust_resets != initial.trust_resets
            {
                return Err(ConfigError::approval(
                    "checkpoint does not belong to pinned trust history",
                ));
            }
            (
                cp.authorization.clone(),
                cp.receipt_seq,
                cp.receipt_sha256.clone(),
                cp.envelope_digest.clone(),
                cp.envelope_version,
                cp.effective_state_digest.clone(),
            )
        }
        None => (
            initial.clone(),
            0,
            GENESIS_PREV.into(),
            String::new(),
            0,
            String::new(),
        ),
    };
    if receipts.is_empty() && checkpoint.is_none() {
        return Err(ConfigError::approval(
            "receipt chain must not be empty without a checkpoint",
        ));
    }
    for receipt in receipts {
        let body = &receipt.body;
        let next = seq
            .checked_add(1)
            .ok_or_else(|| ConfigError::approval("receipt sequence overflow"))?;
        if body.seq != next || body.prev_receipt_sha256 != head {
            return Err(ConfigError::approval(
                "receipt sequence or predecessor mismatch",
            ));
        }
        if body.purpose == ReceiptPurpose::PolicyEnvelope {
            if body.envelope_version <= version || body.envelope_digest == envelope {
                return Err(ConfigError::approval(
                    "envelope rotation must advance version and artifact",
                ));
            }
        } else if version == 0
            || body.envelope_digest != envelope
            || body.envelope_version != version
        {
            return Err(ConfigError::approval(
                "envelope must be activated first and changed only by rotation",
            ));
        }
        if body.purpose == ReceiptPurpose::SignerAuthority && body.effective_state_digest != state {
            return Err(ConfigError::approval(
                "replacement must re-approve the current resolved configuration",
            ));
        }
        verify_receipt(receipt, &authority)?;
        if let Some(replacement) = &body.replacement {
            authority.signer_epoch = body
                .signer_epoch
                .checked_add(1)
                .ok_or_else(|| ConfigError::approval("authorization epoch overflow"))?;
            let old = authority
                .credentials
                .iter_mut()
                .find(|c| Some(c.credential_id.as_str()) == body.replaced_credential_id.as_deref())
                .ok_or_else(|| ConfigError::approval("unknown transition authorizer"))?;
            old.status = CredentialStatus::Revoked;
            old.revoked_epoch = Some(authority.signer_epoch);
            authority.credentials.push(replacement.clone());
            authority.validate()?;
        }
        seq = body.seq;
        head = body.receipt_digest()?;
        envelope = body.envelope_digest.clone();
        version = body.envelope_version;
        state = body.effective_state_digest.clone();
    }
    Ok(ChainReport {
        head_seq: seq,
        head_receipt_sha256: head,
        envelope_digest: envelope,
        envelope_version: version,
        effective_state_digest: state,
        initial_bundle_sha256: root,
        authorization: authority,
        receipt_count: receipts.len(),
        extends_checkpoint: checkpoint.is_some(),
    })
}

pub fn receipt_body_hash(body: &ReceiptBody) -> Result<String, ConfigError> {
    body.receipt_digest()
}

#[cfg(test)]
#[path = "receipt_tests.rs"]
mod tests;
