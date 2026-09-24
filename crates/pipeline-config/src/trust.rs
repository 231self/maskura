//! Versioned customer-pinned trust material (protocol sub-spec §4, §6).
//!
//! The trust bundle and checkpoints live with the customer, not only in
//! Maskura's database: a server-only copy is not an independent trust anchor
//! (R2). This module parses and checks them offline.

use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_cbor, digest_of, is_hex64};
use crate::error::ConfigError;
use crate::receipt::ReceiptStanding;
use crate::webauthn::CoseEs256Key;

/// Trust bundle schema version.
pub const TRUST_BUNDLE_SCHEMA_VERSION: u32 = 1;

/// Checkpoint schema version.
pub const CHECKPOINT_SCHEMA_VERSION: u32 = 2;

/// Whether a credential is currently usable for new approvals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Active,
    Revoked,
}

/// One registered approval credential in the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustCredential {
    pub credential_id: String,
    pub label: String,
    /// Must be `-7` (ES256) in v1; anything else is a parse-time error.
    pub alg: i32,
    /// base64url of the COSE_Key CBOR bytes.
    pub cose_public_key: String,
    pub status: CredentialStatus,
    pub authorized_from_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_epoch: Option<u64>,
}

/// A recorded trust discontinuity. Verifiers must surface these prominently
/// and never present post-reset history as continuity authorized by lost keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustReset {
    pub epoch: u64,
    pub recorded_at: u64,
    pub reason: String,
}

/// The customer-pinned trust root for one workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustBundle {
    pub schema_version: u32,
    pub workspace_id: String,
    pub rp_id: String,
    pub origins: Vec<String>,
    pub audience: String,
    /// The newest authorization epoch covered by this bundle.
    pub signer_epoch: u64,
    pub credentials: Vec<TrustCredential>,
    #[serde(default)]
    pub trust_resets: Vec<TrustReset>,
}

/// A customer-retained chain head for freshness/completeness checks (§6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub schema_version: u32,
    pub workspace_id: String,
    pub receipt_seq: u64,
    /// 64 lowercase hex: `receipt_digest` of the last verified receipt.
    pub receipt_sha256: String,
    pub envelope_digest: String,
    pub envelope_version: u64,
    pub effective_state_digest: String,
    pub initial_bundle_sha256: String,
    /// Independently retained authorization state after the checkpoint receipt.
    pub authorization: TrustBundle,
    pub verified_at: u64,
}

/// Resolved credential with its parsed key.
#[derive(Debug)]
pub struct BundleCredential {
    pub credential_id: String,
    pub status: CredentialStatus,
    pub authorized_from_epoch: u64,
    pub revoked_epoch: Option<u64>,
    pub cose_key: CoseEs256Key,
}

impl TrustCredential {
    pub fn parsed_key(&self) -> Result<CoseEs256Key, ConfigError> {
        if self.alg != -7 || self.cose_public_key.len() > 5464 {
            return Err(ConfigError::invalid(
                "credential must contain a bounded ES256 key",
            ));
        }
        let raw = BASE64URL
            .decode(&self.cose_public_key)
            .map_err(|_| ConfigError::invalid("credential key is not base64url"))?;
        CoseEs256Key::parse_cose(&raw)
    }

    /// Build a credential entry, parsing its COSE key eagerly so hand-built
    /// bundles (tests, importers) match [`TrustBundle::lookup`] expectations.
    pub fn new(
        credential_id: impl Into<String>,
        label: impl Into<String>,
        cose_public_key: impl Into<String>,
        status: CredentialStatus,
        authorized_from_epoch: u64,
        revoked_epoch: Option<u64>,
    ) -> Result<Self, ConfigError> {
        let credential_id = credential_id.into();
        let cose_public_key = cose_public_key.into();
        let raw = BASE64URL.decode(&cose_public_key).map_err(|error| {
            ConfigError::invalid(format!(
                "credential {credential_id:?} cose_public_key is not base64url: {error}"
            ))
        })?;
        CoseEs256Key::parse_cose(&raw)?;
        Ok(Self {
            credential_id,
            label: label.into(),
            alg: -7,
            cose_public_key,
            status,
            authorized_from_epoch,
            revoked_epoch,
        })
    }
}

impl TrustBundle {
    /// Parse from the versioned JSON representation and validate structure.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let bundle: TrustBundle = serde_json::from_str(json).map_err(|error| {
            ConfigError::invalid(format!("trust bundle is not valid JSON: {error}"))
        })?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Structural validation (sub-spec §4).
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != TRUST_BUNDLE_SCHEMA_VERSION {
            return Err(ConfigError::invalid(format!(
                "unsupported trust bundle schema_version {}; expected {TRUST_BUNDLE_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.workspace_id.trim().is_empty() {
            return Err(ConfigError::invalid(
                "trust bundle workspace_id must not be empty",
            ));
        }
        if self.rp_id.trim().is_empty() {
            return Err(ConfigError::invalid("trust bundle rp_id must not be empty"));
        }
        if self.origins.is_empty() {
            return Err(ConfigError::invalid(
                "trust bundle origins must not be empty",
            ));
        }
        for origin in &self.origins {
            let url = url::Url::parse(origin)
                .map_err(|_| ConfigError::invalid("invalid trust origin"))?;
            if url.scheme() != "https"
                || url.origin().ascii_serialization() != *origin
                || url.host_str().is_none_or(|host| {
                    host != self.rp_id && !host.ends_with(&format!(".{}", self.rp_id))
                })
            {
                return Err(ConfigError::invalid(
                    "trust origin must be an exact HTTPS origin scoped to the RP",
                ));
            }
        }
        if self.audience.trim().is_empty() {
            return Err(ConfigError::invalid(
                "trust bundle audience must not be empty",
            ));
        }
        if self.signer_epoch < 1 {
            return Err(ConfigError::invalid(
                "trust bundle signer_epoch must be >= 1",
            ));
        }

        let mut ids = BTreeSet::new();
        for credential in &self.credentials {
            credential.parsed_key()?;
            if credential.credential_id.trim().is_empty() {
                return Err(ConfigError::invalid(
                    "trust bundle credential_id must not be empty",
                ));
            }
            if !ids.insert(&credential.credential_id) {
                return Err(ConfigError::invalid(format!(
                    "trust bundle contains duplicate credential {:?}",
                    credential.credential_id
                )));
            }
            if credential.alg != -7 {
                return Err(ConfigError::invalid(format!(
                    "trust bundle credential alg {} must be -7 (ES256) in v1",
                    credential.alg
                )));
            }
            if credential.label.trim().is_empty() {
                return Err(ConfigError::invalid(
                    "trust bundle credential label must not be empty",
                ));
            }
            if credential.authorized_from_epoch < 1 {
                return Err(ConfigError::invalid(
                    "credential authorized_from_epoch must be >= 1",
                ));
            }
            match credential.status {
                CredentialStatus::Active => {
                    if credential.revoked_epoch.is_some() {
                        return Err(ConfigError::invalid(
                            "active credentials must not carry revoked_epoch",
                        ));
                    }
                }
                CredentialStatus::Revoked => {
                    let revoked = credential.revoked_epoch.ok_or_else(|| {
                        ConfigError::invalid("revoked credentials require revoked_epoch")
                    })?;
                    if revoked <= credential.authorized_from_epoch {
                        return Err(ConfigError::invalid(
                            "revoked_epoch must be greater than authorized_from_epoch",
                        ));
                    }
                    if revoked > self.signer_epoch {
                        return Err(ConfigError::invalid("revocation exceeds bundle epoch"));
                    }
                }
            }
            if credential.authorized_from_epoch > self.signer_epoch {
                return Err(ConfigError::invalid(format!(
                    "credential {:?} is authorized after the bundle's signer_epoch",
                    credential.credential_id
                )));
            }
        }
        for reset in &self.trust_resets {
            if reset.reason.trim().is_empty() {
                return Err(ConfigError::invalid("trust reset reason must not be empty"));
            }
            if reset.epoch < 1 {
                return Err(ConfigError::invalid("trust reset epoch must be >= 1"));
            }
        }
        Ok(())
    }

    /// Canonical digest of the bundle, printed as its fingerprint.
    pub fn digest(&self) -> Result<String, ConfigError> {
        self.validate()?;
        digest_of(self)
    }

    /// Resolve a credential by id for assertion verification.
    pub fn lookup(&self, credential_id: &str) -> Result<BundleCredential, ConfigError> {
        self.validate()?;
        let credential = self
            .credentials
            .iter()
            .find(|credential| credential.credential_id == credential_id)
            .ok_or_else(|| {
                ConfigError::approval(format!(
                    "credential not in bundle (unknown or pre-reset): {credential_id}"
                ))
            })?;
        Ok(BundleCredential {
            credential_id: credential.credential_id.clone(),
            status: credential.status,
            authorized_from_epoch: credential.authorized_from_epoch,
            revoked_epoch: credential.revoked_epoch,
            cose_key: credential.parsed_key()?,
        })
    }

    /// Authorize a credential at `epoch` for an approval. Returns whether the
    /// approval is current against this bundle or only historically valid.
    pub fn authorize(
        &self,
        credential_id: &str,
        epoch: u64,
    ) -> Result<ReceiptStanding, ConfigError> {
        let credential = self.lookup(credential_id)?;
        if epoch > self.signer_epoch {
            return Err(ConfigError::approval(format!(
                "receipt signer_epoch {epoch} exceeds the bundle signer_epoch {}",
                self.signer_epoch
            )));
        }
        if epoch < credential.authorized_from_epoch {
            return Err(ConfigError::approval(format!(
                "credential {credential_id} was not authorized at epoch {epoch}"
            )));
        }
        if let Some(revoked) = credential.revoked_epoch
            && epoch >= revoked
        {
            return Err(ConfigError::approval(format!(
                "credential {credential_id} was revoked at epoch {revoked}"
            )));
        }
        let current = credential.status == CredentialStatus::Active && epoch == self.signer_epoch;
        Ok(if current {
            ReceiptStanding::Current
        } else {
            ReceiptStanding::Historical
        })
    }
}

impl Checkpoint {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CHECKPOINT_SCHEMA_VERSION {
            return Err(ConfigError::invalid(format!(
                "unsupported checkpoint schema_version {}; expected {CHECKPOINT_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.workspace_id.trim().is_empty() {
            return Err(ConfigError::invalid(
                "checkpoint workspace_id must not be empty",
            ));
        }
        if self.receipt_seq < 1 {
            return Err(ConfigError::invalid("checkpoint receipt_seq must be >= 1"));
        }
        if !is_hex64(&self.receipt_sha256) {
            return Err(ConfigError::invalid(
                "checkpoint receipt_sha256 must be 64 lowercase hex",
            ));
        }
        if !is_hex64(&self.envelope_digest) {
            return Err(ConfigError::invalid(
                "checkpoint envelope_digest must be 64 lowercase hex",
            ));
        }
        if self.envelope_version == 0
            || !is_hex64(&self.effective_state_digest)
            || !is_hex64(&self.initial_bundle_sha256)
            || self.authorization.workspace_id != self.workspace_id
        {
            return Err(ConfigError::invalid(
                "checkpoint lacks consistent policy and authorization state",
            ));
        }
        self.authorization.validate()?;
        Ok(())
    }

    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let checkpoint: Checkpoint = serde_json::from_str(json).map_err(|error| {
            ConfigError::invalid(format!("checkpoint is not valid JSON: {error}"))
        })?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }
}

/// Parse a trust bundle from its JSON text.
pub fn parse_trust_bundle_json(json: &str) -> Result<TrustBundle, ConfigError> {
    TrustBundle::from_json(json)
}

/// Canonical-CBOR encode helper re-exported for fingerprint tooling.
pub fn trust_bundle_cbor(bundle: &TrustBundle) -> Result<Vec<u8>, ConfigError> {
    canonical_cbor(bundle)
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;

    use crate::webauthn::test_support::test_credential;

    use super::*;

    fn cose_of(seed: [u8; 32]) -> String {
        let cred = test_credential(seed);
        BASE64URL.encode(cred.cose.to_cose().unwrap())
    }

    fn bundle_json(seed: [u8; 32]) -> String {
        let cred = test_credential(seed);
        serde_json::json!({
            "schema_version": 1,
            "workspace_id": "ws-1",
            "rp_id": "maskura.dev",
            "origins": ["https://maskura.dev"],
            "audience": "https://maskura.dev",
            "signer_epoch": 1,
            "credentials": [{
                "credential_id": cred.credential_id,
                "label": "laptop",
                "alg": -7,
                "cose_public_key": BASE64URL.encode(cred.cose.to_cose().unwrap()),
                "status": "active",
                "authorized_from_epoch": 1,
            }],
            "trust_resets": [],
        })
        .to_string()
    }

    #[test]
    fn parses_and_digests_a_valid_bundle() {
        let bundle = TrustBundle::from_json(&bundle_json([7u8; 32])).unwrap();
        assert_eq!(bundle.credentials.len(), 1);
        let digest = bundle.digest().unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, bundle.digest().unwrap());
    }

    #[test]
    fn serde_and_constructor_resolve_identical_keys() {
        let json = bundle_json([7; 32]);
        let parsed = TrustBundle::from_json(&json).unwrap();
        let direct: TrustBundle = serde_json::from_str(&json).unwrap();
        direct.validate().unwrap();
        let id = &parsed.credentials[0].credential_id;
        assert_eq!(
            parsed.lookup(id).unwrap().cose_key,
            direct.lookup(id).unwrap().cose_key
        );
        assert_eq!(parsed.digest().unwrap(), direct.digest().unwrap());
    }

    #[test]
    fn mutable_serialized_key_is_always_the_verification_key() {
        let mut bundle = TrustBundle::from_json(&bundle_json([7; 32])).unwrap();
        let id = bundle.credentials[0].credential_id.clone();
        let old = bundle.lookup(&id).unwrap().cose_key;
        bundle.credentials[0].cose_public_key = cose_of([8; 32]);
        let reparsed = TrustBundle::from_json(&serde_json::to_string(&bundle).unwrap()).unwrap();
        assert_ne!(bundle.lookup(&id).unwrap().cose_key, old);
        assert_eq!(
            bundle.lookup(&id).unwrap().cose_key,
            reparsed.lookup(&id).unwrap().cose_key
        );
        assert_eq!(bundle.digest().unwrap(), reparsed.digest().unwrap());
        bundle.credentials[0].alg = -8;
        assert!(bundle.lookup(&id).is_err());
    }

    #[test]
    fn digest_changes_with_epoch() {
        let mut bundle = TrustBundle::from_json(&bundle_json([7u8; 32])).unwrap();
        let before = bundle.digest().unwrap();
        bundle.signer_epoch = 2;
        // credential authorized_from must stay <= signer_epoch (validate not
        // re-run for digest); digest covers serialized form
        let after = bundle.digest().unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let mut json: serde_json::Value = serde_json::from_str(&bundle_json([7u8; 32])).unwrap();
        json["schema_version"] = 2.into();
        let error = TrustBundle::from_json(&json.to_string()).unwrap_err();
        assert!(error.to_string().contains("schema_version"));
    }

    #[test]
    fn rejects_non_es256_alg_field() {
        let mut json: serde_json::Value = serde_json::from_str(&bundle_json([7u8; 32])).unwrap();
        json["credentials"][0]["alg"] = (-8).into();
        let error = TrustBundle::from_json(&json.to_string()).unwrap_err();
        assert!(error.to_string().contains("ES256"));
    }

    #[test]
    fn rejects_duplicate_credential_ids() {
        let mut json: serde_json::Value = serde_json::from_str(&bundle_json([7u8; 32])).unwrap();
        let dup = json["credentials"][0].clone();
        json["credentials"].as_array_mut().unwrap().push(dup);
        let error = TrustBundle::from_json(&json.to_string()).unwrap_err();
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn revoked_credential_requires_epoch() {
        let mut json: serde_json::Value = serde_json::from_str(&bundle_json([7u8; 32])).unwrap();
        json["credentials"][0]["status"] = "revoked".into();
        let error = TrustBundle::from_json(&json.to_string()).unwrap_err();
        assert!(error.to_string().contains("revoked_epoch"));
    }

    #[test]
    fn revoked_epoch_must_exceed_authorization_epoch() {
        let mut json: serde_json::Value = serde_json::from_str(&bundle_json([7u8; 32])).unwrap();
        json["credentials"][0]["status"] = "revoked".into();
        json["credentials"][0]["revoked_epoch"] = 1.into();
        let error = TrustBundle::from_json(&json.to_string()).unwrap_err();
        assert!(error.to_string().contains("greater"));
    }

    #[test]
    fn active_credential_must_not_carry_revoked_epoch() {
        let mut json: serde_json::Value = serde_json::from_str(&bundle_json([7u8; 32])).unwrap();
        json["credentials"][0]["revoked_epoch"] = 2.into();
        let error = TrustBundle::from_json(&json.to_string()).unwrap_err();
        assert!(error.to_string().contains("active"));
    }

    #[test]
    fn empty_origins_rejected() {
        let mut json: serde_json::Value = serde_json::from_str(&bundle_json([7u8; 32])).unwrap();
        json["origins"] = serde_json::json!([]);
        let error = TrustBundle::from_json(&json.to_string()).unwrap_err();
        assert!(error.to_string().contains("origins"));
    }

    #[test]
    fn epoch_authorization_matrix() {
        let mut json: serde_json::Value = serde_json::from_str(&bundle_json([7u8; 32])).unwrap();
        json["signer_epoch"] = 3.into();
        json["credentials"][0]["revoked_epoch"] = 3.into();
        json["credentials"][0]["status"] = "revoked".into();
        let bundle = TrustBundle::from_json(&json.to_string()).unwrap();
        let id = bundle.credentials[0].credential_id.clone();

        // before authorized_from
        let mut early = json.clone();
        early["credentials"][0]["authorized_from_epoch"] = 2.into();
        early["credentials"][0]["revoked_epoch"] = 3.into();
        let early_bundle = TrustBundle::from_json(&early.to_string()).unwrap();
        early_bundle.authorize(&id, 1).unwrap_err();
        // at authorized_from
        early_bundle.authorize(&id, 2).unwrap();
        // at revoked_epoch: rejected
        early_bundle.authorize(&id, 3).unwrap_err();
        // beyond bundle epoch: rejected even before revocation check
        bundle.authorize(&id, 4).unwrap_err();
    }

    #[test]
    fn authorize_reports_historical_for_superseded_active_credential() {
        let mut json: serde_json::Value = serde_json::from_str(&bundle_json([7u8; 32])).unwrap();
        json["signer_epoch"] = 2.into();
        // credential stays active from epoch 1 but epoch 1 < bundle epoch 2
        let bundle = TrustBundle::from_json(&json.to_string()).unwrap();
        let id = bundle.credentials[0].credential_id.clone();
        assert_eq!(
            bundle.authorize(&id, 1).unwrap(),
            ReceiptStanding::Historical
        );
        assert_eq!(bundle.authorize(&id, 2).unwrap(), ReceiptStanding::Current);
    }

    #[test]
    fn unknown_credential_reports_not_in_bundle() {
        let bundle = TrustBundle::from_json(&bundle_json([7u8; 32])).unwrap();
        let error = bundle.lookup("missing").unwrap_err();
        assert!(error.to_string().contains("not in bundle"));
    }

    #[test]
    fn checkpoint_validation_matrix() {
        let authority = TrustBundle::from_json(&bundle_json([7; 32])).unwrap();
        let checkpoint = Checkpoint {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            workspace_id: "ws-1".to_string(),
            receipt_seq: 42,
            receipt_sha256: "a".repeat(64),
            envelope_digest: "b".repeat(64),
            envelope_version: 1,
            effective_state_digest: "c".repeat(64),
            initial_bundle_sha256: authority.digest().unwrap(),
            authorization: authority,
            verified_at: 1_000,
        };
        checkpoint.validate().unwrap();

        let mut bad = checkpoint.clone();
        bad.receipt_seq = 0;
        assert!(bad.validate().is_err());

        let mut bad = checkpoint.clone();
        bad.receipt_sha256 = "short".to_string();
        assert!(bad.validate().is_err());

        let mut bad = checkpoint.clone();
        bad.schema_version = 9;
        assert!(bad.validate().is_err());

        // JSON round trip
        let json = serde_json::to_string(&checkpoint).unwrap();
        Checkpoint::from_json(&json).unwrap();
    }

    #[test]
    fn trust_reset_entries_must_have_reason_and_epoch() {
        let mut json: serde_json::Value = serde_json::from_str(&bundle_json([7u8; 32])).unwrap();
        json["trust_resets"] = serde_json::json!([{
            "epoch": 1, "recorded_at": 100, "reason": ""
        }]);
        let error = TrustBundle::from_json(&json.to_string()).unwrap_err();
        assert!(error.to_string().contains("reason"));

        json["trust_resets"] = serde_json::json!([{
            "epoch": 0, "recorded_at": 100, "reason": "lost keys"
        }]);
        let error = TrustBundle::from_json(&json.to_string()).unwrap_err();
        assert!(error.to_string().contains("epoch"));
    }

    #[test]
    fn credential_after_bundle_epoch_is_rejected() {
        let mut json: serde_json::Value = serde_json::from_str(&bundle_json([7u8; 32])).unwrap();
        json["credentials"][0]["authorized_from_epoch"] = 2.into();
        // signer_epoch stays 1
        let error = TrustBundle::from_json(&json.to_string()).unwrap_err();
        assert!(error.to_string().contains("signer_epoch"));
    }

    #[test]
    fn garbage_json_is_rejected() {
        assert!(TrustBundle::from_json("{not json").is_err());
        assert!(Checkpoint::from_json("{not json").is_err());
    }
}
