use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::ConfigError;
use crate::schema::PipelineFile;

/// Ed25519 public keys trusted to author pipeline files, indexed by signer id.
pub type TrustRoots = BTreeMap<String, VerifyingKey>;

/// Parse `signer_id=hex-public-key` entries, separated by `;` or `,`, into a
/// trust-root map. Empty entries are ignored.
pub fn parse_trust_roots(raw: &str) -> Result<TrustRoots, ConfigError> {
    let mut roots = TrustRoots::new();
    for entry in raw.split([';', ',']) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (signer_id, key_hex) = entry.split_once('=').ok_or_else(|| {
            ConfigError::invalid(format!(
                "trust root {entry:?} must be formatted as signer_id=hex-public-key"
            ))
        })?;
        let signer_id = signer_id.trim();
        if signer_id.is_empty() {
            return Err(ConfigError::invalid(format!(
                "trust root {entry:?} has an empty signer id"
            )));
        }
        let raw_key = hex::decode(key_hex.trim()).map_err(|error| {
            ConfigError::invalid(format!(
                "trust root {signer_id:?} public key is not valid hex: {error}"
            ))
        })?;
        let bytes: [u8; 32] = raw_key.try_into().map_err(|_| {
            ConfigError::invalid(format!(
                "trust root {signer_id:?} public key must be 32 bytes"
            ))
        })?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|error| {
            ConfigError::invalid(format!(
                "trust root {signer_id:?} public key is invalid: {error}"
            ))
        })?;
        roots.insert(signer_id.to_string(), key);
    }
    Ok(roots)
}

impl PipelineFile {
    /// Canonical signed body: the parsed model without the `signature` field,
    /// JSON-normalized (sorted keys) and encoded as canonical CBOR. TOML
    /// whitespace and comments are therefore not part of the signed body.
    pub fn canonical_body(&self) -> Result<Vec<u8>, ConfigError> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        let toml_value = toml::Value::try_from(&unsigned).map_err(|error| {
            ConfigError::invalid(format!("cannot canonicalize pipeline config: {error}"))
        })?;
        ensure_finite_numbers(&toml_value)?;
        let value = serde_json::to_value(&unsigned).map_err(|error| {
            ConfigError::invalid(format!("cannot canonicalize pipeline config: {error}"))
        })?;
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded).map_err(|error| {
            ConfigError::invalid(format!("cannot encode canonical body: {error}"))
        })?;
        Ok(encoded)
    }

    /// Immutable revision identifier: the SHA-256 of the canonical body.
    pub fn revision(&self) -> Result<String, ConfigError> {
        Ok(hex::encode(Sha256::digest(self.canonical_body()?)))
    }

    /// Sign the canonical body in place, replacing any existing signature.
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), ConfigError> {
        let signature = signing_key.sign(&self.canonical_body()?);
        self.signature = Some(BASE64.encode(signature.to_bytes()));
        Ok(())
    }

    /// Verify the detached signature against the trust roots and enforce the
    /// optional validity window.
    pub fn verify(&self, trust_roots: &TrustRoots) -> Result<(), ConfigError> {
        let encoded = self
            .signature
            .as_ref()
            .ok_or_else(|| ConfigError::signature("the pipeline file is not signed"))?;
        let raw = BASE64.decode(encoded).map_err(|error| {
            ConfigError::signature(format!("signature is not valid base64: {error}"))
        })?;
        let signature = Signature::from_slice(&raw)
            .map_err(|error| ConfigError::signature(format!("signature is malformed: {error}")))?;
        let verifying_key = trust_roots
            .get(&self.signer_id)
            .ok_or_else(|| ConfigError::signature(format!("unknown signer: {}", self.signer_id)))?;
        verifying_key
            .verify_strict(&self.canonical_body()?, &signature)
            .map_err(|error| {
                ConfigError::signature(format!("signature verification failed: {error}"))
            })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        self.verify_validity_at(now)
    }

    fn verify_validity_at(&self, now: u64) -> Result<(), ConfigError> {
        if let Some(not_before) = self.not_before
            && now < not_before
        {
            return Err(ConfigError::signature(format!(
                "pipeline file is not valid before {not_before} (now {now})"
            )));
        }
        if let Some(expires_at) = self.expires_at
            && now > expires_at
        {
            return Err(ConfigError::signature(format!(
                "pipeline file expired at {expires_at} (now {now})"
            )));
        }
        Ok(())
    }
}

fn ensure_finite_numbers(value: &toml::Value) -> Result<(), ConfigError> {
    match value {
        toml::Value::Float(number) if !number.is_finite() => Err(ConfigError::invalid(
            "pipeline config contains a non-finite float",
        )),
        toml::Value::Array(values) => values.iter().try_for_each(ensure_finite_numbers),
        toml::Value::Table(values) => values.values().try_for_each(ensure_finite_numbers),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"
schema_version = 1
signer_id = "acme-prod"

[write]
[[write.steps]]
plugin = "pii-default"

[read]
[[read.steps]]
plugin = "envelope-decrypt"
"#;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7_u8; 32])
    }

    fn signed_file() -> PipelineFile {
        let mut file = PipelineFile::from_toml_str(BODY).unwrap();
        file.sign(&signing_key()).unwrap();
        file
    }

    fn trust_roots(key: &SigningKey) -> TrustRoots {
        let mut roots = TrustRoots::new();
        roots.insert("acme-prod".to_string(), key.verifying_key());
        roots
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let file = signed_file();
        file.verify(&trust_roots(&signing_key())).unwrap();
    }

    #[test]
    fn unsigned_file_is_rejected() {
        let file = PipelineFile::from_toml_str(BODY).unwrap();
        let error = file.verify(&trust_roots(&signing_key())).unwrap_err();
        assert_eq!(error.code(), maskura_error::codes::POLICY_TAMPERED);
    }

    #[test]
    fn unknown_signer_is_rejected() {
        let file = signed_file();
        let error = file.verify(&TrustRoots::new()).unwrap_err();
        assert!(error.to_string().contains("unknown signer"));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let file = signed_file();
        let other = SigningKey::from_bytes(&[9_u8; 32]);
        let error = file.verify(&trust_roots(&other)).unwrap_err();
        assert!(error.to_string().contains("verification failed"));
    }

    #[test]
    fn tampered_content_is_rejected() {
        let mut file = signed_file();
        file.write.as_mut().unwrap().steps[0].plugin.name = "other-filter".to_string();
        let error = file.verify(&trust_roots(&signing_key())).unwrap_err();
        assert!(error.to_string().contains("verification failed"));
    }

    #[test]
    fn comments_and_whitespace_do_not_change_the_revision() {
        let bare = PipelineFile::from_toml_str(BODY).unwrap();
        let commented = PipelineFile::from_toml_str(&format!(
            "# exported by Maskura\n\n{BODY}\n# trailing comment\n"
        ))
        .unwrap();
        assert_eq!(bare.revision().unwrap(), commented.revision().unwrap());
    }

    #[test]
    fn semantic_change_changes_the_revision() {
        let mut file = PipelineFile::from_toml_str(BODY).unwrap();
        let before = file.revision().unwrap();
        file.read.as_mut().unwrap().steps[0].plugin.name = "other".to_string();
        assert_ne!(before, file.revision().unwrap());
    }

    #[test]
    fn signature_field_is_excluded_from_the_body() {
        let mut file = PipelineFile::from_toml_str(BODY).unwrap();
        let unsigned = file.canonical_body().unwrap();
        file.sign(&signing_key()).unwrap();
        assert_eq!(unsigned, file.canonical_body().unwrap());
    }

    #[test]
    fn signed_file_round_trips_through_toml_with_config() {
        let body = r#"
schema_version = 1
signer_id = "acme-prod"

[write]
[[write.steps]]
plugin = "redactor:0.x.y"
grant = ["stable_fields"]
[write.steps.config]
mode = "hash"
"#;
        let mut file = PipelineFile::from_toml_str(body).unwrap();
        file.sign(&signing_key()).unwrap();
        let rendered = file.to_toml_string().unwrap();
        let reparsed = PipelineFile::from_toml_str(&rendered).unwrap();
        assert_eq!(reparsed.revision().unwrap(), file.revision().unwrap());
        assert_eq!(reparsed.signature, file.signature);
        reparsed.verify(&trust_roots(&signing_key())).unwrap();
    }

    #[test]
    fn trust_roots_parse_from_entries() {
        let encoded = hex::encode(signing_key().verifying_key().to_bytes());
        let roots = parse_trust_roots(&format!("acme={encoded}; other={encoded}")).unwrap();
        assert_eq!(roots.len(), 2);
        assert!(roots.contains_key("acme"));
        assert!(roots.contains_key("other"));
    }

    #[test]
    fn blank_trust_roots_is_allowed() {
        assert!(parse_trust_roots("  ").unwrap().is_empty());
    }

    #[test]
    fn malformed_trust_root_is_rejected() {
        assert!(parse_trust_roots("no-equals").is_err());
        assert!(parse_trust_roots("signer=not-hex").is_err());
        assert!(parse_trust_roots("signer=abcd").is_err());
    }

    #[test]
    fn expired_file_is_rejected() {
        let mut file = PipelineFile::from_toml_str(BODY).unwrap();
        file.not_before = Some(1);
        file.expires_at = Some(2);
        file.sign(&signing_key()).unwrap();
        let error = file.verify(&trust_roots(&signing_key())).unwrap_err();
        assert!(error.to_string().contains("expired"));
    }

    #[test]
    fn not_before_boundary_is_inclusive_and_future_is_rejected() {
        let mut file = PipelineFile::from_toml_str(BODY).unwrap();
        file.not_before = Some(100);
        assert!(file.verify_validity_at(100).is_ok());
        let error = file.verify_validity_at(99).unwrap_err();
        assert!(error.to_string().contains("not valid before"));
    }

    #[test]
    fn malformed_signatures_are_rejected_without_panicking() {
        let mut file = PipelineFile::from_toml_str(BODY).unwrap();
        file.signature = Some("not base64!".to_string());
        assert!(file.verify(&trust_roots(&signing_key())).is_err());

        file.signature = Some(BASE64.encode([1_u8; 12]));
        let error = file.verify(&trust_roots(&signing_key())).unwrap_err();
        assert!(error.to_string().contains("malformed"));
    }

    #[test]
    fn non_finite_config_returns_controlled_canonicalization_errors() {
        for number in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut file = PipelineFile::from_toml_str(BODY).unwrap();
            file.write.as_mut().unwrap().steps[0].config = Some(toml::Value::Float(number));

            assert!(file.canonical_body().is_err());
            assert!(file.revision().is_err());
            assert!(file.sign(&signing_key()).is_err());
            assert!(file.signature.is_none());
        }
    }
}
