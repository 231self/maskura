//! WebAuthn approval-proof binding (protocol sub-spec §3).
//!
//! WebAuthn signs `authenticatorData || SHA256(clientDataJSON)`, never raw
//! artifact bytes. The challenge carries a canonical-CBOR [`ChallengeContext`]
//! that binds ceremony kind, workspace, audience, and artifact digest. This
//! module implements the offline verification rules; ceremony issuance and
//! session handling live in the private control plane.

use std::{collections::BTreeSet, io::Cursor};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use p256::EncodedPoint;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::{canonical_cbor, is_hex64, sha256_hex};
use crate::error::ConfigError;

/// Version of the challenge context format.
pub const CHALLENGE_VERSION: u32 = 1;

/// Minimum accepted random nonce length in bytes.
const MIN_NONCE_BYTES: usize = 32;

/// Offsets into WebAuthn `authenticatorData`.
const RP_ID_HASH_LEN: usize = 32;
const AUTHENTICATOR_DATA_MIN_LEN: usize = RP_ID_HASH_LEN + 1 + 4;
/// `attestedCredentialData` header: AAGUID(16) + credIdLen(2).
const ATTESTED_HEADER_LEN: usize = 16 + 2;
const FLAG_UP: u8 = 1 << 0;
const FLAG_UV: u8 = 1 << 2;
const FLAG_BE: u8 = 1 << 3;
const FLAG_BS: u8 = 1 << 4;
const FLAG_AT: u8 = 1 << 6;
const FLAG_ED: u8 = 1 << 7;

/// Maximum accepted `clientDataJSON` size in bytes.
const MAX_CLIENT_DATA_JSON_LEN: usize = 16_384;
/// Maximum accepted `attestationObject` or `authenticatorData` size in bytes.
const MAX_ATTESTATION_OBJECT_LEN: usize = 16_384;
/// Maximum accepted credential ID length in bytes.
const MAX_CREDENTIAL_ID_LEN: usize = 1_024;

/// Ceremony purpose. Domain separation alone is insufficient (R6); this plus
/// workspace/audience/artifact digest in the expectation defines the bound
/// statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    Login,
    Register,
    Envelope,
    Receipt,
    Signer,
}

/// The statement a WebAuthn assertion approves. Canonical-CBOR encoded and
/// base64url-no-pad encoded into `clientDataJSON.challenge`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeContext {
    pub v: u32,
    pub kind: ChallengeKind,
    /// base64url of >= 32 CSPRNG bytes; single-use with `ceremony_id`.
    pub nonce: String,
    /// Single-use ceremony identifier, consumed at completion.
    pub ceremony_id: String,
    pub user_id: String,
    /// Verified Supabase session id; empty only when there is no session.
    pub session_id: String,
    pub audience: String,
    /// Empty for login ceremonies.
    pub workspace_id: String,
    /// 64 lowercase hex for artifact ceremonies; empty for login.
    pub artifact_digest: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// What an offline verifier expects an assertion to have approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionExpectation {
    pub kind: ChallengeKind,
    pub audience: String,
    pub workspace_id: String,
    pub artifact_digest: String,
    pub rp_id: String,
    pub origins: Vec<String>,
}

/// The exact bytes retained for offline verification of one assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebAuthnProof {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
}

/// A parsed COSE ES256 (P-256) public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseEs256Key {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// What a registration attestation must have bound itself to: the exact
/// challenge context issued for the ceremony plus the RP/origin policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationExpectation {
    pub context: ChallengeContext,
    pub rp_id: String,
    pub origins: Vec<String>,
}

/// A credential extracted from a `fmt:"none"` registration attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCredential {
    /// Raw attested credential ID bytes.
    pub credential_id: Vec<u8>,
    pub cose_key: CoseEs256Key,
    pub sign_count: u32,
    pub backup_eligible: bool,
    pub backed_up: bool,
}

impl ChallengeContext {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.v != CHALLENGE_VERSION {
            return Err(ConfigError::approval(format!(
                "unsupported challenge version {}; expected {CHALLENGE_VERSION}",
                self.v
            )));
        }
        let nonce_len = BASE64URL
            .decode(&self.nonce)
            .map_err(|error| {
                ConfigError::approval(format!("challenge nonce is not base64url: {error}"))
            })?
            .len();
        if nonce_len < MIN_NONCE_BYTES {
            return Err(ConfigError::approval(format!(
                "challenge nonce must be at least {MIN_NONCE_BYTES} bytes"
            )));
        }
        if self.ceremony_id.trim().is_empty() {
            return Err(ConfigError::approval(
                "challenge ceremony_id must not be empty",
            ));
        }
        if self.user_id.trim().is_empty() {
            return Err(ConfigError::approval("challenge user_id must not be empty"));
        }
        match self.kind {
            ChallengeKind::Login | ChallengeKind::Register => {
                if !self.workspace_id.is_empty() || !self.artifact_digest.is_empty() {
                    return Err(ConfigError::approval(
                        "login and register challenges must not bind a workspace or artifact",
                    ));
                }
            }
            ChallengeKind::Envelope | ChallengeKind::Receipt | ChallengeKind::Signer => {
                if self.workspace_id.trim().is_empty() {
                    return Err(ConfigError::approval(
                        "artifact challenges must bind a workspace",
                    ));
                }
                if !is_hex64(&self.artifact_digest) {
                    return Err(ConfigError::approval(
                        "artifact challenges must bind a 64-hex artifact digest",
                    ));
                }
            }
        }
        if self.audience.trim().is_empty() {
            return Err(ConfigError::approval(
                "challenge audience must not be empty",
            ));
        }
        if self.issued_at >= self.expires_at {
            return Err(ConfigError::approval(
                "challenge issued_at must be strictly before expires_at",
            ));
        }
        Ok(())
    }

    /// base64url-no-pad encoding of the canonical CBOR challenge body, as it
    /// appears in `clientDataJSON.challenge`.
    pub fn challenge_string(&self) -> Result<String, ConfigError> {
        Ok(BASE64URL.encode(canonical_cbor(self)?))
    }
}

impl CoseEs256Key {
    /// Parse a COSE_Key CBOR map. v1 accepts only EC2/ES256/P-256; anything
    /// else is rejected (no silent algorithm downgrade).
    pub fn parse_cose(cbor: &[u8]) -> Result<Self, ConfigError> {
        if cbor.len() > 4096 {
            return Err(ConfigError::approval("COSE key exceeds size limit"));
        }
        let mut reader = Cursor::new(cbor);
        let value: ciborium::value::Value =
            ciborium::de::from_reader(&mut reader).map_err(|error| {
                ConfigError::approval(format!("COSE key is not valid CBOR: {error}"))
            })?;
        if reader.position() != cbor.len() as u64 {
            return Err(ConfigError::approval("trailing bytes after COSE key"));
        }
        let ciborium::value::Value::Map(entries) = value else {
            return Err(ConfigError::approval("COSE key must be a CBOR map"));
        };
        let mut kty: Option<i64> = None;
        let mut alg: Option<i64> = None;
        let mut crv: Option<i64> = None;
        let mut x: Option<Vec<u8>> = None;
        let mut y: Option<Vec<u8>> = None;
        let mut labels = BTreeSet::new();
        for (key, val) in entries {
            let ciborium::value::Value::Integer(key) = key else {
                return Err(ConfigError::approval("COSE key labels must be integers"));
            };
            let label = i64::try_from(key)
                .map_err(|_| ConfigError::approval("COSE key label does not fit in i64"))?;
            if !labels.insert(label) {
                return Err(ConfigError::approval("duplicate COSE key label"));
            }
            match label {
                1 => kty = Some(as_i64(&val, "kty")?),
                3 => alg = Some(as_i64(&val, "alg")?),
                -1 => crv = Some(as_i64(&val, "crv")?),
                -2 => x = Some(as_bytes(&val, "x")?),
                -3 => y = Some(as_bytes(&val, "y")?),
                -4 => {
                    return Err(ConfigError::approval(
                        "private key material is not a trust root",
                    ));
                }
                _ => {}
            }
        }
        if kty != Some(2) {
            return Err(ConfigError::approval(format!(
                "unsupported COSE key type {kty:?}; expected 2 (EC2)"
            )));
        }
        if alg != Some(-7) {
            return Err(ConfigError::approval(format!(
                "unsupported COSE algorithm {alg:?}; expected -7 (ES256)"
            )));
        }
        if crv != Some(1) {
            return Err(ConfigError::approval(format!(
                "unsupported COSE curve {crv:?}; expected 1 (P-256)"
            )));
        }
        let key = Self {
            x: fixed32(x, "x")?,
            y: fixed32(y, "y")?,
        };
        key.verifying_key()?;
        Ok(key)
    }

    /// Encode as a COSE_Key CBOR map (EC2/ES256/P-256).
    pub fn to_cose(&self) -> Result<Vec<u8>, ConfigError> {
        use ciborium::value::Value;
        let entries = vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-7).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (Value::Integer((-2).into()), Value::Bytes(self.x.to_vec())),
            (Value::Integer((-3).into()), Value::Bytes(self.y.to_vec())),
        ];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf)
            .map_err(|error| ConfigError::approval(format!("cannot encode COSE key: {error}")))?;
        Ok(buf)
    }

    /// Uncompressed SEC1 point `0x04 || x || y`.
    pub fn to_encoded_point(&self) -> [u8; 65] {
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(&self.x);
        point[33..].copy_from_slice(&self.y);
        point
    }

    fn verifying_key(&self) -> Result<VerifyingKey, ConfigError> {
        let point = EncodedPoint::from_bytes(self.to_encoded_point())
            .map_err(|error| ConfigError::approval(format!("invalid P-256 point: {error}")))?;
        VerifyingKey::from_encoded_point(&point)
            .map_err(|error| ConfigError::approval(format!("invalid P-256 key: {error}")))
    }
}

fn as_i64(value: &ciborium::value::Value, label: &str) -> Result<i64, ConfigError> {
    match value {
        ciborium::value::Value::Integer(number) => i64::try_from(*number)
            .map_err(|_| ConfigError::approval(format!("COSE {label} does not fit in i64"))),
        _ => Err(ConfigError::approval(format!(
            "COSE {label} must be an integer"
        ))),
    }
}

fn as_bytes(value: &ciborium::value::Value, label: &str) -> Result<Vec<u8>, ConfigError> {
    match value {
        ciborium::value::Value::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(ConfigError::approval(format!(
            "COSE {label} must be a byte string"
        ))),
    }
}

fn fixed32(value: Option<Vec<u8>>, label: &str) -> Result<[u8; 32], ConfigError> {
    value
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| ConfigError::approval(format!("COSE {label} must be 32 bytes")))
}

/// Verify one stored assertion against an expectation and the credential's
/// COSE key. Returns the decoded challenge for receipt-window checks.
///
/// Verification order (sub-spec §3): clientDataJSON structure and origin,
/// challenge decode + bound-field equality, authenticator data (RP hash,
/// UP/UV, no AT), ECDSA P-256 signature over
/// `authenticatorData || SHA256(clientDataJSON)`.
pub fn verify_assertion(
    proof: &WebAuthnProof,
    expected: &AssertionExpectation,
    key: &CoseEs256Key,
) -> Result<ChallengeContext, ConfigError> {
    if proof.client_data_json.len() > 16_384
        || proof.authenticator_data.len() > 16_384
        || proof.signature.len() > 128
    {
        return Err(ConfigError::approval("assertion exceeds size limit"));
    }
    #[derive(Deserialize)]
    struct ClientData {
        #[serde(rename = "type")]
        kind: String,
        origin: String,
        challenge: String,
        #[serde(default, rename = "crossOrigin")]
        cross_origin: bool,
        #[serde(rename = "topOrigin")]
        top_origin: Option<String>,
    }
    // 1. clientDataJSON: type and exact origin.
    let client_data: ClientData =
        serde_json::from_str(&proof.client_data_json).map_err(|error| {
            ConfigError::approval(format!("clientDataJSON is not valid JSON: {error}"))
        })?;
    let client_type = client_data.kind.as_str();
    if client_type != "webauthn.get" {
        return Err(ConfigError::approval(format!(
            "unexpected clientDataJSON.type {client_type:?}; expected \"webauthn.get\""
        )));
    }
    let origin = client_data.origin.as_str();
    if !expected.origins.iter().any(|allowed| allowed == origin) {
        return Err(ConfigError::approval(format!(
            "origin {origin:?} is not an allowed origin"
        )));
    }
    if client_data.cross_origin || client_data.top_origin.is_some() {
        return Err(ConfigError::approval(
            "cross-origin approval ceremonies are not supported",
        ));
    }
    let challenge = &client_data.challenge;

    // 2. Decode the signed challenge from canonical CBOR and check every
    //    bound field against the expectation.
    let challenge_bytes = BASE64URL
        .decode(challenge)
        .map_err(|error| ConfigError::approval(format!("challenge is not base64url: {error}")))?;
    let context: ChallengeContext =
        ciborium::de::from_reader(&challenge_bytes[..]).map_err(|error| {
            ConfigError::approval(format!("challenge is not canonical CBOR: {error}"))
        })?;
    context.validate()?;
    if canonical_cbor(&context)? != challenge_bytes {
        return Err(ConfigError::approval(
            "challenge must use the exact canonical encoding",
        ));
    }
    if context.kind != expected.kind {
        return Err(ConfigError::approval(format!(
            "challenge kind {:?} does not match expected {:?}",
            context.kind, expected.kind
        )));
    }
    if context.audience != expected.audience {
        return Err(ConfigError::approval(
            "challenge audience does not match the expected deployment",
        ));
    }
    if context.workspace_id != expected.workspace_id {
        return Err(ConfigError::approval(
            "challenge workspace does not match the expected workspace",
        ));
    }
    if context.artifact_digest != expected.artifact_digest {
        return Err(ConfigError::approval(
            "challenge artifact digest does not match the expected artifact",
        ));
    }

    // 3. Authenticator data: RP ID hash, UP/UV set, AT clear. The sign
    //    counter (bytes 33..37) is parsed but never required to increase —
    //    synced passkeys may legitimately report 0.
    let authenticator_data = BASE64URL
        .decode(&proof.authenticator_data)
        .map_err(|error| {
            ConfigError::approval(format!("authenticator_data is not base64url: {error}"))
        })?;
    if authenticator_data.len() < AUTHENTICATOR_DATA_MIN_LEN {
        return Err(ConfigError::approval(
            "authenticator_data is shorter than the required header",
        ));
    }
    let actual_rp_hash = hex::encode(&authenticator_data[..RP_ID_HASH_LEN]);
    let expected_rp_hash = sha256_hex(expected.rp_id.as_bytes());
    if actual_rp_hash != expected_rp_hash {
        return Err(ConfigError::approval(format!(
            "authenticator_data RP ID hash does not match rp_id {:?}",
            expected.rp_id
        )));
    }
    let flags = authenticator_data[RP_ID_HASH_LEN];
    if flags & FLAG_UP == 0 {
        return Err(ConfigError::approval("assertion is missing the UP flag"));
    }
    if flags & FLAG_UV == 0 {
        return Err(ConfigError::approval("assertion is missing the UV flag"));
    }
    if flags & FLAG_AT != 0 {
        return Err(ConfigError::approval(
            "assertion must not carry attested credential data (AT flag set)",
        ));
    }
    if flags & 0x22 != 0 || (flags & 0x10 != 0 && flags & 0x08 == 0) {
        return Err(ConfigError::approval("invalid authenticator flags"));
    }
    let extensions = &authenticator_data[AUTHENTICATOR_DATA_MIN_LEN..];
    if flags & 0x80 == 0 {
        if !extensions.is_empty() {
            return Err(ConfigError::approval(
                "unexpected authenticator data suffix",
            ));
        }
    } else {
        let mut reader = Cursor::new(extensions);
        let extension: ciborium::value::Value = ciborium::de::from_reader(&mut reader)
            .map_err(|_| ConfigError::approval("invalid authenticator extensions"))?;
        if !matches!(extension, ciborium::value::Value::Map(_))
            || reader.position() != extensions.len() as u64
        {
            return Err(ConfigError::approval("invalid authenticator extensions"));
        }
    }

    let signature_bytes = BASE64URL
        .decode(&proof.signature)
        .map_err(|error| ConfigError::approval(format!("signature is not base64url: {error}")))?;
    verify_der_signature(
        &authenticator_data,
        proof.client_data_json.as_bytes(),
        &signature_bytes,
        key,
    )?;

    Ok(context)
}

fn verify_der_signature(
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature_bytes: &[u8],
    key: &CoseEs256Key,
) -> Result<(), ConfigError> {
    let mut message = Vec::with_capacity(authenticator_data.len() + 32);
    message.extend_from_slice(authenticator_data);
    message.extend_from_slice(&Sha256::digest(client_data_json));

    let signature = Signature::from_der(signature_bytes).map_err(|error| {
        ConfigError::approval(format!("signature is malformed for ES256: {error}"))
    })?;
    let verifying_key = key.verifying_key()?;
    verifying_key
        .verify(&message, &signature)
        .map_err(|error| ConfigError::approval(format!("assertion signature invalid: {error}")))?;

    Ok(())
}

/// Parse and verify a WebAuthn registration (`fmt:"none"` attestation),
/// returning the attested credential.
///
/// Verification order mirrors [`verify_assertion`]: clientDataJSON structure
/// and origin, challenge echo of the exact expected canonical
/// [`ChallengeContext`] bytes (trailing bytes rejected), attestation statement
/// (`fmt:"none"` with empty `attStmt`), then authenticator data (RP hash,
/// UP+UV+AT, well-formed extension data, attested credential data layout).
/// The COSE key is parsed with [`CoseEs256Key::parse_cose`], which already
/// rejects duplicate labels, private material, trailing bytes, oversized keys,
/// and non-ES256 algorithms.
///
/// Under `fmt:"none"` nothing but TLS binds the attestation statement to the
/// challenge; the typed challenge buys replay prevention and session binding,
/// not attestation authenticity (ADR 0022).
pub fn parse_registration(
    client_data_json: &str,
    attestation_object: &[u8],
    expected: &RegistrationExpectation,
) -> Result<RegisteredCredential, ConfigError> {
    if client_data_json.len() > MAX_CLIENT_DATA_JSON_LEN
        || attestation_object.len() > MAX_ATTESTATION_OBJECT_LEN
    {
        return Err(ConfigError::approval("registration exceeds size limit"));
    }
    if expected.context.kind != ChallengeKind::Register {
        return Err(ConfigError::approval(
            "registration ceremonies must expect a register challenge",
        ));
    }
    expected.context.validate()?;

    // 1. clientDataJSON: type and exact origin. serde rejects duplicate
    //    recognized fields for derived structs.
    #[derive(Deserialize)]
    struct ClientData {
        #[serde(rename = "type")]
        kind: String,
        origin: String,
        challenge: String,
        #[serde(default, rename = "crossOrigin")]
        cross_origin: bool,
        #[serde(rename = "topOrigin")]
        top_origin: Option<String>,
    }
    let client_data: ClientData = serde_json::from_str(client_data_json).map_err(|error| {
        ConfigError::approval(format!("clientDataJSON is not valid JSON: {error}"))
    })?;
    if client_data.kind != "webauthn.create" {
        return Err(ConfigError::approval(format!(
            "unexpected clientDataJSON.type {:?}; expected \"webauthn.create\"",
            client_data.kind
        )));
    }
    let origin = client_data.origin.as_str();
    if !expected.origins.iter().any(|allowed| allowed == origin) {
        return Err(ConfigError::approval(format!(
            "origin {origin:?} is not an allowed origin"
        )));
    }
    if client_data.cross_origin || client_data.top_origin.is_some() {
        return Err(ConfigError::approval(
            "cross-origin registration ceremonies are not supported",
        ));
    }

    // 2. The echoed challenge must decode to exactly the expected canonical
    //    ChallengeContext bytes; anything else (including trailing bytes) is
    //    a different statement.
    let challenge_bytes = BASE64URL
        .decode(client_data.challenge.as_str())
        .map_err(|error| ConfigError::approval(format!("challenge is not base64url: {error}")))?;
    if challenge_bytes != canonical_cbor(&expected.context)? {
        return Err(ConfigError::approval(
            "registration challenge does not match the expected challenge",
        ));
    }

    // 3. attestationObject: CBOR map with fmt "none" and an empty attStmt.
    let mut reader = Cursor::new(attestation_object);
    let value: ciborium::value::Value =
        ciborium::de::from_reader(&mut reader).map_err(|error| {
            ConfigError::approval(format!("attestationObject is not valid CBOR: {error}"))
        })?;
    if reader.position() != attestation_object.len() as u64 {
        return Err(ConfigError::approval(
            "trailing bytes after attestationObject",
        ));
    }
    let ciborium::value::Value::Map(entries) = value else {
        return Err(ConfigError::approval(
            "attestationObject must be a CBOR map",
        ));
    };
    let mut fmt: Option<String> = None;
    let mut att_stmt: Option<ciborium::value::Value> = None;
    let mut auth_data: Option<Vec<u8>> = None;
    let mut labels = BTreeSet::new();
    for (key, val) in entries {
        let ciborium::value::Value::Text(label) = key else {
            return Err(ConfigError::approval(
                "attestationObject labels must be text",
            ));
        };
        if !labels.insert(label.clone()) {
            return Err(ConfigError::approval("duplicate attestationObject label"));
        }
        match label.as_str() {
            "fmt" => fmt = Some(as_text(&val, "fmt")?),
            "attStmt" => att_stmt = Some(val),
            "authData" => auth_data = Some(as_bytes(&val, "authData")?),
            _ => {}
        }
    }
    let (Some(fmt), Some(att_stmt), Some(auth_data)) = (fmt, att_stmt, auth_data) else {
        return Err(ConfigError::approval(
            "attestationObject must carry fmt, attStmt, and authData",
        ));
    };
    if fmt != "none" {
        return Err(ConfigError::approval(format!(
            "unsupported attestation format {fmt:?}; expected \"none\""
        )));
    }
    let ciborium::value::Value::Map(ref stmt) = att_stmt else {
        return Err(ConfigError::approval("attStmt must be a CBOR map"));
    };
    if !stmt.is_empty() {
        return Err(ConfigError::approval(
            "fmt \"none\" attestation must carry an empty attStmt",
        ));
    }

    // 4. authData: RP ID hash, UP+UV+AT, well-formed extensions.
    if auth_data.len() < AUTHENTICATOR_DATA_MIN_LEN + ATTESTED_HEADER_LEN {
        return Err(ConfigError::approval(
            "authData is shorter than the attested credential header",
        ));
    }
    let actual_rp_hash = hex::encode(&auth_data[..RP_ID_HASH_LEN]);
    let expected_rp_hash = sha256_hex(expected.rp_id.as_bytes());
    if actual_rp_hash != expected_rp_hash {
        return Err(ConfigError::approval(format!(
            "authData RP ID hash does not match rp_id {:?}",
            expected.rp_id
        )));
    }
    let flags = auth_data[RP_ID_HASH_LEN];
    if flags & FLAG_UP == 0 {
        return Err(ConfigError::approval("registration is missing the UP flag"));
    }
    if flags & FLAG_UV == 0 {
        return Err(ConfigError::approval("registration is missing the UV flag"));
    }
    if flags & FLAG_AT == 0 {
        return Err(ConfigError::approval(
            "registration must carry attested credential data (AT flag clear)",
        ));
    }
    if flags & 0x22 != 0 || (flags & FLAG_BS != 0 && flags & FLAG_BE == 0) {
        return Err(ConfigError::approval("invalid authenticator flags"));
    }
    let sign_count = u32::from_be_bytes(
        auth_data[RP_ID_HASH_LEN + 1..AUTHENTICATOR_DATA_MIN_LEN]
            .try_into()
            .expect("sign count is four bytes"),
    );

    // attestedCredentialData: AAGUID(16) ‖ credIdLen(2) ‖ credId ‖ COSE key.
    let attested_start = AUTHENTICATOR_DATA_MIN_LEN;
    let cred_len_start = attested_start + 16;
    let cred_id_len = u16::from_be_bytes(
        auth_data[cred_len_start..cred_len_start + 2]
            .try_into()
            .expect("credIdLen is two bytes"),
    ) as usize;
    if cred_id_len == 0 || cred_id_len > MAX_CREDENTIAL_ID_LEN {
        return Err(ConfigError::approval(format!(
            "credential ID length {cred_id_len} is outside 1..={MAX_CREDENTIAL_ID_LEN}"
        )));
    }
    let cred_id_start = cred_len_start + 2;
    let cose_start = cred_id_start + cred_id_len;
    if cose_start >= auth_data.len() {
        return Err(ConfigError::approval(
            "authData is truncated before the COSE key",
        ));
    }
    let credential_id = auth_data[cred_id_start..cose_start].to_vec();
    let cose_and_rest = &auth_data[cose_start..];

    // 5. Delimit the COSE key map, then hand exactly those bytes to the COSE
    //    parser (which rejects trailing bytes). Extension data (optional, ED
    //    flag) must follow as a well-formed CBOR map.
    let mut key_reader = Cursor::new(cose_and_rest);
    let key_value: ciborium::value::Value = ciborium::de::from_reader(&mut key_reader)
        .map_err(|_| ConfigError::approval("COSE key is not valid CBOR"))?;
    if !matches!(key_value, ciborium::value::Value::Map(_)) {
        return Err(ConfigError::approval("COSE key must be a CBOR map"));
    }
    let cose_end = key_reader.position() as usize;
    let cose_key = CoseEs256Key::parse_cose(&cose_and_rest[..cose_end])?;
    let extensions = &cose_and_rest[cose_end..];
    if flags & FLAG_ED == 0 {
        if !extensions.is_empty() {
            return Err(ConfigError::approval(
                "unexpected authenticator data suffix",
            ));
        }
    } else {
        let mut ext_reader = Cursor::new(extensions);
        let extension: ciborium::value::Value = ciborium::de::from_reader(&mut ext_reader)
            .map_err(|_| ConfigError::approval("invalid authenticator extensions"))?;
        if !matches!(extension, ciborium::value::Value::Map(_))
            || ext_reader.position() != extensions.len() as u64
        {
            return Err(ConfigError::approval("invalid authenticator extensions"));
        }
    }

    Ok(RegisteredCredential {
        credential_id,
        cose_key,
        sign_count,
        backup_eligible: flags & FLAG_BE != 0,
        backed_up: flags & FLAG_BS != 0,
    })
}

fn as_text(value: &ciborium::value::Value, label: &str) -> Result<String, ConfigError> {
    match value {
        ciborium::value::Value::Text(text) => Ok(text.clone()),
        _ => Err(ConfigError::approval(format!(
            "attestationObject {label} must be text"
        ))),
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod test_support {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use rand::RngCore;

    use super::*;
    use crate::webauthn::ChallengeContext;

    /// A deterministic software credential for golden and adversarial tests.
    pub struct TestCredential {
        pub signing: SigningKey,
        pub cose: CoseEs256Key,
        pub credential_id: String,
    }

    pub fn test_credential(seed: [u8; 32]) -> TestCredential {
        let signing = SigningKey::from_bytes(&seed.into()).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let bytes = point.as_bytes();
        let cose = CoseEs256Key {
            x: bytes[1..33].try_into().unwrap(),
            y: bytes[33..65].try_into().unwrap(),
        };
        let credential_id = BASE64URL.encode(sha256_hex(bytes).as_bytes());
        TestCredential {
            signing,
            cose,
            credential_id,
        }
    }

    pub fn challenge(kind: ChallengeKind, workspace: &str, artifact: &str) -> ChallengeContext {
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        ChallengeContext {
            v: CHALLENGE_VERSION,
            kind,
            nonce: BASE64URL.encode(nonce),
            ceremony_id: "ceremony-1".to_string(),
            user_id: "user-1".to_string(),
            session_id: "session-1".to_string(),
            audience: "https://maskura.dev".to_string(),
            workspace_id: workspace.to_string(),
            artifact_digest: artifact.to_string(),
            issued_at: 1_000,
            expires_at: 1_600,
        }
    }

    pub const UP_UV: u8 = FLAG_UP | FLAG_UV;
    pub const UP_UV_AT: u8 = FLAG_UP | FLAG_UV | FLAG_AT;

    /// Build a stored assertion over `context` with controllable flags/origin.
    pub fn assert_proof(
        cred: &TestCredential,
        context: &ChallengeContext,
        rp_id: &str,
        origin: &str,
        flags: u8,
    ) -> WebAuthnProof {
        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": context.challenge_string().unwrap(),
            "origin": origin,
            "crossOrigin": false,
        });
        let client_data_json = serde_json::to_string(&client_data).unwrap();
        let mut authenticator_data = Vec::new();
        authenticator_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&0u32.to_be_bytes());
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&Sha256::digest(client_data_json.as_bytes()));
        let signature: Signature = cred.signing.sign(&message);
        WebAuthnProof {
            credential_id: cred.credential_id.clone(),
            client_data_json,
            authenticator_data: BASE64URL.encode(authenticator_data),
            signature: BASE64URL.encode(signature.to_der().as_bytes()),
        }
    }

    pub fn expectation(
        kind: ChallengeKind,
        workspace: &str,
        artifact: &str,
    ) -> AssertionExpectation {
        AssertionExpectation {
            kind,
            audience: "https://maskura.dev".to_string(),
            workspace_id: workspace.to_string(),
            artifact_digest: artifact.to_string(),
            rp_id: "maskura.dev".to_string(),
            origins: vec!["https://maskura.dev".to_string()],
        }
    }

    /// Build a `fmt:"none"` registration attestation over `context`.
    ///
    /// Returns `(client_data_json, attestation_object)` with controllable
    /// flags/origin, mirroring [`assert_proof`].
    pub fn register_attestation(
        cred: &TestCredential,
        context: &ChallengeContext,
        rp_id: &str,
        origin: &str,
        flags: u8,
    ) -> (String, Vec<u8>) {
        register_attestation_with_cred_id(
            cred,
            context,
            rp_id,
            origin,
            flags,
            cred.credential_id.as_bytes(),
            None,
        )
    }

    /// Build a registration attestation with explicit credential-ID bytes and
    /// an optional raw override for the COSE key bytes (for malformed-key
    /// vectors). When `cose_override` is `None` the credential's real COSE key
    /// is attested.
    pub fn register_attestation_with_cred_id(
        cred: &TestCredential,
        context: &ChallengeContext,
        rp_id: &str,
        origin: &str,
        flags: u8,
        credential_id: &[u8],
        cose_override: Option<&[u8]>,
    ) -> (String, Vec<u8>) {
        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": context.challenge_string().unwrap(),
            "origin": origin,
            "crossOrigin": false,
        });
        let client_data_json = serde_json::to_string(&client_data).unwrap();
        let cose_bytes = match cose_override {
            Some(bytes) => bytes.to_vec(),
            None => cred.cose.to_cose().unwrap(),
        };
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        auth_data.push(flags);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(&cose_bytes);
        let attestation = ciborium_attestation(&auth_data);
        (client_data_json, attestation)
    }

    /// Serialize a `fmt:"none"` attestation object over `auth_data`.
    pub fn ciborium_attestation(auth_data: &[u8]) -> Vec<u8> {
        use ciborium::value::Value;
        let entries = vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (
                Value::Text("authData".into()),
                Value::Bytes(auth_data.to_vec()),
            ),
        ];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
        buf
    }

    /// The registration-side expectation over `context`.
    pub fn register_expectation(context: &ChallengeContext) -> RegistrationExpectation {
        RegistrationExpectation {
            context: context.clone(),
            rp_id: "maskura.dev".to_string(),
            origins: vec!["https://maskura.dev".to_string()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    fn cred() -> TestCredential {
        test_credential([7u8; 32])
    }

    #[test]
    fn w3c_es256_assertion_signature_fixture() {
        // WebAuthn Level 3 Recommendation (2026-08-25), section 16.2.
        // Independent signature/key/message vector; its random challenge and
        // UV-optional flags are not a Maskura policy-approval ceremony.
        let key = CoseEs256Key::parse_cose(&hex::decode("a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220").unwrap()).unwrap();
        let auth = hex::decode(
            "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000",
        )
        .unwrap();
        let client = hex::decode("7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d").unwrap();
        let signature = hex::decode("3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87").unwrap();
        verify_der_signature(&auth, &client, &signature, &key).unwrap();
        let mut tampered = client;
        tampered.push(b' ');
        assert!(verify_der_signature(&auth, &tampered, &signature, &key).is_err());
    }

    fn resign(cred: &TestCredential, proof: &mut WebAuthnProof) {
        use p256::ecdsa::signature::Signer;
        let mut message = BASE64URL.decode(&proof.authenticator_data).unwrap();
        message.extend_from_slice(&Sha256::digest(proof.client_data_json.as_bytes()));
        let sig: Signature = cred.signing.sign(&message);
        proof.signature = BASE64URL.encode(sig.to_der().as_bytes());
    }

    #[test]
    fn der_is_required_and_raw_signature_is_rejected() {
        let cred = cred();
        let ctx = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let mut proof = assert_proof(&cred, &ctx, "maskura.dev", "https://maskura.dev", UP_UV);
        let expected = expectation(ctx.kind, &ctx.workspace_id, &ctx.artifact_digest);
        verify_assertion(&proof, &expected, &cred.cose).unwrap();
        let sig = Signature::from_der(&BASE64URL.decode(&proof.signature).unwrap()).unwrap();
        proof.signature = BASE64URL.encode(sig.to_bytes());
        assert!(verify_assertion(&proof, &expected, &cred.cose).is_err());
    }

    #[test]
    fn signed_cross_origin_and_top_origin_are_rejected() {
        let cred = cred();
        let ctx = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let original = assert_proof(&cred, &ctx, "maskura.dev", "https://maskura.dev", UP_UV);
        let expected = expectation(ctx.kind, &ctx.workspace_id, &ctx.artifact_digest);
        for (cross, top) in [
            (true, None),
            (true, Some("https://evil.example")),
            (false, Some("https://maskura.dev")),
        ] {
            let mut proof = original.clone();
            let mut json: serde_json::Value =
                serde_json::from_str(&proof.client_data_json).unwrap();
            json["crossOrigin"] = cross.into();
            if let Some(top) = top {
                json["topOrigin"] = top.into();
            }
            proof.client_data_json = json.to_string();
            resign(&cred, &mut proof);
            assert!(
                verify_assertion(&proof, &expected, &cred.cose)
                    .unwrap_err()
                    .to_string()
                    .contains("cross-origin")
            );
        }
        let mut proof = original;
        let mut json: serde_json::Value = serde_json::from_str(&proof.client_data_json).unwrap();
        json.as_object_mut().unwrap().remove("crossOrigin");
        proof.client_data_json = json.to_string();
        resign(&cred, &mut proof);
        verify_assertion(&proof, &expected, &cred.cose).unwrap();
    }

    #[test]
    fn signed_trailing_challenge_bytes_are_rejected() {
        let cred = cred();
        let ctx = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let mut proof = assert_proof(&cred, &ctx, "maskura.dev", "https://maskura.dev", UP_UV);
        let mut bytes = canonical_cbor(&ctx).unwrap();
        bytes.push(0);
        let mut json: serde_json::Value = serde_json::from_str(&proof.client_data_json).unwrap();
        json["challenge"] = BASE64URL.encode(bytes).into();
        proof.client_data_json = json.to_string();
        resign(&cred, &mut proof);
        let expected = expectation(ctx.kind, &ctx.workspace_id, &ctx.artifact_digest);
        assert!(verify_assertion(&proof, &expected, &cred.cose).is_err());
    }

    #[test]
    fn cose_duplicate_labels_and_trailing_bytes_are_rejected() {
        let encoded = cred().cose.to_cose().unwrap();
        let mut value: ciborium::value::Value =
            ciborium::de::from_reader(encoded.as_slice()).unwrap();
        let ciborium::value::Value::Map(ref mut entries) = value else {
            panic!()
        };
        entries.push(entries[0].clone());
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&value, &mut bytes).unwrap();
        assert!(CoseEs256Key::parse_cose(&bytes).is_err());
        let mut bytes = encoded;
        bytes.push(0);
        assert!(CoseEs256Key::parse_cose(&bytes).is_err());
    }

    #[test]
    fn valid_assertion_verifies_and_returns_context() {
        let cred = cred();
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let proof = assert_proof(&cred, &context, "maskura.dev", "https://maskura.dev", UP_UV);
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let verified = verify_assertion(&proof, &expected, &cred.cose).unwrap();
        assert_eq!(verified, context);
    }

    #[test]
    fn wrong_origin_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let proof = assert_proof(
            &cred,
            &context,
            "maskura.dev",
            "https://evil.example",
            UP_UV,
        );
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let error = verify_assertion(&proof, &expected, &cred.cose).unwrap_err();
        assert!(error.to_string().contains("origin"));
    }

    #[test]
    fn wrong_rp_id_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let proof = assert_proof(&cred, &context, "other.dev", "https://maskura.dev", UP_UV);
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let error = verify_assertion(&proof, &expected, &cred.cose).unwrap_err();
        assert!(error.to_string().contains("RP ID"));
    }

    #[test]
    fn missing_up_flag_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let proof = assert_proof(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            FLAG_UV,
        );
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let error = verify_assertion(&proof, &expected, &cred.cose).unwrap_err();
        assert!(error.to_string().contains("UP"));
    }

    #[test]
    fn missing_uv_flag_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let proof = assert_proof(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            FLAG_UP,
        );
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let error = verify_assertion(&proof, &expected, &cred.cose).unwrap_err();
        assert!(error.to_string().contains("UV"));
    }

    #[test]
    fn attestation_flag_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let proof = assert_proof(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV | FLAG_AT,
        );
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let error = verify_assertion(&proof, &expected, &cred.cose).unwrap_err();
        assert!(error.to_string().contains("AT"));
    }

    #[test]
    fn kind_mismatch_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Login, "", "");
        let proof = assert_proof(&cred, &context, "maskura.dev", "https://maskura.dev", UP_UV);
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        assert!(verify_assertion(&proof, &expected, &cred.cose).is_err());
    }

    #[test]
    fn workspace_mismatch_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let proof = assert_proof(&cred, &context, "maskura.dev", "https://maskura.dev", UP_UV);
        let expected = expectation(ChallengeKind::Receipt, "ws-other", &"c".repeat(64));
        let error = verify_assertion(&proof, &expected, &cred.cose).unwrap_err();
        assert!(error.to_string().contains("workspace"));
    }

    #[test]
    fn artifact_mismatch_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let proof = assert_proof(&cred, &context, "maskura.dev", "https://maskura.dev", UP_UV);
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"d".repeat(64));
        let error = verify_assertion(&proof, &expected, &cred.cose).unwrap_err();
        assert!(error.to_string().contains("artifact"));
    }

    #[test]
    fn audience_mismatch_is_rejected() {
        let cred = cred();
        let mut context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        context.audience = "https://other.example".to_string();
        let proof = assert_proof(&cred, &context, "maskura.dev", "https://maskura.dev", UP_UV);
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let error = verify_assertion(&proof, &expected, &cred.cose).unwrap_err();
        assert!(error.to_string().contains("audience"));
    }

    #[test]
    fn tampered_client_data_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let mut proof = assert_proof(&cred, &context, "maskura.dev", "https://maskura.dev", UP_UV);
        proof.client_data_json = proof
            .client_data_json
            .replace("https://maskura.dev", "https://evil.example");
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        assert!(verify_assertion(&proof, &expected, &cred.cose).is_err());
    }

    #[test]
    fn wrong_credential_key_is_rejected() {
        let cred = cred();
        let other = test_credential([9u8; 32]);
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let proof = assert_proof(&cred, &context, "maskura.dev", "https://maskura.dev", UP_UV);
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let error = verify_assertion(&proof, &expected, &other.cose).unwrap_err();
        assert!(error.to_string().contains("signature"));
        // the correct key still verifies
        verify_assertion(&proof, &expected, &cred.cose).unwrap();
        assert_ne!(other.credential_id, cred.credential_id);
    }

    #[test]
    fn login_challenge_with_workspace_is_rejected() {
        let mut context = challenge(ChallengeKind::Login, "", "");
        context.workspace_id = "ws-1".to_string();
        assert!(context.validate().is_err());
    }

    #[test]
    fn receipt_challenge_requires_hex64_artifact() {
        let mut context = challenge(ChallengeKind::Receipt, "ws-1", "short");
        assert!(context.validate().is_err());
        context.artifact_digest = "c".repeat(64);
        context.validate().unwrap();
    }

    #[test]
    fn short_nonce_is_rejected() {
        let mut context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        context.nonce = BASE64URL.encode([0u8; 16]);
        assert!(
            context
                .validate()
                .unwrap_err()
                .to_string()
                .contains("nonce")
        );
    }

    #[test]
    fn expiry_must_follow_issue() {
        let mut context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        context.expires_at = context.issued_at;
        assert!(context.validate().is_err());
    }

    #[test]
    fn unsupported_challenge_version_is_rejected() {
        let mut context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        context.v = 2;
        assert!(
            context
                .validate()
                .unwrap_err()
                .to_string()
                .contains("version")
        );
    }

    #[test]
    fn cose_rejects_non_es256_algorithm() {
        let mut entries = vec![
            (
                ciborium::value::Value::Integer(1.into()),
                ciborium::value::Value::Integer(2.into()),
            ),
            (
                ciborium::value::Value::Integer(3.into()),
                ciborium::value::Value::Integer((-8).into()),
            ),
            (
                ciborium::value::Value::Integer((-1).into()),
                ciborium::value::Value::Integer(1.into()),
            ),
            (
                ciborium::value::Value::Integer((-2).into()),
                ciborium::value::Value::Bytes(vec![0u8; 32]),
            ),
            (
                ciborium::value::Value::Integer((-3).into()),
                ciborium::value::Value::Bytes(vec![0u8; 32]),
            ),
        ];
        entries.dedup_by_key(|_| false);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&ciborium::value::Value::Map(entries), &mut buf).unwrap();
        let error = CoseEs256Key::parse_cose(&buf).unwrap_err();
        assert!(error.to_string().contains("ES256"));
    }

    #[test]
    fn cose_round_trips_a_real_p256_key() {
        let cred = cred();
        let encoded = cred.cose.to_cose().unwrap();
        let parsed = CoseEs256Key::parse_cose(&encoded).unwrap();
        assert_eq!(parsed, cred.cose);
    }

    #[test]
    fn cose_rejects_garbage() {
        assert!(CoseEs256Key::parse_cose(b"not cbor").is_err());
    }

    #[test]
    fn cose_rejects_non_map() {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&ciborium::value::Value::Text("x".into()), &mut buf).unwrap();
        let error = CoseEs256Key::parse_cose(&buf).unwrap_err();
        assert!(error.to_string().contains("map"));
    }

    #[test]
    fn zero_counter_synced_style_assertion_verifies() {
        // assert_proof writes sign_count = 0; a legitimate synced-passkey
        // value that offline verification must accept.
        let cred = cred();
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let proof = assert_proof(&cred, &context, "maskura.dev", "https://maskura.dev", UP_UV);
        let data = BASE64URL.decode(&proof.authenticator_data).unwrap();
        assert_eq!(&data[33..37], &[0, 0, 0, 0]);
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        verify_assertion(&proof, &expected, &cred.cose).unwrap();
    }

    #[test]
    fn cross_domain_login_assertion_cannot_verify_a_receipt() {
        // A login assertion (no artifact binding) replayed against a receipt
        // expectation must fail on kind and artifact bounds.
        let cred = cred();
        let login = challenge(ChallengeKind::Login, "", "");
        let proof = assert_proof(&cred, &login, "maskura.dev", "https://maskura.dev", UP_UV);
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let error = verify_assertion(&proof, &expected, &cred.cose).unwrap_err();
        assert!(
            error.to_string().contains("artifact") || error.to_string().contains("kind"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn short_authenticator_data_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let mut proof = assert_proof(&cred, &context, "maskura.dev", "https://maskura.dev", UP_UV);
        proof.authenticator_data = BASE64URL.encode([0u8; 10]);
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let error = verify_assertion(&proof, &expected, &cred.cose).unwrap_err();
        assert!(error.to_string().contains("shorter"));
    }

    #[test]
    fn malformed_signature_is_rejected_without_panic() {
        let cred = cred();
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let mut proof = assert_proof(&cred, &context, "maskura.dev", "https://maskura.dev", UP_UV);
        proof.signature = BASE64URL.encode([1u8; 10]);
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let error = verify_assertion(&proof, &expected, &cred.cose).unwrap_err();
        assert!(error.to_string().contains("malformed"));
    }

    #[test]
    fn non_json_client_data_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let mut proof = assert_proof(&cred, &context, "maskura.dev", "https://maskura.dev", UP_UV);
        proof.client_data_json = "{not json".to_string();
        let expected = expectation(ChallengeKind::Receipt, "ws-1", &"c".repeat(64));
        let error = verify_assertion(&proof, &expected, &cred.cose).unwrap_err();
        assert!(error.to_string().contains("JSON"));
    }

    #[test]
    fn register_challenge_validates_and_round_trips() {
        let context = challenge(ChallengeKind::Register, "", "");
        context.validate().unwrap();
        let encoded = context.challenge_string().unwrap();
        let decoded: ChallengeContext =
            ciborium::de::from_reader(&BASE64URL.decode(&encoded).unwrap()[..]).unwrap();
        assert_eq!(decoded, context);
    }

    #[test]
    fn register_challenge_with_workspace_is_rejected() {
        let mut context = challenge(ChallengeKind::Register, "", "");
        context.workspace_id = "ws-1".to_string();
        assert!(context.validate().is_err());
    }

    #[test]
    fn valid_fmt_none_registration_parses() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (client_data, attestation) = register_attestation(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV_AT,
        );
        let registered =
            parse_registration(&client_data, &attestation, &register_expectation(&context))
                .unwrap();
        assert_eq!(registered.credential_id, cred.credential_id.as_bytes());
        assert_eq!(registered.cose_key, cred.cose);
        assert_eq!(registered.sign_count, 0);
        assert!(!registered.backup_eligible);
        assert!(!registered.backed_up);
    }

    #[test]
    fn registration_golden_vector_is_pinned() {
        // Frozen `fmt:"none"` vector: fixed credential ID bytes and the W3C
        // Level 3 (2026-08-25) §16.2 COSE key. Pins the authData layout and
        // attestationObject encoding accepted by parse_registration.
        let context = ChallengeContext {
            v: CHALLENGE_VERSION,
            kind: ChallengeKind::Register,
            nonce: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".to_string(),
            ceremony_id: "ceremony-golden".to_string(),
            user_id: "user-golden".to_string(),
            session_id: "session-golden".to_string(),
            audience: "https://maskura.dev".to_string(),
            workspace_id: String::new(),
            artifact_digest: String::new(),
            issued_at: 1_000,
            expires_at: 1_600,
        };
        let attestation = hex::decode(concat!(
            "a363666d74646e6f6e656761747453746d74a068617574684461746158a4dea2",
            "63f8198815672b4cfbf6ff844f3dd0d57a91fdd6229a6f25f9bd1b7030434500",
            "000000000000000000000000000000000000000020000102030405060708090a",
            "0b0c0d0e0f101112131415161718191a1b1c1d1e1fa5010203262001215820af",
            "efa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df6122",
            "5820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b",
            "9220"
        ))
        .unwrap();
        let client_data = concat!(
            r#"{"type":"webauthn.create","challenge":"q29hcnRpZmFjdF9kaWdlc3RgaGF1ZGllbmNlc2h0dHBzOi8vbWFza3VyYS5kZXZrY2VyZW1vbnlfaWRvY2VyZW1vbnktZ29sZGVuamV4cGlyZXNfYXQZBkBpaXNzdWVkX2F0GQPoZGtpbmRocmVnaXN0ZXJlbm9uY2V4K0J3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2Nqc2Vzc2lvbl9pZG5zZXNzaW9uLWdvbGRlbmd1c2VyX2lka3VzZXItZ29sZGVuYXYBbHdvcmtzcGFjZV9pZGA","#,
            r#""origin":"https://maskura.dev","crossOrigin":false}"#
        );
        assert_eq!(
            context.challenge_string().unwrap(),
            "q29hcnRpZmFjdF9kaWdlc3RgaGF1ZGllbmNlc2h0dHBzOi8vbWFza3VyYS5kZXZrY2VyZW1vbnlfaWRvY2VyZW1vbnktZ29sZGVuamV4cGlyZXNfYXQZBkBpaXNzdWVkX2F0GQPoZGtpbmRocmVnaXN0ZXJlbm9uY2V4K0J3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2NIQndjSEJ3Y0hCd2Nqc2Vzc2lvbl9pZG5zZXNzaW9uLWdvbGRlbmd1c2VyX2lka3VzZXItZ29sZGVuYXYBbHdvcmtzcGFjZV9pZGA"
        );
        let registered =
            parse_registration(client_data, &attestation, &register_expectation(&context)).unwrap();
        assert_eq!(registered.credential_id, (0u8..32).collect::<Vec<u8>>());
        assert_eq!(
            registered.cose_key,
            CoseEs256Key {
                x: hex::decode("afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                y: hex::decode("930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            }
        );
    }

    #[test]
    fn registration_wrong_challenge_echo_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (client_data, attestation) = register_attestation(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV_AT,
        );
        let mut other = context.clone();
        other.nonce = BASE64URL.encode([9u8; 32]);
        let error = parse_registration(&client_data, &attestation, &register_expectation(&other))
            .unwrap_err();
        assert!(error.to_string().contains("challenge"));
    }

    #[test]
    fn registration_login_challenge_cannot_register() {
        // A login-kind challenge echo must not satisfy a register expectation
        // even with identical bytes for every other field.
        let cred = cred();
        let login = challenge(ChallengeKind::Login, "", "");
        let (client_data, attestation) = register_attestation(
            &cred,
            &login,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV_AT,
        );
        let mut register = login.clone();
        register.kind = ChallengeKind::Register;
        let error =
            parse_registration(&client_data, &attestation, &register_expectation(&register))
                .unwrap_err();
        assert!(error.to_string().contains("challenge"));
    }

    #[test]
    fn registration_cannot_verify_as_assertion() {
        // Cross-domain replay: a create attestation carries no assertion
        // signature and must never verify as one.
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (client_data, attestation) = register_attestation(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV_AT,
        );
        let proof = WebAuthnProof {
            credential_id: cred.credential_id.clone(),
            client_data_json: client_data,
            authenticator_data: BASE64URL.encode(&attestation),
            signature: BASE64URL.encode([0u8; 8]),
        };
        let expected = expectation(ChallengeKind::Login, "", "");
        assert!(verify_assertion(&proof, &expected, &cred.cose).is_err());
    }

    #[test]
    fn registration_wrong_origin_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (client_data, attestation) = register_attestation(
            &cred,
            &context,
            "maskura.dev",
            "https://evil.example",
            UP_UV_AT,
        );
        let error = parse_registration(&client_data, &attestation, &register_expectation(&context))
            .unwrap_err();
        assert!(error.to_string().contains("origin"));
    }

    #[test]
    fn registration_cross_origin_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (mut client_data, attestation) = register_attestation(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV_AT,
        );
        for (cross, top) in [(true, None), (false, Some("https://maskura.dev"))] {
            let mut json: serde_json::Value = serde_json::from_str(&client_data).unwrap();
            json["crossOrigin"] = cross.into();
            if let Some(top) = top {
                json["topOrigin"] = top.into();
            }
            client_data = serde_json::to_string(&json).unwrap();
            let error =
                parse_registration(&client_data, &attestation, &register_expectation(&context))
                    .unwrap_err();
            assert!(error.to_string().contains("cross-origin"));
        }
    }

    #[test]
    fn registration_at_clear_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (client_data, attestation) =
            register_attestation(&cred, &context, "maskura.dev", "https://maskura.dev", UP_UV);
        let error = parse_registration(&client_data, &attestation, &register_expectation(&context))
            .unwrap_err();
        assert!(error.to_string().contains("AT"));
    }

    #[test]
    fn registration_wrong_rp_id_hash_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (client_data, attestation) = register_attestation(
            &cred,
            &context,
            "other.dev",
            "https://maskura.dev",
            UP_UV_AT,
        );
        let error = parse_registration(&client_data, &attestation, &register_expectation(&context))
            .unwrap_err();
        assert!(error.to_string().contains("RP ID"));
    }

    #[test]
    fn registration_malformed_cose_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (client_data, attestation) = register_attestation_with_cred_id(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV_AT,
            b"cred-1",
            Some(b"not cbor"),
        );
        let error = parse_registration(&client_data, &attestation, &register_expectation(&context))
            .unwrap_err();
        assert!(error.to_string().contains("COSE"), "{error}");
    }

    #[test]
    fn registration_oversized_cose_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        // A well-formed COSE map padded past the 4 KiB key limit must not
        // parse (unknown labels are ignored, size is not).
        let mut cose = cred.cose.to_cose().unwrap();
        let mut entries = match ciborium::de::from_reader(&cose[..]) {
            Ok(ciborium::value::Value::Map(entries)) => entries,
            other => panic!("cose must be a map: {other:?}"),
        };
        entries.push((
            ciborium::value::Value::Integer(49.into()),
            ciborium::value::Value::Bytes(vec![0u8; 5_000]),
        ));
        cose.clear();
        ciborium::ser::into_writer(&ciborium::value::Value::Map(entries), &mut cose).unwrap();
        assert!(cose.len() > 4096);
        let (client_data, attestation) = register_attestation_with_cred_id(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV_AT,
            b"cred-1",
            Some(&cose),
        );
        let error = parse_registration(&client_data, &attestation, &register_expectation(&context))
            .unwrap_err();
        assert!(
            error.to_string().contains("COSE") || error.to_string().contains("CBOR"),
            "{error}"
        );
    }

    #[test]
    fn registration_oversized_credential_id_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (client_data, attestation) = register_attestation_with_cred_id(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV_AT,
            &[0u8; 1_025],
            None,
        );
        let error = parse_registration(&client_data, &attestation, &register_expectation(&context))
            .unwrap_err();
        assert!(error.to_string().contains("credential ID"), "{error}");
    }

    #[test]
    fn registration_oversized_inputs_are_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (client_data, attestation) = register_attestation(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV_AT,
        );
        let expected = register_expectation(&context);
        let padded_client = format!("{client_data}{}", " ".repeat(16_384));
        assert!(parse_registration(&padded_client, &attestation, &expected).is_err());
        let mut padded_attestation = attestation.clone();
        padded_attestation.extend_from_slice(&[0u8; 16_384]);
        assert!(parse_registration(&client_data, &padded_attestation, &expected).is_err());
    }

    #[test]
    fn registration_wrong_type_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (mut client_data, attestation) = register_attestation(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV_AT,
        );
        let mut json: serde_json::Value = serde_json::from_str(&client_data).unwrap();
        json["type"] = "webauthn.get".into();
        client_data = serde_json::to_string(&json).unwrap();
        let error = parse_registration(&client_data, &attestation, &register_expectation(&context))
            .unwrap_err();
        assert!(error.to_string().contains("webauthn.create"), "{error}");
    }

    #[test]
    fn registration_non_none_attestation_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (client_data, mut attestation) = register_attestation(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV_AT,
        );
        // Flip "none" to "tpm" inside the serialized attestation object.
        let needle = b"none".to_vec();
        let pos = attestation
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap();
        attestation[pos..pos + 4].copy_from_slice(b"tpm\x00");
        let error = parse_registration(&client_data, &attestation, &register_expectation(&context))
            .unwrap_err();
        assert!(error.to_string().contains("attestation format"), "{error}");
    }

    #[test]
    fn registration_expectation_must_be_register_kind() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (client_data, attestation) = register_attestation(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV_AT,
        );
        let mut expected = register_expectation(&context);
        expected.context.kind = ChallengeKind::Login;
        let error = parse_registration(&client_data, &attestation, &expected).unwrap_err();
        assert!(error.to_string().contains("register"), "{error}");
    }

    #[test]
    fn registration_missing_up_or_uv_is_rejected() {
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        for flags in [FLAG_UV | FLAG_AT, FLAG_UP | FLAG_AT] {
            let (client_data, attestation) =
                register_attestation(&cred, &context, "maskura.dev", "https://maskura.dev", flags);
            let error =
                parse_registration(&client_data, &attestation, &register_expectation(&context))
                    .unwrap_err();
            assert!(error.to_string().contains("flag"), "{error}");
        }
    }

    #[test]
    fn registration_backup_flags_round_trip() {
        use super::FLAG_BE;
        use super::FLAG_BS;
        let cred = cred();
        let context = challenge(ChallengeKind::Register, "", "");
        let (client_data, attestation) = register_attestation(
            &cred,
            &context,
            "maskura.dev",
            "https://maskura.dev",
            UP_UV_AT | FLAG_BE | FLAG_BS,
        );
        let registered =
            parse_registration(&client_data, &attestation, &register_expectation(&context))
                .unwrap();
        assert!(registered.backup_eligible);
        assert!(registered.backed_up);
    }
}
