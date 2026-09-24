use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::ConfigError;

/// Canonical CBOR encoding shared by envelope, receipt, and challenge digests:
/// serde value with BTreeMap-ordered JSON keys, then CBOR. Mirrors the
/// construction used by `PipelineFile::canonical_body`.
pub fn canonical_cbor<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, ConfigError> {
    let json = serde_json::to_value(value)
        .map_err(|error| ConfigError::invalid(format!("cannot canonicalize value: {error}")))?;
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&json, &mut encoded)
        .map_err(|error| ConfigError::invalid(format!("cannot encode canonical body: {error}")))?;
    Ok(encoded)
}

/// SHA-256 of `bytes` as 64 lowercase hex chars.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// True when `value` is exactly 64 lowercase hexadecimal characters.
pub fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Canonical digest of a serializable value: `sha256(canonical_cbor(value))`
/// as 64 lowercase hex.
pub fn digest_of<T: Serialize + ?Sized>(value: &T) -> Result<String, ConfigError> {
    Ok(sha256_hex(&canonical_cbor(value)?))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn canonical_cbor_is_key_order_independent() {
        let mut a = BTreeMap::new();
        a.insert("b", 2u32);
        a.insert("a", 1u32);
        let mut b = BTreeMap::new();
        b.insert("a", 1u32);
        b.insert("b", 2u32);
        assert_eq!(canonical_cbor(&a).unwrap(), canonical_cbor(&b).unwrap());
    }

    #[test]
    fn sha256_hex_is_lowercase_64() {
        let digest = sha256_hex(b"");
        assert_eq!(digest.len(), 64);
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(is_hex64(&digest));
    }

    #[test]
    fn is_hex64_rejects_uppercase_short_and_empty() {
        assert!(!is_hex64(""));
        assert!(!is_hex64("abc"));
        assert!(!is_hex64(&"A".repeat(64)));
        assert!(!is_hex64(&"0".repeat(63)));
        assert!(!is_hex64(&format!("{}g", "0".repeat(63))));
        assert!(is_hex64(&"0".repeat(64)));
    }

    #[test]
    fn digest_of_differs_for_different_values() {
        assert_ne!(digest_of(&1u32).unwrap(), digest_of(&2u32).unwrap());
    }
}
