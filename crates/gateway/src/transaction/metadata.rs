//! Versioned journal/authority metadata shared by publication, reconciliation,
//! reads, and repair. Keys beginning with `:` cannot be HTTP header names and
//! are reserved for internal serialization, not sent to the provider.

use std::collections::BTreeMap;

const VERSION_KEY: &str = ":maskura:metadata-version";
const USER_PREFIX: &str = ":maskura:user:";
const ENCODING_KEY: &str = ":maskura:representation:content-encoding";
const VERSION: &str = "1";

/// Provider metadata keys used to identify or bind the physical transaction.
/// Customer values must never overwrite any of them.
pub(crate) const RESERVED_PROVIDER_NAMES: &[&str] = &[
    "maskura-operation-id",
    "maskura-sha256",
    "maskura-size",
    "maskura-generation",
    "maskura-provider-instance",
    "maskura-provider-account",
    "maskura-credential-epoch",
];

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Decoded {
    pub(crate) versioned: bool,
    pub(crate) content_type: Option<String>,
    pub(crate) content_encoding: Option<String>,
    pub(crate) user_metadata: BTreeMap<String, String>,
    pub(crate) internal: BTreeMap<String, String>,
}

fn valid_user_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
        && !RESERVED_PROVIDER_NAMES
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

fn valid_value(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
}

#[cfg(test)]
pub(crate) fn encode(
    content_type: &str,
    users: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, &'static str> {
    encode_with_representation(content_type, &BTreeMap::new(), users)
}

pub(crate) fn encode_with_representation(
    content_type: &str,
    representation: &BTreeMap<String, String>,
    users: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, &'static str> {
    if !valid_value(content_type) {
        return Err("invalid representation metadata value");
    }
    let mut record = BTreeMap::from([
        (VERSION_KEY.to_string(), VERSION.to_string()),
        ("content-type".to_string(), content_type.to_string()),
    ]);
    for (key, value) in representation {
        if key != "content-encoding" || !valid_value(value) {
            return Err("invalid representation metadata");
        }
        record.insert(ENCODING_KEY.to_string(), value.clone());
    }
    for (key, value) in users {
        if !valid_user_name(key) || !valid_value(value) {
            return Err("invalid or reserved customer metadata name");
        }
        record.insert(format!("{USER_PREFIX}{key}"), value.clone());
    }
    Ok(record)
}

pub(crate) fn decode(record: &BTreeMap<String, String>) -> Result<Decoded, &'static str> {
    let versioned = match record.get(VERSION_KEY) {
        Some(value) if value == VERSION => true,
        Some(_) => return Err("unsupported metadata record version"),
        None => false,
    };
    let mut decoded = Decoded {
        versioned,
        content_type: None,
        content_encoding: None,
        user_metadata: BTreeMap::new(),
        internal: BTreeMap::new(),
    };
    for (key, value) in record {
        if key == VERSION_KEY {
            continue;
        }
        if !valid_value(value) {
            return Err("invalid metadata value");
        }
        if key == "content-type" {
            decoded.content_type = Some(value.clone());
        } else if versioned && key == ENCODING_KEY {
            decoded.content_encoding = Some(value.clone());
        } else if matches!(
            key.as_str(),
            "maskura-generation"
                | "maskura-provider-instance"
                | "maskura-provider-account"
                | "maskura-credential-epoch"
        ) {
            decoded.internal.insert(key.clone(), value.clone());
        } else if versioned && key.starts_with(USER_PREFIX) {
            let name = &key[USER_PREFIX.len()..];
            if !valid_user_name(name) {
                return Err("invalid or reserved customer metadata name");
            }
            decoded
                .user_metadata
                .insert(name.to_string(), value.clone());
        } else {
            return Err("ambiguous or corrupt metadata record");
        }
    }
    if versioned && decoded.content_type.is_none() {
        return Err("versioned metadata record is missing content type");
    }
    Ok(decoded)
}

/// Convert only a validated record into provider metadata. Representation
/// headers stay separate; transaction identity is always supplied by the
/// trusted operation, never read from customer metadata.
pub(crate) fn provider_metadata(
    record: &BTreeMap<String, String>,
    operation_id: &str,
    digest: Option<&str>,
    size: Option<u64>,
) -> Result<BTreeMap<String, String>, &'static str> {
    if !valid_value(operation_id) || digest.is_some_and(|value| !valid_value(value)) {
        return Err("invalid transaction metadata value");
    }
    let decoded = decode(record)?;
    let mut result = decoded.user_metadata;
    result.extend(decoded.internal);
    result.insert("maskura-operation-id".to_string(), operation_id.to_string());
    if let Some(digest) = digest {
        result.insert("maskura-sha256".to_string(), digest.to_string());
    }
    if let Some(size) = size {
        result.insert("maskura-size".to_string(), size.to_string());
    }
    Ok(result)
}

/// The child journal must contain exactly the logical recipe's customer
/// metadata and its independently recorded physical identity. Historical
/// records with both metadata maps empty carry no metadata claim and retain
/// their previous recovery behavior; mixed or unknown records fail closed.
pub(crate) fn managed_child_matches(
    recipe: &BTreeMap<String, String>,
    child: &BTreeMap<String, String>,
    generation: &str,
    instance: &str,
    account: &str,
    credential_epoch: u64,
) -> Result<bool, &'static str> {
    let parent = decode(recipe)?;
    let child_decoded = decode(child)?;
    if !parent.versioned && !child_decoded.versioned && recipe.is_empty() && child.is_empty() {
        return Ok(true);
    }
    let expected_internal = BTreeMap::from([
        ("maskura-generation".to_string(), generation.to_string()),
        (
            "maskura-provider-instance".to_string(),
            instance.to_string(),
        ),
        ("maskura-provider-account".to_string(), account.to_string()),
        (
            "maskura-credential-epoch".to_string(),
            credential_epoch.to_string(),
        ),
    ]);
    Ok(parent.versioned == child_decoded.versioned
        && parent.internal.is_empty()
        && parent.content_type == child_decoded.content_type
        && parent.content_encoding == child_decoded.content_encoding
        && parent.user_metadata == child_decoded.user_metadata
        && child_decoded.internal == expected_internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn namespaced_user_keys_stay_distinct_from_representation_and_internal_fields() {
        let users = BTreeMap::from([
            ("content-type".to_string(), "user-marker".to_string()),
            ("project".to_string(), "synthetic".to_string()),
        ]);
        let record = encode("text/plain", &users).unwrap();
        assert_eq!(
            record.get("content-type").map(String::as_str),
            Some("text/plain")
        );
        let decoded = decode(&record).unwrap();
        assert_eq!(decoded.user_metadata, users);
        assert_eq!(decoded.content_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn representation_encoding_is_separate_from_user_metadata() {
        let representation =
            BTreeMap::from([("content-encoding".to_string(), "identity".to_string())]);
        let users =
            BTreeMap::from([("content-encoding".to_string(), "customer-value".to_string())]);
        let record = encode_with_representation("text/plain", &representation, &users).unwrap();
        let decoded = decode(&record).unwrap();
        assert_eq!(decoded.content_encoding.as_deref(), Some("identity"));
        assert_eq!(decoded.user_metadata, users);
        let provider = provider_metadata(&record, "operation", None, None).unwrap();
        assert_eq!(
            provider.get("content-encoding").map(String::as_str),
            Some("customer-value")
        );
        assert!(!provider.keys().any(|key| key.starts_with(':')));
    }

    #[test]
    fn reserved_provider_names_are_rejected_case_insensitively() {
        for key in RESERVED_PROVIDER_NAMES {
            let users = BTreeMap::from([(key.to_ascii_uppercase(), "untrusted".to_string())]);
            assert!(encode("text/plain", &users).is_err(), "{key}");
        }
    }

    #[test]
    fn legacy_known_authority_fields_are_read_without_inventing_user_metadata() {
        let legacy = BTreeMap::from([
            ("content-type".to_string(), "text/plain".to_string()),
            (
                "maskura-generation".to_string(),
                "synthetic-generation".to_string(),
            ),
        ]);
        let decoded = decode(&legacy).unwrap();
        assert!(decoded.user_metadata.is_empty());
        assert_eq!(
            decoded.internal.get("maskura-generation"),
            legacy.get("maskura-generation")
        );
    }

    #[test]
    fn unknown_version_ambiguous_legacy_and_corrupt_names_fail_closed() {
        let mut versioned = encode("text/plain", &BTreeMap::new()).unwrap();
        versioned.insert(VERSION_KEY.to_string(), "999".to_string());
        assert!(decode(&versioned).is_err());
        assert!(
            decode(&BTreeMap::from([(
                "project".to_string(),
                "ambiguous".to_string()
            )]))
            .is_err()
        );
        let mut versioned = encode("text/plain", &BTreeMap::new()).unwrap();
        versioned.insert(format!("{USER_PREFIX}maskura-size"), "fake".to_string());
        assert!(decode(&versioned).is_err());
        let mut versioned = encode("text/plain", &BTreeMap::new()).unwrap();
        versioned.insert(format!("{USER_PREFIX}project"), "bad\r\nvalue".to_string());
        assert!(decode(&versioned).is_err());
        let mut versioned = encode("text/plain", &BTreeMap::new()).unwrap();
        versioned.remove("content-type");
        assert!(decode(&versioned).is_err());
    }

    #[test]
    fn provider_values_keep_customer_names_without_exposing_record_namespace() {
        let users = BTreeMap::from([
            ("content-type".to_string(), "user-marker".to_string()),
            ("project".to_string(), "synthetic".to_string()),
        ]);
        let mut record = encode("text/plain", &users).unwrap();
        record.insert("maskura-generation".to_string(), "generation".to_string());
        let provider = provider_metadata(&record, "operation", Some("digest"), Some(9)).unwrap();
        assert_eq!(
            provider.get("content-type").map(String::as_str),
            Some("user-marker")
        );
        assert_eq!(
            provider.get("project").map(String::as_str),
            Some("synthetic")
        );
        assert_eq!(
            provider.get("maskura-generation").map(String::as_str),
            Some("generation")
        );
        assert_eq!(
            provider.get("maskura-operation-id").map(String::as_str),
            Some("operation")
        );
        assert_eq!(
            provider.get("maskura-sha256").map(String::as_str),
            Some("digest")
        );
        assert_eq!(provider.get("maskura-size").map(String::as_str), Some("9"));
        assert!(!provider.keys().any(|key| key.starts_with(':')));
    }

    #[test]
    fn malformed_legacy_record_cannot_be_used_to_rewrite_provider_metadata() {
        let ambiguous = BTreeMap::from([("project".to_string(), "untrusted".to_string())]);
        assert!(provider_metadata(&ambiguous, "operation", Some("digest"), Some(9)).is_err());
        let spoofed = BTreeMap::from([("maskura-operation-id".to_string(), "other".to_string())]);
        assert!(provider_metadata(&spoofed, "operation", Some("digest"), Some(9)).is_err());
    }

    #[test]
    fn managed_child_must_bind_recipe_and_exact_physical_identity() {
        for users in [
            BTreeMap::new(),
            BTreeMap::from([("project".to_string(), "synthetic".to_string())]),
        ] {
            let recipe = encode("text/plain", &users).unwrap();
            let mut child = recipe.clone();
            child.extend(BTreeMap::from([
                ("maskura-generation".to_string(), "generation".to_string()),
                (
                    "maskura-provider-instance".to_string(),
                    "instance".to_string(),
                ),
                (
                    "maskura-provider-account".to_string(),
                    "account".to_string(),
                ),
                ("maskura-credential-epoch".to_string(), "1".to_string()),
            ]));
            assert!(
                managed_child_matches(&recipe, &child, "generation", "instance", "account", 1)
                    .unwrap()
            );
            assert!(
                !managed_child_matches(&recipe, &child, "generation", "instance", "account", 2)
                    .unwrap()
            );
            child.insert(format!("{USER_PREFIX}extra"), "tampered".to_string());
            assert!(
                !managed_child_matches(&recipe, &child, "generation", "instance", "account", 1)
                    .unwrap()
            );
        }
    }

    #[test]
    fn legacy_empty_child_recipe_has_no_invented_user_metadata() {
        let empty = BTreeMap::new();
        assert!(
            managed_child_matches(&empty, &empty, "generation", "instance", "account", 1).unwrap()
        );
        let legacy_recipe =
            BTreeMap::from([("content-type".to_string(), "text/plain".to_string())]);
        assert!(
            !managed_child_matches(
                &legacy_recipe,
                &empty,
                "generation",
                "instance",
                "account",
                1
            )
            .unwrap()
        );
    }
}
