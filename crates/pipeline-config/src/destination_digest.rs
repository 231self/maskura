//! Single source of truth for destination-binding digest preimages.
//!
//! These digests are signed material: the customer-approved `EffectiveState`
//! commits to where data physically goes, and the enforcement gate later
//! check/uses the request-time destination snapshot against the committed
//! value. Both the gateway (at request time) and the control plane (at
//! construction time) must compute byte-identical digests, so every preimage
//! lives here — never re-implemented inline at a call site.

use sha2::{Digest, Sha256};

/// Length-prefixed field encoding used by the placement-policy fingerprint.
/// Prefixing the length removes ambiguity between adjacent variable-length
/// fields.
fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hex_digest(hasher: Sha256) -> String {
    hex::encode(hasher.finalize())
}

/// Digest of a per-object presigned backend override.
///
/// Preimage: `maskura-presigned\0{origin}`.
pub fn presigned_configuration_sha256(origin: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"maskura-presigned\0");
    h.update(origin.as_bytes());
    hex_digest(h)
}

/// Digest of a workspace's static-credential S3-compatible destination.
///
/// Preimage: `maskura-s3-compatible\0{endpoint}\0{region}`.
pub fn s3_compatible_configuration_sha256(endpoint: &str, region: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"maskura-s3-compatible\0");
    h.update(endpoint.as_bytes());
    h.update(b"\0");
    h.update(region.as_bytes());
    hex_digest(h)
}

/// Digest of a workspace's IAM-role AWS destination.
///
/// Preimage: `maskura-aws-role\0{role_arn}\0{region}`.
pub fn aws_role_configuration_sha256(role_arn: &str, region: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"maskura-aws-role\0");
    h.update(role_arn.as_bytes());
    h.update(b"\0");
    h.update(region.as_bytes());
    hex_digest(h)
}

/// Digest of the operator-wide global S3 destination (explicit single-tenant).
///
/// Preimage: `maskura-global-s3\0`.
pub fn global_s3_configuration_sha256() -> String {
    let mut h = Sha256::new();
    h.update(b"maskura-global-s3\0");
    hex_digest(h)
}

/// Digest of one managed backend's immutable non-secret configuration facts.
///
/// Preimage: `maskura-managed-backend\0{provider}\0{instance}\0{account}\0{endpoint}\0{region}\0{bucket}\0{weight.to_be}\0{capacity.to_be}\0{cred_epoch.to_be}`.
#[allow(clippy::too_many_arguments)]
pub fn managed_backend_configuration_sha256(
    provider: &str,
    provider_instance_id: &str,
    provider_account_id: &str,
    endpoint: &str,
    region: &str,
    bucket: &str,
    placement_weight: u64,
    placement_capacity_units: u64,
    credential_epoch: u64,
) -> String {
    let mut h = Sha256::new();
    h.update(b"maskura-managed-backend\0");
    h.update(provider.as_bytes());
    h.update(b"\0");
    h.update(provider_instance_id.as_bytes());
    h.update(b"\0");
    h.update(provider_account_id.as_bytes());
    h.update(b"\0");
    h.update(endpoint.as_bytes());
    h.update(b"\0");
    h.update(region.as_bytes());
    h.update(b"\0");
    h.update(bucket.as_bytes());
    h.update(b"\0");
    h.update(placement_weight.to_be_bytes());
    h.update(placement_capacity_units.to_be_bytes());
    h.update(credential_epoch.to_be_bytes());
    hex_digest(h)
}

/// Canonical fingerprint of a managed placement policy: the version plus every
/// backend's identity, weight, and capacity in a stable order. A policy edit
/// changes the fingerprint, so a version bump is required to admit it.
///
/// Preimage: `s4-placement-policy\0{version.to_be}` followed by each sorted
/// `(backend_id, weight, capacity)` triple encoded as length-prefixed fields.
pub fn placement_policy_fingerprint(
    version: u32,
    backends: impl IntoIterator<Item = (String, u64, u64)>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"s4-placement-policy\0");
    hasher.update(version.to_be_bytes());
    let mut facts: Vec<_> = backends.into_iter().collect();
    facts.sort();
    for (backend_id, weight, capacity) in facts {
        hash_field(&mut hasher, backend_id.as_bytes());
        hash_field(&mut hasher, &weight.to_be_bytes());
        hash_field(&mut hasher, &capacity.to_be_bytes());
    }
    hex_digest(hasher)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors pin each preimage. Any drift in the encoding breaks these
    // and therefore breaks compatibility with already-signed material. The
    // expected values are the exact hex the gateway historically produced.
    #[test]
    fn presigned_digest_is_pinned() {
        assert_eq!(
            presigned_configuration_sha256("https://s3.example.com"),
            "ace144a1bc8db0ea4bff2510dc0ef039762af795cc45282fceb7b2c990ffe316"
        );
    }

    #[test]
    fn s3_compatible_digest_is_pinned() {
        assert_eq!(
            s3_compatible_configuration_sha256("https://s3.example.com/", "us-east-1"),
            "a986b662f8069e5b073707b17c9123e98b7bcb705c43f98ee9e8db0f3471682b"
        );
    }

    #[test]
    fn aws_role_digest_is_pinned() {
        assert_eq!(
            aws_role_configuration_sha256("arn:aws:iam::123:role/r", "us-west-2"),
            "377979a6b0447458e0317edca55d75d922fa909e32a5690835da0ddfd83f8995"
        );
    }

    #[test]
    fn global_s3_digest_is_pinned() {
        assert_eq!(
            global_s3_configuration_sha256(),
            "5a9156fdb49dfc89b193e61761d09011b06a4f8408098c4efe29eaeb04d8f182"
        );
    }

    #[test]
    fn managed_backend_digest_is_pinned() {
        assert_eq!(
            managed_backend_configuration_sha256(
                "aws",
                "i-1",
                "acct-1",
                "https://s3.amazonaws.com",
                "us-east-1",
                "bucket-1",
                2,
                1,
                7,
            ),
            "27b765d17bde5f8d99a40ba0eda999762090f3becaa3d50824386aa62b4a8d5c"
        );
    }

    #[test]
    fn placement_fingerprint_is_pinned() {
        assert_eq!(
            placement_policy_fingerprint(1, [("a".to_string(), 1, 2), ("b".to_string(), 3, 4)]),
            "1450298f70f46a4f639440b1721e9f516ee0093ab61de73508d67270b7617fe9"
        );
    }

    #[test]
    fn digest_lengths_are_hex64() {
        assert_eq!(presigned_configuration_sha256("o").len(), 64);
        assert_eq!(s3_compatible_configuration_sha256("e", "r").len(), 64);
        assert_eq!(aws_role_configuration_sha256("arn", "r").len(), 64);
        assert_eq!(global_s3_configuration_sha256().len(), 64);
        assert_eq!(
            managed_backend_configuration_sha256("p", "i", "a", "e", "r", "b", 1, 2, 3).len(),
            64
        );
        assert_eq!(placement_policy_fingerprint(1, Vec::new()).len(), 64);
    }

    #[test]
    fn distinct_inputs_give_distinct_digests() {
        assert_ne!(
            presigned_configuration_sha256("a"),
            presigned_configuration_sha256("b")
        );
        assert_ne!(
            s3_compatible_configuration_sha256("e1", "r"),
            s3_compatible_configuration_sha256("e2", "r")
        );
        assert_ne!(
            s3_compatible_configuration_sha256("e", "r1"),
            s3_compatible_configuration_sha256("e", "r2")
        );
        assert_ne!(
            aws_role_configuration_sha256("arn1", "r"),
            aws_role_configuration_sha256("arn2", "r")
        );
        assert_ne!(
            managed_backend_configuration_sha256("p", "i", "a", "e", "r", "b", 1, 2, 3),
            managed_backend_configuration_sha256("p", "i", "a", "e", "r", "b", 1, 2, 4)
        );
    }

    #[test]
    fn mode_prefixes_domain_separate() {
        // A same-valued endpoint/region under different modes must not collide.
        assert_ne!(
            s3_compatible_configuration_sha256("https://x", "r"),
            aws_role_configuration_sha256("https://x", "r")
        );
    }

    #[test]
    fn placement_fingerprint_is_order_independent_and_version_sensitive() {
        let a = placement_policy_fingerprint(1, [("a".to_string(), 1, 2), ("b".to_string(), 3, 4)]);
        let b = placement_policy_fingerprint(1, [("b".to_string(), 3, 4), ("a".to_string(), 1, 2)]);
        assert_eq!(a, b, "backend order must not change the fingerprint");
        let v2 =
            placement_policy_fingerprint(2, [("a".to_string(), 1, 2), ("b".to_string(), 3, 4)]);
        assert_ne!(a, v2, "version must change the fingerprint");
        let w = placement_policy_fingerprint(1, [("a".to_string(), 1, 2), ("b".to_string(), 5, 4)]);
        assert_ne!(a, w, "weight must change the fingerprint");
    }
}
