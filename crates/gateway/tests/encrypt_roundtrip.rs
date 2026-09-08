//! Envelope encryption roundtrip: the gateway encrypts PII fields with the
//! API key's public key, and a client holding the private key can decrypt
//! them back to plaintext.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use s4_gateway::Format;
use s4_gateway::hybrid::{HybridPrivateKey, HybridPublicKey};
use s4_gateway::plugin_registry::PluginRegistry;
use std::fs;
use std::path::PathBuf;

mod common;

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("pii")
        .join("crypto")
        .join(name)
        .to_string_lossy()
        .to_string()
}

fn read_component(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("components")
            .join(name),
    )
    .unwrap_or_else(|_| panic!("component not found: {name}; run `just build-filters` first"))
}

fn encrypt_registry() -> PluginRegistry {
    let registry = PluginRegistry::new();
    registry
        .import(
            "envelope-encrypt",
            &read_component("envelope-encrypt.component.wasm"),
        )
        .unwrap();
    registry
}

fn process(registry: &PluginRegistry, input: &[u8], key: Option<&str>) -> Vec<u8> {
    let mut bytes =
        common::stream_process(registry, input, Format::Text, "text/plain", key, None, None)
            .unwrap();
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    bytes
}

#[derive(Debug, serde::Deserialize)]
struct Envelope {
    #[allow(dead_code)]
    alg: String,
    iv: String,
    enc_dek: String,
    ct: String,
    tag: String,
}

fn decrypt_envelope(env: &Envelope, key: &HybridPrivateKey) -> Vec<u8> {
    let dek = key
        .decapsulate_dek(&B64.decode(&env.enc_dek).unwrap())
        .expect("hybrid decapsulation failed");
    let cipher = Aes256Gcm::new_from_slice(&dek).expect("bad dek");
    let iv_bytes = B64.decode(&env.iv).unwrap();
    let iv = Nonce::from_slice(&iv_bytes);
    let mut ct = B64.decode(&env.ct).unwrap();
    ct.extend_from_slice(&B64.decode(&env.tag).unwrap());
    cipher
        .decrypt(iv, ct.as_ref())
        .expect("AES-GCM decrypt failed")
}

fn extract_envelopes(output: &str) -> Vec<Envelope> {
    // Envelopes are JSON objects embedded in the output; naive scan for
    // "alg":"X25519+ML-KEM-768/AES-256-GCM" objects.
    let mut envelopes = Vec::new();
    let mut rest = output;
    while let Some(idx) = rest.find("\"alg\":\"X25519+ML-KEM-768/AES-256-GCM\"") {
        let start = rest[..idx].rfind('{').expect("envelope start");
        let mut depth = 0i32;
        let mut end = start;
        for (i, ch) in rest[start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let obj: &str = &rest[start..end];
        envelopes.push(serde_json::from_str(obj).expect("parse envelope"));
        rest = &rest[end..];
    }
    envelopes
}

#[test]
fn encrypts_pii_with_hybrid_key_and_roundtrips() {
    let public_pem = fs::read_to_string(fixture("hybrid-public.pem")).unwrap();
    let priv_pem = fs::read_to_string(fixture("hybrid-private.pem")).unwrap();
    let key = HybridPrivateKey::parse_pem(&priv_pem).expect("parse private key");

    let registry = encrypt_registry();
    let input = b"alice@example.com SSN 123-45-6789 card 4111111111111111";

    let output = process(&registry, input, Some(&public_pem));
    let out_str = String::from_utf8_lossy(&output);

    assert!(
        !out_str.contains("alice@example.com"),
        "plaintext email leaked"
    );
    assert!(!out_str.contains("123-45-6789"), "plaintext ssn leaked");
    assert!(
        !out_str.contains("4111111111111111"),
        "plaintext card leaked"
    );

    let envelopes = extract_envelopes(&out_str);
    assert_eq!(envelopes.len(), 3, "expected 3 envelopes, got {}", out_str);

    let mut fields: Vec<Vec<u8>> = envelopes
        .iter()
        .map(|e| decrypt_envelope(e, &key))
        .collect();
    fields.sort();
    assert_eq!(fields[0], b"123-45-6789");
    assert_eq!(fields[1], b"4111111111111111");
    assert_eq!(fields[2], b"alice@example.com");
}

#[test]
fn encrypts_with_hybrid_public_key_pem() {
    let public_pem = fs::read_to_string(fixture("hybrid-public.pem")).unwrap();
    let priv_pem = fs::read_to_string(fixture("hybrid-private.pem")).unwrap();
    let key = HybridPrivateKey::parse_pem(&priv_pem).expect("parse private key");
    // sanity: the hybrid public PEM parses
    HybridPublicKey::parse_pem(&public_pem).expect("hybrid public key should parse");

    let registry = encrypt_registry();
    let output = process(&registry, b"bob@x.io 078-05-1120", Some(&public_pem));
    let out_str = String::from_utf8_lossy(&output);
    assert!(!out_str.contains("bob@x.io"), "plaintext leaked");
    let envelopes = extract_envelopes(&out_str);
    assert_eq!(envelopes.len(), 2);
    let mut fields: Vec<Vec<u8>> = envelopes
        .iter()
        .map(|e| decrypt_envelope(e, &key))
        .collect();
    fields.sort();
    assert_eq!(fields[0], b"078-05-1120");
    assert_eq!(fields[1], b"bob@x.io");
}

#[test]
fn redacts_when_no_public_key() {
    let registry = encrypt_registry();
    let input = b"alice@example.com 123-45-6789";
    let output = process(&registry, input, None);
    let out_str = String::from_utf8_lossy(&output);
    assert_eq!(out_str, "[REDACTED_EMAIL] [REDACTED_SSN]");
    assert!(!out_str.contains("X25519"), "no encryption without a key");
}

#[test]
fn deterministic_redaction_without_key() {
    let registry = encrypt_registry();
    let input = b"a@b.co 123-45-6789";
    let a = process(&registry, input, None);
    let b = process(&registry, input, None);
    assert_eq!(a, b);
}
