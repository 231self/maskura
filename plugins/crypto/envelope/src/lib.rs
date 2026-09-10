//! Envelope encryption filter plugin.
//!
//! For every PII span detected in a record: derive a fresh 256-bit DEK via a
//! hybrid X25519 + ML-KEM-768 key encapsulation using the client's hybrid
//! public key (from `Context.public-key-pem`), encrypt the field with
//! AES-256-GCM, and replace the field with a JSON envelope:
//!
//! ```json
//! {"alg":"X25519+ML-KEM-768/AES-256-GCM","iv":"<b64>","enc_dek":"<b64>","ct":"<b64>","tag":"<b64>"}
//! ```
//!
//! When no public key is configured, falls back to redaction (`[REDACTED_*]`).
//! Randomness comes from `Context.entropy-seed` (a fresh 32-byte host seed per
//! session) seeding a ChaCha20 CSPRNG — no host imports required.

#[cfg(target_arch = "wasm32")]
mod guest {
    use std::cell::RefCell;

    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use hkdf::Hkdf;
    use maskura_plugin_pii_core::find_all_spans;
    use maskura_plugin_sdk::{Context, Decision, Guest, export_plugin};
    use ml_kem::{B32, EncapsulationKey768, TryKeyInit};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use rand_core::{CryptoRng, RngCore};
    use sha2::Sha256;
    use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

    const ENVELOPE_ALG: &str = "X25519+ML-KEM-768/AES-256-GCM";
    const KDF_INFO: &[u8] = b"maskura/hybrid/envelope-dek/v1";
    const PUBLIC_PEM_LABEL: &str = "MASKURA HYBRID PUBLIC KEY";
    const X25519_KEY_LEN: usize = 32;
    const MLKEM_EK_LEN: usize = 1184;

    #[derive(Clone)]
    struct HybridPublicKey {
        x25519_pk: [u8; X25519_KEY_LEN],
        mlkem_ek: EncapsulationKey768,
    }

    impl HybridPublicKey {
        fn encapsulate_dek(
            &self,
            x25519_eph: [u8; X25519_KEY_LEN],
            m: [u8; X25519_KEY_LEN],
        ) -> Result<([u8; X25519_KEY_LEN], Vec<u8>), String> {
            let x25519_epk = x25519(x25519_eph, X25519_BASEPOINT_BYTES);
            let x25519_ss = x25519(x25519_eph, self.x25519_pk);
            let m = B32::try_from(&m[..]).map_err(|e| format!("invalid ML-KEM coins: {e}"))?;
            let (mlkem_ct, mlkem_ss) = self.mlkem_ek.encapsulate_deterministic(&m);

            let mut ikm = [0u8; X25519_KEY_LEN * 2];
            ikm[..X25519_KEY_LEN].copy_from_slice(&x25519_ss);
            ikm[X25519_KEY_LEN..].copy_from_slice(mlkem_ss.as_slice());
            let hk = Hkdf::<Sha256>::new(None, &ikm);
            let mut dek = [0u8; X25519_KEY_LEN];
            hk.expand(KDF_INFO, &mut dek)
                .map_err(|e| format!("HKDF-SHA256 expand failed: {e}"))?;

            let mut enc_dek = Vec::with_capacity(X25519_KEY_LEN + 1088);
            enc_dek.extend_from_slice(&x25519_epk);
            enc_dek.extend_from_slice(mlkem_ct.as_slice());
            Ok((dek, enc_dek))
        }
    }

    thread_local! {
        static KEY: RefCell<Option<HybridPublicKey>> = const { RefCell::new(None) };
        static RNG: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };
    }

    fn decode_pem(pem: &str, label: &str) -> Result<Vec<u8>, String> {
        let pem = pem.trim();
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let body = pem
            .strip_prefix(&begin)
            .and_then(|rest| rest.strip_suffix(&end))
            .ok_or_else(|| format!("expected a {label} PEM block"))?;
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        B64.decode(compact.as_bytes())
            .map_err(|e| format!("invalid base64 in {label} PEM block: {e}"))
    }

    fn parse_public_key(pem: &str) -> Result<Option<HybridPublicKey>, String> {
        if pem.trim().is_empty() {
            return Ok(None);
        }
        let raw = decode_pem(pem, PUBLIC_PEM_LABEL)?;
        let expected = X25519_KEY_LEN + MLKEM_EK_LEN;
        if raw.len() != expected {
            return Err(format!("hybrid public key must be {expected} bytes"));
        }
        let mut x25519_pk = [0u8; X25519_KEY_LEN];
        x25519_pk.copy_from_slice(&raw[..X25519_KEY_LEN]);
        let mlkem_ek = EncapsulationKey768::new_from_slice(&raw[X25519_KEY_LEN..])
            .map_err(|e| format!("invalid ML-KEM-768 encapsulation key: {e}"))?;
        Ok(Some(HybridPublicKey {
            x25519_pk,
            mlkem_ek,
        }))
    }

    fn encrypt_field(field: &str, marker: &str) -> Result<String, String> {
        let (iv, enc_dek, ct_full) = RNG.with(|r| {
            let mut guard = r.borrow_mut();
            let rng = guard
                .as_mut()
                .ok_or_else(|| "no entropy seed".to_string())?;
            let mut iv = [0u8; 12];
            let mut x25519_eph = [0u8; X25519_KEY_LEN];
            let mut m = [0u8; X25519_KEY_LEN];
            rng.fill_bytes(&mut iv);
            rng.fill_bytes(&mut x25519_eph);
            rng.fill_bytes(&mut m);

            let key = KEY
                .with(|k| k.borrow().clone())
                .ok_or_else(|| "no public key".to_string())?;
            let (dek, enc_dek) = key.encapsulate_dek(x25519_eph, m)?;

            let cipher =
                Aes256Gcm::new_from_slice(&dek).map_err(|e| format!("AES key init failed: {e}"))?;
            let ct = cipher
                .encrypt(Nonce::from_slice(&iv), field.as_bytes())
                .map_err(|e| format!("AES-GCM encrypt failed: {e}"))?;
            Ok::<([u8; 12], Vec<u8>, Vec<u8>), String>((iv, enc_dek, ct))
        })?;

        if ct_full.len() < 16 {
            return Err(format!("ciphertext too short to carry a tag for {marker}"));
        }
        let split = ct_full.len() - 16;
        let ct = &ct_full[..split];
        let tag = &ct_full[split..];

        let envelope = serde_json::json!({
            "alg": ENVELOPE_ALG,
            "iv": B64.encode(iv),
            "enc_dek": B64.encode(enc_dek),
            "ct": B64.encode(ct),
            "tag": B64.encode(tag),
        });
        Ok(envelope.to_string())
    }

    fn transform_record(payload: &[u8]) -> Result<Vec<u8>, String> {
        let text = std::str::from_utf8(payload).map_err(|e| e.to_string())?;
        let has_key = KEY.with(|k| k.borrow().is_some());

        if !has_key {
            return Ok(maskura_plugin_pii_core::redact_pii(text).into_bytes());
        }

        let mut spans = find_all_spans(text);
        if spans.is_empty() {
            return Ok(payload.to_vec());
        }
        spans.sort_by_key(|(start, end, _)| (*start, *end));

        let mut output = String::with_capacity(text.len());
        let mut pos = 0;
        for (start, end, marker) in spans {
            if start < pos {
                continue;
            }
            output.push_str(&text[pos..start]);
            let field = &text[start..end];
            match encrypt_field(field, marker) {
                Ok(envelope) => output.push_str(&envelope),
                Err(e) => {
                    // Never leak plaintext: redact on any crypto failure.
                    let _ = e;
                    output.push_str(marker);
                }
            }
            pos = end;
        }
        output.push_str(&text[pos..]);
        Ok(output.into_bytes())
    }

    struct EnvelopeEncrypt;

    impl Guest for EnvelopeEncrypt {
        fn begin(context: Context) -> Result<(), String> {
            let key = match context.public_key_pem {
                Some(pem) => parse_public_key(&pem)?,
                None => None,
            };
            let seed: Option<[u8; 32]> = match context.entropy_seed {
                Some(bytes) if bytes.len() >= 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes[..32]);
                    Some(arr)
                }
                _ => None,
            };

            KEY.with(|k| *k.borrow_mut() = key);
            RNG.with(|r| *r.borrow_mut() = seed.map(ChaCha20Rng::from_seed));

            if KEY.with(|k| k.borrow().is_some()) && !RNG.with(|r| r.borrow().is_some()) {
                return Err(
                    "public key provided but no entropy seed from host — refusing to encrypt"
                        .to_string(),
                );
            }
            Ok(())
        }

        fn transform(payload: Vec<u8>) -> Result<Decision, String> {
            Ok(Decision::Emit(transform_record(&payload)?))
        }

        fn finish() -> Result<Vec<u8>, String> {
            Ok(Vec::new())
        }
    }

    // Silence unused warning for the CryptoRng import in non-encrypt paths.
    #[allow(dead_code)]
    fn _assert_crypto_rng(_rng: &mut ChaCha20Rng) {
        fn requires_crypto<R: CryptoRng + RngCore>() {}
        requires_crypto::<ChaCha20Rng>();
    }

    export_plugin!(EnvelopeEncrypt);
}
