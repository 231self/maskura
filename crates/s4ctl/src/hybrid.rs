use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hkdf::Hkdf;
use ml_kem::{Decapsulate, DecapsulationKey768, KeyExport, Seed};
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

const ENVELOPE_ALG: &str = "X25519+ML-KEM-768/AES-256-GCM";
const KDF_INFO: &[u8] = b"maskura/hybrid/envelope-dek/v1";
const PUBLIC_LABEL: &str = "MASKURA HYBRID PUBLIC KEY";
const PRIVATE_LABEL: &str = "MASKURA HYBRID PRIVATE KEY";
const X25519_KEY_LEN: usize = 32;
const MLKEM_EK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;
const MLKEM_SEED_LEN: usize = 64;
const PRIVATE_KEY_LEN: usize = X25519_KEY_LEN + MLKEM_SEED_LEN;
const PUBLIC_KEY_LEN: usize = X25519_KEY_LEN + MLKEM_EK_LEN;
const ENC_DEK_LEN: usize = X25519_KEY_LEN + MLKEM_CT_LEN;

#[derive(serde::Deserialize)]
struct Envelope {
    alg: String,
    iv: String,
    enc_dek: String,
    ct: String,
    tag: String,
}

pub fn generate_keypair() -> (String, String) {
    let mut x25519_secret = [0u8; X25519_KEY_LEN];
    let mut mlkem_seed = [0u8; MLKEM_SEED_LEN];
    rand::rngs::OsRng.fill_bytes(&mut x25519_secret);
    rand::rngs::OsRng.fill_bytes(&mut mlkem_seed);

    let x25519_public = x25519(x25519_secret, X25519_BASEPOINT_BYTES);
    let mlkem_private = DecapsulationKey768::from_seed(
        Seed::try_from(&mlkem_seed[..]).expect("fixed-size ML-KEM seed"),
    );
    let mut public_raw = Vec::with_capacity(PUBLIC_KEY_LEN);
    public_raw.extend_from_slice(&x25519_public);
    public_raw.extend_from_slice(mlkem_private.encapsulation_key().to_bytes().as_slice());
    let mut private_raw = Vec::with_capacity(PRIVATE_KEY_LEN);
    private_raw.extend_from_slice(&x25519_secret);
    private_raw.extend_from_slice(&mlkem_seed);
    (
        encode_pem(PRIVATE_LABEL, &private_raw),
        encode_pem(PUBLIC_LABEL, &public_raw),
    )
}

pub fn decrypt_payload(payload: &[u8], private_key_pem: &str) -> anyhow::Result<Vec<u8>> {
    let private_raw = decode_pem(private_key_pem, PRIVATE_LABEL)?;
    anyhow::ensure!(
        private_raw.len() == PRIVATE_KEY_LEN,
        "hybrid private key must contain {PRIVATE_KEY_LEN} bytes, got {}",
        private_raw.len()
    );
    let mut x25519_secret = [0u8; X25519_KEY_LEN];
    x25519_secret.copy_from_slice(&private_raw[..X25519_KEY_LEN]);
    let mlkem_private = DecapsulationKey768::from_seed(
        Seed::try_from(&private_raw[X25519_KEY_LEN..])
            .map_err(|error| anyhow::anyhow!("invalid ML-KEM seed: {error}"))?,
    );

    let marker = format!("\"alg\":\"{ENVELOPE_ALG}\"").into_bytes();
    let mut output = Vec::with_capacity(payload.len());
    let mut position = 0;
    while let Some(relative) = find_bytes(&payload[position..], &marker) {
        let marker_start = position + relative;
        let Some(start) = payload[..marker_start]
            .iter()
            .rposition(|byte| *byte == b'{')
        else {
            output.extend_from_slice(&payload[position..marker_start + marker.len()]);
            position = marker_start + marker.len();
            continue;
        };
        let Some(end) = matching_brace_end(payload, start) else {
            break;
        };
        let envelope: Envelope = serde_json::from_slice(&payload[start..end])?;
        output.extend_from_slice(&payload[position..start]);
        output.extend_from_slice(&decrypt_envelope(&envelope, x25519_secret, &mlkem_private)?);
        position = end;
    }
    output.extend_from_slice(&payload[position..]);
    Ok(output)
}

fn decrypt_envelope(
    envelope: &Envelope,
    x25519_secret: [u8; X25519_KEY_LEN],
    mlkem_private: &DecapsulationKey768,
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        envelope.alg == ENVELOPE_ALG,
        "unsupported envelope algorithm: {}",
        envelope.alg
    );
    let encapsulated = BASE64.decode(&envelope.enc_dek)?;
    anyhow::ensure!(
        encapsulated.len() == ENC_DEK_LEN,
        "hybrid enc_dek must contain {ENC_DEK_LEN} bytes, got {}",
        encapsulated.len()
    );
    let mut ephemeral_public = [0u8; X25519_KEY_LEN];
    ephemeral_public.copy_from_slice(&encapsulated[..X25519_KEY_LEN]);
    let x25519_shared = x25519(x25519_secret, ephemeral_public);
    let mlkem_shared = mlkem_private
        .decapsulate_slice(&encapsulated[X25519_KEY_LEN..])
        .map_err(|error| anyhow::anyhow!("ML-KEM-768 decapsulation failed: {error}"))?;
    let dek = derive_dek(&x25519_shared, mlkem_shared.as_slice())?;
    let iv = BASE64.decode(&envelope.iv)?;
    anyhow::ensure!(iv.len() == 12, "AES-GCM IV must contain 12 bytes");
    let mut ciphertext = BASE64.decode(&envelope.ct)?;
    ciphertext.extend_from_slice(&BASE64.decode(&envelope.tag)?);
    Aes256Gcm::new_from_slice(&dek)
        .map_err(|error| anyhow::anyhow!("AES key initialization failed: {error}"))?
        .decrypt(Nonce::from_slice(&iv), ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM authentication failed"))
}

fn derive_dek(x25519_shared: &[u8; 32], mlkem_shared: &[u8]) -> anyhow::Result<[u8; 32]> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(x25519_shared);
    ikm[32..].copy_from_slice(mlkem_shared);
    let mut dek = [0u8; 32];
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(KDF_INFO, &mut dek)
        .map_err(|error| anyhow::anyhow!("HKDF-SHA256 expand failed: {error}"))?;
    Ok(dek)
}

fn matching_brace_end(payload: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in payload.iter().enumerate().skip(start) {
        match *byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(offset + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn decode_pem(pem: &str, label: &str) -> anyhow::Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = pem
        .trim()
        .strip_prefix(&begin)
        .and_then(|rest| rest.strip_suffix(&end))
        .ok_or_else(|| anyhow::anyhow!("expected a {label} PEM block"))?;
    BASE64
        .decode(
            body.chars()
                .filter(|value| !value.is_whitespace())
                .collect::<String>(),
        )
        .map_err(Into::into)
}

fn encode_pem(label: &str, raw: &[u8]) -> String {
    let base64 = BASE64.encode(raw);
    let body = base64
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use ml_kem::{B32, EncapsulationKey768, TryKeyInit};

    #[test]
    fn generated_keys_round_trip_a_gateway_compatible_envelope() {
        let (private_pem, public_pem) = generate_keypair();
        let public_raw = decode_pem(&public_pem, PUBLIC_LABEL).unwrap();
        assert_eq!(decode_pem(&private_pem, PRIVATE_LABEL).unwrap().len(), 96);
        assert_eq!(public_raw.len(), 1216);

        let mut recipient_x25519 = [0u8; 32];
        recipient_x25519.copy_from_slice(&public_raw[..32]);
        let mlkem_public = EncapsulationKey768::new_from_slice(&public_raw[32..]).unwrap();
        let ephemeral_secret = [0x33; 32];
        let ephemeral_public = x25519(ephemeral_secret, X25519_BASEPOINT_BYTES);
        let x25519_shared = x25519(ephemeral_secret, recipient_x25519);
        let coins = B32::try_from(&[0x44; 32][..]).unwrap();
        let (mlkem_ciphertext, mlkem_shared) = mlkem_public.encapsulate_deterministic(&coins);
        let dek = derive_dek(&x25519_shared, mlkem_shared.as_slice()).unwrap();
        let iv = [0x55; 12];
        let sealed = Aes256Gcm::new_from_slice(&dek)
            .unwrap()
            .encrypt(Nonce::from_slice(&iv), b"alice@example.com".as_ref())
            .unwrap();
        let mut enc_dek = ephemeral_public.to_vec();
        enc_dek.extend_from_slice(mlkem_ciphertext.as_slice());
        let envelope = serde_json::json!({
            "alg": ENVELOPE_ALG,
            "iv": BASE64.encode(iv),
            "enc_dek": BASE64.encode(enc_dek),
            "ct": BASE64.encode(&sealed[..sealed.len() - 16]),
            "tag": BASE64.encode(&sealed[sealed.len() - 16..]),
        });
        let payload = format!("before {envelope} after");
        assert_eq!(
            decrypt_payload(payload.as_bytes(), &private_pem).unwrap(),
            b"before alice@example.com after"
        );
    }

    #[test]
    fn payload_without_envelopes_is_unchanged() {
        let (private_pem, _) = generate_keypair();
        assert_eq!(decrypt_payload(b"plain", &private_pem).unwrap(), b"plain");
    }
}
