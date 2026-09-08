//! Hybrid X25519 + ML-KEM-768 envelope key encapsulation.
//!
//! Replaces the RSA-OAEP DEK wrap with a post-quantum hybrid construction: the
//! two KEM shared secrets (X25519 ECDH and ML-KEM-768) are combined with
//! HKDF-SHA256 into a single 32-byte DEK. The data cipher stays AES-256-GCM.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hkdf::Hkdf;
use ml_kem::{
    B32, Decapsulate, DecapsulationKey768, EncapsulationKey768, KeyExport, Seed, TryKeyInit,
};
use sha2::Sha256;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

pub const ENVELOPE_ALG: &str = "X25519+ML-KEM-768/AES-256-GCM";
pub const KDF_INFO: &[u8] = b"maskura/hybrid/envelope-dek/v1";

pub const X25519_KEY_LEN: usize = 32;
pub const MLKEM_EK_LEN: usize = 1184;
pub const MLKEM_CT_LEN: usize = 1088;
pub const MLKEM_SEED_LEN: usize = 64;
pub const HYBRID_PUBLIC_KEY_LEN: usize = X25519_KEY_LEN + MLKEM_EK_LEN;
pub const HYBRID_PRIVATE_KEY_LEN: usize = X25519_KEY_LEN + MLKEM_SEED_LEN;
pub const ENC_DEK_LEN: usize = X25519_KEY_LEN + MLKEM_CT_LEN;

const PUBLIC_PEM_LABEL: &str = "MASKURA HYBRID PUBLIC KEY";
const PRIVATE_PEM_LABEL: &str = "MASKURA HYBRID PRIVATE KEY";

#[derive(Clone, Debug)]
pub struct HybridPublicKey {
    x25519_pk: [u8; X25519_KEY_LEN],
    mlkem_ek: EncapsulationKey768,
}

#[derive(Clone)]
pub struct HybridPrivateKey {
    x25519_sk: [u8; X25519_KEY_LEN],
    mlkem_dk: DecapsulationKey768,
}

impl HybridPublicKey {
    pub fn parse_pem(pem: &str) -> Result<Self, String> {
        let raw = decode_pem(pem, PUBLIC_PEM_LABEL)?;
        if raw.len() != HYBRID_PUBLIC_KEY_LEN {
            return Err(format!(
                "hybrid public key must be {HYBRID_PUBLIC_KEY_LEN} bytes, got {}",
                raw.len()
            ));
        }
        let mut x25519_pk = [0u8; X25519_KEY_LEN];
        x25519_pk.copy_from_slice(&raw[..X25519_KEY_LEN]);
        let mlkem_ek = EncapsulationKey768::new_from_slice(&raw[X25519_KEY_LEN..])
            .map_err(|e| format!("invalid ML-KEM-768 encapsulation key: {e}"))?;
        Ok(Self {
            x25519_pk,
            mlkem_ek,
        })
    }

    pub fn encapsulate_dek(
        &self,
        x25519_eph: [u8; X25519_KEY_LEN],
        m: [u8; X25519_KEY_LEN],
    ) -> Result<([u8; X25519_KEY_LEN], Vec<u8>), String> {
        let x25519_epk = x25519(x25519_eph, X25519_BASEPOINT_BYTES);
        let x25519_ss = x25519(x25519_eph, self.x25519_pk);
        let m = B32::try_from(&m[..]).map_err(|e| format!("invalid ML-KEM coins: {e}"))?;
        let (mlkem_ct, mlkem_ss) = self.mlkem_ek.encapsulate_deterministic(&m);
        let dek = derive_dek(&x25519_ss, mlkem_ss.as_slice())?;
        let mut enc_dek = Vec::with_capacity(ENC_DEK_LEN);
        enc_dek.extend_from_slice(&x25519_epk);
        enc_dek.extend_from_slice(mlkem_ct.as_slice());
        Ok((dek, enc_dek))
    }

    pub fn to_pem(&self) -> String {
        let mut raw = Vec::with_capacity(HYBRID_PUBLIC_KEY_LEN);
        raw.extend_from_slice(&self.x25519_pk);
        raw.extend_from_slice(self.mlkem_ek.to_bytes().as_slice());
        encode_pem(PUBLIC_PEM_LABEL, &raw)
    }
}

impl HybridPrivateKey {
    pub fn parse_pem(pem: &str) -> Result<Self, String> {
        let raw = decode_pem(pem, PRIVATE_PEM_LABEL)?;
        if raw.len() != HYBRID_PRIVATE_KEY_LEN {
            return Err(format!(
                "hybrid private key must be {HYBRID_PRIVATE_KEY_LEN} bytes, got {}",
                raw.len()
            ));
        }
        let mut x25519_sk = [0u8; X25519_KEY_LEN];
        x25519_sk.copy_from_slice(&raw[..X25519_KEY_LEN]);
        let mut seed = [0u8; MLKEM_SEED_LEN];
        seed.copy_from_slice(&raw[X25519_KEY_LEN..]);
        let mlkem_dk = DecapsulationKey768::from_seed(
            Seed::try_from(&seed[..]).map_err(|e| format!("invalid ML-KEM seed: {e}"))?,
        );
        Ok(Self {
            x25519_sk,
            mlkem_dk,
        })
    }

    pub fn decapsulate_dek(&self, enc_dek: &[u8]) -> Result<[u8; X25519_KEY_LEN], String> {
        if enc_dek.len() != ENC_DEK_LEN {
            return Err(format!(
                "hybrid enc_dek must be {ENC_DEK_LEN} bytes, got {}",
                enc_dek.len()
            ));
        }
        let mut x25519_epk = [0u8; X25519_KEY_LEN];
        x25519_epk.copy_from_slice(&enc_dek[..X25519_KEY_LEN]);
        let x25519_ss = x25519(self.x25519_sk, x25519_epk);
        let mlkem_ss = self
            .mlkem_dk
            .decapsulate_slice(&enc_dek[X25519_KEY_LEN..])
            .map_err(|e| format!("ML-KEM-768 decapsulation failed: {e}"))?;
        derive_dek(&x25519_ss, mlkem_ss.as_slice())
    }

    pub fn to_pem(&self) -> String {
        let mut raw = Vec::with_capacity(HYBRID_PRIVATE_KEY_LEN);
        raw.extend_from_slice(&self.x25519_sk);
        let seed = self
            .mlkem_dk
            .to_seed()
            .expect("decapsulation key is seed-backed");
        raw.extend_from_slice(seed.as_slice());
        encode_pem(PRIVATE_PEM_LABEL, &raw)
    }
}

pub fn generate_keypair(
    x25519_sk: [u8; X25519_KEY_LEN],
    mlkem_seed: [u8; MLKEM_SEED_LEN],
) -> (HybridPublicKey, HybridPrivateKey) {
    let x25519_pk = x25519(x25519_sk, X25519_BASEPOINT_BYTES);
    let mlkem_dk = DecapsulationKey768::from_seed(
        Seed::try_from(&mlkem_seed[..]).expect("64-byte ML-KEM seed"),
    );
    let mlkem_ek = mlkem_dk.encapsulation_key().clone();
    (
        HybridPublicKey {
            x25519_pk,
            mlkem_ek,
        },
        HybridPrivateKey {
            x25519_sk,
            mlkem_dk,
        },
    )
}

fn derive_dek(
    x25519_ss: &[u8; X25519_KEY_LEN],
    mlkem_ss: &[u8],
) -> Result<[u8; X25519_KEY_LEN], String> {
    let mut ikm = [0u8; X25519_KEY_LEN * 2];
    ikm[..X25519_KEY_LEN].copy_from_slice(x25519_ss);
    ikm[X25519_KEY_LEN..].copy_from_slice(mlkem_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut dek = [0u8; X25519_KEY_LEN];
    hk.expand(KDF_INFO, &mut dek)
        .map_err(|e| format!("HKDF-SHA256 expand failed: {e}"))?;
    Ok(dek)
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
    BASE64
        .decode(compact.as_bytes())
        .map_err(|e| format!("invalid base64 in {label} PEM block: {e}"))
}

fn encode_pem(label: &str, raw: &[u8]) -> String {
    let b64 = BASE64.encode(raw);
    let mut body = String::with_capacity(b64.len() + b64.len() / 64 + 1);
    for chunk in b64.as_bytes().chunks(64) {
        body.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        body.push('\n');
    }
    format!("-----BEGIN {label}-----\n{body}-----END {label}-----\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_roundtrip_derives_the_same_dek() {
        let (public, private) = generate_keypair([0x11; 32], [0x22; 64]);
        let public_pem = public.to_pem();
        let private_pem = private.to_pem();

        let parsed_public = HybridPublicKey::parse_pem(&public_pem).unwrap();
        let parsed_private = HybridPrivateKey::parse_pem(&private_pem).unwrap();

        let x25519_eph = [0x33; 32];
        let m = [0x44; 32];
        let (dek, enc_dek) = parsed_public.encapsulate_dek(x25519_eph, m).unwrap();
        assert_eq!(enc_dek.len(), ENC_DEK_LEN);
        let recovered = parsed_private.decapsulate_dek(&enc_dek).unwrap();
        assert_eq!(dek, recovered);
    }

    #[test]
    fn hybrid_key_lengths_are_as_documented() {
        let (public, private) = generate_keypair([0x55; 32], [0x66; 64]);
        let public_pem = public.to_pem();
        let private_pem = private.to_pem();
        assert!(public_pem.starts_with("-----BEGIN MASKURA HYBRID PUBLIC KEY-----"));
        assert!(private_pem.starts_with("-----BEGIN MASKURA HYBRID PRIVATE KEY-----"));
        let public_raw = decode_pem(&public_pem, PUBLIC_PEM_LABEL).unwrap();
        let private_raw = decode_pem(&private_pem, PRIVATE_PEM_LABEL).unwrap();
        assert_eq!(public_raw.len(), HYBRID_PUBLIC_KEY_LEN);
        assert_eq!(private_raw.len(), HYBRID_PRIVATE_KEY_LEN);
    }
}
