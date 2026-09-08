# Encryption

This page explains how Maskura's envelope encryption works, from the key you
hand the gateway to the bytes that leave your writer. It is the long-form
companion to the [post-quantum](post-quantum-crypto.md) feature page and
[ADR 0011](adr/0011-post-quantum-hybrid-envelope.md).

## The model

Encryption is **envelope encryption** with a fresh data key per field:

1. The gateway generates a random 256-bit **data encryption key (DEK)** and
   encrypts the field with **AES-256-GCM**.
2. The DEK is then **key-encapsulated** to your public key, so only the holder
   of the matching private key can recover it.
3. Both the ciphertext and the encapsulated DEK are written to storage.

Maskura never sees a plaintext field, never sees the DEK after it is wrapped,
and never holds your private key. Decryption happens entirely on the client.

## The primitives

| Role | Primitive | Why |
|------|-----------|-----|
| Data cipher | AES-256-GCM | Authenticated encryption; 256-bit keys resist Grover (~2^128) |
| Classical KEM | X25519 (ECDH) | Protects against an undiscovered weakness in a young PQ scheme |
| Post-quantum KEM | ML-KEM-768 (FIPS 203) | Protects against a cryptographically relevant quantum computer |
| Combiner | HKDF-SHA256 | Folds the two shared secrets into one DEK |

The construction is a **hybrid KEM**: the DEK is secure unless *both* X25519 and
ML-KEM-768 are broken. This is the consensus position of the IETF hybrid
key-exchange draft, NSA CNSA 2.0, and BSI.

The data path contains no signatures, so ML-DSA and SLH-DSA are out of scope —
KEM-only.

## Encapsulation (encrypt)

For each detected field the gateway:

```text
m            = 32 random bytes from a CSPRNG
(mlkem_ss, mlkem_ct) = ML-KEM-768.Encaps(ek, m)        # ek = your ML-KEM public key
x25519_sk    = 32 random bytes
x25519_epk   = X25519(x25519_sk, basepoint)
x25519_ss    = X25519(x25519_sk, your_x25519_pk)
dek          = HKDF-SHA256(ikm = x25519_ss ‖ mlkem_ss,
                           salt = "",
                           info = "maskura/hybrid/envelope-dek/v1",
                           L = 32)
enc_dek      = x25519_epk ‖ mlkem_ct                  # 1120 bytes
field        = AES-256-GCM(dek, iv, plaintext)
```

The wrapped key material (`enc_dek`) carries everything you need to decrypt:
your X25519 ephemeral public key and the ML-KEM-768 ciphertext. The DEK itself
is never stored — it is derived from the two shared secrets on both sides.

## Decapsulation (decrypt, client-side)

```text
(x25519_epk, mlkem_ct) = split(enc_dek)
x25519_ss = X25519(your_x25519_sk, x25519_epk)
mlkem_ss  = ML-KEM-768.Decaps(your_mlkem_dk, mlkem_ct)
dek       = HKDF-SHA256(same construction as above)
plaintext = AES-256-GCM.Decrypt(dek, iv, ct ‖ tag)
```

## The envelope

Each encrypted field becomes a JSON object with five fields:

```json
{"alg":"X25519+ML-KEM-768/AES-256-GCM","iv":"<b64>","enc_dek":"<b64>","ct":"<b64>","tag":"<b64>"}
```

- `alg` identifies the construction. Existing `RSA-OAEP/AES-256-GCM` envelopes
  remain decryptable (dual-alg read); new writes are hybrid-only.
- `iv` is the 12-byte AES-GCM nonce.
- `enc_dek` is the 1120-byte hybrid encapsulation (base64).
- `ct` / `tag` are the AES-256-GCM ciphertext and authentication tag.

## Key format

Keys are a single base64 blob of fixed-length concatenation, wrapped in PEM:

```text
-----BEGIN MASKURA HYBRID PUBLIC KEY-----
base64( x25519_pk ‖ mlkem_ek )        # 32 + 1184 = 1216 bytes
-----END MASKURA HYBRID PUBLIC KEY-----

-----BEGIN MASKURA HYBRID PRIVATE KEY-----
base64( x25519_sk ‖ mlkem_seed )      # 32 + 64 = 96 bytes
-----END MASKURA HYBRID PRIVATE KEY-----
```

| Component | Size |
|-----------|------|
| X25519 public key / shared secret | 32 B |
| ML-KEM-768 encapsulation key (public) | 1184 B |
| ML-KEM-768 ciphertext | 1088 B |
| ML-KEM-768 shared secret | 32 B |
| ML-KEM-768 seed (private key serialization) | 64 B |
| Hybrid public key | 1216 B |
| Hybrid private key | 96 B |
| `enc_dek` | 1120 B |

The gateway's `public-key-pem` config field is unchanged: it is still a string.
The private key never touches the gateway.

## Security properties

- **IND-CCA2.** Both KEMs are CCA-secure; the HKDF combiner produces an
  indistinguishable DEK unless both are broken.
- **Per-field keys.** A fresh DEK per field means a compromise of one DEK does
  not expose any other field.
- **Authenticated encryption.** AES-GCM binds the ciphertext to its tag; any
  tampering fails decryption.
- **Fail closed.** If key encapsulation or encryption fails, the field is
  redacted rather than emitted as plaintext.
- **Single-alg write.** New writes are hybrid-only; legacy RSA keys are rejected
  for new writes and remain only for decrypting previously written objects.

## Cost

The hybrid wrap trades a slightly larger key encapsulation for materially
cheaper CPU than the RSA-OAEP wrap it replaces:

- ~34M Wasm fuel per encrypted field (vs ~52M for RSA-2048 OAEP).
- `enc_dek` grows from 256 B (RSA-2048) to 1120 B per field.

Measured numbers and methodology are in [Benchmarks](benchmarks.md).
