# ADR 0011: Post-quantum hybrid envelope (X25519 + ML-KEM-768)

- Status: Accepted
- Date: 2026-09-07

## Context

Maskura's encryption filters use envelope encryption: a fresh AES-256-GCM data
key (DEK) per field, wrapped with the client's public key so only the key holder
can decrypt. Today the DEK is wrapped with RSA-OAEP (SHA-256). A
cryptographically relevant quantum computer breaks RSA via Shor's algorithm,
exposing long-lived ciphertext to harvest-now-decrypt-later.

The symmetric layers are already post-quantum-safe: AES-256-GCM resists Grover
(~2^128 for a 256-bit key), as does the API-key `SecretCipher` and the KMS/Vault
wrapping. The only quantum-vulnerable primitive in the data path is the RSA-OAEP
key wrap.

## Decision

Replace the RSA-OAEP DEK wrap with a **hybrid X25519 + ML-KEM-768** key
encapsulation:

- **ML-KEM-768** (NIST FIPS 203), a post-quantum KEM, protects against a CRQC.
- **X25519** ECDH, a classical KEM, protects against an undiscovered weakness in
  a young post-quantum scheme.

The construction is secure unless *both* are broken — the consensus position of
the IETF hybrid key-exchange draft, NSA CNSA 2.0, and BSI. The two shared secrets
are combined with HKDF-SHA256 into a single 32-byte DEK; the data cipher remains
AES-256-GCM.

Scope is KEM-only: the data path contains no signatures, so ML-DSA and SLH-DSA
are out of scope.

The envelope carries a new `alg` value: `X25519+ML-KEM-768/AES-256-GCM`.

## Consequences

- New client key format (hybrid public/private keys). The WIT `public-key-pem`
  config field is unchanged — it still carries a string.
- Per-field wrap overhead grows from 256 B (RSA-2048) to 1120 B; the hybrid
  public key is 1216 B. Negligible for objects, meaningful for many-field
  records.
- Expected fuel reduction: ML-KEM encapsulation has no modular exponentiation,
  versus RSA-OAEP's ~25M wasm instructions per wrap.
- Dual-alg read, single-alg write: existing RSA-OAEP envelopes remain
  decryptable; new writes are hybrid-only.
- Implementation is planned, not yet shipped.

## Alternatives considered

- Pure ML-KEM-768 — post-quantum-safe but exposes the young-scheme risk alone;
  rejected in favor of hybrid.
- ML-KEM-1024 — AES-256 parity but ~1.5 KB keys and larger ciphertext; deferred.
- RSA-4096 — still broken by Shor's algorithm; no post-quantum benefit.
