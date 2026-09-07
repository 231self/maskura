# Post-quantum encryption

> **Status: planned.** This page describes an upcoming feature, not shipped
> behavior. Current builds use RSA-OAEP key wrapping.

## What it is

Maskura's encryption filters protect fields with envelope encryption: a fresh
AES-256-GCM key per field, wrapped with a public key so only the key holder can
decrypt. Today that wrap is RSA-OAEP, which a quantum computer can break.

The post-quantum feature replaces the RSA-OAEP wrap with a **hybrid X25519 +
ML-KEM-768** key encapsulation:

- **ML-KEM-768** (NIST FIPS 203) protects against a cryptographically relevant
  quantum computer (harvest-now-decrypt-later).
- **X25519** protects against the risk of an undiscovered weakness in a young
  post-quantum scheme.

The data cipher stays AES-256-GCM, which is already post-quantum-safe.

## What changes

- New envelope `alg`: `X25519+ML-KEM-768/AES-256-GCM`.
- New client key format (hybrid public/private keys).
- Existing `RSA-OAEP` envelopes remain decryptable (dual-alg read).

## What does not change

- The plugin model, the `transform`/`finish` interface, and the sandbox are
  untouched — this is a new filter implementation, not a new runtime.
- API-key secrets (`KeyWrapping`) and KMS/Vault wrapping are symmetric and already
  safe.

## See also

- [Plugins](plugins.md)
- [Security](security.md)
