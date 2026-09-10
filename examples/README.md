# Examples

Runnable end-to-end demonstrations. They create temporary credentials and
storage, assert their results, and clean up after themselves.

## Canonical proof suite

Run all three black-box proofs against the published container:

```bash
just proof
```

Or run one claim at a time:

```bash
just proof redaction  # unmodified AWS CLI + local S3 endpoint
just proof plugin     # runtime Wasm import, no gateway rebuild
just proof python     # hybrid encrypted write + client-only decrypt
```

See [Run the claims](../docs/proofs.md) for prerequisites, exact assertions,
and the limits of each result. `local-quickstart.sh` remains as a compatible
entry point for the redaction proof; `maskura-demo.sh` runs the whole suite.

## B2 redaction demo (`b2-redact-demo.sh`)

Round-trips against a real Backblaze B2 bucket, fetching the stored object
**directly from B2** (bypassing Maskura) so you can see exactly what leaves your
writer:

The fixture passes through `pii-default`, and the object stored in B2 contains
only `[REDACTED_*]` markers. The script fetches the stored object **directly
from B2** (bypassing Maskura) so you can inspect exactly what left the writer.

```bash
export B2_S3_ENDPOINT=https://s3.us-east-005.backblazeb2.com
export B2_REGION=us-east-005
export B2_BUCKET=your-bucket
export B2_ACCESS_KEY_ID=your-key-id
export B2_SECRET_ACCESS_KEY=your-application-key

bash examples/b2-redact-demo.sh
```

The B2 application key needs `readFiles`/`writeFiles`/`deleteFiles` on the
bucket.

## Hybrid envelope encryption

[`python-hybrid-roundtrip.py`](python-hybrid-roundtrip.py) uses the packaged
Python client. It creates a scoped API key, generates an X25519 + ML-KEM-768
keypair, attaches only the public key, confirms no plaintext reached storage,
and decrypts with the private key held by the process. The Rust wire-level
round trip remains covered by `crates/gateway/tests/encrypt_roundtrip.rs`.
