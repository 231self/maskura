# Examples

Runnable end-to-end demos. Credentials always come from the environment —
never committed.

## Local quickstart (`local-quickstart.sh`)

The getting-started flow as a testable script: start the gateway from the
published image (pinned to the `maskura` executable version), push a sample through the
pipeline, assert redaction, stop.

```bash
bash examples/local-quickstart.sh
```

Requires `maskura`
(`cargo install --git https://github.com/231self/maskura --bin maskura s4ctl`)
and Docker.

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

## Envelope-encryption examples

The former B2 and Python SDK encryption demos used the legacy RSA envelope and
were removed when new writes moved to hybrid X25519 + ML-KEM-768. The current
Rust round-trip is covered by `crates/gateway/tests/encrypt_roundtrip.rs`.
Packaged Python and TypeScript hybrid client support is still a known gap; see
[Encryption](../docs/encryption.md#client-tooling-status).
