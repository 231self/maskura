# Run the claims

This is the shortest path from a Maskura claim to observable behavior. The
proof harness treats the published container as a black box and exits nonzero
if an assertion fails. It does not scrape gateway logs for credentials or ask
you to trust a screenshot.

```bash
just proof
```

Requirements: Docker, curl, Python 3, the AWS CLI, and preferably
[uv](https://docs.astral.sh/uv/). Without uv, install the Python SDK's declared
dependencies first. The run uses an isolated container, Docker volume, API key,
and object keys, then removes the container and volume.

The default is the current published image. Pin a release when you want the
same bytes on a later run:

```bash
MASKURA_PROOF_IMAGE=ghcr.io/231self/maskura/maskura:v0.7.0 just proof
```

The harness prints the pulled image digest before it starts its assertions. It
boots Maskura with transformed reads disabled, so each GET returns the raw
write-path result rather than applying a second transform on read.

## What it proves

| Claim | Command | Assertion |
|---|---|---|
| Maskura is an S3-compatible local endpoint | `just proof redaction` | An unmodified AWS CLI writes and reads an object through Maskura. The raw read-back contains the email/card redaction markers and neither plaintext value. |
| A Wasm component can change the pipeline at runtime | `just proof plugin` | The harness disables the bundled pipeline, imports `email-detect.component.wasm` over the live admin API, and writes the same email/card input. Only the email changes, showing that the imported component—not a hard-coded gateway transform—produced the result. |
| The Python client implements the shipped hybrid envelope | `just proof python` | The SDK creates an X25519 + ML-KEM-768 keypair, confirms only its public key is attached, writes PII, confirms the raw read-back contains hybrid envelopes and no plaintext, then recovers the exact input with the client-held private key. |

The Python step is deliberately a normal script rather than test-only code:
[`examples/python-hybrid-roundtrip.py`](../examples/python-hybrid-roundtrip.py).
The orchestrator is
[`examples/prove-maskura.sh`](../examples/prove-maskura.sh).

## What it does not prove

This suite is narrow on purpose. It does not establish formal cryptographic
correctness, exhaustive S3 conformance, hosted tenant isolation, or the
security of your deployment configuration. Those claims have separate
evidence:

- [Encryption design and exact construction](encryption.md)
- [Security model and trust boundaries](security.md)
- [Full MinIO end-to-end and external-client coverage](e2e.md)
- [Filter cost and reproducible benchmark method](benchmarks.md)
- [Architecture decisions](adr/0011-post-quantum-hybrid-envelope.md)
