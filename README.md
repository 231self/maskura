<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/maskura-lockup-dark.svg" />
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/maskura-lockup-light.svg" />
    <img alt="Maskura — object data, masked." src="docs/assets/maskura-lockup-light.svg" width="400" />
  </picture>
</p>

# Maskura

<p align="center">
  <a href="https://github.com/231self/maskura/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/231self/maskura/ci.yml?branch=main&label=CI" /></a>
  <a href="https://github.com/231self/maskura/actions/workflows/docs.yml"><img alt="Docs" src="https://img.shields.io/github/actions/workflow/status/231self/maskura/docs.yml?branch=main&label=docs" /></a>
  <a href="https://github.com/231self/maskura/releases"><img alt="Release" src="https://img.shields.io/github/v/release/231self/maskura" /></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" /></a>
</p>

Maskura is the open-source policy boundary between AI agents and object storage.
It gives existing S3 clients one place to decide which representation may cross
that boundary—and to bind the decision to the exact policy code that ran.

An ordered Wasm component pipeline can validate, reject, reshape, redact, or
encrypt object data. Maskura runs locally as an S3-compatible Docker service or
in front of storage you already use.

## Capabilities

- **Protected matching.** `stable-encrypt` applies deterministic AES-SIV to
  selected fields. The same value under the same key produces the same protected
  value, so datasets can be joined and deduplicated without exposing the
  original field. Equality is intentionally visible; the feature is opt-in.
- **Content-addressed policy.** A request resolves one immutable pipeline
  revision with ordered component hashes, configuration, capabilities, and
  execution limits. Imported read components are not trusted for direct
  streaming until an operator allowlists their exact digest.
- **Client-held decryption keys.** Recoverable fields use hybrid X25519 +
  ML-KEM-768 encapsulation and AES-256-GCM. Maskura receives the public key; the
  private key stays with the client.
- **An open policy runtime.** Bring built-in or custom Wasm components through a
  small WIT contract. Plugins run in fresh wasmtime instances with bounded
  memory, fuel, deadlines, and no host access to storage or credentials.
- **Storage neutrality.** Maskura is itself an S3 endpoint with durable local
  storage and can front S3-compatible providers. Its optional service-storage
  engine distributes keys across providers, dual-writes primary and replica,
  and fails reads over without making one cloud the control point.
- **Evidence follows execution.** The gateway binds operation evidence to the
  pipeline revision, fingerprint, component digests, byte counts, fuel, and
  duration. Release binaries and container manifests ship with checksums, an
  SBOM, and provenance attestations.

Official plugins include PII redaction, focused email/SSN/payment-card filters,
hybrid envelope encryption, deterministic encryption, and a no-op baseline. The
same data path is available to AWS-compatible tools, the `maskura` CLI, Python
and TypeScript clients, and the local MCP server.

## Quickstart

No cloud account, database, or repository clone is required:

```bash
docker run --rm -p 127.0.0.1:8791:8080 -v maskura-data:/data \
  -e AUTH_DISABLED=true \
  -e MASKURA_STORAGE_MODE=local \
  -e MASKURA_LOCAL_STORAGE_DIR=/data \
  -e MASKURA_MULTIPART_MODE=staged \
  ghcr.io/231self/maskura/maskura:v0.7.2
```

Maskura is now an S3-compatible endpoint at `http://localhost:8791`. Use any
non-empty credentials when auth is disabled:

```bash
export AWS_ACCESS_KEY_ID=demo AWS_SECRET_ACCESS_KEY=demo
printf '{"email":"jane@example.com","card":"4111111111111111"}\n' > data.jsonl

aws s3 --endpoint-url http://localhost:8791 \
  cp data.jsonl s3://maskura-local/ingest/data.jsonl \
  --content-type application/x-ndjson

aws s3 --endpoint-url http://localhost:8791 \
  cp s3://maskura-local/ingest/data.jsonl -
# {"email":"[REDACTED_EMAIL]","card":"[REDACTED_CARD]"}
```

Open <http://localhost:8791> for the local dashboard.

## CLI

Install with Cargo, or download a prebuilt Linux amd64/arm64 or native Apple
Silicon binary from [GitHub Releases](https://github.com/231self/maskura/releases):

```bash
cargo install --git https://github.com/231self/maskura --bin maskura
maskura local init
maskura put ./data.jsonl ingest/data.jsonl --bucket maskura-local
maskura get ingest/data.jsonl --bucket maskura-local
maskura local down
```

`maskura local init` uses the gateway image matching the CLI version, stores data
in a Docker volume, and binds only to localhost. Run `maskura --help` for keys,
external storage, plugins, and MCP commands.

## Bring your own Wasm pipeline

Plugins are runtime-loaded components; adding one does not require rebuilding the
gateway:

```bash
maskura plugin upload my-plugin.component.wasm
maskura plugin enable <id>
maskura plugin reorder pii-default my-plugin
```

The output of each plugin becomes the input of the next. The SDK, WIT contract,
sandbox limits, and a minimal component are documented in
[Build a plugin](docs/plugins.md). Schema-aware binary adapters use a separate
[binary reductor contract](docs/binary-adapters.md).

## Python client

Generated Python and TypeScript clients ship with every release. The Python
high-level client can use the S3 data plane directly:

```python
from maskura_client import MaskuraClient

client = MaskuraClient("http://localhost:8791", "demo", "demo")
client.put_object(
    "maskura-local",
    "ingest/data.txt",
    b"jane@example.com 4111111111111111",
)
print(client.get_object("maskura-local", "ingest/data.txt").decode())
# [REDACTED_EMAIL] [REDACTED_CARD]
```

For recoverable PII, the clients generate a hybrid X25519 + ML-KEM-768 keypair,
attach only the public key, and decrypt locally. Run `just proof python` for the
complete assertion-backed flow, or read [Encryption](docs/encryption.md).

## Read projections

Maskura can also transform on read. The original remains in storage while a
caller opting into `x-maskura-process: read` receives the pipeline output. The
path is fail-closed and deliberately disabled until its spool and reviewed plugin
policy are configured. See [Security](docs/security.md) for the deployment rules.

## Run the proof

```bash
just proof
```

The proof runs against the published container and checks an AWS CLI redaction
round trip, live Wasm import without a gateway rebuild, and Python hybrid
encryption with client-only decryption. It prints the tested image digest and
fails when an assertion is missing. [Proof contract](docs/proofs.md) states the
exact checks and their limits.

```text
S3 SDK / CLI / agent ──▶ Maskura ──▶ storage
                            │
                            └─ Wasm pipeline
                               ├─ redact
                               ├─ encrypt
                               └─ your plugins, in order
```

## Develop

```bash
just check          # format, lint, build plugins, and test
just pre-push       # fast local trust and dependency gate
just e2e            # S3 interoperability against MinIO
just proof          # black-box checks against a published image
just build-sdks     # regenerate clients from OpenAPI
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, local CI runners, and the pull
request process. Architecture decisions live in [docs/adr/](docs/adr/).

## Security

Read [the security model](docs/security.md) before exposing Maskura beyond a
local machine. Vulnerabilities should be reported through
[private vulnerability reporting](https://github.com/231self/maskura/security/advisories/new)
or security@231self.com, never a public issue.

Releases include checksums, an SPDX JSON SBOM, and GitHub build-provenance
attestations. CI runs RustSec, dependency policy and diff review, plus CodeQL for
Rust, Python, JavaScript/TypeScript, and workflow code.

## More

- [Documentation](https://231self.github.io/maskura/)
- [Runnable examples](examples/README.md)
- [MCP server](docs/mcp.md)
- [Avro support](docs/avro.md)
- [Benchmarks](docs/benchmarks.md)
- [Open-source and hosted Maskura](https://maskura.dev/open-source/)

## License

Apache-2.0. See [LICENSE](LICENSE).
