# Maskura Python SDK (`maskura-client`)

Generated Python client for the Maskura Gateway API. Import it as
`maskura_client`.

## Requirements

Python 3.9+

## Installation

Install directly from the current Maskura repository:

```sh
pip install "git+https://github.com/231self/maskura.git#subdirectory=sdks/python"
```

Release downloads can be installed directly as well:

```sh
pip install https://github.com/231self/maskura/releases/latest/download/maskura-python-sdk.tar.gz
```

## Usage

```python
from maskura_client import Configuration, MaskuraClient

configuration = Configuration(host="https://maskura.dev")
client = MaskuraClient(
    endpoint=configuration.host,
    access_key="maskura_example",
    secret_key="maskura_secret_example",
)
```

The high-level client supports the current hybrid encryption flow:

```python
private_pem, public_pem = MaskuraClient.generate_keypair()
client.attach_public_key(public_pem)
client.put_object("bucket", "data.jsonl", b'{"email":"jane@example.com"}')
stored = client.get_object("bucket", "data.jsonl")
plaintext = MaskuraClient.decrypt_payload(stored, private_pem)
```

Store `private_pem` securely; only the public key is uploaded. Hybrid support
requires `cryptography >= 47`. `decrypt_payload` also reads legacy RSA
envelopes, and `generate_legacy_rsa_keypair` remains available only for
pre-hybrid gateways and compatibility fixtures. See the
[encryption reference](../../docs/encryption.md#client-tooling-status).

## Tests

```sh
pytest
```
