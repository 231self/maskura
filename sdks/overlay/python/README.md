# Maskura Python SDK (`maskura-client`)

Generated Python client for the Maskura Gateway API. The canonical import is
`maskura_client`; the permanent <code>s4&#95;client</code> compatibility namespace is included
in the same distribution.

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

configuration = Configuration(host="https://api.s4.231self.com")
client = MaskuraClient(
    endpoint=configuration.host,
    access_key="s4_example",
    secret_key="s4s_example",
)
```

Object PUT/GET helpers work with current gateways. The high-level
`generate_keypair` and `decrypt_payload` helpers implement the legacy RSA
envelope for compatibility with older stored objects. Current gateways accept
only Maskura hybrid X25519 + ML-KEM-768 public keys for new encrypted writes;
see the [client tooling status](../../docs/encryption.md#client-tooling-status)
before using envelope encryption.

## Tests

```sh
pytest
```
