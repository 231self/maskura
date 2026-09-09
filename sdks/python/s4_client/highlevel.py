"""High-level Maskura client: object I/O plus legacy envelope compatibility.

The generated low-level client covers the dashboard API (keys, plugins,
backends). This module adds the S3 data-plane operations the gateway exposes
plus the client side of the envelope-encryption scheme:

* ``put_object`` / ``get_object`` — raw byte objects through the gateway,
  authenticated with the Maskura API key headers (``x-maskura-access-key`` /
  ``x-maskura-secret-key``).
* ``generate_keypair`` / ``attach_public_key`` — legacy RSA provisioning for
  pre-hybrid gateways. Current gateways reject these RSA public keys.
* ``decrypt_payload`` — recover plaintext from legacy stored payloads: scans for
  ``RSA-OAEP/AES-256-GCM`` envelopes, unwraps each DEK with the client-held
  private key, and AES-256-GCM-decrypts the field back to plaintext.

Legacy read path (client-side decryption):
    raw = client.get_object("my-bucket", "ingest/data.jsonl")
    plaintext = MaskuraClient.decrypt_payload(raw, private_pem)

Extra dependencies beyond the generated client: ``requests`` and
``cryptography``.
"""

from __future__ import annotations

import base64
import json
from typing import Tuple

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_ENVELOPE_ALG = "RSA-OAEP/AES-256-GCM"
_MARKER = b'"alg":"' + _ENVELOPE_ALG.encode() + b'"'
_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


class MaskuraClient:
    """Minimal high-level client for the Maskura S3 data plane."""

    def __init__(self, endpoint: str, access_key: str, secret_key: str, timeout: int = 60):
        self.endpoint = endpoint.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        self.timeout = timeout

    def _headers(self) -> dict:
        return {
            "x-maskura-access-key": self.access_key,
            "x-maskura-secret-key": self.secret_key,
        }

    # -- keys ---------------------------------------------------------

    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """Generate a legacy RSA-2048 envelope keypair.

        Current gateways accept only Maskura hybrid public keys for new writes;
        this helper exists to support pre-hybrid gateways and stored objects.

        Returns ``(private_key_pem, public_key_pem)`` — PKCS#8 private key
        and SPKI public key, both PEM. Store the private key somewhere safe;
        it is the only way to decrypt what Maskura stores.
        """
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        public_pem = private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return private_pem, public_pem

    def attach_public_key(self, public_key_pem: str) -> None:
        """Bind a public key to this API key.

        Current gateways reject the legacy RSA keys created by
        ``generate_keypair``. This method remains for pre-hybrid gateways.
        """
        resp = requests.put(
            f"{self.endpoint}/dashboard/api/keys/public-key",
            headers=self._headers(),
            json={"key_id": self.access_key, "public_key_pem": public_key_pem},
            timeout=self.timeout,
        )
        resp.raise_for_status()

    # -- object data plane -------------------------------------------

    def put_object(self, bucket: str, key: str, data: bytes, content_type: str = "text/plain") -> None:
        """Upload ``data`` to ``bucket/key`` through the Maskura filter pipeline."""
        resp = requests.put(
            f"{self.endpoint}/{bucket}/{key}",
            headers={**self._headers(), "Content-Type": content_type},
            data=data,
            timeout=self.timeout,
        )
        resp.raise_for_status()

    def get_object(self, bucket: str, key: str) -> bytes:
        """Download the object stored at ``bucket/key`` (envelopes included)."""
        resp = requests.get(
            f"{self.endpoint}/{bucket}/{key}",
            headers=self._headers(),
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.content

    # -- envelope crypto ----------------------------------------------

    @staticmethod
    def decrypt_payload(payload: bytes, private_key_pem: str) -> bytes:
        """Decrypt every envelope in ``payload`` back to plaintext.

        Encrypted fields are replaced in place; anything else (e.g. the
        non-Luhn numbers the detector ignores) is left untouched.
        """
        key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        out = bytearray()
        pos = 0
        while True:
            idx = payload.find(_MARKER, pos)
            if idx < 0:
                out += payload[pos:]
                break
            start = payload.rfind(b"{", 0, idx)
            if start < 0:
                out += payload[pos : idx + len(_MARKER)]
                pos = idx + len(_MARKER)
                continue
            depth = 0
            end = -1
            for j in range(start, len(payload)):
                c = payload[j]
                if c == 0x7B:
                    depth += 1
                elif c == 0x7D:
                    depth -= 1
                    if depth == 0:
                        end = j + 1
                        break
            if end < 0:
                out += payload[pos:]
                break
            env = json.loads(payload[start:end])
            plain = MaskuraClient._decrypt_envelope(env, key)
            out += payload[pos:start]
            out += plain
            pos = end
        return bytes(out)

    @staticmethod
    def _decrypt_envelope(env: dict, private_key) -> bytes:
        assert env["alg"] == _ENVELOPE_ALG, env["alg"]
        dek = private_key.decrypt(base64.b64decode(env["enc_dek"]), _OAEP)
        ciphertext = base64.b64decode(env["ct"]) + base64.b64decode(env["tag"])
        return AESGCM(dek).decrypt(base64.b64decode(env["iv"]), ciphertext, None)


# Permanent compatibility export for existing integrations.
S4Client = MaskuraClient
