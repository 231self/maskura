"""High-level Maskura client: object I/O and envelope encryption helpers.

The generated low-level client covers the dashboard API. This module adds the
S3 data-plane operations plus client-held hybrid key generation and decryption.
New keys use X25519 + ML-KEM-768; legacy RSA envelopes remain readable.
"""

from __future__ import annotations

import base64
import json
from typing import Tuple

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, x25519
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_HYBRID_ALG = "X25519+ML-KEM-768/AES-256-GCM"
_LEGACY_RSA_ALG = "RSA-OAEP/AES-256-GCM"
_HYBRID_PUBLIC_LABEL = "MASKURA HYBRID PUBLIC KEY"
_HYBRID_PRIVATE_LABEL = "MASKURA HYBRID PRIVATE KEY"
_KDF_INFO = b"maskura/hybrid/envelope-dek/v1"
_X25519_KEY_LEN = 32
_MLKEM_CIPHERTEXT_LEN = 1088
_MLKEM_SEED_LEN = 64
_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def _encode_pem(label: str, raw: bytes) -> str:
    body = base64.b64encode(raw).decode()
    lines = "\n".join(body[offset : offset + 64] for offset in range(0, len(body), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n"


def _decode_pem(label: str, pem: str) -> bytes:
    begin = f"-----BEGIN {label}-----"
    end = f"-----END {label}-----"
    value = pem.strip()
    if not value.startswith(begin) or not value.endswith(end):
        raise ValueError(f"expected a {label} PEM block")
    body = "".join(value[len(begin) : -len(end)].split())
    return base64.b64decode(body, validate=True)


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

    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """Generate a gateway-compatible hybrid keypair.

        Returns ``(private_key_pem, public_key_pem)``. The private PEM contains
        only the X25519 secret and the ML-KEM seed and must never be uploaded.
        """
        x25519_private = x25519.X25519PrivateKey.generate()
        mlkem_private = MLKEM768PrivateKey.generate()
        private_raw = x25519_private.private_bytes_raw() + mlkem_private.private_bytes_raw()
        public_raw = (
            x25519_private.public_key().public_bytes_raw()
            + mlkem_private.public_key().public_bytes_raw()
        )
        return (
            _encode_pem(_HYBRID_PRIVATE_LABEL, private_raw),
            _encode_pem(_HYBRID_PUBLIC_LABEL, public_raw),
        )

    @staticmethod
    def generate_legacy_rsa_keypair() -> Tuple[str, str]:
        """Generate an RSA keypair for pre-hybrid gateways and old fixtures."""
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
        """Bind a Maskura hybrid public key to this API key."""
        resp = requests.put(
            f"{self.endpoint}/dashboard/api/keys/public-key",
            headers=self._headers(),
            json={"key_id": self.access_key, "public_key_pem": public_key_pem},
            timeout=self.timeout,
        )
        resp.raise_for_status()

    def put_object(self, bucket: str, key: str, data: bytes, content_type: str = "text/plain") -> None:
        """Upload ``data`` to ``bucket/key`` through the Maskura pipeline."""
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

    @staticmethod
    def decrypt_payload(payload: bytes, private_key_pem: str) -> bytes:
        """Decrypt current hybrid or legacy RSA envelopes in ``payload``."""
        if f"-----BEGIN {_HYBRID_PRIVATE_LABEL}-----" in private_key_pem:
            key = MaskuraClient._load_hybrid_private_key(private_key_pem)
            supported_alg = _HYBRID_ALG
        else:
            key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
            if not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError("expected a Maskura hybrid or RSA private key")
            supported_alg = _LEGACY_RSA_ALG

        marker = b'"alg":"' + supported_alg.encode() + b'"'
        out = bytearray()
        pos = 0
        while True:
            idx = payload.find(marker, pos)
            if idx < 0:
                out += payload[pos:]
                break
            start = payload.rfind(b"{", 0, idx)
            if start < 0:
                out += payload[pos : idx + len(marker)]
                pos = idx + len(marker)
                continue
            depth = 0
            end = -1
            for offset in range(start, len(payload)):
                if payload[offset] == 0x7B:
                    depth += 1
                elif payload[offset] == 0x7D:
                    depth -= 1
                    if depth == 0:
                        end = offset + 1
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
    def _load_hybrid_private_key(private_key_pem: str) -> tuple[x25519.X25519PrivateKey, MLKEM768PrivateKey]:
        raw = _decode_pem(_HYBRID_PRIVATE_LABEL, private_key_pem)
        expected = _X25519_KEY_LEN + _MLKEM_SEED_LEN
        if len(raw) != expected:
            raise ValueError(f"hybrid private key must contain {expected} bytes, got {len(raw)}")
        return (
            x25519.X25519PrivateKey.from_private_bytes(raw[:_X25519_KEY_LEN]),
            MLKEM768PrivateKey.from_seed_bytes(raw[_X25519_KEY_LEN:]),
        )

    @staticmethod
    def _decrypt_envelope(env: dict, private_key) -> bytes:
        algorithm = env.get("alg")
        enc_dek = base64.b64decode(env["enc_dek"], validate=True)
        if algorithm == _HYBRID_ALG:
            x25519_private, mlkem_private = private_key
            expected = _X25519_KEY_LEN + _MLKEM_CIPHERTEXT_LEN
            if len(enc_dek) != expected:
                raise ValueError(f"hybrid enc_dek must contain {expected} bytes, got {len(enc_dek)}")
            x25519_public = x25519.X25519PublicKey.from_public_bytes(enc_dek[:_X25519_KEY_LEN])
            shared = x25519_private.exchange(x25519_public) + mlkem_private.decapsulate(
                enc_dek[_X25519_KEY_LEN:]
            )
            dek = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None, info=_KDF_INFO
            ).derive(shared)
        elif algorithm == _LEGACY_RSA_ALG:
            dek = private_key.decrypt(enc_dek, _OAEP)
        else:
            raise ValueError(f"unsupported envelope algorithm: {algorithm or 'missing'}")
        ciphertext = base64.b64decode(env["ct"], validate=True) + base64.b64decode(
            env["tag"], validate=True
        )
        return AESGCM(dek).decrypt(base64.b64decode(env["iv"], validate=True), ciphertext, None)


S4Client = MaskuraClient
