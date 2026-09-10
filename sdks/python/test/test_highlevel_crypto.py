import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, x25519
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from maskura_client.highlevel import MaskuraClient


def _pem_bytes(pem, label):
    return base64.b64decode(
        pem.replace(f"-----BEGIN {label}-----", "")
        .replace(f"-----END {label}-----", "")
        .replace("\n", "")
    )


def test_hybrid_keypair_and_gateway_envelope_roundtrip():
    private_pem, public_pem = MaskuraClient.generate_keypair()
    private_raw = _pem_bytes(private_pem, "MASKURA HYBRID PRIVATE KEY")
    public_raw = _pem_bytes(public_pem, "MASKURA HYBRID PUBLIC KEY")
    assert len(private_raw) == 96
    assert len(public_raw) == 1216

    ephemeral = x25519.X25519PrivateKey.generate()
    x25519_shared = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(public_raw[:32]))
    mlkem_shared, mlkem_ciphertext = MLKEM768PublicKey.from_public_bytes(
        public_raw[32:]
    ).encapsulate()
    dek = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"maskura/hybrid/envelope-dek/v1",
    ).derive(x25519_shared + mlkem_shared)
    iv = os.urandom(12)
    sealed = AESGCM(dek).encrypt(iv, b"alice@example.com", None)
    envelope = {
        "alg": "X25519+ML-KEM-768/AES-256-GCM",
        "iv": base64.b64encode(iv).decode(),
        "enc_dek": base64.b64encode(
            ephemeral.public_key().public_bytes_raw() + mlkem_ciphertext
        ).decode(),
        "ct": base64.b64encode(sealed[:-16]).decode(),
        "tag": base64.b64encode(sealed[-16:]).decode(),
    }
    payload = b"before " + json.dumps(envelope, separators=(",", ":")).encode() + b" after"
    assert MaskuraClient.decrypt_payload(payload, private_pem) == b"before alice@example.com after"


def test_legacy_rsa_envelopes_remain_readable():
    private_pem, public_pem = MaskuraClient.generate_legacy_rsa_keypair()
    public_key = serialization.load_pem_public_key(public_pem.encode())
    dek = os.urandom(32)
    iv = os.urandom(12)
    sealed = AESGCM(dek).encrypt(iv, b"legacy@example.com", None)
    wrapped = public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    envelope = {
        "alg": "RSA-OAEP/AES-256-GCM",
        "iv": base64.b64encode(iv).decode(),
        "enc_dek": base64.b64encode(wrapped).decode(),
        "ct": base64.b64encode(sealed[:-16]).decode(),
        "tag": base64.b64encode(sealed[-16:]).decode(),
    }
    payload = json.dumps(envelope, separators=(",", ":")).encode()
    assert MaskuraClient.decrypt_payload(payload, private_pem) == b"legacy@example.com"
