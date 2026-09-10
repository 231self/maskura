#!/usr/bin/env python3
"""Prove Maskura's Python hybrid-encryption path against a live gateway."""

from __future__ import annotations

import os

import requests

from maskura_client import MaskuraClient


def main() -> None:
    endpoint = os.environ.get("MASKURA_PROOF_ENDPOINT", "http://127.0.0.1:8793")
    response = requests.post(
        f"{endpoint}/dashboard/api/keys",
        json={"label": "python-hybrid-proof"},
        timeout=30,
    )
    response.raise_for_status()
    credential = response.json()

    client = MaskuraClient(endpoint, credential["key_id"], credential["secret"])
    private_key, public_key = client.generate_keypair()
    client.attach_public_key(public_key)

    listed = requests.get(f"{endpoint}/dashboard/api/keys", timeout=30)
    listed.raise_for_status()
    serialized_keys = listed.text
    assert "MASKURA HYBRID PUBLIC KEY" in serialized_keys
    assert "MASKURA HYBRID PRIVATE KEY" not in serialized_keys

    plaintext = b"customer jane@example.com card 4111111111111111\n"
    client.put_object("maskura-local", "proof/python-hybrid.txt", plaintext)
    stored = client.get_object("maskura-local", "proof/python-hybrid.txt")

    assert b"jane@example.com" not in stored, "plaintext email reached raw read-back"
    assert b"4111111111111111" not in stored, "plaintext card reached raw read-back"
    assert b'"alg":"X25519+ML-KEM-768/AES-256-GCM"' in stored
    assert client.decrypt_payload(stored, private_key) == plaintext
    print("PASS  Python client -> hybrid encrypted object -> client-only decryption")


if __name__ == "__main__":
    main()
