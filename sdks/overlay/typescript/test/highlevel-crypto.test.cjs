const test = require("node:test");
const assert = require("node:assert/strict");
const { x25519 } = require("@noble/curves/ed25519");
const { hkdf } = require("@noble/hashes/hkdf");
const { sha256 } = require("@noble/hashes/sha256");
const { ml_kem768 } = require("@noble/post-quantum/ml-kem");
const { MaskuraClient } = require("../dist/highlevel.js");

function pemBytes(pem, label) {
  return Uint8Array.from(
    Buffer.from(
      pem
        .replace(`-----BEGIN ${label}-----`, "")
        .replace(`-----END ${label}-----`, "")
        .replace(/\s+/g, ""),
      "base64",
    ),
  );
}

function concat(...values) {
  return Uint8Array.from(Buffer.concat(values.map((value) => Buffer.from(value))));
}

test("hybrid keypair and gateway envelope round trip", async () => {
  const pair = await MaskuraClient.generateKeypair();
  const privateRaw = pemBytes(pair.privateKeyPem, "MASKURA HYBRID PRIVATE KEY");
  const publicRaw = pemBytes(pair.publicKeyPem, "MASKURA HYBRID PUBLIC KEY");
  assert.equal(privateRaw.length, 96);
  assert.equal(publicRaw.length, 1216);

  const ephemeralSecret = crypto.getRandomValues(new Uint8Array(32));
  const encapsulated = ml_kem768.encapsulate(publicRaw.slice(32));
  const dek = hkdf(
    sha256,
    concat(
      x25519.getSharedSecret(ephemeralSecret, publicRaw.slice(0, 32)),
      encapsulated.sharedSecret,
    ),
    new Uint8Array(0),
    new TextEncoder().encode("maskura/hybrid/envelope-dek/v1"),
    32,
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["encrypt"]);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      key,
      new TextEncoder().encode("alice@example.com"),
    ),
  );
  const envelope = {
    alg: "X25519+ML-KEM-768/AES-256-GCM",
    iv: Buffer.from(iv).toString("base64"),
    enc_dek: Buffer.from(
      concat(x25519.getPublicKey(ephemeralSecret), encapsulated.cipherText),
    ).toString("base64"),
    ct: Buffer.from(sealed.slice(0, -16)).toString("base64"),
    tag: Buffer.from(sealed.slice(-16)).toString("base64"),
  };
  const payload = new TextEncoder().encode(`before ${JSON.stringify(envelope)} after`);
  const plaintext = await MaskuraClient.decryptPayload(payload, pair.privateKeyPem);
  assert.equal(new TextDecoder().decode(plaintext), "before alice@example.com after");
});

test("legacy RSA envelopes remain readable", async () => {
  const pair = await MaskuraClient.generateLegacyRsaKeypair();
  const publicKey = await crypto.subtle.importKey(
    "spki",
    pemBytes(pair.publicKeyPem, "PUBLIC KEY"),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
  const dek = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["encrypt"]);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      aesKey,
      new TextEncoder().encode("legacy@example.com"),
    ),
  );
  const envelope = {
    alg: "RSA-OAEP/AES-256-GCM",
    iv: Buffer.from(iv).toString("base64"),
    enc_dek: Buffer.from(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, dek)).toString(
      "base64",
    ),
    ct: Buffer.from(sealed.slice(0, -16)).toString("base64"),
    tag: Buffer.from(sealed.slice(-16)).toString("base64"),
  };
  const plaintext = await MaskuraClient.decryptPayload(
    new TextEncoder().encode(JSON.stringify(envelope)),
    pair.privateKeyPem,
  );
  assert.equal(new TextDecoder().decode(plaintext), "legacy@example.com");
});
