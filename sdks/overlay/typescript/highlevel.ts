/** High-level Maskura data-plane and envelope-encryption client. */
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";

declare const globalThis: any;

const HYBRID_ALG = "X25519+ML-KEM-768/AES-256-GCM";
const LEGACY_RSA_ALG = "RSA-OAEP/AES-256-GCM";
const HYBRID_PUBLIC_LABEL = "MASKURA HYBRID PUBLIC KEY";
const HYBRID_PRIVATE_LABEL = "MASKURA HYBRID PRIVATE KEY";
const KDF_INFO = new TextEncoder().encode("maskura/hybrid/envelope-dek/v1");
const X25519_KEY_LEN = 32;
const MLKEM_CIPHERTEXT_LEN = 1088;
const MLKEM_SEED_LEN = 64;

export interface MaskuraClientOptions {
  endpoint: string;
  accessKey: string;
  secretKey: string;
  timeoutMs?: number;
}

export class MaskuraClient {
  private readonly endpoint: string;
  private readonly accessKey: string;
  private readonly secretKey: string;
  private readonly timeoutMs: number;

  constructor(opts: MaskuraClientOptions) {
    this.endpoint = opts.endpoint.replace(/\/$/, "");
    this.accessKey = opts.accessKey;
    this.secretKey = opts.secretKey;
    this.timeoutMs = opts.timeoutMs ?? 60_000;
  }

  private authHeaders(): Record<string, string> {
    return { "x-maskura-access-key": this.accessKey, "x-maskura-secret-key": this.secretKey };
  }

  /** Generate a gateway-compatible X25519 + ML-KEM-768 keypair. */
  static async generateKeypair(): Promise<{ privateKeyPem: string; publicKeyPem: string }> {
    const x25519Secret = MaskuraClient.randomBytes(X25519_KEY_LEN);
    const mlkemSeed = MaskuraClient.randomBytes(MLKEM_SEED_LEN);
    const mlkem = ml_kem768.keygen(mlkemSeed);
    return {
      publicKeyPem: MaskuraClient.toPem(
        MaskuraClient.concat(x25519.getPublicKey(x25519Secret), mlkem.publicKey),
        HYBRID_PUBLIC_LABEL,
      ),
      privateKeyPem: MaskuraClient.toPem(
        MaskuraClient.concat(x25519Secret, mlkemSeed),
        HYBRID_PRIVATE_LABEL,
      ),
    };
  }

  /** Generate an RSA keypair for pre-hybrid gateways and old fixtures. */
  static async generateLegacyRsaKeypair(): Promise<{ privateKeyPem: string; publicKeyPem: string }> {
    const subtle = globalThis.crypto.subtle;
    const kp = await subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"],
    );
    return {
      publicKeyPem: MaskuraClient.toPem(new Uint8Array(await subtle.exportKey("spki", kp.publicKey)), "PUBLIC KEY"),
      privateKeyPem: MaskuraClient.toPem(new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey)), "PRIVATE KEY"),
    };
  }

  /** Bind a Maskura hybrid public key to this API key. */
  async attachPublicKey(publicKeyPem: string): Promise<void> {
    const resp = await fetch(`${this.endpoint}/dashboard/api/keys/public-key`, {
      method: "PUT",
      headers: { ...this.authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ key_id: this.accessKey, public_key_pem: publicKeyPem }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!resp.ok) throw new Error(`attachPublicKey failed: ${resp.status} ${await resp.text()}`);
  }

  /** Upload `data` to `bucket/key` through the Maskura filter pipeline. */
  async putObject(
    bucket: string,
    key: string,
    data: Uint8Array,
    contentType = "text/plain",
  ): Promise<void> {
    const resp = await fetch(`${this.endpoint}/${bucket}/${key}`, {
      method: "PUT",
      headers: { ...this.authHeaders(), "Content-Type": contentType },
      body: data,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!resp.ok) throw new Error(`putObject failed: ${resp.status} ${await resp.text()}`);
  }

  /** Download the object stored at `bucket/key` (envelopes included). */
  async getObject(bucket: string, key: string): Promise<Uint8Array> {
    const resp = await fetch(`${this.endpoint}/${bucket}/${key}`, {
      method: "GET",
      headers: this.authHeaders(),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!resp.ok) throw new Error(`getObject failed: ${resp.status} ${await resp.text()}`);
    return new Uint8Array(await resp.arrayBuffer());
  }

  /** Decrypt current hybrid or legacy RSA envelopes in `payload`. */
  static async decryptPayload(payload: Uint8Array, privateKeyPem: string): Promise<Uint8Array> {
    const hybrid = privateKeyPem.includes(`-----BEGIN ${HYBRID_PRIVATE_LABEL}-----`);
    const algorithm = hybrid ? HYBRID_ALG : LEGACY_RSA_ALG;
    const privateKey = hybrid
      ? MaskuraClient.parseHybridPrivateKey(privateKeyPem)
      : await MaskuraClient.importLegacyRsaPrivateKey(privateKeyPem);
    const bytes = Array.from(payload);
    const marker = Array.from(new TextEncoder().encode(`"alg":"${algorithm}"`));
    const out: number[] = [];
    let pos = 0;
    while (true) {
      const idx = MaskuraClient.indexOf(bytes, marker, pos);
      if (idx < 0) {
        for (let i = pos; i < bytes.length; i++) out.push(bytes[i]!);
        break;
      }
      const start = bytes.lastIndexOf(0x7b, idx);
      if (start < 0) {
        for (let i = pos; i < idx + marker.length; i++) out.push(bytes[i]!);
        pos = idx + marker.length;
        continue;
      }
      let depth = 0;
      let end = -1;
      for (let offset = start; offset < bytes.length; offset++) {
        if (bytes[offset] === 0x7b) depth++;
        else if (bytes[offset] === 0x7d && --depth === 0) {
          end = offset + 1;
          break;
        }
      }
      if (end < 0) {
        for (let i = pos; i < bytes.length; i++) out.push(bytes[i]!);
        break;
      }
      const env = JSON.parse(new TextDecoder().decode(new Uint8Array(bytes.slice(start, end))));
      const plain = hybrid
        ? await MaskuraClient.decryptHybridEnvelope(env, privateKey as HybridPrivateKey)
        : await MaskuraClient.decryptLegacyRsaEnvelope(env, privateKey as CryptoKey);
      for (let i = pos; i < start; i++) out.push(bytes[i]!);
      for (let i = 0; i < plain.length; i++) out.push(plain[i]!);
      pos = end;
    }
    return new Uint8Array(out);
  }

  private static parseHybridPrivateKey(pem: string): HybridPrivateKey {
    const raw = MaskuraClient.pemToBytes(pem, HYBRID_PRIVATE_LABEL);
    const expected = X25519_KEY_LEN + MLKEM_SEED_LEN;
    if (raw.length !== expected) {
      throw new Error(`Hybrid private key must contain ${expected} bytes, got ${raw.length}.`);
    }
    const mlkem = ml_kem768.keygen(raw.slice(X25519_KEY_LEN));
    return { x25519Secret: raw.slice(0, X25519_KEY_LEN), mlkemSecret: mlkem.secretKey };
  }

  private static async decryptHybridEnvelope(env: any, key: HybridPrivateKey): Promise<Uint8Array> {
    if (env.alg !== HYBRID_ALG) throw new Error(`unsupported alg: ${env.alg}`);
    const encapsulated = MaskuraClient.b64ToBytes(env.enc_dek);
    const expected = X25519_KEY_LEN + MLKEM_CIPHERTEXT_LEN;
    if (encapsulated.length !== expected) {
      throw new Error(`Hybrid enc_dek must contain ${expected} bytes, got ${encapsulated.length}.`);
    }
    const x25519Shared = x25519.getSharedSecret(key.x25519Secret, encapsulated.slice(0, X25519_KEY_LEN));
    const mlkemShared = ml_kem768.decapsulate(encapsulated.slice(X25519_KEY_LEN), key.mlkemSecret);
    const dek = hkdf(
      sha256,
      MaskuraClient.concat(x25519Shared, mlkemShared),
      new Uint8Array(0),
      KDF_INFO,
      32,
    );
    return MaskuraClient.decryptAesGcm(env, dek);
  }

  private static async importLegacyRsaPrivateKey(pem: string): Promise<CryptoKey> {
    return globalThis.crypto.subtle.importKey(
      "pkcs8",
      MaskuraClient.pemToBytes(pem, "PRIVATE KEY"),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"],
    );
  }

  private static async decryptLegacyRsaEnvelope(env: any, key: CryptoKey): Promise<Uint8Array> {
    if (env.alg !== LEGACY_RSA_ALG) throw new Error(`unsupported alg: ${env.alg}`);
    const dek = await globalThis.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      key,
      MaskuraClient.b64ToBytes(env.enc_dek),
    );
    return MaskuraClient.decryptAesGcm(env, new Uint8Array(dek));
  }

  private static async decryptAesGcm(env: any, dek: Uint8Array): Promise<Uint8Array> {
    const subtle = globalThis.crypto.subtle;
    const key = await subtle.importKey("raw", dek, "AES-GCM", false, ["decrypt"]);
    const plaintext = await subtle.decrypt(
      { name: "AES-GCM", iv: MaskuraClient.b64ToBytes(env.iv), tagLength: 128 },
      key,
      MaskuraClient.concat(MaskuraClient.b64ToBytes(env.ct), MaskuraClient.b64ToBytes(env.tag)),
    );
    return new Uint8Array(plaintext);
  }

  private static randomBytes(length: number): Uint8Array {
    return globalThis.crypto.getRandomValues(new Uint8Array(length));
  }

  private static concat(...arrays: Uint8Array[]): Uint8Array {
    const output = new Uint8Array(arrays.reduce((sum, value) => sum + value.length, 0));
    let offset = 0;
    for (const value of arrays) {
      output.set(value, offset);
      offset += value.length;
    }
    return output;
  }

  private static toPem(bytes: Uint8Array, label: string): string {
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode.apply(
        null,
        Array.from(bytes.subarray(offset, offset + 0x8000)),
      );
    }
    const body = btoa(binary).match(/.{1,64}/g)?.join("\n") ?? "";
    return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
  }

  private static pemToBytes(pem: string, label: string): Uint8Array {
    const begin = `-----BEGIN ${label}-----`;
    const end = `-----END ${label}-----`;
    const value = pem.trim();
    if (!value.startsWith(begin) || !value.endsWith(end)) {
      throw new Error(`Expected a ${label} PEM block.`);
    }
    return MaskuraClient.b64ToBytes(value.slice(begin.length, -end.length).replace(/\s+/g, ""));
  }

  private static b64ToBytes(value: string): Uint8Array {
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  private static indexOf(haystack: number[], needle: number[], from: number): number {
    outer: for (let i = from; i <= haystack.length - needle.length; i++) {
      for (let j = 0; j < needle.length; j++) {
        if (haystack[i + j] !== needle[j]) continue outer;
      }
      return i;
    }
    return -1;
  }
}

interface HybridPrivateKey {
  x25519Secret: Uint8Array;
  mlkemSecret: Uint8Array;
}

export type S4ClientOptions = MaskuraClientOptions;
export class S4Client extends MaskuraClient {}
