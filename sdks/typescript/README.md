## Maskura TypeScript SDK (`maskura-client`)

This generated TypeScript/JavaScript client uses the Fetch API. It is not
currently published to npm.

### Install From A Release

Download and extract the canonical SDK archive, then install the extracted
package directory:

```sh
curl -fLO https://github.com/231self/maskura/releases/latest/download/maskura-typescript-sdk.tar.gz
mkdir -p vendor/maskura-client
tar -xzf maskura-typescript-sdk.tar.gz -C vendor/maskura-client
npm install --install-links ./vendor/maskura-client --save
```

### Install From Source

From a checkout of `https://github.com/231self/maskura`:

```sh
npm install --prefix sdks/typescript --no-package-lock
npm run --prefix sdks/typescript build
npm install --install-links ./sdks/typescript --save
```

### Build And Test

```sh
npm install
npm run build
node --test test/highlevel-attach.test.cjs
```

### Usage

```typescript
import { MaskuraClient } from "maskura-client";

const client = new MaskuraClient({
  endpoint: "https://maskura.dev",
  accessKey: "maskura_example",
  secretKey: "maskura_secret_example",
});
```

The high-level client supports the current hybrid encryption flow:

```typescript
const { privateKeyPem, publicKeyPem } = await MaskuraClient.generateKeypair();
await client.attachPublicKey(publicKeyPem);
await client.putObject("bucket", "data.jsonl", new TextEncoder().encode('{"email":"jane@example.com"}'));
const stored = await client.getObject("bucket", "data.jsonl");
const plaintext = await MaskuraClient.decryptPayload(stored, privateKeyPem);
```

Store `privateKeyPem` securely; only the public key is uploaded. The package
retains CommonJS output and supports Node 18+ or browsers with Web Crypto.
`decryptPayload` also reads legacy RSA envelopes, and
`generateLegacyRsaKeypair` remains available only for pre-hybrid gateways and
compatibility fixtures. See the
[encryption reference](../../docs/encryption.md#client-tooling-status).
