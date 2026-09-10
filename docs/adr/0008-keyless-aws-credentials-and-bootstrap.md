# ADR 0008: Keyless AWS credentials, `aws_role` backends, and bootstrapped gateway keys

- Status: Accepted
- Date: 2026-09-06

## Context

The gateway historically required static long-lived credentials for every S3
destination: `S3_ACCESS_KEY_ID`/`S3_SECRET_ACCESS_KEY` for the global
single-tenant client, and a persisted `s3_compatible` access/secret pair for
per-workspace backends. `BackendType::AwsRole` existed in the schema but was
rejected at configuration time. Static keys are a security liability and are
awkward to rotate, and AWS-native deployments should be able to rely on
short-lived, automatically-refreshed credentials instead.

At the same time, headless automation had no stable gateway credential: the
only key material was either generated at startup (demo mode) or minted
interactively, so operators had to copy a freshly generated secret on every
cold start.

## Decision

1. **Default credential provider chain for the global client.** When
   `S3_ENDPOINT` is configured without static `S3_ACCESS_KEY_ID` /
   `S3_SECRET_ACCESS_KEY`, the global single-tenant client is built without an
   explicit `credentials_provider`, deferring to the AWS default chain (EC2
   instance profile, ECS task role, EKS IRSA, SSO, OIDC web identity). Static
   keys still take precedence when both are present.

2. **`aws_role` per-workspace backends via STS.** `RuntimeBackendConfig::AwsRole`
   carries a role ARN, region, and optional `external_id`. On resolution the
   gateway assumes the role with `aws-sdk-sts` (using the default credential
   chain), then builds the destination client from the returned temporary
   credentials (access key, secret, session token, expiry). The destination is
   always the canonical AWS regional endpoint (`https://s3.<region>.amazonaws.com`),
   so the operator endpoint allowlist does not apply; the trust boundary is the
   role ARN itself plus the identity allowed to assume it, reinforced by the
   optional `external_id`.

3. **Bootstrapped gateway key.** `MASKURA_BOOTSTRAP_KEY` / `MASKURA_BOOTSTRAP_SECRET`
   (with permanent `MASKURA_*` aliases) seed a preconfigured key id/secret pair at
   startup when the pair is not already present. The secret is SHA-256 hashed and
   encrypted with the same envelope as generated keys. This is scoped to
   operator/headless bootstrap; interactive and production flows keep using the
   normal key-creation path.

## Consequences

- **No long-lived AWS keys in the keyless path.** Credentials resolve lazily via
  the ambient AWS identity, so rotation is handled by the platform (IRSA, SSO,
  instance profile) rather than by redistributing secrets.
- **STS assume-role happens per request.** Temporary credentials are used for a
  single operation and are never serialized or persisted. This trades a per-request
  STS call for the absence of any credential cache; a short-TTL in-process cache
  is a follow-up if request volume justifies it.
- **`aws_role` config is validated at the boundary.** Role ARNs must be
  `arn:...:role/...`, a region is required, and static credentials/endpoints are
  rejected for this backend type. The redacted dashboard response exposes
  `external_id` (it is a correlation value, not a secret) but never the temporary
  credentials.
- **Schema change.** `BackendConfigRequest` and `BackendConfigResponse` gain an
  `external_id` field, requiring SDK regeneration via `just build-sdks`.
- **Bootstrapped keys are operator-managed.** They are printed nowhere at
  startup and rely on the operator rotating them out of band; they must not be
  used in place of per-user keys where attribution matters.
