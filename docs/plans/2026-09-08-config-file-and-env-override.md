# Layered TOML configuration with env override

Status: planned
Scope: self-hosted OSS gateway, shared `build_state`, private SaaS control binary
Repositories: public `231self/maskura` (base schema, gateway), private `s4-private` (extension)

## Objective

Give the gateway a single TOML config file as the canonical home for its
non-secret settings, with environment variables overriding the file, so that
operating basic local behaviour requires as few user-tweakable knobs as
possible. The private SaaS binary gets its own TOML that *inherits* the OSS
schema (via serde flatten) and extends it with SaaS-only fields.

## Current-State Findings

- Configuration is read almost entirely from environment variables. There are
  ~50 distinct names in the gateway, split across three kinds: feature gates
  (safe "off" defaults), storage/identity, and operator/SaaS-only controls.
- The `MASKURA_*`/`S4_*` alias pairs are centralized in
  `crates/customer-config/src/lib.rs` (`EnvAlias`, `resolve`, `validate`,
  `GATEWAY_CUSTOMER_SETTINGS`, `CLIENT_CUSTOMER_SETTINGS`). But many reads bypass
  this crate and call `std::env::var` directly.
- `build_state` (`crates/gateway/src/server.rs:10986`) and
  `build_state_with_pipeline_template` (`:10999`) read the non-secret settings
  inline: `S3_ENDPOINT`/`S3_REGION`/`S3_*` creds (`11006`, `11038`–`11047`),
  `SUPABASE_URL`/`SUPABASE_JWT_SECRET` (`11089`–`11091`),
  `S4_MANAGED_STREAMING_MODE`/`S4_MANAGED_PLACEMENT_VERSION` (`11096`–`11099`),
  multipart quotas (`11104`–`11117`), `S4_MULTIPART_STAGING_*` (`11256`–`11289`),
  `DATABASE_URL` key store (`11180`), and spool/dev-memory settings
  (`11143`–`11173`).
- Helper readers: `enabled_env_flag` (`10839`), `multipart_mode` (`974`),
  `configured_s3_streaming_capabilities` (`987`),
  `configured_managed_streaming_capabilities` (`1009`),
  `legacy_max_object_bytes` (`1026`), `StreamingReadMode::from_env` (`911`),
  `transformed_read_spool_enabled` (`930`), `binary_avro_enabled` (`935`),
  `prefix_safe_component_hashes` (`943`), `source_body_limits_from_env` (`10967`),
  `component_path` (`10804`), `StatePipelineTemplate::from_env` (`721`).
- Policy constructors read env directly: `PresignedHttpPolicy::from_env`
  (`backend.rs:880`), `SigV4Policy::from_env` (`sigv4.rs:104`),
  `WorkspaceEndpointPolicy::from_env` (`backend.rs:656`).
- Secrets are read where used and stay env-only: `default_wrapping` /
  `LocalKeyWrapping::from_env` (`key_cipher.rs:129`/`62`) reads `S4_SECRET_KEK`;
  `DATABASE_URL`, `S3_*` creds, and `SUPABASE_JWT_SECRET` are read inside
  `build_state`.
- The OSS binary (`crates/gateway/src/main.rs`) reads only `LISTEN_ADDR` and
  injects `NoopControlPlane`, `default_wrapping()`, and
  `InMemoryWorkspaceStorageRepository` into `build_state`.
- The private binary (`s4-private/crates/s4-control/src/main.rs`) reads its own
  env surface (`DATABASE_URL`, `PADDLE_*`, `S4_VAULT_*`, `S4_KMS_KEY_ID`,
  `S4_FILTER_ARTIFACT_*`, `S4_CUSTOM_FILTER_UPLOADS_*`,
  `S4_HOSTED_PIPELINES_ENABLED`, `S4_UNSAFE_LOCAL_FILTER_VALIDATION`, …) and
  injects `SaaSControlPlane`, KMS/Vault wrapping, and
  `HostedWorkspaceStorageRepository` into the same `build_state` (`main.rs:695`).

## Decisions

1. **Layered TOML, schema inheritance via serde flatten.** The public
   `maskura-customer-config` crate grows a `Config` struct (base schema, TOML
   deserialize, defaults, validation, env override). The private crate defines
   `PrivateConfig { #[serde(flatten)] base: Config, … }` so a private TOML is a
   literal superset of the OSS TOML.
2. **Config file is canonical for non-secret settings; secrets stay env-only.**
   Secrets (`S3_ACCESS_KEY_ID`/`S3_SECRET_ACCESS_KEY`, `DATABASE_URL`,
   `SUPABASE_JWT_SECRET`/`SUPABASE_ANON_KEY`, `S4_SECRET_KEK`,
   `S4_MULTIPART_STAGING_*_KEY_ID/SECRET`, `MASKURA_BOOTSTRAP_SECRET`) are not
   fields in `Config`. With `deny_unknown_fields`, a secret in the file is a
   hard startup error — the property is enforced structurally.
3. **Precedence: defaults < file < env.** Compiled defaults via
   `#[serde(default)]`; the file supplies values when present; every non-secret
   field keeps an env override using its `MASKURA_*` name (or the existing
   operator name for operator-only settings).
4. **Discovery: default path + override.** Default `./maskura.toml`; explicit
   `--config <path>` or `MASKURA_CONFIG` wins. The private binary defaults to
   `./maskura-control.toml` with the same override rule.
5. **Fail closed on invalid file values.** Unknown keys, malformed TOML, and
   invalid enum/numeric values are hard startup errors (upgrading the current
   warn-then-default behaviour for file-sourced values).
6. **`build_state` takes the resolved config.** Signature becomes
   `build_state(control, wrapping, workspace_storage, config: &Config)`; the
   scattered non-secret env reads move to `config` field reads. Secrets keep
   their current env reads.
7. **Abandon the `S4_*` env aliases.** The customer-facing `MASKURA_*`/`S4_*`
   alias pairs collapse to the single `MASKURA_*` name; `EnvAlias::legacy` and
   its conflict handling are removed. A repo-wide sweep removes leftover `S4_*`
   alias references (code, tests, docs, scripts, `s4ctl`, examples, compose
   files). Operator-only `S4_*` names (`S4_SECRET_KEK`, `S4_SERVICE_BUCKETS`,
   `S4_SIGV4_*`, `S4_MANAGED_*`, `S4_MULTIPART_STAGING_*`, `S4_PRESIGNED_HTTP_*`,
   `S4_WORKSPACE_ENDPOINT_*`) are canonical, not aliases, and remain.
8. **Add `maskura config --check`** (`s4ctl`) to load a config file and report
   validation without booting the gateway.

## Ordered Implementation

### 1. Add `Config` to `maskura-customer-config`

**Files:** `crates/customer-config/src/lib.rs` (+ new `config.rs` module).

- Define `Config` with serde derive, `Default`, TOML tables
  (`[server]`, `[auth]`, `[storage]`, `[supabase]`, `[features]`, `[wasm]`,
  `[limits]`, `[spool]`, `[keys]`, `[managed]`, `[multipart_staging]`,
  `[sigv4]`, `[allowlists]`).
- Implement `Config::load(path) -> Result<Config>` (parse + `deny_unknown_fields`)
  and `apply_env_overrides(&mut self)` mapping each field to its single env name
  (`MASKURA_*` for customer settings, the operator name for operator-only settings).
- Implement `Config::resolve(path, env) -> Result<Config>` returning
  defaults → file → env with validation.

**Verify:** table-driven unit tests for parse, defaults, precedence
(default < file < env), `deny_unknown_fields`, and hard-error on invalid values.

### 2. Abandon the `S4_*` env aliases

**Files:** `crates/customer-config/src/lib.rs` plus repo-wide sweep.

- Remove `EnvAlias::legacy` and its conflict handling; collapse each alias pair
  to a single `MASKURA_*` name. `resolve` becomes a single-name read.
- Sweep every `S4_*` reference that was a customer-settings alias (code, tests,
  docs, `README.md`, `restart-dev.sh`, `justfile`, `local/docker-compose.yml`,
  `s4ctl`, examples) and remove/rename. Operator-only `S4_*` names stay.

**Verify:** `rg -n "S4_[A-Z]"` returns only operator-only names
(`S4_SECRET_KEK`, `S4_SERVICE_BUCKETS`, `S4_SIGV4_*`, `S4_MANAGED_*`,
`S4_MULTIPART_STAGING_*`, `S4_PRESIGNED_HTTP_*`, `S4_WORKSPACE_ENDPOINT_*`) and
no customer-setting aliases; `just check` green.

### 3. Thread `config: &Config` through `build_state`

**Files:** `crates/gateway/src/server.rs`.

- Change `build_state` and `build_state_with_pipeline_template` to accept
  `config: &Config`; replace the non-secret `std::env::var` reads and helper
  `*_from_env` functions with `config` field reads.
- Keep secret reads (`DATABASE_URL`, `S3_*` creds, `SUPABASE_JWT_SECRET`) in
  place.
- Re-key `validate_storage_boundary_startup`, `validate_multipart_startup`, and
  `validate_mode` onto `config` values.

**Verify:** existing gateway tests pass via config fixtures; the env-override
layer keeps env-driven tests green.

### 4. Wire the OSS binary + `maskura config --check`

**Files:** `crates/gateway/src/main.rs`, `crates/s4ctl/src/main.rs`.

- Gateway: resolve config (default `./maskura.toml`, `--config`/`MASKURA_CONFIG`
  override), then call `build_state(…, &config)`.
- `s4ctl`: add `config --check [--config <path>]` that loads and validates a file
  (defaults, file, env override, secret rejection) and prints a pass/fail report
  without booting.

**Verify:** boot with no file (today's behaviour) and with a file (file values
take effect, env overrides them); `maskura config --check` reports errors for an
invalid file and exit 0 for a valid one.

### 5. Private extension (in `s4-private`)

**Files:** `s4-private/crates/s4-control/src/config.rs`, `main.rs`.

- Add `PrivateConfig { #[serde(flatten)] base: Config, …SaaS fields… }` covering
  the private env surface (Paddle, Vault/KMS, filter artifacts, hosted
  pipelines, custom-upload scope, …).
- Resolve `./maskura-control.toml` → `PrivateConfig`; pass `&config.base` into
  `build_state` and use the SaaS fields for control-plane/KMS wiring.

**Verify:** private boot with `maskura-control.toml`; secrets still env-only.

### 6. Documentation + ADR

**Files:** new `docs/reference/configuration.md` (or extend `docs/security.md`),
`AGENTS.md`, and a new `docs/adr/0012-*.md`.

- Document the config file schema, env override table, secret boundary, and
  discovery rules.
- ADR records the lasting choice (config file as canonical non-secret source,
  env override, secrets env-only, two-repo schema inheritance).

**Verify:** `just check` green; docs reference the real default paths.

## Verification Gates

- `just check` passes (`-D warnings`).
- No file present → gateway behaviour identical to today (env/defaults).
- `./maskura.toml` supplies non-secret values; a documented env var overrides a
  file value; precedence default < file < env holds under test.
- A secret key in the TOML fails startup (structural rejection).
- An invalid value (e.g. unknown `multipart_mode`) fails startup.
- No customer-setting `S4_*` alias remains in the repo (sweep is exhaustive).
- `maskura config --check` exits 0 on a valid file and non-zero on an invalid one.
- Private binary boots from `maskura-control.toml` with `base` fields honoured.

## Success Criteria

- Basic local operation needs at most `auth.disabled = true` + storage endpoint
  + credentials in the file (or their env equivalents); every feature gate and
  limit has a safe default that needs no user action.
- One reference doc lists every setting, its default, its file key, and its env
  override name.
- Secrets are impossible to put in the config file.
- The `S4_*` customer-setting alias layer is fully removed; only operator-only
  `S4_*` names remain.

## Open Decisions

- Whether the `x-s4-*` HTTP header aliases are also abandoned in the same sweep
  or deferred to a separate change (they are headers, not env vars, and were
  not part of this survey).
- Whether `maskura config --check` also validates the private
  `maskura-control.toml` schema (requires the private crate to expose its schema
  to `s4ctl`, likely out of scope for the OSS binary).
