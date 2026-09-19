# Configuration reference

Maskura accepts non-secret gateway settings in TOML. The schema is strict:
unknown tables or keys, malformed values, and invalid combinations stop startup.
Credentials, tokens, and the service-storage backend list are environment-only
and are rejected if placed in TOML.

## Loading and validation

The gateway discovers one configuration file in this order:

1. `maskura-gateway --config <path>`
2. `MASKURA_CONFIG=<path>`
3. `./maskura.toml`, if it exists
4. No file

If a file selected with `--config` or `MASKURA_CONFIG` does not exist, Maskura
reports an error. Without a file, Maskura uses its built-in defaults and any
environment variables. Settings are applied in this order:

```text
compiled defaults < TOML file < environment overrides
```

Validate the same configuration without starting the gateway:

```bash
maskura config --check
maskura config --check --config /etc/maskura/maskura.toml
```

The command finds and validates the file in the same way as the gateway. It also
applies non-secret environment overrides and checks settings that depend on one
another. It exits with a non-zero status if the selected file is missing or the
configuration is invalid. Credentials and other environment-only values, such
as `MASKURA_SERVICE_BUCKETS`, are checked when the gateway starts. Run the check
with the same environment you plan to use for the gateway.

TOML booleans are `true` or `false`. Boolean environment overrides accept
`true`/`false` or `1`/`0`. Byte values are unsigned integers. List overrides are
comma-separated; surrounding whitespace and empty entries are removed.

## TOML schema

Every table and field is optional. "Unset" below means that no value is supplied
by the configuration file or environment; the gateway may still apply the
default described in the table.

### Server and authentication

| TOML key | Environment override | Default and behavior |
|---|---|---|
| `server.listen_addr` | `LISTEN_ADDR` | Unset. Listens on `0.0.0.0:9000` in automatic local-appliance mode and `0.0.0.0:8080` otherwise. Must be a socket address. |
| `auth.disabled` | `AUTH_DISABLED` | `false`. Bypasses authentication and implies explicit single-tenant mode; use only for local development. |

### Storage and Supabase

| TOML key | Environment override | Default and behavior |
|---|---|---|
| `storage.mode` | `MASKURA_STORAGE_MODE` | Unset; the only accepted configured value is `local`. Mutually exclusive with `storage.s3_endpoint`. |
| `storage.s3_endpoint` | `S3_ENDPOINT` | Unset. HTTP(S) URL for process-global S3-compatible storage; allowed only in explicit single-tenant mode. Credentials remain environment-only. |
| `storage.s3_region` | `S3_REGION`, then `AWS_REGION`, then `AWS_DEFAULT_REGION` | Unset; effective S3 client region is `us-east-1`. The first non-empty override wins. |
| `storage.single_tenant` | `MASKURA_SINGLE_TENANT` | `false`. Enables global or local storage for a single-tenant deployment. |
| `storage.local_dir` | `MASKURA_LOCAL_STORAGE_DIR` | Unset. Selects local storage at this path and requires single-tenant mode. `storage.mode = "local"` without a path uses `./data`; automatic local-appliance mode uses `/data`. Local storage is mutually exclusive with global S3 and service storage. |
| `supabase.url` | `SUPABASE_URL` | Unset; effective local default is `http://127.0.0.1:54321`. |

If you do not configure service buckets, a database, a global S3 endpoint, or
local storage, Maskura starts as a local appliance. It stores data in `/data`,
enables staged multipart uploads, saves local credentials, listens on port 9000,
and leaves plugins disabled. Settings for multipart uploads, streaming reads,
and filter components replace these defaults when provided.

### Features

| TOML key | Environment override | Default and behavior |
|---|---|---|
| `features.multipart_mode` | `MASKURA_MULTIPART_MODE` | `reject`; accepted values are `reject` and `staged`. Local staged mode uses the local root. Hosted staged mode requires the complete staging configuration and env-only dependencies. |
| `features.streaming_read_mode` | `MASKURA_STREAMING_READ_MODE` | `off`; accepted values are `off`, `passthrough`, and `transformed`. `transformed` also requires `transformed_read_spool = true`. |
| `features.transformed_read_spool` | `MASKURA_TRANSFORMED_READ_SPOOL` | `false`. The environment value enables it only when equal to `encrypted` (case-insensitive). Required for transformed reads with any component not declared prefix-safe. |
| `features.enable_avro` | `MASKURA_ENABLE_AVRO` | `false`. Enables Avro processing. |
| `features.streaming_s3_provider` | `MASKURA_STREAMING_S3_PROVIDER` | Unset; accepted values are `aws`, `minio`, `r2`, and `b2`. Required so Maskura can verify support for direct streaming to global S3. |
| `features.dev_memory_streaming` | `MASKURA_DEV_MEMORY_STREAMING` | `false`. Enables the development in-memory streaming path outside explicit single-tenant mode. |
| `features.managed_streaming_mode` | `MASKURA_MANAGED_STREAMING_MODE` | `off`; accepted values are `off`, `observe`, and `enforce`. `observe`/`enforce` require transactional mode and durable hosted dependencies. |
| `features.managed_streaming_transactional` | `MASKURA_MANAGED_STREAMING_TRANSACTIONAL` | `false`. Declares that the managed backend supports the required transactions. |

### Wasm pipeline

| TOML key | Environment override | Default and behavior |
|---|---|---|
| `wasm.filter_component` | `MASKURA_DEFAULT_PLUGIN` | Unset; uses the bundled/default `pii-default` component path. Automatic local-appliance mode starts with all plugins disabled unless this field is explicitly configured. |
| `wasm.plugins_dir` | `MASKURA_PLUGINS_DIR` | Unset. Existing components in this directory are loaded at startup. |
| `wasm.fuel` | `MASKURA_WASM_FUEL` | `1,000,000,000` instructions per pipeline session; must be greater than zero. |
| `wasm.prefix_safe_component_hashes` | `MASKURA_PREFIX_SAFE_COMPONENT_HASHES` | Empty list. Each entry must be a 64-character hexadecimal SHA-256 digest. Maskura trusts the declaration only for that exact component and does not allow it to change while running. |

### Limits and spool

| TOML key | Environment override | Default and behavior |
|---|---|---|
| `limits.source_max_frame_bytes` | `MASKURA_SOURCE_MAX_FRAME_BYTES` | 8 MiB; must be positive and fit the platform `usize`. |
| `limits.max_object_bytes` | `MASKURA_MAX_OBJECT_BYTES` | 5 GiB. Positive values may lower but cannot raise the 5 GiB hard limit for source data. |
| `limits.max_pipeline_output_bytes` | `MASKURA_MAX_PIPELINE_OUTPUT_BYTES` | 5 GiB. Positive values may lower but cannot raise the 5 GiB hard limit for pipeline output. |
| `limits.legacy_max_object_bytes` | `MASKURA_LEGACY_MAX_OBJECT_BYTES` | 16 MiB. Positive values may lower but cannot raise the 16 MiB hard limit for the legacy path. |
| `limits.dev_memory_max_object_bytes` | `MASKURA_DEV_MEMORY_MAX_OBJECT_BYTES` | 16 MiB. Positive values may lower it or raise it to at most 64 MiB. |
| `spool.dir` | `MASKURA_SPOOL_DIR` | The OS temporary directory plus `maskura-spool`. |
| `spool.max_object_bytes` | `MASKURA_SPOOL_MAX_OBJECT_BYTES` | Effective object limit; cannot exceed `limits.max_object_bytes`. |
| `spool.quota_bytes` | `MASKURA_SPOOL_QUOTA_BYTES` | Twice the effective spool object limit. Must be positive and at least `spool.max_object_bytes`. |

The pipeline also has fixed limits: at most 16 plugins, 16 MiB intermediate
records, 8 MiB of plugin-finish output, 32x expansion plus 1 MiB of slack, and a
five-minute processing time.

### Keys and managed placement

| TOML key | Environment override | Default and behavior |
|---|---|---|
| `keys.keys_file` | `MASKURA_KEYS_FILE` | Unset. Selects a JSON key store when local storage or Postgres does not take precedence. Local storage defaults to `.maskura/keys.json` beneath its root. |
| `keys.bootstrap_key` | `MASKURA_BOOTSTRAP_KEY` | Unset. Non-secret bootstrap access-key ID; must be paired with env-only `MASKURA_BOOTSTRAP_SECRET`. |
| `managed.placement_version` | `MASKURA_MANAGED_PLACEMENT_VERSION` | `1`; must be greater than zero. Bump it when changing a durable managed placement policy. |

### Multipart staging

| TOML key | Environment override | Default and behavior |
|---|---|---|
| `multipart_staging.endpoint` | `MASKURA_MULTIPART_STAGING_ENDPOINT` | Unset. HTTP(S) URL for the hosted staging object store. |
| `multipart_staging.bucket` | `MASKURA_MULTIPART_STAGING_BUCKET` | Unset; must not be empty. |
| `multipart_staging.region` | `MASKURA_MULTIPART_STAGING_REGION` | Unset; must not be empty. |
| `multipart_staging.dir` | `MASKURA_MULTIPART_STAGING_DIR` | Unset; must not be empty. Temporary hosted staging directory. |
| `multipart_staging.tenant_quota_bytes` | `MASKURA_MULTIPART_STAGING_TENANT_QUOTA_BYTES` | In local mode, 16 times the effective object limit. Hosted staged mode requires an explicit value. Must be positive and no greater than the global quota. |
| `multipart_staging.global_quota_bytes` | `MASKURA_MULTIPART_STAGING_GLOBAL_QUOTA_BYTES` | In local mode, four times the tenant quota. Hosted staged mode requires an explicit value. Must be positive. |

Hosted staged mode additionally requires `DATABASE_URL`, durable key wrapping,
and the env-only staging access-key pair. Local staged mode derives all durable
state from the local storage root.

### SigV4 and outbound allowlists

| TOML key | Environment override | Default and behavior |
|---|---|---|
| `sigv4.region` | `MASKURA_SIGV4_REGION` | `us-east-1`; expected SigV4 credential-scope region. |
| `sigv4.trusted_tls` | `MASKURA_SIGV4_TRUSTED_TLS` | `false`. Set only when a trusted proxy terminates TLS before the gateway. |
| `allowlists.workspace_endpoint` | `MASKURA_WORKSPACE_ENDPOINT_ALLOWLIST` | Empty. Hosts or `*.suffix` entries trusted for multi-tenant persisted workspace endpoints. |
| `allowlists.workspace_endpoint_private` | `MASKURA_WORKSPACE_ENDPOINT_PRIVATE_ALLOWLIST` | Empty. Exact private hosts; valid only in explicit single-tenant mode. |
| `allowlists.presigned_http` | `MASKURA_PRESIGNED_HTTP_ALLOWLIST` | Empty. Hosts or `*.suffix` entries allowed for presigned HTTP(S) sources. |
| `allowlists.presigned_http_private` | `MASKURA_PRESIGNED_HTTP_PRIVATE_ALLOWLIST` | Empty. Exact hosts allowed to resolve to private addresses. |
| `allowlists.presigned_http_allow_http` | `MASKURA_PRESIGNED_HTTP_ALLOW_HTTP` | `false`. Permits HTTP only for presigned source `GET`; destinations remain HTTPS-only. |
| `allowlists.presigned_http_min_validity_secs` | `MASKURA_PRESIGNED_HTTP_MIN_VALIDITY_SECS` | 30 seconds; must be greater than zero. |

Allowlist entries are hostnames, IP literals, or `*.suffix` patterns as
applicable, never URLs. More restrictive runtime DNS and public/private address
checks still apply; see [Security](../security.md#10-outbound-requests--ssrf-dns-redirect-expiry-address-pinning).

## Observability

Telemetry is environment-only and disabled unless an OTLP endpoint is
configured. Collector vendor, production endpoint, and credentials are an
operations decision; see [ADR 0020](../adr/0020-safe-opentelemetry-observability.md).

### Local logging

| Environment variable | Default and behavior |
|---|---|
| `MASKURA_LOG_FORMAT` | `text` or `json`; default `text`. |
| `MASKURA_LOG_LEVEL` | `error`, `warn`, `info`, or `debug`; default `info`. Applies only to Maskura-owned targets. Dependency targets stay capped at WARN; OpenTelemetry and HTTP-client targets are never written locally. |

### OTLP export

| Environment variable | Default and behavior |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Base endpoint; enables traces, logs, and metrics when set. Signal-specific endpoints override it. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`, `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | Per-signal endpoints; enable only that signal. |
| `OTEL_TRACES_EXPORTER`, `OTEL_LOGS_EXPORTER`, `OTEL_METRICS_EXPORTER` | `otlp` or `none` only; `none` disables one signal. |
| `OTEL_EXPORTER_OTLP_PROTOCOL` (and per-signal variants) | `http/protobuf` only; any other value fails startup. |
| `OTEL_EXPORTER_OTLP_INSECURE` (and per-signal variants) | `false` by default. A plaintext `http://` endpoint requires the matching `true`; an `https://` endpoint rejects `true`. |
| `OTEL_EXPORTER_OTLP_HEADERS` (and per-signal variants) | Comma-separated `name=value` pairs, at most 32, no CR/LF. Values are never echoed in diagnostics. |
| `OTEL_EXPORTER_OTLP_TIMEOUT` (and per-signal variants) | Export timeout in milliseconds, 1–300000; default 10000. |
| `OTEL_SERVICE_NAME` | Non-empty bounded printable-ASCII service name; defaults to `maskura-gateway`. |
| `OTEL_RESOURCE_ATTRIBUTES` | Comma-separated `key=value` pairs restricted to `service.namespace`, `service.instance.id`, `deployment.environment.name`, `cloud.provider`, `cloud.region`, and `cloud.availability_zone`. Reserved or unknown keys, duplicates, and unbounded or non-printable values fail startup. |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off`, or `parentbased_traceidratio`; ratio in `(0, 1]`. Default `parentbased_traceidratio` with ratio `0.1`. |
| `OTEL_BSP_MAX_QUEUE_SIZE`, `OTEL_BSP_SCHEDULE_DELAY`, `OTEL_BSP_MAX_EXPORT_BATCH_SIZE`, `OTEL_BSP_EXPORT_TIMEOUT` | Bounded span batch queue, delay, batch size, and export timeout. Batch size cannot exceed the queue. |
| `OTEL_BLRP_MAX_QUEUE_SIZE`, `OTEL_BLRP_SCHEDULE_DELAY`, `OTEL_BLRP_MAX_EXPORT_BATCH_SIZE`, `OTEL_BLRP_EXPORT_TIMEOUT` | The same bounds for the log batch processor. |
| `OTEL_METRIC_EXPORT_INTERVAL`, `OTEL_METRIC_EXPORT_TIMEOUT` | Metric export interval (1000–3600000 ms, default 60000) and timeout (1–300000 ms, default 10000). |

Malformed explicit configuration fails startup with a fixed message that never
echoes the offending endpoint, header, or resource value. Exported attributes,
logs, and metrics are limited to the allowlist in
[Security §13.1](../security.md#131-exported-telemetry). On SIGTERM or Ctrl-C
the gateway stops accepting requests, drains in-flight connections for at most
30 seconds, then flushes providers for at most 10 seconds.

## Environment-only values

These values are deliberately absent from the TOML schema. Do not put them in
`maskura.toml`; strict parsing rejects secret-like keys rather than accepting or
ignoring them.

| Environment variable | Purpose and default/behavior |
|---|---|
| `MASKURA_CONFIG` | Selects the config file when `--config` is absent. It is not a TOML field. |
| `DATABASE_URL` | Postgres connection string for durable keys, journal, managed metadata, and hosted multipart state. Its presence also prevents automatic local-appliance mode. |
| `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | Static credentials for `S3_ENDPOINT`; `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are fallbacks. With no static pair, the AWS default credential provider chain is used. |
| `SUPABASE_JWT_SECRET` | Dashboard JWT verification secret. Unset by default. |
| `SUPABASE_ANON_KEY` | Supabase public/anonymous client key. Defaults to the local Supabase development value. |
| `MASKURA_SECRET_KEK` | Base64-encoded 32-byte local key-encryption key. Without it, non-local OSS wrapping is ephemeral; automatic local storage persists its own root wrapping key. |
| `MASKURA_SERVICE_BUCKETS` | Semicolon-separated service-storage backends. Each backend is pipe-separated as `provider|endpoint|region|bucket|access_key|secret_key`, `provider|instance|account|credential_epoch|endpoint|region|bucket|access_key|secret_key`, or the latter with `placement_weight|placement_capacity_units` inserted before `endpoint`. Multi-tenant mode requires a non-empty value. |
| `MASKURA_MULTIPART_STAGING_ACCESS_KEY_ID`, `MASKURA_MULTIPART_STAGING_SECRET_ACCESS_KEY` | Required credential pair for hosted multipart staging. |
| `MASKURA_BOOTSTRAP_SECRET` | Secret paired with `keys.bootstrap_key` / `MASKURA_BOOTSTRAP_KEY`; both must be present or absent. |
| `MASKURA_ROOT_USER`, `MASKURA_ROOT_PASSWORD` | Optional local-appliance root access key and secret; set both or neither. Otherwise Maskura generates and displays a credential once. On restart, configured values must match the saved credential or Maskura will not start. |
