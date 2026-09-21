# Signed TOML pipeline configuration (design)

Status: draft (design)
Scope: public OSS gateway (`maskura`), private SaaS UI/control (`s4-private`)
Repositories: public `231self/maskura` (schema, resolver, CLI), private `s4-private`
(editor/export)
Related: [ADR-0003 canonical policy manifests](../adr/0003-canonical-policy-manifests.md),
[plugins.md](../plugins.md), `docs/plans/2026-09-08-config-file-and-env-override.md`

## Objective

Give OSS/self-hosted Maskura a declarative, user-authorable source of truth for
its WASM processing chains — a signed TOML file — and make that same schema the
portable representation the hosted dashboard produces. The file is
**hierarchical**: each scope (default, bucket, workspace, workspace+bucket)
carries a dedicated, ordered **write** chain and a dedicated, ordered **read**
chain. The gateway consumes the file through the existing `PipelineResolver`
seam; no read/write handler changes.

## Context

Plugin selection is currently two layers:

- **Catalog** — `PluginRegistry` (`crates/gateway/src/plugin_registry.rs`) holds
  imported components, a global `order`, and per-plugin `enabled`. The OSS
  resolver (`StaticPipelineResolver`) returns all enabled plugins in order and
  ignores workspace/bucket (`crates/gateway/src/pipeline.rs:185-236`).
- **Resolution seam** — `PipelineResolver::resolve(workspace_id, bucket,
  direction)` freezes an immutable `PipelineResolution` after auth, before the
  body is read (`pipeline.rs:65-79`, `:163-171`). Hosted injects
  `RelationalPipelineResolver` from Postgres
  (`s4-private/crates/s4-control/src/filter_runtime.rs:68-135`).

There is no declarative, file-based, per-workspace/bucket chain definition in
OSS. `maskura-customer-config` already parses TOML but is not wired into the
gateway runtime, and the signed `PolicyManifest` (ADR-0003) models routes and an
ordered filter list but is unused by the data plane.

## Decisions

1. **The signed TOML is the OSS source of truth.** When a pipeline file is
   present it defines the effective chains and replaces the catalog-order
   behavior. With no file, the gateway keeps `StaticPipelineResolver`.
2. **Same schema is the portable export.** The private dashboard authors the
   identical file; the private `PrivateConfig` may later `#[serde(flatten)]`
   SaaS-only fields without breaking OSS parsing.
3. **New dedicated crate `maskura-pipeline-config`** owns the schema, parse,
   validate, canonical encoding, signing/verification, and selection. A thin
   resolver adapter lives in the gateway.
4. **Selection is direction + workspace + bucket, expressed hierarchically.**
   Scopes are `default`, `buckets.<bucket>`, `workspaces.<id>`, and
   `workspaces.<id>.buckets.<bucket>`. Precedence is
   `workspace+bucket > workspace > bucket > default`. No prefix or content-type
   routing in v1; that would require extending the resolver input and is
   deferred.
5. **Write and read chains are first-class and independent.** Each scope has its
   own `write` and `read` chains; there are no named pipelines and no assignment
   table. Step order is the TOML array order.
6. **Fail closed.** A missing chain at every applicable scope, unknown plugin,
   source or version mismatch, unsupported world or grant, an empty chain
   without `explicit_passthrough`, unknown keys, and bad signatures are all load
   or selection errors. Step configuration is allowed when the selected WIT
   world exposes `config-json`; the current transformer v0.1 world does.
7. **Ed25519 over canonical CBOR, reusing ADR-0003.** The parsed, validated
   model (minus the `signature` field) is canonical-CBOR encoded with sorted map
   keys and signed. TOML whitespace and comments are not part of the signed
   body. Trust roots are keyed by `signer_id`; failure to verify is a hard
   startup error.
8. **No change to `PipelineResolver`.** The resolver still receives
   `(workspace_id, bucket, direction)`; it performs selection internally.
9. **Immutability is inherited.** The file's canonical digest is the
   `PipelineLocator.revision`; the ordered steps produce the fingerprint via the
   existing `resolution_fingerprint`. Multipart persistence, fingerprint
   verification, and metering work unchanged through `snapshot_for`.
10. **Plugin identity is `(source, name, version)`.** A step references a
    component with a qualified string `<source-uri>:<name>:<version>`, for
    example `https://github.com/231self/maskura/plugins:pii-default:0.x.y`.
    Local directories use a canonical absolute `file:///` URI, for example
    `file:///srv/maskura/plugins:plugin_name:0.2.0`. The source URI is the namespace
    that makes names globally meaningful; the digest in the resolved
    `PipelineStep` remains authoritative. An omitted version means the latest
    available.
11. **The name→entry index is a gateway-side adapter.** `PluginRegistry` is not
    changed by this feature; a `PluginRegistryCatalog` implements the catalog
    trait over it.
12. **Unsigned files are a logged hack.** `MASKURA_PIPELINE_ALLOW_UNSIGNED=1`
    is allowed without a loopback restriction, but startup logs a prominent
    warning on every boot and the revision is labeled `unsigned-dev`.

## User-facing configuration

The on-disk file is self-contained and signed. It is the only artifact users
edit or the dashboard exports.

### Minimal

```toml
schema_version = 1
signer_id      = "acme-prod"
signature      = "Xzo..."                  # standard Base64 Ed25519 signature

[write]
[[write.steps]]
plugin = "pii-default"

[[write.steps]]
plugin = "envelope-encrypt"
grant  = ["public_key_pem"]                # sensitive context is deny-by-default

[read]
[[read.steps]]
plugin = "envelope-decrypt"
```

### Full-featured

```toml
schema_version = 1
signer_id      = "acme-prod"
signature      = "Xzo..."

# ---- Default chains ----
[write]
description = "applied to every PUT"

[[write.steps]]
# qualified reference: <source-uri>:<name>:<version-requirement>
plugin = "https://github.com/231self/maskura/plugins:stable-encrypt:1.2.0"
grant  = ["stable_key", "stable_fields"]

[write.steps.config]                       # worlds exposing config-json
mode = "hash"

[[write.steps]]
plugin = "pii-default"                     # unqualified => local file:// namespace, latest

[[write.steps]]
plugin = "file:///srv/maskura/plugins:custom-redactor:0.2.0"

[read]
description = "applied to processed GET (x-maskura-process: read)"

[[read.steps]]
plugin = "envelope-decrypt"
grant  = ["public_key_pem"]

# ---- Workspace override: replaces that workspace's default for a direction ----
[workspaces."0f8fad5b-d9cb-469f-a165-70867728950e".write]
[[workspaces."0f8fad5b-d9cb-469f-a165-70867728950e".write.steps]]
plugin = "strict-redactor"

[workspaces."0f8fad5b-d9cb-469f-a165-70867728950e".read]
[[workspaces."0f8fad5b-d9cb-469f-a165-70867728950e".read.steps]]
plugin = "envelope-decrypt"

# ---- Bucket override nested under a workspace ----
[workspaces."0f8fad5b-d9cb-469f-a165-70867728950e".buckets."tenant-a".write]
[[workspaces."0f8fad5b-d9cb-469f-a165-70867728950e".buckets."tenant-a".write.steps]]
plugin = "tenant-redactor"

# ---- Bucket override for any workspace: explicit identity chain ----
[buckets."raw-events".write]
explicit_passthrough = true                # legal empty chain
```

### Selection precedence

For a request `(workspace_id, bucket, direction)`:

1. `workspaces.<id>.buckets.<bucket>.<direction>`
2. `workspaces.<id>.<direction>`
3. `buckets.<bucket>.<direction>`
4. `<direction>` (default)

The first scope that defines the requested direction wins; deeper (more
specific) scopes do not "merge" with shallower ones — a chain replaces, it does
not extend. If no applicable scope defines the direction, selection fails
closed. A present chain with zero steps requires `explicit_passthrough = true`.

## Schema (Rust)

New crate `maskura-pipeline-config`:

```rust
pub struct PipelineFile {
    pub schema_version: u32,
    pub signer_id: String,
    pub signature: Option<String>,                 // base64 Ed25519, not in signed body
    pub not_before: Option<u64>,
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub write: Option<DirectionPipeline>,          // default scope
    #[serde(default)]
    pub read: Option<DirectionPipeline>,           // default scope
    #[serde(default)]
    pub buckets: BTreeMap<String, ScopeOverride>,  // bucket-only scopes
    #[serde(default)]
    pub workspaces: BTreeMap<String, WorkspaceScope>,
}

pub struct WorkspaceScope {
    #[serde(default)]
    pub write: Option<DirectionPipeline>,
    #[serde(default)]
    pub read: Option<DirectionPipeline>,
    #[serde(default)]
    pub buckets: BTreeMap<String, ScopeOverride>,
}

/// A non-workspace scope: direction chains only.
pub struct ScopeOverride {
    #[serde(default)]
    pub write: Option<DirectionPipeline>,
    #[serde(default)]
    pub read: Option<DirectionPipeline>,
}

pub struct DirectionPipeline {
    pub description: Option<String>,
    #[serde(default)]
    pub explicit_passthrough: bool,                // must be true if steps is empty
    pub steps: Vec<StepDef>,
}

pub struct StepDef {
    pub plugin: PluginRef,                         // qualified ref, see "Plugin reference grammar"
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    pub config: Option<toml::Value>,               // world must expose config-json
    #[serde(default)]
    pub grant: Vec<String>,                        // public_key_pem|entropy_seed|stable_key|stable_fields
}

/// `<source-uri>:<name>:<version>`; the source may itself contain colons.
pub struct PluginRef {
    pub source: Option<String>,                    // None => unqualified; local file:// namespace
    pub name: String,                              // plugin name, or 64-hex digest
    pub version: Option<String>,                   // exact version or semver requirement; None => latest
}
```

Supporting types:

- `PipelineFile::from_toml_str` / `from_file` with `deny_unknown_fields`.
- `PipelineFile::validate(&self) -> Result<(), ConfigError>` covering every rule
  in "Failure rules" below.
- `PipelineFile::canonical_body(&self) -> Result<Vec<u8>, ConfigError>` — clone with `signature`
  cleared, canonical-CBOR encode (sorted keys, reusing the `maskura-policy`
  encoder).
- `PipelineFile::sign(&mut self, &SigningKey) -> Result<(), ConfigError>`.
- `PipelineFile::verify(&self, trust_roots: &BTreeMap<String, VerifyingKey>)`.
- `PipelineFile::revision(&self) -> Result<String, ConfigError>` — `hex(sha256(canonical_body))`.
- `PipelineFile::select(&self, workspace_id, bucket, direction) -> Result<&DirectionPipeline, ConfigError>`.
- `PipelineCatalog` trait — `lookup(&self, &PluginRef) -> Result<CatalogEntry, ConfigError>`
  with `{ source, name, version, component_hash, capabilities, world_version }`.
- `CatalogEntry::to_pipeline_step(&self, &StepDef) -> Result<PipelineStep, ConfigError>`.
- `PluginRef::parse(&str)` / `Display` — canonical round-trip so refs are
  fingerprint-stable.

### Plugin reference grammar

```
ref     = [ source ":" ] name [ ":" version ]
source  = absolute-uri            ; https:// or file://, may itself contain ":"
name    = 1*( ALPHA / DIGIT / "-" / "_" ) | 64-hex-digest
version = semver-requirement      ; any semver form; omitted = latest
```

- A qualified ref is `<source-uri>:<name>[:<version>]`; an unqualified ref is
  `name[:version]`. The source is always a URI — local directories use their
  canonical absolute `file:///` URI without a host.
- Parsing: the final colon-separated segment is the version iff it parses as a
  semver requirement; otherwise it is the name. The remainder before the name is
  the source URI. This keeps `https://host:8443/path:pii-default` (no version,
  URI containing a colon) unambiguous.
- Version requirements accept the full range of semver forms: exact (`1.2.0`),
  wildcards (`1.x`, `*`), tilde (`~1.2.0`), caret (`^1.2.0`), and comparators
  (`>=1.2.0`, `<2.0.0` / comma-AND). The highest matching version wins.
- `version` omitted means **latest** — the highest version available under that
  source. An exact version is reproducible only when that source preserves
  version immutability; use a 64-hex digest as the plugin name to
  cryptographically pin local bytes across restarts. The resolved digest — not
  the requirement — enters the fingerprint, so each execution is pinned.

The gateway provides a `PluginRegistryCatalog` adapter over `PluginRegistry`.
The adapter indexes entries by `(source, name, version)` (including disabled
entries, since the file — not the catalog — decides enabled state) and leaves
the registry itself unchanged. Directory auto-load and `MASKURA_FILTER_COMPONENT`
imports register under a `file://` source URI for their directory.

## Resolver adapter

```rust
pub struct SignedTomlPipelineResolver {
    file: PipelineFile,                        // verified at construction
    revision: String,
    catalog: Arc<dyn PipelineCatalog>,
    limits: PipelineLimits,
}

#[async_trait]
impl PipelineResolver for SignedTomlPipelineResolver {
    async fn resolve(
        &self,
        workspace_id: &str,
        bucket: &str,
        direction: PipelineDirection,
    ) -> Result<PipelineResolution, S4Error> {
        let pipeline = self.file.select(workspace_id, bucket, direction)?;
        let mut steps = Vec::with_capacity(pipeline.steps.len());
        for step in &pipeline.steps {
            steps.push(self.catalog.lookup(&step.plugin)?.to_pipeline_step(step)?);
        }
        let fingerprint = resolution_fingerprint(
            direction, &steps, pipeline.explicit_passthrough, self.limits);
        Ok(PipelineResolution {
            locator: PipelineLocator {
                revision: self.revision.clone(),
                fingerprint,
            },
            steps,
            policy_generation: None,
            explicit_passthrough: pipeline.explicit_passthrough,
            limits: self.limits,
        })
    }
}
```

Wiring at startup:

1. Read the path (`[wasm] pipelines_file` in the layered config, or
   `MASKURA_PIPELINES_FILE`).
2. `PipelineFile::from_file`, `validate`, `verify(trust_roots)`.
3. Build `SignedTomlPipelineResolver` and call
   `Gateway::with_resolver(resolver, component_source)`.
4. If no path is configured, keep `StaticPipelineResolver`.

Startup fails hard if the file is absent-when-configured, malformed, unsigned
without the dev escape hatch, or fails verification.

## Signing and trust

- **Body:** canonical CBOR of the parsed model with `signature` removed and
  sorted keys. Reuses the exact construction in `maskura-policy` (ADR-0003).
- **Envelope:** `signer_id` (in the signed body) + `signature` (base64 Ed25519,
  excluded). Embedded rather than a sidecar so the file is self-contained.
- **Verification:** look up the `signer_id` in the trust-root map; reject
  unknown signers and bad signatures. Optional `not_before` / `expires_at` are
  checked when present.
- **Trust roots:** configured as
  `[[pipeline_trust.roots]] signer_id = "..." public_key = "..."` in the layered
  config, or the operator env equivalent.
- **Unsigned hack (logged at boot):** `MASKURA_PIPELINE_ALLOW_UNSIGNED=1`
  accepts an unsigned file and labels the revision `unsigned-dev`. It is allowed
  without a loopback restriction, but every boot logs a prominent warning naming
  the file and stating that policy is unverified. Default is fail closed.
- **CLI (`maskura`):** `pipelines init-key`, `pipelines sign`, `pipelines verify`,
  `pipelines check`.

## Failure rules (hard load errors)

- Unknown keys (`deny_unknown_fields`) or malformed TOML.
- Malformed plugin reference, or an unknown source URI.
- A plugin name that does not exist under its source.
- A version requirement that matches no available version.
- A digest reference not present in the component source.
- Unsupported `grant` name.
- `config` present when the selected world does not expose `config-json`.
- A scope chain with empty `steps` and no `explicit_passthrough = true`.
- `signature` present but `signer_id` absent.
- Missing, malformed, or unverifiable signature (unless the dev escape hatch is
  set).

`select` additionally fails closed when no applicable scope defines the
requested direction.

## Testing

- **Schema:** parse, defaults, `deny_unknown_fields`, empty-chain rejection,
  passthrough acceptance, and world/config compatibility.
- **Plugin refs:** parse/Display round-trip for qualified, name-only, digest, and
  versioned forms; `file://` sources; omitted version resolving to latest;
  port-bearing source URIs without a version; no-match rejection; semver forms
  (`^`, `~`, `*`, comparators) selecting the highest match.
- **Selection:** precedence matrix across `{workspace+bucket, workspace, bucket,
  default}`, deeper-replaces-not-merges behavior, and fail-closed on an
  unassigned direction.
- **Signing:** sign/verify round-trip, tamper, wrong key, unknown signer,
  expiry, `signature` excluded from the body digest (whitespace/comment edits do
  not change the revision).
- **Resolver:** emitted `PipelineResolution` passes `verify_fingerprint`,
  carries exact `SensitiveGrant`s, and rejects catalog/digest/version mismatches.
- **End-to-end:** PUT and `x-maskura-process: read` through `snapshot_for` with a
  file-backed resolver; multipart freeze/restore round-trip.
- **Cross-repo:** a private-export fixture parses and resolves identically in
  OSS.

## Verification gates

- `just check` green (`-D warnings`).
- No pipeline file configured → behavior identical to today.
- A signed file loads and its assigned chain runs on PUT and transformed GET.
- Editing a comment/whitespace does not invalidate the signature or change the
  revision; editing a semantic value does.
- An unsigned file fails startup unless the dev escape hatch is set.
- Every failure rule above is covered by a test asserting the specific error.
- A private-export fixture round-trips through the OSS schema.

## Success criteria

- Self-hosted users define and sign hierarchical read/write processing chains in
  one TOML file; no code or gateway rebuild is needed to change them.
- The dashboard can export the same file for a hosted workspace, and it loads
  unchanged in OSS.
- Sensitive context is deny-by-default and grantable only per step.
- Component references are content-addressed and digest-verified at snapshot
  build.

## Non-goals (deferred)

- Prefix and content-type routing (requires extending the resolver input).
- Hot reload (v1 is startup-only).
- Replacing the hosted Postgres source of truth (the DB stays authoritative; the
  TOML is an export).
- Fetching component bytes from remote registries.
- Replacing catalog-order behavior when no file is configured.
- Applying byte-oriented transformer chains to typed binary formats such as
  Avro; those use the schema-aware binary adapter pipeline.

## Implementation order (for the follow-on plan)

1. `maskura-pipeline-config`: schema, `PluginRef` grammar, parse, validate,
   canonical body, sign/verify.
2. Hierarchical selection + `PipelineCatalog` trait and unit tests.
3. Gateway `PluginRegistryCatalog` `(source, name, version)` adapter and
   `SignedTomlPipelineResolver`.
4. Startup wiring + layered-config/env path, trust roots, and the logged unsigned
   hack.
5. `maskura pipelines` CLI.
6. `docs/reference/configuration.md` + ADR recording the lasting choice.
7. Private export fixture (in `s4-private`).
