# ADR 0016: Maskura plugin contract and namespace

- Status: Accepted
- Date: 2026-09-10

## Context

The original Component Model contract and several product surfaces retained
the project’s pre-Maskura name. The host supported two versions of a
filter-specific world, every plugin generated its own Rust bindings from a
relative WIT path, and official components lived in one flat `filters/`
directory. That made the contract easy to drift and incorrectly suggested that
plugins were limited to PII filtering and encryption.

There are no external Maskura plugin users yet. Carrying aliases now would make
the old namespace a permanent compatibility and security-review burden without
protecting a real deployment. A separate community-plugin repository would add
governance and release machinery before contributor volume requires it.

## Decision

The public Maskura repository owns one canonical WIT package,
`maskura:plugin@0.1.0`, in `crates/plugin-sdk/wit/world.wit`.

The primary `transformer` world preserves the established streaming lifecycle:
`begin`, `transform`, and `finish`. A plugin’s purpose is not encoded in a new
world. Filters, cryptographic protections, validation, normalization, and
future transformations share the transformer contract. Schema-aware binary
adapters use the `binary-reductor` world in the same package.

`maskura-plugin-sdk` is a thin Rust authoring crate. It contains generated WIT
types, the `Guest` trait, and the `export_plugin!` macro; it contains no gateway
policy, storage, transport, or product logic. The host runtime binds directly
to the WIT shipped by that crate. Raw WIT remains available to every other
Component Model language toolchain.

Official components live under capability-oriented paths:

```text
plugins/filters/<name>
plugins/crypto/<name>
plugins/transforms/<name>
plugins/shared/<internal-library>
```

Loadable components declare stable identity and lifecycle metadata in
`plugin.toml`. `official` and `experimental` are maintenance states, not
sandbox trust levels. New category directories appear only with a real plugin.

The 0.7 release is a clean namespace cut. Active crates, binaries, environment
variables, headers, credentials, MCP tools and tokens, SDK imports, local state,
release assets, container images, internal metadata, and cryptographic domain
separators use Maskura names. The host does not load the old WIT packages, and
the SDKs do not export old client aliases. The private hosted deployment is a
coordinated consumer of the new contract and must update before rollout.

A separate community-plugin repository is deferred until outside contribution
volume creates a concrete ownership, moderation, or release-cadence need.

## Consequences

- Plugin authors have one discoverable contract and one Rust dependency.
- The gateway and its hosted deployment cannot silently disagree about the WIT
  shape; consumer checks compile and load the same canonical component.
- Plugin categories can grow beyond PII without multiplying ABIs.
- 0.7 intentionally invalidates pre-release components, credentials, local
  state paths, and deployment configuration that use the old namespace.
- Operators must update public and private configuration atomically during the
  0.7 rollout. There is no fallback alias.
- Future ABI changes require a new WIT package version and an ADR; an existing
  published contract is never edited in place after external adoption.
- A future community repository can depend on the same SDK without moving or
  forking interface ownership.
