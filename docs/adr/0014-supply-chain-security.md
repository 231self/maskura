# ADR 0014: Supply-chain security gates and release provenance

- Status: Accepted
- Date: 2026-09-09

## Context

Maskura processes security-sensitive object data, but its public CI previously
relied on mutable GitHub Action tags and did not make dependency policy,
RustSec advisories, CodeQL results, software bills of materials, checksums, or
build provenance part of the enforced release path. A passing compiler and test
suite do not prove which automation executed or let a consumer verify the
origin and dependency inventory of a downloaded release.

## Decision

Every external GitHub Action is referenced by a full commit SHA, with the
human-readable release line retained as a comment for update tooling and
reviewers. The aggregate `check` required on `main` includes `cargo audit`,
`cargo deny`, `pip-audit`, `npm audit`, dependency-diff review, and CodeQL
analysis of Rust, Python, JavaScript/TypeScript, and GitHub Actions workflows in
addition to the existing format, lint, test, SDK, database, interoperability,
and end-to-end jobs.

`just pre-push` is the canonical fast local gate. It runs formatting and
clippy, the same Rust, Python, and npm dependency audits, and
immutable-reference checks for workflow actions and container base images.
The protected CI remains responsible for the long Wasm, SDK, database,
interoperability, end-to-end, and full test suites. `just push` runs the local
gate before delegating publication to `jj git push`.

The RustSec audit has one narrowly guarded exception for RUSTSEC-2023-0071.
SQLx's compile-time migration macro records the vulnerable `rsa` crate through
its MySQL macro support even though Maskura enables only Postgres and the crate
is absent from every resolved workspace target. The audit script first fails if
`rsa 0.9.10` becomes reachable in any workspace target, then applies the
lockfile-only exception. This exception must be removed when SQLx no longer
records that crate.

Release jobs generate an SPDX JSON SBOM and deterministic SHA-256 checksum
manifest for downloadable files. GitHub artifact attestations bind those files
to the release workflow. The canonical and compatibility multi-architecture
container manifests are resolved to immutable digests and receive build
provenance attestations that are also published to GHCR.
Native Apple Silicon CLI and MCP binaries are built on an arm64 macOS runner,
smoke-tested there, and included in the same checksum and artifact-provenance
set as the Linux binaries. The release also includes the repository SBOM.

## Consequences

- A moved upstream Action tag cannot silently change Maskura CI or release
behavior; dependency updates require an explicit reviewed SHA change.
- Dependabot proposes grouped weekly updates for Rust, both generated SDKs,
  GitHub Actions, and container images; security updates remain enabled.
- Newly disclosed Rust, Python, or npm advisories and dependency-policy
  violations block the aggregate merge check rather than remaining a
  local-only command.
- Code scanning covers source, generated clients, and workflow code and
  publishes findings through GitHub's security surface.
- Release consumers can verify file hashes, inspect the SBOM, and validate
  GitHub/Sigstore provenance instead of trusting a mutable download URL.
- Security scans and release assembly take longer and can fail when upstream
  advisory data changes. That cost is accepted for a security boundary.
- MPL-2.0 and CDLA-Permissive-2.0 are accepted for transitive dependencies;
  neither changes the Apache-2.0 license of Maskura's own source.
