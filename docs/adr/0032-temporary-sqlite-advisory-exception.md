# ADR 0032: Temporary exception for inactive SQLite dependency

- Status: Accepted
- Date: 2026-11-10

## Context

The lockfile records `libsqlite3-sys` 0.30.1 through optional SQLx SQLite
dependencies. RUSTSEC-2026-0459 affects versions before 0.39.0. Published
`sqlx-sqlite` 0.9.0 still requires a version below 0.38.0, so a SQLx/SeaORM
major upgrade does not establish a fix. At the decision revision the package
was absent from the inspected supported build graphs. Lockfile scanners still
report it; graph absence is not a fix for SQLite itself.

## Decision

Owner Amit Mor approved, on 2026-11-10, an exception **only** for
RUSTSEC-2026-0459. It expires at **2026-12-10T00:00:00Z** and does not apply
to active SQLite dependencies. The guard checks the locked workspace graph
with all workspace features and all targets, and separately checks the
documented default-feature Linux x86_64/arm64 and macOS arm64 release binaries
and the workspace's WASI and bare-Wasm component targets. A missing, malformed,
failed, or SQLite-containing graph, or invalid/expired UTC time, blocks the
exception. All-features does not imply arbitrary transitive optional features.

The Rust audit invokes the guard before supplying its one advisory ignore.
The deny wrapper runs the guard before constructing a temporary configuration
with that one added ignore; `deny.toml` itself remains unmodified so direct
`cargo deny` does not gain the exception. The guard requires Python 3.11 or
later and the repository's locked Cargo toolchain. CI security and artifact builders
run the guard as well. Each Cargo graph inspection has a 120-second deadline;
failure, timeout, malformed output and missing roots fail closed.

Supported local image paths are `python3 scripts/guarded-image.py docker --tag
<tag>`, `just image-local`, `just publish-local TAG=<tag>`, and `just dev-up`
(for the local Compose image). `just build-local` uses the same Dagger wrapper.
Each invocation checks the local locked graph and UTC clock outside the cached
engine, then generates a fresh cryptographically random nonce. Docker and
Dagger require that nonce in a final in-builder guard step after cacheable
compilation and before artifact assembly. For Dagger, the wrapper supplies the
trusted guard source and the in-builder check inspects the **resolved remote
ref's** graph, not merely the local checkout. A new nonce forces that guard
step to execute even when compilation is cached. The Compose wrapper also
rechecks immediately before starting the prebuilt image. The GitHub release
workflow independently rechecks outside those caches before upload, image push,
and publication.

These wrappers prove only the SQLite exception's time and graph conditions.
They do not independently qualify all security advisories or the identity of
an arbitrary remote ref. Normal revision review and release permission and
security gates remain mandatory; an older ref is not made safe by SQLite absence.

A bare `docker build`, `docker compose build`, or `dagger call` is outside this
supported entrypoint contract: an operator can replay a nonce or otherwise
bypass the wrapper. A nonce alone is not proof of freshness. These controls
also do not cover external consumers. Engine/cache behavior must still be
qualified in a real Docker and Dagger environment; mocked tests are not a
published-image or deployment qualification.
RUSTSEC-2026-0457 and RUSTSEC-2026-0462 require the
patched rmcp release, not exceptions. Other dependency checks remain in force.
The separate RUSTSEC-2026-0441 unmaintained `pin-utils` finding is not ignored:
the compatible Smithy HTTP and runtime updates remove its dependency paths.

## Consequences

Regression checks in `tests/test_sqlite_guard.py` pin the remediated MCP minimum
and reject reintroduction of `pin-utils`, inspect the real supported Cargo graph,
reject a later SQLite-enabled build shape after an earlier clean shape, and reject
an unconditional SQLite ignore even when graph inspection succeeds. These run
through the existing dependency-audit gate, not an optional manual-only suite.
The image-entrypoint tests also simulate a previously successful cached Docker
build followed by expiry: the later invocation must fail before reaching the
cached engine. This is mocked cache coverage, not a real engine qualification.

This is not a runtime fix, a statement about arbitrary downstream feature
unification, custom SQLite builds, or authorization for another repository.
Remove the exception when a fixed optional dependency can be adopted, or at
expiry, whichever comes first. Any extension or change of scope requires a new
owner security review before expiry. If the guard fails, do not bypass it to
ship: remediate the dependency or obtain a separately reviewed decision.
