# Open source and hosted boundaries

Maskura has an Apache-2.0 data plane and a separately operated hosted service.
This page states the boundary directly so evaluating the open-source project
does not require reverse-engineering the commercial model.

## In this Apache-2.0 repository

The public repository contains:

- the self-hosted S3-compatible gateway and streaming object data plane;
- the Wasmtime runtime, WIT contracts, built-in filters, and local plugin
  lifecycle;
- supported storage adapters and routing behavior;
- the `maskura` CLI and local `maskura-mcp` stdio server;
- the OpenAPI schema and generated Python and TypeScript clients;
- local file, in-memory, and Postgres-backed credential repositories; and
- tests, benchmarks, security documentation, and architecture decisions for
  the public engine.

The local Docker quickstart runs without a Maskura account, cloud account, or
database. Self-hosted operators choose their own storage, deployment, identity,
and operational controls.

## In hosted Maskura

The hosted service operates the public gateway engine with separate services
for multi-tenant identity and workspace administration, billing and usage
accounting, hosted policy management, managed operations, and Maskura Store.
Those hosted control-plane and operational services are not part of this
Apache-2.0 repository.

The hosted browser preview requires login. This is an abuse-control boundary
for a public processing endpoint, not a requirement of the self-hosted engine.

## Data boundary

With a self-hosted gateway, Maskura's hosted service is not in the request
path. The operator controls the gateway and destination storage.

With hosted Maskura Gateway, object bytes pass through the operated gateway and
then go to the workspace's configured storage. With Maskura Store, the hosted
service also provides the destination storage. The selected pipeline determines
whether supported fields are passed through, redacted, or encrypted; Maskura
does not claim that every object is automatically confidential.

See [Security](security.md) for trust boundaries, fail-closed behavior, feature
gates, and operator responsibilities.
