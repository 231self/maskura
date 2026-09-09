# ADR 0010: Workspace-bound principals and hosted MCP transport boundary

- Status: Accepted
- Date: 2026-09-07

## Context

API keys and MCP tokens were historically owned only by a dashboard user. On
each data-plane request the gateway authenticated the credential and then asked
the workspace repository to resolve that user's current workspace. A durable
credential could therefore move between workspaces when membership or default
workspace selection changed. Existing rows contain no history from which the
original workspace can be reconstructed safely.

The stdio MCP server also owned the tool request schemas, list result contract,
and dispatch names. A hosted transport would otherwise duplicate those
contracts or call the gateway through loopback HTTP with a synthesized
credential header. The latter would turn an internal trust decision into
spoofable network input and introduce a second auth path.

## Decision

API keys and MCP tokens retain `user_id` as dashboard ownership metadata and
gain an immutable `workspace_id` execution principal. MCP tokens also expose a
stable credential UUID and credential-policy identity as one atomic
authentication result. Creation resolves the user's workspace once and
persists it with the credential. Authentication uses that persisted workspace
directly and never resolves a current/default workspace. Records with no valid
workspace binding fail authentication.

The migration leaves genuinely unbound credentials null. Existing hosted UUID
bindings are converted to canonical text and preserved after removing their
incompatible foreign key. Database triggers reject changes to a credential's
workspace after insertion.

Transport-independent MCP request schemas, result types, validation, tool
definitions, legacy aliases, dispatch, and S3 list parsing live in the small
`maskura-mcp-protocol` crate. The stdio binary consumes those types and
continues to call the network S3 surface with its configured credential. The
stdio client sends credentials over HTTPS only, except when the configured host
is a literal loopback address; non-loopback cleartext HTTP fails during startup.

Hosted adapters use `s4_gateway::server::invoke_mcp`. They provide an already
authenticated `AuthenticatedMcpPrincipal`, server operation UUID, typed tool
request, hard-bounded request/response limits, timeout, and cancellation token.
The gateway derives credential policy identity only from that principal, binds
operation UUID reuse to the complete canonical operation, and carries trusted
state in task-local storage unavailable to HTTP clients. The API accepts no
authentication, metering, backend, or presigned URL headers.

## Consequences

- Credentials cannot silently follow a user into another workspace.
- Legacy unbound credentials fail closed and require rotation.
- Dashboard ownership and data-plane workspace scope remain separate facts.
- Hosted MCP uses the same authorization, pipeline, storage, transaction, and
  usage paths as S3 without opening a loopback listener.
- Text MCP bodies and responses have non-configurable hard ceilings. The
  private transport remains responsible for envelope and chunk preparse bounds.
- Local stdio development remains simple over loopback HTTP, while a
  misconfigured remote gateway cannot receive MCP or API credentials in cleartext.
- Cancellation reaches active Wasm work and waits for gateway settlement;
  provider SDK calls that do not expose cooperative cancellation may complete
  before the invocation returns its committed outcome.
