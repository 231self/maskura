# MCP server

`maskura-mcp` is a local stdio Model Context Protocol server. It exposes four text
object tools to Claude, Codex, Cursor, and other MCP clients:

- `maskura_put_object`
- `maskura_get_object`
- `maskura_list_objects`
- `maskura_delete_object`

The stdio server does not implement a second storage or processing path. Every tool
calls the Maskura Gateway's S3-compatible HTTP surface, so gateway authentication,
the configured plugin pipeline, backend selection, limits, and metering still
apply.

## Install

Build and install from the public source:

```bash
cargo install --git https://github.com/231self/maskura --bin maskura-mcp s4-mcp
```

Linux x86_64 and arm64 binaries are also attached to each
[Maskura GitHub release](https://github.com/231self/maskura/releases) as
`maskura-mcp-linux-amd64` and `maskura-mcp-linux-arm64`. The `s4-mcp` binary
and `s4_*` tools remain permanent compatibility aliases.

There is currently no npm package or public hosted MCP endpoint. The public
gateway does provide the foundation used by a hosted transport: shared typed
contracts in `maskura-mcp-protocol` (re-exported as `s4_gateway::mcp`) and trusted in-process execution through
`s4_gateway::server::invoke_mcp`.

## Configure

Create an MCP token in the Maskura dashboard, then configure the local server:

```json
{
  "mcpServers": {
    "maskura": {
      "command": "maskura-mcp",
      "env": {
        "MASKURA_GATEWAY_URL": "https://api.s4.231self.com",
        "MASKURA_MCP_TOKEN": "s4m_your_token"
      }
    }
  }
}
```

A Maskura API key pair can be used instead:

```json
{
  "MASKURA_GATEWAY_URL": "https://api.s4.231self.com",
  "MASKURA_ACCESS_KEY": "s4_your_access_key",
  "MASKURA_SECRET_KEY": "s4s_your_secret_key"
}
```

`MASKURA_MCP_TOKEN` takes precedence when both credential forms are present. Secret
values are validated at startup and are omitted from debug output.
Legacy `S4_*` names remain accepted. If both forms are set, their values must
match exactly, including empty values, or startup fails closed.

## Tool behavior

`maskura_put_object` accepts a UTF-8 body and a `content_type` (default
`text/plain; charset=utf-8`). Maskura uses that Content-Type to select the processing
format before writing to the configured backend.

`maskura_get_object` returns the stored representation by default. Set `process` to
`true` to send `x-maskura-process: read` and run the configured read pipeline before
the MCP client receives the object.

`maskura_list_objects` performs S3 ListObjectsV2 with an optional prefix and returns
decoded object keys. `maskura_delete_object` deletes one bucket/key pair.

MCP text responses are limited to 8 MiB. Binary request/response bodies,
presigning, hosted Streamable HTTP transport, and agent payment protocols are
not part of this stdio release.

## Hosted adapter boundary

A hosted adapter authenticates its transport session outside the engine, then
calls `invoke_mcp` with:

- an atomically resolved `AuthenticatedMcpPrincipal` containing the credential
  UUID, derived policy identity, user, and immutable workspace
- a server operation UUID
- a typed `ToolRequest`
- request/response byte limits, timeout, and cancellation token

The invocation enters the same gateway handlers used by S3, including control
plane authorization, plugin resolution and filtering, workspace storage,
transactions, and usage recording. It does not use loopback HTTP and does not
accept credential, metering, backend-selection, or presigned URL headers.
Cancellation interrupts active Wasm work and waits for route settlement before
returning. Provider SDK calls do not expose a cooperative cancellation guarantee,
so an in-flight backend call may finish first; if it commits, Maskura returns the
settled committed outcome instead of reporting or releasing it as cancelled.

API keys and MCP tokens are bound to the workspace selected when they are
created. User identity is retained separately so dashboard owners can list and
revoke credentials. Credentials persisted before workspace binding was added
remain visible for rotation but fail authentication; Maskura never infers a
default workspace for them.
