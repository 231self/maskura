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

## Run locally

Start the published gateway image and copy the loopback URL printed by the CLI:

```bash
maskura local init
# Gateway: http://127.0.0.1:8080 (the selected port may differ)
```

The local gateway runs with `AUTH_DISABLED=true`. `maskura-mcp` still requires
an explicit credential shape so a configuration cannot accidentally become
credential-free when pointed at production. Use local-only placeholder values:

```json
{
  "mcpServers": {
    "maskura-local": {
      "command": "maskura-mcp",
      "env": {
        "MASKURA_GATEWAY_URL": "http://127.0.0.1:8080",
        "MASKURA_ACCESS_KEY": "local",
        "MASKURA_SECRET_KEY": "local"
      }
    }
  }
}
```

Use the exact port printed by `maskura local init`. These placeholder
credentials are accepted only because that loopback gateway explicitly disables
authentication; never use `AUTH_DISABLED` on a network-accessible deployment.

For Kilo, the equivalent local entry in `kilo.json` is:

```json
{
  "mcp": {
    "maskura-local": {
      "type": "local",
      "command": ["maskura-mcp"],
      "environment": {
        "MASKURA_GATEWAY_URL": "http://127.0.0.1:8080",
        "MASKURA_ACCESS_KEY": "local",
        "MASKURA_SECRET_KEY": "local"
      },
      "enabled": true
    }
  }
}
```

## Connect to a hosted gateway

Create an MCP token in the Maskura dashboard, or through the dashboard API with
a signed-in session JWT:

```bash
curl --fail-with-body \
  --request POST "$MASKURA_GATEWAY_URL/dashboard/api/mcp-tokens" \
  --header "Authorization: Bearer $MASKURA_SESSION_JWT" \
  --header "Content-Type: application/json" \
  --data '{"label":"desktop-agent","expires_in":2592000}'
```

The response reveals the `s4m_...` token once. Store it in a secret manager,
not in source control. The token remains bound to the workspace selected when
it was created.

Claude Desktop and Cursor use the standard `mcpServers` shape:

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

For Claude Desktop on macOS, place this under the `mcpServers` key in
`~/Library/Application Support/Claude/claude_desktop_config.json`. Cursor uses
`.cursor/mcp.json` in a project or its equivalent global MCP settings.

Kilo uses its local-process MCP configuration shape in `kilo.json`:

```json
{
  "mcp": {
    "maskura": {
      "type": "local",
      "command": ["maskura-mcp"],
      "environment": {
        "MASKURA_GATEWAY_URL": "https://api.s4.231self.com",
        "MASKURA_MCP_TOKEN": "s4m_your_token"
      },
      "enabled": true
    }
  }
}
```

Restart the client after changing its MCP configuration. Desktop applications
often do not inherit shell environment variables, so use the client's secret
storage or a restricted configuration file when literal values are required.

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

## Try it locally

The stdlib-only example connects over MCP stdio and lists the available tools:

```bash
export MASKURA_GATEWAY_URL="http://127.0.0.1:8080" # use the printed port
export MASKURA_ACCESS_KEY="local"
export MASKURA_SECRET_KEY="local"
python3 examples/mcp-client.py
```

Run a complete put, filtered get, paged list, and delete lifecycle:

```bash
MCP_EXAMPLE_RUN_MUTATIONS=1 \
MCP_EXAMPLE_BUCKET=agent-data \
python3 examples/mcp-client.py
```

The upload contains `alice@example.com`; the read result should contain
`[REDACTED_EMAIL]`, proving the MCP call used the normal gateway filter path.

Equivalent requests from an MCP-enabled agent are:

```text
Store "Contact alice@example.com" at agent-data/examples/mcp.txt with Maskura.
Read agent-data/examples/mcp.txt and show me the stored value.
List up to 10 keys under examples/ in agent-data.
Delete agent-data/examples/mcp.txt.
```

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
