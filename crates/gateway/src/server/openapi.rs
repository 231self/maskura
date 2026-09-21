//! OpenAPI document aggregation.
//!
//! Extracted from `server.rs`. Re-exported from [`crate::server`].

use super::*;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Maskura Gateway API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Pluggable processing gateway for S3-compatible storage. Manage plugins and API keys, proxy S3 requests through a Wasm plugin pipeline."
    ),
    paths(get_keys, create_key, delete_key, get_mcp_tokens, create_mcp_token, delete_mcp_token, get_backend, put_backend, list_objects),
    components(schemas(ApiKeyResponse, ListKeyResponse, CreateKeyRequest, DeleteKeyRequest, McpTokenResponse, McpTokenCreatedResponse, CreateMcpTokenRequest, DeleteMcpTokenRequest, ObjectResponse, BackendConfigRequest, BackendConfigResponse)),
    tags(
        (name = "keys", description = "API key management"),
        (name = "mcp", description = "Hosted MCP credential management"),
        (name = "objects", description = "Object store listing")
    )
)]
pub(crate) struct ApiDoc;
