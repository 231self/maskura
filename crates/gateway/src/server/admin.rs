//! Dashboard, key/plugin/MCP administration, and health endpoints.
//!
//! Extracted from `server.rs`. Items are re-exported from [`crate::server`].

use super::*;

#[derive(Serialize, ToSchema)]
pub(crate) struct ApiKeyResponse {
    pub(crate) key_id: String,
    pub(crate) workspace_id: String,
    pub(crate) secret: String,
    pub(crate) label: String,
    pub(crate) created_at: String,
    pub(crate) expires_at: Option<String>,
    pub(crate) public_key_pem: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct InternalErrorResponse {
    pub(crate) error: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ListKeyResponse {
    pub(crate) key_id: String,
    pub(crate) workspace_id: Option<String>,
    pub(crate) label: String,
    pub(crate) created_at: String,
    pub(crate) expires_at: Option<String>,
    pub(crate) public_key_pem: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ObjectResponse {
    pub(crate) key: String,
    pub(crate) size: usize,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct CreateKeyRequest {
    pub(crate) label: String,
    #[serde(default)]
    pub(crate) expires_in: u64,
    #[serde(default)]
    pub(crate) public_key_pem: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct DeleteKeyRequest {
    pub(crate) key_id: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct McpTokenResponse {
    pub(crate) credential_id: String,
    pub(crate) token_hash: String,
    pub(crate) workspace_id: Option<String>,
    pub(crate) label: String,
    pub(crate) created_at: String,
    pub(crate) expires_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct McpTokenCreatedResponse {
    pub(crate) credential_id: String,
    pub(crate) token: String,
    pub(crate) workspace_id: String,
    pub(crate) label: String,
    pub(crate) created_at: String,
    pub(crate) expires_at: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct CreateMcpTokenRequest {
    pub(crate) label: String,
    #[serde(default)]
    pub(crate) expires_in: u64,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct DeleteMcpTokenRequest {
    pub(crate) token_hash: String,
}

#[derive(serde::Deserialize, Default)]
pub(crate) struct S3Query {
    #[serde(rename = "uploads")]
    pub(crate) uploads: Option<String>,
    #[serde(rename = "uploadId")]
    pub(crate) upload_id: Option<String>,
    #[serde(rename = "partNumber")]
    pub(crate) part_number: Option<u32>,
    #[serde(rename = "part-number-marker")]
    pub(crate) part_number_marker: Option<u32>,
    #[serde(rename = "max-parts")]
    pub(crate) max_parts: Option<u32>,
    #[serde(rename = "list-type")]
    pub(crate) list_type: Option<String>,
    pub(crate) prefix: Option<String>,
    pub(crate) delimiter: Option<String>,
    #[serde(rename = "continuation-token")]
    pub(crate) continuation_token: Option<String>,
    #[serde(rename = "start-after")]
    pub(crate) start_after: Option<String>,
    #[serde(rename = "max-keys")]
    pub(crate) max_keys: Option<u32>,
    #[serde(rename = "encoding-type")]
    pub(crate) encoding_type: Option<String>,
    pub(crate) marker: Option<String>,
    #[serde(rename = "key-marker")]
    pub(crate) key_marker: Option<String>,
    #[serde(rename = "upload-id-marker")]
    pub(crate) upload_id_marker: Option<String>,
    #[serde(rename = "max-uploads")]
    pub(crate) max_uploads: Option<u32>,
}

/// `GET /` — serve the dashboard to browsers, ListBuckets to S3 clients.
pub(crate) async fn root(
    State(state): State<Arc<AppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let is_s3 = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .map(|a| a.starts_with("AWS4-"))
        .unwrap_or(false)
        || headers.contains_key(customer_headers::ACCESS_KEY.as_str())
        || uri.query().is_some_and(|query| {
            query
                .split('&')
                .any(|pair| pair.starts_with("X-Amz-Algorithm="))
        });
    if !is_s3 {
        return Html(dashboard_html(&state)).into_response();
    }
    let auth = match authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response("", error).into_response(),
    };
    match list_buckets(&state, &auth, &headers).await {
        Ok(xml) => s3_xml_ok(xml).into_response(),
        Err(_) => backend_resolution_error_response(""),
    }
}

pub(crate) async fn list_buckets(
    state: &AppState,
    auth: &Auth,
    headers: &HeaderMap,
) -> anyhow::Result<String> {
    let mut names: Vec<String> = Vec::new();
    match resolve_backend(state, auth, headers, StorageOperation::List)
        .await
        .map_err(anyhow::Error::msg)?
    {
        ResolvedBackend::S3 { client, .. } => {
            let out = client
                .list_buckets()
                .send()
                .await
                .map_err(|error| record_s3_failure("list_buckets", &error))?;
            for bucket in out.buckets() {
                if let Some(name) = bucket.name() {
                    names.push(name.to_string());
                }
            }
        }
        ResolvedBackend::Memory(store) => {
            let mut set = std::collections::BTreeSet::new();
            for full in store.list_keys() {
                if let Some((bucket, _)) = full.split_once('/') {
                    set.insert(bucket.to_string());
                }
            }
            names.extend(set);
        }
        ResolvedBackend::File(store) => {
            names.extend(
                store
                    .list_buckets()
                    .await
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?,
            );
        }
        ResolvedBackend::Managed(_) | ResolvedBackend::PresignedHttp(_) => {}
    }
    names.sort();
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>maskura</ID><DisplayName>Maskura</DisplayName></Owner><Buckets>"#,
    );
    for n in names {
        xml.push_str(&format!(
            "<Bucket><Name>{}</Name><CreationDate>1970-01-01T00:00:00.000Z</CreationDate></Bucket>",
            xml_escape(&n)
        ));
    }
    xml.push_str("</Buckets></ListAllMyBucketsResult>");
    Ok(xml)
}

/// CreateBucket is not allowed — buckets map to configured backends.
pub(crate) async fn s3_bucket_put(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response(&bucket, error),
    };
    match resolve_backend(&state, &auth, &headers, StorageOperation::Put).await {
        Ok(ResolvedBackend::File(store)) => match store.bucket_exists(&bucket).await {
            Ok(true) => s3_error::bucket_already_exists(&bucket),
            Ok(false) => match store.create_bucket(&bucket).await {
                Ok(()) => StatusCode::OK.into_response(),
                Err(error) => s3_error::invalid_request(&bucket, &error.to_string()),
            },
            Err(error) => s3_error::invalid_request(&bucket, &error.to_string()),
        },
        Ok(_) => s3_error::bucket_not_allowed(&bucket),
        Err(_) => backend_resolution_error_response(&bucket),
    }
}

/// DeleteBucket is not allowed for the same reason as CreateBucket.
pub(crate) async fn s3_bucket_delete(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = match authenticate(method.as_str(), &uri, &headers, &[], &state.keys, &state).await {
        Ok(auth) => auth,
        Err(error) => return authentication_error_response(&bucket, error),
    };
    match resolve_backend(&state, &auth, &headers, StorageOperation::Delete).await {
        Ok(ResolvedBackend::File(store)) => match store.bucket_exists(&bucket).await {
            Ok(false) => s3_error::no_such_bucket(&bucket),
            Ok(true) => match store.delete_bucket(&bucket).await {
                Ok(_) => StatusCode::NO_CONTENT.into_response(),
                Err(crate::file_store::FileStoreError::BucketNotEmpty) => {
                    s3_error::bucket_not_empty(&bucket)
                }
                Err(error) => s3_error::invalid_request(&bucket, &error.to_string()),
            },
            Err(error) => s3_error::invalid_request(&bucket, &error.to_string()),
        },
        Ok(_) => s3_error::bucket_not_allowed(&bucket),
        Err(_) => backend_resolution_error_response(&bucket),
    }
}

pub(crate) fn dashboard_html(state: &AppState) -> String {
    let html = include_str!("../../static/dashboard.html");
    let auth_disabled = state.auth_disabled;
    let supabase_url = &state.supabase_url;
    let anon_key = &state.supabase_anon_key;
    let has_supabase = anon_key.starts_with("sb_");

    let supabase_script = if has_supabase {
        format!(
            "<script src=\"https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js\"></script>\n<script>var supabase = window.supabase.createClient('{supabase_url}', '{anon_key}');\nvar HAS_SUPABASE = true;</script>"
        )
    } else {
        "<script>var HAS_SUPABASE = false;</script>".to_string()
    };

    // Local mode (AUTH_DISABLED=true): skip the auth modal entirely, go
    // straight into the dashboard as the local demo user.
    let boot = if auth_disabled || !has_supabase {
        "isDemo = true; onAuthReady();".to_string()
    } else {
        "supabase.auth.getSession().then(function(r) { if (r.data.session) { session = r.data.session; sessionToken = session.access_token; onAuthReady(); } });".to_string()
    };

    let auth_flag = format!(
        "<script>var AUTH_DISABLED = {};</script>",
        if auth_disabled { "true" } else { "false" }
    );

    html.replace("<!--SUPABASE-->", &format!("{auth_flag}{supabase_script}"))
        .replace("/*BOOT*/", &boot)
}

pub(crate) async fn health() -> impl IntoResponse {
    "ok"
}

/// Readiness: local storage is initialized and listable (liveness plus a
/// filesystem sanity check). The OCI healthcheck and Compose gate on this.
pub(crate) async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(file_store) = &state.file_store {
        match file_store.list_buckets().await {
            Ok(_) => StatusCode::OK,
            Err(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    } else {
        StatusCode::OK
    }
}

pub(crate) fn invalid_credential_mutation_response() -> axum::response::Response {
    (StatusCode::BAD_REQUEST, "invalid credential mutation").into_response()
}

/// List API keys for the authenticated user
#[utoipa::path(
    get,
    path = "/dashboard/api/keys",
    responses((status = 200, description = "API keys", body = Vec<ListKeyResponse>)),
    tag = "keys"
)]
pub(crate) async fn get_keys(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let keys = match state.keys.list_for_user(&uid).await {
        Ok(keys) => keys,
        Err(_) => {
            tracing::error!(error_category = "persistence", "API key listing failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let resp: Vec<ListKeyResponse> = keys
        .into_iter()
        .map(|k| ListKeyResponse {
            key_id: k.key_id,
            workspace_id: k.workspace_id,
            label: k.label,
            created_at: k.created_at,
            expires_at: k.expires_at,
            public_key_pem: k.public_key_pem,
        })
        .collect();
    Json(resp).into_response()
}

/// Create a new API key
#[utoipa::path(
    post,
    path = "/dashboard/api/keys",
    request_body = CreateKeyRequest,
    responses((status = 200, description = "Created key with secret", body = ApiKeyResponse)),
    tag = "keys"
)]
pub(crate) async fn create_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateKeyRequest>,
) -> impl IntoResponse {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let label = match canonicalize_credential_label(&body.label) {
        Ok(label) => label,
        Err(_) => return invalid_credential_mutation_response(),
    };
    if validate_credential_ttl(body.expires_in).is_err() {
        return invalid_credential_mutation_response();
    }
    let public_key_pem = match body
        .public_key_pem
        .as_deref()
        .map(canonicalize_public_key_pem)
        .transpose()
    {
        Ok(public_key_pem) => public_key_pem,
        Err(_) => return invalid_credential_mutation_response(),
    };
    let workspace = match state.workspace_storage.resolve_workspace(&uid).await {
        Ok(workspace) => workspace,
        Err(error) => return workspace_storage_error_response(error),
    };
    let result = state
        .keys
        .create_key(&uid, &workspace, &label, body.expires_in, public_key_pem)
        .await;
    let (secret, created) = match result {
        Ok(created) => created,
        Err(_) => {
            tracing::error!(
                error_category = "persistence",
                "API key creation persistence failed"
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(InternalErrorResponse {
                    error: "internal_error".to_string(),
                }),
            )
                .into_response();
        }
    };
    Json(ApiKeyResponse {
        key_id: created.key_id,
        workspace_id: created
            .workspace_id
            .expect("new API keys are workspace-bound"),
        secret,
        label: created.label,
        created_at: created.created_at,
        expires_at: created.expires_at,
        public_key_pem: created.public_key_pem,
    })
    .into_response()
}

/// Revoke an API key
#[utoipa::path(
    delete,
    path = "/dashboard/api/keys",
    request_body = DeleteKeyRequest,
    responses((status = 204, description = "Key revoked"), (status = 404, description = "Key not found")),
    tag = "keys"
)]
pub(crate) async fn delete_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DeleteKeyRequest>,
) -> impl IntoResponse {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match state.keys.delete_key(&body.key_id, &uid).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "key not found").into_response(),
        Err(_) => {
            tracing::error!(error_category = "persistence", "API key deletion failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

/// List MCP bearer tokens for the authenticated user (hashes only).
#[utoipa::path(
    get,
    path = "/dashboard/api/mcp-tokens",
    responses((status = 200, description = "MCP tokens", body = Vec<McpTokenResponse>)),
    tag = "mcp"
)]
pub(crate) async fn get_mcp_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let tokens = match state.keys.list_mcp_tokens(&uid).await {
        Ok(tokens) => tokens,
        Err(_) => {
            tracing::error!(error_category = "persistence", "MCP token listing failed");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let resp = mcp_token_responses(tokens);
    Json(resp).into_response()
}

pub(crate) fn mcp_token_responses(tokens: Vec<McpToken>) -> Vec<McpTokenResponse> {
    let mut omitted = 0usize;
    let responses = tokens
        .into_iter()
        .filter_map(|token| {
            let (Some(credential_id), Some(workspace_id)) =
                (token.credential_id, token.workspace_id)
            else {
                omitted += 1;
                return None;
            };
            Some(McpTokenResponse {
                credential_id,
                token_hash: token.token_hash,
                workspace_id: Some(workspace_id),
                label: token.label,
                created_at: token.created_at,
                expires_at: token.expires_at,
            })
        })
        .collect();
    if omitted > 0 {
        warn!(
            omitted,
            "omitted unusable legacy MCP tokens from dashboard response"
        );
    }
    responses
}

/// Create an MCP bearer token (`maskura_mcp_...`). The plaintext token is returned
/// once and only its hash is stored.
#[utoipa::path(
    post,
    path = "/dashboard/api/mcp-tokens",
    request_body = CreateMcpTokenRequest,
    responses((status = 200, description = "Created MCP token", body = McpTokenCreatedResponse)),
    tag = "mcp"
)]
pub(crate) async fn create_mcp_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateMcpTokenRequest>,
) -> impl IntoResponse {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let label = match canonicalize_credential_label(&body.label) {
        Ok(label) => label,
        Err(_) => return invalid_credential_mutation_response(),
    };
    if validate_credential_ttl(body.expires_in).is_err() {
        return invalid_credential_mutation_response();
    }
    let workspace = match state.workspace_storage.resolve_workspace(&uid).await {
        Ok(workspace) => workspace,
        Err(error) => return workspace_storage_error_response(error),
    };
    let (token, created) = match state
        .keys
        .create_mcp_token(&uid, &workspace, &label, body.expires_in)
        .await
    {
        Ok(created) => created,
        Err(_) => {
            tracing::error!(
                error_category = "persistence",
                "MCP token creation persistence failed"
            );
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    Json(McpTokenCreatedResponse {
        credential_id: created
            .credential_id
            .expect("new MCP tokens have credential IDs"),
        token,
        workspace_id: created
            .workspace_id
            .expect("new MCP tokens are workspace-bound"),
        label,
        created_at: created.created_at,
        expires_at: created.expires_at,
    })
    .into_response()
}

/// Revoke an MCP bearer token.
#[utoipa::path(
    delete,
    path = "/dashboard/api/mcp-tokens",
    request_body = DeleteMcpTokenRequest,
    responses((status = 204, description = "Token revoked"), (status = 404, description = "Token not found")),
    tag = "mcp"
)]
pub(crate) async fn delete_mcp_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DeleteMcpTokenRequest>,
) -> impl IntoResponse {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match state.keys.delete_mcp_token(&body.token_hash, &uid).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "token not found").into_response(),
        Err(_) => {
            tracing::error!(error_category = "persistence", "MCP token deletion failed");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/dashboard/api/backend",
    responses(
        (status = 200, description = "Redacted workspace backend configuration", body = BackendConfigResponse),
        (status = 401, description = "Not authenticated")
    ),
    tag = "backend"
)]
pub(crate) async fn get_backend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> axum::response::Response {
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let workspace = match state.workspace_storage.resolve_workspace(&uid).await {
        Ok(workspace) => workspace,
        Err(error) => return workspace_storage_error_response(error),
    };
    match state.workspace_storage.get_public_config(&workspace).await {
        Ok(config) => Json(config).into_response(),
        Err(error) => workspace_storage_error_response(error),
    }
}

pub(crate) fn workspace_storage_error_response(
    error: WorkspaceStorageError,
) -> axum::response::Response {
    let (status, code, message) = match &error {
        WorkspaceStorageError::InvalidConfig(_) | WorkspaceStorageError::UnsupportedConfig(_) => (
            StatusCode::BAD_REQUEST,
            "invalid_backend_config",
            error.to_string(),
        ),
        WorkspaceStorageError::Repository(_) | WorkspaceStorageError::AmbiguousAdmission(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "workspace_storage_unavailable",
            "workspace storage is temporarily unavailable".to_string(),
        ),
    };
    (
        status,
        Json(serde_json::json!({
            "code": code,
            "message": message,
        })),
    )
        .into_response()
}

pub(crate) async fn validate_and_put_workspace_backend(
    repository: &dyn WorkspaceStorageRepository,
    endpoint_policy: &WorkspaceEndpointPolicy,
    workspace: &WorkspaceId,
    config: BackendConfigRequest,
) -> Result<BackendConfigResponse, WorkspaceStorageError> {
    if config.backend_type == BackendType::S3Compatible {
        endpoint_policy
            .validate(&config.endpoint)
            .await
            .map_err(WorkspaceStorageError::InvalidConfig)?;
    }
    repository.put_config(workspace, config).await
}

#[utoipa::path(
    put,
    path = "/dashboard/api/backend",
    request_body = BackendConfigRequest,
    responses(
        (status = 200, description = "Redacted saved workspace backend configuration", body = BackendConfigResponse),
        (status = 400, description = "Incomplete or unsupported configuration"),
        (status = 401, description = "A real authenticated user is required")
    ),
    tag = "backend"
)]
pub(crate) async fn put_backend(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(config): Json<BackendConfigRequest>,
) -> impl IntoResponse {
    if state.auth_disabled {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(uid) = require_user_id(&headers, &state).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let workspace = match state.workspace_storage.resolve_workspace(&uid).await {
        Ok(workspace) => workspace,
        Err(error) => return workspace_storage_error_response(error),
    };
    match validate_and_put_workspace_backend(
        state.workspace_storage.as_ref(),
        &state.workspace_endpoint_policy,
        &workspace,
        config,
    )
    .await
    {
        Ok(config) => Json(config).into_response(),
        Err(error) => workspace_storage_error_response(error),
    }
}

pub(crate) async fn get_plugins(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.plugins.list())
}

#[derive(Deserialize)]
pub(crate) struct SetPublicKeyRequest {
    pub(crate) key_id: String,
    pub(crate) public_key_pem: String,
}

pub(crate) enum PublicKeyMutationActor {
    ApiKey { access_key: String, user_id: String },
    DashboardUser(String),
}

pub(crate) fn unique_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, StatusCode> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    value
        .map(|value| value.to_str().map_err(|_| StatusCode::UNAUTHORIZED))
        .transpose()
}

pub(crate) fn unique_customer_header(
    headers: &HeaderMap,
    alias: customer_headers::HeaderAlias,
) -> Result<Option<&str>, StatusCode> {
    customer_headers::aliased_unique(headers, alias)
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .map(|value| value.to_str().map_err(|_| StatusCode::UNAUTHORIZED))
        .transpose()
}

pub(crate) async fn authenticate_public_key_mutation(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<PublicKeyMutationActor, StatusCode> {
    let authorization = unique_header(headers, "authorization")?;
    let access_key = unique_customer_header(headers, customer_headers::ACCESS_KEY)?;
    let secret_key = unique_customer_header(headers, customer_headers::SECRET_KEY)?;
    let mcp_token = unique_customer_header(headers, customer_headers::MCP_TOKEN)?;
    let api_headers_supplied = access_key.is_some() || secret_key.is_some();
    if (api_headers_supplied && authorization.is_some())
        || (mcp_token.is_some() && (api_headers_supplied || authorization.is_some()))
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if mcp_token.is_some() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if access_key.is_some() || secret_key.is_some() {
        let access_key = access_key
            .filter(|value| !value.is_empty())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let secret_key = secret_key
            .filter(|value| !value.is_empty())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let resolved = state
            .keys
            .resolve_credentials(access_key, secret_key)
            .await
            .map_err(|_| {
                tracing::error!(
                    error_category = "persistence",
                    "credential storage unavailable"
                );
                StatusCode::SERVICE_UNAVAILABLE
            })?;
        let (context, _) = resolved.ok_or(StatusCode::UNAUTHORIZED)?;
        return Ok(PublicKeyMutationActor::ApiKey {
            access_key: access_key.to_string(),
            user_id: context.user_id,
        });
    }

    let token = authorization
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if let Some((access_key, secret_key)) = token.split_once(':') {
        if access_key.is_empty() || secret_key.is_empty() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let resolved = state
            .keys
            .resolve_credentials(access_key, secret_key)
            .await
            .map_err(|_| {
                tracing::error!(
                    error_category = "persistence",
                    "credential storage unavailable"
                );
                StatusCode::SERVICE_UNAVAILABLE
            })?;
        let (context, _) = resolved.ok_or(StatusCode::UNAUTHORIZED)?;
        return Ok(PublicKeyMutationActor::ApiKey {
            access_key: access_key.to_string(),
            user_id: context.user_id,
        });
    }

    if state.auth_disabled || token.starts_with("maskura_mcp_") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    require_user_id(headers, state)
        .await
        .map(PublicKeyMutationActor::DashboardUser)
        .ok_or(StatusCode::UNAUTHORIZED)
}

pub(crate) async fn set_public_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SetPublicKeyRequest>,
) -> impl IntoResponse {
    let actor = match authenticate_public_key_mutation(&state, &headers).await {
        Ok(actor) => actor,
        Err(status) => return status.into_response(),
    };
    let uid = match actor {
        PublicKeyMutationActor::ApiKey {
            access_key,
            user_id,
        } => {
            if body.key_id != access_key {
                return (StatusCode::NOT_FOUND, "key not found").into_response();
            }
            user_id
        }
        PublicKeyMutationActor::DashboardUser(user_id) => user_id,
    };
    let public_key_pem = match canonicalize_public_key_pem(&body.public_key_pem) {
        Ok(public_key_pem) => public_key_pem,
        Err(_) => return invalid_credential_mutation_response(),
    };
    match state
        .keys
        .set_public_key(&body.key_id, &uid, &public_key_pem)
        .await
    {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "key not found").into_response(),
        Err(_) => {
            tracing::error!(
                error_category = "persistence",
                "public key persistence failed"
            );
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

pub(crate) async fn create_plugin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let name = match customer_headers::aliased(&headers, customer_headers::PLUGIN_NAME) {
        Ok(Some(value)) => match value.to_str() {
            Ok(value) => value.to_string(),
            Err(_) => return (StatusCode::BAD_REQUEST, "invalid plugin name").into_response(),
        },
        Ok(None) => "imported".to_string(),
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "conflicting plugin name headers").into_response();
        }
    };
    match state.plugins.import(&name, &body) {
        Ok(info) => (StatusCode::CREATED, Json(info)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub(crate) struct PluginUpdate {
    pub(crate) enabled: Option<bool>,
    pub(crate) name: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct PluginReorder {
    pub(crate) order: Vec<String>,
}

pub(crate) async fn reorder_plugins(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PluginReorder>,
) -> impl IntoResponse {
    state.plugins.reorder(body.order);
    StatusCode::OK.into_response()
}

pub(crate) async fn update_plugin(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(update): Json<PluginUpdate>,
) -> impl IntoResponse {
    let found = update
        .enabled
        .is_some_and(|enabled| state.plugins.set_enabled(&id, enabled).is_some())
        || update
            .name
            .is_some_and(|name| state.plugins.set_name(&id, &name).is_some());
    if let Some(info) = state.plugins.get_info(&id) {
        Json(info).into_response()
    } else if found {
        StatusCode::OK.into_response()
    } else {
        (StatusCode::NOT_FOUND, "plugin not found").into_response()
    }
}

pub(crate) async fn delete_plugin(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.plugins.remove(&id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, "plugin not found").into_response()
    }
}

/// List all objects in the store
#[utoipa::path(
    get,
    path = "/dashboard/api/objects",
    responses((status = 200, description = "Objects", body = Vec<ObjectResponse>)),
    tag = "objects"
)]
pub(crate) async fn list_objects(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let objects: Vec<ObjectResponse> = state
        .store
        .list_keys()
        .into_iter()
        .map(|k| {
            let parts: Vec<&str> = k.splitn(2, '/').collect();
            let bucket = parts[0];
            let obj_key = parts.get(1).unwrap_or(&"");
            let size = state
                .store
                .metadata(bucket, obj_key)
                .map(|(size, _, _)| size)
                .unwrap_or(0);
            ObjectResponse { key: k, size }
        })
        .collect();
    Json(objects)
}
