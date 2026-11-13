//! Router construction and S3 subresource rejection.
//!
//! Extracted from `server.rs`. Items are re-exported from [`crate::server`].

use super::*;

/// S3 subresources Maskura does not implement. Before dispatch, any request
/// carrying one of these is rejected with `NotImplemented` so it can never be
/// misrouted into a destructive operation (e.g. `PUT ?versioning` creating a
/// bucket or `PUT ?tagging` overwriting an object). The `delete` subresource
/// is not listed: `POST /{bucket}?delete` (S3 Multi-Object Delete) is routed
/// to `s3_delete_objects`, and the method/path guard below keeps every other
/// `?delete` request rejected.
pub(crate) const UNSUPPORTED_S3_SUBRESOURCES: &[&str] = &[
    "acl",
    "tagging",
    "policy",
    "location",
    "lifecycle",
    "retention",
    "legal-hold",
    "cors",
    "encryption",
    "replication",
    "requestPayment",
    "website",
    "notification",
    "object-lock",
    "accelerate",
    "logging",
    "metrics",
    "ownershipControls",
    "publicAccessBlock",
    "intelligent-tiering",
    "inventory",
    "analytics",
    "select",
    "restore",
];

/// Reject unsupported S3 operations before method/path dispatch. CopyObject and
/// UploadPartCopy (via `x-amz-copy-source`) and any unsupported subresource
/// return `501 NotImplemented` without touching state. The `delete` subresource
/// is only routed for `POST /{bucket}` (Multi-Object Delete); every other
/// method/path carrying `?delete` is rejected here before dispatch.
pub(crate) async fn reject_unsupported_s3_operations(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> axum::response::Response {
    if request.headers().contains_key("x-amz-copy-source") {
        return s3_error::not_implemented("");
    }
    let pairs = match super::s3_versioning::query_pairs(request.uri().query()) {
        Ok(pairs) => pairs,
        Err(()) => return s3_error::invalid_argument("", "Malformed query encoding."),
    };
    if pairs
        .iter()
        .any(|(key, _)| UNSUPPORTED_S3_SUBRESOURCES.contains(&key.as_str()))
    {
        return s3_error::not_implemented("");
    }
    let configuration = match super::s3_versioning::validate_query(&request, &pairs) {
        Ok(configuration) => configuration,
        Err(()) => return s3_error::invalid_argument("", "Invalid versioning query."),
    };
    if configuration {
        return super::s3_versioning::bucket_configuration(state, request).await;
    }
    let query = request.uri().query();
    if super::s3_batch_delete::has_delete_subresource(query) {
        let is_bucket_level = request
            .uri()
            .path()
            .split('/')
            .filter(|s| !s.is_empty())
            .count()
            == 1;
        if request.method() != Method::POST || !is_bucket_level {
            return s3_error::not_implemented("");
        }
    }
    next.run(request).await
}

/// Build the axum router for the engine. The SaaS crate merges its own
/// control-plane routes (workspaces, billing, dashboard) onto this.
pub fn build_router(state: Arc<AppState>) -> Router {
    let s3_routes = Router::new()
        .route("/{bucket}", get(s3_list_objects))
        .route("/{bucket}", put(s3_bucket_put))
        .route("/{bucket}", delete(s3_bucket_delete))
        .route("/{bucket}", post(s3_delete_objects))
        .route("/{bucket}/", get(s3_list_objects))
        .route("/{bucket}/", put(s3_bucket_put))
        .route("/{bucket}/", delete(s3_bucket_delete))
        .route("/{bucket}/", post(s3_delete_objects))
        .route("/{bucket}/{*key}", put(s3_put))
        .route("/{bucket}/{*key}", get(s3_get))
        .route("/{bucket}/{*key}", head(s3_head))
        .route("/{bucket}/{*key}", delete(s3_delete))
        .route("/{bucket}/{*key}", post(s3_post))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            reject_unsupported_s3_operations,
        ));
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/", get(root))
        .route("/dashboard/api/keys", get(get_keys))
        .route(
            "/dashboard/api/keys",
            post(create_key).layer(DefaultBodyLimit::max(CREATE_KEY_BODY_BYTES)),
        )
        .route(
            "/dashboard/api/keys",
            delete(delete_key).layer(DefaultBodyLimit::max(SIMPLE_CREDENTIAL_MUTATION_BODY_BYTES)),
        )
        .route(
            "/dashboard/api/keys/public-key",
            put(set_public_key).layer(DefaultBodyLimit::max(SET_PUBLIC_KEY_BODY_BYTES)),
        )
        .route("/dashboard/api/mcp-tokens", get(get_mcp_tokens))
        .route(
            "/dashboard/api/mcp-tokens",
            post(create_mcp_token)
                .layer(DefaultBodyLimit::max(SIMPLE_CREDENTIAL_MUTATION_BODY_BYTES)),
        )
        .route(
            "/dashboard/api/mcp-tokens",
            delete(delete_mcp_token)
                .layer(DefaultBodyLimit::max(SIMPLE_CREDENTIAL_MUTATION_BODY_BYTES)),
        )
        .route("/dashboard/api/me", get(get_me))
        .route("/dashboard/api/demo/redact", post(demo_redact))
        .route("/dashboard/api/demo/process", post(demo_process))
        .route("/dashboard/api/backend", get(get_backend))
        .route("/dashboard/api/backend", put(put_backend))
        .merge(s3_routes);
    if state.auth_disabled {
        router = router
            .route("/dashboard/api/plugins", get(get_plugins))
            .route("/dashboard/api/plugins", post(create_plugin))
            .route("/dashboard/api/plugins/reorder", put(reorder_plugins))
            .route("/dashboard/api/plugins/{id}", put(update_plugin))
            .route("/dashboard/api/plugins/{id}", delete(delete_plugin))
            .route("/dashboard/api/objects", get(list_objects));
    }
    let router = router.layer(CorsLayer::permissive());
    router
        // Remove at the next major release. Registration after CORS lets OPTIONS return 410.
        .route("/dashboard/api/demo/store", any(legacy_demo_gone))
        .route("/dashboard/api/demo/read", any(legacy_demo_gone))
        .with_state(state)
        .route("/openapi.json", get(openapi_document))
        .route("/docs", get(openapi_docs))
        .route("/docs/", get(openapi_docs))
}

/// Serve the generated OpenAPI 3.1 document.
pub(crate) async fn openapi_document() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

/// Serve the self-contained OpenAPI reference without build-time archive extraction.
pub(crate) async fn openapi_docs() -> Html<&'static str> {
    Html(include_str!("../../static/openapi-docs.html"))
}
