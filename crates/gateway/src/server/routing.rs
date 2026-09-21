//! Router construction and S3 subresource rejection.
//!
//! Extracted from `server.rs`. Items are re-exported from [`crate::server`].

use super::*;

/// S3 subresources Maskura does not implement. Before dispatch, any request
/// carrying one of these is rejected with `NotImplemented` so it can never be
/// misrouted into a destructive operation (e.g. `PUT ?versioning` creating a
/// bucket or `PUT ?tagging` overwriting an object).
pub(crate) const UNSUPPORTED_S3_SUBRESOURCES: &[&str] = &[
    "acl",
    "tagging",
    "policy",
    "versioning",
    "versions",
    "location",
    "lifecycle",
    "retention",
    "legal-hold",
    "delete",
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
/// return `501 NotImplemented` without touching state.
pub(crate) async fn reject_unsupported_s3_operations(
    request: Request,
    next: Next,
) -> axum::response::Response {
    if request.headers().contains_key("x-amz-copy-source") {
        return s3_error::not_implemented("");
    }
    if request.uri().query().is_some_and(|query| {
        query.split('&').any(|pair| {
            let key = pair.split('=').next().unwrap_or(pair);
            UNSUPPORTED_S3_SUBRESOURCES.contains(&key)
        })
    }) {
        return s3_error::not_implemented("");
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
        .route("/{bucket}/", get(s3_list_objects))
        .route("/{bucket}/", put(s3_bucket_put))
        .route("/{bucket}/", delete(s3_bucket_delete))
        .route("/{bucket}/{*key}", put(s3_put))
        .route("/{bucket}/{*key}", get(s3_get))
        .route("/{bucket}/{*key}", head(s3_head))
        .route("/{bucket}/{*key}", delete(s3_delete))
        .route("/{bucket}/{*key}", post(s3_post))
        .route_layer(middleware::from_fn(reject_unsupported_s3_operations));
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
        .merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()))
}
