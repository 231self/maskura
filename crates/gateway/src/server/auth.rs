//! Authentication and authorization: credential verification, JWT claims,
//! and metering/authorization helpers.
//!
//! Extracted from `server.rs`. Items are re-exported from [`crate::server`].

use super::*;

#[derive(Clone)]
pub struct Auth {
    pub(crate) context: AuthenticatedRequestContext,
    pub(crate) credential_policy_id: String,
    pub(crate) public_key_pem: Option<String>,
    pub(crate) stable_key: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct TrustedInvocationContext {
    pub(crate) principal: crate::store::AuthenticatedMcpPrincipal,
}

impl TrustedInvocationContext {
    pub fn new(principal: crate::store::AuthenticatedMcpPrincipal) -> Self {
        Self { principal }
    }
}

#[derive(Clone)]
pub(crate) struct TrustedInvocation {
    pub(crate) auth: Auth,
    pub(crate) operation: OperationIdentity,
    pub(crate) cancellation: tokio_util::sync::CancellationToken,
    pub(crate) committed: Arc<std::sync::atomic::AtomicBool>,
}

tokio::task_local! {
    pub(crate) static TRUSTED_INVOCATION: TrustedInvocation;
}

impl Auth {
    pub(crate) fn workspace_id(&self) -> &crate::workspace_storage::WorkspaceId {
        &self.context.workspace_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OperationIdentity {
    pub(crate) receipt_id: Uuid,
    pub(crate) operation_id: Uuid,
}

pub(crate) struct OperationUsage<'a> {
    pub(crate) grant: &'a AuthorizationGrant,
    pub(crate) source_bytes: u64,
    pub(crate) output_bytes: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct AuthorizedOperation<'a> {
    pub(crate) auth: &'a Auth,
    pub(crate) grant: &'a AuthorizationGrant,
}

#[derive(Clone, Copy)]
pub(crate) struct AuthorizedUsage<'a> {
    pub(crate) grant: &'a AuthorizationGrant,
}

impl OperationUsage<'_> {
    pub(crate) fn event(&self) -> UsageEvent {
        UsageEvent::from_grant(self.grant, self.source_bytes, self.output_bytes)
    }
}

pub(crate) fn operation_id_for_receipt(receipt_id: Uuid) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_X500, receipt_id.as_bytes())
}

pub(crate) fn request_operation_identity() -> OperationIdentity {
    if let Ok(operation) = TRUSTED_INVOCATION.try_with(|value| value.operation) {
        return operation;
    }
    let receipt_id = Uuid::now_v7();
    OperationIdentity {
        receipt_id,
        operation_id: operation_id_for_receipt(receipt_id),
    }
}

pub(crate) fn trusted_wasm_cancellation() -> maskura_wasm_runtime::CancellationToken {
    let pipeline = maskura_wasm_runtime::CancellationToken::new();
    if let Ok(invocation) = TRUSTED_INVOCATION.try_with(|value| value.cancellation.clone()) {
        let pipeline_on_cancel = pipeline.clone();
        tokio::spawn(async move {
            invocation.cancelled().await;
            pipeline_on_cancel.cancel();
        });
    }
    pipeline
}

impl OperationIdentity {
    pub(crate) fn authorization(
        self,
        bucket: &str,
        route: UsageRoute,
        kind: RequestKind,
        max_processed_bytes: u64,
    ) -> UsageAuthorization {
        UsageAuthorization::new(
            self.operation_id,
            self.receipt_id,
            bucket,
            route,
            kind,
            max_processed_bytes,
        )
    }

    pub(crate) fn pipeline_authorization(
        self,
        bucket: &str,
        route: UsageRoute,
        kind: RequestKind,
        max_processed_bytes: u64,
        resolution: &crate::pipeline::PipelineResolution,
    ) -> UsageAuthorization {
        self.authorization(bucket, route, kind, max_processed_bytes)
            .with_pipeline(&resolution.locator)
    }
}

pub(crate) fn object_max_processed_bytes(state: &AppState) -> u64 {
    state
        .source_body_limits
        .max_bytes
        .max(state.max_pipeline_output_bytes)
}

pub(crate) fn multipart_completion_operation_identity(
    upload_id: &str,
    request_fingerprint: &str,
) -> OperationIdentity {
    let identity = format!("{upload_id}\0{request_fingerprint}");
    OperationIdentity {
        receipt_id: Uuid::new_v5(&Uuid::NAMESPACE_OID, identity.as_bytes()),
        operation_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, identity.as_bytes()),
    }
}

pub(crate) fn client_metering_id_rejection(
    headers: &HeaderMap,
    key: &str,
) -> Option<axum::response::Response> {
    if [
        "x-maskura-metering-id",
        "x-maskura-operation-id",
        "x-maskura-usage-id",
    ]
    .into_iter()
    .any(|name| headers.contains_key(name))
    {
        return Some(s3_error::invalid_request(
            key,
            "The request contains an unsupported header.",
        ));
    }
    None
}

pub(crate) fn metering_error_response(key: &str, error: MeteringError) -> axum::response::Response {
    match error {
        MeteringError::Unavailable => {
            s3_error::service_unavailable(key, "Usage metering is temporarily unavailable.")
        }
        MeteringError::IdempotencyConflict => s3_error::invalid_request(
            key,
            "The usage receipt conflicts with an existing usage event.",
        ),
        MeteringError::Rejected => s3_error::payment_required(key, "The usage event was rejected."),
    }
}

pub(crate) async fn authorize_request(
    control: &dyn ControlPlane,
    context: &AuthenticatedRequestContext,
    authorization: &UsageAuthorization,
    key: &str,
) -> Result<AuthorizationGrant, axum::response::Response> {
    match control.authorize(context, authorization).await {
        Ok(AuthorizationDecision::Granted(grant)) if grant.matches(authorization) => Ok(grant),
        Ok(AuthorizationDecision::Granted(_)) => Err(s3_error::service_unavailable(
            key,
            "Authorization returned an invalid grant.",
        )),
        Ok(AuthorizationDecision::Blocked(reason)) => {
            Err(s3_error::payment_required(key, reason.message))
        }
        Err(AuthorizationError::Unavailable) => Err(s3_error::service_unavailable(
            key,
            "Authorization is temporarily unavailable.",
        )),
    }
}

pub(crate) async fn release_failure(
    control: &dyn ControlPlane,
    context: &AuthenticatedRequestContext,
    grant: &AuthorizationGrant,
    key: &str,
    response: axum::response::Response,
) -> axum::response::Response {
    match control.release(context, grant.operation_id()).await {
        Ok(()) => response,
        Err(AuthorizationError::Unavailable) => {
            warn!(
                operation_id = %grant.operation_id(),
                "usage reservation was not released"
            );
            s3_error::service_unavailable(
                key,
                "Authorization is temporarily unavailable while releasing the operation.",
            )
        }
    }
}

pub(crate) async fn managed_delete_failure_response(
    control: &dyn ControlPlane,
    context: &AuthenticatedRequestContext,
    grant: &AuthorizationGrant,
    key: &str,
    error: crate::managed::ManagedDeleteError,
) -> axum::response::Response {
    let response = s3_error::internal_error(key, "The managed delete could not be completed.");
    match error {
        crate::managed::ManagedDeleteError::PreCommit(_) => {
            release_failure(control, context, grant, key, response).await
        }
        crate::managed::ManagedDeleteError::CommitUnknown(_) => response,
    }
}

pub(crate) async fn record_usage(
    control: Arc<dyn ControlPlane>,
    context: &AuthenticatedRequestContext,
    event: &UsageEvent,
    key: &str,
) -> Result<(), axum::response::Response> {
    let _ = TRUSTED_INVOCATION.try_with(|invocation| {
        invocation
            .committed
            .store(true, std::sync::atomic::Ordering::Release);
    });
    control.record(context, event).await.map_err(|error| {
        warn!(event_id = %event.receipt_id(), ?error, "usage event was not recorded");
        metering_error_response(key, error)
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn record_failed_pipeline_attempt(
    control: &dyn ControlPlane,
    context: &AuthenticatedRequestContext,
    operation_id: Uuid,
    bucket: &str,
    direction: crate::pipeline::PipelineDirection,
    resolution: Option<&crate::pipeline::PipelineResolution>,
    error_code: &'static str,
    duration_ms: u64,
) {
    let components =
        resolution.map(|value| crate::pipeline::component_digest_evidence(&value.steps));
    let attempt = PipelineAttempt::failed(
        operation_id,
        bucket,
        direction,
        resolution,
        components,
        error_code,
        0,
        duration_ms,
    );
    warn!(
        operation_id = %attempt.operation_id(),
        direction = ?attempt.direction(),
        error_code = attempt.error_code(),
        fuel_consumed = attempt.fuel_consumed(),
        duration_ms = attempt.duration_ms(),
        "pipeline attempt failed without customer usage"
    );
    if control
        .record_pipeline_attempt(context, &attempt)
        .await
        .is_err()
    {
        warn!(operation_id = %operation_id, error_code, "pipeline attempt evidence was not recorded");
    }
}

pub(crate) async fn record_operation(
    control: Arc<dyn ControlPlane>,
    context: &AuthenticatedRequestContext,
    usage: OperationUsage<'_>,
    key: &str,
) -> Result<(), axum::response::Response> {
    let event = usage.event();
    record_operation_with_event(control, context, event, key).await
}

pub(crate) async fn record_operation_with_event(
    control: Arc<dyn ControlPlane>,
    context: &AuthenticatedRequestContext,
    event: UsageEvent,
    key: &str,
) -> Result<(), axum::response::Response> {
    record_usage(control, context, &event, key).await
}

pub(crate) async fn record_durable_operation_with_event(
    journal: Option<&Arc<dyn OperationJournal>>,
    control: Arc<dyn ControlPlane>,
    context: &AuthenticatedRequestContext,
    event: UsageEvent,
    key: &str,
) -> Result<(), axum::response::Response> {
    persist_usage_evidence(journal, &event).await.map_err(|_| {
        warn!(
            operation_id = %event.operation_id(),
            "failed to persist usage evidence"
        );
        s3_error::service_unavailable(key, "Usage evidence could not be persisted.")
    })?;
    record_operation_with_event(control, context, event, key).await
}

pub(crate) fn multipart_completion_event(
    grant: &AuthorizationGrant,
    result: &MultipartCompletionResult,
) -> UsageEvent {
    let event = UsageEvent::from_grant(grant, result.source_bytes, result.size_bytes);
    match &result.pipeline_evidence {
        Some(evidence) => event.with_pipeline_evidence(evidence.clone()),
        None => event,
    }
}

/// Persist the complete canonical usage event before entering a provider
/// commit window. Exact retries use one deterministic evidence identity.
pub(crate) async fn persist_usage_evidence(
    journal: Option<&Arc<dyn OperationJournal>>,
    event: &UsageEvent,
) -> Result<(), JournalError> {
    let Some(journal) = journal else {
        return Ok(());
    };
    // A process may have a Postgres journal because DATABASE_URL is set while
    // writing to the development memory sink. That sink has no operation row;
    // skip evidence rather than violating the evidence foreign key.
    if journal.get(event.operation_id()).await?.is_none() {
        return Ok(());
    }
    append_usage_evidence(journal, event).await
}

pub(crate) async fn persist_transaction_usage_evidence(
    journal: Option<&Arc<dyn OperationJournal>>,
    durable_operation_id: Option<Uuid>,
    event: &UsageEvent,
) -> Result<(), JournalError> {
    let Some(durable_operation_id) = durable_operation_id else {
        return Ok(());
    };
    if durable_operation_id != event.operation_id() {
        return Err(JournalError::Corrupt(
            "sink operation does not match usage evidence operation".to_string(),
        ));
    }
    let journal = journal.ok_or_else(|| {
        JournalError::Persistence("durable sink has no operation journal".to_string())
    })?;
    if journal.get(durable_operation_id).await?.is_none() {
        return Err(JournalError::Corrupt(format!(
            "durable sink operation {durable_operation_id} has no journal intent"
        )));
    }
    append_usage_evidence(journal, event).await
}

pub(crate) fn admitted_response_bytes(response: &axum::response::Response) -> Option<u64> {
    let mut lengths = response.headers().get_all(header::CONTENT_LENGTH).iter();
    if let Some(length) = lengths.next() {
        if lengths.next().is_some() {
            return None;
        }
        return length.to_str().ok()?.parse().ok();
    }
    http_body::Body::size_hint(response.body()).exact()
}

pub(crate) fn content_length(headers: &HeaderMap) -> Option<u64> {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()?.parse().ok()
}

/// Launch policy: persist the admitted representation size before releasing a
/// streaming body. This intentionally never relies on body drop or background
/// best effort. Responses without a trustworthy size fail closed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn metered_read_response(
    control: Arc<dyn ControlPlane>,
    auth: &Auth,
    grant: &AuthorizationGrant,
    key: &str,
    source_bytes: Option<u64>,
    response: axum::response::Response,
    pipeline_evidence: Option<crate::control::PipelineEvidence>,
) -> axum::response::Response {
    if !response.status().is_success() {
        return release_failure(control.as_ref(), &auth.context, grant, key, response).await;
    }
    let Some(bytes) = admitted_response_bytes(&response) else {
        let response = s3_error::service_unavailable(
            key,
            "The response size is unavailable for usage metering.",
        );
        return release_failure(control.as_ref(), &auth.context, grant, key, response).await;
    };
    let source_bytes = source_bytes.unwrap_or(bytes);
    if source_bytes.max(bytes) > grant.max_processed_bytes() {
        return release_failure(
            control.as_ref(),
            &auth.context,
            grant,
            key,
            s3_error::entity_too_large(key),
        )
        .await;
    }
    let event = UsageEvent::from_grant(grant, source_bytes, bytes);
    let event = match pipeline_evidence {
        Some(evidence) => event.with_pipeline_evidence(evidence),
        None => event,
    };
    if let Err(response) = record_usage(control, &auth.context, &event, key).await {
        return response;
    }
    response
}

pub(crate) struct HeaderAuthentication {
    pub(crate) auth: Auth,
    pub(crate) body_verifier: Option<BodyVerifier>,
}

impl HeaderAuthentication {
    pub(crate) fn without_body(auth: Auth) -> Self {
        Self {
            auth,
            body_verifier: None,
        }
    }

    pub(crate) fn verify_body(mut self, body: &[u8]) -> Result<Auth, IntegrityError> {
        if let Some(mut verifier) = self.body_verifier.take() {
            verifier.push(body)?;
            verifier.finish()?;
        }
        Ok(self.auth)
    }
}

#[derive(Debug)]
pub(crate) enum HeaderAuthError {
    Denied,
    InvalidPayload(IntegrityError),
    CredentialStoreUnavailable(String),
    Unavailable(String),
}

pub(crate) async fn authenticated_request(
    state: &AppState,
    user_id: String,
    credential_policy_id: String,
    public_key_pem: Option<String>,
    stable_key: Option<Vec<u8>>,
) -> Result<Auth, HeaderAuthError> {
    let workspace_id = state
        .workspace_storage
        .resolve_workspace(&user_id)
        .await
        .map_err(|error| HeaderAuthError::Unavailable(error.to_string()))?;
    Ok(Auth {
        context: AuthenticatedRequestContext {
            user_id,
            workspace_id,
        },
        credential_policy_id,
        public_key_pem,
        stable_key,
    })
}

pub(crate) fn authenticated_credential(
    context: AuthenticatedRequestContext,
    credential_policy_id: String,
    public_key_pem: Option<String>,
    stable_key: Option<Vec<u8>>,
) -> Auth {
    Auth {
        context,
        credential_policy_id,
        public_key_pem,
        stable_key,
    }
}

pub(crate) fn persisted_credential_context(
    user_id: String,
    workspace_id: Option<String>,
) -> Result<AuthenticatedRequestContext, HeaderAuthError> {
    let workspace_id = workspace_id
        .and_then(|value| WorkspaceId::new(value).ok())
        .ok_or(HeaderAuthError::Denied)?;
    Ok(AuthenticatedRequestContext {
        user_id,
        workspace_id,
    })
}

impl From<SigV4Error> for HeaderAuthError {
    fn from(error: SigV4Error) -> Self {
        match error {
            SigV4Error::Payload(error) => Self::InvalidPayload(error),
            _ => Self::Denied,
        }
    }
}

pub(crate) fn authentication_error_response(
    key: &str,
    error: HeaderAuthError,
) -> axum::response::Response {
    match error {
        HeaderAuthError::Denied => s3_error::signature_mismatch(key),
        HeaderAuthError::InvalidPayload(error) => {
            s3_error::invalid_request(key, &error.to_string())
        }
        HeaderAuthError::CredentialStoreUnavailable(detail) => {
            drop(detail);
            warn!(
                error_category = "persistence",
                "credential storage unavailable during authentication"
            );
            s3_error::service_unavailable(key, "credential storage is temporarily unavailable")
        }
        HeaderAuthError::Unavailable(detail) => {
            drop(detail);
            warn!(
                error_category = "persistence",
                "workspace resolution failed"
            );
            s3_error::service_unavailable(key, "workspace storage is temporarily unavailable")
        }
    }
}

pub(crate) async fn authenticate_headers(
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    keys: &Arc<dyn KeyRepository>,
    state: &AppState,
) -> Result<HeaderAuthentication, HeaderAuthError> {
    if let Ok(auth) = TRUSTED_INVOCATION.try_with(|value| value.auth.clone()) {
        return Ok(HeaderAuthentication::without_body(auth));
    }
    customer_headers::validate_all(headers).map_err(|_| HeaderAuthError::Denied)?;
    if let Some(sigv4) = RequestAuthorization::parse(uri, headers).map_err(HeaderAuthError::from)? {
        // AUTH_DISABLED is an explicit local-only bypass retained for the
        // development S3 front door. Production always takes the strict
        // authorization and integrity path below.
        if state.auth_disabled {
            return Ok(HeaderAuthentication::without_body(
                authenticated_request(
                    state,
                    "demo-user".to_string(),
                    "local-demo".to_string(),
                    None,
                    None,
                )
                .await?,
            ));
        }
        let key = keys
            .get_key(sigv4.access_key())
            .await
            .map_err(|error| HeaderAuthError::CredentialStoreUnavailable(error.to_string()))?
            .ok_or(HeaderAuthError::Denied)?;
        if key_expired(key.expires_at.as_deref()) {
            return Err(HeaderAuthError::Denied);
        }
        let secret = keys
            .decrypt_secret(sigv4.access_key())
            .await
            .map_err(|error| HeaderAuthError::CredentialStoreUnavailable(error.to_string()))?
            .ok_or(HeaderAuthError::Denied)?;
        let body_verifier = sigv4
            .authorize(
                method,
                uri,
                headers,
                &secret,
                &state.sigv4_cache,
                &state.sigv4_policy,
                SystemTime::now(),
            )
            .map_err(HeaderAuthError::from)?;
        return Ok(HeaderAuthentication {
            auth: authenticated_credential(
                persisted_credential_context(key.user_id.clone(), key.workspace_id.clone())?,
                key.key_id.clone(),
                key.public_key_pem.clone(),
                Some(derive_stable_key(&secret)),
            ),
            body_verifier: Some(body_verifier),
        });
    }

    let auth = headers.get("Authorization").and_then(|v| v.to_str().ok());
    match auth {
        Some(a) if a.starts_with("Bearer ") => {
            let token = &a[7..];
            // MCP bearer token (maskura_mcp_...): a self-contained credential.
            if token.starts_with("maskura_mcp_") {
                let context = keys.resolve_mcp_token(token).await.map_err(|error| {
                    HeaderAuthError::CredentialStoreUnavailable(error.to_string())
                })?;
                if let Some(principal) = context {
                    return Ok(HeaderAuthentication::without_body(
                        authenticated_credential(
                            principal.context,
                            principal.credential_policy_id,
                            None,
                            None,
                        ),
                    ));
                }
                return Err(HeaderAuthError::Denied);
            }
            // Try API key format: Bearer maskura_xxx:maskura_secret_xxx
            if let Some((ak, sk)) = token.split_once(':') {
                let (context, public_key_pem) = keys
                    .resolve_credentials(ak, sk)
                    .await
                    .map_err(|error| {
                        HeaderAuthError::CredentialStoreUnavailable(error.to_string())
                    })?
                    .ok_or(HeaderAuthError::Denied)?;
                return Ok(HeaderAuthentication::without_body(
                    authenticated_credential(
                        context,
                        ak.to_string(),
                        public_key_pem,
                        Some(derive_stable_key(sk)),
                    ),
                ));
            }
            // Try JWT
            if state.jwt_decoder.is_some() {
                let uid = get_user_id(headers, state);
                if uid != "demo-user" {
                    return Ok(HeaderAuthentication::without_body(
                        authenticated_request(state, uid, "jwt".to_string(), None, None).await?,
                    ));
                }
            }
            return Err(HeaderAuthError::Denied);
        }
        _ => {}
    };
    // Canonical and legacy MCP headers resolve to one credential value.
    if let Some(tok) = customer_headers::validated(headers, customer_headers::MCP_TOKEN)
        .and_then(|v| v.to_str().ok())
    {
        let context = if tok.starts_with("maskura_mcp_") {
            keys.resolve_mcp_token(tok)
                .await
                .map_err(|error| HeaderAuthError::CredentialStoreUnavailable(error.to_string()))?
        } else {
            None
        };
        if let Some(principal) = context {
            return Ok(HeaderAuthentication::without_body(
                authenticated_credential(
                    principal.context,
                    principal.credential_policy_id,
                    None,
                    None,
                ),
            ));
        }
        return Err(HeaderAuthError::Denied);
    }
    let ak = customer_headers::validated(headers, customer_headers::ACCESS_KEY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let sk = customer_headers::validated(headers, customer_headers::SECRET_KEY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let resolved = keys
        .resolve_credentials(ak, sk)
        .await
        .map_err(|error| HeaderAuthError::CredentialStoreUnavailable(error.to_string()))?;
    if let Some((context, public_key_pem)) = resolved {
        return Ok(HeaderAuthentication::without_body(
            authenticated_credential(
                context,
                ak.to_string(),
                public_key_pem,
                Some(derive_stable_key(sk)),
            ),
        ));
    }
    // Allow access in demo mode only when auth is explicitly disabled or
    // when using an in-memory keystore with no keys (dev/first-run mode).
    // Never allow unauthenticated access when keys are persisted — this
    // prevents an empty database from becoming an open door in production.
    if state.auth_disabled {
        return Ok(HeaderAuthentication::without_body(
            authenticated_request(
                state,
                "demo-user".to_string(),
                "local-demo".to_string(),
                None,
                None,
            )
            .await?,
        ));
    }
    Err(HeaderAuthError::Denied)
}

pub(crate) async fn authenticate(
    method: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    keys: &Arc<dyn KeyRepository>,
    state: &AppState,
) -> Result<Auth, HeaderAuthError> {
    authenticate_headers(method, uri, headers, keys, state)
        .await?
        .verify_body(body)
        .map_err(HeaderAuthError::InvalidPayload)
}

pub(crate) fn key_expired(expires_at: Option<&str>) -> bool {
    if let Some(exp) = expires_at {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if exp.parse::<u64>().is_ok_and(|ts| now >= ts) {
            return true;
        }
    }
    false
}

pub(crate) fn get_user_id(headers: &HeaderMap, state: &AppState) -> String {
    match get_user_claims(headers, state) {
        Some(claims) => claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("demo-user")
            .to_string(),
        None => "demo-user".to_string(),
    }
}

pub(crate) fn supabase_jwt_validation(
    algorithm: jsonwebtoken::Algorithm,
    issuer: &str,
) -> jsonwebtoken::Validation {
    let mut validation = jsonwebtoken::Validation::new(algorithm);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&["authenticated"]);
    validation.validate_exp = true;
    validation
}

/// Resolve and validate the authenticated user's Supabase claims.
pub async fn require_user_claims(
    headers: &HeaderMap,
    state: &AppState,
) -> Option<serde_json::Value> {
    if state.auth_disabled {
        return Some(serde_json::json!({
            "sub": "demo-user",
            "email": "",
            "app_metadata": { "provider": "demo" },
        }));
    }
    if let Some(claims) = verify_jwks_claims(headers, state).await {
        return Some(claims);
    }
    get_user_claims(headers, state)
}

/// Resolve the authenticated user id, or `None` when the request is not
/// authenticated. When auth is disabled (local/demo mode) this is permissive
/// and returns the demo user. When auth is enabled (production SaaS) an
/// unauthenticated request returns `None` so callers can reject with 401.
/// Accepts both ES256 (Supabase OAuth access tokens, via JWKS) and HS256
/// (email/password sessions, via the JWT secret).
pub async fn require_user_id(headers: &HeaderMap, state: &AppState) -> Option<String> {
    let claims = require_user_claims(headers, state).await?;
    let sub = claims.get("sub")?.as_str()?;
    if sub.is_empty() {
        return None;
    }
    Some(sub.to_string())
}

/// Verify a Supabase ES256 access token against the project JWKS and return
/// its `sub`. Uses the async client (safe in tokio handlers).
#[allow(clippy::type_complexity)]
pub(crate) async fn verify_jwks_claims(
    headers: &HeaderMap,
    state: &AppState,
) -> Option<serde_json::Value> {
    use std::sync::OnceLock;
    use std::time::Instant;

    static CACHE: OnceLock<std::sync::Mutex<Option<(String, Vec<serde_json::Value>, Instant)>>> =
        OnceLock::new();

    let auth = headers.get("Authorization").and_then(|v| v.to_str().ok())?;
    let token = auth.strip_prefix("Bearer ")?;
    let header = jsonwebtoken::decode_header(token).ok()?;
    let kid = header.kid.as_deref()?;
    let issuer = format!("{}/auth/v1", state.supabase_url.trim_end_matches('/'));
    let jwks_url = format!("{}/.well-known/jwks.json", issuer);

    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(None));
    {
        let stale = {
            let guard = cache.lock().ok()?;
            match &*guard {
                Some((url, _, at)) => {
                    url != &jwks_url || at.elapsed() > Duration::from_secs(6 * 60 * 60)
                }
                None => true,
            }
        };
        if stale {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .ok()?;
            let resp = client.get(&jwks_url).send().await.ok()?;
            let body: serde_json::Value = resp.json().await.ok()?;
            let keys = body.get("keys")?.as_array()?.clone();
            let mut guard = cache.lock().ok()?;
            *guard = Some((jwks_url, keys, Instant::now()));
        }
    }
    let guard = cache.lock().ok()?;
    let (_, keys, _) = guard.as_ref()?;
    let key = keys
        .iter()
        .find(|k| k.get("kid").and_then(|v| v.as_str()) == Some(kid))?;
    let x = key.get("x")?.as_str()?;
    let y = key.get("y")?.as_str()?;
    let pem = engine_ec_pem(x, y)?;

    let decoding_key = jsonwebtoken::DecodingKey::from_ec_pem(pem.as_bytes()).ok()?;
    let validation = supabase_jwt_validation(jsonwebtoken::Algorithm::ES256, &issuer);
    let data = jsonwebtoken::decode::<serde_json::Value>(token, &decoding_key, &validation).ok()?;
    Some(data.claims)
}

/// Build an EC public-key PEM (SPKI) from base64url JWK x/y coordinates.
pub(crate) fn engine_ec_pem(x: &str, y: &str) -> Option<String> {
    use base64::Engine;
    let xb = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(x)
        .ok()?;
    let yb = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(y)
        .ok()?;
    if xb.len() != 32 || yb.len() != 32 {
        return None;
    }
    let alg_id = [
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];
    let mut bit_string = vec![0x00];
    bit_string.push(0x04);
    bit_string.extend_from_slice(&xb);
    bit_string.extend_from_slice(&yb);
    let bit_len = bit_string.len();
    let mut bit_tlv = vec![0x03];
    bit_tlv.push(if bit_len < 128 {
        bit_len as u8
    } else {
        return None;
    });
    bit_tlv.extend_from_slice(&bit_string);
    let body_len = alg_id.len() + bit_tlv.len();
    let mut spki = vec![0x30];
    spki.push(if body_len < 128 {
        body_len as u8
    } else {
        return None;
    });
    spki.extend_from_slice(&alg_id);
    spki.extend_from_slice(&bit_tlv);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&spki);
    Some(format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        b64.as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

/// Decode and validate the Supabase JWT, returning its claims.
pub(crate) fn get_user_claims(headers: &HeaderMap, state: &AppState) -> Option<serde_json::Value> {
    let auth = headers.get("Authorization").and_then(|v| v.to_str().ok());
    let token = match auth {
        Some(a) if a.starts_with("Bearer ") => &a[7..],
        _ => return None,
    };

    let key = state.jwt_decoder.as_ref()?;
    let issuer = format!("{}/auth/v1", state.supabase_url.trim_end_matches('/'));
    let validation = supabase_jwt_validation(jsonwebtoken::Algorithm::HS256, &issuer);
    match jsonwebtoken::decode::<serde_json::Value>(token, key, &validation) {
        Ok(data) => Some(data.claims),
        Err(_) => {
            warn!(error_category = "invalid_token", "JWT validation failed");
            None
        }
    }
}

pub(crate) async fn get_me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(claims) = require_user_claims(&headers, &state).await else {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    let Some(user_id) = claims.get("sub").and_then(|v| v.as_str()) else {
        return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
    };
    let email = claims
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let provider = claims
        .get("app_metadata")
        .and_then(|m| m.get("provider"))
        .and_then(|v| v.as_str())
        .unwrap_or("email")
        .to_string();
    let keys = match state.keys.list_for_user(user_id).await {
        Ok(keys) => keys,
        Err(_) => {
            tracing::error!(
                error_category = "persistence",
                "credential storage unavailable"
            );
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    Json(serde_json::json!({
        "user_id": user_id,
        "email": email,
        "provider": provider,
        "keys": keys.len(),
    }))
    .into_response()
}
