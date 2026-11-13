//! S3 Multi-Object Delete (`POST /{bucket}?delete`) and the shared single-key
//! gated delete pipeline it wraps.
//!
//! A DeleteObjects batch of N keys is N policy-gated, receipted deletes
//! presented under one S3 request: per key the exact single-delete pipeline
//! runs (authorization grant → policy verdict → storage delete → usage
//! receipt). There is no averaged authorization and no silent outcome: every
//! key lands in the response as `<Deleted>` or `<Error>`.
//!
//! Systemic failures (authentication, malformed XML, oversized bodies) fail
//! the request before any key is touched. The batch is idempotent: a missing
//! key reports `<Deleted>`, exactly like S3.
//!
//! The request body is parsed as the small DeleteObjects grammar only (no
//! general XML resolver): DTDs, entity declarations, comments, and CDATA are
//! rejected outright, and only XML's predefined and numeric character
//! references are decoded. `VersionId`/MFA delete are rejected (versioning is
//! an unsupported subresource).

use super::*;

use crate::control::{AuthorizationDecision, BlockReason};
use crate::managed::ManagedDeleteError;
use crate::policy_gate::{PolicyRequest, enforce_policy, policy_error_response};
use crate::s3_safety::{S3Failure, S3Missing, record_s3_client_failure};
use maskura_error::MaskuraError;
use maskura_pipeline_config::PolicyOperation;

/// S3's own Multi-Object Delete caps: at most 1000 keys per request and at
/// most 128 KiB of XML body. Both are enforced before any key is touched.
pub(crate) const MAX_DELETE_OBJECTS_KEYS: usize = 1000;
pub(crate) const MAX_DELETE_OBJECTS_XML_BYTES: usize = 128 * 1024;

/// A parsed DeleteObjects request: the Quiet flag and the key list in
/// document order.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DeleteObjectsRequest {
    pub(crate) quiet: bool,
    pub(crate) keys: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DeleteObjectsXmlError {
    /// The document is not a well-formed DeleteObjects request.
    Malformed(&'static str),
    /// The document lists more than [`MAX_DELETE_OBJECTS_KEYS`] keys.
    TooManyKeys,
    /// The document exceeds [`MAX_DELETE_OBJECTS_XML_BYTES`].
    BodyTooLarge,
}

impl From<&'static str> for DeleteObjectsXmlError {
    fn from(detail: &'static str) -> Self {
        Self::Malformed(detail)
    }
}

impl DeleteObjectsXmlError {
    fn response(self, bucket: &str) -> axum::response::Response {
        match self {
            Self::Malformed(detail) => s3_error::malformed_xml(bucket, detail),
            Self::TooManyKeys => {
                s3_error::malformed_xml(bucket, "The Delete request supports at most 1000 keys.")
            }
            Self::BodyTooLarge => s3_error::entity_too_large(bucket),
        }
    }
}

/// Decode one run of element text. Only XML's five predefined entities and
/// numeric character references are accepted; everything else (including any
/// entity that a DTD could have declared) is rejected, so no entity expansion
/// is possible.
fn decode_delete_xml_text(text: &str) -> Result<String, &'static str> {
    decode_complete_xml_text(text)
        .map_err(|_| "invalid XML entity or character reference in the Delete request")
}

/// Validate the attribute remainder of an open tag. Only `xmlns` namespace
/// declarations are accepted (SDKs commonly carry the S3 namespace on the
/// root); every other attribute is rejected fail-closed.
fn validate_delete_xml_attributes(rest: &str) -> Result<(), &'static str> {
    let mut remaining = rest.trim();
    while !remaining.is_empty() {
        let name_end = remaining
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '-' | '.')))
            .unwrap_or(remaining.len());
        let name = &remaining[..name_end];
        if !(name == "xmlns" || name.starts_with("xmlns:")) {
            return Err("unexpected attribute on a Delete XML element");
        }
        remaining = remaining[name_end..].trim_start();
        let Some(after_eq) = remaining.strip_prefix('=') else {
            return Err("malformed attribute on a Delete XML element");
        };
        remaining = after_eq.trim_start();
        let quote = match remaining.chars().next() {
            Some(q @ ('"' | '\'')) => q,
            _ => return Err("unquoted attribute on a Delete XML element"),
        };
        remaining = &remaining[1..];
        let Some(value_end) = remaining.find(quote) else {
            return Err("unterminated attribute on a Delete XML element");
        };
        remaining = remaining[value_end + 1..].trim_start();
    }
    Ok(())
}

/// Strictly parse the small DeleteObjects grammar instead of using a general
/// XML resolver. DTDs, comments, and CDATA are rejected outright (`<!`),
/// self-closing elements are not allowed, and anything outside
/// `<Delete>(<Quiet>|<Object><Key>…</Key></Object>)</Delete>` fails the whole
/// request before any key is touched.
pub(crate) fn parse_delete_objects_xml(
    body: &[u8],
) -> Result<DeleteObjectsRequest, DeleteObjectsXmlError> {
    if body.len() > MAX_DELETE_OBJECTS_XML_BYTES {
        return Err(DeleteObjectsXmlError::BodyTooLarge);
    }
    let input = std::str::from_utf8(body)
        .map_err(|_| DeleteObjectsXmlError::Malformed("Delete XML must be UTF-8"))?;
    if input.contains("<!") {
        return Err(DeleteObjectsXmlError::Malformed(
            "Delete XML entities and DTDs are prohibited",
        ));
    }
    let mut stack = Vec::<String>::new();
    let mut keys = Vec::<String>::new();
    let mut quiet: Option<bool> = None;
    let mut current_key: Option<String> = None;
    let mut current_quiet_text: Option<String> = None;
    let mut root_started = false;
    let mut root_closed = false;
    let mut cursor = 0;
    while cursor < input.len() {
        let open = input[cursor..]
            .find('<')
            .map(|index| cursor + index)
            .ok_or(DeleteObjectsXmlError::Malformed("malformed Delete XML"))?;
        // Element text: verbatim inside <Key> (S3 keys preserve whitespace),
        // whitespace-only between all other elements.
        let raw_text = &input[cursor..open];
        match stack.last().map(String::as_str) {
            Some("Key") => {
                let decoded = decode_delete_xml_text(raw_text)?;
                if let Some(key) = current_key.as_mut() {
                    key.push_str(&decoded);
                }
            }
            Some("Quiet") => {
                let decoded = decode_delete_xml_text(raw_text.trim())?;
                if !decoded.is_empty()
                    && let Some(text) = current_quiet_text.as_mut()
                {
                    text.push_str(&decoded);
                }
            }
            _ => {
                if !raw_text.trim().is_empty() {
                    return Err(DeleteObjectsXmlError::Malformed(
                        "unexpected XML character data in the Delete request",
                    ));
                }
            }
        }
        let close = input[open..]
            .find('>')
            .map(|index| open + index)
            .ok_or(DeleteObjectsXmlError::Malformed("malformed Delete XML"))?;
        let raw = input[open + 1..close].trim();
        cursor = close + 1;
        if root_closed {
            return Err(DeleteObjectsXmlError::Malformed(
                "multiple Delete XML roots",
            ));
        }
        if raw.starts_with('?') && raw.ends_with('?') {
            if !stack.is_empty() || root_started {
                return Err(DeleteObjectsXmlError::Malformed(
                    "XML declaration is not at the beginning",
                ));
            }
            continue;
        }
        if let Some(close_tag) = raw.strip_prefix('/') {
            let name = close_tag.trim().rsplit(':').next().unwrap_or_default();
            if stack.last().map(String::as_str) != Some(name) {
                return Err(DeleteObjectsXmlError::Malformed(
                    "mismatched Delete XML element",
                ));
            }
            stack.pop();
            match name {
                "Delete" => root_closed = true,
                "Object" => {
                    let key = current_key
                        .take()
                        .ok_or(DeleteObjectsXmlError::Malformed("Object is missing Key"))?;
                    keys.push(key);
                    if keys.len() > MAX_DELETE_OBJECTS_KEYS {
                        return Err(DeleteObjectsXmlError::TooManyKeys);
                    }
                }
                "Quiet" => {
                    let text = current_quiet_text.take().unwrap_or_default();
                    if quiet
                        .replace(match text.trim().to_ascii_lowercase().as_str() {
                            "true" | "1" => true,
                            "false" | "0" => false,
                            _ => {
                                return Err(DeleteObjectsXmlError::Malformed(
                                    "Quiet must be true or false",
                                ));
                            }
                        })
                        .is_some()
                    {
                        return Err(DeleteObjectsXmlError::Malformed("duplicate Quiet element"));
                    }
                }
                _ => {}
            }
            continue;
        }
        if raw.ends_with('/') {
            return Err(DeleteObjectsXmlError::Malformed(
                "self-closing Delete XML elements are not allowed",
            ));
        }
        let mut parts = raw.split_ascii_whitespace();
        let name = parts
            .next()
            .unwrap_or_default()
            .rsplit(':')
            .next()
            .unwrap_or_default();
        validate_delete_xml_attributes(parts.collect::<Vec<_>>().join(" ").as_str())?;
        match (stack.len(), name) {
            (0, "Delete") if !root_started => {
                root_started = true;
                stack.push(name.to_string());
            }
            (1, "Object") if stack.last().map(String::as_str) == Some("Delete") => {
                current_key = None;
                current_quiet_text = None;
                stack.push(name.to_string());
            }
            (1, "Quiet") if stack.last().map(String::as_str) == Some("Delete") => {
                current_key = None;
                current_quiet_text = Some(String::new());
                stack.push(name.to_string());
            }
            (2, "Key") if stack.last().map(String::as_str) == Some("Object") => {
                if current_key.replace(String::new()).is_some() {
                    return Err(DeleteObjectsXmlError::Malformed(
                        "duplicate Key element in Object",
                    ));
                }
                stack.push(name.to_string());
            }
            _ => {
                return Err(DeleteObjectsXmlError::Malformed(
                    "unexpected Delete XML element",
                ));
            }
        }
    }
    if !root_started || !root_closed || !stack.is_empty() {
        return Err(DeleteObjectsXmlError::Malformed("malformed Delete XML"));
    }
    for key in &keys {
        if key.is_empty() {
            return Err(DeleteObjectsXmlError::Malformed(
                "Object Key must not be empty",
            ));
        }
    }
    Ok(DeleteObjectsRequest {
        quiet: quiet.unwrap_or(false),
        keys,
    })
}

/// Per-key outcome in a DeleteObjects response.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BatchKeyOutcome {
    Deleted,
    Failed { code: &'static str, message: String },
}

/// Escape a value for element text in a DeleteObjects response document,
/// replacing characters that XML 1.0 cannot carry with U+FFFD.
fn escape_delete_xml_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            '\t'
            | '\n'
            | '\r'
            | '\u{20}'..='\u{d7ff}'
            | '\u{e000}'..='\u{fffd}'
            | '\u{10000}'..='\u{10ffff}' => output.push(character),
            _ => output.push('\u{fffd}'),
        }
    }
    output
}

fn push_delete_xml_element(output: &mut String, name: &str, value: &str) {
    output.push('<');
    output.push_str(name);
    output.push('>');
    output.push_str(&escape_delete_xml_text(value));
    output.push_str("</");
    output.push_str(name);
    output.push('>');
}

/// Assemble the standard `<DeleteResult>` envelope. `Quiet` suppresses
/// `<Deleted>` entries; `<Error>` entries are always present.
pub(crate) fn delete_objects_result_xml(
    outcomes: &[(String, BatchKeyOutcome)],
    quiet: bool,
) -> String {
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n",
    );
    for (key, outcome) in outcomes {
        match outcome {
            BatchKeyOutcome::Deleted => {
                if !quiet {
                    body.push_str("  <Deleted>");
                    push_delete_xml_element(&mut body, "Key", key);
                    body.push_str("</Deleted>\n");
                }
            }
            BatchKeyOutcome::Failed { code, message } => {
                body.push_str("  <Error>");
                push_delete_xml_element(&mut body, "Key", key);
                push_delete_xml_element(&mut body, "Code", code);
                push_delete_xml_element(&mut body, "Message", message);
                body.push_str("</Error>\n");
            }
        }
    }
    body.push_str("</DeleteResult>");
    body
}

/// A per-key failure on the gated single-object delete pipeline. Each variant
/// renders to exactly the S3 XML error document the single-key `DELETE
/// /{bucket}/{key}` path answers with, and to the matching per-key `<Error>`
/// entry inside a DeleteObjects response.
#[derive(Debug)]
pub(crate) enum DeleteKeyFailure {
    /// `control.authorize` blocked the operation (billing/quota). Carries the
    /// typed block reason.
    AuthorizationBlocked(BlockReason),
    /// `control.authorize` could not decide.
    AuthorizationUnavailable,
    /// Authorization returned a grant that does not match the request.
    InvalidGrant,
    /// Per-workspace backend resolution failed.
    BackendResolution,
    /// The policy gate rejected (or failed to bind) the delete.
    Policy(MaskuraError),
    /// The presigned backend destination was rejected by policy.
    PresignedRejected(String),
    /// The presigned DELETE answered with a non-success status.
    PresignedStatus(u16),
    /// The presigned DELETE could not reach the backend.
    PresignedTransport,
    /// The S3-compatible backend request failed.
    S3(S3Failure),
    /// Managed storage is in observe mode and mutations are disabled.
    ManagedObserveDisabled,
    /// The managed authoritative delete failed.
    ManagedDelete(ManagedDeleteError),
    /// The local file store delete failed.
    FileStore(String),
    /// The usage event for a completed delete could not be recorded.
    Metering(MeteringError),
    /// The usage reservation could not be released after a failed key.
    ReleaseUnavailable,
}

impl DeleteKeyFailure {
    /// Whether the single-key path releases the usage reservation before
    /// answering with this failure. Backend/metering failures past the
    /// reservation point keep the exact single-delete behavior.
    fn releases_grant(&self) -> bool {
        match self {
            Self::Policy(_)
            | Self::PresignedRejected(_)
            | Self::BackendResolution
            | Self::ManagedObserveDisabled => true,
            Self::ManagedDelete(error) => matches!(error, ManagedDeleteError::PreCommit(_)),
            _ => false,
        }
    }

    /// The S3 XML error document the single-key path answers with.
    pub(crate) fn response(self, bucket: &str, key: &str) -> axum::response::Response {
        match self {
            Self::AuthorizationBlocked(reason) => s3_error::payment_required(key, reason.message),
            Self::AuthorizationUnavailable => {
                s3_error::service_unavailable(key, "Authorization is temporarily unavailable.")
            }
            Self::InvalidGrant => {
                s3_error::service_unavailable(key, "Authorization returned an invalid grant.")
            }
            Self::BackendResolution => backend_resolution_error_response(key),
            Self::Policy(error) => policy_error_response(key, &error),
            Self::PresignedRejected(detail) => {
                open_error_response(bucket, key, OpenObjectError::Rejected(detail))
            }
            Self::PresignedStatus(status) => {
                s3_error::internal_error(key, &format!("presigned DELETE returned {}", status))
            }
            Self::PresignedTransport => {
                s3_error::internal_error(key, "presigned backend request failed")
            }
            Self::S3(failure) => s3_failure_response(bucket, key, failure),
            Self::ManagedObserveDisabled => {
                s3_error::service_unavailable(key, "managed mutations are disabled in observe mode")
            }
            Self::ManagedDelete(_) => {
                s3_error::internal_error(key, "The managed delete could not be completed.")
            }
            Self::FileStore(detail) => s3_error::internal_error(key, &detail),
            Self::Metering(error) => metering_error_response(key, error),
            Self::ReleaseUnavailable => s3_error::service_unavailable(
                key,
                "Authorization is temporarily unavailable while releasing the operation.",
            ),
        }
    }

    /// The per-key `<Code>`/`<Message>` pair inside a DeleteObjects response:
    /// the same document the single-key path renders, without the resource
    /// and request-id wrapper.
    pub(crate) fn entry(self) -> (&'static str, String) {
        match self {
            Self::AuthorizationBlocked(reason) => ("PaymentRequired", reason.message.to_string()),
            Self::AuthorizationUnavailable => (
                "ServiceUnavailable",
                "The service is temporarily unavailable.".to_string(),
            ),
            Self::InvalidGrant => (
                "ServiceUnavailable",
                "The service is temporarily unavailable.".to_string(),
            ),
            Self::BackendResolution | Self::ReleaseUnavailable => (
                "ServiceUnavailable",
                "The service is temporarily unavailable.".to_string(),
            ),
            Self::Policy(error) => match error.code() {
                maskura_error::codes::POLICY_DENIED
                | maskura_error::codes::POLICY_UNPROVISIONED
                | maskura_error::codes::POLICY_EXPIRED
                | maskura_error::codes::POLICY_TAMPERED => {
                    (error.code(), error.message().to_string())
                }
                _ => (
                    "InternalError",
                    "We encountered an internal error.".to_string(),
                ),
            },
            Self::PresignedRejected(_) => ("AccessDenied", "Access Denied".to_string()),
            Self::PresignedStatus(_) | Self::PresignedTransport | Self::FileStore(_) => (
                "InternalError",
                "We encountered an internal error.".to_string(),
            ),
            Self::S3(failure) => match failure.missing() {
                Some(S3Missing::Bucket) => (
                    "NoSuchBucket",
                    "The specified bucket does not exist.".to_string(),
                ),
                Some(S3Missing::Object) => {
                    ("NoSuchKey", "The specified key does not exist.".to_string())
                }
                None => (
                    "InternalError",
                    "We encountered an internal error.".to_string(),
                ),
            },
            Self::ManagedObserveDisabled => (
                "ServiceUnavailable",
                "The service is temporarily unavailable.".to_string(),
            ),
            Self::ManagedDelete(_) => (
                "InternalError",
                "We encountered an internal error.".to_string(),
            ),
            Self::Metering(error) => match error {
                MeteringError::Unavailable => (
                    "ServiceUnavailable",
                    "The service is temporarily unavailable.".to_string(),
                ),
                MeteringError::IdempotencyConflict => (
                    "InvalidRequest",
                    "The usage receipt conflicts with an existing usage event.".to_string(),
                ),
                MeteringError::Rejected => (
                    "PaymentRequired",
                    "The usage event was rejected.".to_string(),
                ),
            },
        }
    }
}

/// The authorization step of the gated delete: one fresh receipt identity and
/// one usage reservation per key. The batch presents one per listed key; the
/// single-key handler authorizes through the same request-level seam shared
/// with its multipart-abort branch.
pub(crate) async fn authorize_delete_key(
    state: &Arc<AppState>,
    auth: &Auth,
    bucket: &str,
) -> Result<AuthorizationGrant, DeleteKeyFailure> {
    let operation = request_operation_identity();
    let authorization =
        operation.authorization(bucket, UsageRoute::DeleteObject, RequestKind::Write, 0);
    let grant = match state.control.authorize(&auth.context, &authorization).await {
        Ok(AuthorizationDecision::Granted(grant)) if grant.matches(&authorization) => grant,
        Ok(AuthorizationDecision::Granted(_)) => return Err(DeleteKeyFailure::InvalidGrant),
        Ok(AuthorizationDecision::Blocked(reason)) => {
            return Err(DeleteKeyFailure::AuthorizationBlocked(reason));
        }
        Err(AuthorizationError::Unavailable) => {
            return Err(DeleteKeyFailure::AuthorizationUnavailable);
        }
    };
    Ok(grant)
}

/// The gated single-object delete pipeline: one key, one authorization grant,
/// one policy verdict, one storage delete, one usage receipt. This is the
/// exact body of the single-key `DELETE /{bucket}/{key}` handler and the
/// per-key unit of `POST /{bucket}?delete`.
///
/// Failures return a [`DeleteKeyFailure`]; the caller renders it as the
/// single-key error document or a per-key `<Error>` entry.
pub(crate) async fn delete_object_key(
    state: &Arc<AppState>,
    auth: &Auth,
    headers: &HeaderMap,
    bucket: &str,
    key: &str,
) -> Result<(), DeleteKeyFailure> {
    let grant = authorize_delete_key(state, auth, bucket).await?;
    info!(
        operation_id = %grant.operation_id(),
        receipt_id = %grant.receipt_id(),
        "DELETE authorized"
    );
    let failure = delete_authorized_object_key(state, auth, headers, bucket, key, &grant).await;
    let failure = match failure {
        Ok(()) => return Ok(()),
        Err(failure) => failure,
    };
    Err(release_failed_key(state.control.as_ref(), &auth.context, &grant, failure).await)
}

/// Release the usage reservation exactly when the single-key path does, and
/// fold a failed release into the typed release failure.
pub(crate) async fn release_failed_key(
    control: &dyn ControlPlane,
    context: &AuthenticatedRequestContext,
    grant: &AuthorizationGrant,
    failure: DeleteKeyFailure,
) -> DeleteKeyFailure {
    if failure.releases_grant()
        && let Err(AuthorizationError::Unavailable) =
            control.release(context, grant.operation_id()).await
    {
        warn!(
            operation_id = %grant.operation_id(),
            "usage reservation was not released"
        );
        return DeleteKeyFailure::ReleaseUnavailable;
    }
    failure
}

pub(crate) async fn delete_authorized_object_key(
    state: &Arc<AppState>,
    auth: &Auth,
    headers: &HeaderMap,
    bucket: &str,
    key: &str,
    grant: &AuthorizationGrant,
) -> Result<(), DeleteKeyFailure> {
    let mut selection = resolve_backend(state, auth, headers, StorageOperation::Delete)
        .await
        .map_err(|_| DeleteKeyFailure::BackendResolution)?;
    freeze_read_placement(&mut selection, auth.workspace_id().as_str(), bucket, key).await;
    let backend = &selection.backend;
    let policy = enforce_policy(
        state.policy_gate.as_ref(),
        PolicyRequest {
            workspace_id: auth.workspace_id().as_str(),
            operation: PolicyOperation::Delete,
            bucket,
            key,
            resolution: None,
            destination: backend,
            snapshot: &selection.snapshot,
            direction: crate::pipeline::PipelineDirection::Write,
            frozen: None,
        },
    )
    .await
    .map_err(DeleteKeyFailure::Policy)?;
    if let Err(error) = crate::policy_gate::consume_policy(&policy, &selection.snapshot) {
        return Err(DeleteKeyFailure::Policy(error));
    }
    match backend {
        ResolvedBackend::PresignedHttp(url) => {
            let client = state
                .presigned_http_policy
                .client_for_destination(url, Duration::from_secs(30))
                .await
                .map_err(|error| DeleteKeyFailure::PresignedRejected(error.to_string()))?;
            match client.delete(url.clone()).send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => {
                    return Err(DeleteKeyFailure::PresignedStatus(
                        response.status().as_u16(),
                    ));
                }
                Err(error) => {
                    let failure = PresignedTransportFailure::from_reqwest(&error);
                    warn!(
                        category = failure.as_str(),
                        "presigned DELETE transport failed"
                    );
                    return Err(DeleteKeyFailure::PresignedTransport);
                }
            }
        }
        ResolvedBackend::S3 { client, .. } => {
            if let Err(error) = client.delete_object().bucket(bucket).key(key).send().await {
                let failure = record_s3_client_failure("delete_object", &error);
                return Err(DeleteKeyFailure::S3(failure));
            }
        }
        ResolvedBackend::Managed(storage) => {
            if storage.managed_mode() == ManagedStreamingMode::Observe {
                return Err(DeleteKeyFailure::ManagedObserveDisabled);
            }
            let result = match storage.managed_mode() {
                ManagedStreamingMode::Off => storage
                    .delete(&format!("{}/{bucket}/{key}", auth.workspace_id().as_str()))
                    .await
                    .map_err(|error| {
                        crate::managed::ManagedDeleteError::PreCommit(
                            crate::managed::ManagedError::Persistence(error.to_string()),
                        )
                    }),
                ManagedStreamingMode::Observe => unreachable!("handled above"),
                ManagedStreamingMode::Enforce => {
                    storage
                        .delete_authoritative(
                            &managed_logical_key(auth, bucket, key),
                            grant.operation_id(),
                            grant.receipt_id(),
                            grant.occurred_at().timestamp_micros(),
                            grant.rate_version(),
                            grant.max_processed_bytes(),
                        )
                        .await
                }
            };
            if let Err(error) = result {
                return Err(DeleteKeyFailure::ManagedDelete(error));
            }
            record_delete_usage(state, auth, grant).await?;
            if storage.managed_mode() == ManagedStreamingMode::Enforce
                && let Err(_) = storage
                    .mark_authoritative_delete_settled(grant.operation_id(), grant.receipt_id())
                    .await
            {
                warn!(
                    operation_id = %grant.operation_id(),
                    error_category = "persistence",
                    "durable managed DELETE settlement remains pending"
                );
            }
            return Ok(());
        }
        ResolvedBackend::File(store) => {
            if let Err(error) = store.delete(bucket, key).await {
                return Err(DeleteKeyFailure::FileStore(error.to_string()));
            }
        }
        ResolvedBackend::Memory(store) => {
            store.delete(bucket, key);
        }
    }
    record_delete_usage(state, auth, grant).await
}

/// Record the per-key usage receipt (`UsageRoute::DeleteObject`) after the
/// storage delete, exactly like the single-key path.
async fn record_delete_usage(
    state: &Arc<AppState>,
    auth: &Auth,
    grant: &AuthorizationGrant,
) -> Result<(), DeleteKeyFailure> {
    let event = OperationUsage {
        grant,
        source_bytes: 0,
        output_bytes: 0,
    }
    .event();
    let _ = TRUSTED_INVOCATION.try_with(|invocation| {
        invocation
            .committed
            .store(true, std::sync::atomic::Ordering::Release);
    });
    state
        .control
        .record(&auth.context, &event)
        .await
        .map_err(|error| {
            warn!(event_id = %event.receipt_id(), ?error, "usage event was not recorded");
            DeleteKeyFailure::Metering(error)
        })
}

/// `POST /{bucket}?delete` — S3 Multi-Object Delete. Systemic failures fail
/// the request before any key is touched; per-key outcomes land in the
/// `<DeleteResult>` envelope.
pub(crate) async fn s3_delete_objects(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    request: Request,
) -> impl IntoResponse {
    let (parts, body) = request.into_parts();
    if !has_delete_subresource(parts.uri.query()) {
        return s3_error::not_implemented(&bucket);
    }
    let authentication = match authenticate_headers(
        parts.method.as_str(),
        &parts.uri,
        &parts.headers,
        &state.keys,
        &state,
    )
    .await
    {
        Ok(authentication) => authentication,
        Err(error) => return authentication_error_response(&bucket, error),
    };
    if let Some(response) = client_metering_id_rejection(&parts.headers, &bucket) {
        return response;
    }
    let (auth, body) =
        match read_verified_body(authentication, body, MAX_DELETE_OBJECTS_XML_BYTES).await {
            Ok(value) => value,
            Err(VerifiedBodyError::TooLarge) => {
                return DeleteObjectsXmlError::BodyTooLarge.response(&bucket);
            }
            Err(VerifiedBodyError::Integrity(error)) => {
                return s3_error::bad_digest(&bucket, &error.to_string());
            }
            Err(VerifiedBodyError::Transport) => {
                return s3_error::invalid_request(&bucket, "DeleteObjects request body failed");
            }
        };
    let mut content_md5 = match ContentMd5Verifier::from_headers(&parts.headers) {
        Ok(verifier) => verifier,
        Err(error) => return s3_error::bad_digest(&bucket, &error.to_string()),
    };
    if let Some(verifier) = &mut content_md5 {
        verifier.update(&body);
    }
    if let Some(verifier) = content_md5
        && let Err(error) = verifier.finish()
    {
        return s3_error::bad_digest(&bucket, &error.to_string());
    }
    // Parsing (and every cap) completes before any key is touched.
    let request = match parse_delete_objects_xml(&body) {
        Ok(request) => request,
        Err(error) => return error.response(&bucket),
    };
    let mut outcomes = Vec::with_capacity(request.keys.len());
    for key in &request.keys {
        let outcome = match delete_object_key(&state, &auth, &parts.headers, &bucket, key).await {
            Ok(()) => BatchKeyOutcome::Deleted,
            Err(failure) => {
                let (code, message) = failure.entry();
                BatchKeyOutcome::Failed { code, message }
            }
        };
        outcomes.push((key.clone(), outcome));
    }
    s3_xml_ok(delete_objects_result_xml(&outcomes, request.quiet))
}

/// Whether the request carries the `delete` subresource (`?delete` or
/// `?delete=`).
pub(crate) fn has_delete_subresource(query: Option<&str>) -> bool {
    query.is_some_and(|query| {
        query
            .split('&')
            .any(|pair| pair.split('=').next().unwrap_or(pair) == "delete")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(body: &str) -> Result<DeleteObjectsRequest, DeleteObjectsXmlError> {
        parse_delete_objects_xml(body.as_bytes())
    }

    #[test]
    fn parses_the_documented_grammar() {
        let request = parse(
            "<Delete><Object><Key>a.txt</Key></Object><Object><Key>b.txt</Key></Object></Delete>",
        )
        .expect("valid Delete document");
        assert!(!request.quiet);
        assert_eq!(request.keys, ["a.txt", "b.txt"]);
    }

    #[test]
    fn parses_quiet_anywhere_in_the_document() {
        for body in [
            "<Delete><Quiet>true</Quiet><Object><Key>k</Key></Object></Delete>",
            "<Delete><Object><Key>k</Key></Object><Quiet>true</Quiet></Delete>",
            "<Delete><Quiet>True</Quiet><Object><Key>k</Key></Object></Delete>",
            "<Delete><Quiet>1</Quiet><Object><Key>k</Key></Object></Delete>",
        ] {
            let request = parse(body).expect("valid Delete document");
            assert!(request.quiet, "{body}");
        }
        for body in [
            "<Delete><Quiet>false</Quiet><Object><Key>k</Key></Object></Delete>",
            "<Delete><Quiet>0</Quiet><Object><Key>k</Key></Object></Delete>",
        ] {
            let request = parse(body).expect("valid Delete document");
            assert!(!request.quiet, "{body}");
        }
    }

    #[test]
    fn accepts_the_xml_declaration_and_sdk_namespace_declarations() {
        let request = parse(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Delete xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Object><Key>k</Key></Object></Delete>",
        )
        .expect("valid Delete document");
        assert_eq!(request.keys, ["k"]);
        let prefixed = parse(
            "<s3:Delete xmlns:s3=\"http://s3.amazonaws.com/doc/2006-03-01/\"><s3:Object><s3:Key>k</s3:Key></s3:Object></s3:Delete>",
        )
        .expect("prefixed Delete document");
        assert_eq!(prefixed.keys, ["k"]);
    }

    #[test]
    fn preserves_key_whitespace_verbatim() {
        let request = parse("<Delete><Object><Key>  spaced\tkey\n</Key></Object></Delete>")
            .expect("valid Delete document");
        assert_eq!(request.keys, ["  spaced\tkey\n"]);
    }

    #[test]
    fn decodes_predefined_and_numeric_character_references_in_keys() {
        let request = parse(
            "<Delete><Object><Key>a&amp;b&lt;c&gt;d&quot;e&apos;f&#x2f;g&#32;</Key></Object></Delete>",
        )
        .expect("valid Delete document");
        assert_eq!(request.keys, ["a&b<c>d\"e'f/g "]);
    }

    #[test]
    fn rejects_malformed_documents() {
        let malformed = [
            "",
            "not xml",
            "<Delete>",
            "</Delete>",
            "<Delete><Object><Key>k</Key></Object>",
            "<Delete></Quiet></Delete>",
            "<Delete><Object><Key>k</Key></Object></Delete></Delete>",
            "<Delete><Object><Key>k</Key></Object></Delete><Delete></Delete>",
            "<Delete><Object><Key>k</Key></Object></Delete>trailing",
            "<Delete><Object><Key>k</Key></Object><Mystery/></Delete>",
            "<Delete><Object><Key>k</Key><Key>j</Key></Object></Delete>",
            "<Delete><Object></Object></Delete>",
            "<Delete><Object><Key></Key></Object></Delete>",
            "<Delete><Object><Key/></Object></Delete>",
            "<Delete/>",
            "<Delete><Object><Key>k</Key></Object><Quiet>true</Quiet><Quiet>false</Quiet></Delete>",
            "<Delete><Quiet>yes</Quiet><Object><Key>k</Key></Object></Delete>",
            "<Delete><Object><Key>k</Key></Object></Delete><?pi after?>",
            "<Delete attr=\"x\"><Object><Key>k</Key></Object></Delete>",
            "<Delete><Object onclick=\"x\"><Key>k</Key></Object></Delete>",
            "<Delete><Object><Key>k</Key></Object><Object><Key>k</Key><Quiet>true</Quiet></Object></Delete>",
        ];
        for body in malformed {
            assert!(parse(body).is_err(), "expected {body:?} to be rejected");
        }
    }

    #[test]
    fn rejects_versioned_and_mfa_delete_shapes() {
        for body in [
            "<Delete><Object><Key>k</Key><VersionId>v</VersionId></Object></Delete>",
            "<Delete><Object><Key>k</Key></Object><MFA>true</MFA></Delete>",
            "<Delete><Object><VersionId>v</VersionId></Object></Delete>",
        ] {
            assert!(parse(body).is_err(), "expected {body:?} to be rejected");
        }
    }

    #[test]
    fn rejects_entity_expansion_and_dtd_attacks() {
        for body in [
            "<!DOCTYPE Delete [<!ENTITY x \"boom\">]><Delete><Object><Key>&x;</Key></Object></Delete>",
            "<!DOCTYPE Delete><Delete><Object><Key>k</Key></Object></Delete>",
            "<Delete><Object><Key>&custom;</Key></Object></Delete>",
            "<Delete><Object><Key>&amp</Key></Object></Delete>",
            "<Delete><Object><Key>&#xZZ;</Key></Object></Delete>",
            "<Delete><Object><Key>&#999999999999;</Key></Object></Delete>",
            "<!-- <Delete><Object><Key>hidden</Key></Object></Delete> --><Delete><Object><Key>k</Key></Object></Delete>",
            "<Delete><Object><Key><![CDATA[<Delete>]]></Key></Object></Delete>",
        ] {
            assert!(parse(body).is_err(), "expected {body:?} to be rejected");
        }
    }

    #[test]
    fn accepts_repeated_keys_across_object_entries() {
        // S3 processes each listed entry; the batch is idempotent, so
        // repeated keys are accepted and each entry is answered.
        let request =
            parse("<Delete><Object><Key>k</Key></Object><Object><Key>k</Key></Object></Delete>")
                .expect("repeated keys across Object entries are accepted");
        assert_eq!(request.keys, ["k", "k"]);
    }

    #[test]
    fn accepts_an_empty_document_as_a_no_op() {
        let request = parse("<Delete></Delete>").expect("empty Delete document");
        assert!(request.keys.is_empty());
        assert!(!request.quiet);
    }

    #[test]
    fn enforces_the_thousand_key_cap() {
        let mut body = String::from("<Delete>");
        for index in 0..MAX_DELETE_OBJECTS_KEYS {
            body.push_str(&format!("<Object><Key>k{index}</Key></Object>"));
        }
        body.push_str("</Delete>");
        let accepted = parse(&body).expect("exactly 1000 keys are accepted");
        assert_eq!(accepted.keys.len(), MAX_DELETE_OBJECTS_KEYS);

        let mut body = String::from("<Delete>");
        for index in 0..(MAX_DELETE_OBJECTS_KEYS + 1) {
            body.push_str(&format!("<Object><Key>k{index}</Key></Object>"));
        }
        body.push_str("</Delete>");
        assert_eq!(
            parse(&body),
            Err(DeleteObjectsXmlError::TooManyKeys),
            "1001 keys must be rejected"
        );
    }

    #[test]
    fn enforces_the_body_size_cap_before_parsing() {
        let oversized = vec![b' '; MAX_DELETE_OBJECTS_XML_BYTES + 1];
        assert_eq!(
            parse_delete_objects_xml(&oversized),
            Err(DeleteObjectsXmlError::BodyTooLarge)
        );
    }

    #[test]
    fn quiet_suppresses_deleted_entries_but_never_error_entries() {
        let outcomes = vec![
            ("gone".to_string(), BatchKeyOutcome::Deleted),
            (
                "denied".to_string(),
                BatchKeyOutcome::Failed {
                    code: "AccessDenied",
                    message: "Access Denied".to_string(),
                },
            ),
        ];
        let loud = delete_objects_result_xml(&outcomes, false);
        assert!(loud.contains("<Deleted><Key>gone</Key></Deleted>"));
        assert!(loud.contains(
            "<Error><Key>denied</Key><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
        ));
        let quiet = delete_objects_result_xml(&outcomes, true);
        assert!(!quiet.contains("<Deleted>"));
        assert!(quiet.contains("<Error><Key>denied</Key>"));
    }

    #[test]
    fn envelope_escapes_keys_and_invalid_characters() {
        let outcomes = vec![(
            "</Key><Injected>&\"\u{1}".to_string(),
            BatchKeyOutcome::Deleted,
        )];
        let xml = delete_objects_result_xml(&outcomes, false);
        assert!(xml.contains("<Key>&lt;/Key&gt;&lt;Injected&gt;&amp;&quot;\u{fffd}</Key>"));
        assert!(!xml.contains("<Injected>"));
        let tokens: Vec<_> = xmlparser::Tokenizer::from(xml.as_str())
            .map(|token| token.expect("generated envelope must be well-formed XML"))
            .filter_map(|token| match token {
                xmlparser::Token::ElementStart { local, .. } => Some(local.as_str().to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(
            tokens,
            ["DeleteResult", "Deleted", "Key"],
            "the envelope must carry exactly the documented elements"
        );
    }

    #[test]
    fn envelope_shape_matches_the_s3_document() {
        let outcomes = vec![
            ("a".to_string(), BatchKeyOutcome::Deleted),
            (
                "b".to_string(),
                BatchKeyOutcome::Failed {
                    code: "InternalError",
                    message: "We encountered an internal error.".to_string(),
                },
            ),
        ];
        let xml = delete_objects_result_xml(&outcomes, false);
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"));
        assert!(xml.ends_with("</DeleteResult>"));
    }
}
