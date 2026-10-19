use std::fmt;
use std::time::Duration;

use aws_config::retry::RetryConfig;
use aws_config::timeout::TimeoutConfig;
use aws_smithy_runtime_api::client::result::SdkError;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;

const S3_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const S3_READ_TIMEOUT: Duration = Duration::from_secs(30);
const S3_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) fn s3_retry_config() -> RetryConfig {
    RetryConfig::standard().with_max_attempts(1)
}

pub(crate) fn s3_timeout_config() -> TimeoutConfig {
    TimeoutConfig::builder()
        .connect_timeout(S3_CONNECT_TIMEOUT)
        .read_timeout(S3_READ_TIMEOUT)
        .operation_attempt_timeout(S3_OPERATION_TIMEOUT)
        .operation_timeout(S3_OPERATION_TIMEOUT)
        .build()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum S3FailureCategory {
    Configuration,
    Timeout,
    Transport,
    Response,
    Provider,
    Request,
}

impl S3FailureCategory {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::Response => "response",
            Self::Provider => "provider",
            Self::Request => "request",
        }
    }

    fn client_message(self) -> &'static str {
        match self {
            Self::Configuration => "S3 backend request configuration failed",
            Self::Timeout => "S3 backend request timed out",
            Self::Transport => "S3 backend connection failed",
            Self::Response => "S3 backend returned an invalid response",
            Self::Provider => "S3 backend rejected the request",
            Self::Request => "S3 backend request failed",
        }
    }
}

/// Provider-reported condition that S3 itself surfaces to clients as a typed
/// 404 error document. Preserved so the S3 data plane can mirror S3 instead of
/// hiding these expected conditions behind `InternalError`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum S3Missing {
    Bucket,
    Object,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct S3Failure {
    category: S3FailureCategory,
    missing: Option<S3Missing>,
}

impl S3Failure {
    pub(crate) fn category(self) -> S3FailureCategory {
        self.category
    }

    pub(crate) fn missing(self) -> Option<S3Missing> {
        self.missing
    }

    fn with_missing(mut self, missing: Option<S3Missing>) -> Self {
        self.missing = missing;
        self
    }

    pub(crate) fn client_message(self) -> &'static str {
        self.category.client_message()
    }
}

impl fmt::Display for S3Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.client_message())
    }
}

impl std::error::Error for S3Failure {}

fn classify_s3_failure<E, R>(error: &SdkError<E, R>) -> S3Failure {
    let category = match error {
        SdkError::ConstructionFailure(_) => S3FailureCategory::Configuration,
        SdkError::TimeoutError(_) => S3FailureCategory::Timeout,
        SdkError::DispatchFailure(error) if error.is_timeout() => S3FailureCategory::Timeout,
        SdkError::DispatchFailure(_) => S3FailureCategory::Transport,
        SdkError::ResponseError(_) => S3FailureCategory::Response,
        SdkError::ServiceError(_) => S3FailureCategory::Provider,
        _ => S3FailureCategory::Request,
    };
    S3Failure {
        category,
        missing: None,
    }
}

/// Provider-documented missing conditions, keyed by the service error code S3
/// clients already understand (`NoSuchBucket`, `NoSuchKey`).
pub(crate) fn classify_provider_missing<E, R>(error: &SdkError<E, R>) -> Option<S3Missing>
where
    E: ProvideErrorMetadata,
{
    let SdkError::ServiceError(context) = error else {
        return None;
    };
    match context.err().code() {
        Some("NoSuchBucket") => Some(S3Missing::Bucket),
        Some("NoSuchKey") | Some("NotFound") => Some(S3Missing::Object),
        _ => None,
    }
}

/// [`record_s3_failure`] for requests answered with client-facing S3 error
/// documents: also preserves the provider's missing-object/bucket condition so
/// callers can mirror S3's own 404 responses.
pub(crate) fn record_s3_client_failure<E, R>(
    operation: &'static str,
    error: &SdkError<E, R>,
) -> S3Failure
where
    E: ProvideErrorMetadata,
{
    record_s3_failure(operation, error).with_missing(classify_provider_missing(error))
}

pub(crate) fn record_s3_failure<E, R>(
    operation: &'static str,
    error: &SdkError<E, R>,
) -> S3Failure {
    let failure = classify_s3_failure(error);
    tracing::warn!(
        operation,
        category = failure.category().as_str(),
        "S3 backend request failed"
    );
    failure
}

pub(crate) fn record_s3_body_failure(operation: &'static str) -> &'static str {
    tracing::warn!(
        operation,
        category = S3FailureCategory::Response.as_str(),
        "S3 backend response body failed"
    );
    "S3 backend response body failed"
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_runtime_api::client::result::ConnectorError;

    const SECRET: &str = "https://access-key@example.invalid/object?token=credential Authorization=AWS4-HMAC-SHA256 provider-body-secret";

    #[derive(Debug)]
    struct SecretError;

    impl fmt::Display for SecretError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(SECRET)
        }
    }

    impl std::error::Error for SecretError {}

    fn assert_redacted<E, R>(error: SdkError<E, R>, expected: S3FailureCategory) {
        let failure = classify_s3_failure(&error);
        assert_eq!(failure.category(), expected);
        let rendered = format!("{failure:?} {failure}");
        assert!(rendered.len() <= 96);
        for forbidden in [
            "example.invalid",
            "token=",
            "access-key",
            "Authorization",
            "AWS4-HMAC-SHA256",
            "provider-body-secret",
            "credential",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "leaked {forbidden}: {rendered}"
            );
        }
    }

    #[test]
    fn sdk_failure_categories_never_render_sources_or_provider_responses() {
        assert_redacted(
            SdkError::<SecretError, String>::construction_failure(SecretError),
            S3FailureCategory::Configuration,
        );
        assert_redacted(
            SdkError::<SecretError, String>::timeout_error(SecretError),
            S3FailureCategory::Timeout,
        );
        assert_redacted(
            SdkError::<SecretError, String>::dispatch_failure(ConnectorError::io(Box::new(
                SecretError,
            ))),
            S3FailureCategory::Transport,
        );
        assert_redacted(
            SdkError::<SecretError, String>::response_error(SecretError, SECRET.to_string()),
            S3FailureCategory::Response,
        );
        assert_redacted(
            SdkError::service_error(SecretError, SECRET.to_string()),
            S3FailureCategory::Provider,
        );
    }

    fn provider_error(code: &'static str) -> ProviderError {
        ProviderError {
            meta: aws_smithy_types::error::metadata::ErrorMetadata::builder()
                .code(code)
                .build(),
        }
    }

    struct ProviderError {
        meta: aws_smithy_types::error::metadata::ErrorMetadata,
    }

    impl ProvideErrorMetadata for ProviderError {
        fn code(&self) -> Option<&str> {
            self.meta.code()
        }

        fn meta(&self) -> &aws_smithy_types::error::metadata::ErrorMetadata {
            &self.meta
        }
    }

    #[test]
    fn provider_missing_conditions_are_preserved_for_s3_documents() {
        for (code, expected) in [
            ("NoSuchBucket", Some(S3Missing::Bucket)),
            ("NoSuchKey", Some(S3Missing::Object)),
            ("NotFound", Some(S3Missing::Object)),
            ("AccessDenied", None),
            ("", None),
        ] {
            let error = SdkError::service_error(provider_error(code), SECRET.to_string());
            let failure = record_s3_client_failure("list_objects_v2", &error);
            assert_eq!(failure.missing(), expected, "provider code {code:?}");
            assert_eq!(failure.category(), S3FailureCategory::Provider);
            assert_redacted(error, S3FailureCategory::Provider);
        }
        let failure = record_s3_client_failure(
            "get_object",
            &SdkError::<ProviderError, String>::dispatch_failure(ConnectorError::io(Box::new(
                SecretError,
            ))),
        );
        assert_eq!(failure.missing(), None);
    }
}
