use std::time::Duration;

use axum::http::{Method, StatusCode};

pub(crate) const UNMATCHED_ROUTE: &str = "unmatched";
pub(crate) const TELEMETRY_TARGET: &str = "maskura.telemetry";
pub(crate) const REQUEST_SPAN_NAME: &str = "HTTP request";
pub(crate) const COMPLETION_EVENT_NAME: &str = "http.server.request.completed";
pub(crate) const REQUEST_ID_HEADER: &str = "x-maskura-request-id";

/// Documented ceiling for the exported `duration_ms` field. Longer durations
/// saturate rather than overflow.
pub(crate) const MAX_DURATION_MS: u64 = 86_400_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HttpMethodClass {
    Get,
    Head,
    Put,
    Post,
    Delete,
    Options,
    Patch,
    Other,
}

impl HttpMethodClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Put => "PUT",
            Self::Post => "POST",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Patch => "PATCH",
            Self::Other => "OTHER",
        }
    }

    pub(crate) fn from_method(method: &Method) -> Self {
        match *method {
            Method::GET => Self::Get,
            Method::HEAD => Self::Head,
            Method::PUT => Self::Put,
            Method::POST => Self::Post,
            Method::DELETE => Self::Delete,
            Method::OPTIONS => Self::Options,
            Method::PATCH => Self::Patch,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatusClass {
    Informational,
    Success,
    Redirect,
    ClientError,
    ServerError,
    None,
}

impl StatusClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "1xx",
            Self::Success => "2xx",
            Self::Redirect => "3xx",
            Self::ClientError => "4xx",
            Self::ServerError => "5xx",
            Self::None => "none",
        }
    }

    pub(crate) fn from_status(status: StatusCode) -> Self {
        Self::from_code(status.as_u16())
    }

    pub(crate) fn from_code(code: u16) -> Self {
        match code {
            100..=199 => Self::Informational,
            200..=299 => Self::Success,
            300..=399 => Self::Redirect,
            400..=499 => Self::ClientError,
            500..=599 => Self::ServerError,
            _ => Self::None,
        }
    }

    pub(crate) fn is_server_error(self) -> bool {
        matches!(self, Self::ServerError)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Completed,
    BodyError,
    Cancelled,
}

impl Outcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::BodyError => "body_error",
            Self::Cancelled => "cancelled",
        }
    }
}

pub(crate) struct CompletionRecord<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) method: HttpMethodClass,
    pub(crate) route: &'a str,
    pub(crate) status_code: Option<u16>,
    pub(crate) outcome: Outcome,
    pub(crate) duration: Duration,
}

impl CompletionRecord<'_> {
    pub(crate) fn status_class(&self) -> StatusClass {
        match self.status_code {
            Some(code) => StatusClass::from_code(code),
            None => StatusClass::None,
        }
    }

    pub(crate) fn duration_ms(&self) -> u64 {
        let millis = u64::try_from(self.duration.as_millis()).unwrap_or(u64::MAX);
        millis.min(MAX_DURATION_MS)
    }
}

/// Create the single module-owned request span.
///
/// `otel.kind` is consumed by the OpenTelemetry layer to set the OTel span kind
/// and is not exported as an attribute. The dotted semantic attributes are set
/// directly on the OTel span because `tracing` field names cannot contain dots.
pub(crate) fn request_span() -> tracing::Span {
    tracing::info_span!(
        target: "maskura.telemetry",
        "HTTP request",
        otel.kind = "server",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_methods_to_a_bounded_set() {
        assert_eq!(
            HttpMethodClass::from_method(&Method::GET),
            HttpMethodClass::Get
        );
        assert_eq!(
            HttpMethodClass::from_method(&Method::PATCH),
            HttpMethodClass::Patch
        );
        assert_eq!(
            HttpMethodClass::from_method(&Method::from_bytes(b"PROPFIND").unwrap()),
            HttpMethodClass::Other
        );
        assert_eq!(HttpMethodClass::Other.as_str(), "OTHER");
    }

    #[test]
    fn normalizes_status_classes() {
        assert_eq!(
            StatusClass::from_status(StatusCode::CONTINUE).as_str(),
            "1xx"
        );
        assert_eq!(StatusClass::from_status(StatusCode::OK).as_str(), "2xx");
        assert_eq!(
            StatusClass::from_status(StatusCode::NOT_MODIFIED).as_str(),
            "3xx"
        );
        assert_eq!(
            StatusClass::from_status(StatusCode::UNAUTHORIZED).as_str(),
            "4xx"
        );
        assert_eq!(
            StatusClass::from_status(StatusCode::BAD_GATEWAY).as_str(),
            "5xx"
        );
        assert!(StatusClass::ServerError.is_server_error());
        assert!(!StatusClass::ClientError.is_server_error());
    }

    #[test]
    fn duration_saturates_at_the_documented_ceiling() {
        let make = |duration| CompletionRecord {
            request_id: "id",
            method: HttpMethodClass::Get,
            route: "/health",
            status_code: Some(200),
            outcome: Outcome::Completed,
            duration,
        };
        assert_eq!(make(Duration::from_millis(1500)).duration_ms(), 1500);
        assert_eq!(
            make(Duration::from_secs(10 * 24 * 3600)).duration_ms(),
            MAX_DURATION_MS
        );
        assert_eq!(
            make(Duration::from_millis(u64::MAX)).duration_ms(),
            MAX_DURATION_MS
        );
    }

    #[test]
    fn completion_status_class_derives_from_the_exact_code() {
        let make = |status_code| CompletionRecord {
            request_id: "id",
            method: HttpMethodClass::Post,
            route: "/v1/objects/{key}",
            status_code,
            outcome: Outcome::Completed,
            duration: Duration::from_millis(1),
        };
        assert_eq!(make(Some(204)).status_class(), StatusClass::Success);
        assert_eq!(make(Some(503)).status_class(), StatusClass::ServerError);
        assert_eq!(make(None).status_class(), StatusClass::None);
    }

    #[test]
    fn request_span_has_the_exact_metadata() {
        let span = request_span();
        let metadata = span.metadata().expect("span metadata");
        assert_eq!(metadata.target(), TELEMETRY_TARGET);
        assert_eq!(metadata.name(), REQUEST_SPAN_NAME);
        assert!(metadata.is_span());
    }
}
