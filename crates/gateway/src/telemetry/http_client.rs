use std::fmt;
use std::time::Duration;

use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use reqwest::Client;

/// OTLP HTTP client that never lets collector transport detail leave the
/// exporter.
///
/// Transport failures are collapsed into a fixed opaque error and collector
/// response bodies are discarded, so a misconfigured or hostile collector
/// cannot inject URLs, headers, or body contents into an exporter error that is
/// later rendered.
pub(crate) struct SanitizingHttpClient {
    client: Client,
}

impl SanitizingHttpClient {
    pub(crate) fn new(timeout: Duration) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| anyhow::anyhow!("failed to build OTLP HTTP client"))?;
        Ok(Self { client })
    }
}

impl fmt::Debug for SanitizingHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SanitizingHttpClient")
            .finish_non_exhaustive()
    }
}

fn opaque_error() -> HttpError {
    Box::new(std::io::Error::other("otlp request failed"))
}

#[async_trait::async_trait]
impl HttpClient for SanitizingHttpClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let method = request.method().clone();
        let uri = request.uri().to_string();
        let headers = request.headers().clone();
        let body = request.into_body();

        let request = self
            .client
            .request(method, uri)
            .headers(headers)
            .body(body)
            .build()
            .map_err(|_| opaque_error())?;

        let response = self
            .client
            .execute(request)
            .await
            .map_err(|_| opaque_error())?;
        let status = response.status();
        let response_headers = response.headers().clone();

        let mut sanitized = Response::builder()
            .status(status)
            .body(Bytes::new())
            .map_err(|_| opaque_error())?;
        *sanitized.headers_mut() = response_headers;
        Ok(sanitized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use axum::Router;
    use axum::routing::any;

    fn request(uri: &str) -> Request<Bytes> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .body(Bytes::from_static(b"payload"))
            .unwrap()
    }

    #[test]
    fn debug_never_renders_transport_state() {
        let client = SanitizingHttpClient::new(Duration::from_secs(1)).unwrap();
        let debug = format!("{client:?}");
        assert!(!debug.contains("http"));
        assert!(!debug.contains("authorization"));
    }

    #[tokio::test]
    async fn transport_errors_are_opaque() {
        let client = SanitizingHttpClient::new(Duration::from_millis(250)).unwrap();
        let error = client
            .send_bytes(request("http://127.0.0.1:1/v1/traces"))
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "otlp request failed");
        assert!(!error.to_string().contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn collector_response_bodies_are_stripped() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let router = Router::new().fallback(any(|| async {
            (
                [(axum::http::header::CONTENT_TYPE, "text/plain")],
                "SENTINEL-collector-body",
            )
        }));
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let client = SanitizingHttpClient::new(Duration::from_secs(5)).unwrap();
        let response = client
            .send_bytes(request(&format!("http://{address}/v1/traces")))
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert!(response.body().is_empty());
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain")
        );
    }
}
