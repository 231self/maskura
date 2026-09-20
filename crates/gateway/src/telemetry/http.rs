//! Request lifecycle instrumentation.
//!
//! The middleware is applied to the fully composed router and accounts for the
//! complete response lifecycle. It never reads concrete paths, queries,
//! headers, or error text into an exported record.

use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::Body;
use axum::extract::{MatchedPath, Request, State};
use axum::http::HeaderValue;
use axum::middleware::{self, Next};
use axum::response::Response;
use http_body::{Body as HttpBody, Frame};
use pin_project_lite::pin_project;
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use uuid::Uuid;

use crate::telemetry::provider::{
    TelemetryHandle, apply_completion_span_attributes, apply_completion_span_status,
};
use crate::telemetry::schema::{
    self, CompletionRecord, HttpMethodClass, Outcome, REQUEST_ID_HEADER, UNMATCHED_ROUTE,
};

/// Instrument a fully composed router.
///
/// Apply this only after every engine, dashboard, hosted MCP, and private
/// control-plane route has been merged, so the middleware encloses the complete
/// request surface. It must not change route matching or body limits.
pub fn instrument_router(router: Router, handle: Arc<TelemetryHandle>) -> Router {
    router.layer(middleware::from_fn_with_state(handle, lifecycle))
}

async fn lifecycle(
    State(handle): State<Arc<TelemetryHandle>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Caller-supplied correlation is never trusted.
    request.headers_mut().remove(REQUEST_ID_HEADER);

    let request_id = Uuid::now_v7().to_string();
    let method = HttpMethodClass::from_method(request.method());
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| UNMATCHED_ROUTE.to_string());

    let span = schema::request_span();
    handle.record_active_request(method, &route, 1);
    let mut pending = Pending {
        handle: handle.clone(),
        request_id,
        method,
        route,
        status_code: None,
        started: Instant::now(),
        span: span.clone(),
        finalized: false,
    };

    let response = next.run(request).instrument(span).await;

    pending.status_code = Some(response.status().as_u16());
    let (mut parts, body) = response.into_parts();
    if let Ok(value) = HeaderValue::from_str(&pending.request_id) {
        parts.headers.insert(REQUEST_ID_HEADER, value);
    }
    Response::from_parts(
        parts,
        Body::new(LifecycleBody {
            inner: body,
            pending: Some(pending),
        }),
    )
}

pin_project! {
    /// Response body wrapper that finalizes the request exactly once.
    struct LifecycleBody<B> {
        #[pin]
        inner: B,
        pending: Option<Pending>,
    }
}

impl<B> HttpBody for LifecycleBody<B>
where
    B: HttpBody,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        let result = {
            let _entered = this.pending.as_ref().map(|pending| pending.span.enter());
            this.inner.as_mut().poll_frame(cx)
        };

        match &result {
            std::task::Poll::Ready(Some(Ok(_))) if this.inner.is_end_stream() => {
                if let Some(pending) = this.pending.as_mut() {
                    pending.finalize(Outcome::Completed);
                }
            }
            std::task::Poll::Ready(Some(Ok(_))) => {}
            std::task::Poll::Ready(Some(Err(_))) => {
                if let Some(pending) = this.pending.as_mut() {
                    pending.finalize(Outcome::BodyError);
                }
            }
            std::task::Poll::Ready(None) => {
                if let Some(pending) = this.pending.as_mut() {
                    pending.finalize(Outcome::Completed);
                }
            }
            std::task::Poll::Pending => {}
        }

        result
    }
}

/// The single-owner request finalizer.
///
/// It finalizes exactly once. Dropping it without an explicit finalization
/// records a cancellation, which covers a dropped handler future and a dropped
/// response body that was never fully consumed.
struct Pending {
    handle: Arc<TelemetryHandle>,
    request_id: String,
    method: HttpMethodClass,
    route: String,
    status_code: Option<u16>,
    started: Instant,
    span: tracing::Span,
    finalized: bool,
}

impl Pending {
    fn finalize(&mut self, outcome: Outcome) {
        if self.finalized {
            return;
        }
        self.finalized = true;

        let record = CompletionRecord {
            request_id: &self.request_id,
            method: self.method,
            route: &self.route,
            status_code: self.status_code,
            outcome,
            duration: self.started.elapsed(),
        };
        let context = self.span.context();

        {
            let _entered = self.span.enter();
            apply_completion_span_attributes(&context, &record);
            apply_completion_span_status(&context, &record);
            self.handle.emit_completion(&context, &record);
            self.handle.record_completion_metrics(&record);
            tracing::info!(
                target: schema::TELEMETRY_TARGET,
                request_id = %self.request_id,
                method = self.method.as_str(),
                route = %self.route,
                status_class = record.status_class().as_str(),
                outcome = outcome.as_str(),
                duration_ms = record.duration_ms(),
                "http.server.request.completed",
            );
        }

        self.handle
            .record_active_request(self.method, &self.route, -1);
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.finalize(Outcome::Cancelled);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context as TaskContext, Poll, Waker};
    use std::time::Duration;

    use axum::body::Bytes;
    use axum::extract::State as AxumState;
    use axum::http::{HeaderMap, StatusCode, Uri};
    use axum::routing::{any, get};
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::common::v1::any_value::Value as ProtoValue;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue as ProtoKeyValue};
    use opentelemetry_proto::tonic::metrics::v1::metric::Data as MetricData;
    use opentelemetry_proto::tonic::metrics::v1::number_data_point::Value as NumberValue;
    use prost::Message;
    use tower::ServiceExt as _;

    use crate::telemetry::config::{
        BatchConfig, Sampler, SamplerConfig, SignalEndpoint, TelemetryConfig,
    };
    use crate::telemetry::provider::RemoteTelemetry;

    #[derive(Clone)]
    struct Capture {
        path: String,
        body: Vec<u8>,
    }

    #[derive(Default)]
    struct Collector {
        captures: Mutex<Vec<Capture>>,
    }

    async fn capture(
        AxumState(state): AxumState<Arc<Collector>>,
        uri: Uri,
        _headers: HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        state.captures.lock().unwrap().push(Capture {
            path: uri.path().to_string(),
            body: body.to_vec(),
        });
        StatusCode::OK
    }

    async fn start_collector() -> (String, Arc<Collector>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Collector::default());
        let router = Router::new()
            .fallback(any(capture))
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (format!("http://{address}"), state)
    }

    fn test_batch() -> BatchConfig {
        BatchConfig {
            max_queue_size: 64,
            scheduled_delay: Duration::from_millis(5),
            max_export_batch_size: 16,
            export_timeout: Duration::from_secs(5),
        }
    }

    fn exported_handle(endpoint: &str) -> Arc<TelemetryHandle> {
        let signals = || SignalEndpoint {
            endpoint: endpoint.to_string(),
            insecure: true,
            headers: Vec::new(),
            timeout: Duration::from_secs(5),
        };
        let config = TelemetryConfig {
            service_name: "maskura-gateway".to_string(),
            service_version: "0.0.0-test".to_string(),
            process_role: "gateway".to_string(),
            traces: Some(signals()),
            logs: Some(signals()),
            metrics: Some(signals()),
            sampler: SamplerConfig {
                sampler: Sampler::AlwaysOn,
                ratio: 1.0,
            },
            resource_attributes: Vec::new(),
            span_batch: test_batch(),
            log_batch: test_batch(),
            metric_interval: Duration::from_secs(60),
            metric_timeout: Duration::from_secs(5),
        };
        let remote = RemoteTelemetry::build(&config).unwrap();
        Arc::new(TelemetryHandle { config, remote })
    }

    fn local_handle() -> Arc<TelemetryHandle> {
        let config = TelemetryConfig {
            service_name: "maskura-gateway".to_string(),
            service_version: "0.0.0-test".to_string(),
            process_role: "gateway".to_string(),
            traces: None,
            logs: None,
            metrics: None,
            sampler: SamplerConfig {
                sampler: Sampler::AlwaysOn,
                ratio: 1.0,
            },
            resource_attributes: Vec::new(),
            span_batch: test_batch(),
            log_batch: test_batch(),
            metric_interval: Duration::from_secs(60),
            metric_timeout: Duration::from_secs(5),
        };
        let remote = RemoteTelemetry::build(&config).unwrap();
        Arc::new(TelemetryHandle { config, remote })
    }

    fn test_app(handle: Arc<TelemetryHandle>) -> Router {
        instrument_router(
            Router::new()
                .route("/health", get(|| async { StatusCode::OK }))
                .route("/v1/objects/{*key}", get(|| async { StatusCode::OK }))
                .route("/boom", get(|| async { StatusCode::INTERNAL_SERVER_ERROR }))
                .route(
                    "/stream",
                    get(|| async { Response::new(Body::new(StreamingBody { sent: false })) }),
                )
                .route("/error-body", get(error_body))
                .route("/auth-denied", get(|| async { StatusCode::UNAUTHORIZED }))
                .route(
                    "/unsupported",
                    get(|| async { StatusCode::NOT_IMPLEMENTED }),
                )
                .route("/cors", any(|| async { StatusCode::NO_CONTENT }))
                .route("/readyz", get(|| async { StatusCode::SERVICE_UNAVAILABLE }))
                .route("/pending", get(pending_handler)),
            handle,
        )
    }

    async fn error_body() -> Response {
        Response::new(Body::new(FailingBody))
    }

    /// A response body whose first poll is an error.
    struct FailingBody;

    impl HttpBody for FailingBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(Some(Err(std::io::Error::other("SENTINEL-body-error-text"))))
        }
    }

    async fn pending_handler() -> StatusCode {
        std::future::pending::<()>().await;
        StatusCode::OK
    }

    struct StreamingBody {
        sent: bool,
    }

    impl HttpBody for StreamingBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            if this.sent {
                Poll::Pending
            } else {
                this.sent = true;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"hello")))))
            }
        }
    }

    fn request_id(response: &Response) -> String {
        response
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    async fn drain(response: Response) {
        let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;
    }

    fn string_attribute(attributes: &[ProtoKeyValue], key: &str) -> Option<String> {
        attributes
            .iter()
            .find(|kv| kv.key == key)
            .and_then(|kv| match &kv.value {
                Some(AnyValue {
                    value: Some(ProtoValue::StringValue(value)),
                }) => Some(value.clone()),
                _ => None,
            })
    }

    fn int_attribute(attributes: &[ProtoKeyValue], key: &str) -> Option<i64> {
        attributes
            .iter()
            .find(|kv| kv.key == key)
            .and_then(|kv| match &kv.value {
                Some(AnyValue {
                    value: Some(ProtoValue::IntValue(value)),
                }) => Some(*value),
                _ => None,
            })
    }

    fn captured(collector: &Collector, path: &str) -> Vec<u8> {
        collector
            .captures
            .lock()
            .unwrap()
            .iter()
            .filter(|capture| capture.path == path)
            .map(|capture| capture.body.clone())
            .collect::<Vec<_>>()
            .first()
            .cloned()
            .unwrap_or_default()
    }

    /// Every export body for a signal path, in arrival order.
    ///
    /// A signal may arrive in more than one export batch, so assertions that
    /// span multiple requests must not assume a single capture.
    fn captured_all(collector: &Collector, path: &str) -> Vec<Vec<u8>> {
        collector
            .captures
            .lock()
            .unwrap()
            .iter()
            .filter(|capture| capture.path == path)
            .map(|capture| capture.body.clone())
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn request_id_is_replaced_with_a_generated_uuid_v7() {
        let app = test_app(local_handle());
        let request = Request::builder()
            .uri("/health")
            .header(REQUEST_ID_HEADER, "caller-supplied-id")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let generated = request_id(&response);
        assert_ne!(generated, "caller-supplied-id");
        let parsed = Uuid::parse_str(&generated).expect("uuid");
        assert_eq!(parsed.get_version_num(), 7);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn matched_route_is_a_template_and_secrets_are_not_exported() {
        let (endpoint, collector) = start_collector().await;
        let handle = exported_handle(&endpoint);
        let app = test_app(handle.clone());
        let subscriber = logging_subscriber(handle.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let sentinel = "SENTINEL-route-4d1a";
        let request = Request::builder()
            .uri(format!("/v1/objects/{sentinel}/object?token={sentinel}"))
            .header("authorization", format!("Bearer {sentinel}"))
            .header("x-maskura-request-id", sentinel)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        drain(response).await;

        let unmatched = Request::builder()
            .uri("/definitely-not-a-route")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(unmatched).await.unwrap();
        drain(response).await;

        assert!(handle.flush(Duration::from_secs(10)));

        for path in ["/v1/traces", "/v1/logs", "/v1/metrics"] {
            for body in captured_all(&collector, path) {
                assert!(
                    !String::from_utf8_lossy(&body).contains(sentinel),
                    "sentinel leaked into exported records"
                );
            }
        }

        let mut routes = BTreeSet::new();
        for body in captured_all(&collector, "/v1/traces") {
            let trace_request = ExportTraceServiceRequest::decode(body.as_slice()).unwrap();
            for resource in &trace_request.resource_spans {
                for scope in &resource.scope_spans {
                    for span in &scope.spans {
                        if let Some(route) = string_attribute(&span.attributes, "http.route") {
                            routes.insert(route);
                        }
                    }
                }
            }
        }
        assert!(routes.contains("/v1/objects/{*key}"));
        assert!(routes.contains(UNMATCHED_ROUTE));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_errors_set_the_span_error_status() {
        let (endpoint, collector) = start_collector().await;
        let handle = exported_handle(&endpoint);
        let app = test_app(handle.clone());
        let subscriber = logging_subscriber(handle.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let response = app
            .oneshot(Request::builder().uri("/boom").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        drain(response).await;
        assert!(handle.flush(Duration::from_secs(10)));

        let traces = captured(&collector, "/v1/traces");
        let trace_request = ExportTraceServiceRequest::decode(traces.as_slice()).unwrap();
        let span = &trace_request.resource_spans[0].scope_spans[0].spans[0];
        let status = span.status.as_ref().expect("span status");
        assert_eq!(status.code, 2, "500 must set the span error status");
        assert_eq!(
            int_attribute(&span.attributes, "http.response.status_code"),
            Some(500)
        );

        let metrics = captured(&collector, "/v1/metrics");
        let metric_request = ExportMetricsServiceRequest::decode(metrics.as_slice()).unwrap();
        let (completed, histogram) = completed_and_histogram_counts(&metric_request);
        assert_eq!(completed, 1);
        assert_eq!(histogram as i64, completed);
        assert_eq!(active_value(&metric_request), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn client_errors_are_not_exported_as_errors() {
        let (endpoint, collector) = start_collector().await;
        let handle = exported_handle(&endpoint);
        let app = test_app(handle.clone());
        let subscriber = logging_subscriber(handle.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/definitely-not-a-route")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        drain(response).await;
        assert!(handle.flush(Duration::from_secs(10)));

        let traces = captured(&collector, "/v1/traces");
        let trace_request = ExportTraceServiceRequest::decode(traces.as_slice()).unwrap();
        let span = &trace_request.resource_spans[0].scope_spans[0].spans[0];
        assert_ne!(span.status.as_ref().map(|status| status.code), Some(2));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropped_body_finalizes_as_cancelled_once() {
        use http_body_util::BodyExt as _;

        let (endpoint, collector) = start_collector().await;
        let handle = exported_handle(&endpoint);
        let app = test_app(handle.clone());
        let subscriber = logging_subscriber(handle.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut body = response.into_body();
        let frame = body.frame().await;
        assert!(frame.is_some(), "first frame delivered");
        drop(body);
        assert!(handle.flush(Duration::from_secs(10)));

        let logs = captured(&collector, "/v1/logs");
        let log_request = ExportLogsServiceRequest::decode(logs.as_slice()).unwrap();
        let records = &log_request.resource_logs[0].scope_logs[0].log_records;
        assert_eq!(records.len(), 1);
        assert_eq!(
            string_attribute(&records[0].attributes, "outcome").as_deref(),
            Some("cancelled")
        );

        let metrics = captured(&collector, "/v1/metrics");
        let metric_request = ExportMetricsServiceRequest::decode(metrics.as_slice()).unwrap();
        assert_eq!(active_value(&metric_request), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_before_headers_finalizes_once() {
        let (endpoint, collector) = start_collector().await;
        let handle = exported_handle(&endpoint);
        let app = test_app(handle.clone());
        let subscriber = logging_subscriber(handle.clone());
        let _guard = tracing::subscriber::set_default(subscriber);

        let request = Request::builder()
            .uri("/pending")
            .body(Body::empty())
            .unwrap();
        let mut future = Box::pin(app.oneshot(request));
        let mut context = TaskContext::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
        drop(future);
        assert!(handle.flush(Duration::from_secs(10)));

        let logs = captured(&collector, "/v1/logs");
        let log_request = ExportLogsServiceRequest::decode(logs.as_slice()).unwrap();
        let records = &log_request.resource_logs[0].scope_logs[0].log_records;
        assert_eq!(records.len(), 1, "exactly one completion log");
        assert_eq!(
            string_attribute(&records[0].attributes, "outcome").as_deref(),
            Some("cancelled")
        );
        assert_eq!(
            string_attribute(&records[0].attributes, "status_class").as_deref(),
            Some("none")
        );

        let metrics = captured(&collector, "/v1/metrics");
        let metric_request = ExportMetricsServiceRequest::decode(metrics.as_slice()).unwrap();
        assert_eq!(active_value(&metric_request), 0);
    }

    fn completed_and_histogram_counts(request: &ExportMetricsServiceRequest) -> (i64, u64) {
        let metrics = &request.resource_metrics[0].scope_metrics[0].metrics;
        let completed = metrics
            .iter()
            .find(|metric| metric.name == "maskura.http.server.completed_requests")
            .expect("completed metric");
        let completed_count = match completed.data.as_ref().unwrap() {
            MetricData::Sum(sum) => match sum.data_points[0].value {
                Some(NumberValue::AsInt(value)) => value,
                other => panic!("unexpected completed value: {other:?}"),
            },
            other => panic!("completed is not a sum: {other:?}"),
        };
        let histogram = metrics
            .iter()
            .find(|metric| metric.name == "maskura.http.server.request.duration")
            .expect("duration metric");
        let histogram_count = match histogram.data.as_ref().unwrap() {
            MetricData::Histogram(histogram) => histogram.data_points[0].count,
            other => panic!("duration is not a histogram: {other:?}"),
        };
        (completed_count, histogram_count)
    }

    fn active_value(request: &ExportMetricsServiceRequest) -> i64 {
        let metrics = &request.resource_metrics[0].scope_metrics[0].metrics;
        let active = metrics
            .iter()
            .find(|metric| metric.name == "maskura.http.server.active_requests")
            .expect("active requests metric");
        match active.data.as_ref().unwrap() {
            MetricData::Sum(sum) => match sum.data_points[0].value {
                Some(NumberValue::AsInt(value)) => value,
                other => panic!("unexpected active value: {other:?}"),
            },
            other => panic!("active requests is not a sum: {other:?}"),
        }
    }

    fn logging_subscriber(
        handle: Arc<TelemetryHandle>,
    ) -> Arc<dyn tracing::Subscriber + Send + Sync> {
        use crate::telemetry::logging::{self, LogFormat};
        let tracer = handle.tracer().expect("tracer");
        logging::subscriber_with_writer_and_tracer(
            tracing::Level::INFO,
            LogFormat::Text,
            std::io::sink,
            tracer,
        )
    }

    #[test]
    fn finalize_is_exactly_once() {
        let handle = local_handle();
        let span = schema::request_span();
        let mut pending = Pending {
            handle,
            request_id: "01920000-0000-7000-8000-000000000002".to_string(),
            method: HttpMethodClass::Get,
            route: "/x".to_string(),
            status_code: Some(200),
            started: Instant::now(),
            span,
            finalized: false,
        };
        pending.finalize(Outcome::Completed);
        pending.finalize(Outcome::BodyError);
        assert!(pending.finalized);
    }

    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl LogCapture {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = LogCapture;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn instrumented_app(
        handle: Arc<TelemetryHandle>,
        route: &str,
        method_router: axum::routing::MethodRouter,
    ) -> Router {
        instrument_router(Router::new().route(route, method_router), handle)
    }

    fn sdk_log_attr(record: &opentelemetry_sdk::logs::SdkLogRecord, key: &str) -> Option<String> {
        record
            .attributes_iter()
            .find(|(name, _)| name.as_str() == key)
            .map(|(_, value)| match value {
                opentelemetry::logs::AnyValue::String(text) => text.to_string(),
                opentelemetry::logs::AnyValue::Int(number) => number.to_string(),
                other => format!("{other:?}"),
            })
    }

    fn in_memory_active(exporter: &opentelemetry_sdk::metrics::InMemoryMetricExporter) -> i64 {
        use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
        for resource_metrics in exporter.get_finished_metrics().expect("metrics") {
            for scope in resource_metrics.scope_metrics() {
                for metric in scope.metrics() {
                    if metric.name() == "maskura.http.server.active_requests"
                        && let AggregatedMetrics::I64(MetricData::Sum(sum)) = metric.data()
                    {
                        return sum.data_points().next().expect("data point").value();
                    }
                }
            }
        }
        panic!("active requests metric missing");
    }

    fn local_in_memory_subscriber(
        handle: &Arc<TelemetryHandle>,
    ) -> Arc<dyn tracing::Subscriber + Send + Sync> {
        logging_subscriber(handle.clone())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn body_error_finalizes_once_as_body_error() {
        use crate::telemetry::provider::in_memory_handle;

        let (handle, exporters) = in_memory_handle();
        let _guard = tracing::subscriber::set_default(local_in_memory_subscriber(&handle));
        let app = instrumented_app(handle.clone(), "/error-body", get(error_body));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/error-body")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await;
        assert!(body.is_err(), "the body error must surface to the caller");
        assert!(handle.flush(Duration::from_secs(10)));

        let logs = exporters.log.get_emitted_logs().expect("emitted logs");
        assert_eq!(logs.len(), 1, "exactly one completion log");
        assert_eq!(
            sdk_log_attr(&logs[0].record, "outcome").as_deref(),
            Some("body_error")
        );
        assert_eq!(in_memory_active(&exporters.metric), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_completion_event_has_only_its_fixed_fields() {
        use crate::telemetry::logging::{self, LogFormat};

        let capture = LogCapture::default();
        let subscriber =
            logging::subscriber_with_writer(tracing::Level::INFO, LogFormat::Json, capture.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        let app = test_app(local_handle());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        drain(response).await;

        let output = capture.contents();
        let line = output
            .lines()
            .find(|line| line.contains("http.server.request.completed"))
            .expect("one local completion event");
        let value: serde_json::Value = serde_json::from_str(line).expect("valid json record");
        assert_eq!(value["target"], schema::TELEMETRY_TARGET);
        assert_eq!(value["fields"]["message"], "http.server.request.completed");
        let fields: BTreeSet<String> = value["fields"]
            .as_object()
            .expect("fields object")
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            fields,
            BTreeSet::from([
                "message".to_string(),
                "request_id".to_string(),
                "method".to_string(),
                "route".to_string(),
                "status_class".to_string(),
                "outcome".to_string(),
                "duration_ms".to_string(),
            ])
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_response_status_carries_a_generated_request_id() {
        let app = test_app(local_handle());
        for (uri, status) in [
            ("/health", StatusCode::OK),
            ("/auth-denied", StatusCode::UNAUTHORIZED),
            ("/unsupported", StatusCode::NOT_IMPLEMENTED),
            ("/readyz", StatusCode::SERVICE_UNAVAILABLE),
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), status, "{uri}");
            let parsed = Uuid::parse_str(&request_id(&response)).expect("generated uuid");
            assert_eq!(parsed.get_version_num(), 7, "{uri}");
            drain(response).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cors_preflight_and_retries_get_distinct_request_ids() {
        let app = test_app(local_handle());

        let preflight = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/cors")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            Uuid::parse_str(&request_id(&preflight))
                .expect("generated uuid")
                .get_version_num(),
            7
        );
        drain(preflight).await;

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let second = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            request_id(&first),
            request_id(&second),
            "retries must get distinct request ids"
        );
        drain(first).await;
        drain(second).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn credential_presigned_and_body_error_sentinels_are_never_exported() {
        use crate::telemetry::provider::in_memory_handle;
        use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};

        let (handle, exporters) = in_memory_handle();
        let _guard = tracing::subscriber::set_default(local_in_memory_subscriber(&handle));
        let app = test_app(handle.clone());

        let sentinel = "SENTINEL-adversarial-7c31";
        let request = Request::builder()
            .uri(format!(
                "/v1/objects/{sentinel}/key?X-Amz-Signature={sentinel}&X-Amz-Credential={sentinel}"
            ))
            .header("authorization", format!("Bearer maskura_mcp_{sentinel}"))
            .header("x-api-key", sentinel)
            .header("x-maskura-api-key", sentinel)
            .header("user-agent", format!("agent/{sentinel}"))
            .header("x-maskura-request-id", sentinel)
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        drain(response).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/error-body")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;
        assert!(handle.flush(Duration::from_secs(10)));

        let mut dump = String::new();
        for span in exporters.span.get_finished_spans().expect("spans") {
            dump.push_str(&format!("{span:?}"));
        }
        for log in exporters.log.get_emitted_logs().expect("logs") {
            dump.push_str(log.record.event_name().unwrap_or_default());
            for (name, value) in log.record.attributes_iter() {
                dump.push_str(name.as_str());
                dump.push_str(&format!("{value:?}"));
            }
        }
        for resource_metrics in exporters.metric.get_finished_metrics().expect("metrics") {
            for scope in resource_metrics.scope_metrics() {
                for metric in scope.metrics() {
                    dump.push_str(metric.name());
                    match metric.data() {
                        AggregatedMetrics::U64(MetricData::Sum(sum)) => {
                            for point in sum.data_points() {
                                for kv in point.attributes() {
                                    dump.push_str(&format!("{kv:?}"));
                                }
                            }
                        }
                        AggregatedMetrics::I64(MetricData::Sum(sum)) => {
                            for point in sum.data_points() {
                                for kv in point.attributes() {
                                    dump.push_str(&format!("{kv:?}"));
                                }
                            }
                        }
                        AggregatedMetrics::F64(MetricData::Histogram(histogram)) => {
                            for point in histogram.data_points() {
                                for kv in point.attributes() {
                                    dump.push_str(&format!("{kv:?}"));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        assert!(!dump.contains(sentinel), "sentinel leaked: {dump}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unreachable_collector_never_changes_the_response() {
        let handle = exported_handle("http://127.0.0.1:1");
        let app = instrumented_app(handle.clone(), "/health", get(|| async { StatusCode::OK }));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(Uuid::parse_str(&request_id(&response)).is_ok());
        drain(response).await;

        // A collector outage must never block or panic shutdown.
        let _ = handle.flush(Duration::from_millis(300));
    }
}
