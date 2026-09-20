//! Bounded process serving and shutdown for the telemetry handle.

use std::future::{Future, IntoFuture as _};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use tokio::net::TcpListener;
use tracing::warn;

use crate::telemetry::provider::TelemetryHandle;

/// How long in-flight connections may take to drain after a shutdown signal.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
/// How long remote providers may take to flush after draining.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve until SIGTERM or Ctrl-C, then drain and flush within fixed bounds.
///
/// At the drain deadline the serve future is dropped so stalled connections and
/// response bodies cannot block process exit. Flush then runs within its own
/// deadline. Either timeout logs one fixed local warning and shutdown continues.
pub async fn serve_with_telemetry(
    listener: TcpListener,
    router: Router,
    handle: Arc<TelemetryHandle>,
) -> std::io::Result<()> {
    serve_with_shutdown(
        listener,
        router,
        handle,
        DRAIN_TIMEOUT,
        FLUSH_TIMEOUT,
        shutdown_signal(),
    )
    .await
}

pub(crate) async fn serve_with_shutdown<F>(
    listener: TcpListener,
    router: Router,
    handle: Arc<TelemetryHandle>,
    drain_timeout: Duration,
    flush_timeout: Duration,
    shutdown: F,
) -> std::io::Result<()>
where
    F: Future<Output = ()>,
{
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .into_future();
    tokio::pin!(server);
    tokio::pin!(shutdown);

    tokio::select! {
        result = &mut server => {
            result?;
        }
        _ = &mut shutdown => {
            let _ = shutdown_tx.send(());
            if tokio::time::timeout(drain_timeout, &mut server).await.is_err() {
                warn!("telemetry.drain_timeout");
            }
        }
    }

    if !handle.flush(flush_timeout) {
        warn!("telemetry.flush_timeout");
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    use axum::body::Body;
    use axum::routing::get;
    use http_body::{Body as HttpBody, Frame};

    use crate::telemetry::provider::local_handle_for_test;

    /// A body that yields one frame and then never completes.
    struct StalledBody {
        sent: bool,
    }

    impl HttpBody for StalledBody {
        type Data = bytes::Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            let this = self.get_mut();
            if this.sent {
                Poll::Pending
            } else {
                this.sent = true;
                Poll::Ready(Some(Ok(Frame::data(bytes::Bytes::from_static(b"first")))))
            }
        }
    }

    async fn stalled() -> axum::response::Response {
        axum::response::Response::new(Body::new(StalledBody { sent: false }))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_deadline_is_enforced() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = local_handle_for_test();
        let app = crate::telemetry::instrument_router(
            Router::new().route("/stall", get(stalled)),
            handle.clone(),
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(serve_with_shutdown(
            listener,
            app,
            handle,
            Duration::from_millis(100),
            Duration::from_millis(100),
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let client = reqwest::Client::new();
        let request = tokio::spawn(async move {
            let _ = client.get(format!("http://{address}/stall")).send().await;
        });
        tokio::time::sleep(Duration::from_millis(75)).await;

        let _ = shutdown_tx.send(());
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(5), serving).await;
        assert!(result.is_ok(), "serve must exit after the drain deadline");
        assert!(started.elapsed() < Duration::from_secs(2));
        request.abort();
    }
}
