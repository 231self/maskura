use super::*;
use crate::transaction::SinkCommitState;
use std::sync::atomic::{AtomicUsize, Ordering};

type SinkFixture = (
    Arc<tokio::sync::Mutex<Box<dyn ObjectSinkTransaction>>>,
    Arc<MemoryStore>,
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Notify>,
    Arc<AtomicUsize>,
);

struct ControlledSink {
    inner: MemorySinkTransaction,
    state: SinkCommitState,
    entered: Arc<tokio::sync::Notify>,
    resume: Arc<tokio::sync::Notify>,
    aborts: Arc<AtomicUsize>,
    fail_abort: bool,
}

#[async_trait::async_trait]
impl ObjectSinkTransaction for ControlledSink {
    fn commit_state(&self) -> SinkCommitState {
        self.state
    }
    async fn write(&mut self, bytes: bytes::Bytes) -> Result<(), TransactionError> {
        self.inner.write(bytes).await
    }
    async fn verify_output(&mut self, size: u64, digest: &str) -> Result<(), TransactionError> {
        self.inner.verify_output(size, digest).await
    }
    async fn complete(
        &mut self,
        authority: DestinationCommitAuthority,
    ) -> Result<StoredObjectMeta, TransactionError> {
        self.inner.complete(authority).await
    }
    async fn abort(&mut self) -> Result<(), TransactionError> {
        self.aborts.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        self.resume.notified().await;
        if self.fail_abort {
            return Err(TransactionError::OutputMismatch);
        }
        self.inner.abort().await
    }
}

fn sink(state: SinkCommitState, fail_abort: bool) -> SinkFixture {
    let store = Arc::new(MemoryStore::new());
    let entered = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let aborts = Arc::new(AtomicUsize::new(0));
    let inner =
        MemorySinkTransaction::new(store.clone(), "bucket", "key", "text/plain", 128).unwrap();
    let sink: Box<dyn ObjectSinkTransaction> = Box::new(ControlledSink {
        inner,
        state,
        entered: entered.clone(),
        resume: resume.clone(),
        aborts: aborts.clone(),
        fail_abort,
    });
    (
        Arc::new(tokio::sync::Mutex::new(sink)),
        store,
        entered,
        resume,
        aborts,
    )
}

#[tokio::test]
async fn cleanup_waits_for_real_memory_abort_before_releasing_authority() {
    let (sink, store, entered, resume, aborts) = sink(SinkCommitState::PreCommit, false);
    sink.lock()
        .await
        .write(bytes::Bytes::from_static(b"pending"))
        .await
        .unwrap();
    let worker = tokio::spawn({
        let sink = sink.clone();
        async move { abort_uncommitted_sink(&sink, true, Uuid::nil()).await }
    });
    entered.notified().await;
    assert!(!worker.is_finished());
    assert!(store.get("bucket", "key").is_none());
    resume.notify_one();
    assert!(!worker.await.unwrap());
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
    assert!(store.get("bucket", "key").is_none());
}

#[tokio::test]
async fn unknown_or_committed_sinks_are_not_aborted_and_reservations_remain() {
    for state in [SinkCommitState::CommitUnknown, SinkCommitState::Committed] {
        let (sink, _, _, _, aborts) = sink(state, false);
        assert!(abort_uncommitted_sink(&sink, true, Uuid::nil()).await);
        assert_eq!(aborts.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn failed_abort_preserves_reservation_for_reconciliation() {
    let (sink, _, entered, resume, aborts) = sink(SinkCommitState::PreCommit, true);
    let worker =
        tokio::spawn(async move { abort_uncommitted_sink(&sink, true, Uuid::nil()).await });
    entered.notified().await;
    resume.notify_one();
    assert!(worker.await.unwrap());
    assert_eq!(aborts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn transaction_details_are_redacted_without_losing_reservation_state() {
    let error = StreamingPutError::PreserveReservation(Box::new(StreamingPutError::Transaction(
        TransactionError::Spool("synthetic-record-value-and-path".to_string()),
    )))
    .sanitized_for_validation();
    assert!(error.preserves_reservation());
    let response = streaming_put_error_response("", error);
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    let sentinel = b"synthetic-record-value-and-path";
    assert!(
        !body
            .windows(sentinel.len())
            .any(|window| window == sentinel)
    );
}

#[tokio::test]
async fn duplicate_trailer_detail_is_closed_only_for_validated_puts() {
    let sentinel = "synthetic-trailer-record-path";
    let validated =
        StreamingPutError::Integrity(IntegrityError::DuplicateTrailer(sentinel.to_string()))
            .sanitized_for_validation();
    let response = streaming_put_error_response("", validated);
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    assert!(
        body.windows(b"<Code>InvalidRequest</Code>".len())
            .any(|part| part == b"<Code>InvalidRequest</Code>")
    );
    assert!(
        !body
            .windows(sentinel.len())
            .any(|part| part == sentinel.as_bytes())
    );

    // The factory-absent mapping retains its previous S3 behavior.
    let baseline = streaming_put_error_response(
        "",
        StreamingPutError::Integrity(IntegrityError::DuplicateTrailer(sentinel.to_string())),
    );
    let body = axum::body::to_bytes(baseline.into_body(), 16 * 1024)
        .await
        .unwrap();
    assert!(
        body.windows(sentinel.len())
            .any(|part| part == sentinel.as_bytes())
    );
}

#[tokio::test]
async fn validated_integrity_categories_keep_closed_s3_codes() {
    for (error, code) in [
        (
            IntegrityError::InvalidChecksum("synthetic-detail"),
            "BadDigest",
        ),
        (IntegrityError::SignatureMismatch, "SignatureDoesNotMatch"),
    ] {
        let response = streaming_put_error_response(
            "",
            StreamingPutError::Integrity(error).sanitized_for_validation(),
        );
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        assert!(body.windows(code.len()).any(|part| part == code.as_bytes()));
        assert!(
            !body
                .windows(b"synthetic-detail".len())
                .any(|part| part == b"synthetic-detail")
        );
    }
}

#[tokio::test]
async fn validated_pipeline_error_does_not_reflect_unknown_code_or_message() {
    let error = maskura_error::MaskuraError::Generic {
        code: "synthetic-private-code-sentinel",
        message: "synthetic-private-message-sentinel".to_string(),
    };
    let response = streaming_put_error_response(
        "",
        StreamingPutError::Pipeline(error).sanitized_for_validation(),
    );
    let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    for sentinel in [
        "synthetic-private-code-sentinel",
        "synthetic-private-message-sentinel",
    ] {
        assert!(
            !body
                .windows(sentinel.len())
                .any(|part| part == sentinel.as_bytes())
        );
    }
}
