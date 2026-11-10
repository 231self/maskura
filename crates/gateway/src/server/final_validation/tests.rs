use super::*;
use std::sync::{Arc, Mutex};

#[path = "../../../tests/support/isolated_process.rs"]
mod isolated_process;

struct RecordingValidator(Arc<Mutex<Vec<u8>>>);

#[async_trait::async_trait]
impl FinalOutputValidator for RecordingValidator {
    async fn observe(&mut self, bytes: &[u8]) -> Result<(), ValidationFailure> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(())
    }

    async fn finish(self: Box<Self>) -> Result<(), ValidationFailure> {
        Ok(())
    }
}

#[tokio::test]
async fn observes_ordered_bytes_and_finalizes_only_once() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut session = ValidationSession::new(Box::new(RecordingValidator(seen.clone())));
    let cancel = tokio_util::sync::CancellationToken::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    session.observe(b"one", deadline, &cancel).await.unwrap();
    session.observe(b"\n", deadline, &cancel).await.unwrap();
    session.observe(b"two", deadline, &cancel).await.unwrap();
    session.finish(deadline, &cancel).await.unwrap();
    assert_eq!(&*seen.lock().unwrap(), b"one\ntwo");
    assert_eq!(
        session.finish(deadline, &cancel).await,
        Err(ValidationError::Finished)
    );
    assert_eq!(
        session.observe(b"later", deadline, &cancel).await,
        Err(ValidationError::Finished)
    );
}

#[tokio::test]
async fn cancelled_or_expired_session_cannot_finalize() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut session = ValidationSession::new(Box::new(RecordingValidator(seen)));
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    assert_eq!(
        session.observe(b"ignored", deadline, &cancel).await,
        Err(ValidationError::Cancelled)
    );
    assert_eq!(
        session.finish(deadline, &cancel).await,
        Err(ValidationError::Finished)
    );

    let mut session = ValidationSession::new(Box::new(RecordingValidator(Arc::default())));
    let cancel = tokio_util::sync::CancellationToken::new();
    assert_eq!(
        session.finish(std::time::Instant::now(), &cancel).await,
        Err(ValidationError::Deadline)
    );
    assert_eq!(
        session.finish(deadline, &cancel).await,
        Err(ValidationError::Finished)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn synchronous_callback_retains_ownership_until_it_really_returns() {
    let cancel = tokio_util::sync::CancellationToken::new();
    let child_cancel = cancel.clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let task = tokio::spawn(async move {
        callback(
            std::time::Instant::now() + std::time::Duration::from_secs(5),
            &child_cancel,
            async move {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                Ok::<(), ValidationFailure>(())
            },
        )
        .await
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    cancel.cancel();
    assert!(!task.is_finished());
    resume_tx.send(()).unwrap();
    assert_eq!(task.await.unwrap(), Err(ValidationError::Cancelled));
}

#[test]
fn static_reporter_hides_panic_payload_in_child_process() {
    const SENTINEL: &str = "synthetic-panic-payload-with-path";
    const SCENARIO: &str =
        "server::final_validation::tests::static_reporter_hides_panic_payload_in_child_process";
    if let Some(output) = isolated_process::dispatch(SCENARIO, false) {
        output.assert_success();
        for stream in [&output.stdout.bytes, &output.stderr.bytes] {
            assert!(
                !stream
                    .windows(SENTINEL.len())
                    .any(|window| window == SENTINEL.as_bytes())
            );
        }
        assert!(
            output
                .stderr
                .bytes
                .windows(b"native callback panicked".len())
                .any(|window| window == b"native callback panicked")
        );
    } else {
        let _capability = install_static_panic_reporter();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(callback(
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            &tokio_util::sync::CancellationToken::new(),
            async {
                panic!("synthetic-panic-payload-with-path");
                #[allow(unreachable_code)]
                Ok::<(), ValidationFailure>(())
            },
        ));
        assert_eq!(result, Err(ValidationError::Panicked));
        struct PanicOnDrop;
        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                panic!("synthetic-panic-payload-with-path");
            }
        }
        let cancelled = tokio_util::sync::CancellationToken::new();
        let trigger = cancelled.clone();
        let result = runtime.block_on(callback(
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            &cancelled,
            async move {
                trigger.cancel();
                Ok::<_, ValidationFailure>(PanicOnDrop)
            },
        ));
        assert!(matches!(result, Err(ValidationError::Panicked)));
    }
}
