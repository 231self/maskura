//! Trusted native final-output validation primitives for an embedding server.
//!
//! The embedding process is responsible for treating callbacks as trusted,
//! cooperative code. They are not sandboxed and must not print sensitive data.

use std::future::{Future, poll_fn};
use std::io::Write as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;
use std::task::Poll;
use std::time::Instant;

use tokio_util::sync::CancellationToken;

static STATIC_REPORTER: OnceLock<()> = OnceLock::new();

/// Proof that the embedding process deliberately installed the static reporter.
///
/// The process owner must install this before processing sensitive data and
/// must not subsequently replace the process-wide panic hook. This does not
/// prevent native callbacks from explicitly writing to logs or stderr, and
/// cannot recover from aborts, double panics, or process death.
#[derive(Clone, Copy)]
pub struct StaticPanicReporter {
    _private: (),
}

/// Replace the process-wide panic hook with a static, payload-free reporter.
/// Never called automatically by the gateway. Hosts opting in own the process
/// panic policy for the remainder of the process lifetime.
pub fn install_static_panic_reporter() -> StaticPanicReporter {
    STATIC_REPORTER.get_or_init(|| {
        std::panic::set_hook(Box::new(|_| {
            let _ = std::io::stderr()
                .lock()
                .write_all(b"native callback panicked\n");
        }));
    });
    StaticPanicReporter { _private: () }
}

/// Engine-selected authority for one authenticated PUT. Its fields may contain
/// customer identifiers or configuration and must not be logged indiscriminately.
pub struct FinalOutputContext {
    pub authenticated: crate::control::AuthenticatedRequestContext,
    pub grant: crate::control::AuthorizationGrant,
    pub resolution: crate::pipeline::PipelineResolution,
    pub policy: crate::policy_gate::VerifiedPolicy,
    pub destination: crate::backend::DestinationSelectionSnapshot,
    pub key: String,
}

/// Callback rejection without dynamically formatted or customer-derived detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationFailure {
    Rejected,
    Unavailable,
}

/// A fresh session must be returned for every invocation. Callbacks are trusted
/// and cooperative: a synchronous callback that never returns cannot be
/// preempted by an async timeout and holds its operation's resources.
/// Callbacks must not detach work that outlives the callback future or session;
/// cancellation may drop a pending future. All callback-owned work must stop
/// before that future or session is dropped, and no output bytes may be retained
/// after abort or finalization. The gateway cannot join hidden native tasks.
#[async_trait::async_trait]
pub trait FinalOutputValidationFactory: Send + Sync {
    async fn begin(
        &self,
        context: &FinalOutputContext,
    ) -> Result<Box<dyn FinalOutputValidator>, ValidationFailure>;
}

/// Receives exactly the ordered output bytes destined for one sink transaction.
/// The same cooperative, cancellation-safe and no-detached-work contract as
/// [`FinalOutputValidationFactory`] applies to the entire session lifecycle.
#[async_trait::async_trait]
pub trait FinalOutputValidator: Send {
    async fn observe(&mut self, bytes: &[u8]) -> Result<(), ValidationFailure>;
    async fn finish(self: Box<Self>) -> Result<(), ValidationFailure>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValidationError {
    Rejected,
    Unavailable,
    Panicked,
    Deadline,
    Cancelled,
    Finished,
}

pub(crate) async fn callback<T>(
    deadline: Instant,
    cancellation: &CancellationToken,
    future: impl Future<Output = Result<T, ValidationFailure>>,
) -> Result<T, ValidationError> {
    let mut future = Box::pin(future);
    let result = {
        let caught =
            poll_fn(
                |cx| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
                    Ok(Poll::Pending) => Poll::Pending,
                    Ok(Poll::Ready(Ok(value))) => Poll::Ready(Ok(value)),
                    Ok(Poll::Ready(Err(ValidationFailure::Rejected))) => {
                        Poll::Ready(Err(ValidationError::Rejected))
                    }
                    Ok(Poll::Ready(Err(ValidationFailure::Unavailable))) => {
                        Poll::Ready(Err(ValidationError::Unavailable))
                    }
                    Err(_) => Poll::Ready(Err(ValidationError::Panicked)),
                },
            );
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(ValidationError::Cancelled),
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => Err(ValidationError::Deadline),
            result = caught => result,
        }
    };
    let drop_panicked = catch_unwind(AssertUnwindSafe(|| drop(future))).is_err();
    // A synchronous poll can run past the deadline or cancellation. Do not
    // accept its result merely because it eventually returned successfully.
    let interruption = if drop_panicked {
        Some(ValidationError::Panicked)
    } else if cancellation.is_cancelled() {
        Some(ValidationError::Cancelled)
    } else if Instant::now() >= deadline {
        Some(ValidationError::Deadline)
    } else {
        None
    };
    if let Some(error) = interruption {
        // A late successful factory result can itself own a validator whose
        // destructor panics. Contain that unwind before returning failure.
        if catch_unwind(AssertUnwindSafe(|| drop(result))).is_err() {
            return Err(ValidationError::Panicked);
        }
        return Err(error);
    }
    result
}

pub(crate) struct ValidationSession {
    inner: Option<Box<dyn FinalOutputValidator>>,
}

impl ValidationSession {
    pub(crate) fn new(inner: Box<dyn FinalOutputValidator>) -> Self {
        Self { inner: Some(inner) }
    }

    pub(crate) async fn observe(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<(), ValidationError> {
        let inner = self.inner.as_mut().ok_or(ValidationError::Finished)?;
        let result = callback(deadline, cancellation, async { inner.observe(bytes).await }).await;
        if result.is_err() {
            let _ = catch_unwind(AssertUnwindSafe(|| drop(self.inner.take())));
        }
        result
    }

    pub(crate) async fn finish(
        &mut self,
        deadline: Instant,
        cancellation: &CancellationToken,
    ) -> Result<(), ValidationError> {
        let inner = self.inner.take().ok_or(ValidationError::Finished)?;
        callback(deadline, cancellation, async move { inner.finish().await }).await
    }
}

impl Drop for ValidationSession {
    fn drop(&mut self) {
        // A session can remain live when decoding, framing, or sink work fails.
        // Contain an unwind from the trusted validator's destructor as well.
        // Abort, double panic, and process death are not catchable here.
        let _ = catch_unwind(AssertUnwindSafe(|| drop(self.inner.take())));
    }
}

#[cfg(test)]
mod tests;
