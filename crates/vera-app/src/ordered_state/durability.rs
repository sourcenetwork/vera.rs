use std::time::Instant;

use commonware_glue::stateful::db::Barrier;
use commonware_runtime::{Error, Handle};

pub(super) fn observe(barrier: Barrier, height: Option<u64>, started: Instant) -> Barrier {
    Barrier::from_handles::<super::OrderedState>([Handle::from_future(async move {
        let polled = Instant::now();
        let durable = barrier.durable().await;
        let wait_us = polled.elapsed().as_micros();
        let since_finalize_us = started.elapsed().as_micros();
        tracing::debug!(target: "vera_diagnostics", ?height, durable, wait_us, since_finalize_us,
            "finalized state durability completed");
        tracing::debug!(target: "vera_publication_diagnostics", ?height, durable, wait_us, since_finalize_us,
            "finalized state durability completed");
        // Preserve the barrier's shutdown result; storage failures still panic inside durable().
        if durable { Ok(()) } else { Err(Error::Aborted) }
    })])
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{FutureExt as _, channel::oneshot};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test]
    async fn observation_preserves_completion_and_shutdown_results() {
        for (result, expected) in [
            (Ok(()), true),
            (Err(Error::Aborted), false),
            (Err(Error::Closed), false),
        ] {
            let barrier = Barrier::from_handles::<()>([Handle::ready(result)]);
            assert_eq!(
                observe(barrier, Some(7), Instant::now()).durable().await,
                expected
            );
        }
    }

    #[tokio::test]
    async fn observation_does_not_resolve_before_the_underlying_barrier() {
        let (send, receive) = oneshot::channel();
        let barrier = Barrier::from_handles::<()>([Handle::from_future(async move {
            receive.await.map_err(|_| Error::Closed)
        })]);
        let mut observed = Box::pin(observe(barrier, Some(8), Instant::now()).durable());
        assert!(observed.as_mut().now_or_never().is_none());
        send.send(()).unwrap();
        assert!(observed.await);
    }

    #[tokio::test]
    async fn observation_preserves_storage_failure_panic() {
        let barrier = Barrier::from_handles::<()>([Handle::ready(Err(Error::WriteFailed))]);
        let result = std::panic::AssertUnwindSafe(observe(barrier, None, Instant::now()).durable())
            .catch_unwind()
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn dropping_observation_drops_the_original_wait_without_detaching_it() {
        struct DropProbe(Arc<AtomicUsize>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        for poll in [false, true] {
            let drops = Arc::new(AtomicUsize::new(0));
            let probe = DropProbe(drops.clone());
            let barrier = Barrier::from_handles::<()>([Handle::from_future(async move {
                let _probe = probe;
                std::future::pending::<Result<(), Error>>().await
            })]);
            let mut observed = Box::pin(observe(barrier, Some(9), Instant::now()).durable());
            if poll {
                assert!(observed.as_mut().now_or_never().is_none());
            }
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            drop(observed);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }
}
