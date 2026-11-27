//! The thread an embedded node runs on, as its owner stops and joins it.

use std::thread::JoinHandle;

use tokio::sync::oneshot;
use vera_jsonrpc::LocalRpc;

use super::EmbedError;

/// A node thread, its stop signal and the result it reports when it ends.
///
/// Every wait borrows the owner, so a caller that is dropped while it waits
/// leaves the thread with an owner that can still stop and join it. Dropping
/// the owner asks the thread to stop and does not wait for it.
#[derive(Debug)]
pub(super) struct NodeThread {
    stop: Option<oneshot::Sender<()>>,
    exit: Option<oneshot::Receiver<Result<(), EmbedError>>>,
    outcome: Option<Result<(), EmbedError>>,
    handle: Option<JoinHandle<()>>,
}

impl NodeThread {
    pub(super) const fn new(
        stop: oneshot::Sender<()>,
        exit: oneshot::Receiver<Result<(), EmbedError>>,
        handle: JoinHandle<()>,
    ) -> Self {
        Self {
            stop: Some(stop),
            exit: Some(exit),
            outcome: None,
            handle: Some(handle),
        }
    }

    /// Ask the node to stop. It may already have stopped by itself.
    pub(super) fn signal(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    /// Wait for the thread's result and keep it.
    async fn exited(&mut self) {
        if let Some(exit) = &mut self.exit {
            let outcome = exit.await.unwrap_or(Err(EmbedError::Panicked));
            // A completed receiver panics when polled again.
            self.exit = None;
            self.outcome = Some(outcome);
        }
    }

    /// Wait until the node serves requests. A node that ends first is joined.
    pub(super) async fn started(
        &mut self,
        ready: &mut oneshot::Receiver<LocalRpc>,
    ) -> Result<LocalRpc, EmbedError> {
        ::tokio::select! {
            Ok(rpc) = ready => return Ok(rpc),
            () = self.exited() => {}
        }
        Err(self.halt().await.err().unwrap_or(EmbedError::Panicked))
    }

    /// Wait until the node stops on its own, which is always an error.
    pub(super) async fn failed(&mut self) -> EmbedError {
        self.exited().await;
        match self.outcome.take() {
            Some(Err(error)) => error,
            Some(Ok(())) | None => EmbedError::Panicked,
        }
    }

    /// Stop the node and join its thread. Once this returns the thread has
    /// ended; a call after that returns `Ok`.
    pub(super) async fn halt(&mut self) -> Result<(), EmbedError> {
        self.signal();
        self.exited().await;
        // The thread has sent its result or is unwinding, so this join is brief.
        let joined = self.handle.take().map_or(Ok(()), JoinHandle::join);
        match (self.outcome.take(), joined) {
            (outcome, Ok(())) => outcome.unwrap_or(Ok(())),
            (_, Err(_)) => Err(EmbedError::Panicked),
        }
    }

    #[cfg(test)]
    pub(super) fn id(&self) -> Option<std::thread::ThreadId> {
        self.handle.as_ref().map(|handle| handle.thread().id())
    }
}
