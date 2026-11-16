//! The check a device makes before proposing after a gap in its own blocks.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::sync::{mpsc, oneshot};

use super::control::Command;

/// Holds a proposal back until the other devices were asked for a later term.
///
/// An active device that slept, or was stopped, cannot tell whether another
/// device took the deployment over meanwhile. Once its newest block is older
/// than the freshness window it asks before proposing. The window is measured
/// on the wall clock, which keeps running while a device sleeps.
#[derive(Clone, Debug, Default)]
pub(crate) struct WakeGate(Option<Arc<Inner>>);

#[derive(Debug)]
struct Inner {
    freshness: Duration,
    /// Unix seconds of this device's newest block; zero before its first.
    last: AtomicU64,
    commands: mpsc::UnboundedSender<Command>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

impl WakeGate {
    pub(crate) fn new(freshness: Duration, commands: mpsc::UnboundedSender<Command>) -> Self {
        Self(Some(Arc::new(Inner {
            freshness,
            last: AtomicU64::new(0),
            commands,
        })))
    }

    /// Record the time of the newest block the device starts from.
    pub(crate) fn seed(&self, timestamp: u64) {
        if let Some(inner) = &self.0 {
            inner.last.fetch_max(timestamp, Ordering::AcqRel);
        }
    }

    /// Record a block this device proposed.
    pub(crate) fn proposed(&self) {
        if let Some(inner) = &self.0 {
            inner.last.fetch_max(now(), Ordering::AcqRel);
        }
    }

    /// Whether the newest block is inside the freshness window, so the
    /// device may build without asking.
    pub(crate) fn fresh(&self) -> bool {
        self.0.as_ref().is_none_or(|inner| {
            let last = inner.last.load(Ordering::Acquire);
            last == 0 || now().saturating_sub(last) <= inner.freshness.as_secs()
        })
    }

    /// Resolves when this device may propose, and never if another device
    /// holds a later term.
    pub(crate) async fn pass(&self) {
        let Some(inner) = &self.0 else {
            return;
        };
        if self.fresh() {
            return;
        }
        let (reply, answer) = oneshot::channel();
        if inner.commands.send(Command::Probe { reply }).is_err() {
            return;
        }
        match answer.await {
            Ok(true) | Err(_) => inner.last.store(now(), Ordering::Release),
            Ok(false) => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answering(clear: bool) -> (WakeGate, tokio::task::JoinHandle<usize>) {
        let (sender, mut commands) = mpsc::unbounded_channel();
        let gate = WakeGate::new(Duration::from_secs(30), sender);
        let asked = tokio::spawn(async move {
            let mut asked = 0;
            while let Some(Command::Probe { reply }) = commands.recv().await {
                asked += 1;
                let _ = reply.send(clear);
            }
            asked
        });
        (gate, asked)
    }

    #[tokio::test]
    async fn a_device_asks_only_after_a_gap_longer_than_the_window() {
        let (gate, asked) = answering(true);
        gate.pass().await;
        gate.seed(now() - 10);
        gate.pass().await;
        gate.seed(1);
        gate.proposed();
        gate.pass().await;
        drop(gate);
        assert_eq!(asked.await.unwrap(), 0);

        let (gate, asked) = answering(true);
        gate.seed(now() - 31);
        gate.pass().await;
        // The answer covers the proposals that follow it.
        gate.pass().await;
        drop(gate);
        assert_eq!(asked.await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_device_that_learns_of_a_later_term_never_passes() {
        let (gate, _asked) = answering(false);
        gate.seed(now() - 31);
        let passed = tokio::time::timeout(Duration::from_millis(100), gate.pass()).await;
        assert!(passed.is_err());
    }

    #[tokio::test]
    async fn a_node_without_switching_never_asks() {
        WakeGate::default().pass().await;
    }
}
