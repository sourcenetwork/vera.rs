//! The check a device makes before proposing after a gap in its own blocks.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use tokio::sync::{mpsc, oneshot};

use super::control::{Asked, Command};

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
            inner.last.store(timestamp, Ordering::Release);
        }
    }

    /// Record a block this device proposed.
    pub(crate) fn proposed(&self) {
        if let Some(inner) = &self.0 {
            inner.last.store(now(), Ordering::Release);
        }
    }

    /// Whether the newest block is inside the freshness window, so the
    /// device may build without asking.
    pub(crate) fn fresh(&self) -> bool {
        self.0.as_ref().is_none_or(|inner| {
            let last = inner.last.load(Ordering::Acquire);
            // A device with no block of its own, a block dated after the
            // local clock, or a clock set back cannot show it is fresh.
            now()
                .checked_sub(last)
                .is_some_and(|gap| last != 0 && gap <= inner.freshness.as_secs())
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
            Ok(Asked::Clear) | Err(_) => inner.last.store(now(), Ordering::Release),
            // The next proposal asks again.
            Ok(Asked::Contested | Asked::Replaced) => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answering(answer: Asked) -> (WakeGate, tokio::task::JoinHandle<usize>) {
        let (sender, mut commands) = mpsc::unbounded_channel();
        let gate = WakeGate::new(Duration::from_secs(30), sender);
        let asked = tokio::spawn(async move {
            let mut asked = 0;
            while let Some(Command::Probe { reply }) = commands.recv().await {
                asked += 1;
                let _ = reply.send(answer);
            }
            asked
        });
        (gate, asked)
    }

    #[tokio::test]
    async fn a_device_asks_only_after_a_gap_longer_than_the_window() {
        let (gate, asked) = answering(Asked::Clear);
        gate.seed(now() - 10);
        gate.pass().await;
        gate.seed(1);
        gate.proposed();
        gate.pass().await;
        drop(gate);
        assert_eq!(asked.await.unwrap(), 0);

        let (gate, asked) = answering(Asked::Clear);
        gate.seed(now() - 31);
        assert!(!gate.fresh());
        gate.pass().await;
        // The answer covers the proposals that follow it.
        gate.pass().await;
        drop(gate);
        assert_eq!(asked.await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_device_that_cannot_show_it_is_fresh_asks() {
        // No block of its own, and a newest block dated after the local clock.
        for seed in [None, Some(now() + 3_600)] {
            let (gate, asked) = answering(Asked::Clear);
            if let Some(timestamp) = seed {
                gate.seed(timestamp);
            }
            assert!(!gate.fresh(), "{seed:?}");
            gate.pass().await;
            assert!(gate.fresh());
            drop(gate);
            assert_eq!(asked.await.unwrap(), 1, "{seed:?}");
        }
    }

    #[tokio::test]
    async fn a_device_told_another_one_validates_does_not_pass() {
        for answer in [Asked::Replaced, Asked::Contested] {
            let (gate, _asked) = answering(answer);
            gate.seed(now() - 31);
            let passed = tokio::time::timeout(Duration::from_millis(100), gate.pass()).await;
            assert!(passed.is_err(), "{answer:?}");
            assert!(!gate.fresh());
        }
    }

    #[tokio::test]
    async fn a_node_without_switching_never_asks() {
        WakeGate::default().pass().await;
        assert!(WakeGate::default().fresh());
    }
}
