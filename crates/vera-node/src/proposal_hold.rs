//! Stopping a validator between views.

use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::sync::watch;

const POLL: Duration = Duration::from_millis(5);

type FinalizedHeight = Box<dyn Fn() -> u64 + Send + Sync>;

/// Holds back new proposals and waits for the ones already made to finalize.
///
/// After a restart Simplex replays a validator's own journaled votes into its
/// round state but does not send them again, so no certificate forms from
/// them. A lone validator stopped after voting for a block and before storing
/// that block's certificate therefore waits out a view timeout on its next
/// start.
#[derive(Clone)]
pub struct ProposalHold {
    inner: Arc<Inner>,
}

struct Inner {
    held: watch::Sender<bool>,
    proposed: AtomicU64,
    /// Proposals being built or handed to consensus.
    building: AtomicU64,
    finalized: OnceLock<FinalizedHeight>,
}

/// Marks a proposal from the start of its build until its height is recorded
/// or the build is abandoned.
pub(crate) struct Building(Arc<Inner>);

impl Drop for Building {
    fn drop(&mut self) {
        self.0.building.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Default for ProposalHold {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                held: watch::Sender::new(false),
                proposed: AtomicU64::new(0),
                building: AtomicU64::new(0),
                finalized: OnceLock::new(),
            }),
        }
    }
}

impl std::fmt::Debug for ProposalHold {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProposalHold")
            .field("held", &*self.inner.held.borrow())
            .field("proposed", &self.inner.proposed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl ProposalHold {
    /// Sets where the durably finalized height is read from.
    pub(crate) fn attach(&self, finalized: impl Fn() -> u64 + Send + Sync + 'static) {
        let _ = self.inner.finalized.set(Box::new(finalized));
    }

    /// Marks a proposal in progress. [`Self::settle`] waits for it to be
    /// recorded or dropped, so the height it compares is the last one proposed.
    pub(crate) fn building(&self) -> Building {
        self.inner.building.fetch_add(1, Ordering::AcqRel);
        Building(self.inner.clone())
    }

    /// Records a block handed to consensus.
    pub(crate) fn record(&self, height: u64) {
        self.inner.proposed.fetch_max(height, Ordering::AcqRel);
    }

    /// Holds back new proposals without waiting for the ones already made.
    pub(crate) fn hold(&self) {
        self.inner.held.send_replace(true);
    }

    /// Lets proposals through again. A proposal that was already held back
    /// stays unanswered, so the next block waits out that view.
    pub(crate) fn release(&self) {
        self.inner.held.send_replace(false);
    }

    /// Whether proposals are held back.
    pub(crate) fn is_held(&self) -> bool {
        *self.inner.held.borrow()
    }

    /// Resolves once proposals are held back.
    pub(crate) async fn held(&self) {
        let mut held = self.inner.held.subscribe();
        if held.wait_for(|held| *held).await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    /// Holds back new proposals, then waits up to `limit` for every block
    /// already proposed to finalize. Returns whether they all did.
    pub async fn settle(&self, limit: Duration) -> bool {
        self.inner.held.send_replace(true);
        let Some(finalized) = self.inner.finalized.get() else {
            return true;
        };
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            tokio::time::sleep(POLL).await;
            // A proposal answered just before the hold is recorded once its mark is gone.
            if self.inner.building.load(Ordering::Acquire) == 0
                && finalized() >= self.inner.proposed.load(Ordering::Acquire)
            {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn settling_waits_for_the_proposed_height_and_gives_up_at_the_limit() {
        let hold = ProposalHold::default();
        let finalized = Arc::new(AtomicU64::new(3));
        let reader = finalized.clone();
        hold.attach(move || reader.load(Ordering::Acquire));
        hold.record(5);
        hold.record(4);

        assert!(!hold.settle(Duration::from_millis(100)).await);
        hold.held().await;

        let waiting = tokio::spawn({
            let hold = hold.clone();
            async move { hold.settle(Duration::from_secs(1)).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        finalized.store(5, Ordering::Release);
        assert!(waiting.await.unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_that_never_attached_has_nothing_to_wait_for() {
        let hold = ProposalHold::default();
        hold.record(9);
        assert!(hold.settle(Duration::from_secs(1)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn settling_waits_for_a_proposal_that_is_not_recorded_yet() {
        let hold = ProposalHold::default();
        let finalized = Arc::new(AtomicU64::new(3));
        let reader = finalized.clone();
        hold.attach(move || reader.load(Ordering::Acquire));
        hold.record(3);
        let building = hold.building();
        let settling = tokio::spawn({
            let hold = hold.clone();
            async move { hold.settle(Duration::from_secs(1)).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !settling.is_finished(),
            "the cut was chosen under a proposal"
        );
        hold.record(4);
        drop(building);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!settling.is_finished());
        finalized.store(4, Ordering::Release);
        assert!(settling.await.unwrap());
    }
}
