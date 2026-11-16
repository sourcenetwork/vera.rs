//! Refusing a finalized block of a term the node no longer accepts.

use std::sync::Arc;

use commonware_actor::Feedback;
use commonware_consensus::{Reporter as ConsensusReporter, marshal::Update};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use vera_app::TermGuard;
use vera_domain::Block;

use super::TermRefusal;

/// Stops a finalized block of a lower term before it reaches execution.
///
/// The application refuses such a block too, and Commonware's stateful actor
/// panics on a finalized block its application refuses. This reporter ends
/// the node with [`TermRefusal::LowerTerm`] instead. The block stays in the
/// consensus archive, so the directory needs the consensus state of the
/// device that holds the term before it can follow again.
#[derive(Clone)]
pub(crate) struct TermReporter<R> {
    inner: R,
    guard: TermGuard,
    refused: mpsc::UnboundedSender<TermRefusal>,
    /// The refused update. Its acknowledgement must not be dropped while the node stops.
    parked: Arc<Mutex<Option<Update<Block>>>>,
}

impl<R> TermReporter<R> {
    /// Refusals are sent to `refused`, whose receiver ends the node.
    pub(crate) fn new(
        inner: R,
        guard: TermGuard,
        refused: mpsc::UnboundedSender<TermRefusal>,
    ) -> Self {
        Self {
            inner,
            guard,
            refused,
            parked: Arc::default(),
        }
    }
}

impl<R: ConsensusReporter<Activity = Update<Block>>> ConsensusReporter for TermReporter<R> {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if self.parked.lock().is_some() {
            return Feedback::Ok;
        }
        if let Update::Block(block, _) = &activity {
            let (height, term) = (block.inner().height, block.inner().term);
            if !self.guard.admits_finalized(height, term) {
                let _ = self.refused.send(TermRefusal::LowerTerm {
                    height,
                    term,
                    held: self.guard.term(),
                });
                *self.parked.lock() = Some(activity);
                return Feedback::Ok;
            }
        }
        self.inner.report(activity)
    }
}
