//! Refusing a finalized block of a term the node no longer accepts.

use std::sync::Arc;

use commonware_actor::Feedback;
use commonware_consensus::{Block as _, Reporter as ConsensusReporter, marshal::Update};
use commonware_cryptography::Digestible as _;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use vera_app::TermGuard;
use vera_domain::{Block, ConsensusDigest};

use super::TermRefusal;

/// The newest finalized block the node has applied, by height and digest.
#[derive(Clone, Debug, Default)]
pub(crate) struct Applied(Arc<Mutex<Option<(u64, ConsensusDigest)>>>);

impl Applied {
    /// Record the block the node starts from.
    pub(crate) fn seed(&self, height: u64, digest: ConsensusDigest) {
        *self.0.lock() = Some((height, digest));
    }
}

/// Stops a finalized block the node must not apply before it reaches execution.
///
/// A block above the cut in a lower term than the node holds comes from a
/// device that was replaced. A block that does not extend the node's newest
/// block comes from a history this device left: it missed a switch whose cut
/// was below blocks it kept. The application or Commonware's stateful actor
/// would panic on either. This reporter ends the node with
/// [`TermRefusal::LowerTerm`] or [`TermRefusal::Diverged`] instead. The
/// block stays in the consensus archive.
#[derive(Clone)]
pub(crate) struct TermReporter<R> {
    inner: R,
    guard: TermGuard,
    applied: Applied,
    refused: mpsc::UnboundedSender<TermRefusal>,
    /// The refused update. Its acknowledgement must not be dropped while the node stops.
    parked: Arc<Mutex<Option<Update<Block>>>>,
}

impl<R> TermReporter<R> {
    /// Refusals are sent to `refused`, whose receiver ends the node.
    pub(crate) fn new(
        inner: R,
        guard: TermGuard,
        applied: Applied,
        refused: mpsc::UnboundedSender<TermRefusal>,
    ) -> Self {
        Self {
            inner,
            guard,
            applied,
            refused,
            parked: Arc::default(),
        }
    }

    fn refusal(&self, block: &Block, parent: ConsensusDigest) -> Option<TermRefusal> {
        if !self.guard.admits_finalized(block.height, block.term) {
            return Some(TermRefusal::LowerTerm {
                height: block.height,
                term: block.term,
                held: self.guard.term(),
            });
        }
        let applied = *self.applied.0.lock();
        applied
            .filter(|(height, digest)| height + 1 == block.height && *digest != parent)
            .map(|(height, _)| TermRefusal::Diverged { height })
    }
}

impl<R: ConsensusReporter<Activity = Update<Block>>> ConsensusReporter for TermReporter<R> {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if self.parked.lock().is_some() {
            return Feedback::Ok;
        }
        if let Update::Block(block, _) = &activity {
            if let Some(refusal) = self.refusal(block.inner(), block.inner().parent()) {
                let _ = self.refused.send(refusal);
                *self.parked.lock() = Some(activity);
                return Feedback::Ok;
            }
            let mut applied = self.applied.0.lock();
            if applied.is_none_or(|(height, _)| block.inner().height > height) {
                *applied = Some((block.inner().height, block.digest()));
            }
        }
        self.inner.report(activity)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use commonware_cryptography::Digested;
    use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
    use vera_domain::{BlockId, DbTargets, StateRoot};

    use super::*;

    #[derive(Clone, Default)]
    struct Delivered(Arc<Mutex<Vec<u64>>>);

    impl ConsensusReporter for Delivered {
        type Activity = Update<Block>;
        fn report(&mut self, activity: Self::Activity) -> Feedback {
            if let Update::Block(block, _) = &activity {
                self.0.lock().push(block.inner().height);
            }
            Feedback::Ok
        }
    }

    fn block(height: u64, parent: BlockId, term: u64) -> Block {
        Block {
            context: Block::genesis_context(),
            parent,
            height,
            timestamp: height,
            term,
            state_root: StateRoot(B256::ZERO),
            module_state_root: B256::ZERO,
            txs: Vec::new(),
            payload: None,
            native_targets: None,
            receipt_commitment: None,
            db_targets: DbTargets::default(),
        }
    }

    fn deliver(reporter: &mut TermReporter<Delivered>, block: &Block) {
        let block = Digested::precomputed(block.clone(), block.digest());
        let (acknowledgement, _waiter) = Exact::handle();
        let _ = reporter.report(Update::Block(block, acknowledgement));
    }

    fn reporter() -> (
        TermReporter<Delivered>,
        Delivered,
        Applied,
        TermGuard,
        mpsc::UnboundedReceiver<TermRefusal>,
    ) {
        let (refused, refusals) = mpsc::unbounded_channel();
        let (delivered, applied, guard) = (
            Delivered::default(),
            Applied::default(),
            TermGuard::default(),
        );
        let reporter =
            TermReporter::new(delivered.clone(), guard.clone(), applied.clone(), refused);
        (reporter, delivered, applied, guard, refusals)
    }

    #[test]
    fn a_block_that_does_not_extend_the_applied_block_is_refused_as_diverged() {
        let (mut reporter, delivered, applied, _, mut refusals) = reporter();
        let first = block(5, BlockId(B256::repeat_byte(1)), 0);
        applied.seed(5, first.digest());
        let next = block(6, first.id(), 0);
        deliver(&mut reporter, &next);
        // The holder's history left this device's below its newest block.
        let foreign = block(7, BlockId(B256::repeat_byte(9)), 1);
        deliver(&mut reporter, &foreign);
        deliver(&mut reporter, &block(8, foreign.id(), 1));
        assert_eq!(*delivered.0.lock(), [6]);
        assert!(matches!(
            refusals.try_recv(),
            Ok(TermRefusal::Diverged { height: 6 })
        ));
        assert!(refusals.try_recv().is_err());
    }

    #[test]
    fn a_block_of_a_lower_term_above_the_cut_is_refused() {
        let (mut reporter, delivered, _, guard, mut refusals) = reporter();
        guard.raise(2, 5);
        deliver(&mut reporter, &block(5, BlockId(B256::ZERO), 1));
        deliver(&mut reporter, &block(6, BlockId(B256::ZERO), 1));
        assert_eq!(*delivered.0.lock(), [5]);
        assert!(matches!(
            refusals.try_recv(),
            Ok(TermRefusal::LowerTerm {
                height: 6,
                term: 1,
                held: 2
            })
        ));
    }
}
