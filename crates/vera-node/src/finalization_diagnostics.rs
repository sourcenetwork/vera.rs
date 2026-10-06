use commonware_actor::Feedback;
use commonware_consensus::{Reporter as ConsensusReporter, marshal::Update};
use vera_domain::Block;

#[derive(Clone)]
pub(crate) struct Reporter<R>(R);

impl<R> Reporter<R> {
    pub(crate) const fn new(inner: R) -> Self {
        Self(inner)
    }
}

impl<R: ConsensusReporter<Activity = Update<Block>>> ConsensusReporter for Reporter<R> {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let observed = (tracing::enabled!(target: "vera_diagnostics", tracing::Level::DEBUG)
            || tracing::enabled!(target: "vera_publication_diagnostics", tracing::Level::DEBUG))
        .then(|| match &activity {
            Update::Tip(round, height, _) => ("tip", height.get(), *round),
            Update::Block(block, _) => ("block", block.height, block.context.round),
        });
        let feedback = self.0.report(activity);
        if let Some((stage, height, round)) = observed {
            tracing::debug!(target: "vera_diagnostics", stage, height,
                epoch = round.epoch().get(), view = round.view().get(), ?feedback,
                "marshal stateful delivery");
            tracing::debug!(target: "vera_publication_diagnostics", stage, height,
                epoch = round.epoch().get(), view = round.view().get(), ?feedback,
                "marshal stateful delivery");
        }
        feedback
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use commonware_consensus::types::Height;
    use commonware_cryptography::sha256::Digest;
    use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
    use futures::FutureExt as _;
    use std::sync::{Arc, Mutex};
    use vera_domain::{BlockId, DbTargets, StateRoot};

    #[derive(Clone)]
    struct Recording {
        feedback: Feedback,
        updates: Arc<Mutex<Vec<Update<Block>>>>,
    }

    impl ConsensusReporter for Recording {
        type Activity = Update<Block>;
        fn report(&mut self, activity: Self::Activity) -> Feedback {
            self.updates.lock().unwrap().push(activity);
            self.feedback
        }
    }

    #[tokio::test]
    async fn observation_preserves_delivery_feedback_and_acknowledgement_ownership() {
        for feedback in [Feedback::Ok, Feedback::Backoff, Feedback::Closed] {
            let updates = Arc::new(Mutex::new(Vec::new()));
            let mut reporter = Reporter::new(Recording {
                feedback,
                updates: updates.clone(),
            });
            let block = Arc::new(Block {
                context: Block::genesis_context(),
                parent: BlockId(B256::ZERO),
                height: 7,
                timestamp: 7,
                prevrandao: B256::ZERO,
                state_root: StateRoot(B256::ZERO),
                module_state_root: B256::ZERO,
                txs: Vec::new(),
                payload: None,
                native_targets: None,
                receipt_commitment: None,
                db_targets: DbTargets::default(),
            });
            assert_eq!(
                reporter.report(Update::Tip(
                    block.context.round,
                    Height::new(7),
                    Digest::from([0; 32])
                )),
                feedback
            );
            assert!(
                matches!(updates.lock().unwrap().pop(), Some(Update::Tip(_, height, _)) if height.get() == 7)
            );
            let (acknowledgement, mut waiter) = Exact::handle();
            assert_eq!(
                reporter.report(Update::Block(block.clone(), acknowledgement)),
                feedback
            );
            assert!((&mut waiter).now_or_never().is_none());
            let Some(Update::Block(forwarded, acknowledgement)) = updates.lock().unwrap().pop()
            else {
                panic!("missing original block delivery");
            };
            assert!(Arc::ptr_eq(&block, &forwarded));
            acknowledgement.acknowledge();
            waiter.await.unwrap();

            let (acknowledgement, waiter) = Exact::handle();
            reporter.report(Update::Block(block, acknowledgement));
            updates.lock().unwrap().clear();
            assert!(
                waiter.await.is_err(),
                "dropped delivery must remain cancelled"
            );
        }
    }
}
