//! Keep speculative DKG work behind recovered execution state.

use commonware_consensus::{Application, Handoff, Heightable as _, marshal::ancestry::Ancestry};
use commonware_cryptography::Digested;
use commonware_runtime::tokio::Context;
use tokio::sync::watch;

#[derive(Clone)]
pub(crate) struct ReadyApplication<A> {
    inner: A,
    ready: watch::Receiver<bool>,
    hold: crate::ProposalHold,
    gate: crate::term::WakeGate,
}

impl<A> ReadyApplication<A> {
    pub(crate) fn new(
        inner: A,
        hold: crate::ProposalHold,
        gate: crate::term::WakeGate,
    ) -> (Self, watch::Sender<bool>) {
        let (sender, ready) = watch::channel(false);
        (
            Self {
                inner,
                ready,
                hold,
                gate,
            },
            sender,
        )
    }
}

impl<A> Application<Context> for ReadyApplication<A>
where
    A: Application<Context>,
    A::Context: Send,
{
    type SigningScheme = A::SigningScheme;
    type Context = A::Context;
    type Block = A::Block;
    type Input = A::Input;

    async fn prepare(
        &mut self,
        context: (Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Handoff<Digested<Self::Block>> {
        // A block built ahead of its turn would escape a hold and the wake check.
        if !*self.ready.borrow() || self.hold.is_held() || !self.gate.fresh() {
            return Handoff::Wait;
        }
        self.inner.prepare(context, ancestry, input).await
    }

    async fn propose(
        &mut self,
        context: (Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Option<Digested<Self::Block>> {
        // Declining here would cost the whole view: a validator that starts as
        // leader would wait out the leader timeout before its next proposal.
        // Consensus drops this request if recovery outlasts the view.
        if self.ready.wait_for(|ready| *ready).await.is_err() {
            return None;
        }
        // A host that is stopping must not be left with a vote whose
        // certificate it has not stored; consensus drops the unanswered request.
        let building = self.hold.building();
        let proposal = tokio::select! {
            biased;
            () = self.hold.held() => {
                drop(building);
                return std::future::pending().await;
            }
            proposal = async {
                // A device that may have been replaced asks before it builds.
                self.gate.pass().await;
                let proposal = self.inner.propose(context, ancestry, input).await;
                // The build can wait for a first request, and the machine can
                // sleep inside that wait: ask again before the block leaves.
                if proposal.is_some() {
                    self.gate.pass().await;
                }
                proposal
            } => proposal,
        };
        if let Some(block) = &proposal {
            self.hold.record(block.height().get());
            self.gate.proposed();
        }
        drop(building);
        proposal
    }

    async fn verify(
        &mut self,
        context: (Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        if self.ready.wait_for(|ready| *ready).await.is_err() {
            // Startup failure cannot establish that a peer's proposal is invalid.
            return std::future::pending().await;
        }
        self.inner.verify(context, ancestry).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::marshal::ancestry;
    use commonware_runtime::{Runner as _, Supervisor as _, tokio};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use vera_domain::{Block, ConsensusContext};

    #[derive(Clone, Default)]
    struct RecordingApp(Arc<AtomicUsize>);

    impl Application<Context> for RecordingApp {
        type SigningScheme = vera_app::ConsensusScheme;
        type Context = ConsensusContext;
        type Block = Block;
        type Input = ();

        async fn prepare(
            &mut self,
            _: (Context, Self::Context),
            _: impl Ancestry<Self::Block>,
            _: Self::Input,
        ) -> Handoff<Digested<Self::Block>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Handoff::Wait
        }

        async fn propose(
            &mut self,
            _: (Context, Self::Context),
            _: impl Ancestry<Self::Block>,
            _: Self::Input,
        ) -> Option<Digested<Self::Block>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            None
        }

        async fn verify(
            &mut self,
            _: (Context, Self::Context),
            _: impl Ancestry<Self::Block>,
        ) -> bool {
            true
        }
    }

    #[test]
    fn a_proposal_waits_for_recovery_instead_of_giving_up_its_view() {
        tokio::Runner::default().start(|context| async move {
            let inner = RecordingApp::default();
            let calls = inner.0.clone();
            let (mut app, ready) = ReadyApplication::new(
                inner,
                crate::ProposalHold::default(),
                crate::term::WakeGate::default(),
            );
            let _ = app
                .prepare(
                    (context.child("prepare"), Block::genesis_context()),
                    ancestry::from_iter(std::iter::empty::<Digested<Block>>()),
                    (),
                )
                .await;
            assert_eq!(calls.load(Ordering::Relaxed), 0);

            let mut proposer = app.clone();
            let propose_context = context.child("propose");
            let mut proposal = Box::pin(async move {
                proposer
                    .propose(
                        (propose_context, Block::genesis_context()),
                        ancestry::from_iter(std::iter::empty::<Digested<Block>>()),
                        (),
                    )
                    .await
            });
            let waited =
                ::tokio::time::timeout(std::time::Duration::from_millis(50), proposal.as_mut())
                    .await;
            assert!(waited.is_err(), "a proposal was answered before recovery");
            assert_eq!(calls.load(Ordering::Relaxed), 0);

            ready.send(true).unwrap();
            assert!(proposal.await.is_none());
            assert_eq!(calls.load(Ordering::Relaxed), 1);

            let _ = app
                .prepare(
                    (context.child("prepared"), Block::genesis_context()),
                    ancestry::from_iter(std::iter::empty::<Digested<Block>>()),
                    (),
                )
                .await;
            assert_eq!(calls.load(Ordering::Relaxed), 2);
        });
    }

    #[test]
    fn a_proposal_is_declined_when_recovery_fails() {
        tokio::Runner::default().start(|context| async move {
            let inner = RecordingApp::default();
            let calls = inner.0.clone();
            let (mut app, ready) = ReadyApplication::new(
                inner,
                crate::ProposalHold::default(),
                crate::term::WakeGate::default(),
            );
            drop(ready);
            assert!(
                app.propose(
                    (context.child("propose"), Block::genesis_context()),
                    ancestry::from_iter(std::iter::empty::<Digested<Block>>()),
                    (),
                )
                .await
                .is_none()
            );
            assert_eq!(calls.load(Ordering::Relaxed), 0);
        });
    }

    /// Builds a block after `0` has passed, as a proposer does that waits for a first request.
    #[derive(Clone)]
    struct SlowApp(std::time::Duration);

    impl Application<Context> for SlowApp {
        type SigningScheme = vera_app::ConsensusScheme;
        type Context = ConsensusContext;
        type Block = Block;
        type Input = ();

        async fn propose(
            &mut self,
            _: (Context, Self::Context),
            _: impl Ancestry<Self::Block>,
            _: Self::Input,
        ) -> Option<Digested<Self::Block>> {
            ::tokio::time::sleep(self.0).await;
            let block = vera_app::genesis_block(
                vera_domain::StateRoot(alloy_primitives::B256::ZERO),
                vera_domain::DbTargets::default(),
                alloy_primitives::B256::ZERO,
            );
            let digest = commonware_cryptography::Digestible::digest(&block);
            Some(Digested::precomputed(block, digest))
        }

        async fn verify(
            &mut self,
            _: (Context, Self::Context),
            _: impl Ancestry<Self::Block>,
        ) -> bool {
            true
        }
    }

    #[test]
    fn a_gap_inside_the_build_is_checked_before_the_block_reaches_consensus() {
        tokio::Runner::default().start(|context| async move {
            let (sender, mut commands) = ::tokio::sync::mpsc::unbounded_channel();
            let gate = crate::term::WakeGate::new(std::time::Duration::from_secs(1), sender);
            gate.proposed();
            let asked = Arc::new(AtomicUsize::new(0));
            let counted = asked.clone();
            ::tokio::spawn(async move {
                while let Some(crate::term::Command::Probe { reply }) = commands.recv().await {
                    counted.fetch_add(1, Ordering::Relaxed);
                    let _ = reply.send(crate::term::Asked::Replaced);
                }
            });
            // The device was fresh when the build began and is not when it ends.
            let slow = SlowApp(std::time::Duration::from_millis(2_100));
            let (mut app, ready) =
                ReadyApplication::new(slow, crate::ProposalHold::default(), gate);
            ready.send_replace(true);
            let proposal = app.propose(
                (context.child("propose"), Block::genesis_context()),
                ancestry::from_iter(std::iter::empty::<Digested<Block>>()),
                (),
            );
            let handed = ::tokio::time::timeout(std::time::Duration::from_secs(4), proposal).await;
            assert!(
                handed.is_err(),
                "a block built across the gap reached consensus"
            );
            assert_eq!(asked.load(Ordering::Relaxed), 1);
        });
    }
}
