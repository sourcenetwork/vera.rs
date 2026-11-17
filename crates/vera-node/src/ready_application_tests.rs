//! Proposals held back by recovery, a hold and the wake check.

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

    async fn verify(&mut self, _: (Context, Self::Context), _: impl Ancestry<Self::Block>) -> bool {
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
            ::tokio::time::timeout(std::time::Duration::from_millis(50), proposal.as_mut()).await;
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

const STAGED: u64 = 5;

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
        let mut block = vera_app::genesis_block(
            vera_domain::StateRoot(alloy_primitives::B256::ZERO),
            vera_domain::DbTargets::default(),
            alloy_primitives::B256::ZERO,
        );
        block.height = STAGED;
        let digest = commonware_cryptography::Digestible::digest(&block);
        Some(Digested::precomputed(block, digest))
    }

    async fn prepare(
        &mut self,
        context: (Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Handoff<Digested<Self::Block>> {
        self.propose(context, ancestry, input)
            .await
            .map_or(Handoff::Wait, Handoff::Stage)
    }

    async fn verify(&mut self, _: (Context, Self::Context), _: impl Ancestry<Self::Block>) -> bool {
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
        let (mut app, ready) = ReadyApplication::new(slow, crate::ProposalHold::default(), gate);
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

fn finalized_at(hold: &crate::ProposalHold, height: u64) {
    hold.attach(move || height);
}

fn stage(
    app: &mut ReadyApplication<SlowApp>,
    context: &Context,
) -> impl Future<Output = Handoff<Digested<Block>>> {
    app.prepare(
        (context.child("prepare"), Block::genesis_context()),
        ancestry::from_iter(std::iter::empty::<Digested<Block>>()),
        (),
    )
}

#[test]
fn a_staged_block_is_counted_until_it_finalizes() {
    tokio::Runner::default().start(|context| async move {
        let hold = crate::ProposalHold::default();
        finalized_at(&hold, STAGED - 1);
        let slow = SlowApp(std::time::Duration::ZERO);
        let (mut app, ready) =
            ReadyApplication::new(slow, hold.clone(), crate::term::WakeGate::default());
        ready.send_replace(true);
        assert!(matches!(stage(&mut app, &context).await, Handoff::Stage(_)));
        assert!(
            !hold.settle(std::time::Duration::from_millis(100)).await,
            "a handover settled below a staged block"
        );
    });
}

#[test]
fn a_hold_drops_a_block_staged_during_it() {
    tokio::Runner::default().start(|context| async move {
        let hold = crate::ProposalHold::default();
        finalized_at(&hold, STAGED - 1);
        let slow = SlowApp(std::time::Duration::from_millis(200));
        let (mut app, ready) =
            ReadyApplication::new(slow, hold.clone(), crate::term::WakeGate::default());
        ready.send_replace(true);
        let staging = context.child("staging");
        let staged = ::tokio::spawn(async move { stage(&mut app, &staging).await });
        ::tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(hold.settle(std::time::Duration::from_secs(1)).await);
        assert!(matches!(staged.await.unwrap(), Handoff::Wait));
    });
}
