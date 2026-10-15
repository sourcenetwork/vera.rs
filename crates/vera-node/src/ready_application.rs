//! Keep speculative DKG work behind recovered execution state.

use commonware_consensus::{Application, Handoff, marshal::ancestry::Ancestry};
use commonware_cryptography::Digested;
use commonware_runtime::tokio::Context;
use tokio::sync::watch;

#[derive(Clone)]
pub(crate) struct ReadyApplication<A> {
    inner: A,
    ready: watch::Receiver<bool>,
}

impl<A> ReadyApplication<A> {
    pub(crate) fn new(inner: A) -> (Self, watch::Sender<bool>) {
        let (sender, ready) = watch::channel(false);
        (Self { inner, ready }, sender)
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
        if !*self.ready.borrow() {
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
        if !*self.ready.borrow() {
            return None;
        }
        self.inner.propose(context, ancestry, input).await
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
    fn recovery_gates_both_prepared_and_ordinary_proposals() {
        tokio::Runner::default().start(|context| async move {
            let inner = RecordingApp::default();
            let calls = inner.0.clone();
            let (mut app, ready) = ReadyApplication::new(inner);
            for expected in [0, 2] {
                let _ = app
                    .prepare(
                        (context.child("prepare"), Block::genesis_context()),
                        ancestry::from_iter(std::iter::empty::<Digested<Block>>()),
                        (),
                    )
                    .await;
                assert!(
                    app.propose(
                        (context.child("propose"), Block::genesis_context()),
                        ancestry::from_iter(std::iter::empty::<Digested<Block>>()),
                        (),
                    )
                    .await
                    .is_none()
                );
                assert_eq!(calls.load(Ordering::Relaxed), expected);
                ready.send(true).unwrap();
            }
        });
    }
}
