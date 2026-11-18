//! A lone validator's wait for a first request before it proposes.

use std::{
    collections::BTreeSet,
    sync::{Arc, OnceLock},
    time::Duration,
};

use commonware_consensus::{Application, Handoff, marshal::ancestry::Ancestry};
use commonware_cryptography::Digested;
use commonware_runtime::tokio::Context;
use futures::StreamExt as _;
use vera_consensus::{TxId, components::InMemoryMempool};
use vera_domain::Block;

/// Unfinalized ancestors whose requests a new block must not repeat, as the
/// application bounds them.
const MAX_PENDING_ANCESTORS: usize = 64;

type FinalizedHeight = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Waits up to `idle` for a request before a proposal request reaches `inner`.
///
/// The stateful actor processes finalized blocks only between builds, so a
/// wait inside the build would hold back the previous block's finality
/// evidence until the wait ended. Waiting here leaves the actor free.
///
/// The first proposal since the start does not wait: a client that verifies
/// state against finalized headers needs a current one before it can read.
#[derive(Clone)]
pub(crate) struct IdlePacing<A> {
    inner: A,
    pacing: Pacing,
}

#[derive(Clone)]
struct Pacing {
    mempool: InMemoryMempool,
    idle: Duration,
    finalized: FinalizedHeight,
    first_parent: Arc<OnceLock<u64>>,
}

impl<A> IdlePacing<A> {
    /// A zero `idle` hands every request on at once.
    pub(crate) fn new(
        inner: A,
        mempool: InMemoryMempool,
        idle: Duration,
        finalized: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner,
            pacing: Pacing {
                mempool,
                idle,
                finalized: Arc::new(finalized),
                first_parent: Arc::default(),
            },
        }
    }
}

impl Pacing {
    async fn wait_for_request(&self, mut ancestors: impl Ancestry<Block>) {
        if self.idle.is_zero() {
            return;
        }
        let Some(parent) = ancestors.next().await else {
            return;
        };
        let height = parent.inner().height;
        if height <= *self.first_parent.get_or_init(|| height) {
            return;
        }
        // Requests in unfinalized ancestors stay in the pool until their
        // block's finalization is processed, and do not end the wait.
        let finalized = (self.finalized)();
        let mut excluded = BTreeSet::<TxId>::new();
        let mut pending = 0;
        let mut next = Some(parent);
        while let Some(block) = next.take() {
            let block = block.inner();
            excluded.extend(block.txs.iter().map(vera_domain::Tx::id));
            pending += 1;
            if block.height <= finalized || pending == MAX_PENDING_ANCESTORS {
                break;
            }
            next = ancestors.next().await;
        }
        self.mempool.await_request(&excluded, self.idle).await;
    }
}

impl<A> Application<Context> for IdlePacing<A>
where
    A: Application<Context, Block = Block>,
    A::Context: Send,
{
    type SigningScheme = A::SigningScheme;
    type Context = A::Context;
    type Block = Block;
    type Input = A::Input;

    async fn prepare(
        &mut self,
        context: (Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Handoff<Digested<Self::Block>> {
        self.pacing.wait_for_request(ancestry.clone()).await;
        self.inner.prepare(context, ancestry, input).await
    }

    async fn propose(
        &mut self,
        context: (Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Option<Digested<Self::Block>> {
        self.pacing.wait_for_request(ancestry.clone()).await;
        self.inner.propose(context, ancestry, input).await
    }

    async fn verify(
        &mut self,
        context: (Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        self.inner.verify(context, ancestry).await
    }
}

#[cfg(test)]
#[path = "idle_pacing_tests.rs"]
mod tests;
