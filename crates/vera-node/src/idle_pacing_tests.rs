//! When a lone validator's proposal request waits for a first request.

use super::*;
use commonware_consensus::marshal::ancestry;
use commonware_cryptography::Digestible as _;
use commonware_runtime::{Runner as _, Supervisor as _, tokio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use vera_consensus::Mempool as _;
use vera_domain::{ConsensusContext, Tx};

/// Longer than any test runs, so only a request can end the wait.
const IDLE: Duration = Duration::from_secs(3600);
const SHORT: Duration = Duration::from_millis(200);

#[derive(Clone, Default)]
struct CountingApp(Arc<AtomicUsize>);

impl Application<Context> for CountingApp {
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
        self.0.fetch_add(1, Ordering::SeqCst);
        None
    }

    async fn verify(&mut self, _: (Context, Self::Context), _: impl Ancestry<Self::Block>) -> bool {
        true
    }
}

fn block(height: u64, txs: Vec<Tx>) -> Digested<Block> {
    child(None, height, txs)
}

fn child(parent: Option<&Digested<Block>>, height: u64, txs: Vec<Tx>) -> Digested<Block> {
    let mut block = vera_app::genesis_block(
        alloy_primitives::B256::ZERO,
        Default::default(),
        alloy_primitives::B256::ZERO,
    );
    if let Some(parent) = parent {
        block.parent = parent.inner().id();
    }
    block.height = height;
    block.txs = txs;
    let digest = block.digest();
    Digested::precomputed(block, digest)
}

fn request(byte: u8) -> Tx {
    Tx::new(vec![byte].into())
}

struct Pacer {
    app: IdlePacing<CountingApp>,
    calls: Arc<AtomicUsize>,
    mempool: InMemoryMempool,
    finalized: Arc<AtomicU64>,
}

fn pacer(idle: Duration) -> Pacer {
    let inner = CountingApp::default();
    let calls = inner.0.clone();
    let mempool = InMemoryMempool::new();
    let finalized = Arc::new(AtomicU64::new(0));
    let reader = finalized.clone();
    let app = IdlePacing::new(inner, mempool.clone(), idle, move || {
        reader.load(Ordering::SeqCst)
    });
    Pacer {
        app,
        calls,
        mempool,
        finalized,
    }
}

async fn propose(
    app: &mut IdlePacing<CountingApp>,
    context: &Context,
    blocks: Vec<Digested<Block>>,
) {
    let _ = app
        .propose(
            (context.child("propose"), Block::genesis_context()),
            ancestry::from_iter(blocks),
            (),
        )
        .await;
}

#[test]
fn the_first_proposal_since_the_start_does_not_wait() {
    tokio::Runner::default().start(|context| async move {
        let Pacer { mut app, calls, .. } = pacer(IDLE);
        propose(&mut app, &context, vec![block(4, Vec::new())]).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // The same parent again: nothing of this node's has been built on yet.
        propose(&mut app, &context, vec![block(4, Vec::new())]).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn a_later_proposal_waits_for_a_request_or_the_idle_limit() {
    tokio::Runner::default().start(|context| async move {
        let Pacer {
            mut app,
            calls,
            mempool,
            ..
        } = pacer(IDLE);
        propose(&mut app, &context, vec![block(1, Vec::new())]).await;

        let mut waiting = app.clone();
        let child = context.child("waiting");
        let mut proposal = Box::pin(async move {
            propose(&mut waiting, &child, vec![block(2, Vec::new())]).await;
        });
        assert!(
            ::tokio::time::timeout(SHORT, &mut proposal).await.is_err(),
            "an idle proposal reached the application"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(mempool.insert(request(1)));
        ::tokio::time::timeout(Duration::from_secs(10), proposal)
            .await
            .expect("a request ends the wait");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let Pacer { mut app, calls, .. } = pacer(SHORT);
        propose(&mut app, &context, vec![block(1, Vec::new())]).await;
        let started = std::time::Instant::now();
        propose(&mut app, &context, vec![block(2, Vec::new())]).await;
        assert!(started.elapsed() >= SHORT);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn requests_of_unfinalized_ancestors_do_not_end_the_wait() {
    tokio::Runner::default().start(|context| async move {
        let Pacer {
            mut app,
            calls,
            mempool,
            finalized,
        } = pacer(IDLE);
        propose(&mut app, &context, vec![block(1, Vec::new())]).await;
        finalized.store(1, Ordering::SeqCst);
        let (included, earlier) = (request(1), request(2));
        assert!(mempool.insert(included.clone()));
        assert!(mempool.insert(earlier.clone()));
        let first = block(1, Vec::new());
        let second = child(Some(&first), 2, vec![earlier]);
        let third = child(Some(&second), 3, vec![included]);
        let ancestors = vec![third, second, first];

        let mut waiting = app.clone();
        let child = context.child("waiting");
        let mut proposal = Box::pin(async move {
            propose(&mut waiting, &child, ancestors).await;
        });
        assert!(
            ::tokio::time::timeout(SHORT, &mut proposal).await.is_err(),
            "a request already in a block ended the wait"
        );
        assert!(mempool.insert(request(3)));
        ::tokio::time::timeout(Duration::from_secs(10), proposal)
            .await
            .expect("a new request ends the wait");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn no_idle_limit_hands_every_request_on() {
    tokio::Runner::default().start(|context| async move {
        let Pacer { mut app, calls, .. } = pacer(Duration::ZERO);
        for height in 1..4 {
            propose(&mut app, &context, vec![block(height, Vec::new())]).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    });
}
