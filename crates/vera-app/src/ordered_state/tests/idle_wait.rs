use super::*;
use crate::{FinalizedSink, ReshareInput, StatefulVeraApp};
use commonware_consensus::marshal::ancestry;
use commonware_cryptography::{Digested, Digestible as _};
use commonware_glue::stateful::{Application, Input};
use std::sync::atomic::{AtomicU64, Ordering};
use vera_consensus::{Mempool as _, components::InMemoryMempool};
use vera_domain::Block;
use vera_executor::ExecutionReceipt;

const IDLE: Duration = Duration::from_millis(400);

#[derive(Clone, Default)]
struct HeightSink(Arc<AtomicU64>);

impl FinalizedSink for HeightSink {
    fn finalized_height(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    async fn finalized(&self, _: &Block, _: Vec<ExecutionReceipt>) {}
}

fn block_ancestry<const N: usize>(blocks: [Block; N]) -> impl ancestry::Ancestry<Block> {
    ancestry::from_iter(blocks.map(|block| {
        let digest = block.digest();
        Digested::precomputed(block, digest)
    }))
}

fn input(mempool: &InMemoryMempool) -> Input<ReshareInput, InMemoryMempool> {
    Input {
        upstream: ReshareInput {
            upstream: (),
            payload: None,
        },
        provider: mempool.clone(),
    }
}

#[test]
fn a_finalized_parent_with_requests_does_not_cut_the_idle_wait_short() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| {
            Box::pin(async move {
                let executor = VeraExecutor::new(DEPLOYMENT);
                let set = OrderedState::init(
                    context.child("state"),
                    config(&context, "state", executor.clone()),
                    None,
                )
                .await;
                let genesis = checkpoint::block(&set, 0).await;
                let mempool = InMemoryMempool::new();
                let sink = HeightSink::default();
                let mut app = StatefulVeraApp::<HeightSink>::new(
                    executor,
                    genesis.clone(),
                    mempool.clone(),
                    sink.clone(),
                    64,
                    30_000_000,
                )
                .with_native_pipeline(true, Duration::ZERO)
                .with_idle_wait(IDLE);
                let request = policy(&BlsSigner::new(1u64.into(), DEPLOYMENT).unwrap(), "idle");
                assert!(mempool.insert(request.clone()));
                let mut round = Block::genesis_context();
                round.round = Round::new(Epoch::zero(), View::new(1));
                let first = app
                    .propose(
                        (context.child("first"), round.clone()),
                        block_ancestry([genesis.clone()]),
                        set.new_batches().await,
                        input(&mempool),
                    )
                    .await
                    .unwrap();
                assert_eq!(first.block.txs, vec![request.clone()]);
                mempool.prune(&[request.id()]);

                round.round = Round::new(Epoch::zero(), View::new(2));
                let unfinalized = std::time::Instant::now();
                let second = app
                    .propose(
                        (context.child("unfinalized"), round.clone()),
                        block_ancestry([first.block.clone(), genesis.clone()]),
                        OrderedState::fork_batches(&first.merkleized),
                        input(&mempool),
                    )
                    .await
                    .unwrap();
                assert!(second.block.txs.is_empty());
                assert!(
                    unfinalized.elapsed() < IDLE,
                    "an unfinalized parent with requests must not be delayed"
                );

                sink.0.store(first.block.height, Ordering::SeqCst);
                let finalized = std::time::Instant::now();
                let third = app
                    .propose(
                        (context.child("finalized"), round),
                        block_ancestry([first.block.clone(), genesis]),
                        OrderedState::fork_batches(&first.merkleized),
                        input(&mempool),
                    )
                    .await
                    .unwrap();
                assert!(third.block.txs.is_empty());
                assert!(
                    finalized.elapsed() >= IDLE,
                    "a finalized parent's requests are settled"
                );
            })
        },
    );
}
