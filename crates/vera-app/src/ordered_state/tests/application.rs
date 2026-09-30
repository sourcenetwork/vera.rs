use super::*;
use crate::{NoopSink, ReshareInput, StatefulVeraApp};
use commonware_consensus::{
    marshal::ancestry,
    types::{Epoch, Round, View},
};
use commonware_glue::stateful::{Application, Input};
use vera_consensus::{Mempool as _, components::InMemoryMempool};

#[test]
fn native_proposals_bind_every_target_and_isolate_competing_execution() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| {
            Box::pin(async move {
                let executor = VeraExecutor::new(DEPLOYMENT);
                let initialization = OrderedState::init(
                    context.child("state"),
                    config(&context, "state", executor.clone()),
                    None,
                );
                // The actor moves these futures through its startup state machine.
                // Large inline journal futures previously overflowed the node's stack.
                assert!(std::mem::size_of_val(&initialization) <= 64 * 1024);
                let set = initialization.await;
                let genesis = checkpoint::block(&set, 0).await;
                type App = StatefulVeraApp<NoopSink, OrderedState>;
                let genesis_targets = App::sync_targets(&genesis);
                drop(set);
                let recovery = OrderedState::init(
                    context.child("recovered_genesis"),
                    config(&context, "state", executor.clone()).recover_from_marshal(),
                    Some(genesis_targets.clone()),
                );
                assert!(std::mem::size_of_val(&recovery) <= 64 * 1024);
                let set = recovery.await;
                let mempool = InMemoryMempool::new();
                let first = policy(&BlsSigner::new(1u64.into(), DEPLOYMENT).unwrap(), "first");
                assert!(mempool.insert(first.clone()));
                let mut app = App::new(
                    executor.clone(),
                    genesis.clone(),
                    mempool.clone(),
                    NoopSink,
                    64,
                    30_000_000,
                );
                let mut proposal_context = vera_domain::Block::genesis_context();
                proposal_context.round = Round::new(Epoch::new(0), View::new(1));
                let proposal = app
                    .propose(
                        (context.child("propose"), proposal_context.clone()),
                        ancestry::from_iter([Arc::new(genesis.clone())]),
                        set.new_batches().await,
                        Input {
                            upstream: ReshareInput {
                                upstream: (),
                                payload: None,
                            },
                            provider: mempool.clone(),
                        },
                    )
                    .await
                    .unwrap();
                assert!(proposal.block.native_targets.is_some());
                assert!(OrderedState::matches_sync_targets(
                    &proposal.merkleized,
                    &App::sync_targets(&proposal.block)
                ));
                assert_eq!(set.committed_targets().await, genesis_targets);
                assert!(
                    executor
                        .modules()
                        .read()
                        .unwrap()
                        .acp
                        .query_policy_ids()
                        .unwrap()
                        .is_empty()
                );
                for mutation in 0..7 {
                    let mut changed = proposal.block.clone();
                    match mutation {
                        0 => changed.native_targets.as_mut().unwrap()[0].root.0[0] ^= 1,
                        1 => changed.native_targets.as_mut().unwrap()[1].floor += 1,
                        2 => changed.native_targets.as_mut().unwrap()[2].tip += 1,
                        3 => changed.module_state_root.0[0] ^= 1,
                        4 => changed.native_targets = None,
                        5 => changed.receipt_commitment.as_mut().unwrap().0[0] ^= 1,
                        6 => changed.receipt_commitment = None,
                        _ => unreachable!(),
                    }
                    assert!(
                        app.verify(
                            (context.child("reject"), changed.context.clone()),
                            ancestry::from_iter([Arc::new(changed), Arc::new(genesis.clone())]),
                            set.new_batches().await,
                        )
                        .await
                        .is_none()
                    );
                }
                mempool.prune(&[first.id()]);
                assert!(mempool.insert(policy(
                    &BlsSigner::new(1u64.into(), DEPLOYMENT).unwrap(),
                    "other"
                )));
                let competing = app
                    .propose(
                        (context.child("competing"), proposal_context.clone()),
                        ancestry::from_iter([Arc::new(genesis.clone())]),
                        set.new_batches().await,
                        Input {
                            upstream: ReshareInput {
                                upstream: (),
                                payload: None,
                            },
                            provider: mempool,
                        },
                    )
                    .await
                    .unwrap();
                assert_ne!(
                    proposal.block.module_state_root,
                    competing.block.module_state_root
                );
                let verified = app
                    .verify(
                        (context.child("verify"), proposal.block.context.clone()),
                        ancestry::from_iter([Arc::new(proposal.block.clone()), Arc::new(genesis)]),
                        set.new_batches().await,
                    )
                    .await
                    .unwrap();
                let receipts = app
                    .capture(
                        (context.child("capture"), proposal.block.context.clone()),
                        &proposal.block,
                        &verified,
                        set.readers(),
                    )
                    .await;
                assert_eq!(receipts.len(), 1);
                assert!(receipts[0].success());
                set.apply(verified).await;
                assert!(set.finalize().await.durable().await);
                let seeds = app.vrf_seed_cache();
                let old_round = Round::new(Epoch::new(0), View::new(0));
                let pending_round = Round::new(Epoch::new(0), View::new(2));
                seeds.insert(old_round, B256::ZERO);
                seeds.insert(pending_round, B256::repeat_byte(7));
                app.finalized(
                    (context.child("finalized"), proposal.block.context.clone()),
                    &proposal.block,
                    receipts,
                    set.readers(),
                )
                .await;
                assert!(seeds.get(old_round).is_none());
                assert_eq!(seeds.get(pending_round), Some(B256::repeat_byte(7)));

                assert_eq!(
                    set.committed_targets().await,
                    App::sync_targets(&proposal.block)
                );
                assert_eq!(
                    executor
                        .modules()
                        .read()
                        .unwrap()
                        .acp
                        .query_policy_ids()
                        .unwrap()
                        .len(),
                    1
                );
                drop(proposal);
                drop(competing);
                drop(set);
                let recovered = OrderedState::init(
                    context.child("recovered"),
                    config(&context, "state", executor.clone()).recover_from_marshal(),
                    Some(genesis_targets.clone()),
                )
                .await;
                assert_eq!(recovered.committed_targets().await, genesis_targets);
                assert!(
                    executor
                        .modules()
                        .read()
                        .unwrap()
                        .acp
                        .query_policy_ids()
                        .unwrap()
                        .is_empty()
                );
            })
        },
    );
}
