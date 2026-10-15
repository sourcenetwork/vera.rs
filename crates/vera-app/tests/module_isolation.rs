//! Pending branches must not replace module state served to queries.

#![recursion_limit = "256"]

use alloy_sol_types::SolCall;
use commonware_consensus::Handoff;
use commonware_glue::stateful::{Application, Input, Proposed, db::DatabaseSet as _};
use commonware_runtime::{Runner as _, Supervisor as _, tokio};
use vera_app::ordered_state::{OrderedPending, OrderedState};
use vera_app::{NoopSink, ReshareInput, StatefulVeraApp};
use vera_backend::Ctx;
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_consensus::{Mempool as _, components::InMemoryMempool};
use vera_domain::{Block, Tx};
use vera_executor::VeraExecutor;
use vera_genesis::GenesisState;
use vera_modules::acp::abi::IAcp;
mod support;
use support::block_ancestry;

const CHAIN_ID: u64 = 9001;

fn create_policy(signer: &BlsSigner, name: &str) -> Tx {
    Tx::new(
        signer
            .sign_native_tx(
                ACP_ADDRESS,
                IAcp::createPolicyCall {
                    policy: format!("name: {name}\nresources:\n  - name: file\n")
                        .into_bytes()
                        .into(),
                    marshalType: 1,
                }
                .abi_encode()
                .into(),
            )
            .unwrap()
            .into(),
    )
}

async fn propose(
    app: &mut StatefulVeraApp<NoopSink>,
    context: Ctx,
    parent: &Block,
    batches: OrderedPending,
    tx: Option<Tx>,
    handoff: bool,
) -> Proposed<StatefulVeraApp<NoopSink>, Ctx> {
    let provider = InMemoryMempool::new();
    if let Some(tx) = tx {
        assert!(provider.insert(tx));
    }
    let context = (context, Block::genesis_context());
    let ancestry = block_ancestry([parent.clone()]);
    let input = Input {
        upstream: ReshareInput {
            upstream: (),
            payload: None,
        },
        provider,
    };
    if handoff {
        match app.prepare(context, ancestry, batches, input).await {
            Handoff::Stage(proposed) => proposed,
            _ => panic!("native handoff must stage without voting on an uncertified parent"),
        }
    } else {
        app.propose(context, ancestry, batches, input)
            .await
            .expect("proposal")
    }
}

#[test]
fn pending_branches_do_not_replace_query_state() {
    check_pending_branches(false);
}

#[test]
fn staged_handoffs_do_not_replace_query_state() {
    check_pending_branches(true);
}

fn check_pending_branches(handoff: bool) {
    let dir = tempfile::tempdir().unwrap();
    let config = tokio::Config::default().with_storage_directory(dir.path().to_path_buf());
    tokio::Runner::new(config).start(|context| async move {
        let executor = VeraExecutor::new(CHAIN_ID);
        let set = OrderedState::init(
            context.child("set"),
            support::state_config(&context, "modules", executor.clone()),
            None,
        )
        .await;
        let genesis = support::genesis(&set, &GenesisState::default()).await;
        drop(set);
        let set = OrderedState::init(
            context.child("anchored_genesis"),
            support::state_config(&context, "modules", executor.clone()).recover_from_marshal(),
            Some(StatefulVeraApp::<NoopSink>::sync_targets(&genesis)),
        )
        .await;
        let mut app = StatefulVeraApp::new(
            executor.clone(),
            genesis.clone(),
            InMemoryMempool::new(),
            NoopSink,
            64,
            30_000_000,
        )
        .with_native_pipeline(handoff, std::time::Duration::ZERO);
        let alice = BlsSigner::new(1u64.into(), CHAIN_ID).unwrap();
        let bob = BlsSigner::new(2u64.into(), CHAIN_ID).unwrap();

        let a = propose(
            &mut app,
            context.child("a"),
            &genesis,
            set.new_batches().await,
            Some(create_policy(&alice, "alice")),
            handoff,
        )
        .await;
        let b = propose(
            &mut app,
            context.child("b"),
            &genesis,
            set.new_batches().await,
            Some(create_policy(&bob, "bob")),
            handoff,
        )
        .await;
        assert_ne!(a.block.module_state_root, b.block.module_state_root);
        assert_eq!(a.block.txs.len(), 1);
        assert_eq!(b.block.txs.len(), 1);

        let target = StatefulVeraApp::<NoopSink>::sync_targets(&a.block);
        assert!(OrderedState::matches_sync_targets(&a.merkleized, &target));
        let mut wrong_bounds = a.block.clone();
        wrong_bounds.native_targets.as_mut().unwrap()[0].tip += 1;
        assert!(!OrderedState::matches_sync_targets(
            &a.merkleized,
            &StatefulVeraApp::<NoopSink>::sync_targets(&wrong_bounds)
        ));
        let mut wrong_root = target;
        wrong_root.3.root = b.block.native_targets.as_ref().unwrap()[0].root;
        assert!(!OrderedState::matches_sync_targets(
            &a.merkleized,
            &wrong_root
        ));

        let mut sibling = app.clone();
        let (child_a, child_b) = ::tokio::join!(
            propose(
                &mut app,
                context.child("child_a"),
                &a.block,
                OrderedState::fork_batches(&a.merkleized),
                None,
                handoff,
            ),
            propose(
                &mut sibling,
                context.child("child_b"),
                &b.block,
                OrderedState::fork_batches(&b.merkleized),
                None,
                handoff,
            ),
        );
        for child in [&child_a, &child_b] {
            assert!(child.block.txs.is_empty());
            assert!(OrderedState::matches_sync_targets(
                &child.merkleized,
                &StatefulVeraApp::<NoopSink>::sync_targets(&child.block)
            ));
        }
        assert_eq!(child_a.block.parent, a.block.id());
        assert_eq!(child_b.block.parent, b.block.id());
        assert_eq!(
            set.committed_targets().await,
            StatefulVeraApp::<NoopSink>::sync_targets(&genesis),
            "pending execution advanced committed storage"
        );

        {
            let visible = executor.modules().read().unwrap();
            assert_eq!(
                visible.nonces.get_nonce(alice.did()).unwrap(),
                0,
                "pending Alice state leaked to queries"
            );
            assert_eq!(
                visible.nonces.get_nonce(bob.did()).unwrap(),
                0,
                "pending Bob state leaked to queries"
            );
            assert!(visible.acp.query_policy_ids().unwrap().is_empty());
        }

        let first_target = StatefulVeraApp::<NoopSink>::sync_targets(&a.block);
        for winner in [a, child_a] {
            let captured = app
                .capture(
                    (context.child("capture"), winner.block.context.clone()),
                    &winner.block,
                    &winner.merkleized,
                    set.readers(),
                )
                .await;
            set.apply(winner.merkleized).await;
            assert_eq!(
                set.committed_targets().await,
                StatefulVeraApp::<NoopSink>::sync_targets(&winner.block)
            );
            assert_eq!(
                executor
                    .modules()
                    .read()
                    .unwrap()
                    .nonces
                    .get_nonce(alice.did())
                    .unwrap(),
                1,
                "database apply must publish native state before the application callback"
            );
            app.finalized(
                (context.child("finalized"), winner.block.context.clone()),
                &winner.block,
                captured,
                set.readers(),
            )
            .await;
            let partitions = set.native_databases();
            let [a, b, h, n] = vera_backend::native::read_partitions([
                &partitions.0,
                &partitions.1,
                &partitions.2,
                &partitions.3,
            ])
            .await;
            assert_eq!(
                vera_modules::module_state::combine_module_roots(&[
                    a.root().0,
                    b.root().0,
                    h.root().0,
                    n.root().0
                ]),
                winner.block.module_state_root
            );
            let visible = executor.modules().read().unwrap();
            assert_eq!(visible.nonces.get_nonce(alice.did()).unwrap(), 1);
            assert_eq!(visible.nonces.get_nonce(bob.did()).unwrap(), 0);
            assert_eq!(visible.acp.query_policy_ids().unwrap().len(), 1);
        }
        assert!(set.finalize().await.durable().await);
        drop(b);
        drop(child_b);
        drop(set);
        let set = OrderedState::init(
            context.child("recovered_first"),
            support::state_config(&context, "modules", executor.clone()).recover_from_marshal(),
            Some(first_target.clone()),
        )
        .await;
        assert_eq!(set.committed_targets().await, first_target);
        assert_eq!(
            executor
                .modules()
                .read()
                .unwrap()
                .nonces
                .get_nonce(alice.did())
                .unwrap(),
            1
        );
        drop(set);
        let set = OrderedState::init(
            context.child("recovered_genesis"),
            support::state_config(&context, "modules", executor.clone()).recover_from_marshal(),
            Some(StatefulVeraApp::<NoopSink>::sync_targets(&genesis)),
        )
        .await;
        assert_eq!(
            set.committed_targets().await,
            StatefulVeraApp::<NoopSink>::sync_targets(&genesis)
        );
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
        assert_eq!(
            executor
                .modules()
                .read()
                .unwrap()
                .nonces
                .get_nonce(alice.did())
                .unwrap(),
            0
        );
    });
}
