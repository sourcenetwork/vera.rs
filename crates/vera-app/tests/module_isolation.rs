//! Pending branches must not replace module state served to queries.

#![recursion_limit = "256"]

use std::sync::Arc;

use alloy_sol_types::SolCall;
use commonware_consensus::marshal::ancestry;
use commonware_glue::stateful::{
    Application, Input, Proposed,
    db::{DatabaseSet as _, ManagedDb as _, Shared},
};
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_utils::{NZU16, NZUsize};
use vera_app::{ModuleDb, VeraStateSet, VeraUnmerkleized};
use vera_app::{NoopSink, ReshareInput, StatefulVeraApp, apply_genesis, genesis_block};
use vera_backend::{Ctx, VeraStateSet as BackendStateSet, state_set_config};
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_consensus::{Mempool as _, components::InMemoryMempool};
use vera_domain::{Block, Tx};
use vera_executor::{ModuleTrees, VeraExecutor};
use vera_genesis::GenesisState;
use vera_modules::module_state::state_root_from_jmt;
use vera_modules::{ModuleState, acp::abi::IAcp};
use vera_state::ModuleStateTree;

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
    batches: VeraUnmerkleized,
    tx: Option<Tx>,
) -> Proposed<StatefulVeraApp<NoopSink>, Ctx> {
    let provider = InMemoryMempool::new();
    if let Some(tx) = tx {
        assert!(provider.insert(tx));
    }
    app.propose(
        (context, Block::genesis_context()),
        ancestry::from_iter([Arc::new(parent.clone())]),
        batches,
        Input {
            upstream: ReshareInput {
                upstream: (),
                payload: None,
            },
            provider,
        },
    )
    .await
    .expect("proposal")
}

#[test]
fn pending_branches_do_not_replace_query_state() {
    check_pending_branches(false);
}

#[test]
fn pending_branches_do_not_change_persistent_trees() {
    check_pending_branches(true);
}

fn check_pending_branches(persistent: bool) {
    let dir = tempfile::tempdir().unwrap();
    let config = tokio::Config::default().with_storage_directory(dir.path().to_path_buf());
    tokio::Runner::new(config).start(|context| async move {
        let page_cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        let set = BackendStateSet::init(
            context.child("set"),
            state_set_config("modules", page_cache.clone()),
            None,
        )
        .await;
        let (root, targets) = apply_genesis(&set, &GenesisState::default()).await.unwrap();
        let genesis = genesis_block(root, targets, ModuleState::default().state_root());
        let trees: Option<ModuleTrees> = persistent.then(|| {
            std::array::from_fn(|i| {
                Arc::new(std::sync::Mutex::new(
                    ModuleStateTree::open(dir.path().join(format!("module-{i}"))).unwrap(),
                ))
            })
        });
        let mut executor = VeraExecutor::new(CHAIN_ID);
        if let Some(trees) = &trees {
            executor = executor.with_module_trees(trees.clone());
        }
        let native = ModuleDb::init(context.child("native"), executor.clone(), None)
            .await
            .unwrap();
        let set: VeraStateSet = (set.0, set.1, set.2, Shared::new("native", native));
        let mut app = StatefulVeraApp::new(
            executor.clone(),
            genesis.clone(),
            InMemoryMempool::new(),
            NoopSink,
            64,
            30_000_000,
        );
        let alice = BlsSigner::new(1u64.into(), CHAIN_ID).unwrap();
        let bob = BlsSigner::new(2u64.into(), CHAIN_ID).unwrap();

        let a = propose(
            &mut app,
            context.child("a"),
            &genesis,
            set.new_batches().await,
            Some(create_policy(&alice, "alice")),
        )
        .await;
        let b = propose(
            &mut app,
            context.child("b"),
            &genesis,
            set.new_batches().await,
            Some(create_policy(&bob, "bob")),
        )
        .await;
        assert_ne!(a.block.module_state_root, b.block.module_state_root);
        assert_eq!(a.block.txs.len(), 1);
        assert_eq!(b.block.txs.len(), 1);

        let target = StatefulVeraApp::<NoopSink>::sync_targets(&a.block);
        assert!(VeraStateSet::matches_sync_targets(&a.merkleized, &target));
        let mut wrong_height = target.clone();
        wrong_height.3.height += 1;
        assert!(!VeraStateSet::matches_sync_targets(
            &a.merkleized,
            &wrong_height
        ));
        let mut wrong_root = target;
        wrong_root.3.root = b.block.module_state_root;
        assert!(!VeraStateSet::matches_sync_targets(
            &a.merkleized,
            &wrong_root
        ));

        let mut sibling = app.clone();
        let (child_a, child_b) = ::tokio::join!(
            propose(
                &mut app,
                context.child("child_a"),
                &a.block,
                VeraStateSet::fork_batches(&a.merkleized),
                None
            ),
            propose(
                &mut sibling,
                context.child("child_b"),
                &b.block,
                VeraStateSet::fork_batches(&b.merkleized),
                None
            ),
        );
        assert_eq!(
            child_a.block.module_state_root, a.block.module_state_root,
            "empty child changed Alice's state root"
        );
        assert_eq!(
            child_b.block.module_state_root, b.block.module_state_root,
            "empty child changed Bob's state root"
        );
        if let Some(trees) = &trees {
            for tree in trees {
                let tree = tree.lock().unwrap();
                assert_eq!(
                    tree.version(),
                    0,
                    "pending execution advanced the persistent version"
                );
                assert_eq!(tree.canonical_height(), 0);
                assert!(tree.load_all().unwrap().is_empty());
                assert!(tree.root_at_height(1).is_err());
            }
        }
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
            assert_eq!(set.committed_targets().await.3.height, winner.block.height);
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
            let visible = executor.modules().read().unwrap();
            assert_eq!(visible.nonces.get_nonce(alice.did()).unwrap(), 1);
            assert_eq!(visible.nonces.get_nonce(bob.did()).unwrap(), 0);
            assert_eq!(visible.acp.query_policy_ids().unwrap().len(), 1);
            if let Some(trees) = &trees {
                let roots = std::array::from_fn(|i| {
                    let tree = trees[i].lock().unwrap();
                    assert_eq!(tree.canonical_height(), winner.block.height);
                    let root = tree.root().unwrap();
                    assert_eq!(tree.root_at_height(winner.block.height).unwrap(), root);
                    root.0
                });
                assert_eq!(state_root_from_jmt(&roots), winner.block.module_state_root);
            } else {
                assert_eq!(visible.state_root(), winner.block.module_state_root);
            }
        }
        assert!(set.finalize().await.durable().await);
        if persistent {
            drop(b);
            drop(child_b);
            drop(set);
            let config = state_set_config("modules", page_cache.clone());
            let set = VeraStateSet::init(
                context.child("recovered_first"),
                (config.0, config.1, config.2, executor.clone()),
                Some(first_target),
            )
            .await;
            assert_eq!(executor.module_height().unwrap(), 1);
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
            let config = state_set_config("modules", page_cache);
            let _set = VeraStateSet::init(
                context.child("recovered_genesis"),
                (config.0, config.1, config.2, executor.clone()),
                Some(StatefulVeraApp::<NoopSink>::sync_targets(&genesis)),
            )
            .await;
            assert_eq!(executor.module_height().unwrap(), 0);
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
        }
    });
}
