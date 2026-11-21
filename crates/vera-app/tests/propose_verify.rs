//! Verify competing proposals and capture the winning branch's receipts.

#![recursion_limit = "256"]

use alloy_sol_types::SolCall;
use commonware_glue::stateful::{Application, Input, db::DatabaseSet as _};
use commonware_runtime::{Runner as _, Supervisor as _, tokio};
use futures::FutureExt as _;
use vera_app::ordered_state::OrderedState;
use vera_app::{NoopSink, ReshareInput, StatefulVeraApp};
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_consensus::{Mempool as _, components::InMemoryMempool};
use vera_domain::{Block, DbTarget, NativeTx, Tx};
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
                    nonce: Default::default(),
                }
                .abi_encode()
                .into(),
            )
            .unwrap()
            .into(),
    )
}

#[test]
fn competing_proposals_preserve_receipts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = tokio::Config::default().with_storage_directory(dir.path().to_path_buf());
    tokio::Runner::new(config).start(|context| async move {
        let executor = VeraExecutor::new(CHAIN_ID);
        let set = OrderedState::init(
            context.child("set"),
            support::state_config(&context, "app", executor.clone()),
            None,
        )
        .await;

        let genesis = support::genesis(&set, &GenesisState::default()).await;
        drop(set);
        let set = OrderedState::init(
            context.child("anchored_genesis"),
            support::state_config(&context, "app", executor.clone()).recover_from_marshal(),
            Some(StatefulVeraApp::<NoopSink>::sync_targets(&genesis)),
        )
        .await;

        let mempool = InMemoryMempool::new();
        let first = BlsSigner::new(7u64.into(), CHAIN_ID).unwrap();
        let second = BlsSigner::new(8u64.into(), CHAIN_ID).unwrap();
        assert!(mempool.insert(create_policy(&first, "first")));

        let mut app = StatefulVeraApp::<NoopSink>::new(
            executor,
            genesis.clone(),
            mempool.clone(),
            NoopSink,
            100,
            30_000_000,
        )
        .with_native_pipeline(true, std::time::Duration::ZERO);

        let consensus_context = Block::genesis_context();
        let proposed = app
            .propose(
                (context.child("propose"), consensus_context.clone()),
                block_ancestry([genesis.clone()]),
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
            .expect("proposal");
        let block = proposed.block;
        assert_eq!(block.height, 1);
        assert_eq!(block.txs.len(), 1);
        assert_ne!(block.module_state_root, genesis.module_state_root);
        assert_ne!(block.native_targets, genesis.native_targets);

        let verified = app
            .process(
                (context.child("verify"), consensus_context),
                block_ancestry([block.clone(), genesis.clone()]),
                set.new_batches().await,
                commonware_glue::stateful::Finality::Candidate,
            )
            .await
            .expect("verification");
        assert!(OrderedState::matches_sync_targets(
            &verified,
            &StatefulVeraApp::<NoopSink>::sync_targets(&block)
        ));

        mempool.prune(&[block.txs[0].id()]);
        assert!(mempool.insert(create_policy(&second, "second")));
        let mut verifier = app.clone();
        let competing = verifier
            .propose(
                (context.child("competing"), Block::genesis_context()),
                block_ancestry([genesis]),
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
            .expect("competing proposal");
        assert_eq!(competing.block.height, block.height);
        assert_ne!(competing.block.id(), block.id());

        for (candidate, batches) in [
            (&block, &verified),
            (&competing.block, &competing.merkleized),
        ] {
            let mut capturer = StatefulVeraApp::<NoopSink>::new(
                VeraExecutor::new(CHAIN_ID),
                block.clone(),
                InMemoryMempool::new(),
                NoopSink,
                100,
                30_000_000,
            )
            .with_native_pipeline(true, std::time::Duration::ZERO);
            let mut wrong = candidate.clone();
            wrong.receipt_commitment = Some(alloy_primitives::B256::ZERO);
            assert!(
                std::panic::AssertUnwindSafe(capturer.capture(
                    (context.child("wrong_receipts"), wrong.context.clone()),
                    &wrong,
                    batches,
                    set.readers(),
                ))
                .catch_unwind()
                .await
                .is_err()
            );
            let receipts = capturer
                .capture(
                    (context.child("capture"), candidate.context.clone()),
                    candidate,
                    batches,
                    set.readers(),
                )
                .await;
            assert_eq!(receipts.len(), 1);
            assert_eq!(
                receipts[0].tx_hash,
                NativeTx::decode_wire(&candidate.txs[0].bytes)
                    .unwrap()
                    .tx_id()
                    .0
            );
            assert!(receipts[0].success());
            assert!(receipts[0].gas_used > 0);
        }

        set.apply(verified).await;
        assert!(set.finalize().await.durable().await);
        let committed = set.committed_targets().await;
        let native = [committed.3, committed.4, committed.5, committed.6];
        assert_eq!(
            Some(native.each_ref().map(|target| DbTarget {
                root: target.root,
                floor: *target.range.start(),
                tip: *target.range.end(),
            })),
            block.native_targets
        );
    });
}
