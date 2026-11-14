//! A proposer drops pending requests that block building can never include.

#![recursion_limit = "256"]

use alloy_primitives::{Address, U256};
use commonware_glue::stateful::{Application, Input, db::DatabaseSet as _};
use commonware_runtime::{Runner as _, Supervisor as _, tokio};
use k256::ecdsa::SigningKey;
use vera_app::ordered_state::OrderedState;
use vera_app::{NoopSink, ReshareInput, StatefulVeraApp};
use vera_consensus::{Mempool as _, components::InMemoryMempool};
use vera_domain::{Block, Tx, evm::Evm};
use vera_executor::VeraExecutor;
use vera_genesis::GenesisState;
mod support;
use support::block_ancestry;

const CHAIN_ID: u64 = 9001;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32].into()).expect("key")
}

fn transfer(key: &SigningKey, nonce: u64) -> Tx {
    let to = Address::repeat_byte(0x42);
    Evm::sign_eip1559_transfer(key, CHAIN_ID, to, U256::from(1000u64), nonce, 21_000)
}

#[test]
fn rejected_requests_leave_the_pool_and_deferred_ones_stay() {
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
        let (funded, waiting) = (key(7), key(8));
        let balance = U256::from(1_000_000_000_000_000_000u128);
        let genesis_state = GenesisState {
            genesis_alloc: vec![
                (Evm::address_from_key(&funded), balance),
                (Evm::address_from_key(&waiting), balance),
            ],
            ..Default::default()
        };
        let genesis = support::genesis(&set, &genesis_state).await;
        drop(set);
        let set = OrderedState::init(
            context.child("anchored_genesis"),
            support::state_config(&context, "app", executor.clone()).recover_from_marshal(),
            Some(StatefulVeraApp::<NoopSink>::sync_targets(&genesis)),
        )
        .await;

        // These entered the pool without passing admission, as a request does
        // when admission and execution disagree about it.
        let undecodable = Tx::new(vec![0x02, 0xff].into());
        let unfunded = transfer(&key(9), 0);
        let ahead = transfer(&waiting, 1);
        let valid = transfer(&funded, 0);
        let mempool = InMemoryMempool::new();
        for tx in [&undecodable, &unfunded, &ahead, &valid] {
            assert!(mempool.insert(tx.clone()));
        }

        let mut app = StatefulVeraApp::<NoopSink>::new(
            executor,
            genesis.clone(),
            mempool.clone(),
            NoopSink,
            100,
            30_000_000,
        );
        let proposed = app
            .propose(
                (context.child("propose"), Block::genesis_context()),
                block_ancestry([genesis]),
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

        assert_eq!(proposed.block.txs, vec![valid.clone()]);
        assert!(!mempool.contains(&undecodable.id()));
        assert!(!mempool.contains(&unfunded.id()));
        assert!(
            mempool.contains(&ahead.id()),
            "a nonce ahead of its account can still become valid"
        );
        assert!(mempool.contains(&valid.id()));
    });
}
