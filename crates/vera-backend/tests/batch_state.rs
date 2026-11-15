//! Executed change sets written into pending batches.

#![recursion_limit = "256"]

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, KECCAK256_EMPTY, U256, keccak256};
use commonware_glue::stateful::db::DatabaseSet;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_utils::{NZU16, NZUsize};
use vera_backend::{
    BatchState, CodeKey, MerkleizedTriple as _, StorageKey, VeraMerkleized, VeraStateSet,
    state_set_config,
};
use vera_qmdb::{AccountUpdate, ChangeSet, StorageKey as StorageSlotKey};
use vera_traits::StateDbRead as _;

const CONTRACT: Address = Address::repeat_byte(0xC0);

const fn update(code_hash: B256) -> AccountUpdate {
    AccountUpdate {
        created: false,
        selfdestructed: false,
        nonce: 1,
        balance: U256::ZERO,
        code_hash,
        code: None,
        storage: BTreeMap::new(),
    }
}

fn changes(address: Address, update: AccountUpdate) -> ChangeSet {
    let mut changes = ChangeSet::new();
    changes.insert(address, update);
    changes
}

async fn apply(
    parent: Option<&VeraMerkleized>,
    set: &VeraStateSet,
    changes: &ChangeSet,
) -> VeraMerkleized {
    let batches = match parent {
        Some(parent) => VeraStateSet::fork_batches(parent),
        None => set.new_batches().await,
    };
    let batches = BatchState::apply_changes(batches, changes)
        .await
        .expect("apply");
    BatchState::merkleize(batches).await.expect("merkleize")
}

fn run<F, Fut>(test: F)
where
    F: FnOnce(VeraStateSet) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let dir = tempfile::tempdir().expect("tempdir");
    let config = tokio::Config::default().with_storage_directory(dir.path().to_path_buf());
    tokio::Runner::new(config).start(|context| async move {
        let cache = CacheRef::new(NZU16!(4084), NZUsize!(64));
        let set =
            VeraStateSet::init(context.child("set"), state_set_config("t", cache), None).await;
        test(set).await;
    });
}

#[test]
fn recreated_account_does_not_read_a_destroyed_incarnations_storage() {
    run(|set| async move {
        let slot = U256::from(5);
        let destroyed = AccountUpdate {
            created: true,
            selfdestructed: true,
            storage: BTreeMap::from([(slot, U256::from(0xDEAD))]),
            ..update(KECCAK256_EMPTY)
        };
        let first = apply(None, &set, &changes(CONTRACT, destroyed)).await;

        let recreated = AccountUpdate {
            created: true,
            ..update(KECCAK256_EMPTY)
        };
        let second = apply(Some(&first), &set, &changes(CONTRACT, recreated)).await;

        let batches = VeraStateSet::fork_batches(&second);
        let key = StorageKey::new(StorageSlotKey::new(CONTRACT, 1, slot).to_bytes());
        assert!(batches.1.get(&key).await.expect("storage read").is_none());
        let state = BatchState::new(batches);
        assert_eq!(state.storage(&CONTRACT, &slot).await.unwrap(), U256::ZERO);
        assert_eq!(
            state.account(&CONTRACT).await.unwrap(),
            Some((1, U256::ZERO, KECCAK256_EMPTY))
        );
    });
}

#[test]
fn code_is_written_once_per_account() {
    run(|set| async move {
        let code = vec![0x60, 0x2a, 0x60, 0x00, 0x55];
        let code_hash = keccak256(&code);
        let deployed = AccountUpdate {
            created: true,
            code: Some(code.clone()),
            ..update(code_hash)
        };
        let first = apply(None, &set, &changes(CONTRACT, deployed)).await;
        let stored = VeraStateSet::fork_batches(&first)
            .2
            .get(&CodeKey::new(code_hash.0))
            .await
            .expect("code read");
        assert_eq!(stored, Some(code.clone()));

        let called = AccountUpdate {
            nonce: 2,
            code: Some(code),
            ..update(code_hash)
        };
        let untouched = AccountUpdate {
            nonce: 2,
            ..update(code_hash)
        };
        let with_code = apply(Some(&first), &set, &changes(CONTRACT, called)).await;
        let without_code = apply(Some(&first), &set, &changes(CONTRACT, untouched)).await;
        assert_eq!(with_code.roots(), without_code.roots());
    });
}

#[test]
fn accounts_without_code_write_no_code_record() {
    run(|set| async move {
        let sender = AccountUpdate {
            code: Some(Vec::new()),
            ..update(KECCAK256_EMPTY)
        };
        let first = apply(None, &set, &changes(CONTRACT, sender)).await;
        let stored = VeraStateSet::fork_batches(&first)
            .2
            .get(&CodeKey::new(KECCAK256_EMPTY.0))
            .await
            .expect("code read");
        assert_eq!(stored, None);
    });
}
