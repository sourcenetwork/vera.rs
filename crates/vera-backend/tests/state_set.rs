//! Lifecycle of the glue-managed state set: fork, write, merkleize, apply,
//! finalize, read back, and restart from the same partitions.

#![recursion_limit = "256"]

use alloy_primitives::U256;
use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized as _};
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_utils::{NZU16, NZUsize};
use vera_backend::{
    AccountKey, AccountValue, CodeKey, StorageKey, StorageValue, VeraReaders, VeraStateSet,
    combined_root, state_set_config,
};
use vera_qmdb::AccountEncoding;

const fn account_key(seed: u8) -> AccountKey {
    AccountKey::new([seed; 20])
}

const fn storage_key(seed: u8) -> StorageKey {
    StorageKey::new([seed; 60])
}

const fn code_key(seed: u8) -> CodeKey {
    CodeKey::new([seed; 32])
}

const fn account(seed: u8) -> AccountValue {
    AccountValue([seed; AccountEncoding::SIZE])
}

fn page_cache(context: &tokio::Context) -> CacheRef {
    CacheRef::from_pooler(context, NZU16!(4084), NZUsize!(64))
}

async fn read_all(
    readers: &VeraReaders,
    seed: u8,
) -> (Option<AccountValue>, Option<U256>, Option<Vec<u8>>) {
    let accounts = readers.0.read().await;
    let storage = readers.1.read().await;
    let code = readers.2.read().await;
    (
        accounts
            .get(&account_key(seed))
            .await
            .expect("account read"),
        storage
            .get(&storage_key(seed))
            .await
            .expect("storage read")
            .map(|v| v.0),
        code.get(&code_key(seed)).await.expect("code read"),
    )
}

#[test]
fn fork_apply_finalize_and_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = tokio::Config::default().with_storage_directory(dir.path().to_path_buf());
    let runner = tokio::Runner::new(config.clone());
    let root_before = runner.start(|context| async move {
        let set = VeraStateSet::init(
            context.child("set"),
            state_set_config("t", page_cache(&context)),
            None,
        )
        .await;

        let (mut accounts, mut storage, mut code) = set.new_batches().await;
        accounts = accounts.write(account_key(1), Some(account(0xA1)));
        storage = storage.write(storage_key(2), Some(StorageValue(U256::from(0xB2u64))));
        code = code.write(code_key(3), Some(vec![0xC3; 128]));
        let first = (
            accounts.merkleize().await.expect("accounts"),
            storage.merkleize().await.expect("storage"),
            code.merkleize().await.expect("code"),
        );
        let first_root = combined_root(&first);

        let (mut accounts, mut storage, mut code) = VeraStateSet::fork_batches(&first);
        let seen = accounts.get(&account_key(1)).await.expect("read-through");
        assert_eq!(seen.map(|v| v.0), Some([0xA1; AccountEncoding::SIZE]));
        accounts = accounts.write(account_key(4), Some(account(0xD4)));
        storage = storage.write(storage_key(5), Some(StorageValue(U256::from(0xE5u64))));
        code = code.write(code_key(6), Some(vec![0xF6; 96]));
        let second = (
            accounts.merkleize().await.expect("accounts"),
            storage.merkleize().await.expect("storage"),
            code.merkleize().await.expect("code"),
        );
        let second_root = combined_root(&second);
        assert_ne!(first_root, second_root);

        set.apply(first).await;
        set.apply(second).await;
        assert!(set.finalize().await.durable().await);

        let readers = set.readers();
        let (a, s, c) = read_all(&readers, 1).await;
        assert_eq!(a.map(|v| v.0), Some([0xA1; AccountEncoding::SIZE]));
        assert_eq!(s, None);
        assert_eq!(c, None);
        let (_, s, _) = read_all(&readers, 2).await;
        assert_eq!(s, Some(U256::from(0xB2u64)));
        let (_, _, c) = read_all(&readers, 6).await;
        assert_eq!(c, Some(vec![0xF6; 96]));
        second_root
    });

    let runner = tokio::Runner::new(config);
    runner.start(|context| async move {
        let set = VeraStateSet::init(
            context.child("set"),
            state_set_config("t", page_cache(&context)),
            None,
        )
        .await;
        let targets = set.committed_targets().await;
        let (a, s, c) = (
            alloy_primitives::B256::from_slice(targets.0.root.as_ref()),
            alloy_primitives::B256::from_slice(targets.1.root.as_ref()),
            alloy_primitives::B256::from_slice(targets.2.root.as_ref()),
        );
        assert_eq!(vera_qmdb::StateRoot::compute(a, s, c), root_before);
        let readers = set.readers();
        let (_, _, c) = read_all(&readers, 3).await;
        assert_eq!(c, Some(vec![0xC3; 128]));
    });
}
