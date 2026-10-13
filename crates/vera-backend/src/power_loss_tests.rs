use bytes::Bytes;
use commonware_cryptography::Sha256;
use commonware_glue::stateful::db::{DatabaseSet, Shared, Unmerkleized as _};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Metrics as _, Runner as _, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, FaultConfig, PartialWriteMode, WriteConfig},
};
use commonware_storage::{merkle::mmr, qmdb::any::unordered::variable, translator::EightCap};
use commonware_utils::{NZU16, NZUsize, probability};
use vera_qmdb::AccountEncoding;

use crate::{AccountKey, AccountValue, CodeKey, StorageKey, StorageValue, native};

type Accounts<E> =
    variable::Db<mmr::Family, E, AccountKey, AccountValue, Sha256, EightCap, Sequential>;
type Storage<E> =
    variable::Db<mmr::Family, E, StorageKey, StorageValue, Sha256, EightCap, Sequential>;
type Code<E> = variable::Db<mmr::Family, E, CodeKey, Vec<u8>, Sha256, EightCap, Sequential>;
type Journals<E> = (
    Shared<Accounts<E>>,
    Shared<Storage<E>>,
    Shared<Code<E>>,
    Shared<native::NativeDbFor<E>>,
    Shared<native::NativeDbFor<E>>,
    Shared<native::NativeDbFor<E>>,
    Shared<native::NativeDbFor<E>>,
);
type Context = deterministic::Context;
type Databases = Journals<Context>;
type Sealed = <Databases as DatabaseSet<Context>>::Merkleized;

fn config(context: &Context) -> <Databases as DatabaseSet<Context>>::Config {
    let cache = CacheRef::from_pooler(context, NZU16!(4084), NZUsize!(4096));
    let execution = crate::state_set_config("power-loss", cache.clone());
    let native = native::state_config("power-loss", cache);
    (
        execution.0,
        execution.1,
        execution.2,
        native.0,
        native.1,
        native.2,
        native.3,
    )
}

async fn revision(databases: &Databases, version: u8, count: usize) -> Sealed {
    let (mut accounts, mut storage, mut code, mut acp, mut bulletin, mut vera, mut nonces) =
        databases.new_batches().await;
    for index in 0..count {
        let key = u64::try_from(index).unwrap().to_be_bytes();
        let mut address = [0; 20];
        address[..8].copy_from_slice(&key);
        accounts = accounts.write(
            AccountKey::new(address),
            Some(AccountValue([version; AccountEncoding::SIZE])),
        );
        let mut slot = [0; 60];
        slot[..8].copy_from_slice(&key);
        storage = storage.write(
            StorageKey::new(slot),
            Some(StorageValue(alloy_primitives::U256::from(version))),
        );
        let mut code_key = [0; 32];
        code_key[..8].copy_from_slice(&key);
        code = code.write(CodeKey::new(code_key), Some(vec![version; 128]));
        let value = Some(Bytes::from(vec![version; 128]));
        acp = acp.write(key.to_vec(), value.clone());
        bulletin = bulletin.write(key.to_vec(), value.clone());
        vera = vera.write(key.to_vec(), value.clone());
        nonces = nonces.write(key.to_vec(), value);
    }
    (
        accounts.merkleize().await.unwrap(),
        storage.merkleize().await.unwrap(),
        code.merkleize().await.unwrap(),
        acp.merkleize().await.unwrap(),
        bulletin.merkleize().await.unwrap(),
        vera.merkleize().await.unwrap(),
        nonces.merkleize().await.unwrap(),
    )
}

fn written_bytes(context: &Context) -> u64 {
    let metrics = context.encode();
    let mut values = metrics.lines().filter_map(|line| {
        let (name, value) = line.split_once(' ')?;
        name.ends_with("_storage_write_bytes_total")
            .then(|| value.parse::<u64>().unwrap())
    });
    let value = values.next().expect("registered storage byte counter");
    assert!(values.next().is_none());
    value
}

async fn assert_restored_records(databases: &Databases, version: u8) {
    let readers = databases.readers();
    assert_eq!(
        readers
            .0
            .read()
            .await
            .get(&AccountKey::new([0; 20]))
            .await
            .unwrap()
            .unwrap()
            .0,
        [version; AccountEncoding::SIZE]
    );
    assert_eq!(
        readers
            .1
            .read()
            .await
            .get(&StorageKey::new([0; 60]))
            .await
            .unwrap()
            .unwrap()
            .0,
        alloy_primitives::U256::from(version)
    );
    assert_eq!(
        readers
            .2
            .read()
            .await
            .get(&CodeKey::new([0; 32]))
            .await
            .unwrap()
            .unwrap(),
        vec![version; 128]
    );
    let key = 16_384u64.to_be_bytes();
    let mut address = [0; 20];
    address[..8].copy_from_slice(&key);
    assert!(
        readers
            .0
            .read()
            .await
            .get(&AccountKey::new(address))
            .await
            .unwrap()
            .is_none()
    );
    let mut slot = [0; 60];
    slot[..8].copy_from_slice(&key);
    assert!(
        readers
            .1
            .read()
            .await
            .get(&StorageKey::new(slot))
            .await
            .unwrap()
            .is_none()
    );
    let mut code_key = [0; 32];
    code_key[..8].copy_from_slice(&key);
    assert!(
        readers
            .2
            .read()
            .await
            .get(&CodeKey::new(code_key))
            .await
            .unwrap()
            .is_none()
    );
    for reader in [readers.3, readers.4, readers.5, readers.6] {
        let database = reader.read().await;
        assert_eq!(
            database.get(&vec![0; 8]).await.unwrap().unwrap().as_ref(),
            &[version; 128]
        );
        assert!(
            database
                .get(&16_384u64.to_be_bytes().to_vec())
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn seven_journals_recover_the_anchor_after_unsynced_write_loss() {
    type Production = (
        Shared<crate::AccountsDb>,
        Shared<crate::StorageDb>,
        Shared<crate::CodeDb>,
        Shared<native::NativeDb>,
        Shared<native::NativeDb>,
        Shared<native::NativeDb>,
        Shared<native::NativeDb>,
    );
    let _: fn(Production) -> Journals<crate::Ctx> = std::convert::identity;

    for (durable_mask, retention, mode) in [
        (0x00u8, probability!(0.0), PartialWriteMode::Prefix),
        (0x55, probability!(0.0), PartialWriteMode::Prefix),
        (0x7f, probability!(0.0), PartialWriteMode::Prefix),
        (0x00, probability!(0.5), PartialWriteMode::Prefix),
        (0x00, probability!(0.5), PartialWriteMode::Subset),
    ] {
        let runtime = deterministic::Runner::new(deterministic::Config::default());
        let partial_retention = !retention.is_zero();
        let ((anchor, before_crash), checkpoint) =
            runtime.start_and_recover(|context| async move {
                let databases =
                    Databases::init(context.child("journals"), config(&context), None).await;
                databases.apply(revision(&databases, 1, 1).await).await;
                assert!(databases.finalize().await.durable().await);
                let anchor = databases.committed_targets().await;
                *context.storage_fault_config().write() =
                    FaultConfig::default().write(WriteConfig {
                        failure_rate: probability!(0.0),
                        retention_rate: retention,
                        mode,
                    });
                let next = revision(&databases, 2, 16_385).await;
                macro_rules! apply {
                    ($index:tt) => {
                        let before = written_bytes(&context);
                        databases.$index.apply(next.$index).await;
                        assert!(
                            written_bytes(&context) > before,
                            "partition {} issued no storage write",
                            $index
                        );
                        if durable_mask & (1 << $index) != 0 {
                            assert!(databases.$index.finalize().await.durable().await);
                        }
                    };
                }
                apply!(0);
                apply!(1);
                apply!(2);
                apply!(3);
                apply!(4);
                apply!(5);
                apply!(6);
                (anchor, context.storage_audit())
            });
        let (next_anchor, checkpoint) =
            deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
                if partial_retention {
                    assert_ne!(
                        context.storage_audit(),
                        before_crash,
                        "crash did not retain any issued unsynced bytes"
                    );
                }
                *context.storage_fault_config().write() = FaultConfig::default();
                let databases = Databases::init(
                    context.child("recover"),
                    config(&context),
                    Some(anchor.clone()),
                )
                .await;
                assert_eq!(databases.committed_targets().await, anchor);
                assert_restored_records(&databases, 1).await;
                databases.apply(revision(&databases, 3, 1).await).await;
                assert!(databases.finalize().await.durable().await);
                databases.committed_targets().await
            });
        deterministic::Runner::from(checkpoint).start(|context| async move {
            let databases = Databases::init(
                context.child("reopen"),
                config(&context),
                Some(next_anchor.clone()),
            )
            .await;
            assert_eq!(databases.committed_targets().await, next_anchor);
            assert_restored_records(&databases, 3).await;
        });
    }
}
