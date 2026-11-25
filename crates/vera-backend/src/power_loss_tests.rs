use bytes::Bytes;
use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized as _};
use commonware_runtime::{
    Metrics as _, Runner as _, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, FaultConfig, PartialWriteMode, WriteConfig},
};
use commonware_utils::{NZU16, NZUsize, probability};

use crate::native;

type Journals<E> = native::NativeSetFor<E>;
type Context = deterministic::Context;
type Databases = Journals<Context>;
type Sealed = <Databases as DatabaseSet<Context>>::Merkleized;

fn config(_context: &Context) -> <Databases as DatabaseSet<Context>>::Config {
    let cache = CacheRef::new(NZU16!(4084), NZUsize!(4096));
    let mut config = native::state_config("power-loss", cache);
    // The paged writer requires two pages; fill them without sealing a section.
    macro_rules! small_buffers {
        ($($index:tt),+) => {
            $(config.$index.journal_config.write_buffer = NZUsize!(2 * 4084);)+
        };
    }
    small_buffers!(0, 1, 2, 3);
    config
}

async fn revision(databases: &Databases, version: u8, count: usize) -> Sealed {
    let (mut acp, mut bulletin, mut vera, mut nonces) = databases.new_batches().await;
    for index in 0..count {
        let key = u64::try_from(index).unwrap().to_be_bytes();
        let value = Some(Bytes::from(vec![version; 128]));
        acp = acp.write(key.to_vec(), value.clone());
        bulletin = bulletin.write(key.to_vec(), value.clone());
        vera = vera.write(key.to_vec(), value.clone());
        nonces = nonces.write(key.to_vec(), value);
    }
    (
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
    for reader in [readers.0, readers.1, readers.2, readers.3] {
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
fn four_journals_recover_the_anchor_after_unsynced_write_loss() {
    let _: fn(native::NativeStateSet) -> Journals<crate::Ctx> = std::convert::identity;

    for (durable_mask, retention, mode) in [
        (0x00u8, probability!(0.0), PartialWriteMode::Prefix),
        (0x05, probability!(0.0), PartialWriteMode::Prefix),
        (0x0e, probability!(0.0), PartialWriteMode::Prefix),
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
                let next = revision(&databases, 2, 100).await;
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
