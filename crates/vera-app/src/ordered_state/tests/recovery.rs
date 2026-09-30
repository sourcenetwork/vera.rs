use super::*;

use std::{io::Write as _, panic::AssertUnwindSafe, path::Path, process::Command};

use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_glue::stateful::db::Unmerkleized as _;
use futures::FutureExt as _;
use vera_backend::{AccountKey, AccountValue, CodeKey, StorageKey, StorageValue};
use vera_modules::{ModuleState, kv_store::InMemoryKvStore};
use vera_qmdb::AccountEncoding;

fn modules(version: u8) -> ModuleState {
    ModuleState::from_stores(std::array::from_fn(|module| {
        InMemoryKvStore::from_pairs(vec![(
            b"record".to_vec(),
            vec![version + u8::try_from(module).unwrap(); 128],
        )])
    }))
}

pub(super) async fn revision(set: &OrderedState, version: u8) -> OrderedSealed {
    let (accounts, storage, code, acp, bulletin, vera, nonces, _) =
        set.databases.new_batches().await;
    let accounts = accounts
        .write(
            AccountKey::new([1; 20]),
            Some(AccountValue([version; AccountEncoding::SIZE])),
        )
        .merkleize()
        .await
        .unwrap();
    let storage = storage
        .write(
            StorageKey::new([2; 60]),
            Some(StorageValue(alloy_primitives::U256::from(version))),
        )
        .merkleize()
        .await
        .unwrap();
    let code = code
        .write(CodeKey::new([3; 32]), Some(vec![version; 128]))
        .merkleize()
        .await
        .unwrap();
    let modules = modules(version);
    let native = native::prepare(
        (acp, bulletin, vera, nonces),
        modules.diff_from(&ModuleState::default()),
    )
    .await
    .unwrap();
    let snapshot = VeraExecutor::new(DEPLOYMENT);
    snapshot.set_base_modules(modules);
    let module_root = native::state_root(&native);
    OrderedSealed {
        databases: (
            accounts,
            storage,
            code,
            native.0,
            native.1,
            native.2,
            native.3,
            commitment::Commitment(Some(Digest::from(module_root.0))),
        ),
        modules: snapshot.snapshot().unwrap(),
        height: u64::from(version),
    }
}

pub(super) async fn assert_records(set: &OrderedState, version: u8) {
    let readers = set.readers();
    assert_eq!(
        readers
            .0
            .read()
            .await
            .get(&AccountKey::new([1; 20]))
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
            .get(&StorageKey::new([2; 60]))
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
            .get(&CodeKey::new([3; 32]))
            .await
            .unwrap()
            .unwrap(),
        vec![version; 128]
    );
    assert_eq!(
        set.executor.modules().read().unwrap().serialize_stores(),
        modules(version).serialize_stores()
    );
}

fn runtime(directory: &Path) -> tokio::Runner {
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.join("db")))
}

#[test]
fn startup_recovers_each_partial_apply_before_publication() {
    if let Ok(directory) = std::env::var("VERA_ORDERED_RECOVERY_DIR") {
        let directory = Path::new(&directory);
        let applied: usize = std::env::var("VERA_ORDERED_RECOVERY_COUNT")
            .unwrap()
            .parse()
            .unwrap();
        runtime(directory).start(|context| {
            Box::pin(async move {
                let state = OrderedState::init(
                    context.child("create"),
                    config(&context, "recover", VeraExecutor::new(DEPLOYMENT)),
                    None,
                )
                .await;
                state.apply(revision(&state, 1).await).await;
                assert!(state.finalize().await.durable().await);
                let anchor = state.committed_targets().await;
                let mut file = std::fs::File::create(directory.join("anchor")).unwrap();
                file.write_all(&anchor.encode()).unwrap();
                file.sync_all().unwrap();
                let next = revision(&state, 2).await;
                macro_rules! advance {
                    ($index:tt) => {
                        if applied > $index {
                            state.databases.$index.apply(next.databases.$index).await;
                            assert!(state.databases.$index.finalize().await.durable().await);
                        }
                    };
                }
                advance!(0);
                advance!(1);
                advance!(2);
                advance!(3);
                advance!(4);
                advance!(5);
                advance!(6);
                assert_eq!(
                    state.executor.modules().read().unwrap().serialize_stores(),
                    modules(1).serialize_stores()
                );
                std::process::exit(77);
            })
        });
        unreachable!();
    }

    for applied in 1..=7 {
        let directory = tempfile::tempdir().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ordered_state::tests::recovery::startup_recovers_each_partial_apply_before_publication", "--nocapture"])
            .env("VERA_ORDERED_RECOVERY_DIR", directory.path())
            .env("VERA_ORDERED_RECOVERY_COUNT", applied.to_string())
            .output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(77),
            "apply {applied}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = std::fs::read(directory.path().join("anchor")).unwrap();
        let anchor = OrderedTargets::decode(commonware_codec::Copying(bytes.as_slice())).unwrap();
        let next_target = runtime(directory.path()).start(|context| {
            Box::pin(async move {
                let executor = VeraExecutor::new(DEPLOYMENT);
                executor
                    .modules()
                    .write()
                    .unwrap()
                    .nonces
                    .check_and_increment("unpublished", 0)
                    .unwrap();
                let unpublished = executor.modules().read().unwrap().serialize_stores();
                let raw = Box::pin(OrderedDatabases::init(
                    context.child("inspect"),
                    config(&context, "recover", executor.clone()).databases,
                    None,
                ))
                .await;
                let actual = raw.committed_targets().await;
                let actual = [
                    actual.0, actual.1, actual.2, actual.3, actual.4, actual.5, actual.6,
                ];
                let first = [
                    anchor.0.clone(),
                    anchor.1.clone(),
                    anchor.2.clone(),
                    anchor.3.clone(),
                    anchor.4.clone(),
                    anchor.5.clone(),
                    anchor.6.clone(),
                ];
                for (index, (actual, expected)) in actual.iter().zip(&first).enumerate() {
                    assert_eq!(
                        actual != expected,
                        index < applied,
                        "unexpected persisted partition {index}"
                    );
                }
                drop(raw);
                let unanchored = OrderedState::open(
                    context.child("unanchored"),
                    config(&context, "recover", executor.clone()),
                )
                .await;
                assert!(matches!(unanchored, Err(AppError::Execution(_))));
                assert_eq!(
                    executor.modules().read().unwrap().serialize_stores(),
                    unpublished
                );
                if applied == 4 {
                    let mut wrong = anchor.clone();
                    wrong.3.root = Digest::from([0; 32]);
                    let failed = AssertUnwindSafe(OrderedState::open(
                        context.child("wrong"),
                        config(&context, "recover", executor.clone()).recover_to(wrong),
                    ))
                    .catch_unwind()
                    .await;
                    assert!(failed.is_err());
                    assert_eq!(
                        executor.modules().read().unwrap().serialize_stores(),
                        unpublished
                    );
                }
                let state = OrderedState::open(
                    context.child("recover"),
                    config(&context, "recover", executor).recover_to(anchor.clone()),
                )
                .await
                .unwrap();
                assert_eq!(state.committed_targets().await, anchor);
                assert_records(&state, 1).await;
                state.apply(revision(&state, 3).await).await;
                assert!(state.finalize().await.durable().await);
                assert_records(&state, 3).await;
                state.committed_targets().await
            })
        });
        runtime(directory.path()).start(|context| {
            Box::pin(async move {
                let state = OrderedState::init(
                    context.child("reopen"),
                    config(&context, "recover", VeraExecutor::new(DEPLOYMENT))
                        .recover_to(next_target.clone()),
                    None,
                )
                .await;
                assert_eq!(state.committed_targets().await, next_target);
                assert_records(&state, 3).await;
            })
        });
    }
}
