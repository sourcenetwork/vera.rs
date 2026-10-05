use super::*;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::db::{
    DatabaseSet, ManagedDb, Merkleized as _, Shared, Unmerkleized as _,
};

use commonware_runtime::Supervisor as _;
use std::{path::Path, process::Command};

type Set = Shared<Store>;
type Target = <Store as ManagedDb<tokio::Context>>::SyncTarget;
const PREFIX: &[u8] = b"blocked/";
const ALICE: &[u8] = b"blocked/alice";
const BOB: &[u8] = b"blocked/bob";
const EVE: &[u8] = b"blocked/eve";
const DENY: Bytes = Bytes::from_static(b"deny");

async fn assert_records(set: &Set, root: Digest, keys: &[&[u8]]) {
    let reader = set.readers();
    let db = reader.read().await;
    assert_eq!(db.root(), root);
    let witness = proof::prove(&db, PREFIX).await.unwrap();
    assert!(witness.verify(PREFIX, &root));
    assert_eq!(
        witness
            .entries
            .iter()
            .map(|entry| entry.key.as_slice())
            .collect::<Vec<_>>(),
        keys
    );
}

#[test]
fn pending_forks_do_not_change_committed_proofs() {
    run(|context| async move {
        let cfg = config(&context);
        let set = Set::init(context.child("initial"), cfg, None).await;
        let empty_root = set.read().await.root();
        let parent = set
            .new_batches()
            .await
            .write(ALICE.to_vec(), Some(DENY))
            .merkleize()
            .await
            .unwrap();
        let parent_root = parent.root();
        let selected = Set::fork_batches(&parent)
            .write(ALICE.to_vec(), None)
            .write(BOB.to_vec(), Some(DENY));
        let rejected = Set::fork_batches(&parent).write(EVE.to_vec(), Some(DENY));
        assert_eq!(rejected.get(&ALICE.to_vec()).await.unwrap(), Some(DENY));
        assert_eq!(selected.get(&ALICE.to_vec()).await.unwrap(), None);
        assert_eq!(selected.get(&EVE.to_vec()).await.unwrap(), None);
        let selected = selected.merkleize().await.unwrap();
        let rejected = rejected.merkleize().await.unwrap();
        assert_ne!(selected.root(), rejected.root());
        assert_records(&set, empty_root, &[]).await;

        set.apply(parent).await;
        assert!(set.finalize().await.durable().await);
        let parent_target = set.committed_targets().await;
        assert_records(&set, parent_root, &[ALICE]).await;
        assert_ne!(parent_root, parent_target.root);
        let witness = {
            let db = set.read().await;
            proof::prove(&db, PREFIX).await.unwrap()
        };
        assert!(!witness.verify(PREFIX, &parent_target.root));
        let selected_root = selected.root();
        set.apply(selected).await;
        assert!(set.finalize().await.durable().await);
        drop(rejected);
        assert_records(&set, selected_root, &[BOB]).await;

        drop(set);
        let set = Set::init(
            context.child("recovered"),
            config(&context),
            Some(parent_target),
        )
        .await;
        assert_records(&set, parent_root, &[ALICE]).await;
    });
}

fn runtime(path: &Path) -> tokio::Runner {
    tokio::Runner::new(tokio::Config::new().with_storage_directory(path))
}

#[test]
fn recover_checkpoint_after_process_exit() {
    if let Ok(directory) = std::env::var("VERA_PREFIX_RECOVERY_DIR") {
        let directory = Path::new(&directory);
        let phase = std::env::var("VERA_PREFIX_RECOVERY_PHASE").unwrap();
        runtime(&directory.join("db")).start(|context| async move {
            let cfg = config(&context);
            let set = Set::init(context.child("initial"), cfg, None).await;
            let first = set
                .new_batches()
                .await
                .write(ALICE.to_vec(), Some(DENY))
                .merkleize()
                .await
                .unwrap();
            let root = first.root();
            set.apply(first).await;
            assert!(set.finalize().await.durable().await);
            let target = set.committed_targets().await;
            std::fs::write(directory.join("anchor"), (root, target).encode()).unwrap();
            let suffix = set
                .new_batches()
                .await
                .write(ALICE.to_vec(), None)
                .write(BOB.to_vec(), Some(DENY))
                .merkleize()
                .await
                .unwrap();
            if phase != "prepared" {
                set.apply(suffix).await;
                if phase == "durable" {
                    assert!(set.finalize().await.durable().await);
                }
            }
            std::process::exit(0);
        });
        unreachable!();
    }

    for phase in ["prepared", "applied", "durable"] {
        let directory = tempfile::tempdir().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lifecycle::recover_checkpoint_after_process_exit",
                "--nocapture",
            ])
            .env("VERA_PREFIX_RECOVERY_DIR", directory.path())
            .env("VERA_PREFIX_RECOVERY_PHASE", phase)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "phase {phase}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = std::fs::read(directory.path().join("anchor")).unwrap();
        let (root, target) =
            <(Digest, Target)>::decode(commonware_codec::Copying(bytes.as_slice())).unwrap();
        runtime(&directory.path().join("db")).start(|context| async move {
            let cfg = config(&context);
            let set = Set::init(context.child("initial"), cfg, None).await;
            if phase == "durable" {
                assert_ne!(set.read().await.root(), root);
            }
            drop(set);
            let set = Set::init(context.child("recovered"), config(&context), Some(target)).await;
            assert_records(&set, root, &[ALICE]).await;
        });
        runtime(&directory.path().join("db")).start(|context| async move {
            let cfg = config(&context);
            let set = Set::init(context.child("initial"), cfg, None).await;
            assert_records(&set, root, &[ALICE]).await;
        });
    }
}
