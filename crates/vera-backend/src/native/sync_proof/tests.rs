use super::*;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_runtime::{Runner as _, Supervisor as _, tokio};
use commonware_storage::qmdb::sync::{Request, Source as _};
use commonware_utils::NZU16;

async fn root(set: &NativeStateSet) -> B256 {
    combine_module_roots(&[
        set.0.read().await.root().0,
        set.1.read().await.root().0,
        set.2.read().await.root().0,
        set.3.read().await.root().0,
    ])
}

#[test]
fn proofs_bind_all_namespaces_and_commit_ranges_after_pruning() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            let set =
                NativeStateSet::init(context.child("source"), state_config("source", cache), None)
                    .await;
            let initial_root = root(&set).await;
            let initial = SyncProof::capture(&set, initial_root).await.unwrap();
            assert_eq!(
                initial.verify(initial_root).unwrap(),
                set.committed_targets().await
            );
            for revision in 0..11 {
                let changes = std::array::from_fn(|module| {
                    (0..128)
                        .map(|i| {
                            (
                                format!("key/{i:04}").into_bytes(),
                                Some(vec![revision ^ u8::try_from(module).unwrap(); 64]),
                            )
                        })
                        .collect()
                });
                set.apply(prepare(set.new_batches().await, changes).await.unwrap())
                    .await;
                assert!(set.finalize().await.durable().await);
            }
            let target = set.committed_targets().await;
            set.prune(&target).await;
            for (db, target) in [
                (&set.0, &target.0),
                (&set.1, &target.1),
                (&set.2, &target.2),
                (&set.3, &target.3),
            ] {
                assert!(*target.range.start() > 0);
                assert!(
                    db.serve(Request::Operations {
                        size: target.range.end(),
                        start: Location::new(0),
                        max_ops: NZU64!(1)
                    })
                    .await
                    .is_err()
                );
            }
            let expected = root(&set).await;
            assert!(SyncProof::capture(&set, initial_root).await.is_err());
            let proof = SyncProof::capture(&set, expected).await.unwrap();
            let bytes = proof.encode();
            assert_eq!(bytes.len(), proof.encode_size());
            assert_eq!(
                SyncProof::decode(bytes.clone())
                    .unwrap()
                    .verify(expected)
                    .unwrap(),
                target
            );
            assert!(SyncProof::decode(bytes.slice(..bytes.len() - 1)).is_err());
            let mut trailing = bytes.to_vec();
            trailing.push(0);
            assert!(SyncProof::decode(commonware_codec::Copying(trailing.as_slice())).is_err());
            assert!(proof.verify(initial_root).is_err());
            for i in 0..4 {
                let mut changed = proof.clone();
                changed.0[i].ops_root.0[0] ^= 1;
                assert!(changed.verify(expected).is_err());
                let mut changed = proof.clone();
                changed.0[i].witness.grafted_root.0[0] ^= 1;
                assert!(changed.verify(expected).is_err());
                let mut changed = proof.clone();
                changed.0[i].proof.leaves = changed.0[i].proof.leaves.saturating_add(1);
                assert!(changed.verify(expected).is_err());
                let mut changed = proof.clone();
                let Operation::CommitFloor(_, floor) = &mut changed.0[i].commit.0 else {
                    panic!("missing commit")
                };
                *floor = floor.saturating_add(1);
                assert!(changed.verify(expected).is_err());
                let mut changed = proof.clone();
                changed.0[i] = initial.0[i].clone();
                assert!(changed.verify(expected).is_err());
            }
            let mut changed = proof.clone();
            changed.0.swap(0, 1);
            assert!(changed.verify(expected).is_err());
            let mut changed = proof.clone();
            changed.0[0].proof.digests =
                vec![Digest::from([0; 32]); MAX_PROOF_DIGESTS_PER_ELEMENT + 1];
            assert!(SyncProof::decode(changed.encode()).is_err());
            let mut changed = proof;
            changed.0[0].commit.0 = Operation::CommitFloor(
                Some(Bytes::from(vec![0; MAX_VALUE_BYTES + 1])),
                Location::new(0),
            );
            assert!(SyncProof::decode(changed.encode()).is_err());
        },
    );
}
