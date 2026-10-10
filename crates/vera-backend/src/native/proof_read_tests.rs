use super::*;
use alloy_primitives::B256;
use commonware_runtime::{Runner as _, Supervisor as _, tokio};
use commonware_utils::NZU16;
use vera_permission::{AccessRequest, Actor, Object, Operation, PERMISSION_LIMITS};

#[test]
fn proof_readers_release_partial_guards_while_a_partition_is_busy() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            let set =
                NativeStateSet::init(context.child("proof"), state_config("proof", cache), None)
                    .await;
            let partitions = [&set.0, &set.1, &set.2, &set.3];
            {
                let guards = read_partitions(partitions).await;
                let root = combine_module_roots(&guards.each_ref().map(|db| db.root().0));
                assert_ne!(root, B256::ZERO);
            }
            let request = AccessRequest {
                actor: Actor(
                    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                        .parse()
                        .unwrap(),
                ),
                operations: vec![Operation {
                    object: Object {
                        resource: "document".into(),
                        id: "report".into(),
                    },
                    permission: "read".into(),
                }],
            };
            for permission in [false, true] {
                for blocked in 0..4 {
                    let (slot, database) = partitions[blocked].write().await;
                    let proof = async {
                        if permission {
                            permission_proof(
                                &set,
                                B256::ZERO,
                                InMemoryKvStore::default(),
                                "policy",
                                &request,
                                PERMISSION_LIMITS,
                            )
                            .await
                            .map(|_| ())
                        } else {
                            SyncProof::capture(&set, B256::ZERO).await.map(|_| ())
                        }
                    };
                    futures::pin_mut!(proof);
                    assert!(futures::poll!(&mut proof).is_pending());
                    for (index, partition) in partitions.iter().enumerate() {
                        if index != blocked {
                            let writer = partition.write();
                            futures::pin_mut!(writer);
                            let std::task::Poll::Ready((other, value)) =
                                futures::poll!(&mut writer)
                            else {
                                panic!(
                                    "proof reader held partition {index} while waiting on {blocked}"
                                );
                            };
                            other.put(value);
                        }
                    }
                    slot.put(database);
                    let std::task::Poll::Ready(result) = futures::poll!(&mut proof) else {
                        panic!("proof reader did not resume after writer released partition");
                    };
                    assert!(matches!(
                        result,
                        Err(BackendError::InvalidSyncProof(
                            "selected module root changed"
                        )) | Err(BackendError::Permission(
                            vera_permission::PermissionError::Invalid(
                                "selected module root changed"
                            )
                        ))
                    ));
                }
            }
        },
    );
}
