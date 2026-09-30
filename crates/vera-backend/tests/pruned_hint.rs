//! Reproduction of single-source pruning hints stranding synchronization.
use bytes::Bytes;
use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::db::{
    DatabaseSet as _, Shared, StateSyncDb as _, SyncEngineConfig, Unmerkleized as _,
};
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{
    merkle::{Location, mmr},
    qmdb::sync::{Request, Response, Source, source},
};
use commonware_utils::{NZU16, NZU64, NZUsize, channel::mpsc};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use vera_backend::native::{NativeDb, state_config};

struct FirstPruned {
    db: Shared<NativeDb>,
    calls: Arc<AtomicUsize>,
}

impl Source for FirstPruned {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = <NativeDb as Source>::Op;
    type Error = <Shared<NativeDb> as Source>::Error;

    async fn serve(&self, request: Request<Self::Family>) -> source::Result<Self> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return Ok((
                Response::Pruned {
                    frontier: Location::new(1000),
                },
                None,
            ));
        }
        self.db.serve(request).await
    }
}

#[test]
fn one_unproven_pruned_hint_does_not_strand_a_servable_target() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            let source = Shared::<NativeDb>::init(
                context.child("source"),
                state_config("source", cache.clone()).0,
                None,
            )
            .await;
            let batch = source
                .new_batches()
                .await
                .write(b"key".to_vec(), Some(Bytes::from_static(b"value")));
            source.apply(batch.merkleize().await.unwrap()).await;
            assert!(source.finalize().await.durable().await);
            let target = source.committed_targets().await;
            // The requested target is demonstrably available from an honest source.
            let honest = source
                .serve(Request::Operations {
                    size: target.range.end(),
                    start: target.range.start(),
                    max_ops: NZU64!(64),
                })
                .await
                .unwrap();
            assert!(matches!(honest.0, Response::Operations { .. }));
            let calls = Arc::new(AtomicUsize::new(0));
            let (_updates, updates_rx) = mpsc::channel(1);
            let result = ::tokio::time::timeout(
                Duration::from_secs(20),
                NativeDb::sync_db(
                    context.child("replica"),
                    state_config("replica", cache).0,
                    FirstPruned {
                        db: source,
                        calls: calls.clone(),
                    },
                    target,
                    updates_rx,
                    None,
                    None,
                    SyncEngineConfig {
                        fetch_batch_size: NZU64!(64),
                        apply_batch_size: NZU64!(64),
                        max_outstanding_requests: 1,
                        update_channel_size: NZUsize!(1),
                        max_retained_roots: 1,
                    },
                ),
            )
            .await;
            assert!(
                result.is_ok(),
                "one unproven hint paused a servable target; source calls={}",
                calls.load(Ordering::SeqCst)
            );
            assert_eq!(
                result
                    .unwrap()
                    .unwrap()
                    .get(&b"key".to_vec())
                    .await
                    .unwrap(),
                Some(Bytes::from_static(b"value"))
            );
        },
    );
}
