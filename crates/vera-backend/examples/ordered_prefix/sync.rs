use super::*;
use commonware_codec::EncodeSize;
use commonware_glue::stateful::db::{
    DatabaseSet, ManagedDb, Shared, StateSyncDb, SyncEngineConfig, Unmerkleized as _,
};
use commonware_runtime::Supervisor as _;
use commonware_storage::qmdb::sync::{Feedback, Request, Response, Source};
use commonware_utils::channel::{mpsc, oneshot};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

type Set = Shared<Store>;
const RECORDS: usize = 4096;
const PREFIX: &[u8] = b"blocked/";

struct MeasuredSource {
    db: Set,
    gate: ::tokio::sync::Semaphore,
    operations: AtomicU64,
    bytes: AtomicU64,
    tamper: Mutex<Option<oneshot::Sender<bool>>>,
}

impl Source for MeasuredSource {
    type Family = <Set as Source>::Family;
    type Digest = <Set as Source>::Digest;
    type Op = <Set as Source>::Op;
    type Error = <Set as Source>::Error;

    async fn serve(
        &self,
        request: Request<Self::Family>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, Feedback), Self::Error> {
        let _permit = self.gate.acquire().await.unwrap();
        let (mut response, mut feedback) = self.db.serve(request).await?;
        let count = match &mut response {
            Response::Operations { operations, .. } => {
                if operations.len() >= 2
                    && let Some(report) = self.tamper.lock().unwrap().take()
                {
                    operations[0] = operations[1].clone();
                    feedback = Some(report);
                }
                operations.len() as u64
            }
            Response::Boundary { .. } => 1,
        };
        self.operations.fetch_add(count, Ordering::Relaxed);
        self.bytes
            .fetch_add(response.encode_size() as u64, Ordering::Relaxed);
        Ok((response, feedback))
    }
}

fn destination(context: &tokio::Context) -> VariableConfig<index::KeyPrefix, LogCodec, Sequential> {
    let mut cfg = config(context);
    cfg.merkle_config.journal_partition = "replica-mmr".into();
    cfg.merkle_config.metadata_partition = "replica-mmr-meta".into();
    cfg.journal_config.partition = "replica-log".into();
    cfg.grafted_metadata_partition = "replica-graft".into();
    cfg
}

#[test]
fn ordered_sync_rejects_tampering_and_fetches_incremental_updates() {
    check_sync(false, false);
}

#[test]
fn ordered_sync_converges_after_queued_target_updates() {
    check_sync(true, false);
}

#[test]
fn ordered_sync_starts_after_pruned_history() {
    check_sync(true, true);
}

fn check_sync(burst: bool, prune: bool) {
    run(|context| async move {
        let cfg = config(&context);
        let source = Set::init(context.child("source"), cfg, None).await;
        let mut batch = source.new_batches().await;
        for i in 0..RECORDS {
            batch = batch.write(
                format!("unrelated/{i:08}").into_bytes(),
                Some(Bytes::from(vec![7; 256])),
            );
        }
        batch = batch.write(b"blocked/alice".to_vec(), Some(Bytes::from_static(b"deny")));
        source.apply(batch.merkleize().await.unwrap()).await;
        assert!(source.finalize().await.durable().await);
        if prune {
            for value in [6, 7] {
                let mut batch = source.new_batches().await;
                for i in 0..RECORDS {
                    batch = batch.write(
                        format!("unrelated/{i:08}").into_bytes(),
                        Some(Bytes::from(vec![value; 256])),
                    );
                }
                batch = batch.write(b"blocked/alice".to_vec(), Some(Bytes::from(vec![value])));
                source.apply(batch.merkleize().await.unwrap()).await;
                assert!(source.finalize().await.durable().await);
            }
            let target = source.committed_targets().await;
            assert!(
                *target.range.start() > 0,
                "fixture did not advance the sync boundary"
            );
            source.prune(&target).await;
            assert!(
                source
                    .serve(Request::Operations {
                        size: target.range.end(),
                        start: commonware_storage::merkle::Location::new(0),
                        max_ops: NZU64!(1),
                    })
                    .await
                    .is_err(),
                "source still serves pruned history"
            );
        }
        let first = source.committed_targets().await;
        let first_root = source.read().await.root();
        let first_proof = proof::prove(&*source.read().await, PREFIX).await.unwrap();
        assert!(first_proof.verify(PREFIX, &first_root));
        assert_ne!(
            first.root, first_root,
            "sync and activity commitments must stay distinct"
        );

        let (bad_tx, bad_rx) = oneshot::channel();
        let measured = Arc::new(MeasuredSource {
            db: source.clone(),
            gate: ::tokio::sync::Semaphore::new(4),
            operations: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            tamper: Mutex::new(Some(bad_tx)),
        });
        let (updates_tx, updates_rx) = mpsc::channel(4);
        let (finish_tx, finish_rx) = mpsc::channel(1);
        let (reached_tx, mut reached_rx) = mpsc::channel(16);
        let sync = Store::sync_db(
            context.child("replica"),
            destination(&context),
            measured.clone(),
            first.clone(),
            updates_rx,
            Some(finish_rx),
            Some(reached_tx),
            SyncEngineConfig {
                fetch_batch_size: NZU64!(64),
                apply_batch_size: NZU64!(128),
                max_outstanding_requests: 4,
                update_channel_size: NZUsize!(4),
                max_retained_roots: 4,
            },
        );
        let advance = async {
            assert!(!bad_rx.await.unwrap(), "tampered operations were accepted");
            assert_eq!(reached_rx.recv().await.unwrap(), first);
            let initial_ops = measured.operations.load(Ordering::Relaxed);
            let initial_bytes = measured.bytes.load(Ordering::Relaxed);
            let pause = if burst {
                Some(measured.gate.acquire_many(4).await.unwrap())
            } else {
                None
            };
            let mut last = first.clone();
            for revision in 1..=8 {
                let mut batch = source.new_batches().await;
                batch = batch
                    .write(b"blocked/alice".to_vec(), None)
                    .write(b"blocked/bob".to_vec(), Some(Bytes::from(vec![revision])))
                    .write(
                        b"unrelated/00000000".to_vec(),
                        Some(Bytes::from(vec![revision; 256])),
                    );
                source.apply(batch.merkleize().await.unwrap()).await;
                assert!(source.finalize().await.durable().await);
                last = source.committed_targets().await;
                updates_tx.send(last.clone()).await.unwrap();
                if !burst {
                    assert_eq!(reached_rx.recv().await.unwrap(), last);
                }
            }
            if burst {
                assert_eq!(measured.operations.load(Ordering::Relaxed), initial_ops);
                drop(pause);
                while reached_rx.recv().await.unwrap() != last {}
            }
            let delta_ops = measured.operations.load(Ordering::Relaxed) - initial_ops;
            let delta_bytes = measured.bytes.load(Ordering::Relaxed) - initial_bytes;
            assert!(
                delta_ops > 0 && delta_ops < RECORDS as u64 / 4,
                "incremental sync transferred {delta_ops} operations for eight small updates"
            );
            assert!(delta_bytes < initial_bytes / 4);
            eprintln!(
                "ordered sync: burst={burst} prune={prune} initial_ops={initial_ops} initial_bytes={initial_bytes} delta_ops={delta_ops} delta_bytes={delta_bytes}"
            );
            finish_tx.send(()).await.unwrap();
            last
        };
        let (restored, final_target) = ::tokio::time::timeout(Duration::from_secs(30), async {
            ::tokio::join!(sync, advance)
        })
        .await
        .expect("ordered state sync deadline");
        let restored = restored.unwrap();
        assert_eq!(restored.sync_target(), final_target);
        let root = source.read().await.root();
        assert_eq!(restored.root(), root);
        assert!(!first_proof.verify(PREFIX, &root));
        let evidence = proof::prove(&restored, PREFIX).await.unwrap();
        assert!(evidence.verify(PREFIX, &root));
        assert_eq!(evidence.entries.len(), 1);
        assert_eq!(evidence.entries[0].key, b"blocked/bob");
        assert_eq!(
            restored.get(&b"unrelated/00000000".to_vec()).await.unwrap(),
            Some(Bytes::from(vec![8; 256]))
        );
        assert_eq!(
            restored.get(&b"unrelated/00004095".to_vec()).await.unwrap(),
            Some(Bytes::from(vec![7; 256]))
        );
        drop(restored);
        let reopened = Store::init(context.child("reopened"), destination(&context))
            .await
            .unwrap();
        assert_eq!(reopened.root(), root);
        assert_eq!(reopened.sync_target(), final_target);
        assert!(
            proof::prove(&reopened, PREFIX)
                .await
                .unwrap()
                .verify(PREFIX, &root)
        );
    });
}
