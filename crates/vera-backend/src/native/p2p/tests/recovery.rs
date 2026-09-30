use super::*;
use commonware_glue::stateful::db::ManagedDb as _;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct PausedSource {
    resolver: Resolver,
    permits: ::tokio::sync::Semaphore,
    waiting: ::tokio::sync::Notify,
    served: AtomicUsize,
}

impl PausedSource {
    fn new(resolver: Resolver, permits: usize) -> Arc<Self> {
        Arc::new(Self {
            resolver,
            permits: ::tokio::sync::Semaphore::new(permits),
            waiting: ::tokio::sync::Notify::new(),
            served: AtomicUsize::new(0),
        })
    }
}

impl Source for PausedSource {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = Operation;
    type Error = p2p::ResponseDropped;

    async fn serve(
        &self,
        request: Request<Self::Family>,
    ) -> Result<
        (
            Response<Self::Family, Self::Op, Self::Digest>,
            Option<Feedback<Response<Self::Family, Self::Op, Self::Digest>>>,
        ),
        Self::Error,
    > {
        if self.permits.available_permits() == 0 {
            self.waiting.notify_one();
        }
        self.permits.acquire().await.unwrap().forget();
        let response = self.resolver.serve(request).await?;
        self.served.fetch_add(1, Ordering::Relaxed);
        Ok(response)
    }
}

fn sync_config() -> SyncEngineConfig {
    SyncEngineConfig {
        fetch_batch_size: NZU64!(16),
        apply_batch_size: NZU64!(16),
        max_outstanding_requests: 1,
        update_channel_size: NZUsize!(2),
        max_retained_roots: 2,
    }
}

#[test]
fn peer_sync_rejects_a_response_against_a_different_target_root() {
    let directory = tempfile::tempdir().unwrap();
    let config = tokio::Config::new().with_storage_directory(directory.path());
    tokio::Runner::new(config).start(|context| async move {
        ::tokio::time::timeout(Duration::from_secs(20), async {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            let source = Shared::<NativeDb>::init(
                context.child("source"), state_config("source", cache.clone()).0, None,).await;
            let batch = source.new_batches().await.write(b"key".to_vec(), Some(Bytes::from_static(b"value")));
            source.apply(batch.merkleize().await.unwrap()).await;
            assert!(source.finalize().await.durable().await);
            let mut target = source.committed_targets().await;
            target.root.0[0] ^= 1;
            let mut peers = network::Peers::start(&context);
            peers.resolvers[0].attach_database(source).await;
            let (_updates, updates_rx) = mpsc::channel(1);
            let sync = NativeDb::sync_db(
                context.child("replica"), state_config("replica", cache).0,
                peers.resolvers[1].clone(), target, updates_rx, None, None, sync_config(),
            );
            ::tokio::select! {
                result = sync => panic!("mismatched sync returned before rejecting the peer: {:?}", result.err()),
                () = async {
                    while !peers.blocked[1].recv().await.unwrap().iter().any(|peer| peer == &peers.identities[0]) {}
                } => {},
            }
        }).await.expect("target mismatch was not rejected");
    });
}

#[test]
fn pruned_peer_sync_resumes_after_cancellation_and_converges_on_new_target() {
    let directory = tempfile::tempdir().unwrap();
    let config = tokio::Config::new().with_storage_directory(directory.path());
    tokio::Runner::new(config).start(|context| async move {
        ::tokio::time::timeout(Duration::from_secs(30), async {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            let source = Shared::<NativeDb>::init(
                context.child("source"), state_config("source", cache.clone()).0, None,).await;
            for revision in 0..11 {
                let mut batch = source.new_batches().await;
                for i in 0..128 {
                    batch = batch.write(format!("key/{i:04}").into_bytes(), Some(Bytes::from(vec![revision; 256])));
                }
                source.apply(batch.merkleize().await.unwrap()).await;
                assert!(source.finalize().await.durable().await);
            }
            let initial = source.committed_targets().await;
            assert!(*initial.range.start() > 0);
            source.prune(&initial).await;
            assert!(source.serve(Request::Operations {
                size: initial.range.end(), start: Location::new(0), max_ops: MAX_FETCH_OPS,
            }).await.is_err());
            let initial_root = source.read().await.root();
            let peers = network::Peers::start(&context);
            peers.resolvers[0].attach_database(source.clone()).await;
            let interrupted = PausedSource::new(peers.resolvers[1].clone(), 4);
            let replica_config = state_config("replica", cache).0;
            {
                let (_updates, updates_rx) = mpsc::channel(1);
                let sync = NativeDb::sync_db(
                    context.child("interrupted"), replica_config.clone(), interrupted.clone(),
                    initial.clone(), updates_rx, None, None, sync_config(),
                );
                ::tokio::select! {
                    result = sync => panic!("sync finished before cancellation: {:?}", result.err()),
                    () = interrupted.waiting.notified() => {},
                }
            }
            assert_eq!(interrupted.served.load(Ordering::Relaxed), 4);

            let resumed = PausedSource::new(peers.resolvers[1].clone(), 0);
            let (updates, updates_rx) = mpsc::channel(2);
            let (finish, finish_rx) = mpsc::channel(1);
            let (reached, mut reached_rx) = mpsc::channel(4);
            let sync = NativeDb::sync_db(
                context.child("resumed"), replica_config.clone(), resumed.clone(),
                initial.clone(), updates_rx, Some(finish_rx), Some(reached), sync_config(),
            );
            let advance = async {
                resumed.waiting.notified().await;
                let batch = source.new_batches().await
                    .write(b"key/0000".to_vec(), None)
                    .write(b"key/0001".to_vec(), Some(Bytes::from_static(b"changed")))
                    .write(b"key/new".to_vec(), Some(Bytes::from_static(b"added")));
                source.apply(batch.merkleize().await.unwrap()).await;
                assert!(source.finalize().await.durable().await);
                let target = source.committed_targets().await;
                updates.send(target.clone()).await.unwrap();
                resumed.permits.add_permits(1024);
                while reached_rx.recv().await.unwrap() != target {}
                finish.send(()).await.unwrap();
                target
            };
            let (replica, target) = ::tokio::join!(sync, advance);
            let replica = replica.unwrap();
            let root = source.read().await.root();
            assert_ne!(root, initial_root);
            assert_eq!(replica.root(), root);
            assert_eq!(replica.sync_target(), target);
            assert!(replica.get(&b"key/0000".to_vec()).await.unwrap().is_none());
            assert_eq!(replica.get(&b"key/0001".to_vec()).await.unwrap(), Some(Bytes::from_static(b"changed")));
            assert_eq!(replica.get(&b"key/new".to_vec()).await.unwrap(), Some(Bytes::from_static(b"added")));
            for i in 2..128 {
                assert_eq!(replica.get(&format!("key/{i:04}").into_bytes()).await.unwrap(), Some(Bytes::from(vec![10; 256])));
            }
            drop(replica);
            let reopened = NativeDb::init(context.child("reopened"), replica_config, None).await.unwrap();
            assert_eq!(reopened.root(), root);
            assert_eq!(reopened.sync_target(), target);
            assert_eq!(reopened.get(&b"key/new".to_vec()).await.unwrap(), Some(Bytes::from_static(b"added")));
            eprintln!("pruned peer sync: cancelled after {} responses, resumed with {} responses", interrupted.served.load(Ordering::Relaxed), resumed.served.load(Ordering::Relaxed));
        }).await.expect("peer recovery timed out");
    });
}
