use super::*;
use commonware_glue::stateful::db::ManagedDb as _;
use commonware_runtime::Metrics as _;

async fn write_revision(source: &Shared<NativeDb>, revision: u8) {
    let mut batch = source.new_batches().await;
    for i in 0..128 {
        batch = batch.write(
            format!("key/{i:04}").into_bytes(),
            Some(Bytes::from(vec![revision; 256])),
        );
    }
    source.apply(batch.merkleize().await.unwrap()).await;
    assert!(source.finalize().await.durable().await);
}

#[test]
fn peer_sync_retries_after_pruning_without_a_target_update() {
    let directory = tempfile::tempdir().unwrap();
    let config = tokio::Config::new().with_storage_directory(directory.path());
    tokio::Runner::new(config).start(|context| async move {
        ::tokio::time::timeout(Duration::from_secs(30), async {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            let available = Shared::<NativeDb>::init(
                context.child("available"),
                state_config("available", cache.clone()).0,
                None,
            )
            .await;
            write_revision(&available, 0).await;
            let target = available.committed_targets().await;
            let root = available.read().await.root();
            let pruned = Shared::<NativeDb>::init(
                context.child("pruned"),
                state_config("pruned", cache.clone()).0,
                None,
            )
            .await;
            write_revision(&pruned, 0).await;
            assert_eq!(pruned.committed_targets().await, target);
            for revision in 1..11 {
                write_revision(&pruned, revision).await;
            }
            let floor = pruned.committed_targets().await;
            assert!(floor.range.start() > target.range.start());
            pruned.prune(&floor).await;
            assert!(
                pruned
                    .serve(Request::Boundary {
                        size: target.range.end(),
                        start: target.range.start(),
                    })
                    .await
                    .is_err()
            );

            let peers = network::Peers::start(&context);
            peers.resolvers[0].attach_database(pruned).await;
            let (_updates, updates_rx) = ring::channel(NZUsize!(1));
            let sync = NativeDb::sync_db(
                context.child("replica"),
                state_config("replica", cache).0,
                peers.resolvers[1].clone(),
                target.clone(),
                updates_rx,
                None,
                None,
                SyncEngineConfig {
                    fetch_batch_size: NZU64!(64),
                    apply_batch_size: NZU64!(64),
                    max_outstanding_requests: NZUsize!(1),
                },
            );
            let restore = async {
                loop {
                    if context.encode().lines().any(|line| {
                        line.starts_with("resolver_source_serve_requests_total{")
                            && line.contains("status=\"Failure\"")
                            && line
                                .split_whitespace()
                                .last()
                                .and_then(|value| value.parse::<u64>().ok())
                                .is_some_and(|count| count > 0)
                    }) {
                        break;
                    }
                    ::tokio::time::sleep(Duration::from_millis(10)).await;
                }
                peers.resolvers[0].attach_database(available).await;
            };
            let (replica, ()) = ::tokio::join!(sync, restore);
            let replica = replica.unwrap();
            assert_eq!(replica.root(), root);
            assert_eq!(replica.sync_target(), target);
            for i in 0..128 {
                assert_eq!(
                    replica
                        .get(&format!("key/{i:04}").into_bytes())
                        .await
                        .unwrap(),
                    Some(Bytes::from(vec![0; 256])),
                );
            }
        })
        .await
        .expect("an unavailable peer stranded a retained target");
    });
}
