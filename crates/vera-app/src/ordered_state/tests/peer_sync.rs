use super::*;

use commonware_cryptography::ChaCha20Poly1305;
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_glue::stateful::db::p2p;
use commonware_p2p::{Address, AddressableManager as _, authenticated::lookup};
use commonware_runtime::{Handle, Quota};
use commonware_stream::{
    cups::{self, Cups},
    sake::{self, Sake},
};
use commonware_utils::{NZU32, ordered::Map};
use vera_backend::p2p::{MAX_FETCH_OPS, MAX_MESSAGE_BYTES, Resolver, WireDatabase};

struct Tasks(Vec<Handle<()>>);

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

#[test]
fn all_partitions_sync_over_authenticated_peers_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::Config::new().with_storage_directory(directory.path());
    let (target, checkpoint) = tokio::Runner::new(runtime.clone()).start(|context| {
        Box::pin(async move {
            ::tokio::time::timeout(Duration::from_secs(30), async {
                let source = OrderedState::init(
                    context.child("source"),
                    config(&context, "source", VeraExecutor::new(DEPLOYMENT)),
                    None,
                )
                .await;
                source.apply(recovery::revision(&source, 1).await).await;
                assert!(source.finalize().await.durable().await);

                let keys = [PrivateKey::from_seed(31), PrivateKey::from_seed(32)];
                let listeners = keys
                    .each_ref()
                    .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap());
                let addresses = listeners.each_ref().map(|l| l.local_addr().unwrap());
                let identities = keys.each_ref().map(|k| k.public_key());
                let membership: Map<_, Address> = identities
                    .iter()
                    .cloned()
                    .zip(addresses.map(Into::into))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                let mut tasks = Tasks(Vec::new());
                let mut resolvers = Vec::new();
                for (i, (key, listener)) in keys.into_iter().zip(listeners).enumerate() {
                    let mut cfg = lookup::Config::local(
                        Cups::<_, ChaCha20Poly1305>::new(
                            Sake {
                                signer: key,
                                synchrony_bound: std::time::Duration::from_secs(5),
                                max_handshake_age: std::time::Duration::from_secs(10),
                                version: sake::Version::V1,
                            },
                            cups::Version::V1,
                        ),
                        b"vera-partition-sync-test",
                        addresses[i],
                        NZUsize!(2),
                        MAX_MESSAGE_BYTES,
                    );
                    cfg.dial_frequency = Duration::from_millis(10);
                    cfg.peer_connection_cooldown = Duration::from_millis(10);
                    let (mut network, mut oracle) = lookup::Network::new(
                        context
                            .child(["source_peer", "replica_peer"][i])
                            .child("network"),
                        cfg,
                    );
                    oracle.track(0, membership.clone());
                    macro_rules! channel {
                        ($channel:literal, $db:ty) => {{
                            let (actor, mailbox) = p2p::Actor::new(
                                context
                                    .child(["source_peer", "replica_peer"][i])
                                    .child(concat!("resolver_", stringify!($channel))),
                                p2p::Config {
                                    peer_provider: oracle.clone(),
                                    blocker: oracle.clone(),
                                    database: None::<Shared<WireDatabase<$db>>>,
                                    mailbox_size: NZUsize!(4),
                                    me: Some(identities[i].clone()),
                                    timeout: Duration::from_secs(2),
                                    fetch_retry_timeout: Duration::from_millis(10),
                                    max_serve_ops: MAX_FETCH_OPS,
                                    priority_requests: false,
                                    priority_responses: false,
                                },
                            );
                            tasks.0.push(
                                actor.start(
                                    network.register($channel, Quota::per_second(NZU32!(100))),
                                ),
                            );
                            Resolver::<$db>::new(mailbox)
                        }};
                    }
                    resolvers.push((
                        channel!(0, AccountsDb),
                        channel!(1, StorageDb),
                        channel!(2, CodeDb),
                        channel!(3, NativeDb),
                        channel!(4, NativeDb),
                        channel!(5, NativeDb),
                        channel!(6, NativeDb),
                        (),
                    ));
                    drop(listener);
                    tasks.0.push(network.start());
                }
                resolvers[0]
                    .attach_databases(source.databases.clone())
                    .await;
                let mut final_target = source.committed_targets().await;
                let mut final_checkpoint = None;
                assert_ne!(final_target.0, OrderedDatabases::initial_sync_targets().0);
                assert_ne!(final_target.1, OrderedDatabases::initial_sync_targets().1);
                assert_ne!(final_target.2, OrderedDatabases::initial_sync_targets().2);
                for version in 1..=2 {
                    if version == 2 {
                        source
                            .apply(recovery::revision(&source, version).await)
                            .await;
                        assert!(source.finalize().await.durable().await);
                        final_target = source.committed_targets().await;
                    }
                    let executor = VeraExecutor::new(DEPLOYMENT);
                    executor
                        .modules()
                        .write()
                        .unwrap()
                        .nonces
                        .check_and_increment("stale", 0)
                        .unwrap();
                    let block = checkpoint::block(&source, u64::from(version)).await;
                    let native = &source.databases;
                    let proof = native::SyncProof::capture(
                        &(
                            native.3.clone(),
                            native.4.clone(),
                            native.5.clone(),
                            native.6.clone(),
                        ),
                        block.module_state_root,
                    )
                    .await
                    .unwrap();
                    let (light, key) = checkpoint::certify(&block, 42);
                    let checkpoint = OrderedCheckpoint::verify(&light, &key, &proof).unwrap();
                    let expected_anchor = *checkpoint.anchor();
                    final_checkpoint = Some(checkpoint.clone());
                    let sync_config = SyncEngineConfig {
                        fetch_batch_size: MAX_FETCH_OPS,
                        apply_batch_size: NZU64!(64),
                        max_outstanding_requests: 2,
                        update_channel_size: NZUsize!(2),
                        max_retained_roots: 2,
                    };
                    if version == 1 {
                        let failed = OrderedState::sync_checkpoint(
                            context.child("rejected_handoff"),
                            config(&context, "replica", executor.clone())
                                .with_sync_handoff(|_| async { Err("history unavailable".into()) }),
                            resolvers[1].clone(),
                            checkpoint.clone(),
                            sync_config,
                        )
                        .await
                        .unwrap_err();
                        assert_eq!(failed, "history unavailable");
                        assert_eq!(
                            executor
                                .modules()
                                .read()
                                .unwrap()
                                .nonces
                                .get_nonce("stale")
                                .unwrap(),
                            1
                        );
                        assert!(
                            executor
                                .modules()
                                .read()
                                .unwrap()
                                .acp
                                .query_policy_ids()
                                .unwrap()
                                .is_empty()
                        );
                    }
                    let (replica, reached) = OrderedState::sync_checkpoint(
                        context.child(if version == 1 {
                            "replica_first"
                        } else {
                            "replica_second"
                        }),
                        config(&context, "replica", executor),
                        resolvers[1].clone(),
                        checkpoint,
                        sync_config,
                    )
                    .await
                    .unwrap();
                    assert_eq!(reached, expected_anchor);
                    assert_eq!(replica.committed_targets().await, final_target);
                    recovery::assert_records(&replica, version).await;
                    for (source, destination) in [
                        (&source.databases.3, &replica.databases.3),
                        (&source.databases.4, &replica.databases.4),
                        (&source.databases.5, &replica.databases.5),
                        (&source.databases.6, &replica.databases.6),
                    ] {
                        assert_eq!(source.read().await.root(), destination.read().await.root());
                    }
                    assert!(replica.finalize().await.durable().await);
                }
                (final_target, final_checkpoint.unwrap())
            })
            .await
            .expect("partition synchronization deadline")
        })
    });
    tokio::Runner::new(runtime).start(|context| {
        Box::pin(async move {
            let replica = OrderedState::open(
                context.child("reopen"),
                config(&context, "replica", VeraExecutor::new(DEPLOYMENT))
                    .recover_checkpoint(checkpoint),
            )
            .await
            .unwrap();
            assert_eq!(replica.committed_targets().await, target);
            recovery::assert_records(&replica, 2).await;
        })
    });
}
