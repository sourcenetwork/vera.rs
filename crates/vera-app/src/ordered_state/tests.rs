use super::*;

use std::{sync::Arc, time::Duration};

use alloy_consensus::Header;
use alloy_primitives::B256;
use alloy_sol_types::SolCall;
use commonware_consensus::types::{Epoch, Height, Round, View};
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_storage::qmdb::sync::{Feedback, Request, Response, Source};
use commonware_utils::{NZU16, NZU64, NZUsize};
use futures::SinkExt as _;
use vera_backend::state_set_config;
use vera_client::{ACP_ADDRESS, BlsSigner};
use vera_modules::acp::abi::IAcp;

mod application;
mod checkpoint;
mod peer_sync;
mod permission;
mod record;
mod recovery;

const DEPLOYMENT: u64 = 9001;

fn config(
    context: &Ctx,
    prefix: &str,
    executor: VeraExecutor,
) -> <OrderedState as DatabaseSet<Ctx>>::Config {
    let cache = CacheRef::from_pooler(context, NZU16!(4084), NZUsize!(128));
    ordered_config(
        state_set_config(prefix, cache.clone()),
        native::state_config(prefix, cache),
        executor,
    )
}

type Sources = (
    Shared<AccountsDb>,
    Shared<StorageDb>,
    Shared<CodeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
    Shared<NativeDb>,
    (),
);

fn sources(state: &OrderedState) -> Sources {
    let db = &state.databases;
    (
        db.0.clone(),
        db.1.clone(),
        db.2.clone(),
        db.3.clone(),
        db.4.clone(),
        db.5.clone(),
        db.6.clone(),
        (),
    )
}

fn block(height: u64) -> BlockContext {
    BlockContext::new(
        Header {
            number: height,
            timestamp: 1000 + height,
            gas_limit: 30_000_000,
            ..Header::default()
        },
        B256::ZERO,
        B256::ZERO,
    )
}

fn anchor(height: u64) -> Anchor<Digest> {
    Anchor {
        height: Height::new(height),
        round: Round::new(Epoch::new(0), View::new(height)),
        digest: Digest::from([1; 32]),
    }
}

fn policy(signer: &BlsSigner, name: &str) -> Tx {
    Tx::new(
        signer
            .sign_native_tx(
                ACP_ADDRESS,
                IAcp::createPolicyCall {
                    policy: format!("name: {name}\nresources:\n  - name: file\n")
                        .into_bytes()
                        .into(),
                    marshalType: 1,
                }
                .abi_encode()
                .into(),
            )
            .unwrap()
            .into(),
    )
}

struct PausedSource {
    db: Shared<NativeDb>,
    gate: ::tokio::sync::Semaphore,
    requested: ::tokio::sync::Notify,
}

impl Source for PausedSource {
    type Family = <Shared<NativeDb> as Source>::Family;
    type Digest = <Shared<NativeDb> as Source>::Digest;
    type Op = <Shared<NativeDb> as Source>::Op;
    type Error = <Shared<NativeDb> as Source>::Error;

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
        self.requested.notify_one();
        let _permit = self.gate.acquire().await.unwrap();
        // A peer whose journal moved past the requested size cannot serve it:
        // answer Pruned like a real source so the engine releases the target.
        let bounds = self.db.read().await.bounds();
        if request.size() < bounds.end {
            return Ok((
                Response::Pruned {
                    frontier: bounds.start,
                },
                None,
            ));
        }
        self.db.serve(request).await
    }
}

// Ignored pending the newest-wins-versus-converge-at-reached design
// discussion with upstream commonware: this fixture gates the only servable
// source behind a two-permit budget and assumes a superseding target aborts
// in-flight work immediately, which the convergence hold deliberately does
// not do. The stale-target e2e covers the shipped behavior.
#[test]
#[ignore = "supersede-on-update contract conflicts with the convergence hold"]
fn sync_publishes_latest_modules_before_suffix_execution() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::Config::new().with_storage_directory(directory.path());
    let (expected, target) = tokio::Runner::new(runtime.clone()).start(|context| {
        Box::pin(async move {
            let source_executor = VeraExecutor::new(DEPLOYMENT);
            let source = OrderedState::init(
                context.child("source"),
                config(&context, "source", source_executor.clone()),
                None,
            )
            .await;
            let signer = BlsSigner::new(1u64.into(), DEPLOYMENT).unwrap();
            let (first, outcome) = source
                .execute(
                    source.new_batches().await,
                    &block(1),
                    &[policy(&signer, "first")],
                )
                .await
                .unwrap();
            assert!(outcome.receipts[0].success());
            assert!(
                source_executor
                    .modules()
                    .read()
                    .unwrap()
                    .acp
                    .query_policy_ids()
                    .unwrap()
                    .is_empty()
            );
            let sealed_target = first.sync_targets();
            assert!(OrderedState::matches_sync_targets(&first, &sealed_target));
            let mut wrong_target = sealed_target.clone();
            wrong_target.3.root = Digest::from([0; 32]);
            assert!(!OrderedState::matches_sync_targets(&first, &wrong_target));
            let (second, second_outcome) = source
                .execute(
                    OrderedState::fork_batches(&first),
                    &block(2),
                    &[policy(&signer, "second")],
                )
                .await
                .unwrap();
            assert!(second_outcome.receipts[0].success());
            source.apply(first).await;
            assert!(source.finalize().await.durable().await);
            let initial = source.committed_targets().await;
            assert_eq!(initial, sealed_target);
            let destination_executor = VeraExecutor::new(DEPLOYMENT);
            destination_executor
                .modules()
                .write()
                .unwrap()
                .nonces
                .check_and_increment("stale", 0)
                .unwrap();

            let db = &source.databases;
            let paused = Arc::new(PausedSource {
                db: db.6.clone(),
                gate: ::tokio::sync::Semaphore::new(0),
                requested: ::tokio::sync::Notify::new(),
            });
            let sources = (
                db.0.clone(),
                db.1.clone(),
                db.2.clone(),
                db.3.clone(),
                db.4.clone(),
                db.5.clone(),
                paused.clone(),
                (),
            );
            let (mut tip_tx, tip_rx) = ring::channel(NZUsize!(4));
            let handoff_entered = Arc::new(::tokio::sync::Notify::new());
            let handoff_release = Arc::new(::tokio::sync::Notify::new());
            let entered = handoff_entered.clone();
            let release = handoff_release.clone();
            let sync = OrderedState::sync(
                context.child("destination"),
                config(&context, "destination", destination_executor.clone()).with_sync_handoff(
                    move |reached| async move {
                        assert_eq!(reached, anchor(2));
                        entered.notify_one();
                        release.notified().await;
                        Ok(())
                    },
                ),
                sources,
                anchor(1),
                initial,
                tip_rx,
                SyncEngineConfig {
                    fetch_batch_size: NZU64!(16),
                    apply_batch_size: NZU64!(32),
                    max_outstanding_requests: 2,
                    update_channel_size: NZUsize!(4),
                    max_retained_roots: 4,
                },
            );
            let advance = async {
                paused.requested.notified().await;
                assert_eq!(
                    destination_executor
                        .modules()
                        .read()
                        .unwrap()
                        .nonces
                        .get_nonce("stale")
                        .unwrap(),
                    1
                );
                assert!(
                    destination_executor
                        .modules()
                        .read()
                        .unwrap()
                        .acp
                        .query_policy_ids()
                        .unwrap()
                        .is_empty()
                );
                source.apply(second).await;
                assert!(source.finalize().await.durable().await);
                let target = source.committed_targets().await;
                tip_tx
                    .send(TipUpdate::new(anchor(2), target.clone()))
                    .await
                    .unwrap();
                paused.gate.add_permits(2);
                handoff_entered.notified().await;
                assert_eq!(
                    destination_executor
                        .modules()
                        .read()
                        .unwrap()
                        .nonces
                        .get_nonce("stale")
                        .unwrap(),
                    1
                );
                assert!(
                    destination_executor
                        .modules()
                        .read()
                        .unwrap()
                        .acp
                        .query_policy_ids()
                        .unwrap()
                        .is_empty()
                );
                handoff_release.notify_one();
                (target, second_outcome.module_state_root)
            };
            let (synced, (target, module_root)) =
                ::tokio::time::timeout(Duration::from_secs(30), async {
                    ::tokio::join!(sync, advance)
                })
                .await
                .expect("sync deadline");
            let (destination, reached) = synced.unwrap();
            assert_eq!(reached, anchor(2));
            assert_eq!(destination.committed_targets().await, target);
            let expected = source_executor.modules().read().unwrap().serialize_stores();
            assert_eq!(
                destination_executor
                    .modules()
                    .read()
                    .unwrap()
                    .serialize_stores(),
                expected
            );
            let readers = destination.readers();
            assert_eq!(
                vera_modules::module_state::combine_module_roots(&[
                    readers.3.read().await.root().0,
                    readers.4.read().await.root().0,
                    readers.5.read().await.root().0,
                    readers.6.read().await.root().0,
                ]),
                module_root
            );

            let tx = policy(&signer, "third");
            let wrong_root = destination
                .execute(
                    destination.new_batches().await,
                    &block(3)
                        .with_verification()
                        .with_expected_module_state_root(B256::ZERO),
                    std::slice::from_ref(&tx),
                )
                .await;
            assert!(matches!(wrong_root, Err(AppError::RootMismatch(_))));
            let (suffix, outcome) = destination
                .execute(
                    destination.new_batches().await,
                    &block(3),
                    std::slice::from_ref(&tx),
                )
                .await
                .unwrap();
            let (_, source_outcome) = source
                .execute(source.new_batches().await, &block(3), &[tx])
                .await
                .unwrap();
            assert!(outcome.receipts[0].success());
            assert_eq!(outcome.module_state_root, source_outcome.module_state_root);
            assert_eq!(
                destination_executor
                    .modules()
                    .read()
                    .unwrap()
                    .serialize_stores(),
                expected
            );
            let old_acp_root = readers.3.read().await.root();
            let held = readers.6.read().await;
            let observe = async {
                while readers.3.read().await.root() == old_acp_root {
                    ::tokio::task::yield_now().await;
                }
                assert_eq!(
                    destination_executor
                        .modules()
                        .read()
                        .unwrap()
                        .serialize_stores(),
                    expected
                );
                drop(held);
            };
            ::tokio::time::timeout(Duration::from_secs(30), async {
                ::tokio::join!(destination.apply(suffix), observe)
            })
            .await
            .expect("apply publication deadline");
            assert!(destination.finalize().await.durable().await);
            assert_eq!(
                destination_executor
                    .modules()
                    .read()
                    .unwrap()
                    .nonces
                    .get_nonce(signer.did())
                    .unwrap(),
                3
            );
            drop(readers);
            drop(destination);
            let destination = OrderedState::init(
                context.child("recovered"),
                config(&context, "destination", destination_executor.clone()),
                Some(target.clone()),
            )
            .await;
            assert_eq!(destination.committed_targets().await, target);
            assert_eq!(
                destination_executor
                    .modules()
                    .read()
                    .unwrap()
                    .serialize_stores(),
                expected
            );
            (expected, target)
        })
    });
    tokio::Runner::new(runtime).start(|context| async move {
        let executor = VeraExecutor::new(DEPLOYMENT);
        let state = OrderedState::init(
            context.child("reopen"),
            config(&context, "destination", executor.clone()).recover_to(target.clone()),
            None,
        )
        .await;
        assert_eq!(state.committed_targets().await, target);
        assert_eq!(
            executor.modules().read().unwrap().serialize_stores(),
            expected
        );
    });
}
