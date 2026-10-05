use std::{
    future::Future,
    num::{NonZeroU16, NonZeroUsize},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};

use alloy_primitives::{B256, Bytes, U64};
use commonware_glue::stateful::db::DatabaseSet as _;
use commonware_runtime::{Runner as _, buffer::paged::CacheRef, tokio as runtime};
use jsonrpsee::core::RpcResult;
use vera_backend::native::{NativeStateSet, read_partitions, state_config};
use vera_indexer::{BlockIndex, IndexedBlock};
use vera_permission::{ModuleId, PrefixPageRequest};

use crate::{
    NodeState,
    error::codes,
    vera_api::{VeraApiImpl, VeraApiServer},
};

async fn fixture(context: vera_backend::Ctx) -> (VeraApiImpl, NativeStateSet, B256) {
    let cache = CacheRef::from_pooler(
        &context,
        NonZeroU16::new(4084).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    );
    let set = NativeStateSet::init(context, state_config("policy-rpc", cache), None).await;
    let root = {
        let [a, b, h, n] = read_partitions([&set.0, &set.1, &set.2, &set.3]).await;
        vera_modules::module_state::combine_module_roots(&[
            a.root().0,
            b.root().0,
            h.root().0,
            n.root().0,
        ])
    };
    let mut api = VeraApiImpl::new(Arc::new(NodeState::new(1, 0, 1)), None);
    api.index = Some(Arc::new(BlockIndex::new()));
    api.native_modules = Some(set.clone());
    publish(&api, root, 1);
    (api, set, root)
}

fn publish(api: &VeraApiImpl, root: B256, height: u64) {
    let mut hash = [0; 32];
    hash[24..].copy_from_slice(&height.to_be_bytes());
    api.index.as_ref().unwrap().insert_block(
        IndexedBlock {
            hash: hash.into(),
            number: height,
            parent_hash: B256::ZERO,
            state_root: B256::ZERO,
            module_state_root: root,
            timestamp: height,
            gas_limit: 1_000_000,
            gas_used: 0,
            base_fee_per_gas: None,
            prevrandao: B256::ZERO,
            transaction_hashes: vec![],
        },
        vec![],
        vec![],
    );
    api.state.notify_proof_progress();
}

async fn request(api: &VeraApiImpl, page: bool, minimum: u64) -> RpcResult<()> {
    let policy = "ab".repeat(32);
    let prefix: Bytes = vera_modules::acp::keys::relationship_policy_prefix(&policy).into();
    if page {
        api.get_current_policy_prefix_page_proof(
            policy,
            PrefixPageRequest {
                module: ModuleId::Acp,
                start: prefix.clone(),
                prefix,
                limit: 1,
            },
            U64::from(minimum),
        )
        .await
        .map(|_| ())
    } else {
        api.get_current_policy_prefix_proof(policy, prefix, U64::from(minimum))
            .await
            .map(|_| ())
    }
}

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn assert_capacity(state: &NodeState, waiting: usize, proofs: usize) {
    let waiting: Vec<_> = (0..waiting)
        .map(|_| state.permission_read_permit().unwrap())
        .collect();
    assert!(state.permission_read_permit().is_err());
    let proofs: Vec<_> = (0..proofs).map(|_| state.proof_permit().unwrap()).collect();
    assert!(state.proof_permit().is_err());
    drop((waiting, proofs));
}

fn assert_busy(error: jsonrpsee::types::ErrorObjectOwned) {
    assert_eq!(error.code(), codes::RESOURCE_UNAVAILABLE);
    assert_eq!(error.data().unwrap().get(), r#"{"retryable":true}"#);
}

async fn assert_writable(set: &NativeStateSet) {
    for partition in [&set.0, &set.1, &set.2, &set.3] {
        let (slot, database) = tokio::time::timeout(Duration::from_secs(1), partition.write())
            .await
            .unwrap();
        slot.put(database);
    }
}

#[test]
fn future_policy_waiters_leave_proof_capacity_until_revision_is_eligible() {
    let directory = tempfile::tempdir().unwrap();
    runtime::Runner::new(runtime::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let (api, set, root) = fixture(context).await;
            let mut pending: Vec<_> = (0..8)
                .map(|i| Box::pin(request(&api, i % 2 == 0, 2)))
                .collect();
            for future in &mut pending {
                assert!(poll(future.as_mut()).is_pending());
            }
            assert_capacity(&api.state, 0, 8);
            assert_writable(&set).await;
            for page in [false, true] {
                assert_busy(request(&api, page, 2).await.unwrap_err());
            }
            // Publication wakes existing readers; evidence admission happens only now.
            let proofs: Vec<_> = (0..8).map(|_| api.state.proof_permit().unwrap()).collect();
            publish(&api, root, 2);
            for future in &mut pending {
                let Poll::Ready(result) = poll(future.as_mut()) else {
                    panic!("eligible request must check shared proof admission");
                };
                assert_busy(result.unwrap_err());
            }
            drop((pending, proofs));
            assert_capacity(&api.state, 8, 8);
        },
    );
}

#[test]
fn policy_waiter_cancellation_and_deadline_release_admission() {
    let directory = tempfile::tempdir().unwrap();
    runtime::Runner::new(runtime::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let (api, _, _) = fixture(context).await;
            for page in [false, true] {
                let mut cancelled = Box::pin(request(&api, page, 2));
                assert!(poll(cancelled.as_mut()).is_pending());
                assert_capacity(&api.state, 7, 8);
                drop(cancelled);
                assert_capacity(&api.state, 8, 8);
            }
            let (prefix, page) = tokio::time::timeout(Duration::from_secs(4), async {
                tokio::join!(request(&api, false, 2), request(&api, true, 2))
            })
            .await
            .unwrap();
            for result in [prefix, page] {
                let error = result.unwrap_err();
                assert_eq!(error.message(), "current policy evidence deadline exceeded");
                assert_busy(error);
            }
            assert_capacity(&api.state, 8, 8);
        },
    );
}

#[test]
fn captured_policy_evidence_holds_capacity_but_releases_storage_during_finality() {
    let directory = tempfile::tempdir().unwrap();
    runtime::Runner::new(runtime::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let (api, set, _) = fixture(context).await;
            let mut api = Arc::new(api);
            for page in [false, true] {
                let entered = Arc::new(tokio::sync::Notify::new());
                let signal = entered.clone();
                Arc::get_mut(&mut api).unwrap().light_block_lookup = Some(Arc::new(move |_| {
                    signal.notify_one();
                    Err("finalization certificate not found".into())
                }));
                let running = api.clone();
                let task = tokio::spawn(async move { request(&running, page, 1).await });
                tokio::time::timeout(Duration::from_secs(3), entered.notified())
                    .await
                    .unwrap();
                assert_capacity(&api.state, 7, 7);
                assert_writable(&set).await;
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
                assert_capacity(&api.state, 8, 8);
            }
        },
    );
}

#[tokio::test]
async fn policy_request_validation_releases_waiting_admission_without_proof_capacity() {
    let state = Arc::new(NodeState::new(1, 0, 1));
    let api = VeraApiImpl::new(state.clone(), None);
    let _proofs: Vec<_> = (0..8).map(|_| state.proof_permit().unwrap()).collect();
    let prefix: Bytes =
        vera_modules::acp::keys::relationship_policy_prefix(&"ab".repeat(32)).into();
    for _ in 0..10 {
        let error = api
            .get_current_policy_prefix_proof("invalid".into(), prefix.clone(), U64::ZERO)
            .await
            .unwrap_err();
        assert_eq!(error.code(), codes::INVALID_PARAMS);
        let error = api
            .get_current_policy_prefix_page_proof(
                "invalid".into(),
                PrefixPageRequest {
                    module: ModuleId::Acp,
                    start: prefix.clone(),
                    prefix: prefix.clone(),
                    limit: 1,
                },
                U64::ZERO,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), codes::INVALID_PARAMS);
    }
    assert_capacity(&state, 8, 0);
}
