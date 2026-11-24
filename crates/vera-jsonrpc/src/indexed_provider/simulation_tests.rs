use std::sync::{Arc, RwLock};

use alloy_primitives::{Address, B256, Bytes, U64, U256, keccak256};
use vera_domain::NativeCallSimulation;
use vera_executor::{ExecutionConfig, ModuleState, SharedModuleState};
use vera_indexer::{BlockIndex, IndexedBlock};
use vera_modules::acp::types::PolicyRecord;
use vera_modules::types::{BlockExecCtx, Timestamp, TxExecCtx};

use super::IndexedStateProvider;
use crate::simulation_slots::{SIMULATION_SLOTS, SIMULATION_WAITERS};
use crate::state_provider::StateProvider;
use crate::{LocalRpc, LocalRpcError, NodeState, RpcServer, error::codes};

pub(super) const CHAIN: u64 = 9001;
pub(super) const HEAD_NUMBER: u64 = 7;
pub(super) const HEAD_TIME: u64 = 1_800_000_123;
pub(super) const OWNER: &str = "did:key:owner";
pub(super) const POLICY: &str = "name: files\nresources:\n  - name: file\n";

pub(super) fn insert_head(index: &BlockIndex, number: u64, timestamp: u64) {
    index.insert_block(
        IndexedBlock {
            hash: B256::from(U256::from(number)),
            number,
            parent_hash: B256::ZERO,
            module_state_root: B256::ZERO,
            timestamp,
            gas_limit: 30_000_000,
            gas_used: 0,
            transaction_hashes: vec![],
        },
        vec![],
        vec![],
    );
}

pub(super) fn provider(modules: SharedModuleState) -> IndexedStateProvider {
    let index = Arc::new(BlockIndex::new());
    insert_head(&index, HEAD_NUMBER, HEAD_TIME);
    IndexedStateProvider::new(index, ExecutionConfig::new(CHAIN), 30_000_000, modules)
}

pub(super) fn local(provider: IndexedStateProvider) -> LocalRpc {
    RpcServer::with_state_provider(
        NodeState::new(CHAIN, 0, 1),
        "127.0.0.1:0".parse().unwrap(),
        provider,
    )
    .into_local()
    .unwrap()
}

pub(super) fn selector(signature: &str) -> Vec<u8> {
    keccak256(signature)[..4].to_vec()
}

pub(super) fn word(value: usize) -> [u8; 32] {
    U256::from(value).to_be_bytes()
}

/// Committed module values holding one policy `OWNER` created, and its identifier.
pub(super) fn committed() -> (SharedModuleState, B256) {
    let mut modules = ModuleState::default();
    let mut calldata = selector("createPolicy(bytes,uint8,bytes32)");
    calldata.extend_from_slice(&word(96));
    calldata.extend_from_slice(&word(1));
    calldata.extend_from_slice(&word(0));
    calldata.extend_from_slice(&word(POLICY.len()));
    calldata.extend_from_slice(POLICY.as_bytes());
    calldata.resize(calldata.len().next_multiple_of(32) + 4, 0);
    let created = vera_executor::precompiles::dispatch_to_module(
        &mut modules.acp,
        &mut modules.bulletin,
        &mut modules.vera,
        vera_executor::precompiles::ACP_ADDRESS,
        &calldata,
        &BlockExecCtx {
            timestamp: Timestamp {
                seconds: 10,
                block_height: 1,
            },
            deployment_id: CHAIN,
            ..Default::default()
        },
        &TxExecCtx {
            signer: OWNER.into(),
            tx_hash: vec![1; 32],
            sequence: 0,
        },
        vera_executor::ExecutionConfig::new(CHAIN).membership_limits(),
        1_000_000,
    )
    .unwrap()
    .unwrap();
    assert!(created.output.status.is_success());
    let returned = &created.output.bytes;
    let length = U256::from_be_slice(&returned[32..64]).to::<usize>();
    let record: PolicyRecord = serde_json::from_slice(&returned[64..64 + length]).unwrap();
    (
        Arc::new(RwLock::new(modules)),
        record.policy.id.parse().unwrap(),
    )
}

fn delete_policy(signer: &str, policy: B256) -> Vec<serde_json::Value> {
    let mut calldata = selector("deletePolicy(bytes32)");
    calldata.extend_from_slice(policy.as_slice());
    vec![serde_json::json!({
        "signer": signer,
        "target": vera_executor::precompiles::ACP_ADDRESS,
        "calldata": Bytes::from(calldata),
    })]
}

#[tokio::test]
async fn a_native_write_is_simulated_for_its_owner_refused_for_another_did_and_writes_nothing() {
    let (modules, policy) = committed();
    let before = modules.read().unwrap().serialize_stores();
    let local = local(provider(modules.clone()));
    assert!(local.method_names().contains(&"vera_simulateNativeCall"));

    let allowed: NativeCallSimulation = local
        .request("vera_simulateNativeCall", delete_policy(OWNER, policy))
        .await
        .unwrap();
    assert!(allowed.success, "{:?}", allowed.refusal);
    assert_eq!(allowed.refusal, None);
    assert_eq!(U256::from_be_slice(&allowed.output), U256::from(1));
    assert!(allowed.gas_used > U64::ZERO);
    assert_eq!(allowed.block_number, U64::from(HEAD_NUMBER));
    assert_eq!(allowed.timestamp, U64::from(HEAD_TIME));

    let refused: NativeCallSimulation = local
        .request(
            "vera_simulateNativeCall",
            delete_policy("did:key:other", policy),
        )
        .await
        .unwrap();
    assert!(!refused.success);
    let refusal = refused.refusal.unwrap();
    assert_eq!(refusal.kind, vera_domain::RefusalKind::Unauthorized);
    assert!(refusal.message().contains("only the policy creator"));
    assert!(refused.logs.is_empty() && refused.output.is_empty());

    let after = modules.read().unwrap();
    assert_eq!(after.serialize_stores(), before);
    assert_eq!(after.nonces.get_nonce(OWNER).unwrap(), 0);
    assert!(
        after
            .acp
            .query_policy(&alloy_primitives::hex::encode(policy))
            .is_ok()
    );
}

#[tokio::test]
async fn a_native_simulation_outside_submission_bounds_is_invalid_params() {
    let (modules, policy) = committed();
    let local = local(provider(modules));
    let mut unknown_target = delete_policy(OWNER, policy);
    unknown_target[0]["target"] = serde_json::json!(Address::repeat_byte(1));
    let mut unknown_field = delete_policy(OWNER, policy);
    unknown_field[0]["sequence"] = serde_json::json!(1);
    for params in [
        delete_policy("owner", policy),
        delete_policy(&format!("did:key:{}", "z".repeat(256)), policy),
        unknown_target,
        unknown_field,
    ] {
        let error = local
            .request::<NativeCallSimulation>("vera_simulateNativeCall", params)
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                LocalRpcError::Call {
                    code: codes::INVALID_PARAMS,
                    ..
                }
            ),
            "{error:?}"
        );
    }
}

#[tokio::test]
async fn a_native_simulation_beyond_the_shared_slots_is_refused_as_retryable() {
    let (modules, policy) = committed();
    let provider = provider(modules);
    let slots = provider.simulations.clone();
    let local = local(provider);
    let mut running = Vec::new();
    for _ in 0..SIMULATION_SLOTS {
        running.push(slots.acquire().await.unwrap());
    }
    let waiters: Vec<_> = (0..SIMULATION_WAITERS)
        .map(|_| {
            let slots = slots.clone();
            tokio::spawn(async move { slots.acquire().await.map(drop) })
        })
        .collect();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while slots.free_places() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let busy = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        local.request::<NativeCallSimulation>(
            "vera_simulateNativeCall",
            delete_policy(OWNER, policy),
        ),
    )
    .await
    .expect("a full queue must refuse without waiting for a slot")
    .unwrap_err();
    assert!(
        matches!(
            busy,
            LocalRpcError::Call {
                code: codes::RESOURCE_UNAVAILABLE,
                ..
            }
        ),
        "{busy:?}"
    );
    assert!(busy.is_retryable());

    drop(running);
    for waiter in waiters {
        waiter.await.unwrap().unwrap();
    }
    let admitted: NativeCallSimulation = local
        .request("vera_simulateNativeCall", delete_policy(OWNER, policy))
        .await
        .unwrap();
    assert!(admitted.success);
}

#[tokio::test]
async fn a_call_that_waited_for_a_slot_observes_the_head_published_meanwhile() {
    let (modules, policy) = committed();
    let provider = provider(modules);
    let slots = provider.simulations.clone();
    let index = provider.index.clone();
    let mut running = Vec::new();
    for _ in 0..SIMULATION_SLOTS {
        running.push(slots.acquire().await.unwrap());
    }

    let view = tokio::spawn({
        let provider = provider.clone();
        async move {
            provider
                .view_call(
                    vera_executor::precompiles::ACP_ADDRESS,
                    selector("getPolicyIds()").into(),
                )
                .await
        }
    });
    let native = tokio::spawn({
        let local = local(provider);
        async move {
            local
                .request::<NativeCallSimulation>(
                    "vera_simulateNativeCall",
                    delete_policy(OWNER, policy),
                )
                .await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while slots.free_places() != SIMULATION_WAITERS - 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    insert_head(&index, HEAD_NUMBER + 1, HEAD_TIME + 5);
    drop(running);
    let view = view.await.unwrap().unwrap();
    assert_eq!(view.refusal, None);
    assert_eq!(view.block_number, U64::from(HEAD_NUMBER + 1));
    assert_eq!(view.timestamp, U64::from(HEAD_TIME + 5));
    let native = native.await.unwrap().unwrap();
    assert!(native.success, "{:?}", native.refusal);
    assert_eq!(native.block_number, U64::from(HEAD_NUMBER + 1));
    assert_eq!(native.timestamp, U64::from(HEAD_TIME + 5));
}
